//! `guest-agent` — PID 1 inside the Phase 15 guest VM's initrd.
//!
//! Listens on two fixed `AF_VSOCK` ports:
//!
//! - `NIX_DAEMON_PORT`: on each accepted connection, spawns `nix-daemon
//!   --stdio` and splices the connection's bytes straight onto the child's
//!   stdin/stdout, in both directions, until either side closes.
//! - `CONTROL_PORT` (Phase 15 Step 4): a tiny one-shot protocol that unlocks
//!   and mounts the tenant's `store.img` before any `nix-daemon` connection
//!   is worth accepting — see [`handle_control`].
//!
//! Deliberately dumb on the daemon port: unlike `worker/src/serve.rs`'s
//! `ServeConnection`, which has to parse the `nix-store --serve` wire
//! protocol because the frontend it talks to speaks that protocol,
//! `guest-agent` understands none of the bytes it relays there. The real
//! protocol speaker is on the other end of the vsock connection (the worker,
//! since Phase 15 Step 3) — this process only needs to get `nix-daemon` a
//! stdio pipe. The control port is the one place this process does
//! understand its own wire format — see `worker/src/vm.rs::push_key` for the
//! other end of it.
//!
//! No systemd, no udev: there is nothing else running in this VM for either
//! to manage. Running as PID 1 also means this process is the guest's init,
//! so on exit the kernel panics — cloud-hypervisor's `--console`/reboot
//! handling determines what happens next, not anything decided here.
//!
//! Logging is plain `eprintln!`, not `tracing`: verified empirically against
//! a real cloud-hypervisor boot (`nix/guest-vm-test.nix`) that
//! `tracing_subscriber`'s writer produces no output at all on this guest's
//! serial console, while `eprintln!` does -- and a minimal PID-1 binary has
//! no need for structured logging's complexity anyway.

use std::net::Shutdown;
use std::process::Stdio;

use eyre::{Context, Result, eyre};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::process::{Child, Command};
use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener, VsockStream};

/// Fixed by convention between `guest-agent` and whatever dials it (the
/// worker, or this crate's own boot test in the meantime) — there is exactly
/// one service behind this VM's vsock at this port, so there is nothing to
/// negotiate a port for.
const NIX_DAEMON_PORT: u32 = 620;

/// The control channel's fixed port — see the module doc and
/// `worker/src/vm.rs::CONTROL_PORT` (duplicated by convention, same as
/// `NIX_DAEMON_PORT` is on the worker side).
const CONTROL_PORT: u32 = 621;

/// Path to `nix-daemon` inside the initrd. Not configurable: `nix/guest-vm.nix`
/// symlinks it here (there is no NixOS profile / `/run/current-system` in this
/// minimal, systemd-free guest — see that file's `contents` list).
const NIX_DAEMON_BIN: &str = "/bin/nix-daemon";

/// The raw block device `store.img` is attached as (`--disk path=...` in
/// `worker/src/vm.rs`'s `CloudHypervisorLauncher`) — the guest's first (and
/// only) virtio-blk device, so it's `vda`, not `vdb` (`virtio_blk` numbers
/// devices in attach order starting from `a`; there is nothing else attached
/// ahead of it here).
const RAW_DEVICE: &str = "/dev/vda";

/// The name `cryptsetup open` registers under `/dev/mapper/`.
const DM_NAME: &str = "tenant-store";

const STORE_MOUNT: &str = "/nix/store";

// Every exec below uses a fixed absolute path rather than a bare name
// resolved via `$PATH`, same convention as `NIX_DAEMON_BIN`: this PID-1
// process has no `$PATH` set (nothing in this initrd sets one), so a bare
// name's resolution would depend on libc's `execvp` fallback search path
// happening to agree with where `nix/guest-vm.nix` put each binary --
// worth pinning down explicitly rather than relying on.
const MODPROBE_BIN: &str = "/sbin/modprobe";
const CRYPTSETUP_BIN: &str = "/bin/cryptsetup";
const MKFS_EXT4_BIN: &str = "/bin/mkfs.ext4";
const MOUNT_BIN: &str = "/bin/mount";

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install().ok();

    // Since `guest-agent` *is* `/init` (unpacked straight out of the
    // initramfs cpio, execed directly as PID 1), the kernel never runs
    // `prepare_namespace()` -- that's where `devtmpfs_mount()` lives, gated
    // on the "load a real root filesystem" path this guest never takes.
    // `CONFIG_DEVTMPFS_MOUNT` therefore does nothing here despite being set;
    // `/dev` starts out with only the `console` node the kernel's early
    // console init creates directly (not via devtmpfs), so `/dev/vda` would
    // never appear without this. Same shape as any minimal init (busybox
    // `init`, systemd) mounting devtmpfs as its first action.
    if let Err(err) = run(MOUNT_BIN, &["-t", "devtmpfs", "devtmpfs", "/dev"]).await {
        eprintln!("guest-agent: mounting devtmpfs at /dev failed: {err}");
    }
    // Same reasoning as `/dev` above -- nothing else in this minimal,
    // systemd-free guest mounts these, but `cryptsetup`/`libdevmapper`
    // reads `/proc` (misc-device major/minor lookup, among other things)
    // even when `/dev/mapper/control` already exists.
    for (fstype, target) in [("proc", "/proc"), ("sysfs", "/sys")] {
        if let Err(err) = std::fs::create_dir_all(target) {
            eprintln!("guest-agent: creating {target} failed: {err}");
        }
        if let Err(err) = run(MOUNT_BIN, &["-t", fstype, fstype, target]).await {
            eprintln!("guest-agent: mounting {fstype} at {target} failed: {err}");
        }
    }
    log_dev_contents();

    let daemon_listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, NIX_DAEMON_PORT))
        .wrap_err("binding vsock listener")?;
    eprintln!("guest-agent listening on vsock port {NIX_DAEMON_PORT}");

    let control_listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, CONTROL_PORT))
        .wrap_err("binding control vsock listener")?;
    eprintln!("guest-agent listening on control vsock port {CONTROL_PORT}");

    tokio::spawn(async move {
        control_accept_loop(control_listener).await;
    });

    loop {
        let (stream, peer) = match daemon_listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                eprintln!("guest-agent: accept failed: {err}");
                continue;
            }
        };
        eprintln!("guest-agent: accepted vsock connection from {peer:?}");

        // One `nix-daemon` per connection, same as the real daemon's own
        // Unix-socket accept loop. Errors here are per-connection, not fatal
        // to the agent: a build worth retrying dials again.
        tokio::spawn(async move {
            if let Err(err) = serve(stream).await {
                eprintln!("guest-agent: connection handling failed: {err}");
            }
        });
    }
}

/// One-line `/dev` listing at startup — with no udev in this guest, `/dev`'s
/// contents are entirely a function of devtmpfs auto-population, so this is
/// the cheapest way to confirm the block device Step 4 needs (`RAW_DEVICE`)
/// actually showed up before anything tries to open it.
fn log_dev_contents() {
    match std::fs::read_dir("/dev") {
        Ok(entries) => {
            let names: Vec<String> = entries
                .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
                .collect();
            eprintln!("guest-agent: /dev contains: {names:?}");
        }
        Err(err) => eprintln!("guest-agent: reading /dev failed: {err}"),
    }
}

/// Accept loop for the control channel. Handled sequentially per connection,
/// same shape as the daemon port's loop, even though in practice the worker
/// only ever dials this once per boot (right after `wait_for_vsock_ready`
/// succeeds, before it dials `NIX_DAEMON_PORT`).
async fn control_accept_loop(listener: VsockListener) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                eprintln!("guest-agent: control accept failed: {err}");
                continue;
            }
        };
        eprintln!("guest-agent: accepted control connection from {peer:?}");
        tokio::spawn(async move {
            if let Err(err) = handle_control(stream).await {
                eprintln!("guest-agent: control connection failed: {err}");
            }
        });
    }
}

/// One-shot control protocol: read a single `KEY <64 hex chars> <FRESH|REUSE>`
/// line, open `RAW_DEVICE` as plain `dm-crypt` with that key, `mkfs.ext4` it
/// first if `FRESH`, mount the result at `STORE_MOUNT`, and reply `OK` or
/// `ERR <message>` before closing. See `worker/src/vm.rs::push_key` for the
/// client side of this exact protocol.
async fn handle_control(mut stream: VsockStream) -> Result<()> {
    let (read_half, mut write_half) = stream.split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .wrap_err("reading control line")?;

    let reply = match unlock_and_mount(line.trim_end()).await {
        Ok(()) => "OK\n".to_string(),
        // `eyre::Report`'s `Display` only surfaces the outermost context
        // (e.g. "cryptsetup open"), discarding exactly the underlying
        // command's stderr that explains *why* -- join the full chain so a
        // caller (or a console log grep) sees the real cause, not just which
        // step failed.
        Err(err) => {
            let chain: Vec<String> = err.chain().map(|e| e.to_string()).collect();
            format!("ERR {}\n", chain.join(": "))
        }
    };
    write_half
        .write_all(reply.as_bytes())
        .await
        .wrap_err("writing control reply")?;
    write_half.shutdown().await.ok();
    Ok(())
}

async fn unlock_and_mount(line: &str) -> Result<()> {
    let mut parts = line.split(' ');
    let cmd = parts.next().ok_or_else(|| eyre!("empty control line"))?;
    if cmd != "KEY" {
        return Err(eyre!("unrecognised control command {cmd:?}"));
    }
    let hex_key = parts
        .next()
        .ok_or_else(|| eyre!("missing key in KEY command"))?;
    let mode = parts
        .next()
        .ok_or_else(|| eyre!("missing FRESH/REUSE in KEY command"))?;
    let fresh = match mode {
        "FRESH" => true,
        "REUSE" => false,
        other => return Err(eyre!("unrecognised mode {other:?}, want FRESH or REUSE")),
    };
    let key = decode_hex(hex_key).wrap_err("decoding key")?;

    // `BLK_DEV_DM`/`DM_CRYPT` are kernel modules, not builtins (see
    // `nix/guest-vm.nix`'s comment on why), so `/dev/mapper/control` doesn't
    // exist until `dm-mod`/`dm-crypt` are loaded. `modprobe`'s `modules.dep`
    // resolves `dm-crypt`'s dependency on `dm-mod` in one call; the crypto
    // ciphers themselves (`CRYPTO_AES`/`CRYPTO_XTS`, also modules) are loaded
    // on demand by the kernel's own crypto subsystem the first time
    // `cryptsetup` requests the `xts(aes)` transform, via the same
    // `/sbin/modprobe` this depends on being present.
    modprobe("dm-crypt").await?;

    cryptsetup_open(&key).await?;
    if fresh {
        mkfs_ext4().await?;
    }
    mount_store().await?;
    Ok(())
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(eyre!("odd-length hex string"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .wrap_err_with(|| format!("invalid hex byte at {i}"))
        })
        .collect()
}

/// Load `module` and its dependencies via `modprobe`'s `modules.dep`
/// resolution (`/lib/modules/<version>` is packed into the initrd by
/// `nix/guest-vm.nix`, matching this exact kernel build).
async fn modprobe(module: &str) -> Result<()> {
    run(MODPROBE_BIN, &[module]).await.wrap_err("modprobe")
}

/// `cryptsetup open --type plain`, piping the key over stdin (never on
/// argv/the environment, never logged) rather than via `--key-file` on a real
/// path. Plain mode deliberately has no on-disk header — the ciphertext is
/// indistinguishable from random noise to anyone without the key, which is
/// the entire point of Phase 15 Step 4.
async fn cryptsetup_open(key: &[u8]) -> Result<()> {
    run_with_stdin(
        CRYPTSETUP_BIN,
        &[
            "open",
            "--type",
            "plain",
            "--cipher",
            "aes-xts-plain64",
            "--key-size",
            "256",
            "--key-file",
            "-",
            RAW_DEVICE,
            DM_NAME,
        ],
        key,
    )
    .await
    .wrap_err("cryptsetup open")
}

async fn mkfs_ext4() -> Result<()> {
    run(MKFS_EXT4_BIN, &["-q", &format!("/dev/mapper/{DM_NAME}")])
        .await
        .wrap_err("mkfs.ext4")
}

async fn mount_store() -> Result<()> {
    tokio::fs::create_dir_all(STORE_MOUNT)
        .await
        .wrap_err_with(|| format!("creating {STORE_MOUNT}"))?;
    run(
        MOUNT_BIN,
        &["-t", "ext4", &format!("/dev/mapper/{DM_NAME}"), STORE_MOUNT],
    )
    .await
    .wrap_err("mount")
}

async fn run(bin: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(bin)
        .args(args)
        .output()
        .await
        .wrap_err_with(|| format!("spawning {bin}"))?;
    if !output.status.success() {
        return Err(eyre!(
            "{bin} {args:?} exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

async fn run_with_stdin(bin: &str, args: &[&str], stdin: &[u8]) -> Result<()> {
    let mut child = Command::new(bin)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .wrap_err_with(|| format!("spawning {bin}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| eyre!("no stdin"))?
        .write_all(stdin)
        .await
        .wrap_err_with(|| format!("writing {bin}'s stdin"))?;
    let output = child
        .wait_with_output()
        .await
        .wrap_err_with(|| format!("waiting for {bin}"))?;
    if !output.status.success() {
        return Err(eyre!(
            "{bin} {args:?} exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

/// Spawn `nix-daemon --stdio` and relay `stream` onto its stdin/stdout until
/// either side closes.
async fn serve(mut stream: VsockStream) -> Result<()> {
    let mut child = spawn_nix_daemon()?;
    let mut child_stdin = child.stdin.take().ok_or_else(|| eyre::eyre!("no stdin"))?;
    let mut child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| eyre::eyre!("no stdout"))?;

    let (mut stream_read, mut stream_write) = stream.split();

    // Two directions, driven concurrently: the vsock peer's writes feed
    // nix-daemon's stdin, and nix-daemon's stdout feeds back to the peer.
    // Neither `tokio::io::copy` call returns until its source hits EOF, which
    // is exactly "the peer closed" on one side and "nix-daemon exited" on the
    // other — either is a legitimate reason to tear the whole connection down.
    let relay_in = async {
        let result = tokio::io::copy(&mut stream_read, &mut child_stdin).await;
        // nix-daemon reads EOF on its stdin as "no more requests"; without
        // explicitly dropping our end here it would just see the pipe stay
        // open and hang waiting for more.
        drop(child_stdin);
        result
    };
    let relay_out = tokio::io::copy(&mut child_stdout, &mut stream_write);

    tokio::select! {
        result = relay_in => { result.wrap_err("relaying vsock -> nix-daemon")?; }
        result = relay_out => { result.wrap_err("relaying nix-daemon -> vsock")?; }
    }

    reap(&mut child).await;
    stream.shutdown(Shutdown::Both).ok();
    Ok(())
}

fn spawn_nix_daemon() -> Result<Child> {
    Command::new(NIX_DAEMON_BIN)
        .arg("--stdio")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .wrap_err_with(|| format!("spawning {NIX_DAEMON_BIN} --stdio"))
}

/// Wait for the child, logging anything unexpected. Never fatal to the
/// agent's own accept loop — a build worth retrying dials a fresh
/// connection, which spawns a fresh `nix-daemon`.
async fn reap(child: &mut Child) {
    match child.wait().await {
        Ok(status) if status.success() => {}
        Ok(status) => eprintln!("guest-agent: nix-daemon exited with {status}"),
        Err(err) => eprintln!("guest-agent: waiting on nix-daemon: {err}"),
    }
}
