//! `guest-agent` — PID 1 inside the Phase 15 guest VM's initrd.
//!
//! Listens on two fixed `AF_VSOCK` ports:
//!
//! - `NIX_DAEMON_PORT`: on each accepted connection, spawns `nix-daemon
//!   --stdio` and splices the connection's bytes straight onto the child's
//!   stdin/stdout, in both directions, until either side closes.
//! - `CONTROL_PORT` (Phase 15 Step 4): a verb-prefixed line protocol,
//!   one-shot per connection. `KEY` unlocks and mounts the tenant's
//!   `store.img` before any `nix-daemon` connection is worth accepting;
//!   `CAPS?` (Phase 17) answers a boot-time nested-virt self-test. See
//!   [`handle_control`].
//! - `LOG_PORT`: a debugging aid, not part of the production protocol surface
//!   — streams this process's `tracing` output to whoever connects. See the
//!   "Logging" section below for why it's a separate channel.
//!
//! Also brings up its one virtio-net interface at startup (Phase 15 Step 5,
//! [`configure_network`]) with a fixed, static address agreed by convention
//! with the `passt` process `worker/src/vm.rs` spawns alongside this VM — see
//! that function's doc comment for why this is static configuration and not
//! a DHCP client.
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
//! # Logging
//!
//! Startup and lifecycle messages (mounts, accept-loop errors, spawn
//! failures) stay plain `eprintln!`, verified empirically against a real
//! cloud-hypervisor boot (`nix/guest-vm-test.nix`) to actually reach this
//! guest's serial console when `tracing_subscriber`'s own writer did not.
//! `tracing` is used *in addition*, for events worth having as a structured,
//! filterable stream separate from that console -- which is shared with raw
//! kernel boot messages and every spawned child's inherited stderr, and is
//! genuinely not the same failure mode `tracing_subscriber` hit before: that
//! was about writing to the console *tty*, and this writer never does,
//! streaming instead to whichever debugging client dials `LOG_PORT` (see
//! [`VsockLogWriter`]). `tokio_vsock`'s own instrumentation is filtered down
//! (see `main`'s `EnvFilter`) so it doesn't drown out this process's own
//! events -- the whole point of a second channel is a *cleaner* stream, not
//! just a different pipe for the same noise.

mod cgroup;
mod diag;
mod ebpf;

use std::net::Shutdown;
use std::process::Stdio;
use std::sync::Arc;

use eyre::{Context, Result, eyre};
use tokio::io::{
    AsyncBufReadExt as _, AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, BufReader,
};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, broadcast};
use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener, VsockStream};

use ebpf::{DetectionState, FailureStatus};

/// Fixed by convention between `guest-agent` and whatever dials it (the
/// worker, or this crate's own boot test in the meantime) — there is exactly
/// one service behind this VM's vsock at this port, so there is nothing to
/// negotiate a port for.
const NIX_DAEMON_PORT: u32 = 620;

/// The control channel's fixed port — see the module doc and
/// `worker/src/vm.rs::CONTROL_PORT` (duplicated by convention, same as
/// `NIX_DAEMON_PORT` is on the worker side).
const CONTROL_PORT: u32 = 621;

/// The debug log-stream port — see the module doc's "Logging" section.
const LOG_PORT: u32 = 622;

/// Bridges `tracing_subscriber::fmt`'s formatted output into a broadcast
/// channel that [`log_accept_loop`] fans out to every connected client.
///
/// Best-effort by design: a full channel drops the oldest still-unread line
/// rather than blocking `write` (`broadcast::Sender::send` never blocks —
/// slow subscribers lag and get told so via `RecvError::Lagged`, they don't
/// back-pressure the writer), and a line sent with zero subscribers connected
/// is simply discarded. A debugging log stream has no business stalling the
/// process it's observing, or buffering for a client that isn't there yet.
#[derive(Clone)]
struct VsockLogWriter {
    tx: broadcast::Sender<Vec<u8>>,
}

impl std::io::Write for VsockLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let _ = self.tx.send(buf.to_vec());
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for VsockLogWriter {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

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

/// Where `/nix/store`, as the initrd itself baked it in, gets bind-mounted
/// to before anything else is mounted at the real `/nix/store` — see
/// `mount_store`'s doc comment.
const STORE_LOWER: &str = "/mnt/store-lower";

/// Where the decrypted `/dev/mapper/tenant-store` ext4 filesystem is mounted
/// so its `upper`/`work` subdirectories are reachable — the overlay itself
/// goes at `STORE_MOUNT`, not here.
const STORE_RAW: &str = "/mnt/store-raw";

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
const IP_BIN: &str = "/bin/ip";

/// The guest's virtio-net interface, as `VIRTIO_NET`'s driver names the
/// first (and only) network device this guest ever sees.
const NET_IFACE: &str = "eth0";

/// Phase 15 Step 5's network link is a fixed, point-to-point address plan
/// shared by convention with `worker/src/vm.rs`'s `passt` invocation (its
/// `-a`/`-n`/`-g` flags), the same way `NIX_DAEMON_PORT`/`CONTROL_PORT` are
/// shared with it above -- there is exactly one guest and one `passt`
/// process on the other end of this link, so there is nothing to negotiate a
/// dynamic address for, and no DHCP client needs to exist in this guest at
/// all. `passt` itself is the gateway (it NATs everything the guest sends at
/// this address out to the real network).
const GUEST_ADDR: &str = "10.42.100.2/24";
const GUEST_GATEWAY: &str = "10.42.100.1";

#[tokio::main]
async fn main() -> Result<()> {
    // PLAN.md Phase 18: `TRIGGER_OOM`/`TRIGGER_ENOSPC` (below) re-exec this
    // same binary as a disposable child process to run one of `diag`'s
    // payloads, instead of the real PID-1 init logic below -- see
    // `diag.rs`'s module doc for why. Checked before anything else in
    // `main` runs (including `color_eyre::install()`, which a short-lived
    // diagnostic child has no use for).
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("--diag-oom-victim") => diag::oom_victim(),
        Some("--diag-fill-store") => {
            let path = args
                .get(2)
                .map(String::as_str)
                .unwrap_or("/nix/store/.kubernix-enospc-test");
            diag::fill_store(path);
            return Ok(());
        }
        _ => {}
    }

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
    // `devpts`, not `devtmpfs` above, is what actually allocates a sandboxed
    // build's controlling PTY slave once it opens `/dev/ptmx` -- without
    // this mounted, that open fails outright (`local-derivation-goal.cc`
    // does it before the build's own mount namespace even exists, so this
    // has to be visible here, in the guest's root namespace).
    //
    // `/tmp` is where this points Nix's own `build-dir` setting (see
    // `spawn_nix_daemon`'s doc comment), and `/nix/var` is Nix's state
    // directory (its path/GC-roots database, temp roots, ...) -- `nix
    // -daemon` `mkdir`s directly inside both itself, which the read-only
    // EROFS root (`nix/guest-vm.nix`'s `rootImg`) can never allow no matter
    // how the directory got there. Everything else in this list only needs
    // an empty directory to mount *onto*, which `rootImg` ships pre-made
    // for exactly that reason; these two need to be writable themselves.
    for (fstype, target) in [
        ("proc", "/proc"),
        ("sysfs", "/sys"),
        ("devpts", "/dev/pts"),
        ("tmpfs", "/tmp"),
        ("tmpfs", "/nix/var"),
    ] {
        if let Err(err) = std::fs::create_dir_all(target) {
            eprintln!("guest-agent: creating {target} failed: {err}");
        }
        if let Err(err) = run(MOUNT_BIN, &["-t", fstype, fstype, target]).await {
            eprintln!("guest-agent: mounting {fstype} at {target} failed: {err}");
        }
    }
    log_dev_contents();

    // PLAN.md Phase 18: the cgroup v2 leaf nix-daemon's build children get
    // scoped into, and the eBPF programs that watch it -- both need to be
    // ready before the first connection is ever accepted on
    // `NIX_DAEMON_PORT` below. Neither is allowed to block boot on failure:
    // a guest that can't set these up is still a guest that can build
    // (without the retry/escalation mechanism, not without building at
    // all), so this stays best-effort like the mount loop above rather than
    // aborting `main`.
    if let Err(err) = cgroup::setup().await {
        eprintln!("guest-agent: cgroup setup failed: {err}");
    }
    let detection = match DetectionState::setup() {
        Ok(state) => Some(Arc::new(Mutex::new(state))),
        Err(err) => {
            let chain: Vec<String> = err.chain().map(|e| e.to_string()).collect();
            eprintln!(
                "guest-agent: eBPF detection setup failed: {}",
                chain.join(": ")
            );
            None
        }
    };

    // Phase 15 Step 5: bring up the guest's side of the `passt` link so
    // `nix-daemon` can reach substituters directly. Best-effort like the
    // mount loop above -- a VM booted without networking wired up (e.g. the
    // Step 1-4 tests, which never pass `--net` at all) should still boot and
    // serve builds against already-fetched inputs, just without substitution.
    if let Err(err) = configure_network().await {
        eprintln!("guest-agent: network configuration failed: {err}");
    } else {
        eprintln!("guest-agent: network configured: {NET_IFACE} {GUEST_ADDR} via {GUEST_GATEWAY}");
    }

    // `tokio_vsock` (and anything else with its own tracing instrumentation)
    // gets turned down to `warn` by default so this stream stays focused on
    // `guest-agent`'s own events — see the module doc's "Logging" section.
    // `RUST_LOG` still overrides this entirely, same as any `tracing`-based
    // binary, for whoever's actually debugging with this connected.
    let (log_tx, _) = broadcast::channel::<Vec<u8>>(1024);
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,tokio_vsock=warn"));
    tracing_subscriber::fmt()
        .with_writer(VsockLogWriter { tx: log_tx.clone() })
        .with_ansi(false)
        .with_env_filter(filter)
        .init();

    let daemon_listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, NIX_DAEMON_PORT))
        .wrap_err("binding vsock listener")?;
    eprintln!("guest-agent listening on vsock port {NIX_DAEMON_PORT}");

    let control_listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, CONTROL_PORT))
        .wrap_err("binding control vsock listener")?;
    eprintln!("guest-agent listening on control vsock port {CONTROL_PORT}");

    let log_listener = VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, LOG_PORT))
        .wrap_err("binding log vsock listener")?;
    eprintln!("guest-agent listening on log vsock port {LOG_PORT}");

    let control_detection = detection.clone();
    tokio::spawn(async move {
        control_accept_loop(control_listener, control_detection).await;
    });

    tokio::spawn(async move {
        log_accept_loop(log_listener, log_tx).await;
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
        let detection = detection.clone();
        tokio::spawn(async move {
            if let Err(err) = serve(stream, detection).await {
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
async fn control_accept_loop(
    listener: VsockListener,
    detection: Option<Arc<Mutex<DetectionState>>>,
) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                eprintln!("guest-agent: control accept failed: {err}");
                continue;
            }
        };
        eprintln!("guest-agent: accepted control connection from {peer:?}");
        let detection = detection.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_control(stream, detection).await {
                eprintln!("guest-agent: control connection failed: {err}");
            }
        });
    }
}

/// Accept loop for the debug log stream. Each connected client gets its own
/// subscription to the broadcast channel `VsockLogWriter` feeds, so multiple
/// clients (or repeated reconnects while debugging) can watch at once without
/// interfering with each other.
async fn log_accept_loop(listener: VsockListener, tx: broadcast::Sender<Vec<u8>>) {
    loop {
        let (mut stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                eprintln!("guest-agent: log accept failed: {err}");
                continue;
            }
        };
        eprintln!("guest-agent: log stream client connected from {peer:?}");
        let mut rx = tx.subscribe();
        tokio::spawn(async move {
            let (_read_half, mut write_half) = stream.split();
            loop {
                match rx.recv().await {
                    Ok(line) => {
                        if write_half.write_all(&line).await.is_err() {
                            break;
                        }
                    }
                    // A slow client fell behind and missed some lines --
                    // nothing to do but keep going with whatever's next;
                    // this is a best-effort stream, not a reliable log.
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        });
    }
}

/// One-shot-per-connection, verb-prefixed line protocol: read a single line,
/// dispatch on its first space-separated token, and reply either `OK\n`,
/// `OK <data>\n` (a verb that answers with data rather than plain
/// success), or `ERR <message>\n`, before closing. Verbs today:
///
/// - `KEY <64 hex chars> <FRESH|REUSE>` -- open `RAW_DEVICE` as plain
///   `dm-crypt` with that key, `mkfs.ext4` it first if `FRESH`, mount the
///   result at `STORE_MOUNT`. See `worker/src/vm.rs::push_key` for the
///   client side.
/// - `CAPS?` -- report nested-virtualization support as seen from inside
///   this guest (PLAN.md Phase 17). See `worker/src/vm.rs::boot_probe` for
///   the client side.
/// - `STATUS?` -- report whatever resource-exhaustion signal has fired
///   since the last `RESET`, without clearing it (PLAN.md Phase 18). See
///   `worker/src/vm.rs::query_status`.
/// - `RESET` -- clear the OOM/ENOSPC detection state, scoping it to the
///   build about to start (PLAN.md Phase 18). Sent by the worker right
///   before it opens a new build's daemon-protocol connection. See
///   `worker/src/vm.rs::reset_job_status`.
/// - `TRIGGER_OOM` / `TRIGGER_ENOSPC` -- diagnostic-only (PLAN.md Phase
///   18): drive `diag.rs`'s payloads from the outside, for
///   `nix/vm-oom-test.nix`/`vm-enospc-test.nix`. No production client ever
///   sends either.
async fn handle_control(
    mut stream: VsockStream,
    detection: Option<Arc<Mutex<DetectionState>>>,
) -> Result<()> {
    let (read_half, mut write_half) = stream.split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .wrap_err("reading control line")?;

    let reply = match dispatch_control(line.trim_end(), detection).await {
        Ok(ControlReply::Ok) => "OK\n".to_string(),
        Ok(ControlReply::OkWithData(n)) => format!("OK {n}\n"),
        Ok(ControlReply::OkWithStatus(status)) => format!("OK {}\n", format_status(status)),
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
    // Explicit graceful half-close: a `Drop`-only close (tried while chasing
    // what turned out to be an unrelated bug -- see `nix/vm-test-lib.nix`'s
    // `vm_push_key` doc comment) made the client-side `socat` see a less
    // clean disconnect, enough to exit non-zero even after successfully
    // reading the reply -- and under the test script's `set -euo pipefail`,
    // that alone killed the whole script via `pipefail`.
    write_half.shutdown().await.ok();
    Ok(())
}

#[derive(Debug)]
enum ControlReply {
    Ok,
    OkWithData(u32),
    OkWithStatus(FailureStatus),
}

/// `OK <data>\n`'s wire text for a `STATUS?` reply -- see
/// `worker/src/vm.rs::parse_status_reply`, the client-side counterpart.
fn format_status(status: FailureStatus) -> String {
    match status {
        FailureStatus::None => "NONE".to_string(),
        FailureStatus::OutOfMemory {
            builder_victim: true,
        } => "OOM BUILDER".to_string(),
        FailureStatus::OutOfMemory {
            builder_victim: false,
        } => "OOM OTHER".to_string(),
        FailureStatus::DiskFull => "ENOSPC".to_string(),
    }
}

async fn dispatch_control(
    line: &str,
    detection: Option<Arc<Mutex<DetectionState>>>,
) -> Result<ControlReply> {
    let mut parts = line.split(' ');
    let cmd = parts.next().ok_or_else(|| eyre!("empty control line"))?;
    match cmd {
        "KEY" => {
            unlock_and_mount(parts).await?;
            Ok(ControlReply::Ok)
        }
        "CAPS?" => Ok(ControlReply::OkWithData(count_nested_virt_flags()?)),
        "STATUS?" => {
            let detection = detection.ok_or_else(|| eyre!("eBPF detection not available"))?;
            let status = detection.lock().await.status().await;
            Ok(ControlReply::OkWithStatus(status))
        }
        "RESET" => {
            let detection = detection.ok_or_else(|| eyre!("eBPF detection not available"))?;
            detection.lock().await.reset().await?;
            Ok(ControlReply::Ok)
        }
        // PLAN.md Phase 18, diagnostic-only: drives `diag.rs`'s payloads
        // from the outside, for `nix/vm-oom-test.nix`/`vm-enospc-test.nix`.
        // A real deployment never sends either -- only the worker's
        // `KEY`/`CAPS?`/`STATUS?`/`RESET` traffic is production use.
        "TRIGGER_OOM" => {
            trigger_oom().await?;
            Ok(ControlReply::Ok)
        }
        "TRIGGER_ENOSPC" => {
            trigger_enospc().await;
            Ok(ControlReply::Ok)
        }
        other => Err(eyre!("unrecognised control command {other:?}")),
    }
}

/// Re-execs this same binary as `/init --diag-oom-victim` (see `diag.rs`'s
/// module doc), moves its pid into the build cgroup exactly the way `serve`
/// does for a real `nix-daemon` instance, and spawns a reaper task so it
/// doesn't outlive its own `SIGKILL` as a zombie. Returns as soon as the
/// child is launched and scoped -- it's expected to keep running (and,
/// under a real `memory.max`, eventually get OOM-killed) well past this
/// control connection's own one-shot reply.
async fn trigger_oom() -> Result<()> {
    let self_exe = std::env::current_exe().unwrap_or_else(|_| "/init".into());
    let mut child = Command::new(self_exe)
        .arg("--diag-oom-victim")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .wrap_err("spawning the OOM diagnostic child")?;
    if let Some(pid) = child.id() {
        cgroup::move_into_build_cgroup(pid)
            .await
            .wrap_err("moving the OOM diagnostic child into the build cgroup")?;
    }
    tokio::spawn(async move {
        let _ = child.wait().await;
    });
    Ok(())
}

/// Runs `diag::fill_store` in a blocking task against a fixed path under
/// `/nix/store` -- no subprocess needed, unlike [`trigger_oom`]: ENOSPC
/// detection has no builder/non-builder attribution to set up, so there's
/// nothing a separate process buys here. Awaits completion (the write loop
/// itself is bounded, see `diag.rs`) so the caller's `STATUS?` poll
/// afterwards has a real chance of already seeing the flag set.
async fn trigger_enospc() {
    let _ = tokio::task::spawn_blocking(|| {
        diag::fill_store("/nix/store/.kubernix-enospc-test");
    })
    .await;
}

async fn unlock_and_mount(mut parts: std::str::Split<'_, char>) -> Result<()> {
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

/// In-process equivalent of `egrep -c '(vmx|svm)' /proc/cpuinfo`: the count of
/// `/proc/cpuinfo` lines advertising a nested-virt-capable flag, i.e. how many
/// CPUs this guest itself sees as `vmx`/`svm`-capable. Reflects whatever the
/// hypervisor's CPU model passes through to the guest, not host-side
/// capability directly -- which is exactly the perspective that matters for
/// whether an L2 VM inside this guest would actually work (PLAN.md Phase 17).
/// No `regex` crate, no process spawn: a plain read and line scan, matching
/// this crate's minimal-dependency commitment.
fn count_nested_virt_flags() -> Result<u32> {
    let contents = std::fs::read_to_string("/proc/cpuinfo").wrap_err("reading /proc/cpuinfo")?;
    Ok(count_nested_virt_flags_str(&contents))
}

fn count_nested_virt_flags_str(cpuinfo: &str) -> u32 {
    cpuinfo
        .lines()
        .filter(|line| line.contains("vmx") || line.contains("svm"))
        .count() as u32
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

/// Mounts the decrypted `/dev/mapper/tenant-store` ext4 filesystem as the
/// writable *upper* layer of an overlayfs whose *lower* layer is
/// `/nix/store` exactly as the initrd baked it in, then mounts that overlay
/// back at `/nix/store`.
///
/// Mounting the tenant's (initially empty) filesystem directly at
/// `/nix/store`, as an earlier version of this did, shadows the shared
/// libraries `makeInitrdNG` placed there (`nix/guest-vm.nix`'s comment on
/// why `nix-daemon` and friends can dynamically link at all) — any
/// `nix-daemon` this process execs *after* that mount fails to load
/// outright, `Command::spawn` erroring with no more detail than "spawning
/// /bin/nix-daemon --stdio" (found by booting far enough to actually dial
/// the daemon port post-mount, which no earlier step did). The overlay keeps
/// both visible: the initrd's own content through the read-only lower layer,
/// and whatever the tenant's daemon writes through the upper one, persisted
/// on the encrypted disk exactly as a plain mount would have been.
async fn mount_store() -> Result<()> {
    // `lowerdir` has to name a path that stays valid *after* the overlay
    // mount below replaces what's visible at `/nix/store` itself, so the
    // current contents are bind-mounted elsewhere first -- a bind mount is
    // metadata-only (no data copy), and unlike a rename/move it doesn't risk
    // invalidating anything already holding `/nix/store` open.
    tokio::fs::create_dir_all(STORE_LOWER)
        .await
        .wrap_err_with(|| format!("creating {STORE_LOWER}"))?;
    run(MOUNT_BIN, &["--bind", STORE_MOUNT, STORE_LOWER])
        .await
        .wrap_err("bind-mounting /nix/store to the overlay's lower dir")?;

    tokio::fs::create_dir_all(STORE_RAW)
        .await
        .wrap_err_with(|| format!("creating {STORE_RAW}"))?;
    run(
        MOUNT_BIN,
        &["-t", "ext4", &format!("/dev/mapper/{DM_NAME}"), STORE_RAW],
    )
    .await
    .wrap_err("mounting the decrypted device")?;

    // Present already on `REUSE` (persisted in the ext4 filesystem from a
    // prior `FRESH`), created here on `FRESH` — `create_dir_all` is
    // idempotent either way.
    let upper = format!("{STORE_RAW}/upper");
    let work = format!("{STORE_RAW}/work");
    tokio::fs::create_dir_all(&upper)
        .await
        .wrap_err_with(|| format!("creating {upper}"))?;
    tokio::fs::create_dir_all(&work)
        .await
        .wrap_err_with(|| format!("creating {work}"))?;

    run(
        MOUNT_BIN,
        &[
            "-t",
            "overlay",
            "overlay",
            "-o",
            &format!("lowerdir={STORE_LOWER},upperdir={upper},workdir={work}"),
            STORE_MOUNT,
        ],
    )
    .await
    .wrap_err("mounting the overlay")
}

/// Static point-to-point bring-up of `NET_IFACE` against the `passt` link on
/// the other end -- see `GUEST_ADDR`/`GUEST_GATEWAY`'s doc comment for why
/// this is static configuration rather than a DHCP client. Three `ip`
/// invocations, same shape as every other guest-side setup step
/// (`unlock_and_mount` shells out to `cryptsetup`/`mkfs.ext4`/`mount` the
/// same way): bring the link up, assign the fixed address, then point the
/// default route at `passt` itself.
async fn configure_network() -> Result<()> {
    run(IP_BIN, &["link", "set", NET_IFACE, "up"])
        .await
        .wrap_err_with(|| format!("bringing up {NET_IFACE}"))?;
    run(IP_BIN, &["addr", "add", GUEST_ADDR, "dev", NET_IFACE])
        .await
        .wrap_err_with(|| format!("assigning {GUEST_ADDR} to {NET_IFACE}"))?;
    run(IP_BIN, &["route", "add", "default", "via", GUEST_GATEWAY])
        .await
        .wrap_err_with(|| format!("adding a default route via {GUEST_GATEWAY}"))?;
    Ok(())
}

pub(crate) async fn run(bin: &str, args: &[&str]) -> Result<()> {
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
async fn serve(
    mut stream: VsockStream,
    detection: Option<Arc<Mutex<DetectionState>>>,
) -> Result<()> {
    tracing::info!("spawning nix-daemon for a new connection");
    let mut child = spawn_nix_daemon()?;
    // PLAN.md Phase 18: scope this nix-daemon instance (and everything it
    // forks for the sandboxed build) into the memory-capped build cgroup --
    // best-effort, same as `cgroup::setup()` itself: a guest where this
    // fails still builds, just without OOM attribution for this connection.
    if detection.is_some()
        && let Some(pid) = child.id()
        && let Err(err) = cgroup::move_into_build_cgroup(pid).await
    {
        eprintln!("guest-agent: moving nix-daemon into the build cgroup failed: {err}");
    }
    let mut child_stdin = child.stdin.take().ok_or_else(|| eyre::eyre!("no stdin"))?;
    let mut child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| eyre::eyre!("no stdout"))?;

    let (mut stream_read, mut stream_write) = stream.split();

    // Two directions, driven concurrently: the vsock peer's writes feed
    // nix-daemon's stdin, and nix-daemon's stdout feeds back to the peer.
    // Neither `copy_and_log` call returns until its source hits EOF, which is
    // exactly "the peer closed" on one side and "nix-daemon exited" on the
    // other — either is a legitimate reason to tear the whole connection down.
    //
    // `copy_and_log`, not `tokio::io::copy`: a hang here previously looked
    // identical to "zero bytes ever moved" from the outside, because
    // `tokio::io::copy` produces no signal at all until it returns -- and if
    // the whole VM gets killed while it's still pending (a wedged relay,
    // exactly the failure being diagnosed), it never gets the chance to.
    // Logging every chunk as it's relayed means the log stream carries real
    // signal even from a run that never finishes.
    let relay_in = async {
        let result = copy_and_log("vsock->nix-daemon", &mut stream_read, &mut child_stdin).await;
        // nix-daemon reads EOF on its stdin as "no more requests"; without
        // explicitly dropping our end here it would just see the pipe stay
        // open and hang waiting for more.
        drop(child_stdin);
        result
    };
    let relay_out = copy_and_log("nix-daemon->vsock", &mut child_stdout, &mut stream_write);

    // Logging the byte count on whichever side finishes first (in addition
    // to `copy_and_log`'s own per-chunk logging) says definitively whether
    // *any* bytes ever crossed the relay in that direction before the
    // connection ended, which is exactly what "did the client's request ever
    // reach nix-daemon, and did nix-daemon ever answer" needs distinguishing.
    tokio::select! {
        result = relay_in => {
            match &result {
                Ok(n) => tracing::info!(bytes = n, "vsock -> nix-daemon relay ended"),
                Err(err) => tracing::warn!(%err, "vsock -> nix-daemon relay errored"),
            }
            result.wrap_err("relaying vsock -> nix-daemon")?;
        }
        result = relay_out => {
            match &result {
                Ok(n) => tracing::info!(bytes = n, "nix-daemon -> vsock relay ended"),
                Err(err) => tracing::warn!(%err, "nix-daemon -> vsock relay errored"),
            }
            result.wrap_err("relaying nix-daemon -> vsock")?;
        }
    }

    reap(&mut child).await;
    stream.shutdown(Shutdown::Both).ok();
    Ok(())
}

/// Like `tokio::io::copy`, but logs every chunk as it's relayed instead of
/// only the final total once the whole copy finishes — see `serve`'s comment
/// on why that distinction matters for diagnosing a relay that never
/// finishes at all.
async fn copy_and_log<R, W>(direction: &'static str, mut reader: R, mut writer: W) -> Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 8192];
    let mut total: u64 = 0;
    loop {
        let n = reader
            .read(&mut buf)
            .await
            .wrap_err_with(|| format!("reading ({direction})"))?;
        if n == 0 {
            tracing::info!(direction, total, "relay direction hit EOF");
            return Ok(total);
        }
        total += n as u64;
        // `debug`, not `info`: a real NAR transfer is many 8 KiB chunks, and
        // this default-off level is exactly what `RUST_LOG=debug` (passed to
        // `guest-agent` the same way as any `tracing`-based binary) is for --
        // the EOF summary above stays `info` for normal lifecycle visibility.
        tracing::debug!(direction, bytes = n, total, "relayed chunk");
        writer
            .write_all(&buf[..n])
            .await
            .wrap_err_with(|| format!("writing ({direction})"))?;
    }
}

fn spawn_nix_daemon() -> Result<Child> {
    Command::new(NIX_DAEMON_BIN)
        .arg("--stdio")
        // `build-dir`'s compiled-in default (`<nixStateDir>/b`) resolves
        // somewhere this guest never created and has no reason to trust is
        // on the `tmpfs` mounted at `/tmp` above — pinning it there
        // directly is what actually makes the sandbox's `pivot_root`
        // work, since that needs its chroot directory on a real mount,
        // not wherever the default happened to land.
        //
        // `pasta-path = ` (empty) turns off Lix's own per-build network
        // sandbox (`LinuxLocalDerivationGoal::wantNetNS` in
        // lix/libstore/platform/linux.cc, which ORs in `privateNetwork()`
        // with `settings.pastaPath != ""` -- a non-empty compiled-in default
        // makes it fire for every fixed-output derivation regardless).
        // `pasta` needs `CAP_NET_ADMIN` for `TUNSETIFF`, which it only gets
        // via `LocalDerivationGoal::sandboxUid()` returning 0 -- true only
        // when the build has more than one allocated UID
        // (`local-derivation-goal.cc:293`,
        // `parsedDrv->useUidRange() ? 65536 : 1`), which in turn is gated
        // on the *derivation itself* declaring
        // `requiredSystemFeatures = [ "uid-range" ]` -- an immutable,
        // client-eval-time property nothing server-side can force, and
        // which essentially nothing in nixpkgs (`hex0-seed` included)
        // declares. So `pasta` is fundamentally unusable here for ordinary
        // builds regardless of `auto-allocate-uids`
        // (confirmed live: still "TUNSETIFF ... Operation not permitted"
        // with it enabled) short of patching Lix itself. This guest's own
        // `passt` link (`worker/src/vm.rs`) is already the real network
        // isolation boundary (one dedicated VM per build) that Lix's inner
        // sandbox would otherwise redundantly, and here non-functionally,
        // duplicate.
        .env("NIX_CONFIG", "build-dir = /tmp\npasta-path =")
        // `nix/guest-vm.nix` bakes a CA bundle in at this exact path --
        // without pointing `SSL_CERT_FILE` at it, every HTTPS fetch inside
        // the sandbox fails "unable to get local issuer certificate" (no
        // `/etc/ssl/certs` at all otherwise exists in this guest for
        // OpenSSL's own default search paths to find anything at).
        .env("SSL_CERT_FILE", "/etc/ssl/certs/ca-bundle.crt")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_nested_virt_flags_str_no_match() {
        let cpuinfo = "processor\t: 0\nvendor_id\t: GenuineIntel\nflags\t\t: fpu vme de pse\n";
        assert_eq!(count_nested_virt_flags_str(cpuinfo), 0);
    }

    #[test]
    fn count_nested_virt_flags_str_multi_core_intel() {
        let cpuinfo = "\
processor\t: 0\nflags\t\t: fpu vme de pse tsc vmx\n\n\
processor\t: 1\nflags\t\t: fpu vme de pse tsc vmx\n";
        assert_eq!(count_nested_virt_flags_str(cpuinfo), 2);
    }

    #[test]
    fn count_nested_virt_flags_str_amd() {
        let cpuinfo = "processor\t: 0\nflags\t\t: fpu vme de pse tsc svm\n";
        assert_eq!(count_nested_virt_flags_str(cpuinfo), 1);
    }

    #[tokio::test]
    async fn dispatch_control_caps_returns_data() {
        // Real /proc/cpuinfo on the machine running the test -- whatever it
        // reports, dispatch should surface it as OkWithData, not Ok/Err.
        match dispatch_control("CAPS?", None).await {
            Ok(ControlReply::OkWithData(_)) => {}
            other => panic!("expected OkWithData, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dispatch_control_unrecognised_verb_errors() {
        let err = dispatch_control("WAT", None).await.unwrap_err();
        assert!(err.to_string().contains("unrecognised control command"));
    }

    #[tokio::test]
    async fn dispatch_control_empty_line_errors() {
        assert!(dispatch_control("", None).await.is_err());
    }

    // PLAN.md Phase 18: STATUS?/RESET without a real eBPF-backed
    // `DetectionState` (unit tests never boot a real kernel) still exercise
    // the dispatch's own plumbing -- both verbs should fail cleanly (not
    // panic) rather than pretend to answer when detection isn't available,
    // the same shape `dispatch_control_unrecognised_verb_errors` checks for
    // an unknown verb.
    #[tokio::test]
    async fn dispatch_control_status_without_detection_errors() {
        let err = dispatch_control("STATUS?", None).await.unwrap_err();
        assert!(err.to_string().contains("eBPF detection not available"));
    }

    #[tokio::test]
    async fn dispatch_control_reset_without_detection_errors() {
        let err = dispatch_control("RESET", None).await.unwrap_err();
        assert!(err.to_string().contains("eBPF detection not available"));
    }

    #[test]
    fn format_status_matches_wire_convention() {
        assert_eq!(format_status(FailureStatus::None), "NONE");
        assert_eq!(
            format_status(FailureStatus::OutOfMemory {
                builder_victim: true
            }),
            "OOM BUILDER"
        );
        assert_eq!(
            format_status(FailureStatus::OutOfMemory {
                builder_victim: false
            }),
            "OOM OTHER"
        );
        assert_eq!(format_status(FailureStatus::DiskFull), "ENOSPC");
    }
}
