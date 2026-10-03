//! `guest-agent` — PID 1 inside the Phase 15 guest VM's initrd.
//!
//! Listens on two fixed `AF_VSOCK` ports:
//!
//! - `NIX_DAEMON_PORT`: on each accepted connection, spawns `nix-daemon
//!   --stdio` and splices the connection's bytes straight onto the child's
//!   stdin/stdout, in both directions, until either side closes.
//! - `CONTROL_PORT`: a binary `postcard-rpc` control channel, persistent per
//!   connection. `guest/key` unlocks and mounts the tenant's `store.img`
//!   before any `nix-daemon` connection is worth accepting; `guest/caps`
//!   (Phase 17) answers a boot-time nested-virt self-test; the guest also
//!   pushes a `guest/heartbeat` pulse on this connection so the worker can
//!   detect a hung guest without polling. See [`control::run_control_connection`].
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
mod control;
mod control_transport;
mod diag;
mod ebpf;

use std::net::Shutdown;
use std::process::Stdio;
use std::sync::Arc;

use eyre::{Context, Result, eyre};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, broadcast};
use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener, VsockStream};

use ebpf::DetectionState;

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
    // `/tmp` holds substituter cache metadata (see `spawn_nix_daemon`'s
    // `HOME` doc comment), and `/nix/var` is Nix's state directory (its
    // path/GC-roots database, temp roots, ...) -- `nix-daemon` `mkdir`s
    // directly inside both itself, which the read-only EROFS root
    // (`nix/guest-vm.nix`'s `rootImg`) can never allow no matter how the
    // directory got there. Everything else in this list only needs an empty
    // directory to mount *onto*, which `rootImg` ships pre-made for exactly
    // that reason; these two need to be writable themselves. `mount_store()`
    // later bind-mounts disk-backed directories onto `/nix/var/nix/b` (Nix's
    // own default `build-dir`) and `/nix/var/nix/db` (the path-validity
    // SQLite database) once the tmpfs here has given them somewhere to
    // attach to -- without the latter, a path registered before a reboot
    // would come back "not valid" after one even though its content is
    // still sitting in the store overlay, since this tmpfs is wiped on every
    // boot. GC roots and temp roots deliberately stay tmpfs-only, unlike
    // those two: nothing in this guest's production path creates or depends
    // on a permanent GC root, and a temp root surviving a reboot would
    // reference a process that no longer exists -- there should be no roots
    // in this guest's Nix store at all.
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

    let substituters: Substituters = Arc::new(Mutex::new(Vec::new()));
    let extra_ca: ExtraCaCert = Arc::new(Mutex::new(Vec::new()));

    let control_detection = detection.clone();
    let control_substituters = substituters.clone();
    let control_extra_ca = extra_ca.clone();
    tokio::spawn(async move {
        control_accept_loop(
            control_listener,
            control_detection,
            control_substituters,
            control_extra_ca,
        )
        .await;
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
        let substituters = substituters.clone();
        let extra_ca = extra_ca.clone();
        tokio::spawn(async move {
            if let Err(err) = serve(stream, detection, substituters, extra_ca).await {
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
    substituters: Substituters,
    extra_ca: ExtraCaCert,
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
        let substituters = substituters.clone();
        let extra_ca = extra_ca.clone();
        tokio::spawn(async move {
            control::run_control_connection(
                stream,
                control::Context {
                    detection,
                    substituters,
                    extra_ca,
                },
            )
            .await;
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

async fn unlock_and_mount(key: &[u8], fresh: bool) -> Result<()> {
    // `BLK_DEV_DM`/`DM_CRYPT` are kernel modules, not builtins (see
    // `nix/guest-vm.nix`'s comment on why), so `/dev/mapper/control` doesn't
    // exist until `dm-mod`/`dm-crypt` are loaded. `modprobe`'s `modules.dep`
    // resolves `dm-crypt`'s dependency on `dm-mod` in one call; the crypto
    // ciphers themselves (`CRYPTO_AES`/`CRYPTO_XTS`, also modules) are loaded
    // on demand by the kernel's own crypto subsystem the first time
    // `cryptsetup` requests the `xts(aes)` transform, via the same
    // `/sbin/modprobe` this depends on being present.
    modprobe("dm-crypt").await?;

    cryptsetup_open(key).await?;
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
    .wrap_err("mounting the overlay")?;

    // Nix's own `build-dir` default (`<nixStateDir>/b`, i.e.
    // `/nix/var/nix/b`) is where every derivation's actual build/compile
    // scratch directory lives -- left on the `tmpfs` mounted at `/nix/var`
    // in `main()`, that scratch space is bounded by the guest's RAM
    // (`worker.vm.memoryMb`), not by `store.img`'s much larger size, so a
    // build with a large scratch footprint could hit `tmpfs` `ENOSPC` well
    // before the disk-backed store fills up. Bind-mounting a directory on
    // the same decrypted ext4 device onto that exact path moves build
    // scratch space onto disk instead, with no `NIX_CONFIG` override
    // needed (see `spawn_nix_daemon`).
    let build = format!("{STORE_RAW}/b");
    tokio::fs::create_dir_all(&build)
        .await
        .wrap_err_with(|| format!("creating {build}"))?;
    tokio::fs::create_dir_all("/nix/var/nix/b")
        .await
        .wrap_err("creating /nix/var/nix/b")?;
    run(MOUNT_BIN, &["--bind", &build, "/nix/var/nix/b"])
        .await
        .wrap_err("bind-mounting the disk-backed build-dir onto /nix/var/nix/b")?;

    // Nix's path-validity SQLite database (`<nixStateDir>/db`, i.e.
    // `/nix/var/nix/db`) would otherwise live only on the `tmpfs` mounted at
    // `/nix/var` in `main()` -- wiped on every boot, which silently empties
    // the validity DB even though `store.img`'s upper overlay dir (above)
    // and `b` (just above) both persist real content across a reboot. A VM
    // evicted and rebooted for a tenant (`VmPool::ensure_vm_for`) then
    // reports every already-present path as invalid, forcing `fetch_inputs`
    // to redundantly re-download and re-register bytes already sitting in
    // the overlay. Bind-mounting this onto the same disk-backed device,
    // same pattern as `build` above, fixes that.
    let db = format!("{STORE_RAW}/db");
    tokio::fs::create_dir_all(&db)
        .await
        .wrap_err_with(|| format!("creating {db}"))?;
    tokio::fs::create_dir_all("/nix/var/nix/db")
        .await
        .wrap_err("creating /nix/var/nix/db")?;
    run(MOUNT_BIN, &["--bind", &db, "/nix/var/nix/db"])
        .await
        .wrap_err("bind-mounting the disk-backed validity DB onto /nix/var/nix/db")
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
    substituters: Substituters,
    extra_ca: ExtraCaCert,
) -> Result<()> {
    tracing::info!("spawning nix-daemon for a new connection");
    let current_substituters = substituters.lock().await.clone();
    let current_extra_ca = extra_ca.lock().await.clone();
    let mut child = spawn_nix_daemon(&current_substituters, &current_extra_ca)?;
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

/// This tenant's currently configured trusted substituters — nothing at
/// boot, then kept current by the `SUBST` control verb
/// (`worker::vm::push_substituters`, sent on every job, not just a
/// fresh/reused boot). Read by [`spawn_nix_daemon`] on each new
/// `NIX_DAEMON_PORT` connection, so a `nix-daemon` spawned for a later job
/// always sees whatever was pushed most recently, even on a VM whose
/// process has stayed warm across several jobs.
type Substituters = Arc<Mutex<Vec<(String, String)>>>;

/// This deployment's extra trusted CA cert(s), PEM bytes as received from
/// the most recent `CACERT` control verb — empty when the worker has none
/// configured (`tls.extraCaVolumeMounts` unset) or hasn't pushed one yet.
/// Read by [`spawn_nix_daemon`] on each new `NIX_DAEMON_PORT` connection,
/// same lifecycle as [`Substituters`].
type ExtraCaCert = Arc<Mutex<Vec<u8>>>;

/// The guest's own baked-in CA bundle (`nix/guest-vm.nix`) — the sole
/// `SSL_CERT_FILE` target before any extra CA is ever pushed, and the base
/// this merges with once one is.
const BAKED_CA_BUNDLE: &str = "/etc/ssl/certs/ca-bundle.crt";

/// Where the merged bundle (baked-in + pushed extra CA) is written when an
/// extra CA is present — `/tmp` is the guest's one writable location (a real
/// `tmpfs`, same one `HOME`/`build-dir` already point at below), since the
/// rest of this root filesystem is the read-only EROFS image.
const MERGED_CA_BUNDLE: &str = "/tmp/kubernix-extra-ca-bundle.crt";

/// The `SSL_CERT_FILE` path `spawn_nix_daemon` should use: the baked-in
/// bundle unchanged when no extra CA has been pushed (byte-for-byte today's
/// behaviour), or a freshly (re)written merge of that bundle plus `extra_ca`
/// otherwise. Rewritten on every call rather than cached — `extra_ca` is
/// tiny and `/tmp` is a `tmpfs`, so the cost is negligible next to always
/// being correct after a `CACERT` update lands mid-lifetime of a warm guest.
fn merged_ca_bundle_path(extra_ca: &[u8]) -> Result<&'static str> {
    if extra_ca.is_empty() {
        return Ok(BAKED_CA_BUNDLE);
    }
    let mut merged = std::fs::read(BAKED_CA_BUNDLE)
        .wrap_err_with(|| format!("reading the baked-in CA bundle at {BAKED_CA_BUNDLE}"))?;
    merged.push(b'\n');
    merged.extend_from_slice(extra_ca);
    std::fs::write(MERGED_CA_BUNDLE, &merged)
        .wrap_err_with(|| format!("writing the merged CA bundle to {MERGED_CA_BUNDLE}"))?;
    Ok(MERGED_CA_BUNDLE)
}

fn spawn_nix_daemon(substituters: &[(String, String)], extra_ca: &[u8]) -> Result<Child> {
    let mut nix_config = "pasta-path =\n\
             experimental-features = auto-allocate-uids cgroups\n\
             auto-allocate-uids = true\n\
             use-cgroups = true"
        .to_string();
    // Deliberately the *only* substituters this guest ever has: it never
    // reaches an external URL directly (`crate::substitute` doesn't exist
    // here -- that's the frontend's own pull-through cache), so every
    // substitution goes through kubernix, uniformly, and therefore always
    // ends up correctly tiered (Built vs Substituted) on the frontend side.
    if !substituters.is_empty() {
        let urls: Vec<&str> = substituters.iter().map(|(url, _)| url.as_str()).collect();
        let keys: Vec<&str> = substituters.iter().map(|(_, key)| key.as_str()).collect();
        nix_config.push_str(&format!(
            "\nsubstituters = {}\ntrusted-public-keys = {}",
            urls.join(" "),
            keys.join(" ")
        ));
    }

    Command::new(NIX_DAEMON_BIN)
        .arg("--stdio")
        // No `build-dir` override needed: Lix's compiled-in default
        // (`<nixStateDir>/b`, i.e. `/nix/var/nix/b`) is exactly the path
        // `mount_store()` bind-mounts onto the decrypted ext4 device before
        // this ever runs, so it's already a real, disk-backed mount by the
        // time the sandbox's `pivot_root` needs its chroot directory there
        // — no reason left to distrust wherever the default lands.
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
        //
        // `auto-allocate-uids`/`use-cgroups`: genuine, useful Lix features
        // (per-build UID isolation and cgroup-scoped resource accounting)
        // this guest can actually support -- `cgroup::setup()` already
        // prepares and delegates the cgroup v2 hierarchy they need. Kept on
        // even though disabling `pasta` (above) means they're no longer
        // load-bearing for networking specifically: builds still benefit
        // from real per-build UID separation instead of every build sharing
        // the single static `nixbld1` (`nix/guest-vm.nix`'s `passwd`).
        .env("NIX_CONFIG", &nix_config)
        // A substituter (any of them, including the tenant's own namespace
        // -- not just the new `/upstream/…` mirrors) needs somewhere
        // writable for its local metadata cache
        // (`~/.cache/nix/binary-cache-v6.sqlite`) before it can be used at
        // all. `$HOME` otherwise defaults to `/root`, which -- like the
        // rest of this guest's root filesystem -- is the read-only EROFS
        // image (`nix/guest-vm.nix`), so every substituter's setup failed
        // outright with "creating directory '/root/.cache': Read-only file
        // system" before this. `/tmp` is already a real, writable `tmpfs`
        // (mounted in `main()`) -- reusing it here needs no new mount, and
        // unlike `build-dir` above this is just cache metadata, not
        // something worth spending disk space (or persisting across
        // reboots) on.
        .env("HOME", "/tmp")
        // `nix/guest-vm.nix` bakes a CA bundle in at `BAKED_CA_BUNDLE` --
        // without pointing `SSL_CERT_FILE` at it, every HTTPS fetch inside
        // the sandbox fails "unable to get local issuer certificate" (no
        // `/etc/ssl/certs` at all otherwise exists in this guest for
        // OpenSSL's own default search paths to find anything at). Lix's
        // own CA handling only ever trusts a single `SSL_CERT_FILE`,
        // completely replacing the default rather than merging in a
        // directory the way `rustls-native-certs` does for this worker's
        // own `reqwest`/`aws-sdk-s3` clients -- so when an extra CA has
        // been pushed (`CACERT`, dispatch_control), it has to be merged
        // with the baked-in bundle into one file rather than substituted
        // for it outright, or every fetch against a public substituter
        // (cache.nixos.org included) would stop being trusted.
        .env("SSL_CERT_FILE", merged_ca_bundle_path(extra_ca)?)
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

    // The old `dispatch_control_*`/`format_status_*` tests against the
    // line-based protocol moved to `control.rs`'s own test module, now
    // exercising the postcard-rpc handler functions directly instead of a
    // parsed text line -- same intent (SUBST/CACERT update/clear shared
    // state, STATUS?/RESET fail cleanly without a real eBPF backend, CAPS?
    // returns real data), different call surface.
}
