//! Phase 15 Steps 2 and 4: per-tenant `cloud-hypervisor` VM lifecycle, and
//! at-rest encryption of each tenant's `store.img`.
//!
//! Owns exactly one warm VM per worker process (matching today's
//! one-job-at-a-time job loop in `main.rs`), keyed by [`TenantId`]. A job for
//! the same tenant as the currently warm VM reuses it; a job for a different
//! tenant evicts the old VM and boots a fresh one, attaching that tenant's
//! `store.img` — created empty on first use, otherwise reused untouched, so a
//! tenant's Nix store survives across warm-VM cycles as long as the image
//! stays on this worker's local disk.
//!
//! `store.img` is plain-`dm-crypt` ciphertext, not a plaintext filesystem.
//! [`VmPool`] generates a random 256-bit key the first time it creates a
//! tenant's image, keeps it only in this process's memory (never on disk,
//! never logged), and pushes it to `guest-agent`'s control channel
//! (`CONTROL_PORT`) right after every boot for that tenant — the guest opens
//! the encrypted device and mounts it at `/nix/store` before `nix-daemon`
//! ever starts. A worker restart loses every key it held, permanently
//! orphaning the `store.img` files that process created; see
//! [`wipe_orphaned_store_images`], which a fresh process runs before serving
//! any job so those images don't linger as unrecoverable dead weight.
//!
//! This module does not itself speak the Nix daemon protocol over the
//! resulting connection, or make any build actually use it — that is Step
//! 3's `kubernix_daemon_protocol`/`vm_ops.rs`, layered on top of the
//! [`VmHandle`] this module hands out.
//!
//! Process spawning (and, since Step 4, key pushing) is behind the
//! [`VmLauncher`] trait so the reuse/evict decision in
//! [`VmPool::ensure_vm_for`] — the actual thing these steps need to prove —
//! is unit-testable without `/dev/kvm`. [`CloudHypervisorLauncher`] is the
//! real implementation; tests supply a fake.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use eyre::{Context as _, eyre};
use kubernix_types::TenantId;
use rand::Rng as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};

/// `guest-agent`'s fixed vsock port (`guest-agent/src/main.rs::NIX_DAEMON_PORT`).
/// Duplicated here rather than shared through a common crate: the guest and
/// the worker never build as one binary, and a port both sides agree on by
/// convention is exactly the kind of constant a comment (and, eventually,
/// Step 3's connection test) should pin down rather than paper over with an
/// artificial shared dependency.
const NIX_DAEMON_PORT: u32 = 620;

/// `guest-agent`'s fixed control-channel vsock port
/// (`guest-agent/src/main.rs::CONTROL_PORT`), duplicated here for the same
/// reason as `NIX_DAEMON_PORT` above. Carries the Step 4 `KEY ... FRESH|REUSE`
/// handshake that unlocks and mounts the tenant's `store.img` before any
/// daemon-protocol traffic is sent to `NIX_DAEMON_PORT`.
const CONTROL_PORT: u32 = 621;

/// Phase 15 Step 5's fixed point-to-point address plan for the `passt` link,
/// shared by convention with `guest-agent/src/main.rs`'s `configure_network`
/// (`GUEST_ADDR`/`GUEST_GATEWAY` there) — duplicated for the same reason
/// `NIX_DAEMON_PORT`/`CONTROL_PORT` are: the guest and the worker never build
/// as one binary. There is exactly one guest and one `passt` process per VM,
/// so a fixed address needs no allocation scheme.
const NET_GUEST_ADDR: &str = "10.42.100.2";
const NET_PREFIX: &str = "24";
/// `passt` itself answers as this address — it's the `-g` gateway `passt`
/// hands the guest, the address `passt` occupies on the link, *and* (`-D` in
/// `passt_args`) where `passt` answers DNS queries the guest sends, since a
/// statically-configured guest has no other way to learn a DNS address.
const NET_GATEWAY: &str = "10.42.100.1";

/// A tenant's plain-`dm-crypt` key: 256-bit, CSPRNG-generated, held only in
/// this process's memory (see `VmPool::keys`). Never `Debug`/`Display` —
/// accidentally logging one would defeat the entire point.
type StoreKey = [u8; 32];

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Worker-side VM lifecycle configuration, read once at startup.
#[derive(Clone, Debug)]
pub struct VmConfig {
    /// Parent of `tenants/<tenant>/store.img`. Matches the systemd unit's
    /// `StateDirectory` (`nix/module.nix`) so images persist across worker
    /// restarts even though the VMs holding their keys (Step 4) do not.
    pub state_dir: PathBuf,
    pub kernel: PathBuf,
    pub initrd: PathBuf,
    /// Resolved via `$PATH`, same convention as `KUBERNIX_NIX_BUILDER`.
    pub cloud_hypervisor: PathBuf,
    /// Phase 15 Step 5: the userspace-NAT sibling process `CloudHypervisorLauncher::boot`
    /// spawns before `cloud_hypervisor`, so its vhost-user socket exists by
    /// the time `cloud-hypervisor` tries to dial it. Resolved via `$PATH`,
    /// same convention as `cloud_hypervisor` above.
    pub passt: PathBuf,
    pub vcpus: u32,
    pub memory_mb: u32,
    /// Logical size of a freshly created `store.img`. The file is sparse
    /// (`File::set_len`), so this costs no real disk until the guest writes
    /// to it.
    pub store_img_size_mb: u64,
    /// Deadline for the vsock ready-handshake after spawning
    /// `cloud-hypervisor`. Bounds both "the guest kernel never comes up" and
    /// "guest-agent never binds its listener".
    pub boot_timeout: Duration,
    /// Guest CID passed to `--vsock`. Fixed rather than allocated: only one
    /// VM is ever live per worker in this design (see module doc).
    pub cid: u32,
}

impl VmConfig {
    /// Read from `KUBERNIX_VM_*` env vars. `Ok(None)` means VM lifecycle is
    /// simply not configured on this worker — nothing downstream of Step 2
    /// consumes a `VmHandle` yet, so requiring every deployment to boot a VM
    /// per job before Step 3 exists would be a new hard requirement for no
    /// benefit. Setting `KUBERNIX_VM_KERNEL`/`KUBERNIX_VM_INITRD` opts in.
    pub fn from_env() -> eyre::Result<Option<Self>> {
        let kernel = std::env::var("KUBERNIX_VM_KERNEL").ok();
        let initrd = std::env::var("KUBERNIX_VM_INITRD").ok();
        let (kernel, initrd) = match (kernel, initrd) {
            (Some(k), Some(i)) => (k, i),
            (None, None) => return Ok(None),
            _ => {
                return Err(eyre!(
                    "KUBERNIX_VM_KERNEL and KUBERNIX_VM_INITRD must both be set, or neither"
                ));
            }
        };

        let state_dir = std::env::var("KUBERNIX_VM_STATE_DIR")
            .unwrap_or_else(|_| "/var/lib/kubernix-worker".to_string());
        let cloud_hypervisor =
            std::env::var("KUBERNIX_VM_CH_BIN").unwrap_or_else(|_| "cloud-hypervisor".to_string());
        let passt = std::env::var("KUBERNIX_VM_PASST_BIN").unwrap_or_else(|_| "passt".to_string());

        Ok(Some(VmConfig {
            state_dir: PathBuf::from(state_dir),
            kernel: PathBuf::from(kernel),
            initrd: PathBuf::from(initrd),
            cloud_hypervisor: PathBuf::from(cloud_hypervisor),
            passt: PathBuf::from(passt),
            vcpus: parse_env_or("KUBERNIX_VM_VCPUS", 1)?,
            memory_mb: parse_env_or("KUBERNIX_VM_MEMORY_MB", 768)?,
            store_img_size_mb: parse_env_or("KUBERNIX_VM_STORE_IMG_MB", 8192)?,
            boot_timeout: Duration::from_secs(parse_env_or("KUBERNIX_VM_BOOT_TIMEOUT_SECS", 30)?),
            cid: parse_env_or("KUBERNIX_VM_CID", 3)?,
        }))
    }
}

fn parse_env_or<T>(key: &str, default: T) -> eyre::Result<T>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match std::env::var(key) {
        Ok(v) => v.parse().map_err(|e| eyre!("invalid {key} ({v:?}): {e}")),
        Err(_) => Ok(default),
    }
}

/// What a build (Step 3) would need to dial the tenant's `nix-daemon`.
/// Constructed and logged already (`main.rs`); every field here is Step 3's
/// eventual read, not Step 2's — hence `allow(dead_code)` rather than trimming
/// fields a daemon-protocol client will need on day one.
pub struct VmHandle {
    /// Kept for callers that want to attribute a handle to its tenant
    /// (logging, error messages) without threading a second parameter
    /// alongside it — not read by `connect` itself, which only needs
    /// `vsock_socket`/`guest_port`.
    #[allow(dead_code)]
    pub tenant: TenantId,
    /// Host-side UNIX socket `cloud-hypervisor`'s `--vsock ...,socket=`
    /// exposes. Dialing it and sending `CONNECT <port>\n` reaches
    /// `guest_port` inside the guest — see `wait_for_vsock_ready`, and
    /// [`Self::connect`] for the same handshake kept open for real use.
    pub vsock_socket: PathBuf,
    pub guest_port: u32,
    #[allow(dead_code)]
    pub store_img: PathBuf,
}

impl VmHandle {
    /// Dial `vsock_socket` and reach `guest_port` inside the guest — the
    /// same `CONNECT <port>\n` / `OK` inetd-style handshake
    /// `wait_for_vsock_ready` polls with during boot (`handshake_once`), but
    /// keeping the resulting stream open afterwards instead of dropping it.
    /// The returned `UnixStream` is a raw byte pipe straight through to
    /// `guest-agent`'s spawned `nix-daemon --stdio` — hand it to
    /// `kubernix_daemon_protocol::DaemonConnection::open` for a real session.
    pub async fn connect(&self) -> eyre::Result<tokio::net::UnixStream> {
        let mut stream = tokio::net::UnixStream::connect(&self.vsock_socket)
            .await
            .wrap_err_with(|| format!("dialing {}", self.vsock_socket.display()))?;
        stream
            .write_all(format!("CONNECT {}\n", self.guest_port).as_bytes())
            .await
            .wrap_err("sending the vsock CONNECT handshake")?;
        let mut buf = [0u8; 32];
        let n = stream
            .read(&mut buf)
            .await
            .wrap_err("reading the vsock CONNECT reply")?;
        if !buf[..n].starts_with(b"OK") {
            return Err(eyre!(
                "vsock CONNECT to guest port {} refused: {:?}",
                self.guest_port,
                String::from_utf8_lossy(&buf[..n])
            ));
        }
        Ok(stream)
    }
}

/// A booted VM, as far as this module cares: a child process and the paths
/// used to reach and debug it. Ownership passes to [`VmLauncher::stop`] on
/// eviction. `console_log` is read only on a boot failure today
/// (`console_log_tail`); kept on a live `LaunchedVm` too since Step 3/4's
/// error paths will want it just as much.
#[allow(dead_code)]
pub struct LaunchedVm {
    child: Child,
    /// Phase 15 Step 5's `passt` sibling process, if this VM was booted with
    /// networking wired up (`CloudHypervisorLauncher` always sets this;
    /// `FakeLauncher` in tests does not, since none of the reuse/evict
    /// assertions those tests make care about it). Torn down alongside
    /// `child` in `stop()` — there is no independent lifecycle for it.
    passt_child: Option<Child>,
    vsock_socket: PathBuf,
    console_log: PathBuf,
}

/// Spawns and tears down the actual VM process. A trait so
/// [`VmPool::ensure_vm_for`]'s reuse/evict decision — the thing Step 2 is
/// actually about — is testable against a fake, without `/dev/kvm`.
#[async_trait::async_trait]
pub trait VmLauncher: Send + Sync {
    async fn boot(
        &self,
        tenant: &TenantId,
        store_img: &Path,
        vsock_socket: &Path,
        console_log: &Path,
    ) -> eyre::Result<LaunchedVm>;

    /// Takes ownership: the caller has already decided this VM is going
    /// away, so there is no "still holds it" state to return to.
    async fn stop(&self, vm: LaunchedVm);

    /// Push a tenant's plain-`dm-crypt` key to `guest-agent`'s control
    /// channel over `vsock_socket`, right after `boot` has returned — the
    /// guest opens `/dev/vda` with it and mounts the result at `/nix/store`
    /// before `nix-daemon` is exec'd on the `NIX_DAEMON_PORT` connection that
    /// follows. `fresh` selects `FRESH` (mkfs a newly-decrypted device) vs
    /// `REUSE` (mount an existing one) — see [`VmPool::ensure_vm_for`].
    async fn push_key(&self, vsock_socket: &Path, key: &StoreKey, fresh: bool) -> eyre::Result<()>;
}

/// The `passt` command line for the vhost-user backend at `net_socket` —
/// pulled out as a pure function so the exact CLI syntax (flagged as
/// unverified in PLAN.md's Phase 15 Step 5 until checked against this
/// repo's pinned `passt`/`cloud-hypervisor` versions) is covered by a plain
/// unit test rather than only ever exercised inside a real `/dev/kvm` boot.
///
/// `--dns` pins the address `passt` answers DNS queries on to the same fixed
/// `NET_GATEWAY` the guest already routes through, rather than `passt`'s own
/// default of "whatever the *host's* `/etc/resolv.conf` currently says" —
/// that default varies per host/node and a statically-configured guest (see
/// `guest-agent`'s `configure_network`/`resolv.conf`) has no way to learn it
/// at boot. `passt` still forwards the actual query to the real resolver
/// itself; only the address the guest sends queries *to* is fixed.
fn passt_args(net_socket: &Path) -> Vec<String> {
    vec![
        "--foreground".to_string(),
        "--vhost-user".to_string(),
        "--socket".to_string(),
        net_socket.display().to_string(),
        "--address".to_string(),
        NET_GUEST_ADDR.to_string(),
        "--netmask".to_string(),
        NET_PREFIX.to_string(),
        "--gateway".to_string(),
        NET_GATEWAY.to_string(),
        "--dns".to_string(),
        NET_GATEWAY.to_string(),
    ]
}

/// The `cloud-hypervisor --net` value for connecting to `passt`'s
/// vhost-user socket at `net_socket` as a client — `passt` is the listener
/// (see `passt_args` above), so `vhost_mode=client` here, not `server`.
/// `num_queues=2`, not `1`: cloud-hypervisor counts rx and tx as separate
/// queues and rejects anything lower with `VnetQueueLowerThan2` — found by
/// actually booting this against real `/dev/kvm`, not by reading the
/// `--net` help text, which just calls it "`num_queues=<number_of_queues>`"
/// with no hint that 1 is invalid.
fn net_arg(net_socket: &Path) -> String {
    format!(
        "vhost_user=true,socket={},num_queues=2,vhost_mode=client",
        net_socket.display()
    )
}

/// The real launcher: spawns `cloud-hypervisor` as a subprocess, replicating
/// `nix/guest-vm-test.nix`'s invocation plus a `--disk` for the tenant's
/// store image.
pub struct CloudHypervisorLauncher {
    config: VmConfig,
}

#[async_trait::async_trait]
impl VmLauncher for CloudHypervisorLauncher {
    async fn boot(
        &self,
        tenant: &TenantId,
        store_img: &Path,
        vsock_socket: &Path,
        console_log: &Path,
    ) -> eyre::Result<LaunchedVm> {
        // Phase 15 Step 5: `passt` first, so its vhost-user socket exists by
        // the time cloud-hypervisor tries to dial it as a client
        // (`vhost_mode=client` below) — the reverse order would race.
        // `net.sock` lives next to `store.img` (same tenant directory,
        // derived from it) rather than getting its own config knob: it's
        // process-local scratch state, not anything that needs to survive
        // past this VM's lifetime the way `store.img` does.
        let net_socket = store_img
            .parent()
            .expect("store_img always has a tenants/<tenant>/ parent")
            .join("net.sock");
        let _ = tokio::fs::remove_file(&net_socket).await;
        let passt_child = Command::new(&self.config.passt)
            .args(passt_args(&net_socket))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .wrap_err_with(|| {
                format!(
                    "spawning {} for tenant {tenant}",
                    self.config.passt.display()
                )
            })?;
        if !wait_for_socket(&net_socket, self.config.boot_timeout).await {
            return Err(eyre!(
                "timed out after {:?} waiting for passt's vhost-user socket at {} (tenant {tenant})",
                self.config.boot_timeout,
                net_socket.display(),
            ));
        }

        let mut child = match Command::new(&self.config.cloud_hypervisor)
            .arg("--kernel")
            .arg(&self.config.kernel)
            .arg("--initramfs")
            .arg(&self.config.initrd)
            .arg("--cmdline")
            .arg("console=ttyS0 reboot=t panic=1")
            .arg("--cpus")
            .arg(format!("boot={}", self.config.vcpus))
            .arg("--memory")
            // `shared=on` is required for vhost-user net: the backend
            // (`passt`) maps the guest's memory directly, which needs a
            // shared memory mapping cloud-hypervisor's default (anonymous,
            // process-private) memory doesn't provide.
            .arg(format!("size={}M,shared=on", self.config.memory_mb))
            .arg("--vsock")
            .arg(format!(
                "cid={},socket={}",
                self.config.cid,
                vsock_socket.display()
            ))
            .arg("--net")
            .arg(net_arg(&net_socket))
            .arg("--disk")
            // `image_type=raw` is not a formality — leaving it unspecified
            // lets cloud-hypervisor's own format sniffing decide, and on a
            // freshly `truncate`d sparse file that guessed wrong: `mkfs.ext4`
            // reliably failed with a bare `Input/output error while writing
            // out and closing file system`, on real cluster hardware, with
            // no other symptom pointing at the cause. Every Nix-driven guest
            // test (`nix/guest-vm-test.nix`, `nix/vm-encryption-test.nix`)
            // already passed this explicitly, which is why they never caught
            // it — only running against a real backing file, outside the
            // Nix build sandbox, surfaced the gap. Isolated by bisecting a
            // container-runtime probe against the exact production
            // invocation, one flag at a time.
            .arg(format!("path={},image_type=raw", store_img.display()))
            .arg("--console")
            .arg("off")
            .arg("--serial")
            .arg(format!("file={}", console_log.display()))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            // Belt-and-braces: the real teardown path is `stop()` below, but
            // this keeps a worker crash from orphaning a VM process too.
            .kill_on_drop(true)
            .spawn()
        {
            Ok(child) => child,
            Err(e) => {
                let mut passt_child = passt_child;
                let _ = passt_child.kill().await;
                return Err(e).wrap_err_with(|| {
                    format!(
                        "spawning {} for tenant {tenant}",
                        self.config.cloud_hypervisor.display()
                    )
                });
            }
        };

        match tokio::time::timeout(
            self.config.boot_timeout,
            wait_for_vsock_ready(vsock_socket, NIX_DAEMON_PORT),
        )
        .await
        {
            Ok(()) => Ok(LaunchedVm {
                child,
                passt_child: Some(passt_child),
                vsock_socket: vsock_socket.to_path_buf(),
                console_log: console_log.to_path_buf(),
            }),
            Err(_elapsed) => {
                let _ = child.kill().await;
                let mut passt_child = passt_child;
                let _ = passt_child.kill().await;
                let tail = console_log_tail(console_log).await;
                Err(eyre!(
                    "timed out after {:?} waiting for guest-agent on {} (tenant {tenant}); console log:\n{tail}",
                    self.config.boot_timeout,
                    vsock_socket.display(),
                ))
            }
        }
    }

    async fn stop(&self, vm: LaunchedVm) {
        let LaunchedVm {
            mut child,
            passt_child,
            ..
        } = vm;
        // `guest-agent` has no ACPI/graceful-shutdown handler (it is PID 1
        // with nothing else running in the guest), so there is no signal
        // worth sending before a kill — this is always effectively a timed
        // kill, just made explicit rather than left implicit in
        // `kill_on_drop`. A dedicated shutdown handshake, if one is ever
        // worth adding, belongs in a later Phase 15 step.
        if let Err(e) = child.kill().await {
            tracing::warn!(error = %e, "killing VM process failed");
        }
        match child.wait().await {
            Ok(status) => tracing::info!(?status, "VM process reaped"),
            Err(e) => tracing::warn!(error = %e, "waiting for VM process failed"),
        }
        // `passt` has no client left to serve once cloud-hypervisor above is
        // gone — kill it after, not before, so there's never a moment where
        // cloud-hypervisor is still running against a dead net backend.
        if let Some(mut passt_child) = passt_child {
            if let Err(e) = passt_child.kill().await {
                tracing::warn!(error = %e, "killing passt process failed");
            }
            match passt_child.wait().await {
                Ok(status) => tracing::info!(?status, "passt process reaped"),
                Err(e) => tracing::warn!(error = %e, "waiting for passt process failed"),
            }
        }
    }

    async fn push_key(&self, vsock_socket: &Path, key: &StoreKey, fresh: bool) -> eyre::Result<()> {
        let mut stream = tokio::net::UnixStream::connect(vsock_socket)
            .await
            .wrap_err_with(|| {
                format!(
                    "dialing {} for the control-channel key push",
                    vsock_socket.display()
                )
            })?;
        stream
            .write_all(format!("CONNECT {CONTROL_PORT}\n").as_bytes())
            .await
            .wrap_err("sending the vsock CONNECT handshake to the control channel")?;
        let mut buf = [0u8; 32];
        let n = stream
            .read(&mut buf)
            .await
            .wrap_err("reading the control-channel CONNECT reply")?;
        if !buf[..n].starts_with(b"OK") {
            return Err(eyre!(
                "vsock CONNECT to guest control port {CONTROL_PORT} refused: {:?}",
                String::from_utf8_lossy(&buf[..n])
            ));
        }

        let mode = if fresh { "FRESH" } else { "REUSE" };
        stream
            .write_all(format!("KEY {} {mode}\n", encode_hex(key)).as_bytes())
            .await
            .wrap_err("sending the KEY control message")?;

        let mut reply = Vec::new();
        stream
            .read_to_end(&mut reply)
            .await
            .wrap_err("reading the KEY control reply")?;
        if !reply.starts_with(b"OK") {
            return Err(eyre!(
                "guest-agent rejected the store key: {:?}",
                String::from_utf8_lossy(&reply)
            ));
        }
        Ok(())
    }
}

/// Poll for `path` to exist, up to `timeout` — used to wait for `passt`'s
/// vhost-user socket to appear before pointing `cloud-hypervisor` at it as a
/// client. Unlike `wait_for_vsock_ready`, existence is the whole check: there
/// is no handshake to speak here, `cloud-hypervisor` itself is the vhost-user
/// client that negotiates with `passt`.
async fn wait_for_socket(path: &Path, timeout: Duration) -> bool {
    tokio::time::timeout(timeout, async {
        loop {
            if tokio::fs::try_exists(path).await.unwrap_or(false) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .is_ok()
}

/// Poll `vsock_socket` until `guest-agent` accepts the inetd-style handshake
/// cloud-hypervisor's vsock device expects (`CONNECT <port>\n` -> `OK...`) —
/// the same protocol `nix/guest-vm-test.nix` drives with `socat`. No overall
/// deadline of its own; the caller wraps this in `tokio::time::timeout`.
async fn wait_for_vsock_ready(vsock_socket: &Path, port: u32) {
    loop {
        if handshake_once(vsock_socket, port).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn handshake_once(vsock_socket: &Path, port: u32) -> bool {
    let Ok(mut stream) = tokio::net::UnixStream::connect(vsock_socket).await else {
        // Socket not created yet, or cloud-hypervisor not accepting yet.
        return false;
    };
    if stream
        .write_all(format!("CONNECT {port}\n").as_bytes())
        .await
        .is_err()
    {
        return false;
    }
    let mut buf = [0u8; 32];
    let Ok(n) = stream.read(&mut buf).await else {
        return false;
    };
    buf[..n].starts_with(b"OK")
}

/// The last few lines of a VM's serial console log, for attaching to a boot
/// failure — the single most useful debugging string when cloud-hypervisor or
/// the guest kernel misbehaves. Never fails: a missing/unreadable log just
/// means an empty tail, not another error on top of the one being reported.
async fn console_log_tail(path: &Path) -> String {
    match tokio::fs::read_to_string(path).await {
        Ok(contents) => {
            let mut lines: Vec<&str> = contents.lines().rev().take(40).collect();
            lines.reverse();
            lines.join("\n")
        }
        Err(_) => String::new(),
    }
}

fn store_img_path(config: &VmConfig, tenant: &TenantId) -> PathBuf {
    // `TenantId::from_wire` already restricts this to `[a-z0-9-]` — no `/`,
    // no `..` — so joining it directly cannot escape `tenants/`. That
    // invariant is load-bearing here, not just convenient.
    config
        .state_dir
        .join("tenants")
        .join(tenant.as_str())
        .join("store.img")
}

/// Create `path` as a sparse file of `size_mb` if it doesn't already exist.
/// A no-op — not a truncate — if it does: reuse is the entire point. Returns
/// whether it was just created, which is exactly what tells the caller
/// whether to push a `FRESH` (mkfs) or `REUSE` (mount as-is) key handshake.
async fn create_store_img_if_absent(path: &Path, size_mb: u64) -> eyre::Result<bool> {
    if tokio::fs::metadata(path).await.is_ok() {
        return Ok(false);
    }
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .wrap_err_with(|| format!("creating {}", parent.display()))?;
    }
    let file = tokio::fs::File::create(path)
        .await
        .wrap_err_with(|| format!("creating {}", path.display()))?;
    file.set_len(size_mb * 1024 * 1024)
        .await
        .wrap_err_with(|| format!("sizing {}", path.display()))?;
    tracing::info!(path = %path.display(), size_mb, "created tenant store image");
    Ok(true)
}

/// Remove every leftover `tenants/*/store.img` under `state_dir`. Called once
/// at worker startup, before any job is served: a freshly started process
/// holds no in-memory keys for any tenant, so every image left behind by a
/// previous process is permanently unrecoverable ciphertext already — this
/// just stops it from occupying disk indefinitely. Not an error if
/// `state_dir/tenants` doesn't exist yet (a worker that has never booted a
/// VM).
pub async fn wipe_orphaned_store_images(state_dir: &Path) -> eyre::Result<()> {
    let tenants_dir = state_dir.join("tenants");
    let mut entries = match tokio::fs::read_dir(&tenants_dir).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(e).wrap_err_with(|| format!("reading {}", tenants_dir.display()));
        }
    };
    while let Some(entry) = entries
        .next_entry()
        .await
        .wrap_err_with(|| format!("reading {}", tenants_dir.display()))?
    {
        let store_img = entry.path().join("store.img");
        match tokio::fs::remove_file(&store_img).await {
            Ok(()) => tracing::info!(
                path = %store_img.display(),
                "wiped orphaned tenant store image from a previous worker process"
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(e).wrap_err_with(|| format!("removing {}", store_img.display()));
            }
        }
    }
    Ok(())
}

struct WarmVm {
    tenant: TenantId,
    vm: LaunchedVm,
}

/// One warm VM per worker process, LRU-of-one by tenant identity. No
/// `Arc`/`Mutex`: `main.rs`'s job loop is already strictly sequential
/// (`max_ack_pending: 1`), so a plain owned value mutably borrowed once per
/// iteration matches the existing single-in-flight design. Running N VMs
/// concurrently per worker (PLAN.md's flagged v2) is the seam that would have
/// to change if warm-pool latency turns out to matter.
pub struct VmPool<L: VmLauncher = CloudHypervisorLauncher> {
    config: VmConfig,
    launcher: L,
    warm: Option<WarmVm>,
    /// Each tenant's plain-`dm-crypt` key, generated once per process
    /// lifetime and reused across that tenant's later evict/reboot cycles —
    /// exactly as `store.img` itself is reused, and for the same reason: the
    /// image on disk only decrypts with the key it was written with. Never
    /// persisted; see the module doc and [`wipe_orphaned_store_images`].
    keys: HashMap<TenantId, StoreKey>,
}

impl VmPool<CloudHypervisorLauncher> {
    pub fn new(config: VmConfig) -> Self {
        let launcher = CloudHypervisorLauncher {
            config: config.clone(),
        };
        VmPool {
            config,
            launcher,
            warm: None,
            keys: HashMap::new(),
        }
    }
}

impl<L: VmLauncher> VmPool<L> {
    #[cfg(test)]
    fn with_launcher(config: VmConfig, launcher: L) -> Self {
        VmPool {
            config,
            launcher,
            warm: None,
            keys: HashMap::new(),
        }
    }

    /// Reuse the warm VM if it's still `tenant`'s and still alive; otherwise
    /// evict whatever is warm (if anything) and boot a fresh one, creating
    /// `tenants/<tenant>/store.img` first if it doesn't exist yet.
    pub async fn ensure_vm_for(&mut self, tenant: &TenantId) -> eyre::Result<VmHandle> {
        let store_img = store_img_path(&self.config, tenant);

        if let Some(warm) = self.warm.as_mut() {
            let alive = matches!(warm.vm.child.try_wait(), Ok(None));
            if &warm.tenant == tenant && alive {
                return Ok(VmHandle {
                    tenant: tenant.clone(),
                    vsock_socket: warm.vm.vsock_socket.clone(),
                    guest_port: NIX_DAEMON_PORT,
                    store_img,
                });
            }
            // Either a different tenant, or the same tenant's VM died on its
            // own between jobs — either way, not reusable.
            self.evict().await;
        }

        let fresh = create_store_img_if_absent(&store_img, self.config.store_img_size_mb).await?;

        let tenant_dir = store_img
            .parent()
            .expect("store_img always has a tenants/<tenant>/ parent");
        let vsock_socket = tenant_dir.join("vsock.sock");
        let console_log = tenant_dir.join("console.log");
        // A stale socket file from a previous, uncleanly-terminated VM would
        // otherwise make the readiness poll below dial a dead socket.
        let _ = tokio::fs::remove_file(&vsock_socket).await;

        tracing::info!(%tenant, store_img = %store_img.display(), "booting VM");
        let vm = self
            .launcher
            .boot(tenant, &store_img, &vsock_socket, &console_log)
            .await?;
        tracing::info!(%tenant, "VM ready");

        // Generated once per tenant per process lifetime; a still-`fresh`
        // image can only ever pair with a key generated in this same call
        // (nothing else could have written to it), so a cached key from an
        // earlier tenant of this same name within this process is never
        // stale here.
        let key = *self.keys.entry(tenant.clone()).or_insert_with(|| {
            let mut key = [0u8; 32];
            rand::rng().fill_bytes(&mut key);
            key
        });
        if let Err(e) = self.launcher.push_key(&vsock_socket, &key, fresh).await {
            self.launcher.stop(vm).await;
            return Err(e.wrap_err(format!("pushing store key to tenant {tenant}'s VM")));
        }
        tracing::info!(%tenant, fresh, "store key pushed");

        self.warm = Some(WarmVm {
            tenant: tenant.clone(),
            vm,
        });

        Ok(VmHandle {
            tenant: tenant.clone(),
            vsock_socket,
            guest_port: NIX_DAEMON_PORT,
            store_img,
        })
    }

    async fn evict(&mut self) {
        if let Some(warm) = self.warm.take() {
            tracing::info!(tenant = %warm.tenant, "evicting VM");
            self.launcher.stop(warm.vm).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Clone, Default)]
    struct FakeLauncher {
        boots: Arc<AtomicUsize>,
        stops: Arc<AtomicUsize>,
        /// `(key, fresh)` for every `push_key` call, in order — lets tests
        /// assert both bookkeeping (same key reused, `FRESH` only on first
        /// creation) without a real vsock control channel to talk to.
        pushed_keys: Arc<std::sync::Mutex<Vec<(StoreKey, bool)>>>,
    }

    impl FakeLauncher {
        fn boot_count(&self) -> usize {
            self.boots.load(Ordering::SeqCst)
        }
        fn stop_count(&self) -> usize {
            self.stops.load(Ordering::SeqCst)
        }
        fn pushed_keys(&self) -> Vec<(StoreKey, bool)> {
            self.pushed_keys.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl VmLauncher for FakeLauncher {
        async fn boot(
            &self,
            _tenant: &TenantId,
            _store_img: &Path,
            vsock_socket: &Path,
            console_log: &Path,
        ) -> eyre::Result<LaunchedVm> {
            self.boots.fetch_add(1, Ordering::SeqCst);
            // A real, long-lived child process so `try_wait`-based liveness
            // checks in `ensure_vm_for` exercise the same code path as the
            // real launcher, without a second "fake liveness" mechanism.
            let child = Command::new("sleep")
                .arg("3600")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawning `sleep` for a test fake");
            Ok(LaunchedVm {
                child,
                // `FakeLauncher` doesn't spawn a real `passt` — the reuse/
                // evict decision this fake exists to test doesn't touch
                // networking at all (see `CloudHypervisorLauncher::stop`'s
                // own handling of `None` here).
                passt_child: None,
                vsock_socket: vsock_socket.to_path_buf(),
                console_log: console_log.to_path_buf(),
            })
        }

        async fn stop(&self, vm: LaunchedVm) {
            self.stops.fetch_add(1, Ordering::SeqCst);
            let mut child = vm.child;
            let _ = child.kill().await;
            let _ = child.wait().await;
        }

        async fn push_key(
            &self,
            _vsock_socket: &Path,
            key: &StoreKey,
            fresh: bool,
        ) -> eyre::Result<()> {
            self.pushed_keys.lock().unwrap().push((*key, fresh));
            Ok(())
        }
    }

    fn test_config(state_dir: &Path) -> VmConfig {
        VmConfig {
            state_dir: state_dir.to_path_buf(),
            kernel: PathBuf::new(),
            initrd: PathBuf::new(),
            cloud_hypervisor: PathBuf::new(),
            passt: PathBuf::new(),
            vcpus: 1,
            memory_mb: 256,
            store_img_size_mb: 1,
            boot_timeout: Duration::from_secs(1),
            cid: 3,
        }
    }

    #[test]
    fn passt_args_wire_up_the_fixed_address_plan() {
        let args = passt_args(Path::new("/var/lib/kubernix-worker/tenants/acme/net.sock"));
        assert_eq!(
            args,
            vec![
                "--foreground",
                "--vhost-user",
                "--socket",
                "/var/lib/kubernix-worker/tenants/acme/net.sock",
                "--address",
                NET_GUEST_ADDR,
                "--netmask",
                NET_PREFIX,
                "--gateway",
                NET_GATEWAY,
                "--dns",
                NET_GATEWAY,
            ]
        );
    }

    #[test]
    fn net_arg_connects_as_a_vhost_user_client() {
        assert_eq!(
            net_arg(Path::new("/var/lib/kubernix-worker/tenants/acme/net.sock")),
            "vhost_user=true,socket=/var/lib/kubernix-worker/tenants/acme/net.sock,num_queues=2,vhost_mode=client"
        );
    }

    #[test]
    fn store_img_path_is_tenant_scoped() {
        let config = test_config(Path::new("/var/lib/kubernix-worker"));
        let tenant = TenantId::from_wire("acme").unwrap();
        assert_eq!(
            store_img_path(&config, &tenant),
            PathBuf::from("/var/lib/kubernix-worker/tenants/acme/store.img")
        );
    }

    #[tokio::test]
    async fn create_store_img_if_absent_is_sparse_and_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.img");

        let created = create_store_img_if_absent(&path, 4).await.unwrap();
        assert!(created, "first call creates the image");
        let meta = tokio::fs::metadata(&path).await.unwrap();
        assert_eq!(meta.len(), 4 * 1024 * 1024);

        // A second call, with existing content, must not truncate it away —
        // that content is exactly what makes the image worth keeping.
        tokio::fs::write(&path, b"marker").await.unwrap();
        let created = create_store_img_if_absent(&path, 4).await.unwrap();
        assert!(!created, "second call reuses the existing image");
        let content = tokio::fs::read(&path).await.unwrap();
        assert_eq!(content, b"marker");
    }

    #[tokio::test]
    async fn wipe_orphaned_store_images_removes_every_tenant_image() {
        let dir = tempfile::tempdir().unwrap();
        for tenant in ["tenant-a", "tenant-b"] {
            let tenant_dir = dir.path().join("tenants").join(tenant);
            tokio::fs::create_dir_all(&tenant_dir).await.unwrap();
            tokio::fs::write(tenant_dir.join("store.img"), b"ciphertext")
                .await
                .unwrap();
        }

        wipe_orphaned_store_images(dir.path()).await.unwrap();

        for tenant in ["tenant-a", "tenant-b"] {
            let store_img = dir.path().join("tenants").join(tenant).join("store.img");
            assert!(
                tokio::fs::metadata(&store_img).await.is_err(),
                "{} should have been wiped",
                store_img.display()
            );
        }
    }

    #[tokio::test]
    async fn wipe_orphaned_store_images_is_a_noop_without_a_tenants_dir() {
        let dir = tempfile::tempdir().unwrap();
        wipe_orphaned_store_images(dir.path()).await.unwrap();
    }

    #[tokio::test]
    async fn reuses_warm_vm_for_same_tenant_and_evicts_on_different_tenant() {
        let dir = tempfile::tempdir().unwrap();
        let launcher = FakeLauncher::default();
        let mut pool = VmPool::with_launcher(test_config(dir.path()), launcher.clone());

        let tenant_a = TenantId::from_wire("tenant-a").unwrap();
        let tenant_b = TenantId::from_wire("tenant-b").unwrap();

        pool.ensure_vm_for(&tenant_a).await.unwrap();
        pool.ensure_vm_for(&tenant_a).await.unwrap();
        assert_eq!(launcher.boot_count(), 1, "second job for A must reuse");
        assert_eq!(launcher.stop_count(), 0);

        pool.ensure_vm_for(&tenant_b).await.unwrap();
        assert_eq!(launcher.boot_count(), 2, "B's job must boot a fresh VM");
        assert_eq!(launcher.stop_count(), 1, "A's VM must be evicted");
    }

    #[tokio::test]
    async fn dead_warm_vm_is_rebooted_not_reused() {
        let dir = tempfile::tempdir().unwrap();
        let launcher = FakeLauncher::default();
        let mut pool = VmPool::with_launcher(test_config(dir.path()), launcher.clone());

        let tenant_a = TenantId::from_wire("tenant-a").unwrap();
        pool.ensure_vm_for(&tenant_a).await.unwrap();

        // Simulate the guest crashing independently of any eviction.
        let warm = pool.warm.as_mut().unwrap();
        warm.vm.child.kill().await.unwrap();
        warm.vm.child.wait().await.unwrap();

        pool.ensure_vm_for(&tenant_a).await.unwrap();
        assert_eq!(
            launcher.boot_count(),
            2,
            "a dead 'warm' VM must not be handed back as reusable"
        );
    }

    #[tokio::test]
    async fn key_is_generated_fresh_and_reused_on_reboot() {
        let dir = tempfile::tempdir().unwrap();
        let launcher = FakeLauncher::default();
        let mut pool = VmPool::with_launcher(test_config(dir.path()), launcher.clone());

        let tenant_a = TenantId::from_wire("tenant-a").unwrap();
        let tenant_b = TenantId::from_wire("tenant-b").unwrap();

        // First boot for A: image didn't exist yet, so FRESH.
        pool.ensure_vm_for(&tenant_a).await.unwrap();
        // Evict by dispatching B, then come back to A: image now exists, so
        // this reboot must be REUSE with the *same* key as the first push.
        pool.ensure_vm_for(&tenant_b).await.unwrap();
        pool.ensure_vm_for(&tenant_a).await.unwrap();

        let pushed = launcher.pushed_keys();
        assert_eq!(pushed.len(), 3, "one push per fresh boot, none on reuse");
        let (key_a1, fresh_a1) = pushed[0];
        let (key_b, fresh_b) = pushed[1];
        let (key_a2, fresh_a2) = pushed[2];

        assert!(fresh_a1, "A's first ever boot creates the image");
        assert!(fresh_b, "B's first ever boot creates its own image");
        assert!(!fresh_a2, "A's image already existed by the second boot");
        assert_eq!(key_a1, key_a2, "A's key must survive across a reboot");
        assert_ne!(key_a1, key_b, "different tenants must get different keys");
    }

    #[tokio::test]
    async fn warm_vm_reuse_does_not_repush_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let launcher = FakeLauncher::default();
        let mut pool = VmPool::with_launcher(test_config(dir.path()), launcher.clone());

        let tenant_a = TenantId::from_wire("tenant-a").unwrap();
        pool.ensure_vm_for(&tenant_a).await.unwrap();
        pool.ensure_vm_for(&tenant_a).await.unwrap();

        assert_eq!(
            launcher.pushed_keys().len(),
            1,
            "reusing a still-warm VM must not push the key again"
        );
    }
}
