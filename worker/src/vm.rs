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
//!
//! Step 8: every tenant's `cloud-hypervisor`/`passt` pair runs under its own
//! uid ([`crate::uid::UidAllocator`]), dropped to in a `pre_exec` hook
//! before either binary is `execve`d. `store.img` is created only after
//! that drop, so it is naturally owned by the tenant's uid with no
//! `chown(2)` call and no `CAP_CHOWN` on the worker. See `prepare_tenant_dir`
//! for the directory permission layout that still lets the worker `unlink()`
//! a subuid-owned image, and `main.rs`'s `prctl(PR_SET_DUMPABLE)` call for
//! the uid-independent half of the threat model this closes.
//!
//! **`console.log`/`vsock.sock` and `DAC_OVERRIDE`.** See the doc comment
//! above [`drop_privileges`] for why the worker's own container needs that
//! capability back — and for a dead end tried first, worth reading before
//! attempting a cleverer scoped alternative a second time.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use eyre::{Context as _, eyre};
use kubernix_types::TenantId;
use nix::unistd::{Gid, Uid};
use rand::Rng as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};

use crate::uid::UidAllocator;

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
/// daemon-protocol traffic is sent to `NIX_DAEMON_PORT`, and, since PLAN.md
/// Phase 17, `boot_probe`'s `CAPS?` nested-virt self-test.
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
    /// Guest CID for [`boot_probe`]'s one-off kvm self-test (PLAN.md Phase
    /// 17). Distinct from `cid` above on principle rather than necessity —
    /// the probe fully completes, torn down, before the job loop (and so
    /// before any tenant VM) ever starts, so reusing `cid` would be safe
    /// under today's strict startup ordering, but a dedicated CID makes that
    /// safety unconditional instead of dependent on that ordering never
    /// changing.
    pub probe_cid: u32,
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

        let cid: u32 = parse_env_or("KUBERNIX_VM_CID", 3)?;
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
            cid,
            probe_cid: parse_env_or("KUBERNIX_VM_PROBE_CID", cid + 1)?,
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
    /// Whether the boot behind this handle was `FRESH` (`store.img` just
    /// created) as opposed to `REUSE` (an existing one mounted) — PLAN.md
    /// Phase 18's retry loop gates ENOSPC recovery on this.
    pub fresh: bool,
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

/// The dropped-privilege identity (Step 8) a tenant's `cloud-hypervisor`/
/// `passt` pair boots under — [`UidAllocator::allocate`]'s output, bundled
/// so [`VmLauncher::boot`] doesn't carry `uid`/`gid` as two separate
/// arguments on top of everything else it already takes.
#[derive(Clone, Copy)]
pub struct VmIdentity {
    pub uid: Uid,
    pub gid: Gid,
}

/// Spawns and tears down the actual VM process. A trait so
/// [`VmPool::ensure_vm_for`]'s reuse/evict decision — the thing Step 2 is
/// actually about — is testable against a fake, without `/dev/kvm`.
#[async_trait::async_trait]
pub trait VmLauncher: Send + Sync {
    /// `identity` (Step 8) is what `cloud-hypervisor`/`passt` drop to before
    /// `execve`, and — for `cloud-hypervisor` specifically — the owner
    /// `store.img` is created under when `fresh` is true. `fresh` replaces
    /// the old "create it and tell me if that's new" contract: the caller
    /// only checks existence now, since creation has to happen after the
    /// privilege drop to avoid a `chown(2)`.
    async fn boot(
        &self,
        tenant: &TenantId,
        store_img: &Path,
        vsock_socket: &Path,
        console_log: &Path,
        identity: VmIdentity,
        fresh: bool,
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

/// A `pre_exec` closure (Step 8) that drops from the worker's own
/// privilege to `(uid, gid)` — `setgroups([])` first (so `CAP_SETGID` is
/// still held when it's called; an empty list is correct here, not just
/// convenient — these nodes' `/dev/kvm` is `0666` with no owning group to
/// retain, so there is nothing to keep), then `setgid`, then `setuid` last,
/// since once `setuid` succeeds none of the earlier calls are possible
/// anymore.
///
/// Async-signal-safety caveat, stated rather than glossed over: `nix`'s
/// `setgroups`/`setgid`/`setuid` are thin wrappers straight over the libc
/// calls of the same name, which is the part that matters between `fork`
/// and `execve` — but this closure is `FnMut` boxed by `std::process`, and
/// the crate's own `pre_exec` docs call out that not every Rust operation
/// is safe there (allocation, locks). Nothing here allocates at all in the
/// child (the empty `groups` slice is `'static`), so this stays inside the
/// same accepted trade-off every "drop privileges before exec"
/// implementation makes — not a new risk introduced by this step.
///
/// **Why the worker's own container needs `DAC_OVERRIDE` back.**
/// `cloud-hypervisor` creates `console.log` (`--serial file=...`) and
/// `vsock.sock` (`--vsock socket=...`) *after* this drop, so they end up
/// owned by the tenant's own `(uid, gid)`, mode `0600`/`0700`. That's fine
/// for the tenant's *own* processes, but the worker itself then can't open
/// either file to `wait_for_vsock_ready` or attach a console-log tail to a
/// boot-failure error: it runs as uid 0, but its own container
/// `securityContext` drops `DAC_OVERRIDE` along with every other capability
/// except `SETUID`/`SETGID` (see PLAN.md Phase 13's status note on the
/// resulting `timed out waiting for guest-agent` boot failures — the guest
/// was booting fine the whole time; the worker just couldn't see it).
/// `charts/kubernix/templates/worker-deployment.yaml` grants `DAC_OVERRIDE`
/// back to close this.
///
/// **A group-based scheme was tried first and reverted, worth reading before
/// attempting a cleverer scoped alternative a second time.** The idea: give
/// every tenant's `cloud-hypervisor`/`passt` a shared, fixed gid (instead of
/// today's per-tenant one) with `umask(0o070)` clearing the *group* bits on
/// creation — relying on the Unix rule that a gid match is judged on group
/// bits alone, never falling through to "other" even when group denies and
/// other would allow. That correctly blocks a different tenant's process
/// (gid matches, group bits are `0`, denied) while letting the worker in
/// (no uid or gid match, falls to "other," which stays open) — all without
/// any new capability. It worked exactly as designed for `passt`'s
/// `net.sock`. It did **not** work for `cloud-hypervisor`'s own
/// `console.log`/`vsock.sock`: verified live against the real cluster that
/// `cloud-hypervisor` resets its own umask (`0o077`) early in its own
/// startup, unconditionally overriding whatever the parent set before
/// `execve` — the two files this actually needed to fix came out byte-for-
/// byte identical to before the change. Confirmed a second time by the side
/// effect it had instead: `net.sock`'s original mode was `0755` (an ambient
/// `022`-ish umask, not `077`), and forcing `umask(0o070)` left its "other"
/// bits completely untouched — widening them from `r-x` to `rwx` (gaining
/// *write*, i.e. connect access) relative to before, a real if narrow
/// regression on a file that never needed touching. Nothing this process
/// does before `execve` survives `cloud-hypervisor` overwriting it again on
/// its own — `DAC_OVERRIDE` is the mechanism that actually works, at the
/// cost of being a blanket capability rather than a scoped one.
fn drop_privileges(
    uid: Uid,
    gid: Gid,
) -> impl FnMut() -> std::io::Result<()> + Send + Sync + 'static {
    move || {
        nix::unistd::setgroups(&[]).map_err(std::io::Error::from)?;
        nix::unistd::setgid(gid).map_err(std::io::Error::from)?;
        nix::unistd::setuid(uid).map_err(std::io::Error::from)?;
        Ok(())
    }
}

/// [`drop_privileges`] plus, when `fresh`, creating `store_img` as a sparse
/// file of `size_mb` — *after* the drop, so the file is naturally owned by
/// `(uid, gid)`. `create_new` doubles as a safety check: `ensure_vm_for`
/// already verified the path didn't exist before deciding `fresh`, and this
/// makes an unexpected pre-existing file (e.g. a bug in that check) a loud
/// spawn failure rather than a silent truncation of someone's store.
///
/// Kept separate from [`drop_privileges`] rather than folding a `Path` into
/// every caller: `passt` never touches `store.img` at all, so its `pre_exec`
/// only ever needs the plain privilege drop.
fn drop_privileges_and_maybe_create_store_img(
    uid: Uid,
    gid: Gid,
    store_img: PathBuf,
    fresh: bool,
    size_mb: u64,
) -> impl FnMut() -> std::io::Result<()> + Send + Sync + 'static {
    move || {
        nix::unistd::setgroups(&[]).map_err(std::io::Error::from)?;
        nix::unistd::setgid(gid).map_err(std::io::Error::from)?;
        nix::unistd::setuid(uid).map_err(std::io::Error::from)?;
        if fresh {
            use std::os::unix::fs::OpenOptionsExt as _;
            // `.mode(0o600)` sets the permission bits `open(2)` requests
            // directly — without it, `O_CREAT`'s actual bits are
            // `0o666 & !umask`, whichever umask this process happens to be
            // running under, not the `0600` the design calls for. Since the
            // file's owning uid/gid are already this tenant's (we're past
            // the `setuid`/`setgid` above), a wider-than-intended mode here
            // would mean "other" — every other tenant's dropped-privilege
            // process — could open this tenant's ciphertext directly,
            // rather than that being gated on already knowing the path.
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&store_img)?;
            file.set_len(size_mb * 1024 * 1024)?;
        }
        Ok(())
    }
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
        identity: VmIdentity,
        fresh: bool,
    ) -> eyre::Result<LaunchedVm> {
        let VmIdentity { uid, gid } = identity;
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
        // Captured to a file, not `Stdio::null()`: a `passt` that fails
        // silently after the Step 8 privilege drop (wrong CLI arg, a
        // permission it turns out to need, anything) previously vanished
        // into an opaque 30s "timed out waiting for the socket" with no way
        // to tell why. Opened by the worker (uid 0) before `fork`, so the
        // fd is already valid and inherited regardless of what uid the
        // child drops to — no directory-write requirement of its own.
        let passt_log = store_img
            .parent()
            .expect("store_img always has a tenants/<tenant>/ parent")
            .join("passt.log");
        let passt_stdout = std::fs::File::create(&passt_log)
            .wrap_err_with(|| format!("creating {}", passt_log.display()))?;
        let passt_stderr = passt_stdout
            .try_clone()
            .wrap_err("cloning the passt log file handle")?;
        let mut passt_command = Command::new(&self.config.passt);
        passt_command
            .args(passt_args(&net_socket))
            .stdin(Stdio::null())
            .stdout(Stdio::from(passt_stdout))
            .stderr(Stdio::from(passt_stderr))
            .kill_on_drop(true);
        // SAFETY: the closure only calls `nix`'s thin libc wrappers around
        // `setgroups`/`setgid`/`setuid` — see `drop_privileges`'s doc for
        // the async-signal-safety trade-off this accepts.
        unsafe {
            passt_command.pre_exec(drop_privileges(uid, gid));
        }
        let passt_child = passt_command.spawn().wrap_err_with(|| {
            format!(
                "spawning {} for tenant {tenant}",
                self.config.passt.display()
            )
        })?;
        if !wait_for_socket(&net_socket, self.config.boot_timeout).await {
            let tail = console_log_tail(&passt_log).await;
            return Err(eyre!(
                "timed out after {:?} waiting for passt's vhost-user socket at {} (tenant {tenant}); passt log:\n{tail}",
                self.config.boot_timeout,
                net_socket.display(),
            ));
        }

        let mut ch_command = Command::new(&self.config.cloud_hypervisor);
        ch_command
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
            .stdin(Stdio::null());
        // Captured, not `Stdio::null()` — same reasoning as `passt_log`
        // above: `console_log` is the *guest's* serial output, captured by
        // cloud-hypervisor itself once it's far enough along to boot a
        // kernel; if cloud-hypervisor's own process fails before that (bad
        // arg, can't open `/dev/kvm` as the dropped uid, can't open
        // `store_img`), `console_log` stays empty and there was previously
        // nothing else to look at.
        let ch_log = store_img
            .parent()
            .expect("store_img always has a tenants/<tenant>/ parent")
            .join("cloud-hypervisor.log");
        let ch_stdout = std::fs::File::create(&ch_log)
            .wrap_err_with(|| format!("creating {}", ch_log.display()))?;
        let ch_stderr = ch_stdout
            .try_clone()
            .wrap_err("cloning the cloud-hypervisor log file handle")?;
        ch_command
            .stdout(Stdio::from(ch_stdout))
            .stderr(Stdio::from(ch_stderr))
            // Belt-and-braces: the real teardown path is `stop()` below, but
            // this keeps a worker crash from orphaning a VM process too.
            .kill_on_drop(true);
        // SAFETY: see `drop_privileges`'s doc. The `fresh` branch additionally
        // does a plain `open(O_CREAT|O_EXCL)`/`ftruncate` — no allocation
        // beyond the already-built `store_img` path, captured before `fork`.
        // Creating it here, after the drop, is what lets `store.img` end up
        // owned by (uid, gid) with no `chown(2)` call at all: see the module
        // doc and PLAN.md Phase 15 Step 8.
        unsafe {
            ch_command.pre_exec(drop_privileges_and_maybe_create_store_img(
                uid,
                gid,
                store_img.to_path_buf(),
                fresh,
                self.config.store_img_size_mb,
            ));
        }
        let mut child = match ch_command.spawn() {
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
            Ok(Ok(())) => Ok(LaunchedVm {
                child,
                passt_child: Some(passt_child),
                vsock_socket: vsock_socket.to_path_buf(),
                console_log: console_log.to_path_buf(),
            }),
            // A hard failure (see `wait_for_vsock_ready`'s doc) — reported
            // immediately rather than waiting out the rest of the timeout,
            // since retrying it can never succeed. Still attaches both logs:
            // a permission error reaching `vsock_socket` very often means
            // the same permission error would hit `console_log` too (as it
            // did for the Step 8 regression this distinction was added
            // for), and seeing *that* explicitly in the error — rather than
            // a blank line indistinguishable from "guest wrote nothing" — is
            // most of what makes this fast to diagnose.
            Ok(Err(hard_err)) => {
                let _ = child.kill().await;
                let mut passt_child = passt_child;
                let _ = passt_child.kill().await;
                let console_tail = console_log_tail(console_log).await;
                let ch_tail = console_log_tail(&ch_log).await;
                Err(hard_err.wrap_err(format!(
                    "guest-agent handshake on {} failed (tenant {tenant}); console log:\n{console_tail}\ncloud-hypervisor log:\n{ch_tail}",
                    vsock_socket.display(),
                )))
            }
            Err(_elapsed) => {
                let _ = child.kill().await;
                let mut passt_child = passt_child;
                let _ = passt_child.kill().await;
                let console_tail = console_log_tail(console_log).await;
                let ch_tail = console_log_tail(&ch_log).await;
                Err(eyre!(
                    "timed out after {:?} waiting for guest-agent on {} (tenant {tenant}); console log:\n{console_tail}\ncloud-hypervisor log:\n{ch_tail}",
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
        let mut stream = dial_control_port(vsock_socket).await?;

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

/// Dial `vsock_socket`'s control-channel port and complete cloud-hypervisor's
/// own `CONNECT <port>\n` -> `OK...` vsock proxy handshake, returning the
/// still-open stream ready for a guest-agent control verb. Shared by
/// `push_key` and `boot_probe` — the *outer* framing layer both speak before
/// getting to whichever verb of guest-agent's own protocol they actually
/// want (`KEY ...` / `CAPS?`, PLAN.md Phase 17).
async fn dial_control_port(vsock_socket: &Path) -> eyre::Result<tokio::net::UnixStream> {
    let mut stream = tokio::net::UnixStream::connect(vsock_socket)
        .await
        .wrap_err_with(|| format!("dialing {} for the control channel", vsock_socket.display()))?;
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
    Ok(stream)
}

/// Boots a disk-less, network-less, untenanted probe VM at worker startup to
/// check whether nested virtualization actually reaches the guest — `/dev/kvm`
/// presence alone (what the `devices.kubevirt.io/kvm` device plugin checks
/// for in the chart) does not guarantee this, since the plugin may only test
/// that the device file exists, not that nested virt actually works on that
/// node. Returns the count of `vmx`/`svm` lines the guest itself sees in
/// `/proc/cpuinfo`, via the `CAPS?` control-port verb
/// (`guest-agent/src/main.rs::count_nested_virt_flags`) — this checks the
/// perspective that actually matters (would an L2 VM inside this guest see
/// the flags), not host-side capability.
///
/// Entirely outside `VmPool`/`VmHandle`'s per-tenant lifecycle: no `--disk`,
/// no `--net`/`passt` (no networking is needed just to ask `CAPS?`), no
/// `UidAllocator::allocate` — runs as the worker process's own uid. That is a
/// `v1` choice, not a closed question: there is no tenant data or `store.img`
/// here to isolate from, which is what made `UidAllocator`'s per-tenant
/// identities worth their complexity in the first place, but it is worth
/// revisiting if the threat model around `cloud-hypervisor` itself changes.
///
/// Tears the child process down unconditionally before returning, success or
/// failure — never fatal to worker startup on its own (see the call site in
/// `main.rs`): a worker whose probe fails or reports zero flags simply never
/// declares itself `kvm`-capable, and is still a fully useful plain/
/// `big-parallel` worker. PLAN.md Phase 17.
pub async fn boot_probe(config: &VmConfig) -> eyre::Result<u32> {
    let probe_dir = config.state_dir.join("probe");
    tokio::fs::create_dir_all(&probe_dir)
        .await
        .wrap_err_with(|| format!("creating {}", probe_dir.display()))?;
    let vsock_socket = probe_dir.join("vsock.sock");
    let _ = tokio::fs::remove_file(&vsock_socket).await;
    let console_log = probe_dir.join("console.log");
    let ch_log = probe_dir.join("cloud-hypervisor.log");

    let mut ch_command = Command::new(&config.cloud_hypervisor);
    ch_command
        .arg("--kernel")
        .arg(&config.kernel)
        .arg("--initramfs")
        .arg(&config.initrd)
        .arg("--cmdline")
        .arg("console=ttyS0 reboot=t panic=1")
        .arg("--cpus")
        .arg(format!("boot={}", config.vcpus))
        .arg("--memory")
        .arg(format!("size={}M", config.memory_mb))
        .arg("--vsock")
        .arg(format!(
            "cid={},socket={}",
            config.probe_cid,
            vsock_socket.display()
        ))
        .arg("--console")
        .arg("off")
        .arg("--serial")
        .arg(format!("file={}", console_log.display()))
        .stdin(Stdio::null())
        .kill_on_drop(true);
    let ch_stdout = std::fs::File::create(&ch_log)
        .wrap_err_with(|| format!("creating {}", ch_log.display()))?;
    let ch_stderr = ch_stdout
        .try_clone()
        .wrap_err("cloning the cloud-hypervisor log file handle")?;
    ch_command
        .stdout(Stdio::from(ch_stdout))
        .stderr(Stdio::from(ch_stderr));

    let mut child = ch_command.spawn().wrap_err_with(|| {
        format!(
            "spawning {} for the kvm probe",
            config.cloud_hypervisor.display()
        )
    })?;

    let result: eyre::Result<u32> = async {
        tokio::time::timeout(
            config.boot_timeout,
            wait_for_vsock_ready(&vsock_socket, CONTROL_PORT),
        )
        .await
        .wrap_err("timed out waiting for guest-agent's control port")??;

        let mut stream = dial_control_port(&vsock_socket).await?;
        stream
            .write_all(b"CAPS?\n")
            .await
            .wrap_err("sending CAPS?")?;
        let mut reply = Vec::new();
        stream
            .read_to_end(&mut reply)
            .await
            .wrap_err("reading the CAPS? reply")?;
        parse_caps_reply(&reply)
    }
    .await;

    let _ = child.kill().await;
    let _ = child.wait().await;

    match result {
        Ok(n) => Ok(n),
        Err(e) => {
            let console_tail = console_log_tail(&console_log).await;
            let ch_tail = console_log_tail(&ch_log).await;
            Err(e.wrap_err(format!(
                "console log:\n{console_tail}\ncloud-hypervisor log:\n{ch_tail}"
            )))
        }
    }
}

fn parse_caps_reply(reply: &[u8]) -> eyre::Result<u32> {
    let text = String::from_utf8_lossy(reply);
    let text = text.trim();
    match text.strip_prefix("OK ") {
        Some(rest) => rest
            .trim()
            .parse::<u32>()
            .map_err(|e| eyre!("CAPS? reply {text:?} did not carry a decimal count: {e}")),
        None => Err(eyre!("guest-agent rejected CAPS?: {text:?}")),
    }
}

/// PLAN.md Phase 18: what `STATUS?` reports — see
/// `guest-agent/src/ebpf.rs::FailureStatus`, this function's server-side
/// mirror, and `guest-agent/src/main.rs::format_status` for the exact wire
/// text [`parse_status_reply`] below parses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestFailureStatus {
    None,
    OutOfMemory { builder_victim: bool },
    DiskFull,
}

/// Clears the guest's OOM/ENOSPC detection state — sent right before opening
/// a new build's daemon-protocol connection, so whatever `STATUS?` reports
/// afterwards is scoped to *this* build, not the VM's whole lifetime. Follows
/// the same `dial_control_port` + verb-string + one-shot-read pattern as
/// `push_key`/`boot_probe`.
pub async fn reset_job_status(vsock_socket: &Path) -> eyre::Result<()> {
    let mut stream = dial_control_port(vsock_socket).await?;
    stream
        .write_all(b"RESET\n")
        .await
        .wrap_err("sending RESET")?;
    let mut reply = Vec::new();
    stream
        .read_to_end(&mut reply)
        .await
        .wrap_err("reading the RESET reply")?;
    if !reply.starts_with(b"OK") {
        return Err(eyre!(
            "guest-agent rejected RESET: {:?}",
            String::from_utf8_lossy(&reply)
        ));
    }
    Ok(())
}

/// Asks the guest what resource-exhaustion signal (if any) has fired since
/// the last [`reset_job_status`] — called once, right after a VM-path build
/// failure.
pub async fn query_status(vsock_socket: &Path) -> eyre::Result<GuestFailureStatus> {
    let mut stream = dial_control_port(vsock_socket).await?;
    stream
        .write_all(b"STATUS?\n")
        .await
        .wrap_err("sending STATUS?")?;
    let mut reply = Vec::new();
    stream
        .read_to_end(&mut reply)
        .await
        .wrap_err("reading the STATUS? reply")?;
    parse_status_reply(&reply)
}

fn parse_status_reply(reply: &[u8]) -> eyre::Result<GuestFailureStatus> {
    let text = String::from_utf8_lossy(reply);
    let text = text.trim();
    let rest = text
        .strip_prefix("OK ")
        .ok_or_else(|| eyre!("guest-agent rejected STATUS?: {text:?}"))?;
    match rest.trim() {
        "NONE" => Ok(GuestFailureStatus::None),
        "OOM BUILDER" => Ok(GuestFailureStatus::OutOfMemory {
            builder_victim: true,
        }),
        "OOM OTHER" => Ok(GuestFailureStatus::OutOfMemory {
            builder_victim: false,
        }),
        "ENOSPC" => Ok(GuestFailureStatus::DiskFull),
        other => Err(eyre!(
            "STATUS? reply carried an unrecognised state: {other:?}"
        )),
    }
}

/// Deletes `store.img` outright — the ENOSPC-on-`REUSE` retry path (PLAN.md
/// Phase 18): the next `ensure_vm_for` call for this tenant sees the file
/// gone, computes `fresh = true`, and reuses every existing
/// boot/`push_key`/`mkfs.ext4` code path unchanged. No new boot path needed.
async fn wipe_store_image(store_img: &Path) -> eyre::Result<()> {
    tokio::fs::remove_file(store_img)
        .await
        .wrap_err_with(|| format!("removing {}", store_img.display()))
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

/// One attempt at [`handshake_once`] came back — either it's not ready yet
/// (keep polling) or something's actually wrong (stop immediately, rather
/// than burning the rest of `boot_timeout` retrying a condition that will
/// never clear on its own). Named rather than a bare `Result` so the two
/// "give up" cases at the call site — hard failure vs. genuine timeout —
/// stay visually distinct.
enum HandshakeAttempt {
    Ready,
    NotYet,
    HardError(std::io::Error),
}

/// Poll `vsock_socket` until `guest-agent` accepts the inetd-style handshake
/// cloud-hypervisor's vsock device expects (`CONNECT <port>\n` -> `OK...`) —
/// the same protocol `nix/guest-vm-test.nix` drives with `socat`. No overall
/// deadline of its own; the caller wraps this in `tokio::time::timeout` for
/// the "guest is just slow to boot" case. This function's own `Err` return
/// is for the other case: a condition retrying can never fix, surfaced
/// immediately instead of silently eating the whole timeout window first.
///
/// This distinction is exactly what closed the Phase 15 Step 8 permission
/// regression (PLAN.md Phase 13's status note): before it existed, an
/// `EACCES` connecting to a `vsock.sock` the worker didn't have access to
/// looked identical to "cloud-hypervisor hasn't finished booting yet," so
/// every affected build burned the full 30s timeout and reported a boot
/// failure with an empty, equally-permission-blocked console log — even
/// though the guest had booted successfully in well under a second.
async fn wait_for_vsock_ready(vsock_socket: &Path, port: u32) -> eyre::Result<()> {
    loop {
        match handshake_once(vsock_socket, port).await {
            HandshakeAttempt::Ready => return Ok(()),
            HandshakeAttempt::NotYet => {
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
            HandshakeAttempt::HardError(e) => {
                return Err(e).wrap_err_with(|| {
                    format!(
                        "connecting to {} for the guest-agent handshake",
                        vsock_socket.display()
                    )
                });
            }
        }
    }
}

/// `NotFound`/`ConnectionRefused` are the ordinary "cloud-hypervisor hasn't
/// created/bound the socket yet" states early in a boot — worth retrying.
/// Anything else (`PermissionDenied` chief among them — see
/// `wait_for_vsock_ready`'s doc) is a condition that will never clear by
/// itself; surface it instead of retrying blindly. Pulled out as a pure
/// function so this specific classification — the actual fix, distinct from
/// everything else `handshake_once` does — is unit-testable without a real
/// socket.
fn is_transient_connect_error(kind: std::io::ErrorKind) -> bool {
    matches!(
        kind,
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
    )
}

async fn handshake_once(vsock_socket: &Path, port: u32) -> HandshakeAttempt {
    let mut stream = match tokio::net::UnixStream::connect(vsock_socket).await {
        Ok(stream) => stream,
        Err(e) if is_transient_connect_error(e.kind()) => return HandshakeAttempt::NotYet,
        Err(e) => return HandshakeAttempt::HardError(e),
    };
    // Past the `connect()` permission check: a failure writing to or reading
    // from an already-accepted connection is a timing race (guest-agent
    // accepted but isn't ready to speak yet), not a permission problem, so
    // these stay in the "keep retrying" bucket.
    if stream
        .write_all(format!("CONNECT {port}\n").as_bytes())
        .await
        .is_err()
    {
        return HandshakeAttempt::NotYet;
    }
    let mut buf = [0u8; 32];
    let Ok(n) = stream.read(&mut buf).await else {
        return HandshakeAttempt::NotYet;
    };
    if buf[..n].starts_with(b"OK") {
        HandshakeAttempt::Ready
    } else {
        HandshakeAttempt::NotYet
    }
}

/// The last few lines of a VM's serial console log, for attaching to a boot
/// failure — the single most useful debugging string when cloud-hypervisor or
/// the guest kernel misbehaves. Never *fails* (always returns some `String`,
/// there is no `Result` for a caller to unwrap) — but unlike an earlier
/// version of this function, a read failure is not silently folded into "the
/// log is empty": the two are distinguishable in the returned text, because
/// they mean very different things to whoever reads the resulting error
/// (guest wrote nothing vs. the worker couldn't get at what it wrote).
async fn console_log_tail(path: &Path) -> String {
    match tokio::fs::read_to_string(path).await {
        Ok(contents) => {
            let mut lines: Vec<&str> = contents.lines().rev().take(40).collect();
            lines.reverse();
            lines.join("\n")
        }
        Err(e) => format!("(could not read {}: {e})", path.display()),
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

/// Create (idempotently) and enforce the Step 8 permission layout for a
/// tenant's directory:
///
/// - `tenants/` itself: **`0701`** (owner `rwx`, other `--x`) — corrected
///   from an initially-planned `0700`. Reaching `tenants/<T>/net.sock`
///   needs search (`x`) permission on *every* ancestor directory the path
///   crosses, not just the immediate parent — `0700` blocked the tenant's
///   own dropped-privilege `passt`/`cloud-hypervisor` from ever getting
///   past this directory at all, regardless of how permissive
///   `tenants/<T>/` itself was. Found by deploying: fixing `tenants/<T>/`
///   below (from `0711` to `1703`) alone didn't fix `passt`'s
///   `Failed to bind UNIX domain socket: Permission denied` — this
///   ancestor was still in the way. Still no `r`, so `tenants/` itself
///   can't be *listed* — a subdirectory has to already be known by exact
///   name to be reached, which every legitimate caller already does (the
///   worker passes the tenant's own directory path directly).
/// - `tenants/<tenant>/`: `1703` (sticky + owner `rwx` + other `-wx`, no
///   group), owned by the worker's own uid. Corrected from an earlier `0711`
///   (execute-only for "other") that looked right but wasn't: `passt` and
///   `cloud-hypervisor` run as the tenant's *dropped* uid — "other" relative
///   to this directory's owner (the worker, uid 0) — and they don't just
///   *open* an existing `store.img`/`vsock.sock`/`net.sock`, they *create*
///   those files themselves (post-privilege-drop, precisely so no `chown`
///   is needed — see `drop_privileges_and_maybe_create_store_img`). Creating
///   a directory entry needs directory *write*, not just search — found by
///   deploying this and watching `passt` never create its socket at all,
///   `EACCES` swallowed into a bare 30s timeout with no denial logged
///   anywhere obvious. Still no `r`: no listing, so a path has to already be
///   known, not discoverable. The sticky bit is what keeps this from being
///   the naive "just make it world-writable" mistake: it restricts
///   unlink/rename inside the directory to the *file's own owner* (or the
///   directory's owner), even though the directory itself now grants write
///   more broadly — the same mechanism `/tmp` uses, and for the same
///   reason: a broadly-writable directory without it would let any other
///   uid that already knows this tenant's exact path delete or rename its
///   `store.img`. The worker — which owns the directory itself — can still
///   always evict `store.img` regardless of which subuid ends up owning it,
///   since directory-owner is one of the sticky bit's permitted deleters.
///
/// Both permissions are re-applied on every call, not just on first
/// creation, so a manual change on disk between worker runs can't quietly
/// widen access.
async fn prepare_tenant_dir(state_dir: &Path, tenant: &TenantId) -> eyre::Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let tenants_dir = state_dir.join("tenants");
    tokio::fs::create_dir_all(&tenants_dir)
        .await
        .wrap_err_with(|| format!("creating {}", tenants_dir.display()))?;
    tokio::fs::set_permissions(&tenants_dir, std::fs::Permissions::from_mode(0o701))
        .await
        .wrap_err_with(|| format!("chmod 0701 {}", tenants_dir.display()))?;

    // `TenantId::from_wire` already restricts this to `[a-z0-9-]` — no `/`,
    // no `..` — so joining it directly cannot escape `tenants_dir`. That
    // invariant is load-bearing here, not just convenient.
    let tenant_dir = tenants_dir.join(tenant.as_str());
    tokio::fs::create_dir_all(&tenant_dir)
        .await
        .wrap_err_with(|| format!("creating {}", tenant_dir.display()))?;
    tokio::fs::set_permissions(&tenant_dir, std::fs::Permissions::from_mode(0o1703))
        .await
        .wrap_err_with(|| format!("chmod 1703 {}", tenant_dir.display()))?;

    Ok(tenant_dir)
}

/// Create `path` as a sparse file of `size_mb` if it doesn't already exist,
/// owned by the caller's own uid. Used only by the test fake now (Step 8
/// moved the real launcher's creation into a `pre_exec` hook, after the
/// privilege drop, so the image is owned by the tenant's uid instead — see
/// `drop_privileges_and_maybe_create_store_img`) — kept as a real,
/// independently useful helper rather than inlined into the fake, so its own
/// sparseness/idempotency behavior stays covered by a direct test. A no-op —
/// not a truncate — if the file exists: reuse is the entire point. Returns
/// whether it was just created.
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
    /// Whether *this boot* was a `FRESH` `store.img` creation, as opposed to
    /// mounting one that already existed — PLAN.md Phase 18's ENOSPC
    /// recovery only wipes-and-retries on a `REUSE` boot (nothing to gain
    /// from wiping an already-empty disk), so the job loop needs to know
    /// which one it got.
    fresh: bool,
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
    /// Step 8: each tenant's uid/gid for `cloud-hypervisor`/`passt`. Same
    /// lifetime as `keys` — see [`UidAllocator`]'s doc for why that's the
    /// right lifetime rather than something persisted.
    uids: UidAllocator,
}

impl VmPool<CloudHypervisorLauncher> {
    pub fn new(config: VmConfig) -> eyre::Result<Self> {
        let launcher = CloudHypervisorLauncher {
            config: config.clone(),
        };
        Ok(VmPool {
            config,
            launcher,
            warm: None,
            keys: HashMap::new(),
            uids: UidAllocator::new()?,
        })
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
            // Not `UidAllocator::new()`: this fake exists to test the
            // warm-VM reuse/evict decision, not namespace-bound handling,
            // and reading the real `/proc/self/uid_map` here made these
            // tests fail specifically inside the Nix build sandbox (a
            // single-uid user namespace) — see `UidAllocator::for_test`'s
            // doc.
            uids: UidAllocator::for_test(100_000),
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
                    fresh: warm.fresh,
                });
            }
            // Either a different tenant, or the same tenant's VM died on its
            // own between jobs — either way, not reusable.
            self.evict().await;
        }

        // Step 8: (re-)enforce the tenant directory's permission layout
        // before anything else touches it. `fresh` is now an existence
        // check only — creation moves into the launcher, after the
        // privilege drop, so `store.img` ends up owned by the tenant's uid
        // with no `chown(2)` (see `drop_privileges_and_maybe_create_store_img`).
        let tenant_dir = prepare_tenant_dir(&self.config.state_dir, tenant).await?;
        debug_assert_eq!(tenant_dir.join("store.img"), store_img);
        let fresh = tokio::fs::metadata(&store_img).await.is_err();

        let vsock_socket = tenant_dir.join("vsock.sock");
        let console_log = tenant_dir.join("console.log");
        // A stale socket file from a previous, uncleanly-terminated VM would
        // otherwise make the readiness poll below dial a dead socket.
        let _ = tokio::fs::remove_file(&vsock_socket).await;

        let (uid, gid) = self.uids.allocate(tenant)?;
        let identity = VmIdentity { uid, gid };

        tracing::info!(%tenant, store_img = %store_img.display(), uid = uid.as_raw(), "booting VM");
        let vm = self
            .launcher
            .boot(
                tenant,
                &store_img,
                &vsock_socket,
                &console_log,
                identity,
                fresh,
            )
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
            fresh,
        });

        Ok(VmHandle {
            tenant: tenant.clone(),
            vsock_socket,
            guest_port: NIX_DAEMON_PORT,
            store_img,
            fresh,
        })
    }

    /// PLAN.md Phase 18's ENOSPC-on-`REUSE` recovery: evicts the current warm
    /// VM, deletes its `store.img` outright, then re-runs `ensure_vm_for` for
    /// the same tenant — which will see the file gone, compute `fresh = true`,
    /// and reuse every existing boot/`push_key`/`mkfs.ext4` code path
    /// unchanged. Callers are expected to have already checked
    /// `!handle.fresh` (wiping an already-empty disk has nothing to gain) —
    /// this method doesn't re-check, so it can also serve a future caller
    /// that wants an unconditional wipe.
    pub async fn wipe_and_reboot(&mut self, tenant: &TenantId) -> eyre::Result<VmHandle> {
        self.evict().await;
        let store_img = store_img_path(&self.config, tenant);
        wipe_store_image(&store_img).await?;
        self.ensure_vm_for(tenant).await
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
            store_img: &Path,
            vsock_socket: &Path,
            console_log: &Path,
            _identity: VmIdentity,
            fresh: bool,
        ) -> eyre::Result<LaunchedVm> {
            self.boots.fetch_add(1, Ordering::SeqCst);
            if fresh {
                // Mirrors what the real launcher's `pre_exec` hook does
                // after dropping privilege (materializing the file), so the
                // fresh/reuse bookkeeping these tests assert on stays honest
                // across repeated `ensure_vm_for` calls — this fake doesn't
                // exercise the privilege-drop machinery itself, that's not
                // what the reuse/evict decision under test is about.
                create_store_img_if_absent(store_img, 1).await?;
            }
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
            probe_cid: 4,
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

    /// The actual fix for the Step 8 permission regression (PLAN.md Phase
    /// 13's status note): a connect error that will never clear on its own
    /// (`PermissionDenied` chief among them) must not be classified the same
    /// as "socket not up yet," or it silently burns the full boot timeout
    /// instead of failing fast with a diagnosable error.
    #[test]
    fn permission_denied_is_not_a_transient_connect_error() {
        use std::io::ErrorKind;
        assert!(is_transient_connect_error(ErrorKind::NotFound));
        assert!(is_transient_connect_error(ErrorKind::ConnectionRefused));
        assert!(!is_transient_connect_error(ErrorKind::PermissionDenied));
        assert!(!is_transient_connect_error(ErrorKind::Other));
    }

    // PLAN.md Phase 18

    #[test]
    fn parse_status_reply_every_known_state() {
        assert_eq!(
            parse_status_reply(b"OK NONE\n").unwrap(),
            GuestFailureStatus::None
        );
        assert_eq!(
            parse_status_reply(b"OK OOM BUILDER\n").unwrap(),
            GuestFailureStatus::OutOfMemory {
                builder_victim: true
            }
        );
        assert_eq!(
            parse_status_reply(b"OK OOM OTHER\n").unwrap(),
            GuestFailureStatus::OutOfMemory {
                builder_victim: false
            }
        );
        assert_eq!(
            parse_status_reply(b"OK ENOSPC\n").unwrap(),
            GuestFailureStatus::DiskFull
        );
    }

    #[test]
    fn parse_status_reply_rejects_unrecognised_and_error_replies() {
        assert!(parse_status_reply(b"OK WAT\n").is_err());
        assert!(parse_status_reply(b"ERR eBPF detection not available\n").is_err());
    }

    #[tokio::test]
    async fn wipe_and_reboot_deletes_and_recreates_with_fresh_true() {
        let dir = tempfile::tempdir().unwrap();
        let launcher = FakeLauncher::default();
        let mut pool = VmPool::with_launcher(test_config(dir.path()), launcher.clone());
        let tenant = TenantId::from_wire("tenant-a").unwrap();

        let first = pool.ensure_vm_for(&tenant).await.unwrap();
        assert!(first.fresh, "first boot for a tenant is always FRESH");
        assert!(tokio::fs::try_exists(&first.store_img).await.unwrap());

        let rebooted = pool.wipe_and_reboot(&tenant).await.unwrap();
        assert!(
            rebooted.fresh,
            "wipe_and_reboot must see the deleted image and boot FRESH again"
        );
        assert!(tokio::fs::try_exists(&rebooted.store_img).await.unwrap());
        assert_eq!(
            launcher.boot_count(),
            2,
            "wipe_and_reboot evicts the old VM and boots exactly one new one"
        );
    }

    #[tokio::test]
    async fn warm_vm_reuse_reports_the_boot_that_actually_happened() {
        let dir = tempfile::tempdir().unwrap();
        let launcher = FakeLauncher::default();
        let mut pool = VmPool::with_launcher(test_config(dir.path()), launcher.clone());
        let tenant = TenantId::from_wire("tenant-a").unwrap();

        let first = pool.ensure_vm_for(&tenant).await.unwrap();
        assert!(first.fresh);
        let reused = pool.ensure_vm_for(&tenant).await.unwrap();
        assert!(
            reused.fresh,
            "reusing a still-warm VM must report the boot that actually happened (FRESH, since \
             this tenant's very first boot created store.img), not silently flip to REUSE just \
             because no new boot happened on this call"
        );
    }
}
