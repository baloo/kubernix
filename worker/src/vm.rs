//! Phase 15 Step 2: per-tenant `cloud-hypervisor` VM lifecycle.
//!
//! Owns exactly one warm VM per worker process (matching today's
//! one-job-at-a-time job loop in `main.rs`), keyed by [`TenantId`]. A job for
//! the same tenant as the currently warm VM reuses it; a job for a different
//! tenant evicts the old VM and boots a fresh one, attaching that tenant's
//! `store.img` — created empty on first use, otherwise reused untouched, so a
//! tenant's Nix store survives across warm-VM cycles as long as the image
//! stays on this worker's local disk.
//!
//! This module only proves the VM comes up and answers on its vsock socket.
//! It does not yet speak the Nix daemon protocol over that socket, or make
//! any build actually use it — `worker/src/serve.rs` and `upload.rs` still
//! shell out to `nix-store --serve` exactly as before. Wiring a real build
//! through the VM is Phase 15 Step 3; this module hands it a dialable
//! [`VmHandle`] to build against.
//!
//! Process spawning is behind the [`VmLauncher`] trait so the reuse/evict
//! decision in [`VmPool::ensure_vm_for`] — the actual thing this step needs
//! to prove — is unit-testable without `/dev/kvm`. [`CloudHypervisorLauncher`]
//! is the real implementation; tests supply a fake.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use eyre::{Context as _, eyre};
use kubernix_types::TenantId;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};

/// `guest-agent`'s fixed vsock port (`guest-agent/src/main.rs::NIX_DAEMON_PORT`).
/// Duplicated here rather than shared through a common crate: the guest and
/// the worker never build as one binary, and a port both sides agree on by
/// convention is exactly the kind of constant a comment (and, eventually,
/// Step 3's connection test) should pin down rather than paper over with an
/// artificial shared dependency.
const NIX_DAEMON_PORT: u32 = 620;

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
        let cloud_hypervisor = std::env::var("KUBERNIX_VM_CH_BIN")
            .unwrap_or_else(|_| "cloud-hypervisor".to_string());

        Ok(Some(VmConfig {
            state_dir: PathBuf::from(state_dir),
            kernel: PathBuf::from(kernel),
            initrd: PathBuf::from(initrd),
            cloud_hypervisor: PathBuf::from(cloud_hypervisor),
            vcpus: parse_env_or("KUBERNIX_VM_VCPUS", 1)?,
            memory_mb: parse_env_or("KUBERNIX_VM_MEMORY_MB", 512)?,
            store_img_size_mb: parse_env_or("KUBERNIX_VM_STORE_IMG_MB", 8192)?,
            boot_timeout: Duration::from_secs(parse_env_or(
                "KUBERNIX_VM_BOOT_TIMEOUT_SECS",
                30,
            )?),
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
#[allow(dead_code)]
pub struct VmHandle {
    pub tenant: TenantId,
    /// Host-side UNIX socket `cloud-hypervisor`'s `--vsock ...,socket=`
    /// exposes. Dialing it and sending `CONNECT <port>\n` reaches
    /// `guest_port` inside the guest — see `wait_for_vsock_ready`.
    pub vsock_socket: PathBuf,
    pub guest_port: u32,
    pub store_img: PathBuf,
}

/// A booted VM, as far as this module cares: a child process and the paths
/// used to reach and debug it. Ownership passes to [`VmLauncher::stop`] on
/// eviction. `console_log` is read only on a boot failure today
/// (`console_log_tail`); kept on a live `LaunchedVm` too since Step 3/4's
/// error paths will want it just as much.
#[allow(dead_code)]
pub struct LaunchedVm {
    child: Child,
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
        let mut child = Command::new(&self.config.cloud_hypervisor)
            .arg("--kernel")
            .arg(&self.config.kernel)
            .arg("--initramfs")
            .arg(&self.config.initrd)
            .arg("--cmdline")
            .arg("console=ttyS0 reboot=t panic=1")
            .arg("--cpus")
            .arg(format!("boot={}", self.config.vcpus))
            .arg("--memory")
            .arg(format!("size={}M", self.config.memory_mb))
            .arg("--vsock")
            .arg(format!(
                "cid={},socket={}",
                self.config.cid,
                vsock_socket.display()
            ))
            .arg("--disk")
            .arg(format!("path={}", store_img.display()))
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
            .wrap_err_with(|| {
                format!(
                    "spawning {} for tenant {tenant}",
                    self.config.cloud_hypervisor.display()
                )
            })?;

        match tokio::time::timeout(
            self.config.boot_timeout,
            wait_for_vsock_ready(vsock_socket, NIX_DAEMON_PORT),
        )
        .await
        {
            Ok(()) => Ok(LaunchedVm {
                child,
                vsock_socket: vsock_socket.to_path_buf(),
                console_log: console_log.to_path_buf(),
            }),
            Err(_elapsed) => {
                let _ = child.kill().await;
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
        let LaunchedVm { mut child, .. } = vm;
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
    }
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
/// A no-op — not a truncate — if it does: reuse is the entire point.
async fn create_store_img_if_absent(path: &Path, size_mb: u64) -> eyre::Result<()> {
    if tokio::fs::metadata(path).await.is_ok() {
        return Ok(());
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

        create_store_img_if_absent(&store_img, self.config.store_img_size_mb).await?;

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
    }

    impl FakeLauncher {
        fn boot_count(&self) -> usize {
            self.boots.load(Ordering::SeqCst)
        }
        fn stop_count(&self) -> usize {
            self.stops.load(Ordering::SeqCst)
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
    }

    fn test_config(state_dir: &Path) -> VmConfig {
        VmConfig {
            state_dir: state_dir.to_path_buf(),
            kernel: PathBuf::new(),
            initrd: PathBuf::new(),
            cloud_hypervisor: PathBuf::new(),
            vcpus: 1,
            memory_mb: 256,
            store_img_size_mb: 1,
            boot_timeout: Duration::from_secs(1),
            cid: 3,
        }
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

        create_store_img_if_absent(&path, 4).await.unwrap();
        let meta = tokio::fs::metadata(&path).await.unwrap();
        assert_eq!(meta.len(), 4 * 1024 * 1024);

        // A second call, with existing content, must not truncate it away —
        // that content is exactly what makes the image worth keeping.
        tokio::fs::write(&path, b"marker").await.unwrap();
        create_store_img_if_absent(&path, 4).await.unwrap();
        let content = tokio::fs::read(&path).await.unwrap();
        assert_eq!(content, b"marker");
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
}
