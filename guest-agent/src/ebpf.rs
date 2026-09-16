//! PLAN.md Phase 18: userspace loader for `guest-agent-ebpf`'s two
//! programs. Loaded once at `guest-agent` startup, living for the guest's
//! whole lifetime -- only [`DetectionState::reset`] is per-build, driven by
//! the `RESET` control verb (`dispatch_control`), not the attachment
//! itself. See `guest-agent-ebpf/src/main.rs` for what each program does
//! and why its exact tracepoint field offset / kprobe argument index are
//! still hypotheses to confirm against this kernel's own tracefs format by
//! booting.

use std::sync::Arc;
use std::time::Duration;

use aya::maps::Array;
use aya::programs::{KProbe, TracePoint};
use eyre::{Context, Result};
use tokio::sync::Mutex;

/// Compiled by `nix/guest-agent-ebpf.nix`, embedded via `build.rs`.
static PROGRAM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/guest-agent-ebpf.elf"));

/// What [`DetectionState::status`] reports over the `STATUS?` control verb
/// -- see `worker/src/vm.rs::GuestFailureStatus`, its client-side mirror.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureStatus {
    None,
    OutOfMemory { builder_victim: bool },
    DiskFull,
}

/// How often the background poll task ([`DetectionState::setup`]) checks
/// `OOM_VICTIM_PID` for a new victim. Deliberately tight: the victim's own
/// cgroup membership (`cgroup::is_in_build_cgroup`) has to be checked
/// *before* the killed process is reaped and drops out of
/// `build/cgroup.procs` -- found by booting a real `TRIGGER_OOM` and seeing
/// `STATUS?`, queried only afterward (at the old, much coarser polling
/// interval `worker/src/vm.rs::query_status` itself uses), report `OOM
/// OTHER` for a victim the kernel's own OOM-kill log line confirmed was
/// inside `/build`. Checking membership right as the tracepoint's pid shows
/// up, rather than lazily whenever a client happens to ask, is what
/// actually closes that race.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Holds the loaded `aya::Ebpf` instance (keeping the programs attached for
/// as long as this lives), the shared handle the background poll task and
/// [`DetectionState::reset`] both write through, and the poll task's own
/// cached attribution decision.
pub struct DetectionState {
    // Never read directly again after `setup()`; kept alive only so the
    // attached programs stay attached (dropping an `Ebpf` detaches
    // everything it loaded).
    _ebpf: aya::Ebpf,
    oom_victim_pid: Arc<Mutex<Array<aya::maps::MapData, u32>>>,
    enospc_flag: Array<aya::maps::MapData, u32>,
    /// `None` until the background poll task has resolved a victim pid's
    /// cgroup membership; `Some(builder_victim)` after. This, not a live
    /// re-check of `OOM_VICTIM_PID` at query time, is what [`Self::status`]
    /// actually reports -- see [`POLL_INTERVAL`]'s doc for why.
    oom_attribution: Arc<Mutex<Option<bool>>>,
}

impl DetectionState {
    /// Loads `PROGRAM`, attaches both the `oom:mark_victim` tracepoint and
    /// the `errseq_set()` kprobe, and spawns the background poll task that
    /// resolves a victim pid's cgroup membership as soon as it appears.
    /// Failure here is treated as fatal by the caller (`main`) the same way
    /// a failed vsock listener bind would be -- Phase 18's whole mechanism
    /// is inert without this, so a guest that can't load it should fail
    /// loudly at boot rather than silently never detecting anything.
    pub fn setup() -> Result<Self> {
        let mut ebpf = aya::Ebpf::load(PROGRAM).wrap_err("loading guest-agent-ebpf bytecode")?;

        let tracepoint: &mut TracePoint = ebpf
            .program_mut("oom_mark_victim")
            .ok_or_else(|| eyre::eyre!("oom_mark_victim program missing from bytecode"))?
            .try_into()
            .wrap_err("oom_mark_victim is not a tracepoint program")?;
        tracepoint.load().wrap_err("loading oom_mark_victim")?;
        tracepoint
            .attach("oom", "mark_victim")
            .wrap_err("attaching oom_mark_victim to oom:mark_victim")?;

        let kprobe: &mut KProbe = ebpf
            .program_mut("errseq_set")
            .ok_or_else(|| eyre::eyre!("errseq_set program missing from bytecode"))?
            .try_into()
            .wrap_err("errseq_set is not a kprobe program")?;
        kprobe.load().wrap_err("loading errseq_set kprobe")?;
        kprobe
            .attach("errseq_set", 0)
            .wrap_err("attaching errseq_set kprobe")?;

        // Complements the errseq_set kprobe above -- see
        // `guest-agent-ebpf/src/main.rs`'s module doc for why a real
        // disk-full write is caught synchronously (here) far more often in
        // practice than via the async writeback race errseq_set targets.
        let vfs_write_ret: &mut KProbe = ebpf
            .program_mut("vfs_write_ret")
            .ok_or_else(|| eyre::eyre!("vfs_write_ret program missing from bytecode"))?
            .try_into()
            .wrap_err("vfs_write_ret is not a kprobe program")?;
        vfs_write_ret
            .load()
            .wrap_err("loading vfs_write_ret kretprobe")?;
        vfs_write_ret
            .attach("vfs_write", 0)
            .wrap_err("attaching vfs_write_ret kretprobe")?;

        let oom_victim_pid: Array<_, u32> = Array::try_from(
            ebpf.take_map("OOM_VICTIM_PID")
                .ok_or_else(|| eyre::eyre!("OOM_VICTIM_PID map missing from bytecode"))?,
        )
        .wrap_err("opening OOM_VICTIM_PID map")?;
        let enospc_flag: Array<_, u32> = Array::try_from(
            ebpf.take_map("ENOSPC_FLAG")
                .ok_or_else(|| eyre::eyre!("ENOSPC_FLAG map missing from bytecode"))?,
        )
        .wrap_err("opening ENOSPC_FLAG map")?;

        let oom_victim_pid = Arc::new(Mutex::new(oom_victim_pid));
        let oom_attribution: Arc<Mutex<Option<bool>>> = Arc::new(Mutex::new(None));
        spawn_oom_attribution_poller(oom_victim_pid.clone(), oom_attribution.clone());

        eprintln!("guest-agent: eBPF resource-exhaustion detection attached");
        Ok(Self {
            _ebpf: ebpf,
            oom_victim_pid,
            enospc_flag,
            oom_attribution,
        })
    }

    /// Reports whatever happened since the last [`Self::reset`] -- the
    /// `RESET` control verb the worker sends right before opening a new
    /// build's daemon-protocol connection, scoping detection to that one
    /// build rather than the VM's whole lifetime.
    pub async fn status(&self) -> FailureStatus {
        if let Some(builder_victim) = *self.oom_attribution.lock().await {
            return FailureStatus::OutOfMemory { builder_victim };
        }
        if self.enospc_flag.get(&0, 0).unwrap_or(0) != 0 {
            return FailureStatus::DiskFull;
        }
        FailureStatus::None
    }

    /// Clears the map, the cached attribution, and the ENOSPC flag -- back
    /// to "nothing since the last reset". Array maps have no `delete`;
    /// overwriting index 0 with 0 is the reset.
    pub async fn reset(&mut self) -> Result<()> {
        self.oom_victim_pid
            .lock()
            .await
            .set(0, 0, 0)
            .wrap_err("resetting OOM_VICTIM_PID")?;
        *self.oom_attribution.lock().await = None;
        self.enospc_flag
            .set(0, 0, 0)
            .wrap_err("resetting ENOSPC_FLAG")?;
        Ok(())
    }
}

/// Polls `oom_victim_pid` every [`POLL_INTERVAL`] and, the moment a new
/// nonzero pid appears, immediately resolves its cgroup membership and
/// caches the decision into `oom_attribution` -- see [`POLL_INTERVAL`]'s
/// doc for why this can't instead happen lazily whenever `status()` is
/// called. Runs for the guest's whole lifetime, alongside the attached eBPF
/// programs themselves.
///
/// `last_seen` is a plain local, not shared/reset-aware beyond "the map
/// read 0 in between" -- a `RESET` writes the map back to 0, which this
/// loop already treats as "next nonzero pid is new" regardless of what that
/// pid number turns out to be. The one gap this doesn't close: two
/// consecutive OOM victims (across a `RESET` in between) that happen to
/// share the exact same pid number would only be attributed once. Accepted
/// as a known, narrow limitation rather than tracked/reset explicitly --
/// pid reuse landing on the same number twice inside one VM's short
/// lifetime is exceedingly unlikely.
fn spawn_oom_attribution_poller(
    oom_victim_pid: Arc<Mutex<Array<aya::maps::MapData, u32>>>,
    oom_attribution: Arc<Mutex<Option<bool>>>,
) {
    tokio::spawn(async move {
        let mut last_seen: u32 = 0;
        loop {
            let pid = { oom_victim_pid.lock().await.get(&0, 0).unwrap_or(0) };
            if pid == 0 {
                last_seen = 0;
            } else if pid != last_seen {
                last_seen = pid;
                let builder_victim = crate::cgroup::is_in_build_cgroup(pid).await;
                *oom_attribution.lock().await = Some(builder_victim);
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    });
}
