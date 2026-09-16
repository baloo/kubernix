//! PLAN.md Phase 18: userspace loader for `guest-agent-ebpf`'s two
//! programs. Loaded once at `guest-agent` startup, living for the guest's
//! whole lifetime -- only [`DetectionState::reset`] is per-build, driven by
//! the `RESET` control verb (`dispatch_control`), not the attachment
//! itself. See `guest-agent-ebpf/src/main.rs` for what each program does
//! and why its exact tracepoint field offset / kprobe argument index are
//! still hypotheses to confirm against this kernel's own tracefs format by
//! booting.

use aya::maps::Array;
use aya::programs::{KProbe, TracePoint};
use eyre::{Context, Result};

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

/// Holds the loaded `aya::Ebpf` instance (keeping the programs attached for
/// as long as this lives) plus handles onto its two maps.
pub struct DetectionState {
    // Never read directly again after `setup()`; kept alive only so the
    // attached programs stay attached (dropping an `Ebpf` detaches
    // everything it loaded).
    _ebpf: aya::Ebpf,
    oom_victim_pid: Array<aya::maps::MapData, u32>,
    enospc_flag: Array<aya::maps::MapData, u32>,
}

impl DetectionState {
    /// Loads `PROGRAM`, attaches both the `oom:mark_victim` tracepoint and
    /// the `mapping_set_error()` kprobe. Failure here is treated as fatal by
    /// the caller (`main`) the same way a failed vsock listener bind would
    /// be -- Phase 18's whole mechanism is inert without this, so a guest
    /// that can't load it should fail loudly at boot rather than silently
    /// never detecting anything.
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
            .program_mut("mapping_set_error")
            .ok_or_else(|| eyre::eyre!("mapping_set_error program missing from bytecode"))?
            .try_into()
            .wrap_err("mapping_set_error is not a kprobe program")?;
        kprobe.load().wrap_err("loading mapping_set_error kprobe")?;
        kprobe
            .attach("mapping_set_error", 0)
            .wrap_err("attaching mapping_set_error kprobe")?;

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

        eprintln!("guest-agent: eBPF resource-exhaustion detection attached");
        Ok(Self {
            _ebpf: ebpf,
            oom_victim_pid,
            enospc_flag,
        })
    }

    /// Reports whatever happened since the last [`Self::reset`] -- the
    /// `RESET` control verb the worker sends right before opening a new
    /// build's daemon-protocol connection, scoping detection to that one
    /// build rather than the VM's whole lifetime.
    pub async fn status(&self) -> FailureStatus {
        let victim_pid = self.oom_victim_pid.get(&0, 0).unwrap_or(0);
        if victim_pid != 0 {
            let builder_victim = crate::cgroup::is_in_build_cgroup(victim_pid).await;
            return FailureStatus::OutOfMemory { builder_victim };
        }
        if self.enospc_flag.get(&0, 0).unwrap_or(0) != 0 {
            return FailureStatus::DiskFull;
        }
        FailureStatus::None
    }

    /// Clears both maps back to "nothing since the last reset". Array maps
    /// have no `delete`; overwriting index 0 with 0 is the reset.
    pub fn reset(&mut self) -> Result<()> {
        self.oom_victim_pid
            .set(0, 0, 0)
            .wrap_err("resetting OOM_VICTIM_PID")?;
        self.enospc_flag
            .set(0, 0, 0)
            .wrap_err("resetting ENOSPC_FLAG")?;
        Ok(())
    }
}
