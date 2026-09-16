//! PLAN.md Phase 18, Step 0: eBPF build-toolchain spike.
//!
//! A single trivial tracepoint program, attached by `guest-agent`'s userspace
//! loader (`guest-agent/src/ebpf.rs`) at startup, whose only job is to prove
//! that this workspace can build and load real eBPF bytecode inside the
//! guest kernel before any OOM/ENOSPC-specific logic is written. It logs one
//! line (via `aya-log-ebpf`, read back by the userspace side) every time a
//! process calls `getpid(2)` -- a syscall guaranteed to exist and easy to
//! trigger manually from inside the guest to confirm the program actually
//! fires. Superseded by the real `oom:mark_victim`/`mapping_set_error` hooks
//! once this proves out; kept here as the toolchain's own regression check.
#![no_std]
#![no_main]

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::info;

#[tracepoint]
pub fn kubernix_probe_spike(ctx: TracePointContext) -> u32 {
    match try_kubernix_probe_spike(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_kubernix_probe_spike(ctx: &TracePointContext) -> Result<u32, u32> {
    info!(ctx, "kubernix eBPF toolchain spike: getpid observed");
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
