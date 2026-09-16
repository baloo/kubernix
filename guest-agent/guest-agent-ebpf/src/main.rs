//! PLAN.md Phase 18: guest-kernel-side eBPF programs for resource-exhaustion
//! detection. Loaded and attached by `guest-agent`'s userspace side
//! (`guest-agent/src/ebpf.rs`) at startup, living for the guest's whole
//! lifetime; only the maps' contents are reset per-build (via the `RESET`
//! control verb), not the attachment itself.
//!
//! Two independent signals, matching PLAN.md's "two independent signals, not
//! one" decision:
//!
//! - [`oom_mark_victim`]: a tracepoint on `oom:mark_victim`, the exact
//!   structured event the OOM killer fires when it picks a victim. Paired
//!   with `guest-agent`'s own cgroup v2 scoping of `nix-daemon`'s build
//!   children (`guest-agent/src/cgroup.rs`) so a kill's `(pid, comm)` can be
//!   checked against that cgroup's membership userspace-side to decide
//!   builder-victim vs. non-builder-victim.
//! - ENOSPC, via **two** complementary hooks (found by booting: a real
//!   `write(2)`-until-full test showed the disk-full case is caught
//!   synchronously by ext4's own delayed-allocation reservation far more
//!   often than it hits the async writeback race this mechanism was
//!   originally designed around -- neither hook alone is the whole story):
//!   - [`vfs_write_ret`]: a `kretprobe` on `vfs_write`, catching a `write(2)`
//!     that returns `-ENOSPC` directly to its caller -- the common case on
//!     this guest's ext4/kernel combination, `errseq_set` alone would have
//!     missed entirely.
//!   - [`errseq_set`]: a kprobe on `errseq_set()`, which fires whenever the
//!     kernel *records* a writeback failure independent of whether any
//!     application ever calls `fsync()` -- the hook that closes the
//!     "`close()` swallows write errors" gap for whatever slips past
//!     write-time reservation (a genuine race, an I/O error, NFS, ...).
//!     Not `mapping_set_error()` itself, despite that being the function
//!     whose job this conceptually is: `mapping_set_error` is `static
//!     inline` in `<linux/pagemap.h>`, so it has no stable symbol to kprobe
//!     at all -- this kernel's own `System.map` shows only
//!     compiler-generated `mapping_set_error.part.0` clones, duplicated
//!     per-translation-unit at different addresses, found by booting and
//!     checking. `mapping_set_error`'s own body calls `errseq_set(eseq,
//!     err)` with the same error value whenever it actually has one to
//!     record -- a real, exported, stable symbol
//!     (`EXPORT_SYMBOL(errseq_set)` in `lib/errseq.c`) that serves the same
//!     purpose.
//!
//! Both write into tiny fixed-size `Array` maps rather than a ring/perf
//! buffer: there is nothing to stream here, just "did this happen since the
//! last reset" plus the one `(pid, comm)` needed for OOM attribution, so a
//! map userspace can poll with a plain lookup is simpler than wiring up an
//! async event channel for a signal this coarse.
//!
//! The tracepoint's exact field layout (offsets past the 8-byte common
//! tracepoint header) and the kprobe's argument index are hypotheses to
//! confirm against this kernel's own
//! `/sys/kernel/tracing/events/oom/mark_victim/format` by booting, the same
//! "found by booting" methodology `nix/guest-vm.nix` uses throughout.
#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{kprobe, kretprobe, map, tracepoint},
    maps::Array,
    programs::{ProbeContext, RetProbeContext, TracePointContext},
};

/// Set to the victim's pid whenever `oom:mark_victim` fires; 0 means "none
/// since the last `RESET`". `guest-agent`'s userspace side cross-references
/// this against the build cgroup's `cgroup.procs` membership to decide
/// builder-victim vs. non-builder-victim -- that decision lives entirely
/// userspace-side, not here, since cgroup membership can change out from
/// under a single eBPF program run and is far easier to get right in
/// ordinary Rust.
#[map]
static OOM_VICTIM_PID: Array<u32> = Array::with_max_entries(1, 0);

/// Set to 1 whenever `mapping_set_error()` is called with `-ENOSPC`; 0
/// means "none since the last `RESET`".
#[map]
static ENOSPC_FLAG: Array<u32> = Array::with_max_entries(1, 0);

/// Linux's `ENOSPC` errno value -- `mapping_set_error()`'s `error` argument
/// carries the kernel's own negative-errno convention (`-ENOSPC`).
const ENOSPC: i32 = 28;

/// The `oom:mark_victim` tracepoint fires with the standard 8-byte common
/// tracepoint header (`common_type`/`common_flags`/`common_preempt_count`/
/// `common_pid`, 2+1+1+4 bytes) followed by this event's own fields, whose
/// first is the victim's own `pid` (a plain `int`). Confirmed against this
/// kernel's own tracefs format at boot time, not derived from generic
/// documentation alone.
const TRACEPOINT_COMMON_HEADER_LEN: usize = 8;

#[tracepoint]
pub fn oom_mark_victim(ctx: TracePointContext) -> u32 {
    match try_oom_mark_victim(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_oom_mark_victim(ctx: &TracePointContext) -> Result<u32, u32> {
    let pid: u32 = unsafe {
        ctx.read_at(TRACEPOINT_COMMON_HEADER_LEN)
            .map_err(|_| 1u32)?
    };
    if let Some(slot) = OOM_VICTIM_PID.get_ptr_mut(0) {
        unsafe { *slot = pid };
    }
    Ok(0)
}

/// A `kretprobe` on `vfs_write`'s return value, complementing the
/// `errseq_set` kprobe above: found by booting, ext4's own delayed-
/// allocation reservation (`ext4_da_reserve_space`) turns out to catch a
/// disk-full write *synchronously* far more often in practice than the
/// async writeback race `errseq_set` targets -- a real `write(2)` call
/// returning `-ENOSPC` directly to the caller, never reaching
/// `errseq_set` at all, since the block allocation never gets deferred to
/// writeback in the first place. `errseq_set` alone would miss this common
/// case entirely; this closes it, at the cost of running on every write
/// syscall in the guest -- cheap, since it's a single integer comparison.
#[kretprobe]
pub fn vfs_write_ret(ctx: RetProbeContext) -> u32 {
    match try_vfs_write_ret(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_vfs_write_ret(ctx: &RetProbeContext) -> Result<u32, u32> {
    let ret: i64 = ctx.ret::<i64>();
    if ret == -(ENOSPC as i64) {
        if let Some(slot) = ENOSPC_FLAG.get_ptr_mut(0) {
            unsafe { *slot = 1 };
        }
    }
    Ok(0)
}

#[kprobe]
pub fn errseq_set(ctx: ProbeContext) -> u32 {
    match try_errseq_set(&ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_errseq_set(ctx: &ProbeContext) -> Result<u32, u32> {
    // `errseq_t errseq_set(errseq_t *eseq, int err)` -- the error code is
    // argument index 1 (0-indexed), a plain `int`.
    let error: i32 = ctx.arg(1).ok_or(1u32)?;
    if error == -ENOSPC {
        if let Some(slot) = ENOSPC_FLAG.get_ptr_mut(0) {
            unsafe { *slot = 1 };
        }
    }
    Ok(0)
}

// Required by the kernel's BPF_PROG_LOAD syscall (EINVAL without it --
// found by booting): every loaded program must declare a license, checked
// against which kernel helpers it's allowed to call. `aya-ebpf` doesn't
// supply a default -- the crate expects a program to declare its own.
#[unsafe(no_mangle)]
#[link_section = "license"]
pub static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
