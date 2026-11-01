//! PLAN.md Phase 18: diagnostic payloads for `nix/vm-oom-test.nix` and
//! `nix/vm-enospc-test.nix` -- these VM-level tests need something inside
//! the guest that reliably runs itself out of memory or disk, and this
//! guest's minimal initrd has no shell/coreutils for a builder to do that
//! with at all (see `nix/vm-build-test.nix`'s own doc comment on the same
//! gap for a real build). Rather than adding a whole new binary to the
//! initrd, `guest-agent`'s own binary doubles as both: `main()` recognizes
//! a `--diag-*` argv and runs one of these instead of the real init/PID-1
//! logic, so `/init` (`guest-agent`'s own path in the guest, see
//! `nix/guest-vm.nix`) can be re-exec'd as a disposable child process.
//! Reached only via the `TRIGGER_OOM`/`TRIGGER_ENOSPC` control verbs
//! (`main.rs::dispatch_control`), themselves diagnostic-only -- a real
//! deployment never sends them, only the two VM tests do.

use std::io::Write;

/// Allocates and touches memory in a growing loop until something kills
/// this process -- the cgroup's own `memory.max` (`cgroup::setup`), once
/// this process's pid has been moved into the build cgroup by the
/// `TRIGGER_OOM` control-verb handler before it's spawned far enough along
/// to be a plausible victim. Diverges: there is no clean exit from this
/// path, only ever a `SIGKILL` from the OOM killer (or, if the cgroup limit
/// somehow doesn't apply, the guest's own real RAM running out).
pub fn oom_victim() -> ! {
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    loop {
        let mut chunk = vec![0u8; 16 * 1024 * 1024];
        // Touch every page, not just allocate the `Vec` -- `vec![0u8; n]`
        // alone can be satisfied by the allocator without the kernel ever
        // committing real physical pages (overcommit); writing a byte into
        // each 4 KiB page is what actually forces RSS to grow, which is
        // what the cgroup's `memory.max` accounts against.
        for byte in chunk.iter_mut().step_by(4096) {
            *byte = 1;
        }
        chunks.push(chunk);
    }
}

/// Writes to `path` in a growing loop, past available disk space, and
/// returns without ever calling `fsync`/`fdatasync`. Whether the write call
/// itself eventually returns `Err` (synchronous ENOSPC, caught by
/// `vfs_write_ret`'s kretprobe -- the common case on this guest's
/// ext4/kernel combination, found by booting) or every `write` call
/// "succeeds" right up until the process exits (the failure only ever
/// surfacing via background writeback, caught by `errseq_set`'s kprobe
/// instead) is deliberately not distinguished here: either way, one of the
/// eBPF hooks (`guest-agent-ebpf/src/main.rs`) is watching for it, not this
/// function's own return value.
pub fn fill_store(path: &str) {
    // The kernel's own background writeback thread only runs periodically
    // (`dirty_expire_centisecs`/`dirty_writeback_centisecs`, ~30s/~5s by
    // default) -- found by booting: a first version of this test wrote
    // past capacity and polled `STATUS?` for 10s straight without ever
    // seeing `ENOSPC`, because the dirty pages just sat in cache the whole
    // time, nowhere near hitting the `dirty_ratio` threshold that would
    // otherwise force early writeback on a VM this size. Tightening these
    // makes the kernel's *own* async flusher run promptly -- this is not
    // an `fsync()`/`fdatasync()` call of our own, which is the specific
    // thing this whole mechanism exists to work without.
    let _ = std::fs::write("/proc/sys/vm/dirty_writeback_centisecs", "20");
    let _ = std::fs::write("/proc/sys/vm/dirty_expire_centisecs", "20");

    let mut file = match std::fs::File::create(path) {
        Ok(f) => f,
        Err(err) => {
            eprintln!("guest-agent: diag fill_store: creating {path} failed: {err}");
            return;
        }
    };
    let buf = vec![0xABu8; 4 * 1024 * 1024];
    // A hard iteration cap, not an unbounded loop: on a filesystem that
    // somehow never returns an error (sparse allocation, unexpectedly large
    // disk), this still terminates rather than hanging the test forever.
    let mut written_mb = 0u64;
    let mut last_err = None;
    for _ in 0..4096 {
        match file.write_all(&buf) {
            Ok(()) => written_mb += 4,
            Err(err) => {
                last_err = Some(err);
                break;
            }
        }
    }
    eprintln!(
        "guest-agent: diag fill_store: wrote {written_mb} MiB to {path}, last_err={last_err:?}"
    );
    // No `file.sync_all()` / `fdatasync` call, and the plain `drop(file)`
    // below is a bare `close()` -- deliberately never surfacing whatever
    // the last writeback attempt's error was, the same way a real build
    // tool that never calls `fsync()` wouldn't either.
}
