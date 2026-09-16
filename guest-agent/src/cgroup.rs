//! PLAN.md Phase 18: cgroup v2 memory scoping for `nix-daemon`'s build
//! children, paired with `ebpf::OomProbe`'s `oom:mark_victim` tracepoint --
//! a kill inside this cgroup is unambiguously build-related, since nothing
//! else in this guest is ever moved into it.
//!
//! `guest-agent` itself, and the top-level `nix-daemon` supervisory process
//! it spawns per connection, must never enter this cgroup: only what
//! `nix-daemon` forks for the actual build belongs here. This guest serves
//! exactly one connection/build at a time by construction (Phase 15), so
//! "move the whole per-connection `nix-daemon` instance's process tree in"
//! is the correct, simple approximation of "the builder" -- matching
//! PLAN.md's own phrasing, "nix-daemon (and everything it forks)".

use eyre::{Context, Result};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const BUILD_CGROUP: &str = "/sys/fs/cgroup/build";

/// Fraction of observed `/proc/meminfo` `MemTotal` handed to the build
/// cgroup's `memory.max` -- matches PLAN.md's "grant ~all available memory
/// unconditionally", with a fixed headroom for `guest-agent` and
/// `nix-daemon`'s own supervisory process (never scoped into this cgroup,
/// but still consuming real memory outside it).
const MEMORY_HEADROOM_FRACTION: f64 = 0.10;

/// Mounts the unified `cgroup2` hierarchy and creates the `build` leaf with
/// `memory.max` set once, at startup -- not re-derived per job, matching
/// PLAN.md's "no OOM memory-bump ladder" decision.
pub async fn setup() -> Result<()> {
    tokio::fs::create_dir_all(CGROUP_ROOT)
        .await
        .wrap_err_with(|| format!("creating {CGROUP_ROOT}"))?;
    crate::run("/bin/mount", &["-t", "cgroup2", "cgroup2", CGROUP_ROOT])
        .await
        .wrap_err("mounting cgroup2")?;

    // The memory controller has to be delegated to child cgroups explicitly
    // via the root's own `cgroup.subtree_control` before a leaf's own
    // `memory.max` does anything.
    tokio::fs::write(format!("{CGROUP_ROOT}/cgroup.subtree_control"), "+memory")
        .await
        .wrap_err("enabling the memory controller on the cgroup2 root")?;

    tokio::fs::create_dir_all(BUILD_CGROUP)
        .await
        .wrap_err_with(|| format!("creating {BUILD_CGROUP}"))?;

    let memory_max = build_cgroup_memory_max().unwrap_or(u64::MAX);
    tokio::fs::write(
        format!("{BUILD_CGROUP}/memory.max"),
        memory_max.to_string(),
    )
    .await
    .wrap_err("setting the build cgroup's memory.max")?;
    eprintln!("guest-agent: build cgroup ready, memory.max={memory_max}");
    Ok(())
}

/// `(1 - MEMORY_HEADROOM_FRACTION) * MemTotal`, read fresh from
/// `/proc/meminfo` -- independent of the worker/chart's own pod-level
/// memory arithmetic (Helm chart's `KUBERNIX_VM_MEMORY_MB` computation),
/// which is a different layer solving the same "leave headroom" problem for
/// a different budget (the pod's, not this cgroup leaf's).
fn build_cgroup_memory_max() -> Option<u64> {
    let contents = std::fs::read_to_string("/proc/meminfo").ok()?;
    let total_kb: u64 = contents
        .lines()
        .find(|l| l.starts_with("MemTotal:"))?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    let total_bytes = total_kb * 1024;
    Some(((total_bytes as f64) * (1.0 - MEMORY_HEADROOM_FRACTION)) as u64)
}

/// Moves `pid` (and, transitively, everything it has already forked or will
/// fork -- cgroup v2 membership is inherited across `fork`/`clone` unless a
/// child unshares its own cgroup namespace, which nothing here does) into
/// the build cgroup. Called right after `spawn_nix_daemon()` returns, before
/// any build request reaches it.
pub async fn move_into_build_cgroup(pid: u32) -> Result<()> {
    tokio::fs::write(format!("{BUILD_CGROUP}/cgroup.procs"), pid.to_string())
        .await
        .wrap_err_with(|| format!("moving pid {pid} into {BUILD_CGROUP}"))
}

/// Whether `pid` is (still) a member of the build cgroup -- used to decide
/// builder-victim vs. non-builder-victim attribution for an OOM kill.
pub async fn is_in_build_cgroup(pid: u32) -> bool {
    let Ok(contents) = tokio::fs::read_to_string(format!("{BUILD_CGROUP}/cgroup.procs")).await
    else {
        return false;
    };
    contents.lines().any(|line| line.trim() == pid.to_string())
}
