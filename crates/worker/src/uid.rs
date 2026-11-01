//! Phase 15 Step 8: per-tenant uid allocation for `cloud-hypervisor`/`passt`.
//!
//! Every tenant's VM processes run under their own uid/gid, disjoint from
//! the worker's own and from every other tenant's. This closes two things a
//! shared uid would leave open: a compromised `cloud-hypervisor`/`passt`
//! process reaching another tenant's VM process or `store.img` (ordinary
//! Unix isolation instead of none), and — the more serious case — the same
//! process `ptrace`-ing the *worker*, which holds every currently-live
//! tenant's at-rest encryption key in `VmPool::keys`. A same-uid `ptrace`
//! needs no capability at all, so a distinct uid is what closes it (see
//! `prctl::set_dumpable` in `main.rs` for the uid-independent backstop).
//!
//! Allocation is sequential with recycling, not hashed — this is in-memory,
//! per-worker-process state with exactly the same lifetime as
//! `VmPool::keys`: assigned the first time a tenant's `store.img` is
//! created, freed back to the pool when that image is evicted from disk,
//! and reset to empty on every worker restart (consistent with
//! `wipe_orphaned_store_images` already deleting every leftover image at
//! startup — there is nothing left on disk for a reused uid to protect).
//! That bounds the working set to "tenants with a currently-live
//! `store.img` on this node," not "every tenant this process has ever
//! seen," so there is no collision to worry about the way a hashed scheme
//! would have.

use std::collections::HashMap;

use eyre::{Context as _, eyre};
use kubernix_types::TenantId;
use nix::unistd::{Gid, Uid};

/// First uid handed out. Chosen clear of the worker's own uid and of any
/// low system uid — the low end is not "free" just because nothing else on
/// a minimal container image uses it.
const UID_BASE: u32 = 2000;

/// Upper bound applied even when the host's own uid namespace is
/// unrestricted (see [`UidAllocator::new`]) — the conventional size of a
/// per-pod/rootless-container subordinate-id slice (Docker's default
/// `/etc/subuid` allocation, kubelet/containerd's default
/// `UserNamespacesSupport` length). The real working set here is far
/// smaller than this, so the cap costs nothing and is free insurance if
/// this pod ever runs under `hostUsers: false`.
const UID_SOFT_CAP: u32 = 65536;

/// Sequential, recycling uid/gid allocator, one per [`crate::vm::VmPool`].
/// Hands out the same numeric value for both uid and gid — "one group per
/// tenant" is simplest and nothing here needs them to differ.
pub struct UidAllocator {
    /// Exclusive upper bound a freshly allocated (non-recycled) uid must
    /// stay under — `UID_BASE.max(namespace bound).min(UID_SOFT_CAP)`,
    /// computed once at construction.
    ceiling: u32,
    next: u32,
    free: Vec<u32>,
    assigned: HashMap<TenantId, u32>,
}

impl UidAllocator {
    /// Reads `/proc/self/uid_map` to bound the allocator by what this
    /// process's own uid namespace actually maps, rather than assuming.
    /// Today (no `hostUsers: false` anywhere in `charts/kubernix/`, plain
    /// host uid namespace) that reads back unrestricted and `UID_SOFT_CAP`
    /// applies as-is; if pod-level user namespaces are ever turned on for
    /// this workload, this adapts to the pod's real subordinate range
    /// instead of `setuid` failing with `EINVAL` the day someone flips that
    /// pod setting without touching worker code.
    pub fn new() -> eyre::Result<Self> {
        let contents =
            std::fs::read_to_string("/proc/self/uid_map").wrap_err("reading /proc/self/uid_map")?;
        let namespace_bound = parse_uid_map_bound(&contents)
            .ok_or_else(|| eyre!("could not parse /proc/self/uid_map: {contents:?}"))?;
        let ceiling = UID_SOFT_CAP.min(namespace_bound);
        if ceiling <= UID_BASE {
            return Err(eyre!(
                "this process's uid namespace only maps uids up to {namespace_bound}, \
                 leaving no room above UID_BASE ({UID_BASE}) for per-tenant VM uids"
            ));
        }
        Ok(UidAllocator {
            ceiling,
            next: UID_BASE,
            free: Vec::new(),
            assigned: HashMap::new(),
        })
    }

    /// The uid/gid for `tenant`, allocating one if this is the first time
    /// this process has seen it. Stable for the life of this allocator
    /// (i.e. this worker process), matching `VmPool::keys`.
    pub fn allocate(&mut self, tenant: &TenantId) -> eyre::Result<(Uid, Gid)> {
        if let Some(&raw) = self.assigned.get(tenant) {
            return Ok((Uid::from_raw(raw), Gid::from_raw(raw)));
        }
        let raw = if let Some(recycled) = self.free.pop() {
            recycled
        } else {
            let raw = self.next;
            if raw >= self.ceiling {
                return Err(eyre!(
                    "uid allocator exhausted its range ({UID_BASE}..{}) with no freed uid to \
                     recycle — {} tenants currently hold a live store.img on this worker",
                    self.ceiling,
                    self.assigned.len(),
                ));
            }
            self.next += 1;
            raw
        };
        self.assigned.insert(tenant.clone(), raw);
        Ok((Uid::from_raw(raw), Gid::from_raw(raw)))
    }

    /// Test-only constructor that skips `/proc/self/uid_map` entirely.
    /// `VmPool`'s own tests (`vm.rs`) exercise the warm-VM reuse/evict
    /// decision, not this allocator's namespace-bound handling — they
    /// shouldn't depend on the real host's (or, worse, the *build
    /// sandbox's*) uid namespace to pass. That dependency was a real bug,
    /// not a hypothetical one: `nix-build`'s own sandbox runs each builder
    /// in a single-uid user namespace (`/proc/self/uid_map` reporting a
    /// one-uid range), which made `VmPool`'s tests fail specifically
    /// inside the Nix build sandbox while passing everywhere else — an
    /// environment difference that has nothing to do with the Kubernetes
    /// `hostUsers` question this module's real constructor cares about.
    #[cfg(test)]
    pub(crate) fn for_test(ceiling: u32) -> Self {
        UidAllocator {
            ceiling,
            next: UID_BASE,
            free: Vec::new(),
            assigned: HashMap::new(),
        }
    }

    /// Release `tenant`'s uid back to the pool. Call this when — and only
    /// when — `tenant`'s `store.img` has actually been deleted from disk
    /// (LRU eviction); anything still on disk under that uid must keep its
    /// uid reserved, or a later tenant assigned the same recycled number
    /// could open it.
    pub fn release(&mut self, tenant: &TenantId) {
        if let Some(raw) = self.assigned.remove(tenant) {
            self.free.push(raw);
        }
    }
}

/// Sum, across every `inside_start outside_start count` line, of
/// `inside_start + count` — i.e. one past the highest uid this process's own
/// namespace can address — minus 1. A process in the initial (host) uid
/// namespace reads back a single line, `0 0 4294967295`. Pulled out as a
/// pure function so the parsing (the part that can actually be wrong) is
/// unit-tested without needing to fake `/proc/self/uid_map` on disk.
fn parse_uid_map_bound(contents: &str) -> Option<u32> {
    contents
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let inside_start: u64 = fields.next()?.parse().ok()?;
            let _outside_start: u64 = fields.next()?.parse().ok()?;
            let count: u64 = fields.next()?.parse().ok()?;
            Some(inside_start + count)
        })
        .max()
        .map(|bound| bound.min(u64::from(u32::MAX)) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_unrestricted_host_namespace_mapping() {
        assert_eq!(
            parse_uid_map_bound("         0          0 4294967295\n"),
            Some(u32::MAX)
        );
    }

    #[test]
    fn parses_a_restricted_container_namespace_mapping() {
        // e.g. `hostUsers: false`-style: inside uids 0..65536 map to some
        // subordinate range on the host — the *inside* bound is what this
        // allocator cares about, not the outside one.
        assert_eq!(
            parse_uid_map_bound("         0     100000      65536\n"),
            Some(65536)
        );
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(parse_uid_map_bound("not a uid map"), None);
    }

    fn tenant(name: &str) -> TenantId {
        TenantId::from_wire(name).unwrap()
    }

    fn allocator_with_ceiling(ceiling: u32) -> UidAllocator {
        UidAllocator::for_test(ceiling)
    }

    #[test]
    fn allocates_distinct_uids_and_is_stable_per_tenant() {
        let mut alloc = allocator_with_ceiling(UID_BASE + 10);
        let a = alloc.allocate(&tenant("alice")).unwrap();
        let b = alloc.allocate(&tenant("bob")).unwrap();
        assert_ne!(a, b);
        assert_eq!(alloc.allocate(&tenant("alice")).unwrap(), a);
    }

    #[test]
    fn recycles_a_freed_uid_before_bumping_the_counter() {
        let mut alloc = allocator_with_ceiling(UID_BASE + 1);
        let a = alloc.allocate(&tenant("alice")).unwrap();
        // Only one slot in this ceiling — a second distinct tenant can't be
        // allocated until alice's is freed.
        assert!(alloc.allocate(&tenant("bob")).is_err());
        alloc.release(&tenant("alice"));
        let b = alloc.allocate(&tenant("bob")).unwrap();
        assert_eq!(a, b, "the freed uid was recycled, not left idle");
    }

    #[test]
    fn errors_cleanly_once_the_range_is_exhausted() {
        let mut alloc = allocator_with_ceiling(UID_BASE + 1);
        alloc.allocate(&tenant("alice")).unwrap();
        let err = alloc.allocate(&tenant("bob")).unwrap_err();
        assert!(err.to_string().contains("exhausted"));
    }
}
