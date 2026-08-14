-- Phase 9c step two (PLAN.md): let a tenant that never pushed or built a
-- `Verified` path resolve it anyway, once some other tenant has. That lookup
-- is by hash part, tenant-agnostic, and only ever needs to find *one*
-- matching row (content-addressing guarantees they all agree) — this index
-- is what makes it an index scan instead of a sequential scan of every
-- tenant's rows.
--
-- Partial and narrow on purpose: only `Verified` rows ever need a
-- cross-tenant lookup (`Built`/`Quarantined` stay strictly per-tenant, PLAN.md
-- "Only Verified qualifies"), and only `live` ones should ever be found by it
-- — mirroring `store_paths_live`, so this index never points at a row a
-- reader is not supposed to see.
CREATE INDEX IF NOT EXISTS store_paths_verified_hash_part
    ON store_paths (hash_part)
    WHERE tier = 'verified' AND state = 'live';
