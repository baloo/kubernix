-- Per-tenant trusted substituters, plus what kubernix needs to act as a
-- pull-through cache for them (PLAN.md-equivalent design: see the "Per-tenant
-- trusted substituters" plan). Kubernix never authenticates this content
-- itself -- see `server/src/substitute.rs` -- it only caches and records
-- provenance, so the schema here carries no signature-verification state.

-- A tenant's configured trusted substituters. A table of its own, keyed to
-- the tenant, mirroring `tenant_auth_bindings` rather than more columns on
-- `tenants` -- this is a set, not a scalar setting.
CREATE TABLE IF NOT EXISTS tenant_substituters (
    tenant     TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    url        TEXT NOT NULL,
    public_key TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, url)
);

-- Provenance for a `Tier::Substituted` row: exactly which of the tenant's
-- configured substituters this content was fetched from. NULL for every
-- other tier. This is what lets a second tenant materialize a row against
-- already-cached content without re-fetching (only if that tenant has the
-- same (url, public_key) configured -- a policy check, not a cryptographic
-- one), and what the per-substituter HTTP route uses to refuse serving a
-- path recorded against a *different* substituter than the one it names.
ALTER TABLE store_paths ADD COLUMN IF NOT EXISTS substituted_from_url TEXT;
ALTER TABLE store_paths ADD COLUMN IF NOT EXISTS substituted_from_key TEXT;

-- A path a trusted substituter answered "not found" for, so repeated lookups
-- (in particular the high-volume `isValidPath`/`query_missing` path) don't
-- re-query it on every call. Scoped per tenant, not global, since two
-- tenants' trusted-substituter sets can differ. No TTL column or sweep pass:
-- expiry is enforced entirely in the lookup's own `WHERE checked_at > now() -
-- $ttl`, so a stale row simply stops matching and the next miss overwrites it.
CREATE TABLE IF NOT EXISTS substituter_negative_cache (
    tenant     TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    hash_part  TEXT NOT NULL,
    checked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant, hash_part)
);

-- Row-level security, same shape as `store_paths`/`jobs`/`path_access`
-- (`20260814120000_row_level_security.sql`): `kubernix_app` only ever reads
-- or writes its own connection's declared tenant. `kubernix_gc` needs no
-- access to either table -- nothing collects them.
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_substituters TO kubernix_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON substituter_negative_cache TO kubernix_app;

-- `kubernix_admin` (`20260920000000_admin_role.sql`) manages substituters by
-- hand via `kubernix-admin`, the same way it manages `tenant_auth_bindings` --
-- BYPASSRLS, so no `app.current_tenant` is needed for these grants to work.
GRANT SELECT, INSERT, DELETE ON tenant_substituters TO kubernix_admin;

ALTER TABLE tenant_substituters ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON tenant_substituters
    USING (tenant = current_setting('app.current_tenant', true))
    WITH CHECK (tenant = current_setting('app.current_tenant', true));

ALTER TABLE substituter_negative_cache ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON substituter_negative_cache
    USING (tenant = current_setting('app.current_tenant', true))
    WITH CHECK (tenant = current_setting('app.current_tenant', true));

-- The `Tier::Substituted` analogue of `cross_tenant_verified_read`
-- (`20260814120000_row_level_security.sql`): a second permissive SELECT
-- policy on `store_paths`, only for `substituted` rows, only when the
-- connection has explicitly set `app.allow_cross_tenant_substituted_read` --
-- which nothing but `find_substituted_by_hash_part`'s own call site ever
-- does. This is what lets one tenant's already-cached content be *found*
-- across tenants; whether the querying tenant's own `store_paths` row then
-- gets materialized still depends on its `tenant_substituters` including
-- the same (url, public_key) the found row was fetched under -- an
-- application-level check, not something this policy itself enforces.
CREATE POLICY cross_tenant_substituted_read ON store_paths
    FOR SELECT
    USING (
        tier = 'substituted'
        AND current_setting('app.allow_cross_tenant_substituted_read', true) = 'true'
    );
