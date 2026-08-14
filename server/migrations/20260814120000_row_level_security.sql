-- Postgres row-level security, as defense-in-depth on top of every query's
-- own `WHERE tenant = $1` (server/src/postgres_store.rs). A predicate missed
-- at one call site has, until now, been the only thing standing between one
-- tenant and another's rows; this makes the database itself refuse a row
-- that does not belong to the connection's tenant, even if the application
-- code above it forgets to ask.
--
-- Two serving roles, not one, because two very different access patterns
-- need to coexist:
--
--   kubernix_app  - kubernix-sshd and kubernix-cache. Tenant-scoped: RLS-
--                   restricted to whatever `app.current_tenant` a connection
--                   has set for the query it is running (see below).
--   kubernix_gc   - kubernix-gc and kubernix-rotate-capability-secret. These
--                   scan *every* tenant's rows by design (a collector has to
--                   see the whole table to do reachability and referrer
--                   counting at all — see crate::gc's module doc) and would
--                   see nothing at all under a tenant-scoped policy. BYPASSRLS
--                   is the correct tool here, precisely because it is a
--                   distinct, narrowly-used *role* rather than a session flag
--                   any connection could set: only the two binaries that are
--                   actually meant to see every tenant's data ever connect as
--                   it.
--
-- Neither role gets DDL rights (see `PostgresStore::connect`'s doc comment):
-- migrations run over a separate, privileged bootstrap connection, and both
-- serving roles are created here with only the table-level grants their own
-- binaries actually use. A bug in kubernix-sshd's serving path can therefore
-- never widen its own blast radius by altering the schema or disabling its
-- own row-security policy.
--
-- Passwordless (`LOGIN` with no `PASSWORD` clause): both dev (`just run-db`)
-- and the NixOS test (`nix/test.nix`) authenticate every role over `trust`,
-- same as the existing bootstrap `postgres` role. A production deployment
-- wiring these roles up over a network needs its own `ALTER ROLE ... PASSWORD`
-- (or equivalent, e.g. an IAM-authenticated role) as part of its own
-- provisioning — deliberately out of scope for a migration that runs
-- unattended on every startup.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'kubernix_app') THEN
        CREATE ROLE kubernix_app LOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'kubernix_gc') THEN
        CREATE ROLE kubernix_gc LOGIN BYPASSRLS;
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO kubernix_app, kubernix_gc;

-- `store_paths`: kubernix-sshd reads and writes it, on behalf of one tenant
-- at a time; kubernix-gc additionally deletes from it (the sweep/reap
-- passes). Neither ever truncates or drops it.
GRANT SELECT, INSERT, UPDATE ON store_paths TO kubernix_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON store_paths TO kubernix_gc;
GRANT SELECT ON store_paths_live TO kubernix_app, kubernix_gc;

-- Load-bearing, not cosmetic: a view runs with its *owner's* privileges by
-- default (like a SECURITY DEFINER function), including for row-security
-- purposes — and this view's owner is whatever role ran the migrations
-- (the privileged bootstrap connection, effectively a superuser), which
-- always bypasses RLS regardless of context. Without this, every read below
-- going through `store_paths_live` (which is almost all of them) would
-- silently see every tenant's rows no matter which role queried it, making
-- the policies above dead weight. `security_invoker` makes the view instead
-- run — and be RLS-checked — as whichever role actually issued the query.
-- Requires PostgreSQL 15+.
ALTER VIEW store_paths_live SET (security_invoker = true);

-- `jobs`: written once per terminal build (kubernix-sshd) and reaped by
-- kubernix-gc (mark/sweep/reap of logs, then the row itself).
GRANT SELECT, INSERT, UPDATE ON jobs TO kubernix_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON jobs TO kubernix_gc;

-- `path_access`: kubernix-sshd only ever appends to its own tenant's queue
-- (`Store::record_access`); nothing on the serving path reads it back. Only
-- kubernix-gc's drain pass reads and deletes, across every tenant at once.
GRANT INSERT ON path_access TO kubernix_app;
GRANT SELECT, DELETE ON path_access TO kubernix_gc;

-- `objects`, `tenants`, `capability_secrets`: not tenant-keyed (see their own
-- table comments — a `Verified` object is shared across tenants by
-- construction, and a capability secret is deployment-wide), so both roles
-- need full read/write access to them and neither carries a row-security
-- policy.
GRANT SELECT, INSERT, UPDATE ON objects TO kubernix_app, kubernix_gc;
GRANT DELETE ON objects TO kubernix_gc;
GRANT SELECT, INSERT, UPDATE ON tenants TO kubernix_app, kubernix_gc;
GRANT SELECT, INSERT, UPDATE, DELETE ON capability_secrets TO kubernix_app, kubernix_gc;
GRANT USAGE, SELECT ON capability_secrets_kid_seq TO kubernix_app, kubernix_gc;

ALTER TABLE store_paths ENABLE ROW LEVEL SECURITY;

-- The main policy: a row is visible to (and writable by) `kubernix_app` only
-- when it belongs to the tenant that connection has declared, via
-- `SELECT set_config('app.current_tenant', $1, true)` — `true` scopes it to
-- the current transaction only (equivalent to `SET LOCAL`, but usable with a
-- bound parameter, which a literal `SET LOCAL` statement is not). Every
-- tenant-scoped `PostgresStore` method wraps its query in exactly that:
-- `pool.begin()`, set the GUC, run the query, commit — see
-- `PostgresStore::tenant_scoped`.
--
-- `current_setting(..., true)` (the missing_ok form) is deliberate: a
-- connection that never set the GUC at all reads as NULL, which matches
-- nothing, rather than raising an error that would turn a forgotten
-- `tenant_scoped` wrapper into a 500 instead of a silent (and loudly logged
-- elsewhere) empty result.
CREATE POLICY tenant_isolation ON store_paths
    USING (tenant = current_setting('app.current_tenant', true))
    WITH CHECK (tenant = current_setting('app.current_tenant', true));

-- The one deliberate cross-tenant read on the `kubernix_app` role:
-- `Store::find_verified_by_hash_part` (PLAN.md Phase 9c step two) — a
-- `Verified` row is provably identical across tenants by construction, so
-- any tenant's row for a given hash part answers for all of them. This is a
-- second *permissive* policy (Postgres ORs permissive policies together), so
-- it only ever widens visibility, and only for `SELECT`, only for `verified`
-- rows, and only when the connection has explicitly set
-- `app.allow_cross_tenant_verified_read` — which nothing but
-- `find_verified_by_hash_part`'s own call site ever does. This is the
-- policy-level equivalent of the comment that used to be the only thing
-- explaining why that one query has no `tenant` predicate: now the database
-- enforces the same boundary the comment described.
CREATE POLICY cross_tenant_verified_read ON store_paths
    FOR SELECT
    USING (
        tier = 'verified'
        AND current_setting('app.allow_cross_tenant_verified_read', true) = 'true'
    );

ALTER TABLE jobs ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON jobs
    USING (tenant = current_setting('app.current_tenant', true))
    WITH CHECK (tenant = current_setting('app.current_tenant', true));

ALTER TABLE path_access ENABLE ROW LEVEL SECURITY;

-- INSERT-only, matching `kubernix_app`'s GRANT above: nothing on the serving
-- path ever selects, updates or deletes a row here, so there is no read-side
-- policy to write.
CREATE POLICY tenant_isolation ON path_access
    FOR INSERT
    WITH CHECK (tenant = current_setting('app.current_tenant', true));
