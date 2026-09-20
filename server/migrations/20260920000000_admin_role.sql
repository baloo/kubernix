-- A third serving role for the admin CLI (`kubernix-admin`,
-- `server/src/admin.rs`): list/add tenants and list/add/delete their
-- `tenant_auth_bindings` credentials, replacing the hand-run SQL that used
-- to be the only way to do this (see README.md's "Multi-tenancy" section).
--
-- BYPASSRLS like `kubernix_gc` (`20260814120000_row_level_security.sql`):
-- an admin operation addresses tenants and bindings directly by id, not
-- through any one tenant's connection-scoped view, so there is no
-- `app.current_tenant` for a row-security policy to check against.
--
-- Deliberately its own role rather than widening `kubernix_gc`'s grants:
-- GC's write access exists for retention/collection, a different purpose
-- and blast radius than an operator provisioning tenants by hand. Neither
-- gets DDL rights, same as the other two roles (see `PostgresStore::connect`'s
-- doc comment) — this migration itself still runs over the privileged
-- bootstrap connection.
--
-- No `DELETE` on `tenants`: tenant deletion is not provided by the admin CLI
-- yet, so there is nothing that needs it.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'kubernix_admin') THEN
        CREATE ROLE kubernix_admin LOGIN BYPASSRLS;
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO kubernix_admin;
GRANT SELECT, INSERT ON tenants TO kubernix_admin;
GRANT SELECT, INSERT, DELETE ON tenant_auth_bindings TO kubernix_admin;
