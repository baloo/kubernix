-- Binds an authentication credential to a tenant.
--
-- `tenants.identity`/`verified` record what a client *claimed*; this table is
-- what makes a claim provable. A row here says "whoever holds this key is
-- this tenant" - provisioned by hand, out of band (an operator inserts a
-- `tenants` row, then a binding for each key that tenant may connect with),
-- not created by the act of connecting the way `tenants` rows have been.
--
-- One tenant may hold several bindings (e.g. more than one SSH key); a
-- binding belongs to exactly one tenant, hence the primary key on the
-- credential rather than on `tenant`.
CREATE TABLE IF NOT EXISTS tenant_auth_bindings (
    -- Only 'ssh' for now. Rust-side, this is the `KeyType` enum
    -- (`server/src/tenant.rs`), not a raw string; the CHECK constraint widens
    -- (a migration adding 'tls' to it) in the same change that adds the
    -- `Tls` variant and an mTLS API to actually issue that credential type.
    key_type   TEXT NOT NULL CHECK (key_type IN ('ssh')),

    -- Type-dependent lookup key: for ssh, the `SHA256:<base64>` fingerprint
    -- russh already computes (`PublicKey::fingerprint`). For tls (future),
    -- this row would describe a *trusted root CA*, keyed by that root's
    -- Subject Key Identifier (SKI); a client's leaf cert carries an
    -- Authority Key Identifier (AKI) naming its issuer, and lookup is "does
    -- the presented AKI match a `key_id` we hold" - so `key_id` is the
    -- root's SKI, not anything from the leaf cert itself.
    key_id     TEXT NOT NULL,

    tenant     TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,

    -- Type-dependent auth material kept for the record: for ssh, the raw
    -- public key blob; for tls (future), the root CA certificate itself.
    -- Not consulted for the auth decision, which is "does a row exist for
    -- this (key_type, key_id)" - this column is provenance, not policy.
    key_value  BYTEA,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (key_type, key_id)
);

-- Not RLS-scoped, unlike `store_paths`/`jobs`/`path_access`: this table is
-- what *establishes* which tenant a connection is, so it must be readable
-- before `app.current_tenant` is set for one. Same reasoning as `tenants`
-- itself, which carries no policy either.
CREATE INDEX IF NOT EXISTS tenant_auth_bindings_tenant
    ON tenant_auth_bindings (tenant);

-- `kubernix-sshd` (`kubernix_app`) only ever looks a binding up by key; it
-- never writes one - provisioning is a manual `INSERT` run out of band, over
-- a privileged connection, not through this role.
GRANT SELECT ON tenant_auth_bindings TO kubernix_app;
