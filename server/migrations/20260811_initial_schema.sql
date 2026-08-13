-- Kubernix frontend schema.
--
-- Replaces 20260728_create_jobs_table.sql, which predated both the current
-- metadata model and multi-tenancy and was never written to by any code.
--
-- Everything path-shaped is keyed by tenant. That is the schema consequence of
-- PLAN.md Phase 9: `addToStoreNar` takes the client's word for a path's
-- identity, so until pushes can be verified two tenants may legitimately hold
-- different bytes at the same store path, and neither may see the other's.

CREATE TABLE IF NOT EXISTS tenants (
    id         TEXT PRIMARY KEY,
    -- What the id was derived from: `key:<fingerprint>` or `user:<name>`.
    identity   TEXT NOT NULL,
    -- Whether anything actually checked that identity. False while the SSH
    -- surface accepts unconditionally; see PLAN.md "Deferred deliberately".
    verified   BOOLEAN NOT NULL DEFAULT FALSE,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Narinfo signing key, one per tenant, generated on first use. A signature
    -- then says *whose* cache vouched for a path, and distrusting one tenant
    -- does not touch another.
    --
    -- `signing_key_kind` says how to read the material. `local-ed25519` means
    -- the raw 32-byte seed is right here; the intended end state is a *wrapped*
    -- key only an external signer (TPM, HSM, KMS) can use, which becomes a new
    -- kind rather than a reinterpretation of existing rows.
    signing_key_kind     TEXT,
    signing_key_name     TEXT,
    -- Secret: everything able to sign for this tenant is in this column, which
    -- is exactly why it should not stay here.
    signing_key_material BYTEA,
    -- Published to clients as a `trusted-public-keys` entry.
    signing_public_key   BYTEA
);

-- The bytes behind a path, addressed by object-store key. Split out from
-- `store_paths` (PLAN.md Phase 9c / Phase 12) so that two rows can point at
-- the same object: a `Verified` path is content-addressed, so identical
-- content pushed by two tenants is *the same bytes* under `nar_key`'s scheme
-- (no tenant prefix for that tier), and there is no reason to store it twice.
-- `Built` and `Quarantined` stay tenant-prefixed, so this table holds their
-- objects too but never dedups them — one row each, same as before.
--
-- `file_size`/`file_hash` moved here from `store_paths` because they describe
-- the *object*, not the path: once two paths can share one, a column on the
-- shared row is what makes disagreeing about its hash unrepresentable rather
-- than merely unlikely.
--
-- Referrer counting (Phase 12) is an anti-join over `store_paths.object_key`,
-- never a stored counter — a counter has to be maintained correctly by every
-- writer and crash path, and there is no way to audit one after it drifts.
CREATE TABLE IF NOT EXISTS objects (
    key        TEXT PRIMARY KEY,
    file_size  BIGINT NOT NULL,
    -- Hash of the *compressed* object, which is what a narinfo `FileHash`
    -- states and what a client verifies its download against. Distinct from
    -- `store_paths.nar_hash`, which describes the uncompressed NAR — emitting
    -- one where the other is meant makes every substitution fail.
    file_hash  BYTEA  NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One row per valid path. This is simultaneously what `queryPathInfo` answers
-- from and what a narinfo is generated from; they must not become two sources
-- of truth.
CREATE TABLE IF NOT EXISTS store_paths (
    tenant            TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    path              TEXT NOT NULL,

    -- The hash part of `path`, stored rather than derived so that
    -- `queryPathFromHashPart` is an index lookup instead of a scan.
    hash_part         TEXT NOT NULL,

    deriver           TEXT,
    nar_hash_algo     TEXT NOT NULL,
    nar_hash          BYTEA NOT NULL,
    nar_size          BIGINT NOT NULL,
    registration_time BIGINT NOT NULL DEFAULT 0,
    ultimate          BOOLEAN NOT NULL DEFAULT FALSE,

    -- Named `refs` rather than `references`, which is a reserved word and would
    -- need quoting at every use.
    refs              TEXT[] NOT NULL DEFAULT '{}',
    sigs              TEXT[] NOT NULL DEFAULT '{}',

    -- Where the bytes are. The database never holds them: every path, however
    -- it arrived, is a zstd-compressed bare NAR in the object store, recorded
    -- once in `objects` and pointed at from here.
    object_key        TEXT REFERENCES objects(key),

    -- How much the frontend can vouch for this path (PLAN.md Phase 9):
    --   verified    - the path was recomputed from the bytes
    --   built       - one of our workers produced it
    --   quarantined - accepted on the client's word, unverifiable
    --
    -- Defaulting to the untrusted value matters: a row written by code that
    -- does not know about tiers must not become signable by omission.
    tier              TEXT NOT NULL DEFAULT 'quarantined',

    PRIMARY KEY (tenant, path)
);

-- `output_object` and the referrer anti-join both go from a path to its
-- object; without this it is a sequential scan of `store_paths` for either.
CREATE INDEX IF NOT EXISTS store_paths_object_key
    ON store_paths (object_key);

CREATE INDEX IF NOT EXISTS store_paths_hash_part
    ON store_paths (tenant, hash_part);

-- `queryReferrers` asks "who points at this path", which without an index is a
-- scan of every row. GIN over the array makes it a containment lookup.
CREATE INDEX IF NOT EXISTS store_paths_refs
    ON store_paths USING GIN (refs);

CREATE TABLE IF NOT EXISTS jobs (
    id              UUID PRIMARY KEY,
    tenant          TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    derivation_path TEXT NOT NULL,
    system          TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'pending',
    -- Set when the job reaches a terminal state.
    error_msg       TEXT,
    output_paths    TEXT[] NOT NULL DEFAULT '{}',
    -- Object key of the archived build log. One per job, so a column rather
    -- than the separate `build_logs` table DESIGN.md sketches.
    log_key         TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS jobs_tenant_created
    ON jobs (tenant, created_at DESC);
