-- Retention and garbage collection (PLAN.md Phase 12).
--
-- Nothing before this migration ever deleted anything: every path and object
-- lived for the life of the deployment. This adds what GC needs without
-- touching how paths are read or written otherwise.

-- Reads never write here directly (see `path_access` below) — this is what
-- the drain step folds into, and what the mark pass reads a cutoff against.
-- Seeded at registration time rather than left null, so a path that is never
-- read still ages from when it arrived rather than looking eternally fresh.
ALTER TABLE store_paths
    ADD COLUMN last_access TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- live -> marked -> purging. A row stops being visible to any reader the
    -- moment it leaves 'live' — see `store_paths_live` below — so at no
    -- instant does a client see a narinfo for bytes about to disappear.
    ADD COLUMN state       TEXT NOT NULL DEFAULT 'live',
    -- When the mark pass flipped this row to 'marked'. Only meaningful in
    -- that state; not consulted for 'live' or 'purging'.
    ADD COLUMN marked_at   TIMESTAMPTZ;

-- Recording an access as `UPDATE store_paths SET last_access = NOW()` would
-- make the handful of paths every build depends on (bash, coreutils,
-- stdenv) the most-written rows in the database under MVCC, and would turn a
-- cache GET into a lock-taking write transaction. Instead reads append here,
-- cheaply and without contention, and a periodic drain folds these into
-- `store_paths.last_access` in batches (see `server/src/gc.rs`).
--
-- No primary key, no foreign key, no index: inserts never collide with each
-- other or with anything else, which is the whole point.
CREATE TABLE path_access (
    tenant TEXT        NOT NULL,
    path   TEXT        NOT NULL,
    at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- The single choke point every read query goes through instead of repeating
-- a `state = 'live'` predicate at each call site — a predicate missed at one
-- site would serve a narinfo (or a NAR) for bytes the sweep is about to
-- remove.
CREATE VIEW store_paths_live AS
    SELECT * FROM store_paths WHERE state = 'live';

-- The sweep deletes an object's `objects` row while `purging` `store_paths`
-- rows still point at it by design (PLAN.md Phase 12: object gone before its
-- row, so a crash between the two leaves a *findable* row rather than an
-- orphan object). The original constraint had no `ON DELETE` action, which
-- made that delete fail outright with a foreign-key violation instead.
-- `SET NULL` is exactly the right shape for "the object this row pointed at
-- is now confirmably gone" — and `server/src/gc.rs`'s reap query already
-- treats a null `object_key` the same as an object that no longer exists.
ALTER TABLE store_paths DROP CONSTRAINT store_paths_object_key_fkey;
ALTER TABLE store_paths
    ADD CONSTRAINT store_paths_object_key_fkey
    FOREIGN KEY (object_key) REFERENCES objects(key) ON DELETE SET NULL;
