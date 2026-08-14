-- Job and log retention (PLAN.md Phase 12's remainder).
--
-- `jobs` existed since the initial schema but nothing ever wrote to it; this
-- migration is only the piece that retention itself needs once job outcomes
-- start being persisted (see `PostgresStore::record_job_outcome`).

-- The log's own lifecycle, independent of `status` (which describes the
-- *build's* outcome, not whether its archived log still exists). Staged the
-- same way `store_paths.state` is: `present -> marked -> purged`. A row may
-- not be reaped (see `server/src/gc.rs`) while its log is still `present` or
-- `marked` — its `log_key` is the only record of that object's existence,
-- since nothing here ever lists the bucket to rediscover an orphan.
ALTER TABLE jobs
    ADD COLUMN log_state TEXT NOT NULL DEFAULT 'present';

-- What the mark pass scans: terminal jobs (`finished_at` set) whose log is
-- still `present`. Partial, since non-terminal jobs (`finished_at IS NULL`)
-- are never retention candidates.
CREATE INDEX jobs_finished_at
    ON jobs (finished_at) WHERE finished_at IS NOT NULL;
