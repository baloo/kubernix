-- PLAN.md Phase 18: distinguishes a terminal resource-exhaustion failure
-- (every retry/escalation option exhausted) from an ordinary build failure,
-- operator-visible on the jobs row -- NULL for a completed job and for any
-- ordinary failure alike.
ALTER TABLE jobs
    ADD COLUMN failure_kind TEXT
    CHECK (failure_kind IN ('out_of_memory', 'disk_full'));
