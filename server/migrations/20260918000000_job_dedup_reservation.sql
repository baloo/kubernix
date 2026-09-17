-- PLAN.md Phase 19: dedup concurrent identical builds.
--
-- `jobs` rows are, as of this phase, inserted at dispatch time (`status =
-- 'running'`) rather than only once a job finishes -- see
-- `PostgresStore::reserve_job`. This partial unique index is the whole
-- mechanism: two `INSERT`s (from any `kubernix-sshd` replica) racing to
-- reserve the same `(tenant, derivation_path)` while a build is in flight
-- can never both succeed, and a completed/failed/reaped job (whose `status`
-- has moved away from `'running'`) drops out of the index entirely, so a
-- later, genuinely new build of the same derivation is never blocked.
CREATE UNIQUE INDEX jobs_tenant_drv_running
    ON jobs (tenant, derivation_path) WHERE status = 'running';
