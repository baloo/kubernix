-- Widens the `failure_kind` CHECK from 20260917000000_job_failure_kind.sql
-- to include the worker's new guest-hang detection (worker/src/main.rs::
-- guest_ping_monitor): the guest VM stopped responding mid-build and the
-- one wipe-and-retry attempt either wasn't available or also timed out.
ALTER TABLE jobs
    DROP CONSTRAINT jobs_failure_kind_check;
ALTER TABLE jobs
    ADD CONSTRAINT jobs_failure_kind_check
    CHECK (failure_kind IN ('out_of_memory', 'disk_full', 'guest_hang'));
