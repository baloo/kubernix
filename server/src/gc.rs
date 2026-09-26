//! Retention and garbage collection — PLAN.md Phase 12.
//!
//! Nothing on the serving path (`crate::daemon_rpc`, `crate::http`) ever
//! deletes anything; this module is the only thing that does. It runs as its
//! own periodic pass, driven by `kubernix-gc` (`server/src/bin/kubernix-gc.rs`),
//! deliberately separate from the read path (`kubernix-cache`) and the write
//! path (`kubernix-sshd`).
//!
//! One pass is three steps, run in order:
//!
//! 1. [`drain_access_queue`] folds `path_access` (written by
//!    [`crate::store::Store::record_access`]) into `store_paths.last_access`,
//!    and resurrects any `marked` row an access mark reaches.
//! 2. [`mark_expired`] flips `live -> marked` for rows past their tier's
//!    cutoff and *not* reachable through `refs` from a row that is still
//!    fresh — a shared build input must not be collected just because it
//!    looks idle on its own `last_access`.
//! 3. [`sweep_and_reap`] deletes the object store's bytes for any object with
//!    no remaining `live` referrer, then the `objects` row, then reaps the
//!    `purging` `store_paths` rows left pointing at it.
//!
//! All three run under one Postgres advisory lock ([`run_gc_pass`]), so two
//! collectors — two replicas of `kubernix-gc`, or a rolling deploy overlap —
//! degrade to one doing the work and one doing nothing, rather than racing.

use std::time::Duration;

use sqlx::postgres::{PgConnection, PgPool};

use kubernix_types::ObjectKey;
use uuid::Uuid;

use crate::advisory_lock::AdvisoryLock;
use crate::postgres_store::PostgresStore;
use crate::uploads::UploadSigner;

/// Fixed key for `pg_try_advisory_lock`. Any `i64` works as long as nothing
/// else in the deployment uses it; there is nothing else here.
const GC_LOCK_KEY: i64 = 0x6b756e_67630001; // "kunga gc" scrunched down, mostly for readability in a debugger

/// How long a path may go unread before it is eligible for collection, per
/// [`crate::store::Tier`]. Quarantined content is unverifiable, unshared and
/// unservable, so it can — and should — expire far sooner than a tier the
/// frontend actually vouches for (PLAN.md Phase 12).
#[derive(Clone, Copy, Debug)]
pub struct TierCutoffs {
    pub verified: Duration,
    pub built: Duration,
    pub quarantined: Duration,
}

impl Default for TierCutoffs {
    fn default() -> Self {
        Self {
            verified: Duration::from_secs(30 * 24 * 3600),
            built: Duration::from_secs(30 * 24 * 3600),
            quarantined: Duration::from_secs(24 * 3600),
        }
    }
}

/// How long a terminal job's archived log, and then the job's own metadata
/// row, survive after `finished_at` (PLAN.md Phase 12).
///
/// Two cutoffs rather than one because the two things being retained cost
/// different amounts: the log is the heavy, rarely-needed-again part, the row
/// is a few bytes of "what happened". `log_after` should be shorter than
/// `row_after` — `reap_jobs` will not delete a row whose log has not been
/// swept yet (see its doc comment), so if the two are configured backwards
/// the row simply waits for the log to catch up rather than losing track of
/// the object.
#[derive(Clone, Copy, Debug)]
pub struct JobRetention {
    pub log_after: Duration,
    pub row_after: Duration,
    /// PLAN.md Phase 19: how long a `jobs` row may sit at `status =
    /// 'running'` before it's treated as orphaned (the process that
    /// reserved it crashed, or every watcher walked away, before anything
    /// ever completed it) rather than still in flight. Must be the same
    /// value as `jobs::JobQueue::results_retention` — see that field's own
    /// doc comment for why: a reservation must never be reaped while its
    /// job's outcome could still legitimately arrive and be replayed. This
    /// is purely a backstop, not the primary recovery path — a live request
    /// for the same `(tenant, derivation_path)` reclaims a stale
    /// reservation itself, inline, the moment it notices one (see
    /// `PostgresStore::reserve_job_db`); this sweep only catches the case
    /// where nothing ever asks again.
    pub stuck_running_after: Duration,
}

impl Default for JobRetention {
    fn default() -> Self {
        Self {
            log_after: Duration::from_secs(7 * 24 * 3600),
            row_after: Duration::from_secs(90 * 24 * 3600),
            stuck_running_after: Duration::from_secs(24 * 3600),
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct GcStats {
    /// Whether this call actually ran the passes, or found the advisory lock
    /// already held by another collector and did nothing.
    pub ran: bool,
    pub access_marks_drained: u64,
    pub paths_marked: u64,
    pub objects_deleted: u64,
    pub paths_reaped: u64,
    pub job_logs_marked: u64,
    pub job_logs_purged: u64,
    pub jobs_reaped: u64,
    /// PLAN.md Phase 19: orphaned `'running'` reservations reclaimed this
    /// pass — see `JobRetention::stuck_running_after`.
    pub stuck_jobs_reclaimed: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum GcError {
    #[error("database: {0}")]
    Database(#[from] sqlx::Error),
    /// An object failed to delete from the object store. Not fatal to the
    /// pass — the row stays `purging` and the next pass retries it — but
    /// worth the caller knowing about.
    #[error("deleting {key}: {error}")]
    Upload { key: ObjectKey, error: String },
}

type Result<T> = std::result::Result<T, GcError>;

/// Run one full drain → mark → sweep+reap pass, under the advisory lock.
///
/// Acquires a single connection and holds the lock on it for the whole pass
/// (see [`crate::advisory_lock`] for how the lock is guaranteed not to leak
/// into the pool still held, on any exit path).
///
/// Returns `Ok(GcStats { ran: false, .. })`, not an error, when another
/// collector already holds the lock — that is the expected steady state with
/// more than one `kubernix-gc` replica running.
pub async fn run_gc_pass(
    store: &PostgresStore,
    uploader: &UploadSigner,
    cutoffs: &TierCutoffs,
    job_retention: &JobRetention,
    batch_size: i64,
) -> Result<GcStats> {
    run_gc_pass_on(&store.pool, uploader, cutoffs, job_retention, batch_size).await
}

async fn run_gc_pass_on(
    pool: &PgPool,
    uploader: &UploadSigner,
    cutoffs: &TierCutoffs,
    job_retention: &JobRetention,
    batch_size: i64,
) -> Result<GcStats> {
    let Some(mut lock) = AdvisoryLock::try_acquire(pool, GC_LOCK_KEY).await? else {
        tracing::debug!("gc pass skipped: another collector holds the lock");
        return Ok(GcStats::default());
    };

    let result = run_locked(lock.conn(), uploader, cutoffs, job_retention, batch_size).await;

    if let Err(e) = lock.release().await {
        tracing::error!(error = %e, "failed to release the gc advisory lock");
    }

    result
}

async fn run_locked(
    conn: &mut PgConnection,
    uploader: &UploadSigner,
    cutoffs: &TierCutoffs,
    job_retention: &JobRetention,
    batch_size: i64,
) -> Result<GcStats> {
    let access_marks_drained = drain_access_queue(conn, batch_size).await?;
    let paths_marked = mark_expired(conn, cutoffs).await?;
    let (objects_deleted, paths_reaped) = sweep_and_reap(conn, uploader).await?;

    let job_logs_marked = mark_expired_job_logs(conn, job_retention.log_after).await?;
    let job_logs_purged = sweep_job_logs(conn, uploader).await?;
    let jobs_reaped = reap_jobs(conn, job_retention.row_after).await?;
    let stuck_jobs_reclaimed =
        reclaim_stuck_running_jobs(conn, job_retention.stuck_running_after).await?;

    tracing::info!(
        access_marks_drained,
        paths_marked,
        objects_deleted,
        paths_reaped,
        job_logs_marked,
        job_logs_purged,
        jobs_reaped,
        stuck_jobs_reclaimed,
        "gc pass complete"
    );

    Ok(GcStats {
        ran: true,
        access_marks_drained,
        paths_marked,
        objects_deleted,
        paths_reaped,
        job_logs_marked,
        job_logs_purged,
        jobs_reaped,
        stuck_jobs_reclaimed,
    })
}

/// Fold up to `batch_size` queued accesses into `store_paths.last_access`,
/// resurrecting any row still `marked` that one of them touches.
///
/// `FOR UPDATE SKIP LOCKED` is on `path_access`, not on `store_paths`: the
/// store rows are also written by the ingest path (`PostgresStore::
/// upsert_path`), so locking them here would contend with pushes and builds —
/// precisely what the queue exists to avoid. The queue rows are the
/// contended resource. No explicit lock on `store_paths` is needed at all,
/// because the update is commutative (`GREATEST`) and idempotent (the
/// `state = 'marked'` guard), so draining out of order or twice is harmless.
pub(crate) async fn drain_access_queue(conn: &mut PgConnection, batch_size: i64) -> Result<u64> {
    let updated = sqlx::query(
        "WITH claimed AS (
             DELETE FROM path_access
              WHERE ctid IN (SELECT ctid FROM path_access
                              ORDER BY at
                              LIMIT $1
                              FOR UPDATE SKIP LOCKED)
             RETURNING tenant, path, at
         ),
         folded AS (
             SELECT tenant, path, MAX(at) AS at FROM claimed GROUP BY tenant, path
         )
         UPDATE store_paths s
            SET last_access = GREATEST(s.last_access, f.at),
                state = CASE WHEN s.state = 'marked' THEN 'live' ELSE s.state END,
                marked_at = CASE WHEN s.state = 'marked' THEN NULL ELSE s.marked_at END
           FROM folded f
          WHERE s.tenant = f.tenant AND s.path = f.path",
    )
    .bind(batch_size)
    .execute(&mut *conn)
    .await?;

    Ok(updated.rows_affected())
}

/// Flip `live -> marked` for rows past their tier's cutoff, excluding
/// anything reachable through `refs` from a row that is still fresh.
///
/// This is the real work of the phase: the marking pass is not `WHERE
/// last_access < cutoff` on its own, because a narinfo lists `References` and
/// a client that fetches a path will fetch them too. An unreferenced-looking
/// build input (bash, coreutils, stdenv) is usually the *most*-shared path in
/// the store, so it must survive as long as anything live still points at it,
/// regardless of when it was itself last read directly.
///
/// `fresh` is computed once as a recursive closure over `refs` starting from
/// every row that is both `live` and within its own cutoff, then walking
/// outward along references. Membership in it exempts a row from marking even
/// past its own cutoff.
pub(crate) async fn mark_expired(conn: &mut PgConnection, cutoffs: &TierCutoffs) -> Result<u64> {
    let updated = sqlx::query(
        "WITH RECURSIVE cutoff(tier, secs) AS (
             VALUES ('quarantined', $1::double precision),
                    ('built',       $2::double precision),
                    ('verified',    $3::double precision)
         ),
         fresh(tenant, path) AS (
             SELECT sp.tenant, sp.path
               FROM store_paths sp
               JOIN cutoff c ON c.tier = sp.tier
              WHERE sp.state = 'live'
                AND sp.last_access >= NOW() - make_interval(secs => c.secs)
             UNION
             SELECT sp.tenant, r.ref
               FROM fresh f
               JOIN store_paths sp ON sp.tenant = f.tenant AND sp.path = f.path
               CROSS JOIN LATERAL unnest(sp.refs) AS r(ref)
         )
         UPDATE store_paths sp
            SET state = 'marked', marked_at = NOW()
           FROM cutoff c
          WHERE sp.state = 'live'
            AND c.tier = sp.tier
            AND sp.last_access < NOW() - make_interval(secs => c.secs)
            AND NOT EXISTS (
                SELECT 1 FROM fresh f WHERE f.tenant = sp.tenant AND f.path = sp.path
            )",
    )
    .bind(cutoffs.quarantined.as_secs_f64())
    .bind(cutoffs.built.as_secs_f64())
    .bind(cutoffs.verified.as_secs_f64())
    .execute(&mut *conn)
    .await?;

    Ok(updated.rows_affected())
}

/// For each object with no remaining `live` referrer: flip its referrers
/// `marked -> purging`, delete the object's bytes, delete the `objects` row,
/// then reap `purging` rows whose object is confirmably gone.
///
/// The ordering is the point, mirroring PLAN.md Phase 12 exactly: the
/// tombstone (`marked -> purging`) happens first, so at no instant is a
/// client looking at a path whose bytes are being removed — the `narinfo`/
/// `narFromPath` routes already stopped seeing it back when it went `live ->
/// marked`. The object's bytes go before its database row, so a crash
/// between the two leaves a *findable* `purging` row pointing at a missing
/// object rather than an orphan object nobody can name; the reap step is
/// exactly what makes that self-healing on the next pass, crashed or not.
pub(crate) async fn sweep_and_reap(
    conn: &mut PgConnection,
    uploader: &UploadSigner,
) -> Result<(u64, u64)> {
    // Referrer counting is an anti-join, never a stored counter — a counter
    // has to be maintained correctly by every writer and crash path, and
    // there is no way to audit one after it drifts.
    let candidates: Vec<String> = sqlx::query_scalar(
        "SELECT o.key FROM objects o
          WHERE NOT EXISTS (
              SELECT 1 FROM store_paths sp
               WHERE sp.object_key = o.key AND sp.state = 'live'
          )",
    )
    .fetch_all(&mut *conn)
    .await?;

    let mut objects_deleted = 0u64;
    for key in candidates {
        let key = ObjectKey::new(key);

        sqlx::query(
            "UPDATE store_paths SET state = 'purging' WHERE object_key = $1 AND state = 'marked'",
        )
        .bind(key.as_str())
        .execute(&mut *conn)
        .await?;

        // S3 `DeleteObject` is idempotent, which matters on retry: a pass
        // that crashed after this succeeded but before the `objects` row was
        // deleted will reach here again next time and must not fail.
        if let Err(e) = uploader.delete_object(&key).await {
            tracing::error!(error = %e, %key, "failed to delete object; will retry next pass");
            continue;
        }

        sqlx::query("DELETE FROM objects WHERE key = $1")
            .bind(key.as_str())
            .execute(&mut *conn)
            .await?;
        objects_deleted += 1;
    }

    // Self-healing reap: any `purging` row whose object is actually gone,
    // whether that happened just above or in an earlier pass that crashed
    // between deleting the object and deleting this row.
    let reaped = sqlx::query(
        "DELETE FROM store_paths
          WHERE state = 'purging'
            AND (object_key IS NULL
                 OR NOT EXISTS (SELECT 1 FROM objects o WHERE o.key = store_paths.object_key))",
    )
    .execute(&mut *conn)
    .await?;

    Ok((objects_deleted, reaped.rows_affected()))
}

/// Flip `present -> marked` for a terminal job's log once it is past
/// `log_after` old, counted from `finished_at`.
///
/// Mirrors [`mark_expired`]'s role for `store_paths`: this only stages the
/// log for deletion, it does not touch the object store or the job row
/// itself, so a crash between here and [`sweep_job_logs`] leaves nothing
/// inconsistent — the row is simply `marked` again on the next pass.
pub(crate) async fn mark_expired_job_logs(
    conn: &mut PgConnection,
    log_after: Duration,
) -> Result<u64> {
    let updated = sqlx::query(
        "UPDATE jobs
            SET log_state = 'marked'
          WHERE log_state = 'present'
            AND finished_at IS NOT NULL
            AND finished_at < NOW() - make_interval(secs => $1::double precision)",
    )
    .bind(log_after.as_secs_f64())
    .execute(&mut *conn)
    .await?;

    Ok(updated.rows_affected())
}

/// Delete the archived log object for every `marked` job, then clear
/// `log_key` and flip the row to `purged`.
///
/// The object goes before the row is updated, same ordering `sweep_and_reap`
/// uses and for the same reason: a crash between the two leaves a `marked`
/// row whose `log_key` is still known, which the next pass retries — S3
/// `DeleteObject` is idempotent, so retrying a delete that already succeeded
/// is harmless. What must never happen is the row losing track of `log_key`
/// before the object is confirmably gone: nothing here lists the bucket, so
/// that key would be unrecoverable.
pub(crate) async fn sweep_job_logs(
    conn: &mut PgConnection,
    uploader: &UploadSigner,
) -> Result<u64> {
    let marked: Vec<(Uuid, String)> =
        sqlx::query_as("SELECT id, log_key FROM jobs WHERE log_state = 'marked'")
            .fetch_all(&mut *conn)
            .await?;

    let mut purged = 0u64;
    for (id, log_key) in marked {
        let key = ObjectKey::new(log_key);

        if let Err(e) = uploader.delete_object(&key).await {
            tracing::error!(error = %e, %key, job_id = %id, "failed to delete job log; will retry next pass");
            continue;
        }

        sqlx::query(
            "UPDATE jobs SET log_state = 'purged', log_key = NULL
              WHERE id = $1 AND log_state = 'marked'",
        )
        .bind(id)
        .execute(&mut *conn)
        .await?;
        purged += 1;
    }

    Ok(purged)
}

/// Delete terminal job rows once past `row_after` old — but only once their
/// log has actually been swept.
///
/// `log_state = 'purged'` is the load-bearing part of this query, not an
/// optimisation: a row is the only record of its `log_key`'s existence, so
/// deleting it while the log is still `present` or `marked` would orphan
/// that object with no way to ever find it again (this collector never lists
/// the bucket). If `row_after` is configured shorter than `log_after`, or a
/// delete keeps failing, this simply reaps nothing for that row until the log
/// catches up on a later pass — a wait, not a leak.
pub(crate) async fn reap_jobs(conn: &mut PgConnection, row_after: Duration) -> Result<u64> {
    let reaped = sqlx::query(
        "DELETE FROM jobs
          WHERE finished_at IS NOT NULL
            AND finished_at < NOW() - make_interval(secs => $1::double precision)
            AND log_state = 'purged'",
    )
    .bind(row_after.as_secs_f64())
    .execute(&mut *conn)
    .await?;

    Ok(reaped.rows_affected())
}

/// PLAN.md Phase 19 backstop: fail any `jobs` row still `status = 'running'`
/// long enough after `created_at` that its outcome, even if the build
/// eventually finished, could no longer be replayed from NATS (see
/// `JobRetention::stuck_running_after`'s doc comment on why this must share
/// its value with `kubernix_results`' own `max_age`).
///
/// Same `WHERE status = 'running' AND created_at < cutoff` predicate as the
/// inline steal in `PostgresStore::reserve_job_db` — the two race harmlessly
/// against each other on the same row: whichever gets there first wins
/// atomically (one `UPDATE`, one row), the other affects zero rows. `gc`
/// connects `BYPASSRLS` (see the row-level-security migration's doc
/// comment), so this runs across every tenant's rows in one statement,
/// unlike a normal serving-path query.
pub(crate) async fn reclaim_stuck_running_jobs(
    conn: &mut PgConnection,
    stuck_running_after: Duration,
) -> Result<u64> {
    let reclaimed = sqlx::query(
        "UPDATE jobs
            SET status = 'failed',
                error_msg = 'kubernix: orphaned in-flight record reaped (no result observed \
                             within the retention window)',
                finished_at = NOW()
          WHERE status = 'running'
            AND created_at < NOW() - make_interval(secs => $1::double precision)",
    )
    .bind(stuck_running_after.as_secs_f64())
    .execute(&mut *conn)
    .await?;

    Ok(reclaimed.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{Hash, HashType, PathInfo, PathStore, RemoteObject, Tier};
    use crate::tenant::{Tenant, TenantId};
    use kubernix_types::Compression;
    use serial_test::serial;
    use sha2::{Sha256, digest::Output};

    // Every test below is `#[serial]`. Unlike `postgres_store`'s tests, which
    // stay isolated from each other by scoping every query to a per-test
    // tenant, `mark_expired` and `sweep_and_reap` are deliberately *not*
    // tenant-scoped — a collector has to see the whole table to do
    // reachability and referrer counting at all. Calling them directly
    // (rather than through `run_gc_pass`'s advisory lock, which only whoever
    // holds it should) from two tests running concurrently races for real:
    // one test's rows can be marked or swept by another's call mid-assertion.
    // `cargo test`'s default parallelism makes that a `cargo test -p
    // kubernix-server` away, not a hypothetical.

    /// Connect, or return `None` after saying why — same pattern as
    /// `postgres_store`'s tests.
    async fn db() -> Option<std::sync::Arc<PostgresStore>> {
        let Ok(url) = std::env::var("KUBERNIX_TEST_DATABASE_URL") else {
            eprintln!("skipping: KUBERNIX_TEST_DATABASE_URL unset");
            return None;
        };
        match PostgresStore::connect(&url, crate::postgres_store::ServingRole::Gc).await {
            Ok(store) => Some(store),
            Err(e) => panic!("KUBERNIX_TEST_DATABASE_URL is set but unusable: {e}"),
        }
    }

    /// Connect to S3, or return `None` after saying why. Unlike [`db`] there
    /// is no single env var that signals intent, so any failure to configure
    /// is read as "not set up for this test" rather than "misconfigured".
    async fn s3() -> Option<UploadSigner> {
        match UploadSigner::from_env().await {
            Ok(signer) => Some(signer),
            Err(e) => {
                eprintln!("skipping: no S3 configuration ({e})");
                None
            }
        }
    }

    fn tenant(test: &str) -> TenantId {
        Tenant::from_ssh(&format!("test-gc-{test}"), None, false).id
    }

    fn info(path: &str) -> PathInfo {
        PathInfo {
            path: kubernix_types::StorePath::new(path),
            deriver: None,
            nar_hash: Hash {
                hash_type: HashType::Sha256,
                bytes: vec![7; 32],
            },
            nar_size: 3,
            references: Vec::new(),
            registration_time: 0,
            ultimate: false,
            sigs: Vec::new(),
        }
    }

    fn object(key: &str) -> RemoteObject {
        RemoteObject {
            key: ObjectKey::new(key),
            file_size: 3,
            file_hash: Output::<Sha256>::from([9u8; 32]),
            compression: Compression::Zstd,
        }
    }

    /// Push `last_access` (and, for the marked/purging tests, `state`) into
    /// the past/into a given state directly — there is no `Store` method for
    /// this on purpose, since nothing on the serving path should ever set
    /// either.
    async fn age(pool: &PgPool, tenant: &TenantId, path: &str, seconds_ago: i64) {
        sqlx::query(
            "UPDATE store_paths SET last_access = NOW() - make_interval(secs => $3)
              WHERE tenant = $1 AND path = $2",
        )
        .bind(tenant.as_str())
        .bind(path)
        .bind(seconds_ago as f64)
        .execute(pool)
        .await
        .unwrap();
    }

    fn tight_cutoffs() -> TierCutoffs {
        TierCutoffs {
            verified: Duration::from_secs(60),
            built: Duration::from_secs(60),
            quarantined: Duration::from_secs(60),
        }
    }

    fn tight_job_retention() -> JobRetention {
        JobRetention {
            log_after: Duration::from_secs(60),
            row_after: Duration::from_secs(60),
            stuck_running_after: Duration::from_secs(60),
        }
    }

    /// Push a job's `finished_at` into the past, same purpose as [`age`] but
    /// for `jobs` rather than `store_paths`.
    async fn age_job(pool: &PgPool, job_id: Uuid, seconds_ago: i64) {
        sqlx::query(
            "UPDATE jobs SET finished_at = NOW() - make_interval(secs => $2) WHERE id = $1",
        )
        .bind(job_id)
        .bind(seconds_ago as f64)
        .execute(pool)
        .await
        .unwrap();
    }

    /// Record a terminal job outcome via the `Store` trait, same as
    /// production code does, rather than inserting the row directly.
    async fn record_job(store: &PostgresStore, t: &TenantId, job_id: Uuid, log_key: &str) {
        let drv = kubernix_types::StorePath::new(format!(
            "00000000000000000000000000000000-{job_id}.drv"
        ));
        store
            .record_job_outcome(
                t,
                job_id,
                &drv,
                "x86_64-linux",
                &crate::jobs::JobOutcome::Failed {
                    message: "test outcome".to_string(),
                    log_key: log_key.to_string(),
                    failure_kind: None,
                },
            )
            .await;
    }

    #[tokio::test]
    #[serial]
    async fn a_stale_unreferenced_path_is_marked() {
        let Some(store) = db().await else { return };
        let t = tenant("stale");
        let path = "00000000000000000000000000000001-a";
        store
            .record_path(&t, info(path), object("gc/a"), Tier::Verified)
            .await
            .unwrap();
        age(&store.pool, &t, path, 3600).await;

        let marked = mark_expired(&mut store.pool.acquire().await.unwrap(), &tight_cutoffs())
            .await
            .unwrap();
        assert!(marked >= 1);

        let state: String =
            sqlx::query_scalar("SELECT state FROM store_paths WHERE tenant = $1 AND path = $2")
                .bind(t.as_str())
                .bind(path)
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(state, "marked");

        // This test only exercises `mark_expired`, deliberately, so it never
        // sweeps this row. Left behind, a `marked`-but-unswept row with no
        // live referrer is exactly what a *later* test's `sweep_and_reap`
        // call would legitimately also clean up — `sweep_and_reap` is
        // global by design (a collector has to see the whole table), so
        // that would inflate another test's own counts nondeterministically
        // depending on execution order. Clean up rather than leave litter
        // for the shared test database.
        sqlx::query("DELETE FROM store_paths WHERE tenant = $1 AND path = $2")
            .bind(t.as_str())
            .bind(path)
            .execute(&store.pool)
            .await
            .unwrap();
        sqlx::query("DELETE FROM objects WHERE key = 'gc/a'")
            .execute(&store.pool)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn a_stale_path_referenced_by_a_fresh_one_survives() {
        // The whole point of the reachability fixpoint: a shared build input
        // must not be collected just because nothing reads it directly.
        let Some(store) = db().await else { return };
        let t = tenant("shared-dep");
        let dep = "00000000000000000000000000000002-dep";
        let referrer = "00000000000000000000000000000003-referrer";

        store
            .record_path(&t, info(dep), object("gc/dep"), Tier::Verified)
            .await
            .unwrap();
        let mut ref_info = info(referrer);
        ref_info.references = vec![kubernix_types::StorePath::new(dep)];
        store
            .record_path(&t, ref_info, object("gc/referrer"), Tier::Verified)
            .await
            .unwrap();

        // The dependency looks idle on its own; the referrer was just read.
        age(&store.pool, &t, dep, 3600).await;

        let marked = mark_expired(&mut store.pool.acquire().await.unwrap(), &tight_cutoffs())
            .await
            .unwrap();
        assert_eq!(marked, 0, "the dependency must survive via the referrer");
    }

    #[tokio::test]
    #[serial]
    async fn a_read_while_marked_resurrects_the_row() {
        let Some(store) = db().await else { return };
        let t = tenant("resurrect");
        let path = "00000000000000000000000000000004-r";
        store
            .record_path(&t, info(path), object("gc/r"), Tier::Verified)
            .await
            .unwrap();
        age(&store.pool, &t, path, 3600).await;
        mark_expired(&mut store.pool.acquire().await.unwrap(), &tight_cutoffs())
            .await
            .unwrap();

        // Confirm the setup: it really is marked, and therefore invisible.
        assert!(
            store
                .query_path_info(&t, &kubernix_types::StorePath::new(path))
                .await
                .is_none()
        );

        store
            .record_access(&t, &kubernix_types::StorePath::new(path))
            .await;
        let drained = drain_access_queue(&mut store.pool.acquire().await.unwrap(), 100)
            .await
            .unwrap();
        assert_eq!(drained, 1);

        assert!(
            store
                .query_path_info(&t, &kubernix_types::StorePath::new(path))
                .await
                .is_some(),
            "an access must resurrect a marked row"
        );
    }

    #[tokio::test]
    #[serial]
    async fn sweep_deletes_an_objects_bytes_once_its_last_referrer_is_marked() {
        let Some(store) = db().await else { return };
        let Some(uploader) = s3().await else { return };
        let t = tenant("sweep");
        let path = "00000000000000000000000000000005-s";
        // A key private to this test, under the tenant's own prefix, so a
        // failure here cannot step on another test's object.
        let key = ObjectKey::new(format!("{t}/nar/gc-sweep-test.nar.zst"));

        uploader
            .put_object(&key, b"anything".to_vec())
            .await
            .expect("seed the object this test deletes");
        store
            .record_path(
                &t,
                info(path),
                RemoteObject {
                    key: key.clone(),
                    file_size: 8,
                    file_hash: Output::<Sha256>::from([0u8; 32]),
                    compression: Compression::Zstd,
                },
                Tier::Built,
            )
            .await
            .unwrap();

        age(&store.pool, &t, path, 3600).await;
        mark_expired(&mut store.pool.acquire().await.unwrap(), &tight_cutoffs())
            .await
            .unwrap();

        let (deleted, reaped) = sweep_and_reap(&mut store.pool.acquire().await.unwrap(), &uploader)
            .await
            .unwrap();
        assert_eq!(deleted, 1);
        assert_eq!(reaped, 1);

        assert!(
            !store.object_known(&key).await,
            "the objects row must be gone"
        );
        // The bytes themselves must be gone too, not just the row about them.
        assert!(
            uploader.get_object(&key).await.is_err(),
            "the object's bytes must actually be deleted from S3"
        );
    }

    #[tokio::test]
    #[serial]
    async fn sweep_leaves_an_object_with_a_live_referrer_alone() {
        let Some(store) = db().await else { return };
        let Some(uploader) = s3().await else { return };
        let t = tenant("sweep-live");
        let path = "00000000000000000000000000000006-l";
        let key = ObjectKey::new(format!("{t}/nar/gc-sweep-live-test.nar.zst"));

        uploader
            .put_object(&key, b"anything".to_vec())
            .await
            .unwrap();
        store
            .record_path(
                &t,
                info(path),
                RemoteObject {
                    key: key.clone(),
                    file_size: 8,
                    file_hash: Output::<Sha256>::from([0u8; 32]),
                    compression: Compression::Zstd,
                },
                Tier::Built,
            )
            .await
            .unwrap();
        // Deliberately not aged: this row is still fresh and 'live'.

        let (deleted, _) = sweep_and_reap(&mut store.pool.acquire().await.unwrap(), &uploader)
            .await
            .unwrap();
        assert_eq!(deleted, 0);
        assert!(store.object_known(&key).await);
    }

    #[tokio::test]
    #[serial]
    async fn run_gc_pass_drives_all_three_steps_end_to_end() {
        let Some(store) = db().await else { return };
        let Some(uploader) = s3().await else { return };
        let t = tenant("full-pass");
        let path = "00000000000000000000000000000007-p";
        let key = ObjectKey::new(format!("{t}/nar/gc-full-pass-test.nar.zst"));

        uploader
            .put_object(&key, b"anything".to_vec())
            .await
            .unwrap();
        store
            .record_path(
                &t,
                info(path),
                RemoteObject {
                    key: key.clone(),
                    file_size: 8,
                    file_hash: Output::<Sha256>::from([0u8; 32]),
                    compression: Compression::Zstd,
                },
                Tier::Built,
            )
            .await
            .unwrap();
        age(&store.pool, &t, path, 3600).await;

        // Scoped to what this test itself created, not exact global counts:
        // `sweep_and_reap` scans every object in the database, so it may
        // legitimately also clean up an already-`marked` row some other
        // test left behind (e.g. one that exercises `mark_expired` in
        // isolation and never sweeps) — that is correct behaviour, not
        // pollution, and asserting exact totals here would make this test
        // depend on what else happens to run in the same suite.
        let stats = run_gc_pass(
            &store,
            &uploader,
            &tight_cutoffs(),
            &tight_job_retention(),
            1000,
        )
        .await
        .unwrap();
        assert!(stats.ran);
        assert!(stats.paths_marked >= 1);
        assert!(stats.objects_deleted >= 1);
        assert!(stats.paths_reaped >= 1);
        assert!(
            store
                .query_path_info(&t, &kubernix_types::StorePath::new(path))
                .await
                .is_none(),
            "this test's own path must have been collected"
        );
        assert!(!store.object_known(&key).await);
    }

    #[tokio::test]
    #[serial]
    async fn a_second_concurrent_pass_finds_the_lock_held_and_does_nothing() {
        let Some(store) = db().await else { return };
        let Some(uploader) = s3().await else { return };

        // Hold the lock on its own connection, exactly as `run_gc_pass` would
        // for the duration of a pass, without ever unlocking it.
        let mut holder = store.pool.acquire().await.unwrap();
        let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
            .bind(GC_LOCK_KEY)
            .fetch_one(&mut *holder)
            .await
            .unwrap();
        assert!(locked, "test setup: expected to take the lock first");

        let stats = run_gc_pass(
            &store,
            &uploader,
            &tight_cutoffs(),
            &tight_job_retention(),
            1000,
        )
        .await
        .unwrap();
        assert!(!stats.ran, "a second collector must not also run the pass");

        sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(GC_LOCK_KEY)
            .execute(&mut *holder)
            .await
            .unwrap();
    }

    #[tokio::test]
    #[serial]
    async fn a_fresh_terminal_jobs_log_survives() {
        let Some(store) = db().await else { return };
        let t = tenant("job-fresh");
        let job_id = Uuid::new_v4();
        record_job(&store, &t, job_id, &format!("{t}/log/fresh")).await;
        // Deliberately not aged: finished_at is ~now.

        let marked = mark_expired_job_logs(
            &mut store.pool.acquire().await.unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
        assert_eq!(marked, 0, "a job that just finished must not be marked yet");

        let log_state: String = sqlx::query_scalar("SELECT log_state FROM jobs WHERE id = $1")
            .bind(job_id)
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(log_state, "present");
    }

    #[tokio::test]
    #[serial]
    async fn an_aged_job_log_is_marked_then_swept() {
        let Some(store) = db().await else { return };
        let Some(uploader) = s3().await else { return };
        let t = tenant("job-sweep");
        let job_id = Uuid::new_v4();
        let key = format!("{t}/log/gc-job-sweep-test");

        uploader
            .put_object(&ObjectKey::new(key.clone()), b"log output".to_vec())
            .await
            .expect("seed the log object this test deletes");
        record_job(&store, &t, job_id, &key).await;
        age_job(&store.pool, job_id, 3600).await;

        let marked = mark_expired_job_logs(
            &mut store.pool.acquire().await.unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
        assert_eq!(marked, 1);

        let purged = sweep_job_logs(&mut store.pool.acquire().await.unwrap(), &uploader)
            .await
            .unwrap();
        assert_eq!(purged, 1);

        let log_state: String = sqlx::query_scalar("SELECT log_state FROM jobs WHERE id = $1")
            .bind(job_id)
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(log_state, "purged");
        let log_key: Option<String> = sqlx::query_scalar("SELECT log_key FROM jobs WHERE id = $1")
            .bind(job_id)
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert!(log_key.is_none());
        assert!(
            uploader.get_object(&ObjectKey::new(key)).await.is_err(),
            "the log's bytes must actually be deleted from S3"
        );
    }

    #[tokio::test]
    #[serial]
    async fn a_job_row_survives_reap_until_its_log_is_purged() {
        let Some(store) = db().await else { return };
        let Some(uploader) = s3().await else { return };
        let t = tenant("job-reap-order");
        let job_id = Uuid::new_v4();
        let key = format!("{t}/log/gc-job-reap-order-test");

        uploader
            .put_object(&ObjectKey::new(key.clone()), b"log output".to_vec())
            .await
            .unwrap();
        record_job(&store, &t, job_id, &key).await;
        age_job(&store.pool, job_id, 3600).await;

        mark_expired_job_logs(
            &mut store.pool.acquire().await.unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();

        // The row is well past its own row cutoff, but the log has only been
        // marked, not swept: reaping now must not lose track of `log_key`.
        let reaped = reap_jobs(
            &mut store.pool.acquire().await.unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
        assert_eq!(
            reaped, 0,
            "a row must not be reaped while its log is still marked"
        );

        sweep_job_logs(&mut store.pool.acquire().await.unwrap(), &uploader)
            .await
            .unwrap();

        let reaped = reap_jobs(
            &mut store.pool.acquire().await.unwrap(),
            Duration::from_secs(60),
        )
        .await
        .unwrap();
        assert_eq!(reaped, 1, "once purged, the row is free to be reaped");
    }

    #[tokio::test]
    #[serial]
    async fn run_gc_pass_also_retires_terminal_jobs_end_to_end() {
        let Some(store) = db().await else { return };
        let Some(uploader) = s3().await else { return };
        let t = tenant("job-full-pass");
        let job_id = Uuid::new_v4();
        let key = format!("{t}/log/gc-job-full-pass-test");

        uploader
            .put_object(&ObjectKey::new(key.clone()), b"log output".to_vec())
            .await
            .unwrap();
        record_job(&store, &t, job_id, &key).await;
        age_job(&store.pool, job_id, 3600).await;

        let stats = run_gc_pass(
            &store,
            &uploader,
            &tight_cutoffs(),
            &tight_job_retention(),
            1000,
        )
        .await
        .unwrap();
        assert!(stats.ran);
        assert!(stats.job_logs_marked >= 1);
        assert!(stats.job_logs_purged >= 1);
        assert!(stats.jobs_reaped >= 1);

        let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM jobs WHERE id = $1")
            .bind(job_id)
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(
            remaining, 0,
            "this test's own job row must have been reaped"
        );
        assert!(uploader.get_object(&ObjectKey::new(key)).await.is_err());
    }
}
