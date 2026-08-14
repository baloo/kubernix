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

#[derive(Debug, Default, Clone, Copy)]
pub struct GcStats {
    /// Whether this call actually ran the passes, or found the advisory lock
    /// already held by another collector and did nothing.
    pub ran: bool,
    pub access_marks_drained: u64,
    pub paths_marked: u64,
    pub objects_deleted: u64,
    pub paths_reaped: u64,
}

#[derive(Debug)]
pub enum GcError {
    Database(sqlx::Error),
    /// An object failed to delete from the object store. Not fatal to the
    /// pass — the row stays `purging` and the next pass retries it — but
    /// worth the caller knowing about.
    Upload {
        key: ObjectKey,
        error: String,
    },
}

impl std::fmt::Display for GcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GcError::Database(e) => write!(f, "database: {e}"),
            GcError::Upload { key, error } => write!(f, "deleting {key}: {error}"),
        }
    }
}

impl std::error::Error for GcError {}

impl From<sqlx::Error> for GcError {
    fn from(e: sqlx::Error) -> Self {
        GcError::Database(e)
    }
}

type Result<T> = std::result::Result<T, GcError>;

/// Run one full drain → mark → sweep+reap pass, under the advisory lock.
///
/// Acquires a single connection and holds the lock on it for the whole pass,
/// unlocking before returning — a session-level advisory lock outlives the
/// query that took it, so returning the connection to the pool without
/// explicitly unlocking would leave it held against whatever borrows that
/// physical connection next.
///
/// Returns `Ok(GcStats { ran: false, .. })`, not an error, when another
/// collector already holds the lock — that is the expected steady state with
/// more than one `kubernix-gc` replica running.
pub async fn run_gc_pass(
    store: &PostgresStore,
    uploader: &UploadSigner,
    cutoffs: &TierCutoffs,
    batch_size: i64,
) -> Result<GcStats> {
    run_gc_pass_on(&store.pool, uploader, cutoffs, batch_size).await
}

async fn run_gc_pass_on(
    pool: &PgPool,
    uploader: &UploadSigner,
    cutoffs: &TierCutoffs,
    batch_size: i64,
) -> Result<GcStats> {
    let mut conn = pool.acquire().await?;

    let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
        .bind(GC_LOCK_KEY)
        .fetch_one(&mut *conn)
        .await?;
    if !locked {
        tracing::debug!("gc pass skipped: another collector holds the lock");
        return Ok(GcStats::default());
    }

    let result = run_locked(&mut conn, uploader, cutoffs, batch_size).await;

    // Unlock regardless of how the pass above went, so a mid-pass error does
    // not strand the lock until this connection happens to close.
    if let Err(e) = sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(GC_LOCK_KEY)
        .execute(&mut *conn)
        .await
    {
        tracing::error!(error = %e, "failed to release the gc advisory lock");
    }

    result
}

async fn run_locked(
    conn: &mut PgConnection,
    uploader: &UploadSigner,
    cutoffs: &TierCutoffs,
    batch_size: i64,
) -> Result<GcStats> {
    let access_marks_drained = drain_access_queue(conn, batch_size).await?;
    let paths_marked = mark_expired(conn, cutoffs).await?;
    let (objects_deleted, paths_reaped) = sweep_and_reap(conn, uploader).await?;

    tracing::info!(
        access_marks_drained,
        paths_marked,
        objects_deleted,
        paths_reaped,
        "gc pass complete"
    );

    Ok(GcStats {
        ran: true,
        access_marks_drained,
        paths_marked,
        objects_deleted,
        paths_reaped,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{Hash, HashType, PathInfo, RemoteObject, Store, Tier};
    use crate::tenant::{Tenant, TenantId};
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
        match PostgresStore::connect(&url).await {
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

    #[tokio::test]
    #[serial]
    async fn a_stale_unreferenced_path_is_marked() {
        let Some(store) = db().await else { return };
        let t = tenant("stale");
        let path = "/nix/store/00000000000000000000000000000001-a";
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
        let dep = "/nix/store/00000000000000000000000000000002-dep";
        let referrer = "/nix/store/00000000000000000000000000000003-referrer";

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
        let path = "/nix/store/00000000000000000000000000000004-r";
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
        let path = "/nix/store/00000000000000000000000000000005-s";
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
        let path = "/nix/store/00000000000000000000000000000006-l";
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
        let path = "/nix/store/00000000000000000000000000000007-p";
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
        let stats = run_gc_pass(&store, &uploader, &tight_cutoffs(), 1000)
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

        let stats = run_gc_pass(&store, &uploader, &tight_cutoffs(), 1000)
            .await
            .unwrap();
        assert!(!stats.ran, "a second collector must not also run the pass");

        sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(GC_LOCK_KEY)
            .execute(&mut *holder)
            .await
            .unwrap();
    }
}
