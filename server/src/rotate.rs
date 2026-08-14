//! Capability-secret rotation — PLAN.md Phase 14.
//!
//! Driven by `kubernix-rotate-capability-secret`
//! (`server/src/bin/kubernix-rotate-capability-secret.rs`), on its own
//! interval, deliberately separate from GC (`crate::gc`): it mints and prunes
//! rows in `capability_secrets`, a different table with a different blast
//! radius, and there is no reason to couple their schedules.
//!
//! Not a correctness dependency: [`crate::store::Store::current_capability_secret`]
//! already lazily mints a secret on first use if none exists, the same way
//! [`crate::store::Store::signer`] does for a tenant's signing key. Running
//! this periodically only improves things — by rotating under a cadence
//! rather than never — it does not gate anything from working.

use std::time::Duration;

use sqlx::Connection;
use sqlx::postgres::PgConnection;

use crate::advisory_lock::AdvisoryLock;
use crate::postgres_store::PostgresStore;

/// Fixed key for `pg_try_advisory_lock`, distinct from `crate::gc`'s — see
/// that module's doc comment for why one exists at all: so that more than one
/// replica running this on the same schedule degrades to one doing the work,
/// not two racing.
const ROTATE_LOCK_KEY: i64 = 0x6b756e_67720001; // "kung gr" ("gc" -> "gr" for rotate)

#[derive(Debug, Default, Clone, Copy)]
pub struct RotateStats {
    /// Whether this call actually ran, or found the advisory lock already
    /// held by another replica.
    pub ran: bool,
    pub inserted: bool,
    /// Rows that went from current to retired this pass — ordinarily 0 or 1;
    /// see [`rotate_locked`] for when it can (harmlessly) be more.
    pub retired: u64,
    pub pruned: u64,
}

/// Mint a new current secret, retiring whatever was current, and delete any
/// secret that has been retired for longer than `retention` — under the
/// advisory lock, one pass, safe to call on a timer from more than one
/// replica.
pub async fn rotate(
    store: &PostgresStore,
    retention: Duration,
) -> Result<RotateStats, sqlx::Error> {
    let Some(mut lock) = AdvisoryLock::try_acquire(&store.pool, ROTATE_LOCK_KEY).await? else {
        tracing::debug!("rotation pass skipped: another replica holds the lock");
        return Ok(RotateStats::default());
    };

    let result = rotate_locked(lock.conn(), retention).await;

    // See `crate::advisory_lock` for how the lock is guaranteed not to leak
    // into the pool still held, on any exit path.
    if let Err(e) = lock.release().await {
        tracing::error!(error = %e, "failed to release the rotation advisory lock");
    }

    result
}

async fn rotate_locked(
    conn: &mut PgConnection,
    retention: Duration,
) -> Result<RotateStats, sqlx::Error> {
    // Retiring the old current row and inserting its replacement must be
    // atomic: on separate auto-committed statements, a reader in between
    // (`Store::current_capability_secret`, running on a different connection)
    // could observe a moment with no un-retired row at all. The advisory lock
    // held by `rotate` only keeps other *rotations* from interleaving; it
    // says nothing about ordinary reads, which never take it. Wrapping just
    // these two statements in a transaction is what actually closes the gap:
    // nothing outside this transaction sees the retirement until the insert
    // has committed alongside it.
    let mut tx = conn.begin().await?;

    // Retire whatever is current *before* minting its replacement, so the
    // row this call is about to insert is unambiguously the only one left
    // with `rotated_out_at IS NULL` afterwards. Normally retires exactly one
    // row; more only if an earlier pass crashed mid-transaction, which this
    // simply heals rather than needing separate recovery.
    let retired = sqlx::query(
        "UPDATE capability_secrets SET rotated_out_at = now() WHERE rotated_out_at IS NULL",
    )
    .execute(&mut *tx)
    .await?
    .rows_affected();

    let secret: [u8; 32] = rand::random();
    sqlx::query("INSERT INTO capability_secrets (secret) VALUES ($1)")
        .bind(secret.as_slice())
        .execute(&mut *tx)
        .await?;

    tx.commit().await?;

    // Pruning doesn't need the transaction above: it only ever removes rows
    // that are already retired and past their grace period, which has no
    // bearing on "is there a current key" — the invariant the transaction
    // exists to protect. Running it as a separate statement keeps the
    // transaction's lock footprint to just the two writes that must be
    // atomic.
    //
    // Retention counts from the moment a secret was *retired*, not from when
    // it was minted — see the migration's doc comment for why: a secret that
    // stayed current through a long gap between passes (the rotator was down,
    // lost its lock, whatever) must still get a full retention window from
    // the moment this pass finally retires it, not be deleted outright for
    // having been minted longer than `retention` ago. The never-retired
    // current row (`rotated_out_at IS NULL`) is therefore never a pruning
    // candidate, at any age.
    let retention_secs = retention.as_secs() as f64;
    let pruned = sqlx::query(
        "DELETE FROM capability_secrets
          WHERE rotated_out_at IS NOT NULL
            AND rotated_out_at < now() - make_interval(secs => $1)",
    )
    .bind(retention_secs)
    .execute(&mut *conn)
    .await?
    .rows_affected();

    Ok(RotateStats {
        ran: true,
        inserted: true,
        retired,
        pruned,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    // `#[serial]`, like `gc`'s Postgres-backed tests: these mutate the whole
    // `capability_secrets` table (it has no per-tenant scoping to isolate
    // by), so two of them running concurrently would race for real.

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

    #[tokio::test]
    #[serial]
    async fn rotation_inserts_and_prunes() {
        let Some(store) = db().await else { return };

        // A fresh secret younger than any retention window survives...
        let before: i64 = sqlx::query_scalar("SELECT count(*) FROM capability_secrets")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        let stats = rotate(&store, Duration::from_secs(3600))
            .await
            .expect("rotates");
        assert!(stats.ran && stats.inserted);
        let after: i64 = sqlx::query_scalar("SELECT count(*) FROM capability_secrets")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(after, before + 1);

        // ...but a zero-second retention prunes everything already retired,
        // leaving only the row this very call just inserted (still current,
        // so never a pruning candidate regardless of retention).
        let stats = rotate(&store, Duration::from_secs(0))
            .await
            .expect("rotates");
        assert!(stats.ran);
        let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM capability_secrets")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(remaining, 1);
    }

    #[tokio::test]
    #[serial]
    async fn a_long_overdue_secret_gets_a_full_grace_period_when_finally_retired() {
        // Regression: retention must count from when a secret is *retired*,
        // not from when it was minted. A rotator that has not run in far
        // longer than `retention` (down, lost its lock, whatever) must not
        // delete the secret that was current the whole time out from under
        // itself the instant it finally gets superseded — every token signed
        // with it up to that moment needs a real grace period to keep
        // verifying.
        let Some(store) = db().await else { return };
        sqlx::query("DELETE FROM capability_secrets")
            .execute(&store.pool)
            .await
            .unwrap();

        // Minted long before any sane retention window, and still current —
        // exactly what "the rotator hasn't run in a very long time" leaves
        // behind.
        sqlx::query(
            "INSERT INTO capability_secrets (secret, created_at) \
             VALUES ($1, now() - interval '30 days')",
        )
        .bind([0u8; 32].as_slice())
        .execute(&store.pool)
        .await
        .unwrap();

        let stats = rotate(&store, Duration::from_secs(3600))
            .await
            .expect("rotates");
        assert_eq!(
            stats.retired, 1,
            "the long-overdue secret should finally be retired, not left current forever"
        );

        let remaining: i64 = sqlx::query_scalar("SELECT count(*) FROM capability_secrets")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(
            remaining, 2,
            "the just-retired secret must survive this pass despite its age — \
             it gets a full retention window starting now, not measured from \
             when it was minted"
        );
    }
}
