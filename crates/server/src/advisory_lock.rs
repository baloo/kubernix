//! A Postgres session-level advisory lock, held for the lifetime of an
//! [`AdvisoryLock`] guard, guaranteed never to leak into the pool still held.
//!
//! `crate::gc` and `crate::rotate` each run one periodic pass under their own
//! fixed advisory-lock key, so that more than one replica on the same
//! schedule degrades to one doing the work and one doing nothing, rather than
//! racing. Both used to hand-roll the same acquire/run/unlock sequence; this
//! module is that sequence, written once.
//!
//! A session-level advisory lock outlives the query that took it, so handing
//! the connection back to the pool without unlocking would leave the lock
//! held against whatever borrows that physical connection next. The naive
//! fix — unlock, then return to the pool regardless of whether the unlock
//! query itself succeeded — has a hole: if `pg_advisory_unlock` fails (a
//! dropped connection mid-query, say), the connection goes back to the pool
//! *still holding the lock*, and stays that way until the pool happens to
//! recycle it — which, for a long-lived pool under light connection churn,
//! may be a very long time. [`AdvisoryLock::release`] closes that hole:
//! on unlock failure, it marks the connection to be closed rather than
//! pool-returned. [`Drop`] does the same for the "never called `release` at
//! all" case (an early return, or a panic unwinding through the pass) —
//! `close_on_drop` is a synchronous flag, not a query, so it works even
//! though `Drop` cannot `.await`.

use sqlx::PgPool;
use sqlx::pool::PoolConnection;
use sqlx::postgres::{PgConnection, Postgres};

/// Held for as long as this replica is the one running a pass. See the
/// module doc for why a `bool` flag plus a `Drop` impl is the shape this
/// needs to be, rather than just unlocking inline wherever a pass ends.
pub struct AdvisoryLock {
    conn: PoolConnection<Postgres>,
    key: i64,
    released: bool,
}

impl AdvisoryLock {
    /// Acquire a pooled connection and try to take the advisory lock on it.
    ///
    /// `Ok(None)` means another replica already holds `key` — the expected
    /// steady state with more than one collector/rotator running, not an
    /// error. The connection taken to check is simply returned to the pool
    /// unlocked in that case.
    pub async fn try_acquire(pool: &PgPool, key: i64) -> Result<Option<Self>, sqlx::Error> {
        let mut conn = pool.acquire().await?;

        let locked: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1)")
            .bind(key)
            .fetch_one(&mut *conn)
            .await?;
        if !locked {
            return Ok(None);
        }

        Ok(Some(Self {
            conn,
            key,
            released: false,
        }))
    }

    /// The connection to run the locked pass on.
    pub fn conn(&mut self) -> &mut PgConnection {
        &mut self.conn
    }

    /// Release the lock, consuming the guard. On success the connection
    /// returns to the pool normally (unlocked) when it drops. On failure to
    /// unlock, the connection is marked to be closed rather than pool-
    /// returned — see the module doc for why that matters.
    pub async fn release(mut self) -> Result<(), sqlx::Error> {
        let result = sqlx::query("SELECT pg_advisory_unlock($1)")
            .bind(self.key)
            .execute(&mut *self.conn)
            .await;
        self.released = true;
        if result.is_err() {
            self.conn.close_on_drop();
        }
        result.map(|_| ())
    }
}

impl Drop for AdvisoryLock {
    fn drop(&mut self) {
        if !self.released {
            // `release` was never called — an early return before it, or a
            // panic unwinding through the locked pass. Either way, the lock
            // is still held and there is no async context here to unlock it
            // properly; the only sync-safe move is to make sure this
            // connection is closed rather than returned to the pool still
            // holding it.
            self.conn.close_on_drop();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn db() -> Option<PgPool> {
        let Ok(url) = std::env::var("KUBERNIX_TEST_DATABASE_URL") else {
            eprintln!("skipping: KUBERNIX_TEST_DATABASE_URL unset");
            return None;
        };
        match PgPool::connect(&url).await {
            Ok(pool) => Some(pool),
            Err(e) => panic!("KUBERNIX_TEST_DATABASE_URL is set but unusable: {e}"),
        }
    }

    // Distinct from `gc`'s and `rotate`'s own keys, and from each other, so
    // a test here can never contend with those modules' passes or with
    // another test in this file running concurrently.
    const TEST_KEY_A: i64 = 0x6b756e_67740001; // "kunga t" + 1
    const TEST_KEY_B: i64 = 0x6b756e_67740002; // "kunga t" + 2

    #[tokio::test]
    async fn a_second_acquire_finds_it_held_and_a_third_finds_it_free_after_release() {
        let Some(pool) = db().await else { return };

        let guard = AdvisoryLock::try_acquire(&pool, TEST_KEY_A)
            .await
            .unwrap()
            .expect("first acquire must succeed");
        assert!(
            AdvisoryLock::try_acquire(&pool, TEST_KEY_A)
                .await
                .unwrap()
                .is_none(),
            "a second acquire must see the lock held"
        );

        guard.release().await.unwrap();

        assert!(
            AdvisoryLock::try_acquire(&pool, TEST_KEY_A)
                .await
                .unwrap()
                .is_some(),
            "released, a fresh acquire must succeed again"
        );
    }

    #[tokio::test]
    async fn dropping_without_releasing_does_not_strand_the_lock_in_the_pool() {
        let Some(pool) = db().await else { return };

        {
            let _guard = AdvisoryLock::try_acquire(&pool, TEST_KEY_B)
                .await
                .unwrap()
                .expect("acquire must succeed");
            // Dropped here without calling `release` — simulates an early
            // return or a panic partway through a pass.
        }

        // If `Drop` merely returned the connection to the pool, the lock
        // would still be held on it (session-level locks outlive the
        // connection being idle, only a real close drops them) and this
        // pool, being small in tests, would likely hand that same
        // connection back out, wrongly reporting the lock as still taken.
        assert!(
            AdvisoryLock::try_acquire(&pool, TEST_KEY_B)
                .await
                .unwrap()
                .is_some(),
            "an unreleased guard must not leave the lock stuck in the pool"
        );
    }
}
