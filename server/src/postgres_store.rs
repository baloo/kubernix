//! [`Store`] backed by PostgreSQL.
//!
//! The frontend's system of record. Without it every path is forgotten on
//! restart, which strands the objects a worker already uploaded: the bytes stay
//! in the object store but nothing knows their keys or hashes. It is also what
//! lets more than one frontend replica serve the same clients.
//!
//! The schema is `server/migrations/`. Two things worth knowing here:
//!
//! * every lookup is scoped by tenant, matching [`crate::store::MemoryStore`] —
//!   the primary key is `(tenant, path)`;
//! * failures are logged and reported as an empty answer for queries, because
//!   the daemon protocol has no way to say "I could not tell" about most of
//!   them. Writes propagate their error, since a lost write is not something to
//!   paper over.
//!
//! ## Why every operation goes through an actor
//!
//! Each SSH connection the frontend serves gets its own dedicated OS thread
//! with a single-threaded Tokio runtime (`server/src/ssh.rs`'s `exec_request`
//! — capnp-rpc capabilities are `!Send`, PLAN.md Phase 4). If that thread also
//! awaits `sqlx` calls directly, the number of OS threads independently
//! trying to poll a pool-acquire timeout grows with the number of concurrent
//! connections, unbounded. Under load a thread can go unscheduled long enough
//! that its own `acquire_timeout` future never gets polled at all, turning a
//! bounded ~30s wait into an apparently-unbounded hang — observed in
//! practice (PLAN.md Phase 8 and Phase 16's status notes).
//!
//! The fix: no caller — not a connection's dedicated thread, not the main
//! runtime's `auth_publickey` task — ever awaits `self.pool` directly.
//! Instead every [`PathStore`]/[`CapabilitySecretStore`]/[`TenantAuthStore`]
//! method sends a [`DbRequest`] over an `mpsc` channel and awaits a `oneshot`
//! reply. The channel is served by [`spawn_db_actor`], a small, fixed number
//! of worker threads ([`db_actor_threads`]) on their own dedicated runtime,
//! independent of how many SSH connections exist. That bounds the count of
//! threads that ever need to stay promptly scheduled to poll a database
//! timeout, decoupling it from connection count entirely. Real concurrency is
//! unaffected: the actor spawns each request as its own task rather than
//! serializing them, so the `PgPool`'s own `max_connections` remains the only
//! throughput limit, exactly as before.
//!
//! No cross-request transactions are needed (nothing in this codebase
//! composes more than one `Store` call into one atomic unit — see
//! `record_outputs` in `daemon_rpc.rs`, whose "all-or-nothing" is an
//! application-level check-before-any-write, not a DB transaction spanning
//! several operations), and no ordering guarantee beyond what already
//! exists: a single caller's own calls are already ordered by the fact that
//! it awaits each reply before issuing the next, and concurrent writes from
//! different callers were never ordered relative to each other — Postgres's
//! own `ON CONFLICT`/MVCC semantics resolve those the same way with or
//! without the actor in between.

use std::sync::Arc;
use std::time::Duration;

use sha2::{Sha256, digest::Output};
use sqlx::Row;
use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
use tokio::sync::{mpsc, oneshot};

use crate::jobs::JobOutcome;
use crate::store::{
    CapabilitySecretStore, Hash, HashType, MissingPaths, PathInfo, PathStore, RemoteObject,
    Reservation, Result, StoreError, TenantAuthStore, Tier,
};
use kubernix_signing::{KIND_LOCAL_ED25519, LocalSigner, Signer, key_name_for};
use kubernix_types::{ObjectKey, StorePath};
use uuid::Uuid;

use crate::tenant::{KeyType, Tenant, TenantId};

/// Worker threads on the dedicated runtime [`DbRequest`]s are served from.
///
/// Fixed and small, deliberately independent of how many SSH connections are
/// open: that decoupling is the whole point of the actor (see the module doc
/// comment). `num_cpus` rather than a hardcoded constant, since it is the
/// same "keep pace with the box's actual scheduling capacity" reasoning that
/// picked worker-thread counts everywhere else in this codebase.
fn db_actor_threads() -> usize {
    std::thread::available_parallelism().map_or(4, |n| n.get())
}

pub struct PostgresStore {
    // `pub(crate)` rather than private: `crate::gc` runs its own statements
    // (advisory lock, drain/mark/sweep) directly against the pool, which is
    // GC-specific enough that it does not belong on the `Store` trait. This
    // bypasses the actor below entirely — `kubernix-gc`/`kubernix-rotate-
    // capability-secret` are their own processes with their own pool, never
    // sharing the SSH frontend's per-connection thread pile-up, so there is
    // nothing for the actor to fix for them.
    pub(crate) pool: PgPool,
    /// In-process cache over `capability_secrets`, so minting/verifying a
    /// token is not a database round trip on every request. Global rather
    /// than per-tenant, like the table itself.
    ///
    /// `std::sync::Mutex`, not `tokio::sync::Mutex`: every acquisition below
    /// is released before the next `.await`, so there is nothing here an
    /// async-aware lock buys — and using the plain one is what
    /// `store::MemoryStore` already does for its own locks, which this
    /// matches rather than mixing lock strategies for no functional reason.
    capability_secrets: std::sync::Mutex<CapabilitySecretCache>,
    /// Every [`Store`](crate::store::Store)-trait operation is dispatched
    /// here rather than run inline — see [`DbRequest`] and the module doc
    /// comment for why.
    db_tx: mpsc::UnboundedSender<DbRequest>,
}

/// Positive cache for capability secrets. Safe to hold stale for a while:
/// `current` merely delays picking up a rotation by up to
/// [`CAPABILITY_SECRET_CACHE_TTL`], and `by_kid` entries never change once a
/// row exists (a `kid` is never reused), so a cached-but-since-deleted secret
/// is only ever a little more lenient than the database, never less.
#[derive(Default)]
struct CapabilitySecretCache {
    current: Option<(std::time::Instant, u64, [u8; 32])>,
    by_kid: std::collections::HashMap<u64, [u8; 32]>,
}

const CAPABILITY_SECRET_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(60);

/// `<32-char hash>-<name>` → `<32-char hash>`.
///
/// Stored alongside the path so `queryPathFromHashPart` is an index lookup.
fn hash_part_of(path: &str) -> &str {
    path.rsplit('/')
        .next()
        .and_then(|base| base.split('-').next())
        .unwrap_or("")
}

fn algo_name(algo: HashType) -> &'static str {
    match algo {
        HashType::Md5 => "md5",
        HashType::Sha1 => "sha1",
        HashType::Sha256 => "sha256",
        HashType::Sha512 => "sha512",
    }
}

fn algo_from_name(name: &str) -> HashType {
    match name {
        "md5" => HashType::Md5,
        "sha1" => HashType::Sha1,
        "sha512" => HashType::Sha512,
        // Everything we produce is sha256; an unknown value is a schema
        // mismatch, and guessing sha256 is the least surprising reading.
        _ => HashType::Sha256,
    }
}

fn db_err(e: sqlx::Error) -> StoreError {
    StoreError::Other(format!("database: {e}"))
}

/// Which of the two low-privilege Postgres roles a connecting binary serves
/// as — see `server/migrations/20260814120000_row_level_security.sql` for
/// why there are two, not one, and what each is granted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServingRole {
    /// kubernix-sshd, kubernix-cache: tenant-scoped, row-security-restricted
    /// to whatever `app.current_tenant` a query has set (see
    /// [`PostgresStore::tenant_scoped`]).
    App,
    /// kubernix-gc, kubernix-rotate-capability-secret: `BYPASSRLS`, because
    /// these scan every tenant's rows by design — see `crate::gc`'s module
    /// doc.
    Gc,
}

impl ServingRole {
    fn db_role(self) -> &'static str {
        match self {
            ServingRole::App => "kubernix_app",
            ServingRole::Gc => "kubernix_gc",
        }
    }
}

impl PostgresStore {
    /// Connect, apply migrations, then reconnect as `role`'s own scoped
    /// serving role.
    ///
    /// `url` is used twice, for two different purposes: first as a
    /// privileged *bootstrap* connection — expected to authenticate as an
    /// owner/superuser role able to run DDL (creating the `kubernix_app`/
    /// `kubernix_gc` roles themselves, `ALTER TABLE ... ENABLE ROW LEVEL
    /// SECURITY`, and so on) — which runs the migrations and is then
    /// dropped; then again, with only its username swapped for `role`'s, to
    /// open the actual serving pool this function returns. A fresh
    /// deployment still needs no separate provisioning step (one URL, one
    /// `connect` call) while the long-lived pool a compromised serving path
    /// could misuse never holds more than `role`'s own narrow grants — see
    /// the migration's doc comment for the full reasoning.
    pub async fn connect(
        url: &str,
        role: ServingRole,
    ) -> std::result::Result<Arc<Self>, sqlx::Error> {
        tracing::info!("connecting to PostgreSQL to apply migrations");
        let bootstrap = PgPoolOptions::new().max_connections(1).connect(url).await?;

        // Applied on startup rather than by a separate step so a fresh
        // deployment works without one.
        sqlx::migrate!("./migrations")
            .run(&bootstrap)
            .await
            .map_err(|e| sqlx::Error::Configuration(Box::new(e)))?;
        bootstrap.close().await;

        let db_role = role.db_role();
        tracing::info!(
            role = db_role,
            "connecting to PostgreSQL as the serving role"
        );
        let opts: PgConnectOptions = url.parse()?;
        let pool = PgPoolOptions::new()
            .max_connections(16)
            .connect_with(opts.username(db_role))
            .await?;

        tracing::info!("database ready");
        let (db_tx, db_rx) = mpsc::unbounded_channel();
        let store = Arc::new(Self {
            pool,
            capability_secrets: std::sync::Mutex::new(CapabilitySecretCache::default()),
            db_tx,
        });
        spawn_db_actor(Arc::clone(&store), db_rx);
        Ok(store)
    }

    /// Begin a transaction with `app.current_tenant` set to `tenant` for its
    /// duration — the connection-side half of the tenant-isolation policies
    /// in `server/migrations/20260814120000_row_level_security.sql`. Every
    /// method below that takes a `tenant: &TenantId` and touches
    /// `store_paths`, `jobs`, or `path_access` goes through this rather than
    /// a bare `&self.pool` query — otherwise its own `WHERE tenant = $1`
    /// predicate would be the only thing enforcing isolation, exactly the
    /// single point of failure row-level security exists to back up.
    ///
    /// A transaction, not a bare `SET`, because `set_config(..., true)` (the
    /// "is_local" form — equivalent to `SET LOCAL`, but usable with a bound
    /// parameter, which a literal `SET LOCAL` statement is not) only holds
    /// for the duration of one; without a transaction wrapping it, the GUC
    /// would leak onto whatever this pooled connection is checked out for
    /// next.
    async fn tenant_scoped(
        &self,
        tenant: &TenantId,
    ) -> sqlx::Result<sqlx::Transaction<'_, sqlx::Postgres>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT set_config('app.current_tenant', $1, true)")
            .bind(tenant.as_str())
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }

    /// Begin a transaction with the narrow cross-tenant carve-out
    /// [`Self::find_verified_by_hash_part`] needs set for its duration — see
    /// the `cross_tenant_verified_read` policy in the row-level-security
    /// migration for exactly what this does and does not widen.
    async fn cross_tenant_verified_read_scoped(
        &self,
    ) -> sqlx::Result<sqlx::Transaction<'_, sqlx::Postgres>> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT set_config('app.allow_cross_tenant_verified_read', 'true', true)")
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }

    /// Record a tenant so the foreign keys on `store_paths` and `jobs` resolve.
    ///
    /// Called before every write rather than once at connect: a tenant is
    /// created by the act of using the frontend, and there is no separate
    /// registration step. `verified` is refreshed on conflict so that turning
    /// auth on upgrades an existing row rather than leaving it stale.
    pub async fn ensure_tenant(&self, tenant: &Tenant) -> Result<()> {
        sqlx::query(
            "INSERT INTO tenants (id, identity, verified) VALUES ($1, $2, $3)
             ON CONFLICT (id) DO UPDATE SET verified = EXCLUDED.verified",
        )
        .bind(tenant.id.as_str())
        .bind(&tenant.identity)
        .bind(tenant.verified)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    /// Insert the tenant id alone, for the write paths that only have an id.
    ///
    /// The identity is unknown here, so the row is a placeholder that
    /// [`Self::ensure_tenant`] fills in when the same tenant connects.
    async fn ensure_tenant_id(&self, tenant: &TenantId) -> Result<()> {
        sqlx::query(
            "INSERT INTO tenants (id, identity) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING",
        )
        .bind(tenant.as_str())
        .bind(format!("unknown:{tenant}"))
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }

    fn row_to_info(row: &sqlx::postgres::PgRow) -> PathInfo {
        PathInfo {
            path: StorePath::new(row.get::<String, _>("path")),
            deriver: row.get::<Option<String>, _>("deriver").map(StorePath::new),
            nar_hash: Hash {
                hash_type: algo_from_name(row.get::<String, _>("nar_hash_algo").as_str()),
                bytes: row.get("nar_hash"),
            },
            nar_size: row.get::<i64, _>("nar_size") as u64,
            references: row
                .get::<Vec<String>, _>("refs")
                .into_iter()
                .map(StorePath::new)
                .collect(),
            registration_time: row.get("registration_time"),
            ultimate: row.get("ultimate"),
            sigs: row.get("sigs"),
        }
    }

    /// Upsert a path's metadata.
    ///
    /// No bytes: the database records *where* a path is, never what it holds.
    ///
    /// The object is upserted first, in the same transaction, `ON CONFLICT
    /// (key) DO NOTHING` — PLAN.md Phase 9c. For a `Built` or `Quarantined`
    /// key that is a no-op the first time and never fires again, since those
    /// keys are unique per tenant. For a `Verified` key it is the dedup
    /// itself: whichever tenant's push lands first owns the row, and every
    /// later tenant pushing the same content merely points at it.
    async fn upsert_path(
        &self,
        tenant: &TenantId,
        info: &PathInfo,
        object: &RemoteObject,
        tier: Tier,
    ) -> Result<()> {
        self.ensure_tenant_id(tenant).await?;

        let mut txn = self.tenant_scoped(tenant).await.map_err(db_err)?;

        sqlx::query(
            "INSERT INTO objects (key, file_size, file_hash) VALUES ($1, $2, $3)
             ON CONFLICT (key) DO NOTHING",
        )
        .bind(object.key.as_str())
        .bind(object.file_size as i64)
        .bind(&object.file_hash[..])
        .execute(&mut *txn)
        .await
        .map_err(db_err)?;

        let references: Vec<&str> = info.references.iter().map(StorePath::as_str).collect();

        sqlx::query(
            "INSERT INTO store_paths (
                 tenant, path, hash_part, deriver, nar_hash_algo, nar_hash, nar_size,
                 registration_time, ultimate, refs, sigs, object_key, tier
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
             ON CONFLICT (tenant, path) DO UPDATE SET
                 deriver = EXCLUDED.deriver,
                 nar_hash_algo = EXCLUDED.nar_hash_algo,
                 nar_hash = EXCLUDED.nar_hash,
                 nar_size = EXCLUDED.nar_size,
                 registration_time = EXCLUDED.registration_time,
                 ultimate = EXCLUDED.ultimate,
                 refs = EXCLUDED.refs,
                 sigs = EXCLUDED.sigs,
                 object_key = EXCLUDED.object_key,
                 tier = EXCLUDED.tier,
                 -- A path being (re-)recorded is evidence it is wanted right
                 -- now — most commonly a worker rebuilding an output GC had
                 -- already marked. Without this the row would stay 'marked'
                 -- and the next sweep could delete bytes that were just
                 -- written. PLAN.md Phase 12's resurrection rule applies here
                 -- too, not only on the read path.
                 last_access = NOW(),
                 state = 'live',
                 marked_at = NULL",
        )
        .bind(tenant.as_str())
        .bind(info.path.as_str())
        .bind(hash_part_of(info.path.as_str()))
        .bind(info.deriver.as_ref().map(StorePath::as_str))
        .bind(algo_name(info.nar_hash.hash_type))
        .bind(&info.nar_hash.bytes)
        .bind(info.nar_size as i64)
        .bind(info.registration_time)
        .bind(info.ultimate)
        .bind(&references)
        .bind(&info.sigs)
        .bind(object.key.as_str())
        .bind(tier.as_str())
        .execute(&mut *txn)
        .await
        .map_err(db_err)?;

        txn.commit().await.map_err(db_err)?;
        Ok(())
    }
}

/// The database work behind every [`Store`](crate::store::Store) operation.
///
/// Named `_db` throughout to keep them unambiguously distinct from the
/// dispatching trait methods below, which share a base name but send a
/// [`DbRequest`] instead of touching `self.pool` directly — see the module
/// doc comment.
impl PostgresStore {
    async fn is_valid_path_db(&self, tenant: &TenantId, path: &StorePath) -> bool {
        let Ok(mut tx) = self.tenant_scoped(tenant).await else {
            tracing::error!(%tenant, %path, "could not open a tenant-scoped transaction");
            return false;
        };
        sqlx::query("SELECT 1 FROM store_paths_live WHERE tenant = $1 AND path = $2")
            .bind(tenant.as_str())
            .bind(path.as_str())
            .fetch_optional(&mut *tx)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, %path, "isValidPath query failed");
                None
            })
            .is_some()
    }

    async fn query_valid_paths_db(&self, tenant: &TenantId, paths: &[StorePath]) -> Vec<StorePath> {
        let Ok(mut tx) = self.tenant_scoped(tenant).await else {
            tracing::error!(%tenant, "could not open a tenant-scoped transaction");
            return Vec::new();
        };
        let raw: Vec<&str> = paths.iter().map(StorePath::as_str).collect();
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT path FROM store_paths_live WHERE tenant = $1 AND path = ANY($2)",
        )
        .bind(tenant.as_str())
        .bind(&raw)
        .fetch_all(&mut *tx)
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "queryValidPaths failed");
            Vec::new()
        });
        rows.into_iter().map(StorePath::new).collect()
    }

    async fn query_all_valid_paths_db(&self, tenant: &TenantId) -> Vec<StorePath> {
        let Ok(mut tx) = self.tenant_scoped(tenant).await else {
            tracing::error!(%tenant, "could not open a tenant-scoped transaction");
            return Vec::new();
        };
        let rows: Vec<String> =
            sqlx::query_scalar("SELECT path FROM store_paths_live WHERE tenant = $1")
                .bind(tenant.as_str())
                .fetch_all(&mut *tx)
                .await
                .unwrap_or_else(|e| {
                    tracing::error!(error = %e, "queryAllValidPaths failed");
                    Vec::new()
                });
        rows.into_iter().map(StorePath::new).collect()
    }

    async fn query_path_info_db(&self, tenant: &TenantId, path: &StorePath) -> Option<PathInfo> {
        let Ok(mut tx) = self.tenant_scoped(tenant).await else {
            tracing::error!(%tenant, %path, "could not open a tenant-scoped transaction");
            return None;
        };
        sqlx::query("SELECT * FROM store_paths_live WHERE tenant = $1 AND path = $2")
            .bind(tenant.as_str())
            .bind(path.as_str())
            .fetch_optional(&mut *tx)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, %path, "queryPathInfo failed");
                None
            })
            .map(|row| Self::row_to_info(&row))
    }

    async fn query_path_from_hash_part_db(
        &self,
        tenant: &TenantId,
        hash_part: &str,
    ) -> Option<StorePath> {
        let Ok(mut tx) = self.tenant_scoped(tenant).await else {
            tracing::error!(%tenant, "could not open a tenant-scoped transaction");
            return None;
        };
        sqlx::query_scalar::<_, String>(
            "SELECT path FROM store_paths_live WHERE tenant = $1 AND hash_part = $2",
        )
        .bind(tenant.as_str())
        .bind(hash_part)
        .fetch_optional(&mut *tx)
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "queryPathFromHashPart failed");
            None
        })
        .map(StorePath::new)
    }

    async fn query_referrers_db(&self, tenant: &TenantId, path: &StorePath) -> Vec<StorePath> {
        let Ok(mut tx) = self.tenant_scoped(tenant).await else {
            tracing::error!(%tenant, %path, "could not open a tenant-scoped transaction");
            return Vec::new();
        };
        // `@>` is the array-containment operator the GIN index answers.
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT path FROM store_paths_live WHERE tenant = $1 AND refs @> ARRAY[$2]",
        )
        .bind(tenant.as_str())
        .bind(path.as_str())
        .fetch_all(&mut *tx)
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, %path, "queryReferrers failed");
            Vec::new()
        });
        rows.into_iter().map(StorePath::new).collect()
    }

    async fn record_path_db(
        &self,
        tenant: &TenantId,
        info: PathInfo,
        object: RemoteObject,
        tier: Tier,
    ) -> Result<()> {
        tracing::info!(
            %tenant,
            path = %info.path,
            key = %object.key,
            tier = tier.as_str(),
            "recorded path"
        );
        self.upsert_path(tenant, &info, &object, tier).await
    }

    async fn output_object_db(&self, tenant: &TenantId, path: &StorePath) -> Option<RemoteObject> {
        let mut tx = self
            .tenant_scoped(tenant)
            .await
            .inspect_err(|e| tracing::error!(error = %e, %tenant, %path, "could not open a tenant-scoped transaction"))
            .ok()?;
        let row = sqlx::query(
            "SELECT o.key, o.file_size, o.file_hash
               FROM store_paths_live sp JOIN objects o ON o.key = sp.object_key
              WHERE sp.tenant = $1 AND sp.path = $2",
        )
        .bind(tenant.as_str())
        .bind(path.as_str())
        .fetch_optional(&mut *tx)
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, %path, "object lookup failed");
            None
        })?;

        Some(RemoteObject {
            key: ObjectKey::new(row.get::<String, _>("key")),
            file_size: row.get::<i64, _>("file_size") as u64,
            file_hash: Output::<Sha256>::try_from(row.get::<Vec<u8>, _>("file_hash").as_slice())
                .expect("file_hash column is always a sha256 digest"),
        })
    }

    async fn object_known_db(&self, key: &ObjectKey) -> bool {
        sqlx::query("SELECT 1 FROM objects WHERE key = $1")
            .bind(key.as_str())
            .fetch_optional(&self.pool)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, %key, "object lookup failed");
                None
            })
            .is_some()
    }

    async fn find_verified_by_hash_part_db(
        &self,
        hash_part: &str,
    ) -> Option<(PathInfo, RemoteObject)> {
        // No `tenant` predicate at all — deliberately, like `object_known`.
        // Content-addressing means any tenant's `Verified` row for this hash
        // part is provably identical to any other's, so the first one found
        // answers for all. PLAN.md Phase 9c step two.
        //
        // The narrow, audited exception to row-level security's tenant
        // isolation — see `cross_tenant_verified_read` in the row-level-
        // security migration, and `Self::cross_tenant_verified_read_scoped`.
        let mut tx = self
            .cross_tenant_verified_read_scoped()
            .await
            .inspect_err(|e| tracing::error!(error = %e, %hash_part, "could not open a cross-tenant-read transaction"))
            .ok()?;
        let row = sqlx::query(
            "SELECT sp.*, o.key AS obj_key, o.file_size AS obj_file_size,
                    o.file_hash AS obj_file_hash
               FROM store_paths_live sp JOIN objects o ON o.key = sp.object_key
              WHERE sp.tier = 'verified' AND sp.hash_part = $1
              LIMIT 1",
        )
        .bind(hash_part)
        .fetch_optional(&mut *tx)
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, %hash_part, "cross-tenant verified lookup failed");
            None
        })?;

        let object = RemoteObject {
            key: ObjectKey::new(row.get::<String, _>("obj_key")),
            file_size: row.get::<i64, _>("obj_file_size") as u64,
            file_hash: Output::<Sha256>::try_from(
                row.get::<Vec<u8>, _>("obj_file_hash").as_slice(),
            )
            .expect("file_hash column is always a sha256 digest"),
        };
        Some((Self::row_to_info(&row), object))
    }

    async fn add_signatures_db(
        &self,
        tenant: &TenantId,
        path: &StorePath,
        sigs: Vec<String>,
    ) -> Result<()> {
        let mut tx = self.tenant_scoped(tenant).await.map_err(db_err)?;
        // Union in SQL so concurrent signers do not clobber each other, which a
        // read-modify-write would.
        let updated = sqlx::query(
            "UPDATE store_paths
                SET sigs = ARRAY(SELECT DISTINCT unnest(sigs || $3::text[]))
              WHERE tenant = $1 AND path = $2",
        )
        .bind(tenant.as_str())
        .bind(path.as_str())
        .bind(&sigs)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;

        if updated.rows_affected() == 0 {
            return Err(StoreError::NotFound(path.to_string()));
        }
        tx.commit().await.map_err(db_err)?;
        Ok(())
    }

    async fn query_missing_db(&self, tenant: &TenantId, targets: &[StorePath]) -> MissingPaths {
        let present = self.query_valid_paths_db(tenant, targets).await;
        let mut missing = MissingPaths::default();
        for target in targets {
            if !present.contains(target) {
                // The frontend builds rather than substitutes.
                missing.will_build.push(target.clone());
            }
        }
        missing
    }

    async fn register_tenant_db(&self, tenant: &Tenant) -> Result<()> {
        self.ensure_tenant(tenant).await
    }

    /// Load the tenant's key, generating and persisting one on first use.
    ///
    /// The insert is conditional (`WHERE signing_key_material IS NULL`) and the
    /// result is read back, so two frontends racing to create a key for the same
    /// tenant converge on whichever landed first. Losing that race silently and
    /// signing with a key nobody else has would produce signatures no client
    /// could verify.
    async fn signer_db(&self, tenant: &TenantId) -> Option<Arc<dyn Signer>> {
        self.ensure_tenant_id(tenant).await.ok()?;

        let name = key_name_for(tenant);
        let fresh = LocalSigner::generate(&name);

        let row = sqlx::query(
            "WITH claimed AS (
                 UPDATE tenants
                    SET signing_key_kind = $2,
                        signing_key_name = $3,
                        signing_key_material = $4,
                        signing_public_key = $5
                  WHERE id = $1 AND signing_key_material IS NULL
              RETURNING signing_key_name, signing_key_material
             )
             SELECT signing_key_name, signing_key_material FROM claimed
             UNION ALL
             SELECT signing_key_name, signing_key_material FROM tenants WHERE id = $1
             LIMIT 1",
        )
        .bind(tenant.as_str())
        .bind(KIND_LOCAL_ED25519)
        .bind(&name)
        .bind(fresh.material().as_slice())
        .bind(fresh.public_key().as_slice())
        .fetch_optional(&self.pool)
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, %tenant, "could not establish a signing key");
            None
        })?;

        let stored_name: Option<String> = row.get("signing_key_name");
        let material: Option<Vec<u8>> = row.get("signing_key_material");

        match LocalSigner::from_material(stored_name?, &material?) {
            Ok(signer) => Some(Arc::new(signer)),
            Err(e) => {
                tracing::error!(error = %e, %tenant, "stored signing key is unusable");
                None
            }
        }
    }

    async fn tier_db(&self, tenant: &TenantId, path: &StorePath) -> Option<Tier> {
        let Ok(mut tx) = self.tenant_scoped(tenant).await else {
            tracing::error!(%tenant, %path, "could not open a tenant-scoped transaction");
            return None;
        };
        sqlx::query_scalar::<_, String>(
            "SELECT tier FROM store_paths_live WHERE tenant = $1 AND path = $2",
        )
        .bind(tenant.as_str())
        .bind(path.as_str())
        .fetch_optional(&mut *tx)
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, %path, "tier lookup failed");
            None
        })
        // Infallible: unrecognised text is treated as `Quarantined`, per
        // `Tier`'s `FromStr` impl, never as a parse error.
        .map(|s| s.parse().unwrap())
    }

    async fn reject_unverified_pushes_db(&self, tenant: &TenantId) -> bool {
        sqlx::query_scalar::<_, bool>("SELECT reject_unverified_pushes FROM tenants WHERE id = $1")
            .bind(tenant.as_str())
            .fetch_optional(&self.pool)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, %tenant, "reject_unverified_pushes lookup failed");
                None
            })
            // No row for this tenant yet is the same as an unestablished tenant
            // anywhere else in this file: fall back to the column's own default,
            // the stricter behavior, rather than trusting an absence.
            .unwrap_or(true)
    }

    /// Append to `path_access` — deliberately not an `UPDATE store_paths SET
    /// last_access = ...`. See `server/migrations/20260814_retention_and_gc.sql`
    /// and `crate::gc` for why: a direct update would make the store's
    /// hottest-read rows also its most-written, and `crate::gc`'s drain pass
    /// is what folds this queue into `last_access` in batches.
    ///
    /// Best-effort: a lost access mark only makes a path look slightly less
    /// recently used than it was, which is a stricter retention outcome, not
    /// an unsafe one, so a failure here is logged rather than propagated to
    /// callers that only wanted to read a path.
    async fn record_access_db(&self, tenant: &TenantId, path: &StorePath) {
        let mut tx = match self.tenant_scoped(tenant).await {
            Ok(tx) => tx,
            Err(e) => {
                tracing::warn!(error = %e, %tenant, %path, "recording access failed");
                return;
            }
        };
        if let Err(e) = sqlx::query("INSERT INTO path_access (tenant, path) VALUES ($1, $2)")
            .bind(tenant.as_str())
            .bind(path.as_str())
            .execute(&mut *tx)
            .await
        {
            tracing::warn!(error = %e, %tenant, %path, "recording access failed");
            return;
        }
        if let Err(e) = tx.commit().await {
            tracing::warn!(error = %e, %tenant, %path, "recording access failed");
        }
    }

    /// PLAN.md Phase 19: try to reserve `(tenant, derivation_path)` under
    /// `job_id` — see the trait doc comment on
    /// [`PathStore::reserve_job`](crate::store::PathStore::reserve_job) for
    /// the mechanism. One statement does both the ordinary reservation and
    /// the steal-if-stale case at once: `ON CONFLICT ... WHERE status =
    /// 'running'` targets exactly the partial unique index
    /// `jobs_tenant_drv_running`, and the `DO UPDATE ... WHERE` clause only
    /// fires when the conflicting row's own `created_at` is already older
    /// than `retention` — otherwise Postgres treats the conflict as
    /// unresolved and the statement returns no row, same as `DO NOTHING`
    /// would. `RETURNING id` then means "a row now exists under `job_id`",
    /// whether it was freshly inserted or stolen; its absence means another,
    /// still-fresh reservation exists and names it via the follow-up
    /// `SELECT`.
    ///
    /// Fails open to [`Reservation::Won`] on any database error — matching
    /// this trait's existing best-effort stance elsewhere (see
    /// [`Self::record_access_db`]): a dedup optimization must never itself
    /// be the reason a build cannot be dispatched.
    async fn reserve_job_db(
        &self,
        tenant: &TenantId,
        job_id: Uuid,
        derivation_path: &StorePath,
        system: &str,
        retention: Duration,
    ) -> Reservation {
        if let Err(e) = self.ensure_tenant_id(tenant).await {
            tracing::warn!(error = %e, %tenant, %job_id, "reserving job failed, dispatching independently");
            return Reservation::Won;
        }

        // Tried up to twice: a first attempt that finds a fresh conflict
        // reads which job owns it, but the two statements aren't atomic with
        // each other — that owner can complete (and free the slot) in
        // between. A second attempt after seeing that gives this caller the
        // freed slot for real (a row it can later complete via
        // `record_job_outcome_db`'s `UPDATE`) instead of returning `Won`
        // without ever having inserted anything. A third race in the same
        // narrow window is not worth chasing further: this is dedup
        // bookkeeping, not the build itself (see the fail-open doc above).
        for attempt in 0..2 {
            let mut tx = match self.tenant_scoped(tenant).await {
                Ok(tx) => tx,
                Err(e) => {
                    tracing::warn!(error = %e, %tenant, %job_id, "reserving job failed, dispatching independently");
                    return Reservation::Won;
                }
            };

            let reserved: sqlx::Result<Option<Uuid>> = sqlx::query_scalar(
                "INSERT INTO jobs (id, tenant, derivation_path, system, status, created_at)
                 VALUES ($1, $2, $3, $4, 'running', NOW())
                 ON CONFLICT (tenant, derivation_path) WHERE status = 'running'
                 DO UPDATE SET
                     id = EXCLUDED.id,
                     system = EXCLUDED.system,
                     created_at = NOW(),
                     error_msg = NULL,
                     output_paths = '{}',
                     log_key = NULL,
                     failure_kind = NULL,
                     finished_at = NULL
                 WHERE jobs.created_at < NOW() - make_interval(secs => $5::double precision)
                 RETURNING id",
            )
            .bind(job_id)
            .bind(tenant.as_str())
            .bind(derivation_path.as_str())
            .bind(system)
            .bind(retention.as_secs_f64())
            .fetch_optional(&mut *tx)
            .await;

            let reserved = match reserved {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error = %e, %tenant, %job_id, "reserving job failed, dispatching independently");
                    return Reservation::Won;
                }
            };

            if let Some(won_id) = reserved {
                debug_assert_eq!(won_id, job_id);
                if let Err(e) = tx.commit().await {
                    tracing::warn!(error = %e, %tenant, %job_id, "reserving job failed, dispatching independently");
                    return Reservation::Won;
                }
                return Reservation::Won;
            }

            // Conflict, and it wasn't stale enough to steal — find what's
            // actually there.
            let existing: sqlx::Result<Option<Uuid>> = sqlx::query_scalar(
                "SELECT id FROM jobs WHERE tenant = $1 AND derivation_path = $2 AND status = 'running'",
            )
            .bind(tenant.as_str())
            .bind(derivation_path.as_str())
            .fetch_optional(&mut *tx)
            .await;

            match existing {
                Ok(Some(existing_id)) => return Reservation::Lost(existing_id),
                // Raced away between the conflict and this read (it
                // completed in between) — retry the whole reservation once:
                // the slot is free now, so the retry's own INSERT succeeds
                // outright.
                Ok(None) if attempt == 0 => continue,
                Ok(None) => return Reservation::Won,
                Err(e) => {
                    tracing::warn!(error = %e, %tenant, %job_id, "reserving job failed, dispatching independently");
                    return Reservation::Won;
                }
            }
        }
        unreachable!("loop above always returns within two iterations")
    }

    /// Update the `jobs` row [`Self::reserve_job_db`] already inserted with a
    /// terminal outcome. Best-effort, like [`Self::record_access_db`] — see
    /// the trait doc comment for why this may be called more than once (and
    /// must therefore be idempotent) for the same `job_id`.
    async fn record_job_outcome_db(
        &self,
        tenant: &TenantId,
        job_id: Uuid,
        derivation_path: &StorePath,
        system: &str,
        outcome: &JobOutcome,
    ) {
        if let Err(e) = self.ensure_tenant_id(tenant).await {
            tracing::warn!(error = %e, %tenant, %job_id, "recording job outcome failed");
            return;
        }

        let mut tx = match self.tenant_scoped(tenant).await {
            Ok(tx) => tx,
            Err(e) => {
                tracing::warn!(error = %e, %tenant, %job_id, "recording job outcome failed");
                return;
            }
        };

        let (status, error_msg, output_paths, log_key, failure_kind): (
            &str,
            Option<&str>,
            Vec<&str>,
            &str,
            Option<&str>,
        ) = match outcome {
            JobOutcome::Completed {
                outputs, log_key, ..
            } => (
                "completed",
                None,
                outputs.iter().map(StorePath::as_str).collect(),
                log_key,
                None,
            ),
            JobOutcome::Failed {
                message,
                log_key,
                failure_kind,
            } => (
                "failed",
                Some(message.as_str()),
                Vec::new(),
                log_key,
                failure_kind.map(|k| match k {
                    crate::jobs::FailureKind::OutOfMemory => "out_of_memory",
                    crate::jobs::FailureKind::DiskFull => "disk_full",
                }),
            ),
        };

        // `ON CONFLICT (id) DO UPDATE`, not a plain `UPDATE`: the ordinary
        // case is that `reserve_job_db` already inserted this row (this
        // completion is what moves `status` away from `'running'`, which is
        // what releases `jobs_tenant_drv_running`'s reservation) — but on the
        // rare double-race edge that method's own doc comment accepts, no
        // row exists yet, and this still needs to record the outcome rather
        // than silently lose it. Idempotent either way (see this method's
        // doc comment): every watcher of this `job_id` computes the same
        // outcome and may run this exact statement.
        if let Err(e) = sqlx::query(
            "INSERT INTO jobs (
                 id, tenant, derivation_path, system, status, error_msg,
                 output_paths, log_key, failure_kind, finished_at
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())
             ON CONFLICT (id) DO UPDATE SET
                 status = EXCLUDED.status,
                 error_msg = EXCLUDED.error_msg,
                 output_paths = EXCLUDED.output_paths,
                 log_key = EXCLUDED.log_key,
                 failure_kind = EXCLUDED.failure_kind,
                 finished_at = EXCLUDED.finished_at",
        )
        .bind(job_id)
        .bind(tenant.as_str())
        .bind(derivation_path.as_str())
        .bind(system)
        .bind(status)
        .bind(error_msg)
        .bind(&output_paths)
        .bind(log_key)
        .bind(failure_kind)
        .execute(&mut *tx)
        .await
        {
            tracing::warn!(error = %e, %tenant, %job_id, "recording job outcome failed");
            return;
        }
        if let Err(e) = tx.commit().await {
            tracing::warn!(error = %e, %tenant, %job_id, "recording job outcome failed");
        }
    }

    async fn current_capability_secret_db(&self) -> (u64, [u8; 32]) {
        {
            let cache = self.capability_secrets.lock().unwrap();
            if let Some((fetched_at, kid, secret)) = cache.current
                && fetched_at.elapsed() < CAPABILITY_SECRET_CACHE_TTL
            {
                return (kid, secret);
            }
        }

        let found =
            sqlx::query("SELECT kid, secret FROM capability_secrets ORDER BY kid DESC LIMIT 1")
                .fetch_optional(&self.pool)
                .await
                .unwrap_or_else(|e| {
                    tracing::error!(error = %e, "could not read the current capability secret");
                    None
                })
                .and_then(|row| {
                    let kid: i64 = row.get("kid");
                    let secret: Vec<u8> = row.get("secret");
                    secret
                        .try_into()
                        .ok()
                        .map(|secret: [u8; 32]| (kid as u64, secret))
                });

        let (kid, secret) = match found {
            Some(found) => found,
            // Nothing usable yet -- lazily mint the first one, the same way
            // `signer()` establishes a tenant's key on first use. A concurrent
            // replica may race this; the extra row is harmless, since the next
            // read just picks whichever now has the higher `kid`.
            None => {
                let secret: [u8; 32] = rand::random();
                match sqlx::query(
                    "INSERT INTO capability_secrets (secret) VALUES ($1) RETURNING kid",
                )
                .bind(secret.as_slice())
                .fetch_one(&self.pool)
                .await
                {
                    Ok(row) => (row.get::<i64, _>("kid") as u64, secret),
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            "could not persist a capability secret; using a process-local one \
                             until the database is reachable again"
                        );
                        // A `kid` above `i64::MAX` can never collide with a real
                        // `BIGSERIAL` row, so this is unambiguously
                        // non-persistent: no other replica (and not even this
                        // one, after the cache below expires and a fresh
                        // database read succeeds) will ever resolve it.
                        let ephemeral_kid =
                            0x8000_0000_0000_0000u64 | u64::from(rand::random::<u32>());
                        (ephemeral_kid, secret)
                    }
                }
            }
        };

        let mut cache = self.capability_secrets.lock().unwrap();
        cache.current = Some((std::time::Instant::now(), kid, secret));
        cache.by_kid.insert(kid, secret);
        (kid, secret)
    }

    async fn capability_secret_db(&self, kid: u64) -> Option<[u8; 32]> {
        {
            let cache = self.capability_secrets.lock().unwrap();
            if let Some(secret) = cache.by_kid.get(&kid) {
                return Some(*secret);
            }
        }

        // `kid` values above `i64::MAX` are process-local fallbacks (see
        // `current_capability_secret`) and never stored, so do not round-trip
        // through Postgres for one -- it cannot possibly be there.
        let kid_i64 = i64::try_from(kid).ok()?;
        let row = sqlx::query("SELECT secret FROM capability_secrets WHERE kid = $1")
            .bind(kid_i64)
            .fetch_optional(&self.pool)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, kid, "could not look up a capability secret");
                None
            })?;
        let secret: Vec<u8> = row.get("secret");
        let secret: [u8; 32] = secret.try_into().ok()?;

        let mut cache = self.capability_secrets.lock().unwrap();
        cache.by_kid.insert(kid, secret);
        Some(secret)
    }

    async fn find_tenant_by_binding_db(
        &self,
        key_type: KeyType,
        key_id: &str,
    ) -> Result<Option<TenantId>> {
        let row = sqlx::query(
            "SELECT tenant FROM tenant_auth_bindings WHERE key_type = $1 AND key_id = $2",
        )
        .bind(key_type.as_str())
        .bind(key_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err)?;

        let Some(row) = row else {
            return Ok(None);
        };
        let tenant: String = row.get("tenant");
        match TenantId::from_wire(&tenant) {
            Some(id) => Ok(Some(id)),
            // `tenant` is a foreign key into `tenants(id)`, and every id this
            // process has ever written there came from `TenantId::from_wire`
            // or `derive_id` - both wire-safe by construction. Reaching this
            // means a row was inserted with an id neither produced (a manual
            // `INSERT` typo, most likely), which is an operator error, not
            // something to trust a connection's identity to.
            None => {
                tracing::error!(
                    tenant,
                    "tenant_auth_bindings row references a malformed tenant id"
                );
                Ok(None)
            }
        }
    }

    /// Send one [`DbRequest`] to the actor and await its answer.
    ///
    /// `None` means the actor could not be reached at all (its channel is
    /// closed — the actor thread panicked or never started) or it dropped
    /// the reply without answering (should not happen: every [`DbRequest`]
    /// variant is handled and always sends a reply). Both are treated as "no
    /// answer" by callers, the same way a query that failed for any other
    /// reason already was before the actor existed.
    async fn call<T: Send + 'static>(
        &self,
        build: impl FnOnce(oneshot::Sender<T>) -> DbRequest,
    ) -> Option<T> {
        let (reply, rx) = oneshot::channel();
        if self.db_tx.send(build(reply)).is_err() {
            tracing::error!("db request actor is not running");
            return None;
        }
        match rx.await {
            Ok(v) => Some(v),
            Err(_) => {
                tracing::error!("db request actor dropped the reply without answering");
                None
            }
        }
    }
}

/// One formalized database operation, sent from a `Store`-trait method to the
/// actor [`spawn_db_actor`] runs. See the module doc comment for why every
/// operation goes through this instead of touching `self.pool` directly.
enum DbRequest {
    IsValidPath {
        tenant: TenantId,
        path: StorePath,
        reply: oneshot::Sender<bool>,
    },
    QueryValidPaths {
        tenant: TenantId,
        paths: Vec<StorePath>,
        reply: oneshot::Sender<Vec<StorePath>>,
    },
    QueryAllValidPaths {
        tenant: TenantId,
        reply: oneshot::Sender<Vec<StorePath>>,
    },
    QueryPathInfo {
        tenant: TenantId,
        path: StorePath,
        reply: oneshot::Sender<Option<PathInfo>>,
    },
    QueryPathFromHashPart {
        tenant: TenantId,
        hash_part: String,
        reply: oneshot::Sender<Option<StorePath>>,
    },
    QueryReferrers {
        tenant: TenantId,
        path: StorePath,
        reply: oneshot::Sender<Vec<StorePath>>,
    },
    RecordPath {
        tenant: TenantId,
        info: PathInfo,
        object: RemoteObject,
        tier: Tier,
        reply: oneshot::Sender<Result<()>>,
    },
    OutputObject {
        tenant: TenantId,
        path: StorePath,
        reply: oneshot::Sender<Option<RemoteObject>>,
    },
    ObjectKnown {
        key: ObjectKey,
        reply: oneshot::Sender<bool>,
    },
    FindVerifiedByHashPart {
        hash_part: String,
        reply: oneshot::Sender<Option<(PathInfo, RemoteObject)>>,
    },
    AddSignatures {
        tenant: TenantId,
        path: StorePath,
        sigs: Vec<String>,
        reply: oneshot::Sender<Result<()>>,
    },
    QueryMissing {
        tenant: TenantId,
        targets: Vec<StorePath>,
        reply: oneshot::Sender<MissingPaths>,
    },
    RegisterTenant {
        tenant: Tenant,
        reply: oneshot::Sender<Result<()>>,
    },
    Signer {
        tenant: TenantId,
        reply: oneshot::Sender<Option<Arc<dyn Signer>>>,
    },
    Tier {
        tenant: TenantId,
        path: StorePath,
        reply: oneshot::Sender<Option<Tier>>,
    },
    RejectUnverifiedPushes {
        tenant: TenantId,
        reply: oneshot::Sender<bool>,
    },
    RecordAccess {
        tenant: TenantId,
        path: StorePath,
        reply: oneshot::Sender<()>,
    },
    ReserveJob {
        tenant: TenantId,
        job_id: Uuid,
        derivation_path: StorePath,
        system: String,
        retention: Duration,
        reply: oneshot::Sender<Reservation>,
    },
    RecordJobOutcome {
        tenant: TenantId,
        job_id: Uuid,
        derivation_path: StorePath,
        system: String,
        outcome: JobOutcome,
        reply: oneshot::Sender<()>,
    },
    CurrentCapabilitySecret {
        reply: oneshot::Sender<(u64, [u8; 32])>,
    },
    CapabilitySecret {
        kid: u64,
        reply: oneshot::Sender<Option<[u8; 32]>>,
    },
    FindTenantByBinding {
        key_type: KeyType,
        key_id: String,
        reply: oneshot::Sender<Result<Option<TenantId>>>,
    },
}

impl DbRequest {
    /// Run this request's database work and answer its `reply`. A dropped
    /// `reply` (the caller gave up waiting) is not logged — an ordinary race,
    /// not a failure of this request.
    async fn dispatch(self, store: &PostgresStore) {
        match self {
            DbRequest::IsValidPath {
                tenant,
                path,
                reply,
            } => {
                let _ = reply.send(store.is_valid_path_db(&tenant, &path).await);
            }
            DbRequest::QueryValidPaths {
                tenant,
                paths,
                reply,
            } => {
                let _ = reply.send(store.query_valid_paths_db(&tenant, &paths).await);
            }
            DbRequest::QueryAllValidPaths { tenant, reply } => {
                let _ = reply.send(store.query_all_valid_paths_db(&tenant).await);
            }
            DbRequest::QueryPathInfo {
                tenant,
                path,
                reply,
            } => {
                let _ = reply.send(store.query_path_info_db(&tenant, &path).await);
            }
            DbRequest::QueryPathFromHashPart {
                tenant,
                hash_part,
                reply,
            } => {
                let _ = reply.send(
                    store
                        .query_path_from_hash_part_db(&tenant, &hash_part)
                        .await,
                );
            }
            DbRequest::QueryReferrers {
                tenant,
                path,
                reply,
            } => {
                let _ = reply.send(store.query_referrers_db(&tenant, &path).await);
            }
            DbRequest::RecordPath {
                tenant,
                info,
                object,
                tier,
                reply,
            } => {
                let _ = reply.send(store.record_path_db(&tenant, info, object, tier).await);
            }
            DbRequest::OutputObject {
                tenant,
                path,
                reply,
            } => {
                let _ = reply.send(store.output_object_db(&tenant, &path).await);
            }
            DbRequest::ObjectKnown { key, reply } => {
                let _ = reply.send(store.object_known_db(&key).await);
            }
            DbRequest::FindVerifiedByHashPart { hash_part, reply } => {
                let _ = reply.send(store.find_verified_by_hash_part_db(&hash_part).await);
            }
            DbRequest::AddSignatures {
                tenant,
                path,
                sigs,
                reply,
            } => {
                let _ = reply.send(store.add_signatures_db(&tenant, &path, sigs).await);
            }
            DbRequest::QueryMissing {
                tenant,
                targets,
                reply,
            } => {
                let _ = reply.send(store.query_missing_db(&tenant, &targets).await);
            }
            DbRequest::RegisterTenant { tenant, reply } => {
                let _ = reply.send(store.register_tenant_db(&tenant).await);
            }
            DbRequest::Signer { tenant, reply } => {
                let _ = reply.send(store.signer_db(&tenant).await);
            }
            DbRequest::Tier {
                tenant,
                path,
                reply,
            } => {
                let _ = reply.send(store.tier_db(&tenant, &path).await);
            }
            DbRequest::RejectUnverifiedPushes { tenant, reply } => {
                let _ = reply.send(store.reject_unverified_pushes_db(&tenant).await);
            }
            DbRequest::ReserveJob {
                tenant,
                job_id,
                derivation_path,
                system,
                retention,
                reply,
            } => {
                let _ = reply.send(
                    store
                        .reserve_job_db(&tenant, job_id, &derivation_path, &system, retention)
                        .await,
                );
            }
            DbRequest::RecordAccess {
                tenant,
                path,
                reply,
            } => {
                store.record_access_db(&tenant, &path).await;
                let _ = reply.send(());
            }
            DbRequest::RecordJobOutcome {
                tenant,
                job_id,
                derivation_path,
                system,
                outcome,
                reply,
            } => {
                store
                    .record_job_outcome_db(&tenant, job_id, &derivation_path, &system, &outcome)
                    .await;
                let _ = reply.send(());
            }
            DbRequest::CurrentCapabilitySecret { reply } => {
                let _ = reply.send(store.current_capability_secret_db().await);
            }
            DbRequest::CapabilitySecret { kid, reply } => {
                let _ = reply.send(store.capability_secret_db(kid).await);
            }
            DbRequest::FindTenantByBinding {
                key_type,
                key_id,
                reply,
            } => {
                let _ = reply.send(store.find_tenant_by_binding_db(key_type, &key_id).await);
            }
        }
    }
}

/// Spawn the dedicated runtime [`DbRequest`]s are served from — see the
/// module doc comment for why this exists.
///
/// Each request is spawned as its own task rather than processed one at a
/// time: real concurrency stays bounded by the `PgPool`'s own
/// `max_connections`, exactly as it was before this actor existed. What
/// changes is only which threads have to stay promptly scheduled to poll a
/// database timeout — a small, fixed number, independent of how many SSH
/// connections are open.
fn spawn_db_actor(store: Arc<PostgresStore>, mut rx: mpsc::UnboundedReceiver<DbRequest>) {
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_multi_thread()
            .worker_threads(db_actor_threads())
            .thread_name("kubernix-db-actor")
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                tracing::error!(error = %e, "failed to build the database actor runtime");
                return;
            }
        };
        runtime.block_on(async move {
            while let Some(req) = rx.recv().await {
                let store = Arc::clone(&store);
                tokio::spawn(async move { req.dispatch(&store).await });
            }
        });
    });
}

#[async_trait::async_trait]
impl PathStore for PostgresStore {
    async fn is_valid_path(&self, tenant: &TenantId, path: &StorePath) -> bool {
        let (tenant, path) = (tenant.clone(), path.clone());
        self.call(|reply| DbRequest::IsValidPath {
            tenant,
            path,
            reply,
        })
        .await
        .unwrap_or(false)
    }

    async fn query_valid_paths(&self, tenant: &TenantId, paths: &[StorePath]) -> Vec<StorePath> {
        let (tenant, paths) = (tenant.clone(), paths.to_vec());
        self.call(|reply| DbRequest::QueryValidPaths {
            tenant,
            paths,
            reply,
        })
        .await
        .unwrap_or_default()
    }

    async fn query_all_valid_paths(&self, tenant: &TenantId) -> Vec<StorePath> {
        let tenant = tenant.clone();
        self.call(|reply| DbRequest::QueryAllValidPaths { tenant, reply })
            .await
            .unwrap_or_default()
    }

    async fn query_path_info(&self, tenant: &TenantId, path: &StorePath) -> Option<PathInfo> {
        let (tenant, path) = (tenant.clone(), path.clone());
        self.call(|reply| DbRequest::QueryPathInfo {
            tenant,
            path,
            reply,
        })
        .await
        .flatten()
    }

    async fn query_path_from_hash_part(
        &self,
        tenant: &TenantId,
        hash_part: &str,
    ) -> Option<StorePath> {
        let (tenant, hash_part) = (tenant.clone(), hash_part.to_string());
        self.call(|reply| DbRequest::QueryPathFromHashPart {
            tenant,
            hash_part,
            reply,
        })
        .await
        .flatten()
    }

    async fn query_referrers(&self, tenant: &TenantId, path: &StorePath) -> Vec<StorePath> {
        let (tenant, path) = (tenant.clone(), path.clone());
        self.call(|reply| DbRequest::QueryReferrers {
            tenant,
            path,
            reply,
        })
        .await
        .unwrap_or_default()
    }

    async fn record_path(
        &self,
        tenant: &TenantId,
        info: PathInfo,
        object: RemoteObject,
        tier: Tier,
    ) -> Result<()> {
        let tenant = tenant.clone();
        self.call(|reply| DbRequest::RecordPath {
            tenant,
            info,
            object,
            tier,
            reply,
        })
        .await
        .unwrap_or_else(|| Err(StoreError::Other("db request actor unavailable".into())))
    }

    async fn output_object(&self, tenant: &TenantId, path: &StorePath) -> Option<RemoteObject> {
        let (tenant, path) = (tenant.clone(), path.clone());
        self.call(|reply| DbRequest::OutputObject {
            tenant,
            path,
            reply,
        })
        .await
        .flatten()
    }

    async fn object_known(&self, key: &ObjectKey) -> bool {
        let key = key.clone();
        self.call(|reply| DbRequest::ObjectKnown { key, reply })
            .await
            .unwrap_or(false)
    }

    async fn find_verified_by_hash_part(
        &self,
        hash_part: &str,
    ) -> Option<(PathInfo, RemoteObject)> {
        let hash_part = hash_part.to_string();
        self.call(|reply| DbRequest::FindVerifiedByHashPart { hash_part, reply })
            .await
            .flatten()
    }

    async fn add_signatures(
        &self,
        tenant: &TenantId,
        path: &StorePath,
        sigs: Vec<String>,
    ) -> Result<()> {
        let (tenant, path) = (tenant.clone(), path.clone());
        self.call(|reply| DbRequest::AddSignatures {
            tenant,
            path,
            sigs,
            reply,
        })
        .await
        .unwrap_or_else(|| Err(StoreError::Other("db request actor unavailable".into())))
    }

    async fn query_missing(&self, tenant: &TenantId, targets: &[StorePath]) -> MissingPaths {
        let (tenant, targets) = (tenant.clone(), targets.to_vec());
        self.call(|reply| DbRequest::QueryMissing {
            tenant,
            targets,
            reply,
        })
        .await
        .unwrap_or_default()
    }

    async fn register_tenant(&self, tenant: &Tenant) -> Result<()> {
        let tenant = tenant.clone();
        self.call(|reply| DbRequest::RegisterTenant { tenant, reply })
            .await
            .unwrap_or_else(|| Err(StoreError::Other("db request actor unavailable".into())))
    }

    async fn signer(&self, tenant: &TenantId) -> Option<Arc<dyn Signer>> {
        let tenant = tenant.clone();
        self.call(|reply| DbRequest::Signer { tenant, reply })
            .await
            .flatten()
    }

    async fn tier(&self, tenant: &TenantId, path: &StorePath) -> Option<Tier> {
        let (tenant, path) = (tenant.clone(), path.clone());
        self.call(|reply| DbRequest::Tier {
            tenant,
            path,
            reply,
        })
        .await
        .flatten()
    }

    async fn reject_unverified_pushes(&self, tenant: &TenantId) -> bool {
        let tenant = tenant.clone();
        self.call(|reply| DbRequest::RejectUnverifiedPushes { tenant, reply })
            .await
            .unwrap_or(true)
    }

    async fn record_access(&self, tenant: &TenantId, path: &StorePath) {
        let (tenant, path) = (tenant.clone(), path.clone());
        self.call(|reply| DbRequest::RecordAccess {
            tenant,
            path,
            reply,
        })
        .await;
    }

    async fn reserve_job(
        &self,
        tenant: &TenantId,
        job_id: Uuid,
        derivation_path: &StorePath,
        system: &str,
        retention: Duration,
    ) -> Reservation {
        let (tenant, derivation_path, system) =
            (tenant.clone(), derivation_path.clone(), system.to_string());
        self.call(|reply| DbRequest::ReserveJob {
            tenant,
            job_id,
            derivation_path,
            system,
            retention,
            reply,
        })
        .await
        .unwrap_or(Reservation::Won)
    }

    async fn record_job_outcome(
        &self,
        tenant: &TenantId,
        job_id: Uuid,
        derivation_path: &StorePath,
        system: &str,
        outcome: &JobOutcome,
    ) {
        let (tenant, derivation_path, system, outcome) = (
            tenant.clone(),
            derivation_path.clone(),
            system.to_string(),
            outcome.clone(),
        );
        self.call(|reply| DbRequest::RecordJobOutcome {
            tenant,
            job_id,
            derivation_path,
            system,
            outcome,
            reply,
        })
        .await;
    }
}

#[async_trait::async_trait]
impl CapabilitySecretStore for PostgresStore {
    async fn current_capability_secret(&self) -> (u64, [u8; 32]) {
        self.call(|reply| DbRequest::CurrentCapabilitySecret { reply })
            .await
            .unwrap_or_else(|| {
                tracing::error!(
                    "db request actor unavailable; using a process-local capability secret"
                );
                // Same non-persistent-`kid` trick `current_capability_secret_db`
                // falls back to when the database itself is unreachable.
                let ephemeral_kid = 0x8000_0000_0000_0000u64 | u64::from(rand::random::<u32>());
                (ephemeral_kid, rand::random())
            })
    }

    async fn capability_secret(&self, kid: u64) -> Option<[u8; 32]> {
        self.call(|reply| DbRequest::CapabilitySecret { kid, reply })
            .await
            .flatten()
    }
}

#[async_trait::async_trait]
impl TenantAuthStore for PostgresStore {
    async fn find_tenant_by_binding(
        &self,
        key_type: KeyType,
        key_id: &str,
    ) -> Result<Option<TenantId>> {
        let key_id = key_id.to_string();
        self.call(|reply| DbRequest::FindTenantByBinding {
            key_type,
            key_id,
            reply,
        })
        .await
        .unwrap_or_else(|| Err(StoreError::Other("db request actor unavailable".into())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_the_hash_part() {
        assert_eq!(
            hash_part_of("00000000000000000000000000000000-thing"),
            "00000000000000000000000000000000"
        );
        // Not a store path: the column is still NOT NULL, so this must produce
        // something rather than panic. It simply will not match a lookup.
        assert_eq!(hash_part_of("/etc/passwd"), "passwd");
    }

    #[test]
    fn hash_algorithms_round_trip() {
        for algo in [
            HashType::Md5,
            HashType::Sha1,
            HashType::Sha256,
            HashType::Sha512,
        ] {
            assert_eq!(algo_from_name(algo_name(algo)), algo);
        }
    }

    // ---------------------------------------------------------------------
    // Everything below needs a real database, because the whole point of this
    // module is the SQL — a mock would only test the mock. Point
    // `KUBERNIX_TEST_DATABASE_URL` at a scratch database (`just run-db`) to run
    // them; they are skipped, loudly, when it is unset.
    //
    // Each test uses its own tenant, so they share a database without colliding
    // and without needing to truncate between runs.
    // ---------------------------------------------------------------------

    /// Connect, or return `None` after saying why. `ServingRole::App` —
    /// same role `kubernix-sshd`/`kubernix-cache` actually serve as, so
    /// every test below exercises row-level security for real rather than
    /// against a bypassing role.
    async fn db() -> Option<Arc<PostgresStore>> {
        let Ok(url) = std::env::var("KUBERNIX_TEST_DATABASE_URL") else {
            eprintln!("skipping: KUBERNIX_TEST_DATABASE_URL unset");
            return None;
        };
        match PostgresStore::connect(&url, ServingRole::App).await {
            Ok(store) => Some(store),
            Err(e) => panic!("KUBERNIX_TEST_DATABASE_URL is set but unusable: {e}"),
        }
    }

    /// A tenant unique to one test.
    fn tenant(test: &str) -> TenantId {
        Tenant::from_ssh(&format!("test-{test}"), None, false).id
    }

    /// Provision a tenant and a binding for it, the way an operator would by
    /// hand — over a privileged connection, since `kubernix_app` (what `db()`
    /// connects as, matching the real serving role) only has `SELECT` on
    /// `tenant_auth_bindings`, deliberately: see the migration's doc comment.
    async fn provision_binding(url: &str, tenant: &TenantId, key_id: &str) {
        let privileged = PgPoolOptions::new()
            .max_connections(1)
            .connect(url)
            .await
            .expect("KUBERNIX_TEST_DATABASE_URL is set but unusable");
        sqlx::query("INSERT INTO tenants (id) VALUES ($1) ON CONFLICT (id) DO NOTHING")
            .bind(tenant.as_str())
            .execute(&privileged)
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO tenant_auth_bindings (key_type, key_id, tenant) VALUES ('ssh', $1, $2)
             ON CONFLICT (key_type, key_id) DO NOTHING",
        )
        .bind(key_id)
        .bind(tenant.as_str())
        .execute(&privileged)
        .await
        .unwrap();
    }

    fn info(path: &str) -> PathInfo {
        PathInfo {
            path: StorePath::new(path),
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

    /// Where a path's bytes are. The database records this and never the bytes.
    fn object(key: &str) -> RemoteObject {
        RemoteObject {
            key: ObjectKey::new(key),
            file_size: 3,
            file_hash: Output::<Sha256>::from([9u8; 32]),
        }
    }

    const P: &str = "00000000000000000000000000000000-thing";
    const DEP: &str = "11111111111111111111111111111111-dep";

    fn p() -> StorePath {
        StorePath::new(P)
    }

    /// A `.drv` path unique to one test run, the same way
    /// `a_completed_job_outcome_round_trips` and its neighbors already build
    /// theirs from a fresh `job_id` — PLAN.md Phase 19's reservation tests
    /// deliberately collide *within* a test (that's what they assert), so
    /// each test needs its own path to avoid colliding *across* runs against
    /// a persistent `KUBERNIX_TEST_DATABASE_URL`.
    fn reserve_test_drv(uniquifier: Uuid) -> StorePath {
        StorePath::new(format!("00000000000000000000000000000000-{uniquifier}.drv"))
    }

    fn dep() -> StorePath {
        StorePath::new(DEP)
    }

    #[tokio::test]
    async fn round_trips_a_pushed_path() {
        let Some(store) = db().await else { return };
        let t = tenant("roundtrip");

        assert!(!store.is_valid_path(&t, &p()).await);
        store
            .record_path(&t, info(P), object("k"), Tier::Verified)
            .await
            .unwrap();

        assert!(store.is_valid_path(&t, &p()).await);
        assert_eq!(store.query_valid_paths(&t, &[p()]).await, vec![p()]);
        assert_eq!(
            store.output_object(&t, &p()).await.unwrap().key.as_str(),
            "k"
        );

        let read = store.query_path_info(&t, &p()).await.expect("recorded");
        assert_eq!(read.nar_size, 3);
        assert_eq!(read.nar_hash.bytes, vec![7; 32]);
        assert_eq!(read.nar_hash.hash_type, HashType::Sha256);
    }

    #[tokio::test]
    async fn resolves_by_hash_part() {
        let Some(store) = db().await else { return };
        let t = tenant("hashpart");
        store
            .record_path(&t, info(P), object("k"), Tier::Verified)
            .await
            .unwrap();

        assert_eq!(
            store
                .query_path_from_hash_part(&t, "00000000000000000000000000000000")
                .await,
            Some(p())
        );
        assert_eq!(store.query_path_from_hash_part(&t, "deadbeef").await, None);
    }

    #[tokio::test]
    async fn finds_referrers_through_the_array_index() {
        let Some(store) = db().await else { return };
        let t = tenant("referrers");
        store
            .record_path(&t, info(DEP), object("k"), Tier::Verified)
            .await
            .unwrap();
        let mut referrer = info(P);
        referrer.references = vec![dep()];
        store
            .record_path(&t, referrer, object("k"), Tier::Verified)
            .await
            .unwrap();

        assert_eq!(store.query_referrers(&t, &dep()).await, vec![p()]);
        assert!(store.query_referrers(&t, &p()).await.is_empty());
        // And the references survive the round trip, since a narinfo is made of
        // them.
        assert_eq!(
            store.query_path_info(&t, &p()).await.unwrap().references,
            vec![dep()]
        );
    }

    #[tokio::test]
    async fn a_built_output_reports_where_its_bytes_are() {
        let Some(store) = db().await else { return };
        let t = tenant("output");
        let key = "some-tenant/nar/abc.nar.zst";
        store
            .record_path(
                &t,
                info(P),
                RemoteObject {
                    key: ObjectKey::new(key),
                    file_size: 99,
                    file_hash: Output::<Sha256>::from([0xcdu8; 32]),
                },
                Tier::Built,
            )
            .await
            .unwrap();

        // The database records where the bytes are, never the bytes; the RPC
        // layer and the cache both fetch from this key.
        let remote = store.output_object(&t, &p()).await.expect("has an object");
        assert_eq!(remote.key.as_str(), key);
        assert_eq!(remote.file_size, 99);
        // The compressed hash must survive: it is what a narinfo `FileHash`
        // states, and a client verifies its download against it.
        assert_eq!(remote.file_hash, Output::<Sha256>::from([0xcdu8; 32]));
    }

    #[tokio::test]
    async fn signatures_accumulate_without_duplicating() {
        let Some(store) = db().await else { return };
        let t = tenant("sigs");
        store
            .record_path(&t, info(P), object("k"), Tier::Verified)
            .await
            .unwrap();

        store
            .add_signatures(&t, &p(), vec!["a:1".to_string()])
            .await
            .unwrap();
        store
            .add_signatures(&t, &p(), vec!["a:1".to_string(), "b:2".to_string()])
            .await
            .unwrap();

        let mut sigs = store.query_path_info(&t, &p()).await.unwrap().sigs;
        sigs.sort();
        assert_eq!(sigs, vec!["a:1", "b:2"]);
    }

    #[tokio::test]
    async fn signing_an_unknown_path_is_not_found() {
        let Some(store) = db().await else { return };
        let t = tenant("sigs-missing");
        assert!(matches!(
            store
                .add_signatures(&t, &p(), vec!["a:1".to_string()])
                .await,
            Err(StoreError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn one_tenant_cannot_see_anothers_paths() {
        let Some(store) = db().await else { return };
        let (alice, bob) = (tenant("iso-alice"), tenant("iso-bob"));
        store
            .record_path(&alice, info(P), object("alice/nar/x"), Tier::Verified)
            .await
            .unwrap();

        assert!(!store.is_valid_path(&bob, &p()).await);
        assert!(store.query_path_info(&bob, &p()).await.is_none());
        assert!(store.query_all_valid_paths(&bob).await.is_empty());
        assert!(
            store
                .query_path_from_hash_part(&bob, "00000000000000000000000000000000")
                .await
                .is_none()
        );
        assert!(store.output_object(&bob, &p()).await.is_none());

        // And the same path may hold different bytes for each: whoever writes
        // second must not win, which is what `(tenant, path)` as the primary key
        // buys.
        store
            .record_path(&bob, info(P), object("k"), Tier::Verified)
            .await
            .unwrap();
        assert_eq!(
            store
                .output_object(&alice, &p())
                .await
                .unwrap()
                .key
                .as_str(),
            "alice/nar/x"
        );
        assert_eq!(
            store.output_object(&bob, &p()).await.unwrap().key.as_str(),
            "k"
        );
    }

    #[tokio::test]
    async fn row_level_security_blocks_a_query_with_no_tenant_predicate_of_its_own() {
        // Every test above proves the *application's* `WHERE tenant = $1`
        // isolates tenants. This one proves the *database* does too — a
        // regression test for the policy in
        // `server/migrations/20260814120000_row_level_security.sql`, not for
        // application code, since the whole point of row-level security is
        // to hold even when a query forgets its own predicate.
        let Some(store) = db().await else { return };
        let (alice, bob) = (tenant("rls-alice"), tenant("rls-bob"));
        store
            .record_path(&alice, info(P), object("rls/alice/x"), Tier::Built)
            .await
            .unwrap();

        // A connection scoped to bob, running a query that — deliberately,
        // unlike every real `PostgresStore` method — carries no `tenant`
        // predicate at all. If row-level security is doing its job, bob's
        // connection must not see alice's row regardless.
        let mut tx = store.pool.begin().await.unwrap();
        sqlx::query("SELECT set_config('app.current_tenant', $1, true)")
            .bind(bob.as_str())
            .execute(&mut *tx)
            .await
            .unwrap();
        let rows: Vec<String> = sqlx::query_scalar("SELECT path FROM store_paths WHERE path = $1")
            .bind(P)
            .fetch_all(&mut *tx)
            .await
            .unwrap();
        assert!(
            rows.is_empty(),
            "bob's connection must not see alice's row even from a query with no \
             tenant predicate of its own: {rows:?}"
        );

        // Sanity check on the same connection, so a failure above cannot be
        // mistaken for "RLS blocks everything": alice's own row must still
        // be visible once scoped to alice.
        sqlx::query("SELECT set_config('app.current_tenant', $1, true)")
            .bind(alice.as_str())
            .execute(&mut *tx)
            .await
            .unwrap();
        let rows: Vec<String> = sqlx::query_scalar("SELECT path FROM store_paths WHERE path = $1")
            .bind(P)
            .fetch_all(&mut *tx)
            .await
            .unwrap();
        assert_eq!(
            rows,
            vec![P.to_string()],
            "alice must still see her own row"
        );
    }

    #[tokio::test]
    async fn a_tier_survives_the_round_trip() {
        // The tier decides whether a path may ever be signed or served, so a
        // column that read back wrong would quietly make quarantined content
        // vouchable.
        let Some(store) = db().await else { return };
        let t = tenant("tier");
        store
            .record_path(&t, info(P), object("k"), Tier::Quarantined)
            .await
            .unwrap();
        assert_eq!(store.tier(&t, &p()).await, Some(Tier::Quarantined));

        store
            .record_path(&t, info(P), object("k"), Tier::Built)
            .await
            .unwrap();
        assert_eq!(store.tier(&t, &p()).await, Some(Tier::Built));
    }

    #[tokio::test]
    async fn object_known_reports_whether_a_key_is_recorded() {
        let Some(store) = db().await else { return };
        assert!(!store.object_known(&ObjectKey::new("no-such-key")).await);

        let t = tenant("object-known");
        store
            .record_path(&t, info(P), object("shared/nar/x.nar.zst"), Tier::Verified)
            .await
            .unwrap();
        assert!(
            store
                .object_known(&ObjectKey::new("shared/nar/x.nar.zst"))
                .await
        );
    }

    #[tokio::test]
    async fn two_tenants_pushing_the_same_object_key_share_one_objects_row() {
        // The dedup PLAN.md Phase 9c step 1 exists for: a `Verified` key is
        // shared by construction (no tenant prefix — `nar_key`), so two
        // tenants recording the same key must land on one `objects` row, not
        // two, and neither tenant's own row loses its distinct path/tier.
        let Some(store) = db().await else { return };
        let (alice, bob) = (tenant("dedup-alice"), tenant("dedup-bob"));
        let shared_key = "nar/00000000000000000000000000000000.nar.zst";

        store
            .record_path(&alice, info(P), object(shared_key), Tier::Verified)
            .await
            .unwrap();
        store
            .record_path(&bob, info(P), object(shared_key), Tier::Verified)
            .await
            .unwrap();

        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM objects WHERE key = $1")
            .bind(shared_key)
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(count, 1, "one shared object, not one per tenant");

        // And each tenant still has its own store_paths row pointing at it —
        // sharing the bytes did not merge the paths.
        assert_eq!(
            store
                .output_object(&alice, &p())
                .await
                .unwrap()
                .key
                .as_str(),
            shared_key
        );
        assert_eq!(
            store.output_object(&bob, &p()).await.unwrap().key.as_str(),
            shared_key
        );
    }

    // `find_verified_by_hash_part` is deliberately *not* tenant-scoped, unlike
    // every other method in this file — so unlike them it cannot share `P`
    // with the rest of the suite: any other test recording `P` as `Verified`
    // (there are several) would make these races against whichever one the
    // database happens to run first. Each test below gets its own hash part.

    #[tokio::test]
    async fn find_verified_by_hash_part_answers_for_a_row_the_caller_never_wrote() {
        // PLAN.md Phase 9c step two: the read this is built for. Alice pushes;
        // the lookup by hash part alone (no tenant argument) must find it.
        let Some(store) = db().await else { return };
        let alice = tenant("find-verified-alice");
        let path = "22222222222222222222222222222222-thing";
        store
            .record_path(
                &alice,
                info(path),
                object("nar/find-verified.nar.zst"),
                Tier::Verified,
            )
            .await
            .unwrap();

        let (found_info, found_object) = store
            .find_verified_by_hash_part("22222222222222222222222222222222")
            .await
            .expect("some tenant's verified row");
        assert_eq!(found_info.path, StorePath::new(path));
        assert_eq!(found_object.key.as_str(), "nar/find-verified.nar.zst");
    }

    #[tokio::test]
    async fn find_verified_by_hash_part_ignores_built_and_quarantined() {
        // Only `Verified` is provably identical across tenants; `Built` and
        // `Quarantined` rows at the same hash part must not answer this
        // lookup, even though they exist.
        let Some(store) = db().await else { return };
        let alice = tenant("find-verified-built");
        let path = "33333333333333333333333333333333-thing";
        store
            .record_path(&alice, info(path), object("alice/nar/x"), Tier::Built)
            .await
            .unwrap();

        assert!(
            store
                .find_verified_by_hash_part("33333333333333333333333333333333")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn find_verified_by_hash_part_ignores_a_marked_or_purging_row() {
        // Mirrors every other read here going through `store_paths_live`
        // (PLAN.md Phase 12): a row on its way out must not be handed to a
        // second tenant as something worth materializing a fresh copy of.
        let Some(store) = db().await else { return };
        let alice = tenant("find-verified-marked");
        let path = "44444444444444444444444444444444-thing";
        store
            .record_path(
                &alice,
                info(path),
                object("nar/marked.nar.zst"),
                Tier::Verified,
            )
            .await
            .unwrap();
        sqlx::query("UPDATE store_paths SET state = 'marked' WHERE tenant = $1 AND path = $2")
            .bind(alice.as_str())
            .bind(path)
            .execute(&store.pool)
            .await
            .unwrap();

        assert!(
            store
                .find_verified_by_hash_part("44444444444444444444444444444444")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_later_push_of_the_same_key_does_not_overwrite_the_objects_row() {
        // `ON CONFLICT (key) DO NOTHING`: whichever tenant's push lands first
        // owns the object row's file_size/file_hash, and a second push under
        // the same key — necessarily identical content, since the key is a
        // function of it — must not disturb that.
        let Some(store) = db().await else { return };
        let (alice, bob) = (tenant("first-wins-alice"), tenant("first-wins-bob"));
        let shared_key = "nar/11111111111111111111111111111111.nar.zst";

        store
            .record_path(
                &alice,
                info(P),
                crate::store::RemoteObject {
                    key: ObjectKey::new(shared_key),
                    file_size: 111,
                    file_hash: Output::<Sha256>::from([1u8; 32]),
                },
                Tier::Verified,
            )
            .await
            .unwrap();
        // Bob's own compression of identical bytes need not produce the exact
        // same size, so record different metadata to prove it is ignored.
        store
            .record_path(
                &bob,
                info(P),
                crate::store::RemoteObject {
                    key: ObjectKey::new(shared_key),
                    file_size: 222,
                    file_hash: Output::<Sha256>::from([2u8; 32]),
                },
                Tier::Verified,
            )
            .await
            .unwrap();

        let bobs_view = store.output_object(&bob, &p()).await.unwrap();
        assert_eq!(bobs_view.file_size, 111);
        assert_eq!(bobs_view.file_hash, Output::<Sha256>::from([1u8; 32]));
    }

    #[tokio::test]
    async fn a_completed_job_outcome_round_trips() {
        let Some(store) = db().await else { return };
        let t = tenant("job-completed");
        let job_id = uuid::Uuid::new_v4();
        let drv = StorePath::new(format!("00000000000000000000000000000000-{job_id}.drv"));

        store
            .record_job_outcome(
                &t,
                job_id,
                &drv,
                "x86_64-linux",
                &JobOutcome::Completed {
                    outputs: vec![p()],
                    infos: Vec::new(),
                    log_key: format!("{t}/log/{job_id}"),
                },
            )
            .await;

        // Row-level security: `jobs` is tenant-isolated, so reading it back
        // needs `app.current_tenant` set the same way every real write does
        // (`PostgresStore::tenant_scoped`) -- a bare `&store.pool` query has
        // no tenant context and, found by actually running this against a
        // real RLS-enabled Postgres rather than only `cargo build`, silently
        // sees zero rows instead of this test's own freshly written one.
        let mut tx = store.tenant_scoped(&t).await.unwrap();
        let row = sqlx::query(
            "SELECT status, error_msg, output_paths, log_key, failure_kind, finished_at IS NOT NULL AS has_finished_at
               FROM jobs WHERE id = $1",
        )
        .bind(job_id)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert_eq!(row.get::<String, _>("status"), "completed");
        assert!(row.get::<Option<String>, _>("error_msg").is_none());
        assert_eq!(row.get::<Vec<String>, _>("output_paths"), vec![P]);
        assert_eq!(row.get::<String, _>("log_key"), format!("{t}/log/{job_id}"));
        assert!(row.get::<Option<String>, _>("failure_kind").is_none());
        assert!(row.get::<bool, _>("has_finished_at"));
    }

    #[tokio::test]
    async fn a_failed_job_outcome_round_trips() {
        let Some(store) = db().await else { return };
        let t = tenant("job-failed");
        let job_id = uuid::Uuid::new_v4();
        let drv = StorePath::new(format!("00000000000000000000000000000000-{job_id}.drv"));

        store
            .record_job_outcome(
                &t,
                job_id,
                &drv,
                "x86_64-linux",
                &JobOutcome::Failed {
                    message: "builder exited with 1".to_string(),
                    log_key: format!("{t}/log/{job_id}"),
                    failure_kind: None,
                },
            )
            .await;

        // Row-level security -- see `a_completed_job_outcome_round_trips`'s
        // comment above.
        let mut tx = store.tenant_scoped(&t).await.unwrap();
        let status: String = sqlx::query_scalar("SELECT status FROM jobs WHERE id = $1")
            .bind(job_id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        assert_eq!(status, "failed");
        let error_msg: Option<String> =
            sqlx::query_scalar("SELECT error_msg FROM jobs WHERE id = $1")
                .bind(job_id)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        assert_eq!(error_msg.as_deref(), Some("builder exited with 1"));
        let failure_kind: Option<String> =
            sqlx::query_scalar("SELECT failure_kind FROM jobs WHERE id = $1")
                .bind(job_id)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        assert!(
            failure_kind.is_none(),
            "an ordinary build failure must not carry a failure_kind"
        );
    }

    #[tokio::test]
    async fn a_resource_exhaustion_failure_records_its_failure_kind() {
        let Some(store) = db().await else { return };
        let t = tenant("job-oom");
        let job_id = uuid::Uuid::new_v4();
        let drv = StorePath::new(format!("00000000000000000000000000000000-{job_id}.drv"));

        store
            .record_job_outcome(
                &t,
                job_id,
                &drv,
                "x86_64-linux",
                &JobOutcome::Failed {
                    message: "out of memory".to_string(),
                    log_key: format!("{t}/log/{job_id}"),
                    failure_kind: Some(crate::jobs::FailureKind::OutOfMemory),
                },
            )
            .await;

        // Row-level security -- see `a_completed_job_outcome_round_trips`'s
        // comment above.
        let mut tx = store.tenant_scoped(&t).await.unwrap();
        let failure_kind: Option<String> =
            sqlx::query_scalar("SELECT failure_kind FROM jobs WHERE id = $1")
                .bind(job_id)
                .fetch_one(&mut *tx)
                .await
                .unwrap();
        assert_eq!(failure_kind.as_deref(), Some("out_of_memory"));
    }

    #[tokio::test]
    async fn reserve_job_wins_when_nothing_is_in_flight() {
        let Some(store) = db().await else { return };
        let t = tenant("reserve-fresh");
        let job_id = uuid::Uuid::new_v4();
        let drv = reserve_test_drv(job_id);

        let r = store
            .reserve_job(&t, job_id, &drv, "x86_64-linux", Duration::from_secs(3600))
            .await;
        assert_eq!(r, Reservation::Won);
    }

    #[tokio::test]
    async fn reserve_job_loses_to_an_existing_fresh_reservation() {
        let Some(store) = db().await else { return };
        let t = tenant("reserve-lose");
        let first = uuid::Uuid::new_v4();
        let second = uuid::Uuid::new_v4();
        let drv = reserve_test_drv(first);

        assert_eq!(
            store
                .reserve_job(&t, first, &drv, "x86_64-linux", Duration::from_secs(3600))
                .await,
            Reservation::Won
        );
        assert_eq!(
            store
                .reserve_job(&t, second, &drv, "x86_64-linux", Duration::from_secs(3600))
                .await,
            Reservation::Lost(first),
            "a second request for the same (tenant, derivation) must attach to the first job, \
             never dispatch its own"
        );
    }

    #[tokio::test]
    async fn reserve_job_does_not_collide_across_tenants() {
        let Some(store) = db().await else { return };
        let alice = tenant("reserve-alice");
        let bob = tenant("reserve-bob");
        let alice_job = uuid::Uuid::new_v4();
        let bob_job = uuid::Uuid::new_v4();
        // Same derivation path on purpose: it's exactly the case (a shared,
        // content-addressed `.drv`) this test guards against being dedup'd
        // across tenants.
        let drv = reserve_test_drv(alice_job);

        assert_eq!(
            store
                .reserve_job(
                    &alice,
                    alice_job,
                    &drv,
                    "x86_64-linux",
                    Duration::from_secs(3600)
                )
                .await,
            Reservation::Won
        );
        assert_eq!(
            store
                .reserve_job(
                    &bob,
                    bob_job,
                    &drv,
                    "x86_64-linux",
                    Duration::from_secs(3600)
                )
                .await,
            Reservation::Won,
            "two tenants building the identical (content-addressed) derivation must never share \
             a reservation or a job id"
        );
    }

    #[tokio::test]
    async fn reserve_job_steals_a_reservation_older_than_retention() {
        let Some(store) = db().await else { return };
        let t = tenant("reserve-steal");
        let stale = uuid::Uuid::new_v4();
        let fresh = uuid::Uuid::new_v4();
        let drv = reserve_test_drv(stale);

        assert_eq!(
            store
                .reserve_job(&t, stale, &drv, "x86_64-linux", Duration::from_secs(3600))
                .await,
            Reservation::Won
        );
        // Backdate it past any retention this test uses -- standing in for
        // the process that reserved it having crashed before completing it.
        // Row-level security means this has to go through a
        // tenant-scoped transaction (`app.current_tenant` set), the same as
        // every real write to `jobs` -- an ad hoc `&store.pool` query with no
        // tenant context set would match zero rows here, silently.
        let mut tx = store.tenant_scoped(&t).await.unwrap();
        sqlx::query("UPDATE jobs SET created_at = NOW() - INTERVAL '2 hours' WHERE id = $1")
            .bind(stale)
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let r = store
            .reserve_job(&t, fresh, &drv, "x86_64-linux", Duration::from_secs(3600))
            .await;
        assert_eq!(
            r,
            Reservation::Won,
            "a reservation older than the retention window must be stolen, not reported as \
             still in flight"
        );

        // Row-level security again -- see the tenant-scoped write above.
        let mut tx = store.tenant_scoped(&t).await.unwrap();
        let (id, status): (uuid::Uuid, String) = sqlx::query_as(
            "SELECT id, status FROM jobs WHERE tenant = $1 AND derivation_path = $2",
        )
        .bind(t.as_str())
        .bind(drv.as_str())
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert_eq!(id, fresh, "the stolen row must now belong to the new job");
        assert_eq!(status, "running");
    }

    #[tokio::test]
    async fn completing_a_job_frees_its_reservation_for_a_new_build() {
        let Some(store) = db().await else { return };
        let t = tenant("reserve-completed");
        let first = uuid::Uuid::new_v4();
        let second = uuid::Uuid::new_v4();
        let drv = reserve_test_drv(first);

        assert_eq!(
            store
                .reserve_job(&t, first, &drv, "x86_64-linux", Duration::from_secs(3600))
                .await,
            Reservation::Won
        );
        store
            .record_job_outcome(
                &t,
                first,
                &drv,
                "x86_64-linux",
                &JobOutcome::Completed {
                    outputs: vec![p()],
                    infos: Vec::new(),
                    log_key: format!("{t}/log/{first}"),
                },
            )
            .await;

        assert_eq!(
            store
                .reserve_job(&t, second, &drv, "x86_64-linux", Duration::from_secs(3600))
                .await,
            Reservation::Won,
            "a completed job's row must not keep blocking a genuinely new build of the same \
             derivation"
        );
    }

    #[tokio::test]
    async fn verified_is_refreshed_when_auth_is_turned_on() {
        let Some(store) = db().await else { return };
        // The same client, first unverified and later verified: the row must be
        // upgraded rather than a second tenant appearing.
        let claimed = Tenant::from_ssh("upgrade", Some("SHA256:fake"), false);
        let proven = Tenant::from_ssh("upgrade", Some("SHA256:fake"), true);
        assert_eq!(claimed.id, proven.id);

        store.register_tenant(&claimed).await.unwrap();
        store.register_tenant(&proven).await.unwrap();

        let verified: bool = sqlx::query_scalar("SELECT verified FROM tenants WHERE id = $1")
            .bind(proven.id.as_str())
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert!(verified);
    }

    #[tokio::test]
    async fn reject_unverified_pushes_defaults_to_true_for_a_new_tenant() {
        let Some(store) = db().await else { return };
        let t = Tenant::from_ssh("reject-default", None, false);
        store.register_tenant(&t).await.unwrap();

        assert!(store.reject_unverified_pushes(&t.id).await);
    }

    #[tokio::test]
    async fn reject_unverified_pushes_reads_back_a_relaxed_tenant() {
        let Some(store) = db().await else { return };
        let t = Tenant::from_ssh("reject-relaxed", None, false);
        store.register_tenant(&t).await.unwrap();

        sqlx::query("UPDATE tenants SET reject_unverified_pushes = FALSE WHERE id = $1")
            .bind(t.id.as_str())
            .execute(&store.pool)
            .await
            .unwrap();

        assert!(!store.reject_unverified_pushes(&t.id).await);
    }

    #[tokio::test]
    async fn find_tenant_by_binding_resolves_a_provisioned_key() {
        let Some(store) = db().await else { return };
        let Ok(url) = std::env::var("KUBERNIX_TEST_DATABASE_URL") else {
            return;
        };
        let t = tenant("binding-found");
        let key_id = format!("SHA256:{}", t.as_str());
        provision_binding(&url, &t, &key_id).await;

        let found = store
            .find_tenant_by_binding(KeyType::Ssh, &key_id)
            .await
            .unwrap();
        assert_eq!(found, Some(t));
    }

    #[tokio::test]
    async fn find_tenant_by_binding_is_none_for_an_unprovisioned_key() {
        let Some(store) = db().await else { return };
        let found = store
            .find_tenant_by_binding(KeyType::Ssh, "SHA256:never-provisioned")
            .await
            .unwrap();
        assert_eq!(found, None);
    }
}
