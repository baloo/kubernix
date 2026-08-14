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

use std::sync::Arc;

use sha2::{Sha256, digest::Output};
use sqlx::Row;
use sqlx::postgres::{PgPool, PgPoolOptions};

use crate::jobs::JobOutcome;
use crate::store::{
    ClientOptions, Hash, HashType, MissingPaths, PathInfo, RemoteObject, Result, Store, StoreError,
    Tier,
};
use kubernix_signing::{KIND_LOCAL_ED25519, LocalSigner, Signer, key_name_for};
use kubernix_types::{ObjectKey, StorePath};
use uuid::Uuid;

use crate::tenant::{Tenant, TenantId};

pub struct PostgresStore {
    // `pub(crate)` rather than private: `crate::gc` runs its own statements
    // (advisory lock, drain/mark/sweep) directly against the pool, which is
    // GC-specific enough that it does not belong on the `Store` trait.
    pub(crate) pool: PgPool,
}

/// `/nix/store/<32-char hash>-<name>` → `<32-char hash>`.
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

impl PostgresStore {
    /// Connect and apply the migrations.
    pub async fn connect(url: &str) -> std::result::Result<Arc<Self>, sqlx::Error> {
        tracing::info!("connecting to PostgreSQL");
        let pool = PgPoolOptions::new()
            .max_connections(16)
            .connect(url)
            .await?;

        // Applied on startup rather than by a separate step so a fresh
        // deployment works without one.
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(|e| sqlx::Error::Configuration(Box::new(e)))?;

        tracing::info!("database ready");
        Ok(Arc::new(Self { pool }))
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

        let mut txn = self.pool.begin().await.map_err(db_err)?;

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

#[async_trait::async_trait]
impl Store for PostgresStore {
    async fn is_valid_path(&self, tenant: &TenantId, path: &StorePath) -> bool {
        sqlx::query("SELECT 1 FROM store_paths_live WHERE tenant = $1 AND path = $2")
            .bind(tenant.as_str())
            .bind(path.as_str())
            .fetch_optional(&self.pool)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, %path, "isValidPath query failed");
                None
            })
            .is_some()
    }

    async fn query_valid_paths(&self, tenant: &TenantId, paths: &[StorePath]) -> Vec<StorePath> {
        let raw: Vec<&str> = paths.iter().map(StorePath::as_str).collect();
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT path FROM store_paths_live WHERE tenant = $1 AND path = ANY($2)",
        )
        .bind(tenant.as_str())
        .bind(&raw)
        .fetch_all(&self.pool)
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "queryValidPaths failed");
            Vec::new()
        });
        rows.into_iter().map(StorePath::new).collect()
    }

    async fn query_all_valid_paths(&self, tenant: &TenantId) -> Vec<StorePath> {
        let rows: Vec<String> =
            sqlx::query_scalar("SELECT path FROM store_paths_live WHERE tenant = $1")
                .bind(tenant.as_str())
                .fetch_all(&self.pool)
                .await
                .unwrap_or_else(|e| {
                    tracing::error!(error = %e, "queryAllValidPaths failed");
                    Vec::new()
                });
        rows.into_iter().map(StorePath::new).collect()
    }

    async fn query_path_info(&self, tenant: &TenantId, path: &StorePath) -> Option<PathInfo> {
        sqlx::query("SELECT * FROM store_paths_live WHERE tenant = $1 AND path = $2")
            .bind(tenant.as_str())
            .bind(path.as_str())
            .fetch_optional(&self.pool)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, %path, "queryPathInfo failed");
                None
            })
            .map(|row| Self::row_to_info(&row))
    }

    async fn query_path_from_hash_part(
        &self,
        tenant: &TenantId,
        hash_part: &str,
    ) -> Option<StorePath> {
        sqlx::query_scalar::<_, String>(
            "SELECT path FROM store_paths_live WHERE tenant = $1 AND hash_part = $2",
        )
        .bind(tenant.as_str())
        .bind(hash_part)
        .fetch_optional(&self.pool)
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, "queryPathFromHashPart failed");
            None
        })
        .map(StorePath::new)
    }

    async fn query_referrers(&self, tenant: &TenantId, path: &StorePath) -> Vec<StorePath> {
        // `@>` is the array-containment operator the GIN index answers.
        let rows: Vec<String> = sqlx::query_scalar(
            "SELECT path FROM store_paths_live WHERE tenant = $1 AND refs @> ARRAY[$2]",
        )
        .bind(tenant.as_str())
        .bind(path.as_str())
        .fetch_all(&self.pool)
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, %path, "queryReferrers failed");
            Vec::new()
        });
        rows.into_iter().map(StorePath::new).collect()
    }

    async fn record_path(
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

    async fn output_object(&self, tenant: &TenantId, path: &StorePath) -> Option<RemoteObject> {
        let row = sqlx::query(
            "SELECT o.key, o.file_size, o.file_hash
               FROM store_paths_live sp JOIN objects o ON o.key = sp.object_key
              WHERE sp.tenant = $1 AND sp.path = $2",
        )
        .bind(tenant.as_str())
        .bind(path.as_str())
        .fetch_optional(&self.pool)
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

    async fn object_known(&self, key: &ObjectKey) -> bool {
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

    async fn find_verified_by_hash_part(
        &self,
        hash_part: &str,
    ) -> Option<(PathInfo, RemoteObject)> {
        // No `tenant` predicate at all — deliberately, like `object_known`.
        // Content-addressing means any tenant's `Verified` row for this hash
        // part is provably identical to any other's, so the first one found
        // answers for all. PLAN.md Phase 9c step two.
        let row = sqlx::query(
            "SELECT sp.*, o.key AS obj_key, o.file_size AS obj_file_size,
                    o.file_hash AS obj_file_hash
               FROM store_paths_live sp JOIN objects o ON o.key = sp.object_key
              WHERE sp.tier = 'verified' AND sp.hash_part = $1
              LIMIT 1",
        )
        .bind(hash_part)
        .fetch_optional(&self.pool)
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

    async fn add_signatures(
        &self,
        tenant: &TenantId,
        path: &StorePath,
        sigs: Vec<String>,
    ) -> Result<()> {
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
        .execute(&self.pool)
        .await
        .map_err(db_err)?;

        if updated.rows_affected() == 0 {
            return Err(StoreError::NotFound(path.to_string()));
        }
        Ok(())
    }

    async fn query_missing(&self, tenant: &TenantId, targets: &[StorePath]) -> MissingPaths {
        let present = self.query_valid_paths(tenant, targets).await;
        let mut missing = MissingPaths::default();
        for target in targets {
            if !present.contains(target) {
                // The frontend builds rather than substitutes.
                missing.will_build.push(target.clone());
            }
        }
        missing
    }

    async fn register_tenant(&self, tenant: &Tenant) -> Result<()> {
        self.ensure_tenant(tenant).await
    }

    /// Load the tenant's key, generating and persisting one on first use.
    ///
    /// The insert is conditional (`WHERE signing_key_material IS NULL`) and the
    /// result is read back, so two frontends racing to create a key for the same
    /// tenant converge on whichever landed first. Losing that race silently and
    /// signing with a key nobody else has would produce signatures no client
    /// could verify.
    async fn signer(&self, tenant: &TenantId) -> Option<Arc<dyn Signer>> {
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

    async fn tier(&self, tenant: &TenantId, path: &StorePath) -> Option<Tier> {
        sqlx::query_scalar::<_, String>(
            "SELECT tier FROM store_paths_live WHERE tenant = $1 AND path = $2",
        )
        .bind(tenant.as_str())
        .bind(path.as_str())
        .fetch_optional(&self.pool)
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, %path, "tier lookup failed");
            None
        })
        .map(|s| Tier::from_str(&s))
    }

    async fn set_options(&self, tenant: &TenantId, options: ClientOptions) {
        // Deliberately not persisted. These are per-connection client
        // preferences, not store state, and outliving the connection would be
        // wrong rather than merely wasteful. They are on the `Store` trait
        // because that is where the RPC layer could reach them; that is a wart
        // worth undoing when something actually consumes them.
        tracing::debug!(%tenant, ?options, "client options");
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
    async fn record_access(&self, tenant: &TenantId, path: &StorePath) {
        if let Err(e) = sqlx::query("INSERT INTO path_access (tenant, path) VALUES ($1, $2)")
            .bind(tenant.as_str())
            .bind(path.as_str())
            .execute(&self.pool)
            .await
        {
            tracing::warn!(error = %e, %tenant, %path, "recording access failed");
        }
    }

    /// Insert one `jobs` row for a terminal outcome. Best-effort, like
    /// [`Self::record_access`] — see the trait doc comment for why this is
    /// insert-only rather than insert-then-update.
    async fn record_job_outcome(
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

        let (status, error_msg, output_paths, log_key): (&str, Option<&str>, Vec<&str>, &str) =
            match outcome {
                JobOutcome::Completed {
                    outputs, log_key, ..
                } => (
                    "completed",
                    None,
                    outputs.iter().map(StorePath::as_str).collect(),
                    log_key,
                ),
                JobOutcome::Failed { message, log_key } => {
                    ("failed", Some(message.as_str()), Vec::new(), log_key)
                }
            };

        if let Err(e) = sqlx::query(
            "INSERT INTO jobs (
                 id, tenant, derivation_path, system, status, error_msg,
                 output_paths, log_key, finished_at
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())",
        )
        .bind(job_id)
        .bind(tenant.as_str())
        .bind(derivation_path.as_str())
        .bind(system)
        .bind(status)
        .bind(error_msg)
        .bind(&output_paths)
        .bind(log_key)
        .execute(&self.pool)
        .await
        {
            tracing::warn!(error = %e, %tenant, %job_id, "recording job outcome failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_the_hash_part() {
        assert_eq!(
            hash_part_of("/nix/store/00000000000000000000000000000000-thing"),
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

    /// Connect, or return `None` after saying why.
    async fn db() -> Option<Arc<PostgresStore>> {
        let Ok(url) = std::env::var("KUBERNIX_TEST_DATABASE_URL") else {
            eprintln!("skipping: KUBERNIX_TEST_DATABASE_URL unset");
            return None;
        };
        match PostgresStore::connect(&url).await {
            Ok(store) => Some(store),
            Err(e) => panic!("KUBERNIX_TEST_DATABASE_URL is set but unusable: {e}"),
        }
    }

    /// A tenant unique to one test.
    fn tenant(test: &str) -> TenantId {
        Tenant::from_ssh(&format!("test-{test}"), None, false).id
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

    const P: &str = "/nix/store/00000000000000000000000000000000-thing";
    const DEP: &str = "/nix/store/11111111111111111111111111111111-dep";

    fn p() -> StorePath {
        StorePath::new(P)
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
        let path = "/nix/store/22222222222222222222222222222222-thing";
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
        let path = "/nix/store/33333333333333333333333333333333-thing";
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
        let path = "/nix/store/44444444444444444444444444444444-thing";
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
        let drv = StorePath::new(format!(
            "/nix/store/00000000000000000000000000000000-{job_id}.drv"
        ));

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

        let row = sqlx::query(
            "SELECT status, error_msg, output_paths, log_key, finished_at IS NOT NULL AS has_finished_at
               FROM jobs WHERE id = $1",
        )
        .bind(job_id)
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert_eq!(row.get::<String, _>("status"), "completed");
        assert!(row.get::<Option<String>, _>("error_msg").is_none());
        assert_eq!(row.get::<Vec<String>, _>("output_paths"), vec![P]);
        assert_eq!(row.get::<String, _>("log_key"), format!("{t}/log/{job_id}"));
        assert!(row.get::<bool, _>("has_finished_at"));
    }

    #[tokio::test]
    async fn a_failed_job_outcome_round_trips() {
        let Some(store) = db().await else { return };
        let t = tenant("job-failed");
        let job_id = uuid::Uuid::new_v4();
        let drv = StorePath::new(format!(
            "/nix/store/00000000000000000000000000000000-{job_id}.drv"
        ));

        store
            .record_job_outcome(
                &t,
                job_id,
                &drv,
                "x86_64-linux",
                &JobOutcome::Failed {
                    message: "builder exited with 1".to_string(),
                    log_key: format!("{t}/log/{job_id}"),
                },
            )
            .await;

        let status: String = sqlx::query_scalar("SELECT status FROM jobs WHERE id = $1")
            .bind(job_id)
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(status, "failed");
        let error_msg: Option<String> =
            sqlx::query_scalar("SELECT error_msg FROM jobs WHERE id = $1")
                .bind(job_id)
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert_eq!(error_msg.as_deref(), Some("builder exited with 1"));
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
}
