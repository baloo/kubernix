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

use sqlx::Row;
use sqlx::postgres::{PgPool, PgPoolOptions};

use crate::store::{
    ClientOptions, Hash, HashType, MissingPaths, PathInfo, RemoteObject, Result, Store, StoreError,
    Tier,
};
use kubernix_signing::{KIND_LOCAL_ED25519, LocalSigner, Signer, key_name_for};

use crate::tenant::{Tenant, TenantId};

pub struct PostgresStore {
    pool: PgPool,
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
        let pool = PgPoolOptions::new().max_connections(16).connect(url).await?;

        // Applied on startup rather than by a separate step so a fresh
        // deployment works without one.
        sqlx::migrate!("./migrations").run(&pool).await.map_err(
            |e| sqlx::Error::Configuration(Box::new(e)),
        )?;

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
            path: row.get("path"),
            deriver: row.get("deriver"),
            nar_hash: Hash {
                hash_type: algo_from_name(row.get::<String, _>("nar_hash_algo").as_str()),
                bytes: row.get("nar_hash"),
            },
            nar_size: row.get::<i64, _>("nar_size") as u64,
            references: row.get("refs"),
            registration_time: row.get("registration_time"),
            ultimate: row.get("ultimate"),
            sigs: row.get("sigs"),
        }
    }

    /// Upsert a path's metadata.
    ///
    /// No bytes: the database records *where* a path is, never what it holds.
    async fn upsert_path(
        &self,
        tenant: &TenantId,
        info: &PathInfo,
        object: &RemoteObject,
        tier: Tier,
    ) -> Result<()> {
        self.ensure_tenant_id(tenant).await?;
        sqlx::query(
            "INSERT INTO store_paths (
                 tenant, path, hash_part, deriver, nar_hash_algo, nar_hash, nar_size,
                 registration_time, ultimate, refs, sigs, object_key, file_size, file_hash, tier
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
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
                 file_size = EXCLUDED.file_size,
                 file_hash = EXCLUDED.file_hash,
                 tier = EXCLUDED.tier",
        )
        .bind(tenant.as_str())
        .bind(&info.path)
        .bind(hash_part_of(&info.path))
        .bind(&info.deriver)
        .bind(algo_name(info.nar_hash.hash_type))
        .bind(&info.nar_hash.bytes)
        .bind(info.nar_size as i64)
        .bind(info.registration_time)
        .bind(info.ultimate)
        .bind(&info.references)
        .bind(&info.sigs)
        .bind(object.key.as_str())
        .bind(object.file_size as i64)
        .bind(object.file_hash.as_slice())
        .bind(tier.as_str())
        .execute(&self.pool)
        .await
        .map_err(db_err)?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl Store for PostgresStore {
    async fn is_valid_path(&self, tenant: &TenantId, path: &str) -> bool {
        sqlx::query("SELECT 1 FROM store_paths WHERE tenant = $1 AND path = $2")
            .bind(tenant.as_str())
            .bind(path)
            .fetch_optional(&self.pool)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, %path, "isValidPath query failed");
                None
            })
            .is_some()
    }

    async fn query_valid_paths(&self, tenant: &TenantId, paths: &[String]) -> Vec<String> {
        sqlx::query_scalar("SELECT path FROM store_paths WHERE tenant = $1 AND path = ANY($2)")
            .bind(tenant.as_str())
            .bind(paths)
            .fetch_all(&self.pool)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "queryValidPaths failed");
                Vec::new()
            })
    }

    async fn query_all_valid_paths(&self, tenant: &TenantId) -> Vec<String> {
        sqlx::query_scalar("SELECT path FROM store_paths WHERE tenant = $1")
            .bind(tenant.as_str())
            .fetch_all(&self.pool)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "queryAllValidPaths failed");
                Vec::new()
            })
    }

    async fn query_path_info(&self, tenant: &TenantId, path: &str) -> Option<PathInfo> {
        sqlx::query("SELECT * FROM store_paths WHERE tenant = $1 AND path = $2")
            .bind(tenant.as_str())
            .bind(path)
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
    ) -> Option<String> {
        sqlx::query_scalar("SELECT path FROM store_paths WHERE tenant = $1 AND hash_part = $2")
            .bind(tenant.as_str())
            .bind(hash_part)
            .fetch_optional(&self.pool)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "queryPathFromHashPart failed");
                None
            })
    }

    async fn query_referrers(&self, tenant: &TenantId, path: &str) -> Vec<String> {
        // `@>` is the array-containment operator the GIN index answers.
        sqlx::query_scalar("SELECT path FROM store_paths WHERE tenant = $1 AND refs @> ARRAY[$2]")
            .bind(tenant.as_str())
            .bind(path)
            .fetch_all(&self.pool)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, %path, "queryReferrers failed");
                Vec::new()
            })
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

    async fn output_object(&self, tenant: &TenantId, path: &str) -> Option<RemoteObject> {
        let row = sqlx::query(
            "SELECT object_key, file_size, file_hash FROM store_paths WHERE tenant = $1 AND path = $2",
        )
        .bind(tenant.as_str())
        .bind(path)
        .fetch_optional(&self.pool)
        .await
        .unwrap_or_else(|e| {
            tracing::error!(error = %e, %path, "object lookup failed");
            None
        })?;

        Some(RemoteObject {
            key: row.get::<Option<String>, _>("object_key")?,
            file_size: row.get::<Option<i64>, _>("file_size").unwrap_or(0) as u64,
            file_hash: row.get::<Option<Vec<u8>>, _>("file_hash").unwrap_or_default(),
        })
    }

    async fn add_signatures(&self, tenant: &TenantId, path: &str, sigs: Vec<String>) -> Result<()> {
        // Union in SQL so concurrent signers do not clobber each other, which a
        // read-modify-write would.
        let updated = sqlx::query(
            "UPDATE store_paths
                SET sigs = ARRAY(SELECT DISTINCT unnest(sigs || $3::text[]))
              WHERE tenant = $1 AND path = $2",
        )
        .bind(tenant.as_str())
        .bind(path)
        .bind(&sigs)
        .execute(&self.pool)
        .await
        .map_err(db_err)?;

        if updated.rows_affected() == 0 {
            return Err(StoreError::NotFound(path.to_string()));
        }
        Ok(())
    }

    async fn query_missing(&self, tenant: &TenantId, targets: &[String]) -> MissingPaths {
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

        let name = key_name_for(tenant.as_str());
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

    async fn tier(&self, tenant: &TenantId, path: &str) -> Option<Tier> {
        sqlx::query_scalar::<_, String>(
            "SELECT tier FROM store_paths WHERE tenant = $1 AND path = $2",
        )
        .bind(tenant.as_str())
        .bind(path)
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
            path: path.to_string(),
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
            key: key.to_string(),
            file_size: 3,
            file_hash: vec![9; 32],
        }
    }

    const P: &str = "/nix/store/00000000000000000000000000000000-thing";
    const DEP: &str = "/nix/store/11111111111111111111111111111111-dep";

    #[tokio::test]
    async fn round_trips_a_pushed_path() {
        let Some(store) = db().await else { return };
        let t = tenant("roundtrip");

        assert!(!store.is_valid_path(&t, P).await);
        store
            .record_path(&t, info(P), object("k"), Tier::Verified)
            .await
            .unwrap();

        assert!(store.is_valid_path(&t, P).await);
        assert_eq!(store.query_valid_paths(&t, &[P.to_string()]).await, vec![P]);
        assert_eq!(store.output_object(&t, P).await.unwrap().key, "k");

        let read = store.query_path_info(&t, P).await.expect("recorded");
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
                .await
                .as_deref(),
            Some(P)
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
        referrer.references = vec![DEP.to_string()];
        store
            .record_path(&t, referrer, object("k"), Tier::Verified)
            .await
            .unwrap();

        assert_eq!(store.query_referrers(&t, DEP).await, vec![P]);
        assert!(store.query_referrers(&t, P).await.is_empty());
        // And the references survive the round trip, since a narinfo is made of
        // them.
        assert_eq!(
            store.query_path_info(&t, P).await.unwrap().references,
            vec![DEP]
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
                    key: key.to_string(),
                    file_size: 99,
                    file_hash: vec![0xcd; 32],
                },
                Tier::Built,
            )
            .await
            .unwrap();

        // The database records where the bytes are, never the bytes; the RPC
        // layer and the cache both fetch from this key.
        let remote = store.output_object(&t, P).await.expect("has an object");
        assert_eq!(remote.key, key);
        assert_eq!(remote.file_size, 99);
        // The compressed hash must survive: it is what a narinfo `FileHash`
        // states, and a client verifies its download against it.
        assert_eq!(remote.file_hash, vec![0xcd; 32]);
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
            .add_signatures(&t, P, vec!["a:1".to_string()])
            .await
            .unwrap();
        store
            .add_signatures(&t, P, vec!["a:1".to_string(), "b:2".to_string()])
            .await
            .unwrap();

        let mut sigs = store.query_path_info(&t, P).await.unwrap().sigs;
        sigs.sort();
        assert_eq!(sigs, vec!["a:1", "b:2"]);
    }

    #[tokio::test]
    async fn signing_an_unknown_path_is_not_found() {
        let Some(store) = db().await else { return };
        let t = tenant("sigs-missing");
        assert!(matches!(
            store.add_signatures(&t, P, vec!["a:1".to_string()]).await,
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

        assert!(!store.is_valid_path(&bob, P).await);
        assert!(store.query_path_info(&bob, P).await.is_none());
        assert!(store.query_all_valid_paths(&bob).await.is_empty());
        assert!(
            store
                .query_path_from_hash_part(&bob, "00000000000000000000000000000000")
                .await
                .is_none()
        );
        assert!(store.output_object(&bob, P).await.is_none());

        // And the same path may hold different bytes for each: whoever writes
        // second must not win, which is what `(tenant, path)` as the primary key
        // buys.
        store
            .record_path(&bob, info(P), object("k"), Tier::Verified)
            .await
            .unwrap();
        assert_eq!(store.output_object(&alice, P).await.unwrap().key, "alice/nar/x");
        assert_eq!(store.output_object(&bob, P).await.unwrap().key, "k");
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
        assert_eq!(store.tier(&t, P).await, Some(Tier::Quarantined));

        store
            .record_path(&t, info(P), object("k"), Tier::Built)
            .await
            .unwrap();
        assert_eq!(store.tier(&t, P).await, Some(Tier::Built));
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

        let verified: bool =
            sqlx::query_scalar("SELECT verified FROM tenants WHERE id = $1")
                .bind(proven.id.as_str())
                .fetch_one(&store.pool)
                .await
                .unwrap();
        assert!(verified);
    }
}
