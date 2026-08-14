//! The store the daemon protocol is served from.
//!
//! The RPC layer in [`crate::daemon_rpc`] is a pure adapter over this trait, so
//! the protocol code does not change when the backing moves from memory to
//! PostgreSQL + S3 + NATS.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use kubernix_signing::{LocalSigner, Signer, key_name_for};
use kubernix_types::{ObjectKey, StorePath};
use sha2::{Sha256, digest::Output};
use uuid::Uuid;

use crate::jobs::JobOutcome;
use crate::tenant::TenantId;

/// Hash algorithms the daemon protocol can carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashType {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Clone, Debug)]
pub struct Hash {
    pub hash_type: HashType,
    pub bytes: Vec<u8>,
}

/// Everything `queryPathInfo` answers with, and everything a `narinfo` is made
/// of. Store paths here are bare (`<hash>-<name>`, no store directory) — see
/// [`kubernix_types::StorePath`]; the daemon protocol boundary
/// (`StorePath.raw`, `types-rpc.hh:25-38`) is where the full printed form is
/// reconstructed and parsed.
#[derive(Clone, Debug)]
pub struct PathInfo {
    pub path: StorePath,
    pub deriver: Option<StorePath>,
    pub nar_hash: Hash,
    pub nar_size: u64,
    pub references: Vec<StorePath>,
    pub registration_time: i64,
    pub ultimate: bool,
    pub sigs: Vec<String>,
}

/// How much the frontend can vouch for a path — PLAN.md Phase 9.
///
/// The distinction is *provenance*, not content: it records how the path came to
/// be believed, which is what decides whether it may ever be served to anyone
/// but the tenant that produced it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    /// The path was recomputed from the bytes, so the client could not have
    /// lied about it. Safe to share and to sign.
    Verified,
    /// Built by one of our own workers from a derivation we dispatched. Safe to
    /// sign: we are asserting something we did.
    Built,
    /// Accepted on the client's word, because nothing about it is checkable —
    /// an input-addressed path's name is a function of a derivation, not of its
    /// content.
    ///
    /// **Never signed and never publicly served.** Confined to the tenant that
    /// pushed it, so the blast radius of a lie is that tenant's own builds.
    Quarantined,
}

impl Tier {
    /// Whether the frontend may assert this path to anyone else — by signing it,
    /// or by serving it from the public cache.
    pub fn is_vouchable(self) -> bool {
        match self {
            Tier::Verified | Tier::Built => true,
            Tier::Quarantined => false,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Tier::Verified => "verified",
            Tier::Built => "built",
            Tier::Quarantined => "quarantined",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "verified" => Tier::Verified,
            "built" => Tier::Built,
            // An unknown value must not become vouchable by accident.
            _ => Tier::Quarantined,
        }
    }
}

#[derive(Debug)]
pub enum StoreError {
    NotFound(String),
    /// Valid, but its bytes live in the object store rather than here.
    Elsewhere(String),
    Unsupported(&'static str),
    Other(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::NotFound(p) => write!(f, "path not in store: {p}"),
            StoreError::Elsewhere(p) => write!(f, "path is in the object store: {p}"),
            StoreError::Unsupported(op) => write!(f, "operation not supported: {op}"),
            StoreError::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for StoreError {}

pub type Result<T> = std::result::Result<T, StoreError>;

/// Options a client pushes with `setOptions`. Recorded so build dispatch can
/// honour them later.
#[derive(Clone, Debug, Default)]
pub struct ClientOptions {
    pub keep_failed: bool,
    pub keep_going: bool,
    pub try_fallback: bool,
    pub verbosity: u16,
    pub max_build_jobs: u32,
    pub build_cores: u32,
    pub use_substitutes: bool,
    pub overrides: Vec<(String, String)>,
}

/// What the frontend can answer about paths and builds.
///
/// **Every path-facing method is scoped by tenant.** A path is only valid for
/// the tenant it was recorded under, so one tenant cannot observe — or overwrite
/// — another's.
///
/// Each path also carries a [`Tier`] saying how much the frontend can vouch for
/// it. Tenant scoping is the containment; the tier is what decides whether a
/// path may ever leave that containment — be signed, or served to anyone else.
/// A `Quarantined` path never may.
///
/// Async because the backing is a database. `MemoryStore` never actually awaits
/// anything, but it implements the same trait so the protocol layer stays
/// testable without one.
///
/// The futures are `Send` (sqlx's are), while the capnp-rpc caller is `!Send` and
/// runs on a `LocalSet`. Awaiting a `Send` future from a `!Send` task is fine —
/// see NOTES.md item 7.
#[async_trait::async_trait]
pub trait Store: Send + Sync {
    async fn is_valid_path(&self, tenant: &TenantId, path: &StorePath) -> bool;

    async fn query_valid_paths(&self, tenant: &TenantId, paths: &[StorePath]) -> Vec<StorePath>;

    async fn query_all_valid_paths(&self, tenant: &TenantId) -> Vec<StorePath>;

    async fn query_path_info(&self, tenant: &TenantId, path: &StorePath) -> Option<PathInfo>;

    /// Resolve the hash part of a store path (the 32 chars after the store dir).
    async fn query_path_from_hash_part(
        &self,
        tenant: &TenantId,
        hash_part: &str,
    ) -> Option<StorePath>;

    async fn query_referrers(&self, tenant: &TenantId, path: &StorePath) -> Vec<StorePath>;

    /// Paths that could be substituted. The frontend substitutes nothing on the
    /// client's behalf, so this is empty.
    async fn query_substitutable_paths(
        &self,
        _tenant: &TenantId,
        _paths: &[StorePath],
    ) -> Vec<StorePath> {
        Vec::new()
    }

    /// Record a path whose bytes are in the object store.
    ///
    /// One method for both routes a path can arrive by — pushed by a client or
    /// built by a worker — because the database holds metadata only and the two
    /// are stored identically. They differ solely in their [`Tier`], which is
    /// what decides whether the path may ever be vouched for.
    ///
    /// Passing the tier in rather than deciding here keeps the verification,
    /// which needs to hash the bytes, out of every store implementation.
    async fn record_path(
        &self,
        tenant: &TenantId,
        info: PathInfo,
        object: RemoteObject,
        tier: Tier,
    ) -> Result<()>;

    /// Where a path's bytes live in the object store.
    ///
    /// The store never returns bytes: it holds none. The RPC layer and the HTTP
    /// surface fetch from the key, which is what keeps every store
    /// implementation free of an object-store client.
    async fn output_object(&self, tenant: &TenantId, path: &StorePath) -> Option<RemoteObject>;

    /// Whether an object key is already recorded.
    ///
    /// Read before uploading a `Verified` path: if another tenant already
    /// pushed identical content, `nar_key` computed the same key and the bytes
    /// are already in the object store — PLAN.md Phase 9c. Skipping the upload
    /// is the actual saving; `record_path`'s own dedup keeps the database
    /// correct either way, so this is an optimisation, not a safety check.
    async fn object_known(&self, key: &ObjectKey) -> bool;

    /// Any tenant's `Verified` row for this hash part.
    ///
    /// Tenant-agnostic like [`Self::object_known`] — content-addressing means
    /// two tenants' `Verified` rows for the same hash part are provably
    /// identical, so any one of them answers for all. PLAN.md Phase 9c step
    /// two: this is a *read*, and callers still need to write their own,
    /// tenant-signed row before the path becomes valid for them — see
    /// `daemon_rpc::resolve_verified`, the only writer that consults this.
    async fn find_verified_by_hash_part(&self, hash_part: &str)
    -> Option<(PathInfo, RemoteObject)>;

    async fn add_signatures(
        &self,
        tenant: &TenantId,
        path: &StorePath,
        sigs: Vec<String>,
    ) -> Result<()>;

    /// Split `paths` into what would need building versus what is already there.
    async fn query_missing(&self, tenant: &TenantId, targets: &[StorePath]) -> MissingPaths;

    /// How much this path can be vouched for. `None` if it is not here at all.
    ///
    /// Read before signing a path or serving it to anyone but its owner.
    async fn tier(&self, tenant: &TenantId, path: &StorePath) -> Option<Tier>;

    /// The tenant's signing key, creating one on first use.
    ///
    /// `None` only if a key could not be established at all. A caller should
    /// then leave the path unsigned rather than fail the operation: an unsigned
    /// path is inert to clients, which is the safe direction to fall.
    async fn signer(&self, tenant: &TenantId) -> Option<Arc<dyn Signer>>;

    /// The secret currently used to mint capability tokens (`crate::capability`),
    /// and the id that selects it. Generated lazily on first use if none
    /// exists — like [`Self::signer`], correctness never depends on a
    /// separate rotation step having run first; rotation only improves on
    /// this by keying every new token under a fresh id.
    async fn current_capability_secret(&self) -> (u64, [u8; 32]);

    /// The capability secret for a specific `kid`, for verifying a token that
    /// may predate the most recent rotation. `None` once it has aged out of
    /// the retention window and been deleted.
    async fn capability_secret(&self, kid: u64) -> Option<[u8; 32]>;

    async fn set_options(&self, tenant: &TenantId, options: ClientOptions);

    /// Note that a path was read — either its metadata (`queryPathInfo`, a
    /// narinfo) or its bytes (`narFromPath`, a NAR fetch). PLAN.md Phase 12:
    /// this is what retention ages against, so both count, and missing either
    /// would open a window where a client is handed a narinfo for a path that
    /// then gets collected before the bytes are fetched.
    ///
    /// A no-op by default. Only `PostgresStore` has anything to age —
    /// `MemoryStore` has no real garbage problem, and the drain/mark/sweep
    /// passes that consume this are Postgres-only (`server/src/gc.rs`), not
    /// part of this trait.
    async fn record_access(&self, _tenant: &TenantId, _path: &StorePath) {}

    /// Record a job's terminal outcome — PLAN.md Phase 12's job/log retention.
    ///
    /// Called once, when `dispatch()` returns, never on submission: nothing
    /// today needs to observe an in-flight job, and a "pending" row that a
    /// crash or timeout leaves unresolved would just be more state to reason
    /// about for no current benefit. A job lost before an outcome is relayed
    /// is simply not recorded, same as every job before this existed.
    ///
    /// Best-effort, like [`Self::record_access`]: a lost history row does not
    /// affect anything on the serving path, only how much there is to collect
    /// later.
    async fn record_job_outcome(
        &self,
        _tenant: &TenantId,
        _job_id: Uuid,
        _derivation_path: &StorePath,
        _system: &str,
        _outcome: &JobOutcome,
    ) {
    }

    /// Note that a tenant exists, with the identity it presented.
    ///
    /// Called once per connection. A no-op for stores that need no tenant
    /// registry; `PostgresStore` uses it to satisfy the foreign keys on
    /// `store_paths` and `jobs`, and to refresh `verified` so that enabling auth
    /// upgrades existing rows rather than leaving them stale.
    async fn register_tenant(&self, _tenant: &crate::tenant::Tenant) -> Result<()> {
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct MissingPaths {
    pub will_build: Vec<StorePath>,
    pub will_substitute: Vec<StorePath>,
    pub unknown: Vec<StorePath>,
    pub download_size: u64,
    pub nar_size: u64,
}

/// In-memory store, sufficient to exercise the protocol end to end.
///
/// This is not the eventual backing (see DESIGN.md): outputs belong in the
/// object store with metadata in PostgreSQL. It exists so the protocol layer is
/// testable before any of that is wired.
#[derive(Default)]
pub struct MemoryStore {
    inner: Mutex<HashMap<TenantId, Inner>>,
    /// Objects by key, shared across tenants rather than living inside
    /// `Inner` — mirroring `PostgresStore`'s `objects` table, which is what
    /// makes a `Verified` key collision between two tenants a dedup rather
    /// than two independent objects. See [`Store::object_known`].
    objects: Mutex<HashMap<ObjectKey, RemoteObject>>,
    /// The capability-token secret, generated once on first use. Global
    /// rather than per-tenant (unlike `signer`) — a single process has
    /// nothing to rotate against, so there is only ever `kid = 0`.
    capability_secret: Mutex<Option<[u8; 32]>>,
}

/// One tenant's view. Partitioned rather than keyed by `(tenant, path)` so that
/// "everything this tenant can see" is a single lookup — and so that a method
/// which forgets to scope fails to compile rather than quietly reading across
/// tenants.
#[derive(Default)]
struct Inner {
    paths: HashMap<StorePath, PathInfo>,
    /// Where each path's bytes are. Never the bytes themselves — they live in
    /// the object store, whichever route the path arrived by.
    remote: HashMap<StorePath, RemoteObject>,
    /// This tenant's signing key, generated on first use.
    signer: Option<Arc<dyn Signer>>,
    /// How much each path can be vouched for.
    tiers: HashMap<StorePath, Tier>,
    options: ClientOptions,
}

/// Object key for a path's compressed NAR.
///
/// `Built` and `Quarantined` are tenant-scoped, because the key is what a
/// pre-signed URL grants access to and the same store path may hold different
/// bytes for two tenants until pushes can be verified. A quarantined path is
/// additionally segregated under `untrusted/`. The tenant prefix is what the
/// signing check actually enforces, so this is not itself a control — but it
/// is what the HTTP surface routes on when refusing to serve unverifiable
/// content, and it makes the distinction visible in the bucket rather than
/// only in the database.
///
/// `Verified` carries no tenant prefix at all — PLAN.md Phase 9c. A verified
/// path's identity *is* its content (that is what verification checked), so
/// two tenants pushing the same content compute the same key and share the
/// one object rather than paying for it twice. Sharing the bytes is not
/// sharing validity: each tenant's `store_paths` row is unaffected, and
/// `key_is_permitted` still decides who may fetch this key.
pub fn nar_key(tenant: &TenantId, tier: Tier, store_path: &StorePath) -> Option<ObjectKey> {
    let hash = store_path.hash_part()?;
    Some(ObjectKey::new(match tier {
        Tier::Verified => format!("nar/{hash}.nar.zst"),
        Tier::Built => format!("{tenant}/nar/{hash}.nar.zst"),
        Tier::Quarantined => format!("{tenant}/untrusted/nar/{hash}.nar.zst"),
    }))
}

/// Object key for a job's archived build log — mirrors the formula
/// `worker/src/upload.rs::log_key` computes independently on the worker side
/// for the same key. Given a copy here too so `uploads.rs` can check a
/// requested upload key against a job's capability without reaching into the
/// `worker` crate.
pub fn log_key(tenant: &TenantId, drv_path: &StorePath) -> Option<ObjectKey> {
    Some(ObjectKey::new(format!(
        "{tenant}/log/{}",
        drv_path.hash_part()?
    )))
}

#[derive(Clone, Debug)]
pub struct RemoteObject {
    pub key: ObjectKey,
    pub file_size: u64,
    /// Hash of the *compressed* object, which is what a narinfo `FileHash`
    /// states and what a client checks the download against. Distinct from
    /// `PathInfo::nar_hash`, which describes the uncompressed NAR.
    pub file_hash: Output<Sha256>,
}

impl MemoryStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Read one tenant's partition. Absent tenants read as empty rather than
    /// being created, so a lookup never allocates a tenant into existence.
    fn read<T>(&self, tenant: &TenantId, f: impl FnOnce(&Inner) -> T) -> T {
        let inner = self.inner.lock().unwrap();
        match inner.get(tenant) {
            Some(partition) => f(partition),
            None => f(&Inner::default()),
        }
    }

    fn write<T>(&self, tenant: &TenantId, f: impl FnOnce(&mut Inner) -> T) -> T {
        let mut inner = self.inner.lock().unwrap();
        f(inner.entry(tenant.clone()).or_default())
    }
}

#[async_trait::async_trait]
impl Store for MemoryStore {
    async fn is_valid_path(&self, tenant: &TenantId, path: &StorePath) -> bool {
        self.read(tenant, |inner| inner.paths.contains_key(path))
    }

    async fn query_valid_paths(&self, tenant: &TenantId, paths: &[StorePath]) -> Vec<StorePath> {
        self.read(tenant, |inner| {
            paths
                .iter()
                .filter(|p| inner.paths.contains_key(*p))
                .cloned()
                .collect()
        })
    }

    async fn query_all_valid_paths(&self, tenant: &TenantId) -> Vec<StorePath> {
        self.read(tenant, |inner| inner.paths.keys().cloned().collect())
    }

    async fn query_path_info(&self, tenant: &TenantId, path: &StorePath) -> Option<PathInfo> {
        self.read(tenant, |inner| inner.paths.get(path).cloned())
    }

    async fn query_path_from_hash_part(
        &self,
        tenant: &TenantId,
        hash_part: &str,
    ) -> Option<StorePath> {
        self.read(tenant, |inner| {
            inner
                .paths
                .keys()
                .find(|p| p.hash_part() == Some(hash_part))
                .cloned()
        })
    }

    async fn query_referrers(&self, tenant: &TenantId, path: &StorePath) -> Vec<StorePath> {
        self.read(tenant, |inner| {
            inner
                .paths
                .values()
                .filter(|info| info.references.iter().any(|r| r == path))
                .map(|info| info.path.clone())
                .collect()
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
        self.objects
            .lock()
            .unwrap()
            .entry(object.key.clone())
            .or_insert_with(|| object.clone());
        self.write(tenant, |inner| {
            inner.remote.insert(info.path.clone(), object);
            inner.tiers.insert(info.path.clone(), tier);
            inner.paths.insert(info.path.clone(), info);
        });
        Ok(())
    }

    async fn output_object(&self, tenant: &TenantId, path: &StorePath) -> Option<RemoteObject> {
        self.read(tenant, |inner| inner.remote.get(path).cloned())
    }

    async fn object_known(&self, key: &ObjectKey) -> bool {
        self.objects.lock().unwrap().contains_key(key)
    }

    async fn find_verified_by_hash_part(
        &self,
        hash_part: &str,
    ) -> Option<(PathInfo, RemoteObject)> {
        let inner = self.inner.lock().unwrap();
        for partition in inner.values() {
            let Some((path, info)) = partition
                .paths
                .iter()
                .find(|(p, _)| p.hash_part() == Some(hash_part))
            else {
                continue;
            };
            if partition.tiers.get(path) != Some(&Tier::Verified) {
                continue;
            }
            let Some(object) = partition.remote.get(path).cloned() else {
                continue;
            };
            return Some((info.clone(), object));
        }
        None
    }

    async fn add_signatures(
        &self,
        tenant: &TenantId,
        path: &StorePath,
        sigs: Vec<String>,
    ) -> Result<()> {
        self.write(tenant, |inner| {
            let info = inner
                .paths
                .get_mut(path)
                .ok_or_else(|| StoreError::NotFound(path.to_string()))?;
            for sig in sigs {
                if !info.sigs.contains(&sig) {
                    info.sigs.push(sig);
                }
            }
            Ok(())
        })
    }

    async fn query_missing(&self, tenant: &TenantId, targets: &[StorePath]) -> MissingPaths {
        self.read(tenant, |inner| {
            let mut missing = MissingPaths::default();
            for target in targets {
                if !inner.paths.contains_key(target) {
                    // The frontend builds rather than substitutes.
                    missing.will_build.push(target.clone());
                }
            }
            missing
        })
    }

    async fn tier(&self, tenant: &TenantId, path: &StorePath) -> Option<Tier> {
        self.read(tenant, |inner| inner.tiers.get(path).copied())
    }

    async fn signer(&self, tenant: &TenantId) -> Option<Arc<dyn Signer>> {
        self.write(tenant, |inner| {
            Some(
                inner
                    .signer
                    .get_or_insert_with(|| Arc::new(LocalSigner::generate(key_name_for(tenant))))
                    .clone(),
            )
        })
    }

    async fn current_capability_secret(&self) -> (u64, [u8; 32]) {
        let mut guard = self.capability_secret.lock().unwrap();
        let secret = *guard.get_or_insert_with(rand::random);
        (0, secret)
    }

    async fn capability_secret(&self, kid: u64) -> Option<[u8; 32]> {
        if kid != 0 {
            return None;
        }
        *self.capability_secret.lock().unwrap()
    }

    async fn set_options(&self, tenant: &TenantId, options: ClientOptions) {
        tracing::debug!(%tenant, ?options, "client options");
        self.write(tenant, |inner| inner.options = options);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tenant::Tenant;

    fn tenant(name: &str) -> TenantId {
        Tenant::from_ssh(name, None, false).id
    }

    fn info(path: &str) -> PathInfo {
        PathInfo {
            path: StorePath::new(path),
            deriver: None,
            nar_hash: Hash {
                hash_type: HashType::Sha256,
                bytes: vec![0; 32],
            },
            nar_size: 3,
            references: Vec::new(),
            registration_time: 0,
            ultimate: false,
            sigs: Vec::new(),
        }
    }

    /// Where a path's bytes are. The store records this and never the bytes.
    fn object(key: &str) -> RemoteObject {
        RemoteObject {
            key: ObjectKey::new(key),
            file_size: 3,
            file_hash: Output::<Sha256>::from([1u8; 32]),
        }
    }

    const P: &str = "00000000000000000000000000000000-thing";

    fn p() -> StorePath {
        StorePath::new(P)
    }

    #[tokio::test]
    async fn round_trips_a_path() {
        let store = MemoryStore::new();
        let t = tenant("alice");
        assert!(!store.is_valid_path(&t, &p()).await);

        store
            .record_path(&t, info(P), object("alice/nar/x.nar.zst"), Tier::Verified)
            .await
            .unwrap();

        assert!(store.is_valid_path(&t, &p()).await);
        assert_eq!(store.query_path_info(&t, &p()).await.unwrap().nar_size, 3);
        assert_eq!(store.query_valid_paths(&t, &[p()]).await, vec![p()]);
        assert_eq!(
            store.output_object(&t, &p()).await.unwrap().key.as_str(),
            "alice/nar/x.nar.zst"
        );
        assert_eq!(store.tier(&t, &p()).await, Some(Tier::Verified));
    }

    #[tokio::test]
    async fn resolves_by_hash_part() {
        let store = MemoryStore::new();
        let t = tenant("alice");
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
    async fn tracks_referrers() {
        let store = MemoryStore::new();
        let t = tenant("alice");
        let dep = "11111111111111111111111111111111-dep";
        store
            .record_path(&t, info(dep), object("d"), Tier::Verified)
            .await
            .unwrap();
        let mut referrer = info(P);
        referrer.references = vec![StorePath::new(dep)];
        store
            .record_path(&t, referrer, object("r"), Tier::Verified)
            .await
            .unwrap();

        assert_eq!(
            store.query_referrers(&t, &StorePath::new(dep)).await,
            vec![p()]
        );
        assert!(store.query_referrers(&t, &p()).await.is_empty());
    }

    #[tokio::test]
    async fn unknown_targets_are_reported_as_needing_a_build() {
        let store = MemoryStore::new();
        let missing = store.query_missing(&tenant("alice"), &[p()]).await;
        assert_eq!(missing.will_build, vec![p()]);
        assert!(missing.will_substitute.is_empty());
    }

    #[tokio::test]
    async fn an_unknown_path_has_no_object() {
        let store = MemoryStore::new();
        assert!(store.output_object(&tenant("alice"), &p()).await.is_none());
    }

    #[tokio::test]
    async fn find_verified_by_hash_part_scans_across_tenants() {
        // PLAN.md Phase 9c step two: the tenant-agnostic read, mirroring
        // `object_known`. `daemon_rpc::resolve_verified` is what actually
        // materializes a caller's own row from this; the trait method itself
        // is a pure lookup.
        let store = MemoryStore::new();
        let alice = tenant("alice");
        store
            .record_path(&alice, info(P), object("nar/x"), Tier::Verified)
            .await
            .unwrap();

        let (found_info, found_object) = store
            .find_verified_by_hash_part(&"0".repeat(32))
            .await
            .expect("alice's verified row");
        assert_eq!(found_info.path, p());
        assert_eq!(found_object.key.as_str(), "nar/x");

        assert!(store.find_verified_by_hash_part("deadbeef").await.is_none());
    }

    #[tokio::test]
    async fn find_verified_by_hash_part_ignores_built_and_quarantined() {
        let store = MemoryStore::new();
        let alice = tenant("alice");
        store
            .record_path(&alice, info(P), object("alice/nar/x"), Tier::Built)
            .await
            .unwrap();

        assert!(
            store
                .find_verified_by_hash_part(&"0".repeat(32))
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn one_tenant_cannot_see_anothers_paths() {
        let store = MemoryStore::new();
        let (alice, bob) = (tenant("alice"), tenant("bob"));
        store
            .record_path(&alice, info(P), object("alice/nar/x"), Tier::Verified)
            .await
            .unwrap();

        assert!(!store.is_valid_path(&bob, &p()).await);
        assert!(store.query_path_info(&bob, &p()).await.is_none());
        assert!(store.query_valid_paths(&bob, &[p()]).await.is_empty());
        assert!(store.query_all_valid_paths(&bob).await.is_empty());
        assert!(
            store
                .query_path_from_hash_part(&bob, &"0".repeat(32))
                .await
                .is_none()
        );
        assert!(store.output_object(&bob, &p()).await.is_none());
    }

    #[tokio::test]
    async fn one_tenant_cannot_overwrite_anothers_path() {
        // The same store path pointing at different bytes for two tenants is
        // exactly the cache-poisoning case: whoever writes second must not win.
        let store = MemoryStore::new();
        let (alice, bob) = (tenant("alice"), tenant("bob"));

        store
            .record_path(&alice, info(P), object("alice/nar/x"), Tier::Verified)
            .await
            .unwrap();
        store
            .record_path(&bob, info(P), object("bob/nar/x"), Tier::Quarantined)
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
            "bob/nar/x"
        );
        // And the tiers do not leak either.
        assert_eq!(store.tier(&alice, &p()).await, Some(Tier::Verified));
        assert_eq!(store.tier(&bob, &p()).await, Some(Tier::Quarantined));
    }

    #[tokio::test]
    async fn signatures_do_not_cross_tenants() {
        let store = MemoryStore::new();
        let (alice, bob) = (tenant("alice"), tenant("bob"));
        store
            .record_path(&alice, info(P), object("k"), Tier::Verified)
            .await
            .unwrap();

        // Bob cannot vouch for a path he cannot see.
        assert!(matches!(
            store
                .add_signatures(&bob, &p(), vec!["forged".to_string()])
                .await,
            Err(StoreError::NotFound(_))
        ));
        assert!(
            store
                .query_path_info(&alice, &p())
                .await
                .unwrap()
                .sigs
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_lookup_does_not_create_a_tenant() {
        // Otherwise an unauthenticated probe could grow the store's tenant map
        // without bound.
        let store = MemoryStore::new();
        assert!(!store.is_valid_path(&tenant("nobody"), &p()).await);
        assert!(store.inner.lock().unwrap().is_empty());
    }

    #[test]
    fn nar_keys_are_scoped_by_tenant_and_tier() {
        let alice = tenant("alice");
        let built = nar_key(&alice, Tier::Built, &p()).expect("a key");
        let quarantined = nar_key(&alice, Tier::Quarantined, &p()).expect("a key");

        assert!(built.as_str().starts_with(&format!("{alice}/nar/")));
        assert!(
            quarantined.as_str().contains("/untrusted/nar/"),
            "unverifiable content should be visibly separated: {quarantined}"
        );
        // Still inside the tenant's prefix, which is what the signing check
        // enforces — `untrusted/` is a routing marker, not the control.
        assert!(quarantined.as_str().starts_with(&format!("{alice}/")));

        // Two tenants running their own builds hold independent bytes at one
        // path, so their `Built` keys must differ.
        assert_ne!(built, nar_key(&tenant("bob"), Tier::Built, &p()).unwrap());
        assert_eq!(
            nar_key(&alice, Tier::Built, &StorePath::new("/etc/passwd")),
            None
        );
    }

    #[test]
    fn verified_keys_carry_no_tenant_and_are_shared() {
        // PLAN.md Phase 9c: a verified path's identity is its content, so two
        // tenants pushing the same content must compute the same key — that
        // convergence is the whole saving.
        let (alice, bob) = (tenant("alice"), tenant("bob"));
        let key = nar_key(&alice, Tier::Verified, &p()).expect("a key");

        assert_eq!(key, nar_key(&bob, Tier::Verified, &p()).unwrap());
        assert!(!key.as_str().contains(alice.as_str()));
        assert!(key.as_str().starts_with("nar/"));
    }
}
