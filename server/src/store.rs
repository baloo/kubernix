//! The store the daemon protocol is served from.
//!
//! The RPC layer in [`crate::daemon_rpc`] is a pure adapter over this trait, so
//! the protocol code does not change when the backing moves from memory to
//! PostgreSQL + S3 + NATS.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use kubernix_signing::{LocalSigner, Signer, key_name_for};

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
/// of. Store paths are the full printed form (`/nix/store/<hash>-<name>`) —
/// that is what `StorePath.raw` carries on the wire (`types-rpc.hh:25-38`).
#[derive(Clone, Debug)]
pub struct PathInfo {
    pub path: String,
    pub deriver: Option<String>,
    pub nar_hash: Hash,
    pub nar_size: u64,
    pub references: Vec<String>,
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
    async fn is_valid_path(&self, tenant: &TenantId, path: &str) -> bool;

    async fn query_valid_paths(&self, tenant: &TenantId, paths: &[String]) -> Vec<String>;

    async fn query_all_valid_paths(&self, tenant: &TenantId) -> Vec<String>;

    async fn query_path_info(&self, tenant: &TenantId, path: &str) -> Option<PathInfo>;

    /// Resolve the hash part of a store path (the 32 chars after the store dir).
    async fn query_path_from_hash_part(
        &self,
        tenant: &TenantId,
        hash_part: &str,
    ) -> Option<String>;

    async fn query_referrers(&self, tenant: &TenantId, path: &str) -> Vec<String>;

    /// Paths that could be substituted. The frontend substitutes nothing on the
    /// client's behalf, so this is empty.
    async fn query_substitutable_paths(
        &self,
        _tenant: &TenantId,
        _paths: &[String],
    ) -> Vec<String> {
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
    async fn output_object(&self, tenant: &TenantId, path: &str) -> Option<RemoteObject>;

    async fn add_signatures(&self, tenant: &TenantId, path: &str, sigs: Vec<String>) -> Result<()>;

    /// Split `paths` into what would need building versus what is already there.
    async fn query_missing(&self, tenant: &TenantId, targets: &[String]) -> MissingPaths;

    /// How much this path can be vouched for. `None` if it is not here at all.
    ///
    /// Read before signing a path or serving it to anyone but its owner.
    async fn tier(&self, tenant: &TenantId, path: &str) -> Option<Tier>;

    /// The tenant's signing key, creating one on first use.
    ///
    /// `None` only if a key could not be established at all. A caller should
    /// then leave the path unsigned rather than fail the operation: an unsigned
    /// path is inert to clients, which is the safe direction to fall.
    async fn signer(&self, tenant: &TenantId) -> Option<Arc<dyn Signer>>;

    async fn set_options(&self, tenant: &TenantId, options: ClientOptions);

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
    pub will_build: Vec<String>,
    pub will_substitute: Vec<String>,
    pub unknown: Vec<String>,
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
}

/// One tenant's view. Partitioned rather than keyed by `(tenant, path)` so that
/// "everything this tenant can see" is a single lookup — and so that a method
/// which forgets to scope fails to compile rather than quietly reading across
/// tenants.
#[derive(Default)]
struct Inner {
    paths: HashMap<String, PathInfo>,
    /// Where each path's bytes are. Never the bytes themselves — they live in
    /// the object store, whichever route the path arrived by.
    remote: HashMap<String, RemoteObject>,
    /// This tenant's signing key, generated on first use.
    signer: Option<Arc<dyn Signer>>,
    /// How much each path can be vouched for.
    tiers: HashMap<String, Tier>,
    options: ClientOptions,
}

/// Object key for a path's compressed NAR.
///
/// Tenant-scoped, because the key is what a pre-signed URL grants access to and
/// the same store path may hold different bytes for two tenants until pushes can
/// be verified.
///
/// A quarantined path is additionally segregated under `untrusted/`. The tenant
/// prefix is what the signing check actually enforces, so this is not itself a
/// control — but it is what the HTTP surface routes on when refusing to serve
/// unverifiable content, and it makes the distinction visible in the bucket
/// rather than only in the database.
pub fn nar_key(tenant: &TenantId, tier: Tier, store_path: &str) -> Option<String> {
    let base = store_path.rsplit('/').next()?;
    let hash = base.split('-').next()?;
    let scope = if tier.is_vouchable() {
        ""
    } else {
        "untrusted/"
    };
    (hash.len() == 32).then(|| format!("{tenant}/{scope}nar/{hash}.nar.zst"))
}

#[derive(Clone, Debug)]
pub struct RemoteObject {
    pub key: String,
    pub file_size: u64,
    /// Hash of the *compressed* object, which is what a narinfo `FileHash`
    /// states and what a client checks the download against. Distinct from
    /// `PathInfo::nar_hash`, which describes the uncompressed NAR.
    pub file_hash: Vec<u8>,
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

/// `/nix/store/<32-char hash>-<name>` → `<32-char hash>`.
fn hash_part_of(path: &str) -> Option<&str> {
    let base = path.rsplit('/').next()?;
    let hash = base.split('-').next()?;
    (hash.len() == 32).then_some(hash)
}

#[async_trait::async_trait]
impl Store for MemoryStore {
    async fn is_valid_path(&self, tenant: &TenantId, path: &str) -> bool {
        self.read(tenant, |inner| inner.paths.contains_key(path))
    }

    async fn query_valid_paths(&self, tenant: &TenantId, paths: &[String]) -> Vec<String> {
        self.read(tenant, |inner| {
            paths
                .iter()
                .filter(|p| inner.paths.contains_key(*p))
                .cloned()
                .collect()
        })
    }

    async fn query_all_valid_paths(&self, tenant: &TenantId) -> Vec<String> {
        self.read(tenant, |inner| inner.paths.keys().cloned().collect())
    }

    async fn query_path_info(&self, tenant: &TenantId, path: &str) -> Option<PathInfo> {
        self.read(tenant, |inner| inner.paths.get(path).cloned())
    }

    async fn query_path_from_hash_part(&self, tenant: &TenantId, hash_part: &str) -> Option<String> {
        self.read(tenant, |inner| {
            inner
                .paths
                .keys()
                .find(|p| hash_part_of(p) == Some(hash_part))
                .cloned()
        })
    }

    async fn query_referrers(&self, tenant: &TenantId, path: &str) -> Vec<String> {
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
        self.write(tenant, |inner| {
            inner.remote.insert(info.path.clone(), object);
            inner.tiers.insert(info.path.clone(), tier);
            inner.paths.insert(info.path.clone(), info);
        });
        Ok(())
    }

    async fn output_object(&self, tenant: &TenantId, path: &str) -> Option<RemoteObject> {
        self.read(tenant, |inner| inner.remote.get(path).cloned())
    }

    async fn add_signatures(&self, tenant: &TenantId, path: &str, sigs: Vec<String>) -> Result<()> {
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

    async fn query_missing(&self, tenant: &TenantId, targets: &[String]) -> MissingPaths {
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

    async fn tier(&self, tenant: &TenantId, path: &str) -> Option<Tier> {
        self.read(tenant, |inner| inner.tiers.get(path).copied())
    }

    async fn signer(&self, tenant: &TenantId) -> Option<Arc<dyn Signer>> {
        self.write(tenant, |inner| {
            Some(
                inner
                    .signer
                    .get_or_insert_with(|| {
                        Arc::new(LocalSigner::generate(key_name_for(tenant.as_str())))
                    })
                    .clone(),
            )
        })
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
            path: path.to_string(),
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
            key: key.to_string(),
            file_size: 3,
            file_hash: vec![1; 32],
        }
    }

    const P: &str = "/nix/store/00000000000000000000000000000000-thing";

    #[tokio::test]
    async fn round_trips_a_path() {
        let store = MemoryStore::new();
        let t = tenant("alice");
        assert!(!store.is_valid_path(&t, P).await);

        store
            .record_path(&t, info(P), object("alice/nar/x.nar.zst"), Tier::Verified)
            .await
            .unwrap();

        assert!(store.is_valid_path(&t, P).await);
        assert_eq!(store.query_path_info(&t, P).await.unwrap().nar_size, 3);
        assert_eq!(store.query_valid_paths(&t, &[P.to_string()]).await, vec![P]);
        assert_eq!(
            store.output_object(&t, P).await.unwrap().key,
            "alice/nar/x.nar.zst"
        );
        assert_eq!(store.tier(&t, P).await, Some(Tier::Verified));
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
                .await
                .as_deref(),
            Some(P)
        );
        assert_eq!(store.query_path_from_hash_part(&t, "deadbeef").await, None);
    }

    #[tokio::test]
    async fn tracks_referrers() {
        let store = MemoryStore::new();
        let t = tenant("alice");
        let dep = "/nix/store/11111111111111111111111111111111-dep";
        store
            .record_path(&t, info(dep), object("d"), Tier::Verified)
            .await
            .unwrap();
        let mut referrer = info(P);
        referrer.references = vec![dep.to_string()];
        store
            .record_path(&t, referrer, object("r"), Tier::Verified)
            .await
            .unwrap();

        assert_eq!(store.query_referrers(&t, dep).await, vec![P]);
        assert!(store.query_referrers(&t, P).await.is_empty());
    }

    #[tokio::test]
    async fn unknown_targets_are_reported_as_needing_a_build() {
        let store = MemoryStore::new();
        let missing = store
            .query_missing(&tenant("alice"), &[P.to_string()])
            .await;
        assert_eq!(missing.will_build, vec![P]);
        assert!(missing.will_substitute.is_empty());
    }

    #[tokio::test]
    async fn an_unknown_path_has_no_object() {
        let store = MemoryStore::new();
        assert!(store.output_object(&tenant("alice"), P).await.is_none());
    }

    #[tokio::test]
    async fn one_tenant_cannot_see_anothers_paths() {
        let store = MemoryStore::new();
        let (alice, bob) = (tenant("alice"), tenant("bob"));
        store
            .record_path(&alice, info(P), object("alice/nar/x"), Tier::Verified)
            .await
            .unwrap();

        assert!(!store.is_valid_path(&bob, P).await);
        assert!(store.query_path_info(&bob, P).await.is_none());
        assert!(
            store
                .query_valid_paths(&bob, &[P.to_string()])
                .await
                .is_empty()
        );
        assert!(store.query_all_valid_paths(&bob).await.is_empty());
        assert!(
            store
                .query_path_from_hash_part(&bob, &"0".repeat(32))
                .await
                .is_none()
        );
        assert!(store.output_object(&bob, P).await.is_none());
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
            store.output_object(&alice, P).await.unwrap().key,
            "alice/nar/x"
        );
        assert_eq!(store.output_object(&bob, P).await.unwrap().key, "bob/nar/x");
        // And the tiers do not leak either.
        assert_eq!(store.tier(&alice, P).await, Some(Tier::Verified));
        assert_eq!(store.tier(&bob, P).await, Some(Tier::Quarantined));
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
                .add_signatures(&bob, P, vec!["forged".to_string()])
                .await,
            Err(StoreError::NotFound(_))
        ));
        assert!(
            store
                .query_path_info(&alice, P)
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
        assert!(!store.is_valid_path(&tenant("nobody"), P).await);
        assert!(store.inner.lock().unwrap().is_empty());
    }

    #[test]
    fn nar_keys_are_scoped_by_tenant_and_tier() {
        let alice = tenant("alice");
        let verified = nar_key(&alice, Tier::Verified, P).expect("a key");
        let quarantined = nar_key(&alice, Tier::Quarantined, P).expect("a key");

        assert!(verified.starts_with(&format!("{alice}/nar/")));
        assert!(
            quarantined.contains("/untrusted/nar/"),
            "unverifiable content should be visibly separated: {quarantined}"
        );
        // Still inside the tenant's prefix, which is what the signing check
        // enforces — `untrusted/` is a routing marker, not the control.
        assert!(quarantined.starts_with(&format!("{alice}/")));

        // Two tenants may hold different bytes at one path, so keys must differ.
        assert_ne!(verified, nar_key(&tenant("bob"), Tier::Verified, P).unwrap());
        assert_eq!(nar_key(&alice, Tier::Verified, "/etc/passwd"), None);
    }
}
