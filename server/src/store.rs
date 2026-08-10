//! The store the daemon protocol is served from.
//!
//! The RPC layer in [`crate::daemon_rpc`] is a pure adapter over this trait, so
//! the protocol code does not change when the backing moves from memory to
//! PostgreSQL + S3 + NATS.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

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

#[derive(Debug)]
pub enum StoreError {
    NotFound(String),
    Unsupported(&'static str),
    Other(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::NotFound(p) => write!(f, "path not in store: {p}"),
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
/// Deliberately synchronous: capnp-rpc drives it from a `LocalSet` and the
/// in-memory implementation never blocks. When the backing becomes Postgres/S3
/// this becomes async and the RPC layer gains `.await`s — the shape does not
/// otherwise change.
pub trait Store: Send + Sync {
    fn is_valid_path(&self, path: &str) -> bool;

    fn query_valid_paths(&self, paths: &[String]) -> Vec<String>;

    fn query_all_valid_paths(&self) -> Vec<String>;

    fn query_path_info(&self, path: &str) -> Option<PathInfo>;

    /// Resolve the hash part of a store path (the 32 chars after the store dir).
    fn query_path_from_hash_part(&self, hash_part: &str) -> Option<String>;

    fn query_referrers(&self, path: &str) -> Vec<String>;

    /// Paths that could be substituted. The frontend substitutes nothing on the
    /// client's behalf, so this is empty.
    fn query_substitutable_paths(&self, _paths: &[String]) -> Vec<String> {
        Vec::new()
    }

    /// Add a NAR whose `ValidPathInfo` the client already computed.
    fn add_to_store_nar(&self, info: PathInfo, nar: Vec<u8>) -> Result<()>;

    /// Register an output a worker built and uploaded to the object store.
    ///
    /// Unlike [`Store::add_to_store_nar`] the bytes never pass through the
    /// frontend — the worker uploaded them directly with a pre-signed URL — so
    /// only the metadata and the object key are recorded here.
    fn register_output(&self, info: PathInfo, key: String, file_size: u64) -> Result<()>;

    /// The NAR bytes for a path, as `narFromPath` streams them back.
    fn nar_from_path(&self, path: &str) -> Result<Vec<u8>>;

    fn add_signatures(&self, path: &str, sigs: Vec<String>) -> Result<()>;

    /// Split `paths` into what would need building versus what is already there.
    fn query_missing(&self, targets: &[String]) -> MissingPaths;

    fn set_options(&self, options: ClientOptions);
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
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    paths: HashMap<String, PathInfo>,
    nars: HashMap<String, Vec<u8>>,
    /// Outputs living in the object store rather than here: store path → key.
    remote: HashMap<String, RemoteObject>,
    options: ClientOptions,
}

#[derive(Clone, Debug)]
pub struct RemoteObject {
    pub key: String,
    pub file_size: u64,
}

impl MemoryStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

/// `/nix/store/<32-char hash>-<name>` → `<32-char hash>`.
fn hash_part_of(path: &str) -> Option<&str> {
    let base = path.rsplit('/').next()?;
    let hash = base.split('-').next()?;
    (hash.len() == 32).then_some(hash)
}

impl Store for MemoryStore {
    fn is_valid_path(&self, path: &str) -> bool {
        self.inner.lock().unwrap().paths.contains_key(path)
    }

    fn query_valid_paths(&self, paths: &[String]) -> Vec<String> {
        let inner = self.inner.lock().unwrap();
        paths
            .iter()
            .filter(|p| inner.paths.contains_key(*p))
            .cloned()
            .collect()
    }

    fn query_all_valid_paths(&self) -> Vec<String> {
        self.inner.lock().unwrap().paths.keys().cloned().collect()
    }

    fn query_path_info(&self, path: &str) -> Option<PathInfo> {
        self.inner.lock().unwrap().paths.get(path).cloned()
    }

    fn query_path_from_hash_part(&self, hash_part: &str) -> Option<String> {
        self.inner
            .lock()
            .unwrap()
            .paths
            .keys()
            .find(|p| hash_part_of(p) == Some(hash_part))
            .cloned()
    }

    fn query_referrers(&self, path: &str) -> Vec<String> {
        let inner = self.inner.lock().unwrap();
        inner
            .paths
            .values()
            .filter(|info| info.references.iter().any(|r| r == path))
            .map(|info| info.path.clone())
            .collect()
    }

    fn add_to_store_nar(&self, info: PathInfo, nar: Vec<u8>) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        tracing::info!(path = %info.path, nar_size = nar.len(), "added path");
        inner.nars.insert(info.path.clone(), nar);
        inner.paths.insert(info.path.clone(), info);
        Ok(())
    }

    fn register_output(&self, info: PathInfo, key: String, file_size: u64) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
        tracing::info!(path = %info.path, %key, file_size, "recorded built output");
        inner
            .remote
            .insert(info.path.clone(), RemoteObject { key, file_size });
        inner.paths.insert(info.path.clone(), info);
        Ok(())
    }

    fn nar_from_path(&self, path: &str) -> Result<Vec<u8>> {
        let inner = self.inner.lock().unwrap();
        if let Some(nar) = inner.nars.get(path) {
            return Ok(nar.clone());
        }
        // Known, but the bytes are in the object store. Serving it over the
        // daemon connection means fetching and decompressing here; the HTTP
        // cache surface serves it directly instead. Not yet implemented.
        if let Some(remote) = inner.remote.get(path) {
            tracing::warn!(%path, key = %remote.key, "nar is in the object store, not local");
            return Err(StoreError::Unsupported(
                "narFromPath for object-store-backed outputs",
            ));
        }
        Err(StoreError::NotFound(path.to_string()))
    }

    fn add_signatures(&self, path: &str, sigs: Vec<String>) -> Result<()> {
        let mut inner = self.inner.lock().unwrap();
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
    }

    fn query_missing(&self, targets: &[String]) -> MissingPaths {
        let inner = self.inner.lock().unwrap();
        let mut missing = MissingPaths::default();
        for target in targets {
            if !inner.paths.contains_key(target) {
                // The frontend builds rather than substitutes.
                missing.will_build.push(target.clone());
            }
        }
        missing
    }

    fn set_options(&self, options: ClientOptions) {
        tracing::debug!(?options, "client options");
        self.inner.lock().unwrap().options = options;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    const P: &str = "/nix/store/00000000000000000000000000000000-thing";

    #[test]
    fn round_trips_a_nar() {
        let store = MemoryStore::new();
        assert!(!store.is_valid_path(P));

        store.add_to_store_nar(info(P), b"nar".to_vec()).unwrap();

        assert!(store.is_valid_path(P));
        assert_eq!(store.nar_from_path(P).unwrap(), b"nar");
        assert_eq!(store.query_path_info(P).unwrap().nar_size, 3);
        assert_eq!(store.query_valid_paths(&[P.to_string()]), vec![P]);
    }

    #[test]
    fn resolves_by_hash_part() {
        let store = MemoryStore::new();
        store.add_to_store_nar(info(P), b"nar".to_vec()).unwrap();
        assert_eq!(
            store
                .query_path_from_hash_part("00000000000000000000000000000000")
                .as_deref(),
            Some(P)
        );
        assert_eq!(store.query_path_from_hash_part("deadbeef"), None);
    }

    #[test]
    fn tracks_referrers() {
        let store = MemoryStore::new();
        let dep = "/nix/store/11111111111111111111111111111111-dep";
        store.add_to_store_nar(info(dep), b"d".to_vec()).unwrap();
        let mut referrer = info(P);
        referrer.references = vec![dep.to_string()];
        store.add_to_store_nar(referrer, b"r".to_vec()).unwrap();

        assert_eq!(store.query_referrers(dep), vec![P]);
        assert!(store.query_referrers(P).is_empty());
    }

    #[test]
    fn unknown_targets_are_reported_as_needing_a_build() {
        let store = MemoryStore::new();
        let missing = store.query_missing(&[P.to_string()]);
        assert_eq!(missing.will_build, vec![P]);
        assert!(missing.will_substitute.is_empty());
    }

    #[test]
    fn missing_nar_is_an_error_not_a_panic() {
        let store = MemoryStore::new();
        assert!(matches!(
            store.nar_from_path(P),
            Err(StoreError::NotFound(_))
        ));
    }
}
