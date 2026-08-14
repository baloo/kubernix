//! A Nix store path: the bare `<32-char hash>-<name>` printed by a store
//! object, without the store directory.
//!
//! Deliberately just a labelled `String`, not a `std::path::PathBuf`: the
//! content-addressing hash is computed over the *exact bytes* of the printed
//! path, the wire type is capnp `Text` (UTF-8), and every place this needs to
//! act like a path (e.g. `Command::arg`) already accepts `&str` via
//! `AsRef<OsStr>`. `Path`'s normalization semantics would be a hazard here,
//! not a convenience.
//!
//! The store directory (`/nix/store` by default, but configurable) is
//! deliberately not part of this type — it is a deployment-wide setting
//! threaded separately wherever it's needed. [`StorePath::from_full`] and
//! [`StorePath::to_full`] are the only places that combine the two, and exist
//! solely for the boundaries that must speak the full printed form to
//! something outside kubernix's control (the Lix daemon protocol, a `.drv`'s
//! wire bytes, narinfo, signature fingerprints, and real `nix`/`nix-store`
//! invocations).

/// A Nix store path, without its store directory.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StorePath(String);

/// [`StorePath::from_full_or_err`]'s failure: `full` was not actually rooted
/// at `store_dir`.
#[derive(Debug, thiserror::Error)]
#[error("{full} is not rooted at {store_dir}")]
pub struct NotRooted {
    store_dir: String,
    full: String,
}

impl StorePath {
    pub fn new(path: impl Into<String>) -> Self {
        StorePath(path.into())
    }

    /// Parse a full printed path (`<store_dir>/<hash>-<name>`), stripping the
    /// store directory.
    ///
    /// `None` if `full` is not actually rooted at `store_dir` — deliberately
    /// not tolerant of a mismatch: silently keeping the wrong prefix as part
    /// of the "bare" name would corrupt every downstream use of it (content
    /// verification, signing, hash-part lookups) rather than fail loudly. A
    /// caller whose peer's store directory does not match ours needs to know
    /// that, not have it hidden.
    pub fn from_full(store_dir: &str, full: &str) -> Option<Self> {
        let bare = full.strip_prefix(store_dir)?.strip_prefix('/')?;
        Some(StorePath(bare.to_string()))
    }

    /// Reconstruct the full printed path: `<store_dir>/<hash>-<name>`.
    pub fn to_full(&self, store_dir: &str) -> String {
        format!("{store_dir}/{}", self.0)
    }

    /// [`Self::from_full`], but refusing rather than merely failing to
    /// match — this is the same "reject a peer whose store directory does
    /// not match ours" check that shows up independently wherever a full
    /// path arrives from outside kubernix's control (a derivation's wire
    /// bytes, `nix-store --query`'s output, the daemon protocol). Centralised
    /// here so that check, and its message, is written once.
    pub fn from_full_or_err(store_dir: &str, full: &str) -> Result<Self, NotRooted> {
        Self::from_full(store_dir, full).ok_or_else(|| NotRooted {
            store_dir: store_dir.to_string(),
            full: full.to_string(),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    /// The `<name>` part of `<hash>-<name>`.
    pub fn name(&self) -> Option<&str> {
        let base = self.0.rsplit('/').next()?;
        let (hash, name) = base.split_once('-')?;
        (hash.len() == 32 && !name.is_empty()).then_some(name)
    }

    /// The 32-character hash part: `<hash>-<name>` → `<hash>`.
    pub fn hash_part(&self) -> Option<&str> {
        let base = self.0.rsplit('/').next()?;
        let hash = base.split('-').next()?;
        (hash.len() == 32).then_some(hash)
    }
}

impl std::fmt::Display for StorePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for StorePath {
    fn from(path: String) -> Self {
        StorePath(path)
    }
}

impl AsRef<str> for StorePath {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: &str = "21d91afy6vgw4l00yzy92kp92b1w3cdm-kxs-testfile.txt";

    #[test]
    fn splits_paths() {
        let p = StorePath::new(P);
        assert_eq!(p.name(), Some("kxs-testfile.txt"));
        assert_eq!(p.hash_part(), Some("21d91afy6vgw4l00yzy92kp92b1w3cdm"));
    }

    #[test]
    fn rejects_paths_without_a_hash_part() {
        assert_eq!(StorePath::new("not-a-hash").hash_part(), None);
        assert_eq!(StorePath::new("notapath").hash_part(), None);
        assert_eq!(StorePath::new("not-a-hash").name(), None);
    }

    #[test]
    fn from_full_strips_the_store_dir() {
        assert_eq!(
            StorePath::from_full("/nix/store", &format!("/nix/store/{P}")),
            Some(StorePath::new(P))
        );
    }

    #[test]
    fn from_full_refuses_a_path_rooted_elsewhere() {
        // A mismatched store directory must fail loudly, not silently adopt
        // the wrong prefix as part of the "bare" name.
        assert_eq!(StorePath::from_full("/nix/store", P), None);
        assert_eq!(
            StorePath::from_full("/nix/store", &format!("/mnt/other-store/{P}")),
            None
        );
        // A prefix match that isn't actually a directory boundary must not
        // slip through either.
        assert_eq!(
            StorePath::from_full("/nix/store", &format!("/nix/store-other/{P}")),
            None
        );
    }

    #[test]
    fn to_full_reconstructs_the_printed_path() {
        assert_eq!(
            StorePath::new(P).to_full("/nix/store"),
            format!("/nix/store/{P}")
        );
    }
}
