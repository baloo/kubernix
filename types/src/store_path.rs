//! A Nix store path: `/nix/store/<32-char hash>-<name>`.
//!
//! Deliberately just a labelled `String`, not a `std::path::PathBuf`: the
//! content-addressing hash is computed over the *exact bytes* of the printed
//! path, the wire type is capnp `Text` (UTF-8), and every place this needs to
//! act like a path (e.g. `Command::arg`) already accepts `&str` via
//! `AsRef<OsStr>`. `Path`'s normalization semantics would be a hazard here,
//! not a convenience.

/// A Nix store path.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StorePath(String);

impl StorePath {
    pub fn new(path: impl Into<String>) -> Self {
        StorePath(path.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    /// The `<name>` part of `/nix/store/<hash>-<name>`.
    pub fn name(&self) -> Option<&str> {
        let base = self.0.rsplit('/').next()?;
        let (hash, name) = base.split_once('-')?;
        (hash.len() == 32 && !name.is_empty()).then_some(name)
    }

    /// The store directory a path sits in: `/nix/store/abc-x` → `/nix/store`.
    pub fn store_dir(&self) -> Option<&str> {
        self.0.rfind('/').map(|at| &self.0[..at])
    }

    /// The 32-character hash part: `/nix/store/<hash>-<name>` → `<hash>`.
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

    const P: &str = "/nix/store/21d91afy6vgw4l00yzy92kp92b1w3cdm-kxs-testfile.txt";

    #[test]
    fn splits_paths() {
        let p = StorePath::new(P);
        assert_eq!(p.name(), Some("kxs-testfile.txt"));
        assert_eq!(p.store_dir(), Some("/nix/store"));
        assert_eq!(p.hash_part(), Some("21d91afy6vgw4l00yzy92kp92b1w3cdm"));
    }

    #[test]
    fn rejects_paths_without_a_hash_part() {
        assert_eq!(StorePath::new("/etc/passwd").hash_part(), None);
        assert_eq!(StorePath::new("notapath").hash_part(), None);
        assert_eq!(StorePath::new("/etc/passwd").name(), None);
    }
}
