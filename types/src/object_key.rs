//! An object-store key, e.g. `<tenant>/nar/<hash>.nar.zst`.
//!
//! Always built with `format!`, never parsed, so this carries no parsing
//! helpers — just enough to stop a store path and an object key (both plain
//! strings that look similar) from being passed to each other's slot.

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectKey(String);

impl ObjectKey {
    pub fn new(key: impl Into<String>) -> Self {
        ObjectKey(key.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Display for ObjectKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for ObjectKey {
    fn from(key: String) -> Self {
        ObjectKey(key)
    }
}

impl AsRef<str> for ObjectKey {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
