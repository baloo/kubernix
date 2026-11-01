//! A Nix system triple, e.g. `x86_64-linux`.

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct System(String);

impl System {
    pub fn new(system: impl Into<String>) -> Self {
        System(system.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl std::fmt::Display for System {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for System {
    fn from(system: String) -> Self {
        System(system)
    }
}

impl AsRef<str> for System {
    fn as_ref(&self) -> &str {
        &self.0
    }
}
