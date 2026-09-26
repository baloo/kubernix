//! What compression a stored/served NAR's bytes use.
//!
//! Carried as plain text on every wire that mentions it -- a narinfo's
//! `Compression:` field, the `objects` table, the worker/frontend capnp
//! protocol -- but the set kubernix actually knows how to decode is fixed and
//! small, so this is parsed into a closed enum once, at the boundary where
//! that text arrives, rather than re-validated as a bare `String` by every
//! reader downstream.

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Compression {
    None,
    Zstd,
    Xz,
}

impl Compression {
    pub fn as_str(&self) -> &'static str {
        match self {
            Compression::None => "none",
            Compression::Zstd => "zstd",
            Compression::Xz => "xz",
        }
    }
}

impl std::fmt::Display for Compression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A compression name kubernix does not know how to decode -- e.g. an
/// upstream substituter's narinfo naming a format other than `none`, `zstd`
/// or `xz`.
#[derive(Debug, thiserror::Error)]
#[error("unsupported compression: {0:?}")]
pub struct UnsupportedCompression(String);

impl std::str::FromStr for Compression {
    type Err = UnsupportedCompression;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(Compression::None),
            "zstd" => Ok(Compression::Zstd),
            "xz" => Ok(Compression::Xz),
            other => Err(UnsupportedCompression(other.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_its_wire_text() {
        for c in [Compression::None, Compression::Zstd, Compression::Xz] {
            assert_eq!(c.as_str().parse::<Compression>().unwrap(), c);
        }
    }

    #[test]
    fn an_unknown_name_is_refused() {
        assert!("bzip2".parse::<Compression>().is_err());
    }
}
