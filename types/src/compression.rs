//! What compression a stored/served NAR's bytes use.
//!
//! Carried as plain text on every wire that mentions it -- a narinfo's
//! `Compression:` field, the `objects` table, the worker/frontend capnp
//! protocol -- so this is parsed into a closed enum once, at the boundary
//! where that text arrives, rather than re-validated as a bare `String` by
//! every reader downstream. The set of *names* this type recognizes (see
//! `FromStr`) is everything a real Nix substituter (Lix's libarchive-backed
//! `compression.cc`) can realistically emit; the set each caller can
//! actually *decode* is a separate, smaller concern handled at the decode
//! call site (`Compression::Lzip` in particular parses but has no known
//! decoder -- see `worker::decompress` and `server::substitute`).

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Compression {
    None,
    Zstd,
    Xz,
    Bzip2,
    Gzip,
    Lz4,
    Brotli,
    /// Named so a narinfo using it still parses and logs correctly, but no
    /// viable Rust decoder exists for it -- callers must reject this at the
    /// point they'd construct a decoder, not here.
    Lzip,
}

impl Compression {
    pub fn as_str(&self) -> &'static str {
        match self {
            Compression::None => "none",
            Compression::Zstd => "zstd",
            Compression::Xz => "xz",
            Compression::Bzip2 => "bzip2",
            Compression::Gzip => "gzip",
            Compression::Lz4 => "lz4",
            Compression::Brotli => "br",
            Compression::Lzip => "lzip",
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
            "bzip2" => Ok(Compression::Bzip2),
            "gzip" => Ok(Compression::Gzip),
            "lz4" => Ok(Compression::Lz4),
            "br" => Ok(Compression::Brotli),
            "lzip" => Ok(Compression::Lzip),
            other => Err(UnsupportedCompression(other.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_its_wire_text() {
        for c in [
            Compression::None,
            Compression::Zstd,
            Compression::Xz,
            Compression::Bzip2,
            Compression::Gzip,
            Compression::Lz4,
            Compression::Brotli,
            Compression::Lzip,
        ] {
            assert_eq!(c.as_str().parse::<Compression>().unwrap(), c);
        }
    }

    #[test]
    fn an_unknown_name_is_refused() {
        assert!("lrzip".parse::<Compression>().is_err());
    }
}
