//! Reading the derivation the frontend ships inline.
//!
//! `buildDerivation` carries the derivation as bytes rather than as a store
//! path, in the **wire** form `serializeDerivation` produces
//! (`lix/libstore/derivations.cc:710`). Those bytes are handed to
//! `nix-store --serve` unmodified — see `serve.rs` — so nothing here needs to
//! re-encode them. Parsing exists only to read out what the derivation declares,
//! namely its output paths.
//!
//! **This module used to render the ATerm form of a `.drv` too, and that was a
//! dead end.** A `BasicDerivation` has no `inputDrvs`: it is the already-resolved
//! form, with every input a concrete `inputSrc`. Writing it back out therefore
//! produces a *different* derivation from the client's, and because Nix computes
//! an input-addressed output path from the derivation, the reconstructed `.drv`
//! disagreed with the output paths recorded inside it:
//!
//! ```text
//! error: derivation '/nix/store/h6bd…-x.drv' has incorrect output
//!        '/nix/store/7wjk…-x', should be '/nix/store/qff8…-x'
//! ```
//!
//! It only showed up once a derivation depended on another derivation, which is
//! why it survived so long: a leaf derivation's inputs are already `inputSrcs`,
//! so the round trip was faithful by accident.

use std::collections::BTreeMap;

use crate::{StorePath, System};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    pub name: String,
    pub path: StorePath,
    /// Empty for input-addressed outputs.
    pub algo: String,
    pub hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BasicDerivation {
    pub outputs: Vec<Output>,
    pub input_srcs: Vec<StorePath>,
    pub platform: System,
    pub builder: String,
    pub args: Vec<String>,
    /// Ordered: the ATerm form is sorted by key, and `env` is a std::map on the
    /// far side.
    pub env: BTreeMap<String, String>,
}

/// Reader for the wire framing: little-endian u64, strings length-prefixed and
/// zero-padded to a multiple of 8.
struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

#[derive(Debug)]
pub struct ParseError(String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "malformed derivation: {}", self.0)
    }
}

impl std::error::Error for ParseError {}

type Result<T> = std::result::Result<T, ParseError>;

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn u64(&mut self) -> Result<u64> {
        let end = self.pos + 8;
        if end > self.bytes.len() {
            return Err(ParseError(format!("truncated integer at {}", self.pos)));
        }
        let value = u64::from_le_bytes(self.bytes[self.pos..end].try_into().unwrap());
        self.pos = end;
        Ok(value)
    }

    fn string(&mut self) -> Result<String> {
        let len = self.u64()? as usize;
        let end = self.pos + len;
        if end > self.bytes.len() {
            return Err(ParseError(format!("truncated string at {}", self.pos)));
        }
        let value = String::from_utf8_lossy(&self.bytes[self.pos..end]).into_owned();
        // Skip the padding that rounds the field up to 8 bytes.
        self.pos = end + (8 - (len % 8)) % 8;
        Ok(value)
    }

    fn strings(&mut self) -> Result<Vec<String>> {
        let count = self.u64()? as usize;
        (0..count).map(|_| self.string()).collect()
    }
}

/// Decode the `drv :Data` field of a build request.
///
/// `store_dir` strips the store directory off the full printed paths this
/// wire form carries — the client's `serializeDerivation` always writes them
/// full.
pub fn parse(bytes: &[u8], store_dir: &str) -> Result<BasicDerivation> {
    let mut reader = Reader::new(bytes);

    // A path in this wire form that is not rooted at `store_dir` means the
    // client and the frontend disagree about the store directory — refused
    // rather than silently reinterpreted, the same as at the daemon protocol
    // boundary this feeds.
    let rooted = |s: String| {
        StorePath::from_full(store_dir, &s)
            .ok_or_else(|| ParseError(format!("{s} is not rooted at {store_dir}")))
    };

    let output_count = reader.u64()? as usize;
    let mut outputs = Vec::with_capacity(output_count);
    for _ in 0..output_count {
        outputs.push(Output {
            name: reader.string()?,
            path: rooted(reader.string()?)?,
            algo: reader.string()?,
            hash: reader.string()?,
        });
    }

    let input_srcs = reader
        .strings()?
        .into_iter()
        .map(rooted)
        .collect::<Result<_>>()?;
    let platform = System::new(reader.string()?);
    let builder = reader.string()?;
    let args = reader.strings()?;

    let env_count = reader.u64()? as usize;
    let mut env = BTreeMap::new();
    for _ in 0..env_count {
        let key = reader.string()?;
        let value = reader.string()?;
        env.insert(key, value);
    }

    Ok(BasicDerivation {
        outputs,
        input_srcs,
        platform,
        builder,
        args,
        env,
    })
}
#[cfg(test)]
mod tests {
    use super::*;

    fn write_u64(out: &mut Vec<u8>, value: u64) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn write_str(out: &mut Vec<u8>, value: &str) {
        write_u64(out, value.len() as u64);
        out.extend_from_slice(value.as_bytes());
        out.extend(std::iter::repeat_n(0u8, (8 - (value.len() % 8)) % 8));
    }

    fn sample_wire() -> Vec<u8> {
        let mut w = Vec::new();
        write_u64(&mut w, 1); // one output
        write_str(&mut w, "out");
        write_str(&mut w, "/nix/store/00000000000000000000000000000000-thing");
        write_str(&mut w, "");
        write_str(&mut w, "");
        write_u64(&mut w, 1); // one input src
        write_str(&mut w, "/nix/store/11111111111111111111111111111111-dep");
        write_str(&mut w, "x86_64-linux");
        write_str(&mut w, "/bin/sh");
        write_u64(&mut w, 2); // args
        write_str(&mut w, "-c");
        write_str(&mut w, "echo hi");
        write_u64(&mut w, 2); // env
        write_str(&mut w, "out");
        write_str(&mut w, "/nix/store/00000000000000000000000000000000-thing");
        write_str(&mut w, "name");
        write_str(&mut w, "thing");
        w
    }

    #[test]
    fn parses_the_wire_form() {
        let drv = parse(&sample_wire(), "/nix/store").unwrap();
        assert_eq!(drv.outputs.len(), 1);
        assert_eq!(drv.outputs[0].name, "out");
        assert_eq!(
            drv.outputs[0].path,
            StorePath::new("00000000000000000000000000000000-thing")
        );
        assert_eq!(drv.platform.as_str(), "x86_64-linux");
        assert_eq!(drv.builder, "/bin/sh");
        assert_eq!(drv.args, vec!["-c", "echo hi"]);
        assert_eq!(drv.input_srcs.len(), 1);
        assert_eq!(
            drv.input_srcs[0],
            StorePath::new("11111111111111111111111111111111-dep")
        );
        assert_eq!(drv.env.get("name").map(String::as_str), Some("thing"));
    }

    #[test]
    fn rejects_truncated_input() {
        assert!(parse(&[0u8; 4], "/nix/store").is_err());
        assert!(parse(&sample_wire()[..20], "/nix/store").is_err());
    }

    #[test]
    fn rejects_a_path_rooted_at_a_different_store_dir() {
        // The wire's paths are rooted at "/nix/store"; a server configured
        // for a different store directory must refuse rather than silently
        // treat the mismatched prefix as part of the bare name.
        assert!(parse(&sample_wire(), "/mnt/other-store").is_err());
    }
}
