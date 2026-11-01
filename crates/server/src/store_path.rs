//! Computing a Nix store path from content.
//!
//! This is what makes a *verified* push possible: rather than believing a
//! client's claim about which path its bytes belong at, the frontend derives the
//! path itself. A content-addressed path is a function of its bytes, so a lie is
//! not expressible — see PLAN.md Phase 9.
//!
//! Ported from `lix/libstore/store-api.cc`. The shapes, all of which feed the
//! same [`StoreDir::make_store_path`]:
//!
//! | method | type string | hashed |
//! | --- | --- | --- |
//! | text | `text[:<ref>…]` | the file contents |
//! | flat | `output:out` | `"fixed:out:<hash>:"` |
//! | recursive + sha256 | `source[:<ref>…]` | the NAR |
//! | recursive + other | `output:out` | `"fixed:out:r:<hash>:"` |
//!
//! Note the asymmetry in the last two rows: recursive-sha256 is the common case
//! (`nix-store --add`) and gets the short `source` form, which is also the only
//! fixed-output shape allowed to carry references.
//!
//! Verified against real Nix output — see the tests, whose expected paths were
//! produced by `nix-store --add`, `nix-store --add-fixed` and `builtins.toFile`
//! rather than by this code.

use sha2::{Digest, Sha256};

use kubernix_types::StorePath;

/// How the content was ingested, mirroring `ContentAddressMethod` on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaMethod {
    /// `builtins.toFile`: the contents hashed directly, references allowed.
    Text,
    /// A single file, hashed directly.
    Flat,
    /// A NAR serialisation, hashed as a whole.
    Recursive,
}

/// Nix's base32, shared with the signing crate — a narinfo fingerprint embeds a
/// hash in the same encoding, and there should be exactly one implementation of
/// something this easy to get subtly wrong.
use kubernix_signing::base32::encode as base32_encode;

/// Fold a hash down to `new_size` bytes by XOR, as `compressHash`
/// (`lix/libutil/hash.cc:262`) does. Store paths use 20 bytes.
fn compress_hash(hash: &[u8], new_size: usize) -> Vec<u8> {
    let mut out = vec![0u8; new_size];
    for (i, byte) in hash.iter().enumerate() {
        out[i % new_size] ^= byte;
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The store directory a client prepends to every path it sends or expects on
/// the wire — see [`kubernix_types::StorePath`]'s doc comment for why the type
/// itself never carries it. Borrowed, not owned: every caller already has a
/// `&str` or `String` in scope for the lifetime of these calls.
#[derive(Clone, Copy)]
pub struct StoreDir<'a>(pub &'a str);

impl<'a> StoreDir<'a> {
    /// `Store::makeStorePath`: `<type>:<hash>:<storeDir>:<name>`, sha256'd,
    /// compressed to 20 bytes, base32'd. `store_dir` only feeds the hash —
    /// Nix's formula folds it in — the returned string is the bare
    /// `<hash>-<name>`.
    pub fn make_store_path(&self, ty: &str, hash_hex: &str, name: &str) -> String {
        let s = format!("{ty}:{hash_hex}:{}:{name}", self.0);
        let digest = Sha256::digest(s.as_bytes());
        let compressed = compress_hash(&digest, 20);
        format!("{}-{name}", base32_encode(&compressed))
    }

    /// Stuff references into the type string, as `makeType` does.
    ///
    /// A bit hacky, and deliberately so upstream: they cannot go anywhere else
    /// in the grammar without becoming ambiguous.
    fn make_type(&self, base: &str, references: &[StorePath], self_ref: bool) -> String {
        let mut ty = base.to_string();
        for reference in references {
            ty.push(':');
            ty.push_str(&reference.to_full(self.0));
        }
        if self_ref {
            ty.push_str(":self");
        }
        ty
    }

    /// The store path content with this address belongs at.
    ///
    /// `hash` is the raw digest bytes of whatever the method hashes — the file
    /// contents for `Text` and `Flat`, the NAR for `Recursive`.
    ///
    /// Returns `None` for combinations Nix itself refuses: a non-sha256 fixed
    /// output carrying references, which has nowhere to put them.
    pub fn store_path_for(
        &self,
        name: &str,
        method: CaMethod,
        hash_algo: &str,
        hash: &[u8],
        references: &[StorePath],
    ) -> Option<StorePath> {
        match method {
            CaMethod::Text => {
                // `makeTextPath` asserts sha256; anything else is not a text CA.
                if hash_algo != "sha256" {
                    return None;
                }
                let ty = self.make_type("text", references, false);
                Some(StorePath::new(self.make_store_path(
                    &ty,
                    &format!("sha256:{}", hex(hash)),
                    name,
                )))
            }
            CaMethod::Recursive if hash_algo == "sha256" => {
                let ty = self.make_type("source", references, false);
                Some(StorePath::new(self.make_store_path(
                    &ty,
                    &format!("sha256:{}", hex(hash)),
                    name,
                )))
            }
            // The long form: hash the description of the fixed output, then use
            // *that* as the store path's hash.
            CaMethod::Flat | CaMethod::Recursive => {
                if !references.is_empty() {
                    return None;
                }
                let prefix = if method == CaMethod::Recursive {
                    "r:"
                } else {
                    ""
                };
                let inner = format!("fixed:out:{prefix}{hash_algo}:{}:", hex(hash));
                let digest = Sha256::digest(inner.as_bytes());
                Some(StorePath::new(self.make_store_path(
                    "output:out",
                    &format!("sha256:{}", hex(&digest)),
                    name,
                )))
            }
        }
    }
}

/// Parse a lowercase hex string into bytes. `None` on malformed input (odd
/// length, or a character outside `0-9a-f`) — the hash this feeds is
/// untrusted wire input from a `.drv`.
fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

impl<'a> StoreDir<'a> {
    /// Recompute a fixed-output derivation output's store path from its
    /// declared `algo`/`hash`, entirely ignoring whatever `path` the `.drv`
    /// itself claims — mirroring how a real Nix daemon's `buildDerivation`
    /// handles a `CAFixed` output: `parseDerivationOutput`
    /// (`lix/libstore/derivations.cc:223-256`) discards the wire's `path`
    /// field for this case and derives the true one from the content address
    /// alone. PLAN.md Phase 14.
    ///
    /// `algo` is the wire's `Output.algo` field: bare `"<hash-algo>"` selects
    /// [`CaMethod::Flat`], `"r:<hash-algo>"` selects [`CaMethod::Recursive`] —
    /// Nix's `ContentAddressMethod::parsePrefix` convention. Returns `None`
    /// for malformed hex, or any shape [`StoreDir::store_path_for`] itself
    /// refuses.
    pub fn verify_fixed_output(
        &self,
        drv_name: &str,
        output_name: &str,
        algo: &str,
        hash_hex: &str,
    ) -> Option<StorePath> {
        let (method, hash_algo) = match algo.strip_prefix("r:") {
            Some(rest) => (CaMethod::Recursive, rest),
            None => (CaMethod::Flat, algo),
        };
        // `outputPathName`: the "out" output reuses the derivation's own name
        // bare; every other output is suffixed with its own name.
        let output_path_name = if output_name == "out" {
            drv_name.to_string()
        } else {
            format!("{drv_name}-{output_name}")
        };
        self.store_path_for(&output_path_name, method, hash_algo, &unhex(hash_hex)?, &[])
    }
}

/// A content address as it arrives on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContentAddress {
    pub method: CaMethod,
    pub algo: String,
    pub hash: Vec<u8>,
}

/// Why a push was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum Rejection {
    /// The bytes do not hash to what the client said they do.
    HashMismatch { declared: String, actual: String },
    /// They hash correctly, but to a *different path* than the client claimed.
    WrongPath { claimed: String, computed: String },
    /// A shape we cannot check, so we cannot accept it as verified.
    Unverifiable(&'static str),
}

impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Rejection::HashMismatch { declared, actual } => write!(
                f,
                "content hash mismatch: declared {declared}, computed {actual}"
            ),
            Rejection::WrongPath { claimed, computed } => {
                write!(f, "content belongs at {computed}, not {claimed}")
            }
            Rejection::Unverifiable(why) => write!(f, "cannot verify: {why}"),
        }
    }
}

impl<'a> StoreDir<'a> {
    /// Check that `nar` really is the content addressed by `ca` at `path`.
    ///
    /// This is the whole point of the tiering: a path that passes here was
    /// *derived* from its bytes rather than asserted, so a client cannot
    /// register content at a path that is not its own. See PLAN.md Phase 9.
    ///
    /// Two independent things are checked, and both matter. The hash must
    /// match the bytes — otherwise the address is simply false — *and* the
    /// resulting path must match the one claimed, which is what stops a
    /// client presenting honest content under someone else's name.
    pub fn verify(
        &self,
        path: &StorePath,
        ca: &ContentAddress,
        references: &[StorePath],
        nar: &[u8],
    ) -> std::result::Result<(), Rejection> {
        let name = path
            .name()
            .ok_or(Rejection::Unverifiable("not a store path"))?;

        if ca.algo != "sha256" {
            // Everything a Lix client produces is sha256. Refusing the rest is
            // not a limitation worth lifting speculatively — it would mean
            // hashing with an algorithm nothing uses.
            return Err(Rejection::Unverifiable("only sha256 is checked"));
        }

        // What gets hashed depends on the method: the NAR as a whole, or the
        // single file inside it.
        let actual: Vec<u8> = match ca.method {
            CaMethod::Recursive => Sha256::digest(nar).to_vec(),
            CaMethod::Text | CaMethod::Flat => {
                let contents = regular_file_contents(nar)
                    .ok_or(Rejection::Unverifiable("not a single regular file"))?;
                Sha256::digest(contents).to_vec()
            }
        };

        if actual != ca.hash {
            return Err(Rejection::HashMismatch {
                declared: hex(&ca.hash),
                actual: hex(&actual),
            });
        }

        let computed = self
            .store_path_for(name, ca.method, &ca.algo, &actual, references)
            .ok_or(Rejection::Unverifiable("no path for this address"))?;

        if &computed != path {
            return Err(Rejection::WrongPath {
                claimed: path.to_string(),
                computed: computed.to_string(),
            });
        }
        Ok(())
    }
}

/// Contents of a NAR holding exactly one regular file.
///
/// Needed to verify `text` and `flat` content addresses, which hash the *file*
/// rather than the NAR wrapping it. Returning `None` for anything else is
/// correct rather than a limitation: both methods describe a single file, so a
/// NAR that is a directory or a symlink cannot carry either address.
///
/// The layout, from `lix/libutil/archive.cc`:
///
/// ```text
/// "nix-archive-1" "(" "type" "regular" [ "executable" "" ] "contents" <data> ")"
/// ```
fn regular_file_contents(nar: &[u8]) -> Option<&[u8]> {
    let mut at = 0;

    if read_token(nar, &mut at)? != b"nix-archive-1" || read_token(nar, &mut at)? != b"(" {
        return None;
    }
    if read_token(nar, &mut at)? != b"type" || read_token(nar, &mut at)? != b"regular" {
        return None;
    }

    let mut field = read_token(nar, &mut at)?;
    if field == b"executable" {
        // Followed by an empty string, then the real field.
        read_token(nar, &mut at)?;
        field = read_token(nar, &mut at)?;
    }
    if field != b"contents" {
        return None;
    }

    let contents = read_token(nar, &mut at)?;
    (read_token(nar, &mut at)? == b")").then_some(contents)
}

/// One length-prefixed, eight-byte-padded string, advancing `at` past it.
fn read_token<'a>(nar: &'a [u8], at: &mut usize) -> Option<&'a [u8]> {
    let len = nar
        .get(*at..*at + 8)
        .map(|slice| u64::from_le_bytes(slice.try_into().expect("eight bytes")))?
        as usize;
    let start = *at + 8;
    let end = start.checked_add(len)?;
    if end > nar.len() {
        return None;
    }
    // Strings are padded out to a multiple of eight; a reader that skips the
    // padding desynchronises for the rest of the stream.
    *at = end + (8 - len % 8) % 8;
    Some(&nar[start..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIR: StoreDir = StoreDir("/nix/store");

    /// sha256 of `"hello content addressing\n"`, i.e. the file the expected
    /// paths below were produced from.
    const FLAT_HASH: &str = "4e5b6af479ac8a11c0d7e256cf774ac9a1087605837b44e9c95f528d04df5156";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn nar_of(contents: &[u8]) -> Vec<u8> {
        // A NAR for one regular, non-executable file. Enough to reproduce what
        // `nix-store --add` hashes.
        fn str_(out: &mut Vec<u8>, s: &[u8]) {
            out.extend_from_slice(&(s.len() as u64).to_le_bytes());
            out.extend_from_slice(s);
            out.extend(std::iter::repeat_n(0u8, (8 - s.len() % 8) % 8));
        }
        let mut out = Vec::new();
        for token in [
            &b"nix-archive-1"[..],
            b"(",
            b"type",
            b"regular",
            b"contents",
        ] {
            str_(&mut out, token);
        }
        str_(&mut out, contents);
        str_(&mut out, b")");
        out
    }

    #[test]
    fn matches_nix_store_add() {
        // $ nix-store --add f.txt
        // /nix/store/cqarpckbfd0dmdylgwx5rc2wqaz2882r-f.txt
        let nar = nar_of(b"hello content addressing\n");
        let nar_hash = Sha256::digest(&nar);
        assert_eq!(
            DIR.store_path_for("f.txt", CaMethod::Recursive, "sha256", &nar_hash, &[],)
                .as_ref()
                .map(StorePath::as_str),
            Some("cqarpckbfd0dmdylgwx5rc2wqaz2882r-f.txt")
        );
    }

    #[test]
    fn matches_nix_store_add_fixed() {
        // $ nix-store --add-fixed sha256 f.txt
        // /nix/store/6mhsdfmq1xchgx34768mghvp3jlw3fg4-f.txt
        assert_eq!(
            DIR.store_path_for("f.txt", CaMethod::Flat, "sha256", &unhex(FLAT_HASH), &[],)
                .as_ref()
                .map(StorePath::as_str),
            Some("6mhsdfmq1xchgx34768mghvp3jlw3fg4-f.txt")
        );
    }

    #[test]
    fn matches_builtins_to_file() {
        // $ nix-instantiate --eval -E 'builtins.toFile "greeting" "round trip"'
        // "/nix/store/ik0brqacj8rn97il4ygixp855xyh64ld-greeting"
        let hash = Sha256::digest(b"round trip");
        assert_eq!(
            DIR.store_path_for("greeting", CaMethod::Text, "sha256", &hash, &[])
                .as_ref()
                .map(StorePath::as_str),
            Some("ik0brqacj8rn97il4ygixp855xyh64ld-greeting")
        );
    }

    #[test]
    fn verify_fixed_output_matches_nix_store_add_fixed() {
        // Reuses the fixture from `matches_nix_store_add_fixed`: a fixed-output
        // derivation named "f.txt" with a plain (non-"r:") sha256 algo and its
        // "out" output funnels through the same makeFixedOutputPath formula as
        // `nix-store --add-fixed sha256 f.txt`.
        assert_eq!(
            DIR.verify_fixed_output("f.txt", "out", "sha256", FLAT_HASH)
                .as_ref()
                .map(StorePath::as_str),
            Some("6mhsdfmq1xchgx34768mghvp3jlw3fg4-f.txt")
        );
    }

    #[test]
    fn verify_fixed_output_recursive_prefix_selects_recursive() {
        // Reuses the fixture from `matches_nix_store_add`: "r:sha256" is the
        // wire's spelling for CaMethod::Recursive.
        let nar = nar_of(b"hello content addressing\n");
        let nar_hash = hex(&Sha256::digest(&nar));
        assert_eq!(
            DIR.verify_fixed_output("f.txt", "out", "r:sha256", &nar_hash)
                .as_ref()
                .map(StorePath::as_str),
            Some("cqarpckbfd0dmdylgwx5rc2wqaz2882r-f.txt")
        );
    }

    #[test]
    fn verify_fixed_output_names_non_out_outputs() {
        // outputPathName: a non-"out" output is suffixed with its own name
        // rather than reusing the derivation's name bare, so it must land at a
        // different path from "out".
        let named = DIR
            .verify_fixed_output("f.txt", "dev", "sha256", FLAT_HASH)
            .expect("well-formed");
        let bare = DIR
            .verify_fixed_output("f.txt", "out", "sha256", FLAT_HASH)
            .expect("well-formed");
        assert_ne!(named, bare);
        assert_eq!(named.name(), Some("f.txt-dev"));
    }

    #[test]
    fn verify_fixed_output_rejects_malformed_hex() {
        assert_eq!(
            DIR.verify_fixed_output("f.txt", "out", "sha256", "not-hex"),
            None
        );
        assert_eq!(
            DIR.verify_fixed_output("f.txt", "out", "sha256", "abc"), // odd length
            None
        );
    }

    #[test]
    fn references_change_the_path() {
        // They are folded into the type string, so a path with references is a
        // different path — which is the point: the reference set is part of what
        // the content addresses.
        let hash = Sha256::digest(b"x");
        let bare = DIR.store_path_for("n", CaMethod::Text, "sha256", &hash, &[]);
        let with = DIR.store_path_for(
            "n",
            CaMethod::Text,
            "sha256",
            &hash,
            &[StorePath::new("00000000000000000000000000000000-dep")],
        );
        assert_ne!(bare, with);
        assert!(bare.is_some() && with.is_some());
    }

    #[test]
    fn a_fixed_output_may_not_carry_references() {
        // Nix refuses this outright rather than inventing an encoding, so we
        // must too — silently dropping them would compute a path that is not the
        // one the content belongs at.
        let hash = Sha256::digest(b"x");
        assert_eq!(
            DIR.store_path_for(
                "n",
                CaMethod::Flat,
                "sha256",
                &hash,
                &[StorePath::new("00000000000000000000000000000000-dep",)],
            ),
            None
        );
    }

    #[test]
    fn text_requires_sha256() {
        assert_eq!(
            DIR.store_path_for("n", CaMethod::Text, "sha1", &[0; 20], &[]),
            None
        );
    }

    #[test]
    fn a_store_path_hash_is_thirty_two_characters() {
        // 20 bytes at 5 bits per digit. The alphabet itself is the signing
        // crate's business; what matters here is that compressing to 20 bytes
        // produces the hash part Nix expects.
        let encoded = base32_encode(&compress_hash(&Sha256::digest(b"anything"), 20));
        assert_eq!(encoded.len(), 32);
        assert!(kubernix_signing::base32::is_valid(&encoded));
    }

    /// A well-formed push: the content, its address, and the path it belongs at.
    fn honest_push() -> (StorePath, ContentAddress, Vec<u8>) {
        let contents = b"hello content addressing\n";
        let nar = nar_of(contents);
        let ca = ContentAddress {
            method: CaMethod::Recursive,
            algo: "sha256".to_string(),
            hash: Sha256::digest(&nar).to_vec(),
        };
        (
            StorePath::new("cqarpckbfd0dmdylgwx5rc2wqaz2882r-f.txt"),
            ca,
            nar,
        )
    }

    #[test]
    fn accepts_content_that_matches_its_address() {
        let (path, ca, nar) = honest_push();
        assert_eq!(DIR.verify(&path, &ca, &[], &nar), Ok(()));
    }

    #[test]
    fn rejects_content_that_does_not_hash_to_its_address() {
        // Corruption, or a client asserting an address its bytes do not have.
        let (path, ca, mut nar) = honest_push();
        nar.extend_from_slice(b"tampered");
        assert!(matches!(
            DIR.verify(&path, &ca, &[], &nar),
            Err(Rejection::HashMismatch { .. })
        ));
    }

    #[test]
    fn rejects_honest_content_under_someone_elses_name() {
        // The attack the tiering exists to stop: real content, correctly hashed,
        // presented at a path it does not belong at. Only recomputing the path
        // catches this — the hash check alone passes.
        let (_, ca, nar) = honest_push();
        let claimed = StorePath::new("00000000000000000000000000000000-bash");
        match DIR.verify(&claimed, &ca, &[], &nar) {
            Err(Rejection::WrongPath { computed, .. }) => {
                assert_ne!(computed, claimed.to_string());
                // The name is itself part of what is hashed, so the content does
                // not even land at the same hash under a different name — a
                // client cannot rename its way into an existing path.
                assert!(computed.ends_with("-bash"));
                assert!(!computed.starts_with("cqarpckbfd0dmdylgwx5rc2wqaz2882r"));
            }
            other => panic!("should have refused the path, got {other:?}"),
        }
    }

    #[test]
    fn rejects_a_claim_with_references_the_content_does_not_have() {
        // References are folded into the path, so adding one moves the path —
        // which means a client cannot smuggle extra references past us.
        let (path, ca, nar) = honest_push();
        let refs = vec![StorePath::new("00000000000000000000000000000000-dep")];
        assert!(matches!(
            DIR.verify(&path, &ca, &refs, &nar),
            Err(Rejection::WrongPath { .. })
        ));
    }

    #[test]
    fn verifies_a_text_address_against_the_file_not_the_nar() {
        // `text` hashes the contents, so a reader that hashed the NAR would
        // reject every `builtins.toFile` path.
        let contents = b"round trip";
        let ca = ContentAddress {
            method: CaMethod::Text,
            algo: "sha256".to_string(),
            hash: Sha256::digest(contents).to_vec(),
        };
        assert_eq!(
            DIR.verify(
                &StorePath::new("ik0brqacj8rn97il4ygixp855xyh64ld-greeting"),
                &ca,
                &[],
                &nar_of(contents),
            ),
            Ok(())
        );
    }

    #[test]
    fn refuses_to_guess_at_shapes_it_cannot_check() {
        let (path, mut ca, nar) = honest_push();

        // An algorithm we do not hash with cannot be checked, and must not be
        // waved through as verified.
        ca.algo = "sha512".to_string();
        assert!(matches!(
            DIR.verify(&path, &ca, &[], &nar),
            Err(Rejection::Unverifiable(_))
        ));

        // Nor may a non-store path.
        let (_, ca, nar) = honest_push();
        assert!(matches!(
            DIR.verify(&StorePath::new("not-a-store-path"), &ca, &[], &nar),
            Err(Rejection::Unverifiable(_))
        ));
    }

    #[test]
    fn splits_paths() {
        let p = StorePath::new("cqarpckbfd0dmdylgwx5rc2wqaz2882r-f.txt");
        assert_eq!(p.name(), Some("f.txt"));
        assert_eq!(StorePath::new("not-a-store-path").name(), None);
    }
}
