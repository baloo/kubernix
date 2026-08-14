//! Narinfo signing.
//!
//! A signature is the frontend asserting "this path's contents are what its
//! metadata says". Clients enforce it: `require-sigs` defaults to true, so an
//! unsigned narinfo is inert to anyone who has not passed `--no-check-sigs`.
//! That is what makes the absence of a signature the enforcement mechanism for
//! quarantined content (PLAN.md Phase 9) rather than merely a label.
//!
//! **Keys are per tenant.** One tenant's signature says nothing about another's
//! paths, so a tenant can be trusted — or distrusted — on its own.
//!
//! Paths are signed **on creation**, not when a narinfo is served: the signature
//! is part of the row, so it is written once and it is deleted with the path it
//! describes rather than needing its own lifecycle.
//!
//! Wire formats, from `lix/libstore/crypto.cc` and `path-info.cc:26`:
//!
//! ```text
//! fingerprint  1;<path>;sha256:<base32 nar hash>;<nar size>;<refs, comma separated>
//! signature    <key name>:<base64 of the 64-byte ed25519 signature>
//! public key   <key name>:<base64 of the 32-byte public key>
//! ```

use base64::Engine as _;
use crypto_common::Generate;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use kubernix_types::{StorePath, TenantId};

pub mod base32;

pub use base32::encode as base32_encode;

/// The parts of a path a signature commits to.
///
/// Deliberately a plain borrowed struct rather than the server's `PathInfo`:
/// this crate holds the key material, so it should not also need to know what
/// the rest of the system stores about a path.
pub struct Fingerprint<'a> {
    pub path: &'a str,
    /// The raw sha256 digest of the uncompressed NAR.
    pub nar_hash: &'a [u8],
    pub nar_size: u64,
    pub references: &'a [StorePath],
    /// Prepended to each reference: [`StorePath`] itself never carries the
    /// store directory (see its doc comment), but a client recomputes this
    /// fingerprint from full paths, so references have to be printed full too.
    pub store_dir: &'a str,
}

/// What a signature is computed over.
///
/// Every field a client verifies is in here, which is the point: a signature
/// that covered less would let the uncovered part be altered freely.
pub fn fingerprint(f: &Fingerprint<'_>) -> String {
    let references = f
        .references
        .iter()
        .map(|r| r.to_full(f.store_dir))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "1;{};sha256:{};{};{}",
        f.path,
        base32_encode(f.nar_hash),
        f.nar_size,
        references
    )
}

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    /// The key material could not be used — malformed, or the backend refused.
    #[error("signing key unusable: {0}")]
    Unusable(String),
}

/// Something that can sign on a tenant's behalf.
///
/// A trait rather than a concrete key because the key material is not meant to
/// stay here: the intended end state is a *wrapped* key that never leaves an
/// external signer (TPM, HSM, KMS), with this process holding only a handle.
/// `sign` is therefore `async` and fallible — a local key needs neither, but a
/// remote one needs both, and retrofitting that would touch every caller.
#[async_trait::async_trait]
pub trait Signer: Send + Sync {
    /// The name a client sees in `trusted-public-keys`.
    fn key_name(&self) -> &str;

    /// The raw 32-byte ed25519 public key.
    fn public_key(&self) -> [u8; 32];

    /// Sign `data`, returning the raw 64-byte signature.
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SignError>;

    /// `<name>:<base64 public key>`, as `trusted-public-keys` wants it.
    fn public_key_string(&self) -> String {
        format!(
            "{}:{}",
            self.key_name(),
            base64::engine::general_purpose::STANDARD.encode(self.public_key())
        )
    }

    /// Sign a path's fingerprint, returning the `Sig:` field's value.
    async fn sign_path(&self, f: &Fingerprint<'_>) -> Result<String, SignError> {
        let signature = self.sign(fingerprint(f).as_bytes()).await?;
        Ok(format!(
            "{}:{}",
            self.key_name(),
            base64::engine::general_purpose::STANDARD.encode(&signature)
        ))
    }
}

/// How a stored key is to be interpreted.
///
/// Persisted alongside the material so that adding an externally-held key later
/// is a new variant rather than a reinterpretation of existing rows.
pub const KIND_LOCAL_ED25519: &str = "local-ed25519";

/// A key this process holds outright.
///
/// Adequate while the frontend is the only thing that could leak it, and
/// explicitly the thing to replace: see [`Signer`].
pub struct LocalSigner {
    name: String,
    key: SigningKey,
}

impl LocalSigner {
    pub fn generate(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            // Fully qualified: `SigningKey` also has an inherent `generate(rng)`,
            // which shadows the trait method that uses the system RNG.
            key: <SigningKey as Generate>::generate(),
        }
    }

    /// Rebuild from stored material: the 32-byte ed25519 seed.
    ///
    /// Nix's own on-disk format concatenates the public key after the private
    /// one, "for compatibility reasons, even though it is redundant"
    /// (`crypto.cc`). We store only the seed and derive the rest, so there is no
    /// second copy to disagree.
    pub fn from_material(name: impl Into<String>, material: &[u8]) -> Result<Self, SignError> {
        let seed: [u8; 32] = material.try_into().map_err(|_| {
            SignError::Unusable(format!("expected 32 bytes, got {}", material.len()))
        })?;
        Ok(Self {
            name: name.into(),
            key: SigningKey::from_bytes(&seed),
        })
    }

    /// The bytes to persist. Secret: everything that can sign is in here.
    pub fn material(&self) -> [u8; 32] {
        self.key.to_bytes()
    }
}

#[async_trait::async_trait]
impl Signer for LocalSigner {
    fn key_name(&self) -> &str {
        &self.name
    }

    fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SignError> {
        Ok(self.key.sign(data).to_bytes().to_vec())
    }
}

/// Check a `<name>:<base64>` signature against a raw public key.
///
/// Used by the tests, and by anything that wants to confirm what it stored is
/// what a client will accept.
pub fn verify(fingerprint: &str, signature: &str, public_key: &[u8; 32]) -> bool {
    let Some((_, encoded)) = signature.split_once(':') else {
        return false;
    };
    let Ok(raw) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
        return false;
    };
    let Ok(bytes) = <[u8; 64]>::try_from(raw.as_slice()) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    key.verify_strict(
        fingerprint.as_bytes(),
        &ed25519_dalek::Signature::from_bytes(&bytes),
    )
    .is_ok()
}

/// The key name for a tenant.
///
/// Namespaced so a client's `trusted-public-keys` entry says *whose* cache it
/// trusts, and distrusting one tenant does not touch another.
///
/// The trailing `-1` follows the convention `cache.nixos.org-1` sets: it names a
/// key *generation*, so a rotation can be published alongside the old one rather
/// than replacing it.
pub fn key_name_for(tenant: &TenantId) -> String {
    format!("kubernix-{tenant}-1")
}

#[cfg(test)]
mod tests {
    use super::*;

    const STORE_DIR: &str = "/nix/store";
    const PATH: &str = "/nix/store/00000000000000000000000000000000-thing";
    const REFS: [&str; 2] = [
        "11111111111111111111111111111111-a",
        "22222222222222222222222222222222-b",
    ];

    fn refs() -> Vec<StorePath> {
        REFS.iter().map(|s| StorePath::new(*s)).collect()
    }

    fn subject(refs: &[StorePath]) -> Fingerprint<'_> {
        Fingerprint {
            path: PATH,
            nar_hash: &[0xab; 32],
            nar_size: 1234,
            references: refs,
            store_dir: STORE_DIR,
        }
    }

    #[test]
    fn fingerprint_matches_the_documented_shape() {
        // `lix/libstore/path-info.cc:26`. A client recomputes this exactly, so
        // any drift makes every signature we produce invalid rather than wrong
        // in some tolerable way.
        let refs = refs();
        let fingerprint = fingerprint(&subject(&refs));

        assert!(fingerprint.starts_with(&format!("1;{PATH};")));
        assert!(
            fingerprint.contains(";sha256:"),
            "the nar hash carries its type: {fingerprint}"
        );
        assert!(fingerprint.contains(";1234;"), "nar size: {fingerprint}");
        assert!(
            fingerprint.ends_with(
                &format!(
                    "{STORE_DIR}/{};{STORE_DIR}/{}",
                    REFS[0], REFS[1]
                )
                .replace(';', ",")
            ),
            "references are comma separated, printed full: {fingerprint}"
        );
    }

    #[test]
    fn fingerprint_covers_every_field_a_client_checks() {
        // If a field were left out, it could be altered without invalidating the
        // signature — which is the failure mode signing exists to prevent.
        let refs = refs();
        let base = fingerprint(&subject(&refs));

        let mut other = subject(&refs);
        other.path = "/nix/store/00000000000000000000000000000000-other";
        assert_ne!(base, fingerprint(&other));

        let mut other = subject(&refs);
        other.nar_hash = &[0xcd; 32];
        assert_ne!(base, fingerprint(&other));

        let mut other = subject(&refs);
        other.nar_size = 9999;
        assert_ne!(base, fingerprint(&other));

        let fewer = vec![StorePath::new(REFS[0])];
        assert_ne!(base, fingerprint(&subject(&fewer)));
    }

    #[tokio::test]
    async fn signs_and_verifies() {
        let refs = refs();
        let signer = LocalSigner::generate("kubernix-test-1");
        let sig = signer.sign_path(&subject(&refs)).await.expect("signable");

        assert!(sig.starts_with("kubernix-test-1:"));
        assert!(verify(
            &fingerprint(&subject(&refs)),
            &sig,
            &signer.public_key()
        ));
    }

    #[tokio::test]
    async fn a_signature_does_not_verify_against_altered_metadata() {
        let refs = refs();
        let signer = LocalSigner::generate("kubernix-test-1");
        let sig = signer.sign_path(&subject(&refs)).await.expect("signable");

        let mut tampered = subject(&refs);
        tampered.nar_size = 1;
        assert!(!verify(&fingerprint(&tampered), &sig, &signer.public_key()));
    }

    #[tokio::test]
    async fn another_tenants_key_does_not_verify() {
        // Per-tenant keys are only meaningful if one cannot vouch for another.
        let refs = refs();
        let alice = LocalSigner::generate("kubernix-alice-1");
        let bob = LocalSigner::generate("kubernix-bob-1");
        let sig = alice.sign_path(&subject(&refs)).await.expect("signable");

        assert!(!verify(
            &fingerprint(&subject(&refs)),
            &sig,
            &bob.public_key()
        ));
    }

    #[tokio::test]
    async fn survives_a_round_trip_through_storage() {
        // The stored material must reproduce the same key, or every signature
        // written before a restart becomes unverifiable after it.
        let refs = refs();
        let original = LocalSigner::generate("kubernix-test-1");
        let restored =
            LocalSigner::from_material("kubernix-test-1", &original.material()).expect("valid");

        assert_eq!(original.public_key(), restored.public_key());
        assert_eq!(original.public_key_string(), restored.public_key_string());

        let sig = restored.sign_path(&subject(&refs)).await.expect("signable");
        assert!(verify(
            &fingerprint(&subject(&refs)),
            &sig,
            &original.public_key()
        ));
    }

    #[test]
    fn two_generated_keys_differ() {
        // A constant-seeded RNG would make every tenant share a key, which the
        // per-tenant model depends on not happening.
        assert_ne!(
            LocalSigner::generate("a").public_key(),
            LocalSigner::generate("b").public_key()
        );
    }

    #[test]
    fn refuses_malformed_key_material() {
        assert!(LocalSigner::from_material("k", b"too short").is_err());
        assert!(LocalSigner::from_material("k", &[0u8; 64]).is_err());
    }

    #[test]
    fn public_key_string_is_what_trusted_public_keys_wants() {
        let signer = LocalSigner::generate("kubernix-test-1");
        let published = signer.public_key_string();
        let (name, encoded) = published.split_once(':').expect("name:key");

        assert_eq!(name, "kubernix-test-1");
        let raw = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("base64");
        assert_eq!(raw.len(), 32, "ed25519 public keys are 32 bytes");
    }

    #[test]
    fn a_garbled_signature_is_refused_rather_than_panicking() {
        let refs = refs();
        let key = LocalSigner::generate("k").public_key();
        for bad in ["", "no-colon", "k:not-base64!!", "k:c2hvcnQ="] {
            assert!(!verify(&fingerprint(&subject(&refs)), bad, &key));
        }
    }

    #[test]
    fn key_names_are_per_tenant_and_carry_a_generation() {
        let alice = TenantId::from_wire("alice").unwrap();
        let bob = TenantId::from_wire("bob").unwrap();
        assert_ne!(key_name_for(&alice), key_name_for(&bob));
        assert!(key_name_for(&alice).ends_with("-1"));
    }
}
