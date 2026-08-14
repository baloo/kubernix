//! Signed, self-contained per-job capability tokens — PLAN.md Phase 14.
//!
//! A worker holds no credentials of its own: what it may read or write in the
//! object store, and which store paths it may report as its build's outputs,
//! is exactly what this token authorizes. Minted once, at dispatch
//! (`daemon_rpc::build_derivation`), from output paths the frontend has
//! already verified rather than merely parsed off the wire — see
//! [`crate::store_path::verify_fixed_output`].
//!
//! Self-contained on purpose: `uploads.rs`'s `serve` loop runs under a NATS
//! queue group, so any frontend replica may answer a given request, and
//! verification must not depend on looking up per-job state only the
//! dispatching replica holds — everything needed to check a claim travels
//! inside the token itself.
//!
//! The token is a JWT (HS256): the header's standard `kid` field is exactly
//! what a rotating secret needs to name which one signed it, so rotation
//! needs no bespoke framing. No `exp` claim — the token is exactly as
//! powerful as the one job it names, and the presigned URLs it yields already
//! expire (`uploads::URL_TTL`).

use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use kubernix_types::{CapabilityToken, StorePath};

use crate::store::Store;
use crate::tenant::TenantId;

/// What a job is authorized to do: which tenant it belongs to, and which
/// store paths it may write as its outputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    pub job_id: Uuid,
    pub tenant: TenantId,
    /// The `.drv`'s own store path, for deriving the job's log key.
    pub derivation_path: StorePath,
    /// `(output name, verified store path)` — the only paths `record_outputs`
    /// will accept from this job, and the only ones `uploads.rs` will presign
    /// an upload URL for.
    pub expected_outputs: Vec<(String, StorePath)>,
}

/// The JWT's claim set. Plain strings, not the domain types directly: the
/// domain types (`TenantId`, `StorePath`) stay serde-free, and this is the one
/// place their wire (string) form is what matters.
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    job_id: Uuid,
    tenant: String,
    derivation_path: String,
    expected_outputs: Vec<ExpectedOutputClaim>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ExpectedOutputClaim {
    name: String,
    store_path: String,
}

impl From<&Capability> for Claims {
    fn from(capability: &Capability) -> Self {
        Claims {
            job_id: capability.job_id,
            tenant: capability.tenant.as_str().to_string(),
            derivation_path: capability.derivation_path.as_str().to_string(),
            expected_outputs: capability
                .expected_outputs
                .iter()
                .map(|(name, path)| ExpectedOutputClaim {
                    name: name.clone(),
                    store_path: path.as_str().to_string(),
                })
                .collect(),
        }
    }
}

impl Claims {
    /// `None` if `tenant` is not a well-formed wire tenant id — the same
    /// refusal a malformed wire `tenant` field gets elsewhere
    /// (`TenantId::from_wire`), applied to a claim that was itself signed by
    /// this frontend and so should never actually be malformed in practice.
    fn into_capability(self) -> Option<Capability> {
        Some(Capability {
            job_id: self.job_id,
            tenant: TenantId::from_wire(self.tenant)?,
            derivation_path: StorePath::new(self.derivation_path),
            expected_outputs: self
                .expected_outputs
                .into_iter()
                .map(|o| (o.name, StorePath::new(o.store_path)))
                .collect(),
        })
    }
}

impl Capability {
    /// Sign this capability with `(kid, secret)`, producing the token's raw
    /// bytes (a JWT's UTF-8 text) to carry on the wire. `kid` — the JWT
    /// header's standard key-id field — lets a verifier, possibly a different
    /// frontend replica, possibly after the secret has rotated, select the
    /// exact secret this token was signed with.
    pub fn sign(&self, kid: u64, secret: &[u8; 32]) -> CapabilityToken {
        let mut header = Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = Some(kid.to_string());
        let claims = Claims::from(self);
        let token = encode(&header, &claims, &EncodingKey::from_secret(secret))
            .expect("HS256-encoding a well-formed claim set cannot fail");
        CapabilityToken::new(token.into_bytes())
    }

    /// Verify `token`, looking up the secret its header claims to be signed
    /// with via `store`. `None` for anything malformed, unverifiable, or
    /// tampered with — deliberately one outcome for every failure mode, so a
    /// caller cannot treat "unknown key id" any differently from "forged
    /// signature".
    pub async fn verify(token: &CapabilityToken, store: &dyn Store) -> Option<Self> {
        let token = std::str::from_utf8(token.as_bytes()).ok()?;
        let kid: u64 = decode_header(token).ok()?.kid?.parse().ok()?;
        let secret = store.capability_secret(kid).await?;

        let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        // No `exp` claim is ever set — see the module doc — so neither
        // requiring nor checking one here is correct, not merely permissive.
        validation.validate_exp = false;
        validation.required_spec_claims.clear();

        let data = decode::<Claims>(token, &DecodingKey::from_secret(&secret), &validation).ok()?;
        data.claims.into_capability()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemoryStore;

    fn capability() -> Capability {
        Capability {
            job_id: Uuid::new_v4(),
            tenant: TenantId::from_wire("user-alice-0000000000000000").expect("well formed"),
            derivation_path: StorePath::new("00000000000000000000000000000000-x.drv"),
            expected_outputs: vec![(
                "out".to_string(),
                StorePath::new("11111111111111111111111111111111-x"),
            )],
        }
    }

    #[tokio::test]
    async fn round_trips_through_sign_and_verify() {
        let store = MemoryStore::new();
        let (kid, secret) = store.current_capability_secret().await;
        let capability = capability();

        let token = capability.sign(kid, &secret);
        let verified = Capability::verify(&token, &*store)
            .await
            .expect("a freshly signed token verifies");
        assert_eq!(verified, capability);
    }

    #[tokio::test]
    async fn refuses_a_tampered_payload() {
        let store = MemoryStore::new();
        let (kid, secret) = store.current_capability_secret().await;
        let mut bytes = capability().sign(kid, &secret).into_bytes();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xff;
        let token = CapabilityToken::new(bytes);
        assert!(Capability::verify(&token, &*store).await.is_none());
    }

    #[tokio::test]
    async fn refuses_an_unknown_key_id() {
        let store = MemoryStore::new();
        let (_, secret) = store.current_capability_secret().await;
        let token = capability().sign(999, &secret); // no such kid in this store
        assert!(Capability::verify(&token, &*store).await.is_none());
    }

    #[tokio::test]
    async fn refuses_a_token_signed_with_a_different_secret() {
        let store = MemoryStore::new();
        let (kid, _) = store.current_capability_secret().await;
        let token = capability().sign(kid, &[0xAA; 32]);
        assert!(Capability::verify(&token, &*store).await.is_none());
    }

    #[tokio::test]
    async fn refuses_a_truncated_or_non_utf8_token() {
        let store = MemoryStore::new();
        assert!(
            Capability::verify(&CapabilityToken::new(Vec::new()), &*store)
                .await
                .is_none()
        );
        assert!(
            Capability::verify(&CapabilityToken::new(vec![0xFFu8; 10]), &*store)
                .await
                .is_none()
        );
    }
}
