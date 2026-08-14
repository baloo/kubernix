//! The opaque bytes of a signed per-job capability token — PLAN.md Phase 14.
//!
//! A worker carries this from `BuildRequest.token` straight through to every
//! `UploadUrlRequest.token` it sends; it never parses or constructs one
//! itself, only the frontend (`kubernix-server`'s `capability` module) does
//! that. Wrapped rather than passed as a bare `Vec<u8>`/`&[u8]` so a raw NAR
//! hash or some other stray byte string cannot be handed to a slot that
//! expects a token.

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct CapabilityToken(Vec<u8>);

impl CapabilityToken {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        CapabilityToken(bytes.into())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for CapabilityToken {
    fn from(bytes: Vec<u8>) -> Self {
        CapabilityToken(bytes)
    }
}

impl AsRef<[u8]> for CapabilityToken {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
