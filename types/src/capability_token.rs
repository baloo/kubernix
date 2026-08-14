//! The opaque bytes of a signed per-job capability token — PLAN.md Phase 14.
//!
//! A worker carries this from `BuildRequest.token` straight through to every
//! `UploadUrlRequest.token` it sends; it never parses or constructs one
//! itself, only the frontend (`kubernix-server`'s `capability` module) does
//! that. Wrapped rather than passed as a bare `Vec<u8>`/`&[u8]` so a raw NAR
//! hash or some other stray byte string cannot be handed to a slot that
//! expects a token.

use base64::Engine as _;

#[derive(Clone, Default, PartialEq, Eq, Hash)]
pub struct CapabilityToken(Vec<u8>);

/// Prints the token's claims (tenant, output names, ...) but never its
/// signature — a `{:?}`/`tracing::debug!(?token, ...)` of a `CapabilityToken`
/// (or anything embedding one, like a `Job`) must not leak bytes that let the
/// reader forge or replay the capability.
///
/// The claims are safe to print unredacted: a JWT's payload segment is
/// base64url text, not encrypted, so it is already exposed to anyone holding
/// the raw bytes — only the signature segment is worth withholding. This
/// crate never verifies or otherwise trusts the decoded text (that stays the
/// server's `capability` module's job); it is best-effort display only, and
/// falls back to a fully-redacted form for anything that doesn't parse as a
/// 3-segment JWT.
impl std::fmt::Debug for CapabilityToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let decoded = std::str::from_utf8(&self.0).ok().and_then(|token| {
            let mut segments = token.split('.');
            let (header, payload, signature) =
                (segments.next()?, segments.next()?, segments.next()?);
            if segments.next().is_some() {
                return None;
            }
            let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(payload)
                .ok()?;
            let payload = String::from_utf8(payload).ok()?;
            Some((header.len(), payload, signature.len()))
        });

        match decoded {
            Some((header_len, payload, sig_len)) => f
                .debug_struct("CapabilityToken")
                .field("header", &format_args!("<{header_len} bytes>"))
                .field("payload", &payload)
                .field("signature", &format_args!("<redacted, {sig_len} bytes>"))
                .finish(),
            None => write!(f, "CapabilityToken(<{} bytes, undecodable>)", self.0.len()),
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn jwt(header: &str, payload_json: &str, signature: &str) -> CapabilityToken {
        let header = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload_json);
        CapabilityToken::new(format!("{header}.{payload}.{signature}"))
    }

    #[test]
    fn debug_shows_claims_but_not_the_signature() {
        let token = jwt(
            r#"{"alg":"HS256"}"#,
            r#"{"tenant":"acme","expected_outputs":[{"name":"out","store_path":"x"}]}"#,
            "not-a-real-signature-but-shaped-like-one",
        );
        let printed = format!("{token:?}");

        assert!(printed.contains("acme"), "tenant should be visible: {printed}");
        assert!(
            printed.contains("expected_outputs"),
            "output names should be visible: {printed}"
        );
        assert!(
            !printed.contains("not-a-real-signature-but-shaped-like-one"),
            "the signature segment must never appear: {printed}"
        );
        assert!(
            printed.contains("redacted"),
            "the signature field should say it's redacted: {printed}"
        );
    }

    #[test]
    fn debug_falls_back_to_fully_redacted_for_non_jwt_bytes() {
        let token = CapabilityToken::new(vec![0u8, 1, 2, 3]);
        let printed = format!("{token:?}");

        assert!(printed.contains("undecodable"), "{printed}");
        assert!(printed.contains('4'), "should mention the byte count: {printed}");
    }

    #[test]
    fn debug_falls_back_when_the_payload_segment_is_not_valid_json_utf8() {
        // Three dot-separated segments, but the middle one isn't valid base64
        // (or isn't UTF-8 once decoded) — must not panic, must redact fully.
        let token = CapabilityToken::new(b"header.not-valid-base64!!!.sig".to_vec());
        let printed = format!("{token:?}");

        assert!(printed.contains("undecodable"), "{printed}");
    }
}
