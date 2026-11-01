//! Errors in the form Lix can decode.
//!
//! The daemon protocol carries *structured* errors — severity and a trace chain,
//! not just a string — smuggled inside the kj exception's description. Lix
//! encodes them with `encodeLossy` (`lix/libutil/types-rpc.cc:17`) and decodes
//! with `unwrapErrorV1` (`lix/libutil/rpc.cc:16`):
//!
//! ```cpp
//! if (auto decoded = error::v1::tryDecode(e.getDescription().cStr())) {
//!     nix::Error fe(std::move(*decoded));   // a real Nix error
//! } else {
//!     return unwrapErrorRaw(e, loc);        // just the string
//! }
//! ```
//!
//! Without the envelope the client still shows our message, but flattened to one
//! line prefixed "remote exception" instead of rendering as a Nix error with its
//! own level and traces.
//!
//! Layout:
//!
//! ```text
//! "<message, or '(oversize message)' if over 128 chars> " + header + base64(packed Error) + trailer
//! ```
//!
//! Two details are easy to get wrong: the payload is **packed** capnp encoding,
//! not the regular framing, and the message is repeated in the clear so that a
//! peer which cannot decode still has something to print.

use base64::Engine as _;

use crate::types_capnp::{Verbosity, error};

/// `lix/libutil/types.capnp`, `const v1Errors`.
const HEADER: &str = "{error:ODZmMTlmNjgtMjNiMy00MWE3LTgxYzUtMjY5YWUwN2ZkNDY1Cg:";
const TRAILER: &str = ":v1}";

/// Lix elides the plaintext prefix past this length (the payload still carries
/// the full message).
const MAX_PLAINTEXT: usize = 128;

/// Build the description carrying a structured error.
fn encode(level: Verbosity, message: &str, traces: &[String]) -> String {
    let mut builder = capnp::message::Builder::new_default();
    {
        let mut error = builder.init_root::<error::Builder>();
        error.set_level(level);
        error.set_message(message.as_bytes());
        let mut list = error.init_traces(traces.len() as u32);
        for (i, trace) in traces.iter().enumerate() {
            list.set(i as u32, trace.as_bytes());
        }
    }

    let mut packed = Vec::new();
    if capnp::serialize_packed::write_message(&mut packed, &builder).is_err() {
        // Encoding our own message should not fail; if it somehow does, the
        // plain text is still more useful than nothing.
        return message.to_string();
    }

    let plaintext = if message.len() > MAX_PLAINTEXT {
        "(oversize message)"
    } else {
        message
    };

    format!(
        "{plaintext} {HEADER}{}{TRAILER}",
        base64::engine::general_purpose::STANDARD.encode(&packed)
    )
}

/// A failure the client should surface as an error.
pub fn failed(message: impl AsRef<str>) -> capnp::Error {
    capnp::Error::failed(encode(Verbosity::Error, message.as_ref(), &[]))
}

/// A failure with context, rendered by the client as a Nix trace chain.
pub fn failed_with_traces(message: impl AsRef<str>, traces: &[String]) -> capnp::Error {
    capnp::Error::failed(encode(Verbosity::Error, message.as_ref(), traces))
}

/// An operation the frontend does not implement.
///
/// Kept as capnp's `unimplemented` kind rather than a plain failure — that
/// distinction is meaningful to a client deciding whether to fall back — while
/// still carrying the decodable payload.
pub fn unimplemented(message: impl AsRef<str>) -> capnp::Error {
    capnp::Error::unimplemented(encode(Verbosity::Error, message.as_ref(), &[]))
}

/// Mirror of Lix's `tryDecode`, so tests check what the client will actually do
/// rather than what we think we wrote.
///
/// Test-only, but shared across modules: any test asserting on an error's
/// *traces* has to decode, because only the message appears in the clear.
#[cfg(test)]
pub fn decode(description: &str) -> Option<(Verbosity, String, Vec<String>)> {
    let start = description.rfind(HEADER)? + HEADER.len();
    let rest = &description[start..];
    let end = rest.find(TRAILER)?;
    let payload = base64::engine::general_purpose::STANDARD
        .decode(&rest[..end])
        .ok()?;

    let reader = capnp::serialize_packed::read_message(
        &mut payload.as_slice(),
        capnp::message::ReaderOptions::new(),
    )
    .ok()?;
    let error = reader.get_root::<error::Reader>().ok()?;

    let message = String::from_utf8_lossy(error.get_message().ok()?).into_owned();
    let traces = error
        .get_traces()
        .ok()?
        .iter()
        .map(|t| String::from_utf8_lossy(t.unwrap_or_default()).into_owned())
        .collect();
    Some((error.get_level().ok()?, message, traces))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_the_v1_envelope() {
        let error = failed("build of /nix/store/abc-thing failed");
        let (level, message, traces) = decode(error.extra.as_str()).expect("should decode");

        assert_eq!(level, Verbosity::Error);
        assert_eq!(message, "build of /nix/store/abc-thing failed");
        assert!(traces.is_empty());
    }

    #[test]
    fn carries_traces() {
        let error = failed_with_traces(
            "build failed",
            &["while building /nix/store/abc-thing.drv".to_string()],
        );
        let (_, _, traces) = decode(error.extra.as_str()).expect("should decode");
        assert_eq!(traces, vec!["while building /nix/store/abc-thing.drv"]);
    }

    #[test]
    fn repeats_the_message_in_the_clear() {
        // A peer that cannot decode the payload still prints something useful.
        let error = failed("something went wrong");
        assert!(error.extra.starts_with("something went wrong "));
    }

    #[test]
    fn elides_an_oversize_plaintext_but_keeps_the_payload() {
        let long = "x".repeat(MAX_PLAINTEXT + 1);
        let error = failed(&long);
        assert!(error.extra.starts_with("(oversize message) "));

        // The full text still survives where it matters.
        let (_, message, _) = decode(error.extra.as_str()).expect("should decode");
        assert_eq!(message, long);
    }

    #[test]
    fn unimplemented_keeps_its_kind() {
        let error = unimplemented("no narinfo endpoint yet");
        assert_eq!(error.kind, capnp::ErrorKind::Unimplemented);
        assert!(decode(error.extra.as_str()).is_some());
    }
}
