//! A shared vocabulary for the "safe to show a caller" split.
//!
//! Everywhere an internal [`eyre::Report`] crosses a trust boundary — a Nix
//! daemon-protocol response, an HTTP body, a worker's job outcome — the full
//! chain belongs in a log line, not in the bytes sent back. [`Public`] is how
//! a call site marks a message as an exception to that rule: something
//! already known to be safe, worth showing as-is.
//!
//! This module only supplies the marker and the lookup. What counts as safe
//! *beyond* an explicit [`Public`] wrap — a domain error type such as
//! `StoreError` whose `Display` was written for exactly this purpose — is a
//! judgement each boundary makes about its own types, by downcasting the
//! report directly; those types are not visible from here.

use std::fmt;

/// A message already known to be safe to hand back to a caller.
///
/// Construct it as the *root cause* of a report — via `?` on a
/// `Result<_, Public>`, `.ok_or_else(|| Public::new(...))?`, or
/// `eyre::Report::new(Public::new(...))` — rather than passing it to
/// `.wrap_err(...)`: eyre's context wrapper stores the message behind a
/// private type, so a `Public` handed to `wrap_err` as a message is not
/// recoverable by [`public_message`]. As the root cause it is, and plain
/// string context can still be layered on top with `.wrap_err("...")`
/// without hiding it — [`public_message`] walks the whole chain.
#[derive(Debug)]
pub struct Public(String);

impl Public {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for Public {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Public {}

/// Scan an eyre chain for a [`Public`] root cause and return its text, or
/// `None` if the chain carries no such marker — meaning the boundary calling
/// this should fall back to a generic message and log the report in full.
pub fn public_message(report: &eyre::Report) -> Option<String> {
    report
        .chain()
        .find_map(|cause| cause.downcast_ref::<Public>())
        .map(ToString::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_a_public_root_cause() {
        let report: eyre::Report = Public::new("could not fetch this path").into();
        assert_eq!(
            public_message(&report).as_deref(),
            Some("could not fetch this path")
        );
    }

    #[test]
    fn finds_a_public_root_cause_under_layers_of_plain_context() {
        let report: eyre::Report = Public::new("could not fetch this path").into();
        let report = report
            .wrap_err("retrying")
            .wrap_err("giving up after 3 attempts");

        assert_eq!(
            public_message(&report).as_deref(),
            Some("could not fetch this path")
        );
    }

    #[test]
    fn none_when_the_chain_has_no_public_cause() {
        let io_err = std::io::Error::other("permission denied talking to the object store");
        let report = eyre::Report::new(io_err).wrap_err("fetching object");
        assert_eq!(public_message(&report), None);
    }
}
