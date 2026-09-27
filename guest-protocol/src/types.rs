//! Plain data types shared by more than one endpoint/topic message.

use postcard_schema::Schema;
use serde::{Deserialize, Serialize};

/// What `STATUS?` used to report as wire text (`NONE`/`OOM BUILDER`/
/// `OOM OTHER`/`ENOSPC`) — now one type shared verbatim by both sides instead
/// of a string round-trip. Mirrors `guest-agent/src/ebpf.rs::FailureStatus`
/// (kept as a separate, guest-local type there since it predates this crate
/// and nothing outside `ebpf.rs` needs its exact shape) — the control
/// dispatch handler converts between the two at the wire boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub enum GuestFailureStatus {
    None,
    OutOfMemory { builder_victim: bool },
    DiskFull,
}

/// One trusted substituter: a cache URL and its narinfo signing key.
/// Replaces the old flattened/interleaved `SUBST <url1> <key1> ...` token
/// list — a `Vec` of these is structurally well-formed by construction, no
/// even-token-count validation needed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Schema)]
pub struct SubstituterEntry {
    pub url: String,
    pub public_key: String,
}
