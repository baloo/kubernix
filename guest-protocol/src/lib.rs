//! Shared wire types for the worker↔guest-agent control protocol.
//!
//! Exists only because `worker` and `guest-agent` never build as one binary
//! (same reason their old fixed vsock port numbers were duplicated by
//! convention rather than shared) — but unlike a bare port number, the
//! request/response/message *shapes* postcard-rpc hashes into each
//! endpoint/topic key have to match exactly on both ends, so those live here
//! once instead of being copy-pasted.

pub mod client;
pub mod endpoints;
pub mod topics;
pub mod transport;
pub mod types;

pub use endpoints::*;
pub use topics::*;
pub use types::*;
