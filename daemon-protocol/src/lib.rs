//! A client for the wire format `nix-daemon --stdio` speaks — the "worker
//! protocol" (`lix/libstore/worker-protocol.hh`), not the Cap'n Proto
//! `daemon.capnp` protocol `server/src/daemon_rpc.rs` implements. See
//! [`connection`]'s module doc for why those are two unrelated protocols and
//! this crate implements the former.
//!
//! Deliberately narrow: [`DaemonConnection`] speaks exactly the four
//! operations `worker` needs (`Phase 15 Step 3`, see `PLAN.md`) to stop
//! shelling out to `nix-store --serve`/`nix store dump-path`/
//! `nix-store --import`/`nix-store --query`, over any
//! `AsyncRead + AsyncWrite` transport the caller supplies — a vsock-backed
//! `UnixStream` dialed through `worker::vm::VmHandle::connect` in
//! production, an in-memory duplex in this crate's own tests. No NATS, no
//! S3, no VM lifecycle: those stay in `worker`.

pub mod connection;
pub mod nar;
pub mod wire;

pub use connection::{BuildOutcome, DaemonConnection, DaemonError, PathInfo};
pub use nar::NarError;
