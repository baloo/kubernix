//! Domain types shared between `kubernix-server` and `kubernix-worker`.
//!
//! Each of these wraps a plain string that was previously passed around bare
//! on both sides of the NATS/capnp boundary — a tenant id, a store path, an
//! object-store key, a Nix system triple. They look alike as `String`, which
//! is exactly the problem: nothing stopped a store path from being handed to
//! a slot expecting an object key. Living in one crate rather than being
//! independently re-typed by `server` and `worker` is what makes them the
//! *same* type across a process boundary rather than two structurally
//! identical ones that happen not to unify.

pub mod body;
mod capability_token;
mod compression;
pub mod derivation;
pub mod errors;
mod object_key;
mod store_path;
mod system;
mod tenant;
pub mod wire;

pub use capability_token::CapabilityToken;
pub use compression::{Compression, UnsupportedCompression};
pub use object_key::ObjectKey;
pub use store_path::{NotRooted, StorePath};
pub use system::System;
pub use tenant::TenantId;
