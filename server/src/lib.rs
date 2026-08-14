//! Kubernix frontend library.
//!
//! Holds the Lix daemon protocol implementation, shared by the SSH frontend and
//! the `kubernix-stdio` test harness.

/// Generated bindings for the vendored Lix schemas.
///
/// capnpc-rust flattens every schema to a crate-root module named after the file
/// stem, and it resolves cross-schema references the same way. Lix has *two*
/// schemas called `types.capnp` — `lix/libutil` and `lix/libstore` — and
/// `daemon.capnp` imports both, so the generated code refers to
/// `crate::types_capnp` for symbols from each (`option`/`map`/`settings` from
/// libutil, `store_path` from libstore). They are therefore included into a
/// single module here; the two files define disjoint items.
pub mod types_capnp {
    include!(concat!(env!("OUT_DIR"), "/lix/libutil/types_capnp.rs"));
    include!(concat!(env!("OUT_DIR"), "/lix/libstore/types_capnp.rs"));
}

pub mod logging_capnp {
    include!(concat!(env!("OUT_DIR"), "/lix/libutil/logging_capnp.rs"));
}

pub mod daemon_capnp {
    include!(concat!(env!("OUT_DIR"), "/lix/libstore/daemon_capnp.rs"));
}

pub mod kubernix_capnp {
    include!(concat!(env!("OUT_DIR"), "/kubernix_capnp.rs"));
}

pub mod daemon_rpc;
pub mod gc;
pub mod http;
pub mod jobs;
pub mod postgres_store;
pub mod rpc_error;
pub mod ssh;
pub mod store;
pub mod store_path;
pub mod tenant;
pub mod uploads;
