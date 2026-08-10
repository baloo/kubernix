# Vendored schemas

Cap'n Proto schemas copied verbatim from Lix, used to generate the Rust side of the daemon
protocol. **Do not edit** — re-vendor instead.

| Path | Source |
| --- | --- |
| `lix/libstore/daemon.capnp` | Lix `lix/libstore/daemon.capnp` |
| `lix/libstore/types.capnp` | Lix `lix/libstore/types.capnp` |
| `lix/libutil/types.capnp` | Lix `lix/libutil/types.capnp` |
| `lix/libutil/logging.capnp` | Lix `lix/libutil/logging.capnp` |
| `capnp/c++.capnp` | capnproto 1.4.0, so the `$Cxx` annotations resolve without a system include path |

Vendored from Lix rev `2c86e95b2c49826505fadaa453a631dfbaac288f` (2.96.0-dev), matching the
`lix` input pinned in `flake.lock`.

The directory layout must be preserved: the schemas use absolute imports such as
`/lix/libutil/types.capnp`, resolved against this directory as the import root.

`daemon.capnp` states that these definitions are **EXPERIMENTAL with no stability guarantees**.
Re-vendor deliberately when the pinned Lix revision moves, and re-check the bootstrap sequence
and error encoding when you do.

Note the asymmetry with the C++ plugin: the plugin generates its headers from the *Lix source it
links against* rather than from this copy, because it relies on `liblix-store.so` to supply the
schema blobs and so must match that library exactly. The Rust side links no Lix code, so a
vendored copy is safe here — but drift between this copy and the pinned Lix is still a
compatibility bug waiting to happen.
