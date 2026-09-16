{ rustPlatform, workspaceSource, outputHashes, kubernix-guest-agent-ebpf }:

# Unlike `worker.nix`/`server.nix`, no `capnproto` nativeBuildInput: this
# crate has no `build.rs` reaching for `../protocol` — it never speaks
# Cap'n Proto, only relays bytes between a vsock connection and
# `nix-daemon --stdio` (see `guest-agent/src/main.rs`).
#
# It does have its own `build.rs` now (PLAN.md Phase 18): it embeds
# `kubernix-guest-agent-ebpf`'s compiled bytecode via `include_bytes!`, named
# by the `KUBERNIX_GUEST_AGENT_EBPF` env var set below.
rustPlatform.buildRustPackage {
  pname = "kubernix-guest-agent";
  version = "0.1.0";

  src = workspaceSource;
  buildAndTestSubdir = "guest-agent";

  cargoLock = {
    lockFile = ../Cargo.lock;
    inherit outputHashes;
  };

  KUBERNIX_GUEST_AGENT_EBPF = "${kubernix-guest-agent-ebpf}/program";
}
