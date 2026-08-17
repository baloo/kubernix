{ rustPlatform, workspaceSource, outputHashes }:

# Unlike `worker.nix`/`server.nix`, no `capnproto` nativeBuildInput: this
# crate has no `build.rs` reaching for `../protocol` — it never speaks
# Cap'n Proto, only relays bytes between a vsock connection and
# `nix-daemon --stdio` (see `guest-agent/src/main.rs`).
rustPlatform.buildRustPackage {
  pname = "kubernix-guest-agent";
  version = "0.1.0";

  src = workspaceSource;
  buildAndTestSubdir = "guest-agent";

  cargoLock = {
    lockFile = ../Cargo.lock;
    inherit outputHashes;
  };
}
