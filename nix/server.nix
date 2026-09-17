{ rustPlatform, capnproto, workspaceSource, outputHashes }:

rustPlatform.buildRustPackage {
  pname = "kubernix-server";
  version = "0.1.0";

  src = workspaceSource;
  # Scopes `cargo build`/`test` to just this package, the same way
  # `worker.nix` already does -- without it, a bare `cargo build` from the
  # workspace root builds *every* member, including `guest-agent`, which
  # (PLAN.md Phase 18) needs `KUBERNIX_GUEST_AGENT_EBPF` set to a prebuilt
  # `kubernix-guest-agent-ebpf` program. `kubernix-server` has nothing to do
  # with the guest's eBPF bytecode and shouldn't need that wired in at all
  # -- found by actually running `nix-build nix -A test`, not by reading the
  # derivation.
  buildAndTestSubdir = "server";

  cargoLock = {
    lockFile = ../Cargo.lock;
    inherit outputHashes;
  };

  nativeBuildInputs = [ capnproto ];
}
