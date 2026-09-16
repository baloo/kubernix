args:

let
  flakeLock = builtins.fromJSON (builtins.readFile ../flake.lock);
  flakeNodes = flakeLock.nodes;
  flakeRoots = flakeNodes.root.inputs;

  lixSource = flakeNodes."${flakeRoots.lix}";
  nixpkgsSource = flakeNodes."${flakeRoots.nixpkgs}";
  rustOverlaySource = flakeNodes."${flakeRoots.rust-overlay}";

  fetchRepo = locked: builtins.fetchTarball {
    url = "https://github.com/${locked.owner}/${locked.repo}/archive/${locked.rev}.tar.gz";
    sha256 = locked.narHash;
  };

  lix = fetchRepo lixSource.locked;
  nixpkgs = fetchRepo nixpkgsSource.locked;
  # PLAN.md Phase 18: pinned nightly Rust (rust-src + bpfel-unknown-none) for
  # the guest-agent-ebpf crate; see nix/guest-agent-ebpf.nix.
  rustOverlay = import (fetchRepo rustOverlaySource.locked);
in let
  overlay = self: super: {
    lix = self.callPackage "${lix}/package.nix" {
      stdenv = self.clangStdenv;
    };
  };
in import nixpkgs ({
  overlays = [
    rustOverlay
    overlay
  ];
} // args)
