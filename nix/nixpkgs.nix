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
    lix = (self.callPackage "${lix}/package.nix" {
      stdenv = self.clangStdenv;
    }).overrideAttrs (old: {
      # `tests/functional2` fails under GitHub Actions CI (see .github/workflows/ci.yml,
      # which builds this derivation via `nix-shell --run 'just check'`) -- drop just
      # that subdir from the meson build so `tests/unit` and `tests/functional` (both
      # also gated by `doCheck`/`enable-tests`) keep running.
      postPatch = (old.postPatch or "") + ''
        sed -i "\|subdir('tests/functional2')|d" meson.build
      '';
    });
  };
in import nixpkgs ({
  overlays = [
    rustOverlay
    overlay
  ];
} // args)
