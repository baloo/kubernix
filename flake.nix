{
  description = "Kubernix: a distributed remote builder for Lix";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs";
    lix.url = "github:lix-project/lix";
    # PLAN.md Phase 18: the guest-agent-ebpf crate needs a nightly Rust
    # toolchain with `rust-src` (for `-Z build-std=core`) to target
    # `bpfel-unknown-none` -- nixpkgs' own rustc is stable-only, and there's
    # no in-tree way to get a pinned nightly otherwise.
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, ... }:
    let
      system = "x86_64-linux";
      # `nix/nixpkgs.nix` pins nixpkgs from this very flake.lock and applies
      # the `lix` overlay (`pkgs.lix`, which `kubernix-worker-image` and
      # `nix/module.nix` both need) — reused here rather than importing
      # `nixpkgs` plain, so `nix build` and `nix-build nix -A ...` (see
      # `justfile`) build the exact same package set. `system` has to be
      # passed explicitly (rather than left to nixpkgs' own
      # `builtins.currentSystem` default): flake evaluation is pure, and pure
      # evaluation has no access to that builtin at all.
      pkgs = import ./nix/nixpkgs.nix { inherit system; };
      packages = import ./nix { inherit pkgs; };
    in {
      packages.${system} = {
        inherit (packages)
          kubernix-server
          kubernix-worker
          kubernix-plugin
          kubernix-guest-agent
          kubernix-server-image
          kubernix-worker-image;
        default = packages.kubernix-server;
      };
    };
}
