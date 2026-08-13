# `nixpkgs.nix` is a function; it has to be applied. Without the `{}` every
# attribute here fails with "expected a set but found a function", which is why
# nothing under `nix -A` evaluated.
{ pkgs ? (import ./nixpkgs.nix { }) }:

let
  capnproto = pkgs.capnproto;

  source = pkgs.callPackage ./source.nix { };
  # One tree for both Rust packages: same crates, same shared `protocol`, so
  # the source is realised once and reused.
  workspaceSource = source.workspace {
    name = "kubernix-src";
    crates = [ "server" "signing" "types" "worker" ];
  };

  kubernix-server = pkgs.callPackage ./server.nix { inherit workspaceSource; };
  kubernix-worker = pkgs.callPackage ./worker.nix { inherit workspaceSource; };
  kubernix-plugin = pkgs.callPackage ./plugin.nix { };
in {
  inherit kubernix-server kubernix-worker kubernix-plugin;
  test = import ./test.nix {
    inherit pkgs kubernix-server kubernix-worker kubernix-plugin;
  };
}
