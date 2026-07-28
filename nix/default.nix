{ pkgs ? (import ./nixpkgs.nix) }:

let
  capnproto = pkgs.capnproto;
  kubernix-server = pkgs.callPackage ./server.nix { gitignoreRecursiveSource = pkgs.nix-gitignore.gitignoreRecursiveSource; };
  kubernix-worker = pkgs.callPackage ./worker.nix { gitignoreRecursiveSource = pkgs.nix-gitignore.gitignoreRecursiveSource; };
  kubernix-plugin = pkgs.callPackage ./plugin.nix { gitignoreRecursiveSource = pkgs.nix-gitignore.gitignoreRecursiveSource; };
in {
  inherit kubernix-server kubernix-worker kubernix-plugin;
  test = import ./test.nix {
    inherit pkgs kubernix-server kubernix-worker kubernix-plugin;
  };
}
