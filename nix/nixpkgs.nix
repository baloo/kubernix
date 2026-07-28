args:

let
  flakeLock = builtins.fromJSON (builtins.readFile ../flake.lock);
  flakeNodes = flakeLock.nodes;
  flakeRoots = flakeNodes.root.inputs;

  lixSource = flakeNodes."${flakeRoots.lix}";
  nixpkgsSource = flakeNodes."${flakeRoots.nixpkgs}";

  lix = builtins.fetchGit {
    inherit (lixSource.locked) url rev;
  };
  nixpkgs = builtins.fetchTarball {
    url = "https://github.com/nixos/nixpkgs/archives/${nixpkgsSource.locked.rev}.tar.gz";
    sha256 = nixpkgsSource.locked.narHash;
  };
in let
  overlay = self: super: {
    lix = self.callPackage "${lix}/package.nix" {
      stdenv = self.clangStdenv;
    };
  };
in import nixpkgs ({
  overlays = [
    overlay
  ];
} // args)
