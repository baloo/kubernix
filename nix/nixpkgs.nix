args:

let
  flakeLock = builtins.fromJSON (builtins.readFile ../flake.lock);
  flakeNodes = flakeLock.nodes;
  flakeRoots = flakeNodes.root.inputs;

  lixSource = flakeNodes."${flakeRoots.lix}";
  nixpkgsSource = flakeNodes."${flakeRoots.nixpkgs}";

  fetchRepo = locked: builtins.fetchTarball {
    url = "https://github.com/${locked.owner}/${locked.repo}/archive/${locked.rev}.tar.gz";
    sha256 = locked.narHash;
  };

  lix = fetchRepo lixSource.locked;
  nixpkgs = fetchRepo nixpkgsSource.locked;
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
