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
    crates = [ "daemon-protocol" "guest-agent" "server" "signing" "types" "worker" ];
  };
  inherit (source) outputHashes;

  kubernix-server = pkgs.callPackage ./server.nix { inherit workspaceSource outputHashes; };
  kubernix-worker = pkgs.callPackage ./worker.nix { inherit workspaceSource outputHashes; };
  kubernix-plugin = pkgs.callPackage ./plugin.nix { };
  kubernix-guest-agent = pkgs.callPackage ./guest-agent.nix { inherit workspaceSource outputHashes; };
  guest-vm = pkgs.callPackage ./guest-vm.nix { inherit kubernix-guest-agent; };
  vm-lifecycle-test = pkgs.callPackage ./vm-lifecycle-test.nix {
    inherit (guest-vm) kernel initrd;
  };
  vm-build-test = pkgs.callPackage ./vm-build-test.nix {
    inherit (guest-vm) kernel initrd;
    inherit kubernix-worker;
  };
  vm-encryption-test = pkgs.callPackage ./vm-encryption-test.nix {
    inherit (guest-vm) kernel initrd;
  };
  images = pkgs.callPackage ./images.nix { inherit kubernix-server kubernix-worker; };
in {
  inherit kubernix-server kubernix-worker kubernix-plugin kubernix-guest-agent;
  inherit (images) kubernix-server-image kubernix-worker-image;
  kubernix-guest-vm-kernel = guest-vm.kernel;
  kubernix-guest-vm-initrd = guest-vm.initrd;
  guest-vm-test = guest-vm.test;
  inherit vm-lifecycle-test vm-build-test vm-encryption-test;
  test = import ./test.nix {
    inherit pkgs kubernix-server kubernix-worker kubernix-plugin;
  };
}
