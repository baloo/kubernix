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
    crates = [ "daemon-protocol" "guest-agent" "guest-init" "server" "signing" "types" "worker" ];
  };
  inherit (source) outputHashes;

  kubernix-server = pkgs.callPackage ./server.nix { inherit workspaceSource outputHashes; };
  kubernix-worker = pkgs.callPackage ./worker.nix { inherit workspaceSource outputHashes; };
  kubernix-plugin = pkgs.callPackage ./plugin.nix { };
  kubernix-guest-agent = pkgs.callPackage ./guest-agent.nix { inherit workspaceSource outputHashes; };
  kubernix-guest-init = pkgs.pkgsStatic.callPackage ./guest-init.nix { inherit workspaceSource outputHashes; };
  # Shared shell helpers the four guest-VM boot tests below all `source` --
  # see `vm-test-lib.nix`'s own header for why.
  vm-test-lib = pkgs.callPackage ./vm-test-lib.nix { };
  guest-vm = pkgs.callPackage ./guest-vm.nix {
    inherit kubernix-guest-agent kubernix-guest-init vm-test-lib;
  };
  vm-lifecycle-test = pkgs.callPackage ./vm-lifecycle-test.nix {
    inherit (guest-vm) kernel initrd;
    inherit vm-test-lib;
  };
  vm-build-test = pkgs.callPackage ./vm-build-test.nix {
    inherit (guest-vm) kernel initrd;
    inherit kubernix-worker vm-test-lib;
  };
  vm-encryption-test = pkgs.callPackage ./vm-encryption-test.nix {
    inherit (guest-vm) kernel initrd;
    inherit vm-test-lib;
  };
  images = pkgs.callPackage ./images.nix {
    inherit kubernix-server kubernix-worker;
    guestVmKernel = guest-vm.kernel;
    guestVmInitrd = guest-vm.initrd;
  };
  # Diagnostic-only, not part of the Helm chart: runs `vm-encryption-test`'s
  # dm-crypt/mkfs round trip at container runtime instead of Nix build time,
  # so it can be deployed as a one-off Job on real cluster nodes to probe
  # whether their actual storage (not the guest kernel/mkfs pipeline, already
  # ruled out locally) is what a production-sized VM boot is failing on.
  vm-encryption-test-image = pkgs.callPackage ./vm-encryption-test-image.nix {
    guestVmKernel = guest-vm.kernel;
    guestVmInitrd = guest-vm.initrd;
  };
in {
  inherit kubernix-server kubernix-worker kubernix-plugin kubernix-guest-agent kubernix-guest-init;
  inherit (images) kubernix-server-image kubernix-worker-image;
  inherit vm-encryption-test-image;
  kubernix-guest-vm-kernel = guest-vm.kernel;
  kubernix-guest-vm-initrd = guest-vm.initrd;
  guest-vm-test = guest-vm.test;
  inherit vm-lifecycle-test vm-build-test vm-encryption-test;
  test = import ./test.nix {
    inherit pkgs kubernix-server kubernix-worker kubernix-plugin;
  };
}
