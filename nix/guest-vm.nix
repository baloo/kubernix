# Phase 15 Step 1: a bootable kernel + initrd for the per-tenant guest VM.
#
# Deliberately minimal, matching PLAN.md's Phase 15 design: the guest never
# needs a persistent root filesystem, only `/nix/store` eventually will (Step
# 4, not here). Everything else -- `guest-agent`, `nix-daemon` and their
# shared-library closures -- lives in the initrd itself, which is also the
# guest's *entire* root filesystem; there is no separate disk image to boot
# from at all yet.
{ pkgs, lib, kubernix-guest-agent }:

let
  # Built-in (not module) vsock/virtio support, so `guest-agent` -- itself
  # PID 1, see below -- never has to `modprobe` anything before it can bind
  # AF_VSOCK. The stock nixpkgs kernel ships every virtio driver as a
  # module (`=m`); overriding just the handful this guest needs to `=y`
  # keeps everything else -- and the validated base config those modules'
  # dependencies already sit in -- untouched.
  kernel = pkgs.linuxPackages.kernel.override {
    structuredExtraConfig = with lib.kernel; {
      VIRTIO = yes;
      VIRTIO_PCI = yes;
      VIRTIO_MMIO = yes;
      VSOCKETS = yes;
      VIRTIO_VSOCKETS = yes;
    };
    # The override only touches five symbols; letting `make oldconfig`
    # silently resolve everything else it doesn't ask about (the same as
    # every other custom-kernel recipe in nixpkgs) is fine here -- nothing
    # downstream depends on those defaults being anything other than the
    # stock kernel's.
    ignoreConfigErrors = true;
  };

  # `makeInitrdNG`'s `source`/`target` contents list does not copy whole
  # closures -- it walks each source's *direct* ELF/symlink/directory
  # dependencies and includes exactly those (see
  # `pkgs/build-support/kernel/make-initrd-ng/README.md`), so `guest-agent`
  # and `nix-daemon`'s shared libraries are pulled in automatically without
  # this file having to enumerate them.
  initrd = pkgs.makeInitrdNG {
    name = "kubernix-guest-vm-initrd";
    compressor = "zstd";
    contents = [
      # `guest-agent` *is* the guest's init: no systemd, no udev, nothing
      # else runs in this VM (PLAN.md Phase 15's explicit call-out). The
      # kernel execs whatever `/init` resolves to as PID 1.
      {
        source = "${kubernix-guest-agent}/bin/kubernix-guest-agent";
        target = "/init";
      }
      # `guest-agent` execs this fixed path (`guest-agent/src/main.rs`'s
      # `NIX_DAEMON_BIN`) rather than searching `$PATH` -- there is exactly
      # one binary in this guest it ever spawns.
      {
        source = "${pkgs.lix}/bin/nix-daemon";
        target = "/bin/nix-daemon";
      }
    ];
  };
in
{
  inherit kernel initrd;

  # A standalone boot: cloud-hypervisor direct-boots `kernel`+`initrd` with
  # no root block device (matching the "guest never needs a persistent root
  # filesystem" design point) and the test dials the guest's vsock CID to
  # confirm `guest-agent` is alive and willing to spawn `nix-daemon`.
  #
  # Deliberately not a `pkgs.testers.nixosTest` (see `nix/test.nix`): that
  # boots a full NixOS machine under QEMU, which is a different guest
  # entirely from the minimal, non-NixOS image built above.
  test = pkgs.callPackage ./guest-vm-test.nix { inherit kernel initrd; };
}
