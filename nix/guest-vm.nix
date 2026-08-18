# Phase 15 Steps 1 and 4: a bootable kernel + initrd for the per-tenant guest
# VM, now including at-rest encryption of the persistent `/nix/store`.
#
# Deliberately minimal, matching PLAN.md's Phase 15 design: the guest never
# needs a persistent root filesystem, only `/nix/store` does -- as a
# plain-`dm-crypt` block device unlocked by a key `guest-agent` receives over
# its control vsock channel (`guest-agent/src/main.rs::handle_control`), not
# as plaintext. Everything else -- `guest-agent`, `nix-daemon`, `cryptsetup`,
# `mkfs.ext4`/`mount`, and their shared-library closures -- lives in the
# initrd itself, which is also the guest's *entire* root filesystem; there is
# still no separate disk image to boot the guest's own root from.
{ pkgs, lib, kubernix-guest-agent }:

let
  # Built-in (not module) vsock/virtio/ext4 support, so `guest-agent` -- itself
  # PID 1, see below -- never has to `modprobe` anything before it can bind
  # AF_VSOCK or mount the decrypted store. The stock nixpkgs kernel ships
  # every one of these as a module (`=m`); overriding just the handful this
  # guest needs to `=y` keeps everything else -- and the validated base config
  # those modules' dependencies already sit in -- untouched. `dm-crypt` and
  # its dependencies are the one exception: see the `BLK_DEV_DM` comment below
  # for why those stay modules, loaded via `modprobe`.
  kernel = pkgs.linuxPackages.kernel.override {
    structuredExtraConfig = with lib.kernel; {
      VIRTIO = yes;
      VIRTIO_PCI = yes;
      VIRTIO_MMIO = yes;
      VSOCKETS = yes;
      VIRTIO_VSOCKETS = yes;
      # The tenant's `store.img` is attached as a virtio-blk device
      # (`worker/src/vm.rs`'s `--disk path=...`); Steps 1-3 never needed the
      # *guest* to see it as `/dev/vda` (Step 2's persistence test only
      # touches the raw file host-side), so this was never enabled until
      # Step 4 needed the guest to actually open it.
      VIRTIO_BLK = yes;
      # `/dev`, `/dev/vda`, and `/dev/mapper/*` need to exist without udev.
      # `DEVTMPFS_MOUNT` alone does *not* get this guest a populated `/dev`:
      # its auto-mount lives in `prepare_namespace()`, a boot path this pure-
      # initramfs guest (its own `/init` execs directly) never takes --
      # `guest-agent` mounts devtmpfs itself at startup instead (see
      # `guest-agent/src/main.rs::main`). Kept here anyway since `DEVTMPFS`
      # (the filesystem driver itself) is required either way.
      DEVTMPFS = yes;
      DEVTMPFS_MOUNT = yes;
      # Plain `dm-crypt` on the tenant's `store.img` (Component 3b of
      # PLAN.md's Phase 15 design): device-mapper core, the crypt target, and
      # the AES-XTS cipher `cryptsetup_open` (`guest-agent/src/main.rs`)
      # requests. `BLK_DEV_DM`'s tristate ceiling is gated by `DAX` in
      # Kconfig, so `DAX` is disabled here too -- not needed by this guest
      # anyway, it's for persistent-memory-backed filesystems, not a virtio
      # disk.
      BLK_DEV_DM = module;
      DM_CRYPT = module;
      CRYPTO_AES = module;
      CRYPTO_XTS = module;
      # The decrypted device is formatted/mounted ext4.
      EXT4_FS = yes;
    };
    # The override only touches a handful of symbols; letting `make
    # oldconfig` silently resolve everything else it doesn't ask about (the
    # same as every other custom-kernel recipe in nixpkgs) is fine here --
    # nothing downstream depends on those defaults being anything other than
    # the stock kernel's.
    ignoreConfigErrors = true;
  };

  # `BLK_DEV_DM`/`DM_CRYPT`/`CRYPTO_AES`/`CRYPTO_XTS` above are modules, not
  # builtins (`BLK_DEV_DM`'s tristate ceiling is capped by `DAX` in Kconfig --
  # see the comment above -- and this guest has no way to influence that
  # ceiling before it's evaluated). A module this guest never `modprobe`s is
  # dead weight: `guest-agent`'s `cryptsetup_open` needs `dm-mod`/`dm-crypt`
  # loaded, and the kernel's own crypto subsystem needs a working
  # `/sbin/modprobe` on `$PATH` (the hardcoded default `CONFIG_MODPROBE_PATH`)
  # to auto-load `xts(aes)` the first time `dm-crypt` requests that transform
  # -- without it, `request_module()` calls the kernel makes internally have
  # nothing to exec and (empirically) hang rather than failing fast. `kernel
  # .modules` is nixpkgs' `depmod`-generated modules tree (a separate output
  # of the same kernel derivation, so it is guaranteed to match); `pkgs.kmod`
  # provides `modprobe`.
  kernelModules = kernel.modules;

  # A minimal user/group database -- Phase 15 Step 1's retroactive gap
  # (PLAN.md's open-risks table): without it, a real `nix-daemon` exits
  # immediately because the `nixbld` group `build-users-group` names does not
  # exist. One build user is enough: the VM design only ever runs one build
  # at a time (`worker/src/vm.rs`'s one-warm-VM-per-worker model), matching
  # the default `max-jobs = 1`.
  passwd = pkgs.writeText "passwd" ''
    root:x:0:0:root:/root:/bin/sh
    nixbld1:x:30001:30000:Nix build user 1:/var/empty:/bin/nologin
  '';
  group = pkgs.writeText "group" ''
    root:x:0:
    nixbld:x:30000:nixbld1
  '';

  # `makeInitrdNG`'s `source`/`target` contents list does not copy whole
  # closures -- it walks each source's *direct* ELF/symlink/directory
  # dependencies and includes exactly those (see
  # `pkgs/build-support/kernel/make-initrd-ng/README.md`), so every binary
  # below has its shared libraries pulled in automatically without this file
  # having to enumerate them.
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
      # Step 4's control-channel handler shells out to these three rather
      # than linking a crypto/filesystem library into `guest-agent` itself
      # (see PLAN.md's "deliberately shelling out" note) -- the same
      # exec-a-binary shape `nix-daemon` above already uses.
      {
        source = "${pkgs.cryptsetup}/bin/cryptsetup";
        target = "/bin/cryptsetup";
      }
      {
        source = "${pkgs.e2fsprogs}/bin/mkfs.ext4";
        target = "/bin/mkfs.ext4";
      }
      {
        source = "${pkgs.util-linux}/bin/mount";
        target = "/bin/mount";
      }
      # `kmod`'s `modprobe` (a symlink to the same multi-call `kmod` binary,
      # kept alongside it at the same relative path it has in the package so
      # that symlink still resolves) at the kernel's hardcoded
      # `CONFIG_MODPROBE_PATH` default -- the kernel's own crypto subsystem
      # execs this directly to auto-load `xts(aes)` and similar, not just
      # `guest-agent`'s explicit `modprobe dm-crypt` call.
      {
        source = "${pkgs.kmod}/bin/kmod";
        target = "/sbin/kmod";
      }
      {
        source = "${pkgs.kmod}/bin/modprobe";
        target = "/sbin/modprobe";
      }
      # The `depmod`-generated module tree for this exact kernel build (see
      # `kernelModules` above) -- `modprobe dm-crypt` needs `modules.dep` to
      # resolve `dm-crypt.ko`'s dependency on `dm-mod.ko`.
      {
        source = "${kernelModules}/lib/modules";
        target = "/lib/modules";
      }
      {
        source = passwd;
        target = "/etc/passwd";
      }
      {
        source = group;
        target = "/etc/group";
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
