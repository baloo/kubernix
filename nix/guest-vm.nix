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
{ pkgs, lib, kubernix-guest-agent, vm-test-lib }:

let
  # A from-scratch minimal config, not nixpkgs' general-purpose default with a
  # handful of symbols flipped. `pkgs.linuxPackages.kernel` normally builds
  # from `defconfig` plus `common-config.nix`'s distro-oriented settings
  # (`enableCommonConfig`, on by default) -- thousands of drivers this guest
  # never needs, and (via `autoModules`, also on by default) a correspondingly
  # huge `/lib/modules` tree that used to get packed into the initrd wholesale
  # below. `defconfig = "tinyconfig"` starts from close to `allnoconfig`
  # instead, `enableCommonConfig = false` skips the distro config entirely,
  # and `autoModules = false` means nothing becomes a module except what's
  # named `module` below -- so `structuredExtraConfig` has to name everything
  # this guest needs to boot at all, not just the delta from a sane default.
  # `pkgs.linuxPackages.kernel`'s own `src`/`version` carry over unchanged
  # (`.override` only touches the args listed here), so this still tracks
  # whatever kernel nixpkgs pins, same as before.
  #
  # The `yes`/`module` split below is otherwise unchanged from before this
  # rework: vsock/virtio/ext4 stay built in, so `guest-agent` -- itself PID 1,
  # see below -- never has to `modprobe` anything before it can bind AF_VSOCK
  # or mount the store; `dm-crypt` and its dependencies stay modules, loaded
  # via `modprobe` (`guest-agent/src/main.rs::unlock_and_mount`). Only the
  # base underneath that split has changed.
  kernel = pkgs.linuxPackages.kernel.override {
    defconfig = "tinyconfig";
    enableCommonConfig = false;
    autoModules = false;
    structuredExtraConfig = with lib.kernel; {
      # `tinyconfig`/`allnoconfig` can turn module support off entirely --
      # has to be forced back on for the `dm-crypt` modules below to be
      # buildable or loadable at all.
      MODULES = yes;
      # Core boot plumbing `tinyconfig` strips that a real (if minimal) guest
      # still needs: the kernel has to be able to unpack this zstd-compressed
      # initramfs (`nix/guest-vm.nix`'s `makeInitrdNG` uses `compressor =
      # "zstd"`) and exec ELF binaries out of it (`guest-agent` as `/init`,
      # then the `nix-daemon` it spawns).
      BLK_DEV_INITRD = yes;
      RD_ZSTD = yes;
      BINFMT_ELF = yes;
      BLOCK = yes;
      # `tiny.config` (what `tinyconfig` layers on top of `allnoconfig`)
      # disables `PRINTK` outright to save size -- without it the kernel is
      # completely silent, not just quieter, which made an early boot failure
      # indistinguishable from success until this was added.
      PRINTK = yes;
      EARLY_PRINTK = yes;
      NET = yes; # VSOCKETS sits on the core networking stack, not just virtio.
      # `AF_UNIX` itself -- so ubiquitous on a normal system it's easy to
      # forget it's a Kconfig option at all. Missing it doesn't fail to bind
      # vsock; it surfaces one layer up, in tokio's unrelated-looking
      # self-pipe signal handling (`UnixStream::new` failing with
      # `EAFNOSUPPORT`), found by booting past the previous fixes.
      UNIX = yes;
      # `nix-daemon` locks the store with advisory file locks
      # (`flock`/`fcntl`); without this they fail outright with `ENOSYS`
      # ("Function not implemented") rather than actually locking anything.
      FILE_LOCKING = yes;
      # `/dev`, `/proc`, `/sys` -- `guest-agent` mounts all three itself at
      # startup (no udev, no `prepare_namespace()` on this pure-initramfs
      # boot path -- see `guest-agent/src/main.rs::main`), but the drivers
      # for them are `bool` Kconfig symbols, not modularizable either way, so
      # they have to be builtin regardless of the `yes`/`module` split above.
      DEVTMPFS = yes;
      DEVTMPFS_MOUNT = yes;
      PROC_FS = yes;
      SYSFS = yes;
      # `nix/guest-vm-test.nix`'s `console=ttyS0` legacy serial console --
      # needs no guest driver beyond this to carry early boot messages plus
      # `guest-agent`'s own `eprintln!` output.
      TTY = yes;
      SERIAL_8250 = yes;
      SERIAL_8250_CONSOLE = yes;
      # Bus enumeration has to exist before the virtio devices below can be
      # found at all; kept builtin rather than risking a module-load-order
      # problem for something every other symbol here depends on.
      PCI = yes;
      # Without a working clock, boot hangs after "tsc: Marking TSC unstable"
      # (no usable clockevent device left to drive `calibrate_delay()`/
      # jiffies at all -- found by booting and reading the console log).
      # `ACPI = yes` was tried first since the stock default config always
      # carries it (via `enableCommonConfig`) and it's the source of a
      # legacy-PC's PM timer/HPET -- but enabling it here triple-faulted the
      # guest immediately, before any console output at all, so it's pulling
      # in something cloud-hypervisor's direct-kernel-boot path doesn't
      # actually provide. The lighter, VM-native fix: the paravirtual
      # "kvmclock" cloud-hypervisor (like any KVM-based VMM) exposes via
      # CPUID, needing no ACPI/PIT/HPET hardware at all.
      HYPERVISOR_GUEST = yes;
      PARAVIRT = yes;
      PARAVIRT_CLOCK = yes;
      KVM_GUEST = yes;
      # `tinyconfig`'s `EXPERT = yes` hides (and defaults off) a handful of
      # syscall-class options a normal system always has on -- invisible on
      # the stock default config, which never sets `EXPERT` at all. Found by
      # booting past the fixes above: `guest-agent`'s tokio runtime failed to
      # even start with `ENOSYS`, and glibc separately logged "The futex
      # facility returned an unexpected error code" -- both symptoms of the
      # underlying syscalls being compiled out, not merely unavailable at
      # runtime.
      FUTEX = yes; # glibc's pthread/mutex implementation requires this.
      EPOLL = yes; # tokio's reactor is epoll-based.
      EVENTFD = yes; # tokio uses eventfd for cross-thread wakeups.
      SIGNALFD = yes;
      TIMERFD = yes;
      # The virtio-vsock PCI device's probe failed with `-ENOSPC` allocating
      # interrupts (modern virtio-pci wants MSI-X, not legacy INTx).
      PCI_MSI = yes;

      # Menu/gate symbols that have to be enabled before the options they
      # guard are even reachable -- without these, `structuredExtraConfig`
      # below fails outright with "unused option" for every virtio, crypto,
      # and device-mapper symbol, since the question is never asked at all.
      VIRTIO_MENU = yes; # gates the whole virtio submenu (VIRTIO, VIRTIO_PCI, ...)
      CRYPTO = yes; # gates the Cryptographic API menu (CRYPTO_AES, CRYPTO_XTS)
      MD = yes; # "Multiple devices driver support (RAID and LVM)", gates BLK_DEV_DM

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
      # Plain `dm-crypt` on the tenant's `store.img` (Component 3b of
      # PLAN.md's Phase 15 design): device-mapper core, the crypt target, and
      # the AES-XTS cipher `cryptsetup_open` (`guest-agent/src/main.rs`)
      # requests. On the stock default config `BLK_DEV_DM`'s tristate ceiling
      # was gated by `DAX`, forcing these to modules regardless of intent;
      # `DAX` doesn't exist in this from-scratch config at all, but these stay
      # modules on purpose now -- deferred loading is the deliberate default
      # here, not a workaround.
      BLK_DEV_DM = module;
      DM_CRYPT = module;
      CRYPTO_AES = module;
      CRYPTO_XTS = module;
      # The decrypted device is formatted ext4 and mounted as the writable
      # *upper* layer of an overlayfs whose *lower* layer is `/nix/store` as
      # the initrd itself baked it in -- see `guest-agent/src/main.rs`'s
      # `unlock_and_mount`. Without this, mounting the tenant's (initially
      # empty) filesystem directly at `/nix/store` shadows the shared
      # libraries `makeInitrdNG` placed there for `nix-daemon` and friends to
      # dynamically link against, so any `nix-daemon` spawned *after* the
      # mount fails to exec at all -- found by booting past the earlier
      # fixes and hitting exactly that.
      EXT4_FS = yes;
      OVERLAY_FS = yes;
    };
    # Building from `tinyconfig` instead of the validated stock default means
    # there is more room for an unanswered dependency to fall through to a
    # Kconfig default that doesn't boot -- expect this list to grow via the
    # same build-boot-read-the-panic-add-the-symbol loop Step 4's guest-side
    # gaps were found by (see PLAN.md's Phase 15 status note).
    ignoreConfigErrors = true;
  };

  # `BLK_DEV_DM`/`DM_CRYPT`/`CRYPTO_AES`/`CRYPTO_XTS` above are modules, not
  # builtins -- see the comment above for why. A module this guest never
  # `modprobe`s is dead weight: `guest-agent`'s `cryptsetup_open` needs
  # `dm-mod`/`dm-crypt` loaded, and the kernel's own crypto subsystem needs a
  # working `/sbin/modprobe` on `$PATH` (the hardcoded default `CONFIG_MODPROBE_PATH`)
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
  test = pkgs.callPackage ./guest-vm-test.nix { inherit kernel initrd vm-test-lib; };
}
