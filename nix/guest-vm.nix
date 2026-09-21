# Phase 15 Steps 1 and 4: a bootable kernel + initrd for the per-tenant guest
# VM, now including at-rest encryption of the persistent `/nix/store`.
#
# Deliberately minimal, matching PLAN.md's Phase 15 design: the guest never
# needs a persistent root filesystem, only `/nix/store` does -- as a
# plain-`dm-crypt` block device unlocked by a key `guest-agent` receives over
# its control vsock channel (`guest-agent/src/main.rs::handle_control`), not
# as plaintext. Everything else -- `guest-agent`, `nix-daemon`, `cryptsetup`,
# `mkfs.ext4`/`mount`, and their shared-library closures -- lives in the
# initrd itself; there is still no separate disk image to boot the guest's
# own root from.
#
# The boot initramfs is two stages, not one, for a reason that only showed up
# once sandboxed builds worked at all: a sandboxed build's own `pivot_root`
# unconditionally fails when run from the kernel's anonymous initial root
# (`mnt_has_parent()` is false for it -- see `kubernix-guest-init`'s own doc
# comment for the full mechanism), and nothing can give that root a parent
# except a real `mount()` from whatever runs as `/init`. So `/init` here is
# `kubernix-guest-init`, a tiny trampoline that loop-mounts `rootImg` (an
# EROFS image holding everything below) and `chroot`s into it before handing
# off to the *real* `/init` (`guest-agent`) inside that mount -- which, being
# a real mount with a real parent, is a root `pivot_root` is willing to leave
# later on.
{ pkgs, lib, kubernix-guest-agent, kubernix-guest-init, vm-test-lib }:

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

      # Nix's own build sandbox (user/mount/pid/ipc/uts/net/cgroup
      # namespaces) is the entire reason a build runs inside this VM rather
      # than in the worker's own container — the worker can't nest namespaces
      # under Kubernetes, so this guest is what actually provides Nix the
      # isolation it wants. `tinyconfig`'s `EXPERT`/`!MULTIUSER` defaults turn
      # every one of these off; `nix-daemon`'s
      # `libexec/lix/check-namespace-support` probe and its real sandbox
      # setup (`libstore/platform/linux.cc`, `libexec/launch-builder-linux.cc`)
      # between them `clone`/`unshare` every namespace type below, so all of
      # them have to actually work, not just the ones the probe happens to
      # check.
      MULTIUSER = yes; # NAMESPACES depends on this.
      NAMESPACES = yes;
      USER_NS = yes;
      PID_NS = yes;
      UTS_NS = yes;
      NET_NS = yes; # depends on NET, already enabled above.
      IPC_NS = yes;
      SYSVIPC = yes; # IPC_NS depends on (SYSVIPC || POSIX_MQUEUE).
      CGROUPS = yes; # launch-builder unshares CLONE_NEWCGROUP too.
      # `local-derivation-goal.cc` opens the builder's controlling PTY
      # master (`/dev/ptmx`) before entering the sandbox at all -- without
      # Unix98 PTY support there is no `/dev/ptmx` node for devtmpfs to have
      # created, so the open fails outright with plain ENOENT. This is also
      # what allocates the paired slave via `devpts`, mounted at `/dev/pts`
      # by `guest-agent` alongside `/proc`/`/sys` -- `devpts` used to be a
      # separately toggled `DEVPTS_FS` symbol, folded into this one by this
      # kernel version (strict `ignoreConfigErrors = false` below is what
      # caught that it no longer exists at all).
      UNIX98_PTYS = yes;
      # The sandbox's own syscall filter (`local-derivation-goal.cc`,
      # applied inside the builder after the namespace/chroot setup above
      # all already succeeded) — without it, loading the BPF program fails
      # outright with ENOSYS ("Function not implemented").
      SECCOMP = yes;
      SECCOMP_FILTER = yes;

      # PLAN.md Phase 18: `guest-agent`'s own eBPF-based resource-exhaustion
      # detection (an `oom:mark_victim` tracepoint, a `mapping_set_error()`
      # kprobe -- see `guest-agent/src/ebpf.rs`) is a second, independent use
      # of BPF/kprobes from the sandbox's own SECCOMP_FILTER above: this one
      # loads real classic tracing programs from userspace via `bpf(2)`
      # (`aya`), not a seccomp filter installed by the build's own sandbox
      # jail. Every symbol below is a hypothesis to confirm by booting, the
      # same as everywhere else in this file (`ignoreConfigErrors = false`
      # hard-fails the Nix build on a wrong name rather than silently
      # dropping it) -- found for this kernel version by iterating exactly
      # that way.
      BPF = yes;
      BPF_SYSCALL = yes;
      BPF_JIT = yes;
      PERF_EVENTS = yes; # tracepoint attach (oom:mark_victim) goes through the perf subsystem.
      # FTRACE gates TRACEPOINTS/KPROBE_EVENTS/BPF_EVENTS below -- without it
      # `structuredExtraConfig` can't even ask those questions, which is why
      # naming them explicitly first failed as "unused option" (found by
      # booting: `ignoreConfigErrors = false` catches a gate that isn't
      # satisfied the same way it catches a renamed/removed symbol, and the
      # error text alone doesn't distinguish the two -- confirmed by
      # `BPF_PROG_LOAD` itself returning EINVAL on a real boot once the
      # kernel built "successfully" with these still off).
      FTRACE = yes;
      TRACEPOINTS = yes;
      KPROBES = yes;
      KPROBE_EVENTS = yes; # kprobe-attached BPF programs (mapping_set_error()).
      BPF_EVENTS = yes; # tracepoint-attached BPF programs (oom:mark_victim).
      KALLSYMS = yes; # kprobes resolve attach points by symbol name.
      # The cgroup v2 memory controller, for scoping nix-daemon's build
      # children into their own `memory.max`-capped leaf (paired with the
      # OOM tracepoint above for unambiguous kill attribution --
      # `guest-agent/src/cgroup.rs`). `CGROUPS` above is only
      # `CLONE_NEWCGROUP` namespace support for the sandbox; this is the
      # actual controller and the unified-hierarchy (`cgroup2`) filesystem
      # `guest-agent` mounts at `/sys/fs/cgroup`, neither of which existed
      # before this phase.
      CGROUP_BPF = yes;
      MEMCG = yes;
      # The sandboxed build's private network namespace still needs a real
      # AF_INET to set up its loopback interface — `NET`/`NET_NS` alone only
      # get the namespace itself, not the IP protocol family inside it.
      INET = yes;
      # `/tmp` is where `guest-agent` points Nix's own `build-dir` setting
      # (see its `spawn_nix_daemon` doc comment) -- a real filesystem there,
      # same as a normally-booted system already has, rather than more of
      # the anonymous initramfs root a `pivot_root`-ing sandbox can't use.
      # `SHMEM` is `TMPFS`'s actual dependency, normally defaulted `y` --
      # except `tinyconfig`'s `EXPERT` turns that default into a real
      # question this config would otherwise never answer.
      SHMEM = yes;
      TMPFS = yes;
      # `kubernix-guest-init` (the outer initramfs' `/init`) loop-mounts an
      # EROFS image before anything else runs -- both have to be *built in*,
      # not modules: no `modprobe` (no `/sbin/modprobe`, no `/lib/modules`,
      # nothing outside the trampoline's own static binary at all) exists yet
      # at that point for a module to even be loadable from.
      BLK_DEV = yes; # gates the whole "Block devices" menu, including LOOP.
      BLK_DEV_LOOP = yes;
      MISC_FILESYSTEMS = yes; # gates fs/Kconfig's `if MISC_FILESYSTEMS` block, which is where EROFS_FS actually lives.
      EROFS_FS = yes;

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
      # Phase 15 Step 5: the `passt`-backed link `worker/src/vm.rs` attaches
      # via `--net vhost_user=...`. `guest-agent`'s `configure_network`
      # brings this up with a fixed static address -- see its doc comment --
      # so no DHCP client is needed here either. `NETDEVICES` gates the whole
      # "Network device drivers" menu `VIRTIO_NET` lives in -- without it the
      # question is never asked at all ("unused option: VIRTIO_NET"), same
      # shape as `VIRTIO_MENU`/`CRYPTO`/`MD` above gating their own menus.
      NETDEVICES = yes;
      VIRTIO_NET = yes;
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
    # `false`, not the `true` this carried through most of Step 4: nixpkgs'
    # `generate-config.pl` already compares every answer above against what
    # actually landed in the final `.config` -- `ignoreConfigErrors` only
    # controls whether a mismatch (an unmet dependency silently falling back
    # to `n`, most often because a menu/gate symbol upstream of it was never
    # turned on) is a hard build failure or a `warn` buried in build output.
    # `EROFS_FS` sitting behind `MISC_FILESYSTEMS`'s menu gate did exactly
    # that -- accepted by the build, silently `n` in the actual kernel, and
    # only surfaced as a boot-time "No such device" mounting it. `false`
    # turns every future version of that same mistake into a build failure
    # instead of another boot-panic-add-the-symbol round trip.
    ignoreConfigErrors = false;
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

  # Phase 15 Step 5: a static resolver pointed at `passt`'s own address —
  # `worker/src/vm.rs`'s `passt_args` pins `passt --dns` to the same fixed
  # `NET_GATEWAY` value, since a statically-configured guest (no DHCP client,
  # see `guest-agent`'s `configure_network`) has no other way to learn a
  # resolver address. Baked in at build time, not written at runtime, for the
  # same reason `passwd`/`group` above are: the value never changes.
  resolvConf = pkgs.writeText "resolv.conf" ''
    nameserver 10.42.100.1
  '';

  # `nix-store -qR pkgs.lix`, computed at eval time: every store path
  # `nix-daemon` might need at runtime, not just the ones its own dependency
  # graph makes obvious — see the `contents` list below for why this exists.
  lixClosurePaths = builtins.filter (p: p != "") (
    lib.splitString "\n" (
      lib.fileContents "${pkgs.closureInfo { rootPaths = [ pkgs.lix ]; }}/store-paths"
    )
  );

  # `makeInitrdNG`'s `source`/`target` contents list does not copy whole
  # closures -- it walks each source's *direct* ELF/symlink/directory
  # dependencies and includes exactly those (see
  # `pkgs/build-support/kernel/make-initrd-ng/README.md`), so every binary
  # below has its shared libraries pulled in automatically without this file
  # having to enumerate them.
  #
  # This builds the content that goes *inside* `rootImg` below, not the boot
  # initramfs itself -- `compressor = "cat"` leaves it as a plain, uncompressed
  # cpio archive, since it only ever exists to be immediately unpacked again
  # into `rootImg`'s staging directory; compressing it here would just be
  # wasted work undone one derivation later.
  rootContentCpio = pkgs.makeInitrdNG {
    name = "kubernix-guest-vm-root-content";
    compressor = "cat";
    contents = [
      # `guest-agent` *is* the guest's init: no systemd, no udev, nothing
      # else runs in this VM (PLAN.md Phase 15's explicit call-out) --
      # `kubernix-guest-init` execs this exact path once it has chrooted into
      # `rootImg`, the same way the kernel would exec `/init` directly if
      # this weren't a two-stage boot.
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
      # Phase 15 Step 5's `configure_network` shells out to this rather than
      # the guest carrying a DHCP client -- see that function's doc comment.
      {
        source = "${pkgs.iproute2}/bin/ip";
        target = "/bin/ip";
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
      {
        source = resolvConf;
        target = "/etc/resolv.conf";
      }
      # For `builtin:fetchurl`'s (and any external `curl`/`wget` builder's)
      # own TLS verification -- without this, every HTTPS fetch inside the
      # sandbox fails "SSL certificate ... unable to get local issuer
      # certificate", confirmed live once the network path itself (`--dns-
      # forward`/`--dns-host` in `worker/src/vm.rs`) actually started
      # working. `guest-agent`'s `spawn_nix_daemon` points `SSL_CERT_FILE`
      # at this same path.
      {
        source = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
        target = "/etc/ssl/certs/ca-bundle.crt";
      }
    ]
    # `nix-daemon`'s sandboxed build path execs a handful of its own
    # `libexec/lix` helpers (`check-namespace-support`, `launch-builder`,
    # ...) by their exact, compile-time-baked-in store path, and separately
    # needs *its own* default sandbox-shell binary (`busybox`, for any
    # derivation whose builder is `/bin/sh` — effectively all of nixpkgs)
    # bind-mounted into the sandbox from that same fixed path. Naming these
    # one at a time as they turned up (`check-namespace-support` today,
    # something else next) is exactly the whack-a-mole this is deliberately
    # not doing instead: `closureInfo` is the same query `nix-store -qR`
    # answers, over `pkgs.lix` itself, so every store path `nix-daemon`
    # could ever reference — reachable by dependency *or* found by scanning
    # its own binary for embedded store-path references, which is how a
    # baked-in default like the sandbox shell shows up here at all — lands
    # in the image. No `target` on any of them: `makeInitrdNG` already
    # places every `source` at its own real `/nix/store/...` path
    # unconditionally, which is exactly the property being relied on —
    # whatever path `nix-daemon` goes looking for is simply already there.
    ++ map (path: { source = path; }) lixClosurePaths;
  };

  # `rootContentCpio` unpacked into a plain directory, then packed as an
  # EROFS image instead of (another) cpio -- this is what `kubernix-guest
  # -init` loop-mounts and `chroot`s into. Uncompressed for now: `mkfs.erofs`
  # supports per-file compression (`-zlz4hc`), worth revisiting if image size
  # becomes a real concern, but correctness came first.
  rootImg = pkgs.runCommand "kubernix-guest-vm-root.img"
    {
      nativeBuildInputs = [ pkgs.erofs-utils pkgs.cpio ];
    }
    ''
      mkdir root
      (cd root && cpio -idm < ${rootContentCpio}/initrd)

      # EROFS is read-only, so nothing that mounts onto it at runtime can
      # `mkdir` its own mountpoint first the way it could on the old
      # writable initramfs root -- every directory anything ever mounts
      # onto directly has to already exist here. `guest-agent`'s own
      # `create_dir_all` calls still run (harmlessly idempotent once these
      # already exist) and still handle anything nested *under* one of
      # these once it's live and writable (`/dev/pts` under the `devtmpfs`
      # this mounts at `/dev`, for instance) -- only the top-level
      # mountpoints themselves need to be listed here.
      mkdir -p root/{dev,proc,sys,home,root,var,nix/var,mnt/store-raw,mnt/store-lower}

      mkfs.erofs "$out" root
    '';

  # The actual boot initramfs: just the trampoline and the image it mounts —
  # see this file's own module doc for why booting straight into
  # `rootContentCpio` above isn't an option anymore.
  initrd = pkgs.makeInitrdNG {
    name = "kubernix-guest-vm-initrd";
    compressor = "zstd";
    contents = [
      {
        source = "${kubernix-guest-init}/bin/kubernix-guest-init";
        target = "/init";
      }
      {
        source = rootImg;
        target = "/root.img";
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
