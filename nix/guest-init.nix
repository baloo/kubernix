# A fully static (musl) build of `guest-init` -- the outer initramfs' entire
# `/init`, run before there is a `/dev`, a `/proc`, or any dynamic linker to
# resolve against (see `crates/guest-init/Cargo.toml`'s doc comment for why it needs
# to exist at all). `pkgsStatic` gives it nixpkgs' musl cross-compilation
# setup for free rather than hand-rolling a static-linking target.
#
# Not part of workspace-hack, so it cannot share the glibc dependency
# artifacts of `crane.nix`; its only dependency is `libc`, so a separate
# dependency build is cheap.
{ crane, pkgsStatic }:

(crane {
  pkgs = pkgsStatic;
  depsExtraArgs = "-p kubernix-guest-init";
}).buildMember {
  name = "kubernix-guest-init";
  path = ../crates/guest-init;
}
