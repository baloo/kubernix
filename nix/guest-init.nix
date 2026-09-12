# A fully static (musl) build of `guest-init` -- the outer initramfs' entire
# `/init`, run before there is a `/dev`, a `/proc`, or any dynamic linker to
# resolve against (see `guest-init/Cargo.toml`'s doc comment for why it needs
# to exist at all). `pkgsStatic` gives it nixpkgs' musl cross-compilation
# setup for free rather than hand-rolling a static-linking target.
{ pkgsStatic, workspaceSource, outputHashes }:

pkgsStatic.rustPlatform.buildRustPackage {
  pname = "kubernix-guest-init";
  version = "0.1.0";

  src = workspaceSource;
  buildAndTestSubdir = "guest-init";

  cargoLock = {
    lockFile = ../Cargo.lock;
    inherit outputHashes;
  };
}
