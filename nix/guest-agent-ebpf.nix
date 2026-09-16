{ pkgs, lib }:

# PLAN.md Phase 18, Step 0: builds the `guest-agent-ebpf` crate's kernel-side
# bytecode. This is its own Cargo workspace (see the comment atop
# `guest-agent/guest-agent-ebpf/Cargo.toml`), built with a pinned nightly
# toolchain (`rust-src` + `bpfel-unknown-none`, via the `rust-overlay` flake
# input added for this phase) and `-Z build-std=core`, entirely separate from
# the stable-toolchain `rustPlatform` every other crate in this repo uses.
# The output is raw ELF bytecode that `guest-agent`'s own build (see
# `nix/guest-agent.nix`) embeds via `include_bytes!`.
let
  # No `targets = [ "bpfel-unknown-none" ]` here: there is no prebuilt
  # `rust-std` for that target (the whole reason `-Z build-std=core` is
  # needed below) and rustup's component resolution fails outright if asked
  # for one. `rust-src` is what `-Z build-std` actually consumes.
  #
  # Pinned to a specific date, deliberately NOT `nightly.latest`: rustc's
  # bundled LLVM version drifts forward with every nightly, and `bpf-linker`
  # embeds one specific LLVM release (21.1.8 as packaged in this nixpkgs
  # pin) -- a too-new rustc hands it bitcode in a form its own linked LLVM
  # can't parse, and it segfaults deep in an optimization pass rather than
  # failing cleanly. `2025-09-01` was confirmed by hand (build + link
  # succeeded, produced a real `bpfel-unknown-none` ELF object) against this
  # exact `bpf-linker` version; re-pin deliberately, not by bumping to
  # `latest`, if `bpf-linker` is ever upgraded.
  rustNightly = pkgs.rust-bin.nightly."2025-09-01".default.override {
    extensions = [ "rust-src" ];
  };
  rustPlatformNightly = pkgs.makeRustPlatform {
    cargo = rustNightly;
    rustc = rustNightly;
  };
in
rustPlatformNightly.buildRustPackage {
  pname = "kubernix-guest-agent-ebpf";
  version = "0.1.0";

  # A crate of its own, entirely self-contained (no `build.rs` reaching for
  # `../protocol` the way `server`/`worker` do) -- unlike `workspaceSource`
  # (see `nix/source.nix`), it needs no sibling directories alongside it.
  src = lib.fileset.toSource {
    root = ../guest-agent/guest-agent-ebpf;
    fileset = ../guest-agent/guest-agent-ebpf;
  };

  cargoLock = {
    lockFile = ../guest-agent/guest-agent-ebpf/Cargo.lock;
  };

  nativeBuildInputs = [ pkgs.bpf-linker ];

  # No prebuilt std/core exists for bpfel-unknown-none -- build it from
  # `rust-src` as part of this crate's own build, per aya's standard
  # bring-up (this is the whole reason a nightly toolchain is needed at
  # all: `-Z build-std` is unstable).
  buildPhase = ''
    runHook preBuild
    cargo build --release --offline \
      -Z build-std=core \
      --target bpfel-unknown-none
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p $out
    cp target/bpfel-unknown-none/release/kubernix-guest-agent-ebpf $out/program
    runHook postInstall
  '';

  # A `no_std`, no-test-harness kernel-side binary -- `cargo test` (the
  # default buildRustPackage check phase) does not apply. It's also not a
  # native ELF executable (it's `eBPF`, not `x86_64`), so the standard
  # fixup phase's patchelf/strip passes have nothing valid to act on.
  doCheck = false;
  dontPatchELF = true;
  dontStrip = true;
}
