# Shared pieces of the crane-based Rust build, following crane's
# quick-start-workspace example.
#
# Third-party dependencies are compiled once, in `cargoArtifacts`, and every
# glibc package (`server.nix`, `worker.nix`, ...) builds on top of that
# artifact, so editing a workspace crate never recompiles tokio and friends.
# That reuse is only sound because `workspace-hack` (cargo-hakari) gives every
# member the same feature set for every dependency.
#
# Each package also gets a source tree of its own -- its crate, the workspace
# crates it depends on, and the Cargo files -- so editing one crate does not
# rebuild the others. That relies on `workspace.members` being a glob
# (`crates/*`): Cargo then tolerates the member directories left out.
{ pkgs, depsExtraArgs ? "" }:

let
  inherit (pkgs) lib capnproto craneSrc;
  inherit (lib) fileset;
  craneLib = import craneSrc { inherit pkgs; };

  capnpFilter = path: _type: builtins.match ".*capnp$" path != null;
  fileFilter = path: type:
    (capnpFilter path type) || (craneLib.filterCargoSources path type);

  src = lib.cleanSourceWith {
    src = ../.;
    filter = fileFilter;
    name = "source";
  };

  commonArgs = {
    inherit src;
    strictDeps = true;

    buildInputs = [ ];
    nativeBuildInputs = [ 
      capnproto
    ];
  };

  fileSetForCrate =
    { crate, additionalCrates, additionalFiles }:
    lib.fileset.toSource {
      root = ../.;
      fileset = lib.fileset.unions ([
        ../Cargo.toml
        ../Cargo.lock
        (craneLib.fileset.commonCargoSources ../crates/workspace-hack)
        (lib.fileset.fileFilter (file: file.hasExt "capnp") ../protocol) 
        (craneLib.fileset.commonCargoSources ../crates/types)
        (craneLib.fileset.commonCargoSources crate)
      ] ++ (map (p: (craneLib.fileset.commonCargoSources p)) additionalCrates) ++ additionalFiles);
    };

  cargoArtifacts = craneLib.buildDepsOnly (commonArgs // lib.optionalAttrs (depsExtraArgs != "") {
    cargoExtraArgs = "--locked ${depsExtraArgs}";
  });

  individualCrateArgs = commonArgs // {
    inherit cargoArtifacts;
    inherit (craneLib.crateNameFromCargoToml { inherit src; }) version;
    doCheck = false;
  };
  
  buildMember = { name, path, additionalCrates ? [], additionalFiles ? [], args ? {} }: craneLib.buildPackage (
    individualCrateArgs
    // {
      pname = name;
      cargoExtraArgs = "-p ${name}";
      src = fileSetForCrate {
        crate = path;
        inherit additionalCrates additionalFiles;
      };
    } // args
  );
in
{
  inherit craneLib commonArgs cargoArtifacts;

  inherit buildMember;

  tests = craneLib.cargoTest (commonArgs // {
    inherit cargoArtifacts;
    pname = "kubernix-tests";
    version = "0.1.0";
    cargoExtraArgs = "-p kubernix-server -p kubernix-worker";
  });
}
