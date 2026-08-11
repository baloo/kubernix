{ clangStdenv, meson, ninja, pkg-config, lix, curl, nlohmann_json, capnproto, lib, boost }:

clangStdenv.mkDerivation (finalAttrs: {
  pname = "kubernix-plugin";
  version = "0.1.0";

  # Only the plugin directory: it needs no schemas of its own (they come from
  # liblix-store.so), so there is no reason to drag the repository root — and
  # its `target/` — into the store.
  src = lib.fileset.toSource {
    root = ../plugin;
    fileset = lib.fileset.difference ../plugin (lib.fileset.unions [
      (lib.fileset.maybeMissing ../plugin/build)
      (lib.fileset.maybeMissing ../plugin/build-spike)
    ]);
  };

  nativeBuildInputs = [ meson ninja pkg-config capnproto ];
  buildInputs = [ lix curl nlohmann_json capnproto ];
})
