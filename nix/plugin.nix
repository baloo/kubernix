{ clangStdenv, meson, ninja, pkg-config, lix, curl, nlohmann_json, capnproto, gitignoreRecursiveSource, boost }:

clangStdenv.mkDerivation (finalAttrs: {
  pname = "kubernix-plugin";
  version = "0.1.0";
  src = gitignoreRecursiveSource [] ../.;
  sourceRoot = "kubernix/plugin";

  nativeBuildInputs = [ meson ninja pkg-config capnproto ];
  buildInputs = [ lix curl nlohmann_json capnproto ];
})
