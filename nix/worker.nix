{ rustPlatform, capnproto, workspaceSource }:

rustPlatform.buildRustPackage {
  pname = "kubernix-worker";
  version = "0.1.0";

  src = workspaceSource;
  buildAndTestSubdir = "worker";

  cargoLock = {
    lockFile = ../Cargo.lock;
  };

  nativeBuildInputs = [ capnproto ];
}
