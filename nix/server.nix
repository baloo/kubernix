{ rustPlatform, capnproto, workspaceSource }:

rustPlatform.buildRustPackage {
  pname = "kubernix-server";
  version = "0.1.0";

  src = workspaceSource;

  cargoLock = {
    lockFile = ../Cargo.lock;
  };

  nativeBuildInputs = [ capnproto ];
}
