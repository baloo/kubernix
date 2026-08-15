{ rustPlatform, capnproto, workspaceSource, outputHashes }:

rustPlatform.buildRustPackage {
  pname = "kubernix-server";
  version = "0.1.0";

  src = workspaceSource;

  cargoLock = {
    lockFile = ../Cargo.lock;
    inherit outputHashes;
  };

  nativeBuildInputs = [ capnproto ];
}
