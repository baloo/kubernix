{ rustPlatform, capnproto, gitignoreRecursiveSource }:

rustPlatform.buildRustPackage {
  pname = "kubernix-server";
  version = "0.1.0";

  src = gitignoreRecursiveSource [] ../.;

  cargoLock = {
    lockFile = ../Cargo.lock;
  };

  nativeBuildInputs = [ capnproto ];
}
