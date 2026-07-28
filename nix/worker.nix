{ rustPlatform, capnproto, gitignoreRecursiveSource }:

rustPlatform.buildRustPackage {
  pname = "kubernix-worker";
  version = "0.1.0";

  src = gitignoreRecursiveSource [] ../.;
  buildAndTestSubdir = "worker";

  cargoLock = {
    lockFile = ../Cargo.lock;
  };

  nativeBuildInputs = [ capnproto ];
}
