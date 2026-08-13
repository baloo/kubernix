{ rustPlatform, capnproto, workspaceSource }:

rustPlatform.buildRustPackage {
  pname = "kubernix-worker";
  version = "0.1.0";

  src = workspaceSource;
  buildAndTestSubdir = "worker";

  cargoLock = {
    lockFile = ../Cargo.lock;
    outputHashes = {
      "digest-io-0.1.0" = "sha256-K2VCEXmgH73uH2oAOfjjB9n20d2ii4XmHJluigUCti4=";
    };
  };

  nativeBuildInputs = [ capnproto ];
}
