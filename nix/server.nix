{ lib, buildMember }:

# `-p` scopes the build to this crate: a bare `cargo build` from the workspace
# root would also build `guest-agent`, which needs `KUBERNIX_GUEST_AGENT_EBPF`
# pointing at a prebuilt eBPF program that the server has no use for.
buildMember {
  name = "kubernix-server";
  path = ../crates/server;
  additionalCrates = [
    ../crates/signing
  ];
  additionalFiles = [
    (lib.fileset.fileFilter (file: file.hasExt "sql") ../crates/server/migrations)
  ];
}
