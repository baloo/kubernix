# Builds `kubernix-guest-protocol-test-cli`, a tiny binary the Phase 15
# guest-VM boot tests (`nix/vm-test-lib.nix`) shell out to instead of
# `socat`/`printf`, now that the worker<->guest-agent control channel is a
# binary `postcard-rpc` protocol rather than a line-based text one that raw
# shell could hand-construct. Not part of any production image -- see the
# crate's own `Cargo.toml` header comment.
{ buildMember }:

buildMember {
  name = "kubernix-guest-protocol-test-cli";
  path = ../crates/guest-protocol-test-cli;
  additionalCrates = [
    ../crates/guest-protocol
  ];
}
