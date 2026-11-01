{ buildMember, kubernix-guest-agent-ebpf }:

# Unlike `worker.nix`/`server.nix`, no `capnproto` use: this crate has no
# `build.rs` reaching for `../protocol` — it never speaks Cap'n Proto, only
# relays bytes between a vsock connection and `nix-daemon --stdio` (see
# `crates/guest-agent/src/main.rs`).
#
# It does have its own `build.rs` (PLAN.md Phase 18): it embeds
# `kubernix-guest-agent-ebpf`'s compiled bytecode via `include_bytes!`, named
# by the `KUBERNIX_GUEST_AGENT_EBPF` env var set below. Only the final build
# needs it; the shared dependency build stubs out `build.rs`.
buildMember {
  name = "kubernix-guest-agent";
  path = ../crates/guest-agent;
  additionalCrates = [
    ../crates/guest-protocol
  ];

  args = {
    KUBERNIX_GUEST_AGENT_EBPF = "${kubernix-guest-agent-ebpf}/program";
  };
}
