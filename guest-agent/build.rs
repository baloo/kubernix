//! PLAN.md Phase 18: embeds the kernel-side eBPF bytecode
//! (`guest-agent-ebpf`, built separately by `nix/guest-agent-ebpf.nix` with
//! its own pinned nightly toolchain -- see that file's header comment for
//! why) into this binary via `include_bytes!`. `KUBERNIX_GUEST_AGENT_EBPF`
//! names the compiled program's path; `nix/guest-agent.nix` sets it to
//! `${kubernix-guest-agent-ebpf}/program`.

use std::path::PathBuf;

fn main() {
    let ebpf_path = std::env::var("KUBERNIX_GUEST_AGENT_EBPF")
        .expect("KUBERNIX_GUEST_AGENT_EBPF must point at the built guest-agent-ebpf program");
    println!("cargo:rerun-if-env-changed=KUBERNIX_GUEST_AGENT_EBPF");
    println!("cargo:rerun-if-changed={ebpf_path}");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    std::fs::copy(&ebpf_path, out_dir.join("guest-agent-ebpf.elf"))
        .unwrap_or_else(|err| panic!("copying {ebpf_path} into OUT_DIR: {err}"));
}
