# PLAN.md Phase 18: proves the eBPF OOM-detection mechanism doesn't just
# attach (`nix/vm-status-test.nix` already proved that) but actually
# *fires correctly* against a real cgroup-scoped memory-exhaustion kill on a
# real booted guest -- `guest-agent`'s diagnostic-only `TRIGGER_OOM` control
# verb (`guest-agent/src/diag.rs::oom_victim`) re-execs itself as a child
# process, moves it into the build cgroup exactly the way a real
# `nix-daemon` instance is scoped, and lets it allocate memory until the
# kernel's OOM killer takes it out. This confirms the `oom:mark_victim`
# tracepoint fires with the *right* pid, and that the cgroup-membership
# cross-check (`ebpf::DetectionState::status`) correctly attributes it as
# `builder`, not `other`.
#
# No disk attached: `TRIGGER_OOM` never touches storage, so there's nothing
# for `nix/vm-build-test.nix`'s `store.img`/`KEY` setup to do here -- same
# shape as `nix/vm-caps-test.nix`/`vm-status-test.nix`.
#
# Needs `/dev/kvm`, same sandbox requirement as `nix/guest-vm-test.nix`.
{ stdenvNoCC, cloud-hypervisor, socat, kernel, initrd, vm-test-lib }:

stdenvNoCC.mkDerivation {
  name = "kubernix-vm-oom-test";

  nativeBuildInputs = [ cloud-hypervisor socat ];
  requiredSystemFeatures = [ "kvm" ];

  dontUnpack = true;

  buildCommand = ''
    set -euo pipefail
    source ${vm-test-lib}

    vsock="$PWD/vsock.sock"; console="$PWD/console.log"
    vm_boot ${kernel}/bzImage ${initrd}/initrd "$vsock" "$console"
    ch_pid=$!
    log_pid=""
    trap 'vm_stop $ch_pid; kill $log_pid 2>/dev/null || true' EXIT
    vm_wait_for_socket "$vsock" && { vm_stream_logs "$vsock"; log_pid=$!; }
    vm_wait_for_vsock "$vsock" || { echo "boot never came up"; cat "$console"; exit 1; }

    baseline=$(vm_status "$vsock")
    if [[ "$baseline" != "OK NONE" ]]; then
      echo "STATUS? before triggering anything: expected 'OK NONE', got: $baseline"
      cat "$console"; exit 1
    fi

    trigger_reply=$(vm_trigger_oom "$vsock")
    if [[ "$trigger_reply" != OK* ]]; then
      echo "TRIGGER_OOM failed: $trigger_reply"; cat "$console"; exit 1
    fi

    # The OOM killer acts asynchronously -- poll until the tracepoint fires
    # and the cgroup cross-check attributes it, or give up.
    status="OK NONE"
    for i in $(seq 1 100); do
      status=$(vm_status "$vsock")
      if [[ "$status" != "OK NONE" ]]; then break; fi
      sleep 0.2
    done

    vm_stop "$ch_pid"

    if [[ "$status" != "OK OOM BUILDER" ]]; then
      echo "STATUS? after TRIGGER_OOM: expected 'OK OOM BUILDER', got: $status"
      cat "$console"
      exit 1
    fi

    echo "the eBPF OOM tracepoint fired on a real cgroup-scoped kill, correctly attributed as the builder"
    touch $out
  '';
}
