# PLAN.md Phase 18: proves the STATUS?/RESET control-port verbs round-trip
# for real against a live cloud-hypervisor VM -- unit tests
# (`guest-agent/src/main.rs`'s `dispatch_control`/`format_status` tests)
# cover dispatch against a fake `DetectionState`-less path; this is what
# actually confirms the real `aya`-loaded eBPF programs attach cleanly at
# boot (a guest whose `DetectionState::setup()` failed answers `ERR eBPF
# detection not available` instead) and that a fresh boot's detection state
# starts clear.
#
# Deliberately not `nix/vm-oom-test.nix`/`vm-enospc-test.nix`: actually
# triggering a confirmed-builder OOM or a real buffered-write-without-fsync
# ENOSPC needs a live nix-daemon build to run inside the guest, which this
# repo's existing VM tests don't yet drive (`nix/vm-build-test.nix` is the
# nearest thing, and doesn't run against a memory/disk-constrained VM). This
# test proves the mechanism attaches and answers correctly on a real boot --
# the load-bearing checkpoint PLAN.md's own implementation order calls for --
# without yet proving the two failure modes' own trigger conditions.
{ stdenvNoCC, cloud-hypervisor, socat, kernel, initrd, vm-test-lib }:

stdenvNoCC.mkDerivation {
  name = "kubernix-vm-status-test";

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

    status_reply=$(vm_status "$vsock")
    if [[ "$status_reply" != "OK NONE" ]]; then
      echo "STATUS? on a fresh boot: expected 'OK NONE', got: $status_reply"
      cat "$console"
      exit 1
    fi

    reset_reply=$(vm_reset "$vsock")
    if [[ "$reset_reply" != OK* ]]; then
      echo "RESET failed: $reset_reply"
      cat "$console"
      exit 1
    fi

    status_reply=$(vm_status "$vsock")
    vm_stop "$ch_pid"
    if [[ "$status_reply" != "OK NONE" ]]; then
      echo "STATUS? after RESET: expected 'OK NONE', got: $status_reply"
      exit 1
    fi

    echo "STATUS?/RESET round-trip for real; the eBPF OOM/ENOSPC detection attached at boot"
    touch $out
  '';
}
