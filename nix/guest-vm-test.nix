# Standalone boot test for Phase 15 Step 1's `kernel`+`initrd`.
#
# cloud-hypervisor direct-boots the pair with no root block device, then the
# test dials the vsock socket cloud-hypervisor exposes on the host and
# confirms `guest-agent` accepts the connection -- corroborated by grepping
# the guest's own console log for the same event.
#
# Needs `/dev/kvm`: cloud-hypervisor has no non-KVM fallback, unlike QEMU's
# TCG. Nix's build sandbox has to be told to admit it -- add `/dev/kvm` to
# `sandbox-paths` and `kvm` to `system-features` in the builder's `nix.conf`
# (matching how NixOS's own KVM-accelerated VM tests are opted into), and
# `requiredSystemFeatures` below routes the build to a builder that has done
# so instead of failing it outright on one that hasn't.
{ stdenvNoCC, cloud-hypervisor, socat, kernel, initrd, vm-test-lib }:

stdenvNoCC.mkDerivation {
  name = "kubernix-guest-vm-test";

  nativeBuildInputs = [ cloud-hypervisor socat ];
  requiredSystemFeatures = [ "kvm" ];

  # No `src`: everything the test needs is already a build input.
  dontUnpack = true;

  buildCommand = ''
    set -euo pipefail
    source ${vm-test-lib}

    console_log="$PWD/console.log"
    vsock_socket="$PWD/vsock.sock"

    vm_boot ${kernel}/bzImage ${initrd}/initrd "$vsock_socket" "$console_log"
    ch_pid=$!
    log_pid="" # may never be set below; the trap references it either way
    trap 'kill $ch_pid $log_pid 2>/dev/null || true' EXIT

    # `guest-agent`'s `tracing` output, separate from the shared console --
    # see `nix/vm-test-lib.nix`'s `vm_stream_logs` doc comment for why.
    # Started as soon as the vsock socket file exists, not gated on the
    # daemon-port check below succeeding -- it's just as useful for seeing
    # why that check failed as for anything else.
    vm_wait_for_socket "$vsock_socket" && { vm_stream_logs "$vsock_socket"; log_pid=$!; }

    # `guest-agent`'s NIX_DAEMON_PORT (guest-agent/src/main.rs).
    port=620
    ok=0
    vm_wait_for_vsock "$vsock_socket" "$port" && ok=1

    vm_stop "$ch_pid"
    # `tee`'s process substitution is a separate, untracked child -- give its
    # last write a moment to land in $console_log before reading it back.
    sleep 0.2

    echo "==> console log:"
    cat "$console_log" || true

    if [ "$ok" != 1 ]; then
      echo "guest-agent never accepted a vsock connection on port $port"
      exit 1
    fi

    # Corroborate the handshake against the guest's own account of events --
    # a connection accepted at the vsock-device level and one `guest-agent`
    # actually logged are not necessarily the same claim.
    grep -q "guest-agent listening" "$console_log"
    grep -q "accepted vsock connection" "$console_log"

    echo "guest-agent booted, listened, and accepted a vsock connection"
    touch $out
  '';
}
