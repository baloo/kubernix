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
{ stdenvNoCC, cloud-hypervisor, socat, kernel, initrd }:

stdenvNoCC.mkDerivation {
  name = "kubernix-guest-vm-test";

  nativeBuildInputs = [ cloud-hypervisor socat ];
  requiredSystemFeatures = [ "kvm" ];

  # No `src`: everything the test needs is already a build input.
  dontUnpack = true;

  buildCommand = ''
    set -euo pipefail

    console_log="$PWD/console.log"
    vsock_socket="$PWD/vsock.sock"

    # Legacy serial (ttyS0), not virtio-console: it needs no guest driver
    # beyond what every x86 kernel already has built in, so the earliest
    # kernel boot messages land in the log too, not just guest-agent's own
    # eprintln! output.
    cloud-hypervisor \
      --kernel ${kernel}/bzImage \
      --initramfs ${initrd}/initrd \
      --cmdline "console=ttyS0 reboot=t panic=1" \
      --cpus boot=1 \
      --memory size=256M \
      --vsock cid=3,socket=$vsock_socket \
      --console off \
      --serial file=$console_log \
      &
    ch_pid=$!
    trap 'kill $ch_pid 2>/dev/null || true' EXIT

    # The vsock socket appears once cloud-hypervisor's device is live, well
    # before the guest kernel finishes booting and `guest-agent` binds its
    # listener -- the retry loops below absorb that gap instead of needing a
    # fixed sleep.
    for i in $(seq 1 100); do
      [ -S "$vsock_socket" ] && break
      sleep 0.1
    done
    [ -S "$vsock_socket" ] || { echo "cloud-hypervisor never created $vsock_socket"; exit 1; }

    # `guest-agent`'s NIX_DAEMON_PORT (guest-agent/src/main.rs).
    port=620

    ok=0
    for i in $(seq 1 100); do
      if reply=$(printf 'CONNECT %d\n' "$port" | timeout 1 socat - "UNIX-CONNECT:$vsock_socket" 2>/dev/null); then
        case "$reply" in
          OK*) ok=1; break ;;
        esac
      fi
      sleep 0.2
    done

    kill "$ch_pid" 2>/dev/null || true
    wait "$ch_pid" 2>/dev/null || true

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
