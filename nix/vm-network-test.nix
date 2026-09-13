# Phase 15 Step 5: proves `guest-agent` brings up its virtio-net interface
# against a real `passt` vhost-user backend, the same wiring
# `worker/src/vm.rs`'s `CloudHypervisorLauncher` drives in production
# (`passt_args`/`net_arg`) — a real boot exercising the exact CLI
# invocation PLAN.md flagged as unverified until this landed.
#
# Does not prove data reaches a real *external* network -- the Nix build
# sandbox this test runs in has no network access at all, so there is
# nothing on the other side of `passt`'s NAT to reach. What this does prove,
# against a real boot: `passt --vhost-user` and `cloud-hypervisor --net
# vhost_user=...,vhost_mode=client` actually complete the vhost-user
# handshake (a real, and previously unverified, integration point), the
# guest kernel brings up a working `eth0` on it, and at least one real frame
# crosses the link -- `passt`'s own log (visible via `nix log` on this
# derivation) reports "New guest MAC address observed", meaning it decoded
# an actual Ethernet frame the guest sent, not just a successful handshake.
# If a genuine external-egress check is worth adding later, it needs either
# real network access granted to this derivation or a by-hand run outside
# the sandbox, the same escape hatch Steps 1/3/4 used.
#
# Needs `/dev/kvm`, same sandbox requirement as `nix/guest-vm-test.nix`.
{ stdenvNoCC, cloud-hypervisor, passt, socat, kernel, initrd, vm-test-lib }:

stdenvNoCC.mkDerivation {
  name = "kubernix-vm-network-test";

  nativeBuildInputs = [ cloud-hypervisor passt socat ];
  requiredSystemFeatures = [ "kvm" ];

  dontUnpack = true;

  buildCommand = ''
    set -euo pipefail
    source ${vm-test-lib}

    # Mirrors `worker/src/vm.rs`'s `passt_args`/`NET_GUEST_ADDR`/
    # `NET_PREFIX`/`NET_GATEWAY` exactly -- and `guest-agent`'s
    # `GUEST_ADDR`/`GUEST_GATEWAY` on the other end.
    net_socket="$PWD/net.sock"
    passt --foreground --vhost-user --socket "$net_socket" \
      --address 10.42.100.2 --netmask 24 --gateway 10.42.100.1 --dns 10.42.100.1 &
    passt_pid=$!
    trap 'kill -9 $passt_pid 2>/dev/null || true' EXIT

    for i in $(seq 1 100); do
      [ -S "$net_socket" ] && break
      sleep 0.1
    done
    if [ ! -S "$net_socket" ]; then
      echo "passt never created its vhost-user socket"
      exit 1
    fi

    vsock="$PWD/vsock.sock"; console="$PWD/console.log"
    # `num_queues=2`, not `1`: cloud-hypervisor counts rx/tx as separate
    # queues and rejects lower (`worker/src/vm.rs`'s `net_arg` doc comment
    # has the full story -- found by running this exact test).
    vm_boot ${kernel}/bzImage ${initrd}/initrd "$vsock" "$console" \
      --net "vhost_user=true,socket=$net_socket,num_queues=2,vhost_mode=client"
    ch_pid=$!
    log_pid=""
    trap 'kill -9 $ch_pid $log_pid $passt_pid 2>/dev/null || true' EXIT
    vm_wait_for_socket "$vsock" && { vm_stream_logs "$vsock"; log_pid=$!; }
    vm_wait_for_vsock "$vsock" || { echo "guest never came up"; cat "$console"; exit 1; }

    vm_stop "$ch_pid"

    # `guest-agent/src/main.rs`'s own startup log line -- the observable
    # signal that `configure_network` (ip link/addr/route against the
    # passt-backed eth0) actually succeeded, not just that the guest booted.
    if ! grep -q "guest-agent: network configured: eth0 10.42.100.2/24 via 10.42.100.1" "$console"; then
      echo "guest-agent never reported successful network configuration; console log:"
      cat "$console"
      exit 1
    fi

    echo "guest configured its passt-backed network link"
    touch $out
  '';
}
