# Phase 15 Step 3: proves `kubernix_daemon_protocol` actually works against a
# real `nix-daemon --stdio`, not just the in-memory fakes its own unit tests
# (`daemon-protocol/src/connection.rs`) drive.
#
# Boots the guest exactly like `nix/guest-vm-test.nix`, then runs
# `kubernix-worker`'s `vm-smoke` binary against the real vsock socket instead
# of `socat` -- so this is the one place the actual handshake/`SetOptions`/
# `QueryPathInfo` wire bytes this client sends are checked against real Lix,
# not a mock. See `worker/src/bin/vm-smoke.rs`'s own doc comment for why this
# stops at one op rather than a full build: the current guest initrd has no
# shell/coreutils for a builder to run at all (`nix/guest-vm.nix`), and
# getting `BuildDerivation`/`AddToStoreNar` byte-exact against real Nix's own
# path hashing needs iterating against a live daemon, which this sandboxed
# build cannot do. A fuller build-and-NAR-round-trip test is follow-on work,
# not a gap this test pretends to cover.
#
# Needs `/dev/kvm`, same sandbox requirement as `nix/guest-vm-test.nix`.
{ stdenvNoCC, cloud-hypervisor, kernel, initrd, kubernix-worker }:

stdenvNoCC.mkDerivation {
  name = "kubernix-vm-build-test";

  nativeBuildInputs = [ cloud-hypervisor ];
  requiredSystemFeatures = [ "kvm" ];

  dontUnpack = true;

  buildCommand = ''
    set -euo pipefail

    console_log="$PWD/console.log"
    vsock_socket="$PWD/vsock.sock"

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

    for i in $(seq 1 100); do
      [ -S "$vsock_socket" ] && break
      sleep 0.1
    done
    [ -S "$vsock_socket" ] || { echo "cloud-hypervisor never created $vsock_socket"; exit 1; }

    # `guest-agent`'s NIX_DAEMON_PORT (guest-agent/src/main.rs).
    port=620

    # `guest-agent` accepts the vsock connection immediately and only then
    # execs `nix-daemon --stdio`; `vm-smoke` itself does the CONNECT
    # handshake, so simply retry the whole smoke binary until the daemon
    # inside is far enough along to answer, rather than probing readiness
    # with a second tool first.
    ok=0
    for i in $(seq 1 50); do
      if ${kubernix-worker}/bin/vm-smoke "$vsock_socket" "$port" > smoke.log 2>&1; then
        ok=1
        break
      fi
      sleep 0.2
    done

    kill "$ch_pid" 2>/dev/null || true
    wait "$ch_pid" 2>/dev/null || true

    echo "==> vm-smoke output:"
    cat smoke.log || true
    echo "==> console log:"
    cat "$console_log" || true

    if [ "$ok" != 1 ]; then
      echo "vm-smoke never completed a successful round trip against the guest's nix-daemon"
      exit 1
    fi

    echo "kubernix_daemon_protocol's handshake and QueryPathInfo round-tripped against a real nix-daemon"
    touch $out
  '';
}
