# Phase 15 Step 3: proves `kubernix_daemon_protocol` actually works against a
# real `nix-daemon --stdio`, not just the in-memory fakes its own unit tests
# (`daemon-protocol/src/connection.rs`) drive.
#
# `nix-daemon` has no store to open at all without a mounted `/nix/store` --
# there is no plain/unencrypted mount path (`guest-agent` only ever mounts
# the dm-crypt-unlocked device, Step 4), so this attaches a `store.img` and
# pushes a `FRESH` key over the control channel first, exactly like
# `nix/vm-encryption-test.nix`'s boot #1 -- as setup, not as something this
# test itself is asserting about (that's what `vm-encryption-test.nix`
# checks). Only then does it run `kubernix-worker`'s `vm-smoke` binary
# against the real vsock socket instead of `socat` -- so this is the one
# place the actual handshake/`SetOptions`/`QueryPathInfo` wire bytes this
# client sends are checked against real Lix, not a mock. See
# `worker/src/bin/vm-smoke.rs`'s own doc comment for why this stops at one op
# rather than a full build: the current guest initrd has no shell/coreutils
# for a builder to run at all (`nix/guest-vm.nix`), and getting
# `BuildDerivation`/`AddToStoreNar` byte-exact against real Nix's own path
# hashing needs iterating against a live daemon, which this sandboxed build
# cannot do. A fuller build-and-NAR-round-trip test is follow-on work, not a
# gap this test pretends to cover.
#
# Needs `/dev/kvm`, same sandbox requirement as `nix/guest-vm-test.nix`.
{ stdenvNoCC, cloud-hypervisor, socat, kernel, initrd, kubernix-worker, vm-test-lib }:

stdenvNoCC.mkDerivation {
  name = "kubernix-vm-build-test";

  nativeBuildInputs = [ cloud-hypervisor socat ];
  requiredSystemFeatures = [ "kvm" ];

  dontUnpack = true;

  buildCommand = ''
    set -euo pipefail
    source ${vm-test-lib}

    console_log="$PWD/console.log"
    vsock_socket="$PWD/vsock.sock"
    store_img="$PWD/store.img"
    truncate -s 256M "$store_img"
    key=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')

    vm_boot ${kernel}/bzImage ${initrd}/initrd "$vsock_socket" "$console_log" --disk path=$store_img,image_type=raw
    ch_pid=$!
    log_pid="" # may never be set below; the trap references it either way
    trap 'kill $ch_pid $log_pid 2>/dev/null || true' EXIT

    # `guest-agent`'s `tracing` output, separate from the shared console --
    # see `nix/vm-test-lib.nix`'s `vm_stream_logs` doc comment for why. Not
    # load-bearing for the test's own pass/fail, only for reading what
    # actually happened when it doesn't -- started as soon as the vsock
    # socket file exists, not gated on `vm_wait_for_vsock` below succeeding.
    vm_wait_for_socket "$vsock_socket" && { vm_stream_logs "$vsock_socket"; log_pid=$!; }

    vm_wait_for_vsock "$vsock_socket" || { echo "guest never came up"; vm_stop "$ch_pid"; cat "$console_log"; exit 1; }

    reply=$(vm_push_key "$vsock_socket" "$key" FRESH)
    if [[ "$reply" != OK* ]]; then
      echo "FRESH key push failed: $reply"; vm_stop "$ch_pid"; cat "$console_log"; exit 1
    fi

    # `guest-agent`'s NIX_DAEMON_PORT (guest-agent/src/main.rs).
    port=620

    # `guest-agent` accepts the vsock connection immediately and only then
    # execs `nix-daemon --stdio`; `vm-smoke` itself does the CONNECT
    # handshake, so simply retry the whole smoke binary until the daemon
    # inside is far enough along to answer, rather than probing readiness
    # with a second tool first.
    ok=0
    for i in $(seq 1 5); do
      # `vm-smoke` has no internal timeout on its handshake/`query_path_info`
      # awaits -- if the guest's `nix-daemon` hangs rather than erroring
      # (vs. refusing the connection, which is what the retry loop is
      # actually for), an unwrapped call here blocks forever on the very
      # first attempt and the retry budget above never gets used.
      if timeout 5 ${kubernix-worker}/bin/vm-smoke "$vsock_socket" "$port" 2>&1 | tee smoke.log; then
        ok=1
        break
      fi
      sleep 0.2
    done

    vm_stop "$ch_pid"
    # `tee`'s process substitution is a separate, untracked child -- give its
    # last write a moment to land in $console_log before reading it back.
    sleep 0.2

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
