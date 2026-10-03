# Regression test for the guest's `/nix/var/nix/db` persistence fix
# (`guest-agent/src/main.rs::mount_store`): without that fix, `/nix/var` is
# plain tmpfs, so Nix's path-validity SQLite database is wiped on every VM
# boot even though the store's actual file contents (the overlay upper dir
# on `store.img`) persist. The worker's own `skip_already_valid` /
# `vm_ops::path_is_valid` (`worker/src/main.rs`) then re-downloads and
# re-registers inputs whose bytes are already on disk, on every reboot for a
# tenant -- the bug this test exists to catch.
#
# Same FRESH-then-REUSE two-boot shape as `nix/vm-encryption-test.nix`, but
# drives the real daemon port (620) instead of only the control port:
#   1. Boot #1 (FRESH): register one real path via `Op::AddToStoreNar`, and
#      confirm it's valid within that same boot (sanity check).
#   2. Boot #2 (REUSE, same `store.img`): confirm the *same* path is still
#      valid, with NO re-registration. This is the assertion that fails
#      before the fix (an empty validity DB after reboot) and passes after.
#
# Needs `/dev/kvm`, same sandbox requirement as `nix/guest-vm-test.nix`.
{ stdenvNoCC, nix, cloud-hypervisor, socat, kernel, initrd, kubernix-worker, vm-test-lib }:

stdenvNoCC.mkDerivation {
  name = "kubernix-vm-db-persistence-test";

  nativeBuildInputs = [ nix cloud-hypervisor socat ];
  requiredSystemFeatures = [ "kvm" ];

  dontUnpack = true;

  buildCommand = ''
    set -euo pipefail
    source ${vm-test-lib}

    store_img="$PWD/store.img"
    truncate -s 256M "$store_img"
    key=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')

    # A real NAR for a trivial, synthetic leaf path -- `nix-store --dump`
    # serializes any filesystem path, store member or not, so this needs no
    # access to a writable store. The path string itself is never derived
    # from this content (this path registers as input-addressed, `ca =
    # none`, same trust model `worker/src/vm_ops.rs::register_input` uses
    # for worker-fetched inputs) -- only `nar_hash` has to match the bytes
    # actually streamed, which is exactly what's computed below.
    echo -n "kubernix-db-persistence-test-payload" > "$PWD/payload"
    nix-store --dump "$PWD/payload" > "$PWD/payload.nar"
    nar_hash="sha256:$(sha256sum "$PWD/payload.nar" | cut -d' ' -f1)"
    nar_size=$(wc -c < "$PWD/payload.nar")
    store_path="/nix/store/11111111111111111111111111111111-kubernix-db-persistence-test"

    smoke=${kubernix-worker}/bin/vm-db-persistence-smoke

    # Boot #1: FRESH image, register the path, confirm valid in this boot.
    vsock1="$PWD/vsock1.sock"; console1="$PWD/console1.log"
    vm_boot ${kernel}/bzImage ${initrd}/initrd "$vsock1" "$console1" --disk path=$store_img,image_type=raw
    ch1_pid=$!
    log1_pid=""
    trap 'kill $ch1_pid $log1_pid 2>/dev/null || true' EXIT
    vm_wait_for_socket "$vsock1" && { vm_stream_logs "$vsock1"; log1_pid=$!; }
    vm_wait_for_vsock "$vsock1" || { echo "boot #1 never came up"; vm_stop "$ch1_pid"; cat "$console1"; exit 1; }

    reply1=$(vm_push_key "$vsock1" "$key" FRESH)
    if [[ "$reply1" != OK* ]]; then
      echo "FRESH key push failed: $reply1"; vm_stop "$ch1_pid"; cat "$console1"; exit 1
    fi

    port=620
    ok1=0
    for i in $(seq 1 5); do
      if timeout 10 "$smoke" "$vsock1" "$port" register "$store_path" "$PWD/payload.nar" "$nar_hash" "$nar_size" 2>&1 | tee register.log; then
        ok1=1
        break
      fi
      sleep 0.2
    done
    echo "==> boot #1 (register) output:"; cat register.log || true
    if [ "$ok1" != 1 ]; then
      vm_stop "$ch1_pid"
      echo "registering $store_path on boot #1 failed"; cat "$console1"; exit 1
    fi

    # `vm_stop`'s own doc comment only guarantees the *host*-side
    # cloud-hypervisor process has exited before the same store.img is
    # reused -- it says nothing about the *guest* kernel's own dirty-page
    # writeback for the ext4 filesystem it just wrote the registration into,
    # and an idle guest's periodic flusher is timer/workqueue-driven, so a
    # plain `sleep` on the *host* with nothing happening in the *guest*
    # doesn't reliably give it a chance to run. A handful of extra,
    # throwaway connections (each spawning a fresh `nix-daemon`, each doing
    # real scheduling/IO) exercises the guest for real instead of guessing
    # at a sleep long enough to cover a passively idle kernel's own timers.
    # Crucially, this has to run *before* `vm_stop` below, while boot #1 is
    # still alive -- a connection attempt against an already-killed VM is a
    # silent no-op, not a wait.
    for i in $(seq 1 10); do
      timeout 5 "$smoke" "$vsock1" "$port" check "$store_path" >/dev/null 2>&1 || true
      sleep 0.3
    done

    vm_stop "$ch1_pid"
    sleep 0.2

    # Boot #2: REUSE the same store.img, check validity with NO re-registration.
    vsock2="$PWD/vsock2.sock"; console2="$PWD/console2.log"
    vm_boot ${kernel}/bzImage ${initrd}/initrd "$vsock2" "$console2" --disk path=$store_img,image_type=raw
    ch2_pid=$!
    log2_pid=""
    trap 'kill $ch2_pid $log2_pid 2>/dev/null || true' EXIT
    vm_wait_for_socket "$vsock2" && { vm_stream_logs "$vsock2"; log2_pid=$!; }
    vm_wait_for_vsock "$vsock2" || { echo "boot #2 never came up"; vm_stop "$ch2_pid"; cat "$console2"; exit 1; }

    reply2=$(vm_push_key "$vsock2" "$key" REUSE)
    if [[ "$reply2" != OK* ]]; then
      echo "REUSE key push failed: $reply2"; vm_stop "$ch2_pid"; cat "$console2"; exit 1
    fi

    ok2=0
    for i in $(seq 1 5); do
      if timeout 10 "$smoke" "$vsock2" "$port" check "$store_path" 2>&1 | tee check.log; then
        ok2=1
        break
      fi
      sleep 0.2
    done
    vm_stop "$ch2_pid"
    sleep 0.2

    echo "==> boot #2 (check) output:"; cat check.log || true
    echo "==> console log (boot #2):"; cat "$console2" || true

    if [ "$ok2" != 1 ]; then
      echo "$store_path did not survive the reboot as valid -- /nix/var/nix/db did not persist"
      exit 1
    fi

    echo "a path registered on one boot stays valid across a reboot of the same store.img"
    touch $out
  '';
}
