# Phase 15 Step 2: proves the one thing `worker/src/vm.rs`'s unit tests
# cannot without `/dev/kvm` -- that a real `store.img` block device survives,
# byte for byte, across a stop-and-reboot cycle of the VM it's attached to.
# `vm.rs`'s own tests cover the reuse/evict *decision* against a fake
# launcher; this covers the on-disk persistence the real launcher relies on.
#
# Does not assert anything about the image's *content* from the guest's
# perspective -- the guest doesn't format or mount anything onto it yet
# (that lands with Step 4's dm-crypt work), so this only writes a marker from
# the host side, before the disk is ever attached, and reads it back after.
#
# Needs `/dev/kvm`, same sandbox requirement as `nix/guest-vm-test.nix`.
{ stdenvNoCC, cloud-hypervisor, socat, kernel, initrd, vm-test-lib }:

stdenvNoCC.mkDerivation {
  name = "kubernix-vm-lifecycle-test";

  nativeBuildInputs = [ cloud-hypervisor socat ];
  requiredSystemFeatures = [ "kvm" ];

  dontUnpack = true;

  buildCommand = ''
    set -euo pipefail
    source ${vm-test-lib}

    store_img="$PWD/store.img"
    marker="kubernix-vm-lifecycle-marker"

    # Sparse, same construction `create_store_img_if_absent` uses: a logical
    # size with no real content yet.
    truncate -s 64M "$store_img"
    printf '%s' "$marker" > "$store_img.expected"
    dd if="$store_img.expected" of="$store_img" conv=notrunc status=none

    # Boot #1: attach the freshly created image, confirm the VM comes up
    # with the disk attached at all, then stop it. Unlike a fire-and-forget
    # kill, this script actually waits (via `vm_stop`) for the process to
    # exit before reusing the same disk image, so a hung teardown here would
    # hang the whole test.
    vsock1="$PWD/vsock1.sock"; console1="$PWD/console1.log"
    vm_boot ${kernel}/bzImage ${initrd}/initrd "$vsock1" "$console1" --disk path=$store_img,image_type=raw
    ch1_pid=$!
    log1_pid="" # may never be set below; the trap references it either way
    trap 'kill -9 $ch1_pid $log1_pid 2>/dev/null || true' EXIT
    # `guest-agent`'s `tracing` output, separate from the shared console --
    # see `nix/vm-test-lib.nix`'s `vm_stream_logs` doc comment for why.
    vm_wait_for_socket "$vsock1" && { vm_stream_logs "$vsock1"; log1_pid=$!; }
    vm_wait_for_vsock "$vsock1" || { echo "boot #1 never came up"; cat "$console1"; exit 1; }
    vm_stop "$ch1_pid"

    # Boot #2: same image, a fresh VM process -- the "evict, then reboot for
    # the same tenant" case `vm.rs`'s `ensure_vm_for` drives in production.
    vsock2="$PWD/vsock2.sock"; console2="$PWD/console2.log"
    vm_boot ${kernel}/bzImage ${initrd}/initrd "$vsock2" "$console2" --disk path=$store_img,image_type=raw
    ch2_pid=$!
    log2_pid=""
    trap 'kill -9 $ch2_pid $log2_pid 2>/dev/null || true' EXIT
    vm_wait_for_socket "$vsock2" && { vm_stream_logs "$vsock2"; log2_pid=$!; }
    vm_wait_for_vsock "$vsock2" || { echo "boot #2 never came up"; cat "$console2"; exit 1; }
    vm_stop "$ch2_pid"

    # The actual assertion: the marker written before boot #1 is still
    # exactly there after a full stop/reboot cycle -- no truncation, no
    # corruption, nothing cloud-hypervisor's virtio-blk backend touched
    # beyond what the (untouched, in this test) guest asked it to.
    if ! cmp -s <(head -c "$(stat -c%s "$store_img.expected")" "$store_img") "$store_img.expected"; then
      echo "store.img content changed across a stop/reboot cycle"
      exit 1
    fi

    echo "store.img survived a boot/stop/reboot/stop cycle unmodified"
    touch $out
  '';
}
