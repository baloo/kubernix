# Phase 15 Step 4: proves the guest side of the dm-crypt key handshake for
# real, against a live cloud-hypervisor VM -- `worker/src/vm.rs`'s
# `key_is_generated_fresh_and_reused_on_reboot`/`warm_vm_reuse_does_not_repush
# _the_key` tests cover the *worker's* bookkeeping against a fake launcher;
# this covers `guest-agent`'s actual `cryptsetup open`/`mkfs.ext4`/`mount`
# pipeline, which nothing else exercises without `/dev/kvm`.
#
# Drives the same `CONNECT <port>\n` / `OK` vsock handshake
# `nix/guest-vm-test.nix` uses, then speaks the control-channel protocol
# `guest-agent/src/main.rs::handle_control` implements via `vm_push_key`
# (`nix/vm-test-lib.nix`) -- `worker/src/vm.rs::push_key` is the production
# client of this same protocol -- rather than depending on `kubernix-worker`
# at all.
#
# Needs `/dev/kvm`, same sandbox requirement as `nix/guest-vm-test.nix`.
{ stdenvNoCC, cloud-hypervisor, socat, kernel, initrd, vm-test-lib }:

stdenvNoCC.mkDerivation {
  name = "kubernix-vm-encryption-test";

  nativeBuildInputs = [ cloud-hypervisor socat ];
  requiredSystemFeatures = [ "kvm" ];

  dontUnpack = true;

  buildCommand = ''
    set -euo pipefail
    source ${vm-test-lib}

    store_img="$PWD/store.img"
    truncate -s 256M "$store_img"

    key=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')
    wrong_key=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')

    # Boot #1: fresh image, FRESH key push -- mkfs.ext4 + mount.
    vsock1="$PWD/vsock1.sock"; console1="$PWD/console1.log"
    vm_boot ${kernel}/bzImage ${initrd}/initrd "$vsock1" "$console1" --disk path=$store_img,image_type=raw
    ch1_pid=$!
    log1_pid="" # may never be set below; the trap references it either way
    trap 'vm_stop $ch1_pid; kill $log1_pid 2>/dev/null || true' EXIT
    # `guest-agent`'s `tracing` output, separate from the shared console --
    # see `nix/vm-test-lib.nix`'s `vm_stream_logs` doc comment for why.
    vm_wait_for_socket "$vsock1" && { vm_stream_logs "$vsock1"; log1_pid=$!; }
    vm_wait_for_vsock "$vsock1" || { echo "boot #1 never came up"; cat "$console1"; exit 1; }
    reply1=$(vm_push_key "$vsock1" "$key" FRESH)
    vm_stop "$ch1_pid"
    if [[ "$reply1" != OK* ]]; then
      echo "FRESH key push failed: $reply1"; cat "$console1"; exit 1
    fi

    # The raw image is ciphertext now, not a plaintext ext4 filesystem: the
    # standard ext4 superblock magic (0x53ef) at byte offset 1080 should not
    # be there (this is a probabilistic check -- ~1/65536 false-positive rate
    # against random ciphertext -- not a cryptographic proof, but a real
    # plaintext mount would fail it deterministically).
    magic=$(dd if="$store_img" bs=1 skip=1080 count=2 status=none | od -An -tx1 | tr -d ' \n')
    if [ "$magic" = "53ef" ]; then
      echo "store.img looks like a plaintext ext4 filesystem -- not encrypted"
      exit 1
    fi

    # Boot #2: same image, REUSE with the *same* key -- must mount cleanly,
    # proving the ciphertext from boot #1 round-trips.
    vsock2="$PWD/vsock2.sock"; console2="$PWD/console2.log"
    vm_boot ${kernel}/bzImage ${initrd}/initrd "$vsock2" "$console2" --disk path=$store_img,image_type=raw
    ch2_pid=$!
    log2_pid=""
    trap 'vm_stop $ch2_pid; kill $log2_pid 2>/dev/null || true' EXIT
    vm_wait_for_socket "$vsock2" && { vm_stream_logs "$vsock2"; log2_pid=$!; }
    vm_wait_for_vsock "$vsock2" || { echo "boot #2 never came up"; cat "$console2"; exit 1; }
    reply2=$(vm_push_key "$vsock2" "$key" REUSE)
    vm_stop "$ch2_pid"
    if [[ "$reply2" != OK* ]]; then
      echo "REUSE with the correct key failed: $reply2"; cat "$console2"; exit 1
    fi

    # Boot #3: same image, REUSE with the *wrong* key -- plain dm-crypt has
    # no header to reject a wrong key at `cryptsetup open` time, but the
    # resulting garbage is not a valid ext4 filesystem, so the mount itself
    # must fail and guest-agent must report ERR.
    vsock3="$PWD/vsock3.sock"; console3="$PWD/console3.log"
    vm_boot ${kernel}/bzImage ${initrd}/initrd "$vsock3" "$console3" --disk path=$store_img,image_type=raw
    ch3_pid=$!
    log3_pid=""
    trap 'vm_stop $ch3_pid; kill $log3_pid 2>/dev/null || true' EXIT
    vm_wait_for_socket "$vsock3" && { vm_stream_logs "$vsock3"; log3_pid=$!; }
    vm_wait_for_vsock "$vsock3" || { echo "boot #3 never came up"; cat "$console3"; exit 1; }
    reply3=$(vm_push_key "$vsock3" "$wrong_key" REUSE)
    vm_stop "$ch3_pid"
    if [[ "$reply3" != ERR* ]]; then
      echo "REUSE with the wrong key should have failed, got: $reply3"; cat "$console3"; exit 1
    fi

    echo "dm-crypt key handshake round-trips; wrong key is rejected; store.img is opaque without the key"
    touch $out
  '';
}
