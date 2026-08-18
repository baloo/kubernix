# Phase 15 Step 4: proves the guest side of the dm-crypt key handshake for
# real, against a live cloud-hypervisor VM -- `worker/src/vm.rs`'s
# `key_is_generated_fresh_and_reused_on_reboot`/`warm_vm_reuse_does_not_repush
# _the_key` tests cover the *worker's* bookkeeping against a fake launcher;
# this covers `guest-agent`'s actual `cryptsetup open`/`mkfs.ext4`/`mount`
# pipeline, which nothing else exercises without `/dev/kvm`.
#
# Drives the same `CONNECT <port>\n` / `OK` vsock handshake
# `nix/guest-vm-test.nix` uses, then speaks the control-channel protocol
# `guest-agent/src/main.rs::handle_control` implements directly with `socat`
# (`worker/src/vm.rs::push_key` is the production client of this same
# protocol) rather than depending on `kubernix-worker` at all.
#
# Needs `/dev/kvm`, same sandbox requirement as `nix/guest-vm-test.nix`.
{ stdenvNoCC, cloud-hypervisor, socat, kernel, initrd }:

stdenvNoCC.mkDerivation {
  name = "kubernix-vm-encryption-test";

  nativeBuildInputs = [ cloud-hypervisor socat ];
  requiredSystemFeatures = [ "kvm" ];

  dontUnpack = true;

  buildCommand = ''
    set -euo pipefail

    store_img="$PWD/store.img"
    truncate -s 256M "$store_img"

    boot_vm() {
      local vsock_socket="$1" console_log="$2"
      cloud-hypervisor \
        --kernel ${kernel}/bzImage \
        --initramfs ${initrd}/initrd \
        --cmdline "console=ttyS0 reboot=t panic=1" \
        --cpus boot=1 \
        --memory size=768M \
        --vsock cid=3,socket=$vsock_socket \
        --disk path=$store_img,image_type=raw \
        --console off \
        --serial file=$console_log \
        &
      echo $!
    }

    wait_for_vsock() {
      local vsock_socket="$1"
      for i in $(seq 1 100); do
        [ -S "$vsock_socket" ] && break
        sleep 0.1
      done
      [ -S "$vsock_socket" ]
      local ok=0
      for i in $(seq 1 100); do
        if reply=$(printf 'CONNECT 620\n' | timeout 1 socat - "UNIX-CONNECT:$vsock_socket" 2>/dev/null); then
          case "$reply" in
            OK*) ok=1; break ;;
          esac
        fi
        sleep 0.2
      done
      [ "$ok" = 1 ]
    }

    # Speaks the control protocol end to end: CONNECT to the control port,
    # then the KEY line, over the same still-open socat connection --
    # exactly the two-step handshake `worker/src/vm.rs::push_key` drives.
    # Prints guest-agent's final reply line (`OK` or `ERR ...`).
    push_key() {
      local vsock_socket="$1" hex_key="$2" mode="$3"
      printf 'CONNECT 621\nKEY %s %s\n' "$hex_key" "$mode" \
        | timeout 5 socat - "UNIX-CONNECT:$vsock_socket" \
        | tail -n 1
    }

    # SIGKILL, not a plain `kill` (SIGTERM): this guest has no ACPI/
    # graceful-shutdown handler (`guest-agent` is PID 1, nothing else runs in
    # the guest -- see `worker/src/vm.rs`'s `CloudHypervisorLauncher::stop`
    # doc comment), so cloud-hypervisor's SIGTERM handling can sit waiting on
    # a shutdown the guest will never perform, and this function's own `wait`
    # would then hang the whole test rather than just this one boot.
    stop_vm() {
      local pid="$1"
      kill -9 "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    }

    key=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')
    wrong_key=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')

    # Boot #1: fresh image, FRESH key push -- mkfs.ext4 + mount.
    vsock1="$PWD/vsock1.sock"; console1="$PWD/console1.log"
    ch1_pid=$(boot_vm "$vsock1" "$console1")
    trap 'stop_vm $ch1_pid' EXIT
    wait_for_vsock "$vsock1" || { echo "boot #1 never came up"; cat "$console1"; exit 1; }
    reply1=$(push_key "$vsock1" "$key" FRESH)
    stop_vm "$ch1_pid"
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
    ch2_pid=$(boot_vm "$vsock2" "$console2")
    trap 'stop_vm $ch2_pid' EXIT
    wait_for_vsock "$vsock2" || { echo "boot #2 never came up"; cat "$console2"; exit 1; }
    reply2=$(push_key "$vsock2" "$key" REUSE)
    stop_vm "$ch2_pid"
    if [[ "$reply2" != OK* ]]; then
      echo "REUSE with the correct key failed: $reply2"; cat "$console2"; exit 1
    fi

    # Boot #3: same image, REUSE with the *wrong* key -- plain dm-crypt has
    # no header to reject a wrong key at `cryptsetup open` time, but the
    # resulting garbage is not a valid ext4 filesystem, so the mount itself
    # must fail and guest-agent must report ERR.
    vsock3="$PWD/vsock3.sock"; console3="$PWD/console3.log"
    ch3_pid=$(boot_vm "$vsock3" "$console3")
    trap 'stop_vm $ch3_pid' EXIT
    wait_for_vsock "$vsock3" || { echo "boot #3 never came up"; cat "$console3"; exit 1; }
    reply3=$(push_key "$vsock3" "$wrong_key" REUSE)
    stop_vm "$ch3_pid"
    if [[ "$reply3" != ERR* ]]; then
      echo "REUSE with the wrong key should have failed, got: $reply3"; cat "$console3"; exit 1
    fi

    echo "dm-crypt key handshake round-trips; wrong key is rejected; store.img is opaque without the key"
    touch $out
  '';
}
