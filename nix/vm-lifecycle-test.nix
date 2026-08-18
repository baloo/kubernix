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
{ stdenvNoCC, cloud-hypervisor, socat, kernel, initrd }:

stdenvNoCC.mkDerivation {
  name = "kubernix-vm-lifecycle-test";

  nativeBuildInputs = [ cloud-hypervisor socat ];
  requiredSystemFeatures = [ "kvm" ];

  dontUnpack = true;

  buildCommand = ''
    set -euo pipefail

    store_img="$PWD/store.img"
    marker="kubernix-vm-lifecycle-marker"

    # Sparse, same construction `create_store_img_if_absent` uses: a logical
    # size with no real content yet.
    truncate -s 64M "$store_img"
    printf '%s' "$marker" > "$store_img.expected"
    dd if="$store_img.expected" of="$store_img" conv=notrunc status=none

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

    # Boot #1: attach the freshly created image, confirm the VM comes up
    # with the disk attached at all, then stop it. SIGKILL, not a plain
    # `kill` (SIGTERM): this guest has no ACPI/graceful-shutdown handler
    # (`guest-agent` is PID 1 with nothing else running, same as
    # `worker/src/vm.rs`'s `CloudHypervisorLauncher::stop` doc comment
    # explains), so cloud-hypervisor's own SIGTERM handling can sit waiting
    # on a shutdown the guest will never perform -- and unlike
    # `guest-vm-test.nix`'s fire-and-forget kill, this script actually
    # `wait`s for the process to exit before reusing the same disk image, so
    # a hung SIGTERM here hangs the whole test.
    vsock1="$PWD/vsock1.sock"; console1="$PWD/console1.log"
    ch1_pid=$(boot_vm "$vsock1" "$console1")
    trap 'kill -9 $ch1_pid 2>/dev/null || true' EXIT
    wait_for_vsock "$vsock1" || { echo "boot #1 never came up"; cat "$console1"; exit 1; }
    kill -9 "$ch1_pid"; wait "$ch1_pid" 2>/dev/null || true

    # Boot #2: same image, a fresh VM process -- the "evict, then reboot for
    # the same tenant" case `vm.rs`'s `ensure_vm_for` drives in production.
    vsock2="$PWD/vsock2.sock"; console2="$PWD/console2.log"
    ch2_pid=$(boot_vm "$vsock2" "$console2")
    trap 'kill -9 $ch2_pid 2>/dev/null || true' EXIT
    wait_for_vsock "$vsock2" || { echo "boot #2 never came up"; cat "$console2"; exit 1; }
    kill -9 "$ch2_pid"; wait "$ch2_pid" 2>/dev/null || true

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
