# PLAN.md Phase 18: proves the eBPF ENOSPC-detection mechanism actually
# fires against a real disk-exhaustion failure on a real booted guest --
# `guest-agent`'s diagnostic-only `TRIGGER_ENOSPC` control verb
# (`guest-agent/src/diag.rs::fill_store`) writes to a file under
# `/nix/store` past `store.img`'s available capacity, in a loop, and never
# calls `fsync`/`fdatasync` before the file closes.
#
# Found by booting: a first version of this test, and the design this phase
# started with, assumed the interesting case was `write()` succeeding while
# an *async* background-writeback failure gets silently swallowed by
# `close()` -- the `errseq_set()` kprobe alone. Running this for real
# against this guest's ext4/kernel combination showed the opposite is the
# common case: ext4's own delayed-allocation reservation
# (`ext4_da_reserve_space`) catches a disk-full write *synchronously* far
# more often, returning `-ENOSPC` straight from `write(2)` without ever
# reaching `errseq_set` at all. `guest-agent-ebpf` now has a second,
# complementary hook (a `kretprobe` on `vfs_write`) for exactly that case --
# this test is what confirms *both* actually fire on real disk exhaustion,
# not just that they attach (`nix/vm-status-test.nix` already proved that).
#
# Needs a real mounted store, so this reuses `nix/vm-build-test.nix`'s
# store.img/FRESH-key setup (`vm_push_key`) as a precondition, not something
# this test itself asserts about.
#
# `store_img` is small (64M) on purpose -- large enough for the guest's own
# `mkfs.ext4`/overlay bookkeeping, small enough that `fill_store`'s bounded
# write loop reliably exhausts it well within its own iteration cap.
#
# Needs `/dev/kvm`, same sandbox requirement as `nix/guest-vm-test.nix`.
{ stdenvNoCC, cloud-hypervisor, socat, kernel, initrd, vm-test-lib }:

stdenvNoCC.mkDerivation {
  name = "kubernix-vm-enospc-test";

  nativeBuildInputs = [ cloud-hypervisor socat ];
  requiredSystemFeatures = [ "kvm" ];

  dontUnpack = true;

  buildCommand = ''
    set -euo pipefail
    source ${vm-test-lib}

    vsock="$PWD/vsock.sock"; console="$PWD/console.log"
    store_img="$PWD/store.img"
    truncate -s 64M "$store_img"
    key=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')

    vm_boot ${kernel}/bzImage ${initrd}/initrd "$vsock" "$console" --disk path=$store_img,image_type=raw
    ch_pid=$!
    log_pid=""
    trap 'vm_stop $ch_pid; kill $log_pid 2>/dev/null || true' EXIT
    vm_wait_for_socket "$vsock" && { vm_stream_logs "$vsock"; log_pid=$!; }
    vm_wait_for_vsock "$vsock" || { echo "boot never came up"; cat "$console"; exit 1; }

    key_reply=$(vm_push_key "$vsock" "$key" FRESH)
    if [[ "$key_reply" != OK* ]]; then
      echo "FRESH key push failed: $key_reply"; cat "$console"; exit 1
    fi

    baseline=$(vm_status "$vsock")
    if [[ "$baseline" != "OK NONE" ]]; then
      echo "STATUS? before triggering anything: expected 'OK NONE', got: $baseline"
      cat "$console"; exit 1
    fi

    trigger_reply=$(vm_trigger_enospc "$vsock")
    if [[ "$trigger_reply" != OK* ]]; then
      echo "TRIGGER_ENOSPC failed: $trigger_reply"; cat "$console"; exit 1
    fi

    # Background writeback can lag slightly behind TRIGGER_ENOSPC's own
    # return -- poll a little, same shape as nix/vm-oom-test.nix.
    status="OK NONE"
    for i in $(seq 1 150); do
      status=$(vm_status "$vsock")
      if [[ "$status" != "OK NONE" ]]; then break; fi
      sleep 0.2
    done

    vm_stop "$ch_pid"

    if [[ "$status" != "OK ENOSPC" ]]; then
      echo "STATUS? after TRIGGER_ENOSPC: expected 'OK ENOSPC', got: $status"
      cat "$console"
      exit 1
    fi

    echo "the eBPF ENOSPC detection (vfs_write_ret and/or errseq_set) fired on a real disk-exhaustion failure"
    touch $out
  '';
}
