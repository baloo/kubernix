# PLAN.md Phase 17: proves the guest side of the `CAPS?` control-port verb
# for real, against a live cloud-hypervisor VM -- unit tests
# (`guest-agent/src/main.rs`'s `count_nested_virt_flags_str`/`dispatch_control`
# tests) cover the parsing and dispatch logic against fixtures; this covers
# the actual wire round trip and a real `/proc/cpuinfo` inside the guest,
# which nothing else exercises without `/dev/kvm`.
#
# Drives the same `CONNECT <port>\n` / `OK` vsock handshake
# `nix/guest-vm-test.nix` uses, then speaks the control-channel protocol
# `guest-agent/src/main.rs::handle_control` implements via `vm_caps`
# (`nix/vm-test-lib.nix`) -- `worker/src/vm.rs::boot_probe` is the production
# client of this same verb -- rather than depending on `kubernix-worker` at
# all.
#
# Needs `/dev/kvm`, same sandbox requirement as `nix/guest-vm-test.nix`: the
# guest's own `/proc/cpuinfo` only shows `vmx`/`svm` flags when
# cloud-hypervisor is actually running on top of real hardware
# virtualization, so this test's positive assertion (`n >= 1`) is itself a
# real proof that nested virt reaches the guest, not just a protocol check.
{ stdenvNoCC, cloud-hypervisor, socat, kernel, initrd, vm-test-lib }:

stdenvNoCC.mkDerivation {
  name = "kubernix-vm-caps-test";

  nativeBuildInputs = [ cloud-hypervisor socat ];
  requiredSystemFeatures = [ "kvm" ];

  dontUnpack = true;

  buildCommand = ''
    set -euo pipefail
    source ${vm-test-lib}

    vsock="$PWD/vsock.sock"; console="$PWD/console.log"
    vm_boot ${kernel}/bzImage ${initrd}/initrd "$vsock" "$console"
    ch_pid=$!
    log_pid=""
    trap 'vm_stop $ch_pid; kill $log_pid 2>/dev/null || true' EXIT
    vm_wait_for_socket "$vsock" && { vm_stream_logs "$vsock"; log_pid=$!; }
    vm_wait_for_vsock "$vsock" || { echo "boot never came up"; cat "$console"; exit 1; }

    reply=$(vm_caps "$vsock")
    vm_stop "$ch_pid"

    if [[ "$reply" != OK\ * ]]; then
      echo "CAPS? failed: $reply"; cat "$console"; exit 1
    fi
    count="''${reply#OK }"
    if ! [[ "$count" =~ ^[0-9]+$ ]]; then
      echo "CAPS? reply did not carry a decimal count: $reply"; exit 1
    fi
    if [ "$count" -lt 1 ]; then
      echo "CAPS? reported 0 vmx/svm flags -- nested virt not reaching the guest: $reply"
      exit 1
    fi

    echo "CAPS? round-trips over the control port; guest sees $count vmx/svm flag(s)"
    touch $out
  '';
}
