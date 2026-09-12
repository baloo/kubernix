# Packages `vm-encryption-test.nix`'s dm-crypt/mkfs round trip as a container
# image, so it can run on real cluster hardware instead of only under a local
# Nix build sandbox's `/dev/kvm`.
#
# Deliberately not the same derivation as `vm-encryption-test.nix`: that one
# runs *at Nix build time*, inside the build sandbox, and only ever proves the
# guest kernel/`guest-agent` pipeline itself works -- which it does, cleanly,
# at the production 8GiB size. This image runs the same round trip *at
# container runtime*, against whatever storage actually backs the pod's
# writable filesystem on a real node -- the one variable the build-sandbox
# version can't exercise, and the one still unaccounted for after ruling out
# the guest kernel/mkfs pipeline itself.
#
# Run as a Job with `devices.kubevirt.io/kvm: "1"` requested, same as
# kubernix-worker. `STORE_IMG_SIZE` (default 8G, matching
# `KUBERNIX_VM_STORE_IMG_MB` in production) and `STORE_IMG_PATH` (default
# /data/store.img -- mount whatever volume you want probed there) are both
# overridable via env, so the same image probes any size/volume without a
# rebuild.
{
  dockerTools,
  writeShellScriptBin,
  bash,
  coreutils,
  cloud-hypervisor,
  socat,
  guestVmKernel,
  guestVmInitrd,
}:

let
  probe = writeShellScriptBin "vm-encryption-probe" ''
    set -euo pipefail

    store_img="''${STORE_IMG_PATH:-/data/store.img}"
    size="''${STORE_IMG_SIZE:-8G}"
    push_key_timeout="''${PUSH_KEY_TIMEOUT:-120}"

    mkdir -p "$(dirname "$store_img")"
    rm -f "$store_img"
    echo "==> truncating $store_img to $size"
    truncate -s "$size" "$store_img"

    key=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')
    wrong_key=$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')

    # Bisection knobs, all defaulting to match production (worker/src/vm.rs)
    # exactly: SERIAL_MODE=file (vs tty), VSOCK_DIR=shared (vs tmp, i.e.
    # /tmp instead of next to store_img), IMAGE_TYPE=unset (vs raw).
    serial_mode="''${SERIAL_MODE:-file}"
    vsock_dir="''${VSOCK_DIR:-shared}"
    image_type="''${IMAGE_TYPE:-unset}"

    echo "==> knobs: serial_mode=$serial_mode vsock_dir=$vsock_dir image_type=$image_type"

    state_dir="$(dirname "$store_img")"
    if [ "$vsock_dir" = "tmp" ]; then
      run_dir=/tmp
    else
      run_dir="$state_dir"
    fi

    disk_opt="path=$store_img"
    if [ "$image_type" = "raw" ]; then
      disk_opt="$disk_opt,image_type=raw"
    fi
    disk_opt="$disk_opt''${DISK_EXTRA_OPTS:-}"

    vm_boot() {
      local vsock_socket="$1" console_log="$2"
      local serial_arg
      if [ "$serial_mode" = "tty" ]; then
        serial_arg="tty"
      else
        serial_arg="file=$console_log"
      fi
      if [ "$serial_mode" = "tty" ]; then
        cloud-hypervisor \
          --kernel /guest-vm/bzImage \
          --initramfs /guest-vm/initrd \
          --cmdline "console=ttyS0 reboot=t panic=1" \
          --cpus boot=1 \
          --memory size=768M \
          --vsock cid=3,socket="$vsock_socket" \
          --console off \
          --serial "$serial_arg" \
          --disk "$disk_opt" \
          > >(tee "$console_log") 2>&1 &
      else
        cloud-hypervisor \
          --kernel /guest-vm/bzImage \
          --initramfs /guest-vm/initrd \
          --cmdline "console=ttyS0 reboot=t panic=1" \
          --cpus boot=1 \
          --memory size=768M \
          --vsock cid=3,socket="$vsock_socket" \
          --console off \
          --serial "$serial_arg" \
          --disk "$disk_opt" \
          </dev/null >/dev/null 2>&1 &
      fi
    }

    vm_wait_for_vsock() {
      local vsock_socket="$1" port="''${2:-620}"
      for i in $(seq 1 100); do
        [ -S "$vsock_socket" ] && break
        sleep 0.1
      done
      for i in $(seq 1 100); do
        if reply=$(printf 'CONNECT %d\n' "$port" | timeout 1 socat - "UNIX-CONNECT:$vsock_socket" 2>/dev/null); then
          case "$reply" in OK*) return 0 ;; esac
        fi
        sleep 0.2
      done
      return 1
    }

    vm_push_key() {
      local vsock_socket="$1" hex_key="$2" mode="$3" port="''${4:-621}"
      printf 'CONNECT %d\nKEY %s %s\n' "$port" "$hex_key" "$mode" \
        | timeout "$push_key_timeout" socat - "UNIX-CONNECT:$vsock_socket" \
        | tail -n +2 || true
    }

    vm_stop() {
      kill "$1" 2>/dev/null || true
      wait "$1" 2>/dev/null || true
    }

    echo "==> boot #1: FRESH key push (mkfs.ext4 on $size)"
    vsock1="$run_dir/vsock1.sock"; console1="$run_dir/console1.log"
    vm_boot "$vsock1" "$console1"
    ch1=$!
    vm_wait_for_vsock "$vsock1" || { echo "boot #1 never came up"; cat "$console1"; exit 1; }
    reply1=$(vm_push_key "$vsock1" "$key" FRESH)
    vm_stop "$ch1"
    if [[ "$reply1" != OK* ]]; then
      echo "FRESH key push failed: $reply1"
      echo "==> console log:"; cat "$console1"
      exit 1
    fi
    echo "FRESH ok: $reply1"

    echo "==> boot #2: REUSE with the same key"
    vsock2="$run_dir/vsock2.sock"; console2="$run_dir/console2.log"
    rm -f "$vsock2"
    vm_boot "$vsock2" "$console2"
    ch2=$!
    vm_wait_for_vsock "$vsock2" || { echo "boot #2 never came up"; cat "$console2"; exit 1; }
    reply2=$(vm_push_key "$vsock2" "$key" REUSE)
    vm_stop "$ch2"
    if [[ "$reply2" != OK* ]]; then
      echo "REUSE with the correct key failed: $reply2"
      echo "==> console log:"; cat "$console2"
      exit 1
    fi
    echo "REUSE ok: $reply2"

    echo "==> boot #3: REUSE with the wrong key -- must be rejected"
    vsock3="$run_dir/vsock3.sock"; console3="$run_dir/console3.log"
    rm -f "$vsock3"
    vm_boot "$vsock3" "$console3"
    ch3=$!
    vm_wait_for_vsock "$vsock3" || { echo "boot #3 never came up"; cat "$console3"; exit 1; }
    reply3=$(vm_push_key "$vsock3" "$wrong_key" REUSE)
    vm_stop "$ch3"
    if [[ "$reply3" != ERR* ]]; then
      echo "REUSE with the wrong key should have failed, got: $reply3"
      echo "==> console log:"; cat "$console3"
      exit 1
    fi
    echo "wrong-key rejection ok: $reply3"

    rm -f "$store_img"
    echo "PASS: dm-crypt key handshake round-trips at $size on $(dirname "$store_img")"
  '';
in
dockerTools.buildLayeredImage {
  name = "kubernix-vm-encryption-probe";
  tag = "latest";

  extraCommands = ''
    mkdir -p guest-vm data tmp
    chmod 1777 tmp
    ln -s ${guestVmKernel}/bzImage guest-vm/bzImage
    ln -s ${guestVmInitrd}/initrd guest-vm/initrd
  '';

  contents = [
    bash
    coreutils
    cloud-hypervisor
    socat
    probe
  ];

  config = {
    Cmd = [ "${probe}/bin/vm-encryption-probe" ];
    Env = [ "PATH=/bin" ];
  };
}
