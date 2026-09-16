# Shared shell helpers for the Phase 15 guest-VM boot tests
# (`guest-vm-test.nix`, `vm-build-test.nix`, `vm-lifecycle-test.nix`,
# `vm-encryption-test.nix`). All four boot the same kernel+initrd under
# cloud-hypervisor, wait for `guest-agent`'s vsock listener the same way, and
# tear the VM down the same way -- this factors that out so a fix (the
# `--serial tty` streaming change, the SIGKILL-not-SIGTERM teardown) lands
# once instead of drifting across four copies. Each caller `source`s this
# file at the top of its `buildCommand` and calls the functions below;
# nothing here is specific to any one test.
{ writeText }:

writeText "kubernix-vm-test-lib.sh" ''
  # vm_boot <bzImage> <initrd> <vsock-socket> <console-log> [extra cloud-hypervisor args...]
  #
  # Boots <bzImage>+<initrd> under cloud-hypervisor with a legacy serial
  # console (ttyS0, not virtio-console -- it needs no guest driver beyond
  # what every x86 kernel already has built in, so even the earliest kernel
  # boot messages land here, not just guest-agent's own eprintln! output) and
  # a vsock device at <vsock-socket>. Extra args (e.g. `--disk
  # path=...,image_type=raw`) are appended as-is.
  #
  # Does NOT echo the PID -- call this directly (never as `x=$(vm_boot ...)`)
  # and read `$!` right after, in the *caller's* shell. `--serial tty`'s
  # `> >(tee "$console_log")` spawns `tee` as a grandchild that keeps holding
  # the pipe open for as long as cloud-hypervisor runs; wrapped in a command
  # substitution, that pipe IS the substitution's own stdout capture, so
  # `$(...)` blocks until `tee` exits -- i.e. until the VM exits -- before
  # returning anything at all, defeating both the live-stdout streaming this
  # exists for and the PID capture itself. Calling `vm_boot` directly avoids
  # a subshell entirely, so `&` backgrounds in the caller's own shell and
  # `$!` is available immediately without waiting on anything.
  #
  # `--serial tty` (rather than `file=`) streams the console straight into
  # this derivation's own stdout as it happens -- visible live in
  # `nix-build`'s output -- while `tee` still splits it into <console-log>
  # for callers that grep/cat it afterward.
  # `shared=on` on `--memory` below is required for vhost-user net (Phase 15
  # Step 5's `vm-network-test.nix`, which appends a `--net vhost_user=...`
  # extra arg): the backend maps the guest's memory directly, needing a
  # shared mapping cloud-hypervisor's private-by-default memory doesn't
  # provide. Harmless for every other caller of this helper -- none of them
  # care whether the mapping is shared or private.
  vm_boot() {
    local kernel="$1" initrd="$2" vsock_socket="$3" console_log="$4"
    shift 4
    cloud-hypervisor \
      --kernel "$kernel" \
      --initramfs "$initrd" \
      --cmdline "console=ttyS0 reboot=t panic=1" \
      --cpus boot=1 \
      --memory size=768M,shared=on \
      --vsock cid=3,socket="$vsock_socket" \
      --console off \
      --serial tty \
      "$@" \
      > >(tee "$console_log") 2>&1 &
  }

  # vm_wait_for_socket <vsock-socket>
  #
  # Polls for cloud-hypervisor's vsock device socket to appear -- it does
  # once the device is live, well before the guest kernel finishes booting,
  # so this alone is not "guest-agent is ready", just "dialing any port on
  # this VM won't fail outright for want of the socket file existing yet".
  # Split out from `vm_wait_for_vsock` so a caller wanting to start
  # `vm_stream_logs` as early as safely possible (rather than only after a
  # specific port answers) has something to wait on first.
  vm_wait_for_socket() {
    local vsock_socket="$1"
    for i in $(seq 1 100); do
      [ -S "$vsock_socket" ] && return 0
      sleep 0.1
    done
    return 1
  }

  # vm_wait_for_vsock <vsock-socket> [daemon-port=620]
  #
  # `vm_wait_for_socket`, then retries a `CONNECT <port>` handshake against
  # it until guest-agent answers `OK` -- covers both gaps without a fixed
  # sleep for either. Returns non-zero if either wait exhausts its budget.
  vm_wait_for_vsock() {
    local vsock_socket="$1" port="''${2:-620}"
    vm_wait_for_socket "$vsock_socket" || return 1
    local ok=0
    for i in $(seq 1 100); do
      if reply=$(printf 'CONNECT %d\n' "$port" | timeout 1 socat - "UNIX-CONNECT:$vsock_socket" 2>/dev/null); then
        case "$reply" in
          OK*) ok=1; break ;;
        esac
      fi
      sleep 0.2
    done
    [ "$ok" = 1 ]
  }

  # vm_push_key <vsock-socket> <hex-key> <FRESH|REUSE> [control-port=621]
  #
  # Speaks guest-agent's control protocol end to end over one connection:
  # CONNECT to the control port, then the KEY line -- see
  # `guest-agent/src/main.rs::handle_control` for the server side
  # (`worker/src/vm.rs::push_key` is the production client of this same
  # protocol). Prints guest-agent's reply (`OK` or `ERR ...`), which may
  # itself span multiple lines.
  #
  # `tail -n +2` (everything from line 2 on), not `-n 1` (only the last
  # line): the first line received is cloud-hypervisor's own `OK <id>\n`
  # vsock CONNECT acknowledgment, not guest-agent's reply -- skip exactly
  # that one line and keep the rest verbatim. An `ERR` reply's message can
  # itself contain embedded newlines (the failing command's own multi-line
  # stderr, joined into `handle_control`'s error chain) with a trailing
  # blank line after it, so `-n 1` previously grabbed that trailing blank
  # line instead of the reply -- every caller here already does a `case`/
  # `[[ == OK* ]]`-style *prefix* check on the result, which still works
  # correctly against a multi-line string, matching how the production
  # client (`worker/src/vm.rs::push_key`) reads the whole reply via
  # `read_to_end` and does a `starts_with` check rather than assuming one
  # line -- this was a test-script bug, not a `guest-agent` protocol one.
  #
  # Ends in `|| true`: callers run under `set -euo pipefail`, and `socat`
  # exiting non-zero here -- however cleanly `guest-agent` closed its end --
  # is not this function's failure to report, only the caller's own
  # `OK*`/`ERR*` string check on the captured reply is. Without this, a
  # non-zero `socat` exit killed the *whole script* via `pipefail` right at
  # `reply=$(vm_push_key ...)`, before the caller's own check ever ran.
  vm_push_key() {
    local vsock_socket="$1" hex_key="$2" mode="$3" port="''${4:-621}"
    printf 'CONNECT %d\nKEY %s %s\n' "$port" "$hex_key" "$mode" \
      | timeout 20 socat - "UNIX-CONNECT:$vsock_socket" \
      | tail -n +2 || true
  }

  # vm_caps <vsock-socket> [control-port=621]
  #
  # Speaks the `CAPS?` control-port verb (PLAN.md Phase 17) end to end:
  # CONNECT to the control port, then `CAPS?`, mirroring `vm_push_key` above
  # -- see that function's doc comment for why `tail -n +2` and `|| true`
  # are both needed. Prints guest-agent's reply, `OK <n>` (the count of
  # `vmx`/`svm` lines this guest itself sees in `/proc/cpuinfo`) or
  # `ERR ...`.
  vm_caps() {
    local vsock_socket="$1" port="''${2:-621}"
    printf 'CONNECT %d\nCAPS?\n' "$port" \
      | timeout 20 socat - "UNIX-CONNECT:$vsock_socket" \
      | tail -n +2 || true
  }

  # vm_status <vsock-socket> [control-port=621]
  #
  # Speaks the `STATUS?` control-port verb (PLAN.md Phase 18) end to end,
  # mirroring `vm_caps` above. Prints guest-agent's reply -- `OK NONE` /
  # `OK OOM BUILDER` / `OK OOM OTHER` / `OK ENOSPC`, or `ERR ...`.
  vm_status() {
    local vsock_socket="$1" port="''${2:-621}"
    printf 'CONNECT %d\nSTATUS?\n' "$port" \
      | timeout 20 socat - "UNIX-CONNECT:$vsock_socket" \
      | tail -n +2 || true
  }

  # vm_reset <vsock-socket> [control-port=621]
  #
  # Speaks the `RESET` control-port verb (PLAN.md Phase 18) end to end,
  # mirroring `vm_caps` above. Prints guest-agent's reply, `OK` or `ERR ...`.
  vm_reset() {
    local vsock_socket="$1" port="''${2:-621}"
    printf 'CONNECT %d\nRESET\n' "$port" \
      | timeout 20 socat - "UNIX-CONNECT:$vsock_socket" \
      | tail -n +2 || true
  }

  # vm_stream_logs <vsock-socket> [log-port=622]
  #
  # Dials `guest-agent`'s debug log-stream port (`LOG_PORT`,
  # `guest-agent/src/main.rs`) and relays whatever it sends straight to this
  # derivation's own stdout -- separate from, and cleaner than, the shared
  # `--serial tty` console (which also carries raw kernel boot messages and
  # every spawned child's inherited stderr). Backgrounds `socat`; same
  # calling convention as `vm_boot` (call directly, read `$!` right after,
  # never `x=$(vm_stream_logs ...)`) since there's no live-streaming purpose
  # to a helper whose output only surfaces once it's done.
  #
  # `printf`'s pipe closing (EOF on socat's stdin after the one `CONNECT`
  # line) does not close the connection -- only that one direction -- so
  # `socat` keeps relaying whatever the guest sends until it's killed.
  #
  # Retries its own `CONNECT` every 0.2s until it succeeds: `vm_wait_for_socket`
  # only proves cloud-hypervisor's *host-side* vsock device socket exists,
  # not that the guest kernel has booted far enough for `guest-agent` to have
  # bound `LOG_PORT` yet -- calling this right after `vm_wait_for_socket`
  # (rather than only after `vm_wait_for_vsock`/`vm_push_key` have already
  # proven the guest fully up) means that race is real, and a single failed
  # `CONNECT` used to just make the whole backgrounded job exit immediately
  # with nothing ever streamed, silently -- found by every log-stream call
  # site coming up empty even on otherwise-successful boots.
  vm_stream_logs() {
    local vsock_socket="$1" port="''${2:-622}"
    (
      for i in $(seq 1 100); do
        printf 'CONNECT %d\n' "$port" | socat - "UNIX-CONNECT:$vsock_socket" && break
        sleep 0.2
      done
    ) &
  }

  # vm_stop <pid>
  #
  # SIGKILL, not a plain `kill` (SIGTERM): this guest has no ACPI/graceful-
  # shutdown handler -- `guest-agent` is PID 1 with nothing else running (see
  # `worker/src/vm.rs`'s `CloudHypervisorLauncher::stop` doc comment) -- so
  # cloud-hypervisor's own SIGTERM handling can sit waiting on a shutdown the
  # guest will never perform, hanging whatever `wait`s on it next. Actually
  # waits for the process to exit before returning, so a caller reusing the
  # same disk image right after never races the kernel's own writeback.
  vm_stop() {
    local pid="$1"
    kill -9 "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  }
''
