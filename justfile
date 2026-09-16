# Kubernix development commands.

# The pieces:
#   plugin          Lix client plugin, registers the `kubernix://` store scheme
#   kubernix-sshd   SSH frontend: terminates SSH, serves the daemon protocol
#   kubernix-stdio  same protocol on stdin/stdout, for testing without SSH
#   kubernix-worker dequeues jobs, builds, streams logs back
#   kubernix-server binary cache: narinfo, NARs and logs over HTTP
#
# A full local stack, one per shell:
#
#   just nats        message queue
#   just run-db      PostgreSQL   (prints the DATABASE_URL it serves)
#   just s3-mock     object store
#   just sshd        SSH frontend  — needs all three of the above
#   just worker      builder       — needs nats and s3-mock
#   just cache       binary cache  — optional, needs the db and s3-mock
#
# Then `just demo` drives a build through the whole thing.

lix_source := env_var_or_default("KUBERNIX_LIX_SOURCE", "/home/baloo/dev/lix")
nats_url := env_var_or_default("NATS_URL", "nats://127.0.0.1:4222")
ssh_port := env_var_or_default("KUBERNIX_SSH_PORT", "2222")
host_key := env_var_or_default("TMPDIR", "/tmp") / "kubernix_host_ed25519"

# Matches what `just run-db` serves. Override to point at another database.
#
# A privileged/superuser URL, deliberately -- `postgres`, matching `run-db`'s
# own bootstrap user. `PostgresStore::connect` uses it twice: once as-is to
# run migrations (which create the `kubernix_app`/`kubernix_gc` roles and
# their row-level-security policies -- see
# `server/migrations/20260814120000_row_level_security.sql`), then again
# with only the username swapped, to open the actual serving pool under
# whichever of those two roles the connecting binary is. `run-db`'s trust
# auth accepts any role name with no password, so nothing else here needs to
# change to make that swap work.
database_url := env_var_or_default("DATABASE_URL", "postgres://postgres@127.0.0.1:5433/kubernix")

# Matches what `just s3-mock` serves. The frontend and the cache hold these;
# workers never do -- they get pre-signed URLs instead.
s3_endpoint := env_var_or_default("AWS_ENDPOINT_URL", "http://127.0.0.1:9000")
s3_key := env_var_or_default("AWS_ACCESS_KEY_ID", "my-dev-key")
s3_secret := env_var_or_default("AWS_SECRET_ACCESS_KEY", "my-dev-secret")
s3_bucket := env_var_or_default("S3_BUCKET", "kubernix")

# List available commands.
default:
    @just --list

# ---------------------------------------------------------------- build & test

# Build everything: Rust workspace and the Lix plugin.
build: build-rust plugin

# Build the Rust workspace.
build-rust:
    cargo build --workspace

# Run the test suite. The database-backed tests skip unless a DB is reachable.
test:
    cargo test --workspace

# Run the test suite including the PostgreSQL-backed store tests.
# Needs `just run-db` in another shell.
test-db port="5433" db_name="kubernix":
    KUBERNIX_TEST_DATABASE_URL="postgres://postgres@127.0.0.1:{{port}}/{{db_name}}" \
      cargo test --workspace

# Lint and format check.
check:
    cargo clippy --workspace --all-targets
    cargo fmt --check

# Build the Lix client plugin.
plugin lix_src=lix_source:
    #!/usr/bin/env bash
    set -euo pipefail
    # Only the *package* is needed now — the Lix source tree was required solely
    # to regenerate headers Lix did not install, which it now does (NOTES.md
    # items 1-3). `lix_src` here just locates the pkgconfig of a locally built
    # Lix; a system-installed one needs no override at all.
    export PKG_CONFIG_PATH="${PKG_CONFIG_PATH:-}:{{lix_src}}/outputs/out/lib/pkgconfig"
    # Test for build.ninja, not the directory: a failed `meson setup` leaves the
    # directory behind, and ninja then silently re-runs a broken setup.
    if [ ! -f plugin/build/build.ninja ]; then
        rm -rf plugin/build
        CXX=clang++ meson setup plugin/build plugin
    fi
    ninja -C plugin/build

# Build the Nix packages (server, worker, plugin, guest-agent).
nix-build:
    nix-build nix -A kubernix-server -A kubernix-worker -A kubernix-plugin -A kubernix-guest-agent

# Build the two OCI images `charts/kubernix/` deploys (nix/images.nix):
# kubernix-server (sshd/cache/gc/rotate, one image) and kubernix-worker, as
# `./result-server-image`/`./result-worker-image`. `docker load < result-
# server-image` to load either locally; `just image-push` reuses these same
# two outputs to skip straight to a registry instead.
image-build:
    nix-build nix -A kubernix-server-image -o result-server-image
    nix-build nix -A kubernix-worker-image -o result-worker-image

# Push the images `image-build` produces to `registry` without a local Docker
# daemon (skopeo copies straight from the Nix-built tarball). `tag` applies
# to both.
image-push registry tag="latest": image-build
    #!/usr/bin/env bash
    set -euo pipefail
    # skopeo refuses to run without a trust policy at all (not just one that
    # permits everything) — a minimal `insecureAcceptAnything` one, scoped to
    # this invocation rather than written into ~/.config, since we don't
    # verify image signatures either way.
    policy=$(mktemp)
    trap 'rm -f "$policy"' EXIT
    echo '{"default": [{"type": "insecureAcceptAnything"}]}' > "$policy"
    skopeo --policy "$policy" copy docker-archive:result-server-image docker://{{registry}}/kubernix-server:{{tag}}
    skopeo --policy "$policy" copy docker-archive:result-worker-image docker://{{registry}}/kubernix-worker:{{tag}}

# Run the NixOS integration test.
nix-test:
    nix-build nix -A test

# Phase 15 Step 1: boot the guest-vm kernel+initrd standalone under
# cloud-hypervisor and confirm guest-agent accepts a vsock connection. Needs
# /dev/kvm -- see nix/guest-vm-test.nix for the sandbox config that requires.
nix-test-guest-vm:
    nix-build nix -A guest-vm-test

# Phase 15 Step 2: confirm a store.img block device survives a real
# cloud-hypervisor stop/reboot cycle unmodified. Needs /dev/kvm, same as
# nix-test-guest-vm.
nix-test-vm-lifecycle:
    nix-build nix -A vm-lifecycle-test

# Phase 15 Step 3: drive kubernix_daemon_protocol's real handshake and a
# QueryPathInfo round trip against a real nix-daemon inside the guest VM.
# Needs /dev/kvm, same as nix-test-guest-vm.
nix-test-vm-build:
    nix-build nix -A vm-build-test

# Phase 15 Step 4: drive the dm-crypt key handshake against a real guest --
# FRESH mkfs+mount, REUSE with the same key, REUSE rejected with a wrong key,
# and store.img is opaque on the host without the key. Needs /dev/kvm, same
# as nix-test-guest-vm.
nix-test-vm-encryption:
    nix-build nix -A vm-encryption-test

# Phase 15 Step 5: boot the guest against a real `passt` vhost-user backend
# (the same `--net vhost_user=...,vhost_mode=client` wiring
# `worker/src/vm.rs` drives in production) and confirm guest-agent brings up
# its network interface. Needs /dev/kvm, same as nix-test-guest-vm.
nix-test-vm-network:
    nix-build nix -A vm-network-test

# PLAN.md Phase 17: drive the CAPS? control-port verb against a real guest
# and confirm it reports real nested-virt support (vmx/svm flags visible
# from inside the guest itself). Needs /dev/kvm, same as nix-test-guest-vm.
nix-test-vm-caps:
    nix-build nix -A vm-caps-test

# Remove build artifacts.
clean:
    cargo clean
    rm -rf plugin/build

# ---------------------------------------------------------------- run services

# SSH frontend: terminates SSH and serves the daemon protocol.
sshd port=ssh_port:
    #!/usr/bin/env bash
    set -euo pipefail
    # Needs all three dependencies:
    #   nats     - without it builds are refused rather than faked
    #   s3-mock  - the uploader is configured inside the NATS branch, so without
    #              S3 there is nowhere to stage inputs and workers get no upload
    #              URLs; builds then fail at artifact upload
    #   run-db   - startup fails outright if DATABASE_URL is set but unreachable,
    #              which is deliberate: silently forgetting every path on restart
    #              is worse than refusing to start
    #
    # Auth is permissive unless KUBERNIX_SSH_AUTHORIZED_KEYS points at a keys
    # file, so every tenant here is derived from the username.
    export AWS_ACCESS_KEY_ID="{{s3_key}}"
    export AWS_SECRET_ACCESS_KEY="{{s3_secret}}"
    export AWS_ENDPOINT_URL="{{s3_endpoint}}"
    export AWS_REGION=us-east-1
    export S3_BUCKET="{{s3_bucket}}"
    export DATABASE_URL="{{database_url}}"
    NATS_URL="{{nats_url}}" \
    KUBERNIX_SSH_LISTEN="127.0.0.1:{{port}}" \
    KUBERNIX_SSH_HOST_KEY="{{host_key}}" \
    cargo run -p kubernix-server --bin kubernix-sshd

# Worker: dequeues one job at a time and builds it into its own chroot store.
worker system="x86_64-linux" store="local?root=/tmp/kubernix-worker":
    #!/usr/bin/env bash
    set -euo pipefail
    # A store of its own, not the host's /nix/store, for two reasons.
    #
    # It makes a demo mean something: an output appearing there can only have
    # been built there, and an input can only have arrived through kubernix.
    #
    # And it is what lets builds work at all as a non-root user. Builds go
    # through `nix-store --serve`'s BuildDerivation, which a Nix *daemon*
    # refuses for input-addressed derivations unless you are a trusted user:
    #
    #   error: you are not privileged to build input-addressed derivations
    #
    # Opening a store directly makes the worker the authority rather than a
    # client of one. Pass store="" to use the host store, which then needs the
    # worker to be a trusted user.
    export NATS_URL="{{nats_url}}" NIX_SYSTEM="{{system}}"
    if [ -n "{{store}}" ]; then
        export KUBERNIX_NIX_STORE="{{store}}"
    fi
    cargo run -p kubernix-worker

# Binary cache: serves narinfo, NARs and logs under a /<tenant>/ prefix.
cache port="3000":
    #!/usr/bin/env bash
    set -euo pipefail
    # Reads only. Needs the same database and bucket the frontend writes to;
    export DATABASE_URL="{{database_url}}"
    export AWS_ACCESS_KEY_ID=my-dev-key
    export AWS_SECRET_ACCESS_KEY=my-dev-secret
    export AWS_ENDPOINT_URL="http://localhost:9000"
    export AWS_REGION=us-east-1
    export S3_BUCKET=kubernix
    export KUBERNIX_HTTP_LISTEN="127.0.0.1:{{port}}"
    cargo run -p kubernix-server --bin kubernix-server

# ------------------------------------------------------------------- exercises

# Handshake against kubernix-stdio, no SSH involved. Fastest feedback loop.
handshake: plugin
    #!/usr/bin/env bash
    set -euo pipefail
    # `localhost` triggers Lix's fakeSSH path, which runs the remote program under
    # `bash -c` instead of ssh.
    cargo build -p kubernix-server --bin kubernix-stdio
    nix --plugin-files "$PWD/plugin/build/kubernix.so" \
        store ping --store "kubernix://localhost?remote-program=$PWD/target/debug/kubernix-stdio"

# Handshake over real SSH. Requires `just sshd` running in another shell.
ssh-handshake port=ssh_port user=`whoami`: plugin
    #!/usr/bin/env bash
    set -euo pipefail
    # NB: the port is a `?port=` store parameter. `kubernix://host:2222` is NOT
    # parsed as a port -- the whole string goes to ssh as a hostname, and the
    # failure looks like an unrelated connection reset.
    export NIX_SSHOPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes"
    nix --plugin-files "$PWD/plugin/build/kubernix.so" \
        store ping --store "kubernix://{{user}}@127.0.0.1?port={{port}}"

# Copy a path into the frontend store and read it back out.
copy-roundtrip port=ssh_port user=`whoami`: plugin
    #!/usr/bin/env bash
    set -euo pipefail
    # Exercises addToStoreNar and narFromPath in both directions.
    export NIX_SSHOPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes"
    store="kubernix://{{user}}@127.0.0.1?port={{port}}"
    plugin="$PWD/plugin/build/kubernix.so"

    tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
    echo "hello kubernix" > "$tmp/testfile.txt"
    path=$(nix-store --add "$tmp/testfile.txt")
    echo "==> $path"

    nix --plugin-files "$plugin" copy --to "$store" "$path" --no-check-sigs
    nix --plugin-files "$plugin" path-info --store "$store" "$path"
    echo "==> contents from the frontend:"
    nix --plugin-files "$plugin" store cat --store "$store" "$path"

# Drive a real build through the job queue, with logs streaming back.
demo port=ssh_port user=`whoami`: plugin
    #!/usr/bin/env bash
    set -euo pipefail
    # Needs `just nats`, `just run-db`, `just s3-mock`, `just sshd` and
    # `just worker` running.
    export NIX_SSHOPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes"

    # A fresh client store each run, so the build actually happens instead of
    # being reported already-valid from a previous run.
    tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

    # Two derivations, not one: the consumer depends on the *output* of the
    # other, so what reaches the worker is a resolved derivation. That is the
    # case that used to fail, and a single leaf derivation would not exercise it.
    cat > "$tmp/example.nix" <<'NIX'
    let dep = derivation {
          name = "kubernix-dep";
          system = "x86_64-linux";
          builder = "/bin/sh";
          args = [ "-c" "echo building the dependency; echo depvalue > $out" ];
        };
    in derivation {
      name = "kubernix-hello";
      system = "x86_64-linux";
      builder = "/bin/sh";
      args = [ "-c" "echo building on the kubernix worker; read l < ${dep}; echo got $l > $out" ];
    }
    NIX

    # `--max-jobs 0` is what makes this a real test: nothing may be built
    # locally, so if the remote builder does not work, nothing is built at all.
    # `--offline` stops a substituter quietly supplying the answer instead.
    #
    # NB `--builders`, not `--store`: the frontend refuses to realise a
    # derivation graph, deliberately. See PLAN.md Phase 7b.
    out=$(nix -L --plugin-files "$PWD/plugin/build/kubernix.so" \
        build \
        --store "local?root=$tmp/store" --max-jobs 0 \
        --builders 'kubernix://{{user}}@127.0.0.1?port={{port}} x86_64-linux' \
        -f "$tmp/example.nix" --no-link --offline --print-out-paths)

    echo
    echo "==> built $out"
    echo "==> contents: $(cat "$tmp/store$out")"

# ------------------------------------------------------------ local dependencies

# DESTRUCTIVE: delete and recreate the JetStream streams.
reset-streams:
    #!/usr/bin/env bash
    set -euo pipefail
    # A WorkQueue stream allows only one consumer per filter subject, so a
    # leftover consumer from a previous run blocks worker startup with
    # "filtered consumer not unique". This clears that.
    cargo build -p kubernix-worker
    echo "deleting kubernix_jobs and kubernix_results on {{nats_url}}..."
    KUBERNIX_RESET_STREAMS=1 NATS_URL="{{nats_url}}" \
      timeout 5 ./target/debug/kubernix-worker || true

# Ephemeral in-memory S3 (RustFS).
s3-mock:
    #!/usr/bin/env sh
    export RUSTFS_ACCESS_KEY="my-dev-key"
    export RUSTFS_SECRET_KEY="my-dev-secret"
    mkdir -p /dev/shm/rustfs_data
    rustfs server --address :9000 /dev/shm/rustfs_data

# Ephemeral PostgreSQL on 127.0.0.1:5433. Torn down on Ctrl-C.
run-db db_name="kubernix" port="5433":
    #!/usr/bin/env bash
    set -euo pipefail

    # No schema is applied here: kubernix-sshd runs the migrations in
    # `server/migrations/` itself on connect, so a fresh deployment needs no
    # separate provisioning step and there is only one place the schema lives.
    #
    # TCP rather than a unix socket, so DATABASE_URL is an ordinary URL.
    dir=$(mktemp -d)
    trap 'echo "Cleaning up $dir..."; rm -rf "$dir"' EXIT

    echo "Initializing database in $dir..."
    nix-shell -I nixpkgs=./nix/nixpkgs.nix -p postgresql --run "
        set -euo pipefail
        initdb -D \"$dir/db\" -U postgres >/dev/null

        postgres -D \"$dir/db\" -k \"$dir\" \
            -c listen_addresses=127.0.0.1 -p {{port}} >\"$dir/log\" 2>&1 &
        PID=\$!

        echo 'Waiting for database to start...'
        until pg_isready -h 127.0.0.1 -p {{port}} -q; do sleep 0.2; done

        createdb -h 127.0.0.1 -p {{port}} -U postgres '{{db_name}}'

        echo ''
        echo 'Database ready:'
        echo '  export DATABASE_URL=postgres://postgres@127.0.0.1:{{port}}/{{db_name}}'
        echo '  psql -h 127.0.0.1 -p {{port}} -U postgres {{db_name}}'
        echo ''

        wait \"\$PID\"
    "

# NATS with JetStream, which the job and result streams both need.
nats:
    nats-server --jetstream
