# Kubernix development commands.
#
# The pieces:
#   plugin          Lix client plugin, registers the `kubernix://` store scheme
#   kubernix-sshd   SSH frontend: terminates SSH, serves the daemon protocol
#   kubernix-stdio  same protocol on stdin/stdout, for testing without SSH
#   kubernix-worker dequeues jobs, builds, streams logs back
#   kubernix-server legacy HTTP/S3 server (predates the SSH frontend)
#
# A full local stack is: a NATS server, then `just worker` and `just sshd` in
# separate shells. `just demo` drives a build through the whole thing.

lix_source := env_var_or_default("KUBERNIX_LIX_SOURCE", "/home/baloo/dev/lix")
nats_url := env_var_or_default("NATS_URL", "nats://127.0.0.1:4222")
ssh_port := env_var_or_default("KUBERNIX_SSH_PORT", "2222")
host_key := env_var_or_default("TMPDIR", "/tmp") / "kubernix_host_ed25519"

# List available commands.
default:
    @just --list

# ---------------------------------------------------------------- build & test

# Build everything: Rust workspace and the Lix plugin.
build: build-rust plugin

# Build the Rust workspace.
build-rust:
    cargo build --workspace

# Run the test suite.
test:
    cargo test --workspace

# Lint and format check.
check:
    cargo clippy --workspace --all-targets
    cargo fmt --check

# Build the Lix client plugin.
plugin lix_src=lix_source:
    #!/usr/bin/env bash
    set -euo pipefail
    # Needs the Lix *source* tree, not just the package: Lix does not install its
    # generated libstore capnp headers, so we regenerate them. See NOTES.md item 1.
    export PKG_CONFIG_PATH="${PKG_CONFIG_PATH:-}:{{lix_src}}/outputs/out/lib/pkgconfig"
    # Test for build.ninja, not the directory: a failed `meson setup` leaves the
    # directory behind, and ninja then re-runs setup without -Dlix-source and
    # fails with a confusing "lix-source is unset".
    if [ ! -f plugin/build/build.ninja ]; then
        rm -rf plugin/build
        CXX=clang++ meson setup plugin/build plugin -Dlix-source={{lix_src}}
    fi
    ninja -C plugin/build

# Build the Nix packages (server, worker, plugin).
nix-build:
    nix-build nix -A kubernix-server -A kubernix-worker -A kubernix-plugin

# Run the NixOS integration test.
nix-test:
    nix-build nix -A test

# Remove build artifacts.
clean:
    cargo clean
    rm -rf plugin/build

# ---------------------------------------------------------------- run services

# SSH frontend: terminates SSH and serves the daemon protocol.
sshd port=ssh_port:
    #!/usr/bin/env bash
    set -euo pipefail
    # Dispatches builds to the queue when NATS is reachable; without it, builds
    # are refused rather than faked. Auth is permissive unless
    # KUBERNIX_SSH_AUTHORIZED_KEYS points at a keys file.
    cargo build -p kubernix-server --bin kubernix-sshd
    NATS_URL="{{nats_url}}" \
    KUBERNIX_SSH_LISTEN="127.0.0.1:{{port}}" \
    KUBERNIX_SSH_HOST_KEY="{{host_key}}" \
      ./target/debug/kubernix-sshd

# Worker: dequeues one job at a time and builds it against the local Nix store.
worker system="x86_64-linux":
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build -p kubernix-worker
    NATS_URL="{{nats_url}}" NIX_SYSTEM="{{system}}" ./target/debug/kubernix-worker

# Legacy HTTP/S3 server (predates the SSH frontend).
http-server:
    #!/usr/bin/env bash
    set -euo pipefail
    # Kept until the narinfo endpoint moves onto it -- see DESIGN.md "HTTP surface".
    export AWS_ACCESS_KEY_ID=my-dev-key
    export AWS_SECRET_ACCESS_KEY=my-dev-secret
    export AWS_ENDPOINT_URL="http://localhost:9000"
    export S3_BUCKET=kubernix
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
    # Requires `just worker` and `just sshd` running, and a reachable NATS.
    export NIX_SSHOPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes"

    tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
    cat > "$tmp/example.nix" <<'NIX'
    derivation {
      name = "kubernix-hello";
      system = "x86_64-linux";
      builder = "/bin/sh";
      args = [ "-c" "echo building on the kubernix worker; echo hi > $out" ];
    }
    NIX

    drv=$(nix-instantiate "$tmp/example.nix")
    echo "==> $drv"
    nix -L --plugin-files "$PWD/plugin/build/kubernix.so" \
        build --store "kubernix://{{user}}@127.0.0.1?port={{port}}" "$drv^out" --no-link

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

# Temporary PostgreSQL instance with the schema applied. Torn down on Ctrl-C.
run-db db_name="kubernix" sql_script="server/migrations/20260728_create_jobs_table.sql":
    #!/usr/bin/env bash
    set -euo pipefail

    dir=$(mktemp -d)
    trap 'echo "Cleaning up $dir..."; rm -rf "$dir"' EXIT
    cp "{{sql_script}}" "$dir/init.sql"

    echo "Initializing database in $dir..."
    nix-shell -p postgresql --run "
        set -x
        initdb -D \"$dir/db\" -U postgres

        postgres -D \"$dir/db\" -k \"$dir/db\" >/dev/null 2>&1 &
        PID=\$!

        echo \"Waiting for database to start...\"
        until [ -S \"$dir\"/db/.s.PGSQL.5432 ]; do sleep 0.1; done

        echo \"Creating database: {{db_name}}\"
        createdb -h \"$dir/db\" -U postgres \"{{db_name}}\"

        echo \"Applying schema...\"
        psql -h \"$dir/db\" -U postgres -d \"{{db_name}}\" -f \"$dir/init.sql\"

        echo \"Database is ready! psql -h $dir/db -U postgres {{db_name}}\"

        wait \"\$PID\"
    "
