{ pkgs, kubernix-server, kubernix-worker, kubernix-plugin }:

# End-to-end test of the whole system, on one machine.
#
# It follows what a user actually does, in order, because each step depends on
# the one before:
#
#   1. build something on a remote builder      (SSH frontend → NATS → worker)
#   2. read the result back                     (worker → S3 → frontend → client)
#   3. substitute it from the cache             (HTTP narinfo + NAR redirect)
#   4. confirm the signature is load-bearing    (same fetch, key not trusted)
#   5. confirm quarantine holds                 (unverifiable push is not served)
#
# Steps 4 and 5 are the ones worth having: without them the test would pass just
# as happily if signing were skipped entirely and every path served.

let
  # The three stores are deliberately separate. The client's is not the worker's,
  # so nothing can pass between them except through kubernix — which is what the
  # test is for. A shared /nix/store would make every step trivially succeed.
  clientStore = "/tmp/client";
  freshStore = "/tmp/fresh";

  sshOpts = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes";

  # A *two-derivation graph*, not a leaf. The consumer depends on another
  # derivation's output, so what reaches the worker is a resolved derivation
  # that cannot be reconstructed as a `.drv` — the case Phase 9b fixed, and the
  # one that every earlier test silently avoided.
  #
  # The builder also prints, so the same run proves logs still stream.
  example = pkgs.writeText "example.nix" ''
    let dep = derivation {
          name = "kubernix-dep";
          system = "x86_64-linux";
          builder = "/bin/sh";
          args = [ "-c" "echo built by kubernix > $out" ];
        };
    in derivation {
      name = "kubernix-e2e";
      system = "x86_64-linux";
      builder = "/bin/sh";
      args = [ "-c" "echo BUILDING-REMOTELY; read l < ''${dep}; echo $l > $out" ];
    }
  '';

  # Input-addressed: its path is a function of a derivation, not of its content,
  # so the frontend cannot verify it and must quarantine it.
  unverifiable = pkgs.writeText "unverifiable.nix" ''
    derivation {
      name = "kubernix-unverifiable";
      system = "x86_64-linux";
      builder = "/bin/sh";
      args = [ "-c" "echo unverifiable > $out" ];
    }
  '';

  # A second, independent leaf build -- used only to prove a capability token
  # minted *after* a forced rotation still verifies. Deliberately not `example`
  # again: that output is reserved for the GC subtest at the end.
  afterRotation = pkgs.writeText "after-rotation.nix" ''
    derivation {
      name = "kubernix-after-rotation";
      system = "x86_64-linux";
      builder = "/bin/sh";
      args = [ "-c" "echo built after rotation > $out" ];
    }
  '';
in
pkgs.testers.nixosTest {
  name = "kubernix-end-to-end";

  nodes.machine = { config, pkgs, ... }: {
    imports = [ ./module.nix ];

    # The VM builds a derivation of its own and runs a Nix client, so it needs
    # room and cores. Cores matter more than the comment used to suggest: the
    # frontend spawns a dedicated OS thread with its own single-threaded Tokio
    # runtime per SSH connection (capnp-rpc capabilities are `!Send`, PLAN.md
    # Phase 4), so on a single vCPU one connection's thread can go unscheduled
    # long enough that even its own 30s DB pool-acquire timeout never gets
    # polled -- a bounded wait silently becomes an unbounded hang under load.
    virtualisation.memorySize = 4096;
    virtualisation.diskSize = 8192;
    virtualisation.cores = 4;

    environment.systemPackages = [
      pkgs.lix
      pkgs.curl
      pkgs.openssh
      pkgs.jq
    ];

    nix.settings.experimental-features = [ "nix-command" ];

    services.nats = {
      enable = true;
      jetstream = true;
    };

    services.rustfs = {
      enable = true;
      environmentFile = builtins.toString (pkgs.writeText "rustfs-credentials" ''
        RUSTFS_ACCESS_KEY=minioadmin
        RUSTFS_SECRET_KEY=minioadmin
      '');
      settings.RUSTFS_VOLUMES = "/var/lib/rustfs";
    };

    services.postgresql = {
      enable = true;
      ensureDatabases = [ "kubernix" ];
      ensureUsers = [{
        name = "postgres";
        ensureDBOwnership = false;
      }];
      authentication = pkgs.lib.mkOverride 10 ''
        local all all trust
        host  all all 127.0.0.1/32 trust
        host  all all ::1/128      trust
      '';
    };

    # No migration step: the frontend applies them itself on startup, so a fresh
    # deployment needs no provisioning.
    services.kubernix-sshd = {
      enable = true;
      package = kubernix-server;
      listen = "127.0.0.1:2222";
      databaseUrl = "postgres://postgres@127.0.0.1:5432/kubernix";
    };

    services.kubernix-cache = {
      enable = true;
      package = kubernix-server;
      listen = "127.0.0.1:3000";
      databaseUrl = "postgres://postgres@127.0.0.1:5432/kubernix";
    };

    services.kubernix-worker = {
      enable = true;
      package = kubernix-worker;
      # A chroot store, empty at boot: an output appearing in it can only have
      # been built there, and an input can only have arrived through kubernix.
      store = "local?root=/var/lib/kubernix-worker/store";
    };

    # A short interval and short cutoffs so the "garbage collection" subtest
    # below does not have to wait out a production-sized retention window —
    # it ages a row directly via SQL and just needs the next pass to see it.
    services.kubernix-gc = {
      enable = true;
      package = kubernix-server;
      databaseUrl = "postgres://postgres@127.0.0.1:5432/kubernix";
      interval = 2;
      cutoffs = {
        verified = 60;
        built = 60;
        quarantined = 60;
      };
    };

    # Short-circuited the same way kubernix-gc is above: the test forces
    # rotations directly rather than waiting out a production cadence, but a
    # short interval still exercises the service as it would actually run.
    services.kubernix-rotate-capability-secret = {
      enable = true;
      package = kubernix-server;
      databaseUrl = "postgres://postgres@127.0.0.1:5432/kubernix";
      interval = 2;
      retention = 60;
    };
  };

  testScript = ''
    import time

    plugin = "${kubernix-plugin}/lib/lix/plugins/kubernix.so"
    ssh_opts = "${sshOpts}"

    machine.wait_for_unit("nats.service")
    machine.wait_for_unit("rustfs.service")
    machine.wait_for_unit("postgresql.service")
    machine.wait_for_open_port(9000)

    machine.wait_for_unit("kubernix-sshd.service")
    machine.wait_for_unit("kubernix-cache.service")
    machine.wait_for_unit("kubernix-worker.service")
    machine.wait_for_unit("kubernix-gc.service")
    machine.wait_for_unit("kubernix-rotate-capability-secret.service")
    machine.wait_for_open_port(2222)
    machine.wait_for_open_port(3000)

    # An ssh key for the client. The frontend accepts any key here, but Lix
    # still runs a real ssh, so one has to exist.
    # Single-quoted on the Python side so the empty passphrase can be written
    # with double quotes -- a pair of single quotes would end this Nix string.
    machine.succeed('mkdir -p /root/.ssh && ssh-keygen -t ed25519 -N "" -f /root/.ssh/id_ed25519')


    with subtest("a two-derivation graph builds on the worker and comes back"):
        # `--store` keeps this out of the host store, and `--max-jobs 0` means it
        # cannot quietly build locally: if the remote builder does not work,
        # nothing gets built at all.
        #
        # `-L` makes the builder's output appear, so the same command proves logs
        # stream back rather than needing a separate check.
        result = machine.succeed(
            f"NIX_SSHOPTS='{ssh_opts}' nix -L --plugin-files {plugin} build "
            f"--store 'local?root=${clientStore}' --max-jobs 0 "
            f"--builders 'kubernix://root@127.0.0.1?port=2222 x86_64-linux' "
            f"-f ${example} --no-link --print-out-paths 2>&1"
        )

        # The dependency had to be built remotely too, which is what Phase 9b
        # made possible: a resolved derivation cannot be written back out as a
        # `.drv`, so this used to fail with "has incorrect output".
        assert "BUILDING-REMOTELY" in result, f"build log did not stream back:\n{result}"

        out = [l for l in result.splitlines() if l.startswith("/nix/store/")][-1].strip()
        # `store_paths.path` holds the bare `<hash>-<name>` form now — see
        # kubernix_types::StorePath's doc comment — while every `nix`/`curl`
        # command below still wants the full printed path.
        out_bare = out.split("/")[-1]
        print(f"built {out}")
        content = machine.succeed(f"cat ${clientStore}{out}")
        assert "built by kubernix" in content, f"unexpected output: {content}"


    # Every later step is scoped to this tenant. Reading it from the database
    # also asserts the frontend recorded who the client was.
    tenant = machine.succeed(
        "psql -U postgres -h 127.0.0.1 kubernix -tAc "
        "\"SELECT id FROM tenants LIMIT 1\""
    ).strip()
    print(f"tenant {tenant}")
    assert tenant.startswith("user-root-"), f"unexpected tenant: {tenant}"


    with subtest("the built path is signed and the key is published"):
        tier, sigs = machine.succeed(
            "psql -U postgres -h 127.0.0.1 kubernix -tAc "
            "\"SELECT tier, coalesce(array_length(sigs,1),0) FROM store_paths "
            "WHERE tier = 'built' LIMIT 1\""
        ).strip().split("|")
        assert tier == "built", f"unexpected tier: {tier}"
        assert int(sigs) == 1, "a built path should carry exactly one signature"

        key = machine.succeed(f"curl -fsS http://127.0.0.1:3000/{tenant}/public-key").strip()
        assert key.startswith(f"kubernix-{tenant}-1:"), f"unexpected key: {key}"

        info = machine.succeed(f"curl -fsS http://127.0.0.1:3000/{tenant}/nix-cache-info")
        assert "StoreDir: /nix/store" in info, info


    with subtest("a stock client substitutes from the cache"):
        # The real test of the narinfo, the signature and the NAR redirect: a
        # client that has never seen this path fetches it with verification on.
        machine.succeed(
            f"nix copy --from http://127.0.0.1:3000/{tenant} "
            f"--to 'local?root=${freshStore}' {out} "
            f"--option trusted-public-keys '{key}'"
        )
        content = machine.succeed(f"cat ${freshStore}{out}")
        assert "built by kubernix" in content, f"unexpected output: {content}"


    with subtest("the signature is enforced, not decorative"):
        # Without the key trusted, the same fetch must fail. If this passes,
        # everything above proves much less than it appears to.
        machine.succeed("rm -rf ${freshStore}2")
        machine.fail(
            f"nix copy --from http://127.0.0.1:3000/{tenant} "
            f"--to 'local?root=${freshStore}2' {out} "
            f"--option trusted-public-keys "
            f"'cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY='"
        )


    with subtest("an unverifiable push is quarantined and not served"):
        # Built locally, then pushed: input-addressed, so its path cannot be
        # derived from its content and the frontend has to take it on trust.
        pushed = machine.succeed(
            "nix build -f ${unverifiable} --no-link --print-out-paths"
        ).strip()
        pushed_bare = pushed.split("/")[-1]
        machine.succeed(
            f"NIX_SSHOPTS='{ssh_opts}' nix --plugin-files {plugin} copy "
            f"--to 'kubernix://root@127.0.0.1?port=2222' {pushed} --no-check-sigs"
        )

        tier, sigs = machine.succeed(
            "psql -U postgres -h 127.0.0.1 kubernix -tAc "
            f"\"SELECT tier, coalesce(array_length(sigs,1),0) FROM store_paths "
            f"WHERE path = '{pushed_bare}'\""
        ).strip().split("|")
        assert tier == "quarantined", f"unverifiable push should be quarantined, got {tier}"
        assert int(sigs) == 0, "a quarantined path must never be signed"

        # And the cache does not offer it.
        hash_part = pushed.split("/")[-1].split("-")[0]
        status = machine.succeed(
            f"curl -s -o /dev/null -w '%{{http_code}}' "
            f"http://127.0.0.1:3000/{tenant}/{hash_part}.narinfo"
        ).strip()
        assert status == "404", f"quarantined path should not be served, got {status}"


    with subtest("tenants are isolated"):
        # A different tenant id must not reach the first tenant's paths, even
        # though the id is guessable — the scoping is in the store, not in the
        # obscurity of the prefix.
        other = "user-nobody-0000000000000000"
        hash_part = out.split("/")[-1].split("-")[0]
        status = machine.succeed(
            f"curl -s -o /dev/null -w '%{{http_code}}' "
            f"http://127.0.0.1:3000/{other}/{hash_part}.narinfo"
        ).strip()
        assert status == "404", f"cross-tenant read should 404, got {status}"


    with subtest("the capability secret is provisioned and rotates"):
        # Proves the lazy-create-on-first-use path is actually live (not
        # skipped): by now `build_derivation` has minted and verified at least
        # one token, so a row must already exist.
        before = int(machine.succeed(
            "psql -U postgres -h 127.0.0.1 kubernix -tAc "
            "\"SELECT count(*) FROM capability_secrets\""
        ).strip())
        assert before >= 1, "a capability secret should already exist by now"

        # Force a second pass rather than waiting out the shortened 2s
        # interval -- deterministic, and proves rotation actually inserts
        # rather than being a no-op.
        machine.succeed(
            "DATABASE_URL=postgres://postgres@127.0.0.1:5432/kubernix "
            "${kubernix-server}/bin/kubernix-rotate-capability-secret --once"
        )
        after = int(machine.succeed(
            "psql -U postgres -h 127.0.0.1 kubernix -tAc "
            "\"SELECT count(*) FROM capability_secrets\""
        ).strip())
        assert after > before, f"rotation should insert a new secret, {before} -> {after}"


    with subtest("a build still succeeds after the secret rotates"):
        # The token minted for this build is signed with whatever secret is
        # now current -- proving mint and verify agree on it across the
        # rotation forced just above, not only within one secret's lifetime.
        result = machine.succeed(
            f"NIX_SSHOPTS='{ssh_opts}' nix -L --plugin-files {plugin} build "
            f"--store 'local?root=${clientStore}' --max-jobs 0 "
            f"--builders 'kubernix://root@127.0.0.1?port=2222 x86_64-linux' "
            f"-f ${afterRotation} --no-link --print-out-paths 2>&1"
        )
        out2 = [l for l in result.splitlines() if l.startswith("/nix/store/")][-1].strip()
        content = machine.succeed(f"cat ${clientStore}{out2}")
        assert "built after rotation" in content, f"unexpected output: {content}"


    with subtest("garbage collection removes an aged, unreferenced path"):
        # Last of all, deliberately: this consumes the path built in the very
        # first subtest, which every subtest above depends on still existing.
        #
        # Forcing `last_access` into the past is what a real deployment's clock
        # would do over the retention window; there is no `Store` method for
        # this on purpose; see PLAN.md Phase 12.
        machine.succeed(
            "psql -U postgres -h 127.0.0.1 kubernix -c "
            f"\"UPDATE store_paths SET last_access = NOW() - INTERVAL '1 hour' "
            f"WHERE path = '{out_bare}'\""
        )

        # kubernix-gc's drain -> mark -> sweep -> reap all happen within one
        # pass, on a 2s interval here, so the next tick is enough -- poll
        # rather than sleep a fixed amount, in case the pass lands mid-poll.
        hash_part = out.split("/")[-1].split("-")[0]
        deadline = time.time() + 30
        state = "not checked yet"
        while time.time() < deadline:
            state = machine.succeed(
                "psql -U postgres -h 127.0.0.1 kubernix -tAc "
                f"\"SELECT coalesce(state, 'gone') FROM store_paths "
                f"WHERE path = '{out_bare}'\""
            ).strip()
            if state in ("", "gone"):
                break
            time.sleep(1)
        assert state in ("", "gone"), f"row was not reaped in time, last state={state!r}"

        # And the cache agrees: a collected path is not distinguishable from
        # one that was never pushed.
        status = machine.succeed(
            f"curl -s -o /dev/null -w '%{{http_code}}' "
            f"http://127.0.0.1:3000/{tenant}/{hash_part}.narinfo"
        ).strip()
        assert status == "404", f"a collected path should not be served, got {status}"
  '';
}
