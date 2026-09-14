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

    # An ssh key for the client. `AuthPolicy::RequireKey` is the frontend's
    # default now (Phase 16), so the key has to be bound to a tenant in
    # `tenant_auth_bindings` before any connection using it is accepted --
    # unlike the old `AcceptAll` default, an unbound key gets rejected
    # outright rather than attributed an unverified tenant.
    # Single-quoted on the Python side so the empty passphrase can be written
    # with double quotes -- a pair of single quotes would end this Nix string.
    machine.succeed('mkdir -p /root/.ssh && ssh-keygen -t ed25519 -N "" -f /root/.ssh/id_ed25519')

    # Fingerprint in the same `SHA256:<base64>` form `PublicKey::fingerprint`
    # produces server-side (`server/src/ssh.rs`) -- the second field of
    # `ssh-keygen -l`'s default output.
    fingerprint = machine.succeed(
        "ssh-keygen -lf /root/.ssh/id_ed25519.pub | awk '{print $2}'"
    ).strip()

    # Provisioned by hand here, the way an operator would over a privileged
    # connection (PLAN.md Phase 16): a `tenants` row, then a binding from this
    # key's fingerprint to it. `postgres` is a superuser and bypasses
    # row-level security, same as every other `psql` call in this test that
    # isn't the row-level-security check itself.
    tenant_id = "user-testclient-0000000000000000"
    machine.succeed(
        "psql -U postgres -h 127.0.0.1 kubernix -c "
        "\"INSERT INTO tenants (id, identity, verified) VALUES "
        f"('{tenant_id}', 'key:{fingerprint}', true) ON CONFLICT (id) DO NOTHING\""
    )
    machine.succeed(
        "psql -U postgres -h 127.0.0.1 kubernix -c "
        "\"INSERT INTO tenant_auth_bindings (key_type, key_id, tenant) "
        f"VALUES ('ssh', '{fingerprint}', '{tenant_id}') "
        "ON CONFLICT (key_type, key_id) DO NOTHING\""
    )


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
    # also asserts the frontend attributed the connection to the tenant the
    # binding above named -- not a username-derived id, which is what
    # `AcceptAll` would have produced instead.
    tenant = machine.succeed(
        "psql -U postgres -h 127.0.0.1 kubernix -tAc "
        "\"SELECT id FROM tenants LIMIT 1\""
    ).strip()
    print(f"tenant {tenant}")
    assert tenant == tenant_id, f"unexpected tenant: {tenant}"


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


    with subtest("row-level security blocks a cross-tenant read even without an application predicate"):
        # Run early, right after the path this checks is created — not
        # later, after several slower subtests. `services.kubernix-gc`'s
        # cutoffs are deliberately tight in this test (60s, see below), and
        # by now kubernix-gc actually reaps an idle row on schedule; a row
        # this check depends on could otherwise be gone by the time it runs
        # if enough wall-clock time has passed since it was built.
        #
        # Every check elsewhere in this test (e.g. "tenants are isolated")
        # proves the *application*'s own `WHERE tenant = $1` isolates
        # tenants. This proves the *database* does too — against the real
        # `kubernix_app` role kubernix-sshd/kubernix-cache actually connect
        # as after migrating (`server/migrations/20260814120000_row_level_
        # security.sql`), not the `postgres` superuser every other `psql`
        # call in this test uses, which always bypasses row-level security
        # regardless of policy.
        # Two statements in one session (`set_config(..., false)` sets a
        # session-level GUC, so it has to be the same connection as the
        # query that follows it — a second `psql` invocation would start a
        # fresh session with the GUC back to unset), sent as one
        # semicolon-separated `-tAc` string so they run in that order on
        # that one connection. `psql -tAc` prints the result set of *every*
        # statement it runs, though, and `set_config(...)` returns its own
        # new value as a one-row result — so the raw output is two lines:
        # the echoed tenant, then the path query's (possibly empty) answer.
        # Dropping the first line is simpler and more robust than trying to
        # suppress it psql-side (`\o` redirection turned out not to nest
        # cleanly inside a `-c` string here).
        def scoped_path_query(as_tenant: str) -> str:
            output = machine.succeed(
                "psql -U kubernix_app -h 127.0.0.1 kubernix -tAc "
                f"\"SELECT set_config('app.current_tenant', '{as_tenant}', false); "
                f"SELECT path FROM store_paths WHERE path = '{out_bare}'\""
            )
            lines = output.splitlines()
            assert lines and lines[0] == as_tenant, (
                f"expected set_config's own echoed value first, got: {lines!r}"
            )
            return "\n".join(lines[1:]).strip()

        other = "user-nobody-0000000000000000"
        result = scoped_path_query(other)
        assert result == "", (
            f"kubernix_app scoped to a different tenant must not see this row "
            f"from a query with no tenant predicate of its own, got: {result!r}"
        )

        # Sanity check on the same role, so the empty result above cannot be
        # mistaken for "row-level security blocks everything": the owning
        # tenant must still see its own row.
        result = scoped_path_query(tenant)
        assert result == out_bare, f"the owning tenant must still see its own row, got: {result!r}"


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


    # `auth_publickey` shares the same 16-connection pool as kubernix-gc and
    # kubernix-rotate-capability-secret, both polling every couple of seconds,
    # so its `tenant_auth_bindings` lookup can occasionally lose the race for
    # a pool connection and get fail-closed rejected (`ssh.rs` logs "tenant
    # binding lookup failed") under this VM's contention, purely as a client
    # of the same pool, unrelated to shell/exec handling. Retrying the
    # connection rides out that flake instead of conflating it with an actual
    # hang -- a real hang would still fail every attempt via the timeout.
    #
    # Placed here, after every subtest whose own timing matters (the
    # "signed and published"/row-level-security checks above run right after
    # the first build on purpose, inside kubernix-gc's tight 60s cutoff -- see
    # that subtest's own comment) and before the final GC subtest, which has
    # to stay last: these open fresh connections and touch no shared state,
    # so where they land only has to avoid disturbing those two constraints.
    def ssh_no_check(command_suffix=""):
        # 45s per attempt: comfortably past sqlx's own ~30s pool-acquire wait,
        # so a pool-contention rejection has time to actually happen (and be
        # retried below) instead of this wrapper's own timeout cutting the
        # attempt off first and misreporting contention as a hang.
        for _ in range(3):
            # `</dev/null`: `machine.execute`'s backdoor shell never gives its
            # commands an EOF'd stdin. A `shell`-request `ssh` (no remote
            # command) forwards local stdin over the channel and, without
            # this, waited on that open-ended stdin indefinitely even after
            # the server sent its own channel close -- a client-side hang
            # this test's own timeout could not have caught either, since
            # nothing server-side was actually stuck.
            # `2>&1`: `machine.execute` only captures stdout (see its own
            # docstring) -- the unsupported-command message is deliberately
            # sent as stderr (`exec_request`'s `extended_data` call), so
            # without this it would never show up in `output` at all.
            status, output = machine.execute(
                f"timeout 45 ssh {ssh_opts} -p 2222 root@127.0.0.1{command_suffix} </dev/null 2>&1"
            )
            if status != 255:  # 255: ssh itself failed, e.g. auth rejected
                return status, output
        return status, output

    with subtest("a plain shell request gets a message and a clean hangup, not a hang"):
        # A client that asks for an interactive shell instead of exec'ing
        # `<remote-program> --stdio` used to just hang forever -- russh's
        # default `shell_request` silently succeeds and never sends anything
        # back. `SshHandler::shell_request` (server/src/ssh.rs) now replies
        # and closes the channel, so this must return promptly rather than
        # timing out.
        status, output = ssh_no_check()
        assert status != 124, f"shell request hung instead of closing:\n{output}"
        assert "use the lix plugin instead" in output, f"unexpected output: {output}"

    with subtest("an unsupported exec command is rejected with an explicit message"):
        # Not `--stdio`, so `is_stdio_request` rejects it. The message should
        # spell out what is actually expected instead of just echoing the
        # command back -- see `exec_request` in server/src/ssh.rs.
        status, output = ssh_no_check(" 'bash -c true'")
        assert status != 124, f"exec of an unsupported command hung:\n{output}"
        assert "unsupported command" in output, f"unexpected output: {output}"
        assert "--stdio" in output, f"message did not name the expected command:\n{output}"


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
