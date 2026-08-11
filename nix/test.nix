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
in
pkgs.testers.nixosTest {
  name = "kubernix-end-to-end";

  nodes.machine = { config, pkgs, ... }: {
    imports = [ ./module.nix ];

    # The VM builds a derivation of its own and runs a Nix client, so it needs
    # room and cores.
    virtualisation.memorySize = 4096;
    virtualisation.diskSize = 8192;

    environment.systemPackages = [
      pkgs.lix
      pkgs.curl
      pkgs.openssh
      pkgs.jq
    ];

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
  };

  testScript = ''
    import json

    plugin = "${kubernix-plugin}/lib/lix/plugins/kubernix.so"
    ssh_opts = "${sshOpts}"

    machine.wait_for_unit("nats.service")
    machine.wait_for_unit("rustfs.service")
    machine.wait_for_unit("postgresql.service")
    machine.wait_for_open_port(9000)

    machine.wait_for_unit("kubernix-sshd.service")
    machine.wait_for_unit("kubernix-cache.service")
    machine.wait_for_unit("kubernix-worker.service")
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
            f"nix build -f ${unverifiable} --no-link --print-out-paths"
        ).strip()
        machine.succeed(
            f"NIX_SSHOPTS='{ssh_opts}' nix --plugin-files {plugin} copy "
            f"--to 'kubernix://root@127.0.0.1?port=2222' {pushed} --no-check-sigs"
        )

        tier, sigs = machine.succeed(
            "psql -U postgres -h 127.0.0.1 kubernix -tAc "
            f"\"SELECT tier, coalesce(array_length(sigs,1),0) FROM store_paths "
            f"WHERE path = '{pushed}'\""
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
  '';
}
