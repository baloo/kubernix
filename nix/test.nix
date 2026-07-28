{ pkgs, kubernix-server, kubernix-worker, kubernix-plugin }:

pkgs.testers.nixosTest {
  name = "kubernix-integration";

  nodes.machine = { config, pkgs, ... }: {
    imports = [ ./module.nix ];

    environment.systemPackages = [
      kubernix-server
      kubernix-plugin
      pkgs.lix
      pkgs.curl
      pkgs.minio-client
      pkgs.natscli
    ];

    # 1. NATS
    services.nats = {
      enable = true;
      jetstream = true;
    };

    # 2. Rustfs (S3 mock)
    services.rustfs = {
      enable = true;
      environmentFile = builtins.toString (pkgs.writeText "rustfs-credentials" ''
        RUSTFS_ACCESS_KEY=minioadmin
        RUSTFS_SECRET_KEY=minioadmin
      '');
      settings = {
        RUSTFS_VOLUMES = "/var/lib/rustfs";
      };
    };

    # 3. PostgreSQL
    services.postgresql = {
      enable = true;
      ensureDatabases = [ "kubernix" "postgres" ];
      ensureUsers = [
        {
          name = "postgres";
          ensureDBOwnership = true;
        }
      ];
      authentication = pkgs.lib.mkOverride 10 ''
        #type database  DBuser  auth-method
        local all       all     trust
        host  all       all     127.0.0.1/32 trust
        host  all       all     ::1/128      trust
      '';
    };

    # 4. Kubernix Server
    services.kubernix-server = {
      enable = true;
      package = kubernix-server;
      databaseUrl = "postgres://postgres@localhost:5432/kubernix";
    };

    # 5. Kubernix Worker
    services.kubernix-worker = {
      enable = true;
      package = kubernix-worker;
      natsUrl = "nats://localhost:4222";
    };
  };

  testScript = ''
    machine.wait_for_unit("nats.service")
    machine.wait_for_unit("rustfs.service")
    machine.wait_for_unit("postgresql.service")

    # Give postgres a moment to be ready
    machine.wait_until_succeeds("sudo -u postgres psql -c '\\l' | grep kubernix")

    # Run the SQL migrations
    machine.succeed("cat ${../server/migrations/20260728_create_jobs_table.sql} | sudo -u postgres psql kubernix")

    # Wait for minio and create bucket
    machine.wait_for_open_port(9000)
    machine.succeed("mc alias set myminio http://127.0.0.1:9000 minioadmin minioadmin")
    machine.succeed("mc mb myminio/kubernix-cache")

    # We need to setup a dummy stream for kubernix.jobs.*
    # Wait for nats JetStream to be available
    machine.succeed("nats stream add kubernix_jobs --subjects 'kubernix.jobs.>' --storage file --retention workq --discard old --max-msgs=-1 --max-bytes=-1 --max-age=-1 --max-msg-size=-1 --dupe-window=2m --replicas=1 --defaults")

    # Start and wait for Kubernix HTTP Server
    machine.wait_for_unit("kubernix-server.service")
    machine.wait_for_open_port(3000)

    # Make sure we can access the health endpoint
    machine.succeed("curl -f http://127.0.0.1:3000/health")

    # Test that the plugin loads in Lix and we can parse a simple derivation
    machine.succeed("cat << 'DRV' > test.nix\n derivation { name = \"test\"; builder = \"/bin/sh\"; system = \"x86_64-linux\"; }\nDRV")

    # Lix build using kubernix remote builder
    # It should hit the interceptor in the plugin, which posts to the server.
    # Note: we run it in background because it will poll infinitely for the job to complete
    machine.execute("lix build -f test.nix --plugin-files ${kubernix-plugin}/lib/lix/plugins/kubernix.so --builders 'kubernix://127.0.0.1:3000 x86_64-linux' --max-jobs 0 > /tmp/lix.log 2>&1 &")

    # Check the database to see if a job was created
    machine.wait_until_succeeds("sudo -u postgres psql kubernix -t -c 'SELECT COUNT(*) FROM jobs;' | grep -w 1")

    # Ensure it's the expected system
    machine.succeed("sudo -u postgres psql kubernix -t -c 'SELECT system FROM jobs LIMIT 1;' | grep 'x86_64-linux'")

    # Log the lix output for debugging
    print(machine.succeed("cat /tmp/lix.log"))
  '';
}
