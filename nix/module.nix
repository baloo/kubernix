{ config, lib, pkgs, ... }:

with lib;

let
  cfg_sshd = config.services.kubernix-sshd;
  cfg_cache = config.services.kubernix-cache;
  cfg_worker = config.services.kubernix-worker;
  cfg_gc = config.services.kubernix-gc;
  cfg_rotate = config.services.kubernix-rotate-capability-secret;

  # Credentials for the object store. Only the frontend and the cache hold
  # these; workers receive pre-signed URLs instead, which is the whole point of
  # the upload service.
  s3Env = cfg: {
    S3_BUCKET = cfg.s3Bucket;
    AWS_ACCESS_KEY_ID = cfg.s3AccessKey;
    AWS_SECRET_ACCESS_KEY = cfg.s3SecretKey;
    AWS_REGION = "us-east-1";
    AWS_ENDPOINT_URL = cfg.s3Endpoint;
  };

  s3Options = {
    s3Bucket = mkOption {
      type = types.str;
      default = "kubernix";
      description = "Object store bucket. Created on startup if absent.";
    };
    s3Endpoint = mkOption {
      type = types.str;
      default = "http://127.0.0.1:9000";
      description = "S3 endpoint. Setting this selects path-style addressing.";
    };
    s3AccessKey = mkOption {
      type = types.str;
      default = "minioadmin";
      description = "Object store access key.";
    };
    s3SecretKey = mkOption {
      type = types.str;
      default = "minioadmin";
      description = "Object store secret key. Use a credentials file in anger.";
    };
  };
in {
  # The SSH frontend: terminates SSH and serves the Cap'n Proto daemon protocol.
  # This is what clients submit builds to.
  options.services.kubernix-sshd = {
    enable = mkEnableOption "Kubernix SSH frontend";

    package = mkOption {
      type = types.package;
      description = "The kubernix-server package (provides kubernix-sshd).";
    };

    listen = mkOption {
      type = types.str;
      default = "0.0.0.0:2222";
      description = "Address to serve the daemon protocol on.";
    };

    hostKey = mkOption {
      type = types.str;
      default = "/var/lib/kubernix-sshd/host_ed25519";
      description = ''
        SSH host key. Generated on first start if absent.

        Stability matters: clients pin it in known_hosts, so a key that changes
        on every restart trips host-key verification.
      '';
    };

    authorizedKeys = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = ''
        `authorized_keys` file. When null the frontend accepts **any** client,
        and derives each tenant from the username rather than the key — see
        PLAN.md "Deferred deliberately".
      '';
    };

    databaseUrl = mkOption {
      type = types.str;
      default = "postgres://postgres@localhost:5432/kubernix";
      description = ''
        PostgreSQL connection string. Migrations run on startup, over this
        connection as given — it therefore needs to authenticate as an
        owner/superuser role, same as the default here. `kubernix-sshd`
        itself then reconnects with only its username swapped for
        `kubernix_app`, the low-privilege, row-level-security-restricted
        role the migrations create — see
        `server/migrations/20260814120000_row_level_security.sql` and
        `PostgresStore::connect`'s doc comment. One URL is still all this
        needs; the role split happens entirely on the Rust side.
      '';
    };

    natsUrl = mkOption {
      type = types.str;
      default = "nats://localhost:4222";
      description = "NATS connection string. Without it, builds are refused.";
    };
  } // s3Options;

  # The binary cache: narinfo, NARs and logs, under a /<tenant>/ prefix.
  options.services.kubernix-cache = {
    enable = mkEnableOption "Kubernix binary cache";

    package = mkOption {
      type = types.package;
      description = "The kubernix-server package (provides kubernix-server).";
    };

    listen = mkOption {
      type = types.str;
      default = "0.0.0.0:3000";
      description = "Address to serve the cache on.";
    };

    databaseUrl = mkOption {
      type = types.str;
      default = "postgres://postgres@localhost:5432/kubernix";
      description = ''
        PostgreSQL connection string. Read-only in practice, and — like
        kubernix-sshd — serves as `kubernix_app` after migrating; see that
        option's description.
      '';
    };
  } // s3Options;

  # Retention and garbage collection (PLAN.md Phase 12). Its own service,
  # deliberately: it deletes things, on a timer, and neither the read path
  # (kubernix-cache) nor the write path (kubernix-sshd) should carry that
  # blast radius. Safe to run more than one replica of, but there is no
  # throughput reason to.
  options.services.kubernix-gc = {
    enable = mkEnableOption "Kubernix retention and garbage collection";

    package = mkOption {
      type = types.package;
      description = "The kubernix-server package (provides kubernix-gc).";
    };

    databaseUrl = mkOption {
      type = types.str;
      default = "postgres://postgres@localhost:5432/kubernix";
      description = ''
        PostgreSQL connection string. After migrating, kubernix-gc serves as
        `kubernix_gc`, not `kubernix_app` — a `BYPASSRLS` role, since a
        collector has to see every tenant's rows to do reachability and
        referrer counting at all. See `PostgresStore::connect`'s doc comment
        and `services.kubernix-sshd.databaseUrl`'s description for the
        migrate/serve split this relies on.
      '';
    };

    interval = mkOption {
      type = types.ints.positive;
      default = 300;
      description = "Seconds between garbage collection passes.";
    };

    batchSize = mkOption {
      type = types.ints.positive;
      default = 10000;
      description = "Access marks drained from the queue per pass.";
    };

    cutoffs = {
      verified = mkOption {
        type = types.ints.positive;
        default = 30 * 24 * 3600;
        description = "Seconds a verified path may go unread before it is eligible for collection.";
      };
      built = mkOption {
        type = types.ints.positive;
        default = 30 * 24 * 3600;
        description = "Seconds a built path may go unread before it is eligible for collection.";
      };
      quarantined = mkOption {
        type = types.ints.positive;
        default = 24 * 3600;
        description = ''
          Seconds a quarantined path may go unread before it is eligible for
          collection. Shorter than the other tiers by default: a quarantined
          path is unverifiable, unshared and unservable, so there is less
          reason to keep it around.
        '';
      };
    };

    jobRetention = {
      logAfter = mkOption {
        type = types.ints.positive;
        default = 7 * 24 * 3600;
        description = ''
          Seconds after a build job finishes before its archived log is
          deleted from the object store.
        '';
      };
      rowAfter = mkOption {
        type = types.ints.positive;
        default = 90 * 24 * 3600;
        description = ''
          Seconds after a build job finishes before its `jobs` row is
          deleted. Must be at least `logAfter` to mean anything: a row is
          never deleted while it still names a log object, so if this is
          shorter the row simply waits for the log to catch up.
        '';
      };
    };
  } // s3Options;

  # Capability-token secret rotation (PLAN.md Phase 14). Its own service, like
  # kubernix-gc: it mints and prunes rows in a different table with a
  # different blast radius, and there is no scheduling reason to couple the
  # two. Not a correctness dependency for anything else here -- a fresh
  # deployment mints its first secret lazily, on first use, so nothing is
  # gated on this service ever having run.
  options.services.kubernix-rotate-capability-secret = {
    enable = mkEnableOption "Kubernix capability-token secret rotation";

    package = mkOption {
      type = types.package;
      description = "The kubernix-server package (provides kubernix-rotate-capability-secret).";
    };

    databaseUrl = mkOption {
      type = types.str;
      default = "postgres://postgres@localhost:5432/kubernix";
      description = ''
        PostgreSQL connection string. Serves as `kubernix_gc` after
        migrating, same maintenance-tier role as kubernix-gc — see that
        service's `databaseUrl` description.
      '';
    };

    interval = mkOption {
      type = types.ints.positive;
      default = 6 * 3600;
      description = "Seconds between rotation passes.";
    };

    retention = mkOption {
      type = types.ints.positive;
      default = 24 * 3600;
      description = ''
        Seconds a retired secret remains valid for verifying a token, after a
        rotation supersedes it as current. Long enough that an in-flight job's
        token never gets invalidated mid-build by a rotation landing under it.
      '';
    };
  };

  options.services.kubernix-worker = {
    enable = mkEnableOption "Kubernix Worker";

    package = mkOption {
      type = types.package;
      description = "The kubernix-worker package to use.";
    };

    natsUrl = mkOption {
      type = types.str;
      default = "nats://localhost:4222";
      description = "NATS connection string.";
    };

    system = mkOption {
      type = types.str;
      default = "x86_64-linux";
      description = "The Nix system this worker builds for.";
    };

    store = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "local?root=/var/lib/kubernix-worker/store";
      description = ''
        Store URI to build into. A chroot store keeps a worker's builds out of
        the host store, which matters because a worker imports quarantined
        inputs on a tenant's behalf — see PLAN.md Phase 9.

        It is also what lets the worker build at all as a non-root user. Builds
        go through `nix-store --serve`'s `BuildDerivation`, and a Nix *daemon*
        refuses that for input-addressed derivations unless the caller is
        trusted ("you are not privileged to build input-addressed
        derivations"). Opening a store directly makes the worker the authority
        rather than a client of one.
      '';
    };
  };

  config = mkMerge [
    (mkIf cfg_sshd.enable {
      systemd.services.kubernix-sshd = {
        description = "Kubernix SSH frontend";
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" "postgresql.service" "nats.service" "rustfs.service" ];

        environment = {
          DATABASE_URL = cfg_sshd.databaseUrl;
          NATS_URL = cfg_sshd.natsUrl;
          KUBERNIX_SSH_LISTEN = cfg_sshd.listen;
          KUBERNIX_SSH_HOST_KEY = cfg_sshd.hostKey;
          RUST_LOG = "debug";
        } // s3Env cfg_sshd
          // optionalAttrs (cfg_sshd.authorizedKeys != null) {
            KUBERNIX_SSH_AUTHORIZED_KEYS = toString cfg_sshd.authorizedKeys;
          };

        serviceConfig = {
          ExecStart = "${cfg_sshd.package}/bin/kubernix-sshd";
          Restart = "always";
          DynamicUser = true;
          # For the generated host key, which must outlive a restart.
          StateDirectory = "kubernix-sshd";
        };
      };
    })

    (mkIf cfg_cache.enable {
      systemd.services.kubernix-cache = {
        description = "Kubernix binary cache";
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" "postgresql.service" "rustfs.service" ];

        environment = {
          DATABASE_URL = cfg_cache.databaseUrl;
          KUBERNIX_HTTP_LISTEN = cfg_cache.listen;
          RUST_LOG = "debug";
        } // s3Env cfg_cache;

        serviceConfig = {
          ExecStart = "${cfg_cache.package}/bin/kubernix-server";
          Restart = "always";
          DynamicUser = true;
        };
      };
    })

    (mkIf cfg_gc.enable {
      systemd.services.kubernix-gc = {
        description = "Kubernix retention and garbage collection";
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" "postgresql.service" "rustfs.service" ];

        environment = {
          DATABASE_URL = cfg_gc.databaseUrl;
          KUBERNIX_GC_INTERVAL = toString cfg_gc.interval;
          KUBERNIX_GC_BATCH = toString cfg_gc.batchSize;
          KUBERNIX_GC_CUTOFF_VERIFIED = toString cfg_gc.cutoffs.verified;
          KUBERNIX_GC_CUTOFF_BUILT = toString cfg_gc.cutoffs.built;
          KUBERNIX_GC_CUTOFF_QUARANTINED = toString cfg_gc.cutoffs.quarantined;
          KUBERNIX_GC_JOB_LOG_CUTOFF = toString cfg_gc.jobRetention.logAfter;
          KUBERNIX_GC_JOB_ROW_CUTOFF = toString cfg_gc.jobRetention.rowAfter;
          RUST_LOG = "debug";
        } // s3Env cfg_gc;

        serviceConfig = {
          ExecStart = "${cfg_gc.package}/bin/kubernix-gc";
          Restart = "always";
          DynamicUser = true;
        };
      };
    })

    (mkIf cfg_rotate.enable {
      systemd.services.kubernix-rotate-capability-secret = {
        description = "Kubernix capability-token secret rotation";
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" "postgresql.service" ];

        environment = {
          DATABASE_URL = cfg_rotate.databaseUrl;
          KUBERNIX_ROTATE_INTERVAL = toString cfg_rotate.interval;
          KUBERNIX_ROTATE_RETENTION = toString cfg_rotate.retention;
          RUST_LOG = "debug";
        };

        serviceConfig = {
          ExecStart = "${cfg_rotate.package}/bin/kubernix-rotate-capability-secret";
          Restart = "always";
          DynamicUser = true;
        };
      };
    })

    (mkIf cfg_worker.enable {
      systemd.services.kubernix-worker = {
        description = "Kubernix Worker";
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" "nats.service" ];
        # The worker shells out to `nix-store` and `nix store dump-path`.
        path = [ pkgs.lix ];

        environment = {
          NATS_URL = cfg_worker.natsUrl;
          NIX_SYSTEM = cfg_worker.system;
          RUST_LOG = "debug";
        } // optionalAttrs (cfg_worker.store != null) {
          KUBERNIX_NIX_STORE = cfg_worker.store;
        };

        serviceConfig = {
          ExecStart = "${cfg_worker.package}/bin/kubernix-worker";
          Restart = "always";
          StateDirectory = "kubernix-worker";
          # Not DynamicUser: building needs a stable store root, and a chroot
          # store must be created and reused across restarts.
        };
      };
    })
  ];
}
