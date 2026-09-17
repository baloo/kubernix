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

    jobResultsRetention = mkOption {
      type = types.ints.positive;
      default = 24 * 3600;
      description = ''
        Seconds a job's outcome stays replayable in NATS, and how long a
        dedup reservation for an in-flight build (PLAN.md Phase 19) may go
        unclaimed before it is treated as orphaned. Must match
        `kubernix-worker`'s and `kubernix-gc`'s own copies of this same
        value (`jobResultsRetention` / `jobRetention.stuckRunningAfter`
        respectively) -- NATS only actually applies this to the results
        stream once, on whichever of the two processes creates it first, and
        a mismatch would silently pick one side's value rather than error.
      '';
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
      stuckRunningAfter = mkOption {
        type = types.ints.positive;
        default = 24 * 3600;
        description = ''
          Seconds a `jobs` row may sit at `status = 'running'` (PLAN.md
          Phase 19's dedup reservation) before this collector reclaims it as
          orphaned -- a backstop for a reservation nothing ever asks about
          again, not the primary recovery path (a live request reclaims a
          stale one itself, inline). Must match `kubernix-sshd`'s and
          `kubernix-worker`'s own `jobResultsRetention` -- see that option's
          description.
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

    jobResultsRetention = mkOption {
      type = types.ints.positive;
      default = 24 * 3600;
      description = ''
        Must match `kubernix-sshd`'s `jobResultsRetention` and
        `kubernix-gc`'s `jobRetention.stuckRunningAfter` -- see that
        option's own description (PLAN.md Phase 19).
      '';
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

    vmKernel = mkOption {
      type = types.nullOr types.path;
      default = null;
      example = "\${kubernix-guest-vm-kernel}/bzImage";
      description = ''
        Phase 15: kernel image for the per-tenant `cloud-hypervisor` VM.
        Leaving this (and `vmInitrd`) unset disables VM lifecycle entirely —
        the worker builds exactly as it does today.
      '';
    };

    vmInitrd = mkOption {
      type = types.nullOr types.path;
      default = null;
      example = "\${kubernix-guest-vm-initrd}/initrd";
      description = "Phase 15: initrd image, paired with `vmKernel`.";
    };

    vmVcpus = mkOption {
      type = types.int;
      default = 1;
      description = "vCPUs given to the per-tenant VM.";
    };

    vmMemoryMb = mkOption {
      type = types.int;
      default = 768;
      description = "Memory (MB) given to the per-tenant VM.";
    };

    vmStoreImgMb = mkOption {
      type = types.int;
      default = 8192;
      description = "Size (MB) of a freshly created, sparse per-tenant store.img.";
    };

    systemFeatures = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "big-parallel" ];
      description = ''
        PLAN.md Phase 17: static capability classes this worker declares,
        analogous to a Nix `machines` file's supportedFeatures column — routes
        `requiredSystemFeatures = "big-parallel"` jobs here. "kvm" is not
        settable here: kvm-class routing is gated by the worker's own
        boot-time nested-virt self-test (`worker/src/vm.rs::boot_probe`),
        never by static declaration alone.
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
          KUBERNIX_JOB_RESULTS_RETENTION = toString cfg_sshd.jobResultsRetention;
          KUBERNIX_SSH_LISTEN = cfg_sshd.listen;
          KUBERNIX_SSH_HOST_KEY = cfg_sshd.hostKey;
          RUST_LOG = "debug";
        } // s3Env cfg_sshd;

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
          KUBERNIX_JOB_RESULTS_RETENTION = toString cfg_gc.jobRetention.stuckRunningAfter;
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
        # The worker shells out to `nix-store` and `nix store dump-path`, and,
        # when Phase 15's per-tenant VM lifecycle is enabled below, to
        # `cloud-hypervisor` itself, plus (Step 5) `passt` as its network
        # backend — both resolved via bare name on this `$PATH`, same as
        # `KUBERNIX_VM_CH_BIN`'s default of `"cloud-hypervisor"` needs no
        # explicit env var once the binary is on `path`.
        path = [ pkgs.lix pkgs.cloud-hypervisor pkgs.passt ];

        environment = {
          NATS_URL = cfg_worker.natsUrl;
          KUBERNIX_JOB_RESULTS_RETENTION = toString cfg_worker.jobResultsRetention;
          NIX_SYSTEM = cfg_worker.system;
          RUST_LOG = "debug";
        } // optionalAttrs (cfg_worker.systemFeatures != [ ]) {
          KUBERNIX_WORKER_CLASSES = concatStringsSep "," cfg_worker.systemFeatures;
        } // optionalAttrs (cfg_worker.store != null) {
          KUBERNIX_NIX_STORE = cfg_worker.store;
        } // optionalAttrs (cfg_worker.vmKernel != null) {
          KUBERNIX_VM_KERNEL = toString cfg_worker.vmKernel;
          KUBERNIX_VM_INITRD = toString cfg_worker.vmInitrd;
          KUBERNIX_VM_VCPUS = toString cfg_worker.vmVcpus;
          KUBERNIX_VM_MEMORY_MB = toString cfg_worker.vmMemoryMb;
          KUBERNIX_VM_STORE_IMG_MB = toString cfg_worker.vmStoreImgMb;
        };

        serviceConfig = {
          ExecStart = "${cfg_worker.package}/bin/kubernix-worker";
          Restart = "always";
          StateDirectory = "kubernix-worker";
          # Not DynamicUser: building needs a stable store root, and a chroot
          # store must be created and reused across restarts.
        } // optionalAttrs (cfg_worker.vmKernel != null) {
          # cloud-hypervisor needs /dev/kvm; no non-KVM fallback exists.
          # Provisional, dev/test-only posture — cgroup device rules vs.
          # `privileged: true` are Step 7's job (Kubernetes manifests), not
          # this module's. Networking (Step 5) needs no such addition here:
          # `passt` runs as an ordinary unprivileged process needing no
          # `NET_ADMIN`-equivalent capability at all — see PLAN.md's Phase 15
          # Component 4 for why that was the point of choosing it.
          DeviceAllow = [ "/dev/kvm rw" ];
          SupplementaryGroups = [ "kvm" ];
        };
      };
    })
  ];
}
