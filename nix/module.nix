{ config, lib, pkgs, ... }:

with lib;

let
  cfg_server = config.services.kubernix-server;
  cfg_worker = config.services.kubernix-worker;
in {
  options.services.kubernix-server = {
    enable = mkEnableOption "Kubernix HTTP Server";

    package = mkOption {
      type = types.package;
      description = "The kubernix-server package to use.";
    };

    databaseUrl = mkOption {
      type = types.str;
      default = "postgres://postgres:postgres@localhost:5432/kubernix";
      description = "PostgreSQL connection string.";
    };

    natsUrl = mkOption {
      type = types.str;
      default = "nats://localhost:4222";
      description = "NATS connection string.";
    };

    s3Bucket = mkOption {
      type = types.str;
      default = "kubernix-cache";
      description = "S3 bucket name.";
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
      description = "The nix system architecture to build for.";
    };
  };

  config = mkMerge [
    (mkIf cfg_server.enable {
      systemd.services.kubernix-server = {
        description = "Kubernix HTTP Server";
        wantedBy = [ "multi-user.target" ];
        after = [ "network.target" "postgresql.service" "nats.service" "rustfs.service" ];

        environment = {
          DATABASE_URL = cfg_server.databaseUrl;
          NATS_URL = cfg_server.natsUrl;
          S3_BUCKET = cfg_server.s3Bucket;
          RUST_LOG = "debug";
          AWS_ACCESS_KEY_ID = "minioadmin";
          AWS_SECRET_ACCESS_KEY = "minioadmin";
          AWS_REGION = "us-east-1";
          AWS_ENDPOINT_URL = "http://127.0.0.1:9000";
        };

        serviceConfig = {
          ExecStart = "${cfg_server.package}/bin/kubernix-server";
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
        path = [ pkgs.lix ];

        environment = {
          NATS_URL = cfg_worker.natsUrl;
          NIX_SYSTEM = cfg_worker.system;
          RUST_LOG = "debug";
        };

        serviceConfig = {
          ExecStart = "${cfg_worker.package}/bin/kubernix-worker";
          Restart = "always";
          DynamicUser = true;
        };
      };
    })
  ];
}
