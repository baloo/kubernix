# A client-facing image published to ghcr.io/baloo/kubernix/kubernix-client: a stock Lix plus
# the `kubernix://` plugin (nix/plugin.nix), ready to build against a kubernix cluster as soon as
# the consumer injects an SSH private key and the frontend endpoint at `docker run` time — see
# docs/client-image.md.
{
  dockerTools,
  writeShellApplication,
  cacert,
  lix,
  openssh,
  bashInteractive,
  coreutils,
  gnugrep,
  kubernix-plugin,
}:

let
  entrypoint = writeShellApplication {
    name = "kubernix-client-entrypoint";
    text = ''
      : "''${KUBERNIX_HOST:?KUBERNIX_HOST must be set to the kubernix frontend hostname/IP}"
      : "''${KUBERNIX_PORT:=22}"
      : "''${KUBERNIX_SSH_KEY:=/run/secrets/kubernix-ssh-key}"
      : "''${KUBERNIX_SYSTEMS:=x86_64-linux,aarch64-linux}"
      : "''${KUBERNIX_SUBSTITUTE:=1}"

      # `kubernix` is a fixed literal, not the consumer's own username -- the
      # frontend identifies the tenant by the SSH key's fingerprint (see
      # DESIGN.md's Multi-tenancy section), not by who connects as.
      conf="experimental-features = nix-command flakes
      # This image ships no compiler toolchain and (being an ordinary
      # container, not a Nix build sandbox host) can't run a sandboxed local
      # build anyway -- max-jobs=0 makes that explicit instead of an
      # accidental local build silently succeeding or failing oddly, and
      # builders-use-substitutes lets the remote builder pull inputs from
      # substituters itself rather than the client uploading them first.
      max-jobs = 0
      builders-use-substitutes = true
      plugin-files = ${kubernix-plugin}/lib/lix/plugins/kubernix.so
      builders = kubernix://kubernix@''${KUBERNIX_HOST}?ssh-key=''${KUBERNIX_SSH_KEY}&port=''${KUBERNIX_PORT} ''${KUBERNIX_SYSTEMS}"

      if [ "''${KUBERNIX_SUBSTITUTE}" != "0" ]; then
        conf="''${conf}
      substituters = https://''${KUBERNIX_HOST}"
        if [ -n "''${KUBERNIX_TRUSTED_PUBLIC_KEY:-}" ]; then
          conf="''${conf}
      trusted-public-keys = ''${KUBERNIX_TRUSTED_PUBLIC_KEY}"
        fi
      fi

      export NIX_CONFIG="''${NIX_CONFIG:-}
      ''${conf}"

      exec "$@"
    '';
  };
in

dockerTools.buildLayeredImage {
  name = "kubernix-client";
  tag = "latest";
  contents = [
    lix
    kubernix-plugin
    # The plugin drives SSH itself via Lix's `SSH` class (plugin/src/plugin.cc,
    # `#include <lix/libstore/ssh.hh>`), which shells out to a real `ssh` binary.
    openssh
    bashInteractive
    coreutils
    gnugrep
    cacert
  ];
  config = {
    Entrypoint = [ "${entrypoint}/bin/kubernix-client-entrypoint" ];
    Cmd = [ "bash" ];
    Env = [
      "SSL_CERT_FILE=${cacert}/etc/ssl/certs/ca-bundle.crt"
      # No /etc/passwd in this image (no NSS database) -- root's default $HOME
      # is otherwise unset, which breaks Nix's own uid->home lookup.
      "HOME=/root"
    ];
  };
}
