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
  gnutar,
  gzip,
  git,
  python3,
  kubernix-plugin,
}:

let
  entrypoint = writeShellApplication {
    name = "kubernix-client-entrypoint";
    text = ''
      : "''${KUBERNIX_SSH_HOST:?KUBERNIX_SSH_HOST must be set to the kubernix frontend SSH hostname/IP}"
      : "''${KUBERNIX_PORT:=22}"
      : "''${KUBERNIX_SSH_KEY:=/run/secrets/kubernix-ssh-key}"
      : "''${KUBERNIX_SYSTEMS:=x86_64-linux,aarch64-linux}"
      : "''${KUBERNIX_SUBSTITUTE:=1}"
      # The SSH (builder) and HTTPS (substituter) endpoints are separate
      # services and commonly live on different hostnames -- e.g. this
      # cluster's own kubernix-ssh.sf.superbaloo.net vs.
      # kubernix.sf.superbaloo.net. Defaulting to KUBERNIX_SSH_HOST only
      # covers the (less common) case where one hostname serves both.
      : "''${KUBERNIX_HTTP_HOST:=''${KUBERNIX_SSH_HOST}}"

      # `kubernix` is a fixed literal, not the consumer's own username -- the
      # frontend identifies the tenant by the SSH key's fingerprint (see
      # DESIGN.md's Multi-tenancy section), not by who connects as.
      builder="kubernix://kubernix@''${KUBERNIX_SSH_HOST}?ssh-key=''${KUBERNIX_SSH_KEY}&port=''${KUBERNIX_PORT}"

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
      builders = ''${builder} ''${KUBERNIX_SYSTEMS}"

      if [ "''${KUBERNIX_SUBSTITUTE}" != "0" ]; then
        conf="''${conf}
      substituters = https://''${KUBERNIX_HTTP_HOST}"
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
    # Everything below this line exists only so this image can double as a
    # Zuul (Nodepool Kubernetes/OpenShift pod driver) CI node, not for the
    # `docker run`-a-build use case above -- see docs/client-image.md#zuul.
    # A `dockerTools` closure has no FHS at all (no /bin/sh, /usr/bin/env,
    # /etc/passwd, writable /tmp): Ansible's module execution and the
    # `zuul-jobs` base roles (prepare-workspace*, interpreter discovery)
    # assume all of that exists, so it's added deliberately rather than
    # discovered.
    dockerTools.binSh # /bin/sh -> bash, for `shell-type: sh` / `become`
    dockerTools.usrBinEnv # /usr/bin/env, for `#!/usr/bin/env ...` shebangs
    dockerTools.fakeNss # /etc/passwd, /etc/group, /etc/nsswitch.conf
    python3 # pin the label's `python-path` to this instead of relying
    # on Ansible's FHS interpreter-discovery fallback list
    gnutar
    gzip # `kubectl cp`/`oc rsync` shell out to tar on the pod side
    git # for the `prepare-workspace-git` zuul-jobs role
  ];
  extraCommands = ''
    mkdir -p tmp && chmod 1777 tmp
  '';
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
