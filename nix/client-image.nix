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
      if [ -n "''${KUBERNIX_SSH_HOST_KEY:-}" ]; then
        # Without this, Lix's `SSH` class (plugin/src/plugin.cc) falls back to
        # OpenSSH's normal known_hosts/StrictHostKeyChecking behaviour, which
        # means an interactive prompt on first connect -- and since this image
        # is meant to run non-interactively (`docker run ... nix build`), ssh
        # just refuses instead of prompting. Pinning the host key here (the
        # `base64-ssh-public-host-key` store setting, decoded and written to a
        # throwaway UserKnownHostsFile by ssh.cc) skips that prompt entirely.
        # Value is `base64 -w0` of the frontend's `host_ed25519.pub` file
        # as-is (i.e. the whole "ssh-ed25519 AAAA... comment" line, base64'd).
        builder="''${builder}&base64-ssh-public-host-key=''${KUBERNIX_SSH_HOST_KEY}"
      fi

      conf="experimental-features = nix-command flakes
      # This image ships no compiler toolchain and (being an ordinary
      # container, not a Nix build sandbox host) can't run a sandboxed local
      # build anyway -- max-jobs=0 makes that explicit instead of an
      # accidental local build silently succeeding or failing oddly, and
      # builders-use-substitutes lets the remote builder pull inputs from
      # substituters itself rather than the client uploading them first.
      max-jobs = 0
      # No FHS /etc/group in this image (fakeNss's is baked in at build time
      # and has no 'nixbld' entry) -- Lix otherwise warns on every invocation
      # that build-users-group's default ('nixbld') doesn't exist. Harmless
      # since max-jobs=0 means it's never actually used to sandbox a build,
      # but silencing it here beats every consumer discovering and setting
      # this themselves.
      build-users-group =
      builders-use-substitutes = true
      plugin-files = ${kubernix-plugin}/lib/lix/plugins/kubernix.so
      builders = ''${builder} ''${KUBERNIX_SYSTEMS}"

      if [ "''${KUBERNIX_SUBSTITUTE}" != "0" ]; then
        substituters=""
        trusted_public_keys=""

        # Ask kubernix-sshd for this tenant's own id/key and its configured
        # trusted substituters (server/src/ssh.rs's `kubernix-whoami` exec) --
        # a plain SSH request, no Lix/capnp involved, run *before* nix.conf
        # is even written. This is what lets a client automatically benefit
        # from server-side `trusted_substituters` (server/src/substitute.rs)
        # -- those live in kubernix's own database, invisible to any client-
        # side config, and are served from their own `/<tenant>/upstream/
        # <slug>/…` mirror route (server/src/http.rs), never the tenant's own
        # narinfo namespace. Best-effort: a client that cannot reach this (a
        # firewalled host, an older server without this exec, or simply no
        # pinned host key to authenticate the request non-interactively)
        # falls back to the old, manually-configured behaviour below rather
        # than failing the whole entrypoint.
        whoami_output=""
        if [ -n "''${KUBERNIX_SSH_HOST_KEY:-}" ]; then
          known_hosts="$(mktemp)"
          trap 'rm -f "''${known_hosts}"' EXIT
          # `KUBERNIX_SSH_HOST_KEY` decodes to a bare `<keytype> <key>
          # <comment>` line (the same one Lix's own `base64-ssh-public-
          # host-key` handling above takes as-is) -- but a plain `ssh`
          # invocation's `known_hosts` format requires a leading hostname
          # field, which that value never carried. OpenSSH stores (and
          # matches) the *default* port 22 as a bare hostname and only
          # every other port bracketed as `[host]:port` -- confirmed
          # against a real `ssh`, which refuses to match a bracketed
          # `[host]:22` entry at all.
          if [ "''${KUBERNIX_PORT}" = "22" ]; then
            host_entry="''${KUBERNIX_SSH_HOST}"
          else
            host_entry="[''${KUBERNIX_SSH_HOST}]:''${KUBERNIX_PORT}"
          fi
          echo "''${host_entry} $(echo "''${KUBERNIX_SSH_HOST_KEY}" | base64 -d)" \
            > "''${known_hosts}"
          whoami_output="$(ssh -i "''${KUBERNIX_SSH_KEY}" -p "''${KUBERNIX_PORT}" \
            -o BatchMode=yes -o UserKnownHostsFile="''${known_hosts}" -o StrictHostKeyChecking=yes \
            "kubernix@''${KUBERNIX_SSH_HOST}" kubernix-whoami 2>/dev/null || true)"
        fi

        tenant_id=""
        while IFS=' ' read -r kind a _url c; do
          case "''${kind}" in
            tenant) tenant_id="''${a}" ;;
            key) trusted_public_keys="''${trusted_public_keys} ''${a}" ;;
            # `substituter <slug> <url> <public-key>` -- the url is rebuilt
            # from the slug rather than trusted verbatim from the wire, same
            # reasoning as every other tenant-prefixed path in this codebase.
            substituter)
              substituters="''${substituters} https://''${KUBERNIX_HTTP_HOST}/''${tenant_id}/upstream/''${a}"
              trusted_public_keys="''${trusted_public_keys} ''${c}"
              ;;
            *) ;;
          esac
        done <<< "''${whoami_output}"

        if [ -n "''${tenant_id}" ]; then
          substituters="https://''${KUBERNIX_HTTP_HOST}/''${tenant_id}''${substituters}"
        else
          # Discovery failed or was skipped -- the pre-discovery behaviour,
          # unchanged: a bare host (an operator-set `KUBERNIX_HTTP_HOST`
          # already including a tenant path, if that's how this deployment
          # was configured) and whatever key was configured by hand.
          substituters="https://''${KUBERNIX_HTTP_HOST}"
          if [ -n "''${KUBERNIX_TRUSTED_PUBLIC_KEY:-}" ]; then
            trusted_public_keys="''${KUBERNIX_TRUSTED_PUBLIC_KEY}"
          fi
        fi

        conf="''${conf}
      substituters = ''${substituters}"
        if [ -n "''${trusted_public_keys# }" ]; then
          conf="''${conf}
      trusted-public-keys = ''${trusted_public_keys}"
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
