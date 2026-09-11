# OCI images for the Helm chart (`charts/kubernix/`). Two images, not five:
# every `server`-crate binary (`kubernix-sshd`, `kubernix-server`,
# `kubernix-gc`, `kubernix-rotate-capability-secret`) ships from one image,
# built once from `kubernix-server`, and the chart's Deployments pick which
# binary to run via `command:`. `kubernix-worker` gets its own image, since it
# needs `lix`/`cloud-hypervisor` on `PATH` and nothing else here does.
{
  dockerTools,
  cacert,
  tzdata,
  lix,
  cloud-hypervisor,
  kubernix-server,
  kubernix-worker,
}:

{
  kubernix-server-image = dockerTools.buildLayeredImage {
    name = "kubernix-server";
    tag = "latest";
    contents = [
      kubernix-server
      cacert
      tzdata
    ];
    # No `Cmd`: the chart's `command:`/`args:` selects one of
    # kubernix-sshd/kubernix-server/kubernix-gc/kubernix-rotate-capability-secret
    # per Deployment, all present in this one image's `/bin`.
    config = {
      Env = [ "SSL_CERT_FILE=${cacert}/etc/ssl/certs/ca-bundle.crt" ];
    };
  };

  kubernix-worker-image = dockerTools.buildLayeredImage {
    name = "kubernix-worker";
    tag = "latest";
    # No /tmp at all otherwise — dockerTools doesn't create one by default,
    # and Nix needs real scratch space there for every build.
    extraCommands = "mkdir -p tmp && chmod 1777 tmp";
    contents = [
      kubernix-worker
      # Mirrors `nix/module.nix`'s `path = [ pkgs.lix pkgs.cloud-hypervisor ]`
      # for `systemd.services.kubernix-worker`: the worker shells out to
      # `nix-store`/`nix` and, when Phase 15's per-tenant VM feature is
      # enabled, `cloud-hypervisor` itself.
      lix
      cloud-hypervisor
      cacert
    ];
    config = {
      Cmd = [ "${kubernix-worker}/bin/kubernix-worker" ];
      Env = [
        "SSL_CERT_FILE=${cacert}/etc/ssl/certs/ca-bundle.crt"
        # No /etc/passwd in this image at all (no NSS database), so Nix's own
        # uid lookup for a home directory fails outright ("cannot determine
        # user's home directory") under any non-root uid — set $HOME
        # unconditionally rather than relying on whichever orchestrator runs
        # this image to know to set it.
        "HOME=/var/lib/kubernix-worker/home"
        # A chroot store, not the image's real (read-only, empty)
        # /nix/store — see nix/module.nix's `store` option doc: this is also
        # what lets a non-root, non-daemon worker build input-addressed
        # derivations at all. Whatever runs this image just needs to mount
        # writable storage at /var/lib/kubernix-worker.
        "KUBERNIX_NIX_STORE=local?root=/var/lib/kubernix-worker/store"
        # The worker's own container is already namespaced by its
        # container runtime; nesting Nix's build sandbox inside that needs
        # unprivileged user namespaces, which most Kubernetes nodes don't
        # expose to pods (`Sandboxing is enabled ... this system does not
        # support the kernel namespaces that are required`). Same trade-off
        # any nested-container CI/build worker makes — losing the sandbox's
        # extra isolation, not privilege, since the worker's chroot store
        # and non-root uid still hold.
        #
        # `experimental-features = nix-command`: worker/src/upload.rs shells
        # out to `nix store dump-path` (deliberately, over the legacy
        # `nix-store --dump` — see its own comment) to stream a NAR for
        # upload, and that subcommand lives behind this still-experimental
        # flag with no other way to enable it per-invocation.
        "NIX_CONFIG=sandbox = false\nexperimental-features = nix-command"
      ];
    };
  };
}
