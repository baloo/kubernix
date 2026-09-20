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
  coreutils,
  lix,
  cloud-hypervisor,
  passt,
  kubernix-server,
  kubernix-worker,
  # Phase 15's per-tenant guest VM (`nix/guest-vm.nix`) — baked into this
  # image unconditionally, not left to the chart to supply. Per-tenant VM
  # isolation is the only mode this worker runs in (see the Env comment
  # below); a kernel/initrd pair the image doesn't ship would make that a
  # deployment-time footgun instead of something that just works.
  guestVmKernel,
  guestVmInitrd,
}:

{
  kubernix-server-image = dockerTools.buildLayeredImage {
    name = "kubernix-server";
    tag = "latest";
    contents = [
      kubernix-server
      cacert
      tzdata
      # Only for `sleep infinity` in the chart's `admin-deployment.yaml`
      # toolbox — an operator `kubectl exec`s into it to run `kubernix-admin`,
      # and it needs *something* to sit idle on since this image otherwise
      # ships no shell/coreutils at all.
      coreutils
    ];
    # No `Cmd`: the chart's `command:`/`args:` selects one of
    # kubernix-sshd/kubernix-server/kubernix-gc/kubernix-rotate-capability-secret/
    # `sleep` (the admin toolbox) per Deployment, all present in this one
    # image's `/bin`.
    config = {
      Env = [ "SSL_CERT_FILE=${cacert}/etc/ssl/certs/ca-bundle.crt" ];
    };
  };

  kubernix-worker-image = dockerTools.buildLayeredImage {
    name = "kubernix-worker";
    tag = "latest";
    # No /tmp at all otherwise — dockerTools doesn't create one by default,
    # and Nix needs real scratch space there for every build. The
    # `guest-vm/{bzImage,initrd}` symlinks give `KUBERNIX_VM_KERNEL`/
    # `KUBERNIX_VM_INITRD` below a stable path, since the underlying
    # `/nix/store/<hash>-...` path isn't something the chart should have to
    # know at deploy time.
    extraCommands = ''
      mkdir -p tmp && chmod 1777 tmp
      mkdir -p guest-vm
      ln -s ${guestVmKernel}/bzImage guest-vm/bzImage
      ln -s ${guestVmInitrd}/initrd guest-vm/initrd
    '';
    contents = [
      kubernix-worker
      # Mirrors `nix/module.nix`'s
      # `path = [ pkgs.lix pkgs.cloud-hypervisor pkgs.passt ]` for
      # `systemd.services.kubernix-worker`: the worker shells out to
      # `nix-store`/`nix`, drives the per-tenant guest VM via
      # `cloud-hypervisor` itself (see the Env comment below), and (Phase 15
      # Step 5) gives it network egress via `passt` as its vhost-user
      # backend — unlike `nix/module.nix`'s `vmKernel`-gated `optionalAttrs`,
      # VM isolation is unconditional in this image (see that comment below
      # too), so `passt` is unconditional here as well, not behind a flag.
      lix
      cloud-hypervisor
      passt
      cacert
      guestVmKernel
      guestVmInitrd
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
        # Per-tenant `cloud-hypervisor` VM isolation (PLAN.md Phase 15) is
        # the only mode this worker runs jobs in — these two make
        # `worker/src/vm.rs::VmConfig::from_env` construct a `VmPool`
        # unconditionally, rather than being a deployment-time opt-in (see
        # `nix/module.nix`'s `vmKernel`/`vmInitrd`, which stay optional for
        # the NixOS module's own dev/test uses). `KUBERNIX_NIX_STORE` above
        # remains what a job falls back to only if that specific job's VM
        # fails to boot or connect — not a parallel supported mode.
        "KUBERNIX_VM_KERNEL=/guest-vm/bzImage"
        "KUBERNIX_VM_INITRD=/guest-vm/initrd"
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
