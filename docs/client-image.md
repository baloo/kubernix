# Client image

`ghcr.io/baloo/kubernix/kubernix-client` bundles a stock [Lix](https://lix.systems) plus the
`kubernix://` client plugin (`plugin/`, see [DESIGN.md](../DESIGN.md#the-client-plugin)), so you
don't need to build either yourself to use a kubernix cluster as a remote builder. If you'd rather
build your own Lix/plugin instead of using this image, see the manual client configuration in
[DESIGN.md](../DESIGN.md).

```console
docker pull ghcr.io/baloo/kubernix/kubernix-client:latest
```

## What you need to provide

Two things, both at `docker run` time:

- **An SSH private key** for a tenant already provisioned on the cluster (see
  [README.md](../README.md#multi-tenancy) — the frontend identifies your tenant by this key's
  fingerprint). Mount it read-only into the container. By default the image looks for it at
  `/run/secrets/kubernix-ssh-key`; override the path with `KUBERNIX_SSH_KEY`.
- **The frontend's SSH endpoint**, via the `KUBERNIX_SSH_HOST` environment variable (e.g.
  `kubernix-ssh.host`). This is required — the container refuses to start without it.

The SSH (builder) and HTTPS (substituter) endpoints are separate services and commonly live on
different hostnames — set `KUBERNIX_HTTP_HOST` too if yours do (it defaults to
`KUBERNIX_SSH_HOST`, which only works if one hostname serves both).

## Environment variables

| Variable | Default | Meaning |
| --- | --- | --- |
| `KUBERNIX_SSH_HOST` | *(required)* | Frontend's SSH hostname/IP — used for the `kubernix://` builder. |
| `KUBERNIX_HTTP_HOST` | `KUBERNIX_SSH_HOST` | Frontend's HTTPS hostname/IP — used as the substituter URL. Set this explicitly whenever it differs from the SSH endpoint. |
| `KUBERNIX_SSH_KEY` | `/run/secrets/kubernix-ssh-key` | Path (inside the container) to your tenant's SSH private key. |
| `KUBERNIX_PORT` | `22` | SSH port the frontend listens on. |
| `KUBERNIX_SYSTEMS` | `x86_64-linux,aarch64-linux` | Systems advertised for this builder entry. |
| `KUBERNIX_SUBSTITUTE` | `1` | Set to `0` to skip configuring the frontend as a substituter (build-only, no cache pulls). |
| `KUBERNIX_TRUSTED_PUBLIC_KEY` | *(unset)* | The cluster's narinfo signing key, e.g. `builder.example.org:<base64 key>` — set this to let Lix trust substituted outputs without `--no-check-sigs`. |

The container's entrypoint turns these into a `NIX_CONFIG` (`plugin-files`, `builders`,
`substituters`, `trusted-public-keys`) before running your command, so any `nix` invocation you
pass in already talks to the cluster. It also sets `max-jobs = 0` (no local build slots — this
image ships no compiler toolchain and can't sandbox a local build anyway) and
`builders-use-substitutes = true` (the kubernix builder pulls inputs from substituters itself
rather than you uploading them), so builds go exclusively through the remote builder.

## Example

```console
docker run --rm \
  -v "$PWD":/work -w /work \
  -v ~/.ssh/id_kubernix:/run/secrets/kubernix-ssh-key:ro \
  -e KUBERNIX_SSH_HOST=kubernix-ssh.host \
  -e KUBERNIX_HTTP_HOST=kubernix.host \
  ghcr.io/baloo/kubernix/kubernix-client:latest \
  nix build .#foo
```

Running the image with no command (`docker run -it ... bash`) drops you into a shell with Lix and
the plugin already configured, useful for `nix build`/`nix copy`/`nix store ping` one-offs.

Each run starts from the image's own baked-in `/nix/store` — anything built or substituted during
a run is discarded when the container exits, so there's nothing to mount for persistence across
runs.

## Running as a Zuul CI node {#zuul}

The same image can double as a [Zuul](https://zuul-ci.org) Nodepool node — its own Nix closure has
no FHS by default (no `/bin/sh`, `/usr/bin/env`, `/etc/passwd`, writable `/tmp`), which is what
Ansible's module execution and the `zuul-jobs` base roles assume, so the image bakes in that
scaffolding plus `python3`, `git`, and `tar`/`gzip` (for `kubectl cp`/`oc rsync`) alongside Lix.

Use Nodepool's **Kubernetes or OpenShift pod driver**, not the SSH connection: `kubectl exec`
needs no sshd, host keys, or login user, which this image doesn't provide. In the pod's Nodepool
label:

- Set `python-path: /bin/python3` — this pins Ansible's interpreter instead of relying on its FHS
  discovery fallback list (`/usr/bin/python3`, `python3.7`, ...), none of which exist in this
  image.
- Set `shell-type: sh`.
- Prefer the `prepare-workspace-git` (or `prepare-workspace-openshift`, using `oc rsync`)
  `zuul-jobs` role over plain `prepare-workspace`, which uses `synchronize` (rsync) — not
  guaranteed to work over the `kubectl` connection.
- On the executor side: `kubectl` and `socat` installed, Nodepool ≥ 3.12.0, and the
  `start-zuul-console` role in your base pre-playbook — all per the Zuul Kubernetes driver docs,
  independent of this image.

Note that Nodepool's pod spec sets its own container `command` to keep the pod alive (Zuul never
runs a build through this image's `ENTRYPOINT`/`CMD` — jobs reach the container via `kubectl exec`
instead), so `KUBERNIX_SSH_HOST` and friends above are irrelevant to the Zuul path unless a job
explicitly wants to use `nix`/kubernix from inside its playbook — in which case set them as static
env vars on the pod/label (not via this image's entrypoint, which those `kubectl exec` sessions
don't go through).
