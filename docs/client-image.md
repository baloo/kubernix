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
- **The frontend endpoint**, via the `KUBERNIX_HOST` environment variable (e.g.
  `kubernix.host`). This is required — the container refuses to start without it.

## Environment variables

| Variable | Default | Meaning |
| --- | --- | --- |
| `KUBERNIX_HOST` | *(required)* | Frontend hostname/IP to build against. |
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
  -e KUBERNIX_HOST=kubernix.host \
  ghcr.io/baloo/kubernix/kubernix-client:latest \
  nix build .#foo
```

Running the image with no command (`docker run -it ... bash`) drops you into a shell with Lix and
the plugin already configured, useful for `nix build`/`nix copy`/`nix store ping` one-offs.

Each run starts from the image's own baked-in `/nix/store` — anything built or substituted during
a run is discarded when the container exits, so there's nothing to mount for persistence across
runs.
