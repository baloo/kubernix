# Kubernix

A distributed remote builder for [Lix](https://lix.systems). A stock Lix client points
`builders`/`substituters` at Kubernix exactly as it would at any other machine — but instead of
one SSH-reachable box building locally, the build is fanned out to a pool of Kubernetes-hosted
workers, each realising the derivation inside its own single-tenant VM.

See [DESIGN.md](DESIGN.md) for the full architecture and wire-protocol writeup,
[charts/kubernix/README.md](charts/kubernix/README.md) for deploying it, and
[docs/client-image.md](docs/client-image.md) for a ready-to-run client image if you'd rather not
build Lix/the plugin yourself.

## Architecture

```
                      ┌───────────────────────┐
                      │     Lix client        │
                      │ (kubernix:// plugin)  │
                      └──────────┬────────────┘
                                 │ SSH, Cap'n Proto RPC
                                 │ daemon protocol
                                 ▼
┌───────────────────────────────────────────────────────────────────────────┐
│ Frontend (kubernix-sshd / kubernix-server, "server" crate)                │
│                                                                           │
│   SSH surface                          HTTP surface                       │
│   ─────────────                        ────────────                       │
│   • auth_publickey → tenant_auth       • /nix-cache-info                  │
│     bindings lookup (Postgres)         • /<hash>.narinfo                  │
│   • serve daemon-protocol RPCs         • /nar/<...>                       │
│   • allocate job id, enqueue job       • /log/<drv-hash>                  │
│   • relay kubernix.logs.<job_id>       (binary-cache substituter path)    │
│     into the client's LogStream                                           │
└───────┬────────────────────────────┬─────────────────────────────┬────────┘
        │                            │                             │
        ▼                            ▼                             ▼
┌────────────────┐         ┌────────────────────┐        ┌───────────────────┐
│  PostgreSQL    │         │  NATS JetStream    │        │  S3-compatible    │
│  ────────────  │         │  ───────────────   │        │  object store     │
│  jobs          │         │  kubernix.jobs.*   │        │  ─────────────    │
│  store_paths   │         │  kubernix.logs.*   │        │  inputs, outputs  │
│  build_logs    │         │  kubernix.results.*│        │  (zstd NARs),     │
│  tenants       │         │                    │        │  build logs       │
│  tenant_auth_  │         └─────────┬──────────┘        └─────────┬─────────┘
│  bindings      │                   │                             │
└────────────────┘                   │ dequeue exactly             │ pre-signed
                                     │ one job                     │ PUT/GET URLs
                                     ▼                             │ (worker never
                          ┌───────────────────────────────┐        │  holds creds)
                          │ Worker pod (kubernix-worker)  │◄───────┘
                          │                               │
                          │  • fetch inputs from S3       │
                          │  • boot/reuse a per-tenant    │
                          │    cloud-hypervisor VM        │
                          │  • speak nix-daemon's worker  │
                          │    protocol over vsock        │
                          │  • upload outputs + log via   │
                          │    pre-signed URLs            │
                          └───────────────┬───────────────┘
                                          │ vsock
                                          ▼
        ┌──────────────────────────────────────────────────────────────────┐
        │ Per-tenant guest VM (cloud-hypervisor)                           │
        │                                                                  │
        │  stage 1: outer initramfs                                        │
        │  ┌───────────────────────────────────────────────────────────┐   │
        │  │ /init = guest-init (static musl trampoline)               │   │
        │  │   loop-mount /root.img (EROFS) → chroot → execv /init     │   │
        │  │   (works around pivot_root's anonymous-rootfs limit)      │   │
        │  └─────────────────────────┬─────────────────────────────────┘   │
        │                            ▼                                     │
        │  stage 2: /root.img (EROFS, read-only)                           │
        │  ┌────────────────────────────────────────────────────────────┐  │
        │  │ /init = guest-agent                                        │  │
        │  │   • mount /proc /sys /dev/pts, tmpfs /tmp + /nix/var       │  │
        │  │   • unlock + mount the tenant's dm-crypt store.img         │  │
        │  │   • accept a vsock connection, spawn `nix-daemon --stdio`  │  │
        │  │     and relay it byte for byte                             │  │
        │  └────────────────────────────────────────────────────────────┘  │
        └──────────────────────────────────────────────────────────────────┘
```

## Components

| Crate / dir | Role |
| --- | --- |
| `server/` | The frontend: SSH surface (`kubernix-sshd` binary) and HTTP binary cache (`kubernix-server` binary), sharing one Postgres-backed `Store`. |
| `worker/` | Dequeues jobs from NATS, drives a per-tenant guest VM over vsock, uploads results to S3. |
| `guest-agent/` | Runs as `/init` inside the guest VM's EROFS root; brings up mounts, unlocks the tenant's store image, relays `nix-daemon --stdio` over vsock. |
| `guest-init/` | The outer initramfs' `/init` — a minimal static trampoline that loop-mounts `/root.img` and hands off to `guest-agent`. See [DESIGN.md](DESIGN.md) and its own doc comment for why a two-stage boot is necessary at all. |
| `daemon-protocol/` | A minimal client for the real `nix-daemon` worker protocol, used by the worker to talk to the guest over vsock. |
| `plugin/` | The client-side Lix plugin (C++) registering the `kubernix://` store scheme — see [DESIGN.md](DESIGN.md#the-client-plugin) for why `ssh-ng://` itself can't be used. |
| `protocol/` | Vendored Cap'n Proto schemas (`daemon.capnp` and friends) the frontend's RPC surface implements. |
| `types/`, `signing/` | Shared store-path types and NAR/narinfo signing, used by both `server` and `worker`. |
| `charts/kubernix/` | The Helm chart deploying all of the above onto Kubernetes, plus PostgreSQL (CloudNativePG) and cert-manager as optional bundled dependencies. |

## Multi-tenancy

Tenants are provisioned manually: a row in `tenants`, plus one or more rows in
`tenant_auth_bindings` (`key_type`, `key_id`, `tenant`) binding an authentication credential to
that tenant — today only `key_type = 'ssh'`, keyed by the SHA256 fingerprint of the client's SSH
key, with a TLS/mTLS `key_type` designed into the schema for later. The bindings table is
authoritative: a key with no row is rejected outright, not given a fresh unverified tenant.

Each tenant's builds run inside their own `cloud-hypervisor` guest VM, with their own encrypted
(`dm-crypt`) Nix store image — one tenant's builder never shares a kernel, store, or VM with
another's.

## Warning

While the design is solid and I stand by it, a substantial amount of the code was written with the help of an LLM.
Bugs have not been flushed out yet.
