# kubernix

Helm chart for [Kubernix](../../DESIGN.md): the SSH/daemon-protocol frontend
(`kubernix-sshd`), binary cache (`kubernix-server`), retention/GC
(`kubernix-gc`), capability-secret rotation (`kubernix-rotate-capability-secret`)
and the worker pool (`kubernix-worker`), backed by PostgreSQL and NATS
JetStream.

## Dependencies

- **PostgreSQL**, via either the [CloudNativePG](https://cloudnative-pg.io/)
  operator and its [Barman Cloud plugin](https://github.com/cloudnative-pg/plugin-barman-cloud)
  (`postgres.operator: cnpg`, the default), or an already-installed Zalando
  Postgres Operator (`postgres.operator: zalando`). CNPG mode creates
  `Cluster`/`ObjectStore`/`ScheduledBackup` resources and can bundle the
  operator dependencies below. Zalando mode creates an `acid.zalan.do/v1`
  `postgresql` resource and expects that operator to already be installed
  cluster-wide.
- **[cert-manager](https://cert-manager.io/)**, bundled alongside the two
  above under its own `certManager.enabled` condition: `plugin-barman-cloud`
  always creates a self-signed `Issuer`/`Certificate` for its webhook/CNPG-I
  serving certs (`certificate.createIssuer`/`createServerCertificate` in its
  own `values.yaml`, both on by default) — a hard dependency of that chart,
  not something `cnpg.enabled: false` avoids either. Its own condition
  (rather than folded into `cnpg.enabled`) because its CRDs have to exist
  before `plugin-barman-cloud`'s `Certificate`/`Issuer` can — see the
  Quickstart's staged install below.
- **NATS**, with JetStream forced on — the job queue `kubernix-worker`/
  `kubernix-sshd` require. `nats.service.ports.monitor.enabled: true` also
  exposes its monitoring HTTP API (port 8222) so `worker.autoscaling`'s KEDA
  scaler can query queue depth.
- **[KEDA](https://keda.sh/)**, bundled alongside the operators below under
  its own `keda.enabled` condition — scales the worker Deployment
  (`worker.autoscaling`) on `kubernix_jobs`' NATS JetStream queue depth.
- **S3-compatible object storage** stays external (`s3.*` in `values.yaml`) —
  no MinIO subchart. Point it at a real bucket, or a MinIO you run yourself.

### `certManager.enabled`/`cnpg.enabled`/`keda.enabled`: bundled operators vs. cluster-shared ones

`Chart.yaml` lists `cert-manager`, `cloudnative-pg`, `plugin-barman-cloud`, and `keda` as
dependencies. All install **cluster-scoped** CRDs + a controller — normally a once-per-cluster
install, not something every application release should bring its own copy of.

- **Single-tenant cluster, or trying this chart out**: leave `certManager.enabled`, `cnpg.enabled`
  and `keda.enabled` at `true` (the defaults). `helm install`/`helm upgrade` (staged — see
  Quickstart) brings up cert-manager, the CNPG operator, the plugin, KEDA, and this release's
  `Cluster` together.
- **Shared cluster that already runs these**: set `certManager.enabled: false`, `cnpg.enabled:
  false` and/or `keda.enabled: false` for whichever of them the cluster already has. With
  `certManager`/`cnpg` both false, this chart only creates its own
  `Cluster`/`ObjectStore`/`ScheduledBackup` resources (`templates/postgres-*.yaml`, still gated by
  `postgres.cluster.enabled` — see Quickstart) and the `db-role-passwords-job` hook that provisions
  `kubernix_app`/`kubernix_gc`'s passwords — it expects cert-manager, the operator, and the plugin
  to already be running cluster-wide. With `keda` false, it expects KEDA's CRDs/controller to
  already be registered before `worker.autoscaling.enabled` is turned on.
- **Shared cluster with Zalando Postgres Operator**: set `postgres.operator: zalando`,
  `certManager.enabled: false`, and `cnpg.enabled: false`. The chart creates only a namespaced
  Zalando `postgresql` resource plus the Kubernix app resources; it reads the bootstrap credentials
  from the Zalando-generated `<user>.<cluster>.credentials.postgresql.acid.zalan.do` Secret. WAL-G
  backups use the same `postgres.backup.s3` endpoint/bucket/credentials block as CNPG mode, with
  the Zalando-specific schedule and retention count under `postgres.zalando.backup`.

## Known v1 limitations

- `kubernix-sshd` runs as a single replica (`sshd.replicas` isn't
  configurable): its generated SSH host key and any in-flight session live on
  one pod. See `PLAN.md` Phase 13.
- Phase 15's per-tenant `cloud-hypervisor` VM isolation is the only mode the
  worker runs jobs in (`worker.vm.*` sizes each tenant's VM); this needs a
  `devices.kubevirt.io/kvm`-style device-plugin DaemonSet already running on
  the cluster (`worker.vm.kvmResourceName` names the extended resource it
  registers) — without one, the worker pod never gets `/dev/kvm` and every
  job fails to boot its VM. Networking (Step 5) and per-tenant substituter
  credentials (Step 6) aren't implemented yet, so a guest can't reach any
  substituter — only the inputs the worker stages itself are available to a
  build. See `PLAN.md` Phase 15.

## Quickstart

A first install with `certManager.enabled`/`cnpg.enabled: true` (the defaults) needs **three
passes** when none of cert-manager/CNPG/plugin-barman-cloud's CRDs already exist in the cluster:
Helm validates every object in a release against the API server's known types before applying any
of them, so a CRD and a custom resource of that CRD's kind can't land in the same `helm install` —
and that applies twice over here, once between cert-manager's CRDs and `plugin-barman-cloud`'s own
`Certificate`/`Issuer` resources, and again between CNPG's CRDs and this chart's own
`Cluster`/`ObjectStore`/`ScheduledBackup`. Bring each layer up before the next one needs it:

```console
helm dependency update charts/kubernix

# Pass 1: cert-manager only.
helm install kubernix charts/kubernix -n kubernix --create-namespace \
  --set cnpg.enabled=false \
  --set postgres.cluster.enabled=false

# Pass 2: cert-manager's CRDs exist now, so the CNPG operator + plugin-barman-cloud
# (which needs a Certificate/Issuer from cert-manager) can come up.
helm upgrade kubernix charts/kubernix -n kubernix \
  --set postgres.cluster.enabled=false

# Pass 3: CNPG's CRDs exist now, so the Cluster/ObjectStore/ScheduledBackup can too.
helm upgrade kubernix charts/kubernix -n kubernix
```

On a cluster that already has cert-manager and/or CNPG/plugin-barman-cloud running
(`certManager.enabled: false`/`cnpg.enabled: false`) or already has their CRDs registered from a
previous install, skip straight past the corresponding pass(es).

### Enabling worker autoscaling

`worker.autoscaling.enabled` defaults to `false` for the same CRD-ordering reason as
`postgres.cluster.enabled` above: KEDA's `ScaledObject` kind can't land in the same `helm install`
that first registers KEDA's own CRDs. Once the passes above have brought KEDA up (or it's already
running cluster-wide with `keda.enabled: false`):

```console
helm upgrade kubernix charts/kubernix -n kubernix --set worker.autoscaling.enabled=true
```

This creates a `ScaledObject` that scales the worker Deployment on `kubernix_jobs`' durable
per-system consumer (`worker/src/main.rs`) — including down to `minReplicaCount: 0` when idle. That
works because the consumer is *durable*: its pending-message count stays queryable via NATS'
monitoring API with no worker pod running, which is what lets KEDA scale back up from zero.

### Provisioning tenants (`kubernix-admin`)

Tenants and their auth credentials (`server/src/admin.rs`) are managed with `kubernix-admin`, which
ships in the same image as `kubernix-sshd`/`kubernix-cache`/`kubernix-gc`. There's no dedicated
subcommand-taking Job for it — its arguments (a tenant id, an SSH public key) are decided per
invocation, not at `helm install` time — so `admin.enabled: true` instead brings up an idle toolbox
Deployment an operator `kubectl exec`s into:

```console
helm upgrade kubernix charts/kubernix -n kubernix --set admin.enabled=true

# add-tenant takes a name, not an id -- the id is derived from it and
# printed back, so there's nothing to hand-type or get wrong there.
kubectl exec -it -n kubernix deploy/kubernix-admin -- \
  kubernix-admin add-tenant some-customer
# added tenant "some-customer" as name-some-customer-a1b2c3d4e5f60000

kubectl exec -it -n kubernix deploy/kubernix-admin -- \
  kubernix-admin add-credential name-some-customer-a1b2c3d4e5f60000 --type ssh "ssh-ed25519 AAAA... their-key"
```

Leave `admin.enabled` at its default `false` otherwise: it's a live path to a role that can create
tenants and bind auth credentials, worth running only where and while it's actually needed.
