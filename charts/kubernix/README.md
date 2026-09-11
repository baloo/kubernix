# kubernix

Helm chart for [Kubernix](../../DESIGN.md): the SSH/daemon-protocol frontend
(`kubernix-sshd`), binary cache (`kubernix-server`), retention/GC
(`kubernix-gc`), capability-secret rotation (`kubernix-rotate-capability-secret`)
and the worker pool (`kubernix-worker`), backed by PostgreSQL and NATS
JetStream.

## Dependencies

- **PostgreSQL**, via the [CloudNativePG](https://cloudnative-pg.io/) operator
  and its [Barman Cloud plugin](https://github.com/cloudnative-pg/plugin-barman-cloud)
  — gives the `Cluster` this chart creates streaming replication
  (`postgres.instances`, 1 primary + N standbys) and continuous WAL archiving
  + scheduled base backups to the same S3-compatible store Kubernix already
  uses (`postgres.backup.*`).
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
  `kubernix-sshd` require.
- **S3-compatible object storage** stays external (`s3.*` in `values.yaml`) —
  no MinIO subchart. Point it at a real bucket, or a MinIO you run yourself.

### `certManager.enabled`/`cnpg.enabled`: bundled operators vs. cluster-shared ones

`Chart.yaml` lists `cert-manager`, `cloudnative-pg`, and `plugin-barman-cloud` as dependencies.
All three install **cluster-scoped** CRDs + a controller — normally a once-per-cluster install, not
something every application release should bring its own copy of.

- **Single-tenant cluster, or trying this chart out**: leave both `certManager.enabled` and
  `cnpg.enabled` at `true` (the defaults). `helm install`/`helm upgrade` (staged — see Quickstart)
  brings up cert-manager, the CNPG operator, the plugin, and this release's `Cluster` together.
- **Shared cluster that already runs these**: set `certManager.enabled: false` and/or
  `cnpg.enabled: false` for whichever of them the cluster already has. With both false, this chart
  only creates its own `Cluster`/`ObjectStore`/`ScheduledBackup` resources
  (`templates/postgres-*.yaml`, still gated by `postgres.cluster.enabled` — see Quickstart) and the
  `db-role-passwords-job` hook that provisions `kubernix_app`/`kubernix_gc`'s passwords — it expects
  cert-manager, the operator, and the plugin to already be running cluster-wide.

## Known v1 limitations

- `kubernix-sshd` runs as a single replica (`sshd.replicas` isn't
  configurable): its generated SSH host key and any in-flight session live on
  one pod. See `PLAN.md` Phase 13.
- No KEDA autoscaling on NATS queue depth for the worker pool yet
  (`worker.autoscaling.enabled` is a stub for that follow-up) — scale
  `worker.replicas` manually in the meantime.
- Phase 15's per-tenant `cloud-hypervisor` VM feature (`/dev/kvm` passthrough)
  is not wired into this chart; the worker runs exactly as it does without it.

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
