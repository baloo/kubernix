{{/*
Chart name, truncated/sanitized the way every stock Helm chart scaffold does
(kept here rather than pulled in from a library chart, since this is the only
helper more than one template needs).
*/}}
{{- define "kubernix.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "kubernix.fullname" -}}
{{- printf "%s" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "kubernix.labels" -}}
app.kubernetes.io/name: {{ include "kubernix.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{/*
PLAN.md Phase 18: KUBERNIX_VM_MEMORY_MB, chart-computed from
worker.resources.limits.memory minus worker.vm.overheadMb rather than an
independent operator-set value -- removes one way for the two settings to
drift out of sync. worker.vm.memoryMb, if set, is an explicit override that
wins outright. Falls back to the old fixed default (768) when neither is
set, matching today's behaviour for anyone who hasn't set resource limits.
Only a plain Mi/Gi quantity is supported for worker.resources.limits.memory
(Helm has no built-in Kubernetes-quantity parser); anything else fails
loudly with a clear message rather than silently miscomputing.
*/}}
{{- define "kubernix.worker.vmMemoryMb" -}}
{{- if .Values.worker.vm.memoryMb -}}
{{- .Values.worker.vm.memoryMb -}}
{{- else if (dig "limits" "memory" "" .Values.worker.resources) -}}
{{- $mem := dig "limits" "memory" "" .Values.worker.resources -}}
{{- if not (regexMatch "^[0-9]+(Mi|Gi)$" $mem) -}}
{{- fail (printf "worker.resources.limits.memory %q must be a plain Mi/Gi quantity (e.g. \"2Gi\") for worker.vm.memoryMb to be computed from it -- set worker.vm.memoryMb explicitly instead" $mem) -}}
{{- end -}}
{{- $overhead := int .Values.worker.vm.overheadMb -}}
{{- $num := regexFind "^[0-9]+" $mem | int -}}
{{- $limitMb := $num -}}
{{- if hasSuffix "Gi" $mem -}}
{{- $limitMb = mul $num 1024 -}}
{{- end -}}
{{- max 128 (sub $limitMb $overhead) -}}
{{- else -}}
768
{{- end -}}
{{- end -}}

{{/*
Per-component selector labels — every Deployment/Service/Job below is one of
sshd, cache, gc, rotate, worker, or the db-role-passwords/sshd-hostkey hooks.
Call as `include "kubernix.selectorLabels" (dict "context" $ "component" "sshd")`.
*/}}
{{- define "kubernix.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kubernix.name" .context }}
app.kubernetes.io/instance: {{ .context.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/*
`imagePullSecrets:` block for a pod spec, or nothing at all when the list is
empty — shared so every Deployment renders it identically.
*/}}
{{- define "kubernix.imagePullSecrets" -}}
{{- with .Values.imagePullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}

{{/*
The CNPG cluster name, so every template that needs its generated Secrets/
Service names (<cluster>-superuser, <cluster>-rw, ...) agrees on one value.
*/}}
{{- define "kubernix.postgresCluster" -}}
{{- printf "%s-postgres" (include "kubernix.fullname" .) -}}
{{- end -}}

{{- define "kubernix.postgresOperator" -}}
{{- .Values.postgres.operator | default "cnpg" -}}
{{- end -}}

{{/*
env entries every server-image container needs to reach S3 — lifted from
nix/module.nix's `s3Env`/`s3Options`. A single named template so sshd, cache
and gc can't drift from each other.
*/}}
{{- define "kubernix.s3Env" -}}
{{- $secretName := .Values.s3.existingSecret | default (printf "%s-s3" (include "kubernix.fullname" .)) }}
- name: S3_BUCKET
  value: {{ .Values.s3.bucket | quote }}
- name: AWS_REGION
  value: {{ .Values.s3.region | quote }}
- name: AWS_ENDPOINT_URL
  value: {{ .Values.s3.endpoint | quote }}
- name: AWS_ACCESS_KEY_ID
  valueFrom:
    secretKeyRef:
      name: {{ $secretName }}
      key: accessKeyId
- name: AWS_SECRET_ACCESS_KEY
  valueFrom:
    secretKeyRef:
      name: {{ $secretName }}
      key: secretAccessKey
{{- end -}}

{{/*
Resolves postgres.backup.s3's per-field fallback onto the top-level s3:
block (see values.yaml's comment on postgres.backup.s3), plus the two
Secret names the backup ObjectStore and its own secret-postgres-backup-s3*
templates need to agree on. Returned as a JSON-encoded dict (`include ... |
fromJson`) since Helm templates can't return a plain map value.

Credential-secret resolution and region-secret resolution are independent
of each other and of the plain endpoint/bucket fallback, so overriding just
one field (e.g. postgres.backup.s3.bucket alone) reuses the shared
credentials/region secrets rather than spuriously duplicating them.
*/}}
{{- define "kubernix.postgresBackupS3" -}}
{{- $s3 := .Values.s3 -}}
{{- $backup := .Values.postgres.backup.s3 -}}
{{- $ownCreds := or $backup.existingSecret $backup.accessKeyId $backup.secretAccessKey -}}
{{- $secretName := "" -}}
{{- if $backup.existingSecret -}}
  {{- $secretName = $backup.existingSecret -}}
{{- else if $ownCreds -}}
  {{- $secretName = printf "%s-postgres-backup-s3" (include "kubernix.fullname" .) -}}
{{- else -}}
  {{- $secretName = $s3.existingSecret | default (printf "%s-s3" (include "kubernix.fullname" .)) -}}
{{- end -}}
{{- $regionSecretName := "" -}}
{{- if $backup.region -}}
  {{- $regionSecretName = printf "%s-postgres-backup-s3-region" (include "kubernix.fullname" .) -}}
{{- else -}}
  {{- $regionSecretName = printf "%s-s3-region" (include "kubernix.fullname" .) -}}
{{- end -}}
{{- dict
    "endpoint" ($backup.endpoint | default $s3.endpoint)
    "bucket" ($backup.bucket | default $s3.bucket)
    "accessKeyId" ($backup.accessKeyId | default $s3.accessKeyId)
    "secretAccessKey" ($backup.secretAccessKey | default $s3.secretAccessKey)
    "secretName" $secretName
    "regionSecretName" $regionSecretName
    "createOwnSecret" (and (not $backup.existingSecret) $ownCreds)
    "createOwnRegionSecret" (not (not $backup.region))
  | toJson -}}
{{- end -}}

{{/*
DATABASE_URL for every app container, built (not read verbatim) from the
CNPG-generated `<cluster>-superuser` Secret. `PostgresStore::connect` needs a
role able to run DDL and `CREATE ROLE` for its bootstrap connection — the
`-app` secret's owner role doesn't have that by default, but `postgres`
(superuser) always does, hence `enableSuperuserAccess: true` in
postgres-cluster.yaml.

Built rather than used directly because that secret's own `uri`/`jdbc-uri`
keys carry `dbname=*` (CNPG's own wildcard placeholder for its `pgpass`
entry, not a real database name — see `pkg/specs/secrets.go`'s
`CreateSecret`), which doesn't name the `kubernix` database this chart's
`Cluster` bootstraps. Kubernetes' own `$(VAR)` env-value expansion (each
`env` entry can reference an earlier one in the same container, purely
server-side, no shell needed) composes the three real fields into a URI
with the right dbname instead.

`PGSUPERUSER`/`PGSUPERPASSWORD` are also what `db-role-passwords-job.yaml`
uses directly to build its `ALTER ROLE ... PASSWORD` literal — CNPG's
generated passwords are alphanumeric only (`password.Generate(64, 10, 0,
false, true)`, zero symbols), so no URI-escaping concern either place.
*/}}
{{- define "kubernix.databaseUrlEnv" -}}
{{- $cluster := include "kubernix.postgresCluster" . }}
{{- $operator := include "kubernix.postgresOperator" . }}
{{- if eq $operator "cnpg" }}
- name: PGSUPERUSER
  valueFrom:
    secretKeyRef:
      name: {{ $cluster }}-superuser
      key: username
- name: PGSUPERPASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ $cluster }}-superuser
      key: password
- name: PGSUPERHOST
  valueFrom:
    secretKeyRef:
      name: {{ $cluster }}-superuser
      key: host
- name: DATABASE_URL
  value: "postgresql://$(PGSUPERUSER):$(PGSUPERPASSWORD)@$(PGSUPERHOST):5432/kubernix"
{{- else if eq $operator "zalando" }}
- name: PGSUPERUSER
  valueFrom:
    secretKeyRef:
      name: {{ printf "%s.%s.credentials.postgresql.acid.zalan.do" .Values.postgres.zalando.superuser $cluster }}
      key: username
- name: PGSUPERPASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ printf "%s.%s.credentials.postgresql.acid.zalan.do" .Values.postgres.zalando.superuser $cluster }}
      key: password
- name: PGSUPERHOST
  value: {{ $cluster | quote }}
- name: DATABASE_URL
  value: "postgresql://$(PGSUPERUSER):$(PGSUPERPASSWORD)@$(PGSUPERHOST):5432/kubernix"
{{- else }}
{{- fail (printf "postgres.operator must be one of cnpg or zalando, got %q" $operator) }}
{{- end }}
{{- end -}}
