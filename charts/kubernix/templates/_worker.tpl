{{/*
Renders one worker pool's Deployment. Call with
`(dict "context" $ "name" <pool-name-or-""> "worker" <pool-values-dict>)` --
`name: ""` is the default `worker:` pool (keeps today's unsuffixed
`<fullname>-worker` naming exactly); any other name is an extra pool from
`.Values.workers.<name>`, rendered as `<fullname>-worker-<name>` with a
disjoint `app.kubernetes.io/component` selector value so two pools' pods
never collide.
*/}}
{{- define "kubernix.worker.deployment" -}}
{{- $ctx := .context -}}
{{- $worker := .worker -}}
{{- $suffix := include "kubernix.worker.suffix" .name -}}
{{- $component := printf "worker%s" $suffix -}}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ printf "%s-worker%s" (include "kubernix.fullname" $ctx) $suffix }}
  labels:
    {{- include "kubernix.labels" $ctx | nindent 4 }}
spec:
  # Omitted (not set to 0/left implicit) once KEDA owns scaling: an absent
  # field isn't patched to a value on `helm upgrade`, so it can't fight the
  # HPA KEDA's ScaledObject creates for this Deployment's replica count.
  {{- if not $worker.autoscaling.enabled }}
  replicas: {{ $worker.replicas }}
  {{- end }}
  selector:
    matchLabels:
      {{- include "kubernix.selectorLabels" (dict "context" $ctx "component" $component) | nindent 6 }}
  template:
    metadata:
      labels:
        {{- include "kubernix.selectorLabels" (dict "context" $ctx "component" $component) | nindent 8 }}
    spec:
      # Phase 15 Step 8: the worker's own process runs as root (uid 0) —
      # not `runAsNonRoot`/`runAsUser: 1000` as earlier tried — because a
      # non-root container can't actually use an added `CAP_SETUID`/
      # `CAP_SETGID`. Found by deploying: the kernel automatically clears a
      # process's *effective*/*permitted* capability sets on any 0→nonzero
      # uid transition (`capabilities(7)`), and that is exactly what
      # dropping into `runAsUser: 1000` is — confirmed on the deployed pod,
      # `CapBnd` carried the two added capabilities but `CapEff`/`CapPrm`
      # were both zero. Kubernetes exposes no field for the securebit
      # (`SECURE_NOROOT`) that would suppress that clearing, so "non-root
      # container, capability added back" isn't achievable here — the
      # container-level `capabilities.drop: [ALL]` below still constrains
      # what this uid-0 process can actually do to just `SETUID`/`SETGID`,
      # which is the actual point: it's not full root in practice, only in
      # name. Each tenant's `cloud-hypervisor`/`passt` still ends up with a
      # genuinely unprivileged, capability-stripped uid of its own — that
      # same kernel clearing rule does it for free the moment
      # `drop_privileges`'s `setuid(derived_uid)` call succeeds.
      securityContext: {}
      {{- include "kubernix.imagePullSecrets" $ctx | nindent 6 }}
      containers:
        - name: worker
          image: "{{ $ctx.Values.image.worker.repository }}:{{ $ctx.Values.image.worker.tag | default $ctx.Chart.AppVersion }}"
          imagePullPolicy: {{ $ctx.Values.image.worker.pullPolicy }}
          securityContext:
            runAsUser: 0
            runAsGroup: 0
            capabilities:
              drop: ["ALL"]
              # SETUID/SETGID: the Step 8 privilege drop into a per-tenant
              # uid/gid before exec'ing `cloud-hypervisor`/`passt`.
              #
              # DAC_OVERRIDE: `cloud-hypervisor` creates `console.log`
              # (`--serial file=...`) and `vsock.sock` (`--vsock socket=...`)
              # *after* that drop, so they end up owned by the tenant's own
              # uid, mode 0600/0700 — unreachable to this uid-0-but-
              # capability-stripped worker process itself, which needs to
              # dial `vsock.sock` (`wait_for_vsock_ready`) and read
              # `console.log` (attached to a boot-failure error) regardless
              # of which tenant they belong to. A narrower, capability-free
              # fix (a shared gid + `umask` clearing just the group bits) was
              # tried first and reverted: verified live against this cluster
              # that `cloud-hypervisor` resets its own umask early in its own
              # startup, unconditionally overriding whatever this process
              # sets beforehand — nothing survives `execve` into it. See
              # `worker/src/vm.rs`'s doc comment above `drop_privileges` for
              # the full account, including the narrower alternative's own
              # side effect (widening `net.sock`'s permissions) found while
              # diagnosing why it didn't work. This capability only widens
              # what the worker process itself can reach — it does not touch
              # what one tenant's dropped-uid `cloud-hypervisor`/`passt` can
              # reach of another's, which stays governed by uid alone as
              # Step 8 designed it, and the worker already holds every live
              # tenant's at-rest encryption key in memory regardless
              # (`VmPool::keys`), so it crosses no boundary that wasn't
              # already crossed by that design.
              add: ["SETUID", "SETGID", "DAC_OVERRIDE"]
          # No DB/S3 credentials, by design — the worker only ever talks to
          # NATS and to pre-signed S3 URLs it's handed over NATS.
          #
          # KUBERNIX_VM_KERNEL/KUBERNIX_VM_INITRD are baked into
          # image.worker itself (nix/images.nix) — per-tenant VM isolation
          # is the only mode this worker runs in, not a deployment-time
          # opt-in. Only the VM's own sizing is a chart concern.
          env:
            - name: NATS_URL
              value: {{ printf "nats://%s-nats:4222" $ctx.Release.Name | quote }}
            # PLAN.md Phase 19 -- must match kubernix-sshd's and
            # kubernix-gc's own copies of this same value (see values.yaml's
            # own comment).
            - name: KUBERNIX_JOB_RESULTS_RETENTION
              value: {{ $ctx.Values.jobs.resultsRetention | quote }}
            - name: NIX_SYSTEM
              value: {{ $worker.system | quote }}
            - name: KUBERNIX_VM_VCPUS
              value: {{ $worker.vm.vcpus | quote }}
            - name: KUBERNIX_VM_MEMORY_MB
              value: {{ include "kubernix.worker.vmMemoryMb" $worker | quote }}
            - name: KUBERNIX_VM_STORE_IMG_MB
              value: {{ $worker.vm.storeImgMb | quote }}
            # PLAN.md Phase 17: static capability classes this worker
            # declares — "kvm" is never set here, only ever probe-confirmed
            # at startup. See worker.systemFeatures' comment above.
            - name: KUBERNIX_WORKER_CLASSES
              value: {{ $worker.systemFeatures | join "," | quote }}
            {{- if $worker.exclusiveClasses }}
            # This pool only subscribes to its declared classes' NATS
            # subjects, not the plain queue -- see
            # worker/src/main.rs::worker_subjects_and_consumer.
            - name: KUBERNIX_WORKER_EXCLUSIVE_CLASSES
              value: "1"
            {{- end }}
            # Sizes the shared NATS durable consumer's max_ack_pending, not
            # just this Deployment's replica count -- see worker/src/main.rs's
            # comment above create_consumer. Must be >= however many replicas
            # could concurrently pull, so it mirrors whichever setting below
            # actually governs that count. When another pool shares this same
            # consumer (same system, both non-exclusive), size this to cover
            # BOTH pools' combined concurrency -- whichever pool's pod last
            # (re)created the consumer wins this setting otherwise.
            - name: KUBERNIX_WORKER_MAX_CONCURRENT
              {{- if $worker.autoscaling.enabled }}
              value: {{ $worker.autoscaling.maxReplicaCount | quote }}
              {{- else }}
              value: {{ $worker.replicas | quote }}
              {{- end }}
            - name: RUST_LOG
              value: debug
            {{- with $ctx.Values.tls.extraCaVolumeMounts }}
            {{- include "kubernix.extraCaEnv" $ctx | nindent 12 }}
            {{- end }}
          # $HOME and KUBERNIX_NIX_STORE both point under here — baked into
          # the image itself (nix/images.nix), not set here, since they're a
          # property of how this image runs a worker at all, not something
          # deployment-specific.
          volumeMounts:
            - name: state
              mountPath: /var/lib/kubernix-worker
            {{- with $ctx.Values.tls.extraCaVolumeMounts }}
            {{- toYaml . | nindent 12 }}
            {{- end }}
          resources:
            # `devices.kubevirt.io/kvm`-style extended resource, merged with
            # (and overridable by) worker.resources — this is what actually
            # grants /dev/kvm to the container via whatever device-plugin
            # DaemonSet on the cluster registers it, with no `privileged:
            # true` and no node-specific `kvm` group GID to guess at.
            #
            # PLAN.md Phase 18: size worker.resources.limits.memory for the
            # pod as a whole (worker process + its one tenant VM); memoryMb
            # above is now *derived* from it (minus worker.vm.overheadMb),
            # the opposite direction from before this phase — an operator
            # no longer keeps these two numbers in sync by hand. vcpus is
            # still an independent setting: nothing here relates it to
            # worker.resources' cpu requests/limits.
            {{- $vmResources := dict "limits" (dict $worker.vm.kvmResourceName "1") }}
            {{- toYaml (mergeOverwrite $vmResources $worker.resources) | nindent 12 }}
      volumes:
        # Ephemeral by design — Phase 15's own storage decisions treat a
        # worker's local store as a disposable cache, never the source of
        # truth (S3 holds verified outputs), so a pod restart losing it is a
        # cold-cache cost, not a correctness problem.
        - name: state
          emptyDir: {}
        {{- with $ctx.Values.tls.extraCaVolumes }}
        {{- toYaml . | nindent 8 }}
        {{- end }}
      {{- with $worker.nodeSelector }}
      nodeSelector:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with $worker.tolerations }}
      tolerations:
        {{- toYaml . | nindent 8 }}
      {{- end }}
      {{- with $worker.affinity }}
      affinity:
        {{- toYaml . | nindent 8 }}
      {{- end }}
{{- end -}}

{{/*
Renders one worker pool's KEDA ScaledObject, guarded on that pool's own
`autoscaling.enabled`. Call with the same
`(dict "context" $ "name" <pool-name-or-""> "worker" <pool-values-dict>)`
shape as `kubernix.worker.deployment`.
*/}}
{{- define "kubernix.worker.scaledobject" -}}
{{- $ctx := .context -}}
{{- $worker := .worker -}}
{{- if $worker.autoscaling.enabled }}
{{- $suffix := include "kubernix.worker.suffix" .name -}}
# Scales the worker Deployment on kubernix_jobs' NATS JetStream queue depth.
# Requires the `keda` dependency's CRDs already registered on the cluster —
# see values.yaml's comment on worker.autoscaling and the README's Quickstart
# for the staged-install this forces (same shape as postgres.cluster.enabled).
apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: {{ printf "%s-worker%s" (include "kubernix.fullname" $ctx) $suffix }}
  labels:
    {{- include "kubernix.labels" $ctx | nindent 4 }}
spec:
  scaleTargetRef:
    name: {{ printf "%s-worker%s" (include "kubernix.fullname" $ctx) $suffix }}
  minReplicaCount: {{ $worker.autoscaling.minReplicaCount }}
  maxReplicaCount: {{ $worker.autoscaling.maxReplicaCount }}
  pollingInterval: {{ $worker.autoscaling.pollingInterval }}
  cooldownPeriod: {{ $worker.autoscaling.cooldownPeriod }}
  triggers:
    - type: nats-jetstream
      metadata:
        account: "$G"
        natsServerMonitoringEndpoint: {{ printf "%s-nats:8222" (include "kubernix.fullname" $ctx) | quote }}
        stream: kubernix_jobs
        # Must match worker/src/main.rs's durable consumer name exactly --
        # see kubernix.worker.consumer's own doc comment. Unchanged by
        # PLAN.md Phase 17's capability-class routing for the default
        # (non-exclusive) pool: one worker uses one consumer with a
        # `filter_subjects` list spanning every class it declares, so this
        # lag figure now reflects the queue depth across all of them
        # together, not just the plain subject. An exclusiveClasses pool
        # gets its own distinct consumer instead, sized only by its own
        # class(es).
        consumer: {{ include "kubernix.worker.consumer" $worker | quote }}
        lagThreshold: {{ $worker.autoscaling.lagThreshold | quote }}
        activationLagThreshold: {{ $worker.autoscaling.activationLagThreshold | quote }}
{{- end }}
{{- end -}}
