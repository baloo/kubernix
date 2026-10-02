//! Kubernix worker.
//!
//! Dequeues one job at a time from `kubernix.jobs.<system>`, realises the
//! derivation against the local Nix builder, streams the build log to
//! `kubernix.logs.<job_id>` as it is produced, and publishes the terminal outcome
//! to `kubernix.results.<job_id>`.
//!
//! The job message is left un-acked for the duration of the build, so a worker
//! that dies mid-build causes redelivery rather than a silently lost job --
//! `ack_heartbeat` resets JetStream's `ack_wait` timer throughout a live
//! build, so redelivery only actually happens once the worker itself has
//! gone quiet. A hung/dead *guest* VM (worker still alive) is instead
//! detected directly and much faster by `guest_heartbeat_monitor`.

pub mod kubernix_capnp {
    include!(concat!(env!("OUT_DIR"), "/kubernix_capnp.rs"));
}

mod decompress;
mod input_fetch;
mod nar_export;
mod serve;
mod uid;
mod upload;
mod vm;
mod vm_ops;

/// One VM's `nix-daemon` session, as `main.rs`'s job loop and `Job`'s methods
/// see it — a `DaemonConnection` over the `UnixStream` `VmHandle::connect`
/// dials. Named here so `Option<&mut VmConn>` reads as one thing rather than
/// the full generic spelled out at every call site.
type VmConn = kubernix_daemon_protocol::DaemonConnection<tokio::net::UnixStream>;

/// Request/reply subject for pre-signed upload URLs. The frontend holds the S3
/// credentials; this worker never does.
pub const UPLOADS_SUBJECT: &str = "kubernix.uploads";

/// Bounds Nak-based redelivery of a job this worker can't fully satisfy
/// (PLAN.md Phase 17): past this many deliveries, a still-unsatisfied job is
/// reported as a failure instead of Nak'd again, so a feature combination no
/// worker in the fleet declares fails visibly rather than looping forever.
const MAX_JOB_DELIVER: i64 = 5;

use async_nats::jetstream::{self, consumer::PullConsumer};
use eyre::{Context as _, OptionExt as _};
use futures_util::stream::StreamExt;
use kubernix_types::{CapabilityToken, Compression, ObjectKey, StorePath, TenantId, derivation};
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

struct Job {
    job_id: String,
    derivation_path: StorePath,
    /// Whose build this is, per the frontend's own claim — not what
    /// authorizes anything; see `token`.
    tenant: TenantId,
    inputs: Vec<InputRef>,
    /// The derivation itself, shipped inline by `buildDerivation`.
    drv: Vec<u8>,
    /// The signed capability token minted for this job. Carried opaquely —
    /// this worker never parses it, only presents it back with every
    /// upload/download URL request, which is what the frontend actually
    /// checks a key against. PLAN.md Phase 14.
    token: CapabilityToken,
    /// The derivation's full declared `requiredSystemFeatures` — the subject
    /// this job arrived on already routed on the *known* tags, but this
    /// worker still checks the full list against its own capability set
    /// before building, in case it can't actually satisfy every one of them
    /// (e.g. it's subscribed to the kvm subject but wasn't deployed with
    /// big-parallel too). See `worker_capabilities_satisfy`. PLAN.md Phase 17.
    required_features: Vec<String>,
    /// This tenant's configured trusted substituters, as `(url, public_key)`
    /// pairs. Pushed to the guest's control channel so its `nix.conf` points
    /// at kubernix's own per-substituter mirror routes rather than
    /// substituting from anywhere external directly — see
    /// `vm::push_substituters`.
    trusted_substituters: Vec<(String, String)>,
}

#[derive(Clone)]
struct InputRef {
    store_path: StorePath,
    key: ObjectKey,
    /// Needed to wrap the NAR into an importable export stream; a bare NAR
    /// carries neither.
    references: Vec<StorePath>,
    deriver: StorePath,
    /// What `key`'s bytes actually use. See `kubernix_capnp::InputRef`.
    compression: Compression,
    /// The uncompressed NAR's hash, in Nix's own wire form
    /// (`"<algo>:<base16>"`, e.g. `"sha256:abcd..."`) -- known ahead of the
    /// download from the server's own record of this path, so it doubles as
    /// both what's verified against and what's declared to the guest's
    /// `AddToStoreNar` / `nix-store --import`.
    nar_hash: String,
    nar_size: u64,
}

/// Order `inputs` so that every input comes after every other input it
/// references (Kahn's algorithm), so that registering them one at a time in
/// this order never asks the guest's Nix store to validate a path against a
/// reference it hasn't seen yet. References to paths outside `inputs` (the
/// guest's base system closure, presumably already valid there) are ignored.
///
/// Returns indices into `inputs`. Errors if `inputs` contains a reference
/// cycle, which real Nix closures never do.
fn topo_sort_inputs(inputs: &[InputRef]) -> eyre::Result<Vec<usize>> {
    use std::collections::{HashMap, VecDeque};

    let by_path: HashMap<&StorePath, usize> = inputs
        .iter()
        .enumerate()
        .map(|(i, input)| (&input.store_path, i))
        .collect();

    let mut indegree = vec![0usize; inputs.len()];
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); inputs.len()];
    for (i, input) in inputs.iter().enumerate() {
        for reference in &input.references {
            if let Some(&dep) = by_path.get(reference)
                && dep != i
            {
                indegree[i] += 1;
                dependents[dep].push(i);
            }
        }
    }

    let mut queue: VecDeque<usize> = (0..inputs.len()).filter(|&i| indegree[i] == 0).collect();
    let mut order = Vec::with_capacity(inputs.len());
    while let Some(i) = queue.pop_front() {
        order.push(i);
        for &dependent in &dependents[i] {
            indegree[dependent] -= 1;
            if indegree[dependent] == 0 {
                queue.push_back(dependent);
            }
        }
    }

    if order.len() != inputs.len() {
        eyre::bail!("reference cycle among staged inputs");
    }
    Ok(order)
}

impl Job {
    /// The output paths a derivation declares.
    ///
    /// Taken from the derivation rather than from a builder's stdout: with
    /// `nix-store --serve` stdout carries the protocol, and the derivation is
    /// the authoritative statement of where its outputs go regardless.
    fn declared_outputs(&self, store_dir: &str) -> eyre::Result<Vec<StorePath>> {
        let drv = derivation::parse(&self.drv, store_dir).wrap_err("parsing the derivation")?;
        Ok(drv.outputs.into_iter().map(|o| o.path).collect())
    }

    /// Fetch and import every input the frontend staged for this job.
    ///
    /// Done before the build: the whole point is that a worker on another
    /// machine has the closure it needs without ever holding S3 credentials.
    async fn fetch_inputs(
        &self,
        client: &async_nats::Client,
        http: &reqwest::Client,
        nix: upload::NixStore<'_>,
        mut vm: Option<&mut VmConn>,
        max_parallel_fetches: usize,
        vm_store_fresh: bool,
    ) -> eyre::Result<()> {
        if self.inputs.is_empty() {
            return Ok(());
        }

        // The server's `inputs` order is not guaranteed to be closure order:
        // paths the client staged fresh on this connection are (Nix always
        // exports a closure topologically), but paths backfilled from the
        // derivation's own `input_srcs` are ordered however Lix's C++
        // `StringSet` happens to sort store-path strings lexicographically,
        // which has no relation to the reference graph. Registering an input
        // before a path it references makes the guest's real `nix-daemon`
        // reject it ("does not exist in the Lix database"), so re-derive a
        // correct order here from the `references` every `InputRef` already
        // carries, rather than trusting the wire order. Only *registration*
        // needs this order, though -- the download below runs unordered.
        let order = topo_sort_inputs(&self.inputs).wrap_err("ordering inputs")?;
        let order = self
            .skip_already_valid(order, &mut vm, vm_store_fresh, nix.store_dir)
            .await
            .wrap_err("checking which inputs are already valid")?;
        if order.is_empty() {
            tracing::info!(job_id = %self.job_id, "every staged input already valid in the guest's store");
            return Ok(());
        }

        let keys: Vec<ObjectKey> = order.iter().map(|&i| self.inputs[i].key.clone()).collect();
        let urls = upload::request_download_urls(client, &self.job_id, &self.token, &keys)
            .await
            .wrap_err("requesting download urls")?;

        // Every input's download is spawned up front (gated by a semaphore
        // so at most `max_parallel_fetches` run at once), then the loop
        // below registers/imports them sequentially in topo order as each
        // one's download lands -- so registering input `k` overlaps with
        // the still-running downloads for inputs later in `order`, rather
        // than waiting for every download in the job to finish first.
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(max_parallel_fetches));
        let (tx, mut rx) = tokio::sync::mpsc::channel(order.len());
        for (&i, url) in order.iter().zip(urls) {
            let input = self.inputs[i].clone();
            let http = http.clone();
            let semaphore = semaphore.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let _permit = semaphore
                    .acquire_owned()
                    .await
                    .expect("semaphore not closed");
                let result = input_fetch::download_to_spool(
                    &http,
                    &url,
                    input.compression,
                    &input.nar_hash,
                    input.nar_size,
                )
                .await
                .wrap_err_with(|| format!("fetching {}", input.store_path));
                let _ = tx.send((i, result)).await;
            });
        }
        drop(tx);

        let mut ready: std::collections::HashMap<usize, input_fetch::SpooledInput> =
            std::collections::HashMap::new();
        for &i in &order {
            let spooled = match ready.remove(&i) {
                Some(s) => s,
                None => loop {
                    let (j, result) = rx
                        .recv()
                        .await
                        .expect("every spawned download reports back before its sender drops");
                    let s = result?;
                    if j == i {
                        break s;
                    }
                    ready.insert(j, s);
                },
            };

            let input = &self.inputs[i];
            tracing::info!(job_id = %self.job_id, path = %input.store_path, "importing input");
            match &mut vm {
                Some(conn) => vm_ops::register_input(
                    conn,
                    spooled,
                    &input.store_path,
                    &input.references,
                    &input.deriver,
                    nix.store_dir,
                    &input.nar_hash,
                    input.nar_size,
                )
                .await
                .wrap_err_with(|| format!("importing {}", input.store_path))?,
                None => nix
                    .import_spooled(
                        spooled,
                        &input.store_path,
                        &input.references,
                        &input.deriver,
                    )
                    .await
                    .wrap_err_with(|| format!("importing {}", input.store_path))?,
            }
        }

        tracing::info!(job_id = %self.job_id, count = order.len(), "inputs imported");
        Ok(())
    }

    /// Of `order` (already a valid topological order over `self.inputs`),
    /// the subsequence not already valid in `vm`'s guest store. Returns
    /// `order` unchanged with no VM (the non-VM fallback has no retained
    /// store across jobs -- nothing to skip) or when `fresh` (a `store.img`
    /// just created for this boot can't already hold anything a previous
    /// job registered).
    async fn skip_already_valid(
        &self,
        order: Vec<usize>,
        vm: &mut Option<&mut VmConn>,
        fresh: bool,
        store_dir: &str,
    ) -> eyre::Result<Vec<usize>> {
        let Some(conn) = (if fresh { None } else { vm.as_mut() }) else {
            return Ok(order);
        };
        let mut pending = Vec::with_capacity(order.len());
        let mut skipped = 0usize;
        for i in order {
            let input = &self.inputs[i];
            if vm_ops::path_is_valid(conn, &input.store_path, store_dir).await? {
                skipped += 1;
            } else {
                pending.push(i);
            }
        }
        if skipped > 0 {
            tracing::info!(
                job_id = %self.job_id, skipped, remaining = pending.len(),
                "skipping inputs already valid in the guest's retained store"
            );
        }
        Ok(pending)
    }
}

/// Concatenates every regular file under `SSL_CERT_DIR` (if set) into one
/// PEM blob -- mirrors `rustls-native-certs`' own directory-scan semantics
/// (`load_pem_certs_from_dir`: resolve symlinks via `fs::metadata` rather
/// than `lstat`, skip dangling ones, no filename/extension filtering) since
/// that's the crate actually resolving trust for this process's own
/// `reqwest`/`aws-sdk-s3`-style HTTP clients from that same env var.
/// Symlink resolution matters here in practice, not just for parity: a
/// Kubernetes ConfigMap/Secret volume mount presents every key as a symlink
/// to `..data/<key>`, not a plain file -- `DirEntry::file_type()`'s `lstat`
/// semantics would see only the symlink and skip every entry outright.
/// Returns an empty `Vec` -- logged, not fatal -- whenever the var is
/// unset, the directory can't be read, or it's simply empty; a deployment
/// without `tls.extraCaVolumeMounts` configured never sets `SSL_CERT_DIR`
/// at all, so this is the common case.
fn read_extra_ca_pem() -> Vec<u8> {
    let Ok(dir) = std::env::var("SSL_CERT_DIR") else {
        return Vec::new();
    };
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(e) => {
            tracing::warn!(%dir, error = %e, "SSL_CERT_DIR set but unreadable; pushing no extra CA cert to guests");
            return Vec::new();
        }
    };

    let mut pem = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        let metadata = match std::fs::metadata(&path) {
            Ok(metadata) => metadata,
            // A dangling symlink -- silently skipped, same as
            // `rustls-native-certs`.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "statting an SSL_CERT_DIR entry failed");
                continue;
            }
        };
        if !metadata.is_file() {
            continue;
        }
        match std::fs::read(&path) {
            Ok(bytes) => {
                pem.extend_from_slice(&bytes);
                pem.push(b'\n');
            }
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "reading an SSL_CERT_DIR entry failed")
            }
        }
    }
    pem
}

/// Parse a seconds-valued env var, falling back to `default` if it's unset
/// or unparseable. Mirrors `kubernix-gc`/`kubernix-sshd`'s own copies of
/// this -- small enough, and specific enough to each binary's own env var
/// names, that a shared helper isn't worth it.
fn env_secs(name: &str, default: std::time::Duration) -> std::time::Duration {
    match std::env::var(name) {
        Ok(v) => match v.parse::<u64>() {
            Ok(secs) => std::time::Duration::from_secs(secs),
            Err(e) => {
                tracing::warn!(%name, value = %v, error = %e, "unparseable, using the default");
                default
            }
        },
        Err(_) => default,
    }
}

/// Parse a positive-integer-valued env var, falling back to `default` if
/// it's unset, unparseable, or not positive (0 would starve every
/// replica pulling from the shared durable consumer of a message).
fn env_positive_i64(name: &str, default: i64) -> i64 {
    match std::env::var(name) {
        Ok(v) => match v.parse::<i64>() {
            Ok(n) if n > 0 => n,
            Ok(n) => {
                tracing::warn!(%name, value = n, "must be positive, using the default");
                default
            }
            Err(e) => {
                tracing::warn!(%name, value = %v, error = %e, "unparseable, using the default");
                default
            }
        },
        Err(_) => default,
    }
}

#[tokio::main]
async fn main() -> color_eyre::eyre::Result<()> {
    color_eyre::install()?;

    // Phase 15 Step 8: independent of (and a backstop for) per-tenant uid
    // separation below — this alone blocks `ptrace`/`/proc/<pid>/mem` on
    // this process from anything without `CAP_SYS_PTRACE`, regardless of
    // whether the caller's uid happens to match ours. Without it, a same-uid
    // `ptrace` needs no capability at all, and this process holds every
    // currently-live tenant's at-rest encryption key in `VmPool::keys` —
    // exactly what a compromised `cloud-hypervisor`/`passt` child would be
    // going after. Not fatal if it fails (e.g. already non-dumpable, or a
    // sandboxed test environment that restricts `prctl`): log and continue
    // rather than refuse to start a worker over a hardening step.
    if let Err(e) = nix::sys::prctl::set_dumpable(false) {
        tracing::warn!(error = %e, "prctl(PR_SET_DUMPABLE, 0) failed; continuing anyway");
    }

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("{}=debug", env!("CARGO_CRATE_NAME")).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let nats_url =
        std::env::var("NATS_URL").unwrap_or_else(|_| "nats://localhost:4222".to_string());
    let system = std::env::var("NIX_SYSTEM").unwrap_or_else(|_| "x86_64-linux".to_string());
    let builder = std::env::var("KUBERNIX_NIX_BUILDER").unwrap_or_else(|_| "nix-store".to_string());
    // A worker pod owns its store; pointing at one explicitly also makes local
    // testing honest, since it cannot silently rely on the host's /nix/store.
    let nix_cli = std::env::var("KUBERNIX_NIX_CLI").unwrap_or_else(|_| "nix".to_string());
    let store_uri = std::env::var("KUBERNIX_NIX_STORE").ok();
    // The store directory a real Nix client/CLI prepends to every path — see
    // `kubernix_types::StorePath`'s doc comment for why the type itself never
    // carries this.
    let store_dir =
        std::env::var("KUBERNIX_STORE_DIR").unwrap_or_else(|_| "/nix/store".to_string());
    // PLAN.md Phase 19: must match the frontend's own copy of this value
    // (`kubernix_server::jobs::JobQueue::connect`'s `results_retention`
    // parameter) -- `get_or_create_stream` below only actually applies
    // `max_age` for whichever of the two processes creates the stream
    // first, so a mismatch would silently pick one side's value rather than
    // erroring.
    let results_retention = env_secs(
        "KUBERNIX_JOB_RESULTS_RETENTION",
        std::time::Duration::from_secs(24 * 3600),
    );
    let worker_max_concurrent = env_positive_i64("KUBERNIX_WORKER_MAX_CONCURRENT", 1);
    // How many of a single job's inputs may download concurrently.
    // `fetch_inputs` still registers/imports them one at a time, in
    // dependency order -- the guest's/`nix-store`'s own protocol requires
    // that -- but nothing about the network fetch that precedes it does, so
    // this only bounds the fan-out of concurrent HTTP downloads.
    let max_parallel_input_fetches =
        env_positive_i64("KUBERNIX_WORKER_MAX_PARALLEL_INPUT_FETCHES", 8) as usize;
    // Bounds how long a job sits un-redelivered after the worker holding it
    // dies outright (pod killed, node lost, panic) -- shortened from an
    // earlier hardcoded 3600s now that `ack_heartbeat` resets this timer for
    // as long as the worker is alive and actually running the build, so it
    // no longer needs to double as "how long can a legitimately slow build
    // run." A hung *guest* (worker alive, VM unresponsive) is instead
    // detected directly and much faster by `guest_ping_monitor` -- this only
    // remains the backstop for the worker process itself dying.
    let ack_wait = env_secs(
        "KUBERNIX_WORKER_ACK_WAIT",
        std::time::Duration::from_secs(90),
    );
    // Several heartbeats per `ack_wait` window, so a couple of missed sends
    // (a transient NATS blip) don't cause a spurious redelivery of a build
    // that's actually still running fine.
    let ack_heartbeat_interval = env_secs(
        "KUBERNIX_WORKER_ACK_HEARTBEAT_INTERVAL",
        std::time::Duration::from_secs(20),
    );
    // Feature B tunable (guest_heartbeat_monitor): how long since the last
    // heartbeat arrived before the guest is presumed dead -- see that
    // function's doc comment. Replaces the old three-way
    // interval/timeout/threshold PING-polling tunables (their product was
    // roughly 15-20s at the old defaults of 5s/5s/3) with one deadline in the
    // same ballpark, now that the guest pushes heartbeats instead of being
    // polled for them.
    let guest_heartbeat_deadline = env_secs(
        "KUBERNIX_WORKER_GUEST_HEARTBEAT_DEADLINE",
        std::time::Duration::from_secs(20),
    );
    // Same directory this process's own `reqwest`/`aws-sdk-s3`-style trust
    // resolution already reads via `SSL_CERT_DIR` (set by the chart
    // whenever a consumer supplies `tls.extraCaVolumeMounts`, see
    // `charts/kubernix/values.yaml`) -- read once here too, so the exact
    // same extra CA cert(s) this worker trusts for its own S3 traffic also
    // get pushed into every tenant VM's guest-agent (`vm::push_ca_cert`),
    // one source of truth either way. Empty when unset, unreadable, or an
    // empty directory -- a deployment without this configured pushes
    // nothing and every guest behaves exactly as before this existed.
    let extra_ca_pem = read_extra_ca_pem();

    tracing::info!(%nats_url, %system, "starting worker");
    let client = async_nats::connect(&nats_url).await?;
    let jetstream = jetstream::new(client.clone());

    let http = reqwest::Client::new();
    let nix = upload::NixStore {
        nix_store: &builder,
        nix_cli: &nix_cli,
        store_uri: store_uri.as_deref(),
        store_dir: &store_dir,
    };

    // Phase 15 Steps 2-4: per-tenant VM lifecycle, opt-in on
    // KUBERNIX_VM_KERNEL/KUBERNIX_VM_INITRD — a worker without them keeps
    // building exactly as it does today. Moved ahead of consumer creation
    // (Phase 17): the kvm boot-time probe below needs to run, and its result
    // needs to be known, before the subject list a consumer subscribes to
    // can be computed.
    let vm_config = vm::VmConfig::from_env()?;
    let mut vm_pool = if let Some(config) = &vm_config {
        // Step 4: every `store.img` left on disk by a previous run of this
        // process is ciphertext this process holds no key for — wipe them
        // before serving a single job rather than let them sit as
        // unrecoverable dead weight.
        vm::wipe_orphaned_store_images(&config.state_dir)
            .await
            .wrap_err("wiping orphaned tenant store images")?;
        Some(vm::VmPool::new(config.clone()).wrap_err("setting up the per-tenant uid allocator")?)
    } else {
        tracing::info!(
            "KUBERNIX_VM_KERNEL/KUBERNIX_VM_INITRD not set; per-tenant VM lifecycle disabled"
        );
        None
    };

    // PLAN.md Phase 17: this worker's own capability classes — the union of
    // whatever it's statically declared (KUBERNIX_WORKER_CLASSES, a chart/
    // deployment fact analogous to a Nix `machines` file's supportedFeatures
    // column) and, independently, whatever its own boot-time probe confirms.
    // `kvm` is deliberately never settable via the static var — see
    // `worker_capabilities_satisfy`'s doc and the probe below.
    let mut worker_classes =
        parse_static_worker_classes(&std::env::var("KUBERNIX_WORKER_CLASSES").unwrap_or_default());
    if let Some(config) = &vm_config {
        match vm::boot_probe(config).await {
            Ok(n) if n > 0 => {
                tracing::info!(vmx_svm_count = n, "kvm probe: nested virt confirmed");
                worker_classes.push("kvm".to_string());
            }
            Ok(_) => tracing::warn!(
                "kvm probe: 0 vmx/svm flags seen guest-side, not subscribing to kvm jobs"
            ),
            Err(e) => tracing::warn!(error = ?e, "kvm probe failed, not subscribing to kvm jobs"),
        }
    }
    tracing::info!(classes = ?worker_classes, "worker capability classes");

    let worker_exclusive_classes = std::env::var("KUBERNIX_WORKER_EXCLUSIVE_CLASSES").is_ok();
    let (subjects, durable_name) =
        worker_subjects_and_consumer(&system, &worker_classes, worker_exclusive_classes)?;

    // A WorkQueue stream permits only one consumer per filter subject, so a
    // leftover consumer from a previous run blocks startup with "filtered
    // consumer not unique". Deleting streams is destructive, so it is opt-in.
    if std::env::var("KUBERNIX_RESET_STREAMS").is_ok() {
        for name in ["kubernix_jobs", "kubernix_results"] {
            match jetstream.delete_stream(name).await {
                Ok(_) => tracing::warn!(stream = name, "deleted stream (KUBERNIX_RESET_STREAMS)"),
                Err(e) => tracing::debug!(stream = name, error = %e, "no stream to delete"),
            }
        }
    }

    // The frontend creates the streams, but a worker may start first.
    jetstream
        .get_or_create_stream(jetstream::stream::Config {
            name: "kubernix_jobs".to_string(),
            subjects: vec!["kubernix.jobs.>".to_string()],
            retention: jetstream::stream::RetentionPolicy::WorkQueue,
            ..Default::default()
        })
        .await?;
    jetstream
        .get_or_create_stream(jetstream::stream::Config {
            name: "kubernix_results".to_string(),
            subjects: vec!["kubernix.results.>".to_string()],
            max_age: results_retention,
            ..Default::default()
        })
        .await?;

    let stream = jetstream.get_stream("kubernix_jobs").await?;
    let consumer: PullConsumer = stream
        .create_consumer(jetstream::consumer::pull::Config {
            durable_name: Some(durable_name),
            filter_subjects: subjects.clone(),
            // This is a *shared* durable consumer across every replica pulling
            // from it (WorkQueue-retention streams forbid per-replica durable
            // names with overlapping filter subjects), so max_ack_pending caps
            // the fleet's total in-flight jobs, not "per worker". Each worker's
            // own 'jobs loop below only ever pulls one message at a time and
            // holds it un-acked for the build's full duration before acking and
            // pulling the next, so this only needs to be a static ceiling >= the
            // number of replicas that could concurrently pull -- it does not
            // need to track the live replica count. Defaults to 1 (today's
            // single-worker behavior); the Helm chart sizes it to mirror
            // worker.replicas / worker.autoscaling.maxReplicaCount.
            max_ack_pending: worker_max_concurrent,
            // See `ack_wait`'s own doc comment above: this is now a backstop
            // for a dead *worker*, not a dead *build* -- `ack_heartbeat`
            // resets it throughout a live build, and a hung *guest* is
            // caught separately and much faster by `guest_ping_monitor`.
            ack_wait,
            // Bounds Nak-based redelivery (PLAN.md Phase 17): a job needing a
            // feature combination no worker in the fleet actually declares
            // would otherwise Nak forever with no visible failure. See the
            // job loop's own delivery-count check below, which is what
            // turns "redelivered past this bound" into a reported failure
            // instead of a silently exhausted consumer.
            max_deliver: MAX_JOB_DELIVER,
            ..Default::default()
        })
        .await?;

    tracing::info!(?subjects, "waiting for jobs");
    let mut messages = consumer.messages().await?;

    'jobs: while let Some(message) = messages.next().await {
        let message = match message {
            Ok(m) => m,
            Err(e) => {
                tracing::error!(error = %e, "error pulling job");
                continue;
            }
        };

        let job = match decode_job(&message.payload) {
            Ok(job) => job,
            Err(e) => {
                tracing::error!(error = %e, "undecodable job, dropping");
                if let Err(e) = message.ack().await {
                    tracing::error!(error = %e, "failed to ack an undecodable job");
                }
                continue;
            }
        };

        // PLAN.md Phase 17: this worker's own subject list may have routed
        // it a job it can't actually fully satisfy (e.g. it's subscribed to
        // the kvm subject but wasn't deployed with big-parallel too, and the
        // job needs both). Nak rather than build it, so JetStream offers the
        // message to another consumer of the same subject instead — bounded
        // by the consumer's `max_deliver`, so a feature combination no
        // worker in the fleet declares fails visibly instead of Naking
        // forever.
        if !worker_capabilities_satisfy(&worker_classes, &job.required_features) {
            let delivered = message.info().map(|info| info.delivered).unwrap_or(1);
            if delivered < MAX_JOB_DELIVER {
                tracing::warn!(
                    job_id = %job.job_id, ?job.required_features, classes = ?worker_classes,
                    delivered, "cannot satisfy every required feature, nak'ing for redelivery"
                );
                if let Err(e) = message.ack_with(jetstream::AckKind::Nak(None)).await {
                    tracing::error!(job_id = %job.job_id, error = %e, "failed to nak job");
                }
            } else {
                tracing::error!(
                    job_id = %job.job_id, ?job.required_features, classes = ?worker_classes,
                    delivered, "no worker satisfied this job's required features after \
                     redelivery; failing it"
                );
                let outcome = Outcome::failed(format!(
                    "kubernix: no worker in the fleet declares every required feature \
                     ({:?}) for job {}",
                    job.required_features, job.job_id
                ));
                if let Err(e) = job.publish_result(&jetstream, &outcome, &[], None).await {
                    tracing::error!(job_id = %job.job_id, error = %e, "failed to publish result");
                }
                if let Err(e) = message.ack().await {
                    tracing::error!(job_id = %job.job_id, error = %e, "failed to ack job");
                }
            }
            continue;
        }

        tracing::info!(job_id = %job.job_id, drv = %job.derivation_path, inputs = job.inputs.len(), "building");

        // Phase 15 Step 3: a `VmHandle` alone (Step 2) proved nothing beyond
        // "the VM boots" — dialing it and speaking the daemon protocol is
        // what actually routes this job's build through it instead of the
        // worker's own local store. `vm_conn` stays `None` (falling back to
        // the subprocess path everywhere below) whenever `vm_pool` itself is
        // disabled, exactly as before this step.
        let mut vm_conn: Option<VmConn> = None;
        // PLAN.md Phase 18: kept alongside `vm_conn` so the retry loop below
        // can reset/query the guest's detection state and reconnect after a
        // same-tier retry, without re-deriving anything `ensure_vm_for`
        // already worked out (the vsock socket path, and whether *this*
        // boot was FRESH — gates ENOSPC recovery).
        let mut vm_handle: Option<vm::VmHandle> = None;
        if let Some(pool) = vm_pool.as_mut() {
            let dialed = match pool.ensure_vm_for(&job.tenant).await {
                Ok(handle) => {
                    tracing::info!(
                        job_id = %job.job_id, tenant = %job.tenant,
                        vsock = %handle.vsock_socket.display(),
                        "tenant VM ready"
                    );
                    // Every job, not just a fresh/reused boot — see
                    // `vm::push_substituters`'s own doc comment for why a
                    // warm VM still needs this on each connection.
                    match vm::push_substituters(&handle.vsock_socket, &job.trusted_substituters)
                        .await
                    {
                        Ok(()) => tracing::info!(
                            job_id = %job.job_id, tenant = %job.tenant,
                            count = job.trusted_substituters.len(),
                            "pushed trusted substituters to the guest"
                        ),
                        Err(e) => tracing::warn!(
                            job_id = %job.job_id, tenant = %job.tenant, error = %e,
                            "could not push trusted substituters to the guest; it will substitute from none"
                        ),
                    }
                    // Every job, unconditionally, same as push_substituters
                    // just above and for the same reason -- an empty
                    // `extra_ca_pem` still has to be sent so a warm guest
                    // that already has a previously-pushed cert actually
                    // gets it cleared if a later `helm upgrade` removes
                    // `tls.extraCaVolumeMounts` again.
                    match vm::push_ca_cert(&handle.vsock_socket, &extra_ca_pem).await {
                        Ok(()) => tracing::info!(
                            job_id = %job.job_id, tenant = %job.tenant,
                            "pushed extra CA cert to the guest"
                        ),
                        Err(e) => tracing::warn!(
                            job_id = %job.job_id, tenant = %job.tenant, error = %e,
                            "could not push extra CA cert to the guest"
                        ),
                    }
                    match handle.connect().await {
                        Ok(stream) => VmConn::open(stream)
                            .await
                            .map(|conn| (conn, handle))
                            .map_err(eyre::Report::from),
                        Err(report) => Err(report),
                    }
                }
                Err(report) => Err(report),
            };
            match dialed {
                Ok((conn, handle)) => {
                    vm_conn = Some(conn);
                    vm_handle = Some(handle);
                }
                Err(report) => {
                    tracing::error!(job_id = %job.job_id, error = ?report, "could not reach the tenant VM's daemon");
                    let outcome = Outcome::failed(infra_failure_message(
                        &job.job_id,
                        "starting the tenant VM failed",
                    ));
                    if let Err(e) = job.publish_result(&jetstream, &outcome, &[], None).await {
                        tracing::error!(job_id = %job.job_id, error = %e, "failed to publish result");
                    }
                    if let Err(e) = message.ack().await {
                        tracing::error!(job_id = %job.job_id, error = %e, "failed to ack job");
                    }
                    continue;
                }
            }
        }

        // Feature A, extended to the input-download phase: fetch_inputs
        // downloads every input serially and can itself outlast
        // `ack_wait` for a job with many/large assets, well before the
        // retry loop below ever spawns its own heartbeat. Scoped to a
        // block so the guard aborts it as soon as fetch_inputs resolves.
        // PLAN.md Phase 18: whether *this job's* VM boot (not any later
        // retry's) was FRESH — computed once, before both the input-fetch
        // filtering below and the retry loop further down, since both gate
        // on it ("nothing to gain from wiping/skip-checking an
        // already-empty disk").
        let original_boot_was_fresh = vm_handle.as_ref().map(|h| h.fresh).unwrap_or(false);

        let fetch_result = {
            let _heartbeat = HeartbeatGuard::spawn(message.clone(), ack_heartbeat_interval);
            job.fetch_inputs(
                &client,
                &http,
                nix,
                vm_conn.as_mut(),
                max_parallel_input_fetches,
                original_boot_was_fresh,
            )
            .await
        };

        if let Err(report) = fetch_result {
            tracing::error!(job_id = %job.job_id, error = ?report, "could not fetch inputs");
            let outcome =
                Outcome::failed(infra_failure_message(&job.job_id, "fetching inputs failed"));
            if let Err(e) = job.publish_result(&jetstream, &outcome, &[], None).await {
                tracing::error!(job_id = %job.job_id, error = %e, "failed to publish result");
            }
            if let Err(e) = message.ack().await {
                tracing::error!(job_id = %job.job_id, error = %e, "failed to ack job");
            }
            continue;
        }

        // Where the outputs will land, read from the derivation itself.
        let outputs = match job.declared_outputs(&store_dir) {
            Ok(outputs) => outputs,
            Err(report) => {
                tracing::error!(job_id = %job.job_id, error = ?report, "undecodable derivation");
                let outcome = Outcome::failed(infra_failure_message(
                    &job.job_id,
                    "reading the derivation failed",
                ));
                if let Err(e) = job.publish_result(&jetstream, &outcome, &[], None).await {
                    tracing::error!(job_id = %job.job_id, error = %e, "failed to publish result");
                }
                if let Err(e) = message.ack().await {
                    tracing::error!(job_id = %job.job_id, error = %e, "failed to ack job");
                }
                continue;
            }
        };

        let already_on_big_parallel = worker_classes.iter().any(|c| c == "big-parallel");
        let mut enospc_retried = false;
        let mut oom_local_retried = false;
        let mut guest_hang_retried = false;

        let mut outcome;
        let mut log;
        loop {
            if let Some(handle) = &vm_handle
                && let Err(e) = vm::reset_job_status(&handle.vsock_socket).await
            {
                tracing::warn!(job_id = %job.job_id, error = ?e, "resetting guest detection state failed");
            }

            // Feature A: reset this message's ack_wait for as long as this
            // attempt is running, so a live worker never loses the job to
            // redelivery purely because the build is legitimately slow.
            // Dropped (aborting the task) at the end of this scope, right
            // after `run_result` is settled below.
            let heartbeat = HeartbeatGuard::spawn(message.clone(), ack_heartbeat_interval);
            // Feature B: only meaningful with a guest to ping -- the
            // subprocess fallback path has none.
            let (hang_tx, hang_rx) = tokio::sync::oneshot::channel();
            let ping_monitor = vm_handle.as_ref().map(|handle| {
                tokio::spawn(guest_heartbeat_monitor(
                    handle.vsock_socket.clone(),
                    guest_heartbeat_deadline,
                    hang_tx,
                ))
            });

            // Race the build against a guest-hang signal: the Nix daemon wire
            // protocol has no per-request cancellation, so abandoning this
            // future (by picking the other `select!` branch) is the only way
            // to stop waiting on a guest that will never answer.
            let run_result = tokio::select! {
                result = job.run_build(
                    &client,
                    outputs.clone(),
                    &builder,
                    store_uri.as_deref(),
                    &store_dir,
                    vm_conn.as_mut(),
                ) => RunResult::Finished(result),
                _ = hang_rx, if ping_monitor.is_some() => RunResult::GuestHung,
            };

            drop(heartbeat);
            if let Some(pm) = ping_monitor {
                pm.abort();
            }

            match run_result {
                RunResult::Finished((this_outcome, this_log)) => {
                    outcome = this_outcome;
                    log = this_log;
                }
                RunResult::GuestHung => {
                    tracing::error!(job_id = %job.job_id, "guest VM became unresponsive mid-build");
                    let hang_outcome = || {
                        terminal_failure(
                            Outcome::failed(infra_failure_message(
                                &job.job_id,
                                "the guest VM stopped responding during the build",
                            )),
                            FailureKind::GuestHang,
                        )
                    };
                    let (Some(pool), Some(_)) = (vm_pool.as_mut(), vm_handle.as_ref()) else {
                        // Unreachable in practice -- `ping_monitor` only ever
                        // spawns when `vm_handle` is `Some`, which requires
                        // `vm_pool` to be `Some` too. Handled rather than
                        // asserted, since nothing here depends on it holding.
                        outcome = hang_outcome();
                        log = Vec::new();
                        break;
                    };
                    if guest_hang_retried {
                        outcome = hang_outcome();
                        log = Vec::new();
                        break;
                    }
                    guest_hang_retried = true;
                    match pool.wipe_and_reboot(&job.tenant).await {
                        Ok(new_handle) => match reconnect(&new_handle).await {
                            Ok(conn) => {
                                vm_conn = Some(conn);
                                vm_handle = Some(new_handle);
                                continue;
                            }
                            Err(e) => {
                                tracing::error!(job_id = %job.job_id, error = ?e, "reconnecting after a guest-hang wipe-and-reboot failed");
                                outcome = hang_outcome();
                                log = Vec::new();
                                break;
                            }
                        },
                        Err(e) => {
                            tracing::error!(job_id = %job.job_id, error = ?e, "guest-hang wipe-and-reboot failed");
                            outcome = hang_outcome();
                            log = Vec::new();
                            break;
                        }
                    }
                }
            }

            if !matches!(outcome, Outcome::Failed { .. }) {
                break;
            }
            let (Some(pool), Some(handle)) = (vm_pool.as_mut(), vm_handle.as_ref()) else {
                // No VM: an ordinary build failure, or an infra failure with
                // no guest to ask -- nothing to retry.
                break;
            };

            let status = match vm::query_status(&handle.vsock_socket).await {
                Ok(status) => status,
                Err(e) => {
                    tracing::warn!(job_id = %job.job_id, error = ?e, "querying guest detection state failed");
                    break;
                }
            };

            let action = next_action(
                status,
                original_boot_was_fresh,
                already_on_big_parallel,
                enospc_retried,
                oom_local_retried,
            );
            tracing::info!(job_id = %job.job_id, ?status, ?action, "resource-exhaustion retry decision");

            match action {
                RetryAction::GiveUp => break,
                RetryAction::TerminalEnospc => {
                    outcome = terminal_failure(outcome, FailureKind::DiskFull);
                    break;
                }
                RetryAction::TerminalOom => {
                    outcome = terminal_failure(outcome, FailureKind::OutOfMemory);
                    break;
                }
                RetryAction::RetryEnospcWipe => {
                    enospc_retried = true;
                    match pool.wipe_and_reboot(&job.tenant).await {
                        Ok(new_handle) => match reconnect(&new_handle).await {
                            Ok(conn) => {
                                vm_conn = Some(conn);
                                vm_handle = Some(new_handle);
                            }
                            Err(e) => {
                                tracing::error!(job_id = %job.job_id, error = ?e, "reconnecting after an ENOSPC wipe-and-reboot failed");
                                break;
                            }
                        },
                        Err(e) => {
                            tracing::error!(job_id = %job.job_id, error = ?e, "ENOSPC wipe-and-reboot failed");
                            break;
                        }
                    }
                }
                RetryAction::RetryOomLocal => {
                    oom_local_retried = true;
                    match reconnect(handle).await {
                        Ok(conn) => vm_conn = Some(conn),
                        Err(e) => {
                            tracing::error!(job_id = %job.job_id, error = ?e, "reconnecting for a same-tier OOM retry failed");
                            break;
                        }
                    }
                }
                RetryAction::EscalateOom => {
                    let escalated_subject = format!("kubernix.jobs.{system}.big-parallel");
                    tracing::warn!(
                        job_id = %job.job_id, subject = %escalated_subject,
                        "confirmed builder OOM; escalating to big-parallel"
                    );
                    // The original message's payload is already exactly the
                    // right BuildRequest bytes -- escalation only ever
                    // changes the subject, never the job's own content.
                    match jetstream
                        .publish(escalated_subject, message.payload.clone())
                        .await
                    {
                        Ok(ack) => {
                            if let Err(e) = ack.await {
                                tracing::error!(job_id = %job.job_id, error = %e, "awaiting the escalation publish ack failed");
                            }
                        }
                        Err(e) => {
                            tracing::error!(job_id = %job.job_id, error = %e, "publishing the escalated job failed")
                        }
                    }
                    if let Err(e) = message.ack().await {
                        tracing::error!(job_id = %job.job_id, error = %e, "failed to ack escalated job");
                    }
                    // The job isn't done -- it's been handed to a different
                    // subject/worker entirely, so no JobResult is published
                    // for this attempt.
                    continue 'jobs;
                }
            }
        }

        // Artifacts first, then the result: publishing a success whose outputs
        // are not yet fetchable would be worse than reporting the upload failure.
        let (artifacts, log_key) = match job
            .upload_artifacts(&client, &http, &outcome, log, nix, vm_conn.as_mut())
            .await
        {
            Ok(uploaded) => uploaded,
            Err(report) => {
                tracing::error!(job_id = %job.job_id, error = ?report, "artifact upload failed");
                outcome = Outcome::failed(infra_failure_message(
                    &job.job_id,
                    "uploading artifacts failed",
                ));
                (Vec::new(), None)
            }
        };

        if let Err(e) = job
            .publish_result(&jetstream, &outcome, &artifacts, log_key.as_ref())
            .await
        {
            tracing::error!(job_id = %job.job_id, error = %e, "failed to publish result");
            // Not acked: let it be redelivered rather than lose the job.
            continue;
        }

        if let Err(e) = message.ack().await {
            tracing::error!(job_id = %job.job_id, error = %e, "failed to ack job");
        }
    }

    Ok(())
}

fn decode_job(payload: &[u8]) -> eyre::Result<Job> {
    let mut cursor = payload;
    let reader = capnp::serialize::read_message(&mut cursor, capnp::message::ReaderOptions::new())
        .wrap_err("decoding a build request")?;
    let request = reader
        .get_root::<kubernix_capnp::build_request::Reader>()
        .wrap_err("reading the build_request root")?;
    let mut inputs = Vec::new();
    for input in request.get_inputs()?.iter() {
        let mut references = Vec::new();
        for reference in input.get_references()?.iter() {
            references.push(StorePath::new(reference?.to_string()?));
        }
        // Empty on a message from an older server that predates this field
        // -- the only compression that existed before this field did was
        // zstd, so that's the safe assumption for a rolling deploy.
        let compression_str = input.get_compression()?.to_string()?;
        let compression = if compression_str.is_empty() {
            tracing::warn!(
                store_path = %input.get_store_path()?.to_str()?,
                "InputRef carries no compression; assuming zstd"
            );
            Compression::Zstd
        } else {
            compression_str
                .parse()
                .wrap_err("build request carries an unrecognised input compression")?
        };
        inputs.push(InputRef {
            store_path: StorePath::new(input.get_store_path()?.to_string()?),
            key: ObjectKey::new(input.get_key()?.to_string()?),
            references,
            deriver: StorePath::new(input.get_deriver()?.to_string()?),
            compression,
            nar_hash: input.get_nar_hash()?.to_string()?,
            nar_size: input.get_nar_size(),
        });
    }
    let tenant = request.get_tenant()?.to_string()?;
    // Without one the worker cannot name a key the frontend will sign, so
    // failing here beats failing later with a refused URL request.
    let tenant = TenantId::from_wire(tenant).ok_or_eyre("build request carries no tenant")?;

    let mut required_features = Vec::new();
    for feature in request.get_required_features()?.iter() {
        required_features.push(feature?.to_string()?);
    }

    let mut trusted_substituters = Vec::new();
    for substituter in request.get_trusted_substituters()?.iter() {
        trusted_substituters.push((
            substituter.get_url()?.to_string()?,
            substituter.get_public_key()?.to_string()?,
        ));
    }

    Ok(Job {
        job_id: request.get_job_id()?.to_string()?,
        derivation_path: StorePath::new(request.get_derivation_path()?.to_string()?),
        tenant,
        inputs,
        drv: request.get_drv()?.to_vec(),
        token: CapabilityToken::new(request.get_token()?.to_vec()),
        required_features,
        trusted_substituters,
    })
}

/// Parses `KUBERNIX_WORKER_CLASSES` (comma-separated, e.g. `"big-parallel"`)
/// into the set of statically-declared capability classes. `kvm` is filtered
/// out even if present — it is never a static declaration, only ever
/// probe-confirmed at startup (see `boot_probe`); everything else
/// unrecognised is filtered out too, same as the frontend's own routing.
/// PLAN.md Phase 17.
fn parse_static_worker_classes(env_value: &str) -> Vec<String> {
    env_value
        .split(',')
        .map(str::trim)
        .filter(|f| *f == "big-parallel")
        .map(String::from)
        .collect()
}

/// Builds the JetStream subjects a worker subscribes to and the durable
/// consumer name it uses, from its system and declared capability classes.
/// Non-exclusive (the default): always includes the plain
/// `kubernix.jobs.<system>` subject plus one per class, sharing the
/// fleet-wide `worker-<system>` durable consumer -- classes only ever widen
/// what's handled. Exclusive (`KUBERNIX_WORKER_EXCLUSIVE_CLASSES`): drops
/// the plain subject, subscribing only to the declared classes' subjects,
/// under a durable name that folds the (sorted) classes in -- so it doesn't
/// collide with the shared consumer or with another exclusive pool
/// declaring different classes for the same system. Requires at least one
/// class, since a WorkQueue-retention consumer subscribed to nothing would
/// never receive anything.
fn worker_subjects_and_consumer(
    system: &str,
    classes: &[String],
    exclusive: bool,
) -> eyre::Result<(Vec<String>, String)> {
    let mut subjects = Vec::new();
    if !exclusive {
        subjects.push(format!("kubernix.jobs.{system}"));
    }
    for class in classes {
        subjects.push(format!("kubernix.jobs.{system}.{class}"));
    }
    if subjects.is_empty() {
        eyre::bail!(
            "KUBERNIX_WORKER_EXCLUSIVE_CLASSES set but no capability classes \
             declared (KUBERNIX_WORKER_CLASSES empty and no probe-confirmed \
             classes) -- refusing to start a worker subscribed to nothing"
        );
    }
    let durable_name = if exclusive {
        let mut sorted = classes.to_vec();
        sorted.sort();
        format!("worker-{}-{}", system.replace('-', "_"), sorted.join("_"))
    } else {
        format!("worker-{}", system.replace('-', "_"))
    };
    Ok((subjects, durable_name))
}

/// Whether this worker's own declared capability classes cover every feature
/// the job requires. `classes` is this worker's own set (static
/// `KUBERNIX_WORKER_CLASSES` config, plus `kvm` iff the startup probe
/// confirmed it) — unrecognised tags in `required` are ignored, matching the
/// frontend's own routing (`server/src/jobs.rs::jobs_subject`): they were
/// never something any worker could have declared in the first place.
/// PLAN.md Phase 17.
fn worker_capabilities_satisfy(classes: &[String], required: &[String]) -> bool {
    required
        .iter()
        .filter(|f| f.as_str() == "kvm" || f.as_str() == "big-parallel")
        .all(|f| classes.iter().any(|c| c == f))
}

/// A job's terminal state.
///
/// `Failed`'s `String` is sent over the wire on `kubernix.results.<job_id>`
/// and forwarded **verbatim** to the Nix client — `server/src/jobs.rs`'s
/// `decode_outcome` and `daemon_rpc.rs`'s `set_error_msg` do no filtering of
/// their own. Construct it as if writing directly to `nix build`'s stderr:
/// `outcome.describe()` (a real build failure) is exactly that already; for
/// anything else — a failure to even reach the point of building — log the
/// real error with `tracing::error!(error = ?report, ...)` first and use
/// [`infra_failure_message`] for the text that actually goes out.
#[derive(Debug)]
enum Outcome {
    Completed(Vec<StorePath>),
    Failed {
        message: String,
        /// Set only on a *terminal* resource-exhaustion failure (PLAN.md
        /// Phase 18) -- `None` for every ordinary build failure and every
        /// infra failure alike, matching how an empty `errorMsg` already
        /// means "not set" on the wire (`Job::publish_result`).
        failure_kind: Option<FailureKind>,
    },
}

impl Outcome {
    /// Shorthand for the overwhelming majority of `Failed` constructions,
    /// which never carry a `failure_kind` -- an ordinary build failure or an
    /// infra failure (S3, NATS, a malformed derivation).
    fn failed(message: impl Into<String>) -> Outcome {
        Outcome::Failed {
            message: message.into(),
            failure_kind: None,
        }
    }
}

/// PLAN.md Phase 18: what the retry loop should do next, given the guest's
/// reported `STATUS?` and the job/worker's own state. A pure function so
/// every combination is cheaply table-tested without any real VM or vsock
/// connection -- see the `next_action` tests below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetryAction {
    /// Not a resource-exhaustion failure (or the guest couldn't be asked) --
    /// report the build failure exactly as it happened, never retried.
    GiveUp,
    RetryEnospcWipe,
    RetryOomLocal,
    EscalateOom,
    TerminalOom,
    TerminalEnospc,
}

/// See [`RetryAction`]'s doc. `enospc_retried`/`oom_local_retried` bound
/// each same-tier retry to exactly one attempt -- PLAN.md's "retry once" is
/// a hard bound, not "retry until it stops failing."
fn next_action(
    status: vm::GuestFailureStatus,
    original_boot_was_fresh: bool,
    already_on_big_parallel: bool,
    enospc_retried: bool,
    oom_local_retried: bool,
) -> RetryAction {
    use vm::GuestFailureStatus as S;
    match status {
        S::None => RetryAction::GiveUp,
        S::DiskFull => {
            if enospc_retried || original_boot_was_fresh {
                RetryAction::TerminalEnospc
            } else {
                RetryAction::RetryEnospcWipe
            }
        }
        S::OutOfMemory {
            builder_victim: false,
        } => {
            if oom_local_retried {
                RetryAction::TerminalOom
            } else {
                RetryAction::RetryOomLocal
            }
        }
        S::OutOfMemory {
            builder_victim: true,
        } => {
            if already_on_big_parallel {
                RetryAction::TerminalOom
            } else {
                RetryAction::EscalateOom
            }
        }
    }
}

/// Folds a [`FailureKind`] onto an existing failure -- used once a resource-
/// exhaustion failure's retry/escalation options are exhausted. A no-op on
/// `Completed` (unreachable in practice: the retry loop only calls this from
/// branches already matched on `Outcome::Failed`), kept exhaustive rather
/// than `unreachable!()`ing on a variant this function has no business
/// asserting about.
fn terminal_failure(outcome: Outcome, kind: FailureKind) -> Outcome {
    match outcome {
        Outcome::Failed { message, .. } => Outcome::Failed {
            message,
            failure_kind: Some(kind),
        },
        completed => completed,
    }
}

/// Re-dials a `VmHandle` and opens a fresh `DaemonConnection` on it -- the
/// retry loop's own small wrapper around `VmHandle::connect` +
/// `VmConn::open`, used identically for both the same-tier and post-wipe
/// reconnects.
async fn reconnect(handle: &vm::VmHandle) -> eyre::Result<VmConn> {
    let stream = handle.connect().await?;
    VmConn::open(stream).await.map_err(eyre::Report::from)
}

/// One retry-loop iteration's outcome: either `run_build` actually returned,
/// or `guest_ping_monitor` declared the guest presumed dead first. See the
/// `tokio::select!` in the retry loop.
enum RunResult {
    Finished((Outcome, Vec<u8>)),
    GuestHung,
}

/// Periodically resets `message`'s JetStream `ack_wait` timer
/// (`AckKind::Progress`) for as long as the caller lets this task run --
/// spawned once for the input-download phase (`fetch_inputs`, once per
/// job) and again once per retry-loop iteration during the build phase
/// (alongside `guest_ping_monitor`), and stopped once that phase settles.
/// A send failure is logged, not fatal -- an isolated missed heartbeat is
/// tolerated by `ack_wait` comfortably outliving a couple of heartbeat
/// intervals.
async fn ack_heartbeat(message: jetstream::Message, interval: std::time::Duration) {
    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await; // fires immediately; a fresh delivery already starts its own countdown
    loop {
        ticker.tick().await;
        if let Err(e) = message.ack_with(jetstream::AckKind::Progress).await {
            tracing::warn!(error = %e, "sending ack heartbeat failed");
        }
    }
}

/// Aborts the wrapped `ack_heartbeat` task when dropped, so a heartbeat's
/// lifetime can be tied to a lexical scope instead of a manual `.abort()`
/// call.
struct HeartbeatGuard(tokio::task::JoinHandle<()>);

impl HeartbeatGuard {
    fn spawn(message: jetstream::Message, interval: std::time::Duration) -> Self {
        Self(tokio::spawn(ack_heartbeat(message, interval)))
    }
}

impl Drop for HeartbeatGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Watches the guest-agent's heartbeat topic for as long as this build
/// attempt is running, so a hung/dead guest is detected in seconds rather
/// than relying on `ack_wait`'s much longer fuse (see `ack_heartbeat`).
/// Replaces the old active `PING`-polling `guest_ping_monitor`: the guest
/// now pushes a `Heartbeat` on its own cadence
/// (`guest-agent/src/control.rs`), and this task declares the guest hung the
/// moment `deadline` elapses since the last one arrived (or since this task
/// started, if none ever has) — see [`heartbeat_is_stale`], kept pure and
/// separately unit-tested. Sends once on `tx` and returns, either on
/// staleness or if the connection/subscription itself fails outright (a
/// dropped control connection is exactly as strong a "guest is gone" signal
/// as a missed heartbeat, since both share the same underlying connection).
async fn guest_heartbeat_monitor(
    vsock_socket: std::path::PathBuf,
    deadline: std::time::Duration,
    tx: tokio::sync::oneshot::Sender<()>,
) {
    let client = match vm::connect_control_client(&vsock_socket).await {
        Ok(client) => client,
        Err(e) => {
            tracing::warn!(error = ?e, "connecting the heartbeat monitor failed");
            let _ = tx.send(());
            return;
        }
    };
    let mut sub = match client
        .subscribe_multi::<kubernix_guest_protocol::HeartbeatTopic>(8)
        .await
    {
        Ok(sub) => sub,
        Err(_) => {
            let _ = tx.send(());
            return;
        }
    };

    let mut last_seen = std::time::Instant::now();
    loop {
        let remaining = deadline.saturating_sub(last_seen.elapsed());
        match tokio::time::timeout(remaining, sub.recv()).await {
            Ok(Ok(_heartbeat)) => {
                last_seen = std::time::Instant::now();
            }
            // The subscription/connection closed outright -- exactly as
            // strong a "no more heartbeats are coming" signal as staleness.
            Ok(Err(_)) => {
                let _ = tx.send(());
                return;
            }
            // No heartbeat arrived within `deadline` of the last one.
            Err(_elapsed) => {
                debug_assert!(heartbeat_is_stale(
                    last_seen,
                    std::time::Instant::now(),
                    deadline
                ));
                let _ = tx.send(());
                return;
            }
        }
    }
}

/// Pure staleness check behind [`guest_heartbeat_monitor`]: the guest is
/// presumed dead once `deadline` has elapsed since the last heartbeat was
/// actually received.
fn heartbeat_is_stale(
    last_seen: std::time::Instant,
    now: std::time::Instant,
    deadline: std::time::Duration,
) -> bool {
    now.saturating_duration_since(last_seen) >= deadline
}

/// PLAN.md Phase 18: what a *terminal* resource-exhaustion failure was --
/// see `guest-agent/src/ebpf.rs::FailureStatus` and
/// `worker/src/vm.rs::GuestFailureStatus`, the two upstream signals this is
/// derived from once every retry/escalation option is exhausted. `GuestHang`
/// is the odd one out here: it isn't from `GuestFailureStatus` at all, but
/// from `guest_ping_monitor` declaring the guest unresponsive -- grouped
/// with these because it's reported the same way, as a terminal failure
/// distinguished from an ordinary build failure on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailureKind {
    OutOfMemory,
    DiskFull,
    GuestHang,
}

/// The wire text for an infra failure — one that happened before or around
/// the build itself, not a build failure in its own right (S3, NATS, a
/// malformed derivation). Never includes the underlying error: that belongs
/// in the worker's own log via `tracing::error!(error = ?report, ...)`,
/// keyed by the same `job_id` so the two are easy to correlate by hand.
fn infra_failure_message(job_id: &str, context: &str) -> String {
    format!("{context} (job {job_id}); see worker logs")
}

impl Job {
    /// Upload the job's artifacts and return what the frontend needs to serve
    /// them.
    ///
    /// The log is treated as an output and uploaded whether or not the build
    /// succeeded — a failed build's log is the most useful thing it produced.
    ///
    /// Called *before* the result is published, so a completed result always
    /// implies fetchable artifacts. An upload failure is therefore a build
    /// failure.
    async fn upload_artifacts(
        &self,
        client: &async_nats::Client,
        http: &reqwest::Client,
        outcome: &Outcome,
        log: Vec<u8>,
        nix: upload::NixStore<'_>,
        mut vm: Option<&mut VmConn>,
    ) -> eyre::Result<(Vec<upload::OutputArtifact>, Option<ObjectKey>)> {
        let outputs: Vec<StorePath> = match outcome {
            Outcome::Completed(paths) => paths.clone(),
            Outcome::Failed { .. } => Vec::new(),
        };

        let log_key = upload::log_key(&self.tenant, &self.derivation_path)
            .ok_or_eyre("cannot derive a log key")
            .wrap_err_with(|| self.derivation_path.to_string())?;

        // One round trip for every key this job needs.
        let mut keys = vec![log_key.clone()];
        for path in &outputs {
            keys.push(
                upload::nar_key(&self.tenant, path)
                    .ok_or_eyre("cannot derive a nar key")
                    .wrap_err_with(|| path.to_string())?,
            );
        }

        let urls = upload::request_upload_urls(client, &self.job_id, &self.token, &keys)
            .await
            .wrap_err("requesting upload urls")?;

        // An empty log is possible — a build that printed nothing — and some
        // S3 implementations reject a zero-length PUT outright. Losing the
        // whole job over an empty log would be absurd, so skip the upload and
        // report no key.
        let log_key = if log.is_empty() {
            tracing::debug!(job_id = %self.job_id, "build produced no log; not uploading one");
            None
        } else {
            upload::upload_log(http, &urls[0], &log_key, log)
                .await
                .wrap_err("uploading the build log")?;
            Some(log_key)
        };

        let mut artifacts = Vec::new();
        for (i, path) in outputs.iter().enumerate() {
            let key = keys[i + 1].clone();
            tracing::info!(job_id = %self.job_id, %path, %key, "uploading output");
            let artifact = match &mut vm {
                Some(conn) => {
                    vm_ops::upload_output(conn, http, &urls[i + 1], key, path, nix.store_dir)
                        .await
                        .wrap_err_with(|| format!("uploading {path}"))?
                }
                None => nix
                    .upload_output(http, &urls[i + 1], key, path)
                    .await
                    .wrap_err_with(|| format!("uploading {path}"))?,
            };
            artifacts.push(artifact);
        }

        Ok((artifacts, log_key))
    }
}

impl Job {
    /// Build the job's derivation and stream its log.
    ///
    /// Goes through `nix-store --serve` rather than writing a `.drv` and
    /// calling `nix-store --realise`. The derivation we receive is
    /// *resolved*, and Nix computes an input-addressed output path from the
    /// derivation itself, so a reconstructed `.drv` disagrees with the
    /// outputs recorded inside it — see `serve.rs`. Passing the derivation by
    /// value sidesteps that entirely.
    async fn run_build(
        &self,
        client: &async_nats::Client,
        outputs: Vec<StorePath>,
        builder: &str,
        store_uri: Option<&str>,
        store_dir: &str,
        vm: Option<&mut VmConn>,
    ) -> (Outcome, Vec<u8>) {
        let log_subject = format!("kubernix.logs.{}", self.job_id);

        // Phase 15 Step 3: over the tenant VM's daemon connection when one is
        // available, `nix-store --serve` otherwise. The log has to be relayed
        // *while* the build runs here too, the same reason the subprocess
        // path below drains its pipe concurrently rather than after —
        // `on_line` is `DaemonConnection::build_derivation`'s seam for that,
        // sending each line to `pump_channel` as it's read off the wire.
        if let Some(conn) = vm {
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            let pump = tokio::spawn(pump_channel(client.clone(), log_subject.clone(), rx));

            let result = vm_ops::build_derivation(
                conn,
                &self.derivation_path.to_full(store_dir),
                &self.drv,
                Some(&tx),
            )
            .await;
            // Closes the channel, which is what ends `pump_channel`'s loop —
            // done before awaiting it, same ordering the subprocess path
            // below uses for its own pipe.
            drop(tx);
            let (archive, tail) = pump.await.unwrap_or_default();
            let _ = client.flush().await;

            return match result {
                Ok(outcome) => {
                    let outcome = if outcome.succeeded() {
                        Outcome::Completed(outputs)
                    } else {
                        // The client already saw the log live; the tail is
                        // what makes the failure message useful on its own.
                        let mut message = outcome.describe();
                        if !tail.is_empty() {
                            message.push('\n');
                            message.push_str(&tail.join("\n"));
                        }
                        Outcome::failed(message)
                    };
                    (outcome, archive)
                }
                Err(e) => {
                    tracing::error!(
                        job_id = %self.job_id, drv = %self.derivation_path, error = ?e,
                        "builder invocation failed over the VM connection"
                    );
                    let message = infra_failure_message(&self.job_id, "running the builder failed");
                    let _ = client.publish(log_subject, message.clone().into()).await;
                    (Outcome::failed(message.clone()), message.into_bytes())
                }
            };
        }

        let mut conn = match serve::ServeConnection::open(builder, store_uri).await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::error!(job_id = %self.job_id, %builder, error = ?e, "could not start the builder");
                let message = infra_failure_message(&self.job_id, "starting the builder failed");
                let _ = client.publish(log_subject, message.clone().into()).await;
                return (Outcome::failed(message.clone()), message.into_bytes());
            }
        };

        // The log has to be drained *while* the build runs: it is a pipe, and
        // a full one would block the builder rather than merely delaying the
        // output.
        let stderr = conn.stderr.take();
        let pump = tokio::spawn(pump_log(client.clone(), log_subject.clone(), stderr));

        let result = conn
            .build_derivation(&self.derivation_path.to_full(store_dir), &self.drv)
            .await;

        // Closing drops stdin, which is what tells `nix-store --serve` to
        // exit, which in turn ends the log stream. Done before awaiting the
        // pump for that reason.
        if let Err(e) = conn.close().await {
            tracing::warn!(error = %e, "serve connection did not close cleanly");
        }
        let (archive, tail) = pump.await.unwrap_or_default();
        let _ = client.flush().await;

        let outcome = match result {
            Ok(outcome) if outcome.succeeded() => Outcome::Completed(outputs),
            Ok(outcome) => {
                // The client already saw the log live; the tail is what makes
                // the failure message useful on its own.
                let mut message = outcome.describe();
                if !tail.is_empty() {
                    message.push('\n');
                    message.push_str(&tail.join("\n"));
                }
                Outcome::failed(message)
            }
            Err(e) => {
                tracing::error!(
                    job_id = %self.job_id, drv = %self.derivation_path, error = ?e,
                    "builder invocation failed"
                );
                Outcome::failed(infra_failure_message(
                    &self.job_id,
                    "running the builder failed",
                ))
            }
        };

        (outcome, archive)
    }
}

/// The VM path's counterpart to [`pump_log`]: relays
/// `DaemonConnection::build_derivation`'s `on_line` channel to
/// `kubernix.logs.<job_id>` as each line arrives, instead of a subprocess's
/// stderr pipe. Same `(archive, tail)` shape, so both paths converge on
/// identical failure-message construction.
async fn pump_channel(
    client: async_nats::Client,
    subject: String,
    mut rx: tokio::sync::mpsc::UnboundedReceiver<String>,
) -> (Vec<u8>, Vec<String>) {
    let mut archive = Vec::new();
    let mut tail: Vec<String> = Vec::new();

    while let Some(line) = rx.recv().await {
        let _ = client.publish(subject.clone(), line.clone().into()).await;
        archive.extend_from_slice(line.as_bytes());
        archive.push(b'\n');
        if tail.len() == 20 {
            tail.remove(0);
        }
        tail.push(line);
    }
    (archive, tail)
}

/// Relay the builder's output to `kubernix.logs.<job_id>` as it arrives.
///
/// Returns the full log for archival, and the last few lines for the failure
/// message.
async fn pump_log(
    client: async_nats::Client,
    subject: String,
    stderr: Option<tokio::process::ChildStderr>,
) -> (Vec<u8>, Vec<String>) {
    let mut archive = Vec::new();
    let mut tail: Vec<String> = Vec::new();

    let Some(stderr) = stderr else {
        return (archive, tail);
    };
    let mut lines = BufReader::new(stderr).lines();

    loop {
        match lines.next_line().await {
            Ok(Some(line)) => {
                let _ = client.publish(subject.clone(), line.clone().into()).await;
                archive.extend_from_slice(line.as_bytes());
                archive.push(b'\n');
                if tail.len() == 20 {
                    tail.remove(0);
                }
                tail.push(line);
            }
            Ok(None) => break,
            Err(e) => {
                tracing::warn!(error = %e, "log read error");
                break;
            }
        }
    }
    (archive, tail)
}

impl Job {
    async fn publish_result(
        &self,
        jetstream: &jetstream::Context,
        outcome: &Outcome,
        artifacts: &[upload::OutputArtifact],
        log_key: Option<&ObjectKey>,
    ) -> eyre::Result<()> {
        let mut message = capnp::message::Builder::new_default();
        {
            let mut result = message.init_root::<kubernix_capnp::job_result::Builder>();
            result.set_job_id(self.job_id.as_str());
            // The wire has no "absent" representation of its own — an empty
            // string is how "no log was uploaded" travels — but the type here
            // makes that meaning explicit at every call site instead of
            // relying on callers to remember that `ObjectKey::default()` is
            // the sentinel for absence.
            result.set_log_key(log_key.map(ObjectKey::as_str).unwrap_or(""));

            match outcome {
                Outcome::Completed(outputs) => {
                    result.set_status(kubernix_capnp::JobStatus::Completed);
                    let mut list = result.reborrow().init_output_paths(outputs.len() as u32);
                    for (i, path) in outputs.iter().enumerate() {
                        list.set(i as u32, path.as_str());
                    }
                }
                Outcome::Failed {
                    message,
                    failure_kind,
                } => {
                    result.set_status(kubernix_capnp::JobStatus::Failed);
                    result.set_error_msg(message.as_str());
                    result.set_failure_kind(match failure_kind {
                        Some(FailureKind::OutOfMemory) => kubernix_capnp::FailureKind::OutOfMemory,
                        Some(FailureKind::DiskFull) => kubernix_capnp::FailureKind::DiskFull,
                        Some(FailureKind::GuestHang) => kubernix_capnp::FailureKind::GuestHang,
                        None => kubernix_capnp::FailureKind::None,
                    });
                }
            }

            let mut list = result.reborrow().init_outputs(artifacts.len() as u32);
            for (i, artifact) in artifacts.iter().enumerate() {
                let mut out = list.reborrow().get(i as u32);
                out.set_store_path(artifact.store_path.as_str());
                out.set_nar_hash(&artifact.nar_hash);
                out.set_nar_size(artifact.nar_size);
                out.set_file_hash(&artifact.file_hash);
                out.set_file_size(artifact.file_size);
                out.set_key(artifact.key.as_str());
                out.set_compression(kubernix_types::Compression::Zstd.as_str());
                out.set_deriver(
                    artifact
                        .deriver
                        .as_ref()
                        .map(StorePath::as_str)
                        .unwrap_or(""),
                );
                let mut refs = out
                    .reborrow()
                    .init_references(artifact.references.len() as u32);
                for (j, reference) in artifact.references.iter().enumerate() {
                    refs.set(j as u32, reference.as_str());
                }
            }
        }

        let mut payload = Vec::new();
        capnp::serialize::write_message(&mut payload, &message)
            .wrap_err("encoding the job result")?;

        jetstream
            .publish(format!("kubernix.results.{}", self.job_id), payload.into())
            .await
            .wrap_err_with(|| format!("publishing the result for job {}", self.job_id))?
            .await
            .wrap_err_with(|| format!("awaiting the publish ack for job {}", self.job_id))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(path: &str, references: &[&str]) -> InputRef {
        InputRef {
            store_path: StorePath::new(path),
            key: ObjectKey::new(path),
            references: references.iter().map(|r| StorePath::new(*r)).collect(),
            deriver: StorePath::new(format!("{path}.drv")),
            compression: Compression::Zstd,
            nar_hash: format!("sha256:{path}"),
            nar_size: 0,
        }
    }

    #[test]
    fn topo_sort_inputs_reorders_reference_before_dependent() {
        // Mirrors the real failure: the referenced path
        // (`bdw...-xz-5.8.3`) sorts lexicographically *after* the input
        // that references it (`0fb...-xz-5.8.3-bin`), which is the wire
        // order the server actually sent.
        let inputs = vec![
            input("0fb3-xz-5.8.3-bin", &["bdws-xz-5.8.3"]),
            input("bdws-xz-5.8.3", &[]),
        ];
        let order = topo_sort_inputs(&inputs).unwrap();
        assert_eq!(order, vec![1, 0]);
    }

    #[test]
    fn topo_sort_inputs_ignores_references_outside_the_set() {
        // A reference to something not in `inputs` (already valid in the
        // guest, e.g. base system paths) must not block ordering.
        let inputs = vec![input("a", &["not-an-input"]), input("b", &[])];
        let order = topo_sort_inputs(&inputs).unwrap();
        assert_eq!(order.len(), 2);
        assert!(order.contains(&0));
        assert!(order.contains(&1));
    }

    #[test]
    fn topo_sort_inputs_preserves_already_correct_order() {
        let inputs = vec![input("a", &[]), input("b", &["a"]), input("c", &["b"])];
        let order = topo_sort_inputs(&inputs).unwrap();
        assert_eq!(order, vec![0, 1, 2]);
    }

    #[test]
    fn topo_sort_inputs_rejects_a_reference_cycle() {
        let inputs = vec![input("a", &["b"]), input("b", &["a"])];
        assert!(topo_sort_inputs(&inputs).is_err());
    }

    fn job_with_inputs(inputs: Vec<InputRef>) -> Job {
        Job {
            job_id: "job".to_string(),
            derivation_path: StorePath::new("out.drv"),
            tenant: TenantId::from_parts("t", "0"),
            inputs,
            drv: Vec::new(),
            token: CapabilityToken::default(),
            required_features: Vec::new(),
            trusted_substituters: Vec::new(),
        }
    }

    /// Drives the guest side of `DaemonConnection::open`'s handshake/
    /// `set_options`, then answers exactly `valid_for.len()` `QueryPathInfo`
    /// calls in order, reporting each one valid/invalid per that list. Wire
    /// shape and the constants below are copied from `daemon-protocol`'s own
    /// (crate-private) `connection.rs`, the same way that crate's own tests
    /// copy them rather than exposing them across the crate boundary just for
    /// tests.
    mod fake_guest_daemon {
        use kubernix_types::wire::{write_bytes, write_u64};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UnixStream;

        const MAGIC_1: u64 = 0x6e69_7863;
        const MAGIC_2: u64 = 0x6478_696f;
        const PROTOCOL_VERSION: u64 = (1 << 8) | 35;
        const STDERR_LAST: u64 = 0x616c_7473;
        const OP_QUERY_PATH_INFO: u64 = 26;

        fn padding(len: usize) -> usize {
            (8 - len % 8) % 8
        }

        async fn read_u64(stream: &mut UnixStream) -> u64 {
            let mut buf = [0u8; 8];
            stream.read_exact(&mut buf).await.unwrap();
            u64::from_le_bytes(buf)
        }

        async fn discard_wire_str(stream: &mut UnixStream) {
            let len = read_u64(stream).await as usize;
            let mut buf = vec![0u8; len + padding(len)];
            stream.read_exact(&mut buf).await.unwrap();
        }

        pub async fn run(mut stream: UnixStream, valid_for: Vec<bool>) {
            let mut magic = [0u8; 8];
            stream.read_exact(&mut magic).await.unwrap();
            assert_eq!(u64::from_le_bytes(magic), MAGIC_1);

            let mut greeting = Vec::new();
            write_u64(&mut greeting, MAGIC_2);
            write_u64(&mut greeting, PROTOCOL_VERSION);
            stream.write_all(&greeting).await.unwrap();

            // Client's PROTOCOL_VERSION, obsolete CPU affinity, obsolete
            // reserveSpace -- three words, none acted on here.
            let mut discard = [0u8; 24];
            stream.read_exact(&mut discard).await.unwrap();

            let mut reply = Vec::new();
            write_bytes(&mut reply, b"2.96.0-test");
            write_u64(&mut reply, 0); // optional<TrustedFlag>: absent
            write_u64(&mut reply, STDERR_LAST);
            stream.write_all(&reply).await.unwrap();

            // `set_options`: OP_SET_OPTIONS + 13 further words (104 bytes),
            // none of which this fake daemon needs to act on.
            let mut discard = [0u8; 8 + 104];
            stream.read_exact(&mut discard).await.unwrap();
            let mut reply = Vec::new();
            write_u64(&mut reply, STDERR_LAST);
            stream.write_all(&reply).await.unwrap();

            for valid in valid_for {
                let op = read_u64(&mut stream).await;
                assert_eq!(op, OP_QUERY_PATH_INFO);
                discard_wire_str(&mut stream).await; // the queried store path

                let mut reply = Vec::new();
                write_u64(&mut reply, STDERR_LAST);
                write_u64(&mut reply, valid as u64);
                if valid {
                    write_bytes(&mut reply, b""); // deriver: none
                    write_bytes(&mut reply, b"sha256:abc"); // nar_hash
                    write_u64(&mut reply, 0); // references: none
                    write_u64(&mut reply, 0); // registrationTime
                    write_u64(&mut reply, 0); // narSize
                    write_u64(&mut reply, 0); // ultimate: false
                    write_u64(&mut reply, 0); // sigs: none
                    write_bytes(&mut reply, b""); // ca: none
                }
                stream.write_all(&reply).await.unwrap();
            }
        }
    }

    #[tokio::test]
    async fn skip_already_valid_filters_out_valid_inputs_in_order() {
        let (client, guest) = tokio::net::UnixStream::pair().unwrap();
        let guest_task = tokio::spawn(fake_guest_daemon::run(guest, vec![true, false]));

        let job = job_with_inputs(vec![input("a", &[]), input("b", &[])]);
        let mut conn = VmConn::open(client).await.unwrap();
        let mut vm = Some(&mut conn);

        let order = job
            .skip_already_valid(vec![0, 1], &mut vm, false, "/nix/store")
            .await
            .unwrap();

        // `a` (index 0) reported valid, `b` (index 1) not -- only `b`
        // remains, keeping its position in `order`.
        assert_eq!(order, vec![1]);
        guest_task.await.unwrap();
    }

    #[tokio::test]
    async fn skip_already_valid_is_a_noop_on_a_fresh_store() {
        // A fresh `store.img` can't already hold anything a previous job
        // registered, so no `QueryPathInfo` call should ever be sent --
        // `fake_guest_daemon::run` is handed an empty `valid_for`, so it
        // returns right after the handshake and would otherwise panic on
        // seeing a further read it did not expect.
        let (client, guest) = tokio::net::UnixStream::pair().unwrap();
        let guest_task = tokio::spawn(fake_guest_daemon::run(guest, vec![]));

        let job = job_with_inputs(vec![input("a", &[])]);
        let mut conn = VmConn::open(client).await.unwrap();
        let mut vm = Some(&mut conn);

        let order = job
            .skip_already_valid(vec![0], &mut vm, true, "/nix/store")
            .await
            .unwrap();
        assert_eq!(order, vec![0]);
        guest_task.await.unwrap();
    }

    #[tokio::test]
    async fn skip_already_valid_passes_inputs_through_with_no_vm() {
        let job = job_with_inputs(vec![input("a", &[]), input("b", &[])]);
        let mut vm: Option<&mut VmConn> = None;
        let order = job
            .skip_already_valid(vec![0, 1], &mut vm, false, "/nix/store")
            .await
            .unwrap();
        assert_eq!(order, vec![0, 1]);
    }

    // PLAN.md Phase 18: `next_action` table test -- every
    // (GuestFailureStatus, original_boot_was_fresh, already_on_big_parallel,
    // enospc_retried, oom_local_retried) combination that actually matters.

    #[test]
    fn next_action_ordinary_failure_is_never_retried() {
        assert_eq!(
            next_action(vm::GuestFailureStatus::None, true, true, true, true),
            RetryAction::GiveUp
        );
        assert_eq!(
            next_action(vm::GuestFailureStatus::None, false, false, false, false),
            RetryAction::GiveUp
        );
    }

    #[test]
    fn next_action_enospc_retries_once_only_on_reuse() {
        // REUSE boot, first failure: wipe and retry.
        assert_eq!(
            next_action(vm::GuestFailureStatus::DiskFull, false, false, false, false),
            RetryAction::RetryEnospcWipe
        );
        // FRESH boot: nothing to gain from wiping an already-empty disk.
        assert_eq!(
            next_action(vm::GuestFailureStatus::DiskFull, true, false, false, false),
            RetryAction::TerminalEnospc
        );
        // REUSE boot, but already retried once: terminal, not a second wipe.
        assert_eq!(
            next_action(vm::GuestFailureStatus::DiskFull, false, false, true, false),
            RetryAction::TerminalEnospc
        );
    }

    #[test]
    fn next_action_non_builder_oom_retries_once_locally() {
        let status = vm::GuestFailureStatus::OutOfMemory {
            builder_victim: false,
        };
        assert_eq!(
            next_action(status, false, false, false, false),
            RetryAction::RetryOomLocal
        );
        assert_eq!(
            next_action(status, false, false, false, true),
            RetryAction::TerminalOom,
            "a second non-builder OOM after the one local retry is terminal, not another retry"
        );
    }

    #[test]
    fn next_action_builder_oom_escalates_unless_already_on_big_parallel() {
        let status = vm::GuestFailureStatus::OutOfMemory {
            builder_victim: true,
        };
        assert_eq!(
            next_action(status, false, false, false, false),
            RetryAction::EscalateOom
        );
        assert_eq!(
            next_action(status, false, true, false, false),
            RetryAction::TerminalOom,
            "already on big-parallel: nowhere bigger to escalate to"
        );
    }

    #[test]
    fn terminal_failure_sets_failure_kind_on_a_failed_outcome() {
        let outcome = Outcome::failed("build failed");
        let terminal = terminal_failure(outcome, FailureKind::OutOfMemory);
        match terminal {
            Outcome::Failed {
                message,
                failure_kind,
            } => {
                assert_eq!(message, "build failed");
                assert_eq!(failure_kind, Some(FailureKind::OutOfMemory));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn terminal_failure_sets_guest_hang_on_a_failed_outcome() {
        let outcome = Outcome::failed("guest VM stopped responding");
        let terminal = terminal_failure(outcome, FailureKind::GuestHang);
        match terminal {
            Outcome::Failed { failure_kind, .. } => {
                assert_eq!(failure_kind, Some(FailureKind::GuestHang));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn terminal_failure_is_a_noop_on_a_completed_outcome() {
        let outcome = Outcome::Completed(Vec::new());
        let terminal = terminal_failure(outcome, FailureKind::DiskFull);
        assert!(matches!(terminal, Outcome::Completed(_)));
    }

    #[test]
    fn heartbeat_is_stale_fires_once_deadline_elapses() {
        let last_seen = std::time::Instant::now();
        let deadline = std::time::Duration::from_secs(20);
        assert!(!heartbeat_is_stale(
            last_seen,
            last_seen + std::time::Duration::from_secs(19),
            deadline
        ));
        assert!(heartbeat_is_stale(
            last_seen,
            last_seen + std::time::Duration::from_secs(20),
            deadline
        ));
        assert!(heartbeat_is_stale(
            last_seen,
            last_seen + std::time::Duration::from_secs(21),
            deadline
        ));
    }

    #[test]
    fn infra_failure_message_carries_no_error_detail() {
        // A fake error's text, as if it had been formatted straight into the
        // message the way the old code did — proof this construction never
        // does that.
        let leaked = "AccessDenied: request id AKIAABCDEF1234567890";
        let message = infra_failure_message(
            "11111111-2222-3333-4444-555555555555",
            "uploading artifacts failed",
        );

        assert!(message.contains("11111111-2222-3333-4444-555555555555"));
        assert!(message.contains("uploading artifacts failed"));
        assert!(!message.contains(leaked));
    }

    #[test]
    fn parse_static_worker_classes_empty() {
        assert!(parse_static_worker_classes("").is_empty());
    }

    #[test]
    fn parse_static_worker_classes_single() {
        assert_eq!(
            parse_static_worker_classes("big-parallel"),
            vec!["big-parallel".to_string()]
        );
    }

    #[test]
    fn parse_static_worker_classes_trims_whitespace() {
        assert_eq!(
            parse_static_worker_classes(" big-parallel , "),
            vec!["big-parallel".to_string()]
        );
    }

    #[test]
    fn parse_static_worker_classes_rejects_kvm_and_unknown() {
        // kvm is probe-only; anything else unrecognised is dropped too.
        assert!(parse_static_worker_classes("kvm,made-up-feature").is_empty());
    }

    #[test]
    fn worker_subjects_non_exclusive_includes_base_subject() {
        let (subjects, durable_name) =
            worker_subjects_and_consumer("x86_64-linux", &["big-parallel".to_string()], false)
                .unwrap();
        assert_eq!(
            subjects,
            vec![
                "kubernix.jobs.x86_64-linux".to_string(),
                "kubernix.jobs.x86_64-linux.big-parallel".to_string(),
            ]
        );
        assert_eq!(durable_name, "worker-x86_64_linux");
    }

    #[test]
    fn worker_subjects_exclusive_drops_base_subject() {
        let (subjects, durable_name) =
            worker_subjects_and_consumer("x86_64-linux", &["big-parallel".to_string()], true)
                .unwrap();
        assert_eq!(
            subjects,
            vec!["kubernix.jobs.x86_64-linux.big-parallel".to_string()]
        );
        assert_eq!(durable_name, "worker-x86_64_linux-big-parallel");
    }

    #[test]
    fn worker_subjects_exclusive_sorts_classes_into_consumer_name() {
        let (_, durable_name) = worker_subjects_and_consumer(
            "x86_64-linux",
            &["kvm".to_string(), "big-parallel".to_string()],
            true,
        )
        .unwrap();
        assert_eq!(durable_name, "worker-x86_64_linux-big-parallel_kvm");
    }

    #[test]
    fn worker_subjects_exclusive_with_no_classes_errors() {
        assert!(worker_subjects_and_consumer("x86_64-linux", &[], true).is_err());
    }

    #[test]
    fn worker_satisfies_a_plain_job() {
        assert!(worker_capabilities_satisfy(&[], &[]));
    }

    #[test]
    fn worker_satisfies_unrecognised_features() {
        // A tag nothing routes on is not something any worker could have
        // declared, so it's not something this check should demand either.
        assert!(worker_capabilities_satisfy(
            &[],
            &["ca-derivations".to_string()]
        ));
    }

    #[test]
    fn plain_worker_cannot_satisfy_kvm() {
        assert!(!worker_capabilities_satisfy(&[], &["kvm".to_string()]));
    }

    #[test]
    fn kvm_worker_satisfies_kvm() {
        assert!(worker_capabilities_satisfy(
            &["kvm".to_string()],
            &["kvm".to_string()]
        ));
    }

    #[test]
    fn kvm_only_worker_cannot_satisfy_kvm_plus_big_parallel() {
        assert!(!worker_capabilities_satisfy(
            &["kvm".to_string()],
            &["kvm".to_string(), "big-parallel".to_string()]
        ));
    }

    #[test]
    fn worker_declaring_both_satisfies_both() {
        assert!(worker_capabilities_satisfy(
            &["kvm".to_string(), "big-parallel".to_string()],
            &["kvm".to_string(), "big-parallel".to_string()]
        ));
    }
}
