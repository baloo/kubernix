//! Kubernix worker.
//!
//! Dequeues one job at a time from `kubernix.jobs.<system>`, realises the
//! derivation against the local Nix builder, streams the build log to
//! `kubernix.logs.<job_id>` as it is produced, and publishes the terminal outcome
//! to `kubernix.results.<job_id>`.
//!
//! The job message is left un-acked for the duration of the build, so a worker
//! that dies mid-build causes redelivery rather than a silently lost job.

pub mod kubernix_capnp {
    include!(concat!(env!("OUT_DIR"), "/kubernix_capnp.rs"));
}

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
use kubernix_types::{CapabilityToken, ObjectKey, StorePath, TenantId, derivation};
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
}

struct InputRef {
    store_path: StorePath,
    key: ObjectKey,
    /// Needed to wrap the NAR into an importable export stream; a bare NAR
    /// carries neither.
    references: Vec<StorePath>,
    deriver: StorePath,
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
    ) -> eyre::Result<()> {
        if self.inputs.is_empty() {
            return Ok(());
        }

        let keys: Vec<ObjectKey> = self.inputs.iter().map(|i| i.key.clone()).collect();
        let urls = upload::request_download_urls(client, &self.job_id, &self.token, &keys)
            .await
            .wrap_err("requesting download urls")?;

        for (input, url) in self.inputs.iter().zip(urls) {
            tracing::info!(job_id = %self.job_id, path = %input.store_path, "importing input");
            match &mut vm {
                Some(conn) => vm_ops::fetch_input(
                    conn,
                    http,
                    &url,
                    &input.store_path,
                    &input.references,
                    &input.deriver,
                    nix.store_dir,
                )
                .await
                .wrap_err_with(|| format!("importing {}", input.store_path))?,
                None => nix
                    .fetch_input(
                        http,
                        &url,
                        &input.store_path,
                        &input.references,
                        &input.deriver,
                    )
                    .await
                    .wrap_err_with(|| format!("importing {}", input.store_path))?,
            }
        }

        tracing::info!(job_id = %self.job_id, count = self.inputs.len(), "inputs imported");
        Ok(())
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

    let mut subjects = vec![format!("kubernix.jobs.{system}")];
    for class in &worker_classes {
        subjects.push(format!("kubernix.jobs.{system}.{class}"));
    }

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
            max_age: std::time::Duration::from_secs(24 * 3600),
            ..Default::default()
        })
        .await?;

    let stream = jetstream.get_stream("kubernix_jobs").await?;
    let consumer: PullConsumer = stream
        .create_consumer(jetstream::consumer::pull::Config {
            durable_name: Some(format!("worker-{}", system.replace('-', "_"))),
            filter_subjects: subjects.clone(),
            // One at a time: a build holds its message un-acked while it runs.
            max_ack_pending: 1,
            ack_wait: std::time::Duration::from_secs(3600),
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

    while let Some(message) = messages.next().await {
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
                let outcome = Outcome::Failed(format!(
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
        if let Some(pool) = vm_pool.as_mut() {
            let dialed = match pool.ensure_vm_for(&job.tenant).await {
                Ok(handle) => {
                    tracing::info!(
                        job_id = %job.job_id, tenant = %job.tenant,
                        vsock = %handle.vsock_socket.display(),
                        "tenant VM ready"
                    );
                    match handle.connect().await {
                        Ok(stream) => VmConn::open(stream).await.map_err(eyre::Report::from),
                        Err(report) => Err(report),
                    }
                }
                Err(report) => Err(report),
            };
            match dialed {
                Ok(conn) => vm_conn = Some(conn),
                Err(report) => {
                    tracing::error!(job_id = %job.job_id, error = ?report, "could not reach the tenant VM's daemon");
                    let outcome = Outcome::Failed(infra_failure_message(
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

        if let Err(report) = job
            .fetch_inputs(&client, &http, nix, vm_conn.as_mut())
            .await
        {
            tracing::error!(job_id = %job.job_id, error = ?report, "could not fetch inputs");
            let outcome =
                Outcome::Failed(infra_failure_message(&job.job_id, "fetching inputs failed"));
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
                let outcome = Outcome::Failed(infra_failure_message(
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

        let (mut outcome, log) = job
            .run_build(
                &client,
                outputs,
                &builder,
                store_uri.as_deref(),
                &store_dir,
                vm_conn.as_mut(),
            )
            .await;

        // Artifacts first, then the result: publishing a success whose outputs
        // are not yet fetchable would be worse than reporting the upload failure.
        let (artifacts, log_key) = match job
            .upload_artifacts(&client, &http, &outcome, log, nix, vm_conn.as_mut())
            .await
        {
            Ok(uploaded) => uploaded,
            Err(report) => {
                tracing::error!(job_id = %job.job_id, error = ?report, "artifact upload failed");
                outcome = Outcome::Failed(infra_failure_message(
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
        inputs.push(InputRef {
            store_path: StorePath::new(input.get_store_path()?.to_string()?),
            key: ObjectKey::new(input.get_key()?.to_string()?),
            references,
            deriver: StorePath::new(input.get_deriver()?.to_string()?),
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

    Ok(Job {
        job_id: request.get_job_id()?.to_string()?,
        derivation_path: StorePath::new(request.get_derivation_path()?.to_string()?),
        tenant,
        inputs,
        drv: request.get_drv()?.to_vec(),
        token: CapabilityToken::new(request.get_token()?.to_vec()),
        required_features,
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
enum Outcome {
    Completed(Vec<StorePath>),
    Failed(String),
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
            Outcome::Failed(_) => Vec::new(),
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
                        Outcome::Failed(message)
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
                    (Outcome::Failed(message.clone()), message.into_bytes())
                }
            };
        }

        let mut conn = match serve::ServeConnection::open(builder, store_uri).await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::error!(job_id = %self.job_id, %builder, error = ?e, "could not start the builder");
                let message = infra_failure_message(&self.job_id, "starting the builder failed");
                let _ = client.publish(log_subject, message.clone().into()).await;
                return (Outcome::Failed(message.clone()), message.into_bytes());
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
                Outcome::Failed(message)
            }
            Err(e) => {
                tracing::error!(
                    job_id = %self.job_id, drv = %self.derivation_path, error = ?e,
                    "builder invocation failed"
                );
                Outcome::Failed(infra_failure_message(
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
                Outcome::Failed(message) => {
                    result.set_status(kubernix_capnp::JobStatus::Failed);
                    result.set_error_msg(message.as_str());
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
                out.set_compression("zstd");
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
