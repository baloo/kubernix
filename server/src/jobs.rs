//! The NATS job queue.
//!
//! Subjects, per DESIGN.md:
//!
//! | subject | stream | purpose |
//! | --- | --- | --- |
//! | `kubernix.jobs.<system>` | `kubernix_jobs` (WorkQueue) | dispatch to exactly one worker |
//! | `kubernix.logs.<job_id>` | core NATS | live build output |
//! | `kubernix.results.<job_id>` | `kubernix_results` | terminal outcome |
//!
//! Logs are core NATS on purpose: they are high-volume and only interesting while
//! someone is watching. The durable copy is the archived log. Results are
//! JetStream so a frontend restart does not lose an outcome.

use std::time::Duration;

use async_nats::jetstream::{self, consumer::pull, stream::RetentionPolicy};
use eyre::{Context as _, OptionExt as _};
use futures_util::StreamExt;
use kubernix_types::{CapabilityToken, ObjectKey, StorePath, System};
use sha2::{Sha256, digest::Output};
use uuid::Uuid;

use crate::kubernix_capnp;
use crate::tenant::TenantId;

pub const JOBS_STREAM: &str = "kubernix_jobs";
pub const RESULTS_STREAM: &str = "kubernix_results";

/// The subject a job publishes to, given its declared `requiredSystemFeatures`
/// (PLAN.md Phase 17). A plain job (no recognised features) publishes to
/// exactly the same subject as before this phase existed.
///
/// `kvm` takes priority over `big-parallel` when a derivation declares both:
/// `kvm` is a hard functional requirement (the build cannot run at all
/// without it), `big-parallel` is only a sizing hint, so it's the one worth
/// picking a single subject on. This does not silently drop the other
/// declared feature — the full list still travels with the job (see
/// `BuildJob::required_features`), so a worker that's `kvm`-subscribed but
/// wasn't also deployed with `big-parallel` can still notice and Nak the
/// job rather than build it. Unrecognised tags are ignored for routing.
pub fn jobs_subject(system: &System, features: &[&str]) -> String {
    if features.contains(&"kvm") {
        format!("kubernix.jobs.{system}.kvm")
    } else if features.contains(&"big-parallel") {
        format!("kubernix.jobs.{system}.big-parallel")
    } else {
        format!("kubernix.jobs.{system}")
    }
}

pub fn logs_subject(job_id: &Uuid) -> String {
    format!("kubernix.logs.{job_id}")
}

pub fn results_subject(job_id: &Uuid) -> String {
    format!("kubernix.results.{job_id}")
}

#[derive(Debug, Clone)]
pub struct InputRef {
    pub store_path: StorePath,
    /// Object key holding the zstd-compressed bare NAR.
    pub key: ObjectKey,
    /// Sent with the key because a bare NAR cannot be imported alone: the
    /// worker wraps it into an export stream, which needs both of these.
    pub references: Vec<StorePath>,
    pub deriver: StorePath,
}

#[derive(Debug)]
pub struct BuildJob {
    pub job_id: Uuid,
    pub derivation_path: StorePath,
    pub system: System,
    /// Serialized derivation, so the worker does not need it in its store first.
    pub drv: Vec<u8>,
    /// Inputs staged to the object store for this build.
    pub inputs: Vec<InputRef>,
    /// Whose build this is, per the dispatcher's own record — not what
    /// authorizes anything by itself; see `token`.
    pub tenant: TenantId,
    /// The signed capability token minted for this job
    /// (`crate::capability::Capability`). The worker carries this opaquely
    /// and presents it back with every upload/download URL request; it is
    /// what `uploads.rs` and `record_outputs` actually check, rather than
    /// trusting `tenant` or a worker-reported `OutputInfo.store_path` at face
    /// value. PLAN.md Phase 14.
    pub token: CapabilityToken,
    /// The derivation's full declared `requiredSystemFeatures`, used to pick
    /// the subject this job publishes to (`jobs_subject`) and sent along on
    /// the wire so a worker can double-check it actually satisfies every
    /// declared feature, not just the one the subject routed on. PLAN.md
    /// Phase 17.
    pub required_features: Vec<String>,
}

/// Per-output metadata the worker reports, which is what `narinfo` is generated
/// from. The frontend never sees the build, so this cannot be recomputed here.
#[derive(Debug, Clone)]
pub struct OutputInfo {
    pub store_path: StorePath,
    pub nar_hash: Output<Sha256>,
    pub nar_size: u64,
    pub file_hash: Output<Sha256>,
    pub file_size: u64,
    pub key: ObjectKey,
    pub compression: String,
    pub references: Vec<StorePath>,
    pub deriver: Option<StorePath>,
}

#[derive(Debug, Clone)]
pub enum JobOutcome {
    Completed {
        outputs: Vec<StorePath>,
        infos: Vec<OutputInfo>,
        log_key: String,
    },
    Failed {
        message: String,
        log_key: String,
        /// Set only on a terminal resource-exhaustion failure (PLAN.md
        /// Phase 18) -- `None` for every ordinary build failure. See
        /// `worker/src/main.rs::FailureKind`, the worker-side counterpart
        /// this is decoded from.
        failure_kind: Option<FailureKind>,
    },
}

/// PLAN.md Phase 18. Kept as its own small enum here rather than shared
/// with `worker`'s identical-looking type -- this codebase's established
/// pattern for the several structurally-similar Outcome-like types is an
/// explicit conversion at each capnp boundary, not a fifth shared type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    OutOfMemory,
    DiskFull,
}

#[derive(Clone)]
pub struct JobQueue {
    client: async_nats::Client,
    jetstream: jetstream::Context,
    /// How long to wait for a worker to report an outcome.
    pub result_timeout: Duration,
    /// How long a job's outcome stays replayable in `RESULTS_STREAM`
    /// (its `max_age`, set from this same value in [`Self::connect`]) and,
    /// PLAN.md Phase 19, how long a `'running'` reservation in `jobs` may go
    /// unclaimed before it's treated as orphaned rather than still in
    /// flight — see `PathStore::reserve_job`'s doc comment. One value drives
    /// both so they can never drift apart: a reservation can never outlive
    /// the only evidence (the replayed result) that would resolve it.
    pub results_retention: Duration,
}

impl JobQueue {
    /// The underlying NATS client, for services that share the connection.
    pub fn client(&self) -> async_nats::Client {
        self.client.clone()
    }

    pub async fn connect(url: &str) -> eyre::Result<Self> {
        tracing::info!(%url, "connecting to NATS");
        let client = async_nats::connect(url)
            .await
            .wrap_err_with(|| format!("connecting to NATS at {url}"))?;
        let jetstream = jetstream::new(client.clone());

        // Created here rather than assumed: a frontend that starts before any
        // worker should still be able to accept a build.
        jetstream
            .get_or_create_stream(jetstream::stream::Config {
                name: JOBS_STREAM.to_string(),
                subjects: vec!["kubernix.jobs.>".to_string()],
                retention: RetentionPolicy::WorkQueue,
                ..Default::default()
            })
            .await
            .wrap_err_with(|| format!("creating the {JOBS_STREAM} stream"))?;

        // TODO(PLAN.md Phase 19 step 5): chart-driven, not hardcoded --
        // shared with `jobs.resultsRetention` and threaded to the GC's own
        // orphan-reservation sweep, so all three can never disagree.
        let results_retention = Duration::from_secs(24 * 3600);

        jetstream
            .get_or_create_stream(jetstream::stream::Config {
                name: RESULTS_STREAM.to_string(),
                subjects: vec!["kubernix.results.>".to_string()],
                max_age: results_retention,
                ..Default::default()
            })
            .await
            .wrap_err_with(|| format!("creating the {RESULTS_STREAM} stream"))?;

        Ok(Self {
            client,
            jetstream,
            result_timeout: Duration::from_secs(3600),
            results_retention,
        })
    }

    /// Subscribe to a job's logs. Do this *before* submitting: core NATS has no
    /// replay, so a subscription created afterwards can miss the opening lines.
    pub async fn subscribe_logs(
        &self,
        job_id: &Uuid,
    ) -> Result<async_nats::Subscriber, async_nats::SubscribeError> {
        self.client.subscribe(logs_subject(job_id)).await
    }

    /// Create the result consumer. Also do this before submitting — though this
    /// one is JetStream, so a late consumer would still replay.
    pub async fn result_consumer(
        &self,
        job_id: &Uuid,
    ) -> eyre::Result<jetstream::consumer::Consumer<pull::Config>> {
        let stream = self
            .jetstream
            .get_stream(RESULTS_STREAM)
            .await
            .wrap_err_with(|| format!("getting the {RESULTS_STREAM} stream"))?;
        let consumer = stream
            .create_consumer(pull::Config {
                // Ephemeral: this consumer exists for one build.
                filter_subject: results_subject(job_id),
                ..Default::default()
            })
            .await
            .wrap_err_with(|| format!("creating a result consumer for job {job_id}"))?;
        Ok(consumer)
    }

    pub async fn submit(&self, job: &BuildJob) -> eyre::Result<()> {
        let mut message = capnp::message::Builder::new_default();
        {
            let mut req = message.init_root::<kubernix_capnp::build_request::Builder>();
            req.set_job_id(job.job_id.to_string().as_str());
            req.set_derivation_path(job.derivation_path.as_str());
            req.set_system(job.system.as_str());
            req.set_drv(&job.drv);
            req.set_tenant(job.tenant.as_str());
            req.set_token(job.token.as_bytes());

            let mut features = req
                .reborrow()
                .init_required_features(job.required_features.len() as u32);
            for (i, feature) in job.required_features.iter().enumerate() {
                features.set(i as u32, feature.as_str());
            }

            let mut inputs = req.reborrow().init_inputs(job.inputs.len() as u32);
            for (i, input) in job.inputs.iter().enumerate() {
                let mut entry = inputs.reborrow().get(i as u32);
                entry.set_store_path(input.store_path.as_str());
                entry.set_key(input.key.as_str());
                entry.set_deriver(input.deriver.as_str());
                let mut refs = entry.init_references(input.references.len() as u32);
                for (r, reference) in input.references.iter().enumerate() {
                    refs.set(r as u32, reference.as_str());
                }
            }
        }
        let mut payload = Vec::new();
        capnp::serialize::write_message(&mut payload, &message)
            .wrap_err("encoding the build request")?;

        let features: Vec<&str> = job.required_features.iter().map(String::as_str).collect();
        let subject = jobs_subject(&job.system, &features);
        tracing::info!(
            job_id = %job.job_id,
            tenant = %job.tenant,
            %subject,
            drv = %job.derivation_path,
            inputs = job.inputs.len(),
            "submitting job"
        );

        // Await the ack: a publish that silently failed would leave the client
        // waiting for a build nobody queued.
        self.jetstream
            .publish(subject, payload.into())
            .await
            .wrap_err_with(|| format!("publishing job {}", job.job_id))?
            .await
            .wrap_err_with(|| format!("awaiting the publish ack for job {}", job.job_id))?;
        Ok(())
    }

    /// Await the terminal outcome for a job.
    pub async fn await_outcome(
        &self,
        consumer: jetstream::consumer::Consumer<pull::Config>,
    ) -> eyre::Result<JobOutcome> {
        let mut messages = consumer
            .messages()
            .await
            .wrap_err("subscribing to the result consumer")?;

        let message = tokio::time::timeout(self.result_timeout, messages.next())
            .await
            .wrap_err_with(|| {
                format!(
                    "timed out after {:?} waiting for a worker",
                    self.result_timeout
                )
            })?
            .ok_or_eyre("result stream ended before an outcome arrived")?
            .wrap_err("reading a result message")?;

        let outcome = decode_outcome(&message.payload)?;
        message
            .ack()
            .await
            .map_err(|e| eyre::eyre!("{e}"))
            .wrap_err("acking the result message")?;
        Ok(outcome)
    }
}

pub fn decode_outcome(payload: &[u8]) -> eyre::Result<JobOutcome> {
    let mut cursor = payload;
    let reader = capnp::serialize::read_message(&mut cursor, capnp::message::ReaderOptions::new())
        .wrap_err("decoding a job result message")?;
    let result = reader
        .get_root::<kubernix_capnp::job_result::Reader>()
        .wrap_err("reading the job_result root")?;

    let log_key = result.get_log_key()?.to_string()?;

    match result.get_status()? {
        kubernix_capnp::JobStatus::Completed => {
            let mut outputs = Vec::new();
            for path in result.get_output_paths()?.iter() {
                outputs.push(StorePath::new(path?.to_string()?));
            }

            let mut infos = Vec::new();
            for info in result.get_outputs()?.iter() {
                let mut references = Vec::new();
                for reference in info.get_references()?.iter() {
                    references.push(StorePath::new(reference?.to_string()?));
                }
                let deriver = info.get_deriver()?.to_string()?;
                infos.push(OutputInfo {
                    store_path: StorePath::new(info.get_store_path()?.to_string()?),
                    nar_hash: Output::<Sha256>::try_from(info.get_nar_hash()?)?,
                    nar_size: info.get_nar_size(),
                    file_hash: Output::<Sha256>::try_from(info.get_file_hash()?)?,
                    file_size: info.get_file_size(),
                    key: ObjectKey::new(info.get_key()?.to_string()?),
                    compression: info.get_compression()?.to_string()?,
                    references,
                    deriver: (!deriver.is_empty()).then_some(StorePath::new(deriver)),
                });
            }

            Ok(JobOutcome::Completed {
                outputs,
                infos,
                log_key,
            })
        }
        status => {
            let message = result.get_error_msg()?.to_string()?;
            let message = if message.is_empty() {
                format!("build reported status {status:?}")
            } else {
                message
            };
            let failure_kind = match result.get_failure_kind()? {
                kubernix_capnp::FailureKind::None => None,
                kubernix_capnp::FailureKind::OutOfMemory => Some(FailureKind::OutOfMemory),
                kubernix_capnp::FailureKind::DiskFull => Some(FailureKind::DiskFull),
            };
            Ok(JobOutcome::Failed {
                message,
                log_key,
                failure_kind,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn system() -> System {
        System::from("x86_64-linux".to_string())
    }

    #[test]
    fn plain_job_is_unaffected() {
        // Byte-identical to the pre-Phase-17 subject format.
        assert_eq!(jobs_subject(&system(), &[]), "kubernix.jobs.x86_64-linux");
    }

    #[test]
    fn unknown_feature_falls_back_to_plain() {
        assert_eq!(
            jobs_subject(&system(), &["ca-derivations"]),
            "kubernix.jobs.x86_64-linux"
        );
    }

    #[test]
    fn kvm_only() {
        assert_eq!(
            jobs_subject(&system(), &["kvm"]),
            "kubernix.jobs.x86_64-linux.kvm"
        );
    }

    #[test]
    fn big_parallel_only() {
        assert_eq!(
            jobs_subject(&system(), &["big-parallel"]),
            "kubernix.jobs.x86_64-linux.big-parallel"
        );
    }

    #[test]
    fn both_declared_kvm_wins() {
        assert_eq!(
            jobs_subject(&system(), &["big-parallel", "kvm"]),
            "kubernix.jobs.x86_64-linux.kvm"
        );
        // Order in the input slice must not matter.
        assert_eq!(
            jobs_subject(&system(), &["kvm", "big-parallel"]),
            "kubernix.jobs.x86_64-linux.kvm"
        );
    }
}
