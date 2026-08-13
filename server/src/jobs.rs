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
use futures_util::StreamExt;
use kubernix_types::{ObjectKey, StorePath, System};
use sha2::{Sha256, digest::Output};
use uuid::Uuid;

use crate::kubernix_capnp;
use crate::tenant::TenantId;

pub const JOBS_STREAM: &str = "kubernix_jobs";
pub const RESULTS_STREAM: &str = "kubernix_results";

pub fn jobs_subject(system: &System) -> String {
    format!("kubernix.jobs.{system}")
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
    /// Whose build this is.
    ///
    /// Travels with the job because the worker needs it to ask for pre-signed
    /// URLs: the frontend grants keys under this tenant and refuses the rest.
    pub tenant: TenantId,
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
    },
}

#[derive(Clone)]
pub struct JobQueue {
    client: async_nats::Client,
    jetstream: jetstream::Context,
    /// How long to wait for a worker to report an outcome.
    pub result_timeout: Duration,
}

impl JobQueue {
    /// The underlying NATS client, for services that share the connection.
    pub fn client(&self) -> async_nats::Client {
        self.client.clone()
    }

    pub async fn connect(url: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!(%url, "connecting to NATS");
        let client = async_nats::connect(url).await?;
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
            .await?;

        jetstream
            .get_or_create_stream(jetstream::stream::Config {
                name: RESULTS_STREAM.to_string(),
                subjects: vec!["kubernix.results.>".to_string()],
                max_age: Duration::from_secs(24 * 3600),
                ..Default::default()
            })
            .await?;

        Ok(Self {
            client,
            jetstream,
            result_timeout: Duration::from_secs(3600),
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
    ) -> Result<jetstream::consumer::Consumer<pull::Config>, Box<dyn std::error::Error + Send + Sync>>
    {
        let stream = self.jetstream.get_stream(RESULTS_STREAM).await?;
        let consumer = stream
            .create_consumer(pull::Config {
                // Ephemeral: this consumer exists for one build.
                filter_subject: results_subject(job_id),
                ..Default::default()
            })
            .await?;
        Ok(consumer)
    }

    pub async fn submit(
        &self,
        job: &BuildJob,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut message = capnp::message::Builder::new_default();
        {
            let mut req = message.init_root::<kubernix_capnp::build_request::Builder>();
            req.set_job_id(job.job_id.to_string().as_str());
            req.set_derivation_path(job.derivation_path.as_str());
            req.set_system(job.system.as_str());
            req.set_drv(&job.drv);
            req.set_tenant(job.tenant.as_str());

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
        capnp::serialize::write_message(&mut payload, &message)?;

        let subject = jobs_subject(&job.system);
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
            .await?
            .await?;
        Ok(())
    }

    /// Await the terminal outcome for a job.
    pub async fn await_outcome(
        &self,
        consumer: jetstream::consumer::Consumer<pull::Config>,
    ) -> Result<JobOutcome, Box<dyn std::error::Error + Send + Sync>> {
        let mut messages = consumer.messages().await?;

        let message = tokio::time::timeout(self.result_timeout, messages.next())
            .await
            .map_err(|_| {
                format!(
                    "timed out after {:?} waiting for a worker",
                    self.result_timeout
                )
            })?
            .ok_or("result stream ended before an outcome arrived")??;

        let outcome = decode_outcome(&message.payload)?;
        message.ack().await?;
        Ok(outcome)
    }
}

pub fn decode_outcome(
    payload: &[u8],
) -> Result<JobOutcome, Box<dyn std::error::Error + Send + Sync>> {
    let mut cursor = payload;
    let reader = capnp::serialize::read_message(&mut cursor, capnp::message::ReaderOptions::new())?;
    let result = reader.get_root::<kubernix_capnp::job_result::Reader>()?;

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
            Ok(JobOutcome::Failed { message, log_key })
        }
    }
}
