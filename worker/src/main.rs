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

mod upload;

/// Request/reply subject for pre-signed upload URLs. The frontend holds the S3
/// credentials; this worker never does.
pub const UPLOADS_SUBJECT: &str = "kubernix.uploads";

use async_nats::jetstream::{self, consumer::PullConsumer};
use futures_util::stream::StreamExt;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

struct Job {
    job_id: String,
    derivation_path: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    tracing::info!(%nats_url, %system, "starting worker");
    let client = async_nats::connect(&nats_url).await?;
    let jetstream = jetstream::new(client.clone());

    let subject = format!("kubernix.jobs.{system}");

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
            filter_subject: subject.clone(),
            // One at a time: a build holds its message un-acked while it runs.
            max_ack_pending: 1,
            ack_wait: std::time::Duration::from_secs(3600),
            ..Default::default()
        })
        .await?;

    let http = reqwest::Client::new();

    tracing::info!(%subject, "waiting for jobs");
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
                let _ = message.ack().await;
                continue;
            }
        };

        tracing::info!(job_id = %job.job_id, drv = %job.derivation_path, "building");
        let (mut outcome, log) = run_build(&client, &job, &builder).await;

        // Artifacts first, then the result: publishing a success whose outputs
        // are not yet fetchable would be worse than reporting the upload failure.
        let (artifacts, log_key) =
            match upload_artifacts(&client, &http, &job, &outcome, log, &builder).await {
                Ok(uploaded) => uploaded,
                Err(e) => {
                    tracing::error!(job_id = %job.job_id, error = %e, "artifact upload failed");
                    outcome = Outcome::Failed(format!("uploading artifacts: {e}"));
                    (Vec::new(), String::new())
                }
            };

        if let Err(e) = publish_result(&jetstream, &job, &outcome, &artifacts, &log_key).await {
            tracing::error!(error = %e, "failed to publish result");
            // Not acked: let it be redelivered rather than lose the job.
            continue;
        }

        let _ = message.ack().await;
    }

    Ok(())
}

fn decode_job(payload: &[u8]) -> Result<Job, Box<dyn std::error::Error>> {
    let mut cursor = payload;
    let reader =
        capnp::serialize::read_message(&mut cursor, capnp::message::ReaderOptions::new())?;
    let request = reader.get_root::<kubernix_capnp::build_request::Reader>()?;
    Ok(Job {
        job_id: request.get_job_id()?.to_string()?,
        derivation_path: request.get_derivation_path()?.to_string()?,
    })
}

enum Outcome {
    Completed(Vec<String>),
    Failed(String),
}

/// Upload the job's artifacts and return what the frontend needs to serve them.
///
/// The log is treated as an output and uploaded whether or not the build
/// succeeded — a failed build's log is the most useful thing it produced.
///
/// Called *before* the result is published, so a completed result always implies
/// fetchable artifacts. An upload failure is therefore a build failure.
async fn upload_artifacts(
    client: &async_nats::Client,
    http: &reqwest::Client,
    job: &Job,
    outcome: &Outcome,
    log: Vec<u8>,
    nix_store: &str,
) -> Result<(Vec<upload::OutputArtifact>, String), Box<dyn std::error::Error>> {
    let outputs: Vec<String> = match outcome {
        Outcome::Completed(paths) => paths.clone(),
        Outcome::Failed(_) => Vec::new(),
    };

    let log_key = upload::log_key(&job.derivation_path)
        .ok_or_else(|| format!("cannot derive log key from {}", job.derivation_path))?;

    // One round trip for every key this job needs.
    let mut keys = vec![log_key.clone()];
    for path in &outputs {
        keys.push(
            upload::nar_key(path).ok_or_else(|| format!("cannot derive nar key from {path}"))?,
        );
    }

    let urls = upload::request_upload_urls(client, &job.job_id, &keys).await?;

    upload::upload_log(http, &urls[0], &log_key, log).await?;

    let mut artifacts = Vec::new();
    for (i, path) in outputs.iter().enumerate() {
        let key = keys[i + 1].clone();
        tracing::info!(job_id = %job.job_id, %path, %key, "uploading output");
        artifacts.push(upload::upload_output(http, &urls[i + 1], key, path, nix_store).await?);
    }

    Ok((artifacts, log_key))
}

/// Realise the derivation, publishing each output line to the job's log subject
/// as it arrives, and returning the accumulated log for archival.
async fn run_build(
    client: &async_nats::Client,
    job: &Job,
    builder: &str,
) -> (Outcome, Vec<u8>) {
    let log_subject = format!("kubernix.logs.{}", job.job_id);

    let mut child = match Command::new(builder)
        .arg("--realise")
        .arg(&job.derivation_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            let message = format!("failed to spawn {builder}: {e}");
            let _ = client.publish(log_subject, message.clone().into()).await;
            return (Outcome::Failed(message.clone()), message.into_bytes());
        }
    };

    // stdout carries the realised output paths; stderr carries the build log.
    let mut stdout = BufReader::new(child.stdout.take().expect("piped")).lines();
    let mut stderr = BufReader::new(child.stderr.take().expect("piped")).lines();

    let mut outputs = Vec::new();
    let mut tail = Vec::new();
    // The full log, kept for archival to the object store.
    let mut archive: Vec<u8> = Vec::new();

    loop {
        tokio::select! {
            line = stdout.next_line() => match line {
                Ok(Some(line)) => outputs.push(line),
                Ok(None) => {}
                Err(e) => tracing::warn!(error = %e, "stdout read error"),
            },
            line = stderr.next_line() => match line {
                Ok(Some(line)) => {
                    let _ = client.publish(log_subject.clone(), line.clone().into()).await;
                    archive.extend_from_slice(line.as_bytes());
                    archive.push(b'\n');
                    // Kept for the failure message; the client already saw it live.
                    if tail.len() == 20 { tail.remove(0); }
                    tail.push(line);
                }
                Ok(None) => {}
                Err(e) => tracing::warn!(error = %e, "stderr read error"),
            },
            status = child.wait() => {
                let _ = client.flush().await;
                let outcome = match status {
                    Ok(status) if status.success() => Outcome::Completed(outputs),
                    Ok(status) => Outcome::Failed(format!(
                        "{builder} exited with {status}\n{}", tail.join("\n")
                    )),
                    Err(e) => Outcome::Failed(format!("waiting on {builder}: {e}")),
                };
                return (outcome, archive);
            }
        }
    }
}

async fn publish_result(
    jetstream: &jetstream::Context,
    job: &Job,
    outcome: &Outcome,
    artifacts: &[upload::OutputArtifact],
    log_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut message = capnp::message::Builder::new_default();
    {
        let mut result = message.init_root::<kubernix_capnp::job_result::Builder>();
        result.set_job_id(job.job_id.as_str());
        result.set_log_key(log_key);

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
            out.set_deriver(artifact.deriver.as_str());
            let mut refs = out.reborrow().init_references(artifact.references.len() as u32);
            for (j, reference) in artifact.references.iter().enumerate() {
                refs.set(j as u32, reference.as_str());
            }
        }
    }

    let mut payload = Vec::new();
    capnp::serialize::write_message(&mut payload, &message)?;

    jetstream
        .publish(format!("kubernix.results.{}", job.job_id), payload.into())
        .await?
        .await?;
    Ok(())
}
