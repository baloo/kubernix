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
mod upload;

/// Request/reply subject for pre-signed upload URLs. The frontend holds the S3
/// credentials; this worker never does.
pub const UPLOADS_SUBJECT: &str = "kubernix.uploads";

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
}

/// The output paths a derivation declares.
///
/// Taken from the derivation rather than from a builder's stdout: with
/// `nix-store --serve` stdout carries the protocol, and the derivation is the
/// authoritative statement of where its outputs go regardless.
fn declared_outputs(job: &Job, store_dir: &str) -> eyre::Result<Vec<StorePath>> {
    let drv = derivation::parse(&job.drv, store_dir).wrap_err("parsing the derivation")?;
    Ok(drv.outputs.into_iter().map(|o| o.path).collect())
}

struct InputRef {
    store_path: StorePath,
    key: ObjectKey,
    /// Needed to wrap the NAR into an importable export stream; a bare NAR
    /// carries neither.
    references: Vec<StorePath>,
    deriver: StorePath,
}

/// Fetch and import every input the frontend staged for this job.
///
/// Done before the build: the whole point is that a worker on another machine
/// has the closure it needs without ever holding S3 credentials.
async fn fetch_inputs(
    client: &async_nats::Client,
    http: &reqwest::Client,
    job: &Job,
    nix_store: &str,
    store_uri: Option<&str>,
    store_dir: &str,
) -> eyre::Result<()> {
    if job.inputs.is_empty() {
        return Ok(());
    }

    let keys: Vec<ObjectKey> = job.inputs.iter().map(|i| i.key.clone()).collect();
    let urls = upload::request_download_urls(client, &job.job_id, &job.token, &keys)
        .await
        .wrap_err("requesting download urls")?;

    for (input, url) in job.inputs.iter().zip(urls) {
        tracing::info!(job_id = %job.job_id, path = %input.store_path, "importing input");
        upload::fetch_input(
            http,
            &url,
            &input.store_path,
            &input.references,
            &input.deriver,
            nix_store,
            store_uri,
            store_dir,
        )
        .await
        .wrap_err_with(|| format!("importing {}", input.store_path))?;
    }

    tracing::info!(job_id = %job.job_id, count = job.inputs.len(), "inputs imported");
    Ok(())
}

#[tokio::main]
async fn main() -> color_eyre::eyre::Result<()> {
    color_eyre::install()?;
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

        tracing::info!(job_id = %job.job_id, drv = %job.derivation_path, inputs = job.inputs.len(), "building");

        if let Err(report) = fetch_inputs(
            &client,
            &http,
            &job,
            &builder,
            store_uri.as_deref(),
            &store_dir,
        )
        .await
        {
            tracing::error!(job_id = %job.job_id, error = ?report, "could not fetch inputs");
            let outcome = Outcome::Failed(infra_failure_message(&job.job_id, "fetching inputs failed"));
            let _ = publish_result(&jetstream, &job, &outcome, &[], &ObjectKey::default()).await;
            let _ = message.ack().await;
            continue;
        }

        // Where the outputs will land, read from the derivation itself.
        let outputs = match declared_outputs(&job, &store_dir) {
            Ok(outputs) => outputs,
            Err(report) => {
                tracing::error!(job_id = %job.job_id, error = ?report, "undecodable derivation");
                let outcome =
                    Outcome::Failed(infra_failure_message(&job.job_id, "reading the derivation failed"));
                let _ =
                    publish_result(&jetstream, &job, &outcome, &[], &ObjectKey::default()).await;
                let _ = message.ack().await;
                continue;
            }
        };

        let (mut outcome, log) = run_build(
            &client,
            &job,
            outputs,
            &builder,
            store_uri.as_deref(),
            &store_dir,
        )
        .await;

        // Artifacts first, then the result: publishing a success whose outputs
        // are not yet fetchable would be worse than reporting the upload failure.
        let (artifacts, log_key) = match upload_artifacts(
            &client,
            &http,
            &job,
            &outcome,
            log,
            &builder,
            &nix_cli,
            store_uri.as_deref(),
            &store_dir,
        )
        .await
        {
            Ok(uploaded) => uploaded,
            Err(report) => {
                tracing::error!(job_id = %job.job_id, error = ?report, "artifact upload failed");
                outcome = Outcome::Failed(infra_failure_message(&job.job_id, "uploading artifacts failed"));
                (Vec::new(), ObjectKey::default())
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
    let tenant =
        TenantId::from_wire(tenant).ok_or_eyre("build request carries no tenant")?;

    Ok(Job {
        job_id: request.get_job_id()?.to_string()?,
        derivation_path: StorePath::new(request.get_derivation_path()?.to_string()?),
        tenant,
        inputs,
        drv: request.get_drv()?.to_vec(),
        token: CapabilityToken::new(request.get_token()?.to_vec()),
    })
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
    nix_cli: &str,
    store_uri: Option<&str>,
    store_dir: &str,
) -> eyre::Result<(Vec<upload::OutputArtifact>, ObjectKey)> {
    let outputs: Vec<StorePath> = match outcome {
        Outcome::Completed(paths) => paths.clone(),
        Outcome::Failed(_) => Vec::new(),
    };

    let log_key = upload::log_key(&job.tenant, &job.derivation_path)
        .ok_or_eyre("cannot derive a log key")
        .wrap_err_with(|| job.derivation_path.to_string())?;

    // One round trip for every key this job needs.
    let mut keys = vec![log_key.clone()];
    for path in &outputs {
        keys.push(
            upload::nar_key(&job.tenant, path)
                .ok_or_eyre("cannot derive a nar key")
                .wrap_err_with(|| path.to_string())?,
        );
    }

    let urls = upload::request_upload_urls(client, &job.job_id, &job.token, &keys)
        .await
        .wrap_err("requesting upload urls")?;

    // An empty log is possible — a build that printed nothing — and some S3
    // implementations reject a zero-length PUT outright. Losing the whole job
    // over an empty log would be absurd, so skip the upload and report no key.
    let log_key = if log.is_empty() {
        tracing::debug!(job_id = %job.job_id, "build produced no log; not uploading one");
        ObjectKey::default()
    } else {
        upload::upload_log(http, &urls[0], &log_key, log)
            .await
            .wrap_err("uploading the build log")?;
        log_key
    };

    let mut artifacts = Vec::new();
    for (i, path) in outputs.iter().enumerate() {
        let key = keys[i + 1].clone();
        tracing::info!(job_id = %job.job_id, %path, %key, "uploading output");
        artifacts.push(
            upload::upload_output(
                http,
                &urls[i + 1],
                key,
                path,
                nix_store,
                nix_cli,
                store_uri,
                store_dir,
            )
            .await
            .wrap_err_with(|| format!("uploading {path}"))?,
        );
    }

    Ok((artifacts, log_key))
}

/// Build the job's derivation and stream its log.
///
/// Goes through `nix-store --serve` rather than writing a `.drv` and calling
/// `nix-store --realise`. The derivation we receive is *resolved*, and Nix
/// computes an input-addressed output path from the derivation itself, so a
/// reconstructed `.drv` disagrees with the outputs recorded inside it — see
/// `serve.rs`. Passing the derivation by value sidesteps that entirely.
async fn run_build(
    client: &async_nats::Client,
    job: &Job,
    outputs: Vec<StorePath>,
    builder: &str,
    store_uri: Option<&str>,
    store_dir: &str,
) -> (Outcome, Vec<u8>) {
    let log_subject = format!("kubernix.logs.{}", job.job_id);

    let mut conn = match serve::ServeConnection::open(builder, store_uri).await {
        Ok(conn) => conn,
        Err(e) => {
            tracing::error!(job_id = %job.job_id, %builder, error = ?e, "could not start the builder");
            let message = infra_failure_message(&job.job_id, "starting the builder failed");
            let _ = client.publish(log_subject, message.clone().into()).await;
            return (Outcome::Failed(message.clone()), message.into_bytes());
        }
    };

    // The log has to be drained *while* the build runs: it is a pipe, and a full
    // one would block the builder rather than merely delaying the output.
    let stderr = conn.stderr.take();
    let pump = tokio::spawn(pump_log(client.clone(), log_subject.clone(), stderr));

    let result = conn
        .build_derivation(&job.derivation_path.to_full(store_dir), &job.drv)
        .await;

    // Closing drops stdin, which is what tells `nix-store --serve` to exit, which
    // in turn ends the log stream. Done before awaiting the pump for that reason.
    if let Err(e) = conn.close().await {
        tracing::warn!(error = %e, "serve connection did not close cleanly");
    }
    let (archive, tail) = pump.await.unwrap_or_default();
    let _ = client.flush().await;

    let outcome = match result {
        Ok(outcome) if outcome.succeeded() => Outcome::Completed(outputs),
        Ok(outcome) => {
            // The client already saw the log live; the tail is what makes the
            // failure message useful on its own.
            let mut message = outcome.describe();
            if !tail.is_empty() {
                message.push('\n');
                message.push_str(&tail.join("\n"));
            }
            Outcome::Failed(message)
        }
        Err(e) => {
            tracing::error!(
                job_id = %job.job_id, drv = %job.derivation_path, error = ?e,
                "builder invocation failed"
            );
            Outcome::Failed(infra_failure_message(&job.job_id, "running the builder failed"))
        }
    };

    (outcome, archive)
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

async fn publish_result(
    jetstream: &jetstream::Context,
    job: &Job,
    outcome: &Outcome,
    artifacts: &[upload::OutputArtifact],
    log_key: &ObjectKey,
) -> eyre::Result<()> {
    let mut message = capnp::message::Builder::new_default();
    {
        let mut result = message.init_root::<kubernix_capnp::job_result::Builder>();
        result.set_job_id(job.job_id.as_str());
        result.set_log_key(log_key.as_str());

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
            let mut refs = out
                .reborrow()
                .init_references(artifact.references.len() as u32);
            for (j, reference) in artifact.references.iter().enumerate() {
                refs.set(j as u32, reference.as_str());
            }
        }
    }

    let mut payload = Vec::new();
    capnp::serialize::write_message(&mut payload, &message).wrap_err("encoding the job result")?;

    jetstream
        .publish(format!("kubernix.results.{}", job.job_id), payload.into())
        .await
        .wrap_err_with(|| format!("publishing the result for job {}", job.job_id))?
        .await
        .wrap_err_with(|| format!("awaiting the publish ack for job {}", job.job_id))?;
    Ok(())
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
        let message = infra_failure_message("11111111-2222-3333-4444-555555555555", "uploading artifacts failed");

        assert!(message.contains("11111111-2222-3333-4444-555555555555"));
        assert!(message.contains("uploading artifacts failed"));
        assert!(!message.contains(leaked));
    }
}
