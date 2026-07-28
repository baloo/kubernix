pub mod kubernix_capnp {
    include!(concat!(env!("OUT_DIR"), "/kubernix_capnp.rs"));
}

use async_nats::jetstream::{self, consumer::PullConsumer};
use futures_util::stream::StreamExt;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("{}=debug", env!("CARGO_CRATE_NAME")).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting Kubernix Job Runner...");

    let nats_url =
        std::env::var("NATS_URL").unwrap_or_else(|_| "nats://localhost:4222".to_string());
    let system = std::env::var("NIX_SYSTEM").unwrap_or_else(|_| "x86_64-linux".to_string());

    tracing::info!("Connecting to NATS at {} for system {}", nats_url, system);
    let nats_client = async_nats::connect(&nats_url).await?;
    let jetstream = jetstream::new(nats_client.clone());

    let subject = format!("kubernix.jobs.{}", system);
    let stream_name = "kubernix_jobs";

    let consumer_name = format!("worker-{}", uuid::Uuid::new_v4());

    let stream = jetstream.get_stream(stream_name).await?;

    let consumer: PullConsumer = stream
        .create_consumer(jetstream::consumer::pull::Config {
            durable_name: None,
            name: Some(consumer_name.clone()),
            filter_subject: subject.clone(),
            ..Default::default()
        })
        .await?;

    tracing::info!(
        "Worker {} ready, listening on subject {}",
        consumer_name,
        subject
    );

    let mut messages = consumer.messages().await?;

    while let Some(msg_result) = messages.next().await {
        let msg = match msg_result {
            Ok(m) => m,
            Err(e) => {
                tracing::error!("Error pulling message: {}", e);
                continue;
            }
        };

        if let Err(e) = process_job(&msg, &nats_client).await {
            tracing::error!("Failed to process job: {}", e);
            // Optionally publish a failed result to the results queue
        }

        let _ = msg.ack().await;
    }

    Ok(())
}

async fn process_job(
    msg: &async_nats::jetstream::Message,
    nats_client: &async_nats::Client,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut reader = msg.payload.as_ref();
    let message_reader =
        capnp::serialize::read_message(&mut reader, capnp::message::ReaderOptions::new())?;
    let req = message_reader.get_root::<kubernix_capnp::build_request::Reader>()?;

    let job_id = req.get_job_id()?.to_string()?;
    let derivation_path = req.get_derivation_path()?.to_string()?;
    tracing::info!("Received job {} to evaluate: {}", job_id, derivation_path);

    // In a real implementation:
    // 1. Fetch required_inputs from S3 cache
    // 2. Realize/Build the derivation (e.g. using `lix build ...`)
    // 3. Stream logs to `kubernix.logs.<job_id>`
    // 4. Upload outputs to S3 cache
    // 5. Send result to `kubernix_results` stream

    tracing::info!("Simulating build execution for {}", derivation_path);

    // As a proof-of-concept, we'll just shell out to `lix build` and capture output.
    // If the derivation requires paths not in the local store, this will fail unless we implemented step 1.
    let mut child = Command::new("lix")
        .arg("build")
        .arg(&derivation_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let mut stdout = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut stderr = BufReader::new(child.stderr.take().unwrap()).lines();

    loop {
        tokio::select! {
            line = stdout.next_line() => {
                match line {
                    Ok(Some(l)) => tracing::info!("Lix out: {}", l),
                    Ok(None) => break,
                    Err(e) => {
                        tracing::error!("Error reading stdout: {}", e);
                        break;
                    }
                }
            }
            line = stderr.next_line() => {
                match line {
                    Ok(Some(l)) => tracing::info!("Lix err: {}", l),
                    Ok(None) => break,
                    Err(e) => {
                        tracing::error!("Error reading stderr: {}", e);
                        break;
                    }
                }
            }
        }
    }

    let status = child.wait().await?;
    tracing::info!("Job {} completed with status: {}", job_id, status);

    let job_status = if status.success() {
        kubernix_capnp::JobStatus::Completed
    } else {
        kubernix_capnp::JobStatus::Failed
    };

    let mut message = capnp::message::Builder::new_default();
    let mut res_builder = message.init_root::<kubernix_capnp::job_result::Builder>();
    res_builder.set_job_id(&job_id);
    res_builder.set_status(job_status);

    let mut out_res = Vec::new();
    capnp::serialize::write_message(&mut out_res, &message)?;

    let jetstream = async_nats::jetstream::new(nats_client.clone());
    jetstream
        .publish("kubernix_results", out_res.into())
        .await?;

    Ok(())
}
