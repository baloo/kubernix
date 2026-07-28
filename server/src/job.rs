use tokio_stream::StreamExt;
use uuid::Uuid;

use crate::kubernix_capnp;

// Background task to listen to results queue and update the DB
pub async fn process_job_results(jetstream: async_nats::jetstream::Context, db_pool: sqlx::PgPool) {
    tracing::info!("Starting background task to process job results");

    let stream = match jetstream
        .get_or_create_stream(async_nats::jetstream::stream::Config {
            name: "kubernix_results".to_string(),
            subjects: vec!["kubernix_results.>".to_string()],
            ..Default::default()
        })
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to get or create results stream: {}", e);
            return;
        }
    };

    let consumer = match stream
        .get_or_create_consumer(
            "http-server-results-consumer",
            async_nats::jetstream::consumer::pull::Config {
                durable_name: Some("http-server-results-consumer".to_string()),
                ..Default::default()
            },
        )
        .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Failed to create results consumer: {}", e);
            return;
        }
    };

    let mut messages = match consumer.messages().await {
        Ok(m) => m,
        Err(e) => {
            tracing::error!("Failed to get messages stream from consumer: {}", e);
            return;
        }
    };

    while let Some(msg_result) = messages.next().await {
        let msg = match msg_result {
            Ok(m) => m,
            Err(e) => {
                tracing::error!("Error receiving message from results stream: {}", e);
                continue;
            }
        };

        // We assume the payload contains capnp with job_id, status, and output_paths
        let parse_result = {
            let mut reader = msg.payload.as_ref();
            match capnp::serialize::read_message(&mut reader, capnp::message::ReaderOptions::new())
            {
                Ok(message_reader) => {
                    match message_reader.get_root::<kubernix_capnp::job_result::Reader>() {
                        Ok(result) => {
                            let job_id_str = result
                                .get_job_id()
                                .unwrap_or(capnp::text::Reader(b""))
                                .to_string()
                                .unwrap_or_default();

                            let status_str = match result.get_status() {
                                Ok(kubernix_capnp::JobStatus::Running) => "running",
                                Ok(kubernix_capnp::JobStatus::Completed) => "completed",
                                Ok(kubernix_capnp::JobStatus::Failed) => "failed",
                                Ok(kubernix_capnp::JobStatus::Pending) => "pending",
                                Err(_) => "pending",
                            };

                            let mut output_paths = Vec::new();
                            if let Ok(paths) = result.get_output_paths() {
                                for path in paths.iter() {
                                    if let Ok(p) = path {
                                        if let Ok(p_str) = p.to_string() {
                                            output_paths.push(p_str);
                                        }
                                    }
                                }
                            }

                            Ok((job_id_str, status_str, output_paths))
                        }
                        Err(e) => Err(format!("Failed to parse capnp root: {}", e)),
                    }
                }
                Err(e) => Err(format!("Failed to parse message: {}", e)),
            }
        };

        match parse_result {
            Ok((job_id_str, status_str, output_paths)) => {
                let job_id = match Uuid::parse_str(&job_id_str) {
                    Ok(id) => id,
                    Err(e) => {
                        tracing::error!("Invalid job_id uuid {}: {}", job_id_str, e);
                        let _ = msg.ack().await;
                        continue;
                    }
                };

                let db_result =
                    sqlx::query("UPDATE jobs SET status = $1, outputs = $2 WHERE id = $3")
                        .bind(status_str)
                        .bind(&output_paths)
                        .bind(job_id)
                        .execute(&db_pool)
                        .await;

                match db_result {
                    Ok(_) => {
                        tracing::info!("Updated job {} status to {}", job_id, status_str);
                        let _ = msg.ack().await; // Acknowledge on success
                    }
                    Err(e) => {
                        tracing::error!("Failed to update database for job {}: {}", job_id, e);
                        // We do not ack so it will be redelivered
                    }
                }
            }
            Err(e) => {
                tracing::error!("{}", e);
                // Ack unparseable messages so they don't get stuck forever
                let _ = msg.ack().await;
            }
        }
    }
}
