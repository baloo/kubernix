use std::{convert::Infallible, sync::Arc};

use axum::{
    Router,
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    response::sse::{Event, Sse},
    routing::{get, post},
};
use futures_util::stream::Stream;
use tokio_stream::StreamExt;
use uuid::Uuid;

use crate::kubernix_capnp;

pub(crate) struct AppState {
    pub(crate) nats_client: async_nats::Client,
    pub(crate) jetstream: async_nats::jetstream::Context,
    pub(crate) db_pool: sqlx::PgPool,
    pub(crate) s3_client: aws_sdk_s3::Client,
    pub(crate) s3_bucket: String,
}

pub(crate) type SharedState = Arc<AppState>;

pub fn router(state: SharedState) -> Router<()> {
    Router::new()
        // Health check endpoint
        .route("/health", get(health_check))
        // API endpoints
        .route("/api/v1/build", post(submit_build))
        .route("/api/v1/build/{job_id}", get(get_build_status))
        .route("/api/v1/build/{job_id}/logs", get(stream_build_logs))
        .route("/api/v1/inputs/{*key}", post(upload_inputs))
        .with_state(state)
}

async fn health_check(State(_state): State<SharedState>) -> &'static str {
    "OK"
}

// Placeholder for submitting a build command
async fn submit_build(
    State(state): State<SharedState>,
    body: Bytes,
) -> Result<Bytes, (StatusCode, String)> {
    let mut reader = body.as_ref();
    let message_reader =
        capnp::serialize::read_message(&mut reader, capnp::message::ReaderOptions::new())
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid capnp: {}", e)))?;

    let req = message_reader
        .get_root::<kubernix_capnp::build_request::Reader>()
        .map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                format!("Invalid capnp root: {}", e),
            )
        })?;

    let derivation_path = req
        .get_derivation_path()
        .unwrap_or(capnp::text::Reader(b""))
        .to_string()
        .unwrap_or_default();
    let system = req
        .get_system()
        .unwrap_or(capnp::text::Reader(b""))
        .to_string()
        .unwrap_or_default();

    tracing::info!("Received build request for {}", derivation_path);

    let job_id = Uuid::new_v4();

    let mut message = capnp::message::Builder::new_default();
    {
        let mut req_builder = message.init_root::<kubernix_capnp::build_request::Builder>();
        req_builder.set_job_id(&job_id.to_string());
        req_builder.set_derivation_path(&derivation_path);
        req_builder.set_system(&system);
    }

    let mut out_req = Vec::new();
    capnp::serialize::write_message(&mut out_req, &message).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Serialization error: {}", e),
        )
    })?;

    // 1. Publish to NATS JetStream job queue.
    let subject = format!("kubernix.jobs.{}", system);

    state
        .jetstream
        .publish(subject, out_req.into())
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("NATS publish error: {}", e),
            )
        })?;

    // 2. Save job state to database.
    // For now we assume a `jobs` table exists.
    sqlx::query("INSERT INTO jobs (id, derivation_path, system, status) VALUES ($1, $2, $3, $4)")
        .bind(job_id)
        .bind(&derivation_path)
        .bind(&system)
        .bind("pending")
        .execute(&state.db_pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
        })?;

    tracing::info!("Job {} submitted successfully", job_id);

    let mut message = capnp::message::Builder::new_default();
    let mut resp = message.init_root::<kubernix_capnp::build_response::Builder>();
    resp.set_job_id(&job_id.to_string());
    resp.set_status(kubernix_capnp::JobStatus::Pending);

    let mut out = Vec::new();
    capnp::serialize::write_message(&mut out, &message).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Serialization error: {}", e),
        )
    })?;

    Ok(out.into())
}

// Placeholder for getting build status
async fn get_build_status(
    State(state): State<SharedState>,
    Path(job_id): Path<Uuid>,
) -> Result<Bytes, (StatusCode, String)> {
    let record = sqlx::query("SELECT status, outputs FROM jobs WHERE id = $1")
        .bind(job_id)
        .fetch_optional(&state.db_pool)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
        })?;

    use sqlx::Row;
    match record {
        Some(r) => {
            let status_str: String = r
                .try_get("status")
                .unwrap_or_else(|_| "pending".to_string());
            let outputs: Vec<String> = r.try_get("outputs").unwrap_or_default();

            let status = match status_str.as_str() {
                "running" => kubernix_capnp::JobStatus::Running,
                "completed" => kubernix_capnp::JobStatus::Completed,
                "failed" => kubernix_capnp::JobStatus::Failed,
                _ => kubernix_capnp::JobStatus::Pending,
            };

            let mut message = capnp::message::Builder::new_default();
            let mut resp = message.init_root::<kubernix_capnp::job_result::Builder>();
            resp.set_job_id(&job_id.to_string());
            resp.set_status(status);

            let mut outputs_builder = resp.reborrow().init_output_paths(outputs.len() as u32);
            for (i, output) in outputs.iter().enumerate() {
                outputs_builder.set(i as u32, output);
            }

            let mut out = Vec::new();
            capnp::serialize::write_message(&mut out, &message).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Serialization error: {}", e),
                )
            })?;

            Ok(out.into())
        }
        None => Err((StatusCode::NOT_FOUND, "Job not found".to_string())),
    }
}

// Stream build logs
async fn stream_build_logs(
    State(state): State<SharedState>,
    Path(job_id): Path<Uuid>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, (StatusCode, String)> {
    tracing::info!("Client requested logs for job {}", job_id);

    let subject = format!("kubernix.logs.{}", job_id);
    let subscriber = state.nats_client.subscribe(subject).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to subscribe to logs: {}", e),
        )
    })?;

    // Create a stream that maps NATS messages to SSE events
    let stream = subscriber.map(|msg| {
        let text = String::from_utf8_lossy(&msg.payload).to_string();
        Ok(Event::default().data(text))
    });

    Ok(Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::new()))
}

// Upload local inputs to S3 cache
async fn upload_inputs(
    State(state): State<SharedState>,
    Path(key): Path<String>,
    body: Bytes,
) -> Result<&'static str, (StatusCode, String)> {
    tracing::info!("Receiving upload for key: {}", key);

    state
        .s3_client
        .put_object()
        .bucket(&state.s3_bucket)
        .key(&key)
        .body(body.into())
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Failed to upload to S3: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("S3 upload error: {}", e),
            )
        })?;

    // Record upload in the database
    sqlx::query("INSERT INTO cache_objects (key) VALUES ($1) ON CONFLICT DO NOTHING")
        .bind(&key)
        .execute(&state.db_pool)
        .await
        .map_err(|e| {
            tracing::error!("Failed to record S3 upload in db: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
        })?;

    tracing::info!("Successfully uploaded {} to S3", key);

    Ok("Inputs uploaded")
}
