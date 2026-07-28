use std::sync::Arc;
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

pub mod kubernix_capnp {
    include!(concat!(env!("OUT_DIR"), "/kubernix_capnp.rs"));
}

mod api;
mod job;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("{}=debug", env!("CARGO_CRATE_NAME")).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting Kubernix HTTP Server...");

    // Connect to NATS
    let nats_url =
        std::env::var("NATS_URL").unwrap_or_else(|_| "nats://localhost:4222".to_string());
    tracing::info!("Connecting to NATS at {}", nats_url);
    let nats_client = async_nats::connect(&nats_url).await?;
    let jetstream = async_nats::jetstream::new(nats_client.clone());

    // Connect to Database
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/kubernix".to_string());
    tracing::info!("Connecting to PostgreSQL at {}", db_url);
    let db_pool = sqlx::PgPool::connect(&db_url).await?;

    // Connect to S3
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let s3_client = aws_sdk_s3::Client::new(&config);
    let s3_bucket = std::env::var("S3_BUCKET").unwrap_or_else(|_| "kubernix-cache".to_string());

    // Create AppState
    let state = Arc::new(api::AppState {
        nats_client: nats_client.clone(),
        jetstream: jetstream.clone(),
        db_pool: db_pool.clone(),
        s3_client,
        s3_bucket,
    });

    // Spawn background task to process job results
    tokio::spawn(job::process_job_results(jetstream, db_pool));

    // Define the application router
    let app = api::router(state);

    let addr = TcpListener::bind("0.0.0.0:3001").await?;
    tracing::info!("Server listening on {}", addr.local_addr()?);

    axum::serve(addr, app).await?;

    Ok(())
}
