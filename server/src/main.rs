//! Kubernix binary cache.
//!
//! Serves the substituter side — narinfo, NARs and build logs — under a tenant
//! path prefix. The build side is `kubernix-sshd`; this process only reads.
//!
//! Point a client at one tenant's prefix:
//!
//! ```text
//! nix build --substituters https://cache.example/<tenant> \
//!           --trusted-public-keys "$(curl -s https://cache.example/<tenant>/public-key)"
//! ```
//!
//! Environment:
//!   `KUBERNIX_HTTP_LISTEN`  bind address (default `0.0.0.0:3000`)
//!   `DATABASE_URL`          PostgreSQL; without it there is nothing to serve
//!   `KUBERNIX_STORE_DIR`    store dir advertised in `nix-cache-info`
//!   `KUBERNIX_CACHE_PRIORITY` cache priority (default 50, after cache.nixos.org)
//!   `S3_BUCKET`, `AWS_*`    object store holding the NARs and logs

use std::sync::Arc;

use kubernix_server::http::{self, HttpState};
use kubernix_server::postgres_store::PostgresStore;
use kubernix_server::store::{MemoryStore, Store};
use kubernix_server::uploads::UploadSigner;
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "kubernix_server=debug,kubernix_cache=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // A cache with no database has nothing to serve: every path it could offer
    // is a row. Starting anyway would answer 404 to everything, which looks like
    // a cache miss rather than a misconfiguration — so say so loudly instead.
    let store: Arc<dyn Store> = match std::env::var("DATABASE_URL") {
        Ok(url) => PostgresStore::connect(&url).await?,
        Err(_) => {
            tracing::warn!(
                "DATABASE_URL unset - serving from an empty in-memory store, \
                 which will answer 404 to everything"
            );
            MemoryStore::new()
        }
    };

    // Without object-store credentials the narinfo route still works, but the
    // NAR and log routes cannot: those bytes were uploaded directly by workers
    // and never passed through here.
    let uploader = match UploadSigner::from_env().await {
        Ok(signer) => Some(Arc::new(signer)),
        Err(e) => {
            tracing::error!(error = %e, "no S3 configuration; NARs and logs cannot be served");
            None
        }
    };

    let state = HttpState {
        store,
        uploader,
        store_dir: std::env::var("KUBERNIX_STORE_DIR").unwrap_or_else(|_| "/nix/store".to_string()),
        priority: std::env::var("KUBERNIX_CACHE_PRIORITY")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(50),
    };

    let listen =
        std::env::var("KUBERNIX_HTTP_LISTEN").unwrap_or_else(|_| "0.0.0.0:3000".to_string());
    let listener = TcpListener::bind(&listen).await?;
    tracing::info!(%listen, store_dir = %state.store_dir, "kubernix cache listening");

    axum::serve(listener, http::router(state)).await?;
    Ok(())
}
