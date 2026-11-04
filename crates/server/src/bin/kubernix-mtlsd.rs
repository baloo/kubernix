//! Kubernix mutual-TLS frontend.
//!
//! Terminates TLS, requires a client certificate chaining to a CA bound with
//! `kubernix-admin add-credential --type tls`, and serves the Lix daemon
//! protocol on the stream (same RPC surface as `kubernix-sshd`).
//!
//! Environment:
//!   `KUBERNIX_TLS_LISTEN`  bind address (default `0.0.0.0:2224`)
//!   `KUBERNIX_TLS_CERT`    PEM server certificate chain (required)
//!   `KUBERNIX_TLS_KEY`     PEM server private key (required)
//!   plus everything `kubernix-sshd` reads for the store, job queue and
//!   uploads (`DATABASE_URL`, `NATS_URL`, ...); see
//!   `kubernix_server::rpc_env::rpc_config_from_env`.
//!
//! Trusted client CAs are re-read from the database every 30 seconds, so a
//! newly provisioned CA needs no restart.

use std::sync::Arc;

use eyre::Context as _;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> color_eyre::eyre::Result<()> {
    color_eyre::install()?;
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "kubernix_server=debug,kubernix_mtlsd=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let listen =
        std::env::var("KUBERNIX_TLS_LISTEN").unwrap_or_else(|_| "0.0.0.0:2224".to_string());
    let cert = std::env::var("KUBERNIX_TLS_CERT").wrap_err("KUBERNIX_TLS_CERT is required")?;
    let key = std::env::var("KUBERNIX_TLS_KEY").wrap_err("KUBERNIX_TLS_KEY is required")?;
    let (chain, key) = kubernix_server::tls::load_identity(&cert, &key)
        .wrap_err("loading the server certificate")?;

    let rpc_config = kubernix_server::rpc_env::rpc_config_from_env().await?;
    let store: Arc<dyn kubernix_server::store::TenantAuthStore> = rpc_config.store.clone();
    let configs = kubernix_server::tls::spawn_root_refresh(store, chain, key);

    let listener = tokio::net::TcpListener::bind(&listen).await?;
    tracing::info!(%listen, "kubernix mtlsd listening");
    kubernix_server::tls::serve(listener, configs, rpc_config).await?;
    Ok(())
}
