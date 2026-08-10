//! Kubernix SSH frontend.
//!
//! Terminates SSH and serves the Lix daemon protocol on each session channel
//! that execs `<remote-program> --stdio`.
//!
//! Point a client at it with:
//!
//! ```text
//! nix --plugin-files .../kubernix.so \
//!     store ping --store 'kubernix://user@host:2222'
//! ```
//!
//! Environment:
//!   `KUBERNIX_SSH_LISTEN`          bind address (default `0.0.0.0:2222`)
//!   `KUBERNIX_SSH_HOST_KEY`        host key path (generated if absent)
//!   `KUBERNIX_SSH_AUTHORIZED_KEYS` authorized_keys path; if unset, any key is accepted

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use kubernix_server::daemon_rpc::Config as RpcConfig;
use kubernix_server::ssh::{AuthPolicy, SshServer};
use russh::server::Server as _;

use russh::keys::{Algorithm, PrivateKey};

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "kubernix_server=debug,kubernix_sshd=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let listen =
        std::env::var("KUBERNIX_SSH_LISTEN").unwrap_or_else(|_| "0.0.0.0:2222".to_string());

    let host_key = load_or_create_host_key()?;

    let auth = match std::env::var("KUBERNIX_SSH_AUTHORIZED_KEYS") {
        Ok(path) => AuthPolicy::from_authorized_keys_file(&PathBuf::from(path))?,
        Err(_) => {
            tracing::warn!(
                "KUBERNIX_SSH_AUTHORIZED_KEYS unset - accepting ANY public key. Development only."
            );
            AuthPolicy::AcceptAll
        }
    };

    let config = Arc::new(russh::server::Config {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        auth_rejection_time: Duration::from_secs(3),
        keys: vec![host_key],
        ..Default::default()
    });

    let mut rpc_config = RpcConfig::default();
    if let Ok(nats_url) = std::env::var("NATS_URL") {
        match kubernix_server::jobs::JobQueue::connect(&nats_url).await {
            Ok(queue) => {
                // Serve pre-signed upload URLs. This process is the only holder
                // of S3 credentials; workers receive per-object capabilities.
                match kubernix_server::uploads::UploadSigner::from_env().await {
                    Ok(signer) => {
                        let client = queue.client();
                        tokio::spawn(async move {
                            if let Err(e) = signer.serve(client).await {
                                tracing::error!(error = %e, "upload url service stopped");
                            }
                        });
                    }
                    Err(e) => tracing::error!(
                        error = %e,
                        "no S3 configuration; workers will be unable to upload artifacts"
                    ),
                }
                rpc_config.queue = Some(std::sync::Arc::new(queue));
            }
            Err(e) => {
                tracing::error!(error = %e, "could not reach NATS; builds will be refused");
            }
        }
    } else {
        tracing::warn!("NATS_URL unset - builds will be refused");
    }

    let mut server = SshServer::new(rpc_config, auth);

    tracing::info!(%listen, "kubernix sshd listening");
    server.run_on_address(config, &listen[..]).await?;
    Ok(())
}

fn load_or_create_host_key() -> Result<PrivateKey, Box<dyn std::error::Error>> {
    let path = std::env::var("KUBERNIX_SSH_HOST_KEY")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("kubernix_host_ed25519"));

    if path.exists() {
        let key = PrivateKey::read_openssh_file(&path)?;
        tracing::info!(path = %path.display(), "loaded host key");
        return Ok(key);
    }

    // A stable host key matters: clients pin it in known_hosts, and a key that
    // changes every restart trips host-key verification.
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)?;
    key.write_openssh_file(&path, russh::keys::ssh_key::LineEnding::LF)?;
    tracing::warn!(path = %path.display(), "generated new host key");
    Ok(key)
}
