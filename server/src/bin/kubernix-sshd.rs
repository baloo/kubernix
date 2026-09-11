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
//!   `KUBERNIX_SSH_LISTEN`     bind address (default `0.0.0.0:2222`)
//!   `KUBERNIX_SSH_HOST_KEY`   host key path (generated if absent)
//!   `KUBERNIX_SSH_ACCEPT_ALL` if set, also accept clients that offer no key
//!                             at all, attributed by username alone and
//!                             unverified (`ssh::AuthPolicy::AcceptAll`).
//!                             Development only: this bypasses
//!                             `tenant_auth_bindings` for every client, not
//!                             just keyless ones, since OpenSSH always tries
//!                             `auth_none` first. Unset means `RequireKey`.
//!   `DATABASE_URL`            PostgreSQL; if unset, an in-memory store is used,
//!                             and every SSH key is rejected (see
//!                             `ssh::AuthPolicy`) — there is nowhere to look up
//!                             a `tenant_auth_bindings` row without a database
//!   `KUBERNIX_STORE_DIR`      store dir a client's paths are prefixed with
//!                             (default `/nix/store`)

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use eyre::Context as _;
use kubernix_server::daemon_rpc::Config as RpcConfig;
use kubernix_server::postgres_store::{PostgresStore, ServingRole};
use kubernix_server::ssh::{AuthPolicy, SshServer};
use russh::server::Server as _;

use russh::keys::{Algorithm, PrivateKey};

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> color_eyre::eyre::Result<()> {
    color_eyre::install()?;
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

    // Governs only the keyless `auth_none` path (see `ssh::AuthPolicy`'s doc
    // comment); every presented key is checked against `tenant_auth_bindings`
    // regardless of this. `RequireKey` by default: a client that offers no
    // key gets no attributed tenant at all, which is what makes the bindings
    // table an actual gate rather than one only some clients pass through.
    let auth = if std::env::var("KUBERNIX_SSH_ACCEPT_ALL").is_ok() {
        tracing::warn!(
            "KUBERNIX_SSH_ACCEPT_ALL set - accepting keyless clients, unverified. Development only."
        );
        AuthPolicy::AcceptAll
    } else {
        AuthPolicy::RequireKey
    };

    let config = Arc::new(russh::server::Config {
        inactivity_timeout: Some(Duration::from_secs(3600)),
        auth_rejection_time: Duration::from_secs(3),
        keys: vec![host_key],
        ..Default::default()
    });

    let mut rpc_config = RpcConfig::default();
    if let Ok(store_dir) = std::env::var("KUBERNIX_STORE_DIR") {
        rpc_config.store_dir = store_dir;
    }

    // Without a database the frontend still works, but every path it knows is
    // forgotten on restart — which strands objects a worker already uploaded.
    // Refusing to start would be worse for development, so this warns loudly
    // instead.
    match std::env::var("DATABASE_URL") {
        Ok(url) => match PostgresStore::connect(&url, ServingRole::App).await {
            Ok(store) => rpc_config.store = store,
            Err(e) => {
                tracing::error!(error = %e, "could not reach PostgreSQL");
                return Err(e.into());
            }
        },
        Err(_) => tracing::warn!(
            "DATABASE_URL unset - using the in-memory store; every path is lost on restart"
        ),
    }

    if let Ok(nats_url) = std::env::var("NATS_URL") {
        match kubernix_server::jobs::JobQueue::connect(&nats_url).await {
            Ok(queue) => {
                // Serve pre-signed upload URLs. This process is the only holder
                // of S3 credentials; workers receive per-object capabilities.
                match kubernix_server::uploads::UploadSigner::from_env().await {
                    Ok(signer) => {
                        let signer = std::sync::Arc::new(signer);
                        // Same signer both ways: it writes inputs directly and
                        // pre-signs the URLs workers use for outputs.
                        rpc_config.uploader = Some(signer.clone());
                        let client = queue.client();
                        let serving = signer.clone();
                        let serving_store = rpc_config.store.clone();
                        tokio::spawn(async move {
                            if let Err(e) = (*serving).clone().serve(client, serving_store).await {
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

fn load_or_create_host_key() -> eyre::Result<PrivateKey> {
    let path = std::env::var("KUBERNIX_SSH_HOST_KEY")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("kubernix_host_ed25519"));

    if path.exists() {
        let key = PrivateKey::read_openssh_file(&path)
            .wrap_err_with(|| format!("reading the host key at {}", path.display()))?;
        tracing::info!(path = %path.display(), "loaded host key");
        return Ok(key);
    }

    // A stable host key matters: clients pin it in known_hosts, and a key that
    // changes every restart trips host-key verification.
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .wrap_err("generating a host key")?;
    key.write_openssh_file(&path, russh::keys::ssh_key::LineEnding::LF)
        .wrap_err_with(|| format!("writing the host key to {}", path.display()))?;
    tracing::warn!(path = %path.display(), "generated new host key");
    Ok(key)
}
