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
//!   `KUBERNIX_JOB_RESULTS_RETENTION`
//!                             seconds a job's outcome stays replayable in
//!                             NATS, and how long a dedup reservation
//!                             (PLAN.md Phase 19) may go unclaimed before
//!                             it's orphaned (default 24h) -- must match
//!                             the worker's own copy of this value
//!                             (`KUBERNIX_JOB_RESULTS_RETENTION` there too),
//!                             see `jobs::JobQueue::connect`'s doc comment
//!   `KUBERNIX_DEFAULT_SUBSTITUTER_URL`/`_KEY`
//!                             seeded into every tenant's trusted
//!                             substituters on first creation (both must be
//!                             set; unset means no default at all) -- see
//!                             `crate::substitute`
//!   `KUBERNIX_SUBSTITUTER_NEGATIVE_CACHE_TTL`
//!                             seconds a trusted substituter's "not found"
//!                             answer is cached before being re-checked
//!                             (default 600)

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use eyre::Context as _;
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

    let rpc_config = kubernix_server::rpc_env::rpc_config_from_env().await?;
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
