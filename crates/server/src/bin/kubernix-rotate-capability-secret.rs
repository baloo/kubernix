//! Kubernix capability-secret rotation — PLAN.md Phase 14.
//!
//! Deliberately its own process, separate from `kubernix-gc`: it mints and
//! prunes rows in a different table with a different blast radius, and there
//! is no throughput or scheduling reason to couple the two. Safe to run more
//! than one replica of — see `kubernix_server::rotate::rotate` — but there is
//! no reason to.
//!
//! Not a correctness dependency for the rest of the system: a fresh
//! deployment mints its first capability secret lazily, on first use, the
//! same way a tenant's signing key is established on first use. Running this
//! only improves things, by rotating that secret on a cadence instead of
//! never.
//!
//! Environment:
//!   `DATABASE_URL`               PostgreSQL; required, there is nothing to rotate without it
//!   `KUBERNIX_ROTATE_INTERVAL`   seconds between rotation passes (default 6 hours)
//!   `KUBERNIX_ROTATE_RETENTION`  seconds a retired secret remains valid for verification (default 24 hours)

use std::time::Duration;

use eyre::{Context as _, OptionExt as _};
use kubernix_server::postgres_store::{PostgresStore, ServingRole};
use kubernix_server::rotate;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

fn env_secs(name: &str, default: Duration) -> Duration {
    match std::env::var(name) {
        Ok(v) => match v.parse::<u64>() {
            Ok(secs) => Duration::from_secs(secs),
            Err(e) => {
                tracing::warn!(%name, value = %v, error = %e, "unparseable, using the default");
                default
            }
        },
        Err(_) => default,
    }
}

#[tokio::main]
async fn main() -> color_eyre::eyre::Result<()> {
    color_eyre::install()?;
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "kubernix_server=debug,kubernix_rotate_capability_secret=debug".into()
            }),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let database_url = std::env::var("DATABASE_URL")
        .ok()
        .ok_or_eyre("DATABASE_URL must be set - nothing to rotate without it")?;
    // Same maintenance-tier role as kubernix-gc: `capability_secrets` carries
    // no row-level security of its own (it is global, not tenant-keyed), but
    // this is the same class of admin process, not a tenant-scoped one.
    let store = PostgresStore::connect(&database_url, ServingRole::Gc)
        .await
        .wrap_err("connecting to PostgreSQL")?;

    let interval = env_secs("KUBERNIX_ROTATE_INTERVAL", Duration::from_secs(6 * 3600));
    let retention = env_secs("KUBERNIX_ROTATE_RETENTION", Duration::from_secs(24 * 3600));

    // A one-shot pass, purely so tests can force a deterministic rotation
    // without waiting out a production-length interval.
    let once = std::env::args().any(|a| a == "--once");

    tracing::info!(
        ?interval,
        ?retention,
        once,
        "kubernix-rotate-capability-secret starting"
    );

    if once {
        match rotate::rotate(&store, retention).await {
            Ok(stats) => tracing::info!(?stats, "rotation pass ran"),
            Err(e) => {
                tracing::error!(error = %e, "rotation pass failed");
                return Err(e.into());
            }
        }
        return Ok(());
    }

    let mut ticker = tokio::time::interval(interval);
    // The first tick fires immediately; rotating right at startup is the
    // right default rather than waiting out a full interval first.
    loop {
        ticker.tick().await;
        match rotate::rotate(&store, retention).await {
            Ok(stats) if stats.ran => tracing::info!(?stats, "rotation pass ran"),
            Ok(_) => tracing::debug!("rotation pass skipped: another replica holds the lock"),
            Err(e) => tracing::error!(error = %e, "rotation pass failed"),
        }
    }
}
