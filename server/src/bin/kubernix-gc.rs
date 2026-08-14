//! Kubernix retention and garbage collection — PLAN.md Phase 12.
//!
//! Deliberately its own process, separate from `kubernix-cache` (reads) and
//! `kubernix-sshd` (writes): it deletes things, on a timer, and neither of
//! the other two should have that blast radius. Safe to run more than one
//! replica of — see `kubernix_server::gc::run_gc_pass` — but there is no
//! throughput reason to.
//!
//! Environment:
//!   `DATABASE_URL`             PostgreSQL; required, there is nothing to collect without it
//!   `S3_BUCKET`, `AWS_*`       object store holding the NARs and logs
//!   `KUBERNIX_GC_INTERVAL`     seconds between passes (default 300)
//!   `KUBERNIX_GC_BATCH`        access marks drained per pass (default 10000)
//!   `KUBERNIX_GC_CUTOFF_VERIFIED`    seconds a verified path may go unread (default 30 days)
//!   `KUBERNIX_GC_CUTOFF_BUILT`       seconds a built path may go unread (default 30 days)
//!   `KUBERNIX_GC_CUTOFF_QUARANTINED` seconds a quarantined path may go unread (default 1 day)
//!   `KUBERNIX_GC_JOB_LOG_CUTOFF`     seconds after a job finishes before its log is deleted (default 7 days)
//!   `KUBERNIX_GC_JOB_ROW_CUTOFF`     seconds after a job finishes before its row is deleted (default 90 days)

use std::time::Duration;

use kubernix_server::gc::{self, JobRetention, TierCutoffs};
use kubernix_server::postgres_store::PostgresStore;
use kubernix_server::uploads::UploadSigner;
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
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "kubernix_server=debug,kubernix_gc=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Unlike the other two binaries, there is nothing partial to fall back
    // to here: a collector with no database and no object store has nothing
    // to collect, so refusing to start is the honest answer rather than
    // idling forever.
    let database_url = std::env::var("DATABASE_URL")
        .map_err(|_| "DATABASE_URL must be set - nothing to collect without it")?;
    let store = PostgresStore::connect(&database_url).await?;

    let uploader = UploadSigner::from_env()
        .await
        .map_err(|e| format!("no S3 configuration: {e}"))?;

    let cutoffs = TierCutoffs {
        verified: env_secs(
            "KUBERNIX_GC_CUTOFF_VERIFIED",
            TierCutoffs::default().verified,
        ),
        built: env_secs("KUBERNIX_GC_CUTOFF_BUILT", TierCutoffs::default().built),
        quarantined: env_secs(
            "KUBERNIX_GC_CUTOFF_QUARANTINED",
            TierCutoffs::default().quarantined,
        ),
    };
    let job_retention = JobRetention {
        log_after: env_secs(
            "KUBERNIX_GC_JOB_LOG_CUTOFF",
            JobRetention::default().log_after,
        ),
        row_after: env_secs(
            "KUBERNIX_GC_JOB_ROW_CUTOFF",
            JobRetention::default().row_after,
        ),
    };
    let batch_size: i64 = std::env::var("KUBERNIX_GC_BATCH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000);
    let interval = env_secs("KUBERNIX_GC_INTERVAL", Duration::from_secs(300));

    tracing::info!(
        ?cutoffs,
        ?job_retention,
        batch_size,
        ?interval,
        "kubernix-gc starting"
    );

    let mut ticker = tokio::time::interval(interval);
    // The first tick fires immediately; running a pass right at startup is
    // the right default rather than waiting out a full interval first.
    loop {
        ticker.tick().await;
        match gc::run_gc_pass(&store, &uploader, &cutoffs, &job_retention, batch_size).await {
            Ok(stats) if stats.ran => tracing::info!(?stats, "gc pass ran"),
            Ok(_) => tracing::debug!("gc pass skipped: another collector holds the lock"),
            Err(e) => tracing::error!(error = %e, "gc pass failed"),
        }
    }
}
