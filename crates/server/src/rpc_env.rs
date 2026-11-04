//! Process setup shared by the frontends (`kubernix-sshd`, `kubernix-mtlsd`):
//! the environment-driven [`RpcConfig`].

use std::time::Duration;

use crate::daemon_rpc::Config as RpcConfig;
use crate::postgres_store::{PostgresStore, ServingRole};

/// Parse a seconds-valued env var, falling back to `default` if it's unset
/// or unparseable. Mirrors `kubernix-gc`'s own copy of this — small enough,
/// and specific enough to each binary's own env var names, that a shared
/// helper isn't worth it.
pub fn env_secs(name: &str, default: Duration) -> Duration {
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

/// Build the RPC config from `DATABASE_URL`, `NATS_URL`, `KUBERNIX_STORE_DIR`
/// and friends (documented on `kubernix-sshd`). Only an unreachable database
/// is an error; a missing NATS or S3 setup is logged and builds are refused.
pub async fn rpc_config_from_env() -> eyre::Result<RpcConfig> {
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
            Ok(store) => {
                // Seeded into every tenant this process creates from here on
                // (`PostgresStore::ensure_tenant`) — unset means new tenants
                // get no default substituter, not that seeding silently
                // no-ops in a surprising way.
                if let (Ok(url), Ok(key)) = (
                    std::env::var("KUBERNIX_DEFAULT_SUBSTITUTER_URL"),
                    std::env::var("KUBERNIX_DEFAULT_SUBSTITUTER_KEY"),
                ) {
                    store.set_default_substituter(url, key);
                }
                store.set_negative_cache_ttl(env_secs(
                    "KUBERNIX_SUBSTITUTER_NEGATIVE_CACHE_TTL",
                    Duration::from_secs(600),
                ));
                rpc_config.store = store;
            }
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
        let results_retention = env_secs(
            "KUBERNIX_JOB_RESULTS_RETENTION",
            Duration::from_secs(24 * 3600),
        );
        match crate::jobs::JobQueue::connect(&nats_url, results_retention).await {
            Ok(queue) => {
                // Serve pre-signed upload URLs. This process is the only holder
                // of S3 credentials; workers receive per-object capabilities.
                match crate::uploads::UploadSigner::from_env().await {
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
    Ok(rpc_config)
}
