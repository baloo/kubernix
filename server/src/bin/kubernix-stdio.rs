//! Serves the Lix daemon protocol on stdin/stdout.
//!
//! This is the harness the frontend's SSH surface will wrap: when a client
//! `exec`s `<remote-program> --stdio`, the SSH channel is a single bidirectional
//! stream, exactly like the socketpair Lix dups onto the remote command's stdio.
//!
//! Driving it directly, with no SSH involved:
//!
//! ```text
//! nix --plugin-files .../kubernix.so \
//!     store ping --store 'kubernix://localhost?remote-program=.../kubernix-stdio'
//! ```
//!
//! `localhost` triggers Lix's `fakeSSH` path, which runs the command under
//! `bash -c` instead of ssh.
//!
//! NOTE: stdout is the protocol channel. All diagnostics must go to stderr.

use kubernix_server::daemon_capnp::bootstrap;
use kubernix_server::daemon_rpc::{BootstrapImpl, Config};

use capnp_rpc::{RpcSystem, rpc_twoparty_capnp, twoparty};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main(flavor = "current_thread")]
async fn main() -> color_eyre::eyre::Result<()> {
    color_eyre::install()?;
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "kubernix_server=debug,kubernix_stdio=debug".into()),
        )
        // stderr, never stdout: stdout carries the protocol.
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    tracing::info!("kubernix-stdio: serving daemon protocol on stdin/stdout");

    // capnp-rpc capabilities are !Send, so the RPC system runs on a LocalSet.
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            let reader = tokio::io::stdin().compat();
            let writer = tokio::io::stdout().compat_write();

            let network = twoparty::VatNetwork::new(
                reader,
                writer,
                rpc_twoparty_capnp::Side::Server,
                Default::default(),
            );

            let mut config = Config::default();
            if let Ok(store_dir) = std::env::var("KUBERNIX_STORE_DIR") {
                config.store_dir = store_dir;
            }
            let bootstrap: bootstrap::Client = capnp_rpc::new_client(BootstrapImpl::new(config));

            let rpc_system = RpcSystem::new(Box::new(network), Some(bootstrap.client));

            rpc_system.await?;
            color_eyre::eyre::Result::<()>::Ok(())
        })
        .await?;

    tracing::info!("kubernix-stdio: peer disconnected");
    Ok(())
}
