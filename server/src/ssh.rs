//! SSH surface: terminates SSH and serves the Lix daemon protocol on the channel.
//!
//! A Lix client running `ssh-ng://`-style transport opens a session channel and
//! `exec`s `<remote-program> --stdio`. We do not spawn that binary — we recognise
//! the request and serve the Cap'n Proto RPC protocol on the channel's byte
//! stream ourselves. That stream is the exact equivalent of the socketpair Lix
//! dups onto the remote command's stdin/stdout.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use russh::keys::PublicKey;
use russh::server::{Auth, Handler, Msg, Server, Session};
use russh::{Channel, ChannelId};

use crate::daemon_capnp::bootstrap;
use crate::daemon_rpc::{BootstrapImpl, Config as RpcConfig};
use crate::tenant::Tenant;

/// Which public keys may connect.
#[derive(Clone, Default)]
pub enum AuthPolicy {
    /// Accept any key, recording its fingerprint. Development only.
    #[default]
    AcceptAll,
    /// Accept only keys listed in an `authorized_keys` file.
    AuthorizedKeys(Arc<Vec<PublicKey>>),
}

impl AuthPolicy {
    pub fn from_authorized_keys_file(path: &Path) -> std::io::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let mut keys = Vec::new();
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            match PublicKey::from_openssh(line) {
                Ok(key) => keys.push(key),
                Err(e) => tracing::warn!(error = %e, "skipping unparseable authorized_keys entry"),
            }
        }
        tracing::info!(count = keys.len(), path = %path.display(), "loaded authorized keys");
        Ok(AuthPolicy::AuthorizedKeys(Arc::new(keys)))
    }

    fn permits(&self, key: &PublicKey) -> bool {
        match self {
            AuthPolicy::AcceptAll => true,
            // Compare the *key data*, not the `PublicKey`. `PublicKey` equality
            // includes the trailing comment, which an `authorized_keys` line
            // carries (`ssh-ed25519 AAAA… user@host`) and the key a client
            // offers over the wire does not — so comparing whole values rejects
            // every legitimate key.
            AuthPolicy::AuthorizedKeys(keys) => keys.iter().any(|k| k.key_data() == key.key_data()),
        }
    }
}

#[derive(Clone)]
pub struct SshServer {
    rpc_config: RpcConfig,
    auth: AuthPolicy,
}

impl SshServer {
    pub fn new(rpc_config: RpcConfig, auth: AuthPolicy) -> Self {
        Self { rpc_config, auth }
    }
}

impl Server for SshServer {
    type Handler = SshHandler;

    fn new_client(&mut self, peer_addr: Option<SocketAddr>) -> SshHandler {
        tracing::info!(peer = ?peer_addr, "connection");
        SshHandler {
            rpc_config: self.rpc_config.clone(),
            auth: self.auth.clone(),
            peer_addr,
            user: None,
            tenant: None,
            channels: HashMap::new(),
        }
    }
}

pub struct SshHandler {
    rpc_config: RpcConfig,
    auth: AuthPolicy,
    peer_addr: Option<SocketAddr>,
    user: Option<String>,
    /// Who this connection is attributed to, once it has authenticated.
    ///
    /// Derived from the identity the client presented rather than assigned, so
    /// the same client is the same tenant across connections. `verified` records
    /// whether the [`AuthPolicy`] actually checked it — under `AcceptAll` it did
    /// not, and the attribution is a claim rather than a fact.
    tenant: Option<Tenant>,
    /// Channels opened but not yet claimed by an `exec` request.
    channels: HashMap<ChannelId, Channel<Msg>>,
}

impl Handler for SshHandler {
    type Error = russh::Error;

    /// Accepted under `AcceptAll`, so a client that offers no key at all still
    /// gets in. Development convenience; real deployments set an
    /// `authorized_keys` file, which rejects here.
    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        match self.auth {
            AuthPolicy::AcceptAll => {
                // No key at all, so the username is the only identity on offer —
                // and it is pure assertion. Everything this connection does is
                // attributed to it anyway; `verified: false` is what says the
                // attribution must not be mistaken for a permission.
                let tenant = Tenant::from_ssh(user, None, false);
                tracing::warn!(
                    user,
                    tenant = %tenant.id,
                    "accepting unauthenticated client (no auth configured)"
                );
                self.user = Some(user.to_string());
                self.tenant = Some(tenant);
                Ok(Auth::Accept)
            }
            AuthPolicy::AuthorizedKeys(_) => Ok(Auth::reject()),
        }
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        let fingerprint = public_key.fingerprint(Default::default()).to_string();
        let permitted = self.auth.permits(public_key);
        if !permitted {
            tracing::warn!(user, %fingerprint, "rejected: key not authorized");
            return Ok(Auth::reject());
        }

        // The tenant follows the key, not the username: the key is what auth
        // verifies, so deriving from it means enabling auth does not renumber
        // anyone. Under `AcceptAll` the key was accepted without being checked,
        // which is exactly what `verified` records.
        let verified = matches!(self.auth, AuthPolicy::AuthorizedKeys(_));
        let tenant = Tenant::from_ssh(user, Some(&fingerprint), verified);
        tracing::info!(user, %fingerprint, tenant = %tenant.id, verified, "authenticated");
        self.user = Some(user.to_string());
        self.tenant = Some(tenant);
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        self.channels.insert(channel.id(), channel);
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel_id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data).to_string();
        let handle = session.handle();

        // `remote-program` is a client-side setting, so the binary name is not
        // reliably `nix-daemon`. Match on the `--stdio` flag instead.
        if !is_stdio_request(&command) {
            tracing::warn!(%command, "rejecting unsupported command");
            session.channel_failure(channel_id)?;
            let _ = handle
                .extended_data(
                    channel_id,
                    1,
                    format!("kubernix: unsupported command: {command}\n").into_bytes(),
                )
                .await;
            let _ = handle.exit_status_request(channel_id, 127).await;
            let _ = handle.close(channel_id).await;
            self.channels.remove(&channel_id);
            return Ok(());
        }

        let Some(channel) = self.channels.remove(&channel_id) else {
            tracing::error!(?channel_id, "exec on unknown channel");
            session.channel_failure(channel_id)?;
            return Ok(());
        };

        // russh only delivers an exec after a successful auth, so this is set;
        // refusing rather than defaulting keeps an unattributed connection from
        // ever reaching the store.
        let Some(tenant) = self.tenant.clone() else {
            tracing::error!("exec before authentication");
            session.channel_failure(channel_id)?;
            return Ok(());
        };

        session.channel_success(channel_id)?;

        tracing::info!(
            user = ?self.user,
            peer = ?self.peer_addr,
            tenant = %tenant.id,
            %command,
            "serving daemon protocol"
        );

        let mut rpc_config = self.rpc_config.clone();
        rpc_config.tenant = tenant;
        let stream = channel.into_stream();

        // capnp-rpc capabilities are !Send, so the RPC system cannot run on the
        // multi-threaded runtime driving russh. Hand the stream to a dedicated
        // thread with its own current-thread runtime and LocalSet. The stream
        // itself is Send, which is what makes this bridge possible.
        std::thread::spawn(move || {
            tracing::debug!(?channel_id, "rpc thread starting");
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    tracing::error!(error = %e, "failed to build RPC runtime");
                    return;
                }
            };

            tracing::debug!(?channel_id, "rpc runtime built, entering event loop");
            let local = tokio::task::LocalSet::new();
            let result = local.block_on(&runtime, serve_rpc(stream, rpc_config));
            tracing::debug!(?channel_id, ?result, "rpc event loop returned");

            match result {
                Ok(()) => tracing::info!("rpc session ended"),
                Err(e) => tracing::warn!(error = %e, "rpc session ended with error"),
            }

            // The client is done when the RPC system finishes.
            let _ = runtime.block_on(async {
                let _ = handle.exit_status_request(channel_id, 0).await;
                handle.close(channel_id).await
            });
        });

        Ok(())
    }
}

/// Serve the daemon protocol over one bidirectional stream.
async fn serve_rpc<S>(stream: S, config: RpcConfig) -> eyre::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
{
    use capnp_rpc::{RpcSystem, rpc_twoparty_capnp, twoparty};
    use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

    let (reader, writer) = tokio::io::split(stream);
    let network = twoparty::VatNetwork::new(
        reader.compat(),
        writer.compat_write(),
        rpc_twoparty_capnp::Side::Server,
        Default::default(),
    );

    let bootstrap: bootstrap::Client = capnp_rpc::new_client(BootstrapImpl::new(config));
    RpcSystem::new(Box::new(network), Some(bootstrap.client)).await?;
    Ok(())
}

/// Lix sends `<remote-program> --stdio`, optionally followed by
/// `--store <uri>`. The program name is client-configurable, so only the flag is
/// dependable.
fn is_stdio_request(command: &str) -> bool {
    command.split_whitespace().any(|arg| arg == "--stdio")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An `authorized_keys` line, i.e. with a trailing comment.
    const AUTHORIZED: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFDElZlNyHEIqviXh/UmoXKUUqFFJ7ARO3JcpB+eAc5z baloo@khany";
    /// The same key as a client presents it: no comment.
    const OFFERED: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFDElZlNyHEIqviXh/UmoXKUUqFFJ7ARO3JcpB+eAc5z";
    const OTHER: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJCU6/lsgeY1GlUJF2nMkLB5kq008SBiLTz2YswJvb8o";

    fn key(openssh: &str) -> PublicKey {
        PublicKey::from_openssh(openssh).expect("parseable")
    }

    #[test]
    fn an_authorized_key_is_recognised_despite_its_comment() {
        // Regression: `PublicKey` equality includes the comment, so comparing
        // whole values rejected every key in an `authorized_keys` file.
        let policy = AuthPolicy::AuthorizedKeys(Arc::new(vec![key(AUTHORIZED)]));
        assert!(policy.permits(&key(OFFERED)));
        assert!(policy.permits(&key(AUTHORIZED)));
    }

    #[test]
    fn an_unlisted_key_is_refused() {
        let policy = AuthPolicy::AuthorizedKeys(Arc::new(vec![key(AUTHORIZED)]));
        assert!(!policy.permits(&key(OTHER)));
        assert!(!AuthPolicy::AuthorizedKeys(Arc::new(Vec::new())).permits(&key(OFFERED)));
    }

    #[test]
    fn the_same_key_is_the_same_tenant_whatever_the_username() {
        // Tenancy follows the key so that enabling auth does not renumber
        // anyone, and so a username cannot be used to reach another's data.
        let fingerprint = key(OFFERED).fingerprint(Default::default()).to_string();
        let alice = Tenant::from_ssh("alice", Some(&fingerprint), true);
        let claiming_bob = Tenant::from_ssh("bob", Some(&fingerprint), true);
        assert_eq!(alice.id, claiming_bob.id);

        let other = key(OTHER).fingerprint(Default::default()).to_string();
        assert_ne!(alice.id, Tenant::from_ssh("alice", Some(&other), true).id);
    }

    #[test]
    fn accepts_the_shapes_lix_sends() {
        assert!(is_stdio_request("nix-daemon --stdio"));
        assert!(is_stdio_request(
            "/nix/store/abc-lix/bin/nix-daemon --stdio"
        ));
        assert!(is_stdio_request("nix-daemon --stdio --store /custom/store"));
        // remote-program can be anything, including our own test harness
        assert!(is_stdio_request("/tmp/kubernix-stdio --stdio"));
    }

    #[test]
    fn rejects_everything_else() {
        assert!(!is_stdio_request("bash"));
        // the serve protocol is a different wire format; we do not speak it
        assert!(!is_stdio_request("nix-store --serve --write"));
        assert!(!is_stdio_request(""));
        // must be a distinct argument, not a substring
        assert!(!is_stdio_request("evil --stdiofoo"));
    }
}
