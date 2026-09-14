//! SSH surface: terminates SSH and serves the Lix daemon protocol on the channel.
//!
//! A Lix client running `ssh-ng://`-style transport opens a session channel and
//! `exec`s `<remote-program> --stdio`. We do not spawn that binary — we recognise
//! the request and serve the Cap'n Proto RPC protocol on the channel's byte
//! stream ourselves. That stream is the exact equivalent of the socketpair Lix
//! dups onto the remote command's stdin/stdout.

use std::collections::HashMap;
use std::net::SocketAddr;

use russh::keys::PublicKey;
use russh::server::{Auth, Handler, Msg, Server, Session};
use russh::{Channel, ChannelId};

use crate::daemon_capnp::bootstrap;
use crate::daemon_rpc::{BootstrapImpl, Config as RpcConfig};
use crate::tenant::{KeyType, Tenant};

/// Whether a client that offers no key at all may still connect.
///
/// This is unrelated to key-based auth: a presented key is always checked
/// against `tenant_auth_bindings` (see [`SshHandler::auth_publickey`]),
/// unconditionally, regardless of this policy. It exists only for
/// `auth_none`, the step a keyless client is accepted or rejected at before
/// ever reaching `auth_publickey`.
///
/// This is load-bearing, not cosmetic: OpenSSH clients send `auth_none` as
/// their first request unconditionally (to learn what the server requires),
/// regardless of `PreferredAuthentications` — so as long as this accepts,
/// `tenant_auth_bindings` never even gets consulted. `RequireKey` is what
/// makes the bindings table an actual access control rather than a lookup
/// table nothing forces a client through.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AuthPolicy {
    /// Accept a keyless connection, attributing it to the claimed username
    /// alone, unverified. Development only — bypasses `tenant_auth_bindings`
    /// entirely, for every client, not just ones without a key.
    AcceptAll,
    /// Reject `auth_none` outright, forcing every client through
    /// `auth_publickey` — the only path a `tenant_auth_bindings` row can
    /// attribute a tenant from.
    #[default]
    RequireKey,
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
            auth: self.auth,
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
    /// Under `auth_publickey`, the id comes straight from the matching
    /// `tenant_auth_bindings` row and `verified` is always true — the bound
    /// key is what "verified" means here. Under keyless `auth_none`
    /// (`AuthPolicy::AcceptAll`), it is derived from the username alone and
    /// `verified` is false: pure assertion, not a fact.
    tenant: Option<Tenant>,
    /// Channels opened but not yet claimed by an `exec` request.
    channels: HashMap<ChannelId, Channel<Msg>>,
}

impl Handler for SshHandler {
    type Error = russh::Error;

    /// Accepted under `AcceptAll`, so a client that offers no key at all still
    /// gets in. Development convenience only — unrelated to whether a
    /// *presented* key is accepted, which `auth_publickey` always checks
    /// against `tenant_auth_bindings` regardless of this policy.
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
            // Forces every client through `auth_publickey`, the only path
            // that can attribute a real tenant.
            AuthPolicy::RequireKey => Ok(Auth::reject()),
        }
    }

    /// The tenant follows the key, looked up in `tenant_auth_bindings` — not
    /// derived from anything the client presented. A key with no binding row
    /// is rejected outright: `tenants`/bindings are provisioned by hand, so
    /// there is no "attribute an unverified tenant" fallback here the way
    /// `auth_none` has one. `AuthPolicy` plays no part in this decision.
    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        let fingerprint = public_key.fingerprint(Default::default()).to_string();
        match self
            .rpc_config
            .store
            .find_tenant_by_binding(KeyType::Ssh, &fingerprint)
            .await
        {
            Ok(Some(id)) => {
                let tenant = Tenant {
                    id,
                    identity: format!("key:{fingerprint}"),
                    verified: true,
                };
                tracing::info!(user, %fingerprint, tenant = %tenant.id, "authenticated");
                self.user = Some(user.to_string());
                self.tenant = Some(tenant);
                Ok(Auth::Accept)
            }
            Ok(None) => {
                tracing::warn!(user, %fingerprint, "rejected: key not bound to any tenant");
                Ok(Auth::reject())
            }
            Err(e) => {
                // Fail closed: a lookup we could not perform is not evidence
                // of a binding, so treat it the same as none found.
                tracing::error!(error = %e, user, %fingerprint, "tenant binding lookup failed");
                Ok(Auth::reject())
            }
        }
    }

    /// A client that asks for an interactive shell (rather than `exec`ing
    /// `<remote-program> --stdio`) is not using the Lix transport at all —
    /// most likely someone poking at the endpoint with a plain `ssh`. Left
    /// unhandled, russh's default `shell_request` silently succeeds and then
    /// never sends anything, so the client just hangs forever. Tell them
    /// what this is for and hang up instead.
    async fn shell_request(
        &mut self,
        channel_id: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let handle = session.handle();
        let name = self
            .tenant
            .as_ref()
            .map(|t| t.id.to_string())
            .or_else(|| self.user.clone())
            .unwrap_or_else(|| "there".to_string());

        session.channel_success(channel_id)?;

        // `Handle` methods enqueue onto the same session task that is
        // synchronously running this very handler, so awaiting them here
        // directly would wait on a queue nothing can drain until this
        // function returns — a self-deadlock. Send the goodbye message from
        // a spawned task instead, the way `exec_request`'s success path
        // already has to for unrelated reasons (see the comment there).
        tokio::spawn(async move {
            let _ = handle
                .data(
                    channel_id,
                    format!(
                        "hey {name}, you've successfully authenticated, but kubernix has no \
                         shell to give you — use the lix plugin instead.\n"
                    )
                    .into_bytes(),
                )
                .await;
            let _ = handle.eof(channel_id).await;
            let _ = handle.exit_status_request(channel_id, 1).await;
            let _ = handle.close(channel_id).await;
        });
        self.channels.remove(&channel_id);
        Ok(())
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

            // `channel_failure` here would tell the client the *request*
            // itself was refused, and OpenSSH tears the session down right
            // then without ever reading the extended-data message below --
            // confirmed against a real `ssh` client, which prints nothing
            // but "exec request failed on channel 0" and exits. Accepting
            // instead (as if the command ran) is what lets the message and
            // exit status actually reach the client, the same way
            // `shell_request` already has to.
            session.channel_success(channel_id)?;

            // Same self-deadlock hazard as `shell_request`: `Handle` calls
            // are drained by this very session task, so they must not be
            // awaited inline from within the handler that task is currently
            // running. Spawn instead.
            tokio::spawn(async move {
                let _ = handle
                    .extended_data(
                        channel_id,
                        1,
                        format!(
                            "kubernix: unsupported command: {command}\n\
                             kubernix only serves the Lix daemon protocol; expected an exec of \
                             `<remote-program> --stdio` (e.g. `nix-daemon --stdio`), optionally \
                             followed by `--store <uri>`.\n"
                        )
                        .into_bytes(),
                    )
                    .await;
                let _ = handle.exit_status_request(channel_id, 127).await;
                let _ = handle.close(channel_id).await;
            });
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

    const OFFERED: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFDElZlNyHEIqviXh/UmoXKUUqFFJ7ARO3JcpB+eAc5z";
    const OTHER: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJCU6/lsgeY1GlUJF2nMkLB5kq008SBiLTz2YswJvb8o";

    fn key(openssh: &str) -> PublicKey {
        PublicKey::from_openssh(openssh).expect("parseable")
    }

    /// `MemoryStore` (what `RpcConfig::default()` carries) never has a
    /// binding for anything — see its `TenantAuthStore` impl — so this
    /// exercises the "no row" branch of `auth_publickey` without a database:
    /// a key nobody provisioned must be rejected, not attributed a tenant.
    #[tokio::test]
    async fn an_unbound_key_is_rejected() {
        let mut server = SshServer::new(RpcConfig::default(), AuthPolicy::AcceptAll);
        let mut handler = server.new_client(None);

        let auth = handler
            .auth_publickey("alice", &key(OFFERED))
            .await
            .unwrap();

        assert!(matches!(auth, Auth::Reject { .. }), "{auth:?}");
        assert!(handler.tenant.is_none());
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
