//! mTLS surface: terminates TLS with a client certificate and serves the Lix
//! daemon protocol on the stream.
//!
//! Where `ssh.rs` binds individual keys to tenants, a `KeyType::Tls` binding
//! names a trusted **CA** (`key_id` = its Subject Key Identifier, `key_value` =
//! its DER certificate). Chain validation is rustls' job
//! ([`WebPkiClientVerifier`]) against the CAs currently in the database; this
//! module only attributes an already-validated chain to a tenant.
//!
//! Clients are expected to present a direct chain (leaf, then each issuer in
//! order), not a tree, so the **last certificate sent** names the bound CA —
//! see [`candidate_key_ids`].

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rustls::RootCertStore;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use x509_parser::extensions::ParsedExtension;
use x509_parser::oid_registry::{
    OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER, OID_X509_EXT_SUBJECT_KEY_IDENTIFIER,
};
use x509_parser::prelude::{FromDer, X509Certificate};

use crate::daemon_rpc::{Config as RpcConfig, spawn_rpc_thread};
use crate::store::TenantAuthStore;
use crate::tenant::{KeyType, Tenant};

/// How often the trusted CA set is re-read from the database.
pub const ROOT_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// Handshake deadline: a stalled client must not hold a task forever.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// The single encoding of a key identifier used as `key_id` for `tls`
/// bindings: lowercase hex, no separators. Both provisioning
/// ([`ca_from_pem`]) and lookup ([`candidate_key_ids`]) go through it.
fn subject_key_id(cert: &X509Certificate<'_>) -> Option<String> {
    let ext = cert
        .get_extension_unique(&OID_X509_EXT_SUBJECT_KEY_IDENTIFIER)
        .ok()??;
    match ext.parsed_extension() {
        ParsedExtension::SubjectKeyIdentifier(kid) => Some(hex(kid.0)),
        _ => None,
    }
}

fn authority_key_id(cert: &X509Certificate<'_>) -> Option<String> {
    let ext = cert
        .get_extension_unique(&OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER)
        .ok()??;
    match ext.parsed_extension() {
        ParsedExtension::AuthorityKeyIdentifier(aki) => {
            aki.key_identifier.as_ref().map(|kid| hex(kid.0))
        }
        _ => None,
    }
}

/// Read a PEM-encoded CA certificate for `kubernix-admin add-credential`,
/// returning `(key_id, der)`. The CA must carry a Subject Key Identifier.
pub fn ca_from_pem(pem: &str) -> Result<(String, Vec<u8>), String> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(pem.as_bytes())
        .map_err(|e| format!("not a PEM certificate: {e}"))?;
    let (_, cert) = X509Certificate::from_der(&pem.contents)
        .map_err(|e| format!("not a valid X.509 certificate: {e}"))?;
    if !cert.is_ca() {
        return Err("certificate is not a CA (basicConstraints cA=TRUE required)".into());
    }
    let key_id =
        subject_key_id(&cert).ok_or("certificate has no Subject Key Identifier extension")?;
    Ok((key_id, pem.contents))
}

/// Key ids to try, in order, to find the binding for a validated client chain.
///
/// The chain is a direct one, so the last certificate sent is the topmost the
/// client provided. If it is the bound CA itself its SKI matches; if the
/// client left the CA out (as TLS permits), it is a certificate issued by the
/// bound CA and its AKI matches. The handshake has already proved the chain
/// ends at a bound CA, so trying both cannot attribute to an untrusted one.
pub fn candidate_key_ids(chain: &[CertificateDer<'_>]) -> Vec<String> {
    let Some(last) = chain.last() else {
        return Vec::new();
    };
    let Ok((_, cert)) = X509Certificate::from_der(last.as_ref()) else {
        return Vec::new();
    };
    subject_key_id(&cert)
        .into_iter()
        .chain(authority_key_id(&cert))
        .collect()
}

/// Attribute a validated client chain to a tenant. `None` means reject.
pub async fn tenant_for_chain(
    store: &dyn TenantAuthStore,
    chain: &[CertificateDer<'_>],
) -> Option<Tenant> {
    for key_id in candidate_key_ids(chain) {
        match store.find_tenant_by_binding(KeyType::Tls, &key_id).await {
            Ok(Some(id)) => {
                return Some(Tenant {
                    id,
                    identity: format!("tls:{key_id}"),
                    verified: true,
                });
            }
            Ok(None) => {}
            Err(e) => {
                tracing::error!(error = %e, "tls binding lookup failed");
                return None;
            }
        }
    }
    None
}

/// Load the server's own certificate chain and key from PEM files.
pub fn load_identity(
    cert_path: &str,
    key_path: &str,
) -> eyre::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    use rustls::pki_types::pem::PemObject;
    let certs = CertificateDer::pem_file_iter(cert_path)?.collect::<Result<Vec<_>, _>>()?;
    eyre::ensure!(!certs.is_empty(), "no certificates in {cert_path}");
    let key = PrivateKeyDer::from_pem_file(key_path)?;
    Ok((certs, key))
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Build a server config requiring client certificates that chain to `roots`.
/// `None` when no usable root exists: nobody can authenticate, so no config.
pub fn build_server_config(
    roots: &[Vec<u8>],
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> eyre::Result<Option<Arc<rustls::ServerConfig>>> {
    let mut store = RootCertStore::empty();
    for der in roots {
        if let Err(e) = store.add(CertificateDer::from(der.clone())) {
            tracing::warn!(error = %e, "ignoring unusable trusted client CA");
        }
    }
    if store.is_empty() {
        return Ok(None);
    }
    let provider = provider();
    let verifier =
        WebPkiClientVerifier::builder_with_provider(Arc::new(store), provider.clone()).build()?;
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)?;
    Ok(Some(Arc::new(config)))
}

/// Poll the database for the trusted CA set and publish a fresh server config
/// whenever it changes, so a newly provisioned CA takes effect without a
/// restart. A failed read keeps the previous config.
pub fn spawn_root_refresh(
    store: Arc<dyn TenantAuthStore>,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> watch::Receiver<Option<Arc<rustls::ServerConfig>>> {
    let (tx, rx) = watch::channel(None);
    tokio::spawn(async move {
        let mut last: Option<Vec<Vec<u8>>> = None;
        loop {
            match store.trusted_client_roots().await {
                Ok(roots) if last.as_ref() != Some(&roots) => {
                    match build_server_config(&roots, chain.clone(), key.clone_key()) {
                        Ok(config) => {
                            tracing::info!(roots = roots.len(), "trusted client CAs updated");
                            let _ = tx.send(config);
                            last = Some(roots);
                        }
                        Err(e) => tracing::error!(error = %e, "building TLS config failed"),
                    }
                }
                Ok(_) => {}
                Err(e) => tracing::error!(error = %e, "reading trusted client CAs failed"),
            }
            tokio::time::sleep(ROOT_REFRESH_INTERVAL).await;
        }
    });
    rx
}

/// Accept loop: handshake, attribute, serve.
pub async fn serve(
    listener: TcpListener,
    configs: watch::Receiver<Option<Arc<rustls::ServerConfig>>>,
    rpc_config: RpcConfig,
) -> eyre::Result<()> {
    loop {
        let (tcp, peer) = listener.accept().await?;
        let Some(config) = configs.borrow().clone() else {
            tracing::warn!(%peer, "no trusted client CAs configured; dropping connection");
            continue;
        };
        let rpc_config = rpc_config.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(tcp, peer, config, rpc_config).await {
                tracing::warn!(%peer, error = %e, "connection rejected");
            }
        });
    }
}

async fn handle_connection(
    tcp: tokio::net::TcpStream,
    peer: SocketAddr,
    config: Arc<rustls::ServerConfig>,
    mut rpc_config: RpcConfig,
) -> eyre::Result<()> {
    let tls = tokio::time::timeout(HANDSHAKE_TIMEOUT, TlsAcceptor::from(config).accept(tcp))
        .await
        .map_err(|_| eyre::eyre!("TLS handshake timed out"))??;

    let chain = tls.get_ref().1.peer_certificates().unwrap_or_default();
    let tenant = tenant_for_chain(rpc_config.store.as_ref(), chain)
        .await
        .ok_or_else(|| eyre::eyre!("client certificate is not bound to a tenant"))?;

    tracing::info!(%peer, tenant = %tenant.id, identity = %tenant.identity, "serving daemon protocol");
    rpc_config.tenant = tenant;
    spawn_rpc_thread(tls, rpc_config, || async {});
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

    struct Ca {
        cert: rcgen::Certificate,
        issuer: rcgen::Issuer<'static, KeyPair>,
    }

    fn ca(name: &str) -> Ca {
        let mut params = CertificateParams::new(vec![]).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        Ca {
            cert,
            issuer: rcgen::Issuer::new(params, key),
        }
    }

    fn leaf(issuer: &Ca, name: &str) -> (rcgen::Certificate, KeyPair) {
        let mut params = CertificateParams::new(vec![name.to_string()]).unwrap();
        params.use_authority_key_identifier_extension = true;
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &issuer.issuer).unwrap();
        (cert, key)
    }

    #[test]
    fn ca_from_pem_keys_by_ski_and_candidates_match() {
        let root = ca("root");
        let (key_id, der) = ca_from_pem(&root.cert.pem()).unwrap();
        assert_eq!(der, root.cert.der().as_ref());

        let (leaf, _) = leaf(&root, "client");
        // Root omitted: the last cert is the leaf, whose AKI names the root.
        let ids = candidate_key_ids(&[leaf.der().clone()]);
        assert!(ids.contains(&key_id), "{ids:?} should contain {key_id}");
        // Root sent: its own SKI matches.
        let ids = candidate_key_ids(&[leaf.der().clone(), root.cert.der().clone()]);
        assert_eq!(ids.first(), Some(&key_id));
    }

    #[test]
    fn ca_from_pem_rejects_non_ca_and_garbage() {
        let root = ca("root");
        let (leaf, _) = leaf(&root, "client");
        assert!(ca_from_pem(&leaf.pem()).is_err());
        assert!(ca_from_pem("nonsense").is_err());
    }

    #[test]
    fn no_roots_means_no_config() {
        let root = ca("root");
        let (server, server_key) = leaf(&root, "localhost");
        let key = PrivateKeyDer::try_from(server_key.serialize_der()).unwrap();
        let cfg = build_server_config(&[], vec![server.der().clone()], key).unwrap();
        assert!(cfg.is_none());
    }

    #[tokio::test]
    async fn handshake_accepts_bound_ca_and_rejects_others() {
        let trusted = ca("trusted");
        let other = ca("other");
        let (server, server_key) = leaf(&trusted, "localhost");
        let key = PrivateKeyDer::try_from(server_key.serialize_der()).unwrap();
        let config = build_server_config(
            &[trusted.cert.der().as_ref().to_vec()],
            vec![server.der().clone()],
            key,
        )
        .unwrap()
        .unwrap();

        let connect = |issuer: &Ca| {
            let (cert, key) = leaf(issuer, "client");
            let mut roots = RootCertStore::empty();
            roots.add(trusted.cert.der().clone()).unwrap();
            let client = rustls::ClientConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_client_auth_cert(
                    vec![cert.der().clone()],
                    PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
                )
                .unwrap();
            tokio_rustls::TlsConnector::from(Arc::new(client))
        };

        for (issuer, ok) in [(&trusted, true), (&other, false)] {
            let (c, s) = tokio::io::duplex(8192);
            let acceptor = TlsAcceptor::from(config.clone());
            let server = tokio::spawn(async move { acceptor.accept(s).await.map(|_| ()) });
            let name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
            let client = async {
                let mut stream = connect(issuer).connect(name, c).await?;
                // TLS 1.3 reports a client-auth failure on first read.
                tokio::io::AsyncReadExt::read_u8(&mut stream)
                    .await
                    .map(|_| ())
            };
            let client = tokio::time::timeout(Duration::from_secs(5), client)
                .await
                .unwrap();
            let server = server.await.unwrap();
            assert_eq!(server.is_ok(), ok, "server result {server:?}");
            if !ok {
                assert!(client.is_err());
            }
        }
    }
}
