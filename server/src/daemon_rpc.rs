//! Server side of the Lix daemon protocol (Cap'n Proto RPC).
//!
//! Implements the bootstrap sequence a Lix client drives on connect:
//!
//! 1. `Bootstrap.supported()` — advertise protocols
//! 2. `Bootstrap.request(clientInfo, protocol)` — hand back a `LegacyBoot`
//! 3. `LegacyBoot.init(logger)` — take the client's logger capability, hand back
//!    a `LegacyProtocol` plus trust and version
//!
//! Store operations on `LegacyProtocol` dispatch to [`crate::store::Store`].
//! Operations the frontend deliberately does not answer (GC, store maintenance,
//! content-addressed adds, and builds until the job queue exists) are left to
//! capnpc-rust's generated defaults, which report `unimplemented`.

use std::cell::RefCell;
use std::future::Future;
use std::sync::Arc;

use capnp::capability::Rc;

use crate::capnp_ext::{
    DerivedPathReaderExt, ReportExt, StorePathExt, StorePathListBuilderExt, StorePathListReaderExt,
    StorePathReaderExt, UnkeyedValidPathInfoReaderExt, ValidPathInfoBuilderExt,
    ValidPathInfoReaderExt,
};
use crate::daemon_capnp::{bootstrap, legacy_boot, legacy_protocol, protocol};
use crate::jobs::{BuildJob, JobOutcome, JobQueue};
use crate::logging_capnp::log_stream;
use crate::rpc_error;
use crate::store::{ClientOptions, Hash, HashType, MemoryStore, PathInfo, Store, StoreError, Tier};
use crate::store_path::ContentAddress;
use crate::tenant::Tenant;
#[cfg(test)]
use crate::tenant::TenantId;
use crate::tenant_view::TenantView;
use crate::uploads::UploadSigner;
use kubernix_types::{StorePath, System, derivation};
use uuid::Uuid;

/// The identifier Lix asks for is `"lix/legacy/" PACKAGE_VERSION`, so it varies
/// with the client's version.
///
/// We advertise exactly one protocol and accept whatever id the client asks for.
/// That is deliberate: the client's check reads
///
/// ```text
/// if (supportedProtos.size() != 1 && supportedProtos[0].getId() != UNSTABLE_LEGACY_TUNNELED)
/// ```
///
/// — `&&`, not `||` — so advertising a single protocol short-circuits the
/// comparison and it never runs. That makes the frontend version agnostic, but it
/// depends on an upstream bug (NOTES.md item 4). The advertised value is
/// configurable so a fix does not strand us.
pub const DEFAULT_PROTOCOL_ID: &str = "lix/legacy/kubernix";

#[derive(Clone)]
pub struct Config {
    pub protocol_id: String,
    pub version: String,
    /// Whether the authenticated client is allowed privileged operations.
    pub trust: legacy_boot::Trust,
    /// Backing store the protocol is served from.
    pub store: Arc<dyn Store>,
    /// Job queue builds are dispatched to. Without one, builds are refused
    /// explicitly rather than faked.
    pub queue: Option<Arc<JobQueue>>,
    /// System workers are asked to build for.
    pub system: System,
    /// Object store writer. Inputs are staged here for workers to fetch.
    pub uploader: Option<Arc<UploadSigner>>,
    /// Who this connection belongs to.
    ///
    /// Set per connection in [`crate::ssh`] from the identity the client
    /// presented, so a `Config` clone is one client's view of the frontend.
    pub tenant: Tenant,
    /// The store directory a real Nix client prepends to every path it sends
    /// or expects on the wire. [`StorePath`] itself never carries this — see
    /// its doc comment — so every boundary that reads or writes the daemon
    /// protocol needs it in scope.
    pub store_dir: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            protocol_id: DEFAULT_PROTOCOL_ID.to_string(),
            version: concat!("kubernix-", env!("CARGO_PKG_VERSION")).to_string(),
            trust: legacy_boot::Trust::Unknown,
            store: MemoryStore::new(),
            queue: None,
            system: default_system(),
            uploader: None,
            // Overwritten per connection. A default that is nobody in particular
            // keeps a misconfigured caller out of a real tenant's data.
            tenant: Tenant::from_ssh("anonymous", None, false),
            store_dir: "/nix/store".to_string(),
        }
    }
}

pub fn default_system() -> System {
    System::new(std::env::var("KUBERNIX_SYSTEM").unwrap_or_else(|_| "x86_64-linux".to_string()))
}

/// Realise one derived path.
///
/// An *opaque* path is only a request that the path already exist — no build, no
/// worker. That is the call `nix copy --from` makes, and it is the only variant
/// the frontend can serve.
///
pub struct BootstrapImpl {
    config: Config,
}

impl BootstrapImpl {
    pub fn new(config: Config) -> Self {
        Self { config }
    }
}

impl bootstrap::Server for BootstrapImpl {
    fn supported(
        self: Rc<Self>,
        _params: bootstrap::SupportedParams,
        mut results: bootstrap::SupportedResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let protocol_id = self.config.protocol_id.clone();
        async move {
            // Exactly one entry — see DEFAULT_PROTOCOL_ID.
            let mut protocols = results.get().init_protocols(1);
            let mut entry = protocols.reborrow().get(0);
            entry.set_id(protocol_id.as_str());
            entry.set_description("kubernix distributed remote builder");
            tracing::debug!(protocol = %protocol_id, "advertised protocol");
            Ok(())
        }
    }

    fn request(
        self: Rc<Self>,
        params: bootstrap::RequestParams,
        mut results: bootstrap::RequestResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let config = self.config.clone();
        async move {
            let params = params.get()?;
            let client_info = params.get_client_info()?.to_str()?.to_string();
            let requested = params.get_protocol()?.to_str()?.to_string();

            tracing::info!(client = %client_info, protocol = %requested, "bootstrap request");

            // Deliberately lenient about the requested id.
            let boot: legacy_boot::Client = capnp_rpc::new_client(LegacyBootImpl {
                version: config.version,
                trust: config.trust,
                store: config.store,
                queue: config.queue,
                system: config.system,
                uploader: config.uploader,
                tenant: config.tenant,
                store_dir: config.store_dir,
            });

            // LegacyBoot extends Protocol, so it is a valid Protocol capability.
            results.get().set_result(protocol::Client {
                client: boot.client,
            });
            Ok(())
        }
    }
}

pub struct LegacyBootImpl {
    version: String,
    trust: legacy_boot::Trust,
    store: Arc<dyn Store>,
    queue: Option<Arc<JobQueue>>,
    system: System,
    uploader: Option<Arc<UploadSigner>>,
    tenant: Tenant,
    store_dir: String,
}

/// `LegacyBoot extends Protocol`, so the generated `legacy_boot::Server` trait
/// requires `protocol::Server`. `Protocol` declares no methods.
impl protocol::Server for LegacyBootImpl {}

impl legacy_boot::Server for LegacyBootImpl {
    fn init(
        self: Rc<Self>,
        params: legacy_boot::InitParams,
        mut results: legacy_boot::InitResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let version = self.version.clone();
        let trust = self.trust;
        let store = self.store.clone();
        let queue = self.queue.clone();
        let system = self.system.clone();
        let uploader = self.uploader.clone();
        let tenant = self.tenant.clone();
        let store_dir = self.store_dir.clone();
        async move {
            // The client hands us a logger capability. Everything a remote build
            // prints goes back through this, which is why build logs need no side
            // channel: the frontend will pump `kubernix.logs.<job_id>` into it.
            let logger = params.get()?.get_logger()?;

            tracing::debug!(tenant = %tenant.id, "init: registering tenant");
            if let Err(e) = store.register_tenant(&tenant).await {
                tracing::error!(tenant = %tenant.id, error = %e, "could not register tenant");
            }
            tracing::debug!(tenant = %tenant.id, "init: tenant registered");

            let proto: legacy_protocol::Client = capnp_rpc::new_client(LegacyProtocolImpl {
                logger,
                store,
                queue,
                system,
                uploader,
                tenant,
                staged: RefCell::new(Vec::new()),
                store_dir,
            });

            let mut results = results.get();
            results.set_protocol(proto);
            results.set_trust(trust);
            results.set_version(version.as_str());

            tracing::info!(version = %version, "handshake complete");
            Ok(())
        }
    }
}

/// Store operations, dispatched to the [`Store`] trait.
///
/// Methods left to capnpc-rust's generated default answer `unimplemented`; those
/// are called out individually below.
pub struct LegacyProtocolImpl {
    logger: log_stream::Client,
    store: Arc<dyn Store>,
    queue: Option<Arc<JobQueue>>,
    system: System,
    uploader: Option<Arc<UploadSigner>>,
    /// Who this connection belongs to. Every store lookup is scoped by it.
    tenant: Tenant,
    /// Paths this client staged on this connection, in order.
    ///
    /// Nix copies precisely the paths the builder lacks and then asks it to
    /// build, so what arrived on this connection *is* the input set for the
    /// builds that follow. Tracking it per connection avoids shipping every
    /// path the frontend has ever seen.
    staged: RefCell<Vec<crate::jobs::InputRef>>,
    /// The store directory this connection's client prepends to every path.
    store_dir: String,
}

impl LegacyProtocolImpl {
    /// This connection's [`TenantView`] — see its module doc for why this is
    /// the one clone every RPC method below needs, instead of `self.store`
    /// and `self.tenant.id` separately.
    fn tenant_view(&self) -> TenantView {
        TenantView::new(self.store.clone(), self.tenant.id.clone())
    }

    /// Realise one derived path.
    ///
    /// An *opaque* path is only a request that the path already exist — no build, no
    /// worker. That is the call `nix copy --from` makes, and it is the only variant
    /// the frontend can serve.
    ///
    /// A *built* path names a **derivation to realise**, which the frontend cannot
    /// do. Realising a derivation means walking its `inputDrvs`, building each, and
    /// substituting their outputs to reach a resolved derivation; that requires
    /// holding the derivation graph. The frontend holds NAR bytes and metadata, not
    /// derivations — it never receives the `.drv` on this path, so there is nothing
    /// to walk.
    ///
    /// The client already does that walk. `buildDerivation` receives the *resolved*
    /// `BasicDerivation`, which is why building through `--builders` works: local Nix
    /// resolves, then hands us something buildable. Refusing here points at that,
    /// rather than dispatching a job with no derivation in it and failing inside the
    /// worker with a parse error.
    async fn realise(&self, path: &StorePath, built: bool) -> Result<(), capnp::Error> {
        if built {
            tracing::warn!(%path, "refusing buildPaths for a derivation");
            return Err(rpc_error::failed_with_traces(
                format!("kubernix: cannot realise the derivation {path}"),
                &[
                    "the kubernix frontend builds resolved derivations, not derivation graphs"
                        .to_string(),
                    "use it as a remote builder (--builders 'kubernix://…') rather than as a \
                     store (--store kubernix://…)"
                        .to_string(),
                ],
            ));
        }

        if self.is_valid_path_anywhere(path).await {
            Ok(())
        } else {
            Err(rpc_error::failed(format!(
                "kubernix: path not in store and cannot be substituted: {path}"
            )))
        }
    }

    /// Register built outputs so subsequent `queryPathInfo` / `narFromPath` calls
    /// resolve. The worker uploaded the NARs; what it reported is the metadata the
    /// frontend could not compute for itself.
    ///
    /// `expected_outputs` is the same set the job's capability token authorized
    /// (PLAN.md Phase 14) — every reported `store_path` must be in it. All or
    /// nothing: a worker reporting even one path outside its job's verified set
    /// is not a partially-trustworthy outcome, so nothing from the batch is
    /// recorded — see `build_derivation`'s caller, which downgrades the build's
    /// reported status accordingly rather than telling the client it succeeded.
    async fn record_outputs(
        &self,
        infos: &[crate::jobs::OutputInfo],
        expected_outputs: &[(String, StorePath)],
    ) -> Result<(), Vec<StorePath>> {
        let allowed: std::collections::HashSet<&StorePath> =
            expected_outputs.iter().map(|(_, path)| path).collect();

        let bogus: Vec<StorePath> = infos
            .iter()
            .filter(|info| !allowed.contains(&info.store_path))
            .map(|info| info.store_path.clone())
            .collect();
        if !bogus.is_empty() {
            tracing::error!(
                tenant = %self.tenant.id, ?bogus,
                "worker reported outputs outside its job's verified set; refusing to record any of them"
            );
            return Err(bogus);
        }

        for info in infos {
            let mut path_info = PathInfo {
                path: info.store_path.clone(),
                deriver: info.deriver.clone(),
                nar_hash: Hash {
                    hash_type: HashType::Sha256,
                    bytes: info.nar_hash.to_vec(),
                },
                nar_size: info.nar_size,
                references: info.references.clone(),
                registration_time: 0,
                ultimate: true,
                sigs: Vec::new(),
            };
            // A worker we dispatched produced this, so it is `Built` and we are
            // willing to say so.
            self.sign_if_vouchable(&mut path_info, Tier::Built).await;

            if let Err(e) = self
                .tenant_view()
                .record_path(
                    path_info,
                    crate::store::RemoteObject {
                        key: info.key.clone(),
                        file_size: info.file_size,
                        file_hash: info.file_hash,
                    },
                    Tier::Built,
                )
                .await
            {
                tracing::error!(path = %info.store_path, error = %e, "could not record built output");
            }
        }
        Ok(())
    }

    /// Sign a path, if the frontend is willing to vouch for it.
    ///
    /// Signing happens **here, when the path is first recorded**, rather than when a
    /// narinfo is served: the signature becomes part of the row, so it is written
    /// once and deleted with the path it describes instead of needing a lifecycle of
    /// its own.
    ///
    /// A quarantined path is left unsigned, which is the enforcement rather than a
    /// label — `require-sigs` defaults to true, so an unsigned path is inert to any
    /// client that obtains it.
    ///
    /// Failing to sign is not failing to store. An unsigned path is merely unusable
    /// by strict clients; refusing the write would lose data the client already
    /// sent.
    async fn sign_if_vouchable(&self, info: &mut PathInfo, tier: Tier) {
        if !tier.is_vouchable() {
            tracing::debug!(path = %info.path, tier = tier.as_str(), "not signing");
            return;
        }
        let Some(signer) = self.tenant_view().signer().await else {
            tracing::error!(path = %info.path, tenant = %self.tenant.id, "no signing key; storing unsigned");
            return;
        };

        let full_path = info.path.to_full(&self.store_dir);
        let fingerprint = kubernix_signing::Fingerprint {
            path: &full_path,
            nar_hash: &info.nar_hash.bytes,
            nar_size: info.nar_size,
            references: &info.references,
            store_dir: &self.store_dir,
        };
        match signer.sign_path(&fingerprint).await {
            Ok(signature) => {
                if !info.sigs.contains(&signature) {
                    info.sigs.push(signature);
                }
            }
            Err(e) => {
                tracing::error!(path = %info.path, error = %e, "signing failed; storing unsigned")
            }
        }
    }

    /// If the tenant doesn't already have a row for this hash part, but some other
    /// tenant's `Verified` push does, copy it in — signed with the tenant's own key,
    /// never anyone else's. PLAN.md Phase 9c step two.
    ///
    /// Deliberately only reachable from the daemon protocol (this module), never
    /// from the HTTP cache: it writes, and the write path is where writes belong.
    /// A cross-tenant path only becomes visible to a tenant's HTTP cache once its
    /// own daemon-protocol traffic — a build depending on it, `nix copy`, etc. —
    /// has materialized a row for it here, exactly as if that tenant had pushed
    /// it directly.
    async fn resolve_verified(&self, hash_part: &str) -> Option<StorePath> {
        let store = self.tenant_view();
        if let Some(path) = store.query_path_from_hash_part(hash_part).await {
            return Some(path);
        }
        // Cross-tenant by design (see `Store::find_verified_by_hash_part`'s
        // doc comment) — not reachable through `TenantView`, so this one
        // call goes to the raw store instead.
        let (mut info, object) = self.store.find_verified_by_hash_part(hash_part).await?;
        let path = info.path.clone();
        // Drop whichever tenant's signature `find_verified_by_hash_part` happened
        // to return: this is a fresh row for `tenant`, and its only signature
        // should be its own — not a mix that quietly says another tenant also
        // vouched for it.
        info.sigs.clear();
        self.sign_if_vouchable(&mut info, Tier::Verified).await;
        if let Err(e) = store.record_path(info, object, Tier::Verified).await {
            tracing::error!(
                %path, tenant = %self.tenant.id, error = %e,
                "failed to materialize a cross-tenant verified path"
            );
            return None;
        }
        tracing::info!(%path, tenant = %self.tenant.id, "materialized a cross-tenant verified path");
        Some(path)
    }

    /// [`Store::is_valid_path`], falling back to [`Self::resolve_verified`] on a
    /// local miss. The two callers (`isValidPath` itself, and `realise`'s check for
    /// an opaque `buildPaths` dependency) both need this, not just the RPC entry
    /// point — an opaque dependency that only another tenant has pushed is
    /// exactly the case sharing exists for.
    async fn is_valid_path_anywhere(&self, path: &StorePath) -> bool {
        if self.tenant_view().is_valid_path(path).await {
            return true;
        }
        let Some(hash_part) = path.hash_part() else {
            return false;
        };
        self.resolve_verified(hash_part).await.as_ref() == Some(path)
    }
}

impl legacy_protocol::Server for LegacyProtocolImpl {
    fn set_options(
        self: Rc<Self>,
        params: legacy_protocol::SetOptionsParams,
        _results: legacy_protocol::SetOptionsResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let store = self.tenant_view();
        async move {
            let params = params.get()?;
            let overrides = params
                .get_settings_overrides()?
                .get_map()?
                .iter()
                .map(|setting| {
                    Ok((
                        String::from_utf8_lossy(setting.get_name()?).into_owned(),
                        String::from_utf8_lossy(setting.get_value()?).into_owned(),
                    ))
                })
                .collect::<capnp::Result<Vec<_>>>()?;

            store
                .set_options(ClientOptions {
                    keep_failed: params.get_keep_failed(),
                    keep_going: params.get_keep_going(),
                    try_fallback: params.get_try_fallback(),
                    verbosity: params.get_verbosity()? as u16,
                    max_build_jobs: params.get_max_build_jobs(),
                    build_cores: params.get_build_cores(),
                    use_substitutes: params.get_use_substitutes(),
                    overrides,
                })
                .await;
            Ok(())
        }
    }

    fn is_valid_path(
        self: Rc<Self>,
        params: legacy_protocol::IsValidPathParams,
        mut results: legacy_protocol::IsValidPathResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let store_dir = self.store_dir.clone();
        let this = self.clone();
        async move {
            let path = params.get()?.get_path()?.to_store_path(&store_dir)?;
            results
                .get()
                .set_result(this.is_valid_path_anywhere(&path).await);
            Ok(())
        }
    }

    fn query_valid_paths(
        self: Rc<Self>,
        params: legacy_protocol::QueryValidPathsParams,
        mut results: legacy_protocol::QueryValidPathsResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let store = self.tenant_view();
        let store_dir = self.store_dir.clone();
        let this = self.clone();
        async move {
            let paths = params.get()?.get_paths()?.to_store_paths(&store_dir)?;
            let mut valid = store.query_valid_paths(&paths).await;
            for path in &paths {
                if valid.contains(path) {
                    continue;
                }
                let Some(hash_part) = path.hash_part() else {
                    continue;
                };
                if this.resolve_verified(hash_part).await.as_ref() == Some(path) {
                    valid.push(path.clone());
                }
            }
            results
                .get()
                .init_result(valid.len() as u32)
                .write_store_paths(&valid, &store_dir);
            Ok(())
        }
    }

    fn query_all_valid_paths(
        self: Rc<Self>,
        _params: legacy_protocol::QueryAllValidPathsParams,
        mut results: legacy_protocol::QueryAllValidPathsResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let store = self.tenant_view();
        let store_dir = self.store_dir.clone();
        async move {
            let paths = store.query_all_valid_paths().await;
            results
                .get()
                .init_result(paths.len() as u32)
                .write_store_paths(&paths, &store_dir);
            Ok(())
        }
    }

    fn query_path_info(
        self: Rc<Self>,
        params: legacy_protocol::QueryPathInfoParams,
        mut results: legacy_protocol::QueryPathInfoResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let store = self.tenant_view();
        let store_dir = self.store_dir.clone();
        let this = self.clone();
        async move {
            let path = params.get()?.get_path()?.to_store_path(&store_dir)?;
            let mut result = results.get().init_result();
            let mut info = store.query_path_info(&path).await;
            if info.is_none()
                && let Some(hash_part) = path.hash_part()
                && this.resolve_verified(hash_part).await.is_some()
            {
                info = store.query_path_info(&path).await;
            }
            match info {
                Some(info) => {
                    // A narinfo is the earlier half of "fetch metadata, then
                    // fetch bytes" — PLAN.md Phase 12 counts it as an access
                    // in its own right so a path is not collected in the
                    // window between the two.
                    store.record_access(&path).await;
                    result.init_some().write_path_info(&info, &store_dir)
                }
                None => result.set_none(()),
            }
            Ok(())
        }
    }

    fn query_path_from_hash_part(
        self: Rc<Self>,
        params: legacy_protocol::QueryPathFromHashPartParams,
        mut results: legacy_protocol::QueryPathFromHashPartResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let store_dir = self.store_dir.clone();
        let this = self.clone();
        async move {
            let hash_part = String::from_utf8_lossy(params.get()?.get_hash_part()?).into_owned();
            let mut result = results.get().init_result();
            match this.resolve_verified(&hash_part).await {
                Some(path) => result
                    .init_some()
                    .set_raw(path.to_full(&store_dir).as_bytes()),
                None => result.set_none(()),
            }
            Ok(())
        }
    }

    fn query_referrers(
        self: Rc<Self>,
        params: legacy_protocol::QueryReferrersParams,
        mut results: legacy_protocol::QueryReferrersResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let store = self.tenant_view();
        let store_dir = self.store_dir.clone();
        async move {
            let path = params.get()?.get_path()?.to_store_path(&store_dir)?;
            let referrers = store.query_referrers(&path).await;
            results
                .get()
                .init_result(referrers.len() as u32)
                .write_store_paths(&referrers, &store_dir);
            Ok(())
        }
    }

    fn query_substitutable_paths(
        self: Rc<Self>,
        params: legacy_protocol::QuerySubstitutablePathsParams,
        mut results: legacy_protocol::QuerySubstitutablePathsResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let store = self.tenant_view();
        let store_dir = self.store_dir.clone();
        async move {
            let paths = params.get()?.get_paths()?.to_store_paths(&store_dir)?;
            let subs = store.query_substitutable_paths(&paths).await;
            results
                .get()
                .init_result(subs.len() as u32)
                .write_store_paths(&subs, &store_dir);
            Ok(())
        }
    }

    async fn query_valid_derivers(
        self: Rc<Self>,
        _params: legacy_protocol::QueryValidDeriversParams,
        mut results: legacy_protocol::QueryValidDeriversResults,
    ) -> Result<(), capnp::Error> {
        // Derivers are tracked per path in PathInfo, not indexed in reverse.
        results.get().init_result(0);
        Ok(())
    }

    fn query_missing(
        self: Rc<Self>,
        params: legacy_protocol::QueryMissingParams,
        mut results: legacy_protocol::QueryMissingResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let store = self.tenant_view();
        let store_dir = self.store_dir.clone();
        async move {
            // DerivedPath is a union of opaque/built; both name a store path.
            let mut targets = Vec::new();
            for target in params.get()?.get_targets()?.iter() {
                use crate::daemon_capnp::legacy_protocol::derived_path;
                match target.get_raw().which()? {
                    derived_path::raw::Which::Opaque(opaque) => {
                        targets.push(opaque?.get_path()?.to_store_path(&store_dir)?)
                    }
                    derived_path::raw::Which::Built(built) => targets.push(
                        built?
                            .get_drv_path()?
                            .get_path()?
                            .to_store_path(&store_dir)?,
                    ),
                }
            }

            let missing = store.query_missing(&targets).await;
            let mut result = results.get().init_result();
            result
                .reborrow()
                .init_will_build(missing.will_build.len() as u32)
                .write_store_paths(&missing.will_build, &store_dir);
            result
                .reborrow()
                .init_will_substitute(missing.will_substitute.len() as u32)
                .write_store_paths(&missing.will_substitute, &store_dir);
            result
                .reborrow()
                .init_unknown(missing.unknown.len() as u32)
                .write_store_paths(&missing.unknown, &store_dir);
            result.set_download_size(missing.download_size);
            result.set_nar_size(missing.nar_size);
            Ok(())
        }
    }

    fn add_signatures(
        self: Rc<Self>,
        params: legacy_protocol::AddSignaturesParams,
        _results: legacy_protocol::AddSignaturesResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let store = self.tenant_view();
        let store_dir = self.store_dir.clone();
        async move {
            let params = params.get()?;
            let path = params.get_path()?.to_store_path(&store_dir)?;
            let sigs = params
                .get_signatures()?
                .iter()
                .map(|s| Ok(String::from_utf8_lossy(s?).into_owned()))
                .collect::<capnp::Result<Vec<_>>>()?;
            store
                .add_signatures(&path, sigs)
                .await
                .map_err(capnp::Error::from)?;
            Ok(())
        }
    }

    /// Temp roots are a GC concept. The frontend does not GC on the client's
    /// behalf, so these are accepted and ignored rather than refused — refusing
    /// would abort otherwise valid client operations.
    async fn add_temp_root(
        self: Rc<Self>,
        _params: legacy_protocol::AddTempRootParams,
        _results: legacy_protocol::AddTempRootResults,
    ) -> Result<(), capnp::Error> {
        Ok(())
    }

    async fn add_indirect_root(
        self: Rc<Self>,
        _params: legacy_protocol::AddIndirectRootParams,
        _results: legacy_protocol::AddIndirectRootResults,
    ) -> Result<(), capnp::Error> {
        Ok(())
    }

    /// Accept a NAR the client already has `ValidPathInfo` for. This is how a
    /// client uploads a closure to the builder.
    fn add_to_store_nar(
        self: Rc<Self>,
        params: legacy_protocol::AddToStoreNarParams,
        mut results: legacy_protocol::AddToStoreNarResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let uploader = self.uploader.clone();
        let staged = self.clone();
        async move {
            let wire_info = params.get()?.get_info()?;
            let info = wire_info.to_path_info(&staged.store_dir)?;
            let ca = wire_info
                .get_unkeyed_valid_path_info()?
                .to_content_address()?;
            tracing::debug!(path = %info.path, content_addressed = ca.is_some(), "receiving nar");
            let sink: legacy_protocol::stream::Client =
                capnp_rpc::new_client(NarSink::new(uploader, info, ca, staged));
            results.get().set_result(sink);
            Ok(())
        }
    }

    /// Stream a stored NAR back into the client-supplied `Stream` capability.
    fn nar_from_path(
        self: Rc<Self>,
        params: legacy_protocol::NarFromPathParams,
        _results: legacy_protocol::NarFromPathResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let store = self.tenant_view();
        let uploader = self.uploader.clone();
        let store_dir = self.store_dir.clone();
        async move {
            let params = params.get()?;
            let path = params.get_path()?.to_store_path(&store_dir)?;
            let into = params.get_into()?;

            // Every path's bytes are in the object store, whichever route it
            // arrived by, so there is one way to serve them.
            let Some(remote) = store.output_object(&path).await else {
                return Err(StoreError::NotFound(path.to_string()).into());
            };
            // The byte fetch itself, not just the narinfo lookup that usually
            // precedes it — PLAN.md Phase 12.
            store.record_access(&path).await;
            let uploader = uploader.as_ref().ok_or_else(|| {
                rpc_error::failed(format!(
                    "kubernix: {path} is in the object store but no S3 client is configured"
                ))
            })?;

            tracing::debug!(%path, key = %remote.key, "streaming from the object store");
            let mut reader = uploader
                .get_object_reader(&remote.key)
                .await
                .map_err(|e| e.into_capnp_error("fetching a store path"))?;

            // Fetched, decompressed and forwarded a chunk at a time. Nothing
            // here scales with the size of the NAR — the old version held the
            // compressed object *and* the whole NAR in memory at once.
            //
            // `feed` is a capnp streaming method, so awaiting each send gives
            // real backpressure rather than a queue that grows to fit the file.
            // The capnp capability is `!Send` and the S3 reader is `Send`;
            // awaiting a `Send` future from a `!Send` task is fine (NOTES.md
            // item 7), so this needs no extra threading.
            const CHUNK: usize = 64 * 1024;
            let mut decoder = zstd::stream::write::Decoder::new(Vec::new())
                .map_err(|e| eyre::Report::new(e).into_capnp_error("decompressing a store path"))?;
            let mut buf = vec![0u8; CHUNK];
            let mut sent: u64 = 0;

            loop {
                let read = tokio::io::AsyncReadExt::read(&mut reader, &mut buf)
                    .await
                    .map_err(|e| eyre::Report::new(e).into_capnp_error("reading a store path"))?;
                if read == 0 {
                    break;
                }
                std::io::Write::write_all(&mut decoder, &buf[..read]).map_err(|e| {
                    eyre::Report::new(e).into_capnp_error("decompressing a store path")
                })?;
                let decoded = std::mem::take(decoder.get_mut());
                if !decoded.is_empty() {
                    sent += decoded.len() as u64;
                    let mut request = into.feed_request();
                    request.get().set_raw(&decoded);
                    request.send().await?;
                }
            }

            std::io::Write::flush(&mut decoder)
                .map_err(|e| eyre::Report::new(e).into_capnp_error("decompressing a store path"))?;
            let decoded = std::mem::take(decoder.get_mut());
            if !decoded.is_empty() {
                sent += decoded.len() as u64;
                let mut request = into.feed_request();
                request.get().set_raw(&decoded);
                request.send().await?;
            }

            tracing::debug!(%path, size = sent, "sent nar");
            into.finalize_request().send().promise.await?;
            Ok(())
        }
    }

    /// Realise paths. A `DerivedPath::Opaque` is just "ensure this path exists",
    /// which for anything already in the store needs no worker — this is the path
    /// `nix copy --from` takes. A `DerivedPath::Built` names a derivation, which
    /// the frontend cannot realise; see [`LegacyProtocolImpl::realise`].
    fn build_paths(
        self: Rc<Self>,
        params: legacy_protocol::BuildPathsParams,
        _results: legacy_protocol::BuildPathsResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let store_dir = self.store_dir.clone();
        let this = self.clone();
        async move {
            for target in params.get()?.get_paths()?.iter() {
                let (path, built) = target.resolve_target(&store_dir)?;
                this.realise(&path, built).await?;
            }
            Ok(())
        }
    }

    fn build_paths_with_result(
        self: Rc<Self>,
        params: legacy_protocol::BuildPathsWithResultParams,
        mut results: legacy_protocol::BuildPathsWithResultResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let store_dir = self.store_dir.clone();
        let this = self.clone();
        async move {
            let targets = params.get()?.get_paths()?;
            let mut resolved = Vec::new();
            for target in targets.iter() {
                let (path, built) = target.resolve_target(&store_dir)?;
                this.realise(&path, built).await?;
                resolved.push(path);
            }

            let mut out = results.get().init_result(resolved.len() as u32);
            for (i, path) in resolved.iter().enumerate() {
                let mut keyed = out.reborrow().get(i as u32);
                keyed
                    .reborrow()
                    .init_path()
                    .init_raw()
                    .init_opaque()
                    .init_path()
                    .set_raw(path.to_full(&store_dir).as_bytes());
                let mut result = keyed.init_result();
                // Only opaque paths reach here, and `realise` has already
                // confirmed each one is valid — so nothing was built.
                result.set_status(legacy_protocol::build_result::Status::AlreadyValid);
                result.set_times_built(0);
                result.set_is_non_deterministic(false);
            }
            Ok(())
        }
    }

    // Deliberately left to the generated `unimplemented` default:
    //
    //   add_to_store           - needs Nix content-addressed path computation
    //   query_derivation_output_map
    //   ensure_path, optimise_store, verify_store, collect_garbage, find_roots
    //                          - GC and store maintenance are not the frontend's job
    //   add_build_log          - logs are archived by the worker, not pushed here

    /// Dispatch a build to the worker pool and relay its log to the client.
    fn build_derivation(
        self: Rc<Self>,
        params: legacy_protocol::BuildDerivationParams,
        mut results: legacy_protocol::BuildDerivationResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let queue = self.queue.clone();
        let logger = self.logger.clone();
        let system = self.system.clone();
        let store = self.tenant_view();
        let staged = self.staged.borrow().clone();
        let store_dir = self.store_dir.clone();
        let this = self.clone();
        async move {
            let tenant = store.tenant().clone();
            let params = params.get()?;
            let path = params.get_path()?.to_store_path(&store_dir)?;
            let drv = params.get_drv()?.to_vec();

            // Recompute, rather than trust, every fixed-output path this
            // derivation declares — mirroring how a real Nix daemon handles
            // `CAFixed` outputs. Input-addressed outputs (`algo` empty) are not
            // checked here: the resolved form this server receives cannot
            // reproduce `hashDerivationModulo`, and real Nix does not attempt
            // it at this boundary either (PLAN.md Phase 14). Either way, what
            // this loop settles on for each output is exactly what the job's
            // capability token will authorize below.
            let parsed = derivation::parse(&drv, &store_dir)
                .map_err(|e| rpc_error::failed(format!("kubernix: malformed derivation: {e}")))?;
            let drv_name = path.derivation_name();
            let mut expected_outputs = Vec::with_capacity(parsed.outputs.len());
            for output in &parsed.outputs {
                let verified_path = if output.algo.is_empty() {
                    output.path.clone()
                } else {
                    crate::store_path::StoreDir(&store_dir)
                        .verify_fixed_output(drv_name, &output.name, &output.algo, &output.hash)
                        .ok_or_else(|| {
                            tracing::warn!(
                                %path, output = %output.name,
                                "refusing a fixed output whose declared path does not match its \
                                 content address"
                            );
                            rpc_error::failed(format!(
                                "kubernix: fixed output '{}' of {path} does not match its \
                                 declared content address",
                                output.name
                            ))
                        })?
                };
                expected_outputs.push((output.name.clone(), verified_path));
            }

            let Some(queue) = queue else {
                tracing::warn!(%path, "build requested but no job queue is configured");
                return Err(rpc_error::unimplemented(format!(
                    "kubernix: build of {path} not dispatched - no NATS job queue configured"
                )));
            };

            let job_id = Uuid::new_v4();

            // Minted here rather than left implicit: this is the one place
            // that knows both the tenant this connection has authenticated as
            // and the output paths just independently verified above, so it
            // is the only place that can state the job's capability honestly.
            let capability = crate::capability::Capability {
                job_id,
                tenant: tenant.clone(),
                derivation_path: path.clone(),
                expected_outputs,
            };
            // Not tenant-scoped — see `TenantView`'s module doc — so this
            // one call goes through the raw store rather than `store`.
            let (kid, secret) = store.store().current_capability_secret().await;
            let token = capability.sign(kid, &secret);

            let job = BuildJob {
                job_id,
                derivation_path: path.clone(),
                system: system.clone(),
                drv,
                inputs: staged,
                tenant: tenant.clone(),
                token,
            };

            let outcome = queue
                .dispatch(job, &logger)
                .await
                .map_err(|e| e.into_capnp_error("dispatching the build"))?;

            store
                .record_job_outcome(job_id, &path, system.as_str(), &outcome)
                .await;

            let mut result = results.get().init_result();
            match outcome {
                JobOutcome::Completed {
                    outputs,
                    infos,
                    log_key,
                } => {
                    match this
                        .record_outputs(&infos, &capability.expected_outputs)
                        .await
                    {
                        Ok(()) => {
                            tracing::info!(%path, ?outputs, %log_key, "build succeeded");
                            result.set_status(legacy_protocol::build_result::Status::Built);
                        }
                        Err(bogus) => {
                            // The build ran, but reported outputs this job was
                            // never dispatched to produce — nothing was
                            // recorded, so the client must not be told it
                            // succeeded (PLAN.md Phase 14).
                            tracing::warn!(%path, ?bogus, %log_key, "build outcome refused: unverified outputs");
                            result.set_status(
                                legacy_protocol::build_result::Status::PermanentFailure,
                            );
                            result.set_error_msg(
                                format!(
                                    "kubernix: worker reported output(s) outside this job's \
                                     verified set: {}",
                                    bogus
                                        .iter()
                                        .map(StorePath::to_string)
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                )
                                .as_bytes(),
                            );
                        }
                    }
                }
                JobOutcome::Failed { message, log_key } => {
                    tracing::warn!(%path, %message, %log_key, "build failed");
                    result.set_status(legacy_protocol::build_result::Status::PermanentFailure);
                    result.set_error_msg(message.as_bytes());
                }
            }
            result.set_times_built(1);
            result.set_is_non_deterministic(false);
            Ok(())
        }
    }
}

/// Accumulates a streamed NAR, committing it on `finalize`.
///
/// A path arriving here is an *input*: the client is staging its closure so a
/// worker can build against it. It is therefore also pushed to the object store
/// in Nix export format, which is what a worker can `nix-store --import`.
struct NarSink {
    uploader: Option<Arc<UploadSigner>>,
    info: PathInfo,
    /// The content address the client attached, if any. `None` means the path is
    /// input-addressed and therefore unverifiable.
    ca: Option<ContentAddress>,
    buffer: RefCell<Vec<u8>>,
    /// The connection that received this path, so the staged input is attached
    /// to the builds that follow on it. Also where the store lives — see
    /// `Self::tenant_view` — so no separate `store` field is needed here.
    connection: Rc<LegacyProtocolImpl>,
}

impl NarSink {
    fn new(
        uploader: Option<Arc<UploadSigner>>,
        info: PathInfo,
        ca: Option<ContentAddress>,
        connection: Rc<LegacyProtocolImpl>,
    ) -> Self {
        Self {
            uploader,
            info,
            ca,
            buffer: RefCell::new(Vec::new()),
            connection,
        }
    }

    fn tenant_view(&self) -> TenantView {
        self.connection.tenant_view()
    }
}

impl legacy_protocol::stream::Server for NarSink {
    async fn feed(
        self: Rc<Self>,
        params: legacy_protocol::stream::FeedParams,
    ) -> Result<(), capnp::Error> {
        let raw = params.get()?.get_raw()?;
        self.buffer.borrow_mut().extend_from_slice(raw);
        Ok(())
    }

    async fn finalize(
        self: Rc<Self>,
        _params: legacy_protocol::stream::FinalizeParams,
        _results: legacy_protocol::stream::FinalizeResults,
    ) -> Result<(), capnp::Error> {
        let nar = std::mem::take(&mut *self.buffer.borrow_mut());

        // Decide what the frontend is willing to say about this path before
        // recording it. A content address can be checked against the bytes;
        // anything else is the client's word, and is quarantined rather than
        // refused so that ordinary `nix copy` of a build closure keeps
        // working. See PLAN.md Phase 9.
        let tier = match &self.ca {
            Some(ca) => {
                match crate::store_path::StoreDir(&self.connection.store_dir).verify(
                    &self.info.path,
                    ca,
                    &self.info.references,
                    &nar,
                ) {
                    Ok(()) => Tier::Verified,
                    // A *failed* check is different from an absent one: the
                    // client asserted something checkable and it was false,
                    // which is either corruption or an attempt to register
                    // content at a path that is not its own.
                    Err(rejection) => {
                        tracing::warn!(
                            path = %self.info.path,
                            tenant = %self.connection.tenant.id,
                            %rejection,
                            "refusing a push whose content address does not check out"
                        );
                        return Err(rpc_error::failed_with_traces(
                            format!("kubernix: refusing {}: {rejection}", self.info.path),
                            &[
                                "the frontend verifies content-addressed paths against their \
                               bytes"
                                    .to_string(),
                            ],
                        ));
                    }
                }
            }
            None => Tier::Quarantined,
        };

        // A path we already vouch for must not be demoted by someone pushing
        // it back at us. Nix does exactly that: it builds a dependency
        // remotely, copies it home, then pushes it up again as an input for
        // the next build. Taking the push at face value would replace a
        // `built` path with a `quarantined` one, discard its signature, and
        // make the cache start 404ing something it had been serving — while
        // storing a second copy of identical bytes.
        //
        // Keeping what we have is safe precisely because the existing tier
        // is the *stronger* claim: we derived or produced that path, so a
        // client's assertion about it adds nothing.
        let store = self.tenant_view();
        if let Some(existing) = store.tier(&self.info.path).await
            && existing.is_vouchable()
            && !matches!(tier, Tier::Verified)
        {
            tracing::debug!(
                path = %self.info.path,
                tier = existing.as_str(),
                "already vouched for; keeping it rather than accepting the push"
            );
            // Resolved before the borrow below is taken, not inline in the
            // `InputRef` literal — holding `staged`'s `RefCell` guard across
            // this `.await` would risk a panic if anything else on this
            // single-threaded connection tries to borrow it while suspended.
            let key = store
                .output_object(&self.info.path)
                .await
                .map(|o| o.key)
                .unwrap_or_default();
            self.connection
                .staged
                .borrow_mut()
                .push(crate::jobs::InputRef {
                    store_path: self.info.path.clone(),
                    key,
                    references: self.info.references.clone(),
                    deriver: self.info.deriver.clone().unwrap_or_default(),
                });
            return Ok(());
        }

        // The bytes go to the object store, never into the database. One
        // representation of a path exists — a compressed bare NAR — and it
        // is the same one a worker fetches, `narFromPath` streams, and the
        // binary cache serves. See PLAN.md Phase 10b.
        let Some(uploader) = self.uploader.clone() else {
            return Err(rpc_error::failed(
                "kubernix: no object store configured; cannot accept a path",
            ));
        };
        let Some(key) = crate::store::nar_key(store.tenant(), tier, &self.info.path) else {
            return Err(rpc_error::failed(format!(
                "kubernix: not a store path: {}",
                self.info.path
            )));
        };

        let compressed = zstd::stream::encode_all(nar.as_slice(), 3)
            .map_err(|e| eyre::Report::new(e).into_capnp_error("compressing a pushed path"))?;
        let file_size = compressed.len() as u64;
        let file_hash = <sha2::Sha256 as sha2::Digest>::digest(&compressed);

        // A `Verified` key carries no tenant prefix (PLAN.md Phase 9c), so
        // another tenant pushing the same content may already have put
        // these exact bytes at this exact key. Recomputing and
        // re-uploading them would be correct but wasteful — this is the
        // saving the sharing exists for. `Built`/`Quarantined` keys are
        // tenant-scoped and effectively never collide, so they always
        // upload as before.
        // Not tenant-scoped — see `TenantView`'s module doc — so this goes
        // through the raw store rather than `store`.
        let already_there =
            matches!(tier, Tier::Verified) && self.connection.store.object_known(&key).await;

        if already_there {
            tracing::debug!(
                path = %self.info.path,
                %key,
                "content already in the object store under this shared key; skipping upload"
            );
        } else {
            tracing::debug!(
                path = %self.info.path,
                %key,
                nar_bytes = nar.len(),
                object_bytes = file_size,
                "storing pushed path in the object store"
            );

            // Uploaded before the row is written, so a failure here cannot
            // leave a path registered with no bytes behind it.
            uploader
                .put_object(&key, compressed)
                .await
                .map_err(|e| e.into_capnp_error("uploading a pushed path"))?;
        }

        // Signed here, on the way in, so the signature lands in the same row
        // as the path. A verified push is one we derived ourselves, so it is
        // ours to vouch for; a quarantined one is left unsigned.
        let mut info = self.info.clone();
        self.connection.sign_if_vouchable(&mut info, tier).await;

        let references = info.references.clone();
        let deriver = info.deriver.clone().unwrap_or_default();

        store
            .record_path(
                info,
                crate::store::RemoteObject {
                    key: key.clone(),
                    file_size,
                    file_hash,
                },
                tier,
            )
            .await
            .map_err(capnp::Error::from)?;

        // A bare NAR cannot be imported on its own, so the references and
        // deriver travel with the key rather than being stored a second time
        // in export form.
        self.connection
            .staged
            .borrow_mut()
            .push(crate::jobs::InputRef {
                store_path: self.info.path.clone(),
                key,
                references,
                deriver,
            });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{Hash, HashType, MemoryStore, PathInfo};

    const STORE_DIR: &str = "/nix/store";
    const DRV: &str = "00000000000000000000000000000000-thing.drv";
    const OUT: &str = "11111111111111111111111111111111-thing";

    /// A `log_stream` capability nothing in these tests ever calls. Every
    /// method already defaults to capnpc-rust's generated `unimplemented`
    /// answer, so this exists only to give [`LegacyProtocolImpl::for_test`]
    /// something to put in the `logger` field.
    struct FakeLogger;
    impl log_stream::Server for FakeLogger {}

    impl LegacyProtocolImpl {
        /// A connection with no real client behind it, for exercising the
        /// store/tenant/store_dir-scoped methods directly rather than through
        /// the capnp RPC surface.
        fn for_test(store: Arc<dyn Store>, tenant: TenantId) -> Self {
            Self {
                logger: capnp_rpc::new_client(FakeLogger),
                store,
                queue: None,
                system: default_system(),
                uploader: None,
                tenant: Tenant {
                    id: tenant,
                    identity: "test".to_string(),
                    verified: false,
                },
                staged: RefCell::new(Vec::new()),
                store_dir: STORE_DIR.to_string(),
            }
        }
    }

    fn info(path: &str) -> PathInfo {
        PathInfo {
            path: StorePath::new(path),
            deriver: None,
            nar_hash: Hash {
                hash_type: HashType::Sha256,
                bytes: vec![0; 32],
            },
            nar_size: 0,
            references: Vec::new(),
            registration_time: 0,
            ultimate: false,
            sigs: Vec::new(),
        }
    }

    fn tenant() -> crate::tenant::TenantId {
        crate::tenant::Tenant::from_ssh("alice", None, false).id
    }

    fn object(key: &str) -> crate::store::RemoteObject {
        crate::store::RemoteObject {
            key: kubernix_types::ObjectKey::new(key),
            file_size: 0,
            file_hash: Default::default(),
        }
    }

    /// Proof of the safety split `to_client_error` exists for: an internal
    /// error's text must never reach the client, a domain error's must pass
    /// through untouched, and an explicit [`kubernix_types::errors::Public`]
    /// marking must survive exactly as written.
    mod to_client_error_tests {
        use super::*;
        use kubernix_types::errors::Public;

        fn message_of(error: &capnp::Error) -> String {
            rpc_error::decode(&error.extra)
                .expect("should decode as a v1 structured error")
                .1
        }

        #[test]
        fn an_opaque_internal_error_is_not_leaked() {
            let io_err = std::io::Error::other(
                "AccessDenied: request id AKIAABCDEF1234567890 is not authorized",
            );
            let report = eyre::Report::new(io_err).wrap_err("fetching an object");
            let error = report.into_capnp_error("fetching a store path");

            let message = message_of(&error);
            assert!(
                !message.contains("AccessDenied") && !message.contains("AKIAABCDEF1234567890"),
                "internal detail leaked into a client-facing message: {message}"
            );
            assert!(message.contains("fetching a store path"));
        }

        #[test]
        fn a_public_marked_cause_passes_through_verbatim() {
            let report: eyre::Report =
                Public::new("could not fetch this path; see server logs").into();
            let error = report.into_capnp_error("fetching a store path");
            assert_eq!(
                message_of(&error),
                "could not fetch this path; see server logs"
            );
        }

        #[test]
        fn a_store_error_passes_through_as_its_own_display() {
            let report = eyre::Report::new(StoreError::NotFound(OUT.to_string()));
            let error = report.into_capnp_error("looking up a path");
            assert_eq!(
                message_of(&error),
                StoreError::NotFound(OUT.to_string()).to_string()
            );
        }
    }

    #[tokio::test]
    async fn an_opaque_path_in_the_store_needs_no_build() {
        let store = MemoryStore::new();
        let t = tenant();
        store
            .record_path(&t, info(OUT), object("k"), Tier::Verified)
            .await
            .unwrap();
        assert!(
            LegacyProtocolImpl::for_test(store.clone(), t)
                .realise(&StorePath::new(OUT), false)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn an_opaque_path_that_is_missing_is_an_error() {
        let store = MemoryStore::new();
        let error = LegacyProtocolImpl::for_test(store.clone(), tenant())
            .realise(&StorePath::new(OUT), false)
            .await
            .expect_err("should refuse");
        assert!(error.extra.contains("path not in store"));
    }

    #[tokio::test]
    async fn a_derivation_is_refused_rather_than_dispatched() {
        // Regression: this used to dispatch a job with an empty `drv`, which
        // reached the worker and died there with a parse error. The frontend has
        // no derivation to send, so it must say so here.
        let store = MemoryStore::new();
        let error = LegacyProtocolImpl::for_test(store.clone(), tenant())
            .realise(&StorePath::new(DRV), true)
            .await
            .expect_err("should refuse");

        // Decode rather than string-match: the hint lives in a trace, which the
        // client only sees after unpacking the payload.
        let (_, message, traces) = rpc_error::decode(error.extra.as_str()).expect("should decode");
        assert!(message.contains(DRV), "the message should name the path");
        assert!(
            traces.iter().any(|t| t.contains("--builders")),
            "the traces should point at the form that works, got {traces:?}"
        );
    }

    fn bob() -> crate::tenant::TenantId {
        crate::tenant::Tenant::from_ssh("bob", None, false).id
    }

    // PLAN.md Phase 9c step two. `tenant()` (defined above) is reused as
    // "alice" — the first, pushing tenant.

    #[tokio::test]
    async fn resolve_verified_materializes_a_copy_signed_with_the_caller_s_own_key() {
        let store = MemoryStore::new();
        let (alice, bob) = (tenant(), bob());

        let mut pushed = info(OUT);
        LegacyProtocolImpl::for_test(store.clone(), alice.clone())
            .sign_if_vouchable(&mut pushed, Tier::Verified)
            .await;
        store
            .record_path(&alice, pushed, object("k"), Tier::Verified)
            .await
            .unwrap();

        // Bob never pushed or built this path.
        assert!(!store.is_valid_path(&bob, &StorePath::new(OUT)).await);

        let hash_part = StorePath::new(OUT).hash_part().unwrap().to_string();
        let resolved = LegacyProtocolImpl::for_test(store.clone(), bob.clone())
            .resolve_verified(&hash_part)
            .await;
        assert_eq!(resolved, Some(StorePath::new(OUT)));

        // Bob now has his own row, not a view onto Alice's.
        assert!(store.is_valid_path(&bob, &StorePath::new(OUT)).await);
        let bob_info = store
            .query_path_info(&bob, &StorePath::new(OUT))
            .await
            .expect("materialized");
        let alice_info = store
            .query_path_info(&alice, &StorePath::new(OUT))
            .await
            .expect("still there");

        assert_eq!(bob_info.sigs.len(), 1, "signed exactly once, by bob");
        assert_ne!(
            bob_info.sigs, alice_info.sigs,
            "each tenant's signature comes from its own key, even over identical content"
        );
    }

    #[tokio::test]
    async fn resolve_verified_finds_nothing_for_a_path_nobody_has() {
        let store = MemoryStore::new();
        let hash_part = StorePath::new(OUT).hash_part().unwrap().to_string();
        assert_eq!(
            LegacyProtocolImpl::for_test(store.clone(), bob())
                .resolve_verified(&hash_part)
                .await,
            None
        );
    }

    #[tokio::test]
    async fn is_valid_path_anywhere_falls_back_to_another_tenant_s_verified_push() {
        let store = MemoryStore::new();
        let (alice, bob) = (tenant(), bob());
        store
            .record_path(&alice, info(OUT), object("k"), Tier::Verified)
            .await
            .unwrap();

        assert!(
            LegacyProtocolImpl::for_test(store.clone(), bob)
                .is_valid_path_anywhere(&StorePath::new(OUT))
                .await
        );
    }

    #[tokio::test]
    async fn is_valid_path_anywhere_does_not_leak_built_or_quarantined_paths() {
        let store = MemoryStore::new();
        let (alice, bob) = (tenant(), bob());
        store
            .record_path(&alice, info(OUT), object("k"), Tier::Built)
            .await
            .unwrap();

        // Only `Verified` is provably identical across tenants; `Built` stays
        // strictly per-tenant, unaffected by this fallback.
        assert!(
            !LegacyProtocolImpl::for_test(store.clone(), bob)
                .is_valid_path_anywhere(&StorePath::new(OUT))
                .await
        );
    }

    #[tokio::test]
    async fn an_opaque_dependency_only_another_tenant_pushed_still_builds() {
        // Mirrors the Phase 9 "quarantine does not break builds" case: a build
        // depending on a path only a different tenant has needs `realise` (what
        // `buildPaths`/`buildPathsWithResult` use for opaque paths) to resolve
        // it, not just `isValidPath`.
        let store = MemoryStore::new();
        let (alice, bob) = (tenant(), bob());
        store
            .record_path(&alice, info(OUT), object("k"), Tier::Verified)
            .await
            .unwrap();

        assert!(
            LegacyProtocolImpl::for_test(store.clone(), bob)
                .realise(&StorePath::new(OUT), false)
                .await
                .is_ok()
        );
    }

    fn output_info(path: &str, key: &str) -> crate::jobs::OutputInfo {
        crate::jobs::OutputInfo {
            store_path: StorePath::new(path),
            nar_hash: Default::default(),
            nar_size: 0,
            file_hash: Default::default(),
            file_size: 0,
            key: kubernix_types::ObjectKey::new(key),
            compression: "zstd".to_string(),
            references: Vec::new(),
            deriver: None,
        }
    }

    const OTHER: &str = "22222222222222222222222222222222-unrelated";

    #[tokio::test]
    async fn record_outputs_records_a_fully_verified_batch() {
        let store = MemoryStore::new();
        let t = tenant();
        let expected = vec![("out".to_string(), StorePath::new(OUT))];

        LegacyProtocolImpl::for_test(store.clone(), t.clone())
            .record_outputs(&[output_info(OUT, "k")], &expected)
            .await
            .expect("every reported output is in the verified set");

        assert!(store.is_valid_path(&t, &StorePath::new(OUT)).await);
    }

    #[tokio::test]
    async fn record_outputs_is_all_or_nothing_on_a_bogus_report() {
        // PLAN.md Phase 14: a worker reporting even one output outside its
        // job's verified set must not get any of that batch recorded —
        // including the output that *was* legitimate.
        let store = MemoryStore::new();
        let t = tenant();
        let expected = vec![("out".to_string(), StorePath::new(OUT))];
        let infos = [output_info(OUT, "k1"), output_info(OTHER, "k2")];

        let rejected = LegacyProtocolImpl::for_test(store.clone(), t.clone())
            .record_outputs(&infos, &expected)
            .await
            .expect_err("a bogus output should refuse the whole batch");
        assert_eq!(rejected, vec![StorePath::new(OTHER)]);

        assert!(
            !store.is_valid_path(&t, &StorePath::new(OUT)).await,
            "the legitimate output must not be recorded alongside the bogus one"
        );
        assert!(!store.is_valid_path(&t, &StorePath::new(OTHER)).await);
    }
}
