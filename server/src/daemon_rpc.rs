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

use crate::daemon_capnp::{bootstrap, legacy_boot, legacy_protocol, protocol};
use crate::jobs::{BuildJob, JobOutcome, JobQueue};
use crate::logging_capnp::log_stream;
use crate::rpc_error;
use crate::store::{ClientOptions, Hash, HashType, MemoryStore, PathInfo, Store, StoreError, Tier};
use crate::store_path::{CaMethod, ContentAddress};
use crate::tenant::{Tenant, TenantId};
use crate::uploads::UploadSigner;
use futures_util::StreamExt;
use kubernix_types::{StorePath, System};
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
        }
    }
}

pub fn default_system() -> System {
    System::new(std::env::var("KUBERNIX_SYSTEM").unwrap_or_else(|_| "x86_64-linux".to_string()))
}

/// Returns the store path a `DerivedPath` names, and whether it is the `built`
/// variant (i.e. names a derivation to realise rather than a path to check).
fn read_derived_path(
    reader: legacy_protocol::derived_path::Reader<'_>,
) -> capnp::Result<(StorePath, bool)> {
    use crate::daemon_capnp::legacy_protocol::derived_path;
    Ok(match reader.get_raw().which()? {
        derived_path::raw::Which::Opaque(opaque) => (read_store_path(opaque?.get_path()?)?, false),
        derived_path::raw::Which::Built(built) => {
            (read_store_path(built?.get_drv_path()?.get_path()?)?, true)
        }
    })
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
async fn realise(
    store: &dyn Store,
    tenant: &TenantId,
    path: &StorePath,
    built: bool,
) -> Result<(), capnp::Error> {
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

    if is_valid_path_anywhere(store, tenant, path).await {
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
async fn record_outputs(store: &dyn Store, tenant: &TenantId, infos: &[crate::jobs::OutputInfo]) {
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
        sign_if_vouchable(store, tenant, &mut path_info, Tier::Built).await;

        if let Err(e) = store
            .record_path(
                tenant,
                path_info,
                crate::store::RemoteObject {
                    key: info.key.clone(),
                    file_size: info.file_size,
                    file_hash: info.file_hash.clone(),
                },
                Tier::Built,
            )
            .await
        {
            tracing::error!(path = %info.store_path, error = %e, "could not record built output");
        }
    }
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
async fn sign_if_vouchable(store: &dyn Store, tenant: &TenantId, info: &mut PathInfo, tier: Tier) {
    if !tier.is_vouchable() {
        tracing::debug!(path = %info.path, tier = tier.as_str(), "not signing");
        return;
    }
    let Some(signer) = store.signer(tenant).await else {
        tracing::error!(path = %info.path, %tenant, "no signing key; storing unsigned");
        return;
    };

    let fingerprint = kubernix_signing::Fingerprint {
        path: info.path.as_str(),
        nar_hash: &info.nar_hash.bytes,
        nar_size: info.nar_size,
        references: &info.references,
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

/// If `tenant` doesn't already have a row for this hash part, but some other
/// tenant's `Verified` push does, copy it in — signed with `tenant`'s own key,
/// never anyone else's. PLAN.md Phase 9c step two.
///
/// Deliberately only reachable from the daemon protocol (this module), never
/// from the HTTP cache: it writes, and the write path is where writes belong.
/// A cross-tenant path only becomes visible to a tenant's HTTP cache once its
/// own daemon-protocol traffic — a build depending on it, `nix copy`, etc. —
/// has materialized a row for it here, exactly as if that tenant had pushed
/// it directly.
async fn resolve_verified(
    store: &dyn Store,
    tenant: &TenantId,
    hash_part: &str,
) -> Option<StorePath> {
    if let Some(path) = store.query_path_from_hash_part(tenant, hash_part).await {
        return Some(path);
    }
    let (mut info, object) = store.find_verified_by_hash_part(hash_part).await?;
    let path = info.path.clone();
    // Drop whichever tenant's signature `find_verified_by_hash_part` happened
    // to return: this is a fresh row for `tenant`, and its only signature
    // should be its own — not a mix that quietly says another tenant also
    // vouched for it.
    info.sigs.clear();
    sign_if_vouchable(store, tenant, &mut info, Tier::Verified).await;
    if let Err(e) = store
        .record_path(tenant, info, object, Tier::Verified)
        .await
    {
        tracing::error!(
            %path, %tenant, error = %e,
            "failed to materialize a cross-tenant verified path"
        );
        return None;
    }
    tracing::info!(%path, %tenant, "materialized a cross-tenant verified path");
    Some(path)
}

/// [`Store::is_valid_path`], falling back to [`resolve_verified`] on a local
/// miss. The two callers (`isValidPath` itself, and `realise`'s check for an
/// opaque `buildPaths` dependency) both need this, not just the RPC entry
/// point — an opaque dependency that only another tenant has pushed is
/// exactly the case sharing exists for.
async fn is_valid_path_anywhere(store: &dyn Store, tenant: &TenantId, path: &StorePath) -> bool {
    if store.is_valid_path(tenant, path).await {
        return true;
    }
    let Some(hash_part) = path.hash_part() else {
        return false;
    };
    resolve_verified(store, tenant, hash_part).await.as_ref() == Some(path)
}

fn store_err(e: StoreError) -> capnp::Error {
    match e {
        StoreError::Unsupported(op) => rpc_error::unimplemented(op.to_string()),
        other => rpc_error::failed(other.to_string()),
    }
}

/// `StorePath.raw` carries the full printed path (`types-rpc.hh:25-38`).
fn read_store_path(reader: crate::types_capnp::store_path::Reader<'_>) -> capnp::Result<StorePath> {
    Ok(StorePath::new(
        String::from_utf8_lossy(reader.get_raw()?).into_owned(),
    ))
}

fn read_store_paths(
    list: capnp::struct_list::Reader<'_, crate::types_capnp::store_path::Owned>,
) -> capnp::Result<Vec<StorePath>> {
    list.iter().map(read_store_path).collect()
}

fn write_store_paths(
    mut builder: capnp::struct_list::Builder<'_, crate::types_capnp::store_path::Owned>,
    paths: &[StorePath],
) {
    for (i, path) in paths.iter().enumerate() {
        builder
            .reborrow()
            .get(i as u32)
            .set_raw(path.as_str().as_bytes());
    }
}

fn hash_type_from(ht: legacy_protocol::HashType) -> HashType {
    match ht {
        legacy_protocol::HashType::Md5 => HashType::Md5,
        legacy_protocol::HashType::Sha1 => HashType::Sha1,
        legacy_protocol::HashType::Sha256 => HashType::Sha256,
        legacy_protocol::HashType::Sha512 => HashType::Sha512,
    }
}

fn hash_type_to(ht: HashType) -> legacy_protocol::HashType {
    match ht {
        HashType::Md5 => legacy_protocol::HashType::Md5,
        HashType::Sha1 => legacy_protocol::HashType::Sha1,
        HashType::Sha256 => legacy_protocol::HashType::Sha256,
        HashType::Sha512 => legacy_protocol::HashType::Sha512,
    }
}

/// Read a `ValidPathInfo` off the wire.
fn read_path_info(reader: legacy_protocol::valid_path_info::Reader<'_>) -> capnp::Result<PathInfo> {
    use crate::types_capnp::option;

    let path = read_store_path(reader.get_path()?)?;
    let unkeyed = reader.get_unkeyed_valid_path_info()?;

    let deriver = match unkeyed.get_deriver()?.which()? {
        option::Which::None(()) => None,
        option::Which::Some(sp) => Some(read_store_path(sp?)?),
    };

    let nar_hash_reader = unkeyed.get_nar_hash()?;
    let nar_hash = Hash {
        hash_type: hash_type_from(nar_hash_reader.get_hash_type()?),
        bytes: nar_hash_reader.get_hash()?.to_vec(),
    };

    let sigs = unkeyed
        .get_sigs()?
        .iter()
        .map(|s| Ok(String::from_utf8_lossy(s?).into_owned()))
        .collect::<capnp::Result<Vec<_>>>()?;

    Ok(PathInfo {
        path,
        deriver,
        nar_hash,
        nar_size: unkeyed.get_nar_size(),
        references: read_store_paths(unkeyed.get_references()?)?,
        registration_time: unkeyed.get_registration_time(),
        ultimate: unkeyed.get_ultimate(),
        sigs,
    })
}

/// The content address a client attached to a path, if any.
///
/// Its absence is the interesting case: a path with no content address is
/// input-addressed, so nothing about its name follows from its bytes and the
/// frontend has no way to check the client's claim. See [`crate::store::Tier`].
fn read_content_address(
    unkeyed: legacy_protocol::unkeyed_valid_path_info::Reader<'_>,
) -> capnp::Result<Option<ContentAddress>> {
    use crate::types_capnp::option;

    let ca = match unkeyed.get_ca()?.which()? {
        option::Which::None(()) => return Ok(None),
        option::Which::Some(ca) => ca?,
    };

    let method = match ca.get_method()? {
        legacy_protocol::ContentAddressMethod::TextIngestion => CaMethod::Text,
        legacy_protocol::ContentAddressMethod::FlatFileIngestion => CaMethod::Flat,
        legacy_protocol::ContentAddressMethod::RecursiveFileIngestion => CaMethod::Recursive,
    };
    let hash = ca.get_hash()?;

    Ok(Some(ContentAddress {
        method,
        algo: match hash_type_from(hash.get_hash_type()?) {
            HashType::Md5 => "md5",
            HashType::Sha1 => "sha1",
            HashType::Sha256 => "sha256",
            HashType::Sha512 => "sha512",
        }
        .to_string(),
        hash: hash.get_hash()?.to_vec(),
    }))
}

/// Write a `ValidPathInfo` to the wire.
fn write_path_info(mut builder: legacy_protocol::valid_path_info::Builder<'_>, info: &PathInfo) {
    builder
        .reborrow()
        .init_path()
        .set_raw(info.path.as_str().as_bytes());

    let mut unkeyed = builder.init_unkeyed_valid_path_info();
    match &info.deriver {
        Some(deriver) => unkeyed
            .reborrow()
            .init_deriver()
            .init_some()
            .set_raw(deriver.as_str().as_bytes()),
        None => unkeyed.reborrow().init_deriver().set_none(()),
    }

    {
        let mut hash = unkeyed.reborrow().init_nar_hash();
        hash.set_hash(&info.nar_hash.bytes);
        hash.set_hash_type(hash_type_to(info.nar_hash.hash_type));
    }

    unkeyed.set_nar_size(info.nar_size);
    unkeyed.set_registration_time(info.registration_time);
    unkeyed.set_ultimate(info.ultimate);

    write_store_paths(
        unkeyed
            .reborrow()
            .init_references(info.references.len() as u32),
        &info.references,
    );

    let mut sigs = unkeyed.reborrow().init_sigs(info.sigs.len() as u32);
    for (i, sig) in info.sigs.iter().enumerate() {
        sigs.set(i as u32, sig.as_bytes());
    }

    // `ca` is left as the default `none`: nothing here is content-addressed yet.
}

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
}

/// Submit a job, relay its log into the client's `LogStream`, and return the
/// outcome.
///
/// The log subscription and result consumer are created *before* the job is
/// submitted: logs are core NATS with no replay, so subscribing afterwards races
/// the worker and can drop the opening lines.
///
/// This future is deliberately `!Send` — it holds capnp capabilities — which is
/// why it runs on the connection's `LocalSet`. The NATS futures it awaits are
/// `Send`, and awaiting a `Send` future from a `!Send` task is fine.
async fn dispatch(
    queue: &JobQueue,
    job: BuildJob,
    logger: &log_stream::Client,
) -> Result<JobOutcome, Box<dyn std::error::Error + Send + Sync>> {
    let job_id = job.job_id;

    let mut logs = queue.subscribe_logs(&job_id).await?;
    let consumer = queue.result_consumer(&job_id).await?;

    queue.submit(&job).await?;

    // The client sees a build activity for the job, and each log line arrives as
    // a result on it — the same shape a local build produces, so it renders
    // identically.
    let activity_id = job_id.as_u128() as u64;
    start_activity(logger, activity_id, job.derivation_path.as_str()).await?;

    let outcome = {
        let mut outcome_fut = Box::pin(queue.await_outcome(consumer));
        loop {
            tokio::select! {
                // Bias toward draining logs so the tail is not lost when the
                // outcome and the final lines arrive together.
                biased;
                Some(message) = logs.next() => {
                    push_log_line(logger, activity_id, &message.payload).await?;
                }
                outcome = &mut outcome_fut => break outcome?,
            }
        }
    };

    // Drain whatever is already buffered before closing the activity.
    while let Ok(Some(message)) =
        tokio::time::timeout(std::time::Duration::from_millis(50), logs.next()).await
    {
        push_log_line(logger, activity_id, &message.payload).await?;
    }

    stop_activity(logger, activity_id).await?;
    Ok(outcome)
}

/// Open a build activity on the client.
///
/// `actBuild` has a required field layout the client indexes into blindly
/// (`lix/libmain/progress-bar.cc:159-174`): field 0 is the derivation path,
/// field 1 the machine name, and fields 2 and 3 are integers that must both be
/// `1` or the client throws "log message indicated repeating builds". Sending
/// the wrong shape crashes the client rather than degrading, so these four
/// fields are mandatory.
async fn start_activity(
    logger: &log_stream::Client,
    id: u64,
    drv_path: &str,
) -> Result<(), capnp::Error> {
    let mut request = logger.push_request();
    {
        let mut event = request.get().init_e();
        let mut start = event.reborrow().init_start_activity();
        start.set_level(crate::types_capnp::Verbosity::Info);
        start.set_id(id);
        start.set_type(crate::logging_capnp::ActivityType::Build);
        start.set_text(format!("building {drv_path}").as_bytes());
        start.set_parent(0);

        let mut fields = start.init_fields(4);
        fields.reborrow().get(0).set_s(drv_path.as_bytes());
        fields.reborrow().get(1).set_s(b"kubernix");
        fields.reborrow().get(2).set_i(1);
        fields.reborrow().get(3).set_i(1);
    }
    request.send().await?;
    Ok(())
}

async fn push_log_line(
    logger: &log_stream::Client,
    activity_id: u64,
    line: &[u8],
) -> Result<(), capnp::Error> {
    let mut request = logger.push_request();
    {
        let mut event = request.get().init_e();
        let mut result = event.reborrow().init_result();
        result.set_id(activity_id);
        result.set_type(crate::logging_capnp::ResultType::BuildLogLine);
        let mut fields = result.init_fields(1);
        fields.reborrow().get(0).set_s(line);
    }
    request.send().await?;
    Ok(())
}

async fn stop_activity(logger: &log_stream::Client, id: u64) -> Result<(), capnp::Error> {
    let mut request = logger.push_request();
    request.get().init_e().init_stop_activity().set_id(id);
    request.send().await?;
    logger.synchronize_request().send().promise.await?;
    Ok(())
}

impl legacy_protocol::Server for LegacyProtocolImpl {
    fn set_options(
        self: Rc<Self>,
        params: legacy_protocol::SetOptionsParams,
        _results: legacy_protocol::SetOptionsResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let store = self.store.clone();
        let tenant = self.tenant.id.clone();
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
                .set_options(
                    &tenant,
                    ClientOptions {
                        keep_failed: params.get_keep_failed(),
                        keep_going: params.get_keep_going(),
                        try_fallback: params.get_try_fallback(),
                        verbosity: params.get_verbosity()? as u16,
                        max_build_jobs: params.get_max_build_jobs(),
                        build_cores: params.get_build_cores(),
                        use_substitutes: params.get_use_substitutes(),
                        overrides,
                    },
                )
                .await;
            Ok(())
        }
    }

    fn is_valid_path(
        self: Rc<Self>,
        params: legacy_protocol::IsValidPathParams,
        mut results: legacy_protocol::IsValidPathResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let store = self.store.clone();
        let tenant = self.tenant.id.clone();
        async move {
            let path = read_store_path(params.get()?.get_path()?)?;
            results
                .get()
                .set_result(is_valid_path_anywhere(&*store, &tenant, &path).await);
            Ok(())
        }
    }

    fn query_valid_paths(
        self: Rc<Self>,
        params: legacy_protocol::QueryValidPathsParams,
        mut results: legacy_protocol::QueryValidPathsResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let store = self.store.clone();
        let tenant = self.tenant.id.clone();
        async move {
            let paths = read_store_paths(params.get()?.get_paths()?)?;
            let mut valid = store.query_valid_paths(&tenant, &paths).await;
            for path in &paths {
                if valid.contains(path) {
                    continue;
                }
                let Some(hash_part) = path.hash_part() else {
                    continue;
                };
                if resolve_verified(&*store, &tenant, hash_part).await.as_ref() == Some(path) {
                    valid.push(path.clone());
                }
            }
            write_store_paths(results.get().init_result(valid.len() as u32), &valid);
            Ok(())
        }
    }

    fn query_all_valid_paths(
        self: Rc<Self>,
        _params: legacy_protocol::QueryAllValidPathsParams,
        mut results: legacy_protocol::QueryAllValidPathsResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let store = self.store.clone();
        let tenant = self.tenant.id.clone();
        async move {
            let paths = store.query_all_valid_paths(&tenant).await;
            write_store_paths(results.get().init_result(paths.len() as u32), &paths);
            Ok(())
        }
    }

    fn query_path_info(
        self: Rc<Self>,
        params: legacy_protocol::QueryPathInfoParams,
        mut results: legacy_protocol::QueryPathInfoResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let store = self.store.clone();
        let tenant = self.tenant.id.clone();
        async move {
            let path = read_store_path(params.get()?.get_path()?)?;
            let mut result = results.get().init_result();
            let mut info = store.query_path_info(&tenant, &path).await;
            if info.is_none()
                && let Some(hash_part) = path.hash_part()
                && resolve_verified(&*store, &tenant, hash_part)
                    .await
                    .is_some()
            {
                info = store.query_path_info(&tenant, &path).await;
            }
            match info {
                Some(info) => {
                    // A narinfo is the earlier half of "fetch metadata, then
                    // fetch bytes" — PLAN.md Phase 12 counts it as an access
                    // in its own right so a path is not collected in the
                    // window between the two.
                    store.record_access(&tenant, &path).await;
                    write_path_info(result.init_some(), &info)
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
        let store = self.store.clone();
        let tenant = self.tenant.id.clone();
        async move {
            let hash_part = String::from_utf8_lossy(params.get()?.get_hash_part()?).into_owned();
            let mut result = results.get().init_result();
            match resolve_verified(&*store, &tenant, &hash_part).await {
                Some(path) => result.init_some().set_raw(path.as_str().as_bytes()),
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
        let store = self.store.clone();
        let tenant = self.tenant.id.clone();
        async move {
            let path = read_store_path(params.get()?.get_path()?)?;
            let referrers = store.query_referrers(&tenant, &path).await;
            write_store_paths(
                results.get().init_result(referrers.len() as u32),
                &referrers,
            );
            Ok(())
        }
    }

    fn query_substitutable_paths(
        self: Rc<Self>,
        params: legacy_protocol::QuerySubstitutablePathsParams,
        mut results: legacy_protocol::QuerySubstitutablePathsResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let store = self.store.clone();
        let tenant = self.tenant.id.clone();
        async move {
            let paths = read_store_paths(params.get()?.get_paths()?)?;
            let subs = store.query_substitutable_paths(&tenant, &paths).await;
            write_store_paths(results.get().init_result(subs.len() as u32), &subs);
            Ok(())
        }
    }

    fn query_valid_derivers(
        self: Rc<Self>,
        _params: legacy_protocol::QueryValidDeriversParams,
        mut results: legacy_protocol::QueryValidDeriversResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        async move {
            // Derivers are tracked per path in PathInfo, not indexed in reverse.
            results.get().init_result(0);
            Ok(())
        }
    }

    fn query_missing(
        self: Rc<Self>,
        params: legacy_protocol::QueryMissingParams,
        mut results: legacy_protocol::QueryMissingResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let store = self.store.clone();
        let tenant = self.tenant.id.clone();
        async move {
            // DerivedPath is a union of opaque/built; both name a store path.
            let mut targets = Vec::new();
            for target in params.get()?.get_targets()?.iter() {
                use crate::daemon_capnp::legacy_protocol::derived_path;
                match target.get_raw().which()? {
                    derived_path::raw::Which::Opaque(opaque) => {
                        targets.push(read_store_path(opaque?.get_path()?)?)
                    }
                    derived_path::raw::Which::Built(built) => {
                        targets.push(read_store_path(built?.get_drv_path()?.get_path()?)?)
                    }
                }
            }

            let missing = store.query_missing(&tenant, &targets).await;
            let mut result = results.get().init_result();
            write_store_paths(
                result
                    .reborrow()
                    .init_will_build(missing.will_build.len() as u32),
                &missing.will_build,
            );
            write_store_paths(
                result
                    .reborrow()
                    .init_will_substitute(missing.will_substitute.len() as u32),
                &missing.will_substitute,
            );
            write_store_paths(
                result.reborrow().init_unknown(missing.unknown.len() as u32),
                &missing.unknown,
            );
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
        let store = self.store.clone();
        let tenant = self.tenant.id.clone();
        async move {
            let params = params.get()?;
            let path = read_store_path(params.get_path()?)?;
            let sigs = params
                .get_signatures()?
                .iter()
                .map(|s| Ok(String::from_utf8_lossy(s?).into_owned()))
                .collect::<capnp::Result<Vec<_>>>()?;
            store
                .add_signatures(&tenant, &path, sigs)
                .await
                .map_err(store_err)?;
            Ok(())
        }
    }

    /// Temp roots are a GC concept. The frontend does not GC on the client's
    /// behalf, so these are accepted and ignored rather than refused — refusing
    /// would abort otherwise valid client operations.
    fn add_temp_root(
        self: Rc<Self>,
        _params: legacy_protocol::AddTempRootParams,
        _results: legacy_protocol::AddTempRootResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        async move { Ok(()) }
    }

    fn add_indirect_root(
        self: Rc<Self>,
        _params: legacy_protocol::AddIndirectRootParams,
        _results: legacy_protocol::AddIndirectRootResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        async move { Ok(()) }
    }

    /// Accept a NAR the client already has `ValidPathInfo` for. This is how a
    /// client uploads a closure to the builder.
    fn add_to_store_nar(
        self: Rc<Self>,
        params: legacy_protocol::AddToStoreNarParams,
        mut results: legacy_protocol::AddToStoreNarResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let store = self.store.clone();
        let uploader = self.uploader.clone();
        let staged = self.clone();
        async move {
            let wire_info = params.get()?.get_info()?;
            let info = read_path_info(wire_info)?;
            let ca = read_content_address(wire_info.get_unkeyed_valid_path_info()?)?;
            tracing::debug!(path = %info.path, content_addressed = ca.is_some(), "receiving nar");
            let sink: legacy_protocol::stream::Client =
                capnp_rpc::new_client(NarSink::new(store, uploader, info, ca, staged));
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
        let store = self.store.clone();
        let tenant = self.tenant.id.clone();
        let uploader = self.uploader.clone();
        async move {
            let params = params.get()?;
            let path = read_store_path(params.get_path()?)?;
            let into = params.get_into()?;

            // Every path's bytes are in the object store, whichever route it
            // arrived by, so there is one way to serve them.
            let Some(remote) = store.output_object(&tenant, &path).await else {
                return Err(store_err(StoreError::NotFound(path.to_string())));
            };
            // The byte fetch itself, not just the narinfo lookup that usually
            // precedes it — PLAN.md Phase 12.
            store.record_access(&tenant, &path).await;
            let uploader = uploader.as_ref().ok_or_else(|| {
                rpc_error::failed(format!(
                    "kubernix: {path} is in the object store but no S3 client is configured"
                ))
            })?;

            tracing::debug!(%path, key = %remote.key, "streaming from the object store");
            let mut reader = uploader
                .get_object_reader(&remote.key)
                .await
                .map_err(|e| rpc_error::failed(format!("fetching {}: {e}", remote.key)))?;

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
                .map_err(|e| rpc_error::failed(format!("decompressing {}: {e}", remote.key)))?;
            let mut buf = vec![0u8; CHUNK];
            let mut sent: u64 = 0;

            loop {
                let read = tokio::io::AsyncReadExt::read(&mut reader, &mut buf)
                    .await
                    .map_err(|e| rpc_error::failed(format!("reading {}: {e}", remote.key)))?;
                if read == 0 {
                    break;
                }
                std::io::Write::write_all(&mut decoder, &buf[..read])
                    .map_err(|e| rpc_error::failed(format!("decompressing {}: {e}", remote.key)))?;
                let decoded = std::mem::take(decoder.get_mut());
                if !decoded.is_empty() {
                    sent += decoded.len() as u64;
                    let mut request = into.feed_request();
                    request.get().set_raw(&decoded);
                    request.send().await?;
                }
            }

            std::io::Write::flush(&mut decoder)
                .map_err(|e| rpc_error::failed(format!("decompressing {}: {e}", remote.key)))?;
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
    /// the frontend cannot realise; see [`realise`].
    fn build_paths(
        self: Rc<Self>,
        params: legacy_protocol::BuildPathsParams,
        _results: legacy_protocol::BuildPathsResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let store = self.store.clone();
        let tenant = self.tenant.id.clone();
        async move {
            for target in params.get()?.get_paths()?.iter() {
                let (path, built) = read_derived_path(target)?;
                realise(&*store, &tenant, &path, built).await?;
            }
            Ok(())
        }
    }

    fn build_paths_with_result(
        self: Rc<Self>,
        params: legacy_protocol::BuildPathsWithResultParams,
        mut results: legacy_protocol::BuildPathsWithResultResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let store = self.store.clone();
        let tenant = self.tenant.id.clone();
        async move {
            let targets = params.get()?.get_paths()?;
            let mut resolved = Vec::new();
            for target in targets.iter() {
                let (path, built) = read_derived_path(target)?;
                realise(&*store, &tenant, &path, built).await?;
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
                    .set_raw(path.as_str().as_bytes());
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
        let store = self.store.clone();
        let tenant = self.tenant.id.clone();
        let staged = self.staged.borrow().clone();
        async move {
            let params = params.get()?;
            let path = read_store_path(params.get_path()?)?;
            let drv = params.get_drv()?.to_vec();

            let Some(queue) = queue else {
                tracing::warn!(%path, "build requested but no job queue is configured");
                return Err(rpc_error::unimplemented(format!(
                    "kubernix: build of {path} not dispatched - no NATS job queue configured"
                )));
            };

            let job_id = Uuid::new_v4();
            let job = BuildJob {
                job_id,
                derivation_path: path.clone(),
                system: system.clone(),
                drv,
                inputs: staged,
                tenant: tenant.clone(),
            };

            let outcome = dispatch(&queue, job, &logger)
                .await
                .map_err(|e| rpc_error::failed(e.to_string()))?;

            store
                .record_job_outcome(&tenant, job_id, &path, system.as_str(), &outcome)
                .await;

            let mut result = results.get().init_result();
            match outcome {
                JobOutcome::Completed {
                    outputs,
                    infos,
                    log_key,
                } => {
                    tracing::info!(%path, ?outputs, %log_key, "build succeeded");
                    record_outputs(&*store, &tenant, &infos).await;
                    result.set_status(legacy_protocol::build_result::Status::Built);
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
    store: Arc<dyn Store>,
    uploader: Option<Arc<UploadSigner>>,
    info: PathInfo,
    /// The content address the client attached, if any. `None` means the path is
    /// input-addressed and therefore unverifiable.
    ca: Option<ContentAddress>,
    buffer: RefCell<Vec<u8>>,
    /// The connection that received this path, so the staged input is attached
    /// to the builds that follow on it.
    connection: Rc<LegacyProtocolImpl>,
}

impl NarSink {
    fn new(
        store: Arc<dyn Store>,
        uploader: Option<Arc<UploadSigner>>,
        info: PathInfo,
        ca: Option<ContentAddress>,
        connection: Rc<LegacyProtocolImpl>,
    ) -> Self {
        Self {
            store,
            uploader,
            info,
            ca,
            buffer: RefCell::new(Vec::new()),
            connection,
        }
    }
}

impl legacy_protocol::stream::Server for NarSink {
    fn feed(
        self: Rc<Self>,
        params: legacy_protocol::stream::FeedParams,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        async move {
            let raw = params.get()?.get_raw()?;
            self.buffer.borrow_mut().extend_from_slice(raw);
            Ok(())
        }
    }

    fn finalize(
        self: Rc<Self>,
        _params: legacy_protocol::stream::FinalizeParams,
        _results: legacy_protocol::stream::FinalizeResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        async move {
            let nar = std::mem::take(&mut *self.buffer.borrow_mut());

            // Decide what the frontend is willing to say about this path before
            // recording it. A content address can be checked against the bytes;
            // anything else is the client's word, and is quarantined rather than
            // refused so that ordinary `nix copy` of a build closure keeps
            // working. See PLAN.md Phase 9.
            let tier =
                match &self.ca {
                    Some(ca) => {
                        match crate::store_path::verify(
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
                                &["the frontend verifies content-addressed paths against their \
                                   bytes"
                                    .to_string()],
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
            let tenant = &self.connection.tenant.id;
            if let Some(existing) = self.store.tier(tenant, &self.info.path).await
                && existing.is_vouchable()
                && !matches!(tier, Tier::Verified)
            {
                tracing::debug!(
                    path = %self.info.path,
                    tier = existing.as_str(),
                    "already vouched for; keeping it rather than accepting the push"
                );
                self.connection
                    .staged
                    .borrow_mut()
                    .push(crate::jobs::InputRef {
                        store_path: self.info.path.clone(),
                        key: self
                            .store
                            .output_object(tenant, &self.info.path)
                            .await
                            .map(|o| o.key)
                            .unwrap_or_default(),
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
            let Some(key) =
                crate::store::nar_key(&self.connection.tenant.id, tier, &self.info.path)
            else {
                return Err(rpc_error::failed(format!(
                    "kubernix: not a store path: {}",
                    self.info.path
                )));
            };

            let compressed = zstd::stream::encode_all(nar.as_slice(), 3)
                .map_err(|e| rpc_error::failed(format!("compressing {}: {e}", self.info.path)))?;
            let file_size = compressed.len() as u64;
            let file_hash = <sha2::Sha256 as sha2::Digest>::digest(&compressed);

            // A `Verified` key carries no tenant prefix (PLAN.md Phase 9c), so
            // another tenant pushing the same content may already have put
            // these exact bytes at this exact key. Recomputing and
            // re-uploading them would be correct but wasteful — this is the
            // saving the sharing exists for. `Built`/`Quarantined` keys are
            // tenant-scoped and effectively never collide, so they always
            // upload as before.
            let already_there =
                matches!(tier, Tier::Verified) && self.store.object_known(&key).await;

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
                    .map_err(|e| rpc_error::failed(format!("uploading {}: {e}", self.info.path)))?;
            }

            // Signed here, on the way in, so the signature lands in the same row
            // as the path. A verified push is one we derived ourselves, so it is
            // ours to vouch for; a quarantined one is left unsigned.
            let mut info = self.info.clone();
            sign_if_vouchable(&*self.store, &self.connection.tenant.id, &mut info, tier).await;

            let references = info.references.clone();
            let deriver = info.deriver.clone().unwrap_or_default();

            self.store
                .record_path(
                    &self.connection.tenant.id,
                    info,
                    crate::store::RemoteObject {
                        key: key.clone(),
                        file_size,
                        file_hash,
                    },
                    tier,
                )
                .await
                .map_err(store_err)?;

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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{Hash, HashType, MemoryStore, PathInfo};

    const DRV: &str = "/nix/store/00000000000000000000000000000000-thing.drv";
    const OUT: &str = "/nix/store/11111111111111111111111111111111-thing";

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

    #[tokio::test]
    async fn an_opaque_path_in_the_store_needs_no_build() {
        let store = MemoryStore::new();
        let t = tenant();
        store
            .record_path(&t, info(OUT), object("k"), Tier::Verified)
            .await
            .unwrap();
        assert!(
            realise(&*store, &t, &StorePath::new(OUT), false)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn an_opaque_path_that_is_missing_is_an_error() {
        let store = MemoryStore::new();
        let error = realise(&*store, &tenant(), &StorePath::new(OUT), false)
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
        let error = realise(&*store, &tenant(), &StorePath::new(DRV), true)
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
        sign_if_vouchable(&*store, &alice, &mut pushed, Tier::Verified).await;
        store
            .record_path(&alice, pushed, object("k"), Tier::Verified)
            .await
            .unwrap();

        // Bob never pushed or built this path.
        assert!(!store.is_valid_path(&bob, &StorePath::new(OUT)).await);

        let hash_part = StorePath::new(OUT).hash_part().unwrap().to_string();
        let resolved = resolve_verified(&*store, &bob, &hash_part).await;
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
        assert_eq!(resolve_verified(&*store, &bob(), &hash_part).await, None);
    }

    #[tokio::test]
    async fn is_valid_path_anywhere_falls_back_to_another_tenant_s_verified_push() {
        let store = MemoryStore::new();
        let (alice, bob) = (tenant(), bob());
        store
            .record_path(&alice, info(OUT), object("k"), Tier::Verified)
            .await
            .unwrap();

        assert!(is_valid_path_anywhere(&*store, &bob, &StorePath::new(OUT)).await);
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
        assert!(!is_valid_path_anywhere(&*store, &bob, &StorePath::new(OUT)).await);
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
            realise(&*store, &bob, &StorePath::new(OUT), false)
                .await
                .is_ok()
        );
    }
}
