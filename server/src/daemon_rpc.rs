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
use crate::logging_capnp::log_stream;
use crate::jobs::{BuildJob, JobOutcome, JobQueue};
use crate::store::{ClientOptions, Hash, HashType, MemoryStore, PathInfo, Store, StoreError};
use futures_util::StreamExt;
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
    pub system: String,
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
        }
    }
}

pub fn default_system() -> String {
    std::env::var("KUBERNIX_SYSTEM").unwrap_or_else(|_| "x86_64-linux".to_string())
}

/// Returns the store path a `DerivedPath` names, and whether it is the `built`
/// variant (i.e. names a derivation to realise rather than a path to check).
fn read_derived_path(
    reader: legacy_protocol::derived_path::Reader<'_>,
) -> capnp::Result<(String, bool)> {
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
/// worker. A *built* path names a derivation and is dispatched to the job queue.
async fn realise(
    store: &dyn Store,
    queue: &Option<Arc<JobQueue>>,
    logger: &log_stream::Client,
    system: &str,
    path: &str,
    built: bool,
) -> Result<Option<JobOutcome>, capnp::Error> {
    if !built {
        return if store.is_valid_path(path) {
            Ok(None)
        } else {
            Err(capnp::Error::failed(format!(
                "kubernix: path not in store and cannot be substituted: {path}"
            )))
        };
    }

    let Some(queue) = queue else {
        tracing::warn!(%path, "build requested but no job queue is configured");
        return Err(capnp::Error::unimplemented(format!(
            "kubernix: cannot build {path} - no NATS job queue configured"
        )));
    };

    let job = BuildJob {
        job_id: Uuid::new_v4(),
        derivation_path: path.to_string(),
        system: system.to_string(),
        drv: Vec::new(),
    };

    let outcome = dispatch(queue, job, logger)
        .await
        .map_err(|e| capnp::Error::failed(e.to_string()))?;

    match &outcome {
        JobOutcome::Failed { message, .. } => Err(capnp::Error::failed(format!(
            "kubernix: build of {path} failed: {message}"
        ))),
        JobOutcome::Completed { infos, .. } => {
            record_outputs(store, infos);
            Ok(Some(outcome))
        }
    }
}

/// Register built outputs so subsequent `queryPathInfo` / `narFromPath` calls
/// resolve. The worker uploaded the NARs; what it reported is the metadata the
/// frontend could not compute for itself.
fn record_outputs(store: &dyn Store, infos: &[crate::jobs::OutputInfo]) {
    for info in infos {
        let path_info = PathInfo {
            path: info.store_path.clone(),
            deriver: info.deriver.clone(),
            nar_hash: Hash {
                hash_type: HashType::Sha256,
                bytes: info.nar_hash.clone(),
            },
            nar_size: info.nar_size,
            references: info.references.clone(),
            registration_time: 0,
            ultimate: true,
            sigs: Vec::new(),
        };
        if let Err(e) = store.register_output(path_info, info.key.clone(), info.file_size) {
            tracing::error!(path = %info.store_path, error = %e, "could not record built output");
        }
    }
}

fn store_err(e: StoreError) -> capnp::Error {
    match e {
        StoreError::Unsupported(op) => capnp::Error::unimplemented(op.to_string()),
        other => capnp::Error::failed(other.to_string()),
    }
}

/// `StorePath.raw` carries the full printed path (`types-rpc.hh:25-38`).
fn read_store_path(reader: crate::types_capnp::store_path::Reader<'_>) -> capnp::Result<String> {
    Ok(String::from_utf8_lossy(reader.get_raw()?).into_owned())
}

fn read_store_paths(
    list: capnp::struct_list::Reader<'_, crate::types_capnp::store_path::Owned>,
) -> capnp::Result<Vec<String>> {
    list.iter().map(read_store_path).collect()
}

fn write_store_paths(
    mut builder: capnp::struct_list::Builder<'_, crate::types_capnp::store_path::Owned>,
    paths: &[String],
) {
    for (i, path) in paths.iter().enumerate() {
        builder.reborrow().get(i as u32).set_raw(path.as_bytes());
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

/// Write a `ValidPathInfo` to the wire.
fn write_path_info(mut builder: legacy_protocol::valid_path_info::Builder<'_>, info: &PathInfo) {
    builder.reborrow().init_path().set_raw(info.path.as_bytes());

    let mut unkeyed = builder.init_unkeyed_valid_path_info();
    match &info.deriver {
        Some(deriver) => unkeyed
            .reborrow()
            .init_deriver()
            .init_some()
            .set_raw(deriver.as_bytes()),
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
    system: String,
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
        async move {
            // The client hands us a logger capability. Everything a remote build
            // prints goes back through this, which is why build logs need no side
            // channel: the frontend will pump `kubernix.logs.<job_id>` into it.
            let logger = params.get()?.get_logger()?;

            let proto: legacy_protocol::Client =
                capnp_rpc::new_client(LegacyProtocolImpl { logger, store, queue, system });

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
    system: String,
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
    start_activity(logger, activity_id, &job.derivation_path).await?;

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

            store.set_options(ClientOptions {
                keep_failed: params.get_keep_failed(),
                keep_going: params.get_keep_going(),
                try_fallback: params.get_try_fallback(),
                verbosity: params.get_verbosity()? as u16,
                max_build_jobs: params.get_max_build_jobs(),
                build_cores: params.get_build_cores(),
                use_substitutes: params.get_use_substitutes(),
                overrides,
            });
            Ok(())
        }
    }

    fn is_valid_path(
        self: Rc<Self>,
        params: legacy_protocol::IsValidPathParams,
        mut results: legacy_protocol::IsValidPathResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let store = self.store.clone();
        async move {
            let path = read_store_path(params.get()?.get_path()?)?;
            results.get().set_result(store.is_valid_path(&path));
            Ok(())
        }
    }

    fn query_valid_paths(
        self: Rc<Self>,
        params: legacy_protocol::QueryValidPathsParams,
        mut results: legacy_protocol::QueryValidPathsResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let store = self.store.clone();
        async move {
            let paths = read_store_paths(params.get()?.get_paths()?)?;
            let valid = store.query_valid_paths(&paths);
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
        async move {
            let paths = store.query_all_valid_paths();
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
        async move {
            let path = read_store_path(params.get()?.get_path()?)?;
            let mut result = results.get().init_result();
            match store.query_path_info(&path) {
                Some(info) => write_path_info(result.init_some(), &info),
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
        async move {
            let hash_part =
                String::from_utf8_lossy(params.get()?.get_hash_part()?).into_owned();
            let mut result = results.get().init_result();
            match store.query_path_from_hash_part(&hash_part) {
                Some(path) => result.init_some().set_raw(path.as_bytes()),
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
        async move {
            let path = read_store_path(params.get()?.get_path()?)?;
            let referrers = store.query_referrers(&path);
            write_store_paths(results.get().init_result(referrers.len() as u32), &referrers);
            Ok(())
        }
    }

    fn query_substitutable_paths(
        self: Rc<Self>,
        params: legacy_protocol::QuerySubstitutablePathsParams,
        mut results: legacy_protocol::QuerySubstitutablePathsResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let store = self.store.clone();
        async move {
            let paths = read_store_paths(params.get()?.get_paths()?)?;
            let subs = store.query_substitutable_paths(&paths);
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

            let missing = store.query_missing(&targets);
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
        async move {
            let params = params.get()?;
            let path = read_store_path(params.get_path()?)?;
            let sigs = params
                .get_signatures()?
                .iter()
                .map(|s| Ok(String::from_utf8_lossy(s?).into_owned()))
                .collect::<capnp::Result<Vec<_>>>()?;
            store.add_signatures(&path, sigs).map_err(store_err)?;
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
        async move {
            let info = read_path_info(params.get()?.get_info()?)?;
            tracing::debug!(path = %info.path, "receiving nar");
            let sink: legacy_protocol::stream::Client =
                capnp_rpc::new_client(NarSink::new(store, info));
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
        async move {
            let params = params.get()?;
            let path = read_store_path(params.get_path()?)?;
            let into = params.get_into()?;

            let nar = store.nar_from_path(&path).map_err(store_err)?;
            tracing::debug!(%path, size = nar.len(), "sending nar");

            // Chunked so a large NAR does not become one enormous message.
            const CHUNK: usize = 64 * 1024;
            for chunk in nar.chunks(CHUNK) {
                let mut request = into.feed_request();
                request.get().set_raw(chunk);
                request.send().await?;
            }
            into.finalize_request().send().promise.await?;
            Ok(())
        }
    }

    /// Realise paths. A `DerivedPath::Opaque` is just "ensure this path exists",
    /// which for anything already in the store needs no worker — this is the path
    /// `nix copy --from` takes. A `DerivedPath::Built` names a derivation and does
    /// need one, so it fails until the job queue is wired.
    fn build_paths(
        self: Rc<Self>,
        params: legacy_protocol::BuildPathsParams,
        _results: legacy_protocol::BuildPathsResults,
    ) -> impl Future<Output = Result<(), capnp::Error>> + 'static {
        let store = self.store.clone();
        let queue = self.queue.clone();
        let logger = self.logger.clone();
        let system = self.system.clone();
        async move {
            for target in params.get()?.get_paths()?.iter() {
                let (path, built) = read_derived_path(target)?;
                realise(&*store, &queue, &logger, &system, &path, built).await?;
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
        let queue = self.queue.clone();
        let logger = self.logger.clone();
        let system = self.system.clone();
        async move {
            let targets = params.get()?.get_paths()?;
            let mut resolved = Vec::new();
            for target in targets.iter() {
                let (path, built) = read_derived_path(target)?;
                let outcome = realise(&*store, &queue, &logger, &system, &path, built).await?;
                resolved.push((path, outcome.is_some()));
            }

            let mut out = results.get().init_result(resolved.len() as u32);
            for (i, (path, was_built)) in resolved.iter().enumerate() {
                let mut keyed = out.reborrow().get(i as u32);
                keyed
                    .reborrow()
                    .init_path()
                    .init_raw()
                    .init_opaque()
                    .init_path()
                    .set_raw(path.as_bytes());
                let mut result = keyed.init_result();
                result.set_status(if *was_built {
                    legacy_protocol::build_result::Status::Built
                } else {
                    legacy_protocol::build_result::Status::AlreadyValid
                });
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
    //   build_paths / build_paths_with_result / build_derivation
    //                          - no worker pool yet; see build_derivation below
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
        async move {
            let params = params.get()?;
            let path = read_store_path(params.get_path()?)?;
            let drv = params.get_drv()?.to_vec();

            let Some(queue) = queue else {
                tracing::warn!(%path, "build requested but no job queue is configured");
                return Err(capnp::Error::unimplemented(format!(
                    "kubernix: build of {path} not dispatched - no NATS job queue configured"
                )));
            };

            let job = BuildJob {
                job_id: Uuid::new_v4(),
                derivation_path: path.clone(),
                system,
                drv,
            };

            let outcome = dispatch(&queue, job, &logger)
                .await
                .map_err(|e| capnp::Error::failed(e.to_string()))?;

            let mut result = results.get().init_result();
            match outcome {
                JobOutcome::Completed {
                    outputs,
                    infos,
                    log_key,
                } => {
                    tracing::info!(%path, ?outputs, %log_key, "build succeeded");
                    record_outputs(&*store, &infos);
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

/// Accumulates a streamed NAR, committing it to the store on `finalize`.
struct NarSink {
    store: Arc<dyn Store>,
    info: PathInfo,
    buffer: RefCell<Vec<u8>>,
}

impl NarSink {
    fn new(store: Arc<dyn Store>, info: PathInfo) -> Self {
        Self {
            store,
            info,
            buffer: RefCell::new(Vec::new()),
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
            self.store
                .add_to_store_nar(self.info.clone(), nar)
                .map_err(store_err)?;
            Ok(())
        }
    }
}
