//! Pre-signed upload URLs.
//!
//! The frontend is the only component with S3 credentials. Workers ask for
//! permission to write specific keys and receive time-limited pre-signed `PUT`
//! URLs in return, so what crosses the wire is a narrow expiring capability
//! rather than a credential — and build outputs go straight to the object store
//! instead of through the frontend.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use aws_sdk_s3::presigning::PresigningConfig;
use eyre::Context as _;
use futures_util::StreamExt;

use kubernix_types::errors::public_message;
use kubernix_types::{CapabilityToken, ObjectKey};

use crate::capability::Capability;
use crate::kubernix_capnp;
use crate::store::{Store, Tier};
use crate::tenant::TenantId;

pub const UPLOADS_SUBJECT: &str = "kubernix.uploads";

/// How long a worker has to use a URL it was handed. Long enough for a large
/// output on a slow link, short enough that a leaked URL expires quickly.
const URL_TTL: Duration = Duration::from_secs(3600);

/// A `Verified` path's shared object key — `nar/<hash>.nar.zst`, no tenant
/// prefix — PLAN.md Phase 9c. Checked structurally rather than trusted: the
/// shape is what `nar_key` promises to produce, not what any caller asserts.
fn is_shared_verified_key(key: &ObjectKey) -> bool {
    let Some(hash) = key
        .as_str()
        .strip_prefix("nar/")
        .and_then(|r| r.strip_suffix(".nar.zst"))
    else {
        return false;
    };
    hash.len() == 32 && kubernix_signing::base32::is_valid(hash)
}

/// Keys a worker may be granted, for the tenant whose job it is running.
///
/// This is the whole access-control boundary for the object store: workers hold
/// no credentials, so what they can reach is exactly what this function agrees
/// to sign. Two independent things are checked, and both matter:
///
/// * the key belongs to `tenant` — otherwise a worker running one tenant's build
///   could read or overwrite another's artifacts;
/// * within that, it is an artifact namespace and not an escape.
fn key_is_permitted(key: &ObjectKey, download: bool, tenant: &TenantId) -> bool {
    let key_str = key.as_str();
    if key_str.contains("..") || key_str.starts_with('/') {
        return false;
    }

    // A `Verified` object carries no tenant prefix at all, by design: it is
    // shared by every tenant that pushed the same content. Downloading one
    // requires already knowing its key, which requires already knowing the
    // content hash, so this grants nothing a tenant could not already prove
    // it has — never for upload, since only the frontend writes these
    // directly with its own credentials; a worker never should.
    if download && is_shared_verified_key(key) {
        return true;
    }

    // Match the separator too: a prefix test alone would let tenant `a` reach
    // tenant `ab`'s keys.
    let Some(rest) = key_str.strip_prefix(&format!("{tenant}/")) else {
        return false;
    };

    if download {
        // Workers read the inputs staged for a build, and may read back
        // artifacts they or a previous build for this tenant wrote. Both are
        // `nar/`: a path has exactly one representation in the object store.
        //
        // `untrusted/nar/` is included deliberately — quarantined content is
        // exactly what a worker must still be able to build against, and
        // confining it to this tenant is what makes that safe. Quarantine limits
        // who may *rely* on a path, not who may build with it.
        rest.starts_with("nar/") || rest.starts_with("untrusted/nar/") || rest.starts_with("log/")
    } else {
        // Workers only ever write their own build products, which are `built` by
        // definition — so never under `untrusted/`, and never a path the
        // frontend staged, which it writes itself with credentials it holds.
        rest.starts_with("nar/") || rest.starts_with("log/")
    }
}

#[derive(Clone)]
pub struct UploadSigner {
    s3: aws_sdk_s3::Client,
    bucket: String,
}

impl UploadSigner {
    pub async fn from_env() -> eyre::Result<Self> {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let bucket = std::env::var("S3_BUCKET").unwrap_or_else(|_| "kubernix-cache".to_string());

        let mut s3_config = aws_sdk_s3::config::Builder::from(&config);
        // S3-compatible servers (rustfs, minio) are addressed by path, not by
        // virtual host: `http://host/bucket/key`, not `http://bucket.host/key`.
        // Presigned URLs inherit this, so getting it wrong produces URLs the
        // worker cannot resolve.
        if std::env::var("AWS_ENDPOINT_URL").is_ok() {
            tracing::info!("endpoint override set, using path-style addressing");
            s3_config = s3_config.force_path_style(true);
        }

        let s3 = aws_sdk_s3::Client::from_conf(s3_config.build());

        // Idempotent, and makes a fresh dev object store usable without a
        // separate provisioning step.
        match s3.create_bucket().bucket(&bucket).send().await {
            Ok(_) => tracing::info!(%bucket, "created bucket"),
            Err(e) => tracing::debug!(%bucket, error = %e, "bucket not created (likely exists)"),
        }

        tracing::info!(%bucket, "s3 configured for pre-signed uploads");
        Ok(Self { s3, bucket })
    }

    /// Write an object directly. Used for inputs, which arrive at the frontend
    /// over the daemon connection — the frontend already holds the bytes and the
    /// credentials, so there is nothing to delegate.
    pub async fn put_object(&self, key: &ObjectKey, body: Vec<u8>) -> eyre::Result<()> {
        let len = body.len();
        self.s3
            .put_object()
            .bucket(&self.bucket)
            .key(key.as_str())
            .body(body.into())
            .send()
            .await
            .wrap_err_with(|| format!("uploading {key}"))?;
        tracing::debug!(%key, bytes = len, "uploaded object");
        Ok(())
    }

    pub async fn presign_put(&self, key: &ObjectKey) -> eyre::Result<String> {
        let presigned = self
            .s3
            .put_object()
            .bucket(&self.bucket)
            .key(key.as_str())
            .presigned(PresigningConfig::expires_in(URL_TTL).wrap_err("building presign config")?)
            .await
            .wrap_err_with(|| format!("presigning an upload for {key}"))?;
        Ok(presigned.uri().to_string())
    }

    /// Read an object back as a stream.
    ///
    /// Preferred over [`Self::get_object`] for anything artifact-sized: the
    /// caller can decompress and forward as bytes arrive, so peak memory does
    /// not scale with the object.
    pub async fn get_object_reader(
        &self,
        key: &ObjectKey,
    ) -> eyre::Result<impl tokio::io::AsyncRead + Unpin + Send> {
        let object = self
            .s3
            .get_object()
            .bucket(&self.bucket)
            .key(key.as_str())
            .send()
            .await
            .wrap_err_with(|| format!("fetching {key}"))?;
        Ok(object.body.into_async_read())
    }

    /// Read an object back, whole.
    ///
    /// Only for things known to be small — a build log. Artifacts should use
    /// [`Self::get_object_reader`].
    pub async fn get_object(&self, key: &ObjectKey) -> eyre::Result<Vec<u8>> {
        let object = self
            .s3
            .get_object()
            .bucket(&self.bucket)
            .key(key.as_str())
            .send()
            .await
            .wrap_err_with(|| format!("fetching {key}"))?;
        let bytes = object
            .body
            .collect()
            .await
            .wrap_err_with(|| format!("reading {key}"))?
            .into_bytes();
        tracing::debug!(%key, bytes = bytes.len(), "fetched object");
        Ok(bytes.to_vec())
    }

    /// Delete an object outright.
    ///
    /// Only PLAN.md Phase 12's sweep calls this — nothing on the serving path
    /// ever removes bytes. S3 `DeleteObject` is idempotent (deleting an
    /// already-absent key is not an error), which matters here: a sweep that
    /// crashed after deleting the object but before deleting its `objects`
    /// row will call this again on retry, and that must not fail.
    pub async fn delete_object(&self, key: &ObjectKey) -> eyre::Result<()> {
        self.s3
            .delete_object()
            .bucket(&self.bucket)
            .key(key.as_str())
            .send()
            .await
            .wrap_err_with(|| format!("deleting {key}"))?;
        tracing::debug!(%key, "deleted object");
        Ok(())
    }

    /// The same capability model in the read direction: workers fetch staged
    /// inputs with these rather than holding credentials.
    pub async fn presign_get(&self, key: &ObjectKey) -> eyre::Result<String> {
        let presigned = self
            .s3
            .get_object()
            .bucket(&self.bucket)
            .key(key.as_str())
            .presigned(PresigningConfig::expires_in(URL_TTL).wrap_err("building presign config")?)
            .await
            .wrap_err_with(|| format!("presigning a download for {key}"))?;
        Ok(presigned.uri().to_string())
    }

    /// Serve upload-URL requests until the connection drops.
    ///
    /// Uses a queue group so that with several frontends exactly one answers
    /// each request. `store` is consulted for every request's capability
    /// secret — see [`Capability::verify`] — never for anything else here.
    pub async fn serve(self, client: async_nats::Client, store: Arc<dyn Store>) -> eyre::Result<()> {
        let mut requests = client
            .queue_subscribe(UPLOADS_SUBJECT, "kubernix-frontends".to_string())
            .await
            .wrap_err_with(|| format!("subscribing to {UPLOADS_SUBJECT}"))?;

        tracing::info!(subject = UPLOADS_SUBJECT, "serving upload url requests");

        while let Some(message) = requests.next().await {
            let Some(reply) = message.reply.clone() else {
                tracing::warn!("upload request with no reply subject, ignoring");
                continue;
            };

            let response = self.handle(&message.payload, &*store).await;
            // Encoded in a scope that ends before the next await: the capnp
            // builder is !Send.
            let payload = match encode_response(&response) {
                Ok(payload) => payload,
                Err(e) => {
                    tracing::error!(error = %e, "could not encode upload response");
                    continue;
                }
            };

            if let Err(e) = client.publish(reply, payload.into()).await {
                tracing::error!(error = %e, "could not reply to upload request");
            }
        }
        Ok(())
    }

    async fn handle(&self, payload: &[u8], store: &dyn Store) -> Result<Vec<String>, String> {
        // Decode to owned values first. capnp readers are !Send, and holding one
        // across the presigning awaits would make this future !Send — which it
        // cannot be, since it runs under tokio::spawn.
        let (job_id, keys, download, token) = decode_request(payload)?;

        // The tenant this request is scoped to comes entirely from the
        // verified token — there is no separate wire `tenant` field to trust
        // or mistrust (PLAN.md Phase 14).
        let Some(capability) = Capability::verify(&token, store).await else {
            tracing::warn!(%job_id, "refusing url request with an unverifiable capability token");
            return Err("invalid or missing capability token".to_string());
        };
        let tenant = &capability.tenant;

        // Validate every key before signing any: a request containing one
        // disallowed key is refused whole rather than partially honoured.
        if download {
            for key in &keys {
                if !key_is_permitted(key, download, tenant) {
                    tracing::warn!(%job_id, %tenant, %key, "refusing download url for disallowed key");
                    return Err(format!("key not permitted: {key}"));
                }
            }
        } else {
            // Uploads are scoped narrower still: not just "somewhere under
            // this tenant's namespace" but "one of this job's own verified
            // outputs, or its log" — otherwise a worker could still overwrite
            // some other job's output within its own tenant (Gap 2).
            let allowed: HashSet<ObjectKey> = capability
                .expected_outputs
                .iter()
                .filter_map(|(_, path)| crate::store::nar_key(tenant, Tier::Built, path))
                .chain(crate::store::log_key(tenant, &capability.derivation_path))
                .collect();
            for key in &keys {
                if !key_is_permitted(key, download, tenant) || !allowed.contains(key) {
                    tracing::warn!(
                        %job_id, %tenant, %key,
                        "refusing upload url for a key outside this job's verified outputs"
                    );
                    return Err(format!("key not permitted: {key}"));
                }
            }
        }

        let mut urls = Vec::with_capacity(keys.len());
        for key in &keys {
            let url = if download {
                self.presign_get(key).await
            } else {
                self.presign_put(key).await
            }
            .map_err(to_worker_error)?;
            urls.push(url);
        }

        tracing::info!(
            %job_id,
            %tenant,
            count = urls.len(),
            direction = if download { "download" } else { "upload" },
            "issued pre-signed urls"
        );
        Ok(urls)
    }
}

/// Turn an internal error into what a worker sees over the wire.
///
/// The worker is a trusted internal component, not the Nix end user, but the
/// same discipline applies: an S3 error's text (bucket names, request ids)
/// stays in the server's own log, and the worker gets a message it can act
/// on — retry, or give up and report its own generic failure upstream.
fn to_worker_error(report: eyre::Report) -> String {
    if let Some(message) = public_message(&report) {
        return message;
    }
    tracing::error!(error = ?report, "internal error handling an upload-url request");
    "internal error; see server logs".to_string()
}

type UrlRequest = (String, Vec<ObjectKey>, bool, CapabilityToken);

fn decode_request(payload: &[u8]) -> Result<UrlRequest, String> {
    let mut cursor = payload;
    let reader = capnp::serialize::read_message(&mut cursor, capnp::message::ReaderOptions::new())
        .map_err(|e| format!("undecodable request: {e}"))?;
    let request = reader
        .get_root::<kubernix_capnp::upload_url_request::Reader>()
        .map_err(|e| format!("undecodable request: {e}"))?;

    let job_id = request
        .get_job_id()
        .ok()
        .and_then(|t| t.to_string().ok())
        .unwrap_or_default();

    let mut keys = Vec::new();
    for key in request.get_keys().map_err(|e| e.to_string())?.iter() {
        keys.push(ObjectKey::new(
            key.map_err(|e| e.to_string())?
                .to_string()
                .map_err(|e| e.to_string())?,
        ));
    }

    let token = CapabilityToken::new(request.get_token().map_err(|e| e.to_string())?.to_vec());

    Ok((job_id, keys, request.get_download(), token))
}

fn encode_response(response: &Result<Vec<String>, String>) -> capnp::Result<Vec<u8>> {
    let mut message = capnp::message::Builder::new_default();
    {
        let mut builder = message.init_root::<kubernix_capnp::upload_url_response::Builder>();
        match response {
            Ok(urls) => {
                let mut list = builder.reborrow().init_urls(urls.len() as u32);
                for (i, url) in urls.iter().enumerate() {
                    list.set(i as u32, url.as_str());
                }
            }
            Err(message) => builder.set_error_msg(message.as_str()),
        }
    }
    let mut payload = Vec::new();
    capnp::serialize::write_message(&mut payload, &message)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    const UPLOAD: bool = false;
    const DOWNLOAD: bool = true;

    fn tenant(name: &str) -> TenantId {
        crate::tenant::Tenant::from_ssh(name, None, false).id
    }

    const P: &str = "00000000000000000000000000000000-thing";

    fn p() -> kubernix_types::StorePath {
        kubernix_types::StorePath::new(P)
    }

    /// `<tenant>/<suffix>`, as the frontend and worker both build them.
    fn key(t: &TenantId, suffix: &str) -> ObjectKey {
        ObjectKey::new(format!("{t}/{suffix}"))
    }

    mod to_worker_error_tests {
        use super::*;
        use kubernix_types::errors::Public;

        #[test]
        fn an_opaque_internal_error_is_not_leaked() {
            let io_err = std::io::Error::other("SignatureDoesNotMatch: bucket=kubernix-cache");
            let report = eyre::Report::new(io_err).wrap_err("presigning an upload");
            let message = to_worker_error(report);
            assert!(
                !message.contains("SignatureDoesNotMatch") && !message.contains("kubernix-cache"),
                "internal detail leaked into a worker-facing message: {message}"
            );
        }

        #[test]
        fn a_public_marked_cause_passes_through_verbatim() {
            let report: eyre::Report = Public::new("key not permitted").into();
            assert_eq!(to_worker_error(report), "key not permitted");
        }
    }

    #[test]
    fn permits_artifact_keys() {
        let t = tenant("alice");
        assert!(key_is_permitted(&key(&t, "nar/abc123.nar.zst"), UPLOAD, &t));
        assert!(key_is_permitted(&key(&t, "log/def456"), UPLOAD, &t));
    }

    #[test]
    fn refuses_anything_else() {
        // A worker must not be able to write outside the artifact namespaces,
        // escape them, or address the bucket root.
        let t = tenant("alice");
        assert!(!key_is_permitted(&key(&t, "secrets/creds"), UPLOAD, &t));
        assert!(!key_is_permitted(
            &key(&t, "nar/../secrets/creds"),
            UPLOAD,
            &t
        ));
        assert!(!key_is_permitted(&ObjectKey::new("/nar/abc"), UPLOAD, &t));
        assert!(!key_is_permitted(&ObjectKey::new(""), UPLOAD, &t));
        // Unprefixed keys are the pre-tenancy shape and must no longer pass.
        assert!(!key_is_permitted(
            &ObjectKey::new("nar/abc123.nar.zst"),
            UPLOAD,
            &t
        ));
    }

    #[test]
    fn a_verified_objects_shared_key_is_downloadable_by_any_tenant() {
        // PLAN.md Phase 9c: a `Verified` object carries no tenant prefix, so
        // this is the one key shape that must NOT require the tenant match —
        // any tenant whose job needs it as an input may fetch it.
        let (alice, bob) = (tenant("alice"), tenant("bob"));
        let shared = crate::store::nar_key(&alice, crate::store::Tier::Verified, &p()).unwrap();

        assert!(key_is_permitted(&shared, DOWNLOAD, &alice));
        assert!(key_is_permitted(&shared, DOWNLOAD, &bob));

        // But never for upload: only the frontend writes these, directly,
        // with its own credentials. A worker asking to *write* the shared
        // prefix is not making a legitimate request.
        assert!(!key_is_permitted(&shared, UPLOAD, &alice));
        assert!(!key_is_permitted(&shared, UPLOAD, &bob));
    }

    #[test]
    fn a_shared_looking_key_must_still_be_a_real_hash() {
        // The download carve-out is structural, not a blanket exemption for
        // anything starting with `nar/` — that would hand back the unscoped
        // pre-tenancy behaviour `refuses_anything_else` guards against.
        let t = tenant("alice");
        assert!(!key_is_permitted(
            &ObjectKey::new("nar/abc123.nar.zst"),
            DOWNLOAD,
            &t
        ));
        assert!(!key_is_permitted(
            &ObjectKey::new("nar/../secrets"),
            DOWNLOAD,
            &t
        ));
        // Right length, wrong alphabet: `e` is one of the four letters Nix's
        // base32 omits (RFC 4648 has it; this is not that).
        assert!(!key_is_permitted(
            &ObjectKey::new(format!("nar/{}.nar.zst", "e".repeat(32))),
            DOWNLOAD,
            &t
        ));
    }

    #[test]
    fn inputs_and_outputs_share_one_namespace() {
        // A path has exactly one representation in the object store, so the
        // input a worker fetches and the output it writes are the same shape and
        // the same prefix. There is no longer an `input/` namespace to separate.
        let t = tenant("alice");
        let key = key(&t, "nar/abc.nar.zst");
        assert!(key_is_permitted(&key, DOWNLOAD, &t));
        assert!(key_is_permitted(&key, UPLOAD, &t));

        // What a worker still may not write is anything the frontend vouches
        // differently for.
        assert!(!key_is_permitted(
            &crate::store::nar_key(&t, crate::store::Tier::Quarantined, &p()).unwrap(),
            UPLOAD,
            &t
        ));
    }

    #[test]
    fn escapes_are_refused_in_both_directions() {
        let t = tenant("alice");
        assert!(!key_is_permitted(
            &key(&t, "nar/../secrets/creds"),
            DOWNLOAD,
            &t
        ));
        assert!(!key_is_permitted(&key(&t, "secrets/creds"), DOWNLOAD, &t));
    }

    #[test]
    fn quarantined_inputs_are_still_readable_by_a_worker() {
        // Quarantine limits who may *rely* on a path, not who may build with it.
        // Refusing this would break every build whose inputs are ordinary
        // input-addressed store paths, which is most of them.
        let t = tenant("alice");
        assert!(key_is_permitted(
            &key(&t, "untrusted/nar/abc.nar.zst"),
            DOWNLOAD,
            &t
        ));
        // But a worker never writes there: its own outputs are `built`.
        assert!(!key_is_permitted(
            &key(&t, "untrusted/nar/abc.nar.zst"),
            UPLOAD,
            &t
        ));
        assert!(!key_is_permitted(
            &key(&t, "untrusted/nar/abc.nar.zst"),
            UPLOAD,
            &t
        ));
        // And it is still confined to its tenant.
        assert!(!key_is_permitted(
            &key(&t, "untrusted/nar/abc.nar.zst"),
            DOWNLOAD,
            &tenant("bob")
        ));
    }

    #[test]
    fn a_worker_cannot_reach_another_tenants_artifacts() {
        // The point of the whole phase: a worker running alice's job holds a
        // capability for alice's keys and nothing else, in either direction.
        let (alice, bob) = (tenant("alice"), tenant("bob"));
        let bobs_nar = key(&bob, "nar/abc123.nar.zst");

        assert!(key_is_permitted(&bobs_nar, DOWNLOAD, &bob));
        assert!(!key_is_permitted(&bobs_nar, DOWNLOAD, &alice));
        assert!(!key_is_permitted(&bobs_nar, UPLOAD, &alice));
        assert!(!key_is_permitted(
            &key(&bob, "nar/abc.nar.zst"),
            DOWNLOAD,
            &alice
        ));
    }

    #[test]
    fn a_tenant_is_not_a_prefix_of_another() {
        // Without matching the separator, tenant `a` would be granted every key
        // belonging to `ab`. Ids are hash-suffixed so this cannot arise from
        // `from_ssh`, but the check must not depend on that.
        let a = TenantId::from_wire("a").expect("well formed");
        let ab = TenantId::from_wire("ab").expect("well formed");
        assert!(!key_is_permitted(
            &ObjectKey::new("ab/nar/x.nar.zst"),
            DOWNLOAD,
            &a
        ));
        assert!(key_is_permitted(
            &ObjectKey::new("ab/nar/x.nar.zst"),
            DOWNLOAD,
            &ab
        ));
    }

    /// An `UploadSigner` that never makes a network call: presigning is a pure
    /// local SigV4 computation, so a client built from fake, offline
    /// credentials is enough to exercise `handle` end to end, including its
    /// happy path.
    fn stub_signer() -> UploadSigner {
        let config = aws_sdk_s3::config::Builder::new()
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .credentials_provider(aws_sdk_s3::config::Credentials::new(
                "test", "test", None, None, "test",
            ))
            .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
            .build();
        UploadSigner {
            s3: aws_sdk_s3::Client::from_conf(config),
            bucket: "test-bucket".to_string(),
        }
    }

    /// A job authorized to produce exactly one output, `p()`, under `tenant`.
    fn capability_for(tenant: &TenantId) -> Capability {
        Capability {
            job_id: uuid::Uuid::new_v4(),
            tenant: tenant.clone(),
            derivation_path: kubernix_types::StorePath::new(
                "00000000000000000000000000000000-x.drv",
            ),
            expected_outputs: vec![("out".to_string(), p())],
        }
    }

    fn request_payload(keys: &[ObjectKey], download: bool, token: &CapabilityToken) -> Vec<u8> {
        let mut message = capnp::message::Builder::new_default();
        {
            let mut request = message.init_root::<kubernix_capnp::upload_url_request::Builder>();
            request.set_job_id("job");
            request.set_download(download);
            request.set_token(token.as_bytes());
            let mut list = request.reborrow().init_keys(keys.len() as u32);
            for (i, key) in keys.iter().enumerate() {
                list.set(i as u32, key.as_str());
            }
        }
        let mut payload = Vec::new();
        capnp::serialize::write_message(&mut payload, &message).unwrap();
        payload
    }

    #[tokio::test]
    async fn handle_refuses_a_request_with_no_token() {
        let signer = stub_signer();
        let store = crate::store::MemoryStore::new();
        let alice = tenant("alice");
        let payload = request_payload(
            &[key(&alice, "nar/abc.nar.zst")],
            DOWNLOAD,
            &CapabilityToken::default(),
        );
        assert!(signer.handle(&payload, &*store).await.is_err());
    }

    #[tokio::test]
    async fn handle_refuses_a_tampered_token() {
        let signer = stub_signer();
        let store = crate::store::MemoryStore::new();
        let alice = tenant("alice");
        let (kid, secret) = store.current_capability_secret().await;
        let mut bytes = capability_for(&alice).sign(kid, &secret).into_bytes();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xff;
        let token = CapabilityToken::new(bytes);
        let payload = request_payload(&[key(&alice, "nar/abc.nar.zst")], DOWNLOAD, &token);
        assert!(signer.handle(&payload, &*store).await.is_err());
    }

    #[tokio::test]
    async fn handle_scopes_access_to_the_tokens_own_tenant() {
        // The core Gap-1 regression (PLAN.md Phase 14): there is no wire
        // `tenant` field to forge any more — a token minted for alice simply
        // cannot reach bob's keys, full stop.
        let signer = stub_signer();
        let store = crate::store::MemoryStore::new();
        let (alice, bob) = (tenant("alice"), tenant("bob"));
        let (kid, secret) = store.current_capability_secret().await;
        let token = capability_for(&alice).sign(kid, &secret);

        let bobs_key = key(&bob, "nar/abc123.nar.zst");
        let payload = request_payload(&[bobs_key], DOWNLOAD, &token);
        assert!(signer.handle(&payload, &*store).await.is_err());
    }

    #[tokio::test]
    async fn handle_refuses_an_upload_outside_the_jobs_verified_outputs() {
        // The core Gap-2-at-the-URL-layer regression: a token authorizes
        // uploads for its own job's outputs only, not anything else under the
        // same tenant.
        let signer = stub_signer();
        let store = crate::store::MemoryStore::new();
        let alice = tenant("alice");
        let (kid, secret) = store.current_capability_secret().await;
        let token = capability_for(&alice).sign(kid, &secret); // authorizes only p()

        let other = crate::store::nar_key(
            &alice,
            crate::store::Tier::Built,
            &kubernix_types::StorePath::new(
                "22222222222222222222222222222222-unrelated",
            ),
        )
        .unwrap();
        let payload = request_payload(&[other], UPLOAD, &token);
        assert!(signer.handle(&payload, &*store).await.is_err());
    }

    #[tokio::test]
    async fn handle_permits_an_upload_for_a_jobs_verified_output() {
        let signer = stub_signer();
        let store = crate::store::MemoryStore::new();
        let alice = tenant("alice");
        let (kid, secret) = store.current_capability_secret().await;
        let token = capability_for(&alice).sign(kid, &secret);

        let output_key = crate::store::nar_key(&alice, crate::store::Tier::Built, &p()).unwrap();
        let payload = request_payload(&[output_key], UPLOAD, &token);
        let urls = signer
            .handle(&payload, &*store)
            .await
            .expect("this job's own verified output is permitted");
        assert_eq!(urls.len(), 1);
    }

    #[tokio::test]
    async fn handle_permits_a_download_of_a_staged_input_under_the_same_tenant() {
        // Downloads keep the broader, existing `key_is_permitted` scoping —
        // only the tenant it is checked against changed (now the token's,
        // not a wire field).
        let signer = stub_signer();
        let store = crate::store::MemoryStore::new();
        let alice = tenant("alice");
        let (kid, secret) = store.current_capability_secret().await;
        let token = capability_for(&alice).sign(kid, &secret);

        let input_key = key(&alice, "nar/abc123.nar.zst"); // not one of the job's own outputs
        let payload = request_payload(&[input_key], DOWNLOAD, &token);
        let urls = signer
            .handle(&payload, &*store)
            .await
            .expect("a staged input under the job's own tenant is permitted");
        assert_eq!(urls.len(), 1);
    }
}
