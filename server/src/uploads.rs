//! Pre-signed upload URLs.
//!
//! The frontend is the only component with S3 credentials. Workers ask for
//! permission to write specific keys and receive time-limited pre-signed `PUT`
//! URLs in return, so what crosses the wire is a narrow expiring capability
//! rather than a credential — and build outputs go straight to the object store
//! instead of through the frontend.

use std::time::Duration;

use aws_sdk_s3::presigning::PresigningConfig;
use futures_util::StreamExt;

use kubernix_types::ObjectKey;

use crate::kubernix_capnp;
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
    pub async fn from_env() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
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
    pub async fn put_object(
        &self,
        key: &ObjectKey,
        body: Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let len = body.len();
        self.s3
            .put_object()
            .bucket(&self.bucket)
            .key(key.as_str())
            .body(body.into())
            .send()
            .await?;
        tracing::debug!(%key, bytes = len, "uploaded object");
        Ok(())
    }

    pub async fn presign_put(
        &self,
        key: &ObjectKey,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let presigned = self
            .s3
            .put_object()
            .bucket(&self.bucket)
            .key(key.as_str())
            .presigned(PresigningConfig::expires_in(URL_TTL)?)
            .await?;
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
    ) -> Result<impl tokio::io::AsyncRead + Unpin + Send, Box<dyn std::error::Error + Send + Sync>>
    {
        let object = self
            .s3
            .get_object()
            .bucket(&self.bucket)
            .key(key.as_str())
            .send()
            .await?;
        Ok(object.body.into_async_read())
    }

    /// Read an object back, whole.
    ///
    /// Only for things known to be small — a build log. Artifacts should use
    /// [`Self::get_object_reader`].
    pub async fn get_object(
        &self,
        key: &ObjectKey,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let object = self
            .s3
            .get_object()
            .bucket(&self.bucket)
            .key(key.as_str())
            .send()
            .await?;
        let bytes = object.body.collect().await?.into_bytes();
        tracing::debug!(%key, bytes = bytes.len(), "fetched object");
        Ok(bytes.to_vec())
    }

    /// The same capability model in the read direction: workers fetch staged
    /// inputs with these rather than holding credentials.
    pub async fn presign_get(
        &self,
        key: &ObjectKey,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let presigned = self
            .s3
            .get_object()
            .bucket(&self.bucket)
            .key(key.as_str())
            .presigned(PresigningConfig::expires_in(URL_TTL)?)
            .await?;
        Ok(presigned.uri().to_string())
    }

    /// Serve upload-URL requests until the connection drops.
    ///
    /// Uses a queue group so that with several frontends exactly one answers
    /// each request.
    pub async fn serve(
        self,
        client: async_nats::Client,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut requests = client
            .queue_subscribe(UPLOADS_SUBJECT, "kubernix-frontends".to_string())
            .await?;

        tracing::info!(subject = UPLOADS_SUBJECT, "serving upload url requests");

        while let Some(message) = requests.next().await {
            let Some(reply) = message.reply.clone() else {
                tracing::warn!("upload request with no reply subject, ignoring");
                continue;
            };

            let response = self.handle(&message.payload).await;
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

    async fn handle(&self, payload: &[u8]) -> Result<Vec<String>, String> {
        // Decode to owned values first. capnp readers are !Send, and holding one
        // across the presigning awaits would make this future !Send — which it
        // cannot be, since it runs under tokio::spawn.
        let (job_id, keys, download, tenant) = decode_request(payload)?;

        // A request that names no tenant cannot be scoped, so it cannot be
        // safely honoured at all.
        let Some(tenant) = tenant else {
            tracing::warn!(%job_id, "refusing url request with no tenant");
            return Err("request names no tenant".to_string());
        };

        // Validate every key before signing any: a request containing one
        // disallowed key is refused whole rather than partially honoured.
        for key in &keys {
            if !key_is_permitted(key, download, &tenant) {
                tracing::warn!(%job_id, %tenant, %key, download, "refusing url for disallowed key");
                return Err(format!("key not permitted: {key}"));
            }
        }

        let mut urls = Vec::with_capacity(keys.len());
        for key in &keys {
            let url = if download {
                self.presign_get(key).await
            } else {
                self.presign_put(key).await
            }
            .map_err(|e| format!("presigning {key}: {e}"))?;
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

type UrlRequest = (String, Vec<ObjectKey>, bool, Option<TenantId>);

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

    let tenant = request
        .get_tenant()
        .ok()
        .and_then(|t| t.to_string().ok())
        .and_then(TenantId::from_wire);

    let mut keys = Vec::new();
    for key in request.get_keys().map_err(|e| e.to_string())?.iter() {
        keys.push(ObjectKey::new(
            key.map_err(|e| e.to_string())?
                .to_string()
                .map_err(|e| e.to_string())?,
        ));
    }
    Ok((job_id, keys, request.get_download(), tenant))
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

    const P: &str = "/nix/store/00000000000000000000000000000000-thing";

    fn p() -> kubernix_types::StorePath {
        kubernix_types::StorePath::new(P)
    }

    /// `<tenant>/<suffix>`, as the frontend and worker both build them.
    fn key(t: &TenantId, suffix: &str) -> ObjectKey {
        ObjectKey::new(format!("{t}/{suffix}"))
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

    #[test]
    fn a_request_without_a_tenant_is_refused() {
        // Decoding yields None for an absent or malformed tenant, and `handle`
        // refuses rather than falling back to an unscoped grant.
        let mut message = capnp::message::Builder::new_default();
        {
            let mut request = message.init_root::<kubernix_capnp::upload_url_request::Builder>();
            request.set_job_id("job");
            request.reborrow().init_keys(1).set(0, "nar/x.nar.zst");
        }
        let mut payload = Vec::new();
        capnp::serialize::write_message(&mut payload, &message).unwrap();

        let (_, _, _, tenant) = decode_request(&payload).expect("decodable");
        assert!(tenant.is_none());
    }

    #[test]
    fn a_malformed_wire_tenant_decodes_to_none() {
        let mut message = capnp::message::Builder::new_default();
        {
            let mut request = message.init_root::<kubernix_capnp::upload_url_request::Builder>();
            request.set_job_id("job");
            request.set_tenant("../escape");
        }
        let mut payload = Vec::new();
        capnp::serialize::write_message(&mut payload, &message).unwrap();

        let (_, _, _, tenant) = decode_request(&payload).expect("decodable");
        assert!(tenant.is_none(), "an escaping tenant must not be honoured");
    }
}
