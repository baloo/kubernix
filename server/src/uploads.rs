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

use crate::kubernix_capnp;

pub const UPLOADS_SUBJECT: &str = "kubernix.uploads";

/// How long a worker has to use a URL it was handed. Long enough for a large
/// output on a slow link, short enough that a leaked URL expires quickly.
const URL_TTL: Duration = Duration::from_secs(3600);

/// Keys a worker may be granted. Anything else is refused: the URLs are issued
/// by a trusted component, so the prefix check is what stops a compromised
/// worker from writing over unrelated objects.
fn key_is_permitted(key: &str) -> bool {
    if key.contains("..") || key.starts_with('/') {
        return false;
    }
    key.starts_with("nar/") || key.starts_with("log/")
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

    pub async fn presign_put(
        &self,
        key: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let presigned = self
            .s3
            .put_object()
            .bucket(&self.bucket)
            .key(key)
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
        let (job_id, keys) = decode_request(payload)?;

        // Validate every key before signing any: a request containing one
        // disallowed key is refused whole rather than partially honoured.
        for key in &keys {
            if !key_is_permitted(key) {
                tracing::warn!(%job_id, %key, "refusing upload url for disallowed key");
                return Err(format!("key not permitted: {key}"));
            }
        }

        let mut urls = Vec::with_capacity(keys.len());
        for key in &keys {
            let url = self
                .presign_put(key)
                .await
                .map_err(|e| format!("presigning {key}: {e}"))?;
            urls.push(url);
        }

        tracing::info!(%job_id, count = urls.len(), "issued pre-signed upload urls");
        Ok(urls)
    }
}

fn decode_request(payload: &[u8]) -> Result<(String, Vec<String>), String> {
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
        keys.push(
            key.map_err(|e| e.to_string())?
                .to_string()
                .map_err(|e| e.to_string())?,
        );
    }
    Ok((job_id, keys))
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
    use super::key_is_permitted;

    #[test]
    fn permits_artifact_keys() {
        assert!(key_is_permitted("nar/abc123.nar.zst"));
        assert!(key_is_permitted("log/def456"));
    }

    #[test]
    fn refuses_anything_else() {
        // A worker must not be able to write outside the artifact namespaces,
        // escape them, or address the bucket root.
        assert!(!key_is_permitted("secrets/creds"));
        assert!(!key_is_permitted("nar/../secrets/creds"));
        assert!(!key_is_permitted("/nar/abc"));
        assert!(!key_is_permitted(""));
    }
}
