//! Uploading build artifacts to the object store.
//!
//! The worker holds no S3 credentials. It asks the frontend for pre-signed `PUT`
//! URLs for the exact keys it intends to write, then uploads directly — so large
//! outputs never traverse the frontend, but no credential ever reaches here.

use std::process::Stdio;

use async_compression::tokio::write::ZstdEncoder;
use digest_io::{HashReader, HashWriter};
use sha2::{Digest, Sha256, digest::Output};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use kubernix_types::{ObjectKey, StorePath, TenantId};

use crate::kubernix_capnp;

/// Metadata the frontend needs to build a narinfo, which it cannot recompute
/// because it never sees the build.
pub struct OutputArtifact {
    pub store_path: StorePath,
    /// sha256 of the uncompressed NAR — what Nix verifies against.
    pub nar_hash: Output<Sha256>,
    pub nar_size: u64,
    /// sha256 of the compressed object — what a client downloads.
    pub file_hash: Output<Sha256>,
    pub file_size: u64,
    pub key: ObjectKey,
    pub references: Vec<StorePath>,
    pub deriver: StorePath,
}

/// Artifact keys are tenant-scoped: the frontend signs a key only for the
/// tenant whose job asked for it, so the prefix is part of the key rather than
/// something applied later.
pub fn nar_key(tenant: &TenantId, store_path: &StorePath) -> Option<ObjectKey> {
    Some(ObjectKey::new(format!(
        "{tenant}/nar/{}.nar.zst",
        store_path.hash_part()?
    )))
}

pub fn log_key(tenant: &TenantId, drv_path: &StorePath) -> Option<ObjectKey> {
    Some(ObjectKey::new(format!(
        "{tenant}/log/{}",
        drv_path.hash_part()?
    )))
}

/// Ask the frontend to pre-sign the given keys for upload.
pub async fn request_upload_urls(
    client: &async_nats::Client,
    job_id: &str,
    tenant: &TenantId,
    keys: &[ObjectKey],
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    request_urls(client, job_id, tenant, keys, false).await
}

/// Ask the frontend to pre-sign the given keys for download.
///
/// Requested when the job is dequeued rather than baked into the job message:
/// a job can sit queued for longer than a URL's lifetime, and a URL minted at
/// submit time would have started expiring before any worker saw it.
pub async fn request_download_urls(
    client: &async_nats::Client,
    job_id: &str,
    tenant: &TenantId,
    keys: &[ObjectKey],
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    request_urls(client, job_id, tenant, keys, true).await
}

async fn request_urls(
    client: &async_nats::Client,
    job_id: &str,
    tenant: &TenantId,
    keys: &[ObjectKey],
    download: bool,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut message = capnp::message::Builder::new_default();
    {
        let mut request = message.init_root::<kubernix_capnp::upload_url_request::Builder>();
        request.set_job_id(job_id);
        request.set_download(download);
        request.set_tenant(tenant.as_str());
        let mut list = request.reborrow().init_keys(keys.len() as u32);
        for (i, key) in keys.iter().enumerate() {
            list.set(i as u32, key.as_str());
        }
    }
    let mut payload = Vec::new();
    capnp::serialize::write_message(&mut payload, &message)?;

    let reply = client
        .request(crate::UPLOADS_SUBJECT, payload.into())
        .await?;

    let mut cursor = reply.payload.as_ref();
    let reader = capnp::serialize::read_message(&mut cursor, capnp::message::ReaderOptions::new())?;
    let response = reader.get_root::<kubernix_capnp::upload_url_response::Reader>()?;

    let error = response.get_error_msg()?.to_string()?;
    if !error.is_empty() {
        return Err(format!("frontend refused upload: {error}").into());
    }

    let mut urls = Vec::new();
    for url in response.get_urls()?.iter() {
        urls.push(url?.to_string()?);
    }
    if urls.len() != keys.len() {
        return Err(format!("expected {} urls, got {}", keys.len(), urls.len()).into());
    }
    Ok(urls)
}

/// Dump a store path as a NAR, compress it, and PUT it to `url`.
///
/// Hashes both the uncompressed and compressed byte streams in the *same* pass:
/// buffering the whole NAR to hash it afterwards would defeat the point for a
/// large closure.
pub async fn upload_output(
    http: &reqwest::Client,
    url: &str,
    key: ObjectKey,
    store_path: &StorePath,
    nix_store: &str,
    nix_cli: &str,
    store_uri: Option<&str>,
) -> Result<OutputArtifact, Box<dyn std::error::Error>> {
    // `nix store dump-path`, not `nix-store --dump`: the latter takes a
    // *filesystem* path and ignores --store entirely, so it cannot find an
    // output living under a chroot store root.
    let mut command = Command::new(nix_cli);
    command.arg("store").arg("dump-path");
    if let Some(uri) = store_uri {
        command.arg("--store").arg(uri);
    }
    let mut child = command
        .arg(store_path.as_str())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let stdout = child.stdout.take().expect("piped");
    // Compressed as the NAR arrives, into a temporary file rather than memory,
    // so nothing here scales with the size of the output. Both hashes are
    // computed in the same pass — buffering to hash afterwards would defeat the
    // point for a large closure.
    //
    // Why a file and not a streaming request body: a pre-signed PUT is signed
    // for a specific request, and a streaming body means chunked
    // transfer-encoding with no `Content-Length`, which S3 rejects outright
    // (`HTTP 400`). Spooling to disk gives a length to declare while keeping
    // *memory* flat, which is what actually mattered.
    let spool = tempfile::NamedTempFile::new()?;
    let sink = tokio::fs::File::from_std(spool.reopen()?);

    // `HashReader`/`HashWriter` (digest-io) hash a stream as it passes
    // through; `ZstdEncoder` (async-compression) compresses one as it's
    // written. Stacking them turns the whole dump -> hash -> compress ->
    // hash -> spool pipeline into a single `tokio::io::copy`, with no manual
    // buffering.
    let mut nar_reader = HashReader::<Sha256, _>::new(stdout);
    let file_writer = HashWriter::<Sha256, _>::new(sink);
    let mut encoder = ZstdEncoder::with_quality(file_writer, async_compression::Level::Precise(3));

    let nar_size = tokio::io::copy(&mut nar_reader, &mut encoder).await?;
    // Flushes zstd's trailing frame bytes through the `HashWriter` — must
    // happen before the file hash/size below are read.
    encoder.shutdown().await?;
    let file_writer = encoder.into_inner();

    let nar_hash = nar_reader.finalize();
    let (file_hasher, mut sink) = file_writer.into_parts();
    sink.flush().await?;
    let file_hash = file_hasher.finalize();
    let file_size = sink.metadata().await?.len();
    drop(sink);

    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr).await;
    }
    let status = child.wait().await?;
    if !status.success() {
        return Err(format!("dumping {store_path}: {} ({status})", stderr.trim()).into());
    }

    // Streamed from disk with the length declared, so the request is one the
    // pre-signed URL will accept.
    let body = reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::new(
        tokio::fs::File::from_std(spool.reopen()?),
    ));
    let response = http
        .put(url)
        .header("content-type", "application/x-nix-nar-zstd")
        .header(reqwest::header::CONTENT_LENGTH, file_size)
        .body(body)
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(format!("uploading {key}: HTTP {}", response.status()).into());
    }

    let (references, deriver) = query_path_metadata(nix_store, store_path, store_uri).await?;

    Ok(OutputArtifact {
        store_path: store_path.clone(),
        nar_hash,
        nar_size,
        file_hash,
        file_size,
        key,
        references,
        deriver,
    })
}

/// Fetch a staged input and import it into the local store.
///
/// The object is a zstd-compressed *bare NAR* -- the same shape every artifact
/// has. `--import` needs an export stream, so the wrapping is added here, which
/// is why the references and deriver travel alongside the key rather than being
/// stored a second time.
///
/// Streamed end to end: fetched, decompressed and piped into the child a chunk
/// at a time, so peak memory does not scale with the size of the input.
pub async fn fetch_input(
    http: &reqwest::Client,
    url: &str,
    store_path: &StorePath,
    references: &[StorePath],
    deriver: &StorePath,
    nix_store: &str,
    store_uri: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = http.get(url).send().await?;
    if !response.status().is_success() {
        return Err(format!("fetching {store_path}: HTTP {}", response.status()).into());
    }

    let mut command = Command::new(nix_store);
    if let Some(uri) = store_uri {
        command.arg("--store").arg(uri);
    }
    let mut child = command
        .arg("--import")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    {
        use futures_util::StreamExt as _;
        use std::io::Write as _;

        let mut stdin = child.stdin.take().expect("piped");

        // The object is a bare NAR; `--import` wants an export stream. The
        // wrapping is built here rather than stored, so the object store holds
        // one representation of a path rather than two — see `nar_export`.
        stdin.write_all(&crate::nar_export::header()).await?;

        // Decompressed as it arrives rather than in one piece: peak memory is a
        // chunk, not the whole NAR. `zstd`'s streaming writer is enough for
        // this, so it needs no additional dependency.
        let mut decoder = zstd::stream::write::Decoder::new(Vec::new())?;
        let mut body = response.bytes_stream();
        while let Some(chunk) = body.next().await {
            decoder.write_all(&chunk?)?;
            let decoded = std::mem::take(decoder.get_mut());
            if !decoded.is_empty() {
                stdin.write_all(&decoded).await?;
            }
        }
        decoder.flush()?;
        let decoded = std::mem::take(decoder.get_mut());
        if !decoded.is_empty() {
            stdin.write_all(&decoded).await?;
        }

        stdin
            .write_all(&crate::nar_export::trailer(store_path, references, deriver))
            .await?;
        stdin.shutdown().await?;
    }

    let output = child.wait_with_output().await?;
    if !output.status.success() {
        return Err(format!(
            "importing {store_path}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    Ok(())
}

/// Upload the build log.
///
/// Uncompressed, unlike the NARs: `nix log` serves plain text, so an
/// uncompressed object can be handed straight to a client with no decompression
/// in the frontend, and logs are small next to outputs. Reversible later — see
/// PLAN.md Phase 6b.
pub async fn upload_log(
    http: &reqwest::Client,
    url: &str,
    key: &ObjectKey,
    log: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error>> {
    let response = http
        .put(url)
        .header("content-type", "text/plain; charset=utf-8")
        .body(log)
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(format!("uploading {key}: HTTP {}", response.status()).into());
    }
    Ok(())
}

async fn query_path_metadata(
    nix_store: &str,
    store_path: &StorePath,
    store_uri: Option<&str>,
) -> Result<(Vec<StorePath>, StorePath), Box<dyn std::error::Error>> {
    let with_store = |cmd: &str| {
        let mut c = Command::new(nix_store);
        if let Some(uri) = store_uri {
            c.arg("--store").arg(uri);
        }
        c.arg(cmd);
        c
    };

    let references = with_store("--query")
        .arg("--references")
        .arg(store_path.as_str())
        .output()
        .await?;
    let references = String::from_utf8_lossy(&references.stdout)
        .lines()
        .map(StorePath::new)
        .collect();

    let deriver = with_store("--query")
        .arg("--deriver")
        .arg(store_path.as_str())
        .output()
        .await?;
    let deriver = String::from_utf8_lossy(&deriver.stdout).trim().to_string();
    // `--query --deriver` prints "unknown-deriver" when there is none.
    let deriver = if deriver == "unknown-deriver" {
        StorePath::default()
    } else {
        StorePath::new(deriver)
    };

    Ok((references, deriver))
}

#[cfg(test)]
mod tests {
    use super::{log_key, nar_key};
    use kubernix_types::{ObjectKey, StorePath, TenantId};

    const P: &str = "/nix/store/21d91afy6vgw4l00yzy92kp92b1w3cdm-kxs-testfile.txt";

    fn p() -> StorePath {
        StorePath::new(P)
    }

    fn t(name: &str) -> TenantId {
        TenantId::from_wire(name).expect("well formed")
    }

    #[test]
    fn derives_keys_from_store_paths() {
        assert_eq!(p().hash_part(), Some("21d91afy6vgw4l00yzy92kp92b1w3cdm"));
        assert_eq!(
            nar_key(&t("tenant-1"), &p())
                .as_ref()
                .map(ObjectKey::as_str),
            Some("tenant-1/nar/21d91afy6vgw4l00yzy92kp92b1w3cdm.nar.zst")
        );
        assert_eq!(
            log_key(&t("tenant-1"), &p())
                .as_ref()
                .map(ObjectKey::as_str),
            Some("tenant-1/log/21d91afy6vgw4l00yzy92kp92b1w3cdm")
        );
    }

    #[test]
    fn keys_are_scoped_per_tenant() {
        // Two tenants building the same derivation must not collide in the
        // object store, and neither may be signed for the other.
        assert_ne!(nar_key(&t("tenant-1"), &p()), nar_key(&t("tenant-2"), &p()));
        assert_ne!(log_key(&t("tenant-1"), &p()), log_key(&t("tenant-2"), &p()));
    }

    #[test]
    fn rejects_paths_without_a_hash_part() {
        let bad = StorePath::new("/etc/passwd");
        assert_eq!(bad.hash_part(), None);
        assert_eq!(StorePath::new("notapath").hash_part(), None);
        assert_eq!(nar_key(&t("tenant-1"), &bad), None);
    }
}
