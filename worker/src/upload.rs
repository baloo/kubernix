//! Uploading build artifacts to the object store.
//!
//! The worker holds no S3 credentials. It asks the frontend for pre-signed `PUT`
//! URLs for the exact keys it intends to write, then uploads directly — so large
//! outputs never traverse the frontend, but no credential ever reaches here.

use std::process::Stdio;

use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio::process::Command;

use crate::kubernix_capnp;

/// Metadata the frontend needs to build a narinfo, which it cannot recompute
/// because it never sees the build.
pub struct OutputArtifact {
    pub store_path: String,
    /// sha256 of the uncompressed NAR — what Nix verifies against.
    pub nar_hash: Vec<u8>,
    pub nar_size: u64,
    /// sha256 of the compressed object — what a client downloads.
    pub file_hash: Vec<u8>,
    pub file_size: u64,
    pub key: String,
    pub references: Vec<String>,
    pub deriver: String,
}

/// `/nix/store/<32-char hash>-<name>` → `<32-char hash>`.
pub fn hash_part_of(path: &str) -> Option<&str> {
    let base = path.rsplit('/').next()?;
    let hash = base.split('-').next()?;
    (hash.len() == 32).then_some(hash)
}

pub fn nar_key(store_path: &str) -> Option<String> {
    Some(format!("nar/{}.nar.zst", hash_part_of(store_path)?))
}

pub fn log_key(drv_path: &str) -> Option<String> {
    Some(format!("log/{}", hash_part_of(drv_path)?))
}

/// Ask the frontend to pre-sign the given keys.
pub async fn request_upload_urls(
    client: &async_nats::Client,
    job_id: &str,
    keys: &[String],
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut message = capnp::message::Builder::new_default();
    {
        let mut request = message.init_root::<kubernix_capnp::upload_url_request::Builder>();
        request.set_job_id(job_id);
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
    let reader =
        capnp::serialize::read_message(&mut cursor, capnp::message::ReaderOptions::new())?;
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
    key: String,
    store_path: &str,
    nix_store: &str,
) -> Result<OutputArtifact, Box<dyn std::error::Error>> {
    let mut child = Command::new(nix_store)
        .arg("--dump")
        .arg(store_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    let mut stdout = child.stdout.take().expect("piped");

    let mut nar_hasher = Sha256::new();
    let mut nar_size: u64 = 0;
    let mut encoder = zstd::stream::Encoder::new(Vec::new(), 3)?;

    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let read = stdout.read(&mut buf).await?;
        if read == 0 {
            break;
        }
        nar_hasher.update(&buf[..read]);
        nar_size += read as u64;
        std::io::Write::write_all(&mut encoder, &buf[..read])?;
    }

    let status = child.wait().await?;
    if !status.success() {
        return Err(format!("{nix_store} --dump {store_path} exited with {status}").into());
    }

    let compressed = encoder.finish()?;
    let file_size = compressed.len() as u64;
    let file_hash = Sha256::digest(&compressed).to_vec();

    let response = http
        .put(url)
        .header("content-type", "application/x-nix-nar-zstd")
        .body(compressed)
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(format!("uploading {key}: HTTP {}", response.status()).into());
    }

    let (references, deriver) = query_path_metadata(nix_store, store_path).await?;

    Ok(OutputArtifact {
        store_path: store_path.to_string(),
        nar_hash: nar_hasher.finalize().to_vec(),
        nar_size,
        file_hash,
        file_size,
        key,
        references,
        deriver,
    })
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
    key: &str,
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
    store_path: &str,
) -> Result<(Vec<String>, String), Box<dyn std::error::Error>> {
    let references = Command::new(nix_store)
        .arg("--query")
        .arg("--references")
        .arg(store_path)
        .output()
        .await?;
    let references = String::from_utf8_lossy(&references.stdout)
        .lines()
        .map(str::to_string)
        .collect();

    let deriver = Command::new(nix_store)
        .arg("--query")
        .arg("--deriver")
        .arg(store_path)
        .output()
        .await?;
    let deriver = String::from_utf8_lossy(&deriver.stdout).trim().to_string();
    // `--query --deriver` prints "unknown-deriver" when there is none.
    let deriver = if deriver == "unknown-deriver" {
        String::new()
    } else {
        deriver
    };

    Ok((references, deriver))
}

#[cfg(test)]
mod tests {
    use super::{hash_part_of, log_key, nar_key};

    const P: &str = "/nix/store/21d91afy6vgw4l00yzy92kp92b1w3cdm-kxs-testfile.txt";

    #[test]
    fn derives_keys_from_store_paths() {
        assert_eq!(
            hash_part_of(P),
            Some("21d91afy6vgw4l00yzy92kp92b1w3cdm")
        );
        assert_eq!(
            nar_key(P).as_deref(),
            Some("nar/21d91afy6vgw4l00yzy92kp92b1w3cdm.nar.zst")
        );
        assert_eq!(
            log_key(P).as_deref(),
            Some("log/21d91afy6vgw4l00yzy92kp92b1w3cdm")
        );
    }

    #[test]
    fn rejects_paths_without_a_hash_part() {
        assert_eq!(hash_part_of("/etc/passwd"), None);
        assert_eq!(hash_part_of("notapath"), None);
        assert_eq!(nar_key("/etc/passwd"), None);
    }
}
