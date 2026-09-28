//! Downloading a job input, decoupled from registering it.
//!
//! `Job::fetch_inputs` (`main.rs`) needs inputs registered in dependency
//! order (the guest's real `nix-daemon` rejects a path registered before
//! something it references), but nothing about the network fetch itself has
//! that constraint. This module is the download half only: it spools a
//! decompressed input to disk and verifies it against the `nar_hash`/
//! `nar_size` the server already knows for that path (see `InputRef`),
//! rather than computing them to decide what to declare the way
//! `vm_ops::register_input`'s predecessor used to. That lets `fetch_inputs`
//! run many of these concurrently, ahead of the still-sequential register
//! step in `vm_ops::register_input` / `upload::NixStore::import_spooled`.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use eyre::{Context as _, bail};
use futures_util::StreamExt as _;
use kubernix_types::Compression;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio_util::io::InspectWriter;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A downloaded, decompressed input NAR spooled to disk and already
/// verified against the server's declared hash/size -- ready to be streamed
/// straight into a register/import call with no further network or hashing
/// work.
#[derive(Debug)]
pub struct SpooledInput {
    pub file: tempfile::NamedTempFile,
}

/// Fetch `url`, decompress it, and spool the resulting NAR to a temp file,
/// verifying the result against `expected_nar_hash` (Nix's own wire form,
/// `"<algo>:<base16>"`) and `expected_nar_size`.
///
/// Only `sha256:`-prefixed hashes are supported: that's what every path a
/// modern kubernix deployment produces or substitutes actually carries (see
/// `postgres_store::algo_from_name`'s own "everything we produce is
/// sha256" assumption) -- anything else fails loudly here rather than
/// silently mismatching against a hash computed with the wrong algorithm.
pub async fn download_to_spool(
    http: &reqwest::Client,
    url: &str,
    compression: Compression,
    expected_nar_hash: &str,
    expected_nar_size: u64,
) -> eyre::Result<SpooledInput> {
    if !expected_nar_hash.starts_with("sha256:") {
        bail!(
            "input carries an unsupported nar_hash algorithm: {expected_nar_hash:?} \
             (only sha256 is supported)"
        );
    }

    let response = http.get(url).send().await.wrap_err("fetching input")?;
    if !response.status().is_success() {
        bail!("fetching input: HTTP {}", response.status());
    }

    let spool = tempfile::NamedTempFile::new().wrap_err("creating a spool file")?;
    let sink = tokio::fs::File::from_std(spool.reopen().wrap_err("reopening the spool file")?);

    // Tee'd purely to verify against the already-known hash/size, not to
    // learn them -- unlike the old inline fetch-then-register design, the
    // caller knows what to declare before this function ever runs. `Arc`/
    // `Mutex`, not `Rc`/`RefCell`: this function is spawned as its own task
    // by `Job::fetch_inputs` so several downloads can run concurrently,
    // which requires the whole future to be `Send` -- there's still only
    // ever one owner in practice, just one that has to satisfy that bound.
    let hasher = Arc::new(std::sync::Mutex::new(Sha256::new()));
    let nar_size = Arc::new(AtomicU64::new(0));
    let counted = InspectWriter::new(sink, {
        let hasher = hasher.clone();
        let nar_size = nar_size.clone();
        move |chunk: &[u8]| {
            hasher.lock().expect("not poisoned").update(chunk);
            nar_size.fetch_add(chunk.len() as u64, Ordering::Relaxed);
        }
    });

    let mut decoder =
        crate::decompress::decoder_for(compression, counted).wrap_err("starting decompression")?;
    let mut body = response.bytes_stream();
    while let Some(chunk) = body.next().await {
        decoder
            .write_all(&chunk.wrap_err("fetching input")?)
            .await
            .wrap_err("decompressing input")?;
    }
    // Flushes any codec's trailing buffered bytes through to the spool file
    // -- must happen before the hash/size below are read.
    decoder.shutdown().await.wrap_err("decompressing input")?;

    let nar_hash = format!(
        "sha256:{}",
        hex(&hasher.lock().expect("not poisoned").clone().finalize())
    );
    let nar_size = nar_size.load(Ordering::Relaxed);
    if nar_hash != expected_nar_hash || nar_size != expected_nar_size {
        bail!(
            "downloaded NAR does not match the server's record: expected {expected_nar_hash} \
             ({expected_nar_size} bytes), got {nar_hash} ({nar_size} bytes)"
        );
    }

    Ok(SpooledInput { file: spool })
}

#[cfg(test)]
mod tests {
    use async_compression::tokio::write::ZstdEncoder;
    use tokio::io::{AsyncReadExt, AsyncWriteExt as _};
    use tokio::net::TcpListener;

    use super::*;

    /// A bare-bones HTTP/1.1 server that replies with `body` to whatever it
    /// is sent, then closes the connection -- enough for `reqwest` to fetch
    /// it, with no HTTP-mocking crate pulled in for this one test module.
    async fn serve_once(body: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = socket.read(&mut buf).await;
            let mut response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .into_bytes();
            response.extend_from_slice(&body);
            let _ = socket.write_all(&response).await;
            let _ = socket.shutdown().await;
        });
        format!("http://{addr}/")
    }

    async fn zstd_compress(plain: &[u8]) -> Vec<u8> {
        let mut encoder = ZstdEncoder::new(Vec::new());
        encoder.write_all(plain).await.unwrap();
        encoder.shutdown().await.unwrap();
        encoder.into_inner()
    }

    /// `reqwest::Client::new()` eagerly loads the platform's native CA
    /// store at build time, even for a client that will only ever fetch
    /// plain `http://` URLs like these tests do -- and a sandboxed test
    /// environment with no system trust store at all makes that loading
    /// panic before a single request is sent. `tls_certs_only(empty)`
    /// skips native/built-in root loading entirely and uses no roots,
    /// which is fine since nothing here ever negotiates TLS.
    fn test_http_client() -> reqwest::Client {
        reqwest::Client::builder()
            .tls_certs_only(std::iter::empty())
            .build()
            .expect("building a plain-HTTP-only test client")
    }

    #[tokio::test]
    async fn accepts_a_download_matching_the_declared_hash_and_size() {
        let nar = b"hello world".to_vec();
        let compressed = zstd_compress(&nar).await;
        let nar_hash = format!("sha256:{}", hex(&Sha256::digest(&nar)));

        let url = serve_once(compressed).await;
        let http = test_http_client();
        let spooled =
            download_to_spool(&http, &url, Compression::Zstd, &nar_hash, nar.len() as u64)
                .await
                .unwrap();

        let mut out = Vec::new();
        tokio::fs::File::from_std(spooled.file.reopen().unwrap())
            .read_to_end(&mut out)
            .await
            .unwrap();
        assert_eq!(out, nar);
    }

    #[tokio::test]
    async fn rejects_a_download_that_does_not_match_the_declared_hash() {
        let nar = b"hello world".to_vec();
        let compressed = zstd_compress(&nar).await;
        let bogus_hash = format!("sha256:{}", hex(&Sha256::digest(b"not the same bytes")));

        let url = serve_once(compressed).await;
        let http = test_http_client();
        let err = download_to_spool(
            &http,
            &url,
            Compression::Zstd,
            &bogus_hash,
            nar.len() as u64,
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("does not match the server's record")
        );
    }

    #[tokio::test]
    async fn rejects_a_download_that_does_not_match_the_declared_size() {
        let nar = b"hello world".to_vec();
        let compressed = zstd_compress(&nar).await;
        let nar_hash = format!("sha256:{}", hex(&Sha256::digest(&nar)));

        let url = serve_once(compressed).await;
        let http = test_http_client();
        let err = download_to_spool(
            &http,
            &url,
            Compression::Zstd,
            &nar_hash,
            nar.len() as u64 + 1,
        )
        .await
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("does not match the server's record")
        );
    }

    #[tokio::test]
    async fn rejects_a_non_sha256_declared_hash() {
        let http = test_http_client();
        let err = download_to_spool(
            &http,
            "http://127.0.0.1:1/",
            Compression::None,
            "md5:abc",
            0,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("unsupported nar_hash algorithm"));
    }
}
