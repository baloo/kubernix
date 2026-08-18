//! The four `nix-daemon` operations that replace `serve.rs`'s/`upload.rs`'s
//! subprocess calls when a per-tenant VM is available (Phase 15 Step 3).
//!
//! Each function here mirrors one existing subprocess call site closely
//! enough to be a drop-in for it in `main.rs`'s job loop: [`build_derivation`]
//! mirrors `serve::ServeConnection::build_derivation`, [`upload_output`]
//! mirrors `upload::NixStore::upload_output`, [`fetch_input`] mirrors
//! `upload::NixStore::fetch_input`, and path metadata comes from
//! [`kubernix_daemon_protocol::DaemonConnection::query_path_info`] directly
//! rather than a fifth wrapper here.

use digest_io_async::HashWriter;
use eyre::{Context as _, OptionExt as _, bail};
use futures_util::StreamExt as _;
use kubernix_types::StorePath;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

use kubernix_daemon_protocol::DaemonConnection;

use crate::upload::OutputArtifact;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `None` for `StorePath::default()` — the wire's own "no deriver" sentinel
/// (`nar_export.rs`'s trailer comment: "empty when unknown"), not a distinct
/// representation invented here.
fn full_or_none(path: &StorePath, store_dir: &str) -> Option<String> {
    (!path.as_str().is_empty()).then(|| path.to_full(store_dir))
}

/// Build a derivation over the VM's `nix-daemon` connection. Same contract as
/// `serve::ServeConnection::build_derivation`: `drv` travels byte for byte,
/// for the reason both modules' doc comments give.
pub async fn build_derivation<S>(
    conn: &mut DaemonConnection<S>,
    drv_path_full: &str,
    drv: &[u8],
) -> eyre::Result<kubernix_daemon_protocol::BuildOutcome>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    conn.build_derivation(drv_path_full, drv)
        .await
        .wrap_err("building the derivation over the VM's daemon connection")
}

/// References and deriver for a store path, via one `QueryPathInfo` round
/// trip — replaces `upload::NixStore::query_path_metadata`'s two
/// `nix-store --query` subprocesses.
pub async fn path_metadata<S>(
    conn: &mut DaemonConnection<S>,
    store_path: &StorePath,
    store_dir: &str,
) -> eyre::Result<(Vec<StorePath>, Option<StorePath>)>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let full = store_path.to_full(store_dir);
    let info = conn
        .query_path_info(&full)
        .await
        .wrap_err_with(|| format!("querying path info for {store_path}"))?
        .ok_or_eyre("daemon reports the path we just built/imported as invalid")?;

    let references = info
        .references
        .iter()
        .map(|r| StorePath::from_full_or_err(store_dir, r))
        .collect::<Result<_, _>>()
        .wrap_err("KUBERNIX_STORE_DIR does not match the VM daemon's own idea of it")?;
    let deriver = info
        .deriver
        .map(|d| StorePath::from_full_or_err(store_dir, &d))
        .transpose()
        .wrap_err("KUBERNIX_STORE_DIR does not match the VM daemon's own idea of it")?;

    Ok((references, deriver))
}

/// `Op::NarFromPath`, hashed/compressed/spooled/uploaded exactly like
/// `upload::NixStore::upload_output`'s `nix store dump-path` pipeline — only
/// the byte source changes, from a subprocess's stdout to the daemon
/// connection's own NAR stream, run concurrently with hashing through an
/// in-process pipe so neither the raw nor the compressed NAR is ever fully
/// buffered.
pub async fn upload_output<S>(
    conn: &mut DaemonConnection<S>,
    http: &reqwest::Client,
    url: &str,
    key: kubernix_types::ObjectKey,
    store_path: &StorePath,
    store_dir: &str,
) -> eyre::Result<OutputArtifact>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let full = store_path.to_full(store_dir);

    let spool = tempfile::NamedTempFile::new().wrap_err("creating a spool file")?;
    let sink = tokio::fs::File::from_std(spool.reopen().wrap_err("reopening the spool file")?);

    // `nar_from_path` writes the raw NAR into `pipe_w`; `dump_hash_and_compress`
    // reads it back out of `pipe_r` and hashes/compresses it into `sink` — the
    // same pipeline `upload_output`'s subprocess path runs, just fed from an
    // in-process pipe instead of a child's stdout.
    let (pipe_w, pipe_r) = tokio::io::duplex(64 * 1024);

    let nar_task = async {
        let mut pipe_w = pipe_w;
        let result = conn.nar_from_path(&full, &mut pipe_w).await;
        // EOF for the reader: `nar_from_path` returning does not itself close
        // the duplex's write half.
        drop(pipe_w);
        result
    };
    let hash_task = crate::upload::NixStore::dump_hash_and_compress(pipe_r, sink);

    let (nar_result, hash_result) = tokio::join!(nar_task, hash_task);
    nar_result.wrap_err_with(|| format!("streaming the NAR for {store_path}"))?;
    let (nar_hash, nar_size, file_hash, file_size) =
        hash_result.wrap_err_with(|| format!("hashing/compressing {store_path}"))?;

    let body = reqwest::Body::wrap_stream(tokio_util::io::ReaderStream::new(
        tokio::fs::File::from_std(spool.reopen().wrap_err("reopening the spool file")?),
    ));
    let response = http
        .put(url)
        .header("content-type", "application/x-nix-nar-zstd")
        .header(reqwest::header::CONTENT_LENGTH, file_size)
        .body(body)
        .send()
        .await
        .wrap_err_with(|| format!("uploading {key}"))?;
    if !response.status().is_success() {
        bail!("uploading {key}: HTTP {}", response.status());
    }

    let (references, deriver) = path_metadata(conn, store_path, store_dir).await?;

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

/// Fetch a staged input and register it in the VM's store via
/// `Op::AddToStoreNar` — replaces `upload::NixStore::fetch_input`'s
/// `nix-store --import` subprocess. Unlike `--import`, `AddToStoreNar` needs
/// the NAR's hash and size *before* the framed body starts, so the
/// decompressed NAR is spooled to disk while being hashed first, then
/// streamed back out for the actual `add_to_store_nar` call — `--import`
/// gets to compute this itself as it reads; this protocol does not.
pub async fn fetch_input<S>(
    conn: &mut DaemonConnection<S>,
    http: &reqwest::Client,
    url: &str,
    store_path: &StorePath,
    references: &[StorePath],
    deriver: &StorePath,
    store_dir: &str,
) -> eyre::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let response = http
        .get(url)
        .send()
        .await
        .wrap_err_with(|| format!("fetching {store_path}"))?;
    if !response.status().is_success() {
        bail!("fetching {store_path}: HTTP {}", response.status());
    }

    let spool = tempfile::NamedTempFile::new().wrap_err("creating a spool file")?;
    let sink = tokio::fs::File::from_std(spool.reopen().wrap_err("reopening the spool file")?);
    let mut hashed = HashWriter::<Sha256, _>::new(sink);

    let mut decoder =
        zstd::stream::write::Decoder::new(Vec::new()).wrap_err("starting decompression")?;
    let mut body = response.bytes_stream();
    let mut nar_size: u64 = 0;
    while let Some(chunk) = body.next().await {
        std::io::Write::write_all(&mut decoder, &chunk.wrap_err_with(|| format!("fetching {store_path}"))?)
            .wrap_err_with(|| format!("decompressing {store_path}"))?;
        let decoded = std::mem::take(decoder.get_mut());
        if !decoded.is_empty() {
            nar_size += decoded.len() as u64;
            hashed
                .write_all(&decoded)
                .await
                .wrap_err("spooling the decompressed input")?;
        }
    }
    std::io::Write::flush(&mut decoder).wrap_err_with(|| format!("decompressing {store_path}"))?;
    let decoded = std::mem::take(decoder.get_mut());
    if !decoded.is_empty() {
        nar_size += decoded.len() as u64;
        hashed
            .write_all(&decoded)
            .await
            .wrap_err("spooling the decompressed input")?;
    }

    let (hasher, mut sink) = hashed.into_parts();
    sink.flush().await.wrap_err("flushing the spool file")?;
    let nar_hash = format!("sha256:{}", hex(&hasher.finalize()));

    let full = store_path.to_full(store_dir);
    let full_references: Vec<String> = references.iter().map(|r| r.to_full(store_dir)).collect();
    let full_deriver = full_or_none(deriver, store_dir);

    let reader = tokio::fs::File::from_std(spool.reopen().wrap_err("reopening the spool file")?);
    conn.add_to_store_nar(
        &full,
        full_deriver.as_deref(),
        &nar_hash,
        &full_references,
        // Nix's own daemon accepts whatever the client claims here and does
        // not treat it as meaningful beyond bookkeeping — `AddSignatures`/GC
        // liveness use `last_access`, computed separately. "Now" is as good
        // a claim as any.
        chrono_now(),
        nar_size,
        false, // ultimate: this worker did not build it, it fetched it
        &[],   // sigs: none carried across the wire today
        None,  // ca: not tracked for pushed/fetched inputs
        reader,
    )
    .await
    .wrap_err_with(|| format!("registering {store_path} in the VM's store"))
}

/// Unix timestamp, best-effort. `AddToStoreNar`'s `registrationTime` is
/// bookkeeping a real daemon records for its own use, not a value this
/// worker's callers read back — "now" is as good a claim as any for a path
/// being registered right now.
fn chrono_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
