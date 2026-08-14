//! Uploading build artifacts to the object store.
//!
//! The worker holds no S3 credentials. It asks the frontend for pre-signed `PUT`
//! URLs for the exact keys it intends to write, then uploads directly — so large
//! outputs never traverse the frontend, but no credential ever reaches here.

use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_compression::tokio::write::ZstdEncoder;
use digest_io::{HashReader, HashWriter};
use eyre::{Context as _, bail};
use sha2::{Digest, Sha256, digest::Output};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio_util::io::InspectWriter;

use kubernix_types::{CapabilityToken, ObjectKey, StorePath, TenantId};

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
    /// `None` for a path with no deriver — `nix-store --query --deriver`
    /// prints `unknown-deriver` for those, rather than a path in `store_dir`.
    pub deriver: Option<StorePath>,
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
    token: &CapabilityToken,
    keys: &[ObjectKey],
) -> eyre::Result<Vec<String>> {
    request_urls(client, job_id, token, keys, false).await
}

/// Ask the frontend to pre-sign the given keys for download.
///
/// Requested when the job is dequeued rather than baked into the job message:
/// a job can sit queued for longer than a URL's lifetime, and a URL minted at
/// submit time would have started expiring before any worker saw it.
pub async fn request_download_urls(
    client: &async_nats::Client,
    job_id: &str,
    token: &CapabilityToken,
    keys: &[ObjectKey],
) -> eyre::Result<Vec<String>> {
    request_urls(client, job_id, token, keys, true).await
}

async fn request_urls(
    client: &async_nats::Client,
    job_id: &str,
    token: &CapabilityToken,
    keys: &[ObjectKey],
    download: bool,
) -> eyre::Result<Vec<String>> {
    let mut message = capnp::message::Builder::new_default();
    {
        let mut request = message.init_root::<kubernix_capnp::upload_url_request::Builder>();
        request.set_job_id(job_id);
        request.set_download(download);
        // The frontend authorizes this request entirely from `token` — there
        // is no separate wire `tenant` field, per PLAN.md Phase 14.
        request.set_token(token.as_bytes());
        let mut list = request.reborrow().init_keys(keys.len() as u32);
        for (i, key) in keys.iter().enumerate() {
            list.set(i as u32, key.as_str());
        }
    }
    let mut payload = Vec::new();
    capnp::serialize::write_message(&mut payload, &message).wrap_err("encoding an url request")?;

    let reply = client
        .request(crate::UPLOADS_SUBJECT, payload.into())
        .await
        .wrap_err_with(|| format!("requesting urls on {}", crate::UPLOADS_SUBJECT))?;

    let mut cursor = reply.payload.as_ref();
    let reader = capnp::serialize::read_message(&mut cursor, capnp::message::ReaderOptions::new())
        .wrap_err("decoding the url response")?;
    let response = reader
        .get_root::<kubernix_capnp::upload_url_response::Reader>()
        .wrap_err("reading the upload_url_response root")?;

    let error = response.get_error_msg()?.to_string()?;
    if !error.is_empty() {
        bail!("frontend refused upload: {error}");
    }

    let mut urls = Vec::new();
    for url in response.get_urls()?.iter() {
        urls.push(url?.to_string()?);
    }
    if urls.len() != keys.len() {
        bail!("expected {} urls, got {}", keys.len(), urls.len());
    }
    Ok(urls)
}

/// Where and how to invoke the local Nix CLI/daemon, and the store directory
/// it and every wire path agree on. Bundled because every path-touching
/// worker operation — importing an input, dumping an output, querying
/// metadata — needs the same handful of scalars, sourced once from the
/// worker's environment in `main()`.
#[derive(Clone, Copy)]
pub struct NixStore<'a> {
    pub nix_store: &'a str,
    pub nix_cli: &'a str,
    pub store_uri: Option<&'a str>,
    pub store_dir: &'a str,
}

impl<'a> NixStore<'a> {
    /// The "dump -> hash -> compress -> hash -> spool" pipeline
    /// [`Self::upload_output`] runs a `nix store dump-path` child's stdout
    /// through — its own associated function, generic over its source and
    /// sink (any `AsyncRead`/`AsyncWrite`) rather than tied to a real
    /// subprocess and a real spool file, even though it needs none of
    /// `NixStore`'s own fields. That genericity is what lets
    /// `tests::hashes_and_compresses_a_stream` below exercise the actual
    /// hashing/compression logic against an in-memory buffer, with no
    /// subprocess involved.
    ///
    /// Returns `(nar_hash, nar_size, file_hash, file_size)` — the
    /// uncompressed NAR's hash and size, then the compressed object's.
    ///
    /// `file_size` is counted as bytes flow through `sink` (via
    /// [`InspectWriter`]) rather than read back from the sink afterwards
    /// (e.g. `tokio::fs::File::metadata`), which is what makes this generic
    /// over any sink at all, not just a real file.
    async fn dump_hash_and_compress<R, W>(
        nar: R,
        sink: W,
    ) -> eyre::Result<(Output<Sha256>, u64, Output<Sha256>, u64)>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        let written = Arc::new(AtomicU64::new(0));
        let counted = InspectWriter::new(sink, {
            let written = written.clone();
            move |chunk| {
                written.fetch_add(chunk.len() as u64, Ordering::Relaxed);
            }
        });

        // `HashReader`/`HashWriter` (digest-io) hash a stream as it passes
        // through; `ZstdEncoder` (async-compression) compresses one as it's
        // written. Stacking them turns the whole pipeline into a single
        // `tokio::io::copy`, with no manual buffering.
        let mut nar_reader = HashReader::<Sha256, _>::new(nar);
        let file_writer = HashWriter::<Sha256, _>::new(counted);
        let mut encoder =
            ZstdEncoder::with_quality(file_writer, async_compression::Level::Precise(3));

        let nar_size = tokio::io::copy(&mut nar_reader, &mut encoder).await?;
        // Flushes zstd's trailing frame bytes through the `HashWriter` —
        // must happen before the file hash/size below are read.
        encoder
            .shutdown()
            .await
            .wrap_err("flushing the compressor")?;
        let file_writer = encoder.into_inner();

        let nar_hash = nar_reader.finalize();
        let (file_hasher, mut counted) = file_writer.into_parts();
        counted.flush().await.wrap_err("flushing the sink")?;
        let file_hash = file_hasher.finalize();
        let file_size = written.load(Ordering::Relaxed);

        Ok((nar_hash, nar_size, file_hash, file_size))
    }

    /// Dump a store path as a NAR, compress it, and PUT it to `url`.
    ///
    /// Hashes both the uncompressed and compressed byte streams in the *same*
    /// pass: buffering the whole NAR to hash it afterwards would defeat the
    /// point for a large closure.
    ///
    /// TODO: the `nix store dump-path` child below has no timeout — see
    /// `serve::ServeConnection::open`'s doc comment for the same hang risk
    /// and the same real fix (a direct connection to the daemon socket
    /// instead of shelling out).
    pub async fn upload_output(
        &self,
        http: &reqwest::Client,
        url: &str,
        key: ObjectKey,
        store_path: &StorePath,
    ) -> eyre::Result<OutputArtifact> {
        // `nix store dump-path`, not `nix-store --dump`: the latter takes a
        // *filesystem* path and ignores --store entirely, so it cannot find an
        // output living under a chroot store root.
        let mut command = Command::new(self.nix_cli);
        command.arg("store").arg("dump-path");
        if let Some(uri) = self.store_uri {
            command.arg("--store").arg(uri);
        }
        let mut child = command
            .arg(store_path.to_full(self.store_dir))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .wrap_err_with(|| format!("spawning {} store dump-path", self.nix_cli))?;

        let stdout = child.stdout.take().expect("piped");
        // Compressed as the NAR arrives, into a temporary file rather than
        // memory, so nothing here scales with the size of the output. Both
        // hashes are computed in the same pass — buffering to hash afterwards
        // would defeat the point for a large closure.
        //
        // Why a file and not a streaming request body: a pre-signed PUT is
        // signed for a specific request, and a streaming body means chunked
        // transfer-encoding with no `Content-Length`, which S3 rejects
        // outright (`HTTP 400`). Spooling to disk gives a length to declare
        // while keeping *memory* flat, which is what actually mattered.
        let spool = tempfile::NamedTempFile::new().wrap_err("creating a spool file")?;
        let sink = tokio::fs::File::from_std(spool.reopen().wrap_err("reopening the spool file")?);

        let (nar_hash, nar_size, file_hash, file_size) = Self::dump_hash_and_compress(stdout, sink)
            .await
            .wrap_err_with(|| format!("dumping {store_path}"))?;

        let mut stderr = String::new();
        if let Some(mut pipe) = child.stderr.take() {
            let _ = pipe.read_to_string(&mut stderr).await;
        }
        let status = child.wait().await.wrap_err("waiting for dump-path")?;
        if !status.success() {
            bail!("dumping {store_path}: {} ({status})", stderr.trim());
        }

        // Streamed from disk with the length declared, so the request is one
        // the pre-signed URL will accept.
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

        let (references, deriver) = self.query_path_metadata(store_path).await?;

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
    /// The object is a zstd-compressed *bare NAR* -- the same shape every
    /// artifact has. `--import` needs an export stream, so the wrapping is
    /// added here, which is why the references and deriver travel alongside
    /// the key rather than being stored a second time.
    ///
    /// Streamed end to end: fetched, decompressed and piped into the child a
    /// chunk at a time, so peak memory does not scale with the size of the
    /// input.
    ///
    /// TODO: same unbounded-hang risk on the `--import` child as
    /// `upload_output`'s `dump-path` child — see `serve::ServeConnection::
    /// open`'s doc comment.
    pub async fn fetch_input(
        &self,
        http: &reqwest::Client,
        url: &str,
        store_path: &StorePath,
        references: &[StorePath],
        deriver: &StorePath,
    ) -> eyre::Result<()> {
        let response = http
            .get(url)
            .send()
            .await
            .wrap_err_with(|| format!("fetching {store_path}"))?;
        if !response.status().is_success() {
            bail!("fetching {store_path}: HTTP {}", response.status());
        }

        let mut command = Command::new(self.nix_store);
        if let Some(uri) = self.store_uri {
            command.arg("--store").arg(uri);
        }
        let mut child = command
            .arg("--import")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .wrap_err_with(|| format!("spawning {} --import", self.nix_store))?;

        {
            use futures_util::StreamExt as _;
            use std::io::Write as _;

            let mut stdin = child.stdin.take().expect("piped");

            // The object is a bare NAR; `--import` wants an export stream. The
            // wrapping is built here rather than stored, so the object store
            // holds one representation of a path rather than two — see
            // `nar_export`.
            stdin
                .write_all(&crate::nar_export::header())
                .await
                .wrap_err("writing the export header")?;

            // Decompressed as it arrives rather than in one piece: peak
            // memory is a chunk, not the whole NAR. `zstd`'s streaming writer
            // is enough for this, so it needs no additional dependency.
            let mut decoder =
                zstd::stream::write::Decoder::new(Vec::new()).wrap_err("starting decompression")?;
            let mut body = response.bytes_stream();
            while let Some(chunk) = body.next().await {
                decoder
                    .write_all(&chunk.wrap_err_with(|| format!("fetching {store_path}"))?)
                    .wrap_err_with(|| format!("decompressing {store_path}"))?;
                let decoded = std::mem::take(decoder.get_mut());
                if !decoded.is_empty() {
                    stdin
                        .write_all(&decoded)
                        .await
                        .wrap_err("writing to nix-store --import")?;
                }
            }
            decoder
                .flush()
                .wrap_err_with(|| format!("decompressing {store_path}"))?;
            let decoded = std::mem::take(decoder.get_mut());
            if !decoded.is_empty() {
                stdin
                    .write_all(&decoded)
                    .await
                    .wrap_err("writing to nix-store --import")?;
            }

            stdin
                .write_all(&crate::nar_export::trailer(
                    store_path,
                    references,
                    deriver,
                    self.store_dir,
                ))
                .await
                .wrap_err("writing the export trailer")?;
            stdin
                .shutdown()
                .await
                .wrap_err("closing nix-store --import's stdin")?;
        }

        let output = child
            .wait_with_output()
            .await
            .wrap_err("waiting for nix-store --import")?;
        if !output.status.success() {
            bail!(
                "importing {store_path}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }
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
) -> eyre::Result<()> {
    let response = http
        .put(url)
        .header("content-type", "text/plain; charset=utf-8")
        .body(log)
        .send()
        .await
        .wrap_err_with(|| format!("uploading {key}"))?;
    if !response.status().is_success() {
        bail!("uploading {key}: HTTP {}", response.status());
    }
    Ok(())
}

impl<'a> NixStore<'a> {
    // TODO: the `nix-store --query` children spawned below (via `.output()`,
    // which waits for exit with no timeout) share the same unbounded-hang
    // risk as `upload_output`'s and `fetch_input`'s — see
    // `serve::ServeConnection::open`'s doc comment.
    async fn query_path_metadata(
        &self,
        store_path: &StorePath,
    ) -> eyre::Result<(Vec<StorePath>, Option<StorePath>)> {
        let with_store = |cmd: &str| {
            let mut c = Command::new(self.nix_store);
            if let Some(uri) = self.store_uri {
                c.arg("--store").arg(uri);
            }
            c.arg(cmd);
            c
        };

        let references = with_store("--query")
            .arg("--references")
            .arg(store_path.to_full(self.store_dir))
            .output()
            .await
            .wrap_err_with(|| format!("querying references of {store_path}"))?;
        // `nix-store --query` prints full paths, rooted at whatever store
        // directory the local `nix-store` is actually configured for. A
        // mismatch against `store_dir` means this worker's
        // `KUBERNIX_STORE_DIR` disagrees with its real store — a
        // misconfiguration worth failing loudly on rather than silently
        // corrupting every path derived from it.
        let references = String::from_utf8_lossy(&references.stdout)
            .lines()
            .map(|s| StorePath::from_full_or_err(self.store_dir, s))
            .collect::<Result<_, _>>()
            .wrap_err("KUBERNIX_STORE_DIR does not match the local store's own idea of it")?;

        let deriver = with_store("--query")
            .arg("--deriver")
            .arg(store_path.to_full(self.store_dir))
            .output()
            .await
            .wrap_err_with(|| format!("querying the deriver of {store_path}"))?;
        let deriver = String::from_utf8_lossy(&deriver.stdout).trim().to_string();
        // `--query --deriver` prints "unknown-deriver" when there is none.
        let deriver = if deriver == "unknown-deriver" {
            None
        } else {
            Some(
                StorePath::from_full_or_err(self.store_dir, &deriver).wrap_err(
                    "KUBERNIX_STORE_DIR does not match the local store's own idea of it",
                )?,
            )
        };

        Ok((references, deriver))
    }
}

#[cfg(test)]
mod tests {
    use super::{NixStore, log_key, nar_key};
    use kubernix_types::{ObjectKey, StorePath, TenantId};

    const P: &str = "21d91afy6vgw4l00yzy92kp92b1w3cdm-kxs-testfile.txt";

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

    // `dump_hash_and_compress` needs no subprocess to exercise: it is generic
    // over its source and sink, so a plain in-memory buffer stands in for a
    // `nix store dump-path` child's stdout and the spool file.

    #[tokio::test]
    async fn hashes_and_compresses_a_stream() {
        let nar = b"hello kubernix, this is a fake nar".repeat(100);
        let mut sink = Vec::new();

        let (nar_hash, nar_size, file_hash, file_size) =
            NixStore::dump_hash_and_compress(nar.as_slice(), &mut sink)
                .await
                .unwrap();

        // The uncompressed hash/size describe `nar` itself.
        assert_eq!(nar_size, nar.len() as u64);
        assert_eq!(nar_hash, <sha2::Sha256 as sha2::Digest>::digest(&nar));

        // The compressed hash/size describe what actually landed in `sink` —
        // proof `file_size` (counted via `InspectWriter`, not read back from
        // the sink) agrees with what was really written.
        assert_eq!(file_size, sink.len() as u64);
        assert_eq!(file_hash, <sha2::Sha256 as sha2::Digest>::digest(&sink));

        // And `sink` holds something a real client can actually decompress
        // back to the original bytes — the whole point of the pipeline.
        let decompressed = zstd::stream::decode_all(sink.as_slice()).unwrap();
        assert_eq!(decompressed, nar);
    }

    #[tokio::test]
    async fn an_empty_stream_still_produces_a_valid_compressed_object() {
        let mut sink = Vec::new();
        let (nar_hash, nar_size, _file_hash, file_size) =
            NixStore::dump_hash_and_compress(&b""[..], &mut sink)
                .await
                .unwrap();

        assert_eq!(nar_size, 0);
        assert_eq!(nar_hash, <sha2::Sha256 as sha2::Digest>::digest(b""));
        assert_eq!(file_size, sink.len() as u64);
        assert_eq!(zstd::stream::decode_all(sink.as_slice()).unwrap(), b"");
    }
}
