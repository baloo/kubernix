//! Pull-through cache for a tenant's trusted substituters.
//!
//! **Kubernix caches; it does not authenticate.** [`resolve`] never checks a
//! fetched narinfo's `Sig:` line and never re-signs cached content under a
//! tenant's own per-tenant key — it stores the line(s) verbatim. Trust in
//! the content stays exactly where it already lives for any Nix
//! substituter: with whichever `nix-daemon` actually consumes the path,
//! checking the *original, unmodified* signature against its own
//! `trusted-public-keys`. What kubernix does verify is that the bytes it
//! downloaded match what the narinfo it fetched claims — an integrity check
//! against corruption/truncation, not an authenticity check.
//!
//! Two entry points, at two different costs:
//! - [`exists`] — a cheap `HEAD` against each configured substituter, no
//!   download, no recording. Used on the hot `isValidPath`/`query_missing`
//!   path (`server/src/postgres_store.rs`) so a build is not dispatched for
//!   something a trusted upstream already has.
//! - [`resolve`] — the full fetch: GET the narinfo, stream and hash the
//!   NAR, record it as `Tier::Substituted`. Used by `query_path_info` and
//!   the per-substituter HTTP route (`server/src/http.rs`).
//!
//! Both consult [`PathStore::substituter_negative_cache_hit`] first and
//! [`PathStore::find_substituted_by_hash_part`] before ever making a network
//! call — see each function's own doc comment.

use std::sync::OnceLock;

use sha2::{Digest, Sha256};

use kubernix_types::StorePath;

use crate::store::{Hash, HashType, PathInfo, PathStore, RemoteObject, substituted_nar_key};
use crate::tenant::TenantId;
use crate::uploads::UploadSigner;

fn http_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            // reqwest sends no `User-Agent` by default, so this is set
            // outright rather than literally appended to anything -- but
            // still names reqwest's own identity alongside kubernix's, for
            // whoever reads it on the other end.
            .user_agent(format!(
                "kubernix/{} reqwest/0.13",
                env!("CARGO_PKG_VERSION")
            ))
            .build()
            .expect("building the substituter HTTP client")
    })
}

/// A path-safe identifier for one substituter, derived deterministically
/// from its URL's host — what `server/src/http.rs`'s
/// `/<tenant>/upstream/<slug>/…` route uses, and what
/// [`substituted_nar_key`] shares an object under. Not a new admin-assigned
/// field: two tenants configuring the same URL always agree on its slug.
pub fn slug_for(url: &str) -> String {
    let without_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let host = without_scheme.split('/').next().unwrap_or(without_scheme);
    host.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// Cheap existence check: does any of `tenant`'s trusted substituters have
/// `hash_part`? No download, nothing recorded — see the module doc comment.
pub async fn exists<S: PathStore + ?Sized>(store: &S, tenant: &TenantId, hash_part: &str) -> bool {
    if store
        .substituter_negative_cache_hit(tenant, hash_part)
        .await
    {
        return false;
    }
    // A hash part already cached (by this tenant or shared from another
    // trusting the same source) obviously exists -- no need to ask upstream.
    if let Some((_, _, url, key)) = store.find_substituted_by_hash_part(hash_part).await
        && store
            .trusted_substituters(tenant)
            .await
            .contains(&(url, key))
    {
        return true;
    }

    let substituters = store.trusted_substituters(tenant).await;
    if substituters.is_empty() {
        return false;
    }
    for (url, _key) in &substituters {
        let target = format!("{}/{hash_part}.narinfo", url.trim_end_matches('/'));
        match http_client().head(&target).send().await {
            Ok(resp) if resp.status().is_success() => return true,
            Ok(_) => continue,
            Err(e) => {
                tracing::debug!(error = %e, %url, "substituter HEAD request failed");
                continue;
            }
        }
    }
    store.mark_substituter_miss(tenant, hash_part).await;
    false
}

/// The full pull-through fetch: resolve `hash_part` via `tenant`'s trusted
/// substituters, caching the result as `Tier::Substituted`. `store_dir` is
/// kubernix's own configured Nix store directory (`KUBERNIX_STORE_DIR`),
/// needed to parse the narinfo's `StorePath:` field.
pub async fn resolve<S: PathStore + ?Sized>(
    store: &S,
    uploader: &UploadSigner,
    tenant: &TenantId,
    hash_part: &str,
    store_dir: &str,
) -> Option<(PathInfo, RemoteObject)> {
    if store
        .substituter_negative_cache_hit(tenant, hash_part)
        .await
    {
        return None;
    }

    let substituters = store.trusted_substituters(tenant).await;
    for (url, key) in &substituters {
        if let Some(hit) =
            resolve_from_one(store, uploader, tenant, hash_part, store_dir, url, key).await
        {
            return Some(hit);
        }
    }

    store.mark_substituter_miss(tenant, hash_part).await;
    None
}

/// [`resolve`], scoped to one specific configured substituter — what
/// `server/src/http.rs`'s `/<tenant>/upstream/<slug>/…` route uses, so a
/// request there only ever resolves through the one substituter the route
/// names, never falls through to the tenant's other configured sources.
/// Callers are expected to have already checked that `(url, public_key)` is
/// actually one of `tenant`'s configured `trusted_substituters` — this
/// function does not re-check that itself, since [`resolve`] already knows
/// it (from the loop it came from) and the HTTP route resolves `slug` back
/// to a configured entry before ever calling this.
pub async fn resolve_from_one<S: PathStore + ?Sized>(
    store: &S,
    uploader: &UploadSigner,
    tenant: &TenantId,
    hash_part: &str,
    store_dir: &str,
    url: &str,
    public_key: &str,
) -> Option<(PathInfo, RemoteObject)> {
    // Someone else may already have pulled this exact path through from
    // this exact source -- share it rather than re-fetching. A policy
    // check, not a cryptographic one: see the module doc comment and
    // `PathStore::find_substituted_by_hash_part`.
    if let Some((info, object, found_url, found_key)) =
        store.find_substituted_by_hash_part(hash_part).await
        && found_url == url
        && found_key == public_key
    {
        match store
            .record_substituted_path(tenant, info.clone(), object.clone(), url, public_key)
            .await
        {
            Ok(()) => return Some((info, object)),
            Err(e) => {
                tracing::warn!(error = %e, %tenant, %hash_part, "materializing a shared substituted path failed");
            }
        }
    }

    match fetch_one(uploader, url, public_key, hash_part, store_dir).await {
        Ok(Some((info, object))) => {
            if let Err(e) = store
                .record_substituted_path(tenant, info.clone(), object.clone(), url, public_key)
                .await
            {
                tracing::warn!(error = %e, %tenant, %hash_part, %url, "recording a substituted path failed");
                return None;
            }
            Some((info, object))
        }
        Ok(None) => None,
        Err(e) => {
            tracing::debug!(error = %e, %url, %hash_part, "fetching from substituter failed");
            None
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum FetchError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("malformed narinfo: {0}")]
    Malformed(&'static str),
    #[error("unsupported compression: {0}")]
    UnsupportedCompression(String),
    #[error("downloaded content does not match the narinfo's claimed hash")]
    HashMismatch,
    #[error("uploading to the object store: {0}")]
    Upload(#[from] eyre::Report),
}

/// Fetch and cache one path from one substituter. `Ok(None)` is a plain
/// miss (404 -- try the next substituter); `Err` is anything else, logged by
/// the caller and also treated as a miss for this substituter.
async fn fetch_one(
    uploader: &UploadSigner,
    url: &str,
    public_key: &str,
    hash_part: &str,
    store_dir: &str,
) -> Result<Option<(PathInfo, RemoteObject)>, FetchError> {
    let base = url.trim_end_matches('/');
    let resp = http_client()
        .get(format!("{base}/{hash_part}.narinfo"))
        .send()
        .await?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let resp = resp.error_for_status()?;
    let text = resp.text().await?;
    let narinfo = ParsedNarinfo::parse(&text)?;

    let path = StorePath::from_full(store_dir, &narinfo.store_path)
        .ok_or(FetchError::Malformed("StorePath"))?;

    let nar_url = if narinfo.url.contains("://") {
        narinfo.url.clone()
    } else {
        format!("{base}/{}", narinfo.url)
    };
    let compressed = http_client()
        .get(&nar_url)
        .send()
        .await?
        .error_for_status()?
        .bytes()
        .await?
        .to_vec();

    let raw = match narinfo.compression.as_str() {
        "none" => compressed,
        "zstd" => zstd::stream::decode_all(compressed.as_slice())
            .map_err(|_| FetchError::Malformed("nar body did not decode as zstd"))?,
        other => return Err(FetchError::UnsupportedCompression(other.to_string())),
    };

    if Sha256::digest(&raw).as_slice() != narinfo.nar_hash.as_slice() {
        return Err(FetchError::HashMismatch);
    }

    // Kubernix's own object store holds zstd-compressed bare NARs only
    // (`server/migrations/20260811_initial_schema.sql`'s doc comment on
    // `objects`) -- recompressing here, rather than storing whatever
    // compression the substituter used, is what lets every other route
    // (`http::render_narinfo`) keep assuming `Compression: zstd` uniformly.
    let recompressed =
        zstd::stream::encode_all(raw.as_slice(), 3).map_err(|e| FetchError::Upload(e.into()))?;
    let key = substituted_nar_key(&slug_for(url), &path).ok_or(FetchError::Malformed("path"))?;
    uploader.put_object(&key, recompressed.clone()).await?;

    let info = PathInfo {
        path,
        deriver: narinfo.deriver.map(StorePath::new),
        nar_hash: Hash {
            hash_type: HashType::Sha256,
            bytes: narinfo.nar_hash,
        },
        nar_size: narinfo.nar_size,
        references: narinfo.references.into_iter().map(StorePath::new).collect(),
        registration_time: 0,
        ultimate: false,
        sigs: narinfo.sigs,
    };
    let object = RemoteObject {
        key,
        file_size: recompressed.len() as u64,
        file_hash: Sha256::digest(&recompressed),
    };
    let _ = public_key; // recorded by the caller alongside `url`, not used here.
    Ok(Some((info, object)))
}

struct ParsedNarinfo {
    store_path: String,
    url: String,
    compression: String,
    nar_hash: Vec<u8>,
    nar_size: u64,
    references: Vec<String>,
    deriver: Option<String>,
    sigs: Vec<String>,
}

impl ParsedNarinfo {
    fn parse(text: &str) -> Result<Self, FetchError> {
        let mut store_path = None;
        let mut url = None;
        let mut compression = "none".to_string();
        let mut nar_hash = None;
        let mut nar_size = None;
        let mut references = Vec::new();
        let mut deriver = None;
        let mut sigs = Vec::new();

        for line in text.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            match key {
                "StorePath" => store_path = Some(value.to_string()),
                "URL" => url = Some(value.to_string()),
                "Compression" => compression = value.to_string(),
                "NarHash" => {
                    nar_hash = value
                        .strip_prefix("sha256:")
                        .and_then(|h| kubernix_signing::base32::decode(h, 32))
                }
                "NarSize" => nar_size = value.parse().ok(),
                "References" if !value.is_empty() => {
                    references = value.split_whitespace().map(str::to_string).collect();
                }
                "Deriver" => deriver = Some(value.to_string()),
                "Sig" => sigs.push(value.to_string()),
                _ => {}
            }
        }

        Ok(Self {
            store_path: store_path.ok_or(FetchError::Malformed("missing StorePath"))?,
            url: url.ok_or(FetchError::Malformed("missing URL"))?,
            compression,
            nar_hash: nar_hash.ok_or(FetchError::Malformed("missing or malformed NarHash"))?,
            nar_size: nar_size.ok_or(FetchError::Malformed("missing NarSize"))?,
            references,
            deriver,
            sigs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_is_derived_from_the_host() {
        assert_eq!(slug_for("https://cache.nixos.org"), "cache.nixos.org");
        assert_eq!(
            slug_for("https://cache.nixos.org/some/path"),
            "cache.nixos.org"
        );
        assert_eq!(
            slug_for("http://internal-cache:8080"),
            "internal-cache-8080"
        );
    }

    const NARINFO: &str = "StorePath: /nix/store/00000000000000000000000000000000-thing\n\
URL: nar/abc.nar.zst\n\
Compression: zstd\n\
FileHash: sha256:0000000000000000000000000000000000000000000000000000\n\
FileSize: 100\n\
NarHash: sha256:0000000000000000000000000000000000000000000000000000\n\
NarSize: 200\n\
References: 11111111111111111111111111111111-dep\n\
Deriver: 22222222222222222222222222222222-thing.drv\n\
Sig: cache.nixos.org-1:AAAA\n\
Sig: another-1:BBBB\n";

    #[test]
    fn parses_a_narinfo() {
        let parsed = ParsedNarinfo::parse(NARINFO).unwrap();
        assert_eq!(
            parsed.store_path,
            "/nix/store/00000000000000000000000000000000-thing"
        );
        assert_eq!(parsed.url, "nar/abc.nar.zst");
        assert_eq!(parsed.compression, "zstd");
        assert_eq!(parsed.nar_size, 200);
        assert_eq!(
            parsed.references,
            vec!["11111111111111111111111111111111-dep".to_string()]
        );
        assert_eq!(
            parsed.deriver,
            Some("22222222222222222222222222222222-thing.drv".to_string())
        );
        assert_eq!(
            parsed.sigs,
            vec![
                "cache.nixos.org-1:AAAA".to_string(),
                "another-1:BBBB".to_string()
            ]
        );
    }

    #[test]
    fn a_narinfo_missing_a_required_field_is_rejected() {
        let broken = "URL: nar/abc.nar.zst\nNarHash: sha256:0000000000000000000000000000000000000000000000000000\nNarSize: 1\n";
        assert!(ParsedNarinfo::parse(broken).is_err());
    }
}
