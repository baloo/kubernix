//! The binary-cache HTTP surface.
//!
//! This is the *substituter* side: what lets a client add the deployment to
//! `substituters` and fetch outputs somebody else built, as opposed to the SSH
//! surface, which is how builds are submitted.
//!
//! Everything is under a **tenant path prefix** — `/<tenant>/…` — because a
//! tenant's paths are only valid within that tenant (PLAN.md Phase 9) and
//! because each tenant signs with its own key. A client configures one prefix
//! and the matching `trusted-public-keys` entry.
//!
//! > **This is not an access control boundary.** With authentication deferred,
//! > anyone who knows a tenant id can read that tenant's cache. That is
//! > tolerable for a cache — the contents are signed rather than secret — but it
//! > is a decision, not an oversight, and it is why quarantined paths are not
//! > served here at all: they are the ones nothing can vouch for.
//!
//! Routes, mirroring what a Nix client asks a binary cache for:
//!
//! | route | purpose |
//! | --- | --- |
//! | `GET /<tenant>/nix-cache-info` | store dir and priority; a client fetches this first |
//! | `GET /<tenant>/<hash>.narinfo` | metadata and signature for one path |
//! | `GET /<tenant>/nar/<hash>.nar.zst` | the NAR itself, as a redirect to the object store |
//! | `GET /<tenant>/log/<drv hash>` | a build log, plain text |
//! | `GET /<tenant>/public-key` | this tenant's `trusted-public-keys` entry (not a Nix route) |
//! | `GET /<tenant>/upstream/<slug>/…` | a mirror of one trusted substituter — see below |
//!
//! ## `/<tenant>/upstream/<slug>/…`
//!
//! `Tier::Substituted` content — pulled through from one of the tenant's
//! configured trusted substituters (`crate::substitute`) — is deliberately
//! **not** served from the tenant's own narinfo namespace above: that
//! namespace is what a tenant signs, and mixing in un-re-signed upstream
//! content would blur what a client is actually trusting. Instead each
//! configured substituter gets its own mirror, `<slug>` derived from its URL
//! host (`crate::substitute::slug_for`), serving the original, untouched
//! `Sig:` line(s) it was fetched with — kubernix never re-signs this
//! content. A client trusts it the same way it would trust the substituter
//! directly: by configuring that substituter's own public key.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;

use kubernix_types::{Compression, ObjectKey, StorePath};

use crate::store::{PathInfo, PathStore};
use crate::tenant::TenantId;
use crate::uploads::UploadSigner;

#[derive(Clone)]
pub struct HttpState {
    /// `PathStore`, not the whole `Store`: this surface never mints or
    /// verifies a capability token, only ever reads path data.
    pub store: Arc<dyn PathStore>,
    /// Needed to hand out object URLs. Without one, NAR and log routes cannot be
    /// served at all — the frontend does not hold those bytes.
    pub uploader: Option<Arc<UploadSigner>>,
    /// Advertised in `nix-cache-info`. Must match the client's store dir or the
    /// client refuses every path.
    pub store_dir: String,
    /// Advertised in `nix-cache-info`. Higher numbers are consulted later;
    /// `cache.nixos.org` uses 40, so the default here sits after it.
    pub priority: u32,
}

pub fn router(state: HttpState) -> Router {
    // Each tenant's cache is a whole binary cache rooted at its own prefix, so
    // it is nested rather than having every route repeat `{tenant}`. Nesting
    // keeps the captured parameter available to the inner handlers.
    Router::new()
        .nest("/{tenant}", tenant_router())
        .with_state(state)
}

/// One tenant's cache, as a client sees it from its configured root.
fn tenant_router() -> Router<HttpState> {
    Router::new()
        .route("/nix-cache-info", get(nix_cache_info))
        .route("/public-key", get(public_key))
        .route("/nar/{file}", get(nar))
        .route("/log/{drv_hash}", get(log))
        .route(
            "/upstream/{slug}/nix-cache-info",
            get(upstream_nix_cache_info),
        )
        .route("/upstream/{slug}/nar/{file}", get(upstream_nar))
        .route("/upstream/{slug}/{file}", get(upstream_narinfo))
        // Last, and a bare parameter: `{hash}.narinfo` is not a legal route
        // because axum allows one parameter per path segment, so the suffix is
        // stripped in the handler. The literal routes above still win — matchit
        // prefers static segments over parameters.
        .route("/{file}", get(narinfo))
}

/// Parse a tenant out of the path.
///
/// Rejecting a malformed id here rather than passing it through means a
/// traversal attempt cannot reach the object store, where the id becomes a key
/// prefix.
fn tenant_of(raw: &str) -> Result<TenantId, Box<Response>> {
    TenantId::from_wire(raw)
        .ok_or_else(|| Box::new((StatusCode::NOT_FOUND, "unknown tenant\n").into_response()))
}

async fn nix_cache_info(State(state): State<HttpState>, Path(tenant): Path<String>) -> Response {
    if let Err(response) = tenant_of(&tenant) {
        return *response;
    }
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/x-nix-cache-info")],
        format!(
            "StoreDir: {}\nWantMassQuery: 1\nPriority: {}\n",
            state.store_dir, state.priority
        ),
    )
        .into_response()
}

/// The tenant's public key, in the form `trusted-public-keys` wants.
///
/// Not a route Nix knows about — it exists so a tenant can be told what to trust
/// without an operator having to read it out of the database.
async fn public_key(State(state): State<HttpState>, Path(tenant): Path<String>) -> Response {
    let tenant = match tenant_of(&tenant) {
        Ok(tenant) => tenant,
        Err(response) => return *response,
    };

    match state.store.signer(&tenant).await {
        Some(signer) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain")],
            format!("{}\n", signer.public_key_string()),
        )
            .into_response(),
        None => (StatusCode::INTERNAL_SERVER_ERROR, "no signing key\n").into_response(),
    }
}

async fn narinfo(
    State(state): State<HttpState>,
    Path((tenant, file)): Path<(String, String)>,
) -> Response {
    let tenant = match tenant_of(&tenant) {
        Ok(tenant) => tenant,
        Err(response) => return *response,
    };
    let Some(hash) = file.strip_suffix(".narinfo") else {
        return (StatusCode::NOT_FOUND, "not found\n").into_response();
    };

    let Some(path) = state.store.query_path_from_hash_part(&tenant, hash).await else {
        // 404 is a normal answer here: it is how a client learns to build
        // something itself, so it must not look like an error.
        return (StatusCode::NOT_FOUND, "not found\n").into_response();
    };

    let Some(info) = state.store.query_path_info(&tenant, &path).await else {
        return (StatusCode::NOT_FOUND, "not found\n").into_response();
    };

    // Quarantined paths are not served. They are the ones the frontend cannot
    // vouch for, and a cache exists precisely to be believed.
    match state.store.tier(&tenant, &path).await {
        Some(tier) if tier.is_vouchable() => {}
        _ => {
            tracing::debug!(%path, %tenant, "refusing to serve an unvouchable path");
            return (StatusCode::NOT_FOUND, "not found\n").into_response();
        }
    }

    let Some(remote) = state.store.output_object(&tenant, &path).await else {
        // Valid, but its bytes are not in the object store — a client-pushed
        // path held inline. There is no URL to point at, so it is not
        // substitutable even though it exists. See PLAN.md Phase 10b.
        tracing::debug!(%path, "no object backing this path; not substitutable");
        return (StatusCode::NOT_FOUND, "not found\n").into_response();
    };

    // PLAN.md Phase 12: a narinfo fetch counts as an access in its own
    // right, ahead of whatever `GET /nar/…` fetch follows it — that route
    // never touches `store_paths` at all (see `nar()` below), so this is the
    // only mark either request produces.
    state.store.record_access(&tenant, &path).await;

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/x-nix-narinfo")],
        render_narinfo(
            &info,
            &remote.key,
            remote.file_size,
            &remote.file_hash,
            remote.compression,
            &state.store_dir,
        ),
    )
        .into_response()
}

/// Render the narinfo body.
///
/// Field order follows what Nix writes; clients parse by key, but matching it
/// makes a captured response comparable with a real cache's.
fn render_narinfo(
    info: &PathInfo,
    object_key: &ObjectKey,
    file_size: u64,
    file_hash: &[u8],
    compression: Compression,
    store_dir: &str,
) -> String {
    let mut out = String::new();
    out.push_str(&format!("StorePath: {}\n", info.path.to_full(store_dir)));
    // Relative to the cache root, which is the tenant prefix — so a client that
    // fetched `/<tenant>/<hash>.narinfo` resolves this against the same prefix.
    out.push_str(&format!(
        "URL: nar/{}\n",
        object_key_basename(object_key.as_str())
    ));
    out.push_str(&format!("Compression: {}\n", compression.as_str()));
    out.push_str(&format!(
        "FileHash: sha256:{}\n",
        kubernix_signing::base32::encode(file_hash)
    ));
    out.push_str(&format!("FileSize: {file_size}\n"));
    out.push_str(&format!(
        "NarHash: sha256:{}\n",
        kubernix_signing::base32::encode(&info.nar_hash.bytes)
    ));
    out.push_str(&format!("NarSize: {}\n", info.nar_size));

    // References are printed *without* the store directory: a narinfo lists bare
    // names, and a client prepends its own store dir. `StorePath` already
    // carries no prefix, so there is nothing to strip.
    let references: Vec<&str> = info.references.iter().map(StorePath::as_str).collect();
    out.push_str(&format!("References: {}\n", references.join(" ")));

    if let Some(deriver) = &info.deriver {
        out.push_str(&format!("Deriver: {}\n", deriver.as_str()));
    }
    for sig in &info.sigs {
        out.push_str(&format!("Sig: {sig}\n"));
    }
    out
}

/// The last path segment of an object key, which is what the narinfo `URL:`
/// points at relative to the tenant's `nar/`.
fn object_key_basename(key: &str) -> &str {
    key.rsplit('/').next().unwrap_or(key)
}

/// Redirect to a pre-signed object URL rather than proxying the bytes.
///
/// The same reasoning as uploads (PLAN.md Phase 6b): keeping the frontend off
/// the data path is what stops it capping the throughput of everything else.
///
/// **Does not call `record_access`.** This route never looks the path up in
/// `store_paths` at all — the object key is rebuilt directly from the tenant
/// and filename, deliberately, so there is no row here to mark. That is fine:
/// a client fetches `<hash>.narinfo` before `.nar` (that is the only way it
/// learns the URL to redirect from), and `narinfo` already records the
/// access. PLAN.md Phase 12's note that both the narinfo lookup and the byte
/// fetch count is about not missing the *earlier* half of that pair, not
/// about needing both marked independently.
async fn nar(
    State(state): State<HttpState>,
    Path((tenant, file)): Path<(String, String)>,
) -> Response {
    let tenant = match tenant_of(&tenant) {
        Ok(tenant) => tenant,
        Err(response) => return *response,
    };
    let Some(uploader) = &state.uploader else {
        return (StatusCode::SERVICE_UNAVAILABLE, "no object store\n").into_response();
    };
    // The key is rebuilt from the tenant rather than taken from the request, so
    // a client cannot name one outside its own prefix. A single path segment
    // cannot contain `/`, and `..` alone reaches nothing, but both are refused
    // rather than relying on that.
    if file.contains('/') || file.contains("..") {
        return (StatusCode::NOT_FOUND, "not found\n").into_response();
    }
    let key = ObjectKey::new(format!("{tenant}/nar/{file}"));

    match uploader.presign_get(&key).await {
        Ok(url) => Redirect::temporary(&url).into_response(),
        Err(e) => {
            tracing::error!(%key, error = ?e, "could not presign a nar url");
            (StatusCode::INTERNAL_SERVER_ERROR, "cannot serve\n").into_response()
        }
    }
}

/// Resolve `<tenant>`'s configured substituter named by `slug`, or `None` if
/// no currently-configured entry matches — covers both "never configured"
/// and "configured once, since removed".
async fn resolve_substituter(
    state: &HttpState,
    tenant: &TenantId,
    slug: &str,
) -> Option<(String, String)> {
    state
        .store
        .trusted_substituters(tenant)
        .await
        .into_iter()
        .find(|(url, _)| crate::substitute::slug_for(url) == slug)
}

async fn upstream_nix_cache_info(
    State(state): State<HttpState>,
    Path((tenant, slug)): Path<(String, String)>,
) -> Response {
    let tenant = match tenant_of(&tenant) {
        Ok(tenant) => tenant,
        Err(response) => return *response,
    };
    if resolve_substituter(&state, &tenant, &slug).await.is_none() {
        return (StatusCode::NOT_FOUND, "unknown substituter\n").into_response();
    }
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/x-nix-cache-info")],
        format!(
            "StoreDir: {}\nWantMassQuery: 1\nPriority: {}\n",
            state.store_dir, state.priority
        ),
    )
        .into_response()
}

async fn upstream_narinfo(
    State(state): State<HttpState>,
    Path((tenant, slug, file)): Path<(String, String, String)>,
) -> Response {
    let tenant = match tenant_of(&tenant) {
        Ok(tenant) => tenant,
        Err(response) => return *response,
    };
    let Some(hash) = file.strip_suffix(".narinfo") else {
        return (StatusCode::NOT_FOUND, "not found\n").into_response();
    };
    let Some((url, public_key)) = resolve_substituter(&state, &tenant, &slug).await else {
        return (StatusCode::NOT_FOUND, "unknown substituter\n").into_response();
    };

    // Already cached for this tenant from this exact substituter? Serve it
    // without a network round trip. A path recorded against a *different*
    // substituter (even one this tenant also trusts) is deliberately not
    // served here — see the module doc comment.
    let cached = if let Some(path) = state.store.query_path_from_hash_part(&tenant, hash).await
        && state.store.substituted_source(&tenant, &path).await
            == Some((url.clone(), public_key.clone()))
    {
        match (
            state.store.query_path_info(&tenant, &path).await,
            state.store.output_object(&tenant, &path).await,
        ) {
            (Some(info), Some(remote)) => Some((info, remote)),
            _ => None,
        }
    } else {
        None
    };

    let (info, remote) = match cached {
        Some(hit) => hit,
        None => {
            let Some(uploader) = &state.uploader else {
                return (StatusCode::SERVICE_UNAVAILABLE, "no object store\n").into_response();
            };
            match crate::substitute::resolve_from_one(
                state.store.as_ref(),
                uploader,
                &tenant,
                hash,
                &state.store_dir,
                &url,
                &public_key,
            )
            .await
            {
                Some(hit) => hit,
                None => return (StatusCode::NOT_FOUND, "not found\n").into_response(),
            }
        }
    };

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/x-nix-narinfo")],
        // The original `sigs` ride along unmodified inside `info` -- this is
        // the same renderer the tenant's own namespace uses, but nothing
        // here calls `sign_if_vouchable`/re-signs anything first.
        render_narinfo(
            &info,
            &remote.key,
            remote.file_size,
            &remote.file_hash,
            remote.compression,
            &state.store_dir,
        ),
    )
        .into_response()
}

/// Redirect to a pre-signed object URL for a substituted path — mirrors
/// [`nar`], but rebuilds the key from `slug` rather than the tenant (same
/// shape `crate::store::substituted_nar_key` computes), since
/// `Tier::Substituted` objects are keyed by source substituter, not tenant.
async fn upstream_nar(
    State(state): State<HttpState>,
    Path((tenant, slug, file)): Path<(String, String, String)>,
) -> Response {
    let tenant = match tenant_of(&tenant) {
        Ok(tenant) => tenant,
        Err(response) => return *response,
    };
    if resolve_substituter(&state, &tenant, &slug).await.is_none() {
        return (StatusCode::NOT_FOUND, "unknown substituter\n").into_response();
    }
    let Some(uploader) = &state.uploader else {
        return (StatusCode::SERVICE_UNAVAILABLE, "no object store\n").into_response();
    };
    if file.contains('/') || file.contains("..") {
        return (StatusCode::NOT_FOUND, "not found\n").into_response();
    }
    let key = ObjectKey::new(format!("substituted/{slug}/nar/{file}"));

    match uploader.presign_get(&key).await {
        Ok(url) => Redirect::temporary(&url).into_response(),
        Err(e) => {
            tracing::error!(%key, error = ?e, "could not presign a substituted nar url");
            (StatusCode::INTERNAL_SERVER_ERROR, "cannot serve\n").into_response()
        }
    }
}

/// Build logs, which `nix log` fetches as plain text.
///
/// Proxied rather than redirected: logs are small, and `nix log` follows this
/// with no expectation of a redirect.
async fn log(
    State(state): State<HttpState>,
    Path((tenant, drv_hash)): Path<(String, String)>,
) -> Response {
    let tenant = match tenant_of(&tenant) {
        Ok(tenant) => tenant,
        Err(response) => return *response,
    };
    let Some(uploader) = &state.uploader else {
        return (StatusCode::SERVICE_UNAVAILABLE, "no object store\n").into_response();
    };
    if drv_hash.contains('/') || drv_hash.contains("..") {
        return (StatusCode::NOT_FOUND, "not found\n").into_response();
    }

    match uploader
        .get_object(&ObjectKey::new(format!("{tenant}/log/{drv_hash}")))
        .await
    {
        Ok(bytes) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
            bytes,
        )
            .into_response(),
        // Absent is the common case — most derivations were never built here.
        Err(e) => {
            tracing::debug!(%drv_hash, error = ?e, "no log");
            (StatusCode::NOT_FOUND, "not found\n").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{Hash, HashType};
    use sha2::Digest;

    fn info() -> PathInfo {
        PathInfo {
            path: StorePath::new("00000000000000000000000000000000-thing"),
            deriver: Some(StorePath::new("33333333333333333333333333333333-thing.drv")),
            nar_hash: Hash {
                hash_type: HashType::Sha256,
                bytes: vec![0xab; 32],
            },
            nar_size: 4096,
            references: vec![
                StorePath::new("11111111111111111111111111111111-a"),
                StorePath::new("22222222222222222222222222222222-b"),
            ],
            registration_time: 0,
            ultimate: true,
            sigs: vec!["kubernix-t-1:AAAA".to_string()],
        }
    }

    fn rendered() -> String {
        render_narinfo(
            &info(),
            &ObjectKey::new("tenant/nar/abc.nar.zst"),
            1024,
            &[0xcd; 32],
            Compression::Zstd,
            "/nix/store",
        )
    }

    fn field<'a>(body: &'a str, key: &str) -> Option<&'a str> {
        body.lines()
            .find_map(|line| line.strip_prefix(&format!("{key}: ")))
    }

    #[test]
    fn narinfo_carries_the_fields_a_client_needs() {
        let body = rendered();
        assert_eq!(
            field(&body, "StorePath"),
            Some("/nix/store/00000000000000000000000000000000-thing")
        );
        assert_eq!(field(&body, "Compression"), Some("zstd"));
        assert_eq!(field(&body, "NarSize"), Some("4096"));
        assert_eq!(field(&body, "FileSize"), Some("1024"));
        assert_eq!(field(&body, "Sig"), Some("kubernix-t-1:AAAA"));
    }

    #[test]
    fn the_compression_field_reflects_the_objects_actual_compression() {
        // A substituted object is stored exactly as its upstream substituter
        // served it -- not recompressed to zstd -- so `render_narinfo` must
        // report whatever `RemoteObject::compression` actually says, not a
        // hardcoded value.
        let body = render_narinfo(
            &info(),
            &ObjectKey::new("tenant/nar/abc.nar.xz"),
            1024,
            &[0xcd; 32],
            Compression::Xz,
            "/nix/store",
        );
        assert_eq!(field(&body, "Compression"), Some("xz"));
    }

    #[test]
    fn hashes_are_base32_with_their_type() {
        let body = rendered();
        for key in ["NarHash", "FileHash"] {
            let value = field(&body, key).expect(key);
            let encoded = value.strip_prefix("sha256:").expect("type prefix");
            assert!(
                kubernix_signing::base32::is_valid(encoded),
                "{key} should be nix base32: {value}"
            );
        }
    }

    #[test]
    fn references_and_deriver_drop_the_store_directory() {
        // A narinfo lists bare names; a client prepends its own store dir. Full
        // paths here make a client reject the path as malformed.
        let body = rendered();
        assert_eq!(
            field(&body, "References"),
            Some("11111111111111111111111111111111-a 22222222222222222222222222222222-b")
        );
        assert_eq!(
            field(&body, "Deriver"),
            Some("33333333333333333333333333333333-thing.drv")
        );
        assert!(
            !body.contains("References: /nix/store"),
            "references must not be absolute: {body}"
        );
    }

    #[test]
    fn the_url_is_relative_to_the_tenant_prefix() {
        // The client resolves `URL:` against the cache root it fetched the
        // narinfo from, which already includes the tenant.
        assert_eq!(field(&rendered(), "URL"), Some("nar/abc.nar.zst"));
    }

    #[test]
    fn an_unsigned_path_renders_without_a_sig_line() {
        // Quarantined paths never reach here, but a signing failure can still
        // leave a path unsigned — and that must produce a valid narinfo rather
        // than a malformed one.
        let mut unsigned = info();
        unsigned.sigs.clear();
        let body = render_narinfo(
            &unsigned,
            &ObjectKey::new("t/nar/x.nar.zst"),
            1,
            &[0xcd; 32],
            Compression::Zstd,
            "/nix/store",
        );
        assert!(!body.contains("Sig:"));
        assert!(body.contains("StorePath: "));
    }

    #[test]
    fn object_keys_reduce_to_their_basename() {
        assert_eq!(object_key_basename("tenant/nar/abc.nar.zst"), "abc.nar.zst");
        assert_eq!(object_key_basename("abc.nar.zst"), "abc.nar.zst");
    }

    #[test]
    fn the_router_builds() {
        // Regression: `{hash}.narinfo` is not a legal axum route — one parameter
        // per path segment — and building the router panicked at startup rather
        // than failing to compile. Constructing it in a test is what catches
        // that without running the binary.
        let _ = router(HttpState {
            store: crate::store::MemoryStore::new(),
            uploader: None,
            store_dir: "/nix/store".to_string(),
            priority: 50,
        });
    }

    fn state_with(store: Arc<crate::store::MemoryStore>) -> HttpState {
        HttpState {
            store,
            uploader: None,
            store_dir: "/nix/store".to_string(),
            priority: 50,
        }
    }

    fn tenant() -> TenantId {
        crate::tenant::Tenant::from_ssh("upstream-http-test", None, false).id
    }

    #[tokio::test]
    async fn upstream_narinfo_404s_for_an_unknown_slug() {
        let store = crate::store::MemoryStore::new();
        let t = tenant();
        let state = state_with(store);

        let resp = upstream_narinfo(
            State(state),
            Path((
                t.to_string(),
                "cache.nixos.org".to_string(),
                format!("{}.narinfo", "0".repeat(32)),
            )),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn upstream_narinfo_serves_a_cached_path_with_its_original_signature() {
        let store = crate::store::MemoryStore::new();
        let t = tenant();
        let (url, key) = (
            "https://cache.nixos.org".to_string(),
            "cache.nixos.org-1:AAAA".to_string(),
        );
        store.set_trusted_substituters(&t, vec![(url.clone(), key.clone())]);

        let mut path_info = info();
        path_info.sigs = vec![key.clone()];
        store
            .record_substituted_path(
                &t,
                path_info,
                crate::store::RemoteObject {
                    key: ObjectKey::new("substituted/cache.nixos.org/nar/x.nar.zst"),
                    file_size: 10,
                    file_hash: sha2::Sha256::digest([0u8; 1]),
                    compression: Compression::Zstd,
                },
                &url,
                &key,
            )
            .await
            .unwrap();

        let state = state_with(store);
        let resp = upstream_narinfo(
            State(state),
            Path((
                t.to_string(),
                "cache.nixos.org".to_string(),
                "00000000000000000000000000000000.narinfo".to_string(),
            )),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        // Carries the original signature verbatim -- never re-signed.
        assert!(body.contains(&format!("Sig: {key}")));
    }

    #[tokio::test]
    async fn a_path_recorded_against_one_substituter_does_not_read_back_as_sourced_from_another() {
        // The invariant `upstream_narinfo` relies on to refuse serving a
        // path recorded against a *different* substituter than the one
        // named in the route -- exercised at the store level, since driving
        // the handler's live-refetch fallback needs a real `UploadSigner`
        // and a mock HTTP substituter, out of scope for this unit test.
        let store = crate::store::MemoryStore::new();
        let t = tenant();
        let (url_a, key_a) = (
            "https://cache.nixos.org".to_string(),
            "cache.nixos.org-1:AAAA".to_string(),
        );
        let (url_b, key_b) = (
            "https://mirror.example".to_string(),
            "mirror.example-1:BBBB".to_string(),
        );
        store.set_trusted_substituters(
            &t,
            vec![(url_a.clone(), key_a.clone()), (url_b.clone(), key_b)],
        );
        store
            .record_substituted_path(
                &t,
                info(),
                crate::store::RemoteObject {
                    key: ObjectKey::new("substituted/cache.nixos.org/nar/x.nar.zst"),
                    file_size: 10,
                    file_hash: sha2::Sha256::digest([0u8; 1]),
                    compression: Compression::Zstd,
                },
                &url_a,
                &key_a,
            )
            .await
            .unwrap();

        assert_eq!(
            store.substituted_source(&t, &info().path).await,
            Some((url_a, key_a))
        );
        assert_ne!(
            store.substituted_source(&t, &info().path).await,
            Some((url_b, "mirror.example-1:BBBB".to_string()))
        );
    }

    #[test]
    fn a_malformed_tenant_is_refused() {
        // The id becomes an object-key prefix, so anything that could leave its
        // own prefix must not get that far.
        for bad in ["../etc", "a/b", "UPPER", ""] {
            assert!(tenant_of(bad).is_err(), "accepted {bad:?}");
        }
        assert!(tenant_of("user-alice-dabd1db8d35ab131").is_ok());
    }
}
