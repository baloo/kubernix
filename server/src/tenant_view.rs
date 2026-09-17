//! A [`Store`] bound to one tenant, for the lifetime of a connection.
//!
//! Every tenant-scoped `Store` method takes `tenant: &TenantId` as its first
//! argument, and every RPC method in [`crate::daemon_rpc`] needs the same pair
//! — `self.store` and `self.tenant.id` — to call any of them. Cloning that
//! pair separately at each `Rc<Self>`-based trait method (needed to move them
//! into a `'static` future) was, before this module existed, ~9 duplicated
//! `let store = self.store.clone(); let tenant = self.tenant.id.clone();`
//! pairs. `TenantView` is that pair as one `Clone`-cheap value: one clone
//! instead of two, one thing to pass instead of two that have to agree, and
//! no tenant parameter left at each call site to accidentally pass the wrong
//! variable for (there being only one to pass).
//!
//! Deliberately narrower than [`Store`] itself: only the tenant-taking
//! methods of [`crate::store::PathStore`] are here. `object_known` and
//! `find_verified_by_hash_part` are cross-tenant by design (see their own
//! doc comments) and `register_tenant`/[`crate::store::CapabilitySecretStore`]'s
//! methods are not tenant-scoped at all — all reached through the plain
//! `Arc<dyn Store>` instead. `ClientOptions` isn't reached through here
//! either any more — it is connection-local state now, not store state; see
//! its own doc comment.

use std::sync::Arc;
use std::time::Duration;

use kubernix_signing::Signer;
use kubernix_types::StorePath;
use uuid::Uuid;

use crate::jobs::JobOutcome;
use crate::store::{MissingPaths, PathInfo, RemoteObject, Reservation, Result, Store, Tier};
use crate::tenant::TenantId;

#[derive(Clone)]
pub struct TenantView {
    store: Arc<dyn Store>,
    tenant: TenantId,
}

impl TenantView {
    pub fn new(store: Arc<dyn Store>, tenant: TenantId) -> Self {
        Self { store, tenant }
    }

    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    /// The underlying store, for the tenant-agnostic methods `TenantView`
    /// deliberately does not wrap — see the module doc.
    pub fn store(&self) -> &Arc<dyn Store> {
        &self.store
    }

    pub async fn is_valid_path(&self, path: &StorePath) -> bool {
        self.store.is_valid_path(&self.tenant, path).await
    }

    pub async fn query_valid_paths(&self, paths: &[StorePath]) -> Vec<StorePath> {
        self.store.query_valid_paths(&self.tenant, paths).await
    }

    pub async fn query_all_valid_paths(&self) -> Vec<StorePath> {
        self.store.query_all_valid_paths(&self.tenant).await
    }

    pub async fn query_path_info(&self, path: &StorePath) -> Option<PathInfo> {
        self.store.query_path_info(&self.tenant, path).await
    }

    pub async fn query_path_from_hash_part(&self, hash_part: &str) -> Option<StorePath> {
        self.store
            .query_path_from_hash_part(&self.tenant, hash_part)
            .await
    }

    pub async fn query_referrers(&self, path: &StorePath) -> Vec<StorePath> {
        self.store.query_referrers(&self.tenant, path).await
    }

    pub async fn query_substitutable_paths(&self, paths: &[StorePath]) -> Vec<StorePath> {
        self.store
            .query_substitutable_paths(&self.tenant, paths)
            .await
    }

    pub async fn record_path(
        &self,
        info: PathInfo,
        object: RemoteObject,
        tier: Tier,
    ) -> Result<()> {
        self.store
            .record_path(&self.tenant, info, object, tier)
            .await
    }

    pub async fn output_object(&self, path: &StorePath) -> Option<RemoteObject> {
        self.store.output_object(&self.tenant, path).await
    }

    pub async fn add_signatures(&self, path: &StorePath, sigs: Vec<String>) -> Result<()> {
        self.store.add_signatures(&self.tenant, path, sigs).await
    }

    pub async fn query_missing(&self, targets: &[StorePath]) -> MissingPaths {
        self.store.query_missing(&self.tenant, targets).await
    }

    pub async fn tier(&self, path: &StorePath) -> Option<Tier> {
        self.store.tier(&self.tenant, path).await
    }

    pub async fn signer(&self) -> Option<Arc<dyn Signer>> {
        self.store.signer(&self.tenant).await
    }

    pub async fn reject_unverified_pushes(&self) -> bool {
        self.store.reject_unverified_pushes(&self.tenant).await
    }

    pub async fn record_access(&self, path: &StorePath) {
        self.store.record_access(&self.tenant, path).await
    }

    pub async fn record_job_outcome(
        &self,
        job_id: Uuid,
        derivation_path: &StorePath,
        system: &str,
        outcome: &JobOutcome,
    ) {
        self.store
            .record_job_outcome(&self.tenant, job_id, derivation_path, system, outcome)
            .await
    }

    pub async fn reserve_job(
        &self,
        job_id: Uuid,
        derivation_path: &StorePath,
        system: &str,
        retention: Duration,
    ) -> Reservation {
        self.store
            .reserve_job(&self.tenant, job_id, derivation_path, system, retention)
            .await
    }
}
