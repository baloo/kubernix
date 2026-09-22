//! Admin operations on tenants and their credentials.
//!
//! Driven by `kubernix-admin` (`server/src/bin/kubernix-admin.rs`). Until
//! this existed, provisioning a tenant meant hand-writing `INSERT INTO
//! tenants` / `INSERT INTO tenant_auth_bindings` (see README.md's
//! "Multi-tenancy" section, and the test-only `provision_binding` helper in
//! `postgres_store.rs` this module formalises).
//!
//! Like `crate::gc` and `crate::rotate`, this issues SQL directly against
//! `store.pool` rather than through `crate::store::Store` — these are
//! cross-tenant, out-of-band operations that a tenant-scoped connection has
//! no business doing, not something on the serving path.
//!
//! Tenant deletion is deliberately not provided: nothing downstream (worker
//! VMs, object-store data, jobs) has a defined teardown story yet, so this
//! module only ever adds.

use sqlx::Row;

use crate::postgres_store::PostgresStore;
use crate::tenant::KeyType;
use kubernix_types::TenantId;

#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("database: {0}")]
    Database(#[from] sqlx::Error),
    #[error("tenant {0:?} already exists")]
    TenantExists(TenantId),
    #[error("tenant {0:?} does not exist")]
    NoSuchTenant(TenantId),
    #[error("credential {key_type:?}/{key_id:?} is already bound to a tenant")]
    CredentialExists { key_type: KeyType, key_id: String },
    #[error("parsing the SSH public key: {0}")]
    InvalidSshKey(String),
    #[error("tenant {tenant:?} already has substituter {url:?} configured")]
    SubstituterExists { tenant: TenantId, url: String },
}

type Result<T> = std::result::Result<T, AdminError>;

/// Postgres' unique-violation SQLSTATE — used to tell "this row already
/// exists" apart from any other database error.
const UNIQUE_VIOLATION: &str = "23505";
/// Postgres' foreign-key-violation SQLSTATE — used to tell "the tenant this
/// credential would reference doesn't exist" apart from any other database
/// error.
const FOREIGN_KEY_VIOLATION: &str = "23503";

fn is_code(error: &sqlx::Error, code: &str) -> bool {
    matches!(error, sqlx::Error::Database(db) if db.code().as_deref() == Some(code))
}

#[derive(Debug, Clone)]
pub struct TenantSummary {
    pub id: TenantId,
    pub identity: String,
    pub verified: bool,
}

/// Every tenant, oldest first.
pub async fn list_tenants(store: &PostgresStore) -> Result<Vec<TenantSummary>> {
    let rows = sqlx::query("SELECT id, identity, verified FROM tenants ORDER BY first_seen")
        .fetch_all(&store.pool)
        .await?;

    Ok(rows
        .into_iter()
        .filter_map(|row| {
            Some(TenantSummary {
                id: TenantId::from_wire(row.try_get::<String, _>("id").ok()?)?,
                identity: row.try_get("identity").ok()?,
                verified: row.try_get("verified").ok()?,
            })
        })
        .collect())
}

/// Provision a new tenant named `name`, `verified` from the start — an
/// operator creating this row by hand *is* the verification, unlike a
/// connection attributed automatically under `AuthPolicy::AcceptAll`.
///
/// The id is derived from `name` via [`crate::tenant::derive_id`] — the same
/// slug+hash scheme `Tenant::from_ssh` uses — rather than taken from the
/// caller: a hand-typed id is exactly the kind of thing an operator gets
/// subtly wrong (a stale copy-paste, a typo in the hash suffix), and nothing
/// about it needs to be chosen independently of `name`. `name:` prefixes the
/// hash input (not what's stored in `identity`) so an admin-provisioned
/// tenant's id can never collide with an SSH-attributed one that happens to
/// share the same raw text — `Tenant::from_ssh` similarly prefixes with
/// `user:`/`key:`.
///
/// Deliberately not an upsert: a duplicate `add-tenant` invocation is an
/// operator mistake worth surfacing, unlike the serving path's own
/// `PostgresStore::ensure_tenant`, which upserts because a tenant showing up
/// twice is the expected case there.
pub async fn add_tenant(store: &PostgresStore, name: &str) -> Result<TenantId> {
    let id = crate::tenant::derive_id(&format!("name:{name}"));

    let result = sqlx::query("INSERT INTO tenants (id, identity, verified) VALUES ($1, $2, true)")
        .bind(id.as_str())
        .bind(name)
        .execute(&store.pool)
        .await;

    match result {
        Ok(_) => {
            seed_default_substituter(store, &id).await?;
            Ok(id)
        }
        Err(e) if is_code(&e, UNIQUE_VIOLATION) => Err(AdminError::TenantExists(id)),
        Err(e) => Err(e.into()),
    }
}

/// Insert `store`'s configured default substituter (if any) for a
/// freshly-created tenant — the `kubernix-admin` counterpart of
/// `PostgresStore::ensure_tenant`'s own seeding, needed because this path
/// writes `tenants` directly rather than through `ensure_tenant`. `ON
/// CONFLICT DO NOTHING` for the same reason as there: idempotent against a
/// retried call, and never re-inserted if an operator has since edited or
/// removed it.
async fn seed_default_substituter(store: &PostgresStore, tenant: &TenantId) -> Result<()> {
    let Some((url, public_key)) = store.default_substituter.lock().unwrap().clone() else {
        return Ok(());
    };
    sqlx::query(
        "INSERT INTO tenant_substituters (tenant, url, public_key) VALUES ($1, $2, $3)
         ON CONFLICT (tenant, url) DO NOTHING",
    )
    .bind(tenant.as_str())
    .bind(&url)
    .bind(&public_key)
    .execute(&store.pool)
    .await?;
    Ok(())
}

#[derive(Debug, Clone)]
pub struct SubstituterSummary {
    pub url: String,
    pub public_key: String,
}

/// Every trusted substituter configured for `tenant`, oldest first.
pub async fn list_substituters(
    store: &PostgresStore,
    tenant: &TenantId,
) -> Result<Vec<SubstituterSummary>> {
    let rows = sqlx::query(
        "SELECT url, public_key FROM tenant_substituters WHERE tenant = $1 ORDER BY created_at",
    )
    .bind(tenant.as_str())
    .fetch_all(&store.pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| SubstituterSummary {
            url: row.get("url"),
            public_key: row.get("public_key"),
        })
        .collect())
}

/// Add a trusted substituter to `tenant`.
pub async fn add_substituter(
    store: &PostgresStore,
    tenant: &TenantId,
    url: &str,
    public_key: &str,
) -> Result<()> {
    let result = sqlx::query(
        "INSERT INTO tenant_substituters (tenant, url, public_key) VALUES ($1, $2, $3)",
    )
    .bind(tenant.as_str())
    .bind(url)
    .bind(public_key)
    .execute(&store.pool)
    .await;

    match result {
        Ok(_) => Ok(()),
        Err(e) if is_code(&e, UNIQUE_VIOLATION) => Err(AdminError::SubstituterExists {
            tenant: tenant.clone(),
            url: url.to_string(),
        }),
        Err(e) if is_code(&e, FOREIGN_KEY_VIOLATION) => {
            Err(AdminError::NoSuchTenant(tenant.clone()))
        }
        Err(e) => Err(e.into()),
    }
}

/// Remove a trusted substituter from `tenant`. Returns whether a row
/// actually existed to remove.
pub async fn remove_substituter(
    store: &PostgresStore,
    tenant: &TenantId,
    url: &str,
) -> Result<bool> {
    let result = sqlx::query("DELETE FROM tenant_substituters WHERE tenant = $1 AND url = $2")
        .bind(tenant.as_str())
        .bind(url)
        .execute(&store.pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

#[derive(Debug, Clone)]
pub struct CredentialSummary {
    pub key_type: String,
    pub key_id: String,
}

/// Every credential bound to `tenant`, oldest first.
pub async fn list_credentials(
    store: &PostgresStore,
    tenant: &TenantId,
) -> Result<Vec<CredentialSummary>> {
    let rows = sqlx::query(
        "SELECT key_type, key_id FROM tenant_auth_bindings WHERE tenant = $1 ORDER BY created_at",
    )
    .bind(tenant.as_str())
    .fetch_all(&store.pool)
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| CredentialSummary {
            key_type: row.get("key_type"),
            key_id: row.get("key_id"),
        })
        .collect())
}

/// Bind a new credential to `tenant`.
///
/// `key_type` decides how `material` is read; today that is only
/// [`KeyType::Ssh`], an OpenSSH public-key line (`ssh-ed25519 AAAA...
/// comment`), the same shape `~/.ssh/authorized_keys` uses. Taking
/// `key_type` as a parameter now — rather than assuming SSH — means the
/// signature here doesn't need to change once `KeyType` grows a `Tls`
/// variant alongside the mTLS API that would actually issue that credential
/// type (see `crate::tenant::KeyType`'s doc comment): that lands as a new
/// match arm, not a new function.
pub async fn add_credential(
    store: &PostgresStore,
    tenant: &TenantId,
    key_type: KeyType,
    material: &str,
) -> Result<()> {
    let (key_id, key_value) = {
        let key = russh::keys::PublicKey::from_openssh(material)
            .map_err(|e| AdminError::InvalidSshKey(e.to_string()))?;
        let fingerprint = key.fingerprint(Default::default()).to_string();
        let blob = key
            .to_bytes()
            .map_err(|e| AdminError::InvalidSshKey(e.to_string()))?;
        (fingerprint, blob)
    };

    let result = sqlx::query(
        "INSERT INTO tenant_auth_bindings (key_type, key_id, tenant, key_value)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(key_type.as_str())
    .bind(&key_id)
    .bind(tenant.as_str())
    .bind(&key_value)
    .execute(&store.pool)
    .await;

    match result {
        Ok(_) => Ok(()),
        Err(e) if is_code(&e, UNIQUE_VIOLATION) => {
            Err(AdminError::CredentialExists { key_type, key_id })
        }
        Err(e) if is_code(&e, FOREIGN_KEY_VIOLATION) => {
            Err(AdminError::NoSuchTenant(tenant.clone()))
        }
        Err(e) => Err(e.into()),
    }
}

/// Remove a credential binding, regardless of which tenant holds it.
/// Returns whether a row actually existed to remove.
pub async fn delete_credential(
    store: &PostgresStore,
    key_type: KeyType,
    key_id: &str,
) -> Result<bool> {
    let result =
        sqlx::query("DELETE FROM tenant_auth_bindings WHERE key_type = $1 AND key_id = $2")
            .bind(key_type.as_str())
            .bind(key_id)
            .execute(&store.pool)
            .await?;

    Ok(result.rows_affected() > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::postgres_store::ServingRole;
    use crate::tenant::Tenant;

    async fn db() -> Option<std::sync::Arc<PostgresStore>> {
        let Ok(url) = std::env::var("KUBERNIX_TEST_DATABASE_URL") else {
            eprintln!("skipping: KUBERNIX_TEST_DATABASE_URL unset");
            return None;
        };
        match PostgresStore::connect(&url, ServingRole::Admin).await {
            Ok(store) => Some(store),
            Err(e) => panic!("KUBERNIX_TEST_DATABASE_URL is set but unusable: {e}"),
        }
    }

    fn tenant(test: &str) -> TenantId {
        Tenant::from_ssh(&format!("test-admin-{test}"), None, false).id
    }

    /// `add_tenant` is deliberately not an upsert — that's the behaviour
    /// under test — so a tenant a test creates outlives it on this shared,
    /// persistent dev database unless removed explicitly (unlike the
    /// serving path's own upserting writes, which make most other test
    /// modules' fixed per-test ids safe to reuse run after run). Mirrors the
    /// explicit teardown in `gc::tests::a_stale_unreferenced_path_is_marked`.
    ///
    /// Over a privileged connection, not `store.pool`: `kubernix_admin` has
    /// no `DELETE` on `tenants` (there is no tenant-deletion feature to
    /// grant it for), same as `postgres_store`'s own `provision_binding`
    /// test helper needing a privileged connection for the writes
    /// `kubernix_app` isn't granted. `ON DELETE CASCADE` on
    /// `tenant_auth_bindings.tenant` takes any credential with it.
    async fn cleanup_tenant(id: &TenantId) {
        let url = std::env::var("KUBERNIX_TEST_DATABASE_URL").unwrap();
        let privileged = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(&url)
            .await
            .unwrap();
        sqlx::query("DELETE FROM tenants WHERE id = $1")
            .bind(id.as_str())
            .execute(&privileged)
            .await
            .unwrap();
    }

    // Distinct keys per test, not one shared constant: `key_id` (the
    // fingerprint) is the primary key across *every* tenant, so two tests
    // binding the same key text would collide with each other when the
    // suite runs in parallel, regardless of using different tenants.
    const KEY_UNKNOWN_TENANT: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFDElZlNyHEIqviXh/UmoXKUUqFFJ7ARO3JcpB+eAc5z";
    const KEY_LIFECYCLE: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJCU6/lsgeY1GlUJF2nMkLB5kq008SBiLTz2YswJvb8o";
    const KEY_DUP: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINhErKcpxM48zmjf6C7ZBVZqOVVn1ZrbyvL1CwnITVp5";

    #[tokio::test]
    async fn add_then_list_a_tenant() {
        let Some(store) = db().await else { return };

        let id = add_tenant(&store, "test-admin-add-list").await.unwrap();

        let tenants = list_tenants(&store).await.unwrap();
        let found = tenants.iter().find(|t| t.id == id).expect("just added");
        assert_eq!(found.identity, "test-admin-add-list");
        assert!(found.verified, "admin-provisioned tenants are verified");

        cleanup_tenant(&id).await;
    }

    #[tokio::test]
    async fn add_tenant_derives_the_same_id_as_an_ssh_attributed_tenant_would_collide_with() {
        // Not an actual collision -- the point is that it *doesn't* collide,
        // because `add_tenant` hashes `name:<name>`, not the bare name, the
        // same way `Tenant::from_ssh` hashes `user:<user>`/`key:<fp>` rather
        // than the bare identity.
        let Some(store) = db().await else { return };
        let name = "test-admin-prefix-check";

        let id = add_tenant(&store, name).await.unwrap();
        let ssh_derived = Tenant::from_ssh(name, None, false).id;
        assert_ne!(id, ssh_derived);

        cleanup_tenant(&id).await;
    }

    #[tokio::test]
    async fn adding_the_same_tenant_twice_is_rejected() {
        let Some(store) = db().await else { return };

        let id = add_tenant(&store, "test-admin-dup").await.unwrap();
        let err = add_tenant(&store, "test-admin-dup").await.unwrap_err();
        assert!(matches!(err, AdminError::TenantExists(_)));

        cleanup_tenant(&id).await;
    }

    #[tokio::test]
    async fn add_credential_for_an_unknown_tenant_is_rejected() {
        let Some(store) = db().await else { return };
        let id = tenant("no-such-tenant");

        let err = add_credential(&store, &id, KeyType::Ssh, KEY_UNKNOWN_TENANT)
            .await
            .unwrap_err();
        assert!(matches!(err, AdminError::NoSuchTenant(_)));
    }

    #[tokio::test]
    async fn add_list_then_delete_a_credential() {
        let Some(store) = db().await else { return };
        let id = add_tenant(&store, "test-admin-cred-lifecycle")
            .await
            .unwrap();

        add_credential(&store, &id, KeyType::Ssh, KEY_LIFECYCLE)
            .await
            .unwrap();

        let creds = list_credentials(&store, &id).await.unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(creds[0].key_type, "ssh");
        let key_id = creds[0].key_id.clone();

        let deleted = delete_credential(&store, KeyType::Ssh, &key_id)
            .await
            .unwrap();
        assert!(deleted);

        let creds = list_credentials(&store, &id).await.unwrap();
        assert!(creds.is_empty());

        let deleted_again = delete_credential(&store, KeyType::Ssh, &key_id)
            .await
            .unwrap();
        assert!(!deleted_again, "already gone");

        cleanup_tenant(&id).await;
    }

    #[tokio::test]
    async fn adding_the_same_credential_twice_is_rejected() {
        let Some(store) = db().await else { return };
        let id = add_tenant(&store, "test-admin-cred-dup").await.unwrap();

        add_credential(&store, &id, KeyType::Ssh, KEY_DUP)
            .await
            .unwrap();
        let err = add_credential(&store, &id, KeyType::Ssh, KEY_DUP)
            .await
            .unwrap_err();
        assert!(matches!(err, AdminError::CredentialExists { .. }));

        cleanup_tenant(&id).await;
    }

    #[tokio::test]
    async fn add_substituter_for_an_unknown_tenant_is_rejected() {
        let Some(store) = db().await else { return };
        let id = tenant("no-such-tenant-sub");

        let err = add_substituter(
            &store,
            &id,
            "https://cache.nixos.org",
            "cache.nixos.org-1:key",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AdminError::NoSuchTenant(_)));
    }

    #[tokio::test]
    async fn add_list_then_remove_a_substituter() {
        let Some(store) = db().await else { return };
        let id = add_tenant(&store, "test-admin-sub-lifecycle")
            .await
            .unwrap();

        add_substituter(
            &store,
            &id,
            "https://cache.nixos.org",
            "cache.nixos.org-1:key",
        )
        .await
        .unwrap();

        let subs = list_substituters(&store, &id).await.unwrap();
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].url, "https://cache.nixos.org");

        let removed = remove_substituter(&store, &id, "https://cache.nixos.org")
            .await
            .unwrap();
        assert!(removed);

        let subs = list_substituters(&store, &id).await.unwrap();
        assert!(subs.is_empty());

        let removed_again = remove_substituter(&store, &id, "https://cache.nixos.org")
            .await
            .unwrap();
        assert!(!removed_again, "already gone");

        cleanup_tenant(&id).await;
    }

    #[tokio::test]
    async fn adding_the_same_substituter_twice_is_rejected() {
        let Some(store) = db().await else { return };
        let id = add_tenant(&store, "test-admin-sub-dup").await.unwrap();

        add_substituter(
            &store,
            &id,
            "https://cache.nixos.org",
            "cache.nixos.org-1:key",
        )
        .await
        .unwrap();
        let err = add_substituter(
            &store,
            &id,
            "https://cache.nixos.org",
            "cache.nixos.org-1:key",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, AdminError::SubstituterExists { .. }));

        cleanup_tenant(&id).await;
    }

    #[tokio::test]
    async fn add_tenant_seeds_the_configured_default_substituter() {
        let Some(store) = db().await else { return };
        store.set_default_substituter(
            "https://cache.nixos.org".to_string(),
            "cache.nixos.org-1:key".to_string(),
        );

        let id = add_tenant(&store, "test-admin-default-sub").await.unwrap();
        let subs = list_substituters(&store, &id).await.unwrap();
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].url, "https://cache.nixos.org");

        cleanup_tenant(&id).await;
    }
}
