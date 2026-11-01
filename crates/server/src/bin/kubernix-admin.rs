//! Admin CLI: list/add tenants, list/add/delete their credentials.
//!
//! One-shot, unlike `kubernix-gc`/`kubernix-rotate-capability-secret` (which
//! run on a timer): every admin operation here is a single invocation an
//! operator runs by hand, so there is no interval to configure and no
//! `--once` flag needed.
//!
//! Environment:
//!   `DATABASE_URL`   PostgreSQL; required
//!
//! `add-tenant` takes only a name, not an id: the id is derived from it
//! (`admin::add_tenant`/`tenant::derive_id`) rather than hand-typed, since a
//! hand-typed id is exactly the kind of thing an operator gets subtly wrong.
//! `list-tenants`/`add-tenant`'s own output is where the id to copy into a
//! later `add-credential`/`list-credentials` call comes from.

use clap::{Parser, Subcommand, ValueEnum};
use eyre::{Context as _, OptionExt as _, bail};
use kubernix_server::admin;
use kubernix_server::postgres_store::{PostgresStore, ServingRole};
use kubernix_server::tenant::KeyType;
use kubernix_types::TenantId;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// List every tenant.
    ListTenants,
    /// Provision a new tenant; the id is derived from `name`, not chosen.
    AddTenant { name: String },
    /// List a tenant's bound credentials.
    ListCredentials { tenant: TenantIdArg },
    /// Bind a new credential to a tenant.
    AddCredential {
        tenant: TenantIdArg,
        /// Credential type. Only `ssh` is supported today — `KeyType`
        /// (`crate::tenant::KeyType`) has no `Tls`/x509 variant yet.
        #[arg(long, value_enum)]
        r#type: CliKeyType,
        /// An OpenSSH public-key line (`ssh-ed25519 AAAA... comment`), the
        /// same shape `~/.ssh/authorized_keys` uses.
        material: String,
    },
    /// Remove a credential binding.
    DeleteCredential {
        #[arg(long, value_enum)]
        r#type: CliKeyType,
        key_id: String,
    },
    /// List a tenant's trusted substituters.
    ListSubstituters { tenant: TenantIdArg },
    /// Add a trusted substituter to a tenant.
    AddSubstituter {
        tenant: TenantIdArg,
        url: String,
        /// A `trusted-public-keys`-shaped entry, e.g.
        /// `cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=`.
        public_key: String,
    },
    /// Remove a trusted substituter from a tenant.
    RemoveSubstituter { tenant: TenantIdArg, url: String },
}

/// A separate enum from `KeyType`, not that type reused with `#[derive(ValueEnum)]`:
/// `KeyType` lives in `crate::tenant` for the auth path, and this crate's
/// dependency on `clap` should stay confined to this one binary.
#[derive(Clone, Copy, ValueEnum)]
enum CliKeyType {
    Ssh,
}

impl From<CliKeyType> for KeyType {
    fn from(value: CliKeyType) -> Self {
        match value {
            CliKeyType::Ssh => KeyType::Ssh,
        }
    }
}

/// Wraps `TenantId` so `clap` can parse it directly (`TenantId` itself has no
/// `Default`/`From<String>` by design — see its own doc comment — but does
/// implement `FromStr`, which this just exposes to `#[derive(Parser)]`).
#[derive(Clone)]
struct TenantIdArg(TenantId);

impl std::str::FromStr for TenantIdArg {
    type Err = <TenantId as std::str::FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse().map(TenantIdArg)
    }
}

impl std::fmt::Display for TenantIdArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[tokio::main]
async fn main() -> color_eyre::eyre::Result<()> {
    color_eyre::install()?;
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "kubernix_server=debug,kubernix_admin=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    let cli = Cli::parse();

    let database_url = std::env::var("DATABASE_URL")
        .ok()
        .ok_or_eyre("DATABASE_URL must be set")?;
    let store = PostgresStore::connect(&database_url, ServingRole::Admin)
        .await
        .wrap_err("connecting to PostgreSQL")?;
    // Seeded into every tenant `add-tenant` creates from here on — see
    // `admin::add_tenant`'s own doc comment. Unset means no default, not
    // that seeding silently no-ops in a surprising way: an operator running
    // `add-tenant` without these set simply gets a tenant with no
    // substituters configured, same as before this feature existed.
    if let (Ok(url), Ok(key)) = (
        std::env::var("KUBERNIX_DEFAULT_SUBSTITUTER_URL"),
        std::env::var("KUBERNIX_DEFAULT_SUBSTITUTER_KEY"),
    ) {
        store.set_default_substituter(url, key);
    }

    match cli.command {
        Command::ListTenants => list_tenants(&store).await,
        Command::AddTenant { name } => add_tenant(&store, &name).await,
        Command::ListCredentials { tenant } => list_credentials(&store, &tenant.0).await,
        Command::AddCredential {
            tenant,
            r#type,
            material,
        } => add_credential(&store, &tenant.0, r#type.into(), &material).await,
        Command::DeleteCredential { r#type, key_id } => {
            delete_credential(&store, r#type.into(), &key_id).await
        }
        Command::ListSubstituters { tenant } => list_substituters(&store, &tenant.0).await,
        Command::AddSubstituter {
            tenant,
            url,
            public_key,
        } => add_substituter(&store, &tenant.0, &url, &public_key).await,
        Command::RemoveSubstituter { tenant, url } => {
            remove_substituter(&store, &tenant.0, &url).await
        }
    }
}

async fn list_tenants(store: &PostgresStore) -> eyre::Result<()> {
    let tenants = admin::list_tenants(store).await?;
    if tenants.is_empty() {
        println!("no tenants");
        return Ok(());
    }
    println!("{:<40} {:<10} identity", "id", "verified");
    for t in tenants {
        println!("{:<40} {:<10} {}", t.id, t.verified, t.identity);
    }
    Ok(())
}

async fn add_tenant(store: &PostgresStore, name: &str) -> eyre::Result<()> {
    let id = admin::add_tenant(store, name).await?;
    println!("added tenant {name:?} as {id}");
    Ok(())
}

async fn list_credentials(store: &PostgresStore, tenant: &TenantId) -> eyre::Result<()> {
    let creds = admin::list_credentials(store, tenant).await?;
    if creds.is_empty() {
        println!("no credentials");
        return Ok(());
    }
    println!("{:<10} key_id", "type");
    for c in creds {
        println!("{:<10} {}", c.key_type, c.key_id);
    }
    Ok(())
}

async fn add_credential(
    store: &PostgresStore,
    tenant: &TenantId,
    key_type: KeyType,
    material: &str,
) -> eyre::Result<()> {
    admin::add_credential(store, tenant, key_type, material).await?;
    println!("added credential for tenant {tenant}");
    Ok(())
}

async fn delete_credential(
    store: &PostgresStore,
    key_type: KeyType,
    key_id: &str,
) -> eyre::Result<()> {
    let deleted = admin::delete_credential(store, key_type, key_id).await?;
    if deleted {
        println!("deleted credential {key_id}");
    } else {
        bail!("no such credential: {key_id}");
    }
    Ok(())
}

async fn list_substituters(store: &PostgresStore, tenant: &TenantId) -> eyre::Result<()> {
    let substituters = admin::list_substituters(store, tenant).await?;
    if substituters.is_empty() {
        println!("no substituters");
        return Ok(());
    }
    println!("{:<40} public_key", "url");
    for s in substituters {
        println!("{:<40} {}", s.url, s.public_key);
    }
    Ok(())
}

async fn add_substituter(
    store: &PostgresStore,
    tenant: &TenantId,
    url: &str,
    public_key: &str,
) -> eyre::Result<()> {
    admin::add_substituter(store, tenant, url, public_key).await?;
    println!("added substituter {url:?} for tenant {tenant}");
    Ok(())
}

async fn remove_substituter(
    store: &PostgresStore,
    tenant: &TenantId,
    url: &str,
) -> eyre::Result<()> {
    let removed = admin::remove_substituter(store, tenant, url).await?;
    if removed {
        println!("removed substituter {url:?} from tenant {tenant}");
    } else {
        bail!("no such substituter: {url:?}");
    }
    Ok(())
}
