//! Who a connection belongs to.
//!
//! Tenancy is **attribution**, and it is deliberately separate from
//! authentication, which is **verification** (PLAN.md Phase 9). The frontend
//! already knows the SSH username and public-key fingerprint a client presented;
//! that is a real, specific identity even while `AuthPolicy::AcceptAll` means
//! nobody has checked it. Recording it now means the history is attributed when
//! auth arrives, rather than a pile of rows owned by `default`.
//!
//! [`Tenant::verified`] carries that distinction so no caller can lose it by
//! accident: it is set from the auth policy that admitted the connection, and it
//! is what any decision stronger than attribution must consult.

use sha2::{Digest, Sha256};

/// A tenant's stable identifier.
///
/// Defined in `kubernix-types` because it crosses the server/worker process
/// boundary — a worker asking for pre-signed URLs needs the same type the
/// frontend minted. What's here is the derivation logic specific to *this*
/// process: how a tenant is attributed from what an SSH client presented.
pub use kubernix_types::TenantId;

/// A binding's credential type — `key_type` in `tenant_auth_bindings`.
///
/// Only one variant today, deliberately: `KeyType::Tls` and the CHECK
/// constraint that allows it both land together with the mTLS API that would
/// actually issue a TLS-bound credential, not ahead of it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyType {
    Ssh,
}

impl KeyType {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyType::Ssh => "ssh",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Tenant {
    pub id: TenantId,
    /// What the id was derived from, kept for the record: a key fingerprint, or
    /// a username when the client offered no key.
    pub identity: String,
    /// Whether anything actually checked that identity.
    ///
    /// False under `AuthPolicy::AcceptAll`, where a client may claim any user
    /// and any key. Attribution is still useful — a client has no reason to lie
    /// to itself, and consistent liars stay consistently separated — but this
    /// must be true before the id is treated as a permission.
    pub verified: bool,
}

/// How much of the identity hash goes into the id. 16 hex chars is 64 bits,
/// which is far beyond collision range for a tenant list and keeps keys short.
const HASH_CHARS: usize = 16;

/// Longest readable prefix kept from the identity.
const SLUG_CHARS: usize = 24;

impl Tenant {
    /// Derive a tenant from what an SSH client presented.
    ///
    /// The fingerprint is preferred over the username: it is the thing auth will
    /// eventually verify, so deriving from it means enabling auth does not
    /// renumber every existing tenant.
    pub fn from_ssh(user: &str, fingerprint: Option<&str>, verified: bool) -> Self {
        let identity = match fingerprint {
            Some(fingerprint) => format!("key:{fingerprint}"),
            None => format!("user:{user}"),
        };
        Self {
            id: derive_id(&identity),
            identity,
            verified,
        }
    }
}

fn derive_id(identity: &str) -> TenantId {
    let digest = Sha256::digest(identity.as_bytes());
    let hash: String = digest
        .iter()
        .take(HASH_CHARS.div_ceil(2))
        .map(|byte| format!("{byte:02x}"))
        .collect();

    let slug: String = identity
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .take(SLUG_CHARS)
        .collect();
    let slug = slug.trim_matches('-').to_string();

    TenantId::from_parts(&slug, &hash[..HASH_CHARS])
}

#[cfg(test)]
mod tests {
    use super::*;

    const FP: &str = "SHA256:abc+def/ghi=";

    #[test]
    fn derives_from_the_fingerprint_when_there_is_one() {
        let with_key = Tenant::from_ssh("alice", Some(FP), true);
        let without = Tenant::from_ssh("alice", None, false);

        assert_ne!(
            with_key.id, without.id,
            "a key identifies a client; a username is only a claim about one"
        );
        assert!(with_key.verified);
        assert!(!without.verified);
    }

    #[test]
    fn the_same_client_is_the_same_tenant() {
        assert_eq!(
            Tenant::from_ssh("alice", Some(FP), true).id,
            // A different username with the same key: the key is what counts, so
            // enabling auth later must not renumber anyone.
            Tenant::from_ssh("bob", Some(FP), true).id
        );
    }

    #[test]
    fn ids_are_safe_as_object_key_prefixes() {
        // Fingerprints are base64 and contain `/` and `+`; usernames are
        // arbitrary. Neither may reach a key unescaped.
        for identity in [FP, "../../etc/passwd", "a/b", "", "üñïçø∂é"] {
            let id = Tenant::from_ssh(identity, None, false).id;
            let id = id.as_str();
            assert!(
                id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
                "unsafe id {id:?} from {identity:?}"
            );
            assert!(!id.contains(".."), "unsafe id {id:?}");
        }
    }

    #[test]
    fn identities_that_sanitise_alike_stay_distinct() {
        // Both slugify to `user-a-b`; only the hash keeps them apart, and
        // merging them would merge two tenants' stores.
        let one = Tenant::from_ssh("a/b", None, false).id;
        let two = Tenant::from_ssh("a+b", None, false).id;
        assert_ne!(one, two);
    }

    #[test]
    fn wire_ids_that_could_escape_a_key_prefix_are_refused() {
        // A worker supplies this string, and it is concatenated into an object
        // key. Anything that can leave its own prefix defeats the point.
        for bad in ["../other", "a/b", "", "UPPER", "with space", "dot.dot"] {
            assert!(TenantId::from_wire(bad).is_none(), "accepted {bad:?}");
        }
        assert!(TenantId::from_wire("user-alice-dabd1db8d35ab131").is_some());
    }

    #[test]
    fn derived_ids_survive_the_wire_check() {
        // The two must agree, or a worker could never present a real tenant.
        for identity in ["alice", "a/b", "üñïçø∂é", "SHA256:abc+def/ghi="] {
            let id = Tenant::from_ssh(identity, None, false).id;
            assert!(
                TenantId::from_wire(id.as_str()).is_some(),
                "derived id {id} would be refused off the wire"
            );
        }
    }

    #[test]
    fn ids_are_stable() {
        // The id ends up in object keys and (from Phase 10) in a primary key, so
        // a change here is a migration, not a refactor.
        assert_eq!(
            Tenant::from_ssh("alice", None, false).id.as_str(),
            "user-alice-dabd1db8d35ab131"
        );
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // The general form of `ids_are_safe_as_object_key_prefixes` and
        // `derived_ids_survive_the_wire_check` above: an SSH client can
        // present *any* username, and a fingerprint is attacker-influenced
        // input too, so `derive_id` must produce a wire-safe `TenantId` for
        // arbitrary text, not just the handful of tricky examples those
        // tests hand-picked. `proptest`'s default string strategy covers
        // arbitrary Unicode, not just ASCII.
        #[test]
        fn derived_ids_are_always_wire_safe(user in ".{0,64}", fingerprint in proptest::option::of(".{0,64}")) {
            let tenant = Tenant::from_ssh(&user, fingerprint.as_deref(), false);
            let id = tenant.id.as_str();

            prop_assert!(
                id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'),
                "unsafe id {id:?} from user={user:?} fingerprint={fingerprint:?}"
            );
            prop_assert!(!id.contains(".."), "unsafe id {id:?}");
            prop_assert!(
                TenantId::from_wire(id).is_some(),
                "derived id {id} would be refused off the wire"
            );
        }

        // Same identity in, same id out — regardless of what the identity
        // actually contains. Determinism here is load-bearing: it's what
        // lets `the_same_client_is_the_same_tenant` hold for every client,
        // not just the ones under test.
        #[test]
        fn deriving_twice_from_the_same_input_agrees(user in ".{0,64}") {
            prop_assert_eq!(
                Tenant::from_ssh(&user, None, false).id,
                Tenant::from_ssh(&user, None, false).id
            );
        }
    }
}
