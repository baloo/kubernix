//! A tenant's stable identifier.
//!
//! Lives here (rather than in `server` alone) because it crosses the
//! server/worker process boundary: a worker asking for pre-signed URLs needs
//! the same type the frontend minted, not a `String` it has to trust blindly.

/// A tenant's stable identifier.
///
/// Used verbatim as an object-store key prefix and as the scoping key in the
/// store, so it must be safe in both: no `/`, no `..`, no surprises. Rather
/// than trusting the identity to be well-formed, callers are expected to
/// either derive one from a known-safe shape ([`TenantId::from_parts`]) or
/// validate one that arrived over the wire ([`TenantId::from_wire`]).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TenantId(String);

impl TenantId {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Build an id from a sanitised slug and a hex hash, as `server::tenant`'s
    /// `derive_id` does. Trusted: the caller is responsible for the parts
    /// already being safe (lowercase alphanumeric + `-`), since this
    /// constructor does no validation of its own — that is what
    /// [`TenantId::from_wire`] is for.
    pub fn from_parts(slug: &str, hash_hex: &str) -> Self {
        TenantId(format!("{slug}-{hash_hex}"))
    }

    /// Accept an id that arrived over the wire, e.g. from a worker asking for
    /// pre-signed URLs.
    ///
    /// Ids reach object keys by concatenation, so a value carrying `/` or `..`
    /// would break out of its own prefix and defeat the scoping it is
    /// supposed to provide. Rather than escaping it at every use, refuse
    /// anything that is not in the shape [`TenantId::from_parts`] produces.
    pub fn from_wire(id: impl Into<String>) -> Option<Self> {
        let id = id.into();
        let well_formed = !id.is_empty()
            && id.len() <= 128
            && id
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        well_formed.then_some(TenantId(id))
    }
}

impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_ids_that_could_escape_a_key_prefix_are_refused() {
        for bad in ["../other", "a/b", "", "UPPER", "with space", "dot.dot"] {
            assert!(TenantId::from_wire(bad).is_none(), "accepted {bad:?}");
        }
        assert!(TenantId::from_wire("user-alice-dabd1db8d35ab131").is_some());
    }

    #[test]
    fn parts_round_trip_through_the_wire_check() {
        let id = TenantId::from_parts("user-alice", "dabd1db8d35ab131");
        assert_eq!(id.as_str(), "user-alice-dabd1db8d35ab131");
        assert!(TenantId::from_wire(id.as_str()).is_some());
    }
}
