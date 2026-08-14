//! Nix `--export` format.
//!
//! `nix-store --import` needs more than file contents: registering a path also
//! needs its references and deriver, and a bare NAR carries neither. The export
//! format wraps a NAR together with that metadata.
//!
//! **This is built here, on the worker, rather than stored.** The object store
//! holds exactly one representation of a path — a compressed bare NAR — because
//! that is what `narFromPath` streams and what the binary cache serves. Wrapping
//! it for import is a per-consumer concern, so the frontend ships the references
//! and deriver alongside the object key (`InputRef` in `protocol/kubernix.capnp`)
//! and the worker assembles the stream itself. Storing a second, export-shaped
//! copy of every input would be pure duplication.
//!
//! Layout, from `Store::exportPath` (`lix/libstore/export-import.cc:28-58`) and
//! `Store::importPaths`, per path:
//!
//! ```text
//! u64  1                 -- 0 terminates the stream
//! ..   <NAR bytes>
//! u64  exportMagic       -- 0x4558494e
//! str  store path
//! strs references
//! str  deriver           -- empty when unknown
//! u64  0                 -- obsolete signature field
//! ```
//!
//! then a final `u64 0`.

use kubernix_types::StorePath;

/// `lix/libstore/store-api.hh:107`.
const EXPORT_MAGIC: u64 = 0x4558_494e;

/// Integers are little-endian u64; strings are a u64 length followed by the
/// bytes, zero-padded to a multiple of 8.
fn write_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_str(out: &mut Vec<u8>, value: &[u8]) {
    write_u64(out, value.len() as u64);
    out.extend_from_slice(value);
    let padding = (8 - (value.len() % 8)) % 8;
    out.extend(std::iter::repeat_n(0u8, padding));
}

/// The bytes that follow a NAR to make it an importable export stream.
///
/// Returned separately from the NAR so a caller can stream the NAR through
/// without ever holding it: write the header, forward the NAR, then write this.
///
/// `store_dir` reconstructs the full printed paths this format carries — see
/// [`StorePath`]'s doc comment.
pub fn trailer(
    store_path: &StorePath,
    references: &[StorePath],
    deriver: &StorePath,
    store_dir: &str,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    write_u64(&mut out, EXPORT_MAGIC);
    write_str(&mut out, store_path.to_full(store_dir).as_bytes());

    write_u64(&mut out, references.len() as u64);
    for reference in references {
        write_str(&mut out, reference.to_full(store_dir).as_bytes());
    }

    write_str(&mut out, deriver.to_full(store_dir).as_bytes());
    write_u64(&mut out, 0);

    // End of stream.
    write_u64(&mut out, 0);
    out
}

/// The bytes that precede the NAR: the marker saying a path follows.
pub fn header() -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    write_u64(&mut out, 1);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const STORE_DIR: &str = "/nix/store";
    const P: &str = "00000000000000000000000000000000-thing";
    /// The full printed form `trailer` actually writes onto the wire.
    const FULL_P: &str = "/nix/store/00000000000000000000000000000000-thing";

    fn p() -> StorePath {
        StorePath::new(P)
    }

    fn read_u64(bytes: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap())
    }

    #[test]
    fn frames_a_single_path() {
        let header = header();
        assert_eq!(read_u64(&header, 0), 1, "stream starts with a path marker");

        let trailer = trailer(&p(), &[], &StorePath::default(), STORE_DIR);
        assert_eq!(read_u64(&trailer, 0), EXPORT_MAGIC);
        assert_eq!(read_u64(&trailer, 8) as usize, FULL_P.len());
        assert_eq!(&trailer[16..16 + FULL_P.len()], FULL_P.as_bytes());
        assert_eq!(
            read_u64(&trailer, trailer.len() - 8),
            0,
            "stream is terminated"
        );
    }

    #[test]
    fn pads_strings_to_eight_bytes() {
        // A reader that mis-handles padding desynchronises for the rest of the
        // stream, so assert the field *after* the path lands where it should.
        let padding = (8 - (FULL_P.len() % 8)) % 8;
        assert_ne!(padding, 0, "this path should exercise padding");

        let trailer = trailer(&p(), &[], &StorePath::default(), STORE_DIR);
        // magic(8) + length(8) = 16, then the path itself.
        let after_path = 16 + FULL_P.len() + padding;
        assert_eq!(
            read_u64(&trailer, after_path),
            0,
            "reference count should follow the padded path"
        );
    }

    #[test]
    fn carries_references_and_deriver() {
        // Without these a worker can fetch a path's bytes but not register it,
        // which is the whole reason they travel with the object key.
        let dep = StorePath::new("11111111111111111111111111111111-dep");
        let drv = StorePath::new("22222222222222222222222222222222-thing.drv");
        let trailer = trailer(&p(), std::slice::from_ref(&dep), &drv, STORE_DIR);

        let haystack = String::from_utf8_lossy(&trailer);
        assert!(
            haystack.contains(&dep.to_full(STORE_DIR)),
            "references must survive"
        );
        assert!(
            haystack.contains(&drv.to_full(STORE_DIR)),
            "deriver must survive"
        );
    }
}
