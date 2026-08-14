//! Primitives for wire formats shaped like little-endian u64s and strings
//! length-prefixed and zero-padded to a multiple of eight — the shape Nix/Lix
//! agree on across several unrelated protocols: the `nix-store --serve`
//! protocol, the `--export` stream format, and `serializeDerivation`'s output.
//!
//! Before this module existed, three call sites each reimplemented it
//! independently: `worker::serve`'s async stream read/write, `worker::
//! nar_export`'s buffer writer, and this crate's `derivation` reader. The
//! padding arithmetic in particular is easy to get subtly wrong, and silently
//! desynchronises every field after it when it is — worth having in exactly
//! one place rather than three that could drift apart.
//!
//! This covers the *synchronous, in-memory buffer* half of that shape —
//! [`write_u64`]/[`write_bytes`] for building one up, [`Reader`] for reading
//! one back. `worker::serve` talks to a live child process pipe instead of a
//! buffer, so it still has its own `async` read/write side, but reuses
//! [`padding`] rather than recomputing it a third way.

/// Bytes needed to round `len` up to a multiple of eight.
pub fn padding(len: usize) -> usize {
    (8 - len % 8) % 8
}

/// Append a little-endian u64.
pub fn write_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Append a length-prefixed byte string, zero-padded to a multiple of eight.
pub fn write_bytes(out: &mut Vec<u8>, value: &[u8]) {
    write_u64(out, value.len() as u64);
    out.extend_from_slice(value);
    out.extend(std::iter::repeat_n(0u8, padding(value.len())));
}

/// Why a [`Reader`] call failed: the buffer ran out before the field it was
/// reading did.
#[derive(Debug, thiserror::Error)]
#[error("truncated wire data at byte {0}")]
pub struct Truncated(usize);

/// A cursor over an in-memory buffer in this wire format — the read side of
/// [`write_u64`]/[`write_bytes`].
pub struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    pub fn u64(&mut self) -> Result<u64, Truncated> {
        let end = self.pos + 8;
        if end > self.bytes.len() {
            return Err(Truncated(self.pos));
        }
        let value = u64::from_le_bytes(self.bytes[self.pos..end].try_into().unwrap());
        self.pos = end;
        Ok(value)
    }

    /// The next `len` bytes, skipping past their padding.
    pub fn bytes(&mut self, len: usize) -> Result<&'a [u8], Truncated> {
        let end = self.pos + len;
        if end > self.bytes.len() {
            return Err(Truncated(self.pos));
        }
        let value = &self.bytes[self.pos..end];
        self.pos = end + padding(len);
        Ok(value)
    }

    /// A length-prefixed string, lossily decoded — this wire format carries
    /// no encoding guarantee stronger than "bytes Nix printed a path or
    /// similar into", so a caller that needs strict UTF-8 validation is
    /// expected to do it on top of this.
    pub fn string(&mut self) -> Result<String, Truncated> {
        let len = self.u64()? as usize;
        Ok(String::from_utf8_lossy(self.bytes(len)?).into_owned())
    }

    pub fn strings(&mut self) -> Result<Vec<String>, Truncated> {
        let count = self.u64()? as usize;
        (0..count).map(|_| self.string()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn padding_rounds_up_to_a_multiple_of_eight() {
        assert_eq!(padding(0), 0);
        assert_eq!(padding(1), 7);
        assert_eq!(padding(7), 1);
        assert_eq!(padding(8), 0);
        assert_eq!(padding(9), 7);
    }

    #[test]
    fn round_trips_integers_and_strings() {
        let mut buf = Vec::new();
        write_u64(&mut buf, 0x1122_3344_5566_7788);
        write_bytes(&mut buf, b"hello");
        write_bytes(&mut buf, b"");

        let mut r = Reader::new(&buf);
        assert_eq!(r.u64().unwrap(), 0x1122_3344_5566_7788);
        assert_eq!(r.string().unwrap(), "hello");
        assert_eq!(r.string().unwrap(), "");
    }

    #[test]
    fn a_field_after_padding_lands_where_it_should() {
        // A reader that mis-handles padding desynchronises for the rest of
        // the stream, so assert the field *after* a non-multiple-of-8 string
        // lands correctly rather than just checking the string itself.
        let mut buf = Vec::new();
        write_bytes(&mut buf, b"hello"); // 5 bytes: needs 3 bytes of padding
        write_u64(&mut buf, 42);

        let mut r = Reader::new(&buf);
        assert_eq!(r.string().unwrap(), "hello");
        assert_eq!(r.u64().unwrap(), 42);
    }

    #[test]
    fn truncated_input_is_refused_rather_than_panicking() {
        assert!(Reader::new(&[0u8; 4]).u64().is_err());
        assert!(Reader::new(&[0u8; 8]).bytes(100).is_err());

        let mut buf = Vec::new();
        write_u64(&mut buf, 100); // claims a 100-byte string
        write_bytes(&mut buf, b"but"); // actually much shorter
        assert!(Reader::new(&buf).string().is_err());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // A `Reader` over an arbitrary sequence of writes must read back
        // exactly what was written, in order — the general form of
        // `round_trips_integers_and_strings` above, covering shapes a
        // hand-picked example list would not: odd lengths, non-ASCII bytes,
        // long runs of zeros, and everything in between.
        #[test]
        fn round_trips_any_sequence_of_fields(
            fields in proptest::collection::vec(
                prop_oneof![
                    any::<u64>().prop_map(Field::U64),
                    proptest::collection::vec(any::<u8>(), 0..256).prop_map(Field::Bytes),
                ],
                0..32,
            )
        ) {
            let mut buf = Vec::new();
            for field in &fields {
                match field {
                    Field::U64(v) => write_u64(&mut buf, *v),
                    Field::Bytes(b) => write_bytes(&mut buf, b),
                }
            }

            let mut r = Reader::new(&buf);
            for field in &fields {
                match field {
                    Field::U64(v) => prop_assert_eq!(r.u64().unwrap(), *v),
                    Field::Bytes(b) => {
                        // Mirrors exactly what `write_bytes` wrote: a u64
                        // length prefix, then that many bytes (`Reader::bytes`
                        // skips the padding `write_bytes` added itself).
                        let len = r.u64().unwrap() as usize;
                        prop_assert_eq!(len, b.len());
                        prop_assert_eq!(r.bytes(len).unwrap(), b.as_slice());
                    }
                }
            }
        }

        // The property the module doc and `serve.rs`'s own comments worry
        // about most: a `Reader` fed completely arbitrary — not just
        // truncated — bytes must never panic, only ever return `Ok` or
        // `Err`. This is what would have caught an off-by-one in the
        // padding arithmetic before it ever reached a real, harder-to-debug
        // desynchronised stream.
        #[test]
        fn never_panics_on_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let mut r = Reader::new(&bytes);
            // Drain it as a real caller would: alternating length-prefixed
            // reads until one fails, rather than one fixed call shape.
            for _ in 0..16 {
                if r.string().is_err() {
                    break;
                }
            }
        }
    }

    #[derive(Debug)]
    enum Field {
        U64(u64),
        Bytes(Vec<u8>),
    }
}
