//! Nix's base32.
//!
//! Not RFC 4648: the alphabet omits `e`, `o`, `u` and `t`, and the digits are
//! read from the most significant down. It lives here because a narinfo
//! fingerprint embeds a hash in this encoding, and getting it wrong makes every
//! signature invalid rather than merely differently formatted.
//!
//! Ported from `lix/libutil/strings.cc:246`.

/// `lix/libutil/strings.cc:246`.
const BASE32_CHARS: &[u8] = b"0123456789abcdfghijklmnpqrsvwxyz";

pub fn encode(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let len = (bytes.len() * 8 - 1) / 5 + 1;
    let mut out = String::with_capacity(len);

    for n in (0..len).rev() {
        let b = n * 5;
        let i = b / 8;
        let j = b % 8;
        let current = bytes[i] as u32;
        let next = if i + 1 >= bytes.len() {
            0
        } else {
            (bytes[i + 1] as u32) << (8 - j)
        };
        let c = (current >> j) | next;
        out.push(BASE32_CHARS[(c & 0x1f) as usize] as char);
    }
    out
}

/// Whether every character is in the alphabet.
pub fn is_valid(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| BASE32_CHARS.contains(&b))
}

/// Inverse of [`encode`]. `out_len` is the expected decoded byte length —
/// required, not inferred, because (as in Nix's own implementation) the
/// character count alone does not uniquely determine it: this is used to
/// decode a narinfo's `NarHash: sha256:…` field (`server/src/substitute.rs`),
/// where the caller always knows the target is 32 bytes ahead of time.
/// `None` on a wrong length, an out-of-alphabet character, or nonzero
/// padding bits (a malformed or non-canonical encoding).
pub fn decode(s: &str, out_len: usize) -> Option<Vec<u8>> {
    if out_len == 0 {
        return if s.is_empty() { Some(Vec::new()) } else { None };
    }
    let len = (out_len * 8 - 1) / 5 + 1;
    if s.len() != len {
        return None;
    }

    let mut out = vec![0u8; out_len];
    // `encode` writes chars for n = len-1 downto 0 in that order, so the
    // string's first character corresponds to the highest `n`.
    for (pos, ch) in s.bytes().enumerate() {
        let n = len - 1 - pos;
        let digit = BASE32_CHARS.iter().position(|&c| c == ch)? as u32;
        let b = n * 5;
        let i = b / 8;
        let j = b % 8;
        if i >= out_len {
            if digit != 0 {
                return None;
            }
            continue;
        }
        out[i] |= (digit << j) as u8;
        let overflow = digit >> (8 - j);
        if i + 1 < out_len {
            out[i + 1] |= overflow as u8;
        } else if overflow != 0 {
            return None;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omits_the_ambiguous_letters() {
        for c in *b"eout" {
            assert!(
                !BASE32_CHARS.contains(&c),
                "{} should be omitted",
                c as char
            );
        }
    }

    #[test]
    fn encodes_within_the_alphabet() {
        assert_eq!(encode(&[]), "");
        let encoded = encode(&[0xab; 32]);
        // 32 bytes at 5 bits per digit.
        assert_eq!(encoded.len(), (32 * 8 - 1) / 5 + 1);
        assert!(is_valid(&encoded));
    }

    #[test]
    fn decode_inverts_encode() {
        for bytes in [
            vec![],
            vec![0u8],
            vec![0xab; 32],
            vec![0xff; 20],
            (0u8..17).collect(),
        ] {
            let encoded = encode(&bytes);
            assert_eq!(
                decode(&encoded, bytes.len()),
                Some(bytes.clone()),
                "{encoded}"
            );
        }
    }

    #[test]
    fn decode_rejects_the_wrong_length() {
        let encoded = encode(&[0xab; 32]);
        assert_eq!(decode(&encoded, 31), None);
        assert_eq!(decode(&encoded, 33), None);
    }

    #[test]
    fn decode_rejects_an_out_of_alphabet_character() {
        let mut encoded = encode(&[0xab; 32]);
        encoded.replace_range(0..1, "e"); // 'e' is deliberately excluded.
        assert_eq!(decode(&encoded, 32), None);
    }

    #[test]
    fn is_not_rfc4648() {
        // A guard against someone "simplifying" this to a stock base32 crate:
        // the encodings genuinely differ, and the difference is silent.
        assert_ne!(encode(b"hello world"), "NBSWY3DPEB3W64TMMQ======");
    }
}
