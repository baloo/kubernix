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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omits_the_ambiguous_letters() {
        for c in [b'e', b'o', b'u', b't'] {
            assert!(!BASE32_CHARS.contains(&c), "{} should be omitted", c as char);
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
    fn is_not_rfc4648() {
        // A guard against someone "simplifying" this to a stock base32 crate:
        // the encodings genuinely differ, and the difference is silent.
        assert_ne!(encode(b"hello world"), "NBSWY3DPEB3W64TMMQ======");
    }
}
