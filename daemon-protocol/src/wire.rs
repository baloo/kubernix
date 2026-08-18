//! Async read/write primitives for the Nix/Lix "worker protocol"
//! (`lix/libstore/worker-protocol.hh`) — the wire format a real
//! `nix-daemon --stdio` speaks, and what every op in [`crate::connection`]
//! is built from.
//!
//! Same shape as `worker/src/serve.rs`'s `WireWrite`/`WireRead` (little-endian
//! u64s, strings length-prefixed and zero-padded to a multiple of eight; see
//! `kubernix_types::wire` for the synchronous, in-memory-buffer half of the
//! same shape) — not shared code, since this crate deliberately does not
//! depend on `worker`, but the same pattern: blanket-impl'd over any
//! `AsyncRead`/`AsyncWrite` so the framing is exercisable in tests against a
//! `Vec<u8>`/`Cursor`, no live connection required.

use kubernix_types::wire::padding;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(crate) trait WireWrite {
    async fn write_wire_u64(&mut self, value: u64) -> std::io::Result<()>;

    async fn write_wire_bool(&mut self, value: bool) -> std::io::Result<()> {
        self.write_wire_u64(value as u64).await
    }

    /// A length-prefixed byte string, zero-padded to a multiple of eight.
    async fn write_wire_bytes(&mut self, value: &[u8]) -> std::io::Result<()>;

    async fn write_wire_str(&mut self, value: &str) -> std::io::Result<()> {
        self.write_wire_bytes(value.as_bytes()).await
    }

    async fn write_wire_strings<S: AsRef<str>>(&mut self, values: &[S]) -> std::io::Result<()> {
        self.write_wire_u64(values.len() as u64).await?;
        for v in values {
            self.write_wire_str(v.as_ref()).await?;
        }
        Ok(())
    }
}

impl<W: tokio::io::AsyncWrite + Unpin> WireWrite for W {
    async fn write_wire_u64(&mut self, value: u64) -> std::io::Result<()> {
        self.write_all(&value.to_le_bytes()).await
    }

    async fn write_wire_bytes(&mut self, value: &[u8]) -> std::io::Result<()> {
        self.write_wire_u64(value.len() as u64).await?;
        self.write_all(value).await?;
        let padding = padding(value.len());
        if padding > 0 {
            self.write_all(&[0u8; 8][..padding]).await?;
        }
        Ok(())
    }
}

pub(crate) trait WireRead {
    async fn read_wire_u64(&mut self) -> std::io::Result<u64>;

    async fn read_wire_bool(&mut self) -> std::io::Result<bool> {
        Ok(self.read_wire_u64().await? != 0)
    }

    async fn read_wire_bytes(&mut self) -> std::io::Result<Vec<u8>>;

    async fn read_wire_str(&mut self) -> std::io::Result<String> {
        Ok(String::from_utf8_lossy(&self.read_wire_bytes().await?).into_owned())
    }

    async fn read_wire_strings(&mut self) -> std::io::Result<Vec<String>> {
        let count = self.read_wire_u64().await? as usize;
        let mut out = Vec::with_capacity(count.min(1 << 20));
        for _ in 0..count {
            out.push(self.read_wire_str().await?);
        }
        Ok(out)
    }
}

impl<R: tokio::io::AsyncRead + Unpin> WireRead for R {
    async fn read_wire_u64(&mut self) -> std::io::Result<u64> {
        let mut buf = [0u8; 8];
        self.read_exact(&mut buf).await?;
        Ok(u64::from_le_bytes(buf))
    }

    async fn read_wire_bytes(&mut self) -> std::io::Result<Vec<u8>> {
        let len = self.read_wire_u64().await? as usize;
        let mut buf = vec![0u8; len];
        self.read_exact(&mut buf).await?;

        // Skip the padding, or every later field is misaligned.
        let padding = padding(len);
        if padding > 0 {
            let mut discard = [0u8; 8];
            self.read_exact(&mut discard[..padding]).await?;
        }
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trips_scalars_and_strings() {
        let mut buf: Vec<u8> = Vec::new();
        buf.write_wire_u64(0x1122_3344_5566_7788).await.unwrap();
        buf.write_wire_bool(true).await.unwrap();
        buf.write_wire_str("hello").await.unwrap();
        buf.write_wire_strings(&["a", "bc", ""]).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        assert_eq!(cursor.read_wire_u64().await.unwrap(), 0x1122_3344_5566_7788);
        assert!(cursor.read_wire_bool().await.unwrap());
        assert_eq!(cursor.read_wire_str().await.unwrap(), "hello");
        assert_eq!(cursor.read_wire_strings().await.unwrap(), vec!["a", "bc", ""]);
    }

    #[tokio::test]
    async fn a_field_after_a_non_padded_string_lands_where_it_should() {
        let mut buf: Vec<u8> = Vec::new();
        buf.write_wire_str("hello").await.unwrap(); // 5 bytes: 3 bytes of padding
        buf.write_wire_u64(42).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        assert_eq!(cursor.read_wire_str().await.unwrap(), "hello");
        assert_eq!(cursor.read_wire_u64().await.unwrap(), 42);
    }

    #[tokio::test]
    async fn reading_past_the_end_of_the_buffer_is_an_error_not_a_panic() {
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
        assert!(cursor.read_wire_u64().await.is_err());

        let mut buf: Vec<u8> = Vec::new();
        buf.write_wire_u64(100).await.unwrap();
        buf.extend_from_slice(b"short");
        let mut cursor = std::io::Cursor::new(buf);
        assert!(cursor.read_wire_str().await.is_err());
    }
}
