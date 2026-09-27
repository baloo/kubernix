//! Shared length-prefix framing over the raw byte stream both sides get once
//! cloud-hypervisor's own `CONNECT <port>\n`/`OK` vsock-proxy handshake
//! completes (see `worker/src/vm_control_transport.rs` and
//! `guest-agent/src/control_transport.rs`, which wrap these in their
//! respective postcard-rpc `WireTx`/`WireRx` impls).
//!
//! One frame = a 4-byte little-endian `u32` length, then that many bytes of
//! postcard-rpc frame (header + body). A plain length prefix, not COBS: the
//! underlying transport is a reliable, ordered, single-peer stream with no
//! need for COBS's self-resync property, and this is simpler to get right
//! with plain `read_exact`/`write_all`.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Frames larger than this are rejected outright rather than allocated —
/// every message this protocol actually carries (a 32-byte key, a handful of
/// substituter URLs, a small PEM bundle) is tiny next to this; the cap exists
/// only to bound allocation if the length prefix is ever corrupt.
pub const MAX_FRAME_LEN: u32 = 1024 * 1024;

#[derive(Debug)]
pub enum FrameError {
    /// Clean EOF exactly at a frame boundary — the peer closed the
    /// connection. Distinguished from `Io` because it's the expected
    /// shutdown signal, not a corrupt stream.
    Closed,
    Io(std::io::Error),
    /// The peer declared a frame larger than [`MAX_FRAME_LEN`].
    TooLarge(u32),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Closed => write!(f, "connection closed"),
            FrameError::Io(e) => write!(f, "I/O error: {e}"),
            FrameError::TooLarge(n) => write!(f, "frame of {n} bytes exceeds the maximum"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Read one length-prefixed frame. Returns [`FrameError::Closed`] only when
/// EOF lands exactly on a frame boundary (zero bytes read before the length
/// prefix even starts) — an EOF partway through a frame is a genuine error,
/// not a graceful close.
pub async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    max_len: u32,
) -> Result<Vec<u8>, FrameError> {
    let mut len_buf = [0u8; 4];
    let mut filled = 0usize;
    while filled < len_buf.len() {
        let n = reader
            .read(&mut len_buf[filled..])
            .await
            .map_err(FrameError::Io)?;
        if n == 0 {
            if filled == 0 {
                return Err(FrameError::Closed);
            }
            return Err(FrameError::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "connection closed mid-frame while reading the length prefix",
            )));
        }
        filled += n;
    }
    let len = u32::from_le_bytes(len_buf);
    if len > max_len {
        return Err(FrameError::TooLarge(len));
    }
    let mut body = vec![0u8; len as usize];
    reader.read_exact(&mut body).await.map_err(FrameError::Io)?;
    Ok(body)
}

/// Write one length-prefixed frame.
pub async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    bytes: &[u8],
) -> Result<(), FrameError> {
    let len = u32::try_from(bytes.len()).map_err(|_| FrameError::TooLarge(u32::MAX))?;
    writer
        .write_all(&len.to_le_bytes())
        .await
        .map_err(FrameError::Io)?;
    writer.write_all(bytes).await.map_err(FrameError::Io)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trips_a_frame() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        write_frame(&mut a, b"hello").await.unwrap();
        let got = read_frame(&mut b, MAX_FRAME_LEN).await.unwrap();
        assert_eq!(got, b"hello");
    }

    #[tokio::test]
    async fn round_trips_an_empty_frame() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        write_frame(&mut a, b"").await.unwrap();
        let got = read_frame(&mut b, MAX_FRAME_LEN).await.unwrap();
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn clean_close_at_a_frame_boundary_is_closed_not_an_error() {
        let (a, mut b) = tokio::io::duplex(4096);
        drop(a);
        match read_frame(&mut b, MAX_FRAME_LEN).await {
            Err(FrameError::Closed) => {}
            other => panic!("expected Closed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        // Write a length prefix bigger than max_len directly, without ever
        // writing a body — the reader should bail before trying to read it.
        a.write_all(&100u32.to_le_bytes()).await.unwrap();
        match read_frame(&mut b, 10).await {
            Err(FrameError::TooLarge(100)) => {}
            other => panic!("expected TooLarge(100), got {other:?}"),
        }
    }
}
