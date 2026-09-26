//! A streaming HTTP body wrapper that reports its exact length up front.
//!
//! `server` and `worker` each stream an upload whose total length is known
//! before the first byte is sent, to two different HTTP stacks -- a
//! pre-signed `PUT` via `reqwest` (worker) and the S3 SDK's own client
//! (server) -- but both need the same fix for the same reason: neither
//! stack's request signing (SigV4) nor a plain fixed-length `PUT` accepts a
//! body whose `size_hint` doesn't promise an exact length, and a bare
//! `Stream` can't promise one. `SizedBody` wraps any [`http_body::Body`] and
//! overrides just `size_hint`, so the length declared once at construction
//! is what every reader downstream sees, regardless of what the wrapped
//! body reports on its own.

use http_body::{Body, Frame, SizeHint};
use std::pin::Pin;
use std::task::{Context, Poll};

/// See the module doc comment.
pub struct SizedBody<B> {
    inner: B,
    len: u64,
}

impl<B> SizedBody<B> {
    pub fn new(inner: B, len: u64) -> Self {
        SizedBody { inner, len }
    }
}

impl<B> Body for SizedBody<B>
where
    B: Body + Unpin,
{
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.get_mut().inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.len)
    }
}
