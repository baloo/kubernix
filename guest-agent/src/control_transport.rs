//! `postcard-rpc` server-side transport glue over the accepted control
//! `VsockStream`.
//!
//! Unlike the host-client side (`worker/src/vm_control_transport.rs`), the
//! server's `WireTx` is shared (`&self`, not `&mut self`) — postcard-rpc's
//! `Sender<Tx>` is cloned into spawned handler tasks and the heartbeat
//! publisher, so the write half needs its own lock.

use std::sync::Arc;

use kubernix_guest_protocol::transport::{self, MAX_FRAME_LEN};
use postcard_rpc::header::VarHeader;
use postcard_rpc::server::{
    AsWireRxErrorKind, AsWireTxErrorKind, WireRx, WireRxErrorKind, WireSpawn, WireTxErrorKind,
};
use tokio::sync::Mutex;
use tokio_vsock::{OwnedReadHalf, OwnedWriteHalf};

#[derive(Debug, thiserror::Error)]
pub enum ControlWireError {
    #[error("connection closed")]
    Closed,
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("received frame too large ({0} bytes)")]
    TooLarge(u32),
}

impl AsWireTxErrorKind for ControlWireError {
    fn as_kind(&self) -> WireTxErrorKind {
        match self {
            ControlWireError::Closed => WireTxErrorKind::ConnectionClosed,
            ControlWireError::Io(_) => WireTxErrorKind::Other,
            ControlWireError::TooLarge(_) => WireTxErrorKind::Other,
        }
    }
}

impl AsWireRxErrorKind for ControlWireError {
    fn as_kind(&self) -> WireRxErrorKind {
        match self {
            ControlWireError::Closed => WireRxErrorKind::ConnectionClosed,
            ControlWireError::Io(_) => WireRxErrorKind::Other,
            ControlWireError::TooLarge(_) => WireRxErrorKind::ReceivedMessageTooLarge,
        }
    }
}

impl From<transport::FrameError> for ControlWireError {
    fn from(e: transport::FrameError) -> Self {
        match e {
            transport::FrameError::Closed => ControlWireError::Closed,
            transport::FrameError::Io(e) => ControlWireError::Io(e),
            transport::FrameError::TooLarge(n) => ControlWireError::TooLarge(n),
        }
    }
}

/// A [`postcard_rpc::server::WireTx`] impl over the accepted connection's
/// write half. `Clone`-able (an `Arc<Mutex<..>>`) because `Sender<Tx>` —
/// which wraps this — is itself cloned into the heartbeat publisher task
/// alongside the main dispatch loop holding the original.
#[derive(Clone)]
pub struct ControlTx {
    write_half: Arc<Mutex<OwnedWriteHalf>>,
}

// Manual, not derived: `tokio_vsock::OwnedWriteHalf` itself has no `Debug`
// impl, and `#[derive(Debug)]` would otherwise require one. Only needed so
// `ServerError<ControlTx, ControlRx>` (logged via `tracing::debug!(?err, ..)`
// in `control.rs`) can itself derive `Debug` -- the actual output is never
// inspected for anything but a log line.
impl std::fmt::Debug for ControlTx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlTx").finish_non_exhaustive()
    }
}

impl ControlTx {
    pub fn new(write_half: OwnedWriteHalf) -> Self {
        Self {
            write_half: Arc::new(Mutex::new(write_half)),
        }
    }

    async fn send_bytes(&self, buf: &[u8]) -> Result<(), ControlWireError> {
        let mut guard = self.write_half.lock().await;
        transport::write_frame(&mut *guard, buf)
            .await
            .map_err(ControlWireError::from)
    }
}

impl postcard_rpc::server::WireTx for ControlTx {
    type Error = ControlWireError;

    async fn send<T: serde::Serialize + ?Sized>(
        &self,
        hdr: VarHeader,
        msg: &T,
    ) -> Result<(), Self::Error> {
        let mut buf = hdr.write_to_vec();
        let body = postcard::to_stdvec(msg).map_err(|_| ControlWireError::TooLarge(0))?;
        buf.extend_from_slice(&body);
        self.send_bytes(&buf).await
    }

    async fn send_raw(&self, buf: &[u8]) -> Result<(), Self::Error> {
        self.send_bytes(buf).await
    }

    async fn send_log_str(
        &self,
        _kkind: postcard_rpc::header::VarKeyKind,
        _s: &str,
    ) -> Result<(), Self::Error> {
        // No production client subscribes to the standard logging topic --
        // guest-agent already has its own dedicated `LOG_PORT` stream (see
        // `main.rs`'s module doc). Dropped rather than wired up, matching
        // that existing "logging is a separate channel" decision.
        Ok(())
    }

    async fn send_log_fmt<'a>(
        &self,
        _kkind: postcard_rpc::header::VarKeyKind,
        _a: std::fmt::Arguments<'a>,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
}

pub struct ControlRx {
    read_half: OwnedReadHalf,
}

impl std::fmt::Debug for ControlRx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlRx").finish_non_exhaustive()
    }
}

impl ControlRx {
    pub fn new(read_half: OwnedReadHalf) -> Self {
        Self { read_half }
    }
}

impl WireRx for ControlRx {
    type Error = ControlWireError;

    async fn receive<'a>(&mut self, buf: &'a mut [u8]) -> Result<&'a mut [u8], Self::Error> {
        let frame = transport::read_frame(&mut self.read_half, MAX_FRAME_LEN).await?;
        let out = buf
            .get_mut(..frame.len())
            .ok_or(ControlWireError::TooLarge(frame.len() as u32))?;
        out.copy_from_slice(&frame);
        Ok(out)
    }
}

#[derive(Clone)]
pub struct ControlSpawn;

impl WireSpawn for ControlSpawn {
    type Error = std::convert::Infallible;
    type Info = ();

    fn info(&self) -> &Self::Info {
        &()
    }
}

/// Matches `postcard_rpc::server::impls::test_channels::tokio_spawn`'s
/// signature, which `define_dispatch!`'s `spawn_fn:` expects. Never actually
/// called -- see `control.rs`'s import comment -- but the macro requires the
/// identifier to resolve.
#[allow(dead_code)]
pub fn tokio_spawn<Sp, F>(_sp: &Sp, fut: F) -> Result<(), Sp::Error>
where
    Sp: WireSpawn<Error = std::convert::Infallible, Info = ()>,
    F: std::future::Future<Output = ()> + 'static + Send,
{
    tokio::task::spawn(fut);
    Ok(())
}
