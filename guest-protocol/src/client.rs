//! Host-client transport for the control channel over a tunneled vsock
//! connection. Shared by the worker (`worker/src/vm.rs`) and the
//! `kubernix-guest-protocol-test-cli` test tool (`nix/vm-test-lib.nix`'s
//! replacement for its old `socat`-based helpers, since raw shell can no
//! longer hand-construct a binary postcard-rpc frame the way it could a text
//! line) so this framing glue can't drift between the two.
//!
//! `postcard-rpc` ships USB/serial transports only; a `UnixStream` needs its
//! own `WireTx`/`WireRx` impl. The host-client side of these traits is the
//! simple one: each impl is handed (and exclusively owns) one half of the
//! stream, moved by value into `HostClient`'s own background tasks, so
//! unlike the server side (`guest-agent/src/control_transport.rs`) there is
//! no need for internal locking here.

use std::fmt;
use std::path::Path;

use postcard_rpc::header::VarSeqKind;
use postcard_rpc::host_client::{HostClient, WireRx, WireSpawn, WireTx};
use postcard_rpc::standard_icd::WireError;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};

use crate::transport::{self, MAX_FRAME_LEN};

#[derive(Debug)]
pub struct ClientWireError(transport::FrameError);

impl fmt::Display for ClientWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ClientWireError {}

pub struct ClientTx {
    write_half: OwnedWriteHalf,
}

impl WireTx for ClientTx {
    type Error = ClientWireError;

    async fn send(&mut self, data: Vec<u8>) -> Result<(), Self::Error> {
        transport::write_frame(&mut self.write_half, &data)
            .await
            .map_err(ClientWireError)
    }
}

pub struct ClientRx {
    read_half: OwnedReadHalf,
}

impl WireRx for ClientRx {
    type Error = ClientWireError;

    async fn receive(&mut self) -> Result<Vec<u8>, Self::Error> {
        transport::read_frame(&mut self.read_half, MAX_FRAME_LEN)
            .await
            .map_err(ClientWireError)
    }
}

/// Thin `tokio::spawn` wrapper — `HostClient`'s two background tasks
/// (`out_worker`/`in_worker`) are spawned through this.
#[derive(Clone)]
pub struct ClientSpawn;

impl WireSpawn for ClientSpawn {
    fn spawn(&mut self, fut: impl std::future::Future<Output = ()> + Send + 'static) {
        tokio::spawn(fut);
    }
}

/// Dial `vsock_socket` and complete cloud-hypervisor's own `CONNECT
/// <port>\n` / `OK` vsock-proxy handshake — transport-layer, unrelated to
/// postcard-rpc's own framing, and unchanged from before this crate existed
/// (see `worker/src/vm.rs`'s `wait_for_vsock_ready`/`handshake_once`, which
/// speak the exact same handshake for the readiness poll during boot).
/// Returns the raw stream, ready to be wrapped in postcard-rpc framing by
/// [`connect`].
pub async fn dial(vsock_socket: &Path, port: u32) -> std::io::Result<UnixStream> {
    let mut stream = UnixStream::connect(vsock_socket).await?;
    stream
        .write_all(format!("CONNECT {port}\n").as_bytes())
        .await?;
    let mut buf = [0u8; 32];
    let n = stream.read(&mut buf).await?;
    if !buf[..n].starts_with(b"OK") {
        return Err(std::io::Error::other(format!(
            "vsock CONNECT to guest port {port} refused: {:?}",
            String::from_utf8_lossy(&buf[..n])
        )));
    }
    Ok(stream)
}

/// [`dial`], then wrap the resulting stream in a postcard-rpc [`HostClient`]
/// ready to make typed endpoint calls or subscribe to topics.
pub async fn connect(vsock_socket: &Path, port: u32) -> std::io::Result<HostClient<WireError>> {
    let stream = dial(vsock_socket, port).await?;
    let (read_half, write_half) = stream.into_split();
    Ok(HostClient::new_with_wire(
        ClientTx { write_half },
        ClientRx { read_half },
        ClientSpawn,
        VarSeqKind::Seq2,
        postcard_rpc::standard_icd::ERROR_PATH,
        8,
    ))
}
