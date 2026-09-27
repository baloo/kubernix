//! `postcard-rpc` dispatch for the control channel — replaces the old
//! one-shot-per-connection, verb-prefixed line protocol (`ControlReply`/
//! `handle_control`/`dispatch_control`) with a persistent, typed, binary
//! dispatch loop plus a heartbeat publisher, both driven per accepted
//! connection by [`run_control_connection`].
//!
//! Endpoints (see `kubernix_guest_protocol::endpoints` for the exact
//! request/response shapes):
//!
//! - `guest/key` -- unlock and mount `store.img`. See
//!   `worker/src/vm.rs::push_key` for the client side.
//! - `guest/substituters` / `guest/ca-cert` -- update this tenant's trusted
//!   substituters / extra CA bundle, read by `spawn_nix_daemon` on the next
//!   `NIX_DAEMON_PORT` connection.
//! - `guest/caps` -- boot-time nested-virt self-test (PLAN.md Phase 17).
//! - `guest/status` / `guest/reset` -- OOM/ENOSPC detection state (PLAN.md
//!   Phase 18).
//! - `guest/debug/trigger-oom` / `guest/debug/trigger-enospc` --
//!   diagnostic-only, for `nix/vm-oom-test.nix`/`vm-enospc-test.nix`. No
//!   production client ever calls either.
//!
//! Topics: `guest/heartbeat` -- a liveness pulse this process pushes on its
//! own cadence, replacing the old worker-polled `PING` verb. See
//! [`heartbeat_publisher`].

use std::sync::Arc;
use std::time::Duration;

use kubernix_guest_protocol::{
    AckResult, CapsEndpoint, CapsResponse, CapsResult, ENDPOINT_LIST, GuestFailureStatus,
    Heartbeat, HeartbeatTopic, PushCaCertEndpoint, PushCaCertRequest, PushKeyEndpoint,
    PushKeyRequest, PushSubstitutersEndpoint, PushSubstitutersRequest, ResetEndpoint,
    StatusEndpoint, StatusResponse, StatusResult, TOPICS_IN_LIST, TOPICS_OUT_LIST,
    TriggerEnospcEndpoint, TriggerOomEndpoint,
};
use postcard_rpc::define_dispatch;
use postcard_rpc::header::{VarHeader, VarSeq};
use postcard_rpc::server::{Dispatch as _, Server};
use tokio::sync::Mutex;
use tokio_vsock::VsockStream;

use crate::control_transport::{ControlRx, ControlSpawn, ControlTx};
// `define_dispatch!` requires a `spawn_fn` identifier in scope even though
// none of our endpoints/topics use the "spawn" handler flavor (all are
// "async") -- so this is never actually called, only referenced by the
// macro's own generated-but-untaken "spawn" branches.
#[allow(unused_imports)]
use crate::control_transport::tokio_spawn;
use crate::ebpf::{DetectionState, FailureStatus};
use crate::{
    ExtraCaCert, Substituters, count_nested_virt_flags, trigger_enospc, trigger_oom,
    unlock_and_mount,
};

/// How often this process pushes a [`Heartbeat`] on the control connection.
/// Matches the old worker-side `PING` interval default so the guest's
/// liveness cadence doesn't silently change just because who initiates it
/// did.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

/// State threaded through every handler — the same three pieces of shared
/// state `dispatch_control` used to take as parameters.
pub struct Context {
    pub detection: Option<Arc<Mutex<DetectionState>>>,
    pub substituters: Substituters,
    pub extra_ca: ExtraCaCert,
}

impl From<FailureStatus> for GuestFailureStatus {
    fn from(status: FailureStatus) -> Self {
        match status {
            FailureStatus::None => GuestFailureStatus::None,
            FailureStatus::OutOfMemory { builder_victim } => {
                GuestFailureStatus::OutOfMemory { builder_victim }
            }
            FailureStatus::DiskFull => GuestFailureStatus::DiskFull,
        }
    }
}

/// Joins an `eyre::Report`'s full chain into one string — the same
/// information the old text protocol put into an `ERR <chain>\n` reply, now
/// carried as the `Err` side of an [`AckResult`]/[`CapsResult`]/
/// [`StatusResult`] instead.
fn chain(err: &eyre::Report) -> String {
    err.chain()
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join(": ")
}

define_dispatch! {
    app: ControlDispatcher;
    spawn_fn: tokio_spawn;
    tx_impl: ControlTx;
    spawn_impl: ControlSpawn;
    context: Context;

    endpoints: {
        list: ENDPOINT_LIST;

        | EndpointTy               | kind  | handler                   |
        | ----------               | ----  | -------                   |
        | PushKeyEndpoint          | async | handle_push_key            |
        | PushSubstitutersEndpoint | async | handle_push_substituters   |
        | PushCaCertEndpoint       | async | handle_push_ca_cert        |
        | CapsEndpoint             | async | handle_caps                |
        | StatusEndpoint           | async | handle_status              |
        | ResetEndpoint            | async | handle_reset               |
        | TriggerOomEndpoint       | async | handle_trigger_oom         |
        | TriggerEnospcEndpoint    | async | handle_trigger_enospc      |
    };
    topics_in: {
        list: TOPICS_IN_LIST;

        | TopicTy | kind | handler |
        | ------- | ---- | ------- |
    };
    topics_out: {
        list: TOPICS_OUT_LIST;
    };
}

async fn handle_push_key(
    _context: &mut Context,
    _header: VarHeader,
    req: PushKeyRequest,
) -> AckResult {
    unlock_and_mount(&req.key, req.fresh)
        .await
        .map_err(|e| chain(&e))
}

async fn handle_push_substituters(
    context: &mut Context,
    _header: VarHeader,
    req: PushSubstitutersRequest,
) -> AckResult {
    let parsed = req
        .entries
        .into_iter()
        .map(|entry| (entry.url, entry.public_key))
        .collect();
    *context.substituters.lock().await = parsed;
    Ok(())
}

async fn handle_push_ca_cert(
    context: &mut Context,
    _header: VarHeader,
    req: PushCaCertRequest,
) -> AckResult {
    *context.extra_ca.lock().await = req.pem;
    Ok(())
}

async fn handle_caps(_context: &mut Context, _header: VarHeader, _req: ()) -> CapsResult {
    count_nested_virt_flags()
        .map(|nested_virt_flag_count| CapsResponse {
            nested_virt_flag_count,
        })
        .map_err(|e| chain(&e))
}

async fn handle_status(context: &mut Context, _header: VarHeader, _req: ()) -> StatusResult {
    let detection = context
        .detection
        .clone()
        .ok_or_else(|| "eBPF detection not available".to_string())?;
    let status = detection.lock().await.status().await;
    Ok(StatusResponse(status.into()))
}

async fn handle_reset(context: &mut Context, _header: VarHeader, _req: ()) -> AckResult {
    let detection = context
        .detection
        .clone()
        .ok_or_else(|| "eBPF detection not available".to_string())?;
    detection.lock().await.reset().await.map_err(|e| chain(&e))
}

/// Diagnostic-only, for `nix/vm-oom-test.nix` -- see the module doc.
async fn handle_trigger_oom(_context: &mut Context, _header: VarHeader, _req: ()) -> AckResult {
    trigger_oom().await.map_err(|e| chain(&e))
}

/// Diagnostic-only, for `nix/vm-enospc-test.nix` -- see the module doc.
async fn handle_trigger_enospc(_context: &mut Context, _header: VarHeader, _req: ()) -> AckResult {
    trigger_enospc().await;
    Ok(())
}

/// Runs one accepted control connection to completion: a persistent
/// postcard-rpc dispatch loop, plus a heartbeat publisher pushing on its own
/// timer alongside it. Replaces `handle_control`'s one-shot "read a line,
/// reply once, close" -- both tasks run for as long as the connection stays
/// open, torn down together when it closes.
pub async fn run_control_connection(stream: VsockStream, context: Context) {
    let (read_half, write_half) = stream.into_split();
    let tx = ControlTx::new(write_half);
    let rx = ControlRx::new(read_half);

    let dispatch = ControlDispatcher::new(context, ControlSpawn);
    let kkind = dispatch.min_key_len();
    let mut server = Server::new(tx, rx, vec![0u8; 4096].into_boxed_slice(), dispatch, kkind);
    let sender = server.sender();

    let heartbeat = tokio::spawn(heartbeat_publisher(sender));

    let err = server.run().await;
    tracing::debug!(?err, "control connection dispatch loop ended");
    heartbeat.abort();
}

/// Pushes a [`Heartbeat`] on `HEARTBEAT_INTERVAL` for as long as the
/// connection it was spawned alongside stays open -- see
/// [`run_control_connection`]. Publishing failure (the connection is
/// already gone) just ends the task; there is nothing else to do with that
/// error, the dispatch loop on the same connection will notice independently.
async fn heartbeat_publisher(sender: postcard_rpc::server::Sender<ControlTx>) {
    let mut ticker = tokio::time::interval(HEARTBEAT_INTERVAL);
    let mut seq: u64 = 0;
    loop {
        ticker.tick().await;
        let wire_seq = VarSeq::Seq4(seq as u32);
        if sender
            .publish::<HeartbeatTopic>(wire_seq, &Heartbeat { seq })
            .await
            .is_err()
        {
            return;
        }
        seq = seq.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use postcard_rpc::header::{VarKey, VarSeq};

    fn no_substituters() -> Substituters {
        Arc::new(Mutex::new(Vec::new()))
    }

    fn no_extra_ca() -> ExtraCaCert {
        Arc::new(Mutex::new(Vec::new()))
    }

    fn no_detection_context() -> Context {
        Context {
            detection: None,
            substituters: no_substituters(),
            extra_ca: no_extra_ca(),
        }
    }

    /// A placeholder header — every handler here ignores it, the wire
    /// dispatch macro only ever passes it through for handlers that care
    /// (none of ours do).
    fn test_header() -> VarHeader {
        VarHeader {
            key: VarKey::Key8(unsafe { postcard_rpc::Key::from_bytes([0u8; 8]) }),
            seq_no: VarSeq::Seq4(0),
        }
    }

    #[tokio::test]
    async fn handle_caps_returns_real_data() {
        // Real /proc/cpuinfo on the machine running the test -- whatever it
        // reports, the handler should surface it as `Ok`, not `Err`.
        let mut context = no_detection_context();
        match handle_caps(&mut context, test_header(), ()).await {
            Ok(CapsResponse { .. }) => {}
            Err(msg) => panic!("expected Ok, got Err({msg})"),
        }
    }

    #[tokio::test]
    async fn handle_status_without_detection_errors() {
        let mut context = no_detection_context();
        let err = handle_status(&mut context, test_header(), ())
            .await
            .unwrap_err();
        assert!(err.contains("eBPF detection not available"));
    }

    #[tokio::test]
    async fn handle_reset_without_detection_errors() {
        let mut context = no_detection_context();
        let err = handle_reset(&mut context, test_header(), ())
            .await
            .unwrap_err();
        assert!(err.contains("eBPF detection not available"));
    }

    #[tokio::test]
    async fn handle_push_substituters_updates_the_shared_state() {
        let mut context = no_detection_context();
        let substituters = context.substituters.clone();
        handle_push_substituters(
            &mut context,
            test_header(),
            PushSubstitutersRequest {
                entries: vec![kubernix_guest_protocol::SubstituterEntry {
                    url: "https://cache.nixos.org".to_string(),
                    public_key: "cache.nixos.org-1:AAAA".to_string(),
                }],
            },
        )
        .await
        .unwrap();
        assert_eq!(
            *substituters.lock().await,
            vec![(
                "https://cache.nixos.org".to_string(),
                "cache.nixos.org-1:AAAA".to_string()
            )]
        );
    }

    #[tokio::test]
    async fn handle_push_substituters_with_no_entries_clears_it() {
        let mut context = no_detection_context();
        let substituters = context.substituters.clone();
        handle_push_substituters(
            &mut context,
            test_header(),
            PushSubstitutersRequest {
                entries: Vec::new(),
            },
        )
        .await
        .unwrap();
        assert!(substituters.lock().await.is_empty());
    }

    #[tokio::test]
    async fn handle_push_ca_cert_updates_the_shared_state() {
        let mut context = no_detection_context();
        let extra_ca = context.extra_ca.clone();
        handle_push_ca_cert(
            &mut context,
            test_header(),
            PushCaCertRequest {
                pem: vec![0xde, 0xad, 0xbe, 0xef],
            },
        )
        .await
        .unwrap();
        assert_eq!(*extra_ca.lock().await, vec![0xde, 0xad, 0xbe, 0xef]);
    }

    #[tokio::test]
    async fn handle_push_ca_cert_empty_clears_it() {
        let mut context = no_detection_context();
        *context.extra_ca.lock().await = vec![0xde, 0xad, 0xbe, 0xef];
        let extra_ca = context.extra_ca.clone();
        handle_push_ca_cert(
            &mut context,
            test_header(),
            PushCaCertRequest { pem: Vec::new() },
        )
        .await
        .unwrap();
        assert!(extra_ca.lock().await.is_empty());
    }
}
