//! Request/response endpoint definitions for the worker↔guest-agent control
//! protocol. Each endpoint here replaces one verb of the old line-based
//! protocol (`guest-agent/src/main.rs`'s former `dispatch_control`) with a
//! typed, binary postcard-rpc endpoint of the same name.

use postcard_rpc::endpoints;
use postcard_schema::Schema;
use serde::{Deserialize, Serialize};

use crate::types::{GuestFailureStatus, SubstituterEntry};

/// `KEY <hex> FRESH|REUSE` — push the tenant's plain-`dm-crypt` key and
/// unlock/mount `store.img`. `key` is the raw 32 bytes directly (no more hex
/// encoding — postcard is already binary).
#[derive(Debug, Clone, Serialize, Deserialize, Schema)]
pub struct PushKeyRequest {
    pub key: [u8; 32],
    pub fresh: bool,
}

/// `SUBST ...` — replace the tenant's currently trusted substituters.
#[derive(Debug, Clone, Serialize, Deserialize, Schema)]
pub struct PushSubstitutersRequest {
    pub entries: Vec<SubstituterEntry>,
}

/// `CACERT <hex>` — replace the extra trusted CA cert bundle (empty clears
/// it). Raw PEM bytes directly, no more hex encoding.
#[derive(Debug, Clone, Serialize, Deserialize, Schema)]
pub struct PushCaCertRequest {
    pub pem: Vec<u8>,
}

/// `CAPS?`'s reply — the nested-virt flag count the guest itself observes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Schema)]
pub struct CapsResponse {
    pub nested_virt_flag_count: u32,
}

/// `STATUS?`'s reply.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Schema)]
pub struct StatusResponse(pub GuestFailureStatus);

/// Every mutating endpoint's response shape — `Ok(())` on success, `Err(msg)`
/// with guest-agent's `eyre` chain joined into one string on failure (see
/// `guest-agent/src/control.rs`'s handlers). A type alias, not written out at
/// each use, because the `endpoints!` table below needs a single identifier
/// per column.
pub type AckResult = Result<(), String>;

/// `CAPS?`'s full reply shape, error included (reading `/proc/cpuinfo` can
/// fail, same as the old text protocol's `CAPS?` could reply `ERR ...`).
pub type CapsResult = Result<CapsResponse, String>;

/// `STATUS?`'s full reply shape, error included (no eBPF detection state
/// available is reported the same way the old text protocol did).
pub type StatusResult = Result<StatusResponse, String>;

endpoints! {
    list = ENDPOINT_LIST;
    | EndpointTy               | RequestTy                 | ResponseTy    | Path                          |
    | ----------               | ---------                 | ----------    | ----                          |
    | PushKeyEndpoint           | PushKeyRequest            | AckResult     | "guest/key"                   |
    | PushSubstitutersEndpoint  | PushSubstitutersRequest   | AckResult     | "guest/substituters"          |
    | PushCaCertEndpoint        | PushCaCertRequest         | AckResult     | "guest/ca-cert"               |
    | CapsEndpoint              | ()                        | CapsResult    | "guest/caps"                  |
    | StatusEndpoint            | ()                        | StatusResult  | "guest/status"                |
    | ResetEndpoint             | ()                        | AckResult     | "guest/reset"                 |
    | TriggerOomEndpoint        | ()                        | AckResult     | "guest/debug/trigger-oom"     |
    | TriggerEnospcEndpoint     | ()                        | AckResult     | "guest/debug/trigger-enospc"  |
}
