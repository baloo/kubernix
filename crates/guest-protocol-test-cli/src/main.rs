//! A tiny CLI that dials `guest-agent`'s control channel and issues one
//! typed call, printing a reply in the same `OK ...`/`ERR ...` textual
//! convention the old line-based protocol used.
//!
//! Exists only for `nix/vm-test-lib.nix`'s shell helpers: raw shell +
//! `socat` could hand-construct the old protocol's ASCII lines, but can't
//! hand-construct a binary postcard-rpc frame. This binary is the thing
//! those helpers now shell out to instead, keeping every `nix/vm-*-test.nix`
//! integration test's own assertions (`[[ "$reply" == "OK NONE" ]]`, etc.)
//! unchanged.
//!
//! Usage: `kubernix-guest-protocol-test-cli <vsock-socket> <port> <command>
//! [args...]`, one of:
//!
//! - `push-key <hex-key> <FRESH|REUSE>`
//! - `caps`
//! - `status`
//! - `reset`
//! - `trigger-oom`
//! - `trigger-enospc`
//!
//! Always exits 0 and prints exactly one line to stdout, `OK ...` or
//! `ERR ...` -- connection failures included -- so callers under `set -euo
//! pipefail` can capture the reply with a plain `reply=$(... )` and branch on
//! its prefix, exactly as they did against the old text protocol.

use std::path::Path;
use std::time::Duration;

use kubernix_guest_protocol::{
    CapsEndpoint, GuestFailureStatus, PushKeyEndpoint, PushKeyRequest, ResetEndpoint,
    StatusEndpoint, TriggerEnospcEndpoint, TriggerOomEndpoint,
};

const CALL_TIMEOUT: Duration = Duration::from_secs(30);

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, vsock_socket, port, command, rest @ ..] = args.as_slice() else {
        eprintln!(
            "usage: kubernix-guest-protocol-test-cli <vsock-socket> <port> <command> [args...]"
        );
        std::process::exit(2);
    };
    let vsock_socket = Path::new(vsock_socket);
    let port: u32 = match port.parse() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("invalid port {port:?}: {e}");
            std::process::exit(2);
        }
    };

    let reply = run(vsock_socket, port, command, rest).await;
    println!("{reply}");
}

async fn run(vsock_socket: &Path, port: u32, command: &str, args: &[String]) -> String {
    let client = match tokio::time::timeout(
        CALL_TIMEOUT,
        kubernix_guest_protocol::client::connect(vsock_socket, port),
    )
    .await
    {
        Ok(Ok(client)) => client,
        Ok(Err(e)) => return format!("ERR connecting: {e}"),
        Err(_) => return "ERR connecting: timed out".to_string(),
    };

    let call = async {
        match command {
            "push-key" => {
                let [hex_key, mode] = args else {
                    return "ERR push-key needs <hex-key> <FRESH|REUSE>".to_string();
                };
                let key = match decode_hex_32(hex_key) {
                    Ok(key) => key,
                    Err(e) => return format!("ERR decoding key: {e}"),
                };
                let fresh = match mode.as_str() {
                    "FRESH" => true,
                    "REUSE" => false,
                    other => {
                        return format!("ERR unrecognised mode {other:?}, want FRESH or REUSE");
                    }
                };
                let req = PushKeyRequest { key, fresh };
                match client.send_resp::<PushKeyEndpoint>(&req).await {
                    Ok(Ok(())) => "OK".to_string(),
                    Ok(Err(msg)) => format!("ERR {msg}"),
                    Err(e) => format!("ERR {e}"),
                }
            }
            "caps" => match client.send_resp::<CapsEndpoint>(&()).await {
                Ok(Ok(resp)) => format!("OK {}", resp.nested_virt_flag_count),
                Ok(Err(msg)) => format!("ERR {msg}"),
                Err(e) => format!("ERR {e}"),
            },
            "status" => match client.send_resp::<StatusEndpoint>(&()).await {
                Ok(Ok(resp)) => format_status(resp.0),
                Ok(Err(msg)) => format!("ERR {msg}"),
                Err(e) => format!("ERR {e}"),
            },
            "reset" => match client.send_resp::<ResetEndpoint>(&()).await {
                Ok(Ok(())) => "OK".to_string(),
                Ok(Err(msg)) => format!("ERR {msg}"),
                Err(e) => format!("ERR {e}"),
            },
            "trigger-oom" => match client.send_resp::<TriggerOomEndpoint>(&()).await {
                Ok(Ok(())) => "OK".to_string(),
                Ok(Err(msg)) => format!("ERR {msg}"),
                Err(e) => format!("ERR {e}"),
            },
            "trigger-enospc" => match client.send_resp::<TriggerEnospcEndpoint>(&()).await {
                Ok(Ok(())) => "OK".to_string(),
                Ok(Err(msg)) => format!("ERR {msg}"),
                Err(e) => format!("ERR {e}"),
            },
            other => format!("ERR unrecognised command {other:?}"),
        }
    };

    match tokio::time::timeout(CALL_TIMEOUT, call).await {
        Ok(reply) => reply,
        Err(_) => "ERR timed out waiting for a reply".to_string(),
    }
}

/// The same `OK NONE` / `OK OOM BUILDER` / `OK OOM OTHER` / `OK ENOSPC` wire
/// text the old protocol used, so `nix/vm-*-test.nix`'s exact-string
/// assertions don't need to change.
fn format_status(status: GuestFailureStatus) -> String {
    match status {
        GuestFailureStatus::None => "OK NONE".to_string(),
        GuestFailureStatus::OutOfMemory {
            builder_victim: true,
        } => "OK OOM BUILDER".to_string(),
        GuestFailureStatus::OutOfMemory {
            builder_victim: false,
        } => "OK OOM OTHER".to_string(),
        GuestFailureStatus::DiskFull => "OK ENOSPC".to_string(),
    }
}

fn decode_hex_32(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 {
        return Err(format!("expected 64 hex characters, got {}", s.len()));
    }
    let mut key = [0u8; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("invalid hex byte at {}: {e}", i * 2))?;
    }
    Ok(key)
}
