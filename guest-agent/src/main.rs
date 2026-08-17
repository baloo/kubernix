//! `guest-agent` — PID 1 inside the Phase 15 guest VM's initrd.
//!
//! Listens on a fixed `AF_VSOCK` port. On each accepted connection, it spawns
//! `nix-daemon --stdio` and splices the connection's bytes straight onto the
//! child's stdin/stdout, in both directions, until either side closes.
//!
//! Deliberately dumb: unlike `worker/src/serve.rs`'s `ServeConnection`, which
//! has to parse the `nix-store --serve` wire protocol because the frontend it
//! talks to speaks that protocol, `guest-agent` understands none of the bytes
//! it relays. The real protocol speaker is on the other end of the vsock
//! connection (the worker, in Phase 15 Step 3) — this process only needs to
//! get `nix-daemon` a stdio pipe.
//!
//! No systemd, no udev: there is nothing else running in this VM for either
//! to manage. Running as PID 1 also means this process is the guest's init,
//! so on exit the kernel panics — cloud-hypervisor's `--console`/reboot
//! handling determines what happens next, not anything decided here.
//!
//! Logging is plain `eprintln!`, not `tracing`: verified empirically against
//! a real cloud-hypervisor boot (`nix/guest-vm-test.nix`) that
//! `tracing_subscriber`'s writer produces no output at all on this guest's
//! serial console, while `eprintln!` does -- and a minimal PID-1 binary has
//! no need for structured logging's complexity anyway.

use std::net::Shutdown;
use std::process::Stdio;

use eyre::{Context, Result};
use tokio::process::{Child, Command};
use tokio_vsock::{VMADDR_CID_ANY, VsockAddr, VsockListener, VsockStream};

/// Fixed by convention between `guest-agent` and whatever dials it (the
/// worker, in later Phase 15 steps, or this crate's own boot test in the
/// meantime) — there is exactly one service behind this VM's vsock, so there
/// is nothing to negotiate a port for.
const NIX_DAEMON_PORT: u32 = 620;

/// Path to `nix-daemon` inside the initrd. Not configurable: `nix/guest-vm.nix`
/// symlinks it here (there is no NixOS profile / `/run/current-system` in this
/// minimal, systemd-free guest — see that file's `contents` list).
const NIX_DAEMON_BIN: &str = "/bin/nix-daemon";

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install().ok();

    let addr = VsockAddr::new(VMADDR_CID_ANY, NIX_DAEMON_PORT);
    let listener = VsockListener::bind(addr).wrap_err("binding vsock listener")?;
    eprintln!("guest-agent listening on vsock port {NIX_DAEMON_PORT}");

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(err) => {
                eprintln!("guest-agent: accept failed: {err}");
                continue;
            }
        };
        eprintln!("guest-agent: accepted vsock connection from {peer:?}");

        // One `nix-daemon` per connection, same as the real daemon's own
        // Unix-socket accept loop. Errors here are per-connection, not fatal
        // to the agent: a build worth retrying dials again.
        tokio::spawn(async move {
            if let Err(err) = serve(stream).await {
                eprintln!("guest-agent: connection handling failed: {err}");
            }
        });
    }
}

/// Spawn `nix-daemon --stdio` and relay `stream` onto its stdin/stdout until
/// either side closes.
async fn serve(mut stream: VsockStream) -> Result<()> {
    let mut child = spawn_nix_daemon()?;
    let mut child_stdin = child.stdin.take().ok_or_else(|| eyre::eyre!("no stdin"))?;
    let mut child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| eyre::eyre!("no stdout"))?;

    let (mut stream_read, mut stream_write) = stream.split();

    // Two directions, driven concurrently: the vsock peer's writes feed
    // nix-daemon's stdin, and nix-daemon's stdout feeds back to the peer.
    // Neither `tokio::io::copy` call returns until its source hits EOF, which
    // is exactly "the peer closed" on one side and "nix-daemon exited" on the
    // other — either is a legitimate reason to tear the whole connection down.
    let relay_in = async {
        let result = tokio::io::copy(&mut stream_read, &mut child_stdin).await;
        // nix-daemon reads EOF on its stdin as "no more requests"; without
        // explicitly dropping our end here it would just see the pipe stay
        // open and hang waiting for more.
        drop(child_stdin);
        result
    };
    let relay_out = tokio::io::copy(&mut child_stdout, &mut stream_write);

    tokio::select! {
        result = relay_in => { result.wrap_err("relaying vsock -> nix-daemon")?; }
        result = relay_out => { result.wrap_err("relaying nix-daemon -> vsock")?; }
    }

    reap(&mut child).await;
    stream.shutdown(Shutdown::Both).ok();
    Ok(())
}

fn spawn_nix_daemon() -> Result<Child> {
    Command::new(NIX_DAEMON_BIN)
        .arg("--stdio")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .wrap_err_with(|| format!("spawning {NIX_DAEMON_BIN} --stdio"))
}

/// Wait for the child, logging anything unexpected. Never fatal to the
/// agent's own accept loop — a build worth retrying dials a fresh
/// connection, which spawns a fresh `nix-daemon`.
async fn reap(child: &mut Child) {
    match child.wait().await {
        Ok(status) if status.success() => {}
        Ok(status) => eprintln!("guest-agent: nix-daemon exited with {status}"),
        Err(err) => eprintln!("guest-agent: waiting on nix-daemon: {err}"),
    }
}
