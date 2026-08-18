//! Phase 15 Step 3 smoke test: drives `kubernix_daemon_protocol`'s real
//! handshake and one full command round trip against a live `nix-daemon
//! --stdio`, reached through a real guest VM's vsock socket — not the
//! in-memory fakes `daemon-protocol`'s own unit tests use.
//!
//! Deliberately narrow: this proves the wire-level assumptions this client
//! makes about a *real* Lix daemon (magic numbers, `SetOptions`' exact field
//! count, `STDERR_*` framing) actually hold, without needing a working build
//! sandbox inside the guest (the current initrd has no shell/coreutils for a
//! builder to run — see `nix/guest-vm.nix`) or a store path this binary can
//! get byte-exact against real Nix's own hashing without iterating against a
//! live daemon, which this environment cannot do in CI. `query_path_info` on
//! a path that provably does not exist is enough to prove the connection is
//! real: a fake reader could stub out constants, but not answer a question
//! about a path it was never told.
//!
//! Invoked by `nix/vm-build-test.nix` as
//! `vm-smoke <vsock-socket-path> <guest-port>`, exit `0` on success.

use std::io::{Read, Write};

use kubernix_daemon_protocol::DaemonConnection;

fn main() -> eyre::Result<()> {
    let mut args = std::env::args().skip(1);
    let vsock_socket = args
        .next()
        .ok_or_else(|| eyre::eyre!("usage: vm-smoke <vsock-socket-path> <guest-port>"))?;
    let port: u32 = args
        .next()
        .ok_or_else(|| eyre::eyre!("usage: vm-smoke <vsock-socket-path> <guest-port>"))?
        .parse()?;

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(vsock_socket, port))
}

async fn run(vsock_socket: String, port: u32) -> eyre::Result<()> {
    // The same inetd-style handshake `worker::vm::VmHandle::connect` uses in
    // production — reimplemented here rather than depending on `worker`
    // itself, since this binary's entire point is exercising
    // `daemon-protocol` in isolation against a real daemon.
    let mut stream = std::os::unix::net::UnixStream::connect(&vsock_socket)?;
    stream.write_all(format!("CONNECT {port}\n").as_bytes())?;
    let mut buf = [0u8; 32];
    let n = stream.read(&mut buf)?;
    if !buf[..n].starts_with(b"OK") {
        eyre::bail!("vsock CONNECT to guest port {port} refused: {:?}", &buf[..n]);
    }

    let stream = tokio::net::UnixStream::from_std(stream)?;
    let mut conn = DaemonConnection::open(stream).await?;
    eprintln!("vm-smoke: handshake + SetOptions succeeded against a real nix-daemon");

    // A path that cannot possibly be valid: no real Nix store path is 0
    // characters where a hash belongs. A canned/fake reply could return
    // `None` unconditionally; a real daemon has to actually parse this
    // string, fail to find a valid path, and answer honestly.
    let bogus = "/nix/store/00000000000000000000000000000000-kubernix-vm-smoke-does-not-exist";
    match conn.query_path_info(bogus).await? {
        None => eprintln!("vm-smoke: QueryPathInfo round-tripped and correctly reported no path"),
        Some(info) => eyre::bail!("expected no path info for a bogus path, got {info:?}"),
    }

    println!("ok");
    Ok(())
}
