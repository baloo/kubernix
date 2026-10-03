//! Regression test driver for the guest's `/nix/var/nix/db` persistence fix
//! (`guest-agent/src/main.rs::mount_store`): registers a store path over one
//! VM boot, then -- invoked again against a *second* boot of the same
//! `store.img` -- confirms it's still reported valid with no re-registration.
//!
//! Same handshake/connection pattern as `vm-smoke.rs`, reimplemented rather
//! than shared for the same reason that one gives: this binary's entire
//! point is exercising `daemon-protocol` against a real daemon, standalone
//! from the `worker` crate's own NATS/S3/Postgres machinery.
//!
//! Usage:
//!   vm-db-persistence-smoke <vsock-socket> <port> register <store-path> <nar-file> <nar-hash> <nar-size>
//!   vm-db-persistence-smoke <vsock-socket> <port> check <store-path>
//!
//! `register` also confirms the path reports valid within the *same* boot
//! (a same-boot sanity check, not the thing this binary exists to catch);
//! `check` is the one a second boot of the same `store.img` runs, with no
//! re-registration -- this is the assertion that fails before the
//! `mount_store()` fix (an empty validity DB after reboot) and passes after.

use std::io::{Read, Write};

use kubernix_daemon_protocol::DaemonConnection;

fn usage() -> eyre::Report {
    eyre::eyre!(
        "usage: vm-db-persistence-smoke <vsock-socket> <port> register <store-path> <nar-file> <nar-hash> <nar-size>\n       vm-db-persistence-smoke <vsock-socket> <port> check <store-path>"
    )
}

fn main() -> eyre::Result<()> {
    let mut args = std::env::args().skip(1);
    let vsock_socket = args.next().ok_or_else(usage)?;
    let port: u32 = args.next().ok_or_else(usage)?.parse()?;
    let mode = args.next().ok_or_else(usage)?;
    let store_path = args.next().ok_or_else(usage)?;
    let rest: Vec<String> = args.collect();

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run(vsock_socket, port, mode, store_path, rest))
}

async fn run(
    vsock_socket: String,
    port: u32,
    mode: String,
    store_path: String,
    rest: Vec<String>,
) -> eyre::Result<()> {
    // The same inetd-style handshake `vm-smoke.rs` uses -- see its own doc
    // comment for why this is reimplemented rather than shared.
    let mut stream = std::os::unix::net::UnixStream::connect(&vsock_socket)?;
    stream.write_all(format!("CONNECT {port}\n").as_bytes())?;
    let mut buf = [0u8; 32];
    let n = stream.read(&mut buf)?;
    if !buf[..n].starts_with(b"OK") {
        eyre::bail!(
            "vsock CONNECT to guest port {port} refused: {:?}",
            &buf[..n]
        );
    }

    let stream = tokio::net::UnixStream::from_std(stream)?;
    let mut conn = DaemonConnection::open(stream).await?;

    match mode.as_str() {
        "register" => {
            let [nar_file, nar_hash, nar_size] = <[String; 3]>::try_from(rest)
                .map_err(|_| eyre::eyre!("register needs <nar-file> <nar-hash> <nar-size>"))?;
            let nar_size: u64 = nar_size.parse()?;
            let file = tokio::fs::File::open(&nar_file).await?;
            conn.add_to_store_nar(
                &store_path,
                None, // deriver: this test path has none
                &nar_hash,
                &[], // references: a leaf path, none
                0,   // registration_time: bookkeeping only, see chrono_now's own doc
                nar_size,
                false, // ultimate: not built by this daemon
                &[],   // sigs: none
                None,  // ca: not tracked for this test path
                file,
            )
            .await?;
            match conn.query_path_info(&store_path).await? {
                Some(_) => {
                    eprintln!(
                        "vm-db-persistence-smoke: registered and confirmed valid in this boot"
                    )
                }
                None => {
                    eyre::bail!("registered {store_path} but it reports invalid in the same boot")
                }
            }
        }
        "check" => match conn.query_path_info(&store_path).await? {
            Some(_) => eprintln!("vm-db-persistence-smoke: {store_path} is valid"),
            None => {
                eyre::bail!(
                    "{store_path} is NOT valid -- the validity DB did not survive the reboot"
                )
            }
        },
        other => eyre::bail!("unknown mode {other:?}, expected register|check"),
    }

    println!("ok");
    Ok(())
}
