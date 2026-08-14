//! Building a `BasicDerivation` through `nix-store --serve`.
//!
//! **Why this exists.** `buildDerivation` ships a *resolved* derivation: inputs
//! that were `inputDrvs` have already become concrete `inputSrcs`. The obvious
//! implementation — write it out as a `.drv` and run `nix-store --realise` —
//! cannot work for anything but a leaf derivation, because Nix computes an
//! input-addressed output path *from the derivation*, so a reconstructed `.drv`
//! disagrees with the output paths recorded inside it:
//!
//! ```text
//! error: derivation '/nix/store/h6bd…-x.drv' has incorrect output
//!        '/nix/store/7wjk…-x', should be '/nix/store/qff8…-x'
//! ```
//!
//! `nix-store --serve` has a `BuildDerivation` command that takes a derivation
//! *by value* and never writes a `.drv` at all (`lix/legacy/nix-store.cc:1065`,
//! `store->buildDerivation(drvPath, drv)`). It reads exactly the bytes we
//! already hold: both sides use Lix's `serializeDerivation`/`readDerivation`
//! pair, so the `drv` field from the daemon protocol goes out unmodified.
//!
//! The wire format is the serve protocol — u64 little-endian integers, strings
//! length-prefixed and padded to a multiple of eight. Unrelated to the Cap'n
//! Proto daemon protocol the frontend speaks.

use std::process::Stdio;

use eyre::{Context as _, OptionExt as _, bail};
use kubernix_types::wire::padding;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};

/// `lix/libstore/serve-protocol.hh`.
const MAGIC_1: u64 = 0x390c_9deb;
const MAGIC_2: u64 = 0x5452_eecb;

/// Pinned at 2.7 upstream and documented as never changing.
const PROTOCOL_VERSION: u64 = (2 << 8) | 7;

const CMD_BUILD_DERIVATION: u64 = 8;

/// `BuildResult::Status` (`lix/libstore/build-result.hh:24`).
const STATUS_BUILT: u64 = 0;
const STATUS_SUBSTITUTED: u64 = 1;
const STATUS_ALREADY_VALID: u64 = 2;
const STATUS_RESOLVES_TO_ALREADY_VALID: u64 = 13;

#[derive(Debug)]
pub struct BuildOutcome {
    pub status: u64,
    pub error_msg: String,
}

impl BuildOutcome {
    /// Whether the outputs exist afterwards.
    ///
    /// Several statuses mean "it is there now" without meaning "we just built
    /// it", and all of them are success for our purposes.
    pub fn succeeded(&self) -> bool {
        matches!(
            self.status,
            STATUS_BUILT
                | STATUS_SUBSTITUTED
                | STATUS_ALREADY_VALID
                | STATUS_RESOLVES_TO_ALREADY_VALID
        )
    }

    pub fn describe(&self) -> String {
        if self.error_msg.is_empty() {
            format!("build reported status {}", self.status)
        } else {
            self.error_msg.clone()
        }
    }
}

/// Little-endian u64s, written to whatever the serve protocol's stdin is.
trait WireWrite {
    async fn write_wire_u64(&mut self, value: u64) -> std::io::Result<()>;

    /// A length-prefixed string, zero-padded to a multiple of eight.
    async fn write_wire_str(&mut self, value: &[u8]) -> std::io::Result<()>;
}

impl WireWrite for ChildStdin {
    async fn write_wire_u64(&mut self, value: u64) -> std::io::Result<()> {
        self.write_all(&value.to_le_bytes()).await
    }

    async fn write_wire_str(&mut self, value: &[u8]) -> std::io::Result<()> {
        self.write_wire_u64(value.len() as u64).await?;
        self.write_all(value).await?;
        let padding = padding(value.len());
        if padding > 0 {
            self.write_all(&[0u8; 8][..padding]).await?;
        }
        Ok(())
    }
}

/// Little-endian u64s, read from whatever the serve protocol's stdout is.
trait WireRead {
    async fn read_wire_u64(&mut self) -> std::io::Result<u64>;
    async fn read_wire_string(&mut self) -> std::io::Result<String>;
}

impl WireRead for ChildStdout {
    async fn read_wire_u64(&mut self) -> std::io::Result<u64> {
        let mut buf = [0u8; 8];
        self.read_exact(&mut buf).await?;
        Ok(u64::from_le_bytes(buf))
    }

    async fn read_wire_string(&mut self) -> std::io::Result<String> {
        let len = self.read_wire_u64().await? as usize;
        let mut buf = vec![0u8; len];
        self.read_exact(&mut buf).await?;

        // Skip the padding, or every later field is misaligned.
        let padding = padding(len);
        if padding > 0 {
            let mut discard = [0u8; 8];
            self.read_exact(&mut discard[..padding]).await?;
        }
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }
}

/// A running `nix-store --serve --write`.
pub struct ServeConnection {
    child: Child,
    stdin: ChildStdin,
    stdout: ChildStdout,
    /// Taken by the caller so build output can be streamed while the build runs.
    pub stderr: Option<ChildStderr>,
}

impl ServeConnection {
    /// Spawn `nix-store --serve --write` and exchange greetings.
    ///
    /// TODO: nothing here bounds how long a hung or malicious builder can
    /// block this connection's I/O — the only backstop is the worker's NATS
    /// `ack_wait` (3600s), which affects redelivery, not killing the stuck
    /// process. A `tokio::time::timeout` around this and `build_derivation`
    /// would be a bandage; the real fix is to stop shelling out to
    /// `nix-store --serve` at all and speak the Nix/Lix daemon protocol
    /// directly over its Unix socket instead — the same kind of worker
    /// protocol `kubernix-server` already speaks over SSH
    /// (`server/src/daemon_rpc.rs`) — which makes a hung build a connection
    /// the worker controls rather than a subprocess it has to babysit.
    pub async fn open(nix_store: &str, store_uri: Option<&str>) -> eyre::Result<Self> {
        let mut command = Command::new(nix_store);
        command.arg("--serve").arg("--write");
        // Without this the build log never reaches us. `getBuildSettings` on the
        // far side forces `lvlError`, but that is not what suppresses the log:
        // build output is emitted via `printError` and gated on the logger's
        // `printBuildLogs`, which only `raw-with-logs` turns on
        // (`lix/libmain/loggers.cc:31`). Streaming logs is Phase 6 behaviour, so
        // losing them here would be a regression.
        command.arg("--log-format").arg("raw-with-logs");
        if let Some(uri) = store_uri {
            command.arg("--store").arg(uri);
        }

        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .wrap_err_with(|| format!("spawning {nix_store} --serve"))?;

        let mut stdin = child.stdin.take().ok_or_eyre("no stdin")?;
        let mut stdout = child.stdout.take().ok_or_eyre("no stdout")?;
        let stderr = child.stderr.take();

        // The client writes both words before reading; the server answers with
        // its own pair. See `lix/legacy/nix-store.cc:933`.
        stdin
            .write_wire_u64(MAGIC_1)
            .await
            .wrap_err("writing the serve protocol greeting")?;
        stdin
            .write_wire_u64(PROTOCOL_VERSION)
            .await
            .wrap_err("writing the serve protocol greeting")?;
        stdin.flush().await.wrap_err("flushing the greeting")?;

        let magic = stdout
            .read_wire_u64()
            .await
            .wrap_err("reading the serve protocol greeting")?;
        if magic != MAGIC_2 {
            bail!("serve protocol mismatch: got {magic:#x}");
        }
        let remote_version = stdout
            .read_wire_u64()
            .await
            .wrap_err("reading the serve protocol version")?;
        if remote_version & 0xff00 != PROTOCOL_VERSION & 0xff00 {
            bail!("unsupported serve protocol version {remote_version:#x}");
        }

        tracing::debug!(
            version = format_args!("{remote_version:#x}"),
            "serve connection open"
        );
        Ok(Self {
            child,
            stdin,
            stdout,
            stderr,
        })
    }

    /// Build a derivation given its path and its serialized form.
    ///
    /// `drv` is passed through byte for byte: it is already `serializeDerivation`
    /// output, which is exactly what the far side's `readDerivation` expects.
    ///
    /// TODO: same unbounded-hang risk as [`Self::open`] — no timeout on this
    /// exchange, same real fix (talk to the daemon socket directly rather
    /// than through this subprocess).
    pub async fn build_derivation(
        &mut self,
        drv_path: &str,
        drv: &[u8],
    ) -> eyre::Result<BuildOutcome> {
        self.stdin
            .write_wire_u64(CMD_BUILD_DERIVATION)
            .await
            .wrap_err("sending the build command")?;
        self.stdin
            .write_wire_str(drv_path.as_bytes())
            .await
            .wrap_err("sending the derivation path")?;
        self.stdin
            .write_all(drv)
            .await
            .wrap_err("sending the derivation")?;

        // `getBuildSettings` on the far side reads these unconditionally, in
        // this order (`nix-store.cc:952`). Omitting one desynchronises the
        // stream rather than being ignored.
        let settings = async {
            self.stdin.write_wire_u64(0).await?; // maxSilentTime: no limit
            self.stdin.write_wire_u64(0).await?; // buildTimeout: no limit
            self.stdin.write_wire_u64(0).await?; // maxLogSize: no limit
            self.stdin.write_wire_u64(0).await?; // buildRepeat, unsupported upstream
            self.stdin.write_wire_u64(0).await?; // enforceDeterminism, ignored
            self.stdin.write_wire_u64(0).await?; // keepFailed (minor >= 7)
            self.stdin.flush().await
        };
        settings.await.wrap_err("sending build settings")?;

        let status = self
            .stdout
            .read_wire_u64()
            .await
            .wrap_err("reading the build status")?;
        let error_msg = self
            .stdout
            .read_wire_string()
            .await
            .wrap_err("reading the build error message")?;

        // Protocol 2.7 always carries these; reading them keeps the stream in
        // step even though we only report status and message.
        let drained = async {
            self.stdout.read_wire_u64().await?; // times built
            self.stdout.read_wire_u64().await?; // non-deterministic
            self.stdout.read_wire_u64().await?; // start time
            self.stdout.read_wire_u64().await?; // stop time

            // `builtOutputs`, a map of realisations. Empty for input-addressed
            // derivations, which is everything we build today — but it has to
            // be drained regardless.
            let realisations = self.stdout.read_wire_u64().await?;
            for _ in 0..realisations {
                self.stdout.read_wire_string().await?; // DrvOutput
                self.stdout.read_wire_string().await?; // Realisation
            }
            std::io::Result::Ok(())
        };
        drained.await.wrap_err("draining the build result")?;

        Ok(BuildOutcome { status, error_msg })
    }

    /// Close the connection and reap the child.
    ///
    /// Dropping stdin is what tells `nix-store --serve` to exit: it reads
    /// commands until EOF.
    pub async fn close(mut self) -> eyre::Result<()> {
        drop(self.stdin);
        let status = self
            .child
            .wait()
            .await
            .wrap_err("waiting for nix-store --serve")?;
        if !status.success() {
            tracing::warn!(?status, "nix-store --serve exited non-zero");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_covers_every_status_that_means_the_output_exists() {
        // `AlreadyValid` and `Substituted` are not builds, but the outputs are
        // there — treating them as failure would break every rebuild of
        // something already present.
        for status in [
            STATUS_BUILT,
            STATUS_SUBSTITUTED,
            STATUS_ALREADY_VALID,
            STATUS_RESOLVES_TO_ALREADY_VALID,
        ] {
            let outcome = BuildOutcome {
                status,
                error_msg: String::new(),
            };
            assert!(outcome.succeeded(), "status {status} should be a success");
        }
    }

    #[test]
    fn failures_are_failures() {
        for status in [3u64, 4, 5, 6, 8, 9, 10, 11, 12] {
            let outcome = BuildOutcome {
                status,
                error_msg: String::new(),
            };
            assert!(!outcome.succeeded(), "status {status} should be a failure");
        }
    }

    #[test]
    fn a_status_without_a_message_still_describes_itself() {
        let outcome = BuildOutcome {
            status: 3,
            error_msg: String::new(),
        };
        assert!(outcome.describe().contains('3'));

        let outcome = BuildOutcome {
            status: 3,
            error_msg: "builder failed".to_string(),
        };
        assert_eq!(outcome.describe(), "builder failed");
    }
}
