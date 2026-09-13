//! A client for the Nix/Lix "worker protocol" — the wire format a real
//! `nix-daemon --stdio` speaks (`lix/libstore/worker-protocol.hh`,
//! `remote-store.cc`). **Not** the Cap'n Proto `daemon.capnp` protocol
//! `server/src/daemon_rpc.rs` implements; those are two unrelated protocols
//! (`nix-daemon --stdio` "hardcodes `processLegacyConnection`" —
//! `lix/nix/daemon.cc:569-575` — and never serves Cap'n Proto over stdio at
//! all). Every wire detail below is taken from that pinned Lix checkout,
//! not re-derived.
//!
//! Implements exactly the four operations `worker` needs to stop shelling out
//! to `nix-store --serve`/`nix store dump-path`/`nix-store --import`/
//! `nix-store --query`: [`DaemonConnection::build_derivation`],
//! [`DaemonConnection::query_path_info`], [`DaemonConnection::nar_from_path`],
//! [`DaemonConnection::add_to_store_nar`]. Not a general client — no
//! `queryValidPaths`, no `collectGarbage`, nothing this codebase doesn't call.

use crate::nar::{self, NarError};
use crate::wire::{WireRead, WireWrite};

/// `WORKER_MAGIC_1`/`WORKER_MAGIC_2` (`worker-protocol.hh`).
const MAGIC_1: u64 = 0x6e69_7863;
const MAGIC_2: u64 = 0x6478_696f;

/// Frozen at Nix 2.18's shape in Lix — see `worker-protocol.hh`'s own comment
/// on why it will never move again.
const PROTOCOL_VERSION: u64 = (1 << 8) | 35;
const MIN_SUPPORTED_MINOR: u64 = 35;

const STDERR_NEXT: u64 = 0x6f6c_6d67;
const STDERR_LAST: u64 = 0x616c_7473;
const STDERR_ERROR: u64 = 0x6378_7470;
const STDERR_START_ACTIVITY: u64 = 0x5354_5254;
const STDERR_STOP_ACTIVITY: u64 = 0x5354_4f50;
const STDERR_RESULT: u64 = 0x5253_4c54;

#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol mismatch: got magic {0:#x}")]
    BadMagic(u64),
    #[error("unsupported daemon protocol version {0:#x}")]
    UnsupportedVersion(u64),
    #[error("daemon reported an unexpected message tag {0:#x}")]
    UnknownTag(u64),
    #[error("{0}")]
    Nar(#[from] NarError),
    /// `STDERR_ERROR`'s payload: the daemon's own error message.
    #[error("remote error: {message}")]
    Remote { level: u64, message: String },
}

/// `BuildResult::Status` (`lix/libstore/build-result.hh`).
const STATUS_BUILT: u64 = 0;
const STATUS_SUBSTITUTED: u64 = 1;
const STATUS_ALREADY_VALID: u64 = 2;
const STATUS_RESOLVES_TO_ALREADY_VALID: u64 = 13;

#[derive(Debug)]
pub struct BuildOutcome {
    pub status: u64,
    pub error_msg: String,
    /// `STDERR_NEXT` lines emitted while this build ran, in order — the
    /// build log, for archival. The caller also gets each line live, as it's
    /// read, via `build_derivation`'s `on_line` channel.
    pub log: Vec<String>,
}

impl BuildOutcome {
    /// Whether the outputs exist afterwards — mirrors
    /// `worker/src/serve.rs::BuildOutcome::succeeded`'s reasoning exactly,
    /// same status codes, same protocol family.
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

/// `UnkeyedValidPathInfo` (`worker-protocol.cc`), the reply to
/// `Op::QueryPathInfo`.
#[derive(Debug, Clone)]
pub struct PathInfo {
    pub deriver: Option<String>,
    pub nar_hash: String,
    pub references: Vec<String>,
    pub registration_time: i64,
    pub nar_size: u64,
    pub ultimate: bool,
    pub sigs: Vec<String>,
    pub ca: Option<String>,
}

/// A client for one `nix-daemon --stdio` session, over any byte stream —
/// a vsock-backed `UnixStream` in production, an in-memory duplex in tests.
pub struct DaemonConnection<S> {
    stream: S,
    /// The daemon's advertised version, kept only for diagnostics — every op
    /// here targets the one frozen protocol shape `PROTOCOL_VERSION` names.
    #[allow(dead_code)]
    daemon_version: u64,
}

impl<S> DaemonConnection<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    /// The magic/version handshake (`RemoteStore::initConnection`,
    /// `remote-store.cc:52-109`) followed by the mandatory `SetOptions` every
    /// real client sends before anything else — skipping it is untested
    /// territory upstream, so this doesn't either. A minimal settings frame
    /// (every scalar `0`/`false`, no overrides) is enough: this client never
    /// relies on daemon-side settings behaving one way or another.
    pub async fn open(mut stream: S) -> Result<Self, DaemonError> {
        stream.write_wire_u64(MAGIC_1).await?;

        let magic = stream.read_wire_u64().await?;
        if magic != MAGIC_2 {
            return Err(DaemonError::BadMagic(magic));
        }
        let daemon_version = stream.read_wire_u64().await?;
        if (daemon_version & 0xff00) != (PROTOCOL_VERSION & 0xff00) {
            return Err(DaemonError::UnsupportedVersion(daemon_version));
        }
        if (daemon_version & 0x00ff) < MIN_SUPPORTED_MINOR {
            return Err(DaemonError::UnsupportedVersion(daemon_version));
        }

        stream.write_wire_u64(PROTOCOL_VERSION).await?;
        stream.write_wire_u64(0).await?; // obsolete CPU affinity
        stream.write_wire_bool(false).await?; // obsolete reserveSpace

        // Daemon's own version string, then `optional<TrustedFlag>`. The
        // latter is a *single* 8-byte tristate word -- `0` absent, `1`
        // Trusted, `2` NotTrusted (`worker-protocol.cc`'s
        // `Serialise<std::optional<TrustedFlag>>::read`, which calls
        // `readNum<uint8_t>`, itself always an 8-byte wire read regardless of
        // the narrower C++ return type) -- not a present-flag bool followed
        // by a separate value, which was this code's bug until it was found
        // against a real daemon: the extra read that shape implies consumes
        // the first word of `drain_stderr`'s own framing below, desyncing
        // everything after it and leaving the daemon waiting forever for a
        // `SetOptions` this client never actually got around to sending.
        // Neither field is acted on here, but both must still be drained
        // correctly to stay in sync with the rest of the stream.
        stream.read_wire_str().await?; // daemonNixVersion
        stream.read_wire_u64().await?; // optional<TrustedFlag>: 0/1/2

        drain_stderr(&mut stream, None, None).await?;

        let mut conn = Self {
            stream,
            daemon_version,
        };
        conn.set_options().await?;
        Ok(conn)
    }

    async fn set_options(&mut self) -> Result<(), DaemonError> {
        const OP_SET_OPTIONS: u64 = 19;
        self.stream.write_wire_u64(OP_SET_OPTIONS).await?;
        // keepFailed, keepGoing, tryFallback, verbosity, maxBuildJobs,
        // maxSilentTime, useBuildHook(obsolete, must be `true`), buildVerbosity,
        // obsolete logType, obsolete printBuildTrace, buildCores, useSubstitutes
        // — see `remote-store.cc:120-133`. All conservative defaults; nothing
        // downstream of this client depends on daemon-side settings.
        for v in [0u64, 0, 0, 0, 1, 0] {
            self.stream.write_wire_u64(v).await?;
        }
        self.stream.write_wire_bool(true).await?; // obsolete useBuildHook
        self.stream.write_wire_u64(0).await?; // buildVerbosity (lvlError)
        self.stream.write_wire_u64(0).await?; // obsolete log type
        self.stream.write_wire_u64(0).await?; // obsolete print build trace
        self.stream.write_wire_u64(1).await?; // buildCores
        self.stream.write_wire_bool(true).await?; // useSubstitutes
        self.stream.write_wire_u64(0).await?; // no setting overrides
        drain_stderr(&mut self.stream, None, None).await
    }

    /// `Op::BuildDerivation` (`remote-store.cc:541-552`). `drv` is passed
    /// through byte for byte — it is already `serializeDerivation` output —
    /// for exactly the reason `worker/src/serve.rs`'s module doc gives: the
    /// derivation this client receives is already resolved, and
    /// reconstructing a `.drv` from it disagrees with the output paths
    /// recorded inside it as soon as one derivation depends on another.
    pub async fn build_derivation(
        &mut self,
        drv_path: &str,
        drv: &[u8],
        on_line: Option<&tokio::sync::mpsc::UnboundedSender<String>>,
    ) -> Result<BuildOutcome, DaemonError> {
        const OP_BUILD_DERIVATION: u64 = 36;
        self.stream.write_wire_u64(OP_BUILD_DERIVATION).await?;
        self.stream.write_wire_str(drv_path).await?;
        self.stream.write_all_raw(drv).await?;
        self.stream.write_wire_u64(0).await?; // BuildMode::Normal

        // Unlike every other op here, the caller wants this command's build
        // log, not just to have it drained — the entire reason
        // `worker/src/serve.rs`'s `--log-format raw-with-logs` exists for the
        // subprocess path. It travels as `STDERR_RESULT`/`resBuildLogLine`
        // frames, not `STDERR_NEXT` — see `drain_stderr`'s doc comment; a
        // first attempt at this looked for it on `STDERR_NEXT` and silently
        // got nothing, ever, regardless of verbosity settings. Still
        // collected into `log` for archival (the object uploaded alongside
        // the build's outputs), but also sent line-by-line to `on_line` as
        // each one is read, so a caller can relay it live the same way the
        // subprocess path's `pump_log` does.
        let mut log = Vec::new();
        drain_stderr(&mut self.stream, Some(&mut log), on_line).await?;

        let status = self.stream.read_wire_u64().await?;
        let error_msg = self.stream.read_wire_str().await?;
        self.stream.read_wire_u64().await?; // timesBuilt
        self.stream.read_wire_bool().await?; // isNonDeterministic
        self.stream.read_wire_u64().await?; // startTime
        self.stream.read_wire_u64().await?; // stopTime

        // `builtOutputs`, a map of realisations. `serve.rs`'s equivalent
        // read has the full story: Lix's `LocalDerivationGoal::registerOutputs`
        // (`local-derivation-goal.cc`) populates one `Realisation` per output
        // unconditionally — "it's fine to do in all cases", not gated behind
        // the `ca-derivations` experimental feature the way it is upstream —
        // so a real Lix daemon sends a nonempty map here even for the plain
        // input-addressed derivations this worker builds. Draining each
        // entry (a `DrvOutput` key, a JSON-encoded `Realisation` value, both
        // plain wire strings — `common-protocol.cc`) keeps the stream in
        // step; nothing here is otherwise acted on.
        let realisations = self.stream.read_wire_u64().await?;
        for _ in 0..realisations {
            self.stream.read_wire_str().await?; // DrvOutput
            self.stream.read_wire_str().await?; // Realisation
        }

        Ok(BuildOutcome {
            status,
            error_msg,
            log,
        })
    }

    /// `Op::QueryPathInfo` (`remote-store.cc:244-262`). Replaces
    /// `nix-store --query --references`/`--deriver`'s two subprocesses with
    /// one round trip.
    pub async fn query_path_info(
        &mut self,
        store_path: &str,
    ) -> Result<Option<PathInfo>, DaemonError> {
        const OP_QUERY_PATH_INFO: u64 = 26;
        self.stream.write_wire_u64(OP_QUERY_PATH_INFO).await?;
        self.stream.write_wire_str(store_path).await?;
        drain_stderr(&mut self.stream, None, None).await?;

        if !self.stream.read_wire_bool().await? {
            return Ok(None);
        }

        let deriver = self.stream.read_wire_str().await?;
        let nar_hash = self.stream.read_wire_str().await?;
        let references = self.stream.read_wire_strings().await?;
        let registration_time = self.stream.read_wire_u64().await? as i64;
        let nar_size = self.stream.read_wire_u64().await?;
        let ultimate = self.stream.read_wire_bool().await?;
        let sigs = self.stream.read_wire_strings().await?;
        let ca = self.stream.read_wire_str().await?;

        Ok(Some(PathInfo {
            deriver: (!deriver.is_empty()).then_some(deriver),
            nar_hash,
            references,
            registration_time,
            nar_size,
            ultimate,
            sigs,
            ca: (!ca.is_empty()).then_some(ca),
        }))
    }

    /// `Op::NarFromPath` (`remote-store.cc:726-750`): the reply is a raw,
    /// self-delimiting NAR with no length of its own — see [`crate::nar`] for
    /// why that needs a structural walk rather than a byte copy.
    pub async fn nar_from_path<W>(
        &mut self,
        store_path: &str,
        sink: &mut W,
    ) -> Result<(), DaemonError>
    where
        W: tokio::io::AsyncWrite + Unpin + Send,
    {
        const OP_NAR_FROM_PATH: u64 = 38;
        self.stream.write_wire_u64(OP_NAR_FROM_PATH).await?;
        self.stream.write_wire_str(store_path).await?;
        drain_stderr(&mut self.stream, None, None).await?;

        nar::copy_nar(&mut self.stream, sink).await?;
        Ok(())
    }

    /// `Op::AddToStoreNar` (`remote-store.cc:381-408`). Unlike every other
    /// op's fixed-size arguments, the NAR body itself travels as a *framed*
    /// stream — `AsyncFramedOutputStream` (`libutil/async-io.cc:258-277`):
    /// each `write()` is a `u64` chunk length followed by that many raw
    /// bytes (no padding, unlike the length-prefixed *strings* elsewhere in
    /// this protocol), terminated by one zero-length chunk. `nar` is read in
    /// fixed-size chunks and framed as it goes, so peak memory is one chunk,
    /// not the whole NAR — the same reason `upload.rs`'s existing pipelines
    /// stream rather than buffer.
    #[allow(clippy::too_many_arguments)]
    pub async fn add_to_store_nar<R>(
        &mut self,
        store_path: &str,
        deriver: Option<&str>,
        nar_hash: &str,
        references: &[String],
        registration_time: i64,
        nar_size: u64,
        ultimate: bool,
        sigs: &[String],
        ca: Option<&str>,
        mut nar: R,
    ) -> Result<(), DaemonError>
    where
        R: tokio::io::AsyncRead + Unpin + Send,
    {
        const OP_ADD_TO_STORE_NAR: u64 = 39;
        self.stream.write_wire_u64(OP_ADD_TO_STORE_NAR).await?;
        self.stream.write_wire_str(store_path).await?;
        self.stream.write_wire_str(deriver.unwrap_or("")).await?;
        self.stream.write_wire_str(nar_hash).await?;
        self.stream.write_wire_strings(references).await?;
        self.stream.write_wire_u64(registration_time as u64).await?;
        self.stream.write_wire_u64(nar_size).await?;
        self.stream.write_wire_bool(ultimate).await?;
        self.stream.write_wire_strings(sigs).await?;
        self.stream.write_wire_str(ca.unwrap_or("")).await?;
        self.stream.write_wire_bool(false).await?; // repair
        self.stream.write_wire_bool(true).await?; // !checkSigs

        const CHUNK: usize = 65536;
        let mut buf = vec![0u8; CHUNK];
        loop {
            let n = tokio::io::AsyncReadExt::read(&mut nar, &mut buf).await?;
            if n == 0 {
                break;
            }
            self.stream.write_wire_u64(n as u64).await?;
            self.stream.write_all_raw(&buf[..n]).await?;
        }
        self.stream.write_wire_u64(0).await?; // terminating zero-length chunk

        drain_stderr(&mut self.stream, None, None).await
    }
}

/// Bytes with no length prefix/padding of their own — the raw `serializeDerivation`
/// payload in `build_derivation`, and each already-length-prefixed chunk's body
/// in `add_to_store_nar`. A small extension trait rather than reaching for
/// `tokio::io::AsyncWriteExt` at every call site.
trait RawWrite {
    async fn write_all_raw(&mut self, bytes: &[u8]) -> std::io::Result<()>;
}

impl<W: tokio::io::AsyncWrite + Unpin> RawWrite for W {
    async fn write_all_raw(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        tokio::io::AsyncWriteExt::write_all(self, bytes).await
    }
}

/// Drain `STDERR_*` frames until `STDERR_LAST`, exactly the loop every real
/// client runs after every command (`RemoteStore::Connection::processStderr`,
/// `remote-store.cc:780-844`) before reading that command's own typed reply.
/// Activity start/stop frames, and every `STDERR_RESULT` except
/// `resBuildLogLine`, are read and discarded rather than acted on — this
/// client has no live progress display — but every field still has to be
/// consumed in order, or the next read desynchronises.
///
/// `on_line`, when given, is sent each build-log line as it is read — a
/// `STDERR_RESULT`/`resBuildLogLine` frame, *not* `STDERR_NEXT` (which only
/// ever carries the daemon's own messages; see the `STDERR_RESULT` arm below)
/// — in addition to `log` collecting it. The seam that lets a caller relay a
/// build's log live instead of only after it collects the whole thing (see
/// [`DaemonConnection::build_derivation`]'s doc comment).
async fn drain_stderr<S>(
    stream: &mut S,
    mut log: Option<&mut Vec<String>>,
    on_line: Option<&tokio::sync::mpsc::UnboundedSender<String>>,
) -> Result<(), DaemonError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    loop {
        match stream.read_wire_u64().await? {
            STDERR_NEXT => {
                let line = stream.read_wire_str().await?;
                tracing::debug!(target: "kubernix_daemon_protocol::remote_log", "{}", line.trim_end());
                if let Some(tx) = on_line {
                    // A dropped receiver just means nobody is listening live
                    // (e.g. every other `drain_stderr` call site passes
                    // `None` instead) — not a reason to fail the build.
                    let _ = tx.send(line.clone());
                }
                if let Some(log) = log.as_deref_mut() {
                    log.push(line);
                }
            }
            STDERR_START_ACTIVITY => {
                stream.read_wire_u64().await?; // activity id
                stream.read_wire_u64().await?; // verbosity
                stream.read_wire_u64().await?; // activity type
                stream.read_wire_str().await?; // description
                read_fields(stream).await?;
                stream.read_wire_u64().await?; // parent id
            }
            STDERR_STOP_ACTIVITY => {
                stream.read_wire_u64().await?; // activity id
            }
            STDERR_RESULT => {
                stream.read_wire_u64().await?; // activity id
                let result_type = stream.read_wire_u64().await?;
                let fields = read_fields(stream).await?;
                // `resBuildLogLine` (`logging.hh`'s `ResultType`, 101): the
                // builder's own raw stdout/stderr, one line per result — this
                // is where a real build's log actually travels on this
                // protocol (`LocalDerivationGoal`'s `flushLine`, via
                // `act.result(resBuildLogLine, line)`), *not* `STDERR_NEXT`,
                // which only ever carries the daemon's own messages. Found
                // by noticing the daemon's real build log never arrived at
                // all despite `on_line` being wired up correctly — the
                // frames were STDERR_RESULT, silently drained until now.
                // `resultImpl` (`daemon.cc`) isn't gated by `getVerbosity()`
                // the way plain `log()` calls are, so this arrives
                // regardless of `set_options`'s verbosity setting.
                if result_type == RESULT_BUILD_LOG_LINE
                    && let Some(Field::Str(line)) = fields.into_iter().next()
                {
                    tracing::debug!(target: "kubernix_daemon_protocol::remote_log", "{}", line.trim_end());
                    if let Some(tx) = on_line {
                        let _ = tx.send(line.clone());
                    }
                    if let Some(log) = log.as_deref_mut() {
                        log.push(line);
                    }
                }
            }
            STDERR_LAST => return Ok(()),
            STDERR_ERROR => return Err(read_remote_error(stream).await?),
            other => return Err(DaemonError::UnknownTag(other)),
        }
    }
}

/// `ResultType::resBuildLogLine` (`libutil/logging.hh`).
const RESULT_BUILD_LOG_LINE: u64 = 101;

/// One `Logger::Field` (`libutil/logging.hh`): `tInt = 0` or `tString = 1`.
enum Field {
    // Never inspected — no result type this client cares about carries an
    // int field — but still parsed out so the stream stays in sync with
    // whatever field shape the daemon actually sent.
    #[allow(dead_code)]
    Int(u64),
    Str(String),
}

/// `Logger::Fields` (`libutil/logging.hh`, `daemon.cc`'s `operator<<`): a
/// count, then that many `(type, value)` pairs.
async fn read_fields<S>(stream: &mut S) -> Result<Vec<Field>, DaemonError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    let count = stream.read_wire_u64().await?;
    let mut fields = Vec::with_capacity(count as usize);
    for _ in 0..count {
        match stream.read_wire_u64().await? {
            0 => fields.push(Field::Int(stream.read_wire_u64().await?)),
            _ => fields.push(Field::Str(stream.read_wire_str().await?)),
        }
    }
    Ok(fields)
}

/// `readError` (`libutil/serialise.cc:345-367`): a fixed "Error" type tag, a
/// verbosity level, an obsolete (removed) name string, the message, then a
/// trace list each entry of which starts with an always-zero `havePos`
/// marker this client has no use for beyond draining it.
async fn read_remote_error<S>(stream: &mut S) -> Result<DaemonError, DaemonError>
where
    S: tokio::io::AsyncRead + Unpin,
{
    stream.read_wire_str().await?; // "Error"
    let level = stream.read_wire_u64().await?;
    stream.read_wire_str().await?; // obsolete name
    let message = stream.read_wire_str().await?;
    stream.read_wire_u64().await?; // havePos, always 0
    let traces = stream.read_wire_u64().await?;
    for _ in 0..traces {
        stream.read_wire_u64().await?; // havePos, always 0
        stream.read_wire_str().await?; // hint
    }
    Ok(DaemonError::Remote { level, message })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A greeting a real daemon would send, immediately followed by whatever
    /// `extra` bytes the test wants appended (a reply to some op).
    fn greeting_with(extra: &[u8]) -> Vec<u8> {
        greeting_with_trusted_flag(0, extra)
    }

    /// Same as [`greeting_with`], but with the `optional<TrustedFlag>` word
    /// explicit — `0` absent, `1` Trusted, `2` NotTrusted (see `open`'s
    /// comment on this field for why it's a single word, not two).
    /// `greeting_with`'s `0` alone can't tell the correct one-word read
    /// apart from the bug this guards against (a present-flag bool followed
    /// by a separate value bool) — both consume exactly one word when the
    /// value is `0`. Only a *nonzero* value exercises the difference: the
    /// buggy reader would consume an extra word here that was never sent,
    /// desyncing every read after it — this crate's only regression test
    /// against exactly the behavior found live against a real `nix-daemon`
    /// (see `PLAN.md`'s Phase 15 Step 3 status note).
    fn greeting_with_trusted_flag(trusted: u64, extra: &[u8]) -> Vec<u8> {
        let mut w = Vec::new();
        w.write_u64_sync(MAGIC_2);
        w.write_u64_sync(PROTOCOL_VERSION);
        w.write_str_sync("2.96.0-dev-kubernix-test");
        w.write_u64_sync(trusted);
        // `drain_stderr` after the greeting.
        w.write_u64_sync(STDERR_LAST);
        // `drain_stderr` after `set_options`.
        w.write_u64_sync(STDERR_LAST);
        w.extend_from_slice(extra);
        w
    }

    /// Sync helpers so test fixtures don't need `#[tokio::test]` just to
    /// build a byte buffer — mirrors `kubernix_types::wire`'s own split
    /// between the sync buffer builders and this crate's async stream ones.
    trait SyncBuild {
        fn write_u64_sync(&mut self, v: u64);
        fn write_str_sync(&mut self, v: &str);
        fn write_bool_sync(&mut self, v: bool);
    }
    impl SyncBuild for Vec<u8> {
        fn write_u64_sync(&mut self, v: u64) {
            kubernix_types::wire::write_u64(self, v);
        }
        fn write_str_sync(&mut self, v: &str) {
            kubernix_types::wire::write_bytes(self, v.as_bytes());
        }
        fn write_bool_sync(&mut self, v: bool) {
            kubernix_types::wire::write_u64(self, v as u64);
        }
    }

    /// An in-memory duplex standing in for a real vsock `UnixStream`: writes
    /// go into `written`, reads come from `to_read`. Enough to drive `open`
    /// and one op end to end without any live connection.
    struct FakeStream {
        to_read: std::io::Cursor<Vec<u8>>,
        written: Vec<u8>,
    }
    impl tokio::io::AsyncRead for FakeStream {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.to_read).poll_read(cx, buf)
        }
    }
    impl tokio::io::AsyncWrite for FakeStream {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            self.written.extend_from_slice(buf);
            std::task::Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn opens_against_a_well_formed_greeting() {
        let stream = FakeStream {
            to_read: std::io::Cursor::new(greeting_with(&[])),
            written: Vec::new(),
        };
        let conn = DaemonConnection::open(stream).await.unwrap();
        assert_eq!(conn.daemon_version, PROTOCOL_VERSION);
    }

    #[tokio::test]
    async fn opens_against_a_greeting_reporting_trusted() {
        // Regression test for the bug found against a real `nix-daemon`: a
        // nonzero `optional<TrustedFlag>` word used to make `open` read one
        // extra (nonexistent) word, desyncing `drain_stderr` afterwards and
        // hanging rather than erroring — see `greeting_with_trusted_flag`'s
        // doc comment. `1` is `Trusted`.
        let stream = FakeStream {
            to_read: std::io::Cursor::new(greeting_with_trusted_flag(1, &[])),
            written: Vec::new(),
        };
        let conn = DaemonConnection::open(stream).await.unwrap();
        assert_eq!(conn.daemon_version, PROTOCOL_VERSION);
    }

    #[tokio::test]
    async fn a_wrong_magic_is_refused() {
        let mut bytes = Vec::new();
        bytes.write_u64_sync(0xdead_beef);
        let stream = FakeStream {
            to_read: std::io::Cursor::new(bytes),
            written: Vec::new(),
        };
        assert!(matches!(
            DaemonConnection::open(stream).await,
            Err(DaemonError::BadMagic(_))
        ));
    }

    #[tokio::test]
    async fn a_too_old_minor_version_is_refused() {
        let mut w = Vec::new();
        w.write_u64_sync(MAGIC_2);
        w.write_u64_sync((1 << 8) | 10); // below MIN_SUPPORTED_MINOR
        let stream = FakeStream {
            to_read: std::io::Cursor::new(w),
            written: Vec::new(),
        };
        assert!(matches!(
            DaemonConnection::open(stream).await,
            Err(DaemonError::UnsupportedVersion(_))
        ));
    }

    #[tokio::test]
    async fn build_derivation_reports_success_and_drains_the_reply() {
        let mut reply = Vec::new();
        reply.write_u64_sync(STDERR_LAST); // drain_stderr after the command
        reply.write_u64_sync(STATUS_BUILT);
        reply.write_str_sync(""); // error_msg
        reply.write_u64_sync(0); // timesBuilt
        reply.write_bool_sync(false); // isNonDeterministic
        reply.write_u64_sync(0); // startTime
        reply.write_u64_sync(0); // stopTime
        reply.write_u64_sync(0); // builtOutputs: empty

        let stream = FakeStream {
            to_read: std::io::Cursor::new(greeting_with(&reply)),
            written: Vec::new(),
        };
        let mut conn = DaemonConnection::open(stream).await.unwrap();
        let outcome = conn
            .build_derivation("/nix/store/xxx-foo.drv", b"raw drv bytes", None)
            .await
            .unwrap();
        assert!(outcome.succeeded());
    }

    /// Regression: `on_line` used to not exist at all, so a build's log only
    /// reached the caller once `build_derivation` returned — see that
    /// method's doc comment. Every `STDERR_NEXT` line must arrive on the
    /// channel as it's read, not just end up in `BuildOutcome::log`.
    #[tokio::test]
    async fn build_derivation_sends_each_log_line_live() {
        // The real wire shape (`LocalDerivationGoal`'s `flushLine`): each
        // line is a `STDERR_RESULT` frame of type `resBuildLogLine` (101)
        // carrying one string field, tied to a build activity — not a plain
        // `STDERR_NEXT`, which this test used to (wrongly) assume.
        let mut reply = Vec::new();
        for line in ["building...\n", "done\n"] {
            reply.write_u64_sync(STDERR_RESULT);
            reply.write_u64_sync(1); // activity id
            reply.write_u64_sync(RESULT_BUILD_LOG_LINE);
            reply.write_u64_sync(1); // one field
            reply.write_u64_sync(1); // tString
            reply.write_str_sync(line);
        }
        reply.write_u64_sync(STDERR_LAST);
        reply.write_u64_sync(STATUS_BUILT);
        reply.write_str_sync(""); // error_msg
        reply.write_u64_sync(0); // timesBuilt
        reply.write_bool_sync(false); // isNonDeterministic
        reply.write_u64_sync(0); // startTime
        reply.write_u64_sync(0); // stopTime
        reply.write_u64_sync(0); // builtOutputs: empty

        let stream = FakeStream {
            to_read: std::io::Cursor::new(greeting_with(&reply)),
            written: Vec::new(),
        };
        let mut conn = DaemonConnection::open(stream).await.unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let outcome = conn
            .build_derivation("/nix/store/xxx-foo.drv", b"drv", Some(&tx))
            .await
            .unwrap();
        drop(tx);

        let mut lines = Vec::new();
        while let Some(line) = rx.recv().await {
            lines.push(line);
        }
        assert_eq!(lines, vec!["building...\n", "done\n"]);
        // Both channels see the same lines — one isn't a substitute for the
        // other, `on_line` is in addition to the archived `log`.
        assert_eq!(outcome.log, lines);
    }

    #[tokio::test]
    async fn a_remote_error_surfaces_as_daemonerror_remote() {
        let mut reply = Vec::new();
        reply.write_u64_sync(STDERR_ERROR);
        reply.write_str_sync("Error");
        reply.write_u64_sync(0); // level
        reply.write_str_sync(""); // obsolete name
        reply.write_str_sync("derivation produced no such output");
        reply.write_u64_sync(0); // havePos
        reply.write_u64_sync(0); // no traces

        let stream = FakeStream {
            to_read: std::io::Cursor::new(greeting_with(&reply)),
            written: Vec::new(),
        };
        let mut conn = DaemonConnection::open(stream).await.unwrap();
        let err = conn
            .build_derivation("/nix/store/xxx-foo.drv", b"drv", None)
            .await
            .unwrap_err();
        match err {
            DaemonError::Remote { message, .. } => {
                assert_eq!(message, "derivation produced no such output");
            }
            other => panic!("expected Remote, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn query_path_info_none_when_the_daemon_reports_invalid() {
        let mut reply = Vec::new();
        reply.write_u64_sync(STDERR_LAST);
        reply.write_bool_sync(false); // not valid

        let stream = FakeStream {
            to_read: std::io::Cursor::new(greeting_with(&reply)),
            written: Vec::new(),
        };
        let mut conn = DaemonConnection::open(stream).await.unwrap();
        assert!(
            conn.query_path_info("/nix/store/xxx-foo")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn query_path_info_parses_a_valid_reply() {
        let mut reply = Vec::new();
        reply.write_u64_sync(STDERR_LAST);
        reply.write_bool_sync(true); // valid
        reply.write_str_sync(""); // deriver: none
        reply.write_str_sync("sha256:abc");
        reply.write_u64_sync(1); // one reference
        reply.write_str_sync("/nix/store/yyy-dep");
        reply.write_u64_sync(1_700_000_000); // registrationTime
        reply.write_u64_sync(42); // narSize
        reply.write_bool_sync(true); // ultimate
        reply.write_u64_sync(0); // sigs: none
        reply.write_str_sync(""); // ca: none

        let stream = FakeStream {
            to_read: std::io::Cursor::new(greeting_with(&reply)),
            written: Vec::new(),
        };
        let mut conn = DaemonConnection::open(stream).await.unwrap();
        let info = conn
            .query_path_info("/nix/store/xxx-foo")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(info.deriver, None);
        assert_eq!(info.nar_hash, "sha256:abc");
        assert_eq!(info.references, vec!["/nix/store/yyy-dep".to_string()]);
        assert_eq!(info.nar_size, 42);
        assert!(info.ultimate);
        assert_eq!(info.ca, None);
    }

    /// A minimal well-formed NAR for a single regular file — see
    /// `nar.rs`'s own `tests::nar_regular_file`, duplicated here in
    /// miniature rather than exposed across the crate boundary just for
    /// this one test.
    fn small_regular_file_nar(contents: &[u8]) -> Vec<u8> {
        let mut w = Vec::new();
        w.write_str_sync("nix-archive-1");
        w.write_str_sync("(");
        w.write_str_sync("type");
        w.write_str_sync("regular");
        w.write_str_sync("contents");
        w.write_u64_sync(contents.len() as u64);
        w.extend_from_slice(contents);
        w.extend(std::iter::repeat_n(
            0u8,
            kubernix_types::wire::padding(contents.len()),
        ));
        w.write_str_sync(")");
        w
    }

    #[tokio::test]
    async fn nar_from_path_copies_the_raw_nar_after_draining_stderr() {
        let nar_bytes = small_regular_file_nar(b"hello");
        let mut reply = Vec::new();
        reply.write_u64_sync(STDERR_LAST);
        reply.extend_from_slice(&nar_bytes);

        let stream = FakeStream {
            to_read: std::io::Cursor::new(greeting_with(&reply)),
            written: Vec::new(),
        };
        let mut conn = DaemonConnection::open(stream).await.unwrap();
        let mut sink = Vec::new();
        conn.nar_from_path("/nix/store/xxx-foo", &mut sink)
            .await
            .unwrap();
        assert_eq!(sink, nar_bytes);
    }

    #[tokio::test]
    async fn add_to_store_nar_frames_the_body_and_terminates_with_a_zero_chunk() {
        let stream = FakeStream {
            to_read: std::io::Cursor::new(greeting_with(&{
                let mut r = Vec::new();
                r.write_u64_sync(STDERR_LAST);
                r
            })),
            written: Vec::new(),
        };
        let mut conn = DaemonConnection::open(stream).await.unwrap();
        let nar = b"some nar bytes, shorter than one chunk".to_vec();
        conn.add_to_store_nar(
            "/nix/store/xxx-foo",
            None,
            "sha256:abc",
            &[],
            0,
            nar.len() as u64,
            false,
            &[],
            None,
            nar.as_slice(),
        )
        .await
        .unwrap();

        // Inspect the tail of what was written: one framed chunk (length +
        // bytes) followed by a terminating zero-length chunk.
        let written = &conn.stream.written;
        let terminator = &written[written.len() - 8..];
        assert_eq!(u64::from_le_bytes(terminator.try_into().unwrap()), 0);

        let chunk_start = written.len() - 8 - nar.len() - 8;
        let chunk_len_bytes = &written[chunk_start..chunk_start + 8];
        assert_eq!(
            u64::from_le_bytes(chunk_len_bytes.try_into().unwrap()),
            nar.len() as u64
        );
        assert_eq!(
            &written[chunk_start + 8..chunk_start + 8 + nar.len()],
            &nar[..]
        );
    }
}
