@0x8477b65ca68ca353;

# Internal frontend <-> worker messages. Unrelated to the Lix daemon protocol,
# which is vendored under protocol/vendor/ and spoken on the SSH surface.

enum JobStatus {
  pending @0;
  running @1;
  completed @2;
  failed @3;
}

# An input the client staged to the object store for this build. The worker
# fetches it and imports it before building.
struct InputRef {
  storePath @0 :Text;
  # Object key, holding a zstd-compressed bare NAR -- the same format every
  # other artifact uses. The worker wraps it into a Nix `--export` stream
  # locally, which is why the two fields below travel with it: importing a path
  # needs its references and deriver, and a bare NAR carries neither.
  key       @1 :Text;
  references @2 :List(Text);
  # Empty when unknown.
  deriver    @3 :Text;
}

# Published to kubernix.jobs.<system>.
struct BuildRequest {
  jobId          @0 :Text;
  derivationPath @1 :Text;
  system         @2 :Text;
  requiredInputs @3 :List(Text);
  # The serialized derivation, so the worker need not already have it.
  drv            @4 :Data;
  inputs         @5 :List(InputRef);
  # Whose build this is, per the worker's own claim -- informational only
  # (logging/debugging), never trusted: see `token` below.
  tenant         @6 :Text;
  # The signed capability token for this job -- a JWT's UTF-8 bytes, HMAC'd by
  # the frontend (`server/src/capability.rs`). The worker carries this opaquely
  # and hands it back with every upload/download URL request; it never needs
  # to parse it. PLAN.md Phase 14.
  token          @7 :Data;
}

struct BuildResponse {
  jobId  @0 :Text;
  status @1 :JobStatus;
}

# Everything the frontend needs to generate a narinfo for one output, and which
# it cannot recompute later because it never sees the build.
#
# Note the two distinct hash pairs: narHash/narSize describe the *uncompressed*
# NAR (what Nix verifies against), fileHash/fileSize the *compressed* object
# (what a client actually downloads). Both are computed in a single streaming
# pass by the worker.
struct OutputInfo {
  storePath   @0 :Text;
  narHash     @1 :Data;    # sha256 of the uncompressed NAR
  narSize     @2 :UInt64;
  fileHash    @3 :Data;    # sha256 of the compressed object
  fileSize    @4 :UInt64;
  # Object store key the compressed NAR was uploaded to.
  key         @5 :Text;
  compression @6 :Text;    # "zstd"
  references  @7 :List(Text);
  deriver     @8 :Text;
}

# Published to kubernix.results.<job_id>, after the artifacts are uploaded: a
# client that sees a completed result must be able to fetch the outputs.
struct JobResult {
  jobId       @0 :Text;
  status      @1 :JobStatus;
  outputPaths @2 :List(Text);
  logs        @3 :Text;
  errorMsg    @4 :Text;
  outputs     @5 :List(OutputInfo);
  # Object store key of the build log. Set on failure too -- a failed build's
  # log is the most useful thing it produced.
  logKey      @6 :Text;
}

# Request/reply on kubernix.uploads. The worker asks for permission to write
# specific keys; the frontend, which is the only holder of S3 credentials,
# answers with time-limited pre-signed PUT URLs. No credential ever reaches the
# worker -- what it receives is a narrow, expiring, per-object capability.
struct UploadUrlRequest {
  jobId @0 :Text;
  keys  @1 :List(Text);
  # When set, sign GETs instead of PUTs -- the same capability model in the
  # other direction, used to fetch staged inputs.
  download @2 :Bool;
  # The signed capability token minted for this job -- see `BuildRequest.token`.
  # This is the sole source of the tenant a request is authorized for: there
  # is no separate wire `tenant` field to trust or mistrust, so the frontend
  # logs the tenant it verifies out of this token rather than a claim carried
  # alongside it -- PLAN.md Phase 14.
  token @3 :Data;
}

struct UploadUrlResponse {
  # Parallel to the requested keys. Empty when errorMsg is set.
  urls     @0 :List(Text);
  errorMsg @1 :Text;
}

# Build logs are published to kubernix.logs.<job_id> as raw bytes: the subject
# already identifies the job, so no envelope is needed and the worker can forward
# builder output as it arrives.
