@0x8477b65ca68ca353;

# Internal frontend <-> worker messages. Unrelated to the Lix daemon protocol,
# which is vendored under protocol/vendor/ and spoken on the SSH surface.

enum JobStatus {
  pending @0;
  running @1;
  completed @2;
  failed @3;
}

# Published to kubernix.jobs.<system>.
struct BuildRequest {
  jobId          @0 :Text;
  derivationPath @1 :Text;
  system         @2 :Text;
  requiredInputs @3 :List(Text);
  # The serialized derivation, so the worker need not already have it.
  drv            @4 :Data;
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
}

struct UploadUrlResponse {
  # Parallel to the requested keys. Empty when errorMsg is set.
  urls     @0 :List(Text);
  errorMsg @1 :Text;
}

# Build logs are published to kubernix.logs.<job_id> as raw bytes: the subject
# already identifies the job, so no envelope is needed and the worker can forward
# builder output as it arrives.
