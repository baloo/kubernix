@0x8477b65ca68ca353;

enum JobStatus {
  pending @0;
  running @1;
  completed @2;
  failed @3;
}

struct BuildRequest {
  jobId          @0 :Text;
  derivationPath @1 :Text;
  system         @2 :Text;
  requiredInputs @3 :List(Text);
}

struct BuildResponse {
  jobId  @0 :Text;
  status @1 :JobStatus;
}

struct JobResult {
  jobId       @0 :Text;
  status      @1 :JobStatus;
  outputPaths @2 :List(Text);
  logs        @3 :Text;
}
