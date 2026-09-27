//! Topic (one-way, no-reply) definitions. Replaces the old `PING` verb: the
//! guest now pushes a heartbeat on its own cadence instead of the worker
//! polling for one — see `worker/src/main.rs`'s heartbeat-staleness monitor
//! and `guest-agent/src/control.rs`'s publisher task.

use postcard_rpc::{TopicDirection, topics};
use postcard_schema::Schema;
use serde::{Deserialize, Serialize};

/// A guest-agent liveness pulse. `seq` is a plain incrementing counter — no
/// other content is needed, liveness is inferred from arrival alone, exactly
/// as the old stateless `PING` -> `OK` exchange carried no information either.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Schema)]
pub struct Heartbeat {
    pub seq: u64,
}

topics! {
    list = TOPICS_OUT_LIST;
    direction = TopicDirection::ToClient;
    | TopicTy         | MessageTy   | Path              |
    | ----------      | ---------   | ----              |
    | HeartbeatTopic   | Heartbeat   | "guest/heartbeat" |
}

topics! {
    list = TOPICS_IN_LIST;
    direction = TopicDirection::ToServer;
    | TopicTy        | MessageTy   | Path              |
    | ----------     | ---------   | ----              |
}
