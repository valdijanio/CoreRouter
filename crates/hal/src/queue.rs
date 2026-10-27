//! Queues (G4.9) as the data plane sees them: the plan the daemon's
//! `queue` service hands to the HAL ([`ShaperPlan`]: the queues that are not
//! subscriber sessions, their targets and the ports to shape on) and what
//! each queue counted ([`QueueCounters`]). A subscriber session's download
//! shaping rides on its session entry (`crate::pppoe::PppoeSession::shape`).

use corerouter_model::IfName;
use ipnet::IpNet;

pub mod lab;

/// What the queue of one direction does with what waits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Tail drop past `limit_bytes` (`pfifo` × 1514, `bfifo`).
    Fifo { limit_bytes: u64 },
    /// RFC 8289 on the wait (`fq-codel`, `cake`), at most `limit_packets`.
    Codel {
        target_us: u32,
        interval_us: u32,
        ecn: bool,
        limit_packets: u32,
    },
}

impl Default for Kind {
    /// RouterOS fq-codel defaults (the recommended dynamic queue).
    fn default() -> Self {
        Kind::Codel {
            target_us: 5_000,
            interval_us: 100_000,
            ecn: true,
            limit_packets: 10_240,
        }
    }
}

/// PCQ sub-streams of one direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcqSpec {
    /// Each sub-stream, bits per second (0: only the queue's own limit).
    pub rate_bps: u64,
    pub by_src: bool,
    pub mask4: u8,
    pub mask6: u8,
    pub kind: Kind,
}

/// One direction of a queue, RouterOS terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DirSpec {
    /// 0 = no limit.
    pub rate_bps: u64,
    pub burst_bps: u64,
    pub threshold_bps: u64,
    pub burst_time_ms: u32,
    /// Bucket, thousandths of a second of the rate (RouterOS `bucket-size`
    /// × 1000; 100 = 0.1).
    pub bucket_milli: u32,
    pub kind: Kind,
    pub pcq: Option<PcqSpec>,
}

/// One queue: `upload` is policed on the way in, `download` shaped on the
/// way out.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct QueueSpec {
    /// The engine's key (`*5`, `dhcp:10.0.0.7`): counters come back by it.
    pub key: String,
    pub upload: DirSpec,
    pub download: DirSpec,
}

/// Everything the shaper holds besides the sessions.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ShaperPlan {
    /// Index in this list = the queue's slot.
    pub queues: Vec<QueueSpec>,
    /// Address targets → queue index (no overlaps the engine did not
    /// resolve: longest prefix gives RouterOS's first match).
    pub prefixes: Vec<(IpNet, u32)>,
    /// Interface targets → queue index.
    pub interfaces: Vec<(IfName, u32)>,
    /// Ports whose egress (download) and ingress (upload) carry targets:
    /// the tc programs go there, with `fq` on their transmit queues.
    pub ports: Vec<IfName>,
    /// Subscriber sessions may be shaped (`bng0` and the access ports get
    /// the programs too).
    pub sessions: bool,
    /// Access ports of the subscriber services (their egress shapes the
    /// sessions).
    pub access_ports: Vec<IfName>,
}

impl ShaperPlan {
    pub fn is_empty(&self) -> bool {
        self.queues.is_empty() && !self.sessions
    }
}

/// What a queue counted, per direction (`upload` = from the target).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QueueCounters {
    pub bytes: [u64; 2],
    pub packets: [u64; 2],
    /// Dropped by the shaper (queue full, CoDel) or the policer.
    pub dropped: [u64; 2],
    /// How long a packet entering now waits, microseconds (the EDT
    /// backlog of the shaper; 0 for a policer).
    pub queued_us: [u64; 2],
    /// Over the last second, bits per second.
    pub rate_bps: [u64; 2],
    /// PCQ sub-streams (addresses) seen lately.
    pub pcq_queues: u32,
}

impl QueueCounters {
    pub const UPLOAD: usize = 0;
    pub const DOWNLOAD: usize = 1;
}

/// What the shaper said, for `queue.simple.list` and the monitor.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ShaperStatus {
    /// Counters by queue key.
    pub queues: Vec<(String, QueueCounters)>,
    /// The tc programs' reasons (`dataplane-ebpf-common::queue::Stat`),
    /// summed over CPUs; non-zero only.
    pub stats: Vec<(&'static str, u64)>,
    /// Ports the programs are attached to.
    pub ports: Vec<IfName>,
    /// Why there is no shaper, if there is none.
    pub unavailable: Option<String>,
}
