//! Queues (G4.9) as the data plane sees them: what each queue counted.
//! The plan the daemon's `queue` service hands to the HAL comes with the
//! shaper (G4.9b).

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
