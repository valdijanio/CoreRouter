//! G1.6w: how `/config` is shared. The image's `/config` is small (56 MB on
//! the lab VM) and has to take the running config and its two slots, the
//! journal and the package snapshots before any history: each history has a
//! ceiling that is a share of the filesystem, the way journald caps itself
//! at 10 % of its filesystem (`SystemMaxUse`). What does not fit goes,
//! oldest first, with a line in the log and a health item; the running
//! config and the revision before it (the last good one, the target of a
//! rollback) never go.
//!
//! The engine does no I/O: the daemon measures the filesystem once at boot
//! ([`Session::set_config_capacity`]). No capacity (no `--config-dir`, the
//! GUI, wasm): only the older fixed ceilings apply. The log files (G4.6g)
//! have a share too, and stop before they take the room of the config
//! ([`keep_free`]).

use corerouter_model::persist;
use serde::Serialize;
use serde_json::{Value, json};

use crate::Session;
use crate::graph::GraphDb;
use crate::history_files::RevisionFiles;

/// Revision files, at most this much of `/config`.
pub const HISTORY_PERCENT: u64 = 10;
/// Graph files (`graphs/*.rrd`), at most this much of `/config`.
pub const GRAPHS_PERCENT: u64 = 25;

/// Log files (the `disk` action), at most this much of `/config`.
pub const LOG_PERCENT: u64 = 5;
/// Their ceiling whatever the disk, and without a disk measured.
pub const LOG_MAX_BYTES: u64 = 64 << 20;
pub const LOG_DEFAULT_BYTES: u64 = 16 << 20;
/// The DNS query log (G4.1zd), at most this much of `/config` (and at most
/// its `max_size_mib`).
pub const DNS_LOG_PERCENT: u64 = 20;
/// Its ceiling without a disk measured.
pub const DNS_LOG_DEFAULT_BYTES: u64 = 64 << 20;

/// The DNS query log's ceiling: `max_size_mib`, within its share.
pub fn dns_log_budget(capacity: Option<u64>, max_size_mib: u32) -> u64 {
    let wanted = u64::from(max_size_mib) << 20;
    wanted.min(capacity.map_or(DNS_LOG_DEFAULT_BYTES, |c| share(c, DNS_LOG_PERCENT)))
}

/// What the log leaves free of `/config`: this much of it, ...
pub const KEEP_FREE_PERCENT: u64 = 10;
/// ... and this many times the slot of the running config (the next save
/// needs one more beside the two there: G1.6wa).
pub const KEEP_FREE_SLOTS: u64 = 3;

/// Bytes the log files must leave free on a `capacity` disk holding a slot
/// of `slot` bytes: encher o disco não pode impedir gravar a configuração.
pub fn keep_free(capacity: u64, slot: u64) -> u64 {
    share(capacity, KEEP_FREE_PERCENT).max(slot.saturating_mul(KEEP_FREE_SLOTS))
}

/// The log files' ceiling on a disk of `capacity` bytes.
pub fn log_budget(capacity: Option<u64>) -> u64 {
    capacity.map_or(LOG_DEFAULT_BYTES, |c| share(c, LOG_PERCENT).min(LOG_MAX_BYTES))
}

/// `percent` of `capacity`, in bytes.
pub fn share(capacity: u64, percent: u64) -> u64 {
    capacity / 100 * percent
}

/// What the session knows of the disk (`Session::ext`).
#[derive(Debug, Default, Clone, Copy, Serialize)]
pub struct ConfigDisk {
    /// Size of the filesystem of the config directory, in bytes.
    pub capacity: Option<u64>,
    /// Bytes of the revision files, after the last save.
    pub history_bytes: u64,
}

impl ConfigDisk {
    /// The revision files' ceiling in bytes.
    pub fn history_budget(&self) -> usize {
        self.capacity.map_or(persist::SAVE_BUDGET_BYTES, |c| {
            usize::try_from(share(c, HISTORY_PERCENT)).map_or(persist::SAVE_BUDGET_BYTES, |b| b.min(persist::SAVE_BUDGET_BYTES))
        })
    }
}

/// `5.6 MiB`.
pub fn mib(bytes: u64) -> String {
    format!("{:.1} MiB", bytes as f64 / f64::from(1u32 << 20))
}

/// What the `config_disk` health check and `system.config-disk.print` look at.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Usage {
    pub capacity: u64,
    pub history_bytes: u64,
    pub history_budget: u64,
    pub revisions_saved: usize,
    pub revisions_not_saved: usize,
    pub graph_bytes: u64,
    pub graph_budget: u64,
    /// Series the graph cap left out because of `/config`, not of
    /// `max_memory_mib`.
    pub graph_refused: usize,
    /// Old graph files deleted to stay under the share.
    pub graph_removed: usize,
    pub log_bytes: u64,
    pub log_budget: u64,
    /// Lines that never reached a log file.
    pub log_dropped: u64,
    /// The log writer's last error.
    pub log_error: Option<String>,
}

impl Session {
    /// The size of the config directory's filesystem (the daemon, at boot).
    /// A history already past its share (a config directory from before
    /// G1.6w, or a smaller disk) is cut now, not at the next commit.
    pub fn set_config_capacity(&mut self, capacity: Option<u64>) {
        let saved = self.ext::<RevisionFiles>().map_or(0, RevisionFiles::saved_bytes);
        let Some(d) = self.ext_mut::<ConfigDisk>() else { return };
        d.capacity = capacity;
        d.history_bytes = saved as u64;
        let budget = d.history_budget();
        if let Some(db) = self.ext_mut::<GraphDb>() {
            db.set_disk_cap(capacity.map(|c| share(c, GRAPHS_PERCENT)));
        }
        if saved > budget {
            self.save();
        }
    }

    /// The disk's numbers (`None`: the daemon did not measure a disk).
    pub fn config_disk_usage(&self) -> Option<Usage> {
        let d = self.ext::<ConfigDisk>()?;
        let capacity = d.capacity?;
        let graphing = &self.store().running().system.graphing;
        let (graph_bytes, graph_refused, graph_removed) = self.ext::<GraphDb>().map_or((0, 0, 0), |g| {
            let refused = if g.cap_is_disk(graphing) {
                g.refused().len().saturating_add(g.refused_queues())
            } else {
                0
            };
            (g.memory_bytes(), refused, g.disk.removed)
        });
        let not_saved = self.storage_status().revisions_not_saved;
        let log = self.ext::<crate::logging::LogBook>().map(|b| b.disk.clone()).unwrap_or_default();
        Some(Usage {
            capacity,
            history_bytes: d.history_bytes,
            history_budget: d.history_budget() as u64,
            revisions_saved: self.store().history().len().saturating_sub(not_saved),
            revisions_not_saved: not_saved,
            graph_bytes,
            graph_budget: share(capacity, GRAPHS_PERCENT),
            graph_refused,
            graph_removed,
            log_bytes: log.bytes,
            log_budget: log_budget(Some(capacity)),
            log_dropped: log.lines_dropped,
            log_error: log.last_error,
        })
    }

    /// `system.config-disk.print`.
    pub(crate) fn config_disk_json(&self) -> Value {
        let Some(u) = self.config_disk_usage() else {
            return json!({"capacity_bytes": null});
        };
        json!({
            "capacity_bytes": u.capacity,
            "history": {
                "bytes": u.history_bytes,
                "budget_bytes": u.history_budget,
                "percent": HISTORY_PERCENT,
                "revisions_saved": u.revisions_saved,
                "revisions_not_saved": u.revisions_not_saved,
            },
            "graphs": {
                "bytes": u.graph_bytes,
                "budget_bytes": u.graph_budget,
                "percent": GRAPHS_PERCENT,
                "refused": u.graph_refused,
                "removed": u.graph_removed,
            },
            "log": {
                "bytes": u.log_bytes,
                "budget_bytes": u.log_budget,
                "percent": LOG_PERCENT,
                "lines_dropped": u.log_dropped,
                "last_error": u.log_error,
            },
        })
    }
}
