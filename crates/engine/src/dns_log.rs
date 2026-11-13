//! The DNS query log (G4.1zd) as the engine sees it. The daemon writes the
//! files (`service/dns_log.rs`: a thread, the disk) and registers itself
//! here with [`Session::set_dns_log_backend`]; `ip.dns.log.print`,
//! `export` and `clear` reach the files through it, outside the session
//! lock. Without a daemon (headless lab, WASM, tests) nothing is written
//! and the commands say so.

use std::sync::Arc;

use corerouter_proto_dns::querylog::format::{Mode, Record};
use corerouter_proto_dns::querylog::{ClientMatch, Filter};

use crate::Session;

/// How the writer is doing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogStatus {
    /// Queries are being written now.
    pub writing: bool,
    /// Why they are not, when the log is on (no disk, disk full…).
    pub reason: Option<String>,
    /// Files and bytes on disk, and the oldest and newest query (unix ms).
    pub files: u32,
    pub bytes: u64,
    pub oldest_ms: Option<u64>,
    pub newest_ms: Option<u64>,
    /// Queries written to disk since the daemon started.
    pub written: u64,
    /// Bytes written for them (compressed), for the bytes-per-query average.
    pub written_bytes: u64,
    /// Queries the writer could not keep: its queue was full / no room.
    pub dropped_queue: u64,
    pub dropped_disk: u64,
    /// The ceiling in force (`max_size_mib` and the share of `/config`).
    pub budget_bytes: u64,
    /// Files deleted for age or size since the daemon started.
    pub rotated: u64,
}

/// What a search found.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Found {
    /// Newest first, each with how its block wrote clients.
    pub rows: Vec<(Record, Mode)>,
    /// Where to go on (older rows); `None`: nothing older matched.
    pub next: Option<String>,
    /// Queries looked at.
    pub scanned: u64,
    /// The scan stopped at its budget before `limit` rows: `next` goes on.
    pub partial: bool,
}

/// What `clear` removed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cleared {
    pub files: u32,
    pub bytes: u64,
    pub queries: u64,
}

/// What the daemon's writer offers. Implementations never lock the
/// session (the files are theirs).
pub trait DnsLogBackend: Send + Sync {
    fn status(&self) -> LogStatus;
    /// At most `limit` rows matching `filter`, newest first, from `cursor`
    /// (a previous [`Found::next`]) on, looking at most at `budget`
    /// queries.
    fn search(&self, filter: &Filter, limit: usize, cursor: Option<&str>, budget: u64) -> Result<Found, String>;
    /// Removes the queries before `before_ms` (unix ms) and/or those of
    /// `client`; both `None`: everything.
    fn clear(&self, before_ms: Option<u64>, client: Option<&ClientMatch>) -> Result<Cleared, String>;
}

#[derive(Default)]
struct DnsLogRuntime {
    backend: Option<Arc<dyn DnsLogBackend>>,
}

impl Session {
    pub fn set_dns_log_backend(&mut self, backend: Arc<dyn DnsLogBackend>) {
        if let Some(rt) = self.ext_mut::<DnsLogRuntime>() {
            rt.backend = Some(backend);
        }
    }

    pub fn dns_log_backend(&self) -> Option<Arc<dyn DnsLogBackend>> {
        self.ext::<DnsLogRuntime>()?.backend.clone()
    }
}
