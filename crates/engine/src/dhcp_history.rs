//! Lease history at run time (G4.2b): the server's bindings, one entry
//! each (`proto_dhcp::server::history`), in their own journal
//! (`journal-dhcp-history.log`) kept for `ip.dhcp-server.config
//! history_retention` (a year by default). Operational state, never in a
//! revision.

use std::net::Ipv4Addr;

use corerouter_proto_dhcp::server::Now;
use corerouter_proto_dhcp::server::history::{Entry, History};
use corerouter_proto_dhcp::server::leases::{Lease, State};

use crate::Session;

/// The journal's name (`journal-dhcp-history.log`).
pub const JOURNAL: &str = "dhcp-history";
/// Compact at least once a day.
const COMPACT_EVERY_SECS: u64 = 86_400;

#[derive(Default)]
pub struct HistoryRuntime {
    history: History,
    loaded: bool,
    appended: u64,
    compacted_at: u64,
    error: Option<String>,
}

impl Session {
    fn history_retention(&self) -> u64 {
        u64::from(self.store().running().ip.dhcp_server.config.history_retention)
    }

    /// Load the journal once (after the leases, to close what ended while
    /// the daemon was down).
    pub(crate) fn dhcp_history_load(&mut self, now: Now) {
        if self.ext::<HistoryRuntime>().is_none_or(|h| h.loaded) {
            return;
        }
        let Some(bound) = self.dhcp_server().map(|c| {
            c.leases()
                .iter()
                .filter(|l| l.state == State::Bound)
                .map(|l| (l.address, l.mac))
                .collect::<Vec<_>>()
        }) else {
            return;
        };
        let text = self.storage_mut().load_journal(JOURNAL);
        let mut settled = Vec::new();
        if let Some(rt) = self.ext_mut::<HistoryRuntime>() {
            rt.loaded = true;
            rt.compacted_at = now.unix;
            match text {
                Ok(Some(t)) => {
                    rt.appended = t.lines().count() as u64;
                    let bad = rt.history.replay(t.lines());
                    if bad > 0 {
                        log::warn!("dhcp history: {bad} unreadable journal lines skipped");
                    }
                }
                Ok(None) => {}
                Err(e) => rt.error = Some(e.to_string()),
            }
            settled = rt.history.settle(|a, m| bound.contains(&(a, m)));
        }
        self.history_write(&settled);
    }

    fn history_write(&mut self, entries: &[Entry]) {
        if entries.is_empty() {
            return;
        }
        let mut text = String::new();
        for e in entries {
            if let Ok(l) = serde_json::to_string(e) {
                text.push_str(&l);
                text.push('\n');
            }
        }
        let r = self.storage_mut().append_journal(JOURNAL, &text);
        if let Some(rt) = self.ext_mut::<HistoryRuntime>() {
            rt.appended += entries.len() as u64;
            rt.error = r.err().map(|e| e.to_string());
        }
    }

    /// A lease was bound (`new`) or renewed.
    pub(crate) fn dhcp_history_bound(&mut self, l: &Lease, new: bool, now: Now) {
        if self.history_retention() == 0 {
            return;
        }
        let lines = match self.ext_mut::<HistoryRuntime>() {
            Some(rt) if new => rt.history.open(l, now.unix),
            Some(rt) => rt.history.renew(l),
            None => Vec::new(),
        };
        self.history_write(&lines);
    }

    /// The lease of `address` ended.
    pub(crate) fn dhcp_history_gone(&mut self, address: Ipv4Addr, now: Now) {
        let lines = self
            .ext_mut::<HistoryRuntime>()
            .map(|rt| rt.history.close(address, now.unix))
            .unwrap_or_default();
        self.history_write(&lines);
    }

    /// Drop what is past the retention and rewrite the journal, daily or
    /// when it has grown to twice the entries.
    pub(crate) fn dhcp_history_compact(&mut self, now: Now) {
        let retention = self.history_retention();
        let due = self.ext::<HistoryRuntime>().is_some_and(|rt| {
            rt.loaded
                && (rt.appended > 2 * rt.history.len() as u64 + 1024
                    || now.unix >= rt.compacted_at + COMPACT_EVERY_SECS
                    || (retention == 0 && !rt.history.is_empty()))
        });
        if !due {
            return;
        }
        let Some(text) = self
            .ext_mut::<HistoryRuntime>()
            .map(|rt| rt.history.compact(now.unix, retention))
        else {
            return;
        };
        let lines = text.lines().count() as u64;
        let r = self.storage_mut().rewrite_journal(JOURNAL, &text);
        if let Some(rt) = self.ext_mut::<HistoryRuntime>() {
            rt.compacted_at = now.unix;
            match r {
                Ok(()) => rt.appended = lines,
                Err(e) => rt.error = Some(e.to_string()),
            }
        }
    }

    /// The history, once loaded.
    pub fn dhcp_lease_history(&self) -> Option<&History> {
        self.ext::<HistoryRuntime>().filter(|h| h.loaded).map(|h| &h.history)
    }

    pub fn dhcp_lease_history_error(&self) -> Option<String> {
        self.ext::<HistoryRuntime>().and_then(|h| h.error.clone())
    }
}
