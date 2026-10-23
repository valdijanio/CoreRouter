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
    /// Lines of this round, written in one append at its end.
    pending: String,
    pending_lines: u64,
    /// No compaction before this after one failed (a full disk).
    retry_at: u64,
    /// The cap kept the journal from being compacted (logged once).
    held: bool,
}

/// A failed compaction is tried again after this.
const COMPACT_RETRY_SECS: u64 = 60;

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
        self.dhcp_history_flush();
    }

    /// Lines for the journal, written by [`Session::dhcp_history_flush`]
    /// (once per server round: one fsync for a storm of bindings).
    fn history_write(&mut self, entries: &[Entry]) {
        if entries.is_empty() {
            return;
        }
        let Some(rt) = self.ext_mut::<HistoryRuntime>() else {
            return;
        };
        for e in entries {
            if let Ok(l) = serde_json::to_string(e) {
                rt.pending.push_str(&l);
                rt.pending.push('\n');
                rt.pending_lines += 1;
            }
        }
    }

    /// The round's history lines, in one append.
    pub(crate) fn dhcp_history_flush(&mut self) {
        let Some((text, n)) = self.ext_mut::<HistoryRuntime>().and_then(|rt| {
            (rt.pending_lines > 0).then(|| (std::mem::take(&mut rt.pending), std::mem::take(&mut rt.pending_lines)))
        }) else {
            return;
        };
        let r = self.storage_mut().append_journal(JOURNAL, &text);
        if let Some(rt) = self.ext_mut::<HistoryRuntime>() {
            rt.appended += n;
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
                && now.unix >= rt.retry_at
                && (rt.appended > 2 * rt.history.len() as u64 + 1024
                    || now.unix >= rt.compacted_at + COMPACT_EVERY_SECS
                    || (retention == 0 && !rt.history.is_empty()))
        });
        if !due {
            return;
        }
        // Entries the memory cap dropped are on disk only: a compaction
        // (written from memory) would erase records still inside the
        // retention. The journal is kept whole until they are past it.
        let held = self
            .ext::<HistoryRuntime>()
            .and_then(|rt| (!rt.history.can_compact(now.unix, retention)).then(|| rt.history.evicted_until()))
            .flatten();
        if let Some(until) = held {
            let first = self.ext_mut::<HistoryRuntime>().is_some_and(|rt| {
                rt.compacted_at = now.unix;
                !std::mem::replace(&mut rt.held, true)
            });
            if first {
                let when = corerouter_proto_dhcp::server::history::utc(until.saturating_add(retention));
                let text = format!(
                    "lease history is over its memory cap ({} entries): its journal is kept whole, not compacted, until {when}",
                    corerouter_proto_dhcp::server::history::MAX_ENTRIES
                );
                log::error!("dhcp history: {text}");
                self.log_event(&["dhcp", "error"], "dhcp-server", text, serde_json::json!({}));
            }
            return;
        }
        if let Some(rt) = self.ext_mut::<HistoryRuntime>() {
            rt.held = false;
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
                Err(e) => {
                    rt.error = Some(e.to_string());
                    rt.retry_at = now.unix + COMPACT_RETRY_SECS;
                }
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
