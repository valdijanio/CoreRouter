//! Neighbor tables (G1.27d): keeps the engine's ARP/ND table from the
//! platform's events, on this service's own thread.
//!
//! One dump at start (and again when the kernel says it dropped events),
//! then every change as it happens (`RTNLGRP_NEIGH`): O(1) per change,
//! under the table's own lock, never the session's. The session lock is
//! taken only to log (alerts, at most once a second) and to read the few
//! settings that matter here (once a second).
//!
//! - **alerts**, arpwatch style: an address that answers from another MAC,
//!   and back ("flip flop": two hosts claim it), in the log under `arp`;
//! - **table nearly full**: past 80 % of `gc_thresh3` a warning with the
//!   thresholds that would leave room (RFC 6583 §6: an outside scan can
//!   fill the table and push real neighbors out);
//! - **reply-only** (Linux): what the kernel learns on such a port from
//!   requests to us is removed as it appears, so only static entries
//!   reach hosts, as in RouterOS.
//!
//! Why one thread: the kernel serializes the table's events into one
//! socket in order, and applying one costs well under a microsecond
//! (**medido**, `benches/neigh.rs`): a second thread would only add a lock.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use corerouter_engine::neigh_table::{Alert, AlertKind, NeighShared};
use corerouter_engine::{Shared, lock};
use corerouter_hal::neigh::{NeighEvent, NeighState, mac_text};
use corerouter_model::IfName;
use corerouter_model::arp::ArpMode;
use serde_json::json;

/// How long one read waits for events.
const WAIT_MS: u32 = 250;
/// Events applied per lock of the table (a burst is applied in slices,
/// so a list asked meanwhile waits for one slice, not the whole burst).
const BATCH: usize = 4096;
const SETTINGS_EVERY: Duration = Duration::from_secs(1);
const CEILING_EVERY: Duration = Duration::from_secs(10);
/// Alerts logged per second at most; the rest are counted in one line
/// (a spoofer flipping thousands of addresses must not flood the log).
const MAX_ALERT_LINES: usize = 20;

pub(crate) const SERVICE: super::Service = super::Service {
    name: "neighbors",
    flags: &[],
    topic: "arp",
    enable: "always on",
    depends: &[],
    start,
};

fn unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The session's clock (the platform's; the lab has its own) as an
/// offset from this machine's, read once a second with the settings:
/// the table's times must be the ones `ip.arp.list` subtracts from.
fn clock_offset(s: &corerouter_engine::Session) -> i64 {
    let theirs = s.neigh_clock().map_or(0, |t| i64::try_from(t).unwrap_or(0));
    let ours = i64::try_from(unix()).unwrap_or(0);
    if theirs == 0 { 0 } else { theirs - ours }
}

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let session = ctx.session.clone();
    Ok(Box::new(move |health: &super::Health| run(&session, health)))
}

fn run(session: &Shared, health: &super::Health) -> Result<(), String> {
    let (feed, shared, lab) = {
        let mut s = lock(session);
        let lab = s.backend().starts_with("virtual lab");
        (s.neighbor_feed(), s.neigh_shared(), lab)
    };
    let mut feed = match feed {
        Ok(f) => f,
        Err(e) => {
            // No table on this platform: the lists read per query.
            health.disabled(Some(&e));
            health.idle_until_shutdown();
            return Ok(());
        }
    };
    let mut state = State {
        shared,
        reply_only: BTreeSet::new(),
        statics: BTreeSet::new(),
        lab,
        warned_full: [false; 2],
        offset: 0,
    };
    state.offset = clock_offset(&lock(session));
    state.dump(feed.as_mut())?;
    health.event(format!("{} neighbors from {}", state.shared.lock().len(), feed.name()));
    let mut lost = feed.lost();
    let mut ev = Vec::with_capacity(BATCH);
    let mut settings_at = Instant::now() - SETTINGS_EVERY;
    let mut ceiling_at = Instant::now();
    let out = loop {
        if health.stopping() {
            break Ok(());
        }
        health.beat();
        ev.clear();
        if let Err(e) = feed.recv(WAIT_MS, BATCH, &mut ev) {
            break Err(e.to_string());
        }
        // The lab answers at once (it would spin); the kernel waits for
        // events itself.
        if lab && !health.sleep(Duration::from_millis(u64::from(WAIT_MS))) {
            break Ok(());
        }
        if settings_at.elapsed() >= SETTINGS_EVERY {
            settings_at = Instant::now();
            state.settings(session);
            state.log_alerts(session);
        }
        if !ev.is_empty() {
            state.enforce(&ev);
            state.shared.lock().apply(&ev, state.now());
        }
        if feed.lost() != lost {
            lost = feed.lost();
            state.shared.lock().lost = lost;
            health.error(format!("the kernel dropped neighbor events ({lost} times): read again"));
            if let Err(e) = state.dump(feed.as_mut()) {
                break Err(e);
            }
        }
        if ceiling_at.elapsed() >= CEILING_EVERY {
            ceiling_at = Instant::now();
            state.ceiling(session);
        }
    };
    state.shared.lock().fed = false;
    out
}

struct State {
    shared: NeighShared,
    reply_only: BTreeSet<IfName>,
    /// (interface, address) of the enabled static entries.
    statics: BTreeSet<(IfName, IpAddr)>,
    lab: bool,
    warned_full: [bool; 2],
    /// The session clock minus this machine's ([`clock_offset`]).
    offset: i64,
}

impl State {
    /// A full read, with no lock held; then swapped in at once.
    fn dump(&mut self, feed: &mut dyn corerouter_hal::neigh::NeighborFeed) -> Result<(), String> {
        let mut all = Vec::new();
        let complete = feed.dump(&mut all).map_err(|e| e.to_string())?;
        if !complete {
            log::warn!("neighbors: the table holds more than the engine keeps");
        }
        let mut t = self.shared.lock();
        t.load(all, self.now());
        t.fed = true;
        t.source = feed.name();
        Ok(())
    }

    fn now(&self) -> u64 {
        u64::try_from(i64::try_from(unix()).unwrap_or(0).saturating_add(self.offset)).unwrap_or(0)
    }

    fn settings(&mut self, session: &Shared) {
        let s = lock(session);
        self.offset = clock_offset(&s);
        let arp = &s.store().running().ip.arp;
        self.reply_only = arp
            .interfaces
            .iter()
            .filter(|(_, i)| i.mode == ArpMode::ReplyOnly)
            .map(|(n, _)| n.clone())
            .collect();
        self.statics = arp
            .entries
            .iter()
            .filter(|e| !e.disabled)
            .map(|e| (e.interface.clone(), IpAddr::V4(e.address)))
            .collect();
    }

    /// reply-only: a learned IPv4 entry on such a port goes at once.
    fn enforce(&self, ev: &[NeighEvent]) {
        if self.reply_only.is_empty() || self.lab {
            return;
        }
        let learned: Vec<(IfName, IpAddr)> = ev
            .iter()
            .filter_map(|e| match e {
                NeighEvent::Upsert(n) => Some(n),
                NeighEvent::Remove { .. } => None,
            })
            .filter(|n| n.address.is_ipv4() && self.reply_only.contains(&n.interface))
            .filter(|n| !matches!(n.state, NeighState::Permanent | NeighState::Noarp))
            .filter(|n| !self.statics.contains(&(n.interface.clone(), n.address)))
            .map(|n| (n.interface.clone(), n.address))
            .collect();
        if learned.is_empty() {
            return;
        }
        #[cfg(target_os = "linux")]
        if let Err(e) = corerouter_hal_linux::neigh::remove(&learned) {
            log::warn!("reply-only: removing learned entries: {e}");
        }
    }

    fn log_alerts(&mut self, session: &Shared) {
        let alerts = self.shared.lock().take_alerts();
        if alerts.is_empty() {
            return;
        }
        let mut s = lock(session);
        for a in alerts.iter().take(MAX_ALERT_LINES) {
            let (msg, detail) = alert_line(a);
            s.log_event(&["arp", "warning"], "neighbors", msg, detail);
        }
        if alerts.len() > MAX_ALERT_LINES {
            s.log_event(
                &["arp", "warning"],
                "neighbors",
                format!(
                    "{} more MAC changes in the last second (an ARP spoofer or a flapping host?)",
                    alerts.len() - MAX_ALERT_LINES
                ),
                json!({"count": alerts.len() - MAX_ALERT_LINES}),
            );
        }
    }

    /// Warn once when a table passes 80 % of its ceiling (and again after
    /// it went back under).
    fn ceiling(&mut self, session: &Shared) {
        let (n4, n6) = {
            let t = self.shared.lock();
            t.rows().iter().fold((0u64, 0u64), |(a, b), r| {
                if r.address.is_ipv4() { (a + 1, b) } else { (a, b + 1) }
            })
        };
        let mut s = lock(session);
        let ceil = s.neigh_ceiling();
        for (i, (fam, used)) in [("IPv4", n4), ("IPv6", n6)].into_iter().enumerate() {
            let Some(t3) = ceil.get(i).copied().flatten().filter(|t| *t > 0) else {
                continue;
            };
            let near = used.saturating_mul(100)
                >= t3.saturating_mul(corerouter_engine::neigh_table::NEAR_FULL_PCT);
            let Some(warned) = self.warned_full.get_mut(i) else { continue };
            if near && !*warned {
                let [a, b, c] = corerouter_engine::neigh_table::suggest_gc(used);
                let key = if i == 0 { "ipv4" } else { "ipv6" };
                s.log_event(
                    &["arp", "warning"],
                    "neighbors",
                    format!(
                        "{fam} neighbor table at {used} of {t3} (gc_thresh3): new hosts will be refused \
                         (neighbour table overflow). Suggested: system.tuning.set \
                         net.{key}.neigh.default.gc_thresh1={a} gc_thresh2={b} gc_thresh3={c}"
                    ),
                    json!({"family": key, "entries": used, "gc_thresh3": t3, "suggest": [a, b, c]}),
                );
            }
            *warned = near;
        }
    }
}

fn alert_line(a: &Alert) -> (String, serde_json::Value) {
    let (old, new) = (mac_text(a.old), mac_text(a.new));
    let msg = match a.kind {
        AlertKind::MacChanged => format!(
            "{} on {} changed MAC: {old} → {new}",
            a.address, a.interface
        ),
        AlertKind::FlipFlop => format!(
            "{} on {} flip-flops between {old} and {new}: two hosts claim the address \
             (duplicate IP or ARP spoofing)",
            a.address, a.interface
        ),
    };
    let detail = json!({
        "kind": a.kind,
        "address": a.address.to_string(),
        "interface": a.interface.as_str(),
        "old": old,
        "new": new,
    });
    (msg, detail)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alert_lines_name_both_macs() {
        let a = Alert {
            kind: AlertKind::FlipFlop,
            interface: "ether1".parse().unwrap(),
            address: "10.0.0.2".parse().unwrap(),
            old: [2, 0, 0, 0, 0, 1],
            new: [2, 0, 0, 0, 0, 2],
            time: 0,
        };
        let (msg, detail) = alert_line(&a);
        assert!(msg.contains("02:00:00:00:00:01") && msg.contains("duplicate IP"), "{msg}");
        assert_eq!(detail["kind"], "flip-flop");
    }
}
