//! When each link last went up and down (G1.19, RouterOS
//! `last-link-up-time` / `last-link-down-time`). The kernel counts carrier
//! transitions but keeps no times, so the engine notes them whenever it
//! sees link state with a clock: every [`Session::tick`] (the daemon's and
//! the native GUI's clock thread, once a second) and every `interface.list`.
//! Operational state: never saved, gone after a restart.

use std::collections::{BTreeMap, BTreeSet};

use corerouter_hal::LinkState;
use corerouter_model::IfName;

use crate::Session;

/// Links followed at most (the same bound as the kernel link dump would
/// need to be hostile to pass).
const MAX_WATCHED: usize = 4096;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LinkTimes {
    pub running: bool,
    /// Unix seconds; `None`: not seen since watching began.
    pub last_up: Option<u64>,
    pub last_down: Option<u64>,
    /// Downs seen by the engine (for platforms that do not count them).
    pub downs: u32,
}

#[derive(Debug, Clone, Default)]
pub struct LinkWatch {
    /// First time links were seen with a clock.
    pub since: Option<u64>,
    links: BTreeMap<IfName, LinkTimes>,
}

impl LinkWatch {
    /// Note the state of `live` at `now`. A link first seen running is
    /// "up since before watching began" (`last_up` stays `None`).
    pub fn observe(&mut self, live: &[LinkState], now: u64) {
        self.since.get_or_insert(now);
        for l in live {
            let full = self.links.len() >= MAX_WATCHED;
            match self.links.get_mut(&l.name) {
                Some(t) if t.running != l.running => {
                    t.running = l.running;
                    if l.running {
                        t.last_up = Some(now);
                    } else {
                        t.last_down = Some(now);
                        t.downs = t.downs.saturating_add(1);
                    }
                }
                Some(_) => {}
                None if !full => {
                    self.links.insert(
                        l.name.clone(),
                        LinkTimes {
                            running: l.running,
                            ..LinkTimes::default()
                        },
                    );
                }
                None => {}
            }
        }
        // Links gone from the platform are forgotten (a set: a scan of
        // `live` per watched link was O(watched × live) every second).
        let present: BTreeSet<&IfName> = live.iter().map(|l| &l.name).collect();
        self.links.retain(|n, _| present.contains(n));
    }

    pub fn get(&self, name: &IfName) -> Option<&LinkTimes> {
        self.links.get(name)
    }

    /// Links last seen without carrier (G1.27: their routes are inactive).
    pub fn down_links(&self) -> Vec<IfName> {
        self.links
            .iter()
            .filter(|(_, t)| !t.running)
            .map(|(n, _)| n.clone())
            .collect()
    }
}

impl Session {
    /// Note link transitions if there is a clock (see the module docs).
    pub(crate) fn watch_links(&mut self, live: &[LinkState]) {
        if let Some(now) = self.now() {
            self.links.observe(live, now);
        }
    }

    /// Poll the platform and note link transitions (from `tick`).
    pub(crate) fn poll_links(&mut self) {
        let live = self.hal_mut().poll();
        self.watch_links(&live);
        // G1.6t: a card plugged in with the router running joins the config.
        self.adopt_new_ports(&live);
        // G4.5: the same poll feeds the traffic graphs.
        self.graph_sample(&live);
        // G1.29c: finished USB recoveries; configuration back on a
        // recreated port.
        self.usb_tick(&live);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st(name: &str, running: bool) -> LinkState {
        LinkState {
            name: name.parse().unwrap(),
            running,
            rx_bytes: 0,
            tx_bytes: 0,
            rx_packets: 0,
            tx_packets: 0,
            kind: "ether".into(),
            mtu: 1500,
            mac: None,
            bus: None,
            unmanaged: None,
            errors: None,
        }
    }

    #[test]
    fn notes_transitions_and_forgets_gone_links() {
        let mut w = LinkWatch::default();
        let e1: IfName = "ether1".parse().unwrap();
        w.observe(&[st("ether1", true), st("ether2", false)], 100);
        assert_eq!(w.since, Some(100));
        assert_eq!(w.get(&e1).unwrap().last_up, None, "up before watching");
        w.observe(&[st("ether1", false), st("ether2", false)], 105);
        let t = *w.get(&e1).unwrap();
        assert_eq!((t.last_down, t.downs, t.running), (Some(105), 1, false));
        w.observe(&[st("ether1", true)], 107);
        let t = *w.get(&e1).unwrap();
        assert_eq!((t.last_up, t.last_down, t.downs), (Some(107), Some(105), 1));
        assert!(w.get(&"ether2".parse().unwrap()).is_none());
        assert_eq!(w.since, Some(100));
    }
}
