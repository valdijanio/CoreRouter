//! Ports of the config that the platform does not have (G1.3b): unplugged,
//! a USB adapter that fell off, a card that burned. The backend applies the
//! config without them (`corerouter_hal::absent`), so the rest comes up, the
//! management address on another port above all; here the engine shows
//! them `invalid` (the RouterOS `I` flag) in `interface.list` and in the
//! health check, notes in the log when one goes and comes back, and puts
//! the configuration back on one that returned.

use std::collections::{BTreeMap, BTreeSet};

use corerouter_hal::LinkState;
use corerouter_model::{Config, IfName, InterfaceKind};
use serde_json::json;

use crate::Session;

/// Seconds a port may be gone before the log warns (G1.6zr). A USB
/// adapter that switches its configuration at boot (the r8152's
/// `r8152-cfgselector`) drops off for 2–4 s (**medido** on a notebook:
/// two warnings and two "port is back" in 10 s); back within the grace, it
/// is one info line ("replugged"). `interface.list` and the health check
/// show it invalid at once all the same.
pub const WARN_AFTER_SECS: u64 = 10;

/// What the log already said, so each change is logged once.
#[derive(Debug, Default)]
struct Absence {
    /// Ports last seen absent.
    gone: BTreeSet<IfName>,
    /// Since when (engine clock, s) each of `gone` is gone; `None`: no clock.
    since: BTreeMap<IfName, Option<u64>>,
    /// Ports whose absence was logged as a warning.
    warned: BTreeSet<IfName>,
    /// The last failure to put a returned port's configuration back.
    error: Option<String>,
}

/// Why each interface of `cfg` is invalid: a physical port in `absent` not
/// back in `live`, and every VLAN stacked on one (at any depth).
pub(crate) fn invalid(cfg: &Config, absent: &[IfName], live: &[LinkState]) -> BTreeMap<IfName, String> {
    let present: BTreeSet<&IfName> = live.iter().map(|l| &l.name).collect();
    let mut out: BTreeMap<IfName, String> = absent
        .iter()
        .filter(|n| !present.contains(n))
        // G1.30: a radio is hardware too (a USB adapter pulled out).
        .filter_map(|n| match cfg.interfaces.get(n).map(|i| &i.kind) {
            Some(InterfaceKind::Ethernet | InterfaceKind::Wifi(_)) => Some((
                n.clone(),
                "port not on this machine (unplugged or failed): its configuration waits for it".to_owned(),
            )),
            // G1.30m: a peer's link is there while the peer is associated.
            Some(InterfaceKind::WifiPeer(p)) => Some((
                n.clone(),
                format!("peer not associated with '{}': its configuration waits for it", p.radio),
            )),
            _ => None,
        })
        .collect();
    if out.is_empty() {
        return out;
    }
    // Each pass adds at least one VLAN or stops: bounded by the
    // interface count, so a cyclic (hand-edited) config cannot loop.
    for _ in 0..=cfg.interfaces.len() {
        let more: Vec<(IfName, String)> = cfg
            .interfaces
            .values()
            .filter(|i| !out.contains_key(&i.name))
            .filter_map(|i| match &i.kind {
                InterfaceKind::Vlan { parent, .. } if out.contains_key(parent) => {
                    Some((i.name.clone(), format!("its parent '{parent}' is not on this machine")))
                }
                _ => None,
            })
            .collect();
        if more.is_empty() {
            break;
        }
        out.extend(more);
    }
    out
}

impl Session {
    /// The invalid interfaces of the running config, with why (see [`invalid`]).
    pub(crate) fn invalid_interfaces(&self, live: &[LinkState]) -> BTreeMap<IfName, String> {
        invalid(self.store().running(), &self.hal().absent_ports(), live)
    }

    /// G1.3d: the platform says these links were created, removed or
    /// changed (`None`: it dropped events, look at all). When one is a
    /// physical port of the running config, poll now instead of on the next
    /// tick, so a port replugged gets its configuration back at once. A
    /// commit's own changes land here too: that poll finds nothing new.
    pub fn link_events(&mut self, names: Option<&[String]>) {
        if self.link_events_wanted(names) {
            self.link_events_sampled(None);
        }
    }

    /// Whether the links `names` (`None`: unknown, all) are worth a look
    /// (see [`Session::link_events`]): one of them is a physical port of
    /// the running config.
    pub fn link_events_wanted(&self, names: Option<&[String]>) -> bool {
        let running = self.store().running();
        names.is_none_or(|names| {
            names.iter().any(|n| {
                n.parse::<IfName>()
                    .ok()
                    .and_then(|n| running.interfaces.get(&n))
                    .is_some_and(|i| matches!(i.kind, InterfaceKind::Ethernet | InterfaceKind::WifiPeer(_)))
            })
        })
    }

    /// The look of [`Session::link_events`], with the links a
    /// [`Session::link_reader`] read while the session was unlocked
    /// (G1.3f); `None`: poll here.
    pub fn link_events_sampled(&mut self, links: Option<corerouter_hal::link_reader::LinkSample>) {
        let snapshot = self.store().candidate().clone();
        let polled = crate::guard::run("link events", || {
            let live = self.live_links(links);
            self.watch_links(&live);
            self.absent_tick(&live);
            Ok(())
        });
        if polled.is_err() {
            self.store_mut().set_candidate(snapshot);
        }
    }

    /// Every poll (from `tick`): log ports that went and came back, and
    /// put the configuration back on those that came back. A failure is
    /// tried again on the next poll and logged when its text changes.
    pub(crate) fn absent_tick(&mut self, live: &[LinkState]) {
        let absent = self.hal().absent_ports();
        let empty = self.ext::<Absence>().is_none_or(|a| a.gone.is_empty() && a.error.is_none());
        if absent.is_empty() && empty {
            return;
        }
        let now = self.clock_secs();
        let present: BTreeSet<&IfName> = live.iter().map(|l| &l.name).collect();
        let gone: BTreeSet<IfName> = absent.iter().filter(|n| !present.contains(n)).cloned().collect();
        let back: Vec<IfName> = absent.iter().filter(|n| present.contains(n)).cloned().collect();
        let (went, returned, replugged) = match self.ext_mut::<Absence>() {
            Some(a) => {
                for n in gone.difference(&a.gone) {
                    a.since.insert(n.clone(), now);
                }
                let returned: Vec<IfName> = a.gone.difference(&gone).cloned().collect();
                // G1.6zr: warn once a port has been gone for the grace
                // (at once without a clock).
                let went: Vec<IfName> = gone
                    .iter()
                    .filter(|n| !a.warned.contains(*n))
                    .filter(|n| match (now, a.since.get(*n).copied().flatten()) {
                        (Some(now), Some(at)) => now.saturating_sub(at) >= WARN_AFTER_SECS,
                        _ => true,
                    })
                    .cloned()
                    .collect();
                a.warned.extend(went.iter().cloned());
                // G1.3d: back without ever being seen gone: replugged
                // between two polls (the backend saw a new link). G1.6zr:
                // or back within the grace, never warned about.
                let replugged: BTreeMap<IfName, Option<u64>> = back
                    .iter()
                    .filter(|n| !a.warned.contains(*n))
                    .map(|n| {
                        let gone_for = match (now, a.since.get(n).copied().flatten()) {
                            (Some(now), Some(at)) if a.gone.contains(n) => Some(now.saturating_sub(at)),
                            _ => None,
                        };
                        (n.clone(), gone_for)
                    })
                    .collect();
                for n in &returned {
                    a.since.remove(n);
                    a.warned.remove(n);
                }
                a.gone = gone;
                (went, returned, replugged)
            }
            None => return,
        };
        for n in went {
            self.log_event(
                &["interface", "warning"],
                "interface",
                format!("{n}: port not on this machine; its configuration waits for it (invalid)"),
                json!({ "interface": n }),
            );
        }
        for n in &returned {
            if !back.contains(n) {
                // Gone from the config meanwhile: nothing waits for it.
                self.log_event(&["interface", "info"], "interface", format!("{n}: absent port no longer in the configuration"), json!({ "interface": n }));
            }
        }
        // Nothing of the boot apply went in: its retry puts it all back.
        // With only some sections out, they stay out (G1.3g: the port got
        // its config back only once every section was in).
        if back.is_empty() || self.boot_core_out() {
            return;
        }
        let cfg = self.effective(self.store().running()).into_owned();
        let tried = crate::guard::run("put back a returned port", || {
            self.apply_side(&cfg, &cfg).map_err(|e| crate::EngineError::Hal(e.to_string()))
        });
        match tried {
            Ok(()) => {
                if let Some(a) = self.ext_mut::<Absence>() {
                    a.error = None;
                }
                for n in back {
                    let msg = if let Some(gone_for) = replugged.get(&n) {
                        let within = match gone_for {
                            Some(s) if *s > 0 => format!("gone {s} s"),
                            _ => "gone and back within a second".to_owned(),
                        };
                        format!("{n}: port was replugged ({within}); its configuration was applied again")
                    } else {
                        format!("{n}: port is back; its configuration was applied")
                    };
                    self.log_event(&["interface", "info"], "interface", msg, json!({ "interface": n }));
                }
            }
            Err(e) => {
                let e = e.to_string();
                let changed = self.ext_mut::<Absence>().is_some_and(|a| {
                    let changed = a.error.as_deref() != Some(e.as_str());
                    a.error = Some(e.clone());
                    changed
                });
                if changed {
                    let names: Vec<&str> = back.iter().map(IfName::as_str).collect();
                    self.log_event(
                        &["interface", "error"],
                        "interface",
                        format!("{}: port is back but its configuration was not applied (retried every second): {e}", names.join(", ")),
                        json!({ "interfaces": names }),
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_model::Interface;
    use corerouter_model::types::VlanId;

    fn n(s: &str) -> IfName {
        s.parse().unwrap()
    }

    fn live(name: &str) -> LinkState {
        LinkState {
            name: n(name),
            running: true,
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
    fn absent_port_and_its_vlans_are_invalid() {
        let mut c = Config::default();
        for p in ["ether1", "ether2"] {
            c.interfaces.insert(n(p), Interface::new(n(p), InterfaceKind::Ethernet));
        }
        let vlan = |name: &str, parent: &str| {
            Interface::new(n(name), InterfaceKind::Vlan { parent: n(parent), vlan_id: VlanId::new(10).unwrap(), service_tag: false })
        };
        c.interfaces.insert(n("v10"), vlan("v10", "ether2"));
        c.interfaces.insert(n("v20"), vlan("v20", "v10"));
        c.interfaces.insert(n("v30"), vlan("v30", "ether1"));
        let bad = invalid(&c, &[n("ether2")], &[live("ether1")]);
        assert_eq!(bad.keys().map(IfName::as_str).collect::<Vec<_>>(), ["ether2", "v10", "v20"]);
        assert!(bad[&n("v20")].contains("'v10'"));
        // Back in the poll (configuration not put back yet): not invalid.
        assert!(invalid(&c, &[n("ether2")], &[live("ether1"), live("ether2")]).is_empty());
        // A name the backend reports that is not a port of the config.
        assert!(invalid(&c, &[n("v30")], &[]).is_empty());
    }

    fn row(s: &mut Session, name: &str) -> serde_json::Value {
        let rows = s.execute("interface.list", &json!({})).unwrap();
        rows.as_array().unwrap().iter().find(|r| r["name"] == name).unwrap().clone()
    }

    #[test]
    fn a_port_unplugged_is_invalid_and_its_configuration_comes_back() {
        use corerouter_hal::virt::{LatePort, VirtualHal};
        // ether9 is plugged at poll 1, unplugged for polls 12..30 (longer
        // than the grace of the warning, G1.6zr).
        let hal = VirtualHal::new(4).with_late_port(LatePort { name: n("ether9"), appears: 1, absent: Some(12..30) });
        let mut s = Session::new(Box::new(hal));
        for t in 0..6 {
            s.tick(1_000 + t);
        }
        assert!(s.store().running().interfaces.contains_key(&n("ether9")), "adopted");
        s.execute("interface.vlan.add", &json!({"name": "v9", "parent": "ether9", "vlan_id": 9})).unwrap();
        s.execute("ip.address.add", &json!({"address": "192.0.2.9/24", "interface": "v9"})).unwrap();
        assert_eq!(row(&mut s, "ether9")["invalid"], false);
        // Polls so far: 6 ticks + 1 list; tick until it is gone.
        let mut t = 6;
        while t < 12 {
            s.tick(1_000 + t);
            t += 1;
        }
        let e9 = row(&mut s, "ether9");
        assert_eq!(e9["invalid"], true, "{e9}");
        assert!(e9["invalid_reason"].as_str().unwrap().contains("not on this machine"));
        assert_eq!(row(&mut s, "v9")["invalid"], true, "the VLAN on it");
        assert_eq!(row(&mut s, "ether1")["invalid"], false);
        let health = s.execute("system.health.check", &json!({})).unwrap().to_string();
        assert!(health.contains("interface.absent"), "{health}");
        // The rest of the config still commits.
        s.execute("ip.address.add", &json!({"address": "198.51.100.1/24", "interface": "ether1"})).unwrap();
        // Back after poll 30.
        while t < 34 {
            s.tick(1_000 + t);
            t += 1;
        }
        assert_eq!(row(&mut s, "ether9")["invalid"], false);
        assert_eq!(row(&mut s, "v9")["invalid"], false);
        let log = s.execute("log.print", &json!({"find": "ether9"})).unwrap().to_string();
        assert!(log.contains("not on this machine"), "{log}");
        assert!(log.contains("port is back; its configuration was applied"), "{log}");
        assert!(s.hal().absent_ports().is_empty(), "the reapply cleared it");
    }

    /// G1.6zr: the r8152 switching its USB configuration at boot dropped
    /// ether2 twice for 2–4 s, and each time the log warned "not on this
    /// machine" and then "port is back". Back within the grace: one info
    /// line, no warning.
    #[test]
    fn a_port_gone_for_a_few_seconds_is_not_a_warning() {
        use corerouter_hal::virt::{LatePort, VirtualHal};
        let hal = VirtualHal::new(4).with_late_port(LatePort { name: n("ether9"), appears: 1, absent: Some(12..16) });
        let mut s = Session::new(Box::new(hal));
        for t in 0..14 {
            s.tick(1_000 + t);
        }
        assert_eq!(row(&mut s, "ether9")["invalid"], true, "shown invalid at once");
        for t in 14..24 {
            s.tick(1_000 + t);
        }
        let log = s.execute("log.print", &json!({"find": "ether9"})).unwrap().to_string();
        assert!(!log.contains("not on this machine"), "{log}");
        assert!(!log.contains("\"warning\""), "{log}");
        assert!(log.contains("ether9: port was replugged (gone "), "{log}");
        assert_eq!(row(&mut s, "ether9")["invalid"], false);
    }

    #[test]
    fn a_port_replugged_between_two_polls_gets_its_configuration_back() {
        use corerouter_hal::virt::VirtualHal;
        let hal = VirtualHal::new(4).with_replug(n("ether2"), 8);
        let mut s = Session::new(Box::new(hal));
        s.execute("ip.address.add", &json!({"address": "192.0.2.2/24", "interface": "ether2"})).unwrap();
        let mut t = 0;
        while t < 12 {
            s.tick(1_000 + t);
            t += 1;
        }
        let log = s.execute("log.print", &json!({"find": "ether2"})).unwrap().to_string();
        assert!(log.contains("ether2: port was replugged"), "{log}");
        assert!(log.contains("its configuration was applied again"), "{log}");
        assert!(!log.contains("not on this machine"), "never seen gone: {log}");
        assert!(s.hal().absent_ports().is_empty(), "the reapply cleared it");
        assert_eq!(row(&mut s, "ether2")["invalid"], false);
    }

    #[test]
    fn link_events_on_a_port_poll_at_once() {
        use corerouter_hal::virt::VirtualHal;
        let hal = VirtualHal::new(4).with_replug(n("ether2"), 6);
        let mut s = Session::new(Box::new(hal));
        s.execute("ip.address.add", &json!({"address": "192.0.2.2/24", "interface": "ether2"})).unwrap();
        s.tick(1_000);
        let replugged = |s: &mut Session| s.execute("log.print", &json!({"find": "replugged"})).unwrap().to_string().contains("ether2");
        // Links that are not ports of the config: no poll, so poll 6 never comes.
        for _ in 0..20 {
            s.link_events(Some(&["vlan9".to_owned(), "eth0".to_owned(), "bad name!".to_owned()]));
        }
        assert!(!replugged(&mut s));
        // ether2's events: each one polls, no tick needed.
        for _ in 0..20 {
            s.link_events(Some(&["ether2".to_owned()]));
        }
        assert!(replugged(&mut s));
        assert!(s.hal().absent_ports().is_empty());
        // Events dropped: looks too.
        s.link_events(None);
    }
}
