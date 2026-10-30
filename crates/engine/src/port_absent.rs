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

/// What the log already said, so each change is logged once.
#[derive(Debug, Default)]
struct Absence {
    /// Ports last seen absent.
    gone: BTreeSet<IfName>,
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
        .filter(|n| cfg.interfaces.get(*n).is_some_and(|i| i.kind == InterfaceKind::Ethernet))
        .map(|n| (n.clone(), "port not on this machine (unplugged or failed): its configuration waits for it".to_owned()))
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
        let running = self.store().running();
        let ours = names.is_none_or(|names| {
            names.iter().any(|n| {
                n.parse::<IfName>()
                    .ok()
                    .and_then(|n| running.interfaces.get(&n))
                    .is_some_and(|i| i.kind == InterfaceKind::Ethernet)
            })
        });
        if !ours {
            return;
        }
        let snapshot = self.store().candidate().clone();
        let polled = crate::guard::run("link events", || {
            let live = self.hal_mut().poll();
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
        let present: BTreeSet<&IfName> = live.iter().map(|l| &l.name).collect();
        let gone: BTreeSet<IfName> = absent.iter().filter(|n| !present.contains(n)).cloned().collect();
        let back: Vec<IfName> = absent.iter().filter(|n| present.contains(n)).cloned().collect();
        let (went, returned, replugged) = match self.ext_mut::<Absence>() {
            Some(a) => {
                let went: Vec<IfName> = gone.difference(&a.gone).cloned().collect();
                let returned: Vec<IfName> = a.gone.difference(&gone).cloned().collect();
                // G1.3d: back without ever being seen gone: replugged
                // between two polls (the backend saw a new link).
                let replugged: BTreeSet<IfName> = back.iter().filter(|n| !a.gone.contains(*n)).cloned().collect();
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
                    let msg = if replugged.contains(&n) {
                        format!("{n}: port was replugged (gone and back within a second); its configuration was applied again")
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
        // ether9 is plugged at poll 1, unplugged for polls 12..20.
        let hal = VirtualHal::new(4).with_late_port(LatePort { name: n("ether9"), appears: 1, absent: Some(12..20) });
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
        // Back after poll 20.
        while t < 24 {
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
