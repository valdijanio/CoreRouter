//! `interface.ethernet.adopt` (G1.6t): put a physical port the platform
//! has, and the configuration does not, into the configuration, with the
//! kernel's MTU, MAC and admin state (so applying it changes nothing). The
//! daemon's tick runs it for a card plugged in with the router running
//! (`port_adopt.rs`); an operator can run it too.

use corerouter_model::{IfName, Interface, InterfaceKind};
use serde_json::{Value, json};

use super::args::req_parse;
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[cmd!(
    "interface.ethernet.adopt",
    "Adopt Port",
    [],
    None,
    "{name: string (a physical Ethernet port the router has and the configuration does not)} → {name, mtu, mac, disabled}",
    always,
    adopt
)
.positional("name")];

fn adopt(s: &mut Session, p: &Value) -> Result<Value> {
    let name: IfName = req_parse(p, "name")?;
    if s.store().candidate().interfaces.contains_key(&name) {
        return Err(EngineError::bad(
            "name",
            format!("'{name}' is in the configuration already"),
        ));
    }
    let links = s
        .hal_mut()
        .discover_links()
        .map_err(|e| EngineError::Hal(e.to_string()))?;
    let link = links.into_iter().find(|l| l.name == name).ok_or_else(|| {
        EngineError::bad(
            "name",
            format!("'{name}' is not a physical port this router manages (see interface.list)"),
        )
    })?;
    let mut iface = Interface::new(name.clone(), InterfaceKind::Ethernet);
    iface.mtu = link.mtu;
    iface.mac = link.mac.as_deref().and_then(|m| m.parse().ok());
    // As the kernel has it: applying the adoption changes nothing.
    iface.disabled = !link.up;
    let out = json!({
        "name": name,
        "mtu": iface.mtu,
        "mac": iface.mac.map(|m| m.to_string()),
        "disabled": iface.disabled,
    });
    s.store_mut().candidate_mut().interfaces.insert(name, iface);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use corerouter_hal::virt::{LatePort, VirtualHal};
    use serde_json::json;

    use crate::Session;

    /// The lab plus a card that appears at poll `at` (and is gone for
    /// `absent`).
    fn lab_with(at: u64, absent: Option<std::ops::Range<u64>>) -> Session {
        let hal = VirtualHal::new(8).with_late_port(LatePort {
            name: "ether9".parse().unwrap(),
            appears: at,
            absent,
        });
        Session::new(Box::new(hal))
    }

    fn adopted(s: &Session) -> bool {
        s.store().running().interfaces.contains_key(&"ether9".parse().unwrap())
    }

    #[test]
    fn a_card_plugged_in_after_boot_is_adopted_once_after_it_settles() {
        let mut s = lab_with(3, None);
        assert!(!adopted(&s), "not there at boot");
        for t in 0..4 {
            s.tick(1_000 + t);
            assert!(!adopted(&s), "poll {t}: not before it kept its name for 3 polls");
        }
        for t in 4..8 {
            s.tick(1_000 + t);
        }
        assert!(adopted(&s));
        let revisions = s.store().current_revision();
        for t in 8..20 {
            s.tick(1_000 + t);
        }
        assert_eq!(s.store().current_revision(), revisions, "adopted once");
        let log = s.execute("log.print", &json!({"find": "ether9"})).unwrap().to_string();
        assert!(log.contains("adopt"), "the adoption is in the log: {log}");
        let row = s.execute("interface.list", &json!({})).unwrap();
        let e9 = row.as_array().unwrap().iter().find(|r| r["name"] == "ether9").unwrap().clone();
        assert_eq!(e9["managed"], true);
        // Something can be set on it now (the user's point).
        s.execute("ip.address.add", &json!({"address": "192.0.2.9/24", "interface": "ether9"}))
            .unwrap();
    }

    #[test]
    fn a_port_that_goes_away_and_comes_back_is_not_adopted_twice() {
        let mut s = lab_with(1, Some(10..14));
        for t in 0..8 {
            s.tick(1_000 + t);
        }
        assert!(adopted(&s));
        let rev = s.store().current_revision();
        // Gone for four polls, then back under the same name.
        for t in 8..24 {
            s.tick(1_000 + t);
        }
        assert_eq!(s.store().current_revision(), rev, "no second adoption");
        let n = s
            .store()
            .running()
            .interfaces
            .keys()
            .filter(|n| n.as_str() == "ether9")
            .count();
        assert_eq!(n, 1);
    }

    #[test]
    fn pending_changes_hold_the_adoption_back() {
        let mut s = lab_with(1, None);
        s.execute("config.mode.set", &json!({"mode": "transactional"})).unwrap();
        s.execute("interface.set", &json!({"name": "ether1", "comment": "editing"})).unwrap();
        for t in 0..6 {
            s.tick(1_000 + t);
        }
        assert!(!adopted(&s), "the operator's edit is not committed behind their back");
        s.execute("config.commit", &json!({})).unwrap();
        for t in 6..12 {
            s.tick(1_000 + t);
        }
        assert!(adopted(&s));
        assert!(!s.store().is_dirty(), "the adoption committed only itself");
    }

    #[test]
    fn the_command_refuses_what_it_cannot_adopt() {
        let mut s = Session::virtual_lab();
        let e = s
            .execute("interface.ethernet.adopt", &json!({"name": "ether1"}))
            .unwrap_err()
            .to_string();
        assert!(e.contains("in the configuration already"), "{e}");
        let e = s
            .execute("interface.ethernet.adopt", &json!({"name": "wlan0"}))
            .unwrap_err()
            .to_string();
        assert!(e.contains("not a physical port"), "{e}");
        let before = s.store().current_revision();
        assert!(s.execute("interface.ethernet.adopt", &json!({})).is_err());
        assert_eq!(s.store().current_revision(), before, "nothing committed");
    }
}
