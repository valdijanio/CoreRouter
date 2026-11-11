//! G1.6y: the image running live from the ISO, not installed.
//!
//! The daemon says so at start (`--live`). Everything works as on a router
//! to read and to diagnose, and only what the network test and the install
//! need can change anything: no DHCP server, no routing protocol, no firewall
//! or NAT, nothing announced beyond the discovery that lets the GUI find it.
//! The one check is here, so a new command is refused unless it is listed.

use crate::Session;

/// Present in a session of the live image.
#[derive(Default)]
pub struct Live;

/// What may change something on a live image: a prefix ending in `.`, or a
/// whole id. The port and the client side of the network, the web GUI the
/// install is made from (`--web-factory-on` turns it on through here), a
/// password, an install, the power.
const ALLOWED: &[&str] = &[
    // G1.26i: Safe Mode only ever undoes, and the changes above it are
    // the ones that cut the operator off (an address, a route).
    "config.safe-mode.",
    "interface.set",
    "interface.ethernet.adopt",
    "ip.address.",
    "ip.route.",
    "ip.dhcp-client.",
    "ip.dns.set",
    "ip.service.www-ssl.",
    "ip.service.www.",
    "user.",
    "system.install.",
    "system.reboot",
    "system.shutdown",
    // G1.26i: the kernel parameters only, so the Tuning window's diagnosis
    // can be acted on while trying the hardware (nothing is kept: the live
    // image has no disk). Not the ports (rings and queues flap the link
    // the install runs over), the CPU (a hardware watchdog would reboot
    // the live system) nor the boot parameters (there is no next boot).
    "system.tuning.set",
    "system.tuning.unset",
    "system.tuning.profile.apply",
    "tool.",
];

const REFUSED: &str = "this is the live image, not installed: install it first (System › Install to disk)";

pub fn set(session: &mut Session) {
    let _ = session.ext_mut::<Live>();
}

pub fn is_live(session: &Session) -> bool {
    session.ext::<Live>().is_some()
}

fn allowed(id: &str) -> bool {
    ALLOWED
        .iter()
        .any(|a| if a.ends_with('.') { id.starts_with(a) } else { id == *a })
}

/// `Err(reason)` when the live image refuses this command: only commands
/// that change something (`journal`, or the writes without a journal entry).
pub fn permit(session: &Session, id: &str, journal: bool) -> Result<(), String> {
    let writes = crate::auth::required_group(id, journal) != crate::auth::Group::Read;
    if writes && is_live(session) && !allowed(id) {
        return Err(REFUSED.to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_hal::VirtualHal;
    use serde_json::json;

    fn live() -> Session {
        let mut s = Session::new(Box::new(VirtualHal::default()));
        set(&mut s);
        s
    }

    #[test]
    fn a_session_is_not_live_until_told() {
        let s = Session::new(Box::new(VirtualHal::default()));
        assert!(!is_live(&s));
        assert!(is_live(&live()));
    }

    #[test]
    fn only_the_listed_commands_change_anything() {
        assert!(allowed("ip.dhcp-client.add"));
        assert!(allowed("system.install.run"));
        assert!(allowed("ip.service.www-ssl.set"));
        assert!(!allowed("ip.service.api.set"));
        assert!(!allowed("system.installer"));
        assert!(!allowed("ip.dhcp-server.add"));
        assert!(!allowed("routing.bgp.instance.add"));
        assert!(!allowed("ip.firewall.filter.add"));
        assert!(!allowed("system.package.update"));
        // G1.26i: kernel parameters at run time, nothing else of Tuning.
        assert!(allowed("system.tuning.set"));
        assert!(allowed("system.tuning.profile.apply"));
        assert!(!allowed("system.tuning.interface.set"));
        assert!(!allowed("system.tuning.interface.apply"));
        assert!(!allowed("system.tuning.cpu.set"));
        assert!(!allowed("system.tuning.boot.set"));
    }

    /// G1.26i: the live image forwards like an installed router, and its
    /// kernel parameters can be changed while it runs.
    #[test]
    fn the_live_image_forwards_and_takes_kernel_parameters() {
        let mut s = live();
        let d = s.execute("system.tuning.diagnose", &json!({})).unwrap();
        assert!(!d.to_string().contains("forwarding"), "{d}");
        s.execute(
            "system.tuning.set",
            &json!({"name": "net.core.netdev_budget", "value": 600}),
        )
        .unwrap();
        s.execute("system.tuning.unset", &json!({"name": "net.core.netdev_budget"}))
            .unwrap();
        s.execute("system.tuning.profile.apply", &json!({"profile": "balanced"}))
            .unwrap();
        // With Safe Mode, as the window's "Apply with Safe Mode" does:
        // cancelled, the kernel parameters go back.
        s.execute("config.safe-mode.cancel", &json!({})).unwrap_err();
        s.execute("config.safe-mode.enter", &json!({})).unwrap();
        s.execute("system.tuning.profile.apply", &json!({"profile": "throughput"}))
            .unwrap();
        let before = s.execute("system.tuning.print", &json!({})).unwrap();
        s.execute("config.safe-mode.cancel", &json!({})).unwrap();
        let after = s.execute("system.tuning.print", &json!({})).unwrap();
        assert_ne!(before, after, "the profile went back with Safe Mode");
        for (id, p) in [
            ("system.tuning.interface.set", json!({"name": "ether1", "key": "txqueuelen", "value": 2000})),
            ("system.tuning.cpu.set", json!({"key": "governor", "value": 0})),
            ("system.tuning.boot.set", json!({"key": "pcie_aspm", "value": "off"})),
        ] {
            let e = s.execute(id, &p).unwrap_err().to_string();
            assert!(e.contains("live image"), "{id}: {e}");
        }
    }

    #[test]
    fn the_live_image_refuses_a_server_and_rolls_nothing() {
        let mut s = live();
        let before = s.inspect(Some("ip")).unwrap();
        let e = s
            .execute("ip.pool.add", &json!({"name": "p", "ranges": "10.0.0.2-10.0.0.9"}))
            .unwrap_err()
            .to_string();
        assert!(e.contains("live image"), "{e}");
        assert_eq!(s.inspect(Some("ip")).unwrap(), before);
    }

    #[test]
    fn the_live_image_still_reads_and_takes_an_address() {
        let mut s = live();
        s.execute("interface.list", &json!({})).unwrap();
        s.execute(
            "ip.address.add",
            &json!({"address": "192.0.2.10/24", "interface": "ether1"}),
        )
        .unwrap();
    }

    #[test]
    fn the_list_greys_what_the_live_image_refuses() {
        let s = live();
        let list = s.list();
        let find = |id: &str| {
            list.as_array()
                .unwrap()
                .iter()
                .find(|c| c["id"] == id)
                .unwrap()
                .clone()
        };
        assert_eq!(find("ip.pool.add")["enabled"], false);
        assert!(find("ip.pool.add")["disabledReason"].as_str().unwrap().contains("live"));
        assert_eq!(find("ip.address.add")["enabled"], true);
    }
}
