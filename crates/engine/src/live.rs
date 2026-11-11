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
/// whole id. The port and the client side of the network (the NTP client
/// too, G1.6zh: the clock of a live image is as wrong as any other), the
/// web GUI the install is made from (`--web-factory-on` turns it on through
/// here), a password, an install, the power.
const ALLOWED: &[&str] = &[
    "interface.set",
    "interface.ethernet.adopt",
    "ip.address.",
    "ip.route.",
    "ip.dhcp-client.",
    "ip.dns.set",
    "ip.service.www-ssl.",
    "ip.service.www.",
    "user.",
    "system.ntp.client.",
    "system.install.",
    "system.reboot",
    "system.shutdown",
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
pub fn permit(session: &Session, spec: &crate::cmd::CommandSpec) -> Result<(), String> {
    let writes = crate::auth::required_group(spec) != crate::auth::Group::Read;
    if writes && is_live(session) && !allowed(spec.id) {
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

    /// G1.6zh: the clock of a live image needs the NTP client as much as
    /// an installed router's (the install log, TLS, certificates).
    #[test]
    fn the_ntp_client_works_on_a_live_image() {
        let mut s = live();
        s.execute("system.ntp.client.set", &json!({"enabled": true})).unwrap();
        assert!(s.store().running().system.ntp_client.enabled);
        // The server side stays refused: nothing is offered to the network.
        let e = s
            .execute("system.ntp.server.set", &json!({"enabled": true}))
            .unwrap_err()
            .to_string();
        assert!(e.contains("live image"), "{e}");
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
