//! IP › DHCP Relay and the History tab of IP › DHCP Server (G4.2b), panels:
//! a relay on ether3 brings the lab hosts to the router's own server; the
//! leases show their port (option 82) as a chip; the history lists them.

use super::*;
use crate::dhcp_server::{DhcpServerPanel, Tab, WIN};
use corerouter_engine::lock;

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..3 {
        h.idle();
    }
}

fn lab() -> Harness {
    let h = Harness::with_session(Session::virtual_lab());
    {
        let mut s = lock(&h.session);
        s.tick(1_700_000_000);
        for (id, p) in [
            ("ip.address.add", json!({"address": "192.168.88.1/24", "interface": "ether2"})),
            ("ip.address.add", json!({"address": "10.20.0.1/24", "interface": "ether3"})),
            ("ip.pool.add", json!({"name": "far", "ranges": "10.20.0.10-10.20.0.50"})),
            ("ip.dhcp-server.add", json!({"name": "branch", "interface": "ether2", "address_pool": "far", "relay": "10.20.0.1"})),
            ("ip.dhcp-server.network.add", json!({"address": "10.20.0.0/24", "gateway": "10.20.0.1"})),
            ("ip.dhcp-relay.add", json!({"interface": "ether3", "dhcp_server": "192.168.88.1", "add_relay_info": true})),
        ] {
            s.execute(id, &p).unwrap_or_else(|e| panic!("{id}: {e}"));
        }
        for ms in (250..5_000).step_by(250) {
            s.tick(1_700_000_000 + ms / 1000);
            s.dhcp_service(ms);
        }
    }
    h
}

#[test]
fn relays_and_the_port_of_each_lease() {
    let mut h = lab();
    h.app.open.clear();
    h.app.open(Win::Panel(crate::dhcp_relay::WIN));
    refresh(&mut h);
    for t in ["relay1", "ether3", "192.168.88.1", "running", "option 82"] {
        assert!(h.has_text(t), "{t}");
    }
    h.app.open(Win::Panel(WIN));
    h.app.panel_mut::<DhcpServerPanel>().unwrap().tab = Tab::Leases;
    refresh(&mut h);
    assert!(h.has_text("4 bound"));
    assert!(h.has_text("ether3"), "the port chip");
}

#[test]
fn the_history_tab_searches_and_exports() {
    let mut h = lab();
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    refresh(&mut h);
    h.click(h.text("History"));
    refresh(&mut h);
    assert!(h.app.panel_mut::<DhcpServerPanel>().unwrap().show_history);
    assert!(h.has_text("lab-laptop"));
    assert!(h.has_text_containing("4 shown of 4 kept"));
    h.app.panel_mut::<DhcpServerPanel>().unwrap().history_form.mac = "02:1A:B0:03:00:01".into();
    refresh(&mut h);
    assert!(h.has_text_containing("1 shown of 4 kept"));
    h.click(h.text("Export CSV"));
    refresh(&mut h);
    let said = h.app.panel_mut::<DhcpServerPanel>().unwrap().exported.clone();
    assert_eq!(said.as_deref(), Some("1 rows copied as CSV"));
}
