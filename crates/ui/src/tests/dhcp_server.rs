//! IP › DHCP Server and IP › Pool (G4.2a), panels: the lab's hosts get
//! leases from the server and show up with their chips; a network's form
//! shows the engine's checks; the Statistics window draws its KPIs.

use super::*;
use crate::dhcp_server::{DhcpServerPanel, Tab, WIN, params, row};
use corerouter_engine::lock;

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..3 {
        h.idle();
    }
}

/// A LAN on ether2 with a server, a network, a zone; the lab's hosts run
/// for a few seconds of the service clock.
fn lab() -> Harness {
    let h = Harness::with_session(Session::virtual_lab());
    {
        let mut s = lock(&h.session);
        s.tick(1_700_000_000);
        for (id, p) in [
            ("ip.address.add", json!({"address": "192.168.88.1/24", "interface": "ether2"})),
            ("ip.dns.zone.add", json!({"name": "lan.example"})),
            ("ip.pool.add", json!({"name": "lan", "ranges": "192.168.88.10-192.168.88.20"})),
            ("ip.dhcp-server.add", json!({"interface": "ether2", "address_pool": "lan"})),
            (
                "ip.dhcp-server.network.add",
                json!({"address": "192.168.88.0/24", "gateway": "192.168.88.1", "dns_zone": "lan.example"}),
            ),
            ("ip.dhcp-server.alert.add", json!({"interface": "ether2"})),
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
fn leases_show_their_state_and_names_as_chips() {
    let mut h = lab();
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    refresh(&mut h);
    assert!(h.has_text("DHCP Server"));
    assert!(h.has_text("running"), "the server's status chip");
    h.app.panel_mut::<DhcpServerPanel>().unwrap().tab = Tab::Leases;
    refresh(&mut h);
    for t in ["lab-laptop", "4 bound", "1 conflict", "DNS", "bound", "conflict", "Make Static"] {
        assert!(h.has_text(t), "{t} not drawn");
    }
    // Make Static on the laptop: the row turns static.
    h.click(h.text("lab-laptop"));
    h.idle();
    h.click(h.text("Make Static"));
    refresh(&mut h);
    assert!(h.has_text("1 static"), "{:?}", h.app.log());
    h.app.panel_mut::<DhcpServerPanel>().unwrap().tab = Tab::Alerts;
    refresh(&mut h);
    assert!(h.has_text_containing("02:BA:D0:00:00:02"), "the lab's rogue server");
}

#[test]
fn a_network_form_shows_the_checks() {
    let mut h = lab();
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    h.app.panel_mut::<DhcpServerPanel>().unwrap().tab = Tab::Networks;
    refresh(&mut h);
    h.click(h.text("192.168.88.0/24"));
    h.idle();
    h.key(egui::Key::Enter, egui::Modifiers::NONE);
    refresh(&mut h);
    assert_eq!(h.app.panel_mut::<DhcpServerPanel>().unwrap().dialogs.len(), 1, "the properties opened");
    assert!(h.has_text("Network <192.168.88.0/24>"));
    for t in ["gateway", "pool", "served", "LAN", "DNS"] {
        assert!(h.has_text(t), "check chip {t}");
    }
    // An edit sends only what changed.
    let p = h.app.panel_mut::<DhcpServerPanel>().unwrap();
    let d = p.dialogs.first_mut().unwrap();
    d.values.insert("domain", "lan.example".into());
    let sent = params(Tab::Networks.kind_for_test(), d);
    assert_eq!(sent["domain"], "lan.example");
    assert!(sent.get("gateway").is_none());
    assert!(sent["id"].as_str().unwrap().starts_with('*'));
}

#[test]
fn statistics_draw_kpis_and_pool_bars() {
    let mut h = lab();
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    refresh(&mut h);
    h.click(h.text("Statistics"));
    refresh(&mut h);
    assert!(h.app.panel_mut::<DhcpServerPanel>().unwrap().show_stats, "a tab of DHCP Server");
    for t in ["Active leases", "ACK/s", "p99 reply", "Dropped", "Pools", "lan", "DISCOVER", "Why no answer"] {
        assert!(h.has_text(t), "{t}");
    }
    // 4 bound of 11 addresses: 36 %, under the amber line.
    assert!(h.has_text_containing("36 % · 4 of 11"));
}

#[test]
fn rows_carry_chips() {
    let r = json!({"address": "10.0.0.5", "mac_address": "AA:BB:CC:00:00:01", "host_name": "onu-3",
        "dns": "onu-3.lan", "agent_info": "0x0103", "status": "bound", "dynamic": false, "blocked": true});
    let row = row(Tab::Leases, &r);
    let (host, chips) = crate::chip::split(&row.cells[2]);
    assert_eq!(host, "onu-3");
    assert_eq!(chips.len(), 2);
    let (_, status) = crate::chip::split(&row.cells[5]);
    let labels: Vec<&str> = status.iter().map(|(_, l)| *l).collect();
    assert_eq!(labels, ["bound", "static", "blocked"]);
}

#[test]
fn the_pool_window_lists_pools_and_used_addresses() {
    let mut h = lab();
    h.app.open.clear();
    h.app.open(Win::Panel(crate::ip_pool::WIN));
    refresh(&mut h);
    assert!(h.has_text("192.168.88.10-192.168.88.20"));
    assert!(h.has_text("36 %"));
    h.click(h.text("Used Addresses"));
    refresh(&mut h);
    assert!(h.has_text("dhcp1"));
    assert!(h.has_text("conflict"));
    // G4.2i: the owner chip, the count, the owner filter.
    assert!(h.has_text("DHCP"), "owner chip");
    assert!(h.has_text("5 addresses"), "4 bound + the conflict");
    h.click(h.text("PPP"));
    refresh(&mut h);
    let p = h.app.panel_mut::<crate::ip_pool::PoolPanel>().unwrap();
    assert_eq!(p.owner, crate::ip_pool::OwnerFilter::Ppp);
    assert!(p.used.is_empty(), "no PPP service in the lab");
    assert_eq!(p.used_total, 0);
}

/// G4.2i: a PPP row and a conflict row as the window draws them.
#[test]
fn used_rows_show_the_owner_chip_and_the_conflict() {
    let ppp = crate::ip_pool::used_row(&json!({
        "pool": "assin", "address": "100.64.0.2", "owner": "pppoe-ether3", "service": "ppp",
        "info": "ana 02:00:00:00:00:01", "user": "ana", "vlan": 100, "session": "*1-1", "state": "active",
    }));
    assert_eq!(ppp.key, "ppp|100.64.0.2|*1-1");
    let (owner, chips) = crate::chip::split(&ppp.cells[2]);
    assert_eq!(owner, "pppoe-ether3");
    assert_eq!(chips[0].1, "PPP");
    assert_eq!(ppp.cells[3], "ana 02:00:00:00:00:01 vlan 100");
    let c = crate::ip_pool::used_row(&json!({
        "pool": "lan", "address": "192.168.88.12", "owner": "dhcp1", "service": "dhcp",
        "info": "aa:bb:cc:00:00:01", "state": "conflict", "conflict": "also PPP session 'pedro'",
    }));
    assert!(c.cells[3].ends_with("— also PPP session 'pedro'"), "{}", c.cells[3]);
    let (_, chips) = crate::chip::split(&c.cells[4]);
    assert_eq!(chips[0], (crate::chip::Kind::Red, "conflict"));
}
