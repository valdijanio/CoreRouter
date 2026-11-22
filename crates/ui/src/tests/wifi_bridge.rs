//! G1.30m: Interfaces › Wi-Fi › Peers over the lab's access point with a
//! registered peer, the Add Peer dialog, and the modal's pages.

use super::*;
use crate::wifi::WifiPanel;
use corerouter_hal::VirtualHal;

fn with_peer() -> Harness {
    let mut s = Session::new(Box::new(VirtualHal::new(8).with_wifi(1)));
    for t in 0..4 {
        s.tick(1_000 + t);
    }
    for (id, p) in [
        ("interface.wifi.country.set", json!({"country": "BR"})),
        (
            "interface.wifi.set",
            json!({"name": "wifi1", "mode": "ap", "ssid": "Backhaul", "passphrase": "senha-do-backhaul",
                   "station_bridge": "yes", "disabled": false}),
        ),
        (
            "interface.wifi.peer.add",
            json!({"radio": "wifi1", "name": "peer1", "mac_address": "02:00:00:00:b0:01", "comment": "torre"}),
        ),
    ] {
        s.execute(id, &p).unwrap();
    }
    for ms in (1_000..=20_000).step_by(1_000) {
        s.wifi_service(ms);
    }
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(crate::wifi::WIN));
    h.app.cache.refreshed_at = None;
    h.wait(0.5);
    h
}

#[test]
fn the_peers_tab_lists_the_registered_peer_up() {
    let mut h = with_peer();
    h.click(h.text("Peers"));
    h.app.cache.refreshed_at = None;
    h.wait(0.5);
    assert!(h.has_text("peer1"));
    assert!(h.has_text("02:00:00:00:b0:01"));
    assert!(h.has_text("up"), "the peer's state");
    assert!(h.has_text("-55 dBm"));
    assert!(h.has_text("torre"));
    // Add Peer…: the dialog, with the access point picked and a free name.
    let add = h
        .ctx
        .read_response(table::tool_id(crate::wifi_peers::TABLE, table::Icon::Add))
        .expect("add tool")
        .rect
        .center();
    h.click(add);
    h.wait(0.3);
    assert!(h.has_text("Add Peer"));
    let d = h.app.panel_mut::<WifiPanel>().unwrap().peers.add.as_ref().map(|d| (d.radio.clone(), d.name.clone()));
    assert_eq!(d, Some(("wifi1".into(), "peer2".into())));
}

#[test]
fn the_modal_has_general_and_channel_pages() {
    let mut h = with_peer();
    let row = h
        .ctx
        .read_response(table::row_id(crate::wifi::TABLE, "wifi1"))
        .expect("row drawn")
        .rect
        .center();
    h.click(row);
    h.click(row);
    h.wait(0.5);
    assert!(h.has_text("Station Bridge"), "General has the bridge fields");
    assert!(!h.has_text("Frequency"), "the channel is on its own page");
    // ("Channel" is a column of the table behind too: the page by its state.)
    h.app.panel_mut::<WifiPanel>().unwrap().modal_page = 1;
    h.wait(0.3);
    assert!(h.has_text("Frequency") && h.has_text("Width"));
}
