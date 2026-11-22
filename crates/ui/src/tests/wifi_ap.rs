//! G1.30a: Interfaces › Wi-Fi with the lab's radio as an access point — the
//! AP chip and the clients on the Radios tab, the Registration tab, and the
//! Mode field of the modal.

use super::*;
use corerouter_hal::VirtualHal;

/// The lab with `wifi1` announcing "Loja", two clients in.
fn access_point() -> Harness {
    let mut s = Session::new(Box::new(VirtualHal::new(8).with_wifi(1)));
    for t in 0..4 {
        s.tick(1_000 + t);
    }
    s.execute("interface.wifi.country.set", &json!({"country": "BR"}))
        .unwrap();
    s.execute(
        "interface.wifi.set",
        &json!({"name": "wifi1", "mode": "ap", "ssid": "Loja", "passphrase": "senha-da-loja",
                "disabled": false}),
    )
    .unwrap();
    for ms in (1_000..=20_000).step_by(1_000) {
        s.wifi_service(ms);
    }
    let m = s
        .execute("interface.wifi.monitor", &json!({"name": "wifi1"}))
        .unwrap();
    assert_eq!((m["state"].as_str(), m["clients"].as_u64()), (Some("running"), Some(2)), "{m}");
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(crate::wifi::WIN));
    h.app.cache.refreshed_at = None;
    h.idle();
    h.idle();
    h
}

#[test]
fn the_radios_tab_shows_the_access_point_and_its_clients() {
    let h = access_point();
    assert!(h.has_text("AP"), "the mode chip");
    assert!(h.has_text("running"), "the state");
    assert!(h.has_text("2 clients"), "the clients instead of a signal");
    assert!(h.has_text("5 GHz ch 36"), "the channel");
}

#[test]
fn the_registration_tab_lists_the_clients() {
    let mut h = access_point();
    h.click(h.text("Registration"));
    h.app.cache.refreshed_at = None;
    h.wait(0.5);
    assert!(h.has_text("02:00:00:00:a0:01"), "the phone");
    assert!(h.has_text("02:00:00:00:a0:02"), "the laptop");
    assert!(h.has_text("WPA3"));
    assert!(h.has_text("802.11ax"));
    assert!(h.has_text("-48 dBm"));
}

#[test]
fn without_an_access_point_the_tab_says_how_to_make_one() {
    let mut s = Session::new(Box::new(VirtualHal::new(8).with_wifi(1)));
    for t in 0..4 {
        s.tick(1_000 + t);
    }
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(crate::wifi::WIN));
    h.app.cache.refreshed_at = None;
    h.wait(0.5);
    h.click(h.text("Registration"));
    h.idle();
    assert!(h.has_text_containing("No radio is an access point"));
}
