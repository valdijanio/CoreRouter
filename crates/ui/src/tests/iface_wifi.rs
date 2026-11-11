//! G1.30g: "Interface <wifi1>" over the lab's radio — Wi-Fi and Radio tabs
//! instead of Ethernet, Status and SFP; SFP only on a port with a cage; the
//! window resizes with the mouse.

use super::*;
use corerouter_hal::VirtualHal;
use corerouter_hal::lab_wifi::LAB_PASSPHRASE;

/// The lab with `wifi1` on "CoreRouter-Lab", connected.
fn connected() -> Harness {
    let mut s = Session::new(Box::new(VirtualHal::new(8).with_wifi(1)));
    for t in 0..4 {
        s.tick(1_000 + t);
    }
    s.execute("interface.wifi.country.set", &json!({"country": "BR"}))
        .unwrap();
    s.execute(
        "interface.wifi.set",
        &json!({"name": "wifi1", "ssid": "CoreRouter-Lab", "passphrase": LAB_PASSPHRASE, "disabled": false}),
    )
    .unwrap();
    for ms in (100..=12_000).step_by(100) {
        s.wifi_service(ms);
    }
    let m = s
        .execute("interface.wifi.monitor", &json!({"name": "wifi1"}))
        .unwrap();
    assert_eq!(m["state"], "connected", "{m}");
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h
}

#[test]
fn a_wifi_port_has_wifi_and_radio_tabs_and_no_ethernet_or_sfp() {
    let mut h = connected();
    h.app.open_props("wifi1");
    h.wait(1.2);
    for t in ["General", "Wi-Fi", "Radio", "Hardware", "Traffic", "Statistics"] {
        assert!(h.has_text(t), "tab {t}");
    }
    use crate::iface_tabs::Tab;
    assert_eq!(
        Tab::of(h.app.nic.get("wifi1")),
        [Tab::General, Tab::Wifi, Tab::Radio, Tab::Hardware, Tab::Traffic, Tab::Stats],
        "no Ethernet, Status or SFP tab on a Wi-Fi port"
    );
    h.tab("Wi-Fi");
    h.wait(1.2);
    for t in [
        "connected",
        "CoreRouter-Lab",
        "802.11ax (Wi-Fi 6)",
        "HE-MCS",
        "2 streams",
        "SNR",
        "Per Antenna",
        "Retries",
    ] {
        assert!(h.has_text_containing(t), "Wi-Fi tab: {t}");
    }
    h.tab("Radio");
    h.wait(1.2);
    for t in [
        "lab_wifi",
        "802.11a/b/g/n/ac/ax",
        "2×2 (TX 2, RX 2)",
        "up to 80 MHz",
        "Channels, 5 GHz",
        "free",
    ] {
        assert!(h.has_text_containing(t), "Radio tab: {t}");
    }
}

#[test]
fn the_sfp_tab_shows_only_on_a_port_with_a_cage() {
    let mut h = connected();
    h.app.open_props("ether8");
    h.wait(1.2);
    use crate::iface_tabs::Tab;
    assert!(Tab::of(h.app.nic.get("ether8")).contains(&Tab::Sfp), "ether8 has an SFP+ cage");
    assert!(h.has_text("SFP"));
    h.key(egui::Key::Escape, egui::Modifiers::NONE);
    h.app.open_props("ether1");
    h.wait(1.2);
    let tabs = Tab::of(h.app.nic.get("ether1"));
    assert!(tabs.contains(&Tab::Ethernet) && tabs.contains(&Tab::Status), "{tabs:?}");
    assert!(!tabs.contains(&Tab::Sfp), "a copper port has no SFP tab");
    assert!(!h.has_text("SFP"));
}

#[test]
fn the_interface_window_resizes_with_the_mouse() {
    let mut h = connected();
    h.app.open_props("ether1");
    h.wait(0.5);
    let id = h
        .app
        .dialogs
        .first()
        .map(|d| crate::interfaces::dialog_id(d.id))
        .expect("the window is open");
    assert!(h.app.floats.resizable(id), "Interface <name> is resizable");
}
