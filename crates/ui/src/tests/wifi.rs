//! Interfaces › Wi-Fi (G1.30) against the lab's radio and its seven
//! networks: the list with its chips, the monitor of the selected radio,
//! the country dialog, the scan with Connect… filling the modal, the
//! modal's preview, the menu entry and the explanations.

use super::*;
use crate::wifi::{HEARD, TABLE, Tab, WIN, WifiPanel};
use corerouter_hal::VirtualHal;
use corerouter_hal::lab_wifi::LAB_PASSPHRASE;

/// A lab session with one radio, adopted (off, no network, no country).
fn lab() -> Session {
    let mut s = Session::new(Box::new(VirtualHal::new(8).with_wifi(1)));
    for t in 0..4 {
        s.tick(1_000 + t);
    }
    s
}

/// The radio's clock, far enough for a join or a scan to end.
fn spin(s: &mut Session, from_ms: u64) -> u64 {
    let mut ms = from_ms;
    for _ in 0..8 {
        ms += 100;
        s.wifi_service(ms);
    }
    ms
}

/// The lab with `wifi1` told to join `ssid`.
fn joined(ssid: &str, passphrase: &str) -> Session {
    let mut s = lab();
    s.execute("interface.wifi.country.set", &json!({"country": "BR"}))
        .unwrap();
    s.execute(
        "interface.wifi.set",
        &json!({"name": "wifi1", "ssid": ssid, "passphrase": passphrase, "disabled": false}),
    )
    .unwrap();
    spin(&mut s, 0);
    s
}

fn opened(s: Session) -> Harness {
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    refresh(&mut h);
    h
}

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    h.idle();
    h.idle();
}

fn select(h: &mut Harness, table: &str, key: &str) {
    let row = h
        .ctx
        .read_response(table::row_id(table, key))
        .unwrap_or_else(|| panic!("row {key} drawn"))
        .rect
        .center();
    h.click(row);
    refresh(h);
}

#[test]
fn wifi_window_lists_the_radio_and_its_monitor() {
    let mut h = opened(joined("CoreRouter-Lab", LAB_PASSPHRASE));
    assert!(h.has_text("connected"), "state chip");
    assert!(h.has_text("CoreRouter-Lab"), "the network's chip");
    assert!(h.has_text("WPA2/WPA3"), "what the radio accepts");
    assert!(h.has_text_containing("5 GHz ch 44"), "channel column");
    assert!(h.has_text("BR"), "the country chip");
    // Selecting the row shows its monitor under the table.
    select(&mut h, TABLE, "wifi1");
    assert!(h.has_text("02:c0:fe:00:00:01"), "BSSID in the monitor");
    assert!(h.has_text_containing("WPA3 (SAE)"), "what was negotiated");
    h.click(h.text("Reconnect"));
    assert!(
        h.app
            .log()
            .iter()
            .any(|l| l.ok && l.command == "interface.wifi.reconnect"),
        "{:?}",
        h.app.log()
    );
}

#[test]
fn a_wrong_passphrase_shows_why_next_to_the_state() {
    let h = opened(joined("CoreRouter-Lab", "nao-e-essa-senha"));
    assert!(h.has_text("wrong passphrase?"), "the reason chip");
    assert!(!h.has_text("connected"));
}

#[test]
fn no_country_is_said_and_the_dialog_sets_it() {
    let mut h = opened(lab());
    assert!(h.has_text("no country"), "the amber chip");
    assert!(h.has_text("disabled"), "a radio starts off");
    h.click(h.text("Change…"));
    h.idle();
    assert!(h.has_text("Wi-Fi Country"), "the dialog");
    h.app
        .panel_mut::<WifiPanel>()
        .unwrap()
        .country_dialog
        .as_mut()
        .unwrap()
        .value = "br".into();
    h.idle();
    h.click(h.text("OK"));
    for _ in 0..4 {
        h.idle();
    }
    let got = lock(&h.session)
        .execute("interface.wifi.country.get", &Value::Null)
        .unwrap();
    assert_eq!(got["country"], "BR");
    assert!(
        h.app.panel_mut::<WifiPanel>().unwrap().country_dialog.is_none(),
        "closed on success"
    );
    refresh(&mut h);
    assert!(!h.has_text("no country"));
}

#[test]
fn scan_lists_the_networks_and_connect_fills_the_modal() {
    let mut s = lab();
    s.execute("interface.wifi.country.set", &json!({"country": "BR"}))
        .unwrap();
    s.execute("interface.wifi.enable", &json!({"name": "wifi1"}))
        .unwrap();
    let ms = spin(&mut s, 0);
    let mut h = opened(s);
    assert!(h.has_text("no network"), "on, with nothing to join");
    select(&mut h, TABLE, "wifi1");
    h.click(h.text("Scan…"));
    h.idle();
    spin(&mut lock(&h.session), ms);
    refresh(&mut h);
    {
        let p = h.app.panel_mut::<WifiPanel>().unwrap();
        assert_eq!((p.tab, p.radio.as_str()), (Tab::Networks, "wifi1"));
    }
    assert!(h.has_text("Vizinho_2G") && h.has_text("Cafe"), "what the scan heard");
    assert!(h.has_text("802.1X"), "a network that cannot be joined is listed");
    assert!(h.has_text_containing("last scan:"), "how old the scan is");

    // Connect… on the WPA3 network: the radio's modal, the network filled in.
    let bssid = lock(&h.session)
        .execute("interface.wifi.networks", &json!({"name": "wifi1"}))
        .unwrap()["networks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|n| n["ssid"] == "Lab-WPA3")
        .map(|n| n["bssid"].as_str().unwrap().to_owned())
        .unwrap();
    select(&mut h, HEARD, &bssid);
    h.click(h.text("Connect…"));
    for _ in 0..30 {
        h.idle();
    }
    {
        let m = h.app.panel_mut::<WifiPanel>().unwrap().modal.as_mut().expect("the modal");
        assert_eq!(m.values.get("ssid").map(String::as_str), Some("Lab-WPA3"));
        assert_eq!(m.values.get("disabled").map(String::as_str), Some("no"));
        // No passphrase yet: the preview says so, under its field.
        m.values.insert("passphrase", "wpa3-only-pass".into());
    }
    for _ in 0..30 {
        h.idle();
    }
    assert!(h.has_text_containing("yes: -"), "the preview: the network is in range");
    assert!(
        !h.has_text_containing("wpa3-only-pass"),
        "the passphrase is not on screen, not even in the commands"
    );
    h.click(h.text("OK"));
    for _ in 0..4 {
        h.idle();
    }
    let rows = lock(&h.session)
        .execute("interface.wifi.list", &Value::Null)
        .unwrap();
    assert_eq!(rows[0]["ssid"], "Lab-WPA3");
    assert_eq!(rows[0]["passphrase"], "***", "sealed, never read back");
    // And the radio gets on it.
    spin(&mut lock(&h.session), ms + 10_000);
    let m = lock(&h.session)
        .execute("interface.wifi.monitor", &json!({"name": "wifi1"}))
        .unwrap();
    assert_eq!((m["state"].as_str(), m["security"].as_str()), (Some("connected"), Some("wpa3")), "{m}");
}

#[test]
fn the_modal_refuses_a_short_passphrase_before_sending_it() {
    let mut h = opened(joined("CoreRouter-Lab", LAB_PASSPHRASE));
    let row = h
        .ctx
        .read_response(table::row_id(TABLE, "wifi1"))
        .expect("row drawn")
        .rect
        .center();
    h.click(row);
    h.click(row);
    for _ in 0..30 {
        h.idle();
    }
    let m = h.app.panel_mut::<WifiPanel>().unwrap().modal.as_mut().expect("double click opens");
    m.values.insert("passphrase", "curta".into());
    for _ in 0..30 {
        h.idle();
    }
    assert!(
        h.has_text_containing("the passphrase has 5 characters"),
        "the engine's reason, in the modal"
    );
}

#[test]
fn interfaces_menu_has_wifi() {
    assert_eq!(crate::menu::label(Win::Panel(WIN)), "Wi-Fi");
    let group = crate::windows::menu()
        .into_iter()
        .find(|(g, _)| *g == "Interfaces")
        .map(|(_, items)| items)
        .unwrap();
    assert!(group.contains(&Win::Panel(WIN)));
    for query in ["/interface wifi", "ssid", "sem fio"] {
        let hits = crate::menu_search::search(query, std::iter::empty());
        assert!(
            hits.iter().any(|h| matches!(h, crate::menu_search::Hit::Win(w) if *w == Win::Panel(WIN))),
            "{query}: {hits:?}"
        );
    }
}

#[test]
fn every_explanation_of_the_window_exists_in_both_languages() {
    let mut keys = vec![
        "menu.wifi",
        "interface.wifi",
        "interface.wifi.country",
        "interface.wifi.failure",
        "interface.wifi.reconnects",
        "interface.wifi.state",
    ];
    keys.extend(crate::wifi::help_keys());
    for key in keys {
        for lang in [crate::i18n::Lang::Pt, crate::i18n::Lang::En] {
            let langs = crate::i18n::Langs { labels: lang, help: lang };
            let (got, _) = crate::i18n::explain(langs, key).unwrap_or_else(|| panic!("{key}"));
            assert_eq!(got, lang, "{key} in {lang:?}");
        }
    }
}

#[test]
fn every_label_of_the_window_is_translated() {
    for label in crate::wifi::labels() {
        assert_ne!(
            crate::i18n::tr_in("wifi", crate::i18n::Lang::Pt, label),
            "",
            "{label}"
        );
        // Words that are the same in both languages aside, a label left
        // out of the catalog shows in English.
        let same = ["SSID", "BSSID", "MTU", "Wi-Fi"];
        if !same.contains(&label) {
            assert_ne!(
                crate::i18n::tr_in("wifi", crate::i18n::Lang::Pt, label),
                label,
                "{label} has no Portuguese"
            );
        }
    }
}
