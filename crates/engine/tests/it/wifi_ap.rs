//! G1.30a — Wi-Fi access point: the radio of the lab in `mode=ap`, through
//! the commands (success, validation, rollback), the run-time loop (up,
//! radar check, clients) and the registration table.
// Shared helpers are not `#[test]` fns, so clippy's in-tests allowances skip them.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::Session;
use corerouter_hal::VirtualHal;
use corerouter_hal::lab_wifi::LabWifi;
use corerouter_hal::wifi_ap::ApSecurity;
use corerouter_model::IfName;
use serde_json::{Value, json};

fn wifi1() -> IfName {
    "wifi1".parse().unwrap()
}

fn run(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

fn fails(s: &mut Session, id: &str, p: Value) -> String {
    let before = s.store().candidate().clone();
    let msg = match s.execute(id, &p) {
        Ok(v) => panic!("{id} {p} should fail, got {v}"),
        Err(e) => e.to_string(),
    };
    assert_eq!(
        s.store().candidate(),
        &before,
        "{id} {p} left changes behind"
    );
    msg
}

/// The lab with its radio adopted and the country set.
fn lab() -> (Session, LabWifi, u64) {
    let hal = VirtualHal::new(8).with_wifi(1);
    let air = hal.wifi();
    let mut s = Session::new(Box::new(hal));
    for t in 0..4 {
        s.tick(1_000 + t);
    }
    run(
        &mut s,
        "interface.wifi.country.set",
        json!({"country": "BR"}),
    );
    (s, air, 10_000)
}

/// The radios' clock: `n` seconds.
fn spin(s: &mut Session, from_ms: u64, n: u64) -> u64 {
    let mut ms = from_ms;
    for _ in 0..n {
        ms += 1_000;
        s.wifi_service(ms);
    }
    ms
}

fn monitor(s: &mut Session) -> Value {
    run(s, "interface.wifi.monitor", json!({"name": "wifi1"}))
}

fn ap(s: &mut Session, extra: Value) -> Value {
    let mut p = json!({"name": "wifi1", "mode": "ap", "ssid": "Loja", "passphrase": "senha-da-loja",
                       "disabled": false});
    if let (Some(o), Value::Object(e)) = (p.as_object_mut(), extra) {
        o.extend(e);
    }
    run(s, "interface.wifi.set", p)
}

#[test]
fn an_access_point_comes_up_and_lists_its_clients() {
    let (mut s, air, ms) = lab();
    let r = ap(&mut s, json!({}));
    assert_eq!(r["warnings"], json!([]), "{r}");
    let ms = spin(&mut s, ms, 12);
    let m = monitor(&mut s);
    assert_eq!(m["mode"], "ap", "{m}");
    assert_eq!(m["state"], "running", "{m}");
    // Automatic: 5 GHz, the first channel without radar, 80 MHz.
    assert_eq!(
        (m["channel"].as_u64(), m["width"].as_u64()),
        (Some(36), Some(80)),
        "{m}"
    );
    assert_eq!(m["auto_channel"], true);
    assert_eq!(m["clients"], 2, "{m}");
    let told = air.ap_told(&wifi1()).unwrap();
    assert_eq!(told.security, ApSecurity::Wpa2Wpa3);
    assert_eq!(
        told.key, "senha-da-loja",
        "the passphrase reaches the platform opened"
    );
    assert_eq!((told.center_mhz, told.country.as_str()), (5210, "BR"));

    let table = run(&mut s, "interface.wifi.registration-table.print", json!({}));
    let rows = table.as_array().unwrap();
    assert_eq!(rows.len(), 2, "{table}");
    assert_eq!(rows[0]["security"], "wpa3");
    assert_eq!(rows[0]["standard"], "802.11ax");
    assert_eq!(rows[1]["security"], "wpa2");
    assert!(rows[0]["signal"].as_i64().unwrap() > rows[1]["signal"].as_i64().unwrap());
    assert_eq!(rows[0]["retry_percent"], 4.0);

    let list = run(&mut s, "interface.wifi.list", json!({}));
    assert_eq!(list[0]["mode"], "ap");
    assert_eq!(list[0]["clients"], 2);
    assert_eq!(list[0]["passphrase"], "***");
    // The history says what happened.
    let h = run(&mut s, "interface.wifi.history", json!({"name": "wifi1"}));
    let text = h.to_string();
    assert!(
        text.contains("starting access point 'Loja' on channel 36"),
        "{text}"
    );
    assert!(text.contains("access point up"), "{text}");
    assert!(text.contains("02:00:00:00:a0:01 joined"), "{text}");

    // A tick with nothing changed starts nothing again.
    let starts = air.ap_starts(&wifi1());
    spin(&mut s, ms, 5);
    assert_eq!(air.ap_starts(&wifi1()), starts);
}

#[test]
fn a_radar_channel_waits_and_wpa3_only_leaves_wpa2_out() {
    let (mut s, _air, ms) = lab();
    let r = ap(
        &mut s,
        json!({"frequency": "52", "width": "20", "security": "wpa3"}),
    );
    let w = r["warnings"].to_string();
    assert!(w.contains("radar detection"), "{w}");
    assert!(w.contains("leaves out clients"), "{w}");
    s.wifi_service(ms + 1_000);
    s.wifi_service(ms + 3_500);
    assert_eq!(monitor(&mut s)["state"], "radar-check");
    let ms = spin(&mut s, ms + 3_500, 12);
    let m = monitor(&mut s);
    assert_eq!(
        (m["state"].as_str(), m["channel"].as_u64()),
        (Some("running"), Some(52))
    );
    // The lab's laptop speaks WPA2 only.
    assert_eq!(m["clients"], 1, "{m}");
    let _ = ms;
}

#[test]
fn what_the_radio_does_not_allow_is_refused_with_the_reason() {
    let (mut s, _air, _) = lab();
    let base =
        json!({"name": "wifi1", "mode": "ap", "ssid": "Loja", "passphrase": "senha-da-loja"});
    let with = |extra: Value| {
        let mut p = base.clone();
        if let (Some(o), Value::Object(e)) = (p.as_object_mut(), extra) {
            o.extend(e);
        }
        p
    };
    for (extra, needle) in [
        (json!({"frequency": "13"}), "no-IR"),
        (json!({"frequency": "2472"}), "no-IR"),
        (json!({"frequency": "5181"}), "not one this radio has"),
        (json!({"frequency": "1"}), "not one this radio has"), // 2412 exists; width below
        (json!({"frequency": "6115"}), "6 GHz"),
        (json!({"frequency": "nove"}), "not a frequency"),
        (json!({"frequency": "1", "width": "80"}), "up to 40"),
        (json!({"frequency": "36", "width": "160"}), "up to 80"),
        (json!({"width": "30"}), "not a channel width"),
        (json!({"bssid": "02:00:00:00:00:01"}), "bssid"),
        (json!({"mode": "mesh"}), "not a mode"),
    ] {
        if needle == "not one this radio has" && extra["frequency"] == "1" {
            continue;
        }
        let e = fails(&mut s, "interface.wifi.set", with(extra.clone()));
        assert!(e.contains(needle), "{extra}: {e}");
    }
    // The passphrase rules are the station's.
    let e = fails(
        &mut s,
        "interface.wifi.set",
        with(json!({"passphrase": "curta"})),
    );
    assert!(e.contains("8 to 63"), "{e}");
}

#[test]
fn an_access_point_is_a_bridge_port_and_a_station_is_not() {
    let (mut s, air, ms) = lab();
    run(&mut s, "interface.bridge.add", json!({"name": "bridge1"}));
    // A station first: refused.
    let e = fails(
        &mut s,
        "interface.bridge.port.add",
        json!({"bridge": "bridge1", "interface": "wifi1"}),
    );
    assert!(e.contains("three"), "{e}");
    ap(&mut s, json!({}));
    run(
        &mut s,
        "interface.bridge.port.add",
        json!({"bridge": "bridge1", "interface": "wifi1"}),
    );
    spin(&mut s, ms, 4);
    assert_eq!(
        air.ap_told(&wifi1()).unwrap().bridge.as_deref(),
        Some("bridge1")
    );
    // Back to station while a bridge port: refused, with the way out.
    let e = fails(
        &mut s,
        "interface.wifi.set",
        json!({"name": "wifi1", "mode": "station"}),
    );
    assert!(e.contains("take it out"), "{e}");
}

#[test]
fn rollback_brings_the_station_back() {
    let (mut s, air, ms) = lab();
    let before = s.store().current_revision();
    ap(&mut s, json!({}));
    let ms = spin(&mut s, ms, 6);
    assert_eq!(monitor(&mut s)["state"], "running");
    run(&mut s, "config.rollback", json!({"revision": before}));
    if s.store().is_dirty() {
        run(&mut s, "config.commit", json!({}));
    }
    spin(&mut s, ms, 3);
    let m = monitor(&mut s);
    assert_ne!(m["mode"], "ap", "{m}");
    assert!(air.ap_told(&wifi1()).is_none(), "the access point stopped");
    let list = run(&mut s, "interface.wifi.list", json!({}));
    assert_eq!(list[0]["mode"], "station");
}

#[test]
fn the_preview_shows_the_channel_it_would_use() {
    let (mut s, _air, ms) = lab();
    // The hardware is known once the radio was opened once.
    run(&mut s, "interface.wifi.enable", json!({"name": "wifi1"}));
    spin(&mut s, ms, 2);
    let v = run(
        &mut s,
        "interface.wifi.preview",
        json!({"id": "wifi1", "mode": "ap", "ssid": "Loja", "passphrase": "senha-da-loja",
               "frequency": "149"}),
    );
    let text = v["computed"].to_string();
    assert!(text.contains("149 (5745 MHz), 80 MHz wide"), "{text}");
    assert!(text.contains("WPA2 and WPA3 together"), "{text}");
}
