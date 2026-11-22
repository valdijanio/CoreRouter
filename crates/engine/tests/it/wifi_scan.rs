//! G1.30i — what the air around a radio looks like, on the virtual lab:
//! the networks with their channel, load, overlap and contention
//! (`interface.wifi.networks`), the channels' survey
//! (`interface.wifi.frequency-scan`) and the spectral scan
//! (`interface.wifi.spectral-scan`, `interface.wifi.spectral-data`), with
//! what each refuses.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::Session;
use corerouter_hal::VirtualHal;
use corerouter_hal::lab_wifi::{LAB_PASSPHRASE, LabWifi};
use serde_json::{Value, json};

fn run(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

fn fails(s: &mut Session, id: &str, p: Value) -> String {
    match s.execute(id, &p) {
        Ok(v) => panic!("{id} {p} should fail, got {v}"),
        Err(e) => e.to_string(),
    }
}

fn spin(s: &mut Session, from_ms: u64, rounds: u64) -> u64 {
    let mut ms = from_ms;
    for _ in 0..rounds {
        ms += 100;
        s.wifi_service(ms);
    }
    ms
}

/// The lab's radio on its network, and a scan done. `spectral`: the radio
/// has spectral scan.
fn joined(spectral: bool) -> (Session, LabWifi, u64) {
    let hal = VirtualHal::new(8).with_wifi(1);
    let air = hal.wifi();
    if !spectral {
        air.without_spectral(&"wifi1".parse().unwrap());
    }
    let mut s = Session::new(Box::new(hal));
    for t in 0..4 {
        s.tick(1_000 + t);
    }
    run(
        &mut s,
        "interface.wifi.country.set",
        json!({"country": "BR"}),
    );
    run(
        &mut s,
        "interface.wifi.set",
        json!({"name": "wifi1", "ssid": "CoreRouter-Lab", "passphrase": LAB_PASSPHRASE, "disabled": false}),
    );
    let ms = spin(&mut s, 0, 8);
    run(&mut s, "interface.wifi.scan", json!({"name": "wifi1"}));
    let ms = spin(&mut s, ms, 4);
    (s, air, ms)
}

#[test]
fn networks_with_their_channel_load_and_contention() {
    let (mut s, _, _) = joined(true);
    let seen = run(&mut s, "interface.wifi.networks", json!({"name": "wifi1"}));
    let nets = seen["networks"].as_array().unwrap();
    let by = |bssid: &str| nets.iter().find(|n| n["bssid"] == bssid).unwrap().clone();
    let lab = by("02:c0:fe:00:00:01");
    assert_eq!(lab["connected"], true);
    assert_eq!(
        (
            lab["width"].as_u64(),
            lab["center_frequency"].as_u64(),
            lab["low"].as_u64(),
            lab["high"].as_u64()
        ),
        (Some(80), Some(5210), Some(5170), Some(5250)),
        "{lab}"
    );
    assert_eq!(
        (lab["generation"].as_u64(), lab["stations"].as_u64()),
        (Some(6), Some(4))
    );
    assert_eq!(lab["utilization"].as_f64(), Some(14.9), "38 of 255");
    // The neighbour's 80 MHz on 36–48 carries ch 44 (ours) as a secondary:
    // its wide frames hold our primary, heard at −71 dBm (≥ −82).
    assert_eq!(lab["contenders"], json!(["02:c0:fe:00:00:0a"]), "{lab}");
    assert_eq!(lab["contention"], "covered");
    assert_eq!(
        lab["overlaps"],
        json!([36]),
        "Oculta and Vizinho_5G, both on 36"
    );
    // 2.4 GHz: ch 4 overlaps 1 and 6; the 40 MHz one on 11 reaches 7.
    let apto = by("02:c0:fe:00:00:08");
    assert_eq!(
        apto["overlaps"],
        json!([1, 6, 11]),
        "{apto}: the 40 MHz on 11 reaches down to 7"
    );
    assert_eq!(by("02:c0:fe:00:00:04")["width"], 40);
    let six = by("02:c0:fe:00:00:0b");
    assert_eq!(
        (six["band"].as_str(), six["width"].as_u64()),
        (Some("6ghz"), Some(160))
    );
    // A channel suggested on each band the radio has.
    let sug = seen["suggested"].as_array().unwrap();
    let bands: Vec<&str> = sug.iter().filter_map(|g| g["band"].as_str()).collect();
    assert_eq!(bands, ["2ghz", "5ghz"], "{seen}");
    let two = &sug[0];
    assert!(
        [1, 6, 11].contains(&two["channel"].as_u64().unwrap()),
        "{two}"
    );
    assert_eq!(
        two["channel"], 11,
        "the quietest of 1, 6 and 11 here: {sug:?}"
    );
}

#[test]
fn frequency_scan_reads_the_survey() {
    let (mut s, _, ms) = joined(true);
    let f = run(
        &mut s,
        "interface.wifi.frequency-scan",
        json!({"name": "wifi1"}),
    );
    assert_eq!(f["survey"], "full", "{f}");
    let ch = f["channels"].as_array().unwrap();
    let c44 = ch.iter().find(|c| c["channel"] == 44).unwrap();
    assert_eq!(
        (c44["networks"].as_u64(), c44["in_use"].as_bool()),
        (Some(1), Some(true)),
        "{c44}"
    );
    assert!(c44["load"].as_f64().unwrap() > 0.0);
    let c40 = ch
        .iter()
        .find(|c| c["channel"] == 40 && c["band"] == "5ghz")
        .unwrap();
    assert_eq!(
        c40["secondary"], 2,
        "covered by both 80 MHz networks on 36–48"
    );
    // Asking for a scan first answers at once, and the channels follow.
    let f = run(
        &mut s,
        "interface.wifi.frequency-scan",
        json!({"name": "wifi1", "scan": true}),
    );
    assert_eq!(f["scanning"], true);
    spin(&mut s, ms, 3);
    assert_eq!(
        run(
            &mut s,
            "interface.wifi.frequency-scan",
            json!({"name": "wifi1"})
        )["scanning"],
        false
    );
}

#[test]
fn spectral_scan_of_the_channel_in_use() {
    let (mut s, _, ms) = joined(true);
    let none = run(
        &mut s,
        "interface.wifi.spectral-data",
        json!({"name": "wifi1"}),
    );
    assert_eq!(
        (none["supported"].as_bool(), none["running"].as_bool()),
        (Some(true), Some(false))
    );
    let r = run(
        &mut s,
        "interface.wifi.spectral-scan",
        json!({"name": "wifi1", "duration": 5}),
    );
    assert_eq!(
        (r["running"].as_bool(), r["range"].as_str()),
        (Some(true), Some("current"))
    );
    assert_eq!(r["warnings"], json!([]));
    let ms = spin(&mut s, ms, 45);
    let d = run(
        &mut s,
        "interface.wifi.spectral-data",
        json!({"name": "wifi1"}),
    );
    assert_eq!(d["running"], true, "{}", d["seconds_left"]);
    // 80 MHz around 5210 at 0.25 MHz.
    assert_eq!(d["points"], 320);
    let rows = d["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 45);
    assert_eq!(rows[0]["values"].as_array().unwrap().len(), 320);
    assert_eq!(d["realtime"].as_array().unwrap().len(), 320);
    let kinds: Vec<&str> = d["interference"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|i| i["kind"].as_str())
        .collect();
    assert!(
        kinds.contains(&"cw") && kinds.contains(&"wifi"),
        "{}",
        d["interference"]
    );
    let cw = d["interference"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["kind"] == "cw")
        .unwrap();
    assert!(
        (cw["frequency"].as_f64().unwrap() - 5232.0).abs() < 0.5,
        "{cw}"
    );
    // Channels 36–48 in use, by the two 80 MHz networks.
    let usage: Vec<(u64, f64)> = d["channels"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["channel"].as_u64().unwrap(), c["usage"].as_f64().unwrap()))
        .collect();
    assert_eq!(
        usage.iter().map(|u| u.0).collect::<Vec<_>>(),
        [36, 40, 44, 48],
        "{usage:?}"
    );
    // Each as busy as its networks' duty (some 10 to 40 % in the lab).
    // The carrier at 5232 MHz (−72 dBm, narrow) does not hold 48: a signal
    // that is not Wi-Fi counts only from the energy level, −62 dBm.
    assert!(usage.iter().all(|u| u.1 > 5.0 && u.1 < 60.0), "{usage:?}");
    // Only the rows after `since`.
    let last = d["last_seq"].as_u64().unwrap();
    let ms = spin(&mut s, ms, 2);
    let more = run(
        &mut s,
        "interface.wifi.spectral-data",
        json!({"name": "wifi1", "since": last}),
    );
    assert_eq!(more["rows"].as_array().unwrap().len(), 2);
    // The summary alone.
    let brief = run(
        &mut s,
        "interface.wifi.spectral-data",
        json!({"name": "wifi1", "limit": 0}),
    );
    assert_eq!(
        (brief["running"].as_bool(), brief.get("realtime")),
        (Some(true), None),
        "{brief}"
    );
    // Its time up (5 s), it stops by itself and the data stays.
    spin(&mut s, ms, 10);
    let d = run(
        &mut s,
        "interface.wifi.spectral-data",
        json!({"name": "wifi1", "limit": 10}),
    );
    assert_eq!(
        (d["running"].as_bool(), d["rows"].as_array().unwrap().len()),
        (Some(false), 10)
    );
}

#[test]
fn spectral_scan_of_a_band_and_stop() {
    let (mut s, _, ms) = joined(true);
    let r = run(
        &mut s,
        "interface.wifi.spectral-scan",
        json!({"name": "wifi1", "range": "2ghz"}),
    );
    assert!(
        r["warnings"][0]
            .as_str()
            .unwrap()
            .contains("off its channel"),
        "{r}"
    );
    spin(&mut s, ms, 60);
    let d = run(
        &mut s,
        "interface.wifi.spectral-data",
        json!({"name": "wifi1"}),
    );
    assert_eq!(
        (d["range"].as_str(), d["points"].as_u64()),
        (Some("2ghz"), Some(400))
    );
    let kinds: Vec<&str> = d["interference"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|i| i["kind"].as_str())
        .collect();
    assert!(kinds.contains(&"mwo"), "{}", d["interference"]);
    run(
        &mut s,
        "interface.wifi.spectral-scan",
        json!({"name": "wifi1", "stop": true}),
    );
    assert_eq!(
        run(
            &mut s,
            "interface.wifi.spectral-data",
            json!({"name": "wifi1"})
        )["running"],
        false
    );
}

#[test]
fn what_spectral_scan_refuses() {
    let (mut s, _, _) = joined(true);
    for (p, word) in [
        (json!({"name": "wifi1", "duration": 0}), "out of range"),
        (json!({"name": "wifi1", "duration": 601}), "out of range"),
        (json!({"name": "wifi1", "range": "60ghz"}), "not a range"),
        (json!({"name": "ether1"}), "not a Wi-Fi"),
        (json!({"name": "wifi1", "bogus": 1}), "bogus"),
    ] {
        let e = fails(&mut s, "interface.wifi.spectral-scan", p.clone());
        assert!(e.contains(word), "{p}: {e}");
    }
    // A radio without it says why, in the data too.
    let (mut s, _, _) = joined(false);
    let e = fails(
        &mut s,
        "interface.wifi.spectral-scan",
        json!({"name": "wifi1"}),
    );
    assert!(e.contains("Qualcomm Atheros"), "{e}");
    let d = run(
        &mut s,
        "interface.wifi.spectral-data",
        json!({"name": "wifi1"}),
    );
    assert_eq!(d["supported"], false);
    assert!(
        d["why_not"].as_str().unwrap().contains("no spectral scan"),
        "{d}"
    );
    // Off a channel, the channel in use cannot be scanned; a band can.
    run(
        &mut s,
        "interface.wifi.set",
        json!({"name": "wifi1", "ssid": ""}),
    );
    let (mut s, _, ms) = joined(true);
    run(
        &mut s,
        "interface.wifi.set",
        json!({"name": "wifi1", "ssid": ""}),
    );
    spin(&mut s, ms, 3);
    let e = fails(
        &mut s,
        "interface.wifi.spectral-scan",
        json!({"name": "wifi1"}),
    );
    assert!(e.contains("on no channel"), "{e}");
    run(
        &mut s,
        "interface.wifi.spectral-scan",
        json!({"name": "wifi1", "range": "5ghz"}),
    );
}
