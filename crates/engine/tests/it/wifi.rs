//! G1.30 — Wi-Fi in station mode on the virtual lab: a radio (`wifi1`) that
//! hears the lab's networks (`corerouter_hal::lab_wifi`). The commands
//! (`interface.wifi.*`), what they refuse, the radio following the running
//! configuration through commit, rollback and Safe Mode, and the passphrase
//! never leaving in clear.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::{Caller, Principal, Session};
use corerouter_hal::VirtualHal;
use corerouter_hal::lab_wifi::{LAB_PASSPHRASE, LabWifi};
use corerouter_model::IfName;
use serde_json::{Value, json};

fn lab() -> (Session, LabWifi) {
    let hal = VirtualHal::new(8).with_wifi(1);
    let air = hal.wifi();
    let mut s = Session::new(Box::new(hal));
    // A radio is not in the boot's seed: the tick adopts it once its name
    // held for three polls (PID 1 renames `wlan0` to `wifi1` after the
    // driver brings it up).
    assert!(!s.store().running().interfaces.contains_key(&wifi1()));
    for t in 0..4 {
        s.tick(1_000 + t);
    }
    (s, air)
}

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

/// The radios' clock, a few rounds (a lab radio takes three to get in).
fn spin(s: &mut Session, from_ms: u64) -> u64 {
    let mut ms = from_ms;
    for _ in 0..8 {
        ms += 100;
        s.wifi_service(ms);
    }
    ms
}

fn wifi1() -> IfName {
    "wifi1".parse().unwrap()
}

fn monitor(s: &mut Session) -> Value {
    run(s, "interface.wifi.monitor", json!({"name": "wifi1"}))
}

/// Country set, radio on and on the lab's network.
fn joined() -> (Session, LabWifi, u64) {
    let (mut s, air) = lab();
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
    let ms = spin(&mut s, 0);
    assert_eq!(monitor(&mut s)["state"], "connected");
    (s, air, ms)
}

#[test]
fn a_radio_is_there_like_a_port_and_joins_a_network() {
    let (mut s, air) = lab();
    // Adopted as what it is: an interface of type wifi, off, with no network.
    let all = run(&mut s, "interface.list", json!({}));
    let row = all
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "wifi1")
        .unwrap()
        .clone();
    assert_eq!(
        (row["type"].as_str(), row["disabled"].as_bool()),
        (Some("wifi"), Some(true)),
        "{row}"
    );
    assert_eq!(
        all.as_array()
            .unwrap()
            .iter()
            .filter(|r| r["type"] == "ether")
            .count(),
        8
    );
    let list = run(&mut s, "interface.wifi.list", json!({}));
    assert_eq!(list[0]["state"], "disabled");
    assert_eq!(
        (list[0]["mode"].as_str(), list[0]["ssid"].as_str()),
        (Some("station"), Some(""))
    );

    // No country, no radio: the refusal says the command to run.
    let e = fails(&mut s, "interface.wifi.enable", json!({"name": "wifi1"}));
    assert!(e.contains("interface.wifi.country.set country=BR"), "{e}");
    let e = fails(&mut s, "interface.wifi.scan", json!({"name": "wifi1"}));
    assert!(e.contains("country"), "{e}");
    run(
        &mut s,
        "interface.wifi.country.set",
        json!({"country": "br"}),
    );
    assert_eq!(
        run(&mut s, "interface.wifi.country.get", json!({}))["country"],
        "BR"
    );
    let e = fails(&mut s, "interface.wifi.scan", json!({"name": "wifi1"}));
    assert!(e.contains("interface.wifi.enable"), "{e}");

    // On, with no network yet: idle, and it can scan.
    run(&mut s, "interface.wifi.enable", json!({"name": "wifi1"}));
    let mut ms = spin(&mut s, 0);
    assert_eq!(air.country().as_deref(), Some("BR"));
    assert_eq!(monitor(&mut s)["state"], "idle");
    assert_eq!(
        run(&mut s, "interface.wifi.scan", json!({"name": "wifi1"}))["scanning"],
        true
    );
    ms = spin(&mut s, ms);
    let seen = run(&mut s, "interface.wifi.networks", json!({"name": "wifi1"}));
    let nets = seen["networks"].as_array().unwrap();
    assert_eq!(seen["scanning"], false);
    assert_eq!(nets.len(), 7, "{seen}");
    assert_eq!(nets[0]["ssid"], "CoreRouter-Lab");
    assert_eq!(
        (nets[0]["band"].as_str(), nets[0]["channel"].as_u64()),
        (Some("5ghz"), Some(44))
    );
    assert_eq!(nets[0]["security"], "wpa2-wpa3");
    let corp = nets.iter().find(|n| n["ssid"] == "Corp").unwrap();
    assert_eq!(corp["joinable"], false);
    assert!(
        corp["why_not"].as_str().unwrap().contains("802.1X"),
        "{corp}"
    );
    assert!(
        nets.iter().any(|n| n["ssid"] == ""),
        "the hidden network has no name"
    );

    // Join.
    let r = run(
        &mut s,
        "interface.wifi.set",
        json!({"name": "wifi1", "ssid": "CoreRouter-Lab", "passphrase": LAB_PASSPHRASE}),
    );
    assert_eq!(r["warnings"], json!([]));
    ms = spin(&mut s, ms);
    let m = monitor(&mut s);
    assert_eq!(m["state"], "connected", "{m}");
    assert_eq!(
        (m["ssid"].as_str(), m["bssid"].as_str()),
        (Some("CoreRouter-Lab"), Some("02:c0:fe:00:00:01"))
    );
    assert_eq!(
        (
            m["band"].as_str(),
            m["channel"].as_u64(),
            m["signal"].as_i64()
        ),
        (Some("5ghz"), Some(44), Some(-52))
    );
    assert_eq!(
        (m["security"].as_str(), m["pmf"].as_bool()),
        (Some("wpa3"), Some(true))
    );
    assert_eq!(m["failure"], Value::Null);
    assert_eq!(m["driver"], "lab_wifi");
    assert!(air.connected(&wifi1()));
    // The interface has carrier now, and takes an address like any other.
    let all = run(&mut s, "interface.list", json!({}));
    let row = all
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "wifi1")
        .unwrap()
        .clone();
    assert_eq!(row["running"], true, "{row}");
    run(
        &mut s,
        "ip.address.add",
        json!({"address": "192.0.2.9/24", "interface": "wifi1"}),
    );
    let seen = run(&mut s, "interface.wifi.networks", json!({"name": "wifi1"}));
    assert_eq!(seen["networks"][0]["connected"], true);

    // Told once: a thousand rounds of the clock do not join again.
    let joins = air.joins(&wifi1());
    for _ in 0..1000 {
        ms += 10;
        s.wifi_service(ms);
    }
    assert_eq!(air.joins(&wifi1()), joins);
    let calls = air.country_calls();
    spin(&mut s, ms);
    assert_eq!(
        air.country_calls(),
        calls,
        "the country is asked for once per change"
    );

    let h = run(&mut s, "interface.wifi.history", json!({"name": "wifi1"})).to_string();
    assert!(
        h.contains("joining") && h.contains("connected to 'CoreRouter-Lab'"),
        "{h}"
    );
    let log = run(&mut s, "log.print", json!({"topics": "wireless"})).to_string();
    assert!(
        log.contains("wifi1: connected to 'CoreRouter-Lab'"),
        "{log}"
    );
}

#[test]
fn what_the_commands_refuse() {
    let (mut s, _air) = lab();
    run(
        &mut s,
        "interface.wifi.country.set",
        json!({"country": "BR"}),
    );
    let secret = "um-segredo-bem-longo";
    for (p, want) in [
        (
            json!({"name": "wifi1", "ssid": "x".repeat(33), "passphrase": secret}),
            "32",
        ),
        (
            json!({"name": "wifi1", "ssid": "a\tb", "passphrase": secret}),
            "control character",
        ),
        (
            json!({"name": "wifi1", "ssid": "Casa", "passphrase": "curta"}),
            "8 to 63",
        ),
        (
            json!({"name": "wifi1", "ssid": "Casa", "passphrase": "senha com ç dentro"}),
            "printable ASCII",
        ),
        (
            json!({"name": "wifi1", "ssid": "Casa", "passphrase": "a".repeat(64)}),
            "WPA2 only",
        ),
        (
            json!({"name": "wifi1", "ssid": "Casa", "passphrase": "a".repeat(65)}),
            "8 to 63",
        ),
        (
            json!({"name": "wifi1", "ssid": "Casa"}),
            "needs its passphrase",
        ),
        (
            json!({"name": "wifi1", "ssid": "Casa", "security": "wep", "passphrase": secret}),
            "auto, wpa3, wpa2 or open",
        ),
        (
            json!({"name": "wifi1", "ssid": "Casa", "security": "open", "passphrase": secret}),
            "open network has no passphrase",
        ),
        (
            json!({"name": "wifi1", "band": "60ghz"}),
            "2ghz, 5ghz, 6ghz",
        ),
        (json!({"name": "wifi1", "bssid": "not-a-mac"}), "MAC"),
        (json!({"name": "wifi1", "mtu": 9000}), "68..=2304"),
        (
            json!({"name": "wifi9", "ssid": "Casa", "passphrase": secret}),
            "no Wi-Fi interface 'wifi9'",
        ),
        (
            json!({"name": "ether1", "ssid": "Casa", "passphrase": secret}),
            "is a ether, not a Wi-Fi interface",
        ),
        (json!({"name": "wifi1", "ssd": "Casa"}), "ssid"),
    ] {
        let e = fails(&mut s, "interface.wifi.set", p.clone());
        assert!(e.contains(want), "{p}: wanted '{want}' in: {e}");
        assert!(!e.contains(secret), "the passphrase leaked: {e}");
    }
    // Nothing of that changed the configuration.
    let list = run(&mut s, "interface.wifi.list", json!({}));
    assert_eq!(
        (list[0]["ssid"].as_str(), list[0]["passphrase"].as_str()),
        (Some(""), Some(""))
    );

    // The 64-digit key is WPA2's; turning the network to WPA3 afterwards is
    // refused too.
    let hex = "ab".repeat(32);
    run(
        &mut s,
        "interface.wifi.set",
        json!({"name": "wifi1", "ssid": "Casa", "security": "wpa2", "passphrase": hex}),
    );
    let e = fails(
        &mut s,
        "interface.wifi.set",
        json!({"name": "wifi1", "security": "wpa3"}),
    );
    assert!(e.contains("WPA2 only") && !e.contains(&hex), "{e}");

    // Countries.
    for bad in ["BRA", "B", "1A", "brasil"] {
        let e = fails(
            &mut s,
            "interface.wifi.country.set",
            json!({"country": bad}),
        );
        assert!(e.contains("two letters"), "{bad}: {e}");
    }
    run(&mut s, "interface.wifi.enable", json!({"name": "wifi1"}));
    let e = fails(&mut s, "interface.wifi.country.set", json!({"country": ""}));
    assert!(e.contains("wifi1 cannot run without a country"), "{e}");

    // A station is routed, never bridged; and a radio is not removed.
    run(&mut s, "interface.bridge.add", json!({"name": "bridge1"}));
    let e = fails(
        &mut s,
        "interface.bridge.port.add",
        json!({"bridge": "bridge1", "interface": "wifi1"}),
    );
    assert!(
        e.contains("three addresses") && e.contains("Route through it"),
        "{e}"
    );
    let e = fails(&mut s, "interface.remove", json!({"name": "wifi1"}));
    assert!(e.contains("Wi-Fi radio and cannot be removed"), "{e}");
    let e = fails(&mut s, "interface.wifi.adopt", json!({"name": "wifi1"}));
    assert!(e.contains("already"), "{e}");
    let e = fails(&mut s, "interface.wifi.adopt", json!({"name": "ether9"}));
    assert!(e.contains("not a Wi-Fi radio"), "{e}");
    // And an Ethernet port is not adopted as a radio, nor a radio as a port.
    let e = fails(&mut s, "interface.ethernet.adopt", json!({"name": "wifi1"}));
    assert!(e.contains("already"), "{e}");
}

#[test]
fn it_says_why_it_did_not_get_in() {
    let (mut s, air) = lab();
    run(
        &mut s,
        "interface.wifi.country.set",
        json!({"country": "BR"}),
    );
    run(
        &mut s,
        "interface.wifi.set",
        json!({"name": "wifi1", "ssid": "CoreRouter-Lab", "passphrase": "senha-errada", "disabled": false}),
    );
    let mut ms = spin(&mut s, 0);
    let m = monitor(&mut s);
    assert_eq!(m["failure"]["code"], "wrong-key", "{m}");
    assert!(
        m["failure"]["text"]
            .as_str()
            .unwrap()
            .contains("probably a wrong passphrase"),
        "{m}"
    );
    assert_ne!(m["state"], "connected");
    assert_eq!(
        run(&mut s, "interface.wifi.list", json!({}))[0]["failure"],
        "wrong-key"
    );
    // Said once in the log, not at every round.
    ms = spin(&mut s, ms);
    let h = run(&mut s, "interface.wifi.history", json!({}));
    assert_eq!(
        h.as_array()
            .unwrap()
            .iter()
            .filter(|e| e["event"] == "failed")
            .count(),
        1,
        "{h}"
    );

    // The right one: in, and the failure is forgotten.
    run(
        &mut s,
        "interface.wifi.set",
        json!({"name": "wifi1", "passphrase": LAB_PASSPHRASE}),
    );
    ms = spin(&mut s, ms);
    let m = monitor(&mut s);
    assert_eq!(
        (m["state"].as_str(), &m["failure"]),
        (Some("connected"), &Value::Null),
        "{m}"
    );

    // Another network needs its own passphrase: the one of the network
    // before is forgotten, not tried on it.
    let e = fails(
        &mut s,
        "interface.wifi.set",
        json!({"name": "wifi1", "ssid": "Nao-Existe"}),
    );
    assert!(e.contains("needs its passphrase"), "{e}");
    assert_eq!(monitor(&mut s)["ssid"], "CoreRouter-Lab", "nothing changed");
    // A network that is not there, and one held to a band it is not on.
    run(
        &mut s,
        "interface.wifi.set",
        json!({"name": "wifi1", "ssid": "Nao-Existe", "passphrase": LAB_PASSPHRASE}),
    );
    ms = spin(&mut s, ms);
    let m = monitor(&mut s);
    assert_eq!(m["failure"]["code"], "not-found", "{m}");
    assert!(
        m["failure"]["text"]
            .as_str()
            .unwrap()
            .contains("hidden=yes"),
        "{m}"
    );
    run(
        &mut s,
        "interface.wifi.set",
        json!({"name": "wifi1", "ssid": "Vizinho_2G", "passphrase": "outro-segredo", "band": "5ghz"}),
    );
    ms = spin(&mut s, ms);
    assert_eq!(monitor(&mut s)["failure"]["code"], "not-found");
    run(
        &mut s,
        "interface.wifi.set",
        json!({"name": "wifi1", "band": "any"}),
    );
    ms = spin(&mut s, ms);
    assert_eq!(monitor(&mut s)["state"], "connected");

    // The access point goes away, comes back: lost, and found again.
    let saved = corerouter_hal::lab_wifi::default_networks()
        .into_iter()
        .find(|n| n.ssid == "Vizinho_2G")
        .unwrap();
    air.remove_network("Vizinho_2G");
    ms = spin(&mut s, ms);
    let m = monitor(&mut s);
    assert_eq!(
        (m["state"].as_str(), m["reconnects"].as_u64()),
        (Some("searching"), Some(1)),
        "{m}"
    );
    air.add_network(saved);
    run(&mut s, "interface.wifi.reconnect", json!({"name": "wifi1"}));
    ms = spin(&mut s, ms);
    assert_eq!(monitor(&mut s)["state"], "connected");

    // The airplane-mode key.
    air.set_blocked(true);
    ms = spin(&mut s, ms);
    assert_eq!(monitor(&mut s)["state"], "blocked");
    air.set_blocked(false);
    spin(&mut s, ms);
    assert_eq!(monitor(&mut s)["state"], "connected");
    let h = run(&mut s, "interface.wifi.history", json!({})).to_string();
    assert!(h.contains("blocked") && h.contains("unblocked"), "{h}");
}

#[test]
fn the_radio_follows_the_running_configuration_through_rollback_and_transactions() {
    let (mut s, air, mut ms) = joined();
    let good = s.store().current_revision();
    let joins = air.joins(&wifi1());

    // A change that does not work, then back to the revision that did.
    run(
        &mut s,
        "interface.wifi.set",
        json!({"name": "wifi1", "ssid": "Lab-WPA3", "passphrase": "nao-e-essa-senha"}),
    );
    ms = spin(&mut s, ms);
    assert_eq!(monitor(&mut s)["failure"]["code"], "wrong-key");
    assert!(!air.connected(&wifi1()));
    run(&mut s, "config.rollback", json!({"revision": good}));
    if s.store().is_dirty() {
        run(&mut s, "config.commit", json!({}));
    }
    ms = spin(&mut s, ms);
    let m = monitor(&mut s);
    assert_eq!(
        (m["state"].as_str(), m["ssid"].as_str()),
        (Some("connected"), Some("CoreRouter-Lab")),
        "{m}"
    );
    assert_eq!(m["failure"], Value::Null);
    assert_eq!(
        air.joins(&wifi1()),
        joins + 2,
        "one join per change of the running config"
    );

    // Transactional: the candidate is not what the radio is told.
    run(&mut s, "config.mode.set", json!({"mode": "transactional"}));
    run(
        &mut s,
        "interface.wifi.set",
        json!({"name": "wifi1", "ssid": "Cafe", "security": "open"}),
    );
    ms = spin(&mut s, ms);
    assert_eq!(
        monitor(&mut s)["bssid"],
        "02:c0:fe:00:00:01",
        "still on the running one"
    );
    assert_eq!(air.joins(&wifi1()), joins + 2);
    run(&mut s, "config.discard", json!({}));
    assert_eq!(
        run(&mut s, "interface.wifi.list", json!({}))[0]["ssid"],
        "CoreRouter-Lab"
    );
    // Committed, the radio moves; an open network is warned about.
    let r = run(
        &mut s,
        "interface.wifi.set",
        json!({"name": "wifi1", "ssid": "Cafe", "security": "open"}),
    );
    assert!(
        r["warnings"][0].as_str().unwrap().contains("open network"),
        "{r}"
    );
    run(&mut s, "config.commit", json!({}));
    ms = spin(&mut s, ms);
    let m = monitor(&mut s);
    assert_eq!(
        (m["ssid"].as_str(), m["security"].as_str()),
        (Some("Cafe"), Some("open")),
        "{m}"
    );
    // Open stores no passphrase.
    assert_eq!(
        run(&mut s, "interface.wifi.list", json!({}))[0]["passphrase"],
        ""
    );

    // Off: it leaves. No network: idle. Country gone needs it off first.
    run(&mut s, "interface.wifi.disable", json!({"name": "wifi1"}));
    run(&mut s, "config.commit", json!({}));
    ms = spin(&mut s, ms);
    assert!(!air.connected(&wifi1()));
    assert_eq!(
        run(&mut s, "interface.wifi.list", json!({}))[0]["state"],
        "disabled"
    );
    run(&mut s, "interface.wifi.country.set", json!({"country": ""}));
    run(&mut s, "config.commit", json!({}));
    spin(&mut s, ms);
    assert_eq!(air.country(), None);
}

#[test]
fn changing_the_network_this_connection_comes_through_needs_safe_mode() {
    let (mut s, air, mut ms) = joined();
    run(
        &mut s,
        "ip.address.add",
        json!({"address": "10.0.0.1/24", "interface": "wifi1"}),
    );
    let who = Caller::new(42, "tcp 10.0.0.9:51234").with_principal(Principal::Local);
    let change = json!({"name": "wifi1", "passphrase": "outra-senha-qualquer"});
    let e = s
        .execute_as(&who, "interface.wifi.set", &change)
        .unwrap_err()
        .to_string();
    assert!(e.contains("carries this connection (from 10.0.0.9)"), "{e}");
    assert!(
        e.contains("config.safe-mode.enter") && e.contains("force=yes"),
        "{e}"
    );
    assert!(!e.contains("outra-senha"), "{e}");
    let e = s
        .execute_as(&who, "interface.wifi.disable", &json!({"name": "wifi1"}))
        .unwrap_err()
        .to_string();
    assert!(e.contains("carries this connection"), "{e}");
    let e = s
        .execute_as(&who, "interface.wifi.reconnect", &json!({"name": "wifi1"}))
        .unwrap_err()
        .to_string();
    assert!(e.contains("carries this connection"), "{e}");
    // What does not touch the link goes through: a comment, a scan.
    s.execute_as(
        &who,
        "interface.wifi.set",
        &json!({"name": "wifi1", "comment": "uplink"}),
    )
    .unwrap();
    s.execute_as(&who, "interface.wifi.scan", &json!({"name": "wifi1"}))
        .unwrap();
    // From the console (no remote address) nothing is asked.
    run(
        &mut s,
        "interface.wifi.set",
        json!({"name": "wifi1", "comment": "from the console"}),
    );

    // In Safe Mode the wrong passphrase goes in, the connection is lost,
    // and the router goes back to the network that worked.
    s.execute_as(&who, "config.safe-mode.enter", &json!({}))
        .unwrap();
    let r = s.execute_as(&who, "interface.wifi.set", &change).unwrap();
    assert!(
        r["warnings"][0].as_str().unwrap().contains("in Safe Mode"),
        "{r}"
    );
    ms = spin(&mut s, ms);
    assert_eq!(monitor(&mut s)["failure"]["code"], "wrong-key");
    assert!(!air.connected(&wifi1()));
    s.hang_up(42);
    ms = spin(&mut s, ms);
    let m = monitor(&mut s);
    assert_eq!(
        (m["state"].as_str(), m["ssid"].as_str()),
        (Some("connected"), Some("CoreRouter-Lab")),
        "{m}"
    );
    assert!(air.connected(&wifi1()));

    // `force` is the other way, and says so.
    let mut forced = change.clone();
    forced["force"] = json!(true);
    let r = s.execute_as(&who, "interface.wifi.set", &forced).unwrap();
    assert!(
        r["warnings"][0]
            .as_str()
            .unwrap()
            .contains("forced outside Safe Mode"),
        "{r}"
    );
    spin(&mut s, ms);
    assert!(!air.connected(&wifi1()));
}

#[test]
fn the_passphrase_never_leaves_in_clear() {
    let (mut s, _air, _) = joined();
    let list = run(&mut s, "interface.wifi.list", json!({}));
    assert_eq!(list[0]["passphrase"], "***");
    // In clear only for group full, asked for.
    let clear = run(
        &mut s,
        "interface.wifi.list",
        json!({"show_sensitive": true}),
    );
    assert_eq!(clear[0]["passphrase"], LAB_PASSPHRASE);
    run(
        &mut s,
        "user.add",
        json!({"name": "leitor", "group": "read", "password": "uma-senha-de-teste"}),
    );
    let reader = Caller::new(7, "tcp 10.9.9.9:1").with_principal(Principal::User("leitor".into()));
    let e = s
        .execute_as(
            &reader,
            "interface.wifi.list",
            &json!({"show_sensitive": true}),
        )
        .unwrap_err()
        .to_string();
    assert!(e.contains("show_sensitive"), "{e}");

    // The stored value is a sealed box; the journal and the log are masked.
    let stored = serde_json::to_string(s.store().running()).unwrap();
    assert!(stored.contains(r#""passphrase":"$cr1$"#), "{stored}");
    assert!(!stored.contains(LAB_PASSPHRASE));
    let journal = format!("{:?}", s.journal());
    assert!(journal.contains("interface.wifi.set"), "{journal}");
    assert!(!journal.contains(LAB_PASSPHRASE), "{journal}");
    let log = run(&mut s, "log.print", json!({})).to_string();
    assert!(!log.contains(LAB_PASSPHRASE), "{log}");
    let diff = run(&mut s, "config.diff", json!({})).to_string();
    assert!(!diff.contains(LAB_PASSPHRASE));
    // `state.inspect`: the box for group full, not even that below it.
    for path in ["interfaces", "running", "journal"] {
        let state = s.inspect(Some(path)).unwrap().to_string();
        assert!(!state.contains(LAB_PASSPHRASE), "{path}");
        let below = s.inspect_as(&reader, Some(path)).unwrap().to_string();
        assert!(
            !below.contains("$cr1$") && !below.contains(LAB_PASSPHRASE),
            "{path}: {below}"
        );
    }
    let state = s.inspect(Some("interfaces")).unwrap().to_string();
    assert!(
        state.contains("wifi1") && state.contains("$cr1$"),
        "{state}"
    );
    // Forgetting the network forgets the passphrase.
    run(
        &mut s,
        "interface.wifi.set",
        json!({"name": "wifi1", "ssid": ""}),
    );
    let stored = serde_json::to_string(s.store().running()).unwrap();
    assert!(!stored.contains("passphrase"), "{stored}");
}

#[test]
fn a_radio_plugged_in_later_is_adopted_off() {
    let (mut s, air) = lab();
    let wifi2: IfName = "wifi2".parse().unwrap();
    air.add_radio(wifi2.clone());
    assert!(!s.store().running().interfaces.contains_key(&wifi2));
    for t in 10..18 {
        s.tick(1_000 + t);
    }
    let cfg = s.store().running();
    let i = cfg.interfaces.get(&wifi2).expect("adopted");
    assert_eq!(i.kind.label(), "wifi");
    assert!(
        i.disabled,
        "a radio is off until it is told to join a network"
    );
    let revisions = s.store().current_revision();
    for t in 18..30 {
        s.tick(1_000 + t);
    }
    assert_eq!(s.store().current_revision(), revisions, "adopted once");
    let list = run(&mut s, "interface.wifi.list", json!({}));
    assert_eq!(list.as_array().unwrap().len(), 2);
}

#[test]
fn a_router_without_wifi_says_so_and_pays_nothing() {
    let mut s = Session::virtual_lab();
    for id in [
        "interface.wifi.set",
        "interface.wifi.scan",
        "interface.wifi.monitor",
    ] {
        let e = fails(&mut s, id, json!({"name": "wifi1"}));
        assert!(e.contains("no Wi-Fi radio"), "{id}: {e}");
    }
    assert_eq!(run(&mut s, "interface.wifi.list", json!({})), json!([]));
    assert_eq!(run(&mut s, "interface.wifi.history", json!({})), json!([]));
    // The clock's round returns at once: no runtime is even made.
    for ms in 0..1000 {
        s.wifi_service(ms);
    }
    // The country can be set ahead of the card.
    run(
        &mut s,
        "interface.wifi.country.set",
        json!({"country": "BR"}),
    );
}

/// An import is one atomic batch, and an export writes the interfaces
/// before the country: the rule is about the configuration that results,
/// not about the order the commands came in.
#[test]
fn a_batch_may_enable_the_radio_before_it_sets_the_country() {
    let (mut s, air) = lab();
    let steps = json!([
        {"command": "interface.wifi.set", "params": {"name": "wifi1", "ssid": "CoreRouter-Lab", "passphrase": LAB_PASSPHRASE, "disabled": false}},
        {"command": "interface.wifi.country.set", "params": {"country": "BR"}},
    ]);
    s.batch(&steps, true).unwrap();
    spin(&mut s, 0);
    assert!(air.connected(&wifi1()));
    // The same without the country: nothing of it stays.
    let (mut s, air) = lab();
    let alone = json!([steps[0].clone()]);
    let e = s.batch(&alone, true).unwrap_err().to_string();
    assert!(e.contains("interface.wifi.country.set country=BR"), "{e}");
    assert_eq!(run(&mut s, "interface.wifi.list", json!({}))[0]["ssid"], "");
    spin(&mut s, 0);
    assert!(!air.connected(&wifi1()));
    // And a configuration stored with a radio on and no country (edited
    // by hand) is refused by the validation too.
    let mut cfg = s.store().running().clone();
    cfg.interfaces.get_mut(&wifi1()).unwrap().disabled = false;
    let issues = corerouter_engine::validate::validate_all(&cfg);
    assert!(
        issues.iter().any(|i| i.path == "interfaces.wifi1.disabled"),
        "{issues:?}"
    );
}

/// The edit modal's preview: `set` tried on the candidate and undone.
#[test]
fn the_preview_says_what_set_would_do_and_changes_nothing() {
    let (mut s, _air) = lab();
    let level = |v: &Value, check: &str| {
        v["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["check"] == check)
            .map(|c| c["level"].as_str().unwrap().to_owned())
    };
    // Empty fields of the modal are "not given"; a radio on with no country
    // is an error here, before the commit says so.
    let want = json!({"id": "wifi1", "ssid": "CoreRouter-Lab", "passphrase": LAB_PASSPHRASE,
                      "security": "", "mtu": "", "disabled": false});
    let p = run(&mut s, "interface.wifi.preview", want.clone());
    assert_eq!(level(&p, "country").as_deref(), Some("error"), "{p}");
    assert!(p.to_string().contains("interface.wifi.country.set"), "{p}");
    run(
        &mut s,
        "interface.wifi.country.set",
        json!({"country": "BR"}),
    );
    let p = run(&mut s, "interface.wifi.preview", want.clone());
    assert_eq!(level(&p, "valid").as_deref(), Some("ok"), "{p}");
    assert_eq!(level(&p, "country"), None, "{p}");
    assert_eq!(p["commands"][0]["command"], "interface.wifi.set");
    assert_eq!(p["commands"][0]["params"]["name"], "wifi1");
    assert!(p["commands"][0]["params"].get("id").is_none(), "{p}");
    let computed = p["computed"].to_string();
    assert!(
        computed.contains("CoreRouter-Lab") && computed.contains("no scan yet"),
        "{p}"
    );
    // Nothing changed.
    let row = &run(&mut s, "interface.wifi.list", json!({}))[0];
    assert_eq!(
        (row["ssid"].as_str(), row["disabled"].as_bool()),
        (Some(""), Some(true))
    );
    assert!(!s.store().is_dirty());

    // After a scan, whether the network is in range.
    run(&mut s, "interface.wifi.enable", json!({"name": "wifi1"}));
    let ms = spin(&mut s, 0);
    run(&mut s, "interface.wifi.scan", json!({"name": "wifi1"}));
    spin(&mut s, ms);
    let p = run(&mut s, "interface.wifi.preview", want);
    assert!(p["computed"].to_string().contains("yes: -"), "{p}");
    let p = run(
        &mut s,
        "interface.wifi.preview",
        json!({"id": "wifi1", "ssid": "Nao-Existe", "passphrase": "12345678"}),
    );
    assert!(p["computed"].to_string().contains("not heard"), "{p}");

    // A network heard only as 802.1X: `set` and the preview say why it will
    // not be joined, instead of a "not found" later. (The scan lists it; the
    // GUI greys it; typed by hand nothing said so.)
    let corp = json!({"ssid": "Corp", "passphrase": "12345678"});
    let mut id = corp.clone();
    id["id"] = json!("wifi1");
    let p = run(&mut s, "interface.wifi.preview", id);
    assert!(
        p["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["level"] == "warning" && c["message"].as_str().unwrap().contains("802.1X")),
        "{p}"
    );
    assert!(p["computed"].to_string().contains("yes: -70 dBm"), "{p}");
    let mut named = corp;
    named["name"] = json!("wifi1");
    let done = run(&mut s, "interface.wifi.set", named);
    assert!(done["warnings"].to_string().contains("802.1X"), "{done}");
    // One that can be joined says nothing of the kind; one not heard neither.
    for ssid in ["CoreRouter-Lab", "Nao-Existe"] {
        let p = run(
            &mut s,
            "interface.wifi.preview",
            json!({"id": "wifi1", "ssid": ssid, "passphrase": "12345678"}),
        );
        assert!(
            !p["checks"].to_string().contains("cannot join"),
            "{ssid}: {p}"
        );
    }
    run(
        &mut s,
        "interface.wifi.set",
        json!({"name": "wifi1", "ssid": ""}),
    );

    // What `set` refuses comes back as a check on its field, with no command.
    let p = run(
        &mut s,
        "interface.wifi.preview",
        json!({"id": "wifi1", "ssid": "CoreRouter-Lab", "passphrase": "curta"}),
    );
    let bad = &p["checks"][0];
    assert_eq!(
        (bad["level"].as_str(), bad["param"].as_str()),
        (Some("error"), Some("passphrase")),
        "{p}"
    );
    assert_eq!(p["commands"], json!([]));
    // Its warnings too.
    let p = run(
        &mut s,
        "interface.wifi.preview",
        json!({"id": "wifi1", "ssid": "Cafe", "security": "open"}),
    );
    assert!(
        p["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["level"] == "warning"
                && c["message"].as_str().unwrap().contains("open network")),
        "{p}"
    );
}
