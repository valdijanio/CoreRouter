use serde_json::json;

use super::*;
use crate::Session;

const T0: u64 = 1_800_000_000;

/// A lab session ticked once a second from `T0` for `secs` seconds.
fn ticked(secs: u64) -> Session {
    let mut s = Session::virtual_lab();
    for t in 0..secs {
        s.tick(T0 + t);
    }
    s
}

#[test]
fn the_tick_collects_physical_ports_and_the_system() {
    let mut s = ticked(130);
    let db = s.ext::<GraphDb>().unwrap();
    let keys: Vec<&str> = db.keys().collect();
    assert!(keys.contains(&"system"), "{keys:?}");
    assert!(keys.contains(&"interface:ether1"), "{keys:?}");
    let q = s
        .execute(
            "system.graph.query",
            &json!({"series": ["ether1", "system"], "range": "hour", "step": 60}),
        )
        .unwrap();
    assert_eq!(q["resolution"], 60, "a 60 s step reads the 1 min ring");
    let e1 = &q["series"][0];
    let rx = e1["stats"]["rx_bps"].clone();
    assert!(rx["avg"].as_f64().unwrap() > 0.0, "{rx}");
    assert!(rx["max"].as_f64().unwrap() >= rx["avg"].as_f64().unwrap());
    assert!(rx["current"].as_f64().unwrap() > 0.0);
    assert!(rx["max"].as_f64().unwrap() >= rx["current"].as_f64().unwrap(), "{rx}");
    assert!(e1["totals"]["rx_bytes"].as_f64().unwrap() > 0.0);
    assert!(e1["data"]["rx_bps"].as_array().unwrap().len() == 60);
    let cpu = &q["series"][1]["stats"]["cpu"];
    let load = cpu["avg"].as_f64().unwrap();
    assert!((0.0..=100.0).contains(&load) && load > 1.0, "{cpu}");
}

#[test]
fn rates_come_from_counter_deltas() {
    let name: IfName = "ether1".parse().unwrap();
    let mut db = GraphDb::default();
    let cfg = Graphing::default();
    let mut st = LinkState {
        name: name.clone(),
        running: true,
        rx_bytes: 0,
        tx_bytes: 0,
        rx_packets: 0,
        tx_packets: 0,
        kind: "ether".into(),
        mtu: 1500,
        mac: None,
        unmanaged: None,
        errors: None,
    };
    for i in 0..=120u64 {
        st.rx_bytes = i * 1_000; // 8 kbit/s
        st.rx_packets = if i == 60 { 0 } else { i * 10 }; // a reset at 60
        let links = [Link { name: &name, kind: "ether", live: Some(&st) }];
        db.sample(T0 + i, &cfg, &links, None);
    }
    // Two seconds apart: the rate fills both.
    st.rx_bytes += 2_000;
    let links = [Link { name: &name, kind: "ether", live: Some(&st) }];
    db.sample(T0 + 122, &cfg, &links, None);
    let r = db.get("interface:ether1").unwrap();
    let (a, _) = r.row(0, T0 + 50).unwrap();
    assert_eq!(a[0], 8_000.0);
    assert_eq!(a[2], 10.0);
    assert!(a[4].is_nan(), "errors not counted: unknown");
    assert!(r.row(0, T0 + 60).unwrap().0[2].is_nan(), "a counter that went down is unknown");
    assert_eq!(r.row(0, T0 + 121).unwrap().0[0], 8_000.0);
    let (m, max) = r.row(1, T0 / 60).unwrap();
    assert_eq!(m[0], 8_000.0);
    assert_eq!(max.unwrap()[0], 8_000.0);
}

#[test]
fn the_cap_refuses_and_the_grace_drops() {
    let mut s = Session::virtual_lab();
    s.execute("system.graph.set", &json!({"max_memory_mib": 2})).unwrap();
    for t in 0..3 {
        s.tick(T0 + t);
    }
    let p = s.execute("system.graph.print", &json!({})).unwrap();
    let kept = p["series"].as_array().unwrap().len();
    // 2 MiB: the system series and two interfaces (about 0.68 MiB each).
    assert_eq!(kept, 3, "{p}");
    assert!(!p["refused"].as_array().unwrap().is_empty());
    assert!(p["memory_bytes"].as_u64().unwrap() <= 2 * 1024 * 1024);
    let log = s.execute("log.print", &json!({})).unwrap().to_string();
    assert!(log.contains("not kept"), "the refusal is logged");

    s.execute("system.graph.set", &json!({"physical": false, "max_memory_mib": 64})).unwrap();
    s.tick(T0 + 10);
    assert_eq!(s.ext::<GraphDb>().unwrap().keys().count(), 3, "kept during the grace");
    s.tick(T0 + 10 + GRACE);
    let keys: Vec<String> = s.ext::<GraphDb>().unwrap().keys().map(str::to_owned).collect();
    assert_eq!(keys, vec!["system".to_string()]);
}

#[test]
fn store_patches_and_load_survive_a_restart() {
    let mut s = ticked(5);
    // Series the clock started before persistence are written whole.
    let db = s.ext_mut::<GraphDb>().unwrap();
    db.set_persistent("/x");
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let apply = |patches: Vec<Patch>, files: &mut BTreeMap<String, Vec<u8>>| {
        for p in patches {
            match p {
                Patch::Create { file, bytes } => {
                    files.insert(file, bytes);
                }
                Patch::Write { file, writes } => {
                    let f = files.get_mut(&file).unwrap();
                    for w in writes {
                        let at = w.offset as usize;
                        f[at..at + w.bytes.len()].copy_from_slice(&w.bytes);
                    }
                }
                Patch::Remove { file } => {
                    files.remove(&file);
                }
            }
        }
    };
    apply(db.take_patches(false), &mut files);
    for t in 5..400 {
        s.tick(T0 + t);
    }
    let db = s.ext_mut::<GraphDb>().unwrap();
    apply(db.take_patches(true), &mut files);
    let before = s
        .execute("system.graph.query", &json!({"series": "ether2", "range": "hour", "end": T0 + 360}))
        .unwrap();

    let mut back = Session::virtual_lab();
    let db = back.ext_mut::<GraphDb>().unwrap();
    for (f, b) in &files {
        db.load(f, b).unwrap();
    }
    back.tick(T0 + 400);
    let after = back
        .execute("system.graph.query", &json!({"series": "ether2", "range": "hour", "end": T0 + 360}))
        .unwrap();
    assert_eq!(before["series"][0]["data"], after["series"][0]["data"]);
    assert_eq!(
        before["series"][0]["stats"]["rx_bps"]["avg"],
        after["series"][0]["stats"]["rx_bps"]["avg"]
    );
    let db = back.ext_mut::<GraphDb>().unwrap();
    assert!(db.load("interface-ether2.rrd", b"junk").is_err());
    assert!(db.load("system.rrd", &files["interface-ether2.rrd"]).is_err(), "name and contents differ");
}

#[test]
fn export_hands_out_closed_buckets_after_a_cursor() {
    let mut s = ticked(250);
    let first = s
        .execute("system.graph.export", &json!({"resolution": 60, "series": ["ether1"], "limit": 2}))
        .unwrap();
    let rows = first["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "{first}");
    assert_eq!(first["more"], true);
    assert_eq!(rows[0]["time"], T0);
    assert!(rows[0]["avg"]["rx_bps"].as_f64().unwrap() > 0.0);
    let next = s
        .execute(
            "system.graph.export",
            &json!({"resolution": 60, "series": ["ether1"], "since": first["next"]}),
        )
        .unwrap();
    let rows = next["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 2, "minutes 2 and 3 are closed; the 4th is open");
    assert_eq!(next["more"], false);
    // Every series of a bucket comes in the same page.
    let all = s.execute("system.graph.export", &json!({"resolution": 60, "limit": 3})).unwrap();
    let times: Vec<u64> = all["rows"].as_array().unwrap().iter().map(|r| r["time"].as_u64().unwrap()).collect();
    assert!(times.iter().all(|t| *t == T0), "{times:?}");
}

#[test]
fn disabled_collects_nothing() {
    let mut s = Session::virtual_lab();
    s.execute("system.graph.set", &json!({"enabled": false})).unwrap();
    for t in 0..5 {
        s.tick(T0 + t);
    }
    assert!(s.ext::<GraphDb>().is_none_or(|d| d.keys().count() == 0));
}

#[test]
fn file_names_round_trip() {
    for key in ["system", "interface:ether1", "interface:vlan.10", "interface:a-b_c"] {
        let f = file_name(key).unwrap();
        assert_eq!(key_of_file(&f).as_deref(), Some(key));
    }
    assert_eq!(file_name("interface:../x"), None);
    assert_eq!(key_of_file("interface-..rrd"), None);
    assert_eq!(key_of_file("other.txt"), None);
}

#[test]
fn queue_series_have_safe_file_names() {
    for name in ["cam", "<pppoe-ana>", "dhcp-ds<pc 1>", "câmera"] {
        let key = queue_key(name).unwrap();
        let file = file_name(&key).unwrap();
        assert!(file.bytes().all(|b| b.is_ascii_alphanumeric() || b"%._-".contains(&b)), "{file}");
        assert_eq!(key_of_file(&file).as_deref(), Some(key.as_str()), "{file}");
        assert_eq!(sources(&key).len(), QUEUE_SOURCES.len());
    }
    assert_eq!(queue_key(&"x".repeat(59)), None, "past the 64 bytes of a series header");
    assert_eq!(key_of_file("queue-%zz.rrd"), None);
    assert_eq!(key_of_file("queue-a b.rrd"), None);
}
