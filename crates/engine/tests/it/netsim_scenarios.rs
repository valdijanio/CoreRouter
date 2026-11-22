//! G3.7: scenarios exported from Tools › Network Simulator
//! (`tool.netsim.export {expect: true}`) run as tests: every
//! `tests/netsim/*.json` is loaded, run to its `run_ms`, and each virtual
//! router must have the BGP routes and sessions the file expects.
//!
//! A new one: build it in the window (or by commands), export with
//! "expect", save it here. `NETSIM_WRITE=1 cargo test -p corerouter-engine
//! --test it netsim_scenarios:: -- --ignored` rewrites the bundled example.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::Path;

use corerouter_engine::Session;
use serde_json::{Value, json};

fn run(s: &mut Session, until_ms: u64) {
    loop {
        let now = s.execute("tool.netsim.get", &json!({})).unwrap()["now_ms"]
            .as_u64()
            .unwrap();
        if now >= until_ms {
            return;
        }
        s.execute("tool.netsim.advance", &json!({"ms": until_ms - now}))
            .unwrap();
    }
}

#[test]
fn exported_scenarios_still_hold() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/netsim");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "no scenario in {}", dir.display());
    for f in files {
        let file: Value = serde_json::from_str(&std::fs::read_to_string(&f).unwrap()).unwrap();
        let mut s = Session::virtual_lab();
        let r = s
            .execute("tool.netsim.load", &json!({"scenario": file}))
            .unwrap_or_else(|e| panic!("{}: {e}", f.display()));
        run(&mut s, r["run_ms"].as_u64().unwrap());
        let now = s
            .execute("tool.netsim.export", &json!({"expect": true}))
            .unwrap();
        assert_eq!(now["expect"], file["expect"], "{}", f.display());
    }
}

/// The bundled example: the 4-router square, the R4–R1 upstream link cut
/// at 60 s (BFD), 30 s more. R1 keeps every prefix through R3.
#[test]
#[ignore]
fn write_the_example() {
    if std::env::var_os("NETSIM_WRITE").is_none() {
        return;
    }
    let mut s = Session::virtual_lab();
    s.execute("tool.netsim.new", &json!({"preset": "square", "seed": 7}))
        .unwrap();
    run(&mut s, 60_000);
    let v = s.execute("tool.netsim.get", &json!({})).unwrap();
    let link = v["links"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["a_iface"] == "ether1" && l["b"] == 0 && l["a"] == 3)
        .unwrap()["id"]
        .clone();
    s.execute(
        "tool.netsim.fault",
        &json!({"kind": "link-cut", "link": link}),
    )
    .unwrap();
    run(&mut s, 90_000);
    let file = s
        .execute("tool.netsim.export", &json!({"expect": true}))
        .unwrap();
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/netsim/square-upstream-cut.json");
    std::fs::write(path, serde_json::to_string_pretty(&file).unwrap() + "\n").unwrap();
}
