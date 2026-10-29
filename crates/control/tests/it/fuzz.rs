//! G0.5: short, deterministic fuzzing of the control channel for
//! `cargo xtask ci` (line framing and request lines); the long run is
//! `cargo fuzz` (docs/fuzzing.md). Every seed and regression under `fuzz/`
//! replays here too.
#![allow(clippy::unwrap_used)]

use std::path::Path;

use corerouter_control::fuzz::{control_line, wire};
use corerouter_engine::cmd;
use proptest::prelude::*;
use proptest::test_runner::{Config, RngSeed};
use serde_json::{Value, json};

/// Fixed seed and no failure files: the same cases on every machine.
/// `COREROUTER_FUZZ_CASES=N` runs N cases with a random seed instead.
fn config(cases: u32) -> Config {
    let long = std::env::var("COREROUTER_FUZZ_CASES")
        .ok()
        .and_then(|n| n.parse().ok());
    Config {
        cases: long.unwrap_or(cases),
        rng_seed: if long.is_some() {
            RngSeed::Random
        } else {
            RngSeed::Fixed(0x6005)
        },
        failure_persistence: None,
        ..Config::default()
    }
}

fn corpus(target: &str) -> Vec<(String, Vec<u8>)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz");
    let mut out = Vec::new();
    for kind in ["seeds", "regressions"] {
        let Ok(dir) = std::fs::read_dir(root.join(kind).join(target)) else {
            continue;
        };
        for f in dir.flatten() {
            out.push((
                f.path().display().to_string(),
                std::fs::read(f.path()).unwrap(),
            ));
        }
    }
    out
}

fn json_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|n| json!(n)),
        any::<f64>().prop_map(|n| json!(n)),
        "\\PC{0,40}".prop_map(Value::String),
        "\\$[0-9]{1,2}\\.[a-z]{1,6}".prop_map(Value::String),
        "(10|192\\.168|fe80:)[0-9./:]{0,12}".prop_map(Value::String),
        "ether[0-9]|\\*[0-9A-F]{1,3}".prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 32, 6, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            proptest::collection::btree_map("[a-z_]{1,12}", inner, 0..6)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

/// A command id from the registry (or a near miss), with random params.
fn step() -> impl Strategy<Value = Value> {
    let ids: Vec<&str> = cmd::all().map(|c| c.id).collect();
    (proptest::sample::select(ids), any::<bool>(), json_value()).prop_map(|(id, typo, params)| {
        let id = if typo {
            format!("{id}x")
        } else {
            id.to_owned()
        };
        json!({"command": id, "params": params})
    })
}

fn request() -> impl Strategy<Value = Value> {
    let params = prop_oneof![
        json_value(),
        step(),
        (proptest::collection::vec(step(), 0..5), any::<bool>())
            .prop_map(|(steps, atomic)| json!({"steps": steps, "atomic": atomic})),
        "\\PC{0,30}".prop_map(|p| json!({"path": p})),
        ("\\PC{0,12}", "\\PC{0,12}").prop_map(|(u, p)| json!({"user": u, "password": p})),
    ];
    let method = prop_oneof![
        proptest::sample::select(vec![
            "ping",
            "server.info",
            "engine.list",
            "engine.execute",
            "engine.batch",
            "state.inspect",
            "ui.screenshot",
            "auth.login",
            "auth.logout",
            "auth.whoami",
        ])
        .prop_map(Value::from),
        json_value(),
    ];
    (
        json_value(),
        method,
        params,
        proptest::option::of(json_value()),
    )
        .prop_map(|(id, method, params, token)| {
            let mut r = json!({"id": id, "method": method, "params": params});
            if let Some(t) = token {
                r.as_object_mut().map(|o| o.insert("token".into(), t));
            }
            r
        })
}

#[test]
fn seeds_and_regressions_replay() {
    for (target, oracle) in [
        ("wire", wire as fn(&[u8]) -> Result<(), String>),
        ("control_line", control_line),
    ] {
        for (name, data) in corpus(target) {
            if let Err(e) = oracle(&data) {
                panic!("{name}: {e}");
            }
        }
    }
}

proptest! {
    #![proptest_config(config(512))]

    #[test]
    fn line_framing_holds(bytes in proptest::collection::vec(
        prop_oneof![any::<u8>(), Just(b'\n'), Just(b'\r')], 0..300)) {
        if let Err(e) = wire(&bytes) {
            prop_assert!(false, "{e}");
        }
    }
}

proptest! {
    #![proptest_config(config(96))]

    #[test]
    fn requests_never_panic(req in request()) {
        if let Err(e) = control_line(req.to_string().as_bytes()) {
            prop_assert!(false, "{e}");
        }
    }

    #[test]
    fn raw_lines_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
        if let Err(e) = control_line(&bytes) {
            prop_assert!(false, "{e}");
        }
    }
}
