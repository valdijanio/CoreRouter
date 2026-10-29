//! G0.5: short, deterministic fuzzing of the saved config file for
//! `cargo xtask ci`; the long run is `cargo fuzz` (docs/fuzzing.md). Every
//! seed and every regression under `fuzz/` replays here too.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::path::Path;

use corerouter_engine::fuzz::config_file;
use corerouter_engine::{MemoryStorage, Session, Slot};
use corerouter_hal::VirtualHal;
use proptest::prelude::*;
use proptest::test_runner::{Config, RngSeed};
use serde_json::{Value, json};

/// Fixed seed and no failure files: the same cases on every machine.
/// `COREROUTER_FUZZ_CASES=N` runs N cases with a random seed instead (the
/// long run without nightly; a failure prints the seed to replay).
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

/// Files of `fuzz/<kind>/<target>`, the corpus `cargo fuzz` starts from
/// and the crashes it found.
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

/// A file saved by a router with a bit of everything configured.
fn saved_file() -> String {
    let storage = MemoryStorage::default();
    let mut s = Session::with_storage(Box::new(VirtualHal::default()), Box::new(storage.clone()));
    for (id, p) in [
        (
            "ip.address.add",
            json!({"address": "10.0.0.1/24", "interface": "ether1"}),
        ),
        (
            "interface.vlan.add",
            json!({"name": "v10", "vlan_id": 10, "parent": "ether2"}),
        ),
        (
            "ip.route.add",
            json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.254"}),
        ),
        (
            "user.add",
            json!({"name": "noc", "group": "read", "password": "pw-0123456789"}),
        ),
    ] {
        s.execute(id, &p).unwrap();
    }
    storage.get(Slot::Current).unwrap()
}

fn json_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|n| json!(n)),
        any::<u64>().prop_map(|n| json!(n)),
        any::<f64>().prop_map(|n| json!(n)),
        "\\PC{0,40}".prop_map(Value::String),
        "(10|192\\.168|fe80:)[0-9./:]{0,12}".prop_map(Value::String),
    ];
    leaf.prop_recursive(4, 32, 6, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            proptest::collection::btree_map("[a-z-]{1,12}", inner, 0..6)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

/// Replace the node at `path` (indices into objects/arrays, wrapping).
fn graft(v: &mut Value, path: &[usize], new: Value) {
    let Some((&step, rest)) = path.split_first() else {
        *v = new;
        return;
    };
    let child = match v {
        Value::Object(o) if !o.is_empty() => {
            let n = o.len();
            o.values_mut().nth(step % n)
        }
        Value::Array(a) if !a.is_empty() => {
            let n = a.len();
            a.get_mut(step % n)
        }
        _ => None,
    };
    match child {
        Some(c) => graft(c, rest, new),
        None => *v = new,
    }
}

#[derive(Debug, Clone)]
enum Edit {
    Text(String),
    Number(Value),
    Flip,
    Duplicate,
    Remove,
    Clear,
}

fn edit() -> impl Strategy<Value = Edit> {
    prop_oneof![
        prop_oneof![
            "\\PC{0,40}",
            "[0-9a-f:.]{0,20}(/[0-9]{1,3})?",
            "ether[0-9]{1,2}|v10|lo|bridge1|\\*[0-9A-F]{1,4}",
        ]
        .prop_map(Edit::Text),
        prop_oneof![
            any::<u64>().prop_map(|n| json!(n)),
            any::<i64>().prop_map(|n| json!(n)),
            (0u64..70_000).prop_map(|n| json!(n)),
        ]
        .prop_map(Edit::Number),
        Just(Edit::Flip),
        Just(Edit::Duplicate),
        Just(Edit::Remove),
        Just(Edit::Clear),
    ]
}

/// Walk `path` (indices wrap) and apply `e` where it fits the JSON type:
/// a string gets new text, a number a new number, a bool flips, an array
/// duplicates, removes or clears an element (duplicates make clashing
/// names and ids, which a hand-edited file can have).
fn mutate(v: &mut Value, path: &[usize], e: Edit) {
    if let Some((&step, rest)) = path.split_first() {
        let child = match v {
            Value::Object(o) if !o.is_empty() => {
                let n = o.len();
                o.values_mut().nth(step % n)
            }
            Value::Array(a) if !a.is_empty() && !rest.is_empty() => {
                let n = a.len();
                a.get_mut(step % n)
            }
            _ => None,
        };
        if let Some(c) = child {
            return mutate(c, rest, e);
        }
    }
    match (v, e) {
        (Value::String(s), Edit::Text(t)) => *s = t,
        (n @ Value::Number(_), Edit::Number(m)) => *n = m,
        (Value::Bool(b), Edit::Flip) => *b = !*b,
        (Value::Array(a), Edit::Duplicate) => {
            if let Some(first) = a.first().cloned() {
                a.push(first);
            }
        }
        (Value::Array(a), Edit::Remove) => {
            a.pop();
        }
        (Value::Array(a), Edit::Clear) => a.clear(),
        _ => {}
    }
}

#[test]
fn seeds_and_regressions_replay() {
    for (name, data) in corpus("config_file") {
        if let Err(e) = config_file(&data) {
            panic!("{name}: {e}");
        }
    }
    for (name, data) in corpus("routeros_export") {
        if let Err(e) = corerouter_engine::fuzz::routeros_export(&data) {
            panic!("{name}: {e}");
        }
    }
}

/// The oracles would be blind without this: the guard catches the panic
/// and the command just fails, but the hook still counts it.
#[test]
fn caught_panics_are_counted() {
    let (caught, n) = corerouter_engine::fuzz::panics(|| {
        corerouter_engine::guard::run("fuzz.selftest", || -> Result<(), _> { panic!("boom") })
    });
    assert!(caught.is_err());
    assert_eq!(n, 1);
    assert_eq!(corerouter_engine::fuzz::panics(|| ()).1, 0);
}

#[test]
fn saved_file_is_a_fixed_point() {
    config_file(saved_file().as_bytes()).unwrap();
}

proptest! {
    #![proptest_config(config(64))]

    /// A real file with one node swapped for random JSON: gets past the
    /// parser into the store checks and the boot.
    #[test]
    fn grafted_file_never_breaks_the_boot(
        path in proptest::collection::vec(any::<usize>(), 0..8),
        new in json_value(),
    ) {
        let mut v: Value = serde_json::from_str(&saved_file()).unwrap();
        graft(&mut v, &path, new);
        if let Err(e) = config_file(v.to_string().as_bytes()) {
            prop_assert!(false, "{e}");
        }
    }

    /// Type-preserving edits inside `running` (copied to the newest
    /// revision so the store checks pass): the file still decodes and a
    /// hostile but well-typed config reaches the engine.
    #[test]
    fn mutated_config_never_breaks_the_boot(
        edits in proptest::collection::vec(
            (proptest::collection::vec(any::<usize>(), 1..8), edit()), 1..6),
    ) {
        let mut v: Value = serde_json::from_str(&saved_file()).unwrap();
        for (path, e) in edits {
            mutate(&mut v["running"], &path, e);
        }
        let running = v["running"].clone();
        if let Some(last) = v["history"].as_array_mut().and_then(|h| h.last_mut()) {
            last["config"] = running;
        }
        if let Err(e) = config_file(v.to_string().as_bytes()) {
            prop_assert!(false, "{e}");
        }
    }

    /// G4.3n: export-shaped text with hostile quoting and bounds.
    #[test]
    fn routeros_exports_never_panic(
        t in "(/ppp secret\n|/ppp profile\n|add |set |\\[ find name=|\\]|\\*0 |name=|password=|profile=|service=pppoe |caller-id=|\"|\\\\|\\\\\n    |\\\\C3\\\\A7|[a-z0-9 =;#\n])*",
    ) {
        if let Err(e) = corerouter_engine::fuzz::routeros_export(t.as_bytes()) {
            prop_assert!(false, "{e}");
        }
    }

    #[test]
    fn raw_bytes_never_break_the_boot(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        if let Err(e) = config_file(&bytes) {
            prop_assert!(false, "{e}");
        }
    }
}
