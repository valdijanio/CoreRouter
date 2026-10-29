//! Every command, fed garbage, must return Ok or a typed error — never
//! `Internal` (which would mean a panic was caught by the guard).

use corerouter_engine::{EngineError, Session, cmd};
use serde_json::{Value, json};

fn garbage() -> Vec<Value> {
    vec![
        Value::Null,
        json!(true),
        json!(-1),
        json!(1e308),
        json!(u64::MAX),
        json!(""),
        json!("zz"),
        json!("*FFFFFFFFFF"),
        json!("10.0.0.1/99"),
        json!("x".repeat(10_000)),
        json!("\u{0}\u{7}"),
        json!([]),
        json!({}),
    ]
}

/// G0.30: the commands split over the cores (the sweep grows with every
/// command added; one after the other it took ~8 s in a dev build). Each
/// input still gets a fresh lab.
#[test]
fn no_command_panics_on_garbage() {
    let specs: Vec<_> = cmd::all().collect();
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get().min(8));
    let chunk = specs.len().div_ceil(threads).max(1);
    let failures: Vec<String> = std::thread::scope(|scope| {
        let parts: Vec<_> = specs
            .chunks(chunk)
            .map(|part| {
                scope.spawn(move || {
                    part.iter()
                        .filter_map(|s| sweep(s).err())
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        parts.into_iter().flat_map(|p| p.join().unwrap()).collect()
    });
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Every garbage input of one command; `Err` names the one that panicked.
fn sweep(spec: &cmd::CommandSpec) -> Result<(), String> {
    let mut inputs = vec![Value::Null, json!([]), json!(42), json!({"bogus": 1})];
    let keys = cmd::doc_keys(spec.params);
    for g in garbage() {
        let mut obj = serde_json::Map::new();
        for (k, _) in &keys {
            obj.insert((*k).to_owned(), g.clone());
        }
        inputs.push(Value::Object(obj));
        for (k, _) in &keys {
            inputs.push(json!({ *k: g.clone() }));
        }
    }
    for params in inputs {
        let mut s = Session::virtual_lab();
        if let Err(EngineError::Internal(what)) = s.execute(spec.id, &params) {
            return Err(format!("{what} panicked with params {params}"));
        }
    }
    Ok(())
}
