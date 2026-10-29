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

#[test]
fn no_command_panics_on_garbage() {
    for spec in cmd::all() {
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
                panic!("{what} panicked with params {params}");
            }
        }
    }
}
