//! Bateria da fila de entrada: feature sintética 09.
#![allow(clippy::unwrap_used)]

use corerouter_engine::Session;
use serde_json::json;

#[test]
fn bench_f09_answers() {
    let mut s = Session::virtual_lab();
    let v = s.execute("bench.f09.get", &json!({})).unwrap();
    assert_eq!(v["n"], json!(9));
}

#[test]
fn bench_f09_builds_a_system_literal() {
    let s = corerouter_model::System {
        identity: "edge-1".into(),
    };
    assert_eq!(s.identity, "edge-1");
}
