//! Bateria da fila de entrada: feature sintética 01.
#![allow(clippy::unwrap_used)]

use corerouter_engine::Session;
use serde_json::json;

#[test]
fn bench_f01_answers() {
    let mut s = Session::virtual_lab();
    let v = s.execute("bench.f01.get", &json!({})).unwrap();
    assert_eq!(v["n"], json!(1));
}
