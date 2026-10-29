//! Property tests of `tool.ping.start` / `tool.ping.mtu` parameters: any
//! input is either refused with a parameter error before anything starts,
//! or starts a task whose values are inside the documented ranges.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use corerouter_engine::{Clock, EngineError, Job, Runner, Session};
use proptest::prelude::*;
use serde_json::{Value, json};

struct Threads;
struct Wall(Instant);

impl Clock for Wall {
    fn elapsed(&self) -> Duration {
        self.0.elapsed()
    }
    fn sleep(&self, d: Duration) {
        thread::sleep(d);
    }
}

impl Runner for Threads {
    fn spawn(&self, _name: &str, job: Job) -> Result<(), String> {
        thread::spawn(move || job(&Wall(Instant::now())));
        Ok(())
    }
}

fn lab() -> Session {
    let mut s = Session::virtual_lab();
    s.set_runner(Arc::new(Threads));
    s
}

fn any_value() -> impl Strategy<Value = Value> {
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::from),
        any::<i64>().prop_map(Value::from),
        (0u64..70_000).prop_map(Value::from),
        any::<f64>().prop_map(|f| json!(f)),
        "[ -~]{0,40}".prop_map(Value::from),
        prop::collection::vec("[0-9a-z.:,]{0,20}", 0..20).prop_map(|v| json!(v)),
    ]
}

fn address() -> impl Strategy<Value = Value> {
    prop_oneof![
        any_value(),
        Just(json!("127.0.0.1")),
        Just(json!("::1, 198.51.100.4")),
        Just(json!(["example.com", "10.0.0.1"])),
        "[a-z]{1,10}\\.[a-z]{2,3}".prop_map(Value::from),
    ]
}

const KEYS: [&str; 10] = [
    "count",
    "interval_ms",
    "timeout_ms",
    "size",
    "ttl",
    "dscp",
    "do_not_fragment",
    "src_address",
    "interface",
    "routing_table",
];

fn in_range(p: &Value, key: &str, lo: u64, hi: u64) -> bool {
    match p.get(key) {
        None | Some(Value::Null) => true,
        Some(v) => v.as_u64().is_some_and(|n| (lo..=hi).contains(&n)),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn ping_params_are_checked_before_starting(
        addr in address(),
        values in prop::collection::vec(any_value(), KEYS.len()),
        mask in prop::collection::vec(any::<bool>(), KEYS.len()),
    ) {
        let mut s = lab();
        let mut p = serde_json::Map::new();
        p.insert("address".into(), addr);
        for ((k, v), on) in KEYS.iter().zip(values).zip(mask) {
            if on {
                p.insert((*k).into(), v);
            }
        }
        let p = Value::Object(p);
        match s.execute("tool.ping.start", &p) {
            Ok(r) => {
                let id = r["task_id"].as_u64().unwrap();
                prop_assert!(in_range(&p, "count", 0, 1_000_000));
                prop_assert!(in_range(&p, "interval_ms", 10, 60_000));
                prop_assert!(in_range(&p, "timeout_ms", 10, 10_000));
                prop_assert!(in_range(&p, "size", 28, 65_535));
                prop_assert!(in_range(&p, "ttl", 1, 255));
                prop_assert!(in_range(&p, "dscp", 0, 63));
                let n = r["targets"].as_array().unwrap().len();
                prop_assert!((1..=16).contains(&n));
                s.execute("tool.task.stop", &json!({"id": id})).unwrap();
            }
            Err(EngineError::BadParam { .. }) => {
                let tasks = s.execute("tool.task.list", &Value::Null).unwrap();
                prop_assert!(tasks.as_array().unwrap().is_empty());
            }
            Err(other) => panic!("{p}: unexpected {other:?}"),
        }
    }

    #[test]
    fn mtu_and_poll_params_never_panic(a in any_value(), b in any_value(), c in any_value()) {
        let mut s = lab();
        for (cmd, p) in [
            ("tool.ping.mtu", json!({"address": a, "max_size": b, "retries": c})),
            ("tool.task.poll", json!({"id": a, "after_seq": b, "max": c})),
            ("tool.task.stop", json!({"id": a})),
        ] {
            if let Err(EngineError::Internal(e)) = s.execute(cmd, &p) {
                panic!("{cmd} {p}: {e}");
            }
        }
        for t in s.execute("tool.task.list", &json!({})).unwrap().as_array().unwrap() {
            s.execute("tool.task.stop", &json!({"id": t["id"]})).unwrap();
        }
    }
}
