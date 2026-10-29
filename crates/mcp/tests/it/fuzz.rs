//! G0.5: short, deterministic fuzzing of the MCP stdio server for
//! `cargo xtask ci`; the long run is `cargo fuzz` (docs/fuzzing.md). Every
//! seed and regression under `fuzz/` replays here too.
#![allow(clippy::unwrap_used)]

use std::path::Path;

use corerouter_engine::cmd;
use corerouter_mcp::fuzz::messages;
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

/// `tools/call` arguments shaped like the tools expect, or not.
fn arguments() -> impl Strategy<Value = Value> {
    let ids: Vec<&str> = cmd::all().map(|c| c.id).collect();
    let id = proptest::sample::select(ids).prop_map(Value::from);
    prop_oneof![
        json_value(),
        (id.clone(), json_value()).prop_map(|(c, p)| json!({"command": c, "params": p})),
        (
            proptest::collection::vec((id.clone(), json_value()), 0..4),
            json_value()
        )
            .prop_map(|(steps, atomic)| {
                let steps: Vec<Value> = steps
                    .into_iter()
                    .map(|(c, p)| json!({"command": c, "params": p}))
                    .collect();
                json!({"steps": steps, "atomic": atomic})
            }),
        (id, json_value(), 0u64..3)
            .prop_map(|(c, p, w)| json!({"command": c, "params": p, "wait_secs": w})),
        "\\PC{0,20}".prop_map(|p| json!({"prefix": p, "path": p})),
    ]
}

fn message() -> impl Strategy<Value = Value> {
    let method = prop_oneof![
        proptest::sample::select(vec![
            "initialize",
            "ping",
            "tools/list",
            "tools/call",
            "notifications/initialized",
        ])
        .prop_map(Value::from),
        json_value(),
    ];
    let tool = prop_oneof![
        proptest::sample::select(vec![
            "list_commands",
            "command_list",
            "run_command",
            "command_run",
            "command_batch",
            "inspect_state",
            "state_inspect",
            "run_task",
            "task_run",
            "ui_screenshot",
        ])
        .prop_map(Value::from),
        json_value(),
    ];
    (
        proptest::option::of(json_value()),
        method,
        tool,
        arguments(),
    )
        .prop_map(|(id, method, name, args)| {
            let mut m = json!({"jsonrpc": "2.0", "method": method,
                "params": {"name": name, "arguments": args}});
            if let (Some(id), Some(o)) = (id, m.as_object_mut()) {
                o.insert("id".into(), id);
            }
            m
        })
}

#[test]
fn seeds_and_regressions_replay() {
    for (name, data) in corpus("mcp_messages") {
        if let Err(e) = messages(&data) {
            panic!("{name}: {e}");
        }
    }
}

proptest! {
    #![proptest_config(config(96))]

    /// One message per line, or batches of them.
    #[test]
    fn sessions_never_break(lines in proptest::collection::vec(
        prop_oneof![
            message().prop_map(|m| m.to_string()),
            proptest::collection::vec(message(), 0..4).prop_map(|b| Value::Array(b).to_string()),
        ], 1..6)) {
        let input: String = lines.iter().map(|l| format!("{l}\n")).collect();
        if let Err(e) = messages(input.as_bytes()) {
            prop_assert!(false, "{e}");
        }
    }

    #[test]
    fn raw_bytes_never_break(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        if let Err(e) = messages(&bytes) {
            prop_assert!(false, "{e}");
        }
    }
}
