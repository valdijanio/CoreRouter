//! MCP protocol tests (helpers outside #[test] fns may unwrap too).
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::io::Cursor;

use corerouter_engine::Session;
use corerouter_mcp::{Headless, serve};
use proptest::prelude::*;
use serde_json::{Value, json};

fn run(lines: &[Value]) -> Vec<Value> {
    let input: String = lines.iter().map(|l| format!("{l}\n")).collect();
    run_raw(&input)
}

fn run_raw(input: &str) -> Vec<Value> {
    let mut backend = Headless::new(Session::virtual_lab());
    let mut out = Vec::new();
    serve(
        &mut backend,
        Cursor::new(input.as_bytes().to_vec()),
        &mut out,
    )
    .unwrap();
    String::from_utf8(out)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn initialize_list_and_call() {
    let out = run(&[
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"run_command",
            "arguments":{"command":"ip.address.add","params":{"address":"10.1.1.1/30","interface":"ether2"}}}}),
        json!({"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"inspect_state",
            "arguments":{"path":"ip.addresses"}}}),
        json!({"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"ui_screenshot"}}),
        json!({"jsonrpc":"2.0","id":6,"method":"nope"}),
    ]);
    assert_eq!(out.len(), 6, "notification must not be answered");
    assert_eq!(out[0]["result"]["serverInfo"]["name"], "corerouter");
    assert!(out[1]["result"]["tools"].as_array().unwrap().len() >= 5);
    assert_eq!(out[2]["result"]["isError"], false);
    let text = out[3]["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("10.1.1.1/30"));
    assert_eq!(out[4]["result"]["isError"], true, "no UI in headless");
    assert_eq!(out[5]["error"]["code"], -32601);
}

#[test]
fn tool_errors_are_readable_text() {
    let out = run(&[
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{
        "name":"run_command","arguments":{"command":"ip.address.add","params":{"adress":"x"}}}}),
    ]);
    assert_eq!(out[0]["result"]["isError"], true);
    assert!(
        out[0]["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("did you mean 'address'")
    );
}

#[test]
fn parse_error_and_batch() {
    let out = run_raw("{not json\n[{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"ping\"}]\n");
    assert_eq!(out[0]["error"]["code"], -32700);
    assert_eq!(out[1][0]["id"], 7);
}

proptest! {
    #[test]
    fn hostile_lines_never_break_the_server(lines in proptest::collection::vec(".{0,200}", 0..8)) {
        let input: String = lines.iter().map(|l| format!("{l}\n")).collect();
        for reply in run_raw(&input) {
            prop_assert!(reply.is_object() || reply.is_array());
        }
    }
}

#[test]
fn run_task_pings_and_returns_the_statistics() {
    let mut lab = Session::virtual_lab();
    lab.set_runner(corerouter_control::thread_runner());
    let mut backend = Headless::new(lab);
    let mut call = |args: Value| {
        let msg = json!({"jsonrpc":"2.0","id":1,"method":"tools/call",
            "params":{"name":"run_task","arguments": args}});
        let input = format!("{msg}\n");
        let mut out = Vec::new();
        serve(&mut backend, Cursor::new(input.into_bytes()), &mut out).unwrap();
        let reply: Value = serde_json::from_slice(&out).unwrap();
        reply["result"].clone()
    };
    let r = call(json!({"command": "tool.ping.start",
        "params": {"address": ["127.0.0.1", "203.0.113.1"], "count": 3, "interval_ms": 20,
            "timeout_ms": 100}}));
    assert_eq!(r["isError"], false, "{r}");
    let v: Value = serde_json::from_str(r["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(v["state"], "done");
    assert_eq!(v["summary"]["targets"][0]["received"], 3);
    assert_eq!(v["summary"]["targets"][1]["loss_pct"], 100.0);
    assert_eq!(v["events"].as_array().unwrap().len(), 6);

    // Continuous: stopped after wait_secs, statistics kept.
    let r = call(json!({"command": "tool.ping.start",
        "params": {"address": "127.0.0.1", "interval_ms": 100}, "wait_secs": 1}));
    let v: Value = serde_json::from_str(r["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(v["state"], "stopped");
    assert_eq!(v["stopped_after_wait"], true);
    assert!(v["summary"]["targets"][0]["received"].as_u64().unwrap() >= 5);

    // Not a task: readable error.
    let r = call(json!({"command": "interface.list"}));
    assert_eq!(r["isError"], true);
}
