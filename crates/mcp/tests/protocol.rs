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

/// Audit (control finding 6): `run_task` is annotated read-only, so it must
/// not run a config change before noticing it started no task.
#[test]
fn run_task_refuses_anything_but_a_tool() {
    let out = run(&[
        json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"run_task",
            "arguments":{"command":"system.identity.set","params":{"name":"pwned"}}}}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"inspect_state",
            "arguments":{}}}),
    ]);
    assert_eq!(out[0]["result"]["isError"], true);
    let state = out[1]["result"]["content"][0]["text"].as_str().unwrap();
    assert!(!state.contains("pwned"), "{state}");
}

/// Audit (control finding 14): JSON-RPC 2.0 §5, a response is never
/// answered; §4, an id is a string, a number or null.
#[test]
fn responses_are_not_answered_and_ids_are_scalars() {
    let out = run(&[
        json!({"jsonrpc":"2.0","id":1,"result":{}}),
        json!({"jsonrpc":"2.0","id":2,"error":{"code":-1,"message":"x"}}),
        json!({"jsonrpc":"2.0","id":{"a":1},"method":"ping"}),
        json!({"jsonrpc":"2.0","id":[1],"method":"ping"}),
        json!({"jsonrpc":"2.0","id":"s","method":"ping"}),
    ]);
    assert_eq!(out.len(), 3, "{out:?}");
    for bad in &out[..2] {
        assert_eq!(
            (&bad["id"], &bad["error"]["code"]),
            (&Value::Null, &json!(-32600))
        );
    }
    assert_eq!(out[2]["id"], "s");
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
    assert_eq!(out.len(), 2);
    assert_eq!(out[0]["error"]["code"], -32700);
    // MCP 2025-06-18 removed batching: one error object, id null (JSON-RPC 2.0 §6).
    assert_eq!(out[1]["error"]["code"], -32600);
    assert_eq!(out[1]["id"], Value::Null);
    assert!(
        out[1]["error"]["message"]
            .as_str()
            .unwrap()
            .contains("batches are not supported")
    );
}

fn add_address(id: u64) -> Value {
    call(
        id,
        "tools/call",
        json!({"name": "run_command", "arguments": {"command": "ip.address.add",
            "params": {"address": "10.9.9.1/24", "interface": "ether1"}}}),
    )
}

fn address_count(out: &Value) -> usize {
    let text = out["result"]["content"][0]["text"].as_str().unwrap();
    text.matches("10.9.9.1/24").count()
}

#[test]
fn batch_items_never_run_and_the_server_keeps_serving() {
    let list = || {
        call(
            9,
            "tools/call",
            json!({"name": "run_command", "arguments": {"command": "ip.address.list"}}),
        )
    };
    let empty = Value::Array(vec![]);
    let batch = Value::Array(vec![add_address(1), call(2, "ping", json!({}))]);
    let out = run(&[empty, batch, list(), add_address(3), list()]);
    assert_eq!(out.len(), 5, "{out:?}");
    for reply in &out[..2] {
        assert!(reply.is_object(), "{reply}");
        assert_eq!(reply["error"]["code"], -32600, "{reply}");
        assert_eq!(reply["id"], Value::Null);
    }
    assert_eq!(address_count(&out[2]), 0, "a batch item ran: {}", out[2]);
    assert_eq!(out[3]["result"]["isError"], false, "{}", out[3]);
    assert_eq!(address_count(&out[4]), 1, "{}", out[4]);
}

proptest! {
    #[test]
    fn hostile_lines_never_break_the_server(lines in proptest::collection::vec(".{0,200}", 0..8)) {
        let input: String = lines.iter().map(|l| format!("{l}\n")).collect();
        for reply in run_raw(&input) {
            prop_assert!(reply.is_object());
        }
    }

    /// Any array, however its items look, gets exactly one -32600 object.
    #[test]
    fn every_batch_is_refused_with_one_object(ids in proptest::collection::vec(0u64..1000, 0..80)) {
        let batch = Value::Array(ids.iter().map(|&id| add_address(id)).collect());
        let out = run(&[batch]);
        prop_assert_eq!(out.len(), 1);
        prop_assert_eq!(&out[0]["error"]["code"], &json!(-32600));
        prop_assert_eq!(&out[0]["id"], &Value::Null);
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

fn call(id: u64, method: &str, params: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})
}

fn resource_json(reply: &Value) -> Value {
    let c = &reply["result"]["contents"][0];
    assert_eq!(c["mimeType"], "application/json", "{reply}");
    serde_json::from_str(c["text"].as_str().unwrap()).unwrap()
}

#[test]
fn initialize_declares_resources_prompts_and_completions() {
    let out = run(&[call(1, "initialize", json!({}))]);
    let caps = &out[0]["result"]["capabilities"];
    assert_eq!(caps["resources"]["subscribe"], false);
    assert!(caps["prompts"].is_object());
    assert!(caps["completions"].is_object());
}

#[test]
fn resources_list_templates_and_read() {
    let out = run(&[
        call(1, "resources/list", json!({})),
        call(2, "resources/templates/list", json!({})),
        call(
            3,
            "tools/call",
            json!({"name":"run_command","arguments":{"command":"config.mode.set",
                "params":{"mode":"transactional"}}}),
        ),
        call(
            4,
            "tools/call",
            json!({"name":"run_command","arguments":{"command":"ip.address.add",
                "params":{"address":"10.9.9.1/24","interface":"ether3"}}}),
        ),
        call(5, "resources/read", json!({"uri":"corerouter://state"})),
        call(6, "resources/read", json!({"uri":"corerouter://diff"})),
        call(
            7,
            "resources/read",
            json!({"uri":"corerouter://command/ip.address.add"}),
        ),
        call(
            8,
            "resources/read",
            json!({"uri":"corerouter://state/ip.addresses"}),
        ),
        call(9, "resources/read", json!({"uri":"corerouter://commands"})),
    ]);
    let uris: Vec<&str> = out[0]["result"]["resources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["uri"].as_str().unwrap())
        .collect();
    assert_eq!(
        uris,
        [
            "corerouter://state",
            "corerouter://commands",
            "corerouter://diff"
        ]
    );
    let templates: Vec<&str> = out[1]["result"]["resourceTemplates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["uriTemplate"].as_str().unwrap())
        .collect();
    assert!(templates.contains(&"corerouter://command/{id}"));
    assert!(templates.contains(&"corerouter://state/{path}"));

    let state = resource_json(&out[4]);
    assert_eq!(state["mode"], "transactional");
    assert!(state["pending_changes"].as_u64().unwrap() >= 1);
    assert_eq!(out[4]["result"]["contents"][0]["uri"], "corerouter://state");
    let diff = resource_json(&out[5]);
    assert!(diff.to_string().contains("10.9.9.1/24"), "{diff}");
    let cmd = resource_json(&out[6]);
    assert_eq!(cmd["id"], "ip.address.add");
    assert!(cmd["params"].as_str().unwrap().contains("interface"));
    let addrs = resource_json(&out[7]);
    assert!(addrs.to_string().contains("10.9.9.1/24"));
    assert!(resource_json(&out[8]).as_array().unwrap().len() > 20);
}

#[test]
fn missing_resources_are_32002_with_the_uri() {
    let out = run(&[
        call(
            1,
            "resources/read",
            json!({"uri":"corerouter://command/ip.adress.add"}),
        ),
        call(
            2,
            "resources/read",
            json!({"uri":"corerouter://state/nope"}),
        ),
        call(3, "resources/read", json!({"uri":"file:///etc/passwd"})),
        call(4, "resources/read", json!({})),
        call(
            5,
            "resources/read",
            json!({"uri": "corerouter://".to_string() + &"x".repeat(5000)}),
        ),
    ]);
    for r in &out[..4] {
        assert_eq!(r["error"]["code"], -32002, "{r}");
    }
    assert_eq!(
        out[0]["error"]["data"]["uri"],
        "corerouter://command/ip.adress.add"
    );
    let msg = out[0]["error"]["message"].as_str().unwrap();
    assert!(
        msg.contains("ip.address.add"),
        "suggests the right id: {msg}"
    );
    assert!(
        out[1]["error"]["message"]
            .as_str()
            .unwrap()
            .contains("nope")
    );
    assert_eq!(out[4]["error"]["code"], -32602);
    assert!(out[4]["error"]["data"]["uri"].as_str().unwrap().len() <= 512);
}

#[test]
fn prompts_list_and_get() {
    let out = run(&[
        call(1, "prompts/list", json!({})),
        call(
            2,
            "prompts/get",
            json!({"name":"configure_address","arguments":{"interface":"ether2",
                "address":"192.0.2.1/24","gateway":"192.0.2.254"}}),
        ),
        call(3, "prompts/get", json!({"name":"review_and_commit"})),
        call(
            4,
            "prompts/get",
            json!({"name":"diagnose_connectivity","arguments":{"target":"8.8.8.8"}}),
        ),
    ]);
    let names: Vec<&str> = out[0]["result"]["prompts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "configure_address",
            "review_and_commit",
            "diagnose_connectivity"
        ]
    );
    let required = &out[0]["result"]["prompts"][0]["arguments"][0];
    assert_eq!(
        (required["name"].as_str(), required["required"].as_bool()),
        (Some("interface"), Some(true))
    );

    let text = out[1]["result"]["messages"][0]["content"]["text"]
        .as_str()
        .unwrap();
    assert_eq!(out[1]["result"]["messages"][0]["role"], "user");
    for want in [
        "ether2",
        "192.0.2.1/24",
        "0.0.0.0/0",
        "192.0.2.254",
        "config.commit",
    ] {
        assert!(text.contains(want), "{want} missing from {text}");
    }
    // review_and_commit embeds the state and the diff as resources.
    let msgs = out[2]["result"]["messages"].as_array().unwrap();
    assert_eq!(msgs.len(), 3);
    assert_eq!(msgs[0]["content"]["type"], "resource");
    assert_eq!(msgs[0]["content"]["resource"]["uri"], "corerouter://state");
    assert_eq!(msgs[1]["content"]["resource"]["uri"], "corerouter://diff");
    assert!(
        out[3]["result"]["messages"][0]["content"]["text"]
            .as_str()
            .unwrap()
            .contains("tool.ping.start")
    );
}

#[test]
fn bad_prompt_requests_are_32602() {
    let out = run(&[
        call(1, "prompts/get", json!({"name":"nope"})),
        call(
            2,
            "prompts/get",
            json!({"name":"configure_address","arguments":{"interface":"ether1"}}),
        ),
        call(
            3,
            "prompts/get",
            json!({"name":"diagnose_connectivity","arguments":{"target":"1.1.1.1","tagret":"x"}}),
        ),
        call(
            4,
            "prompts/get",
            json!({"name":"diagnose_connectivity","arguments":{"target":"a\"b"}}),
        ),
        call(
            5,
            "prompts/get",
            json!({"name":"diagnose_connectivity","arguments":{"target":7}}),
        ),
        call(
            6,
            "prompts/get",
            json!({"name":"diagnose_connectivity","arguments":{"target":"x".repeat(200)}}),
        ),
    ]);
    for r in &out {
        assert_eq!(r["error"]["code"], -32602, "{r}");
    }
    let msgs: Vec<&str> = out
        .iter()
        .map(|r| r["error"]["message"].as_str().unwrap())
        .collect();
    assert!(msgs[0].contains("configure_address"));
    assert!(msgs[1].contains("missing argument 'address'"));
    assert!(msgs[2].contains("unknown argument 'tagret'"));
}

#[test]
fn completions_for_templates_and_prompt_arguments() {
    let out = run(&[
        call(
            1,
            "completion/complete",
            json!({"ref":{"type":"ref/resource","uri":"corerouter://command/{id}"},
            "argument":{"name":"id","value":"ip.address."}}),
        ),
        call(
            2,
            "completion/complete",
            json!({"ref":{"type":"ref/resource","uri":"corerouter://state/{path}"},
            "argument":{"name":"path","value":"ru"}}),
        ),
        call(
            3,
            "completion/complete",
            json!({"ref":{"type":"ref/prompt","name":"configure_address"},
            "argument":{"name":"interface","value":"ether"}}),
        ),
        call(
            4,
            "completion/complete",
            json!({"ref":{"type":"ref/prompt","name":"nope"},
            "argument":{"name":"x","value":""}}),
        ),
        call(5, "completion/complete", json!({})),
    ]);
    let values = |r: &Value| -> Vec<String> {
        r["result"]["completion"]["values"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect()
    };
    assert!(values(&out[0]).contains(&"ip.address.add".to_string()));
    assert!(values(&out[0]).iter().all(|v| v.starts_with("ip.address.")));
    assert_eq!(values(&out[1]), ["running"]);
    assert_eq!(values(&out[2]).len(), 8, "virtual lab has ether1..8");
    assert_eq!(out[2]["result"]["completion"]["hasMore"], false);
    assert!(values(&out[3]).is_empty());
    assert_eq!(out[4]["error"]["code"], -32602);
}

proptest! {
    #[test]
    fn hostile_resource_and_prompt_params_get_an_answer(
        uri in ".{0,80}", name in ".{0,40}", arg in ".{0,200}",
    ) {
        let out = run(&[
            call(1, "resources/read", json!({"uri": format!("corerouter://{uri}")})),
            call(2, "prompts/get", json!({"name": name, "arguments": {"target": arg}})),
            call(3, "prompts/get", json!({"name": "diagnose_connectivity", "arguments": {"target": arg}})),
            call(4, "completion/complete", json!({"ref": {"type": "ref/resource", "uri": uri},
                "argument": {"name": name, "value": arg}})),
        ]);
        prop_assert_eq!(out.len(), 4);
        for r in out {
            prop_assert!(r.get("result").is_some() || r.get("error").is_some());
        }
    }
}
