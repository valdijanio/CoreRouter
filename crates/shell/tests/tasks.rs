//! Registry metadata the terminal reads for tools (alias, positional,
//! task) and following a task live, against a simulated router: a
//! `tool.ping.start` that starts a task and `tool.task.poll`/`stop` that
//! hand out its events. When the real ping enters the engine with
//! `.alias("ping").positional("address").task()` it works the same.

use corerouter_shell::{Line, Reply, Request, Shell};
use serde_json::{Value, json};

/// A router with one task command; the task emits `total` replies, one per
/// poll, unless stopped.
struct Sim {
    calls: Vec<(String, Value)>,
    started: Option<Value>,
    emitted: u64,
    total: u64,
    stopped: bool,
    /// Answer `text: true` polls with rendered lines (the engine does).
    render: bool,
    mtr: Option<Value>,
}

impl Sim {
    fn new(total: u64) -> Self {
        Self {
            calls: Vec::new(),
            started: None,
            emitted: 0,
            total,
            stopped: false,
            render: false,
            mtr: None,
        }
    }

    fn list() -> Value {
        json!([
            {"id": "tool.ping.start", "label": "Ping", "params": "{address: ip | name, count?: u32, interval_ms?: u32} → {id}",
             "kind": "action", "enabled": true, "alias": "ping", "positional": "address", "task": true},
            {"id": "tool.mtr.start", "label": "MTR", "params": "{address: string, count?: int} → {id}",
             "kind": "query", "enabled": true, "alias": "traceroute,mtr", "positional": "address", "task": true},
            {"id": "tool.task.poll", "label": "Poll Task", "params": "{id: u64, after_seq?: u64} → {events}", "kind": "query", "enabled": true},
            {"id": "tool.task.stop", "label": "Stop Task", "params": "{id: u64} → {id}", "kind": "action", "enabled": true},
            {"id": "tool.task.list", "label": "Tasks", "params": "{} → [{id, kind, state}]", "kind": "query", "enabled": true},
            {"id": "ip.address.list", "label": "Addresses", "params": "{} → [{id, address}]", "kind": "query", "enabled": true},
        ])
    }

    fn answer(&mut self, r: &Request) -> Reply {
        let Request::Call { method, params } = r else {
            return Ok(Value::Null);
        };
        self.calls.push((method.clone(), params.clone()));
        match method.as_str() {
            "server.info" => Ok(json!({"version": "sim"})),
            "engine.list" => Ok(Self::list()),
            "state.inspect" => Ok(json!({"identity": "sim", "safe_mode": {"active": false}})),
            "engine.batch" => Ok(json!({"results": [[], []]})),
            "engine.execute" => {
                let p = &params["params"];
                match params["command"].as_str().unwrap_or("") {
                    "tool.mtr.start" => {
                        self.mtr = Some(p.clone());
                        self.emitted = 0;
                        Ok(json!({"id": 7}))
                    }
                    "tool.ping.start" => {
                        self.started = Some(p.clone());
                        Ok(json!({"id": 7, "columns": ["seq", "host", "time", "status"]}))
                    }
                    "tool.task.poll" => {
                        assert_eq!(p["id"], 7);
                        let after = p["after_seq"].as_u64().unwrap_or(0);
                        assert_eq!(after, self.emitted, "polls continue after the last event");
                        let mut events = Vec::new();
                        if !self.stopped && self.emitted < self.total {
                            self.emitted += 1;
                            let status = if self.emitted == 2 { "timeout" } else { "" };
                            events.push(json!({"seq": self.emitted, "host": "8.8.8.8", "time": "1ms", "status": status}));
                        }
                        let done = self.stopped || self.emitted >= self.total;
                        if self.render && p["text"] == true {
                            let lines: Vec<String> = events
                                .iter()
                                .map(|e| format!("LINE {}", e["seq"]))
                                .collect();
                            return Ok(json!({
                                "id": 7, "state": if done { "done" } else { "running" }, "done": done,
                                "events": events, "next_seq": self.emitted, "more": false, "lost": 0,
                                "summary": {"sent": self.emitted}, "header": "SEQ HOST TIME",
                                "lines": lines,
                                "summary_lines": if done { json!(["sent=3 received=2 packet-loss=33%"]) } else { Value::Null },
                            }));
                        }
                        Ok(json!({
                            "id": 7, "state": if self.stopped { "stopped" } else if done { "done" } else { "running" },
                            "done": done, "reason": if self.stopped { json!("stopped by test") } else { Value::Null },
                            "events": events, "next_seq": self.emitted, "more": false, "lost": 0,
                            "summary": {"sent": self.emitted, "received": self.emitted.saturating_sub(1), "loss": "33%"}
                        }))
                    }
                    "tool.task.stop" => {
                        self.stopped = true;
                        Ok(json!({"id": 7, "stopping": true}))
                    }
                    other => Ok(json!([{"other": other}])),
                }
            }
            other => Err(format!("unknown method {other}")),
        }
    }
}

fn connect(sim: &mut Sim) -> Shell {
    let mut sh = Shell::new("admin");
    let job = sh.connect();
    sh.run_with(job, |r| sim.answer(r));
    sh
}

#[test]
fn ping_is_a_root_alias_with_a_positional_address() {
    let mut sim = Sim::new(3);
    let mut sh = connect(&mut sim);
    for line in [
        "ping 8.8.8.8 count=3",
        "/ping 8.8.8.8 count=3",
        "/tool ping start 8.8.8.8 count=3",
    ] {
        sim.started = None;
        sim.emitted = 0;
        let job = sh.submit(line);
        let out = sh.run_with(job, |r| sim.answer(r));
        assert!(!out.failed, "{line}: {}", out.text());
        assert_eq!(
            sim.started,
            Some(json!({"address": "8.8.8.8", "count": 3})),
            "{line}"
        );
    }
    // From any menu, and offered by Tab and `?`.
    let job = sh.submit("/ip address");
    sh.run_with(job, |r| sim.answer(r));
    sim.emitted = 0;
    let job = sh.submit("ping 1.1.1.1");
    sh.run_with(job, |r| sim.answer(r));
    assert_eq!(sim.started.as_ref().unwrap()["address"], "1.1.1.1");
    let c: Vec<String> = sh
        .complete("pi", 2)
        .candidates
        .into_iter()
        .map(|c| c.display)
        .collect();
    assert_eq!(c, ["ping"]);
    assert!(
        sh.help(&[], None)
            .iter()
            .any(|l| l.text().contains("ping") && l.text().contains("/tool ping start")),
    );
}

#[test]
fn a_task_streams_its_events_live_then_the_summary() {
    let mut sim = Sim::new(3);
    let mut sh = connect(&mut sim);
    let job = sh.submit("ping 8.8.8.8 count=3");
    let mut live: Vec<Vec<String>> = Vec::new();
    let out = sh.run_live(
        job,
        |r| sim.answer(r),
        |lines: &[Line]| live.push(lines.iter().map(Line::text).collect()),
    );
    // Header and first reply in one batch, then one line per poll.
    assert_eq!(live.len(), 3, "{live:?}");
    assert!(
        live[0][0].starts_with("SEQ") && live[0][0].contains("HOST"),
        "{live:?}"
    );
    assert!(live[0][1].starts_with("1") && live[0][1].contains("8.8.8.8"));
    assert!(live[1][0].contains("timeout"));
    let text = out.text();
    assert!(
        text.contains("sent: 3") && text.contains("loss: 33%"),
        "{text}"
    );
    // Polls followed after_seq; sleeps came between polls with nothing new.
    let polls = sim
        .calls
        .iter()
        .filter(|(_, p)| p["command"] == "tool.task.poll")
        .count();
    assert_eq!(polls, 3);
}

#[test]
fn ctrl_c_stops_the_task_and_shows_the_summary() {
    let mut sim = Sim::new(100);
    let mut sh = connect(&mut sim);
    let mut job = sh.submit("ping 8.8.8.8");
    let mut replies = Vec::new();
    let mut polls = 0;
    let out = loop {
        match sh.step(&mut job, replies) {
            corerouter_shell::Step::Send(reqs) => {
                if reqs.iter().any(|r| matches!(r, Request::Call { params, .. } if params["command"] == "tool.task.poll")) {
                    polls += 1;
                    if polls == 2 {
                        sh.interrupt();
                    }
                }
                replies = reqs.iter().map(|r| sim.answer(r)).collect();
            }
            corerouter_shell::Step::Done(o) => break o,
        }
    };
    assert!(sim.stopped, "tool.task.stop was sent");
    let stops = sim
        .calls
        .iter()
        .filter(|(_, p)| p["command"] == "tool.task.stop")
        .count();
    assert_eq!(stops, 1);
    assert!(
        out.text().contains("stopped: stopped by test"),
        "{}",
        out.text()
    );
    assert!(sim.emitted < 100);
}

#[test]
fn a_menu_named_like_an_alias_runs_its_command() {
    let mut sim = Sim::new(1);
    let mut sh = connect(&mut sim);
    for line in [
        "/tool ping 8.8.8.8 count=3",
        "/tool ping address=8.8.8.8 count=3",
    ] {
        sim.started = None;
        sim.emitted = 0;
        let job = sh.submit(line);
        let out = sh.run_with(job, |r| sim.answer(r));
        assert!(!out.failed, "{line}: {}", out.text());
        assert_eq!(
            sim.started,
            Some(json!({"address": "8.8.8.8", "count": 3})),
            "{line}"
        );
    }
    // The menu's own commands still win.
    sim.emitted = 0;
    let job = sh.submit("/tool ping start 1.1.1.1");
    sh.run_with(job, |r| sim.answer(r));
    assert_eq!(sim.started.as_ref().unwrap()["address"], "1.1.1.1");
    // Several aliases: traceroute and mtr, from the root and from /tool.
    for line in [
        "traceroute 9.9.9.9",
        "mtr 9.9.9.9",
        "/tool traceroute 9.9.9.9",
        "/tool mtr 9.9.9.9",
    ] {
        sim.mtr = None;
        let job = sh.submit(line);
        let out = sh.run_with(job, |r| sim.answer(r));
        assert!(!out.failed, "{line}: {}", out.text());
        assert_eq!(sim.mtr, Some(json!({"address": "9.9.9.9"})), "{line}");
    }
}

#[test]
fn lines_rendered_by_the_router_are_printed_as_they_are() {
    let mut sim = Sim::new(3);
    sim.render = true;
    let mut sh = connect(&mut sim);
    let job = sh.submit("ping 8.8.8.8 count=3");
    let out = sh.run_with(job, |r| sim.answer(r));
    let all: Vec<String> = sh
        .take_live()
        .iter()
        .chain(out.lines.iter())
        .map(Line::text)
        .collect();
    let text = all.join("\n");
    assert!(text.contains("SEQ HOST TIME"), "{text}");
    assert!(text.contains("LINE 1") && text.contains("LINE 3"), "{text}");
    assert!(text.contains("packet-loss=33%"), "{text}");
    assert!(
        !text.contains("sent: 3"),
        "the key: value summary is replaced: {text}"
    );
}
