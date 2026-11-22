//! G2.3: CGNAT pools and exceptions survive `/export` → `/import` (the
//! terminal knows no command by name: it builds the script from
//! `ip.firewall.cgnat.*.list` and the `add`/`set` docs).
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::collections::BTreeMap;

use corerouter_engine::{Caller, Principal, Session};
use corerouter_shell::{Reply, Request, Shell};
use serde_json::{Value, json};

struct Term {
    shell: Shell,
    session: Session,
    caller: Caller,
    files: BTreeMap<String, String>,
}

impl Term {
    fn new() -> Self {
        let mut t = Self {
            shell: Shell::new("admin"),
            session: Session::virtual_lab(),
            caller: Caller::new(7, "test 127.0.0.1:1").with_principal(Principal::Local),
            files: BTreeMap::new(),
        };
        let job = t.shell.connect();
        let out = t.drive(job);
        assert!(!out.0, "{}", out.1);
        t
    }

    fn answer(&mut self, r: &Request) -> Reply {
        let err = |e: corerouter_engine::EngineError| e.to_string();
        match r {
            Request::ReadFile { path } => self
                .files
                .get(path)
                .map(|t| Value::String(t.clone()))
                .ok_or_else(|| format!("{path}: no such file")),
            Request::WriteFile { path, content } => {
                self.files.insert(path.clone(), content.clone());
                Ok(Value::Null)
            }
            Request::Sleep { .. } => Ok(Value::Null),
            Request::Call { method, params } => {
                let s = &mut self.session;
                match method.as_str() {
                    "server.info" => Ok(json!({"name": "corerouter", "version": "test"})),
                    "auth.whoami" => Ok(corerouter_engine::auth::whoami(
                        s,
                        &self.caller.principal,
                        &self.caller.name,
                    )),
                    "engine.list" => Ok(s.list()),
                    "engine.execute" => s
                        .execute_as(
                            &self.caller,
                            params["command"].as_str().unwrap_or(""),
                            &params["params"],
                        )
                        .map_err(err),
                    "engine.batch" => s
                        .batch_as(&self.caller, &params["steps"], params["atomic"] != false)
                        .map_err(err),
                    "state.inspect" => s
                        .inspect_as(&self.caller, params["path"].as_str())
                        .map_err(err),
                    other => Err(format!("unknown method {other}")),
                }
            }
        }
    }

    fn drive(&mut self, job: corerouter_shell::Job) -> (bool, String) {
        let mut shell = std::mem::replace(&mut self.shell, Shell::new("x"));
        let out = shell.run_with(job, |q| self.answer(q));
        self.shell = shell;
        (out.failed, out.text())
    }

    fn ok(&mut self, line: &str) -> String {
        let job = self.shell.submit(line);
        let (failed, text) = self.drive(job);
        assert!(!failed, "{line}: {text}");
        text
    }
}

#[test]
fn pools_and_exceptions_round_trip() {
    let mut a = Term::new();
    for (id, p) in [
        (
            "ip.firewall.cgnat.pool.add",
            json!({"name": "cgnat1", "inside": "100.64.0.0/22,100.64.8.0-100.64.8.99", "outside": "203.0.113.0/28", "ports_per_subscriber": 900, "endpoint_independent_filtering": true, "comment": "bairro norte"}),
        ),
        (
            "ip.firewall.cgnat.pool.add",
            json!({"name": "pba", "mode": "blocks", "inside": "100.65.0.0/24", "outside": "198.51.100.0/30", "max_blocks": 8, "block_timeout": "5m", "hairpin": false}),
        ),
        (
            "ip.firewall.cgnat.exception.add",
            json!({"subscriber": "100.64.0.9", "public": "192.0.2.77", "comment": "empresa"}),
        ),
        ("ip.firewall.cgnat.set", json!({"history_days": 730})),
    ] {
        a.session
            .execute(id, &p)
            .unwrap_or_else(|e| panic!("{id}: {e}"));
    }
    a.ok("/export file=x");
    let script = a.files.get("x").cloned().unwrap();
    assert!(script.contains("/ip firewall cgnat pool"), "{script}");
    let mut b = Term::new();
    b.files.insert("c.rsc".into(), script.clone());
    b.ok("/import file=c.rsc");
    let strip = |s: &Session| {
        let mut v = serde_json::to_value(&s.store().running().ip.cgnat).unwrap();
        v["next_id"] = json!(0);
        for key in ["pools", "exceptions"] {
            for item in v[key].as_array_mut().unwrap() {
                item["id"] = json!("*0");
            }
        }
        v
    };
    assert_eq!(strip(&b.session), strip(&a.session), "{script}");
}
