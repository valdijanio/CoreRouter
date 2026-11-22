//! G4.1zd: the DNS query log's settings survive `/export` → `/import`,
//! the log turned on included (the script carries the acknowledgement the
//! operator gave, so importing it turns the log on again), and the search
//! (`ip.dns.log.search`, not a `print`) stays out of the script.
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
fn query_log_settings_round_trip() {
    let mut a = Term::new();
    a.session
        .execute(
            "ip.dns.log.set",
            &json!({"enabled": true, "acknowledge": "marco-civil-art14", "client_address": "hashed",
                "max_size_mib": 256, "exclude": ["example.org"], "except_from": ["10.0.0.0/8"]}),
        )
        .unwrap();
    a.ok("/export file=x");
    let script = a.files.get("x").cloned().unwrap();
    assert!(script.contains("/ip dns log"), "{script}");
    assert!(script.contains("acknowledge=marco-civil-art14"), "{script}");
    assert!(!script.contains("search"), "{script}");
    let mut b = Term::new();
    b.files.insert("c.rsc".into(), script.clone());
    b.ok("/import file=c.rsc");
    assert_eq!(
        b.session.store().running().ip.dns_log,
        a.session.store().running().ip.dns_log,
        "{script}"
    );
    // Off by default: a fresh router's script turns nothing on.
    let mut c = Term::new();
    c.ok("/export file=y");
    let off = c.files.get("y").cloned().unwrap();
    let mut d = Term::new();
    d.files.insert("d.rsc".into(), off);
    d.ok("/import file=d.rsc");
    assert!(!d.session.store().running().ip.dns_log.enabled);
}
