//! G4.3d: PPPoE servers, PPP profiles (built-in ones edited too, hooks
//! included) survive `/export` → `/import`. Passwords never leave in
//! clear: a secret is a commented line of the script (the operator moves
//! secrets with their passwords some other way, or keeps them in RADIUS).
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
fn ppp_round_trips() {
    let mut a = Term::new();
    for (id, p) in [
        (
            "ip.pool.add",
            json!({"name": "clientes", "ranges": "100.64.0.0/22"}),
        ),
        (
            "ppp.profile.add",
            json!({"name": "plano-100M", "remote_address": "clientes", "local_address": "100.64.255.254",
                   "dns_server": "1.1.1.1,8.8.8.8", "rate_limit": "50M/100M 60M/120M 40M/80M 10/10 8",
                   "address_list": "assinantes", "only_one": "yes", "session_timeout": "1d",
                   "on_up": [{"command": "ip.firewall.address-list.add", "params": {"list": "online", "address": "$remote-address", "timeout": "1d"}}],
                   "comment": "plano de 100 mega"}),
        ),
        (
            "ppp.profile.set",
            json!({"id": "default", "dns_server": "9.9.9.9"}),
        ),
        (
            "ppp.secret.add",
            json!({"name": "joao", "password": "s3nh4", "service": "pppoe", "profile": "plano-100M", "caller_id": "AA:BB:CC:00:00:01", "remote_address": "100.64.9.9", "limit_bytes_out": 1000000}),
        ),
        (
            "interface.pppoe-server.server.add",
            json!({"interface": "ether2", "service_name": "isp", "authentication": "mschap2,chap", "pppoe_over_vlan_range": "100-115,120",
                   "default_profile": "plano-100M", "keepalive_timeout": 30, "pado_delay_by_load": "5000:100", "max_sessions": 4000}),
        ),
        (
            "ppp.aaa.set",
            json!({"use_radius": true, "interim_update": 300}),
        ),
    ] {
        a.session
            .execute(id, &p)
            .unwrap_or_else(|e| panic!("{id}: {e}"));
    }
    a.ok("/export file=x");
    let script = a.files.get("x").cloned().unwrap();
    assert!(script.contains("/ppp profile"), "{script}");
    assert!(!script.contains("s3nh4"), "{script}");
    assert!(
        script.contains("# add name=joao: password is not exported"),
        "{script}"
    );
    let mut b = Term::new();
    b.files.insert("c.rsc".into(), script.clone());
    b.ok("/import file=c.rsc");
    let strip = |s: &Session| {
        let mut v = serde_json::to_value(&s.store().running().ppp).unwrap();
        v["next_id"] = json!(0);
        v["secrets"] = json!(null);
        if let Some(p) = v["profiles"].as_array_mut() {
            p.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
        }
        for key in ["profiles", "secrets", "pppoe_servers"] {
            for item in v[key].as_array_mut().into_iter().flatten() {
                item["id"] = json!("*0");
                if let Some(o) = item.as_object_mut() {
                    o.remove("password");
                }
            }
        }
        v
    };
    assert_eq!(strip(&b.session), strip(&a.session), "{script}");
}
