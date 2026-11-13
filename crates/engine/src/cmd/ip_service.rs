//! `/ip service` as one list (G1.6p): `ip.service.print` gathers the rows of
//! `www-ssl`, `www` and `metrics` for the window and says which one carries
//! this session, and `ip.service.check` is the preview of its modal. Each
//! service keeps its own `set` and `get` (`web_service.rs`,
//! `metrics_service.rs`): the preview runs their rules on a copy.

use serde_json::{Map, Value, json};

use super::args::opt_str;
use super::web_service::Row;
use super::{CommandSpec, always, metrics_service, web_service};
use crate::lockout::{comes_through, service_cut};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "ip.service.print", "IP Services", [], None,
        "{} → [{name, enabled, disabled, address, port, available_from, certificate? (www-ssl), status: stopped|listening|error, listening, last_error, refused, requests?, this_session: bool (this connection comes through it)}]",
        always, print),
    cmd!(query "ip.service.check", "Check IP Service", [], None,
        "{id?: string (www-ssl, www or metrics), enabled?: bool, address?: string, port?: string, available_from?: string (comma-separated; empty is everyone), certificate?: string (www-ssl: a /certificate or none)} → {computed: [{label, value}], checks: [{level, check, message, param?}], commands: [{command, params}], risk?}",
        always, check),
];

const NAMES: [&str; 3] = ["www-ssl", "www", "metrics"];

fn get(s: &mut Session, name: &str) -> Result<Value> {
    match name {
        "www-ssl" => web_service::get(s, Row::Ssl),
        "www" => web_service::get(s, Row::Plain),
        _ => metrics_service::get(s, &json!({})),
    }
}

fn print(s: &mut Session, _: &Value) -> Result<Value> {
    let link = s.caller().link;
    let ssl = s.store().running().system.web.www_ssl.clone();
    let mut rows = Vec::with_capacity(NAMES.len());
    for name in NAMES {
        let mut row = get(s, name)?;
        // Only `www-ssl` serves a session: `www` redirects, `metrics` has no login.
        let this = name == "www-ssl" && link.is_some_and(|l| comes_through(&ssl, &l));
        let on = row.get("enabled").and_then(Value::as_bool).unwrap_or(false);
        if let Some(o) = row.as_object_mut() {
            o.insert("name".into(), json!(name));
            o.insert("disabled".into(), json!(!on));
            o.insert("this_session".into(), json!(this));
        }
        rows.push(row);
    }
    Ok(Value::Array(rows))
}

fn check_row(level: &str, check: &str, message: impl Into<String>, param: Option<&str>) -> Value {
    let mut c = json!({"level": level, "check": check, "message": message.into()});
    if let (Some(p), Some(o)) = (param, c.as_object_mut()) {
        o.insert("param".into(), json!(p));
    }
    c
}

/// The fields as typed, as `set` takes them: a bad port is its check here.
fn typed(p: &Value) -> std::result::Result<Value, Value> {
    let mut out = Map::new();
    if let Some(e) = p.get("enabled") {
        out.insert("enabled".into(), e.clone());
    }
    let text = |k: &str| p.get(k).and_then(Value::as_str).map(str::trim).unwrap_or("");
    let address = text("address");
    if address.is_empty() {
        return Err(check_row("error", "address", "an address is required (:: is every address)", Some("address")));
    }
    out.insert("address".into(), json!(address));
    let Ok(port) = text("port").parse::<u32>() else {
        return Err(check_row("error", "port", "must be a number, 1..65535", Some("port")));
    };
    out.insert("port".into(), json!(port));
    out.insert("available_from".into(), json!(text("available_from")));
    if p.get("certificate").is_some() {
        out.insert("certificate".into(), json!(text("certificate")));
    }
    Ok(Value::Object(out))
}

/// Never fails on what was typed: an error is a check, as `docs/ui-style.md`
/// asks of a preview.
fn check(s: &mut Session, p: &Value) -> Result<Value> {
    let bad = |c: Value| json!({"computed": [], "checks": [c], "commands": [], "risk": null});
    let name = opt_str(p, "id").ok().flatten().unwrap_or("");
    if !NAMES.contains(&name) {
        return Ok(bad(check_row("error", "name", "services are fixed: www-ssl, www or metrics", None)));
    }
    let params = match typed(p) {
        Ok(v) => v,
        Err(c) => return Ok(bad(c)),
    };
    let cand = &s.store().candidate().system;
    let before = cand.web.www_ssl.clone();
    let (mut web, mut metrics) = (cand.web.clone(), cand.metrics.clone());
    let certs = cand.certificates.clone();
    let (now, was) = match name {
        "www-ssl" => (web_service::apply(&mut web, &certs, &params, Row::Ssl), get(s, name)?),
        "www" => (web_service::apply(&mut web, &certs, &params, Row::Plain), get(s, name)?),
        _ => (metrics_service::apply(&mut metrics, &params), get(s, name)?),
    };
    let now = match now {
        Ok(v) => v,
        Err(EngineError::BadParam { param, reason }) => {
            return Ok(bad(check_row("error", &param, reason, Some(param.as_str()))));
        }
        Err(e) => return Err(e),
    };
    let mut checks = Vec::new();
    if let Some(w) = now.get("warning").and_then(Value::as_str) {
        checks.push(check_row("warning", "warning", w, None));
    }
    // Only what changes goes out (`set` takes each key on its own).
    let mut changed = Map::new();
    for key in ["enabled", "address", "port", "available_from", "certificate"] {
        if let Some(v) = now.get(key).filter(|v| was.get(key) != Some(*v)) {
            changed.insert(key.into(), v.clone());
        }
    }
    let commands = if changed.is_empty() {
        Vec::new()
    } else {
        vec![json!({"command": format!("ip.service.{name}.set"), "params": changed})]
    };
    let risk = s
        .caller()
        .link
        .filter(|_| name == "www-ssl")
        .and_then(|l| service_cut(&before, &web.www_ssl, &l));
    if risk.is_none() && !commands.is_empty() {
        checks.push(check_row("ok", "access", "this session does not depend on this change", None));
    }
    let address = now.get("address").and_then(Value::as_str).unwrap_or("");
    let everywhere = address == "::" || address == "0.0.0.0";
    let reach = json!({"label": "Listens on", "value": if everywhere { "every address of the router".to_owned() } else { address.to_owned() }});
    Ok(json!({"computed": [reach], "checks": checks, "commands": commands, "risk": risk}))
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use crate::Session;
    use crate::lockout::Link;
    use crate::auth::Principal;
    use crate::safe_mode::Caller;

    /// A browser's session through `www-ssl` on `port`.
    fn through(port: u16) -> Caller {
        let local = format!("192.0.2.1:{port}").parse().unwrap();
        Caller::new(7, "wss 192.0.2.7".to_owned())
            .with_principal(Principal::Local)
            .with_link(Link { peer: "192.0.2.7:50000".parse().unwrap(), local })
    }

    fn row<'a>(rows: &'a Value, name: &str) -> &'a Value {
        rows.as_array().unwrap().iter().find(|r| r["name"] == name).unwrap()
    }

    #[test]
    fn print_lists_the_three_and_says_which_carries_the_session() {
        let mut s = Session::virtual_lab();
        s.execute("ip.service.www-ssl.set", &json!({"enabled": true})).unwrap();
        s.execute("ip.service.metrics.set", &json!({"enabled": true, "port": 9273})).unwrap();
        let rows = s.execute("ip.service.print", &json!({})).unwrap();
        assert_eq!(rows.as_array().unwrap().len(), 3);
        assert_eq!(row(&rows, "www")["disabled"], true);
        assert_eq!(row(&rows, "metrics")["port"], 9273);
        assert_eq!(row(&rows, "www-ssl")["this_session"], false, "inside the process");
        let rows = s.execute_as(&through(443), "ip.service.print", &json!({})).unwrap();
        assert_eq!(row(&rows, "www-ssl")["this_session"], true);
        assert_eq!(row(&rows, "www")["this_session"], false);
        let rows = s.execute_as(&through(8729), "ip.service.print", &json!({})).unwrap();
        assert_eq!(row(&rows, "www-ssl")["this_session"], false, "the TLS control port");
    }

    #[test]
    fn turning_off_the_service_of_this_session_is_refused_and_force_or_safe_mode_pass() {
        let mut s = Session::virtual_lab();
        s.execute("ip.service.www-ssl.set", &json!({"enabled": true})).unwrap();
        let me = through(443);
        let off = json!({"enabled": false});
        let e = s.execute_as(&me, "ip.service.www-ssl.set", &off).unwrap_err().to_string();
        assert!(e.starts_with("lockout: ") && e.contains("turn off www-ssl"), "{e}");
        let g = s.execute("ip.service.www-ssl.get", &json!({})).unwrap();
        assert_eq!(g["enabled"], true, "rolled back");
        for (p, says) in [
            (json!({"port": 8443}), "move"),
            (json!({"available_from": ["198.51.100.0/24"]}), "out of the available_from"),
        ] {
            let e = s.execute_as(&me, "ip.service.www-ssl.set", &p).unwrap_err().to_string();
            assert!(e.contains(says), "{e}");
        }
        // A change that keeps this client in is not refused.
        s.execute_as(&me, "ip.service.www-ssl.set", &json!({"available_from": ["192.0.2.0/24"]})).unwrap();
        // Safe Mode: losing the connection undoes it.
        s.execute_as(&me, "config.safe-mode.enter", &json!({})).unwrap();
        s.execute_as(&me, "ip.service.www-ssl.set", &off).unwrap();
        s.execute_as(&me, "config.safe-mode.cancel", &json!({})).unwrap();
        let g = s.execute("ip.service.www-ssl.get", &json!({})).unwrap();
        assert_eq!(g["enabled"], true, "undone");
        s.execute_as(&me, "ip.service.www-ssl.set", &json!({"enabled": false, "force": true})).unwrap();
        let g = s.execute("ip.service.www-ssl.get", &json!({})).unwrap();
        assert_eq!(g["enabled"], false);
        // `www` and `metrics` never carry a session.
        s.execute_as(&me, "ip.service.www.set", &json!({"enabled": true})).unwrap();
        s.execute_as(&me, "ip.service.www.set", &json!({"enabled": false})).unwrap();
    }

    fn form(id: &str, enabled: bool, address: &str, port: &str, from: Option<&str>) -> Value {
        let mut p = json!({"id": id, "enabled": enabled, "address": address, "port": port});
        if let Some(f) = from {
            p["available_from"] = json!(f);
        }
        p
    }

    #[test]
    fn the_preview_runs_the_rules_of_set_on_a_copy() {
        let mut s = Session::virtual_lab();
        let ask = |s: &mut Session, p: &Value| s.execute("ip.service.check", p).unwrap();
        // Nothing changes: nothing to send.
        let v = ask(&mut s, &form("www-ssl", false, "::", "443", None));
        assert_eq!(v["commands"], json!([]));
        // Only what changes goes out, in the types `set` takes, and it runs.
        let v = ask(&mut s, &form("www-ssl", true, "::", "8443", Some("192.0.2.7, 2001:db8::/32")));
        let c = &v["commands"][0];
        assert_eq!(c["command"], "ip.service.www-ssl.set");
        assert_eq!(c["params"], json!({"enabled": true, "port": 8443, "available_from": ["192.0.2.7/32", "2001:db8::/32"]}));
        assert_eq!(s.execute("ip.service.www-ssl.get", &json!({})).unwrap()["enabled"], false, "only a preview");
        s.execute(c["command"].as_str().unwrap(), &c["params"]).unwrap();
        assert_eq!(s.execute("ip.service.www-ssl.get", &json!({})).unwrap()["port"], 8443);
        // What was typed wrong is a check on its field, never a failure.
        for (p, param) in [
            (form("www", true, "::", "99999", None), "port"),
            (form("www", true, "::", "abc", None), "port"),
            (form("www", true, "banana", "80", None), "address"),
            (form("www", true, "224.0.0.1", "80", None), "address"),
            (form("metrics", true, "127.0.0.1", "9100", Some("nope")), "available_from"),
            (form("www", true, "::", "8443", None), "port"),
        ] {
            let v = ask(&mut s, &p);
            assert_eq!(v["checks"][0]["level"], "error", "{p} {v}");
            assert_eq!(v["checks"][0]["param"], param, "{p} {v}");
            assert_eq!(v["commands"], json!([]));
        }
        assert_eq!(ask(&mut s, &json!({"id": "ssh"}))["checks"][0]["level"], "error");
        assert_eq!(ask(&mut s, &json!({}))["checks"][0]["level"], "error");
        // The warning `set` would give.
        let v = ask(&mut s, &form("metrics", true, "0.0.0.0", "9100", None));
        assert_eq!(v["checks"][0]["level"], "warning");
    }

    #[test]
    fn the_preview_says_the_risk_to_this_session() {
        let mut s = Session::virtual_lab();
        s.execute("ip.service.www-ssl.set", &json!({"enabled": true})).unwrap();
        let me = through(443);
        let v = s.execute_as(&me, "ip.service.check", &form("www-ssl", false, "::", "443", None)).unwrap();
        assert!(v["risk"].as_str().unwrap().contains("turn off www-ssl"), "{v}");
        // What the modal sends once accepted passes.
        let c = &v["commands"][0];
        let mut p = c["params"].clone();
        p["force"] = json!(true);
        s.execute_as(&me, c["command"].as_str().unwrap(), &p).unwrap();
        let v = s.execute_as(&me, "ip.service.check", &form("www-ssl", true, "::", "443", Some("192.0.2.0/24"))).unwrap();
        assert!(v["risk"].is_null(), "{v}");
    }
}
