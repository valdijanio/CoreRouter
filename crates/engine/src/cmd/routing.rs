//! /routing bgp

use std::net::Ipv4Addr;

use corerouter_model::bgp::{BgpParams, resolve_templates};
use corerouter_model::{Asn, BgpInstance};
use serde_json::{Map, Value, json};

use super::args::{opt_bool, opt_str, opt_text, req_parse};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "routing.bgp.instance.set",
        "BGP Instance",
        ["Routing", "BGP"],
        None,
        "{asn: u32 | asdot string, router_id: ipv4, name?: string (default \"default\"), disabled?: bool, comment?: string, graceful_restart_time?: u16 | null (RFC 4724 Restart Time we announce, 1..=4095 s; default 120; absent: kept), graceful_stale_time?: u16 | null (how long a restarted neighbor's routes stay stale, 1..=4095 s; default 360; absent: kept), graceful_defer_time?: u16 | null (after bgpd starts, how long the best path waits for the End-of-RIB of graceful-restart neighbors, 0..=3600 s; default 10; absent: kept)} → {name, frr}",
        always,
        instance_set
    ),
    cmd!(query "routing.bgp.instance.list", "BGP Instances", ["Routing", "BGP"], None,
        "{} → [{name, asn, router_id, disabled, comment, graceful_restart_time? (unset: 120 s), graceful_stale_time? (unset: 360 s), graceful_defer_time? (unset: 10 s)}]",
        always, instance_list),
    cmd!(query "routing.bgp.instance.check", "Check BGP Instance", [], None,
        "{id?: string (the instance being edited), name?: string, asn?: u32 | string, router_id?: string, disabled?: bool | yes | no, comment?: string, graceful_restart_time?: u16 | string | null, graceful_stale_time?: u16 | string | null, graceful_defer_time?: u16 | string | null} → {computed: [{label, value}], checks: [{level, check, message, param}], commands: [{command, params}], risk} (form texts accepted: \"120\", yes/no; an empty timer = its default)",
        always, instance_check),
];

fn parse_asn(p: &Value) -> Result<Asn> {
    match p.get("asn") {
        Some(Value::Number(n)) => n
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .map(Asn)
            .ok_or_else(|| EngineError::bad("asn", "must be 0..=4294967295")),
        Some(Value::String(s)) => s
            .parse()
            .map_err(|e: corerouter_model::ParseError| EngineError::bad("asn", e.to_string())),
        _ => Err(EngineError::bad(
            "asn",
            "is required (number or asdot string)",
        )),
    }
}

fn instance_set(s: &mut Session, p: &Value) -> Result<Value> {
    let name = instance_name(p)?;
    let prev = s.store().candidate().routing.bgp.get(&name).cloned();
    let inst = build_instance(p, name.clone(), prev.as_ref())?;
    let frr = corerouter_proto_bgp::render_frr(&inst);
    s.store_mut()
        .candidate_mut()
        .routing
        .bgp
        .insert(name.clone(), inst);
    Ok(json!({ "name": name, "frr": frr }))
}

fn instance_name(p: &Value) -> Result<String> {
    let name = opt_str(p, "name")?.unwrap_or("default").to_owned();
    if name.is_empty()
        || name.len() > 32
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(EngineError::bad("name", "1..=32 chars of [A-Za-z0-9_-]"));
    }
    Ok(name)
}

/// The instance `p` describes; `prev` is what the name had (the timers
/// left out keep its values).
fn build_instance(p: &Value, name: String, prev: Option<&BgpInstance>) -> Result<BgpInstance> {
    let asn = parse_asn(p)?;
    let router_id: Ipv4Addr = req_parse(p, "router_id")?;
    let disabled = opt_bool(p, "disabled")?.unwrap_or(false);
    let comment = opt_text(p, "comment", 256)?.unwrap_or_default();
    // G3.9ff: absent keeps what the instance had, null goes back to FRR's
    // default.
    let gr_time = |key: &str, had: Option<u16>| -> Result<Option<u16>> {
        match p.get(key) {
            None => Ok(had),
            Some(Value::Null) => Ok(None),
            Some(v) => v
                .as_u64()
                .and_then(|t| u16::try_from(t).ok())
                .filter(|t| (1..=corerouter_proto_bgp::GR_MAX_TIME).contains(t))
                .map(Some)
                .ok_or_else(|| EngineError::bad(key, "1..=4095 seconds (RFC 4724 §3: the Restart Time is 12 bits), or null for the default")),
        }
    };
    let graceful_restart_time = gr_time("graceful_restart_time", prev.and_then(|i| i.graceful_restart_time))?;
    let graceful_stale_time = gr_time("graceful_stale_time", prev.and_then(|i| i.graceful_stale_time))?;
    let graceful_defer_time = match p.get("graceful_defer_time") {
        None => prev.and_then(|i| i.graceful_defer_time),
        Some(Value::Null) => None,
        Some(v) => Some(
            v.as_u64()
                .and_then(|t| u16::try_from(t).ok())
                .filter(|t| *t <= corerouter_proto_bgp::GR_MAX_DEFER)
                .ok_or_else(|| EngineError::bad("graceful_defer_time", "0..=3600 seconds, or null for the default (10)"))?,
        ),
    };
    Ok(BgpInstance {
        name,
        asn,
        router_id,
        disabled,
        comment,
        graceful_restart_time,
        graceful_stale_time,
        graceful_defer_time,
    })
}

/// The modal's form texts as `instance.set` takes them: numbers from
/// text, yes/no, an emptied timer back to its default (null). `id` (the
/// instance being edited) names it.
fn instance_form(raw: &Value) -> Value {
    let mut out = Map::new();
    let Some(obj) = raw.as_object() else {
        return Value::Object(out);
    };
    for (k, v) in obj {
        let text = v.as_str().map(str::trim);
        let v = match (k.as_str(), text) {
            ("id", _) => continue,
            (RESTART_KEY | STALE_KEY | DEFER_KEY, Some("")) => Value::Null,
            ("asn" | "router_id" | "name", Some("")) => continue,
            (RESTART_KEY | STALE_KEY | DEFER_KEY | "asn", Some(t)) => t.parse::<u64>().map_or_else(|_| v.clone(), Value::from),
            ("disabled", Some("yes")) => Value::Bool(true),
            ("disabled", Some("no")) => Value::Bool(false),
            (_, Some(t)) => Value::from(t),
            _ => v.clone(),
        };
        out.insert(k.clone(), v);
    }
    if let Some(id) = obj.get("id").and_then(Value::as_str) {
        out.insert("name".into(), Value::from(id));
    }
    Value::Object(out)
}

const RESTART_KEY: &str = "graceful_restart_time";
const STALE_KEY: &str = "graceful_stale_time";
const DEFER_KEY: &str = "graceful_defer_time";

/// The Instances modal's preview (G3.9fj): the instance as it would be,
/// what it changes for the sessions, and the `instance.set` to run. Never
/// an error for bad input: it becomes a check.
fn instance_check(s: &mut Session, raw: &Value) -> Result<Value> {
    use corerouter_proto_bgp::{GR_DEFER_TIME, GR_RESTART_TIME, GR_STALE_TIME};
    let check = |level: &str, check: &str, message: String, param: &str| {
        json!({"level": level, "check": check, "message": message, "param": param})
    };
    let editing = opt_str(raw, "id").ok().flatten().is_some();
    let mut p = instance_form(raw);
    let mut checks: Vec<Value> = Vec::new();
    let mut computed: Vec<Value> = Vec::new();
    let built = instance_name(&p).and_then(|name| {
        let prev = s.store().candidate().routing.bgp.get(&name).cloned();
        build_instance(&p, name, prev.as_ref()).map(|i| (i, prev))
    });
    let (inst, prev) = match built {
        Ok(x) => x,
        Err(e) => {
            let (param, msg) = match &e {
                EngineError::BadParam { param, reason } => (param.clone(), reason.clone()),
                other => (String::new(), other.to_string()),
            };
            checks.push(check("error", "params", msg, &param));
            return Ok(json!({"computed": computed, "checks": checks, "commands": [], "risk": null}));
        }
    };
    // The command says every timer: what the form left as it was stays.
    if let Some(o) = p.as_object_mut() {
        o.insert("name".into(), json!(inst.name));
        for (k, v) in [
            (RESTART_KEY, inst.graceful_restart_time),
            (STALE_KEY, inst.graceful_stale_time),
            (DEFER_KEY, inst.graceful_defer_time),
        ] {
            o.insert(k.into(), json!(v));
        }
    }
    let routing = &s.store().candidate().routing;
    let resolved = resolve_templates(&routing.bgp_templates);
    let conns: Vec<(&String, Option<BgpParams>)> = routing
        .bgp_connections
        .iter()
        .filter(|(_, c)| c.instance == inst.name)
        .map(|(n, c)| (n, c.effective(&resolved).ok()))
        .collect();
    let restarting: Vec<(&String, u16)> = conns
        .iter()
        .filter_map(|(n, e)| e.as_ref().filter(|e| e.graceful_restart == Some(true)).map(|e| (*n, corerouter_proto_bgp::timers(e).1)))
        .collect();
    let rt = inst.graceful_restart_time.unwrap_or(GR_RESTART_TIME);
    let defer = inst.graceful_defer_time.unwrap_or(GR_DEFER_TIME);
    let secs = |v: Option<u16>, d: u16| match v {
        Some(t) => format!("{t} s"),
        None => format!("{d} s (default)"),
    };
    computed.push(json!({"label": "Restart Time", "value": secs(inst.graceful_restart_time, GR_RESTART_TIME)}));
    computed.push(json!({"label": "Stale Time", "value": secs(inst.graceful_stale_time, GR_STALE_TIME)}));
    computed.push(json!({"label": "Defer Time", "value": secs(inst.graceful_defer_time, GR_DEFER_TIME)}));
    computed.push(json!({"label": "Connections", "value": format!("{} ({} with graceful restart)", conns.len(), restarting.len())}));
    if let Some(old) = &prev {
        if !editing {
            checks.push(check("warning", "exists", format!("instance {} already exists: this replaces it (edit it instead)", inst.name), "name"));
        }
        let n = conns.len();
        if n > 0 && old.asn != inst.asn {
            checks.push(check("warning", "asn", format!("changing the AS from {} to {} restarts the {n} session(s) of this instance (bgpd recreates `router bgp`)", old.asn, inst.asn), "asn"));
        }
        if n > 0 && old.router_id != inst.router_id {
            checks.push(check("warning", "router-id", format!("changing the router id resets the {n} session(s) of this instance (Cease, configuration change; RFC 4486)"), "router_id"));
        }
        if n > 0 && !old.disabled && inst.disabled {
            checks.push(check("warning", "disabled", format!("disabling the instance stops its {n} session(s) and withdraws their routes"), "disabled"));
        }
    }
    // RFC 4724 §3: the Restart Time SHOULD be shorter than the hold time.
    let long: Vec<String> = restarting
        .iter()
        .filter(|(_, hold)| *hold != 0 && rt >= *hold)
        .map(|(n, hold)| format!("{n} (hold {hold} s)"))
        .collect();
    if !long.is_empty() {
        checks.push(check("warning", "gr-restart-time", format!("the Restart Time ({rt} s) is not shorter than the hold time of {}: RFC 4724 §3 recommends it below the hold time", long.join(", ")), RESTART_KEY));
    }
    let set_timers = inst.graceful_restart_time.is_some() || inst.graceful_defer_time.is_some();
    if restarting.is_empty() && set_timers {
        checks.push(check("info", "gr-none", "no connection of this instance has graceful_restart=yes: the Restart Time and the Defer Time only apply to those (the Stale Time applies to every helper session)".into(), ""));
    }
    if defer == 0 && !restarting.is_empty() {
        checks.push(check("info", "gr-defer", "Defer Time 0: after bgpd starts the best path does not wait for the neighbors' End-of-RIB, and routes may change while they resend their tables (RFC 4724 §4.1)".into(), DEFER_KEY));
    }
    // G3.9fj: a neighbor that never sends End-of-RIB (RouterOS 7.25) holds
    // its routes back for the whole Defer Time after a bgpd start.
    if let Some(st) = s.routing_status() {
        let quiet: Vec<String> = crate::health_check::bgp_without_eor(st)
            .filter(|b| b.instance == inst.name)
            .map(|b| b.connection.clone().unwrap_or_else(|| b.remote_address.clone()))
            .collect();
        if !quiet.is_empty() && !restarting.is_empty() {
            checks.push(check("info", "no-eor", format!("{} never sent End-of-RIB (RouterOS 7.25 does not): after a bgpd start, their routes wait the whole Defer Time ({defer} s)", quiet.join(", ")), DEFER_KEY));
        }
    }
    let commands = if prev.as_ref() == Some(&inst) {
        Vec::new()
    } else {
        vec![json!({"command": "routing.bgp.instance.set", "params": p})]
    };
    Ok(json!({"computed": computed, "checks": checks, "commands": commands, "risk": null}))
}

fn instance_list(s: &mut Session, _: &Value) -> Result<Value> {
    Ok(Value::Array(
        s.store()
            .candidate()
            .routing
            .bgp
            .values()
            .map(|b| {
                json!({
                    "name": b.name,
                    "asn": b.asn,
                    "router_id": b.router_id.to_string(),
                    "disabled": b.disabled,
                    "comment": b.comment,
                    "graceful_restart_time": b.graceful_restart_time,
                    "graceful_stale_time": b.graceful_stale_time,
                    "graceful_defer_time": b.graceful_defer_time,
                })
            })
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use corerouter_model::routing_state::{BgpSession, RoutingStatus};

    use super::*;

    fn session() -> Session {
        let mut s = Session::virtual_lab();
        s.execute("routing.bgp.instance.set", &json!({"asn": 65000, "router_id": "10.0.0.1"})).unwrap();
        s.execute(
            "routing.bgp.connection.add",
            &json!({"name": "chr", "remote_address": "192.0.2.2", "remote_as": 65000, "hold_time": 90, "graceful_restart": true}),
        )
        .unwrap();
        s
    }

    fn levels(v: &Value) -> Vec<(String, String)> {
        v["checks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| (c["level"].as_str().unwrap().to_owned(), c["check"].as_str().unwrap().to_owned()))
            .collect()
    }

    /// G3.9fj: the Instances modal edits the graceful-restart timers.
    #[test]
    fn the_instance_preview_takes_form_texts() {
        let mut s = session();
        let before = s.store().candidate().clone();
        let v = s
            .execute(
                "routing.bgp.instance.check",
                &json!({"id": "default", "asn": "65000", "router_id": "10.0.0.1", "disabled": "no", "comment": "", "graceful_restart_time": "60", "graceful_stale_time": "", "graceful_defer_time": "0"}),
            )
            .unwrap();
        assert_eq!(s.store().candidate(), &before, "the preview changes nothing");
        assert_eq!(levels(&v), [("info".to_owned(), "gr-defer".to_owned())], "{v}");
        let cmd = &v["commands"][0];
        assert_eq!(cmd["command"], "routing.bgp.instance.set");
        assert_eq!(
            cmd["params"],
            json!({"name": "default", "asn": 65000, "router_id": "10.0.0.1", "disabled": false, "comment": "", "graceful_restart_time": 60, "graceful_stale_time": null, "graceful_defer_time": 0})
        );
        // The command does what the preview said.
        s.execute("routing.bgp.instance.set", &cmd["params"]).unwrap();
        let i = &s.store().candidate().routing.bgp["default"];
        assert_eq!((i.graceful_restart_time, i.graceful_stale_time, i.graceful_defer_time), (Some(60), None, Some(0)));
        // Unchanged: nothing to run. An emptied timer goes back to its default.
        let same = s.execute("routing.bgp.instance.check", &cmd["params"]).unwrap();
        assert_eq!(same["commands"], json!([]));
        let v = s
            .execute("routing.bgp.instance.check", &json!({"id": "default", "asn": "65000", "router_id": "10.0.0.1", "graceful_restart_time": ""}))
            .unwrap();
        assert_eq!(v["commands"][0]["params"]["graceful_restart_time"], Value::Null);
        assert_eq!(v["computed"][0]["value"], "120 s (default)");
    }

    #[test]
    fn the_instance_preview_warns() {
        let mut s = session();
        // RFC 4724 §3: Restart Time below the hold time (90 s).
        let v = s
            .execute("routing.bgp.instance.check", &json!({"id": "default", "asn": 65000, "router_id": "10.0.0.1", "graceful_restart_time": "120"}))
            .unwrap();
        assert!(levels(&v).contains(&("warning".into(), "gr-restart-time".into())), "{v}");
        assert!(v["checks"][0]["message"].as_str().unwrap().contains("chr (hold 90 s)"));
        // AS and router id restart the sessions.
        let v = s
            .execute("routing.bgp.instance.check", &json!({"id": "default", "asn": "65001", "router_id": "10.0.0.2", "disabled": "yes"}))
            .unwrap();
        let l = levels(&v);
        for c in ["asn", "router-id", "disabled"] {
            assert!(l.contains(&("warning".into(), c.into())), "{c}: {v}");
        }
        // A new instance named like one that exists.
        let v = s.execute("routing.bgp.instance.check", &json!({"name": "default", "asn": 65000, "router_id": "10.0.0.1"})).unwrap();
        assert!(levels(&v).contains(&("warning".into(), "exists".into())), "{v}");
        // Bad input is a check on its field, never an error.
        for (p, param) in [
            (json!({"id": "default", "asn": "65000", "router_id": "10.0.0.1", "graceful_restart_time": "5000"}), "graceful_restart_time"),
            (json!({"id": "default", "asn": "65000", "router_id": "10.0.0.1", "graceful_defer_time": "x"}), "graceful_defer_time"),
            (json!({"name": "new", "router_id": "10.0.0.1"}), "asn"),
            (json!({"name": "bad name", "asn": 1, "router_id": "10.0.0.1"}), "name"),
        ] {
            let v = s.execute("routing.bgp.instance.check", &p).unwrap();
            assert_eq!((v["checks"][0]["level"].as_str(), v["checks"][0]["param"].as_str()), (Some("error"), Some(param)), "{p}: {v}");
            assert_eq!(v["commands"], json!([]));
        }
    }

    /// The RouterOS 7.25 neighbor without End-of-RIB is named next to the
    /// Defer Time.
    #[test]
    fn the_instance_preview_names_neighbors_without_end_of_rib() {
        let mut s = session();
        s.set_routing_status(RoutingStatus {
            backend: "frr 10.7.1".into(),
            bgp_sessions: vec![BgpSession {
                instance: "default".into(),
                remote_address: "192.0.2.2".into(),
                established: true,
                uptime_secs: Some(3600),
                connection: Some("chr".into()),
                gr_local: Some("restart".into()),
                gr_remote: Some("helper".into()),
                ..BgpSession::default()
            }],
            ..RoutingStatus::default()
        });
        let v = s
            .execute("routing.bgp.instance.check", &json!({"id": "default", "asn": 65000, "router_id": "10.0.0.1", "graceful_defer_time": "30"}))
            .unwrap();
        let eor = v["checks"].as_array().unwrap().iter().find(|c| c["check"] == "no-eor").unwrap();
        assert!(eor["message"].as_str().unwrap().starts_with("chr never sent End-of-RIB"), "{eor}");
        assert!(eor["message"].as_str().unwrap().contains("(30 s)"), "{eor}");
    }
}
