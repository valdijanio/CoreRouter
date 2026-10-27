//! `/ip traffic-flow` (G4.4b): flow export in IPFIX or NetFlow v9 from the
//! kernel's connection tracking, with RFC 8158 NAT events. Settings and
//! collectors (`target`) are config; the exporter runs in the daemon
//! (`service/traffic_flow.rs`) and reports its state back, and the records
//! it exported are kept for a while: top talkers, CSV, batches for
//! another exporter (`records`).

use std::fmt::Write as _;
use std::net::IpAddr;

use corerouter_model::ItemId;
use corerouter_model::traffic_flow::{
    FlowTarget, FlowTransport, FlowVersion, MAX_CACHE, MAX_INTERFACES, MAX_PEM,
    MAX_RETENTION_HOURS, MAX_RETENTION_RECORDS, MAX_SAMPLING, MAX_SERVER_NAME, MAX_TARGETS,
    MAX_TIMEOUT, MIN_CACHE, TargetRecords, TrafficFlow, TrafficFlowStatus,
};
use corerouter_proto_flow::Record;
use serde_json::{Value, json};

use super::args::{opt_bool, opt_names, opt_parse, opt_str, opt_text, opt_u32, req_parse};
use super::{CommandSpec, always};
use crate::traffic_flow::{FlowStore, Stored, top};
use crate::{EngineError, Result, Session};

/// Most records one `records` call returns, and one CSV export.
const MAX_BATCH: u32 = 10_000;
const MAX_CSV: u32 = 100_000;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "ip.traffic-flow.set",
        "Traffic Flow Settings",
        ["IP", "Traffic Flow"],
        None,
        "{enabled?: bool, interfaces?: [ifname], cache_entries?: int 1024..4194304, active_flow_timeout?: int 1..604800, inactive_flow_timeout?: int 1..604800, sampling_interval?: int 1..65535, flows?: bool, nat_events?: bool, nat_events_destination?: bool, nat_port_blocks?: bool, nat_limits?: bool, retention_hours?: int 0..72, retention_records?: int 0..5000000} → {enabled, interfaces, cache_entries, active_flow_timeout, inactive_flow_timeout, sampling_interval, flows, nat_events, nat_events_destination, nat_port_blocks, nat_limits, retention_hours, retention_records, warning?}",
        always,
        set
    ),
    cmd!(query "ip.traffic-flow.get", "Traffic Flow", [], None,
        "{} → {enabled, interfaces, cache_entries, active_flow_timeout, inactive_flow_timeout, sampling_interval, flows, nat_events, nat_events_destination, nat_port_blocks, nat_limits, retention_hours, retention_records, targets, state: stopped|running|error, source, last_error, records_per_min}",
        always, get),
    cmd!(
        "ip.traffic-flow.target.add",
        "Add Traffic Flow Target",
        ["IP", "Traffic Flow"],
        None,
        "{dst_address: ip, port?: int 1..65535, src_address?: ip, version?: 9|ipfix, transport?: udp|tcp|sctp|tls, template_refresh?: int 0..1000000, template_timeout?: int 0..86400, content?: all|nat|flows, nat_events_legacy?: bool, certificate?: string, private_key?: string, ca_certificate?: string, server_name?: string, disabled?: bool, comment?: string} → {id}",
        always,
        target_add
    ),
    cmd!(
        "ip.traffic-flow.target.set",
        "Edit Traffic Flow Target",
        [],
        None,
        "{id: string, dst_address?: ip, port?: int 1..65535, src_address?: ip|\"\", version?: 9|ipfix, transport?: udp|tcp|sctp|tls, template_refresh?: int 0..1000000, template_timeout?: int 0..86400, content?: all|nat|flows, nat_events_legacy?: bool, certificate?: string, private_key?: string, ca_certificate?: string, server_name?: string, disabled?: bool, comment?: string} → {id}",
        always,
        target_set
    ),
    cmd!(
        "ip.traffic-flow.target.remove",
        "Remove Traffic Flow Target",
        [],
        None,
        "{id: string} → {id}",
        always,
        target_remove
    ),
    cmd!(query "ip.traffic-flow.target.preview", "Traffic Flow Target Preview", [], None,
        "{id?: string, dst_address?: ip, port?: int 1..65535, src_address?: ip|\"\", version?: 9|ipfix, transport?: udp|tcp|sctp|tls, template_refresh?: int 0..1000000, template_timeout?: int 0..86400, content?: all|nat|flows, nat_events_legacy?: bool, certificate?: string, private_key?: string, ca_certificate?: string, server_name?: string, disabled?: bool, comment?: string} → {computed: [{label, value}], checks: [{level, check, message, param}], commands: [{command, params}]}",
        always, target_preview),
    cmd!(query "ip.traffic-flow.target.list", "Traffic Flow Targets", [], None,
        "{} → [{id, dst_address, port, src_address, version, transport, template_refresh, template_timeout, content, nat_events_legacy, certificate, private_key, ca_certificate, server_name, disabled, comment, state: disabled|sending|connecting|error, records, messages, bytes, records_per_min, template_sends, last_template, queue, dropped, send_errors, last_error}]",
        always, target_list),
    cmd!(query "ip.traffic-flow.stats", "Traffic Flow Statistics", [], None,
        "{} → {state, source, last_error, events, kernel_overruns, queue, queue_size, queue_dropped, cache_used, cache_full, sampled_out, vanished, flows, nat_events, nat_log, nat_log_dropped, records_per_min, accounting, timestamps, kept, evicted, oldest_seq, newest_seq}",
        always, stats),
    cmd!(query "ip.traffic-flow.top", "Traffic Flow Top Talkers", [], None,
        "{minutes?: int 1..60, by?: bytes|packets|flows, limit?: int 1..100} → [{address, bytes, packets, flows, up_bytes, down_bytes}]",
        always, top_talkers),
    cmd!(query "ip.traffic-flow.records", "Traffic Flow Records", [], None,
        "{since?: int, limit?: int 1..10000, address?: ip, type?: flow|nat|port-block|nat-limit} → {records: [{seq, type}], next, oldest_seq, newest_seq}",
        always, records),
    cmd!(query "ip.traffic-flow.export", "Export Traffic Flow Records", [], None,
        "{minutes?: int 1..4320, address?: ip, limit?: int 1..100000} → {csv, rows, truncated}",
        always, export_csv),
];

fn tf(s: &mut Session) -> &mut TrafficFlow {
    &mut s.store_mut().candidate_mut().ip.traffic_flow
}

fn settings_json(c: &TrafficFlow) -> Value {
    json!({
        "enabled": c.enabled,
        "interfaces": c.interfaces.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "cache_entries": c.cache_entries,
        "active_flow_timeout": c.active_flow_timeout,
        "inactive_flow_timeout": c.inactive_flow_timeout,
        "sampling_interval": c.sampling_interval,
        "flows": c.flows,
        "nat_events": c.nat_events,
        "nat_events_destination": c.nat_events_destination,
        "nat_port_blocks": c.nat_port_blocks,
        "nat_limits": c.nat_limits,
        "retention_hours": c.retention_hours,
        "retention_records": c.retention_records,
    })
}

fn ranged(p: &Value, key: &str, lo: u32, hi: u32, hint: &str) -> Result<Option<u32>> {
    opt_u32(p, key)?
        .map(|v| {
            if (lo..=hi).contains(&v) {
                Ok(v)
            } else {
                Err(EngineError::bad(key, format!("must be {lo}..={hi}{hint}")))
            }
        })
        .transpose()
}

fn opt_u64(p: &Value, key: &str) -> Result<Option<u64>> {
    match p.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .map(Some)
            .ok_or_else(|| EngineError::bad(key, "must be a non-negative integer")),
    }
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let mut c = s.store().candidate().ip.traffic_flow.clone();
    if let Some(e) = opt_bool(p, "enabled")? {
        c.enabled = e;
    }
    if let Some(list) = opt_names(p, "interfaces", MAX_INTERFACES)? {
        let cfg = s.store().candidate();
        if let Some(missing) = list.iter().find(|n| !cfg.interfaces.contains_key(*n)) {
            return Err(EngineError::bad(
                "interfaces",
                format!("no interface '{missing}' (see interface.list)"),
            ));
        }
        c.interfaces = list;
    }
    if let Some(v) = ranged(p, "cache_entries", MIN_CACHE, MAX_CACHE, "")? {
        c.cache_entries = v;
    }
    if let Some(v) = ranged(p, "active_flow_timeout", 1, MAX_TIMEOUT, " seconds")? {
        c.active_flow_timeout = v;
    }
    if let Some(v) = ranged(p, "inactive_flow_timeout", 1, MAX_TIMEOUT, " seconds")? {
        c.inactive_flow_timeout = v;
    }
    if let Some(v) = ranged(p, "sampling_interval", 1, MAX_SAMPLING, " (1: every connection)")? {
        c.sampling_interval = v;
    }
    for (key, slot) in [
        ("flows", &mut c.flows),
        ("nat_events", &mut c.nat_events),
        ("nat_events_destination", &mut c.nat_events_destination),
        ("nat_port_blocks", &mut c.nat_port_blocks),
        ("nat_limits", &mut c.nat_limits),
    ] {
        if let Some(v) = opt_bool(p, key)? {
            *slot = v;
        }
    }
    if let Some(v) = ranged(p, "retention_hours", 0, MAX_RETENTION_HOURS, " (0: keep nothing)")? {
        c.retention_hours = v;
    }
    if let Some(v) = ranged(p, "retention_records", 0, MAX_RETENTION_RECORDS, "")? {
        c.retention_records = v;
    }
    let mut out = settings_json(&c);
    let mut warnings = Vec::new();
    if c.inactive_flow_timeout > c.active_flow_timeout {
        warnings.push("inactive_flow_timeout is longer than active_flow_timeout: flows are cut by the active timeout first");
    }
    if c.enabled && !c.targets.iter().any(|t| !t.disabled) {
        warnings.push("no enabled target: flows are only kept on the router (ip.traffic-flow.target.add)");
    }
    if c.enabled && !c.flows && !c.nat_events && !c.nat_port_blocks && !c.nat_limits {
        warnings.push("flows and every NAT event are off: nothing is exported");
    }
    if c.nat_events_destination && !c.nat_events {
        warnings.push("nat_events_destination has no effect while nat_events is off");
    }
    if c.sampling_interval > 1 && c.nat_events {
        warnings.push("sampling applies to flow records only: NAT events stay complete (the connection log)");
    }
    if !warnings.is_empty()
        && let Some(o) = out.as_object_mut()
    {
        o.insert("warning".into(), json!(warnings.join("; ")));
    }
    *tf(s) = c;
    Ok(out)
}

fn status(s: &Session) -> TrafficFlowStatus {
    if s.store().running().ip.traffic_flow.enabled {
        s.ext::<TrafficFlowStatus>().cloned().unwrap_or_default()
    } else {
        TrafficFlowStatus::default()
    }
}

fn get(s: &mut Session, _: &Value) -> Result<Value> {
    let c = s.store().candidate().ip.traffic_flow.clone();
    let st = status(s);
    let mut out = settings_json(&c);
    if let Some(o) = out.as_object_mut() {
        o.insert("targets".into(), json!(c.targets.len()));
        o.insert("state".into(), json!(st.state));
        o.insert("source".into(), json!(st.source));
        o.insert("last_error".into(), json!(st.last_error));
        o.insert("records_per_min".into(), json!(st.records_per_min));
    }
    Ok(out)
}

fn version(p: &Value) -> Result<Option<FlowVersion>> {
    match p.get("version") {
        Some(Value::Number(n)) => n
            .to_string()
            .parse::<FlowVersion>()
            .map(Some)
            .map_err(|e| EngineError::bad("version", e)),
        _ => opt_parse::<FlowVersion>(p, "version"),
    }
}

/// The router's own addresses (a `src_address` must be one).
fn own(s: &Session, a: IpAddr) -> bool {
    s.store()
        .candidate()
        .ip
        .addresses
        .iter()
        .any(|x| x.address.addr() == a)
}

fn apply_target(s: &Session, t: &mut FlowTarget, p: &Value) -> Result<()> {
    if let Some(a) = opt_parse::<IpAddr>(p, "dst_address")? {
        t.dst_address = a;
    }
    if let Some(port) = opt_u32(p, "port")? {
        t.port = u16::try_from(port)
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| EngineError::bad("port", "must be 1..=65535 (NetFlow 2055, IPFIX 4739)"))?;
    }
    match p.get("src_address") {
        Some(Value::String(v)) if v.trim().is_empty() => t.src_address = None,
        _ => {
            if let Some(a) = opt_parse::<IpAddr>(p, "src_address")? {
                if !own(s, a) {
                    return Err(EngineError::bad(
                        "src_address",
                        format!("{a} is not an address of this router (see ip.address.list)"),
                    ));
                }
                t.src_address = Some(a);
            }
        }
    }
    if let Some(v) = version(p)? {
        t.version = v;
    }
    if let Some(tr) = opt_parse::<FlowTransport>(p, "transport")? {
        t.transport = tr;
    }
    if let Some(n) = opt_u32(p, "template_refresh")? {
        if n > 1_000_000 {
            return Err(EngineError::bad("template_refresh", "must be 0..=1000000 packets"));
        }
        t.template_refresh = n;
    }
    if let Some(n) = opt_u32(p, "template_timeout")? {
        if n > 86_400 {
            return Err(EngineError::bad("template_timeout", "must be 0..=86400 seconds"));
        }
        t.template_timeout = n;
    }
    if let Some(r) = opt_parse::<TargetRecords>(p, "content")? {
        t.content = r;
    }
    if let Some(v) = opt_bool(p, "nat_events_legacy")? {
        t.nat_events_legacy = v;
    }
    if let Some(v) = pem(p, "certificate", &["CERTIFICATE"])? {
        t.certificate = v;
    }
    if let Some(v) = pem(p, "private_key", &["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"])? {
        t.private_key = v;
    }
    if let Some(v) = pem(p, "ca_certificate", &["CERTIFICATE"])? {
        t.ca_certificate = v;
    }
    if let Some(v) = opt_text(p, "server_name", MAX_SERVER_NAME)? {
        let v = v.trim().to_ascii_lowercase();
        let ok = v.split('.').all(|l| {
            !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
        if !v.is_empty() && !ok {
            return Err(EngineError::bad("server_name", "a DNS name (collector.example.net), or empty for the address"));
        }
        t.server_name = v;
    }
    if let Some(d) = opt_bool(p, "disabled")? {
        t.disabled = d;
    }
    if let Some(c) = opt_text(p, "comment", 255)? {
        t.comment = c;
    }
    // Checks on the result.
    let d = t.dst_address;
    if d.is_unspecified() || d.is_multicast() || d == IpAddr::from([255, 255, 255, 255]) {
        return Err(EngineError::bad(
            "dst_address",
            format!("{d} is not a collector's address (one unicast address)"),
        ));
    }
    if let Some(src) = t.src_address
        && src.is_ipv4() != d.is_ipv4()
    {
        return Err(EngineError::bad(
            "src_address",
            format!("{src} and dst_address {d} are of different families"),
        ));
    }
    if t.transport != FlowTransport::Udp && t.version == FlowVersion::V9 {
        return Err(EngineError::bad(
            "transport",
            format!("NetFlow v9 is UDP only (RFC 3954 §2); use version=ipfix for {}", t.transport.as_str()),
        ));
    }
    if t.certificate.is_empty() != t.private_key.is_empty() {
        let missing = if t.certificate.is_empty() { "certificate" } else { "private_key" };
        return Err(EngineError::bad(missing, "certificate and private_key go together"));
    }
    if t.transport == FlowTransport::Tls && t.certificate.is_empty() {
        return Err(EngineError::bad(
            "certificate",
            "IPFIX over TLS authenticates both sides (RFC 7011 §11.3): give this router's certificate and private_key",
        ));
    }
    if t.transport == FlowTransport::Udp && t.template_refresh == 0 && t.template_timeout == 0 {
        return Err(EngineError::bad(
            "template_timeout",
            "over UDP the templates must be sent again (RFC 7011 §8.4): set template_timeout or template_refresh",
        ));
    }
    Ok(())
}

/// A PEM text of one of `kinds` (`""` clears it).
fn pem(p: &Value, key: &str, kinds: &[&str]) -> Result<Option<String>> {
    let Some(v) = opt_str(p, key)? else {
        return Ok(None);
    };
    let v = v.trim();
    if v.is_empty() {
        return Ok(Some(String::new()));
    }
    if v.len() > MAX_PEM {
        return Err(EngineError::bad(key, format!("at most {MAX_PEM} bytes")));
    }
    let ok = kinds
        .iter()
        .any(|k| v.contains(&format!("-----BEGIN {k}-----")) && v.contains(&format!("-----END {k}-----")));
    if !ok || v.chars().any(|c| c.is_control() && c != '\n' && c != '\r') {
        return Err(EngineError::bad(
            key,
            format!("must be PEM text (-----BEGIN {}-----)", kinds.first().copied().unwrap_or("")),
        ));
    }
    Ok(Some(format!("{v}\n")))
}

/// The modal's numbers come as text: as numbers for the commands.
fn normalized(p: &Value) -> Value {
    let mut out = p.as_object().cloned().unwrap_or_default();
    for k in ["port", "template_refresh", "template_timeout"] {
        if let Some(Value::String(v)) = out.get(k)
            && let Ok(n) = v.trim().parse::<u64>()
        {
            out.insert(k.into(), json!(n));
        }
    }
    Value::Object(out)
}

/// The add/edit modal's preview (G0.24): never fails for bad input, says
/// what is wrong as a check instead.
fn target_preview(s: &mut Session, p: &Value) -> Result<Value> {
    let p = normalized(p);
    let mut checks = Vec::new();
    let mut computed = Vec::new();
    let mut commands = Vec::new();
    let check = |level: &str, check: &str, message: String, param: Option<&str>| {
        json!({"level": level, "check": check, "message": message, "param": param})
    };
    let id = match p.get("id") {
        Some(v) => match v.as_str().map(str::parse::<ItemId>) {
            Some(Ok(id)) if s.store().candidate().ip.traffic_flow.target(id).is_some() => Some(id),
            _ => {
                checks.push(check("error", "id", "no such target".into(), None));
                None
            }
        },
        None => None,
    };
    let base = id.and_then(|id| s.store().candidate().ip.traffic_flow.target(id).cloned());
    let dst_given = p.get("dst_address").and_then(Value::as_str).is_some_and(|v| !v.trim().is_empty());
    if base.is_none() && !dst_given {
        checks.push(check("error", "required", "the collector's address is required".into(), Some("dst_address")));
    } else if checks.is_empty() {
        let mut t = base.clone().unwrap_or_else(|| FlowTarget::new(ItemId(0), IpAddr::from([0, 0, 0, 0])));
        let mut q = p.clone();
        if let Some(o) = q.as_object_mut() {
            o.remove("id");
        }
        match apply_target(s, &mut t, &q).and_then(|()| duplicate(&s.store().candidate().ip.traffic_flow, &t)) {
            Err(EngineError::BadParam { param, reason }) => {
                checks.push(check("error", "invalid", reason, Some(param.as_str())));
            }
            Err(e) => checks.push(check("error", "invalid", e.to_string(), None)),
            Ok(()) => {
                let (version, transport) = (
                    if t.version == FlowVersion::V9 { "NetFlow v9" } else { "IPFIX" },
                    t.transport.as_str().to_uppercase(),
                );
                let from = t.src_address.map_or_else(|| "the route's address".to_owned(), |a| a.to_string());
                computed.push(json!({"label": "Sends", "value": format!("{version} over {transport} to {}:{} from {from}", t.dst_address, t.port)}));
                let templates = match t.transport {
                    FlowTransport::Udp => format!(
                        "every {} packets and every {} s",
                        t.template_refresh, t.template_timeout
                    ),
                    _ => "once per connection (and on every reconnect)".to_owned(),
                };
                computed.push(json!({"label": "Templates", "value": templates}));
                checks.push(check("ok", "valid", "ready to send".into(), None));
                let tf = &s.store().candidate().ip.traffic_flow;
                if !tf.enabled {
                    checks.push(check("warning", "off", "traffic flow is off: nothing is sent until it is enabled (General)".into(), None));
                }
                computed.push(json!({"label": "Records", "value": match t.content {
                    TargetRecords::All => "flows and NAT events",
                    TargetRecords::Nat => "NAT events only",
                    TargetRecords::Flows => "flows only",
                }}));
                if t.transport == FlowTransport::Udp {
                    checks.push(check("info", "udp", "over UDP a collector that is down loses what is sent; TCP, SCTP and TLS queue it".into(), Some("transport")));
                }
                if t.transport == FlowTransport::Tls {
                    let name = if t.server_name.is_empty() { t.dst_address.to_string() } else { t.server_name.clone() };
                    computed.push(json!({"label": "TLS", "value": format!("the collector's certificate must name {name}; this router shows its own (mutual, RFC 7011 §11.3)")}));
                    if t.port == corerouter_model::traffic_flow::DEFAULT_PORT || t.port == 4739 {
                        checks.push(check("info", "port", "IPFIX over TLS listens on 4740 (RFC 7011 §11.2)".into(), Some("port")));
                    }
                }
                if t.content.wants_nat() && t.transport != FlowTransport::Tls {
                    checks.push(check("info", "plain", "NAT logs say who used which address: RFC 8158 §7 asks for them encrypted (transport=tls)".into(), Some("transport")));
                }
                if t.nat_events_legacy {
                    checks.push(check("info", "legacy", "NAT44 sessions go out as natEvent 1/2 (Historic); blocks and limits keep their RFC 8158 values".into(), Some("nat_events_legacy")));
                }
                if t.version == FlowVersion::Ipfix && t.port == corerouter_model::traffic_flow::DEFAULT_PORT {
                    checks.push(check("info", "port", "2055 is the NetFlow port most collectors use; IPFIX's own is 4739".into(), Some("port")));
                }
                let mut params = q.as_object().cloned().unwrap_or_default();
                params.retain(|_, v| !v.is_null());
                match id {
                    Some(id) => {
                        params.insert("id".into(), json!(id.to_string()));
                        commands.push(json!({"command": "ip.traffic-flow.target.set", "params": params}));
                    }
                    None => commands.push(json!({"command": "ip.traffic-flow.target.add", "params": params})),
                }
            }
        }
    }
    Ok(json!({"computed": computed, "checks": checks, "commands": commands}))
}

fn target_id(s: &Session, p: &Value) -> Result<ItemId> {
    let id: ItemId = req_parse(p, "id")?;
    if s.store().candidate().ip.traffic_flow.target(id).is_none() {
        return Err(EngineError::bad(
            "id",
            format!("no traffic-flow target {id} (see ip.traffic-flow.target.list)"),
        ));
    }
    Ok(id)
}

fn duplicate(c: &TrafficFlow, t: &FlowTarget) -> Result<()> {
    if let Some(o) = c
        .targets
        .iter()
        .find(|o| o.id != t.id && o.dst_address == t.dst_address && o.port == t.port)
    {
        return Err(EngineError::bad(
            "dst_address",
            format!("target {} already sends to {}:{}", o.id, t.dst_address, t.port),
        ));
    }
    Ok(())
}

fn target_add(s: &mut Session, p: &Value) -> Result<Value> {
    let dst: IpAddr = req_parse(p, "dst_address")?;
    if s.store().candidate().ip.traffic_flow.targets.len() >= MAX_TARGETS {
        return Err(EngineError::bad(
            "dst_address",
            format!("at most {MAX_TARGETS} targets"),
        ));
    }
    let mut t = FlowTarget::new(ItemId(0), dst);
    apply_target(s, &mut t, p)?;
    duplicate(&s.store().candidate().ip.traffic_flow, &t)?;
    let c = tf(s);
    t.id = c.next_target_id();
    let id = t.id;
    c.targets.push(t);
    Ok(json!({ "id": id.to_string() }))
}

fn target_set(s: &mut Session, p: &Value) -> Result<Value> {
    let id = target_id(s, p)?;
    let Some(mut t) = s.store().candidate().ip.traffic_flow.target(id).cloned() else {
        return Err(EngineError::bad("id", "gone"));
    };
    apply_target(s, &mut t, p)?;
    duplicate(&s.store().candidate().ip.traffic_flow, &t)?;
    if let Some(slot) = tf(s).targets.iter_mut().find(|x| x.id == id) {
        *slot = t;
    }
    Ok(json!({ "id": id.to_string() }))
}

fn target_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let id = target_id(s, p)?;
    tf(s).targets.retain(|t| t.id != id);
    Ok(json!({ "id": id.to_string() }))
}

fn target_list(s: &mut Session, _: &Value) -> Result<Value> {
    let st = status(s);
    let c = &s.store().candidate().ip.traffic_flow;
    Ok(Value::Array(
        c.targets
            .iter()
            .map(|t| {
                let mut v = json!({
                    "id": t.id.to_string(),
                    "dst_address": t.dst_address,
                    "port": t.port,
                    "src_address": t.src_address,
                    "version": t.version.as_str(),
                    "transport": t.transport.as_str(),
                    "template_refresh": t.template_refresh,
                    "template_timeout": t.template_timeout,
                    "content": t.content.as_str(),
                    "nat_events_legacy": t.nat_events_legacy,
                    "certificate": t.certificate,
                    "private_key": if t.private_key.is_empty() { "" } else { "***" },
                    "ca_certificate": t.ca_certificate,
                    "server_name": t.server_name,
                    "disabled": t.disabled,
                    "comment": t.comment,
                    "state": "disabled",
                    "records": 0, "messages": 0, "bytes": 0, "records_per_min": 0,
                    "template_sends": 0, "last_template": null, "queue": 0,
                    "dropped": 0, "send_errors": 0, "last_error": null,
                });
                if let (Some(o), Some(ts)) = (
                    v.as_object_mut(),
                    st.targets.iter().find(|x| x.id == t.id),
                ) && let Value::Object(more) = serde_json::to_value(ts).unwrap_or(Value::Null)
                {
                    o.extend(more.into_iter().filter(|(k, _)| k != "id"));
                }
                v
            })
            .collect(),
    ))
}

fn stats(s: &mut Session, _: &Value) -> Result<Value> {
    let st = status(s);
    let mut out = serde_json::to_value(&st).unwrap_or_else(|_| json!({}));
    let store = s.ext::<FlowStore>();
    let (kept, evicted, bounds) = store.map_or((0, 0, None), |st| (st.len(), st.evicted, st.bounds()));
    if let Some(o) = out.as_object_mut() {
        o.remove("targets");
        o.insert("kept".into(), json!(kept));
        o.insert("evicted".into(), json!(evicted));
        o.insert("oldest_seq".into(), json!(bounds.map(|b| b.0)));
        o.insert("newest_seq".into(), json!(bounds.map(|b| b.1)));
    }
    Ok(out)
}

/// Now in Unix ms: the router's clock, or the newest record's time.
fn now_ms(s: &Session) -> u64 {
    s.hal_now().map(|t| t * 1000).unwrap_or_else(|| {
        s.ext::<FlowStore>()
            .and_then(|st| st.newer(0).next().map(|r| r.at_ms))
            .unwrap_or(0)
    })
}

fn top_talkers(s: &mut Session, p: &Value) -> Result<Value> {
    let minutes = ranged(p, "minutes", 1, 60, "")?.unwrap_or(5);
    let limit = ranged(p, "limit", 1, 100, "")?.unwrap_or(20);
    let by = match opt_str(p, "by")? {
        None => "bytes",
        Some(b @ ("bytes" | "packets" | "flows")) => b,
        Some(_) => return Err(EngineError::bad("by", "must be bytes, packets or flows")),
    };
    let from = now_ms(s).saturating_sub(u64::from(minutes) * 60_000);
    let Some(store) = s.ext::<FlowStore>() else {
        return Ok(json!([]));
    };
    let list = top(store, from, by, usize::try_from(limit).unwrap_or(20));
    Ok(serde_json::to_value(list).unwrap_or_else(|_| json!([])))
}

fn kind_of(r: &Record) -> &'static str {
    match r {
        Record::Flow(_) => "flow",
        Record::Nat(_) => "nat",
        Record::PortBlock(_) => "port-block",
        Record::NatLimit(_) => "nat-limit",
    }
}

fn touches(r: &Record, a: IpAddr) -> bool {
    match r {
        Record::Flow(f) => [f.src, f.dst, f.post_src, f.post_dst].contains(&a),
        Record::Nat(n) => [n.src, n.dst, n.post_src, n.post_dst]
            .iter()
            .any(|x| IpAddr::V4(*x) == a),
        Record::PortBlock(b) => IpAddr::V4(b.src) == a || IpAddr::V4(b.post_src) == a,
        Record::NatLimit(l) => IpAddr::V4(l.src) == a,
    }
}

/// The batch API: records after `since`, oldest first. The caller keeps
/// `next` and asks again from there (a ClickHouse exporter, a script).
fn records(s: &mut Session, p: &Value) -> Result<Value> {
    let since = opt_u64(p, "since")?.unwrap_or(0);
    let limit = ranged(p, "limit", 1, MAX_BATCH, "")?.unwrap_or(1000);
    let address = opt_parse::<IpAddr>(p, "address")?;
    let kind = match opt_str(p, "type")? {
        None => None,
        Some(k @ ("flow" | "nat" | "port-block" | "nat-limit")) => Some(k),
        Some(_) => return Err(EngineError::bad("type", "must be flow, nat, port-block or nat-limit")),
    };
    let Some(store) = s.ext::<FlowStore>() else {
        return Ok(json!({"records": [], "next": since, "oldest_seq": null, "newest_seq": null}));
    };
    let mut next = since;
    let mut out = Vec::new();
    for r in store.after(since) {
        if out.len() >= usize::try_from(limit).unwrap_or(1000) {
            break;
        }
        next = r.seq;
        if kind.is_some_and(|k| k != kind_of(&r.record))
            || address.is_some_and(|a| !touches(&r.record, a))
        {
            continue;
        }
        out.push(serde_json::to_value(r).unwrap_or(Value::Null));
    }
    let bounds = store.bounds();
    Ok(json!({
        "records": out,
        "next": next,
        "oldest_seq": bounds.map(|b| b.0),
        "newest_seq": bounds.map(|b| b.1),
    }))
}

fn time(ms: u64) -> String {
    format!("{}.{:03}", crate::safe_mode::utc(ms / 1000).trim_end_matches(" UTC"), ms % 1000)
}

const CSV_HEADER: &str = "seq,type,time_utc,start_utc,end_utc,event,protocol,src,src_port,dst,dst_port,post_src,post_src_port,post_dst,post_dst_port,octets,packets,ingress,egress,end_reason,direction,user,vlan,pool,limit";

/// A CSV field: quoted when it holds a comma, a quote or a line break.
fn csv_text(v: &str) -> String {
    if v.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", v.replace('"', "\"\""))
    } else {
        v.to_owned()
    }
}

fn csv_row(out: &mut String, st: &Stored) {
    let r = &st.record;
    let t = time(r.time_ms());
    let _ = match r {
        Record::Flow(f) => writeln!(
            out,
            "{},flow,{t},{},{},,{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},,,,",
            st.seq,
            time(f.start_ms),
            time(f.end_ms),
            f.protocol,
            f.src,
            f.src_port,
            f.dst,
            f.dst_port,
            f.post_src,
            f.post_src_port,
            f.post_dst,
            f.post_dst_port,
            f.octets,
            f.packets,
            f.ingress,
            f.egress,
            f.end_reason.as_str(),
            match f.direction {
                corerouter_proto_flow::Direction::Initiator => "initiator",
                corerouter_proto_flow::Direction::Reverse => "reverse",
            },
        ),
        Record::Nat(n) => writeln!(
            out,
            "{},nat,{t},{},,{},{},{},{},{},{},{},{},{},{},,,,,,,,,,",
            st.seq,
            if n.start_ms > 0 { time(n.start_ms) } else { String::new() },
            n.event.code(),
            n.protocol,
            n.src,
            n.src_port,
            n.dst,
            n.dst_port,
            n.post_src,
            n.post_src_port,
            n.post_dst,
            n.post_dst_port,
        ),
        Record::PortBlock(b) => writeln!(
            out,
            "{},port-block,{t},,,{},,{},,,,{},{}-{},,,,,,,,,{},{},{},",
            st.seq,
            b.event.code(),
            b.src,
            b.post_src,
            b.port_start,
            b.port_end,
            csv_text(&b.user),
            b.vlan,
            b.pool,
        ),
        Record::NatLimit(l) => writeln!(
            out,
            "{},nat-limit,{t},,,{},,{},,,,,,,,,,,,{},,,,{},{}",
            st.seq,
            l.event.code(),
            if l.src.is_unspecified() { String::new() } else { l.src.to_string() },
            l.kind,
            l.pool,
            l.limit,
        ),
    };
}

fn export_csv(s: &mut Session, p: &Value) -> Result<Value> {
    let minutes = ranged(p, "minutes", 1, 4320, "")?.unwrap_or(60);
    let limit = ranged(p, "limit", 1, MAX_CSV, "")?.unwrap_or(MAX_CSV);
    let address = opt_parse::<IpAddr>(p, "address")?;
    let from = now_ms(s).saturating_sub(u64::from(minutes) * 60_000);
    let mut csv = String::from(CSV_HEADER);
    csv.push('\n');
    let Some(store) = s.ext::<FlowStore>() else {
        return Ok(json!({"csv": csv, "rows": 0, "truncated": false}));
    };
    let mut rows: Vec<&Stored> = store
        .newer(from)
        .filter(|r| address.is_none_or(|a| touches(&r.record, a)))
        .take(usize::try_from(limit).unwrap_or(usize::MAX).saturating_add(1))
        .collect();
    let truncated = rows.len() > usize::try_from(limit).unwrap_or(usize::MAX);
    rows.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
    rows.reverse();
    for r in &rows {
        csv_row(&mut csv, r);
    }
    Ok(json!({"csv": csv, "rows": rows.len(), "truncated": truncated}))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::Session;
    use corerouter_hal::VirtualHal;
    use corerouter_proto_flow::{Direction, EndReason, Flow, NatEvent, NatEventType};

    fn session() -> Session {
        Session::new(Box::new(VirtualHal::default()))
    }

    fn ok(s: &mut Session, id: &str, p: Value) -> Value {
        s.execute(id, &p).unwrap_or_else(|e| panic!("{id}: {e}"))
    }

    fn err(s: &mut Session, id: &str, p: Value) -> String {
        s.execute(id, &p).unwrap_err().to_string()
    }

    #[test]
    fn settings_validate_and_commit() {
        let mut s = session();
        let out = ok(&mut s, "ip.traffic-flow.set", json!({"enabled": true, "interfaces": ["ether1"], "active_flow_timeout": 60, "sampling_interval": 4}));
        assert!(out["warning"].as_str().unwrap().contains("no enabled target"));
        assert!(err(&mut s, "ip.traffic-flow.set", json!({"interfaces": ["nope9"]})).contains("no interface"));
        assert!(err(&mut s, "ip.traffic-flow.set", json!({"cache_entries": 10})).contains("1024"));
        assert!(err(&mut s, "ip.traffic-flow.set", json!({"retention_hours": 999})).contains("0..=72"));
        let g = ok(&mut s, "ip.traffic-flow.get", json!({}));
        assert_eq!(g["active_flow_timeout"], 60);
        assert_eq!(g["state"], "stopped");
        assert!(s.store().running().ip.traffic_flow.enabled);
    }

    #[test]
    fn targets_add_set_remove_and_refuse_bad_ones() {
        let mut s = session();
        let a = ok(&mut s, "ip.traffic-flow.target.add", json!({"dst_address": "192.0.2.10", "version": 9}));
        let id = a["id"].as_str().unwrap().to_owned();
        assert!(err(&mut s, "ip.traffic-flow.target.add", json!({"dst_address": "192.0.2.10"})).contains("already sends"));
        assert!(err(&mut s, "ip.traffic-flow.target.add", json!({"dst_address": "224.0.0.1"})).contains("unicast"));
        assert!(err(&mut s, "ip.traffic-flow.target.add", json!({"dst_address": "192.0.2.11", "version": "5"})).contains("v5"));
        assert!(err(&mut s, "ip.traffic-flow.target.add", json!({"dst_address": "192.0.2.11", "src_address": "198.51.100.1"})).contains("not an address of this router"));
        assert!(err(&mut s, "ip.traffic-flow.target.set", json!({"id": id, "transport": "tcp"})).contains("UDP only"));
        assert!(err(&mut s, "ip.traffic-flow.target.set", json!({"id": id, "template_refresh": 0, "template_timeout": 0})).contains("RFC 7011"));
        ok(&mut s, "ip.traffic-flow.target.set", json!({"id": id, "version": "ipfix", "transport": "tcp", "port": 4739}));
        let list = ok(&mut s, "ip.traffic-flow.target.list", json!({}));
        assert_eq!(list[0]["transport"], "tcp");
        assert_eq!(list[0]["port"], 4739);
        assert_eq!(list[0]["state"], "disabled");
        ok(&mut s, "ip.traffic-flow.target.remove", json!({"id": id}));
        assert!(err(&mut s, "ip.traffic-flow.target.remove", json!({"id": id})).contains("no traffic-flow target"));
    }

    #[test]
    fn the_preview_says_what_is_wrong_and_what_it_would_run() {
        let mut s = session();
        let p = ok(&mut s, "ip.traffic-flow.target.preview", json!({}));
        assert_eq!(p["checks"][0]["param"], "dst_address");
        let p = ok(&mut s, "ip.traffic-flow.target.preview", json!({"dst_address": "192.0.2.10", "port": "9", "version": "9", "transport": "tcp"}));
        assert_eq!(p["checks"][0]["level"], "error");
        assert_eq!(p["checks"][0]["param"], "transport");
        assert!(p["commands"].as_array().unwrap().is_empty());
        let p = ok(&mut s, "ip.traffic-flow.target.preview", json!({"dst_address": "192.0.2.10", "port": "4739"}));
        assert_eq!(p["commands"][0]["command"], "ip.traffic-flow.target.add");
        assert_eq!(p["commands"][0]["params"]["port"], 4739, "the modal's text became a number");
        assert!(p["computed"][0]["value"].as_str().unwrap().contains("IPFIX over UDP to 192.0.2.10:4739"));
        assert!(p["checks"].as_array().unwrap().iter().any(|c| c["check"] == "off"));
        // And what it would run, runs.
        let cmd = p["commands"][0].clone();
        let id = ok(&mut s, cmd["command"].as_str().unwrap(), cmd["params"].clone())["id"].clone();
        let p = ok(&mut s, "ip.traffic-flow.target.preview", json!({"id": id, "port": "2055"}));
        assert_eq!(p["commands"][0]["command"], "ip.traffic-flow.target.set");
        assert_eq!(p["checks"][0]["level"], "ok");
    }

    const CERT: &str = "-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----";
    const KEY: &str = "-----BEGIN PRIVATE KEY-----\nAA\n-----END PRIVATE KEY-----";

    /// G4.4j: SCTP, TLS with both certificates, a NAT-only target with the
    /// legacy natEvent codes.
    #[test]
    fn sctp_and_tls_targets_and_what_each_receives() {
        let mut s = session();
        let a = ok(&mut s, "ip.traffic-flow.target.add", json!({"dst_address": "192.0.2.20", "port": 4739, "transport": "sctp", "content": "nat", "nat_events_legacy": true}));
        let sctp = a["id"].as_str().unwrap().to_owned();
        assert!(err(&mut s, "ip.traffic-flow.target.add", json!({"dst_address": "192.0.2.21", "transport": "tls"})).contains("RFC 7011 §11.3"));
        assert!(err(&mut s, "ip.traffic-flow.target.add", json!({"dst_address": "192.0.2.21", "transport": "dtls"})).contains("DTLS is not supported"));
        assert!(err(&mut s, "ip.traffic-flow.target.add", json!({"dst_address": "192.0.2.21", "transport": "sctp", "version": 9})).contains("UDP only"));
        assert!(err(&mut s, "ip.traffic-flow.target.add", json!({"dst_address": "192.0.2.21", "transport": "tls", "certificate": CERT})).contains("go together"));
        assert!(err(&mut s, "ip.traffic-flow.target.add", json!({"dst_address": "192.0.2.21", "certificate": "hello"})).contains("PEM"));
        assert!(err(&mut s, "ip.traffic-flow.target.add", json!({"dst_address": "192.0.2.21", "server_name": "bad name!"})).contains("DNS name"));
        assert!(err(&mut s, "ip.traffic-flow.target.add", json!({"dst_address": "192.0.2.21", "content": "some"})).contains("all, nat or flows"));
        let t = ok(&mut s, "ip.traffic-flow.target.add", json!({"dst_address": "192.0.2.21", "port": 4740, "transport": "tls", "certificate": CERT, "private_key": KEY, "ca_certificate": CERT, "server_name": "Collector.Example.net"}));
        let list = ok(&mut s, "ip.traffic-flow.target.list", json!({}));
        assert_eq!(list[0]["transport"], "sctp");
        assert_eq!(list[0]["content"], "nat");
        assert_eq!(list[0]["nat_events_legacy"], true);
        assert_eq!(list[1]["transport"], "tls");
        assert_eq!(list[1]["private_key"], "***", "the key never comes back");
        assert_eq!(list[1]["server_name"], "collector.example.net");
        let p = ok(&mut s, "ip.traffic-flow.target.preview", json!({"id": t["id"]}));
        assert!(p["computed"].as_array().unwrap().iter().any(|c| c["label"] == "TLS"), "{p}");
        let p = ok(&mut s, "ip.traffic-flow.target.preview", json!({"id": sctp}));
        assert!(p["checks"].as_array().unwrap().iter().any(|c| c["check"] == "plain"), "{p}");
        assert!(p["checks"].as_array().unwrap().iter().any(|c| c["check"] == "legacy"), "{p}");
        // The NAT switches.
        let out = ok(&mut s, "ip.traffic-flow.set", json!({"enabled": true, "flows": false, "nat_events": false, "nat_port_blocks": false, "nat_limits": false}));
        assert!(out["warning"].as_str().unwrap().contains("nothing is exported"));
        let g = ok(&mut s, "ip.traffic-flow.get", json!({}));
        assert_eq!((g["flows"].as_bool(), g["nat_port_blocks"].as_bool()), (Some(false), Some(false)));
        assert!(!TrafficFlow::default().nat_events, "RouterOS nat-events=no");
    }

    #[test]
    fn a_failed_batch_rolls_back() {
        let mut s = session();
        let before = s.store().running().ip.traffic_flow.clone();
        let r = s.batch(
            &json!([
                {"command": "ip.traffic-flow.target.add", "params": {"dst_address": "192.0.2.10"}},
                {"command": "ip.traffic-flow.set", "params": {"cache_entries": 1}},
            ]),
            true,
        );
        assert!(r.is_err());
        assert_eq!(s.store().running().ip.traffic_flow, before);
    }

    fn flow(sub: &str, octets: u64, t: u64) -> Record {
        let a: IpAddr = sub.parse().unwrap();
        let srv: IpAddr = "192.0.2.1".parse().unwrap();
        Record::Flow(Flow {
            start_ms: t,
            end_ms: t,
            protocol: 6,
            src: a,
            dst: srv,
            src_port: 1000,
            dst_port: 443,
            post_src: "203.0.113.1".parse().unwrap(),
            post_dst: srv,
            post_src_port: 2000,
            post_dst_port: 443,
            octets,
            packets: 3,
            ingress: 1,
            egress: 2,
            end_reason: EndReason::End,
            direction: Direction::Initiator,
        })
    }

    #[test]
    fn records_top_and_csv_read_the_store() {
        let mut s = session();
        ok(&mut s, "ip.traffic-flow.set", json!({"enabled": true}));
        let now = s.hal_now().unwrap_or(0) * 1000;
        let nat = Record::Nat(NatEvent {
            time_ms: now,
            start_ms: now,
            event: NatEventType::Nat44SessionCreate,
            protocol: 6,
            src: "100.64.0.1".parse().unwrap(),
            dst: "192.0.2.1".parse().unwrap(),
            src_port: 1000,
            dst_port: 443,
            post_src: "203.0.113.1".parse().unwrap(),
            post_dst: "192.0.2.1".parse().unwrap(),
            post_src_port: 2000,
            post_dst_port: 443,
        });
        s.traffic_flow_store(&[nat, flow("100.64.0.1", 100, now), flow("100.64.0.2", 900, now)], now);
        let r = ok(&mut s, "ip.traffic-flow.records", json!({"limit": 2}));
        assert_eq!(r["records"].as_array().unwrap().len(), 2);
        assert_eq!(r["records"][0]["type"], "nat");
        assert_eq!(r["next"], 2);
        let r = ok(&mut s, "ip.traffic-flow.records", json!({"since": 2}));
        assert_eq!(r["records"][0]["src"], "100.64.0.2");
        let r = ok(&mut s, "ip.traffic-flow.records", json!({"address": "100.64.0.1", "type": "flow"}));
        assert_eq!(r["records"].as_array().unwrap().len(), 1);
        let t = ok(&mut s, "ip.traffic-flow.top", json!({}));
        assert_eq!(t[0]["address"], "100.64.0.2");
        let c = ok(&mut s, "ip.traffic-flow.export", json!({"address": "100.64.0.1"}));
        assert_eq!(c["rows"], 2);
        let csv = c["csv"].as_str().unwrap();
        assert!(csv.starts_with("seq,type,"));
        assert!(csv.contains(",nat,"), "{csv}");
        assert!(csv.contains("203.0.113.1,2000"), "{csv}");
        let st = ok(&mut s, "ip.traffic-flow.stats", json!({}));
        assert_eq!(st["kept"], 3);
    }
}
