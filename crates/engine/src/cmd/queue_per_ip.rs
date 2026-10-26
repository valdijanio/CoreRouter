//! Per-IP limits (G4.9): "every address of 10.0.0.0/16 gets 10M/20M". In
//! RouterOS that is two `pcq` queue types (`pcq-rate`, classified by
//! source for upload and by destination for download) and a simple queue
//! over the prefix that uses them. `queue.per-ip.add` makes the three in
//! one command (and reuses types of the same rate), so an import and a
//! hand-made rule look the same; the list shows those simple queues with
//! the rate of each address resolved. Editing or removing a rule is
//! `queue.simple.set/remove` on its id; the types stay (others may share
//! them).

use corerouter_model::ItemId;
use corerouter_model::queue::{
    Classifier, Kind, MAX_COMMENT, QueueType, Rates, SimpleQueue, Target, TypeNames, rate_text,
    targets_text,
};
use serde_json::{Value, json};

use super::args::{opt_str, opt_text};
use super::queue_simple::{opt_targets, warnings};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!("queue.per-ip.add", "Add Per-IP Limit", [], None,
        "{target: string | [string] (prefixes whose every address is limited: 10.0.0.0/16, 2001:db8::/48), rate: rates (each address, upload/download: 10M/20M), max_limit?: rates (all addresses together; default 0 = no cap), ipv6_mask?: int 32..128 (IPv6 addresses that share a sub-stream: 64 = one per /64, the default), name?: string, comment?: string} → {id, name, queue (the types used), warnings}",
        always, add),
    cmd!(query "queue.per-ip.preview", "Per-IP Limit Preview", [], None,
        "{target?: string, rate?: string, max_limit?: string, ipv6_mask?: string, name?: string, comment?: string} → {computed: [{label, value}], checks: [{level, check, message, param}], commands: [{command, params}]}",
        always, preview),
    cmd!(query "queue.per-ip.list", "Per-IP Limits", [], None,
        "{} → [{id, name, target, rate (each address, upload/download), max_limit, queue, classifier (upload/download), ipv6_mask, disabled, comment?, pcq_queues (addresses seen lately)}]",
        always, list),
];

/// A pcq type for `rate` in one direction: an existing one with the same
/// settings, or a new `pcq-<dir>-<rate>`.
fn pcq_type(s: &mut Session, download: bool, rate: u64, mask6: u8) -> Result<String> {
    let classifier = if download { Classifier::DstAddress } else { Classifier::SrcAddress };
    let fits = |t: &QueueType| {
        t.kind == Kind::Pcq
            && t.pcq_rate == rate
            && t.pcq_classifier == classifier
            && t.pcq_src_address_mask == 32
            && t.pcq_dst_address_mask == 32
            && (if download { t.pcq_dst_address6_mask } else { t.pcq_src_address6_mask }) == mask6
    };
    let q = &s.store().candidate().queue;
    if let Some(t) = q.all_types().into_iter().find(|t| fits(t)) {
        return Ok(t.name);
    }
    let dir = if download { "down" } else { "up" };
    let base = if mask6 == 128 { format!("pcq-{dir}-{}", rate_text(rate)) } else { format!("pcq-{dir}-{}-v6m{mask6}", rate_text(rate)) };
    let name = (0..)
        .map(|i| if i == 0 { base.clone() } else { format!("{base}-{i}") })
        .find(|n| q.queue_type(n).is_none())
        .unwrap_or(base);
    let mut t = QueueType::new(&name, Kind::Pcq);
    t.pcq_rate = rate;
    t.pcq_classifier = classifier;
    t.pcq_src_address6_mask = if download { 128 } else { mask6 };
    t.pcq_dst_address6_mask = if download { mask6 } else { 128 };
    let q = &mut s.store_mut().candidate_mut().queue;
    if q.types.len() >= corerouter_model::queue::MAX_TYPES {
        return Err(EngineError::bad("rate", "too many queue types"));
    }
    t.id = q.next_id();
    q.types.push(t);
    Ok(name)
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let targets = opt_targets(s, p)?.ok_or_else(|| EngineError::bad("target", "is required"))?;
    if targets.iter().any(|t| matches!(t, Target::Interface(_))) {
        return Err(EngineError::bad("target", "prefixes only: a per-IP limit splits a prefix into its addresses"));
    }
    let rate: Rates = opt_str(p, "rate")?
        .ok_or_else(|| EngineError::bad("rate", "is required"))?
        .parse()
        .map_err(|e: corerouter_model::ParseError| EngineError::bad("rate", e.to_string()))?;
    if rate.upload == 0 && rate.download == 0 {
        return Err(EngineError::bad("rate", "give a rate for at least one direction (10M/20M)"));
    }
    let max: Rates = opt_str(p, "max_limit")?
        .map(|t| t.parse().map_err(|e: corerouter_model::ParseError| EngineError::bad("max_limit", e.to_string())))
        .transpose()?
        .unwrap_or_default();
    let mask6 = match p.get("ipv6_mask") {
        None | Some(Value::Null) => 64,
        Some(Value::String(t)) if t.trim().is_empty() => 64,
        Some(v) => v
            .as_u64()
            .or_else(|| v.as_str().and_then(|t| t.trim().parse().ok()))
            .and_then(|m| u8::try_from(m).ok())
            .filter(|m| (32..=128).contains(m))
            .ok_or_else(|| EngineError::bad("ipv6_mask", "32..=128"))?,
    };
    let name = match opt_str(p, "name")? {
        Some(n) => n.trim().to_owned(),
        None => s.store().candidate().queue.free_name(),
    };
    let comment = opt_text(p, "comment", MAX_COMMENT)?.unwrap_or_default();
    if !corerouter_model::queue::name_ok(&name) {
        return Err(EngineError::bad("name", "1..64 characters, without '/', ',' or '\"'"));
    }
    if s.store().candidate().queue.simple_by_name(&name).is_some() {
        return Err(EngineError::bad("name", format!("queue '{name}' exists")));
    }
    // 0 in one direction: the stock type (sub-streams share the cap).
    let up = if rate.upload == 0 { "pcq-upload-default".to_owned() } else { pcq_type(s, false, rate.upload, mask6)? };
    let down = if rate.download == 0 { "pcq-download-default".to_owned() } else { pcq_type(s, true, rate.download, mask6)? };
    let mut q = SimpleQueue::new(ItemId(0), name, targets);
    q.max_limit = max;
    q.queue = TypeNames { upload: up, download: down };
    q.comment = comment;
    let w = warnings(s, &q);
    let types = q.queue.to_string();
    let queues = &mut s.store_mut().candidate_mut().queue;
    q.id = queues.next_id();
    let out = json!({"id": q.id, "name": q.name, "queue": types, "warnings": w});
    queues.simple.push(q);
    Ok(out)
}

/// The modal's preview: `add`'s checks and the types it would make or
/// reuse.
fn preview(s: &mut Session, p: &Value) -> Result<Value> {
    super::ppp_common::preview(s, p, ("queue.per-ip.add", "queue.per-ip.add"), (add, add), |s, v| {
        let id = v.get("id").and_then(Value::as_str).unwrap_or_default();
        let queues = &s.store().candidate().queue;
        let Some(q) = queues.simple.iter().find(|q| q.id.to_string() == id) else {
            return Vec::new();
        };
        let each = |n: &str| queues.queue_type(n).map(|t| rate_text(t.pcq_rate)).unwrap_or_default();
        vec![
            json!({"label": "Each address", "value": format!("{}/{}", each(&q.queue.upload), each(&q.queue.download))}),
            json!({"label": "Queue types", "value": q.queue.to_string()}),
            json!({"label": "Simple queue", "value": q.name}),
        ]
    })
}

fn list(s: &mut Session, _: &Value) -> Result<Value> {
    let q = &s.store().candidate().queue;
    let rows: Vec<Value> = q
        .simple
        .iter()
        .filter_map(|sq| {
            let up = q.queue_type(&sq.queue.upload)?;
            let down = q.queue_type(&sq.queue.download)?;
            if up.kind != Kind::Pcq && down.kind != Kind::Pcq {
                return None;
            }
            let each = |t: &QueueType| if t.kind == Kind::Pcq { rate_text(t.pcq_rate) } else { "—".into() };
            let c = s.queue_counters(&sq.id.to_string()).unwrap_or_default();
            let mut v = json!({
                "id": sq.id,
                "name": sq.name,
                "target": targets_text(&sq.target),
                "rate": format!("{}/{}", each(&up), each(&down)),
                "max_limit": sq.max_limit.to_string(),
                "queue": sq.queue.to_string(),
                "classifier": format!("{}/{}", up.pcq_classifier.as_str(), down.pcq_classifier.as_str()),
                "ipv6_mask": down.pcq_dst_address6_mask,
                "disabled": sq.disabled,
                "pcq_queues": c.pcq_queues,
            });
            if !sq.comment.is_empty()
                && let Some(o) = v.as_object_mut()
            {
                o.insert("comment".into(), json!(sq.comment));
            }
            Some(v)
        })
        .collect();
    Ok(Value::Array(rows))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(s: &mut Session, id: &str, p: Value) -> Value {
        s.execute(id, &p).unwrap_or_else(|e| panic!("{id} {p}: {e}"))
    }

    #[test]
    fn a_rule_is_two_pcq_types_and_a_queue() {
        let mut s = Session::virtual_lab();
        let r = ok(&mut s, "queue.per-ip.add", json!({"target": "10.0.0.0/16", "rate": "10M/20M", "max_limit": "1G/2G", "name": "clientes"}));
        assert_eq!(r["queue"], "pcq-up-10M-v6m64/pcq-down-20M-v6m64");
        // Same rate again: the types are reused.
        let r = ok(&mut s, "queue.per-ip.add", json!({"target": "10.1.0.0/16, 2001:db8::/48", "rate": "10M/20M"}));
        assert_eq!(r["queue"], "pcq-up-10M-v6m64/pcq-down-20M-v6m64");
        assert_eq!(s.store().running().queue.types.len(), 2);
        let r = ok(&mut s, "queue.per-ip.add", json!({"target": "10.2.0.0/24", "rate": "0/5M", "ipv6_mask": 128}));
        assert_eq!(r["queue"], "pcq-upload-default/pcq-down-5M");
        let l = ok(&mut s, "queue.per-ip.list", json!({}));
        assert_eq!(l.as_array().unwrap().len(), 3);
        assert_eq!(l[0]["rate"], "10M/20M");
        assert_eq!(l[0]["classifier"], "src-address/dst-address");
        assert_eq!(l[0]["max_limit"], "1G/2G");
        assert_eq!(l[2]["rate"], "0/5M");
        // The plain list sees them as simple queues.
        let all = ok(&mut s, "queue.simple.list", json!({"origin": "fixed"}));
        assert_eq!(all["total"], 3);
        ok(&mut s, "queue.simple.remove", json!({"id": "clientes"}));
        assert_eq!(ok(&mut s, "queue.per-ip.list", json!({})).as_array().unwrap().len(), 2);
    }

    #[test]
    fn bad_values_are_refused() {
        let mut s = Session::virtual_lab();
        for p in [
            json!({"rate": "10M"}),
            json!({"target": "10.0.0.0/16"}),
            json!({"target": "10.0.0.0/16", "rate": "0/0"}),
            json!({"target": "ether2", "rate": "1M"}),
            json!({"target": "10.0.0.0/16", "rate": "1M", "ipv6_mask": 8}),
            json!({"target": "10.0.0.0/16", "rate": "fast"}),
            json!({"target": "10.0.0.0/16", "rate": "1M", "max_limit": "x"}),
        ] {
            let err = s.execute("queue.per-ip.add", &p).unwrap_err();
            assert!(matches!(err, EngineError::BadParam { .. }), "{p}: {err}");
        }
        assert!(s.store().candidate().queue.simple.is_empty());
        assert!(s.store().candidate().queue.types.is_empty());
    }
}
