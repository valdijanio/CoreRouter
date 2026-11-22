//! `/queue type` (G4.9, RouterOS v7): what a queue does with the traffic
//! that waits. The built-in types (RouterOS's, plus `fq-codel-default` and
//! `cake-default`) always exist; changing one stores a copy, and they
//! cannot be removed.

use corerouter_model::ItemId;
use corerouter_model::queue::{
    Classifier, Kind, MAX_COMMENT, MAX_TYPES, QueueType, name_ok, parse_rate, parse_time_ms,
    rate_text, time_text,
};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, opt_text, opt_u32};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!("queue.type.add", "Add Queue Type", [], None,
        "{name: string, kind: pfifo|bfifo|pcq|fq-codel|cake, pfifo_limit?: int 1..100000 (packets, default 50), bfifo_limit?: int 1500..100000000 (bytes, default 15000), pcq_rate?: rate (each sub-stream, bits/s; 0 = share the queue), pcq_classifier?: src-address|dst-address (what makes a sub-stream; upload: src, download: dst), pcq_limit?: int 1..100000 (KiB per sub-stream, default 50), pcq_total_limit?: int 1..10000000 (KiB of all, default 2000), pcq_src_address_mask?: int 0..32, pcq_dst_address_mask?: int 0..32, pcq_src_address6_mask?: int 0..128, pcq_dst_address6_mask?: int 0..128 (64: one sub-stream per /64), pcq_burst_rate?: rate, pcq_burst_threshold?: rate, pcq_burst_time?: time (default 10s), fq_codel_target?: time (default 5ms), fq_codel_interval?: time (default 100ms), fq_codel_limit?: int 1..1000000 (packets, default 10240), fq_codel_ecn?: bool (mark instead of drop, default yes), cake_rtt?: time (default 100ms: target = rtt/20), comment?: string} → {id, name, warnings}",
        always, add),
    cmd!("queue.type.set", "Set Queue Type", [], None,
        "{id: *hex | name, name?: string, kind?: pfifo|bfifo|pcq|fq-codel|cake, pfifo_limit?: int, bfifo_limit?: int, pcq_rate?: rate, pcq_classifier?: src-address|dst-address, pcq_limit?: int, pcq_total_limit?: int, pcq_src_address_mask?: int, pcq_dst_address_mask?: int, pcq_src_address6_mask?: int, pcq_dst_address6_mask?: int, pcq_burst_rate?: rate, pcq_burst_threshold?: rate, pcq_burst_time?: time, fq_codel_target?: time, fq_codel_interval?: time, fq_codel_limit?: int, fq_codel_ecn?: bool, cake_rtt?: time, comment?: string} → {id, name, warnings}",
        always, set),
    cmd!("queue.type.remove", "Remove Queue Type", [], None,
        "{id: *hex | name} → {id, name}", always, remove),
    cmd!(query "queue.type.preview", "Queue Type Preview", [], None,
        "{id?: *hex | name, name?: string, kind?: string, pfifo_limit?: string, bfifo_limit?: string, pcq_rate?: string, pcq_classifier?: string, pcq_dst_address6_mask?: string, fq_codel_target?: string, fq_codel_interval?: string, fq_codel_ecn?: bool, cake_rtt?: string, comment?: string} → {computed: [{label, value}], checks: [{level, check, message, param}], commands: [{command, params}]}",
        always, preview),
    cmd!(query "queue.type.list", "Queue Types", [], None,
        "{} → [{id, name, kind, builtin, default (built in), pfifo_limit?, bfifo_limit?, pcq_rate?, pcq_classifier?, pcq_limit?, pcq_total_limit?, pcq_src_address_mask?, pcq_dst_address_mask?, pcq_src_address6_mask?, pcq_dst_address6_mask?, pcq_burst_rate?, pcq_burst_threshold?, pcq_burst_time?, fq_codel_target?, fq_codel_interval?, fq_codel_limit?, fq_codel_ecn?, cake_rtt?, comment?, used_by (simple queues and PPP profiles)}]",
        always, list),
];

fn ranged(p: &Value, key: &str, lo: u32, hi: u32) -> Result<Option<u32>> {
    match opt_u32(p, key)? {
        Some(v) if !(lo..=hi).contains(&v) => Err(EngineError::bad(key, format!("{lo}..={hi}"))),
        v => Ok(v),
    }
}

fn mask(p: &Value, key: &str, hi: u32) -> Result<Option<u8>> {
    Ok(ranged(p, key, 0, hi)?.and_then(|v| u8::try_from(v).ok()))
}

fn rate(p: &Value, key: &str) -> Result<Option<u64>> {
    opt_str(p, key)?
        .map(|t| parse_rate(t).map_err(|e| EngineError::bad(key, e.to_string())))
        .transpose()
}

fn time(p: &Value, key: &str, lo: u32, hi: u32) -> Result<Option<u32>> {
    let Some(t) = opt_str(p, key)? else {
        return Ok(None);
    };
    let ms = parse_time_ms(t).map_err(|e| EngineError::bad(key, e.to_string()))?;
    if !(lo..=hi).contains(&ms) {
        return Err(EngineError::bad(key, format!("{}..={}", time_text(lo), time_text(hi))));
    }
    Ok(Some(ms))
}

fn apply(t: &mut QueueType, p: &Value) -> Result<()> {
    if let Some(n) = opt_str(p, "name")? {
        let n = n.trim();
        if !name_ok(n) {
            return Err(EngineError::bad("name", "1..64 characters, without '/', ',' or '\"'"));
        }
        t.name = n.to_owned();
    }
    if let Some(k) = opt_str(p, "kind")? {
        t.kind = Kind::parse(k).ok_or_else(|| {
            EngineError::bad("kind", "pfifo, bfifo, pcq, fq-codel or cake (red, sfq and codel: use fq-codel)")
        })?;
    }
    if let Some(v) = ranged(p, "pfifo_limit", 1, 100_000)? {
        t.pfifo_limit = v;
    }
    if let Some(v) = ranged(p, "bfifo_limit", 1500, 100_000_000)? {
        t.bfifo_limit = v;
    }
    if let Some(v) = rate(p, "pcq_rate")? {
        t.pcq_rate = v;
    }
    if let Some(c) = opt_str(p, "pcq_classifier")? {
        t.pcq_classifier = Classifier::parse(c).ok_or_else(|| {
            EngineError::bad("pcq_classifier", "src-address or dst-address (the shaper keys sub-streams by address)")
        })?;
    }
    if let Some(v) = ranged(p, "pcq_limit", 1, 100_000)? {
        t.pcq_limit = v;
    }
    if let Some(v) = ranged(p, "pcq_total_limit", 1, 10_000_000)? {
        t.pcq_total_limit = v;
    }
    if let Some(v) = mask(p, "pcq_src_address_mask", 32)? {
        t.pcq_src_address_mask = v;
    }
    if let Some(v) = mask(p, "pcq_dst_address_mask", 32)? {
        t.pcq_dst_address_mask = v;
    }
    if let Some(v) = mask(p, "pcq_src_address6_mask", 128)? {
        t.pcq_src_address6_mask = v;
    }
    if let Some(v) = mask(p, "pcq_dst_address6_mask", 128)? {
        t.pcq_dst_address6_mask = v;
    }
    if let Some(v) = rate(p, "pcq_burst_rate")? {
        t.pcq_burst_rate = v;
    }
    if let Some(v) = rate(p, "pcq_burst_threshold")? {
        t.pcq_burst_threshold = v;
    }
    if let Some(v) = time(p, "pcq_burst_time", 0, 3_600_000)? {
        t.pcq_burst_time = v;
    }
    if let Some(v) = time(p, "fq_codel_target", 1, 1000)? {
        t.fq_codel_target = v;
    }
    if let Some(v) = time(p, "fq_codel_interval", 1, 10_000)? {
        t.fq_codel_interval = v;
    }
    if let Some(v) = ranged(p, "fq_codel_limit", 1, 1_000_000)? {
        t.fq_codel_limit = v;
    }
    if let Some(v) = opt_bool(p, "fq_codel_ecn")? {
        t.fq_codel_ecn = v;
    }
    if let Some(v) = time(p, "cake_rtt", 1, 10_000)? {
        t.cake_rtt = v;
    }
    if let Some(c) = opt_text(p, "comment", MAX_COMMENT)? {
        t.comment = c;
    }
    if t.kind == Kind::Pcq && t.pcq_burst_rate != 0 && t.pcq_burst_rate <= t.pcq_rate {
        return Err(EngineError::bad("pcq_burst_rate", "must be above pcq_rate"));
    }
    if t.fq_codel_target >= t.fq_codel_interval {
        return Err(EngineError::bad("fq_codel_target", "must be below fq_codel_interval (RFC 8289 §4.3: 5–10% of it)"));
    }
    Ok(())
}

fn warnings(t: &QueueType) -> Vec<String> {
    let mut w = Vec::new();
    match t.kind {
        Kind::Pfifo if t.pfifo_limit < 50 => w.push(format!(
            "pfifo-limit {}: a short FIFO drops TCP bursts above a few Mbit/s; fq-codel keeps the delay low without that",
            t.pfifo_limit
        )),
        Kind::Pcq if t.pcq_rate == 0 => w.push("pcq-rate 0: the sub-streams share the queue's max-limit".into()),
        Kind::Pcq if t.pcq_classifier == Classifier::SrcAddress && t.name.contains("down") => {
            w.push("src-address classifies by the sender: for download use dst-address".into())
        }
        _ => {}
    }
    w
}

/// The type `p["id"]` names (stored or built-in).
fn named(s: &Session, p: &Value) -> Result<QueueType> {
    let raw = opt_str(p, "id")?.ok_or_else(|| EngineError::bad("id", "is required"))?.trim();
    let q = &s.store().candidate().queue;
    let found = if raw.starts_with('*') {
        let id: ItemId = raw.parse().map_err(|e| EngineError::bad("id", format!("{e}")))?;
        q.all_types().into_iter().find(|t| t.id == id)
    } else {
        q.queue_type(raw)
    };
    found.ok_or_else(|| {
        let shown: String = raw.chars().take(64).collect();
        EngineError::bad("id", format!("no queue type '{shown}'"))
    })
}

/// Who uses type `name`: simple queues and PPP profiles.
fn users(s: &Session, name: &str) -> Vec<String> {
    let cfg = s.store().candidate();
    cfg.queue
        .type_users(name)
        .into_iter()
        .map(|q| format!("queue {q}"))
        .chain(
            cfg.ppp
                .profiles
                .iter()
                .filter(|p| p.queue_type.as_deref() == Some(name))
                .map(|p| format!("ppp profile {}", p.name)),
        )
        .collect()
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let name = opt_str(p, "name")?.ok_or_else(|| EngineError::bad("name", "is required"))?.trim().to_owned();
    let kind = opt_str(p, "kind")?.ok_or_else(|| EngineError::bad("kind", "is required"))?;
    let kind = Kind::parse(kind).ok_or_else(|| EngineError::bad("kind", "pfifo, bfifo, pcq, fq-codel or cake"))?;
    let q = &s.store().candidate().queue;
    if q.queue_type(&name).is_some() {
        return Err(EngineError::bad("name", format!("queue type '{name}' exists")));
    }
    if q.types.len() >= MAX_TYPES {
        return Err(EngineError::bad("name", "too many queue types"));
    }
    let mut t = QueueType::new(&name, kind);
    apply(&mut t, p)?;
    let w = warnings(&t);
    let q = &mut s.store_mut().candidate_mut().queue;
    t.id = q.next_id();
    let out = json!({"id": t.id, "name": t.name, "warnings": w});
    q.types.push(t);
    Ok(out)
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let mut t = named(s, p)?;
    let old = t.name.clone();
    apply(&mut t, p)?;
    if t.name != old {
        if QueueType::is_builtin_name(&old) {
            return Err(EngineError::bad("name", format!("'{old}' is built in and keeps its name")));
        }
        if s.store().candidate().queue.queue_type(&t.name).is_some() {
            return Err(EngineError::bad("name", format!("queue type '{}' exists", t.name)));
        }
        let used = users(s, &old);
        if !used.is_empty() {
            return Err(EngineError::bad("name", format!("{} use it by name: change them first", used.into_iter().take(5).collect::<Vec<_>>().join(", "))));
        }
    }
    let w = warnings(&t);
    let out = json!({"id": t.id, "name": t.name, "warnings": w});
    let q = &mut s.store_mut().candidate_mut().queue;
    if let Some(b) = QueueType::builtin(&t.name) {
        // A built-in back to what it ships with needs no copy; an edited
        // one is stored without the built-in id (ids of stored items stay
        // below the counter).
        q.types.retain(|x| x.name != t.name);
        t.id = b.id;
        if b != t {
            t.id = ItemId(0);
            q.types.push(t);
        }
        return Ok(out);
    }
    match q.types.iter_mut().find(|x| x.name == old) {
        Some(slot) => *slot = t,
        None => q.types.push(t),
    }
    Ok(out)
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let t = named(s, p)?;
    if QueueType::is_builtin_name(&t.name) {
        return Err(EngineError::bad("id", format!("'{}' is built in and cannot be removed", t.name)));
    }
    let used = users(s, &t.name);
    if !used.is_empty() {
        let n = used.len();
        let first: Vec<String> = used.into_iter().take(5).collect();
        return Err(EngineError::bad("id", format!("in use by {n}: {}", first.join(", "))));
    }
    s.store_mut().candidate_mut().queue.types.retain(|x| x.name != t.name);
    Ok(json!({"id": t.id, "name": t.name}))
}

/// The parameters of `t`'s kind, as the list shows them.
pub(super) fn kind_fields(t: &QueueType) -> Vec<(&'static str, Value)> {
    match t.kind {
        Kind::Pfifo => vec![("pfifo_limit", json!(t.pfifo_limit))],
        Kind::Bfifo => vec![("bfifo_limit", json!(t.bfifo_limit))],
        Kind::Pcq => vec![
            ("pcq_rate", json!(rate_text(t.pcq_rate))),
            ("pcq_classifier", json!(t.pcq_classifier.as_str())),
            ("pcq_limit", json!(t.pcq_limit)),
            ("pcq_total_limit", json!(t.pcq_total_limit)),
            ("pcq_src_address_mask", json!(t.pcq_src_address_mask)),
            ("pcq_dst_address_mask", json!(t.pcq_dst_address_mask)),
            ("pcq_src_address6_mask", json!(t.pcq_src_address6_mask)),
            ("pcq_dst_address6_mask", json!(t.pcq_dst_address6_mask)),
            ("pcq_burst_rate", json!(rate_text(t.pcq_burst_rate))),
            ("pcq_burst_threshold", json!(rate_text(t.pcq_burst_threshold))),
            ("pcq_burst_time", json!(time_text(t.pcq_burst_time))),
        ],
        Kind::FqCodel => vec![
            ("fq_codel_target", json!(time_text(t.fq_codel_target))),
            ("fq_codel_interval", json!(time_text(t.fq_codel_interval))),
            ("fq_codel_limit", json!(t.fq_codel_limit)),
            ("fq_codel_ecn", json!(t.fq_codel_ecn)),
        ],
        Kind::Cake => vec![("cake_rtt", json!(time_text(t.cake_rtt)))],
    }
}

/// The modal's preview: numbers typed as text become numbers, emptied
/// fields are left out (the kind's defaults stay).
fn preview(s: &mut Session, p: &Value) -> Result<Value> {
    let mut q = p.clone();
    if let Some(o) = q.as_object_mut() {
        let empty: Vec<String> = o
            .iter()
            .filter(|(k, v)| *k != "comment" && v.as_str().is_some_and(|t| t.trim().is_empty()))
            .map(|(k, _)| k.clone())
            .collect();
        for k in empty {
            o.remove(&k);
        }
        for k in ["pfifo_limit", "bfifo_limit", "pcq_limit", "pcq_total_limit", "fq_codel_limit", "pcq_src_address_mask", "pcq_dst_address_mask", "pcq_src_address6_mask", "pcq_dst_address6_mask"] {
            if let Some(n) = o.get(k).and_then(Value::as_str).and_then(|t| t.trim().parse::<u64>().ok()) {
                o.insert(k.into(), json!(n));
            }
        }
    }
    super::ppp_common::preview(s, &q, ("queue.type.add", "queue.type.set"), (add, set), |s, v| {
        let name = v.get("name").and_then(Value::as_str).unwrap_or_default();
        s.store()
            .candidate()
            .queue
            .queue_type(name)
            .map(|t| kind_fields(&t).into_iter().map(|(k, v)| json!({"label": k, "value": v.as_str().map(str::to_owned).unwrap_or_else(|| v.to_string())})).collect())
            .unwrap_or_default()
    })
}

fn list(s: &mut Session, _: &Value) -> Result<Value> {
    let rows: Vec<Value> = s
        .store()
        .candidate()
        .queue
        .all_types()
        .into_iter()
        .map(|t| {
            let builtin = QueueType::is_builtin_name(&t.name);
            let mut v = json!({
                "id": t.id,
                "name": t.name,
                "kind": t.kind.as_str(),
                "builtin": builtin,
                "default": builtin,
                "used_by": users(s, &t.name),
            });
            if let Some(o) = v.as_object_mut() {
                for (k, val) in kind_fields(&t) {
                    o.insert(k.into(), val);
                }
                if !t.comment.is_empty() {
                    o.insert("comment".into(), json!(t.comment));
                }
            }
            v
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
    fn builtins_and_crud() {
        let mut s = Session::virtual_lab();
        let l = ok(&mut s, "queue.type.list", json!({}));
        let n0 = l.as_array().unwrap().len();
        assert!(n0 >= 7);
        let small = l.as_array().unwrap().iter().find(|r| r["name"] == "default-small").unwrap();
        assert_eq!(small["pfifo_limit"], 10);
        assert_eq!(small["builtin"], true);
        let r = ok(&mut s, "queue.type.add", json!({"name": "pcq-down-20M", "kind": "pcq", "pcq_rate": "20M", "pcq_classifier": "dst-address", "pcq_dst_address6_mask": 64}));
        assert!(r["warnings"].as_array().unwrap().is_empty(), "{r}");
        let r = ok(&mut s, "queue.type.add", json!({"name": "tiny", "kind": "pfifo", "pfifo_limit": 5}));
        assert!(r["warnings"][0].as_str().unwrap().contains("fq-codel"), "{r}");
        ok(&mut s, "queue.type.set", json!({"id": "tiny", "kind": "fq-codel", "fq_codel_target": "10ms", "fq_codel_ecn": false}));
        let l = ok(&mut s, "queue.type.list", json!({}));
        let tiny = l.as_array().unwrap().iter().find(|r| r["name"] == "tiny").unwrap();
        assert_eq!((tiny["kind"].as_str(), tiny["fq_codel_target"].as_str(), tiny["fq_codel_ecn"].as_bool()), (Some("fq-codel"), Some("10ms"), Some(false)));
        // In use: no removal, no rename.
        ok(&mut s, "queue.simple.add", json!({"name": "q", "target": "10.0.0.0/24", "queue": "tiny/pcq-down-20M", "max_limit": "10M/100M"}));
        ok(&mut s, "ppp.profile.add", json!({"name": "plano", "queue_type": "tiny"}));
        let err = s.execute("queue.type.remove", &json!({"id": "tiny"})).unwrap_err();
        assert!(err.to_string().contains("queue q") && err.to_string().contains("ppp profile plano"), "{err}");
        assert!(s.execute("queue.type.set", &json!({"id": "tiny", "name": "small"})).is_err());
        ok(&mut s, "queue.simple.remove", json!({"id": "q"}));
        ok(&mut s, "ppp.profile.remove", json!({"id": "plano"}));
        ok(&mut s, "queue.type.remove", json!({"id": "tiny"}));
        // Built-ins: an edit is a copy without the built-in's id; back to
        // the original, no copy.
        ok(&mut s, "queue.type.set", json!({"id": "default-small", "pfifo_limit": 100}));
        let stored = &s.store().running().queue.types;
        assert_eq!(stored.iter().find(|t| t.name == "default-small").map(|t| t.id), Some(ItemId(0)));
        ok(&mut s, "queue.type.set", json!({"id": "default-small", "pfifo_limit": 10}));
        assert!(s.store().running().queue.types.iter().all(|t| t.name != "default-small"));
        assert!(s.execute("queue.type.remove", &json!({"id": "default"})).is_err());
        assert!(s.execute("queue.type.set", &json!({"id": "default", "name": "x"})).is_err());
    }

    #[test]
    fn bad_values_are_refused() {
        let mut s = Session::virtual_lab();
        for p in [
            json!({"name": "a"}),
            json!({"name": "a", "kind": "sfq"}),
            json!({"name": "default", "kind": "pfifo"}),
            json!({"name": "a/b", "kind": "pfifo"}),
            json!({"name": "a", "kind": "pfifo", "pfifo_limit": 0}),
            json!({"name": "a", "kind": "bfifo", "bfifo_limit": 10}),
            json!({"name": "a", "kind": "pcq", "pcq_rate": "x"}),
            json!({"name": "a", "kind": "pcq", "pcq_classifier": "src-port"}),
            json!({"name": "a", "kind": "pcq", "pcq_dst_address_mask": 33}),
            json!({"name": "a", "kind": "pcq", "pcq_rate": "10M", "pcq_burst_rate": "5M"}),
            json!({"name": "a", "kind": "fq-codel", "fq_codel_target": "200ms"}),
            json!({"name": "a", "kind": "cake", "cake_rtt": "0ms"}),
        ] {
            let err = s.execute("queue.type.add", &p).unwrap_err();
            assert!(matches!(err, EngineError::BadParam { .. }), "{p}: {err}");
        }
        assert!(s.store().candidate().queue.types.is_empty());
    }

    #[test]
    fn rollback() {
        let mut s = Session::virtual_lab();
        s.execute("config.mode.set", &json!({"mode": "transactional"})).unwrap();
        ok(&mut s, "queue.type.add", json!({"name": "x", "kind": "cake"}));
        s.execute("config.discard", &json!({})).unwrap();
        assert!(s.store().candidate().queue.types.is_empty());
    }
}
