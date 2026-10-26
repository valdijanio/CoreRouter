//! `/queue simple` (G4.9, RouterOS v7): bandwidth per target. Every pair
//! is `upload/download` from the target's side. Order matters (first
//! match); dynamic queues (sessions, DHCP leases) come first and win on
//! their own addresses. The list shows both, with the origin of each
//! dynamic queue and the precedence warnings (`crate::queue`).

use corerouter_model::ItemId;
use corerouter_model::queue::{
    Kind, MAX_COMMENT, MAX_SIMPLE, Pair, Rates, SimpleQueue, Target, TypeNames, name_ok,
    parse_ratios, parse_targets, parse_times, rate_text, ratios_text, targets_text, times_text,
};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, opt_text, opt_u32};
use super::{CommandSpec, always};
use crate::queue::{Origin, Plan, Queue, plan_with_sessions};
use crate::{EngineError, Result, Session};

#[cfg(test)]
const FIELDS: &str = "max_limit?: rates (upload/download from the target, bits/s: 10M/50M; 0 = no limit), limit_at?: rates (guaranteed rate, kept for the queue tree), burst_limit?: rates (rate while bursting; above max_limit), burst_threshold?: rates (bursting is allowed while the average over burst_time is under it; 0 = max_limit), burst_time?: times (window of the average: 8s/8s), bucket_size?: ratios (bucket as a share of the rate: 0.1 = 100 ms, the default), priority?: string (1..8/1..8, 8 lowest), queue?: string (/queue type names, upload/download; default default-small/default-small), disabled?: bool, comment?: string";

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!("queue.simple.add", "Add Simple Queue", [], None,
        "{name?: string (default queue<N>), target: string | [string] (addresses, prefixes or one interface: 10.0.0.5,10.0.1.0/24, 2001:db8::/56, ether2), max_limit?: rates (upload/download from the target, bits/s: 10M/50M; 0 = no limit), limit_at?: rates (guaranteed rate, kept for the queue tree), burst_limit?: rates (rate while bursting; above max_limit), burst_threshold?: rates (bursting is allowed while the average over burst_time is under it; 0 = max_limit), burst_time?: times (window of the average: 8s/8s), bucket_size?: ratios (bucket as a share of the rate: 0.1 = 100 ms, the default), priority?: string (1..8/1..8, 8 lowest), queue?: string (/queue type names, upload/download; default default-small/default-small), disabled?: bool, comment?: string, place_before?: *hex | name (a fixed queue: the new one goes above it; default: the end)} → {id, name, warnings}",
        always, add),
    cmd!("queue.simple.set", "Set Simple Queue", [], None,
        "{id: *hex | name, name?: string, target?: string | [string], max_limit?: rates (upload/download from the target, bits/s: 10M/50M; 0 = no limit), limit_at?: rates (guaranteed rate, kept for the queue tree), burst_limit?: rates (rate while bursting; above max_limit), burst_threshold?: rates (bursting is allowed while the average over burst_time is under it; 0 = max_limit), burst_time?: times (window of the average: 8s/8s), bucket_size?: ratios (bucket as a share of the rate: 0.1 = 100 ms, the default), priority?: string (1..8/1..8, 8 lowest), queue?: string (/queue type names, upload/download; default default-small/default-small), disabled?: bool, comment?: string} → {id, name, warnings}",
        always, set),
    cmd!("queue.simple.remove", "Remove Simple Queue", [], None,
        "{id: *hex | name | [*hex | name]} → {removed}", always, remove),
    cmd!("queue.simple.enable", "Enable Simple Queue", [], None,
        "{id: *hex | name | [*hex | name]} → {changed}", always, enable),
    cmd!("queue.simple.disable", "Disable Simple Queue", [], None,
        "{id: *hex | name | [*hex | name]} → {changed}", always, disable),
    cmd!("queue.simple.move", "Move Simple Queue", [], None,
        "{id: *hex | name, destination?: *hex | name (it goes above this one; none: to the end)} → {id, position}",
        always, move_to),
    cmd!(query "queue.simple.list", "Simple Queues", [], None,
        "{find?: string (in name, target or comment), origin?: fixed|dynamic|pppoe|ipoe|dhcp-lease|dhcp-network, limit?: int 1..100000 (default 10000)} → {total, running (a data plane shapes), note?, rows: [{id, name, dynamic, disabled, origin, target, max_limit, limit_at, burst_limit, burst_threshold, burst_time, bucket_size, priority, queue, download_mode, comment?, warnings: [string], rate_bps: [up, down], bytes: [up, down], packets: [up, down], dropped: [up, down], queued_us: [up, down] (wait of a packet entering now), pcq_queues}]}",
        always, list),
];

// The two docs above repeat FIELDS (a `cmd!` needs a literal); this keeps
// them from drifting.
#[cfg(test)]
#[test]
fn docs_carry_the_fields() {
    for c in COMMANDS.iter().take(2) {
        assert!(c.params.contains(FIELDS), "{}", c.id);
    }
}

fn opt_pair<T>(p: &Value, key: &str, parse: impl Fn(&str) -> std::result::Result<T, corerouter_model::ParseError>) -> Result<Option<T>> {
    opt_str(p, key)?
        .map(|t| parse(t).map_err(|e| EngineError::bad(key, e.to_string())))
        .transpose()
}

fn opt_rates(p: &Value, key: &str) -> Result<Option<Rates>> {
    opt_pair(p, key, |t| t.parse::<Rates>())
}

/// `target` as a string (`a,b`) or a list.
pub(super) fn opt_targets(s: &Session, p: &Value) -> Result<Option<Vec<Target>>> {
    let text = match p.get("target") {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(t)) => t.clone(),
        Some(Value::Array(a)) if a.len() <= corerouter_model::queue::MAX_TARGETS => a
            .iter()
            .map(|v| v.as_str().map(str::to_owned).ok_or_else(|| EngineError::bad("target", "a list of addresses, prefixes or interfaces")))
            .collect::<Result<Vec<_>>>()?
            .join(","),
        Some(_) => return Err(EngineError::bad("target", "a string or a list (at most 64)")),
    };
    let t = parse_targets(&text).map_err(|e| EngineError::bad("target", e.to_string()))?;
    let ifaces: Vec<&Target> = t.iter().filter(|t| matches!(t, Target::Interface(_))).collect();
    if ifaces.len() > 1 {
        return Err(EngineError::bad("target", "at most one interface"));
    }
    for i in ifaces {
        if let Target::Interface(name) = i
            && !s.store().candidate().interfaces.contains_key(name)
        {
            return Err(EngineError::bad("target", format!("no interface '{name}'")));
        }
    }
    Ok(Some(t))
}

fn apply(s: &Session, q: &mut SimpleQueue, p: &Value) -> Result<()> {
    if let Some(n) = opt_str(p, "name")? {
        let n = n.trim();
        if !name_ok(n) {
            return Err(EngineError::bad("name", "1..64 characters, without '/', ',' or '\"'"));
        }
        q.name = n.to_owned();
    }
    if let Some(t) = opt_targets(s, p)? {
        q.target = t;
    }
    if let Some(v) = opt_rates(p, "max_limit")? {
        q.max_limit = v;
    }
    if let Some(v) = opt_rates(p, "limit_at")? {
        q.limit_at = v;
    }
    if let Some(v) = opt_rates(p, "burst_limit")? {
        q.burst_limit = v;
    }
    if let Some(v) = opt_rates(p, "burst_threshold")? {
        q.burst_threshold = v;
    }
    if let Some(v) = opt_pair(p, "burst_time", parse_times)? {
        q.burst_time = v;
    }
    if let Some(v) = opt_pair(p, "bucket_size", parse_ratios)? {
        q.bucket_size = v;
    }
    if let Some(v) = opt_pair(p, "priority", |t| t.parse::<Pair<u8>>())? {
        q.priority = v;
    }
    if let Some(v) = opt_pair(p, "queue", |t| t.parse::<TypeNames>())? {
        let queues = &s.store().candidate().queue;
        for n in [&v.upload, &v.download] {
            if queues.queue_type(n).is_none() {
                return Err(EngineError::bad("queue", format!("no /queue type '{n}' (queue.type.add)")));
            }
        }
        q.queue = v;
    }
    if let Some(d) = opt_bool(p, "disabled")? {
        q.disabled = d;
    }
    if let Some(c) = opt_text(p, "comment", MAX_COMMENT)? {
        q.comment = c;
    }
    check(q)
}

/// RouterOS's own refusals, per direction.
fn check(q: &SimpleQueue) -> Result<()> {
    for (dir, down) in [("upload", false), ("download", true)] {
        let (max, at, burst) = (q.max_limit.get(down), q.limit_at.get(down), q.burst_limit.get(down));
        if max != 0 && at > max {
            return Err(EngineError::bad("limit_at", format!("{dir} limit-at {} is above its max-limit {}", rate_text(at), rate_text(max))));
        }
        if burst != 0 && max == 0 {
            return Err(EngineError::bad("burst_limit", format!("{dir} burst-limit needs a max-limit")));
        }
        if burst != 0 && burst <= max {
            return Err(EngineError::bad("burst_limit", format!("{dir} burst-limit {} must be above the max-limit {}", rate_text(burst), rate_text(max))));
        }
    }
    Ok(())
}

pub(super) fn warnings(s: &Session, q: &SimpleQueue) -> Vec<String> {
    let mut w = Vec::new();
    if q.max_limit == Rates::default() {
        w.push("max-limit 0/0: the queue only counts, it limits nothing".into());
    }
    if q.limit_at != Rates::default() || q.priority != Pair::both(corerouter_model::queue::DEFAULT_PRIORITY) {
        w.push("limit-at and priority are kept, but a queue without children is shaped at its max-limit (the queue tree is G4.9e)".into());
    }
    for down in [false, true] {
        let (burst, thr) = (q.burst_limit.get(down), q.burst_threshold.get(down));
        if burst != 0 && thr > burst {
            w.push(format!("burst-threshold {} above burst-limit {}: the burst never stops", rate_text(thr), rate_text(burst)));
        }
    }
    let queues = &s.store().candidate().queue;
    let pcq = [&q.queue.upload, &q.queue.download].iter().any(|n| queues.queue_type(n).is_some_and(|t| t.kind == Kind::Pcq));
    if pcq && q.target.iter().all(|t| matches!(t, Target::Prefix(n) if n.prefix_len() == n.max_prefix_len())) {
        w.push("a pcq type on single addresses works as a plain queue: give it a prefix".into());
    }
    if let Some(t) = q.target.iter().find(|t| matches!(t, Target::Interface(_))) {
        w.push(format!("{t}: every address through it shares this queue, and address targets match first"));
    }
    w
}

/// The fixed queue `raw` names: `*hex` or a name.
pub(super) fn index_of(s: &Session, raw: &str) -> Result<usize> {
    let raw = raw.trim();
    let simple = &s.store().candidate().queue.simple;
    let found = if raw.starts_with('*') {
        let id: ItemId = raw.parse().map_err(|e| EngineError::bad("id", format!("{e}")))?;
        simple.iter().position(|q| q.id == id)
    } else {
        simple.iter().position(|q| q.name == raw)
    };
    found.ok_or_else(|| {
        let shown: String = raw.chars().take(64).collect();
        if raw.starts_with("ppp:") || raw.starts_with("dhcp:") || raw.starts_with('<') || raw.starts_with("dhcp-ds") {
            EngineError::bad("id", format!("'{shown}' is a dynamic queue: change it where it comes from (ppp profile, RADIUS, dhcp-server lease or network)"))
        } else {
            EngineError::bad("id", format!("no simple queue '{shown}'"))
        }
    })
}

fn ids(p: &Value) -> Result<Vec<String>> {
    match p.get("id") {
        Some(Value::String(t)) => Ok(vec![t.clone()]),
        Some(Value::Array(a)) if !a.is_empty() && a.len() <= MAX_SIMPLE => a
            .iter()
            .map(|v| v.as_str().map(str::to_owned).ok_or_else(|| EngineError::bad("id", "a list of ids or names")))
            .collect(),
        None | Some(Value::Null) => Err(EngineError::bad("id", "is required")),
        Some(_) => Err(EngineError::bad("id", "an id, a name or a list of them")),
    }
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let queues = &s.store().candidate().queue;
    if queues.simple.len() >= MAX_SIMPLE {
        return Err(EngineError::bad("name", format!("at most {MAX_SIMPLE} simple queues")));
    }
    if p.get("target").is_none() {
        return Err(EngineError::bad("target", "is required"));
    }
    let before = opt_str(p, "place_before")?.map(|b| index_of(s, b)).transpose()?;
    let mut q = SimpleQueue::new(ItemId(0), queues.free_name(), Vec::new());
    apply(s, &mut q, p)?;
    if s.store().candidate().queue.simple_by_name(&q.name).is_some() {
        return Err(EngineError::bad("name", format!("queue '{}' exists", q.name)));
    }
    let w = warnings(s, &q);
    let queues = &mut s.store_mut().candidate_mut().queue;
    q.id = queues.next_id();
    let out = json!({"id": q.id, "name": q.name});
    match before {
        Some(i) if i <= queues.simple.len() => {
            queues.simple.insert(i, q);
        }
        _ => queues.simple.push(q),
    }
    with_plan_warnings(s, out, w)
}

/// The command's warnings plus what the plan says of the queue now
/// (shadowed targets, overlaps with dynamic queues).
fn with_plan_warnings(s: &Session, mut out: Value, mut w: Vec<String>) -> Result<Value> {
    let id = out.get("id").and_then(Value::as_str).unwrap_or_default().to_owned();
    let plan = crate::queue::plan(s.store().candidate(), crate::queue::dhcp_dynamic(s));
    if let Some(i) = plan.queues.iter().position(|q| q.key == id) {
        w.extend(plan.warnings_of(i).iter().cloned());
    }
    if let Some(o) = out.as_object_mut() {
        o.insert("warnings".into(), json!(w));
    }
    Ok(out)
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let raw = opt_str(p, "id")?.ok_or_else(|| EngineError::bad("id", "is required"))?;
    let i = index_of(s, raw)?;
    let mut q = s.store().candidate().queue.simple.get(i).cloned().ok_or_else(|| EngineError::bad("id", "gone"))?;
    let old = q.name.clone();
    apply(s, &mut q, p)?;
    if q.name != old && s.store().candidate().queue.simple_by_name(&q.name).is_some() {
        return Err(EngineError::bad("name", format!("queue '{}' exists", q.name)));
    }
    let w = warnings(s, &q);
    let out = json!({"id": q.id, "name": q.name});
    if let Some(slot) = s.store_mut().candidate_mut().queue.simple.get_mut(i) {
        *slot = q;
    }
    with_plan_warnings(s, out, w)
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let mut idx: Vec<usize> = ids(p)?.iter().map(|r| index_of(s, r)).collect::<Result<_>>()?;
    idx.sort_unstable();
    idx.dedup();
    let simple = &mut s.store_mut().candidate_mut().queue.simple;
    for i in idx.iter().rev() {
        if *i < simple.len() {
            simple.remove(*i);
        }
    }
    Ok(json!({"removed": idx.len()}))
}

fn toggle(s: &mut Session, p: &Value, disabled: bool) -> Result<Value> {
    let idx: Vec<usize> = ids(p)?.iter().map(|r| index_of(s, r)).collect::<Result<_>>()?;
    let simple = &mut s.store_mut().candidate_mut().queue.simple;
    let mut changed = 0;
    for i in idx {
        if let Some(q) = simple.get_mut(i)
            && q.disabled != disabled
        {
            q.disabled = disabled;
            changed += 1;
        }
    }
    Ok(json!({"changed": changed}))
}

fn enable(s: &mut Session, p: &Value) -> Result<Value> {
    toggle(s, p, false)
}

fn disable(s: &mut Session, p: &Value) -> Result<Value> {
    toggle(s, p, true)
}

fn move_to(s: &mut Session, p: &Value) -> Result<Value> {
    let raw = opt_str(p, "id")?.ok_or_else(|| EngineError::bad("id", "is required"))?;
    let from = index_of(s, raw)?;
    let to = opt_str(p, "destination")?.map(|d| index_of(s, d)).transpose()?;
    let simple = &mut s.store_mut().candidate_mut().queue.simple;
    let Some(q) = simple.remove(from) else {
        return Err(EngineError::bad("id", "gone"));
    };
    let id = q.id;
    let at = match to {
        // The destination moved up by one when the queue left above it.
        Some(t) if t > from => t - 1,
        Some(t) => t,
        None => simple.len(),
    }
    .min(simple.len());
    simple.insert(at, q);
    Ok(json!({"id": id, "position": at}))
}

/// One list row.
pub(super) fn row(s: &Session, plan: &Plan, i: usize, q: &Queue) -> Value {
    let pair = |f: &dyn Fn(&crate::queue::Limit) -> String| format!("{}/{}", f(&q.upload), f(&q.download));
    let c = s.queue_counters(&q.key).unwrap_or_default();
    let mut v = json!({
        "id": q.key,
        "name": q.name,
        "dynamic": q.origin.dynamic(),
        "disabled": q.disabled,
        "origin": q.origin.as_str(),
        "target": targets_text(&q.targets),
        "max_limit": pair(&|l| rate_text(l.max_limit)),
        "limit_at": pair(&|l| rate_text(l.limit_at)),
        "burst_limit": pair(&|l| rate_text(l.burst_limit)),
        "burst_threshold": pair(&|l| rate_text(l.burst_threshold)),
        "burst_time": times_text(&Pair { upload: q.upload.burst_time_ms, download: q.download.burst_time_ms }),
        "bucket_size": ratios_text(&Pair { upload: q.upload.bucket_milli, download: q.download.bucket_milli }),
        "priority": pair(&|l| l.priority.to_string()),
        "queue": q.queue_names.to_string(),
        "download_mode": q.download_mode.as_str(),
        "warnings": plan.warnings_of(i),
        "rate_bps": c.rate_bps,
        "bytes": c.bytes,
        "packets": c.packets,
        "dropped": c.dropped,
        "queued_us": c.queued_us,
        "pcq_queues": c.pcq_queues,
    });
    if !q.comment.is_empty()
        && let Some(o) = v.as_object_mut()
    {
        o.insert("comment".into(), json!(q.comment));
    }
    v
}

/// A PPP session's row takes its byte counters and rates from the session
/// (the subscriber maps count them).
fn session_counters(row: &mut Value, a: &corerouter_model::ppp::ActiveSession) {
    if let Some(o) = row.as_object_mut() {
        o.insert("bytes".into(), json!([a.rx_bytes, a.tx_bytes]));
        o.insert("packets".into(), json!([a.rx_packets, a.tx_packets]));
        o.insert("rate_bps".into(), json!([a.rx_bps, a.tx_bps]));
        o.insert("queued_us".into(), json!([0, a.queue_us]));
        o.insert("dropped".into(), json!([0, a.drops]));
    }
}

fn list(s: &mut Session, p: &Value) -> Result<Value> {
    let needle = opt_text(p, "find", 128)?.map(|t| t.to_lowercase());
    let origin = opt_str(p, "origin")?
        .map(|t| match t.trim() {
            "dynamic" => Ok(None),
            t => Origin::parse(t).map(Some).ok_or_else(|| EngineError::bad("origin", "fixed, dynamic, pppoe, ipoe, dhcp-lease or dhcp-network")),
        })
        .transpose()?;
    let limit = opt_u32(p, "limit")?.unwrap_or(10_000);
    if !(1..=100_000).contains(&limit) {
        return Err(EngineError::bad("limit", "1..=100000"));
    }
    let want_sessions = match origin {
        None => true,
        Some(None) => true,
        Some(Some(o)) => o.session(),
    };
    // Only the page of sessions: 100 000 up would hold the lock for long.
    let sessions = match (want_sessions, s.ppp_backend()) {
        (true, Some(b)) => {
            let n = needle.clone();
            b.active_page(
                &move |a| a.rate_limit.is_some() && n.as_ref().is_none_or(|n| a.name.to_lowercase().contains(n) || a.address.is_some_and(|ip| ip.to_string().contains(n))),
                limit as usize,
            )
            .1
        }
        _ => Vec::new(),
    };
    let plan = plan_with_sessions(s, &sessions);
    let keep = |q: &Queue| {
        let o = match origin {
            None => true,
            Some(None) => q.origin.dynamic(),
            Some(Some(o)) => q.origin == o,
        };
        o && needle.as_ref().is_none_or(|n| {
            q.name.to_lowercase().contains(n) || targets_text(&q.targets).to_lowercase().contains(n) || q.comment.to_lowercase().contains(n)
        })
    };
    let picked: Vec<(usize, &Queue)> = plan.queues.iter().enumerate().filter(|(_, q)| keep(q)).collect();
    let total = picked.len();
    let rows: Vec<Value> = picked
        .into_iter()
        .take(limit as usize)
        .map(|(i, q)| {
            let mut r = row(s, &plan, i, q);
            if let Some(a) = q.key.strip_prefix("ppp:").and_then(|id| sessions.iter().find(|a| a.id == id)) {
                session_counters(&mut r, a);
            }
            r
        })
        .collect();
    let stats = s.ext::<crate::queue::QueueStats>();
    let mut out = json!({"total": total, "running": stats.is_some_and(|x| x.running), "rows": rows});
    if let Some(n) = stats.and_then(|x| x.note.clone())
        && let Some(o) = out.as_object_mut()
    {
        o.insert("note".into(), json!(n));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lab() -> Session {
        Session::virtual_lab()
    }

    fn ok(s: &mut Session, id: &str, p: Value) -> Value {
        s.execute(id, &p).unwrap_or_else(|e| panic!("{id} {p}: {e}"))
    }

    fn names(s: &mut Session) -> Vec<String> {
        s.store().running().queue.simple.iter().map(|q| q.name.clone()).collect()
    }

    #[test]
    fn add_set_move_enable_remove() {
        let mut s = lab();
        let r = ok(&mut s, "queue.simple.add", json!({"target": "10.0.0.0/16", "max_limit": "50M/100M"}));
        assert_eq!(r["name"], "queue1");
        let r = ok(&mut s, "queue.simple.add", json!({
            "name": "camera", "target": ["10.0.1.5", "2001:db8::/56"], "max_limit": "2M/4M",
            "burst_limit": "4M/8M", "burst_threshold": "1500k/3M", "burst_time": "8s", "bucket_size": "0.5/0.2",
            "queue": "default/fq-codel-default", "comment": "câmera"
        }));
        // Below the broad queue: it never matches (RouterOS first match).
        assert!(r["warnings"].to_string().contains("never matches"), "{r}");
        ok(&mut s, "queue.simple.move", json!({"id": "camera", "destination": "queue1"}));
        assert_eq!(names(&mut s), ["camera", "queue1"]);
        let l = ok(&mut s, "queue.simple.list", json!({}));
        let cam = &l["rows"][0];
        assert_eq!(cam["target"], "10.0.1.5,2001:db8::/56");
        assert_eq!(cam["burst_limit"], "4M/8M");
        assert_eq!(cam["burst_threshold"], "1500k/3M");
        assert_eq!(cam["burst_time"], "8s/8s");
        assert_eq!(cam["bucket_size"], "0.5/0.2");
        assert_eq!(cam["queue"], "default/fq-codel-default");
        assert_eq!(cam["origin"], "fixed");
        assert_eq!(cam["comment"], "câmera");
        assert!(cam["warnings"].as_array().unwrap().is_empty(), "{cam}");
        ok(&mut s, "queue.simple.set", json!({"id": "camera", "max_limit": "3M/6M", "name": "cam"}));
        ok(&mut s, "queue.simple.disable", json!({"id": ["cam", "queue1"]}));
        assert!(s.store().running().queue.simple.iter().all(|q| q.disabled));
        let r = ok(&mut s, "queue.simple.enable", json!({"id": "*1"}));
        assert_eq!(r["changed"], 1);
        ok(&mut s, "queue.simple.add", json!({"name": "top", "target": "ether2", "max_limit": "1G", "place_before": "cam"}));
        assert_eq!(names(&mut s), ["top", "cam", "queue1"]);
        ok(&mut s, "queue.simple.move", json!({"id": "top"}));
        assert_eq!(names(&mut s), ["cam", "queue1", "top"]);
        let r = ok(&mut s, "queue.simple.remove", json!({"id": ["cam", "top"]}));
        assert_eq!(r["removed"], 2);
        assert_eq!(names(&mut s), ["queue1"]);
        let l = ok(&mut s, "queue.simple.list", json!({"find": "10.0"}));
        assert_eq!(l["total"], 1);
    }

    #[test]
    fn bad_values_are_refused() {
        let mut s = lab();
        ok(&mut s, "queue.simple.add", json!({"name": "a", "target": "10.0.0.1"}));
        for p in [
            json!({}),
            json!({"target": ""}),
            json!({"target": "nosuchif0"}),
            json!({"target": "ether2,ether3"}),
            json!({"target": "10.0.0.2", "name": "a"}),
            json!({"target": "10.0.0.2", "name": "x/y"}),
            json!({"target": "10.0.0.2", "max_limit": "fast"}),
            json!({"target": "10.0.0.2", "max_limit": "10M", "limit_at": "20M"}),
            json!({"target": "10.0.0.2", "burst_limit": "20M"}),
            json!({"target": "10.0.0.2", "max_limit": "10M", "burst_limit": "5M"}),
            json!({"target": "10.0.0.2", "burst_time": "1h"}),
            json!({"target": "10.0.0.2", "bucket_size": "-1"}),
            json!({"target": "10.0.0.2", "priority": "9/1"}),
            json!({"target": "10.0.0.2", "queue": "nope"}),
            json!({"target": "10.0.0.2", "place_before": "nope"}),
            json!({"target": 7}),
        ] {
            let err = s.execute("queue.simple.add", &p).unwrap_err();
            assert!(matches!(err, EngineError::BadParam { .. }), "{p}: {err}");
        }
        for (id, p) in [
            ("queue.simple.set", json!({"id": "nope"})),
            ("queue.simple.set", json!({"id": "ppp:*1-5", "max_limit": "1M"})),
            ("queue.simple.remove", json!({"id": []})),
            ("queue.simple.move", json!({"id": "a", "destination": "zz"})),
            ("queue.simple.list", json!({"origin": "magic"})),
            ("queue.simple.list", json!({"limit": 0})),
        ] {
            let err = s.execute(id, &p).unwrap_err();
            assert!(matches!(err, EngineError::BadParam { .. }), "{id} {p}: {err}");
        }
        let err = s.execute("queue.simple.set", &json!({"id": "ppp:*1-5"})).unwrap_err();
        assert!(err.to_string().contains("dynamic queue"), "{err}");
        assert_eq!(s.store().running().queue.simple.len(), 1);
    }

    #[test]
    fn rollback_and_transactions() {
        let mut s = lab();
        s.execute("config.mode.set", &json!({"mode": "transactional"})).unwrap();
        ok(&mut s, "queue.simple.add", json!({"name": "t", "target": "10.9.0.0/24"}));
        s.execute("config.discard", &json!({})).unwrap();
        assert!(s.store().candidate().queue.simple.is_empty());
        s.execute("config.mode.set", &json!({"mode": "immediate"})).unwrap();
        ok(&mut s, "queue.simple.add", json!({"name": "t", "target": "10.9.0.0/24"}));
        let rev = s.store().history().last().map(|r| r.number).unwrap();
        ok(&mut s, "queue.simple.remove", json!({"id": "t"}));
        s.execute("config.rollback", &json!({"revision": rev})).unwrap();
        assert_eq!(s.store().running().queue.simple.len(), 1);
    }

    /// The `queue` service's round on a HAL without a shaper (the virtual
    /// lab): applied once, then the list says why nothing shapes.
    #[test]
    fn sync_without_a_shaper_says_why() {
        let mut s = lab();
        assert!(s.queue_sync(), "the first round applies (an empty plan)");
        assert!(!s.queue_sync(), "nothing changed");
        ok(&mut s, "queue.simple.add", json!({"name": "q", "target": "10.0.0.0/24", "max_limit": "1M/1M"}));
        assert!(s.queue_sync());
        let l = ok(&mut s, "queue.simple.list", json!({}));
        assert_eq!(l["running"], false);
        assert!(l["note"].as_str().unwrap().contains("shaper"), "{l}");
        let plan = s.ext::<crate::queue::ShaperRuntime>().unwrap().applied.clone().unwrap();
        assert_eq!(plan.queues.len(), 1);
        assert_eq!(plan.queues[0].download.rate_bps, 1_000_000);
    }

    #[test]
    fn dhcp_leases_and_networks_make_dynamic_queues() {
        let mut s = lab();
        ok(&mut s, "ip.dhcp-server.network.add", json!({"address": "192.168.88.0/24", "rate_limit": "2M/10M"}));
        ok(&mut s, "ip.dhcp-server.lease.add", json!({"address": "192.168.88.20", "mac_address": "02:00:00:00:00:20", "rate_limit": "5M/20M"}));
        let net = ok(&mut s, "ip.dhcp-server.network.print", json!({}));
        assert_eq!(net[0]["rate_limit"], "2M/10M");
        let err = s.execute("ip.dhcp-server.network.set", &json!({"id": "192.168.88.0/24", "rate_limit": "fast"})).unwrap_err();
        assert!(matches!(err, EngineError::BadParam { .. }), "{err}");
        // Without bound leases (the virtual lab serves nobody), nothing
        // dynamic yet; the plan is pure and covered in crate::queue.
        let l = ok(&mut s, "queue.simple.list", json!({"origin": "dynamic"}));
        assert_eq!(l["total"], 0);
    }
}
