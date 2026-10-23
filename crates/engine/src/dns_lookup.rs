//! G6.6 DNS Lookup (`tool.dns.query`, Tools › DNS Lookup, `/tool
//! dns-lookup`): a `dig` run as a task. The daemon carries the bytes
//! ([`DnsBackend::exchange`]); the codec is `corerouter_proto_dns::dig`;
//! this file is the job: one query, the same query to every upstream side
//! by side (`compare`), or the walk from the root down (`trace`), and the
//! terminal text of each.
//!
//! Events of a task (kind `dns-lookup`):
//! - `{kind: "answer", server, transport, ms, stage?, source?, as_client?,
//!   rcode, id, flags, question, answer, authority, additional, edns, size,
//!   dig}`, then with `explain` (G6.8) `{kind: "why", stage, outcome, why,
//!   args, text, rule?}` per stage of the router's chain, then `{kind:
//!   "asn", address, asn, as_name, prefix}` per address;
//! - `{kind: "compare", server, transport, rcode, ms, data, error?,
//!   timeout}` per upstream; the summary adds `diverge` to each;
//! - `{kind: "trace", zone, asked, address, ms, rcode, answer, records,
//!   signed, final, error?}` per delegation.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use corerouter_hal::SharedProber;
use corerouter_hal::probe::Lookup;
use corerouter_proto_dns::dig::{self, Ask, Meta, Name, RecordType, Reply, Row};
use serde_json::{Value, json};

use crate::dns::DnsBackend;
use crate::tasks::TaskCtx;

pub(crate) const NEEDS_DAEMON: &str = "DNS Lookup needs the router daemon's resolver";

/// Where a query goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LookupServer {
    /// The router's own chain (static, adlist, zones, cache, upstream), as a
    /// LAN client would be answered.
    Router,
    Plain(IpAddr),
    /// An encrypted server (`https://…` DoH, `tls://…` DoT).
    Secure(String),
}

impl LookupServer {
    /// What `dig @…` names it (`None`: the router itself).
    pub fn dig_name(&self) -> Option<String> {
        match self {
            Self::Router => None,
            Self::Plain(ip) => Some(ip.to_string()),
            Self::Secure(url) => Some(url.clone()),
        }
    }

    pub fn label(&self) -> String {
        self.dig_name().unwrap_or_else(|| "router".into())
    }
}

/// The English texts of "Why this answer", by id (the GUI words them in
/// its languages).
pub use corerouter_proto_dns::server::explain::TEXTS as WHY_TEXTS;

/// How the router's own chain is asked (G6.8).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RouterAsk {
    /// Each stage's decision ("Why this answer").
    pub explain: bool,
    /// As if this LAN address asked: the ACL, the per-client limit and the
    /// per-source rules see it; no packet is sent.
    pub as_client: Option<IpAddr>,
}

impl RouterAsk {
    /// Plain `exchange` does it.
    pub fn plain(&self) -> bool {
        !self.explain && self.as_client.is_none()
    }
}

/// A reply as the daemon got it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Exchanged {
    pub bytes: Vec<u8>,
    /// `1.1.1.1#53(1.1.1.1)`, as the `;; SERVER:` line of `dig`.
    pub server: String,
    /// `UDP`, `TCP`, `HTTPS`, `TLS`.
    pub transport: String,
    pub ms: u64,
    /// The router's chain: the stage that answered (`cache`, `static`,
    /// `adlist`, `zones`, `upstream`…).
    pub stage: Option<String>,
    /// `cache`, `stale` or the upstream server that answered.
    pub source: Option<String>,
    /// [`RouterAsk::explain`]: each stage's decision.
    pub explain: Vec<corerouter_proto_dns::server::explain::Decision>,
}

/// An error that means "no reply in time".
pub(crate) fn is_timeout(e: &str) -> bool {
    e.starts_with("timeout") || e.contains("no answer")
}

/// What the job does.
#[derive(Debug, Clone)]
pub(crate) enum Mode {
    One(LookupServer),
    Compare(Vec<LookupServer>),
    Trace,
}

/// A lookup, checked.
#[derive(Debug, Clone)]
pub(crate) struct Job {
    /// As typed (an address stays an address in the `dig` line).
    pub typed: String,
    pub ask: Ask,
    pub rtype: &'static str,
    pub tcp: bool,
    pub mode: Mode,
    /// With the router as the server (G6.8).
    pub router: RouterAsk,
}

/// The query's bytes for `to` (DoH: id 0, RFC 8484 §4.1).
fn bytes_for(ask: &Ask, to: &LookupServer) -> Result<Vec<u8>, String> {
    let id = matches!(to, LookupServer::Secure(_)).then_some(0);
    dig::query(ask, id).map(|(_, b)| b)
}

fn rows(r: &[Row]) -> Value {
    Value::Array(
        r.iter()
            .map(|x| json!({"name": x.name, "ttl": x.ttl, "class": x.class, "type": x.rtype, "data": x.data}))
            .collect(),
    )
}

/// The `dig` command line of the job.
pub(crate) fn command_line(job: &Job, server: Option<&str>) -> String {
    let mut c = dig::command(server, &job.typed, job.rtype, &job.ask, job.tcp);
    if matches!(job.mode, Mode::Trace) {
        c.push_str(" +trace");
    }
    c
}

/// The answer event of one reply.
fn answer_event(job: &Job, r: &Reply, x: &Exchanged, server: Option<&str>) -> Value {
    let meta = Meta {
        command: command_line(job, server),
        server: x.server.clone(),
        transport: x.transport.clone(),
        ms: x.ms,
        stage: x.stage.clone(),
    };
    json!({
        "kind": "answer",
        "server": x.server,
        "transport": x.transport,
        "ms": x.ms,
        "stage": x.stage,
        "source": x.source,
        "rcode": r.status,
        "id": r.id,
        "flags": r.flags,
        "question": r.question.as_ref().map(|(n, t)| json!({"name": n, "type": t})),
        "answer": rows(&r.answer),
        "authority": rows(&r.authority),
        "additional": rows(&r.additional),
        "edns": r.edns.map(|e| json!({"version": e.version, "do": e.dnssec_ok, "udp": e.udp})),
        "size": r.size,
        "as_client": job.router.as_client,
        "dig": dig::dig_text(r, &meta),
    })
}

/// The `why` event of one stage's decision.
fn why_event(d: &corerouter_proto_dns::server::explain::Decision) -> Value {
    use corerouter_model::ItemId;
    use corerouter_proto_dns::server::explain::Rule;
    let args: serde_json::Map<String, Value> = d
        .args
        .iter()
        .map(|(k, v)| ((*k).to_owned(), json!(v)))
        .collect();
    let rule = d.rule.as_ref().map(|r| match r {
        Rule::Static(id) => json!({"kind": "static", "id": ItemId(*id).to_string()}),
        Rule::Adlist(id) => json!({"kind": "adlist", "id": ItemId(*id).to_string()}),
        Rule::Forwarders(name) => json!({"kind": "forwarders", "name": name}),
        Rule::Zone(name) => json!({"kind": "zone", "name": name}),
    });
    json!({"kind": "why", "stage": d.stage, "outcome": d.outcome.as_str(), "why": d.why,
        "args": args, "text": d.text(), "rule": rule})
}

/// Addresses whose AS is looked up at most (the pills of the table).
const MAX_AS: usize = 32;
/// How long the AS lookups may take before the task ends without them.
const AS_WAIT: Duration = Duration::from_secs(3);

/// The origin AS of `addrs` (the MTR's lookup, Team Cymru over DNS:
/// G6.3b), waiting at most [`AS_WAIT`]; unknown ones are left out.
fn origin_as(
    ctx: &TaskCtx,
    prober: Option<&SharedProber>,
    addrs: &[IpAddr],
) -> BTreeMap<IpAddr, corerouter_hal::probe::AsInfo> {
    let mut out = BTreeMap::new();
    let Some(prober) = prober else { return out };
    let mut left: Vec<IpAddr> = addrs.iter().copied().take(MAX_AS).collect();
    let until = ctx.now().saturating_add(AS_WAIT);
    while !left.is_empty() && ctx.now() < until {
        left.retain(|ip| match prober.origin_as(*ip) {
            Lookup::Pending => true,
            Lookup::Done(info) => {
                if let Some(a) = info {
                    out.insert(*ip, a);
                }
                false
            }
        });
        if !left.is_empty() && !ctx.sleep(Duration::from_millis(100)) {
            break;
        }
    }
    out
}

/// The addresses among `rows` (A and AAAA data), without repeats.
fn addresses<'a>(rows: impl IntoIterator<Item = &'a Row>) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    for row in rows.into_iter().filter(|x| x.rtype == "A" || x.rtype == "AAAA") {
        if let Ok(ip) = row.data.parse::<IpAddr>()
            && !out.contains(&ip)
        {
            out.push(ip);
        }
    }
    out
}

/// The origin AS of each address in the answer, as `asn` events.
fn as_events(ctx: &TaskCtx, prober: Option<&SharedProber>, r: &Reply) {
    for (ip, a) in origin_as(ctx, prober, &addresses(&r.answer)) {
        ctx.emit(json!({"kind": "asn", "address": ip, "asn": a.asn,
            "as_name": a.name, "prefix": a.prefix}));
    }
}

/// Runs `job` (the task's body).
pub(crate) fn run(
    ctx: &TaskCtx,
    backend: &Arc<dyn DnsBackend>,
    prober: Option<&SharedProber>,
    job: &Job,
) -> Result<(), String> {
    if let Mode::Compare(_) | Mode::Trace = job.mode {
        let mode = if matches!(job.mode, Mode::Trace) { "trace" } else { "compare" };
        ctx.emit(json!({"kind": "begin", "mode": mode}));
    }
    match &job.mode {
        Mode::One(to) => one(ctx, backend, prober, job, to),
        Mode::Compare(list) => compare(ctx, backend, prober, job, list),
        Mode::Trace => trace(ctx, backend, job),
    }
}

fn one(
    ctx: &TaskCtx,
    backend: &Arc<dyn DnsBackend>,
    prober: Option<&SharedProber>,
    job: &Job,
    to: &LookupServer,
) -> Result<(), String> {
    let q = bytes_for(&job.ask, to)?;
    let sent = match to {
        LookupServer::Router if !job.router.plain() => backend.ask_router(&q, job.tcp, job.router),
        _ => backend.exchange(to, &q, job.tcp),
    };
    let got = sent.and_then(|x| dig::decode(&x.bytes).map(|r| (r, x)));
    match got {
        Ok((r, x)) => {
            ctx.emit(answer_event(job, &r, &x, to.dig_name().as_deref()));
            for d in &x.explain {
                ctx.emit(why_event(d));
            }
            ctx.summary(json!({"mode": "query", "rcode": r.status, "ms": x.ms,
                "server": x.server, "answers": r.answer.len()}));
            as_events(ctx, prober, &r);
            Ok(())
        }
        Err(e) => {
            let e: String = e.chars().take(300).collect();
            ctx.emit(json!({"kind": "error", "server": to.label(), "error": e,
                "timeout": is_timeout(&e)}));
            Err(e)
        }
    }
}

/// The data a server answered, comparable across servers (TTLs left out:
/// they count down differently in each cache).
fn compared(r: &Reply) -> Vec<String> {
    let mut d: Vec<String> = r
        .answer
        .iter()
        .filter(|x| x.rtype != "RRSIG")
        .map(|x| format!("{} {}", x.rtype, x.data))
        .collect();
    d.sort();
    d.dedup();
    d
}

fn compare(
    ctx: &TaskCtx,
    backend: &Arc<dyn DnsBackend>,
    prober: Option<&SharedProber>,
    job: &Job,
    list: &[LookupServer],
) -> Result<(), String> {
    let mut asks = Vec::new();
    for to in list {
        asks.push((to.clone(), bytes_for(&job.ask, to)?));
    }
    let results = backend.exchange_all(&asks, job.tcp);
    let mut rowsv: Vec<Value> = Vec::new();
    let mut replies: Vec<Option<Reply>> = Vec::new();
    for (to, got) in list.iter().zip(results) {
        let ev = match got.and_then(|x| dig::decode(&x.bytes).map(|r| (r, x))) {
            Ok((r, x)) => {
                let ev = json!({"kind": "compare", "server": to.label(), "transport": x.transport,
                    "rcode": r.status, "ms": x.ms, "data": compared(&r), "timeout": false});
                replies.push(Some(r));
                ev
            }
            Err(e) => {
                let e: String = e.chars().take(300).collect();
                replies.push(None);
                json!({"kind": "compare", "server": to.label(), "rcode": null, "ms": null,
                    "data": [], "error": e, "timeout": is_timeout(&e)})
            }
        };
        ctx.emit(ev.clone());
        rowsv.push(ev);
    }
    // Addresses compare by the operator announcing them: a CDN hands each
    // resolver its own servers (same AS), a sinkhole or a hijack does not.
    let all = addresses(replies.iter().flatten().flat_map(|r| r.answer.iter()));
    let owners = origin_as(ctx, prober, &all);
    for (row, reply) in rowsv.iter_mut().zip(&replies) {
        if let (Value::Object(o), Some(r)) = (row, reply) {
            o.insert("match".into(), json!(matched(r, &owners)));
        }
    }
    let majority = mark_divergence(&mut rowsv);
    let answered = rowsv.iter().filter(|r| r["rcode"].is_string()).count();
    ctx.summary(json!({"mode": "compare", "servers": rowsv, "majority": majority,
        "answered": answered}));
    if answered == 0 {
        return Err("no upstream answered".into());
    }
    Ok(())
}

/// What a compare row is matched on: [`compared`], with each address whose
/// origin AS is known as that AS (`A AS15169`).
fn matched(r: &Reply, owners: &BTreeMap<IpAddr, corerouter_hal::probe::AsInfo>) -> Vec<String> {
    let mut d: Vec<String> = r
        .answer
        .iter()
        .filter(|x| x.rtype != "RRSIG")
        .map(|x| match x.data.parse::<IpAddr>().ok().and_then(|ip| owners.get(&ip)) {
            Some(a) if x.rtype == "A" || x.rtype == "AAAA" => format!("{} AS{}", x.rtype, a.asn),
            _ => format!("{} {}", x.rtype, x.data),
        })
        .collect();
    d.sort();
    d.dedup();
    d
}

/// Sets `diverge` on each compare row: an answer (status and `match`, or
/// `data` without it) other than the one most servers gave. Without a
/// strict majority every answer diverges (nothing to trust). Returns the
/// majority's data, if any.
pub fn mark_divergence(rows: &mut [Value]) -> Option<Value> {
    let key = |r: &Value| -> Option<(String, String)> {
        let on = r.get("match").unwrap_or(&r["data"]);
        Some((r["rcode"].as_str()?.to_owned(), on.to_string()))
    };
    let answered: Vec<(String, String)> = rows.iter().filter_map(key).collect();
    let mut best: Option<((String, String), usize)> = None;
    for k in &answered {
        let n = answered.iter().filter(|o| *o == k).count();
        if best.as_ref().is_none_or(|(_, b)| n > *b) {
            best = Some((k.clone(), n));
        }
    }
    let majority = best.filter(|(_, n)| *n * 2 > answered.len()).map(|(k, _)| k);
    let distinct = {
        let mut d = answered.clone();
        d.sort();
        d.dedup();
        d.len()
    };
    for r in rows.iter_mut() {
        let diverge = match (key(r), &majority) {
            (None, _) => false,
            (Some(_), _) if distinct <= 1 => false,
            (Some(k), Some(m)) => k != *m,
            (Some(_), None) => true,
        };
        if let Value::Object(o) = r {
            o.insert("diverge".into(), json!(diverge));
        }
    }
    let m = majority?;
    rows.iter()
        .find(|r| key(r).as_ref() == Some(&m))
        .map(|r| r["data"].clone())
}

/// Delegations followed at most (the deepest real names have ~6; more is a
/// loop the zone check missed).
const MAX_DEPTH: usize = 12;
/// Servers of one zone tried before giving up on it.
const TRIES: usize = 3;

/// A server of a zone, by name, with its address when known.
#[derive(Debug, Clone)]
struct Ns {
    name: String,
    addr: Option<IpAddr>,
}

/// `+trace`: from a root server down the referrals (RFC 1034 §4.3.2,
/// RD clear, DO set to see the DS of each delegation), one event per zone.
fn trace(ctx: &TaskCtx, backend: &Arc<dyn DnsBackend>, job: &Job) -> Result<(), String> {
    let mut ask = job.ask.clone();
    ask.recursion = false;
    ask.dnssec = true;
    let target = name_dot(&ask.name);
    // Start at a root server chosen by the clock (not always a.root).
    let first = usize::try_from(ctx.now().subsec_nanos()).unwrap_or(0) % dig::ROOT_SERVERS.len();
    let mut servers: Vec<Ns> = dig::ROOT_SERVERS
        .iter()
        .cycle()
        .skip(first)
        .take(dig::ROOT_SERVERS.len())
        .map(|(n, ip)| Ns {
            name: (*n).to_owned(),
            addr: Some(IpAddr::V4(*ip)),
        })
        .collect();
    let mut zone = ".".to_owned();
    for _ in 0..MAX_DEPTH {
        let mut got = None;
        let mut tried = 0;
        for ns in servers.iter_mut() {
            if tried >= TRIES || ctx.stopped() {
                break;
            }
            let addr = match ns.addr {
                Some(a) => a,
                // No glue: the router's resolver finds it (IPv4 first).
                None => match backend.lookup(ns.name.trim_end_matches('.')) {
                    Ok(mut all) => {
                        all.sort_by_key(IpAddr::is_ipv6);
                        let Some(a) = all.first().copied() else { continue };
                        ns.addr = Some(a);
                        a
                    }
                    Err(_) => continue,
                },
            };
            tried += 1;
            let to = LookupServer::Plain(addr);
            let reply = bytes_for(&ask, &to).and_then(|q| backend.exchange(&to, &q, job.tcp))
                .and_then(|x| dig::decode(&x.bytes).map(|r| (r, x)));
            match reply {
                Ok(r) => {
                    got = Some((ns.clone(), addr, r));
                    break;
                }
                Err(e) => {
                    let e: String = e.chars().take(200).collect();
                    ctx.emit(json!({"kind": "trace", "zone": zone, "asked": ns.name, "address": addr,
                        "ms": null, "rcode": null, "answer": "", "records": [], "signed": null,
                        "final": false, "error": e, "timeout": is_timeout(&e)}));
                }
            }
        }
        if ctx.stopped() {
            return Ok(());
        }
        let Some((ns, addr, (r, x))) = got else {
            return Err(format!("no server of {zone} answered"));
        };
        let referral = dig::referral(&r).filter(|rf| {
            dig::is_below(&rf.zone, &zone)
                && (rf.zone.eq_ignore_ascii_case(&target) || dig::is_below(&target, &rf.zone))
        });
        match referral {
            Some(rf) => {
                ctx.emit(json!({"kind": "trace", "zone": zone, "asked": ns.name, "address": addr,
                    "ms": x.ms, "rcode": r.status,
                    "answer": format!("referral: {} ({} NS)", rf.zone, rf.servers.len()),
                    "records": rows(&r.authority), "signed": rf.signed, "final": false}));
                servers = rf
                    .servers
                    .iter()
                    .map(|name| Ns {
                        name: name.clone(),
                        addr: {
                            let mut glue: Vec<IpAddr> = rf
                                .glue
                                .iter()
                                .filter(|(g, _)| g == name)
                                .map(|(_, a)| *a)
                                .collect();
                            glue.sort_by_key(IpAddr::is_ipv6);
                            glue.first().copied()
                        },
                    })
                    .collect();
                zone = rf.zone;
            }
            None => {
                let answer = if r.status != "NOERROR" {
                    r.status.clone()
                } else if r.answer.is_empty() {
                    "no records of this type".to_owned()
                } else {
                    r.answer
                        .iter()
                        .filter(|a| a.rtype != "RRSIG")
                        .map(|a| format!("{} {}", a.rtype, a.data))
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                ctx.emit(json!({"kind": "trace", "zone": zone, "asked": ns.name, "address": addr,
                    "ms": x.ms, "rcode": r.status, "answer": answer, "records": rows(&r.answer),
                    "signed": dig::signed_answer(&r), "final": true}));
                ctx.summary(json!({"mode": "trace", "rcode": r.status, "zone": zone}));
                return Ok(());
            }
        }
    }
    Err(format!("more than {MAX_DEPTH} delegations: stopped"))
}

fn name_dot(n: &Name) -> String {
    let mut s = n.to_ascii().to_ascii_lowercase();
    if !s.ends_with('.') {
        s.push('.');
    }
    s
}

/// The record type `t`, one of [`dig::TYPES`].
pub(crate) fn record_type(t: &str) -> Option<(&'static str, RecordType)> {
    let up = t.trim().to_ascii_uppercase();
    let known = dig::TYPES.iter().find(|k| **k == up)?;
    Some((*known, known.parse().ok()?))
}

fn s(v: &Value, k: &str) -> String {
    match v.get(k) {
        Some(Value::String(x)) => x.clone(),
        Some(Value::Null) | None => String::new(),
        Some(x) => x.to_string(),
    }
}

/// Terminal text of one event (`tools::text`): the `dig` output, or a row of
/// the compare or trace table. May hold several lines.
pub fn text_line(ev: &Value) -> String {
    match ev.get("kind").and_then(Value::as_str) {
        Some("begin") => header(&s(ev, "mode")).unwrap_or_default(),
        Some("answer") => s(ev, "dig").trim_end().to_owned(),
        Some("asn") => format!(
            ";; {} AS{} {}",
            s(ev, "address"),
            s(ev, "asn"),
            s(ev, "as_name")
        )
        .trim_end()
        .to_owned(),
        Some("compare") => {
            let data: Vec<String> = ev
                .get("data")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
            let status = if ev["timeout"] == true {
                "timeout".to_owned()
            } else if ev.get("error").is_some() {
                format!("error: {}", s(ev, "error"))
            } else {
                s(ev, "rcode")
            };
            let ms = ev.get("ms").and_then(Value::as_u64).map_or("-".into(), |m| format!("{m}ms"));
            format!("{:<40} {:<10} {:>7}  {}", s(ev, "server"), status, ms, data.join(", "))
                .trim_end()
                .to_owned()
        }
        Some("trace") => {
            let ms = ev.get("ms").and_then(Value::as_u64).map_or("-".into(), |m| format!("{m}ms"));
            let signed = match ev.get("signed").and_then(Value::as_bool) {
                Some(true) => "signed",
                Some(false) => "unsigned",
                None => "",
            };
            let answer = match ev.get("error") {
                Some(_) => format!("error: {}", s(ev, "error")),
                None => s(ev, "answer"),
            };
            format!(
                "{:<24} {:<44} {:>7}  {} {}",
                s(ev, "zone"),
                format!("{} ({})", s(ev, "asked"), s(ev, "address")),
                ms,
                answer,
                signed
            )
            .trim_end()
            .to_owned()
        }
        Some("why") => format!(";; WHY {:<9} {:<12} {}", s(ev, "stage"), s(ev, "outcome"), s(ev, "text"))
            .trim_end()
            .to_owned(),
        Some("error") => format!(";; {}: {}", s(ev, "server"), s(ev, "error")),
        _ => ev.to_string(),
    }
}

/// The closing lines: which compare answers diverge.
pub fn summary_lines(summary: &Value) -> Vec<String> {
    match summary.get("mode").and_then(Value::as_str) {
        Some("compare") => summary
            .get("servers")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|r| r["diverge"] == true)
            .map(|r| format!(";; {} diverges from the other servers", s(r, "server")))
            .collect(),
        _ => Vec::new(),
    }
}

/// Column header of a compare or trace (none for one answer).
pub fn header(mode: &str) -> Option<String> {
    match mode {
        "compare" => Some(format!("{:<40} {:<10} {:>7}  DATA", "SERVER", "STATUS", "TIME")),
        "trace" => Some(format!("{:<24} {:<44} {:>7}  ANSWER", "ZONE", "ASKED", "TIME")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn divergence_against_the_majority() {
        let row = |rcode: Option<&str>, data: &[&str]| {
            json!({"rcode": rcode, "data": data})
        };
        let mut rows = vec![
            row(Some("NOERROR"), &["A 192.0.2.1"]),
            row(Some("NOERROR"), &["A 192.0.2.1"]),
            row(Some("NOERROR"), &["A 203.0.113.66"]),
            row(None, &[]),
        ];
        let m = mark_divergence(&mut rows);
        assert_eq!(m, Some(json!(["A 192.0.2.1"])));
        let d: Vec<bool> = rows.iter().map(|r| r["diverge"] == true).collect();
        assert_eq!(d, [false, false, true, false]);
        // Two answers, two opinions: no majority, both flagged.
        let mut two = vec![row(Some("NOERROR"), &["A 1.1.1.1"]), row(Some("NXDOMAIN"), &[])];
        assert_eq!(mark_divergence(&mut two), None);
        assert!(two.iter().all(|r| r["diverge"] == true));
        // All agree: nobody diverges.
        let mut same = vec![row(Some("NOERROR"), &["A 1.1.1.1"]); 2];
        mark_divergence(&mut same);
        assert!(same.iter().all(|r| r["diverge"] == false));
    }

    #[test]
    fn terminal_rows() {
        let l = text_line(&json!({"kind": "compare", "server": "9.9.9.9", "rcode": null, "ms": null,
            "data": [], "error": "timeout (no answer in 3000 ms)", "timeout": true}));
        assert!(l.starts_with("9.9.9.9") && l.contains("timeout"), "{l}");
        let l = text_line(&json!({"kind": "trace", "zone": ".", "asked": "a.root-servers.net.",
            "address": "198.41.0.4", "ms": 20, "answer": "referral: com. (13 NS)", "signed": true}));
        assert!(l.contains("a.root-servers.net. (198.41.0.4)") && l.ends_with("signed"), "{l}");
        let sum = summary_lines(&json!({"mode": "compare", "servers": [
            {"server": "1.1.1.1", "diverge": false}, {"server": "6.6.6.6", "diverge": true}]}));
        assert_eq!(sum, [";; 6.6.6.6 diverges from the other servers"]);
        assert!(header("trace").unwrap().contains("ZONE"));
        assert!(header("query").is_none());
    }
}
