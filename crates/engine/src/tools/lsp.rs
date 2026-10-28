//! `tool.mpls.ping.start` and `tool.mpls.traceroute.start` (G3.5b): MPLS
//! echo requests along the LSP of a FEC (RFC 8029 §4.3), over an
//! [`LspSocket`] from the HAL (the host's packet socket, or the lab's
//! simulated LSPs).
//!
//! - **Ping:** every `interval` a request with the top label's TTL at 255;
//!   the egress answers code 3. Each reply is an event (round trip, return
//!   code, the one-letter code Cisco and Junos print), the summary holds
//!   the statistics ([`super::stats`]) and the count of each code.
//! - **Traceroute:** TTL 1, 2, … with a Downstream Detailed Mapping: the
//!   LSR where the label TTL expires answers "label switched" with its own
//!   downstream mapping, which goes into the next request (§4.6), so each
//!   hop checks the interface and labels the previous one announced
//!   (code 5 on a mismatch). It ends at the egress, at the first error
//!   code, or at `max_hops`.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::ops::ControlFlow;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use corerouter_hal::lsp::respond::ddmap_of;
use corerouter_hal::lsp::wire::{self, Ddmap, Echo, Fec, code};
use corerouter_hal::lsp::{LspAnswer, LspPath, LspProber, LspRequest, LspSocket, destination};
use corerouter_hal::mpls::MplsNexthop;
use corerouter_hal::probe::ProbeError;
use ipnet::IpNet;
use serde_json::{Value, json};

use super::stats::{Outcome, Stats};
use super::ms;
use crate::tasks::TaskCtx;

/// Sender's handles of this process: one per task, so two tasks never
/// take each other's replies.
static NEXT_HANDLE: AtomicU32 = AtomicU32::new(0x4c53_5000);

/// Hops kept in a trace's summary.
const MAX_HOPS: u8 = 64;
/// Longest single wait on the socket, so a stop is noticed quickly.
const MAX_WAIT: Duration = Duration::from_millis(100);

/// What the requests do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `count` requests (0: until stopped), one every `interval`.
    Ping { count: u32, interval: Duration },
    /// TTL 1..=`max_hops`, `probes` tries per hop.
    Trace { max_hops: u8, probes: u8 },
}

/// Everything the commands validated.
#[derive(Debug, Clone)]
pub struct LspJob {
    pub fec: Fec,
    pub mode: Mode,
    pub timeout: Duration,
    /// UDP payload size: a Pad TLV fills the request up to it (§3.5).
    pub size: u16,
    /// Top label TTL of a ping (255, §4.3).
    pub ttl: u8,
    /// Traffic class of the label, and DSCP of the packet (EXP << 5).
    pub exp: u8,
    /// Ask the LSRs to check the FEC (V flag, §3).
    pub validate: bool,
}

fn prefix(fec: &Fec) -> Option<IpNet> {
    fec.prefix()
}

fn path_json(p: &LspPath) -> Value {
    json!({
        "labels": p.labels,
        "out_label": labels_text(&p.labels),
        "nexthop": p.nexthop.map(|a| a.to_string()),
        "interface": p.interface.as_str(),
        "src": p.src.map(|a| a.to_string()),
        "mtu": p.mtu,
        "origin": p.origin.name(),
    })
}

/// "17", "17 300", "implicit-null" (RouterOS spelling).
pub fn labels_text(labels: &[u32]) -> String {
    if labels.is_empty() {
        return "implicit-null".into();
    }
    labels
        .iter()
        .map(|l| match *l {
            wire::LABEL_IMPLICIT_NULL => "implicit-null".to_owned(),
            wire::LABEL_EXPLICIT_NULL_V4 | wire::LABEL_EXPLICIT_NULL_V6 => {
                "explicit-null".to_owned()
            }
            l => l.to_string(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// The request of sequence `seq`.
fn request(job: &LspJob, handle: u32, seq: u32, ddmap: Option<&Ddmap>) -> Vec<u8> {
    let mut e = Echo::request(handle, seq, vec![job.fec.clone()]);
    if job.validate {
        e.flags |= wire::FLAG_VALIDATE;
    }
    if let Some(d) = ddmap {
        let mut d = d.clone();
        // Ask for the interface and labels the request arrived with, to
        // show them on a mismatch.
        d.flags |= wire::DS_FLAG_IF_LABEL_STACK;
        d.return_code = 0;
        d.return_subcode = 0;
        e.ddmaps.push(d);
    }
    let base = wire::encode(&e).len();
    let want = usize::from(job.size);
    // A Pad TLV is 4 octets of header and at least 1 of value.
    if want >= base + 5 {
        let mut pad = vec![0u8; want - base - 4];
        if let Some(first) = pad.first_mut() {
            // §3.5: 1 = "drop Pad TLV from reply".
            *first = 1;
        }
        e.pad = Some(pad);
    }
    wire::encode(&e)
}

/// One answer, read: the reply, or why it is not one of ours.
fn read(a: &LspAnswer, handle: u32) -> Option<Echo> {
    let e = wire::parse(&a.payload).ok()?;
    (e.msg_type == wire::MSG_REPLY && e.handle == handle).then_some(e)
}

/// The code that tells what happened: the header's, or the first DDMAP's
/// when the header says "see DDMAP" (§3.1 note 2).
fn effective(e: &Echo) -> (u8, u8) {
    if e.return_code == code::SEE_DDMAP
        && let Some(d) = e.ddmaps.first()
    {
        return (d.return_code, d.return_subcode);
    }
    (e.return_code, e.return_subcode)
}

fn ddmap_json(d: &Ddmap) -> Value {
    let labels: Vec<u32> = d.labels.iter().map(|l| l.label).collect();
    json!({
        "downstream": d.address.addr().map(|a| a.to_string()),
        "interface_address": d.address.iface().map(|a| a.to_string()),
        "mtu": d.mtu,
        "labels": labels,
        "out_label": labels_text(&labels),
    })
}

fn stack_text(e: &Echo) -> Option<String> {
    let s = e.if_label_stack.as_ref()?;
    let labels: Vec<u32> = s.stack.iter().map(|l| l.label).collect();
    Some(format!(
        "received on {} with {}",
        s.address
            .addr()
            .map_or_else(|| "?".to_owned(), |a| a.to_string()),
        if labels.is_empty() {
            "no label".to_owned()
        } else {
            labels_text(&labels)
        }
    ))
}

/// The fields of a reply, for an event.
fn reply_fields(ev: &mut serde_json::Map<String, Value>, from: IpAddr, e: &Echo, rtt: f64) {
    let (rc, rsc) = effective(e);
    ev.insert("address".into(), json!(from.to_string()));
    ev.insert("rtt_ms".into(), json!(rtt));
    ev.insert("code".into(), json!(rc));
    ev.insert("subcode".into(), json!(rsc));
    ev.insert("letter".into(), json!(wire::letter(rc).to_string()));
    ev.insert("detail".into(), json!(wire::describe(rc, rsc)));
    if let Some(t) = stack_text(e) {
        ev.insert("received".into(), json!(t));
    }
}

/// An open socket, the path the requests take and every path of the FEC.
type Opened = (Box<dyn LspSocket>, LspPath, Vec<LspPath>);

fn open(prober: &dyn LspProber, fec: &Fec) -> Result<Opened, String> {
    let prefix = prefix(fec).ok_or("only prefix FECs can be sent")?;
    let mut sock = prober.open().map_err(|e| e.to_string())?;
    let paths = sock.paths(prefix).map_err(|e| e.to_string())?;
    let first = paths
        .first()
        .cloned()
        .ok_or_else(|| format!("no route for {prefix}: nothing to send the request along"))?;
    Ok((sock, first, paths))
}

/// A send error that answers this request (no neighbor entry, link
/// down, too big), not the end of the task.
fn send_error(e: &ProbeError) -> Option<String> {
    match e {
        ProbeError::Unreachable(_) | ProbeError::TooBig(_) => Some(e.to_string()),
        _ => None,
    }
}

pub fn run(job: LspJob, prober: &dyn LspProber, ctx: &TaskCtx) -> Result<(), String> {
    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    let (mut sock, path, paths) = open(prober, &job.fec)?;
    match job.mode {
        Mode::Ping { count, interval } => ping(&job, handle, sock.as_mut(), &path, &paths, count, interval, prober, ctx),
        Mode::Trace { max_hops, probes } => trace(&job, handle, sock.as_mut(), &path, &paths, max_hops, probes, prober, ctx),
    }
}

fn base_summary(job: &LspJob, prober: &dyn LspProber, path: &LspPath, paths: &[LspPath]) -> serde_json::Map<String, Value> {
    let mut o = serde_json::Map::new();
    o.insert("prober".into(), json!(prober.describe()));
    o.insert(
        "fec".into(),
        json!(prefix(&job.fec).map(|p| p.to_string())),
    );
    o.insert(
        "fec_type".into(),
        json!(match job.fec {
            Fec::Generic(_) => "generic",
            _ => "ldp",
        }),
    );
    o.insert("path".into(), path_json(path));
    // ECMP: the requests follow the first path (one 127/8 destination).
    o.insert("paths".into(), json!(paths.len()));
    o.insert("timeout_ms".into(), json!(ms(job.timeout)));
    o.insert("size".into(), json!(job.size));
    o.insert("exp".into(), json!(job.exp));
    o
}

#[allow(clippy::too_many_arguments)]
fn ping(
    job: &LspJob,
    handle: u32,
    sock: &mut dyn LspSocket,
    path: &LspPath,
    paths: &[LspPath],
    count: u32,
    interval: Duration,
    prober: &dyn LspProber,
    ctx: &TaskCtx,
) -> Result<(), String> {
    let v6 = prefix(&job.fec).is_some_and(|p| p.addr().is_ipv6());
    let mut stats = Stats::default();
    let mut codes: BTreeMap<u8, u64> = BTreeMap::new();
    let mut flights: BTreeMap<u32, Duration> = BTreeMap::new();
    let summary = |stats: &Stats, codes: &BTreeMap<u8, u64>| {
        let mut o = base_summary(job, prober, path, paths);
        o.insert("mode".into(), json!("ping"));
        o.insert("count".into(), json!(count));
        o.insert("interval_ms".into(), json!(ms(interval)));
        o.insert("stats".into(), stats.to_json());
        let c: Vec<Value> = codes
            .iter()
            .map(|(c, n)| json!({"code": c, "letter": wire::letter(*c).to_string(), "count": n, "meaning": wire::describe(*c, 1)}))
            .collect();
        o.insert("codes".into(), json!(c));
        Value::Object(o)
    };
    ctx.summary(summary(&stats, &codes));
    let mut seq: u32 = 0;
    let mut next_send = Duration::ZERO;
    loop {
        let more = count == 0 || seq < count;
        if !more && flights.is_empty() {
            break;
        }
        let now = ctx.now();
        let mut changed = false;
        if more && now >= next_send {
            seq = seq.saturating_add(1);
            let payload = request(job, handle, seq, None);
            let req = LspRequest {
                path,
                ttl: job.ttl,
                dst: destination(v6, 1),
                tos: job.exp << 5,
                payload: &payload,
            };
            stats.sent += 1;
            match sock.send(&req) {
                Ok(()) => {
                    flights.insert(seq, ctx.now());
                }
                Err(e) => {
                    let Some(why) = send_error(&e) else {
                        return Err(e.to_string());
                    };
                    stats.record(Outcome::Unreachable, None);
                    ctx.emit(json!({"seq": seq, "status": "error", "letter": "Q", "detail": format!("request not sent: {why}")}));
                }
            }
            changed = true;
            next_send = next_send.saturating_add(interval);
            if next_send < now {
                next_send = now.saturating_add(interval);
            }
        }
        let now = ctx.now();
        let expired: Vec<u32> = flights
            .iter()
            .filter(|(_, t)| now.saturating_sub(**t) >= job.timeout)
            .map(|(s, _)| *s)
            .collect();
        for s in expired {
            flights.remove(&s);
            stats.record(Outcome::Timeout, None);
            ctx.emit(json!({"seq": s, "status": "timeout", "letter": ".", "detail": "no reply"}));
            changed = true;
        }
        if changed {
            ctx.summary(summary(&stats, &codes));
        }
        let more = count == 0 || seq < count;
        if !more && flights.is_empty() {
            break;
        }
        let mut until = now.saturating_add(Duration::from_millis(250));
        if more {
            until = until.min(next_send);
        }
        if let Some(first) = flights.values().min() {
            until = until.min(first.saturating_add(job.timeout));
        }
        let mut got = false;
        let alive = wait_lsp(sock, ctx, until, |a, at| {
            let Some(e) = read(&a, handle) else {
                return ControlFlow::Continue(());
            };
            let Some(sent) = flights.remove(&e.seq) else {
                return ControlFlow::Continue(());
            };
            let rtt = ms(a.rtt.unwrap_or_else(|| at.saturating_sub(sent)));
            let (rc, _) = effective(&e);
            *codes.entry(rc).or_insert(0) += 1;
            let ok = rc == code::EGRESS;
            stats.record(if ok { Outcome::Ok } else { Outcome::Error }, Some(rtt));
            let mut ev = serde_json::Map::new();
            ev.insert("seq".into(), json!(e.seq));
            ev.insert("status".into(), json!(if ok { "ok" } else { "error" }));
            reply_fields(&mut ev, a.from, &e, rtt);
            ctx.emit(Value::Object(ev));
            got = true;
            ControlFlow::Continue(())
        })?;
        if got {
            ctx.summary(summary(&stats, &codes));
        }
        if !alive {
            break;
        }
    }
    ctx.summary(summary(&stats, &codes));
    Ok(())
}

/// Receive until `until` (job time), as [`super::wait_replies`] does for
/// ICMP; `on` ends the wait early with `Break`. `Ok(false)`: the task was
/// stopped.
fn wait_lsp(
    sock: &mut dyn LspSocket,
    ctx: &TaskCtx,
    until: Duration,
    mut on: impl FnMut(LspAnswer, Duration) -> ControlFlow<()>,
) -> Result<bool, String> {
    loop {
        if ctx.stopped() {
            return Ok(false);
        }
        let now = ctx.now();
        if now >= until {
            return Ok(true);
        }
        let wait = until.saturating_sub(now).min(MAX_WAIT);
        match sock.recv(wait).map_err(|e| e.to_string())? {
            Some(ans) => {
                if on(ans, ctx.now()).is_break() {
                    return Ok(true);
                }
            }
            // A simulated socket answers at once: wait out the slice here.
            None => {
                let left = until.saturating_sub(ctx.now()).min(wait);
                if !left.is_zero() && !ctx.sleep(left) {
                    return Ok(false);
                }
            }
        }
    }
}

/// The DDMAP the ingress sends with TTL 1: its own next hop (§3.4.2).
fn first_ddmap(path: &LspPath, v6: bool) -> Ddmap {
    let nh = MplsNexthop {
        via: path.nexthop,
        interface: Some(path.interface.clone()),
        out_labels: path.labels.clone(),
    };
    ddmap_of(&nh, path.origin, path.mtu, v6)
}

#[allow(clippy::too_many_arguments)]
fn trace(
    job: &LspJob,
    handle: u32,
    sock: &mut dyn LspSocket,
    path: &LspPath,
    paths: &[LspPath],
    max_hops: u8,
    probes: u8,
    prober: &dyn LspProber,
    ctx: &TaskCtx,
) -> Result<(), String> {
    let v6 = prefix(&job.fec).is_some_and(|p| p.addr().is_ipv6());
    let mut hops: Vec<Value> = Vec::new();
    // Hop 0: this router, what it pushes and where.
    let hop0 = json!({
        "hop": 0,
        "status": "local",
        "letter": " ",
        "address": path.src.map(|a| a.to_string()),
        "downstream": path.nexthop.map(|a| a.to_string()),
        "interface": path.interface.as_str(),
        "mtu": path.mtu,
        "out_label": labels_text(&path.labels),
        "labels": path.labels,
    });
    ctx.emit(hop0.clone());
    hops.push(hop0);
    let mut result: Option<String> = None;
    let summary = |hops: &[Value], result: &Option<String>| {
        let mut o = base_summary(job, prober, path, paths);
        o.insert("mode".into(), json!("traceroute"));
        o.insert("max_hops".into(), json!(max_hops));
        o.insert("probes".into(), json!(probes));
        o.insert("hops".into(), json!(hops));
        o.insert("result".into(), json!(result));
        Value::Object(o)
    };
    ctx.summary(summary(&hops, &result));
    let mut ddmap = first_ddmap(path, v6);
    let mut seq: u32 = 0;
    'hops: for ttl in 1..=max_hops.min(MAX_HOPS) {
        let mut answered: Option<(LspAnswer, Echo, f64)> = None;
        for _ in 0..probes.max(1) {
            seq = seq.saturating_add(1);
            let payload = request(job, handle, seq, Some(&ddmap));
            let req = LspRequest {
                path,
                ttl,
                dst: destination(v6, 1),
                tos: job.exp << 5,
                payload: &payload,
            };
            let sent = ctx.now();
            if let Err(e) = sock.send(&req) {
                let Some(why) = send_error(&e) else {
                    return Err(e.to_string());
                };
                result = Some(format!("request not sent: {why}"));
                let ev = json!({"hop": ttl, "status": "error", "letter": "Q", "detail": format!("request not sent: {why}")});
                ctx.emit(ev.clone());
                hops.push(ev);
                break 'hops;
            }
            let until = sent.saturating_add(job.timeout);
            let want = seq;
            let alive = wait_lsp(sock, ctx, until.max(ctx.now()), |a, at| {
                let Some(e) = read(&a, handle).filter(|e| e.seq == want) else {
                    return ControlFlow::Continue(());
                };
                let rtt = ms(a.rtt.unwrap_or_else(|| at.saturating_sub(sent)));
                answered = Some((a, e, rtt));
                ControlFlow::Break(())
            })?;
            if !alive {
                break 'hops;
            }
            if answered.is_some() {
                break;
            }
            let ev = json!({"hop": ttl, "status": "timeout", "letter": ".", "detail": "no reply"});
            ctx.emit(ev);
        }
        let Some((a, e, rtt)) = answered else {
            hops.push(json!({"hop": ttl, "status": "timeout", "letter": ".", "detail": "no reply"}));
            ctx.summary(summary(&hops, &result));
            continue;
        };
        let (rc, _) = effective(&e);
        let mut ev = serde_json::Map::new();
        ev.insert("hop".into(), json!(ttl));
        let status = match rc {
            code::EGRESS => "egress",
            code::LABEL_SWITCHED | code::UPSTREAM_IF_UNKNOWN | code::FEC_CHANGE => "transit",
            _ => "error",
        };
        ev.insert("status".into(), json!(status));
        reply_fields(&mut ev, a.from, &e, rtt);
        if let Some(Value::Object(dm)) = e.ddmaps.first().map(ddmap_json) {
            ev.extend(dm);
        }
        let ev = Value::Object(ev);
        ctx.emit(ev.clone());
        hops.push(ev);
        match status {
            "egress" => {
                result = Some(format!("reached the egress at hop {ttl}"));
                break;
            }
            "error" => {
                result = Some(format!("stopped at hop {ttl}: {}", wire::describe(rc, effective(&e).1)));
                break;
            }
            _ => {}
        }
        // §4.6: the next request carries the mapping this hop announced.
        match e.ddmaps.first() {
            Some(d) => ddmap = d.clone(),
            None => {
                // No mapping back: let the next hop skip the checks.
                ddmap = Ddmap {
                    address: wire::DsAddress::all_routers(v6),
                    labels: Vec::new(),
                    ..ddmap
                };
            }
        }
        ctx.summary(summary(&hops, &result));
    }
    if result.is_none() && !ctx.stopped() {
        result = Some(format!("no egress within {max_hops} hops"));
    }
    ctx.summary(summary(&hops, &result));
    Ok(())
}

/// Terminal rendering (`tool.task.poll {text: true}`).
pub mod text {
    use serde_json::Value;

    fn s(v: &Value, k: &str) -> String {
        match v.get(k) {
            None | Some(Value::Null) => String::new(),
            Some(Value::String(t)) => t.clone(),
            Some(x) => x.to_string(),
        }
    }

    fn time(v: &Value, k: &str) -> String {
        v.get(k)
            .and_then(Value::as_f64)
            .map(|ms| format!("{ms:.3}ms"))
            .unwrap_or_default()
    }

    pub fn header(kind: &str) -> Option<String> {
        match kind {
            "lsp-ping" => Some(format!(
                "{:>5} {} {:<40} {:<10} RETURN CODE",
                "SEQ", "C", "FROM", "TIME"
            )),
            "lsp-traceroute" => Some(format!(
                "{:>3} {} {:<40} {:<10} {:<6} {:<20} RETURN CODE",
                "HOP", "C", "ADDRESS", "TIME", "MTU", "LABELS"
            )),
            _ => None,
        }
    }

    pub fn line(kind: &str, ev: &Value) -> String {
        match kind {
            "lsp-ping" => format!(
                "{:>5} {} {:<40} {:<10} {}",
                s(ev, "seq"),
                s(ev, "letter"),
                s(ev, "address"),
                time(ev, "rtt_ms"),
                s(ev, "detail")
            )
            .trim_end()
            .to_owned(),
            "lsp-traceroute" => {
                let mut detail = s(ev, "detail");
                let received = s(ev, "received");
                if !received.is_empty() {
                    detail = format!("{detail} ({received})");
                }
                format!(
                    "{:>3} {} {:<40} {:<10} {:<6} {:<20} {}",
                    s(ev, "hop"),
                    s(ev, "letter"),
                    s(ev, "address"),
                    time(ev, "rtt_ms"),
                    s(ev, "mtu"),
                    s(ev, "out_label"),
                    detail
                )
                .trim_end()
                .to_owned()
            }
            _ => String::new(),
        }
    }

    pub fn summary(kind: &str, sum: &Value) -> Vec<String> {
        match kind {
            "lsp-ping" => {
                let st = sum.get("stats").cloned().unwrap_or(Value::Null);
                let mut l = format!(
                    "{}: sent={} received={} packet-loss={}%",
                    s(sum, "fec"),
                    s(&st, "sent"),
                    s(&st, "received"),
                    s(&st, "loss_pct")
                );
                if st.get("min_ms").is_some_and(Value::is_number) {
                    l.push_str(&format!(
                        " min-rtt={} avg-rtt={} max-rtt={}",
                        time(&st, "min_ms"),
                        time(&st, "avg_ms"),
                        time(&st, "max_ms")
                    ));
                }
                let mut out = vec![l];
                for c in sum.get("codes").and_then(Value::as_array).into_iter().flatten() {
                    out.push(format!("  {} x{}: {}", s(c, "letter"), s(c, "count"), s(c, "meaning")));
                }
                out
            }
            "lsp-traceroute" => vec![s(sum, "result")],
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests;
