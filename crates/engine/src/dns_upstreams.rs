//! G6.8 DNS Lookup › Upstreams (`tool.dns.upstreams`): a benchmark of
//! every server the router may ask — `ip.dns servers`, `use_doh_server` and
//! each forwarders group's servers — like `dnseval` (dnsdiag) and namebench,
//! with a recommendation of which to keep and which to drop.
//!
//! - `count` queries each (200 by default), popular names and random names
//!   under them in turn: a popular one is likely cached at the server, a
//!   random one never is (it measures the server's own recursion), as
//!   namebench mixes cache hits and misses;
//! - p50 and p99 of the answers, loss and the share of SERVFAIL;
//! - transport: UDP, TCP (asked once over TCP: the fallback of a truncated
//!   answer, RFC 7766 §5), EDNS and the buffer the server offers (a reply
//!   without OPT to a query with it breaks RFC 6891 §7, RFC 8906 §8.2),
//!   and DoT/DoH for the encrypted servers configured;
//! - Check hijack (plain servers): two random names that cannot exist —
//!   an answer instead of NXDOMAIN is `nxdomain-hijack` (namebench's test);
//!   and the resolver that reaches the authoritative servers, by the names
//!   that tell it (`whoami.ds.akahelp.net` TXT, Akamai; `o-o.myaddr.l.google.com`
//!   TXT, Google): when that resolver is from the client's own network
//!   (the AS of this router's public address, which Akamai's answer also
//!   gives) and not the server's, the ISP answered instead (`proxy`; Liu et
//!   al., "Who Is Answering My Queries", USENIX Security 2018). From another
//!   network that is not the client's it is told, not judged: Quad9 and
//!   others leave from their hosting partners' networks (seen in the lab:
//!   9.9.9.9 from AS7195). A server on a private or CGNAT address forwards
//!   to someone else: told, not judged.
//!
//! A server that times out [`DOWN_AFTER`] times in a row before any answer
//! is not asked again: the rest of its queries count as lost (one dead
//! server must not cost `count` timeouts).
//!
//! Events (kind `dns-upstreams`): `{kind: "progress", done, total}`, then
//! `{kind: "bench", …}` per server; the summary `{mode: "upstreams",
//! servers, recommend}`, each advice `{kind: use|remove|note, server, why,
//! args, text}` (`why`: an id of [`TEXTS`]).

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::Arc;

use corerouter_hal::SharedProber;
use corerouter_proto_dns::dig::{self, Ask, Name, RecordType, Reply};
use serde_json::{Value, json};

use crate::dns::DnsBackend;
use crate::dns_lookup::{LookupServer, bytes_for, is_timeout, origin_as};
use crate::tasks::TaskCtx;
use crate::tools::stats::{Outcome, Stats};

pub const DEFAULT_COUNT: u64 = 200;
pub const MAX_COUNT: u64 = 2000;
/// Queries in flight at once, all servers together (each is a thread of the
/// daemon while it waits).
const IN_FLIGHT: usize = 48;
/// Timeouts in a row, before any answer, that mark a server down.
const DOWN_AFTER: u64 = 6;
/// Advice thresholds.
const BAD_LOSS_PCT: f64 = 10.0;
const BAD_SERVFAIL_PCT: f64 = 10.0;
/// Slower than this many times the best p50 (and [`SLOW_MIN_MS`] more) is slow.
const SLOW_FACTOR: f64 = 3.0;
const SLOW_MIN_MS: f64 = 20.0;

/// Names most resolvers have cached (and that exist): the benchmark asks
/// them and random names under them.
pub const POPULAR: [&str; 24] = [
    "google.com", "youtube.com", "facebook.com", "instagram.com", "whatsapp.net",
    "wikipedia.org", "amazon.com", "netflix.com", "microsoft.com", "apple.com",
    "cloudflare.com", "github.com", "linkedin.com", "twitter.com", "tiktok.com",
    "globo.com", "uol.com.br", "mercadolivre.com.br", "gov.br", "bb.com.br",
    "itau.com.br", "nubank.com.br", "terra.com.br", "registro.br",
];

/// Names that tell the resolver's address as the authoritative server saw it.
pub const WHOAMI: [&str; 2] = ["whoami.ds.akahelp.net", "o-o.myaddr.l.google.com"];

/// The advice's texts, by id (the GUI words them in its languages).
pub const TEXTS: &[(&str, &str)] = &[
    ("down", "{server} never answered: remove it"),
    ("forwarder", "{server} is a forwarder on a private address: its answers come from {egress}"),
    ("hijack", "{server} answers names that do not exist ({data}) instead of NXDOMAIN: remove it"),
    ("loss", "{server} lost {loss}% of the queries: remove it"),
    ("no-edns", "{server} drops EDNS (no OPT in its replies): DNSSEC and large answers fail (RFC 8906)"),
    ("no-tcp", "{server} does not answer over TCP: truncated answers fail (RFC 7766)"),
    ("other-network", "{server} reaches the authoritative servers from {egress} ({egress_as}), outside its own network ({server_as}): an anycast partner, or a proxy (check it)"),
    ("proxy", "{server} is answered by {egress} ({egress_as}), from the client's own network: a proxy on the way"),
    ("servfail", "{server} answered SERVFAIL to {servfail}% of the queries: remove it"),
    ("slow", "{server} is slow: p50 {p50} ms against {best} ms of the best"),
    ("use", "use {server}: p50 {p50} ms, p99 {p99} ms, no loss"),
];

/// The English template of `id`.
pub fn text(id: &str) -> &'static str {
    TEXTS
        .binary_search_by(|(k, _)| (*k).cmp(id))
        .ok()
        .and_then(|i| TEXTS.get(i))
        .map_or("", |(_, t)| *t)
}

/// One server to measure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub to: LookupServer,
    /// The forwarders groups that list it (empty: `ip.dns`).
    pub groups: Vec<String>,
}

/// The benchmark, checked.
#[derive(Debug, Clone)]
pub(crate) struct Bench {
    pub targets: Vec<Target>,
    pub count: u64,
    pub hijack: bool,
    /// Seed of the random names (anything that changes between runs).
    pub seed: u64,
}

/// xorshift64*: random labels (no `rand` in the engine: wasm, no OS).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0.max(1);
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// `len` lowercase letters and digits, a letter first.
    fn label(&mut self, len: usize) -> String {
        const ABC: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
        (0..len)
            .map(|i| {
                let span = if i == 0 { 26 } else { ABC.len() as u64 };
                char::from(ABC.get((self.next() % span) as usize).copied().unwrap_or(b'x'))
            })
            .collect()
    }
}

/// What one server gave.
#[derive(Debug, Default)]
struct Tally {
    stats: Stats,
    servfail: u64,
    /// Timeouts in a row before any answer.
    silent: u64,
    down: bool,
    edns: Option<Option<u16>>,
}

impl Tally {
    fn record(&mut self, got: &Result<(Reply, u64), String>) {
        self.stats.sent += 1;
        match got {
            Ok((r, ms)) => {
                self.silent = 0;
                self.stats.record(Outcome::Ok, Some(*ms as f64));
                if r.status == "SERVFAIL" {
                    self.servfail += 1;
                }
                if self.edns.is_none() {
                    self.edns = Some(r.edns.map(|e| e.udp));
                }
            }
            Err(e) => {
                let timeout = is_timeout(e);
                self.stats.record(if timeout { Outcome::Timeout } else { Outcome::Error }, None);
                if self.stats.received == 0 {
                    self.silent += 1;
                    self.down = self.silent >= DOWN_AFTER;
                }
            }
        }
    }

    fn pct(&self, n: u64) -> f64 {
        let done = self.stats.finished();
        if done == 0 {
            return 0.0;
        }
        (n as f64 * 1000.0 / done as f64).round() / 10.0
    }
}

fn ask(name: &str, rtype: RecordType) -> Option<Ask> {
    let mut n = Name::from_ascii(name).ok()?;
    n.set_fqdn(true);
    Some(Ask {
        name: n,
        rtype,
        recursion: true,
        dnssec: false,
    })
}

fn exchange(
    backend: &Arc<dyn DnsBackend>,
    asks: &[(LookupServer, Vec<u8>)],
    tcp: bool,
) -> Vec<Result<(Reply, u64), String>> {
    backend
        .exchange_all(asks, tcp)
        .into_iter()
        .map(|got| got.and_then(|x| dig::decode(&x.bytes).map(|r| (r, x.ms))))
        .collect()
}

/// Whether `ip` is a private, CGNAT or loopback address (a LAN forwarder).
fn private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || (o[0] == 100 && (64..128).contains(&o[1]))
        }
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00 || (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// What the `WHOAMI` answers say: the resolver addresses, and the
/// client's (this router's public address as the resolver passed it on).
/// Akamai's TXT is key/value pairs (`"ns" "<resolver>"`, `"ip"
/// "<client>"`, `"ecs" "<net>"`); Google's is the resolver's address alone
/// (and `"edns0-client-subnet <net>"`, skipped).
fn egress(r: &Reply) -> (Vec<IpAddr>, Vec<IpAddr>) {
    let (mut resolvers, mut clients) = (Vec::new(), Vec::new());
    let add = |list: &mut Vec<IpAddr>, text: &str| {
        if let Ok(ip) = text.trim().parse::<IpAddr>()
            && !list.contains(&ip)
        {
            list.push(ip);
        }
    };
    for row in r.answer.iter().filter(|x| x.rtype == "TXT") {
        // The quoted strings of the presentation form.
        let strings: Vec<&str> = row.data.split('"').skip(1).step_by(2).collect();
        if let [one] = strings.as_slice() {
            add(&mut resolvers, one);
            continue;
        }
        for pair in strings.chunks(2) {
            match pair {
                ["ns", v] => add(&mut resolvers, v),
                ["ip", v] => add(&mut clients, v),
                _ => {}
            }
        }
    }
    (resolvers, clients)
}

/// Runs `b` (the task's body).
pub(crate) fn run(
    ctx: &TaskCtx,
    backend: &Arc<dyn DnsBackend>,
    prober: Option<&SharedProber>,
    b: &Bench,
) -> Result<(), String> {
    ctx.emit(json!({"kind": "begin", "mode": "upstreams"}));
    // The clock and the random query ids (hickory's) seed the names.
    let mut seed = b.seed ^ 0x9e37_79b9_7f4a_7c15 ^ ctx.now().as_nanos() as u64;
    if let Some(a) = ask("seed.invalid", RecordType::A) {
        for _ in 0..4 {
            let id = dig::query(&a, None).map_or(0, |(id, _)| id);
            seed = seed.rotate_left(16) ^ u64::from(id);
        }
    }
    let mut rng = Rng(seed);
    let mut tallies: Vec<Tally> = b.targets.iter().map(|_| Tally::default()).collect();
    let per_round = (IN_FLIGHT / b.targets.len().max(1)).max(1) as u64;
    let total = b.count.saturating_mul(b.targets.len() as u64);
    let mut i = 0u64;
    while i < b.count {
        if ctx.stopped() {
            break;
        }
        let n = per_round.min(b.count - i);
        let mut asks = Vec::new();
        let mut owner = Vec::new();
        for k in 0..n {
            let base = POPULAR.get(((i + k) / 2) as usize % POPULAR.len()).copied().unwrap_or("example.com");
            let name = if (i + k).is_multiple_of(2) {
                base.to_owned()
            } else {
                format!("{}.{base}", rng.label(12))
            };
            let Some(a) = ask(&name, RecordType::A) else { continue };
            for (t, target) in b.targets.iter().enumerate() {
                if tallies.get(t).is_some_and(|x| x.down) {
                    continue;
                }
                asks.push((target.to.clone(), bytes_for(&a, &target.to)?));
                owner.push(t);
            }
        }
        for (t, got) in owner.into_iter().zip(exchange(backend, &asks, false)) {
            if let Some(x) = tallies.get_mut(t) {
                x.record(&got);
            }
        }
        i += n;
        // A dead server's queries count as lost without waiting for them.
        for x in tallies.iter_mut().filter(|x| x.down) {
            while x.stats.sent < i {
                x.stats.sent += 1;
                x.stats.record(Outcome::Timeout, None);
            }
        }
        let done: u64 = tallies.iter().map(|x| x.stats.sent).sum();
        ctx.emit(json!({"kind": "progress", "done": done, "total": total}));
    }
    // TCP, once per plain server that answered.
    let popular = ask(POPULAR.first().copied().unwrap_or("google.com"), RecordType::A)
        .ok_or("no popular name")?;
    let plain: Vec<usize> = b
        .targets
        .iter()
        .enumerate()
        .filter(|(t, x)| matches!(x.to, LookupServer::Plain(_)) && tallies.get(*t).is_some_and(|y| y.stats.received > 0))
        .map(|(t, _)| t)
        .collect();
    let mut tcp: BTreeMap<usize, bool> = BTreeMap::new();
    let asks: Vec<(LookupServer, Vec<u8>)> = plain
        .iter()
        .filter_map(|t| b.targets.get(*t))
        .map(|x| bytes_for(&popular, &x.to).map(|q| (x.to.clone(), q)))
        .collect::<Result<_, _>>()?;
    for (t, got) in plain.iter().zip(exchange(backend, &asks, true)) {
        tcp.insert(*t, got.is_ok());
    }
    let hijacks = if b.hijack {
        check_hijack(ctx, backend, prober, b, &plain, &mut rng)?
    } else {
        BTreeMap::new()
    };
    let mut rows = Vec::new();
    for (t, (target, x)) in b.targets.iter().zip(&tallies).enumerate() {
        let s = x.stats.to_json();
        let transport = match &target.to {
            LookupServer::Secure(url) if url.to_ascii_lowercase().starts_with("tls://") => "DoT",
            LookupServer::Secure(_) => "DoH",
            _ => "UDP",
        };
        let mut row = json!({
            "kind": "bench",
            "server": target.to.label(),
            "groups": target.groups,
            "transport": transport,
            "sent": x.stats.sent,
            "answered": x.stats.received,
            "loss_pct": pick(&s, "loss_pct"),
            "servfail_pct": x.pct(x.servfail),
            "p50_ms": pick(&s, "p50_ms"),
            "p99_ms": pick(&s, "p99_ms"),
            "avg_ms": pick(&s, "avg_ms"),
            "down": x.down,
            "tcp": tcp.get(&t),
            "edns": x.edns.map(|e| e.is_some()),
            "edns_udp": x.edns.flatten(),
        });
        if let (Value::Object(o), Some(Value::Object(h))) = (&mut row, hijacks.get(&t)) {
            o.extend(h.clone());
        }
        ctx.emit(row.clone());
        rows.push(row);
    }
    let recommend = advise(&rows);
    ctx.summary(json!({"mode": "upstreams", "servers": rows, "recommend": recommend}));
    Ok(())
}

/// NXDOMAIN and whoami for each plain server in `plain`: by target, the
/// fields `nxdomain_hijack`, `nx_data`, `egress`, `egress_as`, `server_as`,
/// `proxy`, `forwarder`.
fn check_hijack(
    ctx: &TaskCtx,
    backend: &Arc<dyn DnsBackend>,
    prober: Option<&SharedProber>,
    b: &Bench,
    plain: &[usize],
    rng: &mut Rng,
) -> Result<BTreeMap<usize, Value>, String> {
    let mut asks = Vec::new();
    let mut what = Vec::new();
    for t in plain {
        let Some(target) = b.targets.get(*t) else { continue };
        for _ in 0..2 {
            // RFC 2606/6761 names would be answered by the router's own
            // rules; a long random .com name exists nowhere.
            let name = format!("{}.com", rng.label(20));
            if let Some(a) = ask(&name, RecordType::A) {
                asks.push((target.to.clone(), bytes_for(&a, &target.to)?));
                what.push((*t, "nx"));
            }
        }
        for name in WHOAMI {
            if let Some(a) = ask(name, RecordType::TXT) {
                asks.push((target.to.clone(), bytes_for(&a, &target.to)?));
                what.push((*t, "whoami"));
            }
        }
    }
    let mut nx: BTreeMap<usize, Vec<String>> = BTreeMap::new();
    let mut seen: BTreeMap<usize, Vec<IpAddr>> = BTreeMap::new();
    // This router's public address, as the resolvers passed it on.
    let mut clients: Vec<IpAddr> = Vec::new();
    for ((t, kind), got) in what.into_iter().zip(exchange(backend, &asks, false)) {
        let Ok((r, _)) = got else { continue };
        match kind {
            "nx" if r.status == "NOERROR" && !r.answer.is_empty() => {
                let e = nx.entry(t).or_default();
                e.extend(r.answer.iter().map(|x| format!("{} {}", x.rtype, x.data)));
            }
            "whoami" => {
                let (resolvers, client) = egress(&r);
                let e = seen.entry(t).or_default();
                for ip in resolvers {
                    if !e.contains(&ip) {
                        e.push(ip);
                    }
                }
                for ip in client {
                    if !clients.contains(&ip) {
                        clients.push(ip);
                    }
                }
            }
            _ => {}
        }
    }
    // The AS of every server and resolver address seen.
    let mut addrs: Vec<IpAddr> = seen.values().flatten().copied().chain(clients.iter().copied()).collect();
    for t in plain {
        if let Some(Target { to: LookupServer::Plain(ip), .. }) = b.targets.get(*t) {
            addrs.push(*ip);
        }
    }
    addrs.sort();
    addrs.dedup();
    let owners = origin_as(ctx, prober, &addrs);
    let asn = |ip: &IpAddr| owners.get(ip).map(|a| a.asn);
    // The client's network: an ISP that intercepts answers from it.
    let client_as: Vec<u32> = clients.iter().filter_map(asn).collect();
    let mut out = BTreeMap::new();
    for t in plain {
        let Some(Target { to: LookupServer::Plain(server), .. }) = b.targets.get(*t) else { continue };
        let egress: Vec<IpAddr> = seen.get(t).cloned().unwrap_or_default();
        let server_as = asn(server);
        let forwarder = private(*server);
        // Judged only with what is known: the server's AS and each egress's.
        let foreign: Vec<&IpAddr> = egress
            .iter()
            .filter(|ip| *ip != server && !private(**ip))
            .filter(|ip| match (server_as, asn(ip)) {
                (Some(a), Some(b)) => a != b,
                _ => false,
            })
            .collect();
        // Liu et al. 2018: interception answers from the client's own
        // network. Another network that is not the client's is told, not
        // judged (Quad9 and others leave from partners' networks).
        let intercepted: Vec<&&IpAddr> = foreign
            .iter()
            .filter(|ip| asn(ip).is_some_and(|a| client_as.contains(&a) && Some(a) != server_as))
            .collect();
        let proxy = !forwarder && !intercepted.is_empty();
        let other_network = !forwarder && !proxy && !foreign.is_empty();
        // The one that tells: an intercepting resolver, else a foreign
        // one, else the first seen.
        let shown = intercepted
            .first()
            .map(|ip| ***ip)
            .or(foreign.first().map(|ip| **ip))
            .or(egress.first().copied());
        let data = nx.get(t).cloned().unwrap_or_default();
        out.insert(
            *t,
            json!({
                "nxdomain_hijack": !data.is_empty(),
                "nx_data": data,
                "egress": egress,
                "egress_shown": shown,
                "egress_as": shown.as_ref().and_then(asn),
                "server_as": server_as,
                "proxy": proxy,
                "other_network": other_network,
                "client": clients,
                "client_as": client_as.first(),
                "forwarder": forwarder,
            }),
        );
    }
    Ok(out)
}

/// `v[k]`, or null.
fn pick(v: &Value, k: &str) -> Value {
    v.get(k).cloned().unwrap_or(Value::Null)
}

fn num(v: &Value, k: &str) -> Option<f64> {
    v.get(k).and_then(Value::as_f64)
}

fn advice(kind: &str, server: &str, why: &str, args: &[(&str, String)]) -> Value {
    let mut t = text(why).to_owned();
    let mut a = serde_json::Map::new();
    a.insert("server".into(), json!(server));
    t = t.replace("{server}", server);
    for (k, v) in args {
        t = t.replace(&format!("{{{k}}}"), v);
        a.insert((*k).to_owned(), json!(v));
    }
    json!({"kind": kind, "server": server, "why": why, "args": a, "text": t})
}

/// Which servers to keep and which to drop, and why: a server that hijacks,
/// is proxied, never answers, loses or fails too much goes; of the rest,
/// one much slower than the best of its kind (plain or encrypted) goes too,
/// and the two fastest that stay (p50, then p99) are the ones to use.
pub(crate) fn advise(rows: &[Value]) -> Vec<Value> {
    let mut out = Vec::new();
    let mut good: Vec<&Value> = Vec::new();
    let f = |x: f64| format!("{}", (x * 10.0).round() / 10.0);
    for r in rows {
        let server = r.get("server").and_then(Value::as_str).unwrap_or("?");
        if r["down"] == true || r["answered"] == 0 {
            out.push(advice("remove", server, "down", &[]));
        } else if r["nxdomain_hijack"] == true {
            let mut data: Vec<String> = r["nx_data"].as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_owned).collect();
            data.dedup();
            data.truncate(2);
            out.push(advice("remove", server, "hijack", &[("data", data.join(", "))]));
        } else if r["proxy"] == true {
            let egress = r["egress_shown"].as_str().unwrap_or("?").to_owned();
            let asn = r["egress_as"].as_u64().map_or("AS?".to_owned(), |a| format!("AS{a}"));
            out.push(advice("remove", server, "proxy", &[("egress", egress), ("egress_as", asn)]));
        } else if num(r, "loss_pct").unwrap_or(0.0) >= BAD_LOSS_PCT {
            out.push(advice("remove", server, "loss", &[("loss", f(num(r, "loss_pct").unwrap_or(0.0)))]));
        } else if num(r, "servfail_pct").unwrap_or(0.0) >= BAD_SERVFAIL_PCT {
            out.push(advice("remove", server, "servfail", &[("servfail", f(num(r, "servfail_pct").unwrap_or(0.0)))]));
        } else {
            good.push(r);
        }
    }
    good.sort_by(|a, b| {
        let key = |r: &Value| (num(r, "p50_ms").unwrap_or(f64::MAX), num(r, "p99_ms").unwrap_or(f64::MAX));
        let (x, y) = (key(a), key(b));
        x.0.total_cmp(&y.0).then(x.1.total_cmp(&y.1))
    });
    // Slow against the best of its kind: DoH/DoT pay for privacy with a
    // handshake, and are compared among themselves.
    let encrypted = |r: &Value| matches!(r.get("transport").and_then(Value::as_str), Some("DoH" | "DoT"));
    let best_of = |enc: bool| {
        good.iter()
            .filter(|r| encrypted(r) == enc)
            .filter_map(|r| num(r, "p50_ms"))
            .fold(f64::MAX, f64::min)
    };
    let (best_plain, best_encrypted) = (best_of(false), best_of(true));
    for (i, r) in good.iter().enumerate() {
        let server = r.get("server").and_then(Value::as_str).unwrap_or("?");
        let p50 = num(r, "p50_ms").unwrap_or(0.0);
        let best = if encrypted(r) { best_encrypted } else { best_plain };
        let slow = p50 > best && p50 >= best * SLOW_FACTOR && p50 >= best + SLOW_MIN_MS;
        if slow {
            out.push(advice("remove", server, "slow", &[("p50", f(p50)), ("best", f(best))]));
        } else if i < 2 {
            out.push(advice("use", server, "use", &[("p50", f(p50)), ("p99", f(num(r, "p99_ms").unwrap_or(0.0)))]));
        }
    }
    // Facts worth knowing about the servers that stay.
    let gone: Vec<String> = out
        .iter()
        .filter(|a| a["kind"] == "remove" && a["why"] != "slow")
        .filter_map(|a| a["server"].as_str().map(str::to_owned))
        .collect();
    for r in rows {
        let server = r.get("server").and_then(Value::as_str).unwrap_or("?");
        if r["answered"] == 0 || gone.iter().any(|g| g == server) {
            continue;
        }
        if r["tcp"] == false {
            out.push(advice("note", server, "no-tcp", &[]));
        }
        if r["edns"] == false {
            out.push(advice("note", server, "no-edns", &[]));
        }
        if r["other_network"] == true {
            let egress = r["egress_shown"].as_str().unwrap_or("?").to_owned();
            let asn = |k: &str| r[k].as_u64().map_or("AS?".to_owned(), |a| format!("AS{a}"));
            out.push(advice("note", server, "other-network", &[("egress", egress), ("egress_as", asn("egress_as")), ("server_as", asn("server_as"))]));
        }
        let egress: Vec<String> = r["egress"].as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_owned).collect();
        if r["forwarder"] == true && !egress.is_empty() {
            out.push(advice("note", server, "forwarder", &[("egress", egress.join(", "))]));
        }
    }
    out
}

fn s(v: &Value, k: &str) -> String {
    match v.get(k) {
        Some(Value::String(x)) => x.clone(),
        Some(Value::Null) | None => "-".to_owned(),
        Some(x) => x.to_string(),
    }
}

/// Terminal text of an event.
pub fn text_line(ev: &Value) -> String {
    match ev.get("kind").and_then(Value::as_str) {
        Some("begin") => header(),
        Some("progress") => format!(";; {}/{} queries", s(ev, "done"), s(ev, "total")),
        Some("bench") => {
            let mut flags = Vec::new();
            for (k, label) in [("nxdomain_hijack", "NXDOMAIN-HIJACK"), ("proxy", "PROXY"), ("down", "DOWN")] {
                if ev[k] == true {
                    flags.push(label.to_owned());
                }
            }
            if ev["other_network"] == true {
                flags.push(format!("other-net=AS{}", s(ev, "egress_as")));
            }
            if ev["tcp"] == false {
                flags.push("no-tcp".into());
            }
            match ev["edns"].as_bool() {
                Some(true) => flags.push(format!("edns={}", s(ev, "edns_udp"))),
                Some(false) => flags.push("no-edns".into()),
                None => {}
            }
            format!(
                "{:<40} {:<4} {:>7} {:>7} {:>6} {:>9}  {}",
                s(ev, "server"),
                s(ev, "transport"),
                s(ev, "p50_ms"),
                s(ev, "p99_ms"),
                format!("{}%", s(ev, "loss_pct")),
                format!("{}%", s(ev, "servfail_pct")),
                flags.join(" ")
            )
            .trim_end()
            .to_owned()
        }
        _ => ev.to_string(),
    }
}

pub fn header() -> String {
    format!("{:<40} {:<4} {:>7} {:>7} {:>6} {:>9}  CHECKS", "SERVER", "VIA", "P50", "P99", "LOSS", "SERVFAIL")
}

/// The advice, one line each.
pub fn summary_lines(summary: &Value) -> Vec<String> {
    summary
        .get("recommend")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|a| format!(";; {}: {}", s(a, "kind"), s(a, "text")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn texts_are_sorted() {
        for w in TEXTS.windows(2) {
            if let [(a, _), (b, _)] = w {
                assert!(a < b, "{a} before {b}");
            }
        }
    }

    #[test]
    fn whoami_answers_name_the_resolver() {
        let row = |data: &str| dig::Row { name: "x.".into(), ttl: 60, class: "IN".into(), rtype: "TXT".into(), data: data.into() };
        let r = Reply {
            id: 0,
            opcode: "QUERY".into(),
            status: "NOERROR".into(),
            flags: Vec::new(),
            question: None,
            answer: vec![
                row("\"ip\" \"170.79.76.98\""),
                row("\"ns\" \"172.71.10.5\" \"ip\" \"170.79.76.99\""),
                row("\"ecs\" \"170.79.76.0/24/24\""),
                row("\"edns0-client-subnet 198.51.100.0/24\""),
                row("\"2001:db8::53\""),
            ],
            authority: Vec::new(),
            additional: Vec::new(),
            edns: None,
            size: 0,
        };
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert_eq!(egress(&r), (vec![ip("172.71.10.5"), ip("2001:db8::53")], vec![ip("170.79.76.98"), ip("170.79.76.99")]));
    }

    #[test]
    fn random_labels_differ_and_are_valid() {
        let mut r = Rng(42);
        let (a, b) = (r.label(12), r.label(12));
        assert_ne!(a, b);
        assert!(a.len() == 12 && a.chars().next().unwrap().is_ascii_lowercase());
        assert!(a.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        assert!(private("100.64.1.1".parse().unwrap()) && private("192.168.1.1".parse().unwrap()));
        assert!(!private("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn advice_keeps_the_fast_and_drops_the_bad() {
        let row = |server: &str, p50: f64, loss: f64| json!({"server": server, "answered": 100, "down": false,
            "p50_ms": p50, "p99_ms": p50 * 2.0, "loss_pct": loss, "servfail_pct": 0.0, "tcp": true, "edns": true});
        let mut hijacker = row("192.0.2.66", 5.0, 0.0);
        hijacker["nxdomain_hijack"] = json!(true);
        hijacker["nx_data"] = json!(["A 203.0.113.66"]);
        let mut no_tcp = row("192.0.2.4", 15.0, 0.0);
        no_tcp["tcp"] = json!(false);
        let rows = [
            row("192.0.2.1", 10.0, 0.0),
            row("192.0.2.2", 12.0, 0.0),
            row("192.0.2.3", 90.0, 0.0),
            {
                // Encrypted: compared with its own kind, not with UDP.
                let mut doh = row("https://dns.example/dns-query", 150.0, 0.0);
                doh["transport"] = json!("DoH");
                doh
            },
            row("192.0.2.5", 11.0, 25.0),
            hijacker,
            json!({"server": "192.0.2.9", "answered": 0, "down": true}),
            no_tcp,
        ];
        let a = advise(&rows);
        let said: Vec<(String, String, String)> = a.iter().map(|x| (s(x, "kind"), s(x, "server"), s(x, "why"))).collect();
        let has = |k: &str, srv: &str, why: &str| said.contains(&(k.into(), srv.into(), why.into()));
        assert!(has("use", "192.0.2.1", "use") && has("use", "192.0.2.2", "use"), "{said:?}");
        assert!(has("remove", "192.0.2.3", "slow"));
        assert!(!said.iter().any(|x| x.1 == "https://dns.example/dns-query" && x.0 == "remove"), "{said:?}");
        assert!(has("remove", "192.0.2.5", "loss"));
        assert!(has("remove", "192.0.2.66", "hijack"), "fast, but lies");
        assert!(has("remove", "192.0.2.9", "down"));
        assert!(has("note", "192.0.2.4", "no-tcp"));
        let hj = a.iter().find(|x| x["why"] == "hijack").unwrap();
        assert_eq!(hj["text"], "192.0.2.66 answers names that do not exist (A 203.0.113.66) instead of NXDOMAIN: remove it");
    }
}
