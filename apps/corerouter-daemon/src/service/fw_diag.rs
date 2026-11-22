//! Firewall diagnosis (G2.1c): live rule counters and the packet trace.
//!
//! On its own thread. The session lock is taken only to ask what to do
//! (O(1)) and to hand the result over (O(rules)); the kernel is read with
//! the lock released:
//!
//! - **counters**: while someone looks (`Session::firewall_counters_wanted`:
//!   a counters or rule-list query in the last 30 s, at most every 2 s), one
//!   nfnetlink dump of table `inet corerouter` (`nft_counters::dump`), its
//!   rules mapped back to ours by their `cr:*N` comment;
//! - **trace**: while `ip.firewall.trace.start` asked for one, the table
//!   `inet corerouter_trace` marks the filter's packets and a netlink
//!   socket reads the kernel's trace events; rule handles are mapped to our
//!   rules through the same dump. Deadline, event cap or `trace.stop` end
//!   it, and the table goes.
//!
//! With `--backend virtual` both are made up from the config (the lab has
//! no kernel table): counters grow at a rate per rule, and the trace sends
//! one packet a second through the packet tester (`ip.firewall.test`).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use corerouter_engine::firewall_diag::{RuleCounter, TraceEvent, TraceJob};
use corerouter_engine::{Shared, lock};
use corerouter_model::ItemId;
use corerouter_model::firewall::Table;

const TICK: Duration = Duration::from_millis(250);

pub(crate) const SERVICE: super::Service = super::Service {
    name: "fw-diag",
    flags: &[],
    topic: "firewall",
    enable: "ip.firewall.counters / ip.firewall.trace.start (on demand)",
    depends: &[],
    start,
};

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let session = ctx.session.clone();
    let lab = lock(&session).backend().starts_with("virtual lab");
    Ok(Box::new(move |health: &super::Health| {
        let mut state = State::new(lab);
        while health.sleep(TICK) {
            health.beat();
            state.counters(&session);
            if let Err(e) = state.trace(&session) {
                health.error(&e);
            }
        }
        state.trace_off();
        Ok(())
    }))
}

/// (table, id) of each kernel rule handle, from the last dump.
type Handles = HashMap<(String, u64), (Table, ItemId)>;

struct State {
    lab: bool,
    started: Instant,
    handles: Handles,
    /// The trace being run: its generation, and the listener (Linux).
    trace_gen: Option<u64>,
    #[cfg(target_os = "linux")]
    listener: Option<corerouter_hal_linux::nft_trace::Listener>,
    lab_next: Instant,
}

impl State {
    fn new(lab: bool) -> Self {
        Self {
            lab,
            started: Instant::now(),
            handles: HashMap::new(),
            trace_gen: None,
            #[cfg(target_os = "linux")]
            listener: None,
            lab_next: Instant::now(),
        }
    }

    fn counters(&mut self, session: &Shared) {
        if !lock(session).firewall_counters_wanted() {
            return;
        }
        let read = if self.lab {
            let cfg = lock(session).store().running().clone();
            Ok(lab_counters(&cfg, self.started.elapsed().as_secs()))
        } else {
            self.read_kernel()
        };
        lock(session).firewall_counters_feed(read);
    }

    /// One dump: counters, and the handle map for the trace.
    #[cfg(target_os = "linux")]
    fn read_kernel(&mut self) -> Result<Vec<RuleCounter>, String> {
        use corerouter_hal_linux::nft_counters::{NFPROTO_INET, dump};
        let rules = dump(NFPROTO_INET, corerouter_firewall::TABLE).map_err(|e| e.to_string())?;
        self.handles.clear();
        let mut out = Vec::with_capacity(rules.len());
        for r in rules {
            let Some((table, id)) =
                corerouter_firewall::nft::rule_of(&r.chain, r.comment.as_deref())
            else {
                continue;
            };
            self.handles.insert((r.chain.clone(), r.handle), (table, id));
            out.push(RuleCounter {
                table,
                id,
                packets: r.packets,
                bytes: r.bytes,
            });
        }
        Ok(out)
    }

    #[cfg(not(target_os = "linux"))]
    fn read_kernel(&mut self) -> Result<Vec<RuleCounter>, String> {
        Err("rule counters need Linux".into())
    }

    fn trace(&mut self, session: &Shared) -> Result<(), String> {
        let job = lock(session).firewall_trace_job();
        match (&job, self.trace_gen) {
            (None, Some(_)) => self.trace_off(),
            (Some(j), cur) if cur != Some(j.generation) => {
                self.trace_off();
                if let Err(e) = self.trace_on(j) {
                    lock(session).firewall_trace_failed(j.generation, &e);
                    return Err(e);
                }
                self.trace_gen = Some(j.generation);
            }
            _ => {}
        }
        let Some(job) = job else {
            return Ok(());
        };
        let events = if self.lab {
            self.lab_trace(session)
        } else {
            self.kernel_events(job.max_events)
        };
        if !lock(session).firewall_trace_push(job.generation, events) {
            self.trace_off();
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn trace_on(&mut self, job: &TraceJob) -> Result<(), String> {
        use corerouter_hal_linux::{nfnl, nft_trace};
        if self.lab {
            return Ok(());
        }
        let net = |a: &Option<corerouter_model::firewall::AddrMatch>| match a {
            Some(corerouter_model::firewall::AddrMatch::Net(n)) => Some((n.addr(), n.prefix_len())),
            _ => None,
        };
        let f = &job.filter;
        let m = nft_trace::Match {
            v6: f.family.map(|x| x == corerouter_model::firewall::Family::Ipv6),
            src: net(&f.src),
            dst: net(&f.dst),
            protocol: f.protocol.map(|p| p.0),
            dport: f.port,
            iif: f.in_interface.clone(),
        };
        // Listen first: the first packets are not lost.
        self.listener = Some(nft_trace::Listener::open().map_err(|e| e.to_string())?);
        nfnl::apply(nfnl::replace(&nft_trace::table(&m), 1), "trace")
            .map_err(|e| e.to_string())?;
        let _ = self.read_kernel();
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn trace_on(&mut self, _job: &TraceJob) -> Result<(), String> {
        if self.lab { Ok(()) } else { Err("the packet trace needs Linux".into()) }
    }

    fn trace_off(&mut self) {
        if self.trace_gen.take().is_none() {
            return;
        }
        #[cfg(target_os = "linux")]
        if !self.lab {
            use corerouter_firewall::program::Family;
            use corerouter_hal_linux::{nfnl, nft_trace};
            self.listener = None;
            let mut b = nfnl::Batch::new(1);
            b.family(Family::Inet);
            b.new_table(nft_trace::TABLE);
            b.del_table(nft_trace::TABLE);
            let _ = nfnl::apply(b, "trace off");
        }
    }

    #[cfg(target_os = "linux")]
    fn kernel_events(&mut self, max: usize) -> Vec<TraceEvent> {
        use corerouter_hal_linux::nft_trace;
        let Some(l) = self.listener.as_mut() else {
            return Vec::new();
        };
        let mut raw = Vec::new();
        if l.recv(200, max.min(5000), &mut raw).is_err() {
            return Vec::new();
        }
        // A handle we do not know: the table changed (a commit); read again.
        let unknown = raw.iter().any(|e| {
            e.table == corerouter_firewall::TABLE
                && e.handle.is_some_and(|h| !self.handles.contains_key(&(e.chain.clone(), h)))
        });
        if unknown {
            let _ = self.read_kernel();
        }
        let now = unix_now();
        let mut names: HashMap<u32, Option<String>> = HashMap::new();
        let mut name = |i: Option<u32>| {
            i.and_then(|i| names.entry(i).or_insert_with(|| nft_trace::ifname(i)).clone())
        };
        raw.into_iter()
            // Our own marking rule says nothing about the firewall.
            .filter(|e| e.table != nft_trace::TABLE)
            .map(|e| {
                let ours = e.table == corerouter_firewall::TABLE;
                let mapped = e.handle.and_then(|h| self.handles.get(&(e.chain.clone(), h)).copied());
                let (table, chain) = match corerouter_firewall::nft::table_of_chain(&e.chain) {
                    Some((t, c)) if ours => (t.name().to_owned(), c.to_owned()),
                    _ => (e.table.clone(), e.chain.clone()),
                };
                TraceEvent {
                    trace: e.id,
                    at: now,
                    table,
                    chain,
                    rule: mapped.map(|(_, id)| id),
                    kind: e.kind,
                    verdict: e.verdict,
                    iif: name(e.iif),
                    oif: name(e.oif),
                    src: e.src,
                    dst: e.dst,
                    protocol: e.protocol,
                    sport: e.sport,
                    dport: e.dport,
                }
            })
            .collect()
    }

    #[cfg(not(target_os = "linux"))]
    fn kernel_events(&mut self, _max: usize) -> Vec<TraceEvent> {
        Vec::new()
    }

    /// The lab: one made-up packet a second through the packet tester.
    fn lab_trace(&mut self, session: &Shared) -> Vec<TraceEvent> {
        if Instant::now() < self.lab_next {
            return Vec::new();
        }
        self.lab_next = Instant::now() + Duration::from_secs(1);
        let mut s = lock(session);
        let Some(job) = s.firewall_trace_job() else {
            return Vec::new();
        };
        let n = self.started.elapsed().as_secs();
        lab_events(&mut s, &job, n)
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The lab's counters: a rate per rule from its id (some rules idle).
fn lab_counters(cfg: &corerouter_model::Config, secs: u64) -> Vec<RuleCounter> {
    let mut out = Vec::new();
    for table in Table::ALL {
        for r in cfg.ip.firewall.rules(table).iter() {
            if r.disabled || r.section {
                continue;
            }
            let rate = match r.id.0 % 5 {
                0 => 0,
                k => u64::from(k) * u64::from(r.id.0 % 7 + 1) * 3,
            };
            let packets = rate * (secs + 60);
            out.push(RuleCounter {
                table,
                id: r.id,
                packets,
                bytes: packets * (200 + u64::from(r.id.0 % 9) * 100),
            });
        }
    }
    out
}

/// The lab's trace: the filter made into one packet, walked by
/// `ip.firewall.test`, each rule it matched one event.
fn lab_events(s: &mut corerouter_engine::Session, job: &TraceJob, n: u64) -> Vec<TraceEvent> {
    use serde_json::json;
    let f = &job.filter;
    // A host inside the filter's prefix (not its network address), else a
    // made-up client; to the router's first address by default.
    let pick = |a: &Option<corerouter_model::firewall::AddrMatch>, def: &str| match a {
        Some(m) => {
            let (lo, hi) = m.bounds();
            match (lo, hi) {
                (std::net::IpAddr::V4(l), std::net::IpAddr::V4(h)) if l != h => {
                    let span = u32::from(h).saturating_sub(u32::from(l)).max(1);
                    std::net::Ipv4Addr::from(u32::from(l).saturating_add((n as u32 % span).max(1))).to_string()
                }
                _ => lo.to_string(),
            }
        }
        None => def.to_owned(),
    };
    let v6 = f.src.as_ref().or(f.dst.as_ref()).is_some_and(|a| a.bounds().0.is_ipv6());
    let own = s
        .store()
        .running()
        .ip
        .addresses
        .iter()
        .find(|a| !a.disabled && a.address.addr().is_ipv6() == v6)
        .map(|a| a.address.addr().to_string());
    let (src, dst) = if v6 {
        (pick(&f.src, "2001:db8:1::50"), pick(&f.dst, own.as_deref().unwrap_or("2001:db8::1")))
    } else {
        (pick(&f.src, "203.0.113.50"), pick(&f.dst, own.as_deref().unwrap_or("192.0.2.1")))
    };
    let protocol = f.protocol.map_or("tcp".to_owned(), |p| p.to_string());
    let iif = f.in_interface.clone().unwrap_or_else(|| "ether1".into());
    let mut p = json!({"src": src, "dst": dst, "protocol": protocol, "in_interface": iif, "running": true});
    if f.protocol.is_none_or(|p| p.has_ports())
        && let Some(o) = p.as_object_mut()
    {
        o.insert("dst_port".into(), json!(f.port.unwrap_or(80)));
    }
    let Ok(way) = s.execute("ip.firewall.test", &p) else {
        return Vec::new();
    };
    let now = unix_now();
    let id = (n as u32).wrapping_mul(2_654_435_761);
    let mut out = Vec::new();
    let ip = |k: &str| at(at(&way, "packet"), k).as_str().and_then(|a| a.parse().ok());
    let base = TraceEvent {
        trace: id,
        at: now,
        table: String::new(),
        chain: String::new(),
        rule: None,
        kind: "rule",
        verdict: String::new(),
        iif: Some(iif),
        oif: at(at(&way, "packet"), "out_interface").as_str().map(str::to_owned),
        src: src.parse().ok().or(ip("src")),
        dst: dst.parse().ok().or(ip("dst")),
        protocol: f.protocol.map(|p| p.0).or(Some(6)),
        sport: Some(40_000),
        dport: f.port.or(Some(80)),
    };
    for st in at(&way, "steps").as_array().into_iter().flatten() {
        if !at(st, "skipped").is_null() {
            continue;
        }
        let (table, chain) = (at(st, "table").as_str().unwrap_or(""), at(st, "chain").as_str().unwrap_or(""));
        let decided = at(st, "rule").as_str().map(str::to_owned);
        for h in at(st, "hits").as_array().into_iter().flatten() {
            let rid: Option<ItemId> = at(h, "id").as_str().and_then(|i| i.parse().ok());
            let is_decider = at(h, "id").as_str() == decided.as_deref();
            out.push(TraceEvent {
                table: table.into(),
                chain: at(h, "chain").as_str().unwrap_or(chain).into(),
                rule: rid,
                verdict: if is_decider {
                    at(st, "verdict").as_str().unwrap_or("accept").into()
                } else {
                    "continue".into()
                },
                ..base.clone()
            });
        }
        if decided.is_none() {
            out.push(TraceEvent {
                table: table.into(),
                chain: chain.into(),
                kind: "policy",
                verdict: "accept".into(),
                ..base.clone()
            });
        }
    }
    out
}

/// `v[key]` without indexing (missing = null).
fn at<'a>(v: &'a serde_json::Value, key: &str) -> &'a serde_json::Value {
    v.get(key).unwrap_or(&serde_json::Value::Null)
}
