//! Statistics (G4.1e, `ip.dns.statistics.print`): what the forwarder did
//! with every query — which stage answered (cache, static, upstream,
//! stale, refused, limit…), the response codes, the record types asked,
//! the clients that ask most and the upstream servers that answered.
//!
//! Only an `after` hook: it sees every reply, drops included, once the
//! chain is done. `handle` never decides anything; the stage sits last so
//! it costs nothing on the way down.
//!
//! Bounded memory under a flood from spoofed sources: at most
//! [`MAX_CLIENTS`] clients are kept. Past that, the client with the fewest
//! queries makes room (Space-Saving, Metwally et al. 2005): the newcomer
//! starts from that count, so the top of the list is right and each count
//! is off by at most its `error`.

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::sync::Mutex;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;

use crate::resolver::{Source, Transport};
use crate::server::{Forwarder, Query, Reply, Stage, Step};

pub(crate) const STAGE: Stage = Stage {
    name: "statistics",
    order: 100,
    handle,
    after: Some(after),
};

/// Clients counted one by one.
pub const MAX_CLIENTS: usize = 1024;
/// Distinct record types counted; the rest go under `other`.
const MAX_TYPES: usize = 64;
/// Upstream servers counted (static FWD entries can name others).
const MAX_UPSTREAMS: usize = 64;

/// One client's counts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ClientStats {
    pub queries: u64,
    /// Refused (ACL, limit over TCP) or dropped (limit over UDP).
    pub refused: u64,
    /// Space-Saving: how many of `queries` may belong to clients it
    /// replaced (0 while the table never filled up).
    pub error: u64,
}

/// The counts since the last reset.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counters {
    pub queries: u64,
    pub udp: u64,
    pub tcp: u64,
    /// Queries per stage that answered, by [`category`].
    pub answered: BTreeMap<&'static str, u64>,
    /// Replies per response code (`noerror`, `nxdomain`, … `dropped`).
    pub rcodes: BTreeMap<&'static str, u64>,
    /// Queries per record type asked (its code; [`Snapshot::types`] names
    /// them), at most `MAX_TYPES` of them.
    pub types: BTreeMap<u16, u64>,
    /// Queries of types past `MAX_TYPES`.
    pub types_other: u64,
    /// Client answers per upstream server.
    pub upstreams: BTreeMap<IpAddr, u64>,
    /// Clients that had to replace another (the table was full).
    pub clients_replaced: u64,
    clients: HashMap<IpAddr, ClientStats>,
}

/// A copy to show: the counters and the `top` clients.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub counters: Counters,
    /// Clients tracked now.
    pub clients_tracked: usize,
    /// Most queries first.
    pub top_clients: Vec<(IpAddr, ClientStats)>,
}

impl Snapshot {
    /// Queries per record type by name (`A`, `AAAA`, `TYPE65534`…), most
    /// first; the types past the limit as `other`.
    pub fn types(&self) -> Vec<(String, u64)> {
        let c = &self.counters;
        let mut out: Vec<(String, u64)> = c
            .types
            .iter()
            .map(|(t, n)| (RecordType::from(*t).to_string(), *n))
            .collect();
        if c.types_other > 0 {
            out.push(("other".to_owned(), c.types_other));
        }
        out.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        out
    }
}

/// The forwarder's statistics (`f.state::<Statistics>()`).
#[derive(Debug, Default)]
pub struct Statistics(Mutex<Counters>);

impl Statistics {
    pub fn snapshot(&self, top: usize) -> Snapshot {
        let c = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let mut top_clients: Vec<(IpAddr, ClientStats)> =
            c.clients.iter().map(|(ip, s)| (*ip, *s)).collect();
        top_clients.sort_by(|a, b| b.1.queries.cmp(&a.1.queries).then(a.0.cmp(&b.0)));
        top_clients.truncate(top);
        let mut counters = c.clone();
        let clients_tracked = counters.clients.len();
        counters.clients = HashMap::new();
        Snapshot {
            counters,
            clients_tracked,
            top_clients,
        }
    }

    /// Back to zero (`ip.dns.statistics.reset`).
    pub fn reset(&self) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Counters::default();
    }

    fn record(&self, q: &Query, r: &Reply) {
        let what = category(q.answered_by, q.source.as_ref());
        let rcode = if q.dropped() { "dropped" } else { rcode(r.rcode) };
        let refused = q.dropped() || r.rcode == ResponseCode::Refused;
        let mut c = self.0.lock().unwrap_or_else(|e| e.into_inner());
        c.queries += 1;
        if q.tcp {
            c.tcp += 1;
        } else {
            c.udp += 1;
        }
        *c.answered.entry(what).or_default() += 1;
        *c.rcodes.entry(rcode).or_default() += 1;
        let t = u16::from(q.qtype);
        if c.types.contains_key(&t) || c.types.len() < MAX_TYPES {
            *c.types.entry(t).or_default() += 1;
        } else {
            c.types_other += 1;
        }
        if let Some(Source::Server(ip)) = q.source
            && what == "upstream"
            && (c.upstreams.contains_key(&ip) || c.upstreams.len() < MAX_UPSTREAMS)
        {
            *c.upstreams.entry(ip).or_default() += 1;
        }
        c.client(q.client, refused);
    }
}

impl Counters {
    fn client(&mut self, ip: IpAddr, refused: bool) {
        if !self.clients.contains_key(&ip) && self.clients.len() >= MAX_CLIENTS {
            // Space-Saving: the smallest count makes room.
            let Some((&old, &min)) = self.clients.iter().min_by_key(|(_, s)| s.queries) else {
                return;
            };
            self.clients.remove(&old);
            self.clients.insert(
                ip,
                ClientStats {
                    queries: min.queries,
                    refused: 0,
                    error: min.queries,
                },
            );
            self.clients_replaced += 1;
        }
        let s = self.clients.entry(ip).or_default();
        s.queries += 1;
        s.refused += u64::from(refused);
    }
}

/// What a query counts as: the stage that answered, with the ACL's refusal
/// called `refused`, and the upstream stage split by where its answer came
/// from (`stale`: RFC 8767; `cache`: another query filled it meanwhile).
pub fn category(answered_by: &'static str, source: Option<&Source>) -> &'static str {
    match (answered_by, source) {
        ("acl", _) => "refused",
        ("upstream", Some(Source::Stale)) => "stale",
        ("upstream", Some(Source::Cache)) => "cache",
        ("", _) => "none",
        (stage, _) => stage,
    }
}

fn rcode(r: ResponseCode) -> &'static str {
    match r {
        ResponseCode::NoError => "noerror",
        ResponseCode::NXDomain => "nxdomain",
        ResponseCode::ServFail => "servfail",
        ResponseCode::Refused => "refused",
        ResponseCode::FormErr => "formerr",
        ResponseCode::NotImp => "notimp",
        _ => "other",
    }
}

fn handle(_: &Forwarder, _: &mut Query, _: Option<&mut dyn Transport>) -> Step {
    Step::Next
}

fn after(f: &Forwarder, q: &mut Query, r: &Reply) {
    f.state::<Statistics>().record(q, r);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categories() {
        let up: IpAddr = [198, 51, 100, 53].into();
        assert_eq!(category("acl", None), "refused");
        assert_eq!(category("upstream", Some(&Source::Server(up))), "upstream");
        assert_eq!(category("upstream", Some(&Source::Stale)), "stale");
        assert_eq!(category("cache", Some(&Source::Cache)), "cache");
        assert_eq!(category("limit", None), "limit");
        assert_eq!(category("busy", None), "busy");
    }

    #[test]
    fn the_chain_counts_every_reply_and_drop() {
        use crate::server::tests::{LAN, Up, ask, forwarder, run};
        let f = forwarder(|c| c.ip.dns.max_queries_per_client = 1);
        let mut up = Up::new();
        let q = ask("www.example.com.", RecordType::A);
        // Burst of 2: upstream, cache, then dropped (UDP over the limit).
        for _ in 0..3 {
            run(&f, &mut up, LAN, &q);
        }
        run(&f, &mut up, [203, 0, 113, 9], &ask("x.example.", RecordType::TXT));
        let s = f.state::<Statistics>().snapshot(10);
        let c = &s.counters;
        assert_eq!((c.queries, c.udp, c.tcp), (4, 4, 0));
        let got = |k| c.answered.get(k).copied().unwrap_or(0);
        assert_eq!(
            [got("upstream"), got("cache"), got("limit"), got("refused")],
            [1, 1, 1, 1]
        );
        assert_eq!(c.rcodes.get("dropped"), Some(&1));
        assert_eq!(c.rcodes.get("refused"), Some(&1));
        assert_eq!(s.types(), [("A".to_owned(), 3), ("TXT".to_owned(), 1)]);
        assert_eq!(c.upstreams.get(&IpAddr::from([198, 51, 100, 53])), Some(&1));
        let lan = s.top_clients.first().copied().unwrap();
        assert_eq!(lan.0, IpAddr::from(LAN));
        assert_eq!((lan.1.queries, lan.1.refused), (3, 1));
        f.state::<Statistics>().reset();
        assert_eq!(f.state::<Statistics>().snapshot(10), Snapshot::default());
    }

    #[test]
    fn space_saving_keeps_the_heavy_client() {
        let mut c = Counters::default();
        let heavy: IpAddr = [10, 0, 0, 1].into();
        for _ in 0..50 {
            c.client(heavy, false);
        }
        // A flood from as many sources as the table holds, and more.
        for i in 0..(MAX_CLIENTS as u32 * 3) {
            c.client(IpAddr::from((0x0a01_0000 + i).to_be_bytes()), true);
        }
        assert_eq!(c.clients.len(), MAX_CLIENTS, "bounded");
        let h = c.clients.get(&heavy).copied().unwrap();
        assert_eq!((h.queries, h.error), (50, 0), "never replaced");
        assert!(c.clients_replaced >= MAX_CLIENTS as u64 * 2 - 1);
        // Every count is at least the truth and at most truth + error.
        assert!(c.clients.values().all(|s| s.queries > s.error));
    }
}
