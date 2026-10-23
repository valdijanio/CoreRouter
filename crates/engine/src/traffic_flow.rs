//! Traffic Flow (G4.4b): the router's side of the flow exporter that the
//! daemon runs (`service/traffic_flow.rs`).
//!
//! - [`FlowStore`]: the exported records kept locally for
//!   `retention_hours` (at most `retention_records`), with a sequence
//!   number each, so `ip.traffic-flow.records` hands them out in batches to
//!   another exporter (ClickHouse, G4.4f) and `ip.traffic-flow.top` ranks
//!   subscribers without a collector.
//! - [`IfRouter`]: which interface a connection enters and leaves by,
//!   from the routing table of the config (conntrack does not say), and
//!   the `interfaces` filter.
//! - The session's hooks the daemon calls: the event source from the HAL,
//!   storing a batch of records, the exporter's status.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr};

use corerouter_hal::conntrack::EventSource;
use corerouter_model::Config;
use corerouter_model::route::{self, Reach};
use corerouter_model::traffic_flow::{TrafficFlow, TrafficFlowStatus};
use corerouter_model::types::RoutingTable;
use corerouter_model::logging::LogEvent;
use corerouter_proto_flow::{NatEventType, PortBlock, Record, Router};
use ipnet::IpNet;
use serde::Serialize;

use crate::Session;

/// One kept record and its place in the sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Stored {
    pub seq: u64,
    /// When the exporter kept it (Unix ms): the store's order. A record's
    /// own time can be older (a connection's end comes late).
    #[serde(skip)]
    pub at_ms: u64,
    #[serde(flatten)]
    pub record: Record,
}

#[derive(Debug, Default)]
pub struct FlowStore {
    recs: VecDeque<Stored>,
    next_seq: u64,
    /// Records dropped to keep under `retention_records` before their time.
    pub evicted: u64,
}

impl FlowStore {
    /// Keep `recs` (a batch from the exporter), then forget what is older
    /// than `retention_ms` or beyond `cap` records.
    pub fn push(&mut self, recs: &[Record], now_ms: u64, retention_ms: u64, cap: usize) {
        if cap == 0 || retention_ms == 0 {
            self.recs.clear();
            return;
        }
        for r in recs {
            self.next_seq += 1;
            self.recs.push_back(Stored {
                seq: self.next_seq,
                at_ms: now_ms,
                record: r.clone(),
            });
        }
        while self.recs.len() > cap {
            self.recs.pop_front();
            self.evicted += 1;
        }
        let oldest = now_ms.saturating_sub(retention_ms);
        while self.recs.front().is_some_and(|s| s.at_ms < oldest) {
            self.recs.pop_front();
        }
    }

    pub fn len(&self) -> usize {
        self.recs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.recs.is_empty()
    }

    /// First and last sequence numbers kept.
    pub fn bounds(&self) -> Option<(u64, u64)> {
        Some((self.recs.front()?.seq, self.recs.back()?.seq))
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Records after `seq`, in order. The sequence numbers only grow, so a
    /// binary search finds the start.
    pub fn after(&self, seq: u64) -> impl Iterator<Item = &Stored> {
        let start = self.recs.partition_point(|s| s.seq <= seq);
        self.recs.range(start..)
    }

    /// Records kept at or after `from_ms`, newest first.
    pub fn newer(&self, from_ms: u64) -> impl Iterator<Item = &Stored> {
        self.recs.iter().rev().take_while(move |s| s.at_ms >= from_ms)
    }
}

/// A subscriber's traffic in the top talkers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Talker {
    pub address: String,
    pub bytes: u64,
    pub packets: u64,
    /// Connections (initiator records).
    pub flows: u64,
    /// Sent by the subscriber, and received.
    pub up_bytes: u64,
    pub down_bytes: u64,
}

/// Rank subscribers by traffic over the records since `from_ms`.
pub fn top(store: &FlowStore, from_ms: u64, by: &str, limit: usize) -> Vec<Talker> {
    let mut acc: BTreeMap<IpAddr, Talker> = BTreeMap::new();
    for s in store.newer(from_ms) {
        let Record::Flow(f) = &s.record else { continue };
        let sub = f.subscriber();
        let t = acc.entry(sub).or_default();
        t.bytes = t.bytes.saturating_add(f.octets);
        t.packets = t.packets.saturating_add(f.packets);
        match f.direction {
            corerouter_proto_flow::Direction::Initiator => {
                t.flows += 1;
                t.up_bytes = t.up_bytes.saturating_add(f.octets);
            }
            corerouter_proto_flow::Direction::Reverse => {
                t.down_bytes = t.down_bytes.saturating_add(f.octets);
            }
        }
    }
    let mut v: Vec<Talker> = acc
        .into_iter()
        .map(|(a, mut t)| {
            t.address = a.to_string();
            t
        })
        .collect();
    v.sort_by(|a, b| {
        let key = |t: &Talker| match by {
            "packets" => t.packets,
            "flows" => t.flows,
            _ => t.bytes,
        };
        key(b).cmp(&key(a)).then_with(|| a.address.cmp(&b.address))
    });
    v.truncate(limit);
    v
}

/// Interfaces of a connection by the routing table of the config, and the
/// `interfaces` filter. ifIndex numbers are the interfaces' places in the
/// config (by name, from 1); the exporter sends the names next to them.
#[derive(Debug, Clone, Default)]
pub struct IfRouter {
    names: Vec<(u32, String)>,
    /// Longest prefix first.
    routes: Vec<(IpNet, u32)>,
    wanted: BTreeSet<u32>,
}

impl IfRouter {
    pub fn new(cfg: &Config) -> Self {
        let index: BTreeMap<String, u32> = cfg
            .interfaces
            .keys()
            .enumerate()
            .map(|(i, n)| (n.to_string(), u32::try_from(i + 1).unwrap_or(u32::MAX)))
            .collect();
        let of = |n: &str| index.get(n).copied();
        let mut routes: Vec<(IpNet, u32)> = route::connected(cfg)
            .into_iter()
            .filter(|c| c.active && c.table == RoutingTable::Main)
            .filter_map(|c| Some((c.dst, of(c.interface.as_str())?)))
            .collect();
        for r in cfg.ip.routes.iter().filter(|r| r.routing_table == RoutingTable::Main) {
            if let Reach::Active { link, .. } = route::reach(cfg, r)
                && let Some(i) = of(link.as_str())
            {
                routes.push((r.dst_address, i));
            }
        }
        // Longest prefix first; at equal length the first (connected) wins.
        routes.sort_by_key(|(n, _)| std::cmp::Reverse(n.prefix_len()));
        let tf = &cfg.ip.traffic_flow;
        Self {
            wanted: tf
                .interfaces
                .iter()
                .filter_map(|n| of(n.as_str()))
                .collect(),
            names: index.into_iter().map(|(n, i)| (i, n)).collect(),
            routes,
        }
    }

    /// (ifIndex, name), for the exporter's options records.
    pub fn names(&self) -> Vec<(u32, String)> {
        let mut v = self.names.clone();
        v.sort();
        v
    }
}

impl Router for IfRouter {
    fn ifindex(&self, addr: IpAddr) -> u32 {
        self.routes
            .iter()
            .find(|(n, _)| n.contains(&addr))
            .map_or(0, |(_, i)| *i)
    }

    fn wanted(&self, ingress: u32, egress: u32) -> bool {
        self.wanted.is_empty() || self.wanted.contains(&ingress) || self.wanted.contains(&egress)
    }
}

/// RFC 8158 port block events from the router's log: the `ALLOC` and
/// `RELEASE` lines of the CGNAT in blocks mode (G2.3c, topic `cgnat`,
/// with the block in `detail`).
pub fn port_blocks(events: &[LogEvent]) -> Vec<Record> {
    events
        .iter()
        .filter(|e| e.topics.iter().any(|t| t == "cgnat"))
        .filter_map(|e| {
            let d = &e.detail;
            let event = match d.get("event")?.as_str()? {
                "alloc" => NatEventType::PortBlockAllocation,
                "release" => NatEventType::PortBlockDeallocation,
                _ => return None,
            };
            let ip = |k: &str| d.get(k)?.as_str()?.parse::<Ipv4Addr>().ok();
            let port = |k: &str| u16::try_from(d.get(k)?.as_u64()?).ok();
            let (first, last) = (port("first_port")?, port("last_port")?);
            Some(Record::PortBlock(PortBlock {
                time_ms: e.time.saturating_mul(1000),
                event,
                src: ip("subscriber")?,
                post_src: ip("public")?,
                port_start: first,
                port_end: last,
                step: 1,
                ports: last.saturating_sub(first).saturating_add(1),
            }))
        })
        .collect()
}

/// Retention in ms and records, from the settings.
pub fn retention(tf: &TrafficFlow) -> (u64, usize) {
    (
        u64::from(tf.retention_hours) * 3_600_000,
        usize::try_from(tf.retention_records).unwrap_or(usize::MAX),
    )
}

impl Session {
    /// The conntrack event feed of the backend (the kernel's, or the
    /// lab's), for the daemon's exporter.
    pub fn traffic_flow_source(&mut self) -> Result<Box<dyn EventSource>, String> {
        self.hal_mut().conntrack_events().map_err(|e| e.to_string())
    }

    /// Keep a batch of exported records (the local store).
    pub fn traffic_flow_store(&mut self, recs: &[Record], now_ms: u64) {
        let (ms, cap) = retention(&self.store().running().ip.traffic_flow);
        if let Some(st) = self.ext_mut::<FlowStore>() {
            st.push(recs, now_ms, ms, cap);
        }
    }

    pub fn traffic_flow_set_status(&mut self, status: TrafficFlowStatus) {
        if let Some(s) = self.ext_mut::<TrafficFlowStatus>() {
            *s = status;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_proto_flow::{Direction, EndReason, Flow};

    fn flow(sub: &str, t: u64, octets: u64, dir: Direction) -> Record {
        let s: IpAddr = sub.parse().unwrap();
        let srv: IpAddr = "192.0.2.1".parse().unwrap();
        let (src, post_dst) = match dir {
            Direction::Initiator => (s, srv),
            Direction::Reverse => (srv, s),
        };
        Record::Flow(Flow {
            start_ms: t,
            end_ms: t,
            protocol: 6,
            src,
            dst: srv,
            src_port: 1,
            dst_port: 2,
            post_src: src,
            post_dst,
            post_src_port: 1,
            post_dst_port: 2,
            octets,
            packets: 1,
            ingress: 0,
            egress: 0,
            end_reason: EndReason::End,
            direction: dir,
        })
    }

    #[test]
    fn block_lines_of_the_log_become_port_block_events() {
        let ev = |topics: &[&str], detail: serde_json::Value| LogEvent {
            seq: 1,
            time: 100,
            topics: topics.iter().map(|t| (*t).to_owned()).collect(),
            origin: String::new(),
            message: String::new(),
            detail,
        };
        let block = serde_json::json!({"event": "alloc", "subscriber": "100.64.0.9", "public": "203.0.113.1", "first_port": 2048, "last_port": 3071, "pool": "p"});
        let out = port_blocks(&[
            ev(&["cgnat", "info"], block.clone()),
            ev(&["dhcp"], block),
            ev(&["cgnat", "warning"], serde_json::json!({"alert": 1})),
        ]);
        assert_eq!(out.len(), 1);
        let Record::PortBlock(b) = &out[0] else { panic!() };
        assert_eq!((b.time_ms, b.event, b.port_start, b.port_end, b.ports), (100_000, NatEventType::PortBlockAllocation, 2048, 3071, 1024));
    }

    #[test]
    fn the_store_keeps_its_window_and_its_cap() {
        let mut st = FlowStore::default();
        let recs: Vec<Record> = (0..10).map(|i| flow("100.64.0.1", i * 1000, 1, Direction::Initiator)).collect();
        st.push(&recs[..4], 1000, 5000, 100);
        st.push(&recs[4..], 9000, 5000, 100);
        assert_eq!(st.len(), 6, "kept at 9000; the ones kept at 1000 are past 5 s");
        st.push(&recs[..1], 9000, 60_000, 3);
        assert_eq!(st.len(), 3);
        assert_eq!(st.evicted, 4);
        assert_eq!(st.bounds(), Some((9, 11)));
        assert_eq!(st.after(9).map(|s| s.seq).collect::<Vec<_>>(), vec![10, 11]);
        st.push(&[], 0, 0, 3);
        assert!(st.is_empty(), "retention off");
    }

    #[test]
    fn top_talkers_sum_both_directions_per_subscriber() {
        let mut st = FlowStore::default();
        st.push(&[flow("100.64.0.3", 1, 9999, Direction::Initiator)], 1, 60_000, 100);
        st.push(
            &[
                flow("100.64.0.1", 100, 10, Direction::Initiator),
                flow("100.64.0.1", 100, 1000, Direction::Reverse),
                flow("100.64.0.2", 100, 500, Direction::Initiator),
            ],
            100,
            60_000,
            100,
        );
        let t = top(&st, 50, "bytes", 10);
        assert_eq!(t.len(), 2, "the old one is outside the window");
        assert_eq!((t[0].address.as_str(), t[0].bytes, t[0].up_bytes, t[0].down_bytes, t[0].flows), ("100.64.0.1", 1010, 10, 1000, 1));
        assert_eq!(top(&st, 50, "flows", 1).len(), 1);
    }
}
