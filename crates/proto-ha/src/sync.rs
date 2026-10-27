//! Hot-standby replication of the session table: the active node's
//! [`Publisher`] and the standby's [`Replica`], sans-IO.
//!
//! - A **stream** is one history of the table (a random id chosen when a
//!   node becomes active); every change gets the next **sequence number**.
//! - A replica that connects with the same stream and a position the
//!   publisher still has in its **log** catches up from there; any other
//!   gets a **snapshot** (the whole table in chunks, at sequence `base`),
//!   then the deltas after `base`.
//! - Every operation is idempotent (whole-record upsert, remove, absolute
//!   counters), so a record read during the snapshot that already includes
//!   a later change converges when that change's delta arrives.
//! - The replica **acks** in batches; a hole in the sequence asks for a
//!   **resync** from the first missing number (or a snapshot, if the
//!   publisher's log no longer has it).
//!
//! Memory is bounded: the log by bytes ([`SyncConfig::log_bytes`]), the
//! output by the caller's byte budget per [`Publisher::poll`] (what the
//! socket can take now), a snapshot by the table it copies.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use crate::Millis;
use crate::msg::{Counters, Hello, Key, Msg, Op, Record};

#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// Changes kept for a replica that reconnects (**estimado**: 32 MiB
    /// ≈ 150 k upserts of 200 B, minutes of churn of a 100 k BNG).
    pub log_bytes: usize,
    /// Operations per delta message.
    pub batch_ops: usize,
    /// Bytes per snapshot chunk or delta message (under `msg::MAX_FRAME`).
    pub chunk_bytes: usize,
    /// The replica acks after this many operations…
    pub ack_every: u64,
    /// …or this long after the first unacked one.
    pub ack_interval_ms: u64,
}

impl Default for SyncConfig {
    fn default() -> Self {
        SyncConfig {
            log_bytes: 32 << 20,
            batch_ops: 2048,
            chunk_bytes: 256 << 10,
            ack_every: 1024,
            ack_interval_ms: 20,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    value: Arc<[u8]>,
    counters: Counters,
}

struct Logged {
    op: Op,
    at: Millis,
}

struct Snap {
    base: u64,
    keys: Vec<Key>,
    pos: usize,
    count: u32,
    begun: bool,
}

struct Peer {
    acked: u64,
    sent: u64,
    snap: Option<Snap>,
    need_snapshot: bool,
}

/// What the publisher reports (`ppp.redundancy.monitor`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PublisherStatus {
    pub stream: u64,
    pub seq: u64,
    pub connected: bool,
    pub acked: u64,
    pub sessions: u32,
    /// Changes kept for a reconnect.
    pub log_ops: u64,
    pub log_bytes: u64,
    /// `(sent, total)` while a snapshot is under way.
    pub snapshot: Option<(u32, u32)>,
    /// Snapshots sent since start.
    pub snapshots: u64,
    /// From a change to the replica's ack of it, the last one (ms).
    pub delay_ms: u64,
}

/// The active node's side: the table, the log and one replica's position.
pub struct Publisher {
    cfg: SyncConfig,
    stream: u64,
    seq: u64,
    table: HashMap<Key, Entry>,
    log: VecDeque<Logged>,
    /// Sequence number of `log.front()`.
    log_first: u64,
    log_bytes: usize,
    peer: Option<Peer>,
    snapshots: u64,
    delay_ms: u64,
}

impl Publisher {
    pub fn new(stream: u64, cfg: SyncConfig) -> Publisher {
        Publisher {
            cfg,
            stream,
            seq: 0,
            table: HashMap::new(),
            log: VecDeque::new(),
            log_first: 1,
            log_bytes: 0,
            peer: None,
            snapshots: 0,
            delay_ms: 0,
        }
    }

    /// A new active node's publisher, starting from the replica it held
    /// (a new stream: the old active, back as standby, takes a snapshot).
    pub fn from_replica(stream: u64, cfg: SyncConfig, replica: &Replica) -> Publisher {
        let mut p = Publisher::new(stream, cfg);
        p.table = replica.table.clone();
        p
    }

    pub fn stream(&self) -> u64 {
        self.stream
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    pub fn len(&self) -> usize {
        self.table.len()
    }

    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    pub fn get(&self, key: &Key) -> Option<(&[u8], Counters)> {
        self.table.get(key).map(|e| (&e.value[..], e.counters))
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Key, &[u8], Counters)> {
        self.table
            .iter()
            .map(|(k, e)| (k, &e.value[..], e.counters))
    }

    fn log(&mut self, now: Millis, op: Op) {
        self.seq += 1;
        if self.log.is_empty() {
            self.log_first = self.seq;
        }
        self.log_bytes += op.wire_len();
        self.log.push_back(Logged { op, at: now });
        while self.log_bytes > self.cfg.log_bytes {
            let Some(old) = self.log.pop_front() else {
                break;
            };
            self.log_bytes = self.log_bytes.saturating_sub(old.op.wire_len());
            let gone = self.log_first;
            self.log_first += 1;
            if let Some(p) = &mut self.peer {
                // The replica still needs it (unsent, or the base of the
                // snapshot it is reading): only a new snapshot catches up.
                let snap_needs = p.snap.as_ref().is_some_and(|s| gone > s.base);
                if gone > p.sent || snap_needs {
                    p.snap = None;
                    p.need_snapshot = true;
                }
            }
        }
    }

    /// The session is new or its record changed.
    pub fn upsert(&mut self, now: Millis, key: Key, value: Arc<[u8]>) {
        let counters = self.table.get(&key).map(|e| e.counters).unwrap_or_default();
        self.table.insert(
            key,
            Entry {
                value: value.clone(),
                counters,
            },
        );
        self.log(now, Op::Upsert { key, value });
    }

    pub fn remove(&mut self, now: Millis, key: Key) {
        if self.table.remove(&key).is_some() {
            self.log(now, Op::Remove { key });
        }
    }

    /// New counters of a session (ignored for one not in the table).
    pub fn counters(&mut self, now: Millis, key: Key, c: Counters) {
        if let Some(e) = self.table.get_mut(&key)
            && e.counters != c
        {
            e.counters = c;
            self.log(now, Op::Counters { key, c });
        }
    }

    /// A replica connected and said where it is.
    pub fn connect(&mut self, hello: &Hello) {
        let resumable = hello.stream == self.stream
            && hello.stream != 0
            && hello.applied <= self.seq
            && (hello.applied == self.seq || hello.applied + 1 >= self.log_first);
        self.peer = Some(Peer {
            acked: if resumable { hello.applied } else { 0 },
            sent: if resumable { hello.applied } else { 0 },
            snap: None,
            need_snapshot: !resumable,
        });
    }

    pub fn disconnect(&mut self) {
        self.peer = None;
    }

    /// The replica's message (an [`Msg::Ack`] or [`Msg::Resync`]; others
    /// are not for the publisher and are ignored).
    pub fn handle(&mut self, now: Millis, msg: &Msg) {
        let log_first = self.log_first;
        let seq = self.seq;
        let Some(p) = &mut self.peer else {
            return;
        };
        match *msg {
            Msg::Ack { stream, seq: a } if stream == self.stream => {
                if a > p.sent || a <= p.acked {
                    return;
                }
                p.acked = a;
                if let Some(l) = a
                    .checked_sub(log_first)
                    .and_then(|i| usize::try_from(i).ok())
                    .and_then(|i| self.log.get(i))
                {
                    self.delay_ms = now.saturating_sub(l.at);
                }
            }
            Msg::Resync { stream, from } => {
                if stream == self.stream && from >= log_first && from <= seq + 1 && from > 0 {
                    p.sent = from - 1;
                    p.acked = p.acked.min(from - 1);
                } else {
                    p.snap = None;
                    p.need_snapshot = true;
                }
            }
            _ => {}
        }
    }

    /// Messages for the replica, up to about `budget` bytes.
    pub fn poll(&mut self, budget: usize, out: &mut Vec<Msg>) {
        let Some(p) = &mut self.peer else {
            return;
        };
        let mut left = budget;
        if p.need_snapshot {
            p.need_snapshot = false;
            self.snapshots += 1;
            p.sent = self.seq;
            p.acked = 0;
            p.snap = Some(Snap {
                base: self.seq,
                keys: self.table.keys().copied().collect(),
                pos: 0,
                count: 0,
                begun: false,
            });
        }
        if let Some(s) = &mut p.snap {
            let total = u32::try_from(s.keys.len()).unwrap_or(u32::MAX);
            if !s.begun {
                s.begun = true;
                out.push(Msg::SnapshotBegin {
                    stream: self.stream,
                    base: s.base,
                    total,
                });
            }
            while left > 0 && s.pos < s.keys.len() {
                let mut records = Vec::new();
                let mut bytes = 0;
                while bytes < self.cfg.chunk_bytes
                    && records.len() < self.cfg.batch_ops
                    && let Some(k) = s.keys.get(s.pos)
                {
                    s.pos += 1;
                    // Gone since the snapshot began: its Remove follows.
                    if let Some(e) = self.table.get(k) {
                        bytes += 36 + k.as_bytes().len() + e.value.len();
                        records.push(Record {
                            key: *k,
                            value: e.value.clone(),
                            counters: e.counters,
                        });
                    }
                }
                s.count += u32::try_from(records.len()).unwrap_or(0);
                left = left.saturating_sub(bytes);
                if !records.is_empty() {
                    out.push(Msg::SnapshotChunk {
                        stream: self.stream,
                        records,
                    });
                }
            }
            if s.pos < s.keys.len() {
                return;
            }
            out.push(Msg::SnapshotEnd {
                stream: self.stream,
                base: s.base,
                count: s.count,
            });
            p.snap = None;
        }
        while left > 0 && p.sent < self.seq {
            let Some(start) = (p.sent + 1)
                .checked_sub(self.log_first)
                .and_then(|i| usize::try_from(i).ok())
            else {
                p.need_snapshot = true;
                return;
            };
            let mut ops = Vec::new();
            let mut bytes = 0;
            for l in self.log.range(start..) {
                if ops.len() >= self.cfg.batch_ops || bytes >= self.cfg.chunk_bytes {
                    break;
                }
                bytes += l.op.wire_len();
                ops.push(l.op.clone());
            }
            if ops.is_empty() {
                break;
            }
            let first = p.sent + 1;
            p.sent += ops.len() as u64;
            left = left.saturating_sub(bytes);
            out.push(Msg::Delta {
                stream: self.stream,
                first,
                ops,
            });
        }
    }

    pub fn status(&self) -> PublisherStatus {
        PublisherStatus {
            stream: self.stream,
            seq: self.seq,
            connected: self.peer.is_some(),
            acked: self.peer.as_ref().map_or(0, |p| p.acked),
            sessions: u32::try_from(self.table.len()).unwrap_or(u32::MAX),
            log_ops: self.log.len() as u64,
            log_bytes: self.log_bytes as u64,
            snapshot: self.peer.as_ref().and_then(|p| {
                p.snap
                    .as_ref()
                    .map(|s| (s.count, u32::try_from(s.keys.len()).unwrap_or(u32::MAX)))
            }),
            snapshots: self.snapshots,
            delay_ms: self.delay_ms,
        }
    }
}

/// What the replica reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReplicaStatus {
    pub stream: u64,
    pub applied: u64,
    /// Holds a whole snapshot of `stream` and the deltas after it.
    pub complete: bool,
    pub sessions: u32,
    /// `(received, total)` while a snapshot is arriving.
    pub snapshot: Option<(u32, u32)>,
    pub snapshots: u64,
    /// Holes in the sequence seen (each asked a resync).
    pub gaps: u64,
    pub ops: u64,
}

struct Staging {
    stream: u64,
    base: u64,
    total: u32,
    table: HashMap<Key, Entry>,
}

/// Most records a snapshot may announce (**estimado**: 4 × the 65 534
/// SESSION_IDs of a port group, times 16 groups).
pub const MAX_SNAPSHOT: u32 = 4 << 20;

/// The standby's copy of the active's table.
pub struct Replica {
    cfg: SyncConfig,
    stream: u64,
    applied: u64,
    complete: bool,
    table: HashMap<Key, Entry>,
    staging: Option<Staging>,
    unacked: u64,
    first_unacked: Millis,
    asked: Option<u64>,
    snapshots: u64,
    gaps: u64,
    ops: u64,
}

impl Replica {
    pub fn new(cfg: SyncConfig) -> Replica {
        Replica {
            cfg,
            stream: 0,
            applied: 0,
            complete: false,
            table: HashMap::new(),
            staging: None,
            unacked: 0,
            first_unacked: 0,
            asked: None,
            snapshots: 0,
            gaps: 0,
            ops: 0,
        }
    }

    /// Where to resume, for the Hello: `(0, 0)` unless complete.
    pub fn position(&self) -> (u64, u64) {
        if self.complete {
            (self.stream, self.applied)
        } else {
            (0, 0)
        }
    }

    pub fn complete(&self) -> bool {
        self.complete
    }

    pub fn len(&self) -> usize {
        self.table.len()
    }

    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    pub fn get(&self, key: &Key) -> Option<(&[u8], Counters)> {
        self.table.get(key).map(|e| (&e.value[..], e.counters))
    }

    pub fn iter(&self) -> impl Iterator<Item = (&Key, &[u8], Counters)> {
        self.table
            .iter()
            .map(|(k, e)| (k, &e.value[..], e.counters))
    }

    /// The connection dropped: a snapshot half received is useless.
    pub fn disconnect(&mut self) {
        self.staging = None;
        self.asked = None;
        self.unacked = 0;
    }

    /// Forgets everything (this node became active from another source, or
    /// the config changed the pairing).
    pub fn clear(&mut self) {
        *self = Replica::new(self.cfg.clone());
    }

    fn apply(&mut self, op: &Op) {
        match op {
            Op::Upsert { key, value } => {
                let counters = self.table.get(key).map(|e| e.counters).unwrap_or_default();
                self.table.insert(
                    *key,
                    Entry {
                        value: value.clone(),
                        counters,
                    },
                );
            }
            Op::Remove { key } => {
                self.table.remove(key);
            }
            Op::Counters { key, c } => {
                if let Some(e) = self.table.get_mut(key) {
                    e.counters = *c;
                }
            }
        }
    }

    /// A publisher's message; answers (resync requests) go to `out`.
    pub fn handle(&mut self, now: Millis, msg: &Msg, out: &mut Vec<Msg>) {
        match msg {
            Msg::SnapshotBegin {
                stream,
                base,
                total,
            } => {
                let total = (*total).min(MAX_SNAPSHOT);
                self.staging = Some(Staging {
                    stream: *stream,
                    base: *base,
                    total,
                    table: HashMap::with_capacity(usize::try_from(total).unwrap_or(0).min(1 << 20)),
                });
            }
            Msg::SnapshotChunk { stream, records } => {
                let Some(s) = &mut self.staging else {
                    return;
                };
                if s.stream != *stream {
                    return;
                }
                for r in records {
                    if s.table.len() >= usize::try_from(s.total).unwrap_or(0)
                        && !s.table.contains_key(&r.key)
                    {
                        // More than announced: hostile or broken; drop it all.
                        self.staging = None;
                        return;
                    }
                    s.table.insert(
                        r.key,
                        Entry {
                            value: r.value.clone(),
                            counters: r.counters,
                        },
                    );
                }
            }
            Msg::SnapshotEnd {
                stream,
                base,
                count: _,
            } => {
                let Some(s) = self.staging.take() else {
                    return;
                };
                if s.stream != *stream || s.base != *base {
                    return;
                }
                self.table = s.table;
                self.stream = s.stream;
                self.applied = s.base;
                self.complete = true;
                self.asked = None;
                self.snapshots += 1;
                self.unacked = 0;
                out.push(Msg::Ack {
                    stream: self.stream,
                    seq: self.applied,
                });
            }
            Msg::Delta { stream, first, ops } => {
                if !self.complete || *stream != self.stream || self.staging.is_some() {
                    return;
                }
                let next = self.applied + 1;
                if *first > next {
                    if self.asked != Some(next) {
                        self.asked = Some(next);
                        self.gaps += 1;
                        out.push(Msg::Resync {
                            stream: self.stream,
                            from: next,
                        });
                    }
                    return;
                }
                let skip = usize::try_from(next - *first).unwrap_or(usize::MAX);
                let mut n = 0;
                for op in ops.iter().skip(skip) {
                    self.apply(op);
                    n += 1;
                }
                if n > 0 {
                    if self.unacked == 0 {
                        self.first_unacked = now;
                    }
                    self.applied += n;
                    self.unacked += n;
                    self.ops += n;
                    self.asked = None;
                }
            }
            _ => {}
        }
    }

    /// An [`Msg::Ack`] when one is due.
    pub fn poll(&mut self, now: Millis, out: &mut Vec<Msg>) {
        if self.unacked > 0
            && (self.unacked >= self.cfg.ack_every
                || now.saturating_sub(self.first_unacked) >= self.cfg.ack_interval_ms)
        {
            self.unacked = 0;
            out.push(Msg::Ack {
                stream: self.stream,
                seq: self.applied,
            });
        }
    }

    /// When [`Replica::poll`] wants to run next.
    pub fn next_deadline(&self) -> Option<Millis> {
        (self.unacked > 0).then(|| self.first_unacked + self.cfg.ack_interval_ms)
    }

    pub fn status(&self) -> ReplicaStatus {
        ReplicaStatus {
            stream: self.stream,
            applied: self.applied,
            complete: self.complete,
            sessions: u32::try_from(self.table.len()).unwrap_or(u32::MAX),
            snapshot: self
                .staging
                .as_ref()
                .map(|s| (u32::try_from(s.table.len()).unwrap_or(u32::MAX), s.total)),
            snapshots: self.snapshots,
            gaps: self.gaps,
            ops: self.ops,
        }
    }

    /// Same contents as the publisher (tests and the lab's check).
    pub fn same_as(&self, p: &Publisher) -> bool {
        self.table == p.table
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::msg::{Role, VERSION};

    fn key(n: u32) -> Key {
        Key::new(&n.to_le_bytes()).unwrap()
    }

    fn val(n: u32) -> Arc<[u8]> {
        Arc::from(format!("record-{n}").into_bytes())
    }

    fn hello(r: &Replica) -> Hello {
        let (stream, applied) = r.position();
        Hello {
            version: VERSION,
            node_id: 2,
            epoch: 0,
            role: Role::Standby,
            priority: 100,
            hot_standby: true,
            stream,
            applied,
            sessions: 0,
            sections: vec![],
            features: 0,
        }
    }

    /// Runs both until quiet, through the codec.
    fn pump(p: &mut Publisher, r: &mut Replica, now: Millis) {
        for _ in 0..10_000 {
            let mut to_r = Vec::new();
            p.poll(1 << 20, &mut to_r);
            let mut to_p = Vec::new();
            for m in &to_r {
                let mut b = Vec::new();
                m.encode(&mut b).unwrap();
                let mut fr = crate::msg::FrameReader::new();
                fr.push(&b);
                let m = fr.next_msg().unwrap().unwrap();
                r.handle(now, &m, &mut to_p);
            }
            r.poll(now + 1000, &mut to_p);
            for m in &to_p {
                p.handle(now, m);
            }
            if to_r.is_empty() && to_p.is_empty() {
                return;
            }
        }
        panic!("did not settle");
    }

    #[test]
    fn a_new_replica_gets_a_snapshot_then_deltas() {
        let mut p = Publisher::new(7, SyncConfig::default());
        for i in 0..5000 {
            p.upsert(0, key(i), val(i));
        }
        let mut r = Replica::new(SyncConfig::default());
        p.connect(&hello(&r));
        pump(&mut p, &mut r, 1);
        assert!(r.complete() && r.same_as(&p));
        assert_eq!(p.status().snapshots, 1);
        p.remove(2, key(1));
        p.counters(
            2,
            key(2),
            Counters {
                rx_bytes: 9,
                ..Counters::default()
            },
        );
        p.upsert(2, key(9999), val(9999));
        pump(&mut p, &mut r, 3);
        assert!(r.same_as(&p));
        assert_eq!(p.status().acked, p.seq());
        assert_eq!(r.status().snapshots, 1, "deltas, not a second snapshot");
    }

    #[test]
    fn changes_during_the_snapshot_converge() {
        let cfg = SyncConfig {
            chunk_bytes: 1000,
            ..SyncConfig::default()
        };
        let mut p = Publisher::new(1, cfg.clone());
        for i in 0..2000 {
            p.upsert(0, key(i), val(i));
        }
        let mut r = Replica::new(cfg);
        p.connect(&hello(&r));
        let mut to_r = Vec::new();
        p.poll(3000, &mut to_r); // a few chunks only
        for i in 0..2000 {
            if i % 3 == 0 {
                p.remove(1, key(i));
            } else if i % 3 == 1 {
                p.upsert(1, key(i), val(i + 10_000));
            }
        }
        let mut to_p = Vec::new();
        for m in &to_r {
            r.handle(1, m, &mut to_p);
        }
        pump(&mut p, &mut r, 2);
        assert!(r.same_as(&p));
    }

    #[test]
    fn a_reconnect_resumes_from_the_log_or_takes_a_snapshot() {
        let mut p = Publisher::new(1, SyncConfig::default());
        let mut r = Replica::new(SyncConfig::default());
        for i in 0..100 {
            p.upsert(0, key(i), val(i));
        }
        p.connect(&hello(&r));
        pump(&mut p, &mut r, 1);
        p.disconnect();
        r.disconnect();
        for i in 100..200 {
            p.upsert(2, key(i), val(i));
        }
        p.connect(&hello(&r));
        pump(&mut p, &mut r, 3);
        assert!(r.same_as(&p));
        assert_eq!(p.status().snapshots, 1, "resumed from the log");
        // A log too small for the outage: a snapshot.
        let mut p = Publisher::new(
            2,
            SyncConfig {
                log_bytes: 500,
                ..SyncConfig::default()
            },
        );
        let mut r = Replica::new(SyncConfig::default());
        p.connect(&hello(&r));
        pump(&mut p, &mut r, 1);
        p.disconnect();
        r.disconnect();
        for i in 0..1000 {
            p.upsert(2, key(i), val(i));
        }
        p.connect(&hello(&r));
        pump(&mut p, &mut r, 3);
        assert!(r.same_as(&p));
        assert_eq!(p.status().snapshots, 2);
    }

    #[test]
    fn a_hole_asks_a_resync_once_and_heals() {
        let mut p = Publisher::new(1, SyncConfig::default());
        let mut r = Replica::new(SyncConfig::default());
        p.connect(&hello(&r));
        pump(&mut p, &mut r, 0);
        for i in 0..10 {
            p.upsert(1, key(i), val(i));
        }
        let mut to_r = Vec::new();
        p.poll(1 << 20, &mut to_r);
        // Lose the first delta: deliver a later one by hand.
        p.upsert(1, key(50), val(50));
        let mut more = Vec::new();
        p.poll(1 << 20, &mut more);
        let mut to_p = Vec::new();
        for m in &more {
            r.handle(1, m, &mut to_p);
            r.handle(1, m, &mut to_p);
        }
        assert_eq!(to_p, vec![Msg::Resync { stream: 1, from: 1 }]);
        for m in &to_p {
            p.handle(1, m);
        }
        pump(&mut p, &mut r, 2);
        assert!(r.same_as(&p));
        assert_eq!(r.status().gaps, 1);
    }

    #[test]
    fn hostile_replica_messages_change_nothing() {
        let mut p = Publisher::new(1, SyncConfig::default());
        let mut r = Replica::new(SyncConfig::default());
        p.connect(&hello(&r));
        p.upsert(0, key(1), val(1));
        pump(&mut p, &mut r, 0);
        let before = p.status();
        p.handle(0, &Msg::Ack { stream: 1, seq: 99 });
        p.handle(0, &Msg::Ack { stream: 2, seq: 1 });
        assert_eq!(p.status().acked, before.acked);
        // A resync from outside the log: a snapshot, never a crash.
        p.handle(
            0,
            &Msg::Resync {
                stream: 1,
                from: u64::MAX,
            },
        );
        pump(&mut p, &mut r, 1);
        assert!(r.same_as(&p));
        // A snapshot that sends more than it announced is dropped.
        let mut r2 = Replica::new(SyncConfig::default());
        let mut out = Vec::new();
        r2.handle(
            0,
            &Msg::SnapshotBegin {
                stream: 5,
                base: 0,
                total: 1,
            },
            &mut out,
        );
        let recs = (0..3)
            .map(|i| Record {
                key: key(i),
                value: val(i),
                counters: Counters::default(),
            })
            .collect();
        r2.handle(
            0,
            &Msg::SnapshotChunk {
                stream: 5,
                records: recs,
            },
            &mut out,
        );
        r2.handle(
            0,
            &Msg::SnapshotEnd {
                stream: 5,
                base: 0,
                count: 3,
            },
            &mut out,
        );
        assert!(!r2.complete() && r2.is_empty());
    }
}
