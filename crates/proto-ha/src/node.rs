//! One node of the pair, whole and sans-IO: the role machine, the
//! publisher (while active) or the replica (while standby), the sync
//! stream with its mutual authentication, and the access hellos. The
//! daemon's `ppp-ha` service and the in-memory [`crate::lab`] drive the
//! same code: bytes and hellos in, bytes and hellos out, the clock and the
//! witness/track probes from the caller.
//!
//! **Link authentication** (on top of TLS, which pins the peer's
//! certificate): both ends send a [`Msg::Challenge`] with a fresh nonce;
//! each answers the other's with a [`Msg::Proof`], HMAC-SHA-256 under a key
//! derived from the pair's secret over (the verifier's nonce, the prover's
//! nonce, the prover's node id). Our own nonce coming back as the peer's is
//! refused (reflection). Nothing else is accepted before both proofs.

use std::sync::Arc;

use hmac::{Hmac, KeyInit, Mac as _};
use sha2::Sha256;

use crate::Millis;
use crate::hello::{HelloFrame, ReplayGuard};
use crate::msg::{
    Counters, FEATURE_FORWARD, FrameReader, Heartbeat, Hello, Key, Msg, Role, Section, VERSION,
};
use crate::role::{Action, Ha, Path, PeerView, Refused, RoleConfig, RoleStatus, Transition};
use crate::sync::{Publisher, PublisherStatus, Replica, ReplicaStatus, SyncConfig};
use crate::wire::Error;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub role: RoleConfig,
    pub sync: SyncConfig,
    /// `hello::derive("hello", secret)`.
    pub hello_key: [u8; 32],
    /// `hello::derive("link", secret)`.
    pub link_key: [u8; 32],
    /// Hashes of the config sections both nodes must agree on.
    pub sections: Vec<Section>,
}

/// What the caller must act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The role changed. To active: answer subscribers, announce the
    /// virtual MAC, and with `stateful` take the sessions of
    /// [`Node::publisher`] over (they came from the replica). From active:
    /// stop answering.
    Role(Transition),
    /// The link authenticated: the peer is `node_id`.
    PeerUp { node_id: u64 },
    /// The peer asks for a service (G4.3hb, a CoA/DM): answer with
    /// [`Node::forward_reply`] and the same `id`.
    Forward { id: u64, body: Vec<u8> },
    /// The answer to our [`Node::forward`] `id`.
    ForwardReply { id: u64, body: Vec<u8> },
}

/// Why the caller must close the sync connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkError {
    Codec(Error),
    /// The peer's proof did not match (another secret, or not the peer).
    Auth(&'static str),
    Version(u8),
    /// A message before the handshake finished.
    Early,
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkError::Codec(e) => write!(f, "sync stream: {e}"),
            LinkError::Auth(why) => write!(f, "peer not authenticated: {why}"),
            LinkError::Version(v) => write!(f, "peer speaks sync version {v}, we speak {VERSION}"),
            LinkError::Early => f.write_str("peer sent data before authenticating"),
        }
    }
}

#[derive(Clone, Copy)]
enum Link {
    Down,
    Auth {
        ours: [u8; 32],
        theirs: Option<[u8; 32]>,
        verified: Option<u64>,
    },
    Up {
        peer: u64,
    },
}

/// Counters and state for the monitor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeStatus {
    pub role: RoleStatus,
    pub publisher: Option<PublisherStatus>,
    pub replica: ReplicaStatus,
    /// The sync link is up and authenticated (with this peer node id).
    pub link: Option<u64>,
    pub peer_priority: u8,
    /// The peer's table size (its last heartbeat), and its sequence.
    pub peer_sessions: u32,
    pub peer_seq: u64,
    /// Config sections whose hash differs from the peer's.
    pub drift: Vec<String>,
    pub bad_hellos: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

pub struct Node {
    cfg: NodeConfig,
    ha: Ha,
    publisher: Option<Publisher>,
    replica: Replica,
    link: Link,
    reader: FrameReader,
    out: Vec<u8>,
    access_out: Vec<(Vec<u8>, bool)>,
    events: Vec<Event>,
    hello_seq: u64,
    guard: ReplayGuard,
    next_hello: Millis,
    last_view: Option<PeerView>,
    peer_hello: Option<Hello>,
    peer_stream: u64,
    peer_priority: u8,
    peer_sessions: u32,
    peer_seq: u64,
    seen_peer_active: Millis,
    streams: u64,
    drift: Vec<String>,
    bad_hellos: u64,
    bytes_in: u64,
    bytes_out: u64,
}

impl Node {
    pub fn new(cfg: NodeConfig, now: Millis) -> Node {
        Node {
            ha: Ha::new(cfg.role.clone(), now),
            replica: Replica::new(cfg.sync.clone()),
            cfg,
            publisher: None,
            link: Link::Down,
            reader: FrameReader::new(),
            out: Vec::new(),
            access_out: Vec::new(),
            events: Vec::new(),
            hello_seq: 0,
            guard: ReplayGuard::default(),
            next_hello: now,
            last_view: None,
            peer_hello: None,
            peer_stream: 0,
            peer_priority: 0,
            peer_sessions: 0,
            peer_seq: 0,
            seen_peer_active: 0,
            streams: 0,
            drift: Vec::new(),
            bad_hellos: 0,
            bytes_in: 0,
            bytes_out: 0,
        }
    }

    pub fn role(&self) -> Role {
        self.ha.role()
    }

    pub fn ha(&self) -> &Ha {
        &self.ha
    }

    /// Answer subscribers now.
    pub fn answering(&self) -> bool {
        self.ha.answering()
    }

    /// The table this node serves (active) — after a stateful takeover it
    /// holds the replicated sessions to import.
    pub fn publisher(&self) -> Option<&Publisher> {
        self.publisher.as_ref()
    }

    pub fn replica(&self) -> &Replica {
        &self.replica
    }

    /// When a hello last said the peer is active (the lab's watch).
    pub fn seen_peer_active(&self) -> Millis {
        self.seen_peer_active
    }

    pub fn link_up(&self) -> bool {
        matches!(self.link, Link::Up { .. })
    }

    fn send(&mut self, m: &Msg) {
        if matches!(self.link, Link::Down) {
            return;
        }
        let before = self.out.len();
        if m.encode(&mut self.out).is_ok() {
            self.bytes_out += (self.out.len() - before) as u64;
        }
    }

    /// The sync connection is open (TLS done): start the handshake with
    /// `nonce` (32 random bytes).
    pub fn connected(&mut self, now: Millis, nonce: [u8; 32]) {
        self.disconnected();
        self.link = Link::Auth {
            ours: nonce,
            theirs: None,
            verified: None,
        };
        self.next_hello = now;
        self.send(&Msg::Challenge { nonce });
    }

    /// The sync connection closed.
    pub fn disconnected(&mut self) {
        self.link = Link::Down;
        self.reader = FrameReader::new();
        self.out.clear();
        self.replica.disconnect();
        self.peer_hello = None;
        if let Some(p) = &mut self.publisher {
            p.disconnect();
        }
    }

    fn proof(&self, verifier: &[u8; 32], prover: &[u8; 32], node_id: u64) -> [u8; 32] {
        let Ok(mut h) = <HmacSha256 as KeyInit>::new_from_slice(&self.cfg.link_key) else {
            return [0; 32];
        };
        h.update(b"corerouter-ha proof");
        h.update(verifier);
        h.update(prover);
        h.update(&node_id.to_le_bytes());
        h.finalize().into_bytes().into()
    }

    fn hello_msg(&self) -> Hello {
        let (stream, applied) = match &self.publisher {
            Some(p) => (p.stream(), p.seq()),
            None => self.replica.position(),
        };
        Hello {
            version: VERSION,
            node_id: self.cfg.role.node_id,
            epoch: self.ha.epoch(),
            role: self.ha.role(),
            priority: self.cfg.role.priority,
            hot_standby: self.cfg.role.hot_standby,
            stream,
            applied,
            sessions: self.sessions(),
            sections: self.cfg.sections.clone(),
            features: FEATURE_FORWARD,
        }
    }

    /// The link is up and the peer takes [`Msg::Forward`].
    pub fn can_forward(&self) -> bool {
        self.link_up()
            && self
                .peer_hello
                .as_ref()
                .is_some_and(|h| h.features & FEATURE_FORWARD != 0)
    }

    /// Hands `body` to the peer (its answer comes as
    /// [`Event::ForwardReply`] with `id`). `false`: not sent (no link, a
    /// peer without the feature, or a body over the limit).
    pub fn forward(&mut self, id: u64, body: Vec<u8>) -> bool {
        if !self.can_forward() {
            return false;
        }
        let before = self.out.len();
        self.send(&Msg::Forward { id, body });
        self.out.len() > before
    }

    /// The answer to the peer's [`Event::Forward`] `id`.
    pub fn forward_reply(&mut self, id: u64, body: Vec<u8>) {
        if self.link_up() {
            self.send(&Msg::ForwardReply { id, body });
        }
    }

    fn sessions(&self) -> u32 {
        let n = self
            .publisher
            .as_ref()
            .map_or(self.replica.len(), Publisher::len);
        u32::try_from(n).unwrap_or(u32::MAX)
    }

    fn heartbeat(&self) -> Heartbeat {
        let v = self.ha.view();
        let (stream, seq) = match &self.publisher {
            Some(p) => (p.stream(), p.seq()),
            None => self.replica.position(),
        };
        Heartbeat {
            node_id: v.node_id,
            incarnation: v.incarnation,
            hears: v.hears,
            view_seq: v.view_seq,
            acked: v.acked,
            epoch: v.epoch,
            role: v.role,
            priority: v.priority,
            witness: v.witness,
            in_sync: v.in_sync,
            eligible: v.eligible,
            stream,
            seq,
            sessions: self.sessions(),
        }
    }

    /// Bytes read from the sync connection. An error means: close it (and
    /// call [`Node::disconnected`]).
    pub fn input(&mut self, now: Millis, bytes: &[u8]) -> Result<(), LinkError> {
        if matches!(self.link, Link::Down) {
            return Ok(());
        }
        self.bytes_in += bytes.len() as u64;
        self.reader.push(bytes);
        loop {
            match self.reader.next_msg() {
                Ok(Some(m)) => self.on_msg(now, m)?,
                Ok(None) => break,
                Err(e) => return Err(LinkError::Codec(e)),
            }
        }
        self.after(now);
        Ok(())
    }

    fn on_msg(&mut self, now: Millis, m: Msg) -> Result<(), LinkError> {
        if let Link::Auth {
            ours,
            mut theirs,
            mut verified,
        } = self.link
        {
            match m {
                Msg::Challenge { nonce } => {
                    if nonce == ours {
                        return Err(LinkError::Auth("our own challenge came back"));
                    }
                    if theirs.is_some() {
                        return Err(LinkError::Auth("two challenges"));
                    }
                    theirs = Some(nonce);
                    let id = self.cfg.role.node_id;
                    let mac = self.proof(&nonce, &ours, id);
                    self.send(&Msg::Proof { node_id: id, mac });
                }
                Msg::Proof { node_id, mac } => {
                    let Some(t) = theirs else {
                        return Err(LinkError::Auth("proof before challenge"));
                    };
                    if node_id == self.cfg.role.node_id {
                        return Err(LinkError::Auth("the peer has our node id"));
                    }
                    let want = self.proof(&ours, &t, node_id);
                    let diff = want
                        .iter()
                        .zip(mac.iter())
                        .fold(0u8, |a, (x, y)| a | (x ^ y));
                    if diff != 0 {
                        return Err(LinkError::Auth(
                            "wrong proof (is the secret the same on both nodes?)",
                        ));
                    }
                    verified = Some(node_id);
                }
                _ => return Err(LinkError::Early),
            }
            if let (Some(_), Some(peer)) = (theirs, verified) {
                self.link = Link::Up { peer };
                self.events.push(Event::PeerUp { node_id: peer });
                let h = self.hello_msg();
                self.send(&Msg::Hello(h));
                self.next_hello = now;
            } else {
                self.link = Link::Auth {
                    ours,
                    theirs,
                    verified,
                };
            }
            return Ok(());
        }
        if matches!(self.link, Link::Down) {
            return Ok(());
        }
        match &m {
            Msg::Challenge { .. } | Msg::Proof { .. } => {
                return Err(LinkError::Auth("a second handshake"));
            }
            Msg::Hello(h) => {
                if h.version != VERSION {
                    return Err(LinkError::Version(h.version));
                }
                self.peer_hello = Some(h.clone());
                self.peer_priority = h.priority;
                if matches!(h.role, Role::Active | Role::Yielding) {
                    self.peer_stream = h.stream;
                }
                self.drift = drift(&self.cfg.sections, &h.sections);
                if let Some(p) = &mut self.publisher {
                    p.connect(h);
                }
            }
            Msg::Heartbeat(hb) => {
                self.peer_stream = hb.stream;
                self.peer_priority = hb.priority;
                self.peer_sessions = hb.sessions;
                self.peer_seq = hb.seq;
                if hb.role == Role::Active {
                    self.seen_peer_active = now;
                }
                self.ha.peer_heard(
                    now,
                    Path::Sync,
                    PeerView {
                        node_id: hb.node_id,
                        incarnation: hb.incarnation,
                        hears: hb.hears,
                        view_seq: hb.view_seq,
                        acked: hb.acked,
                        epoch: hb.epoch,
                        role: hb.role,
                        priority: hb.priority,
                        witness: hb.witness,
                        in_sync: hb.in_sync,
                        eligible: hb.eligible,
                    },
                );
            }
            Msg::Handover { epoch } => self.ha.handover(now, *epoch),
            Msg::HandoverRequest { epoch } => self.ha.handover_request(now, *epoch),
            Msg::Forward { id, body } => self.events.push(Event::Forward {
                id: *id,
                body: body.clone(),
            }),
            Msg::ForwardReply { id, body } => self.events.push(Event::ForwardReply {
                id: *id,
                body: body.clone(),
            }),
            Msg::Ack { .. } | Msg::Resync { .. } => {
                if let Some(p) = &mut self.publisher {
                    p.handle(now, &m);
                }
            }
            Msg::SnapshotBegin { .. }
            | Msg::SnapshotChunk { .. }
            | Msg::SnapshotEnd { .. }
            | Msg::Delta { .. } => {
                if self.publisher.is_none() {
                    let mut replies = Vec::new();
                    self.replica.handle(now, &m, &mut replies);
                    for r in replies {
                        self.send(&r);
                    }
                }
            }
        }
        self.after(now);
        Ok(())
    }

    /// An access hello body (after the EtherType) from an access port.
    pub fn access_input(&mut self, now: Millis, body: &[u8]) {
        match HelloFrame::decode(&self.cfg.hello_key, body) {
            Ok(h) if h.view.node_id != self.cfg.role.node_id => {
                if self.guard.check(&h).is_err() {
                    self.bad_hellos += 1;
                    return;
                }
                if h.view.role == Role::Active {
                    self.seen_peer_active = now;
                }
                self.ha.peer_heard(now, Path::Access, h.view);
                self.after(now);
            }
            // Our own hello looped back by the switch.
            Ok(_) => {}
            Err(_) => self.bad_hellos += 1,
        }
    }

    pub fn witness(&mut self, now: Millis, ok: bool) {
        self.ha.witness(now, ok);
        self.after(now);
    }

    pub fn track(&mut self, now: Millis, ok: bool) {
        self.ha.track(now, ok);
        self.after(now);
    }

    /// The peer's BFD session on `path` changed (G3.6h): see [`Ha::bfd`].
    pub fn bfd(&mut self, now: Millis, path: Path, up: bool, expired: bool) {
        self.ha.bfd(now, path, up, expired);
        self.after(now);
    }

    pub fn bfd_off(&mut self, now: Millis, path: Path) {
        self.ha.bfd_off(now, path);
        self.after(now);
    }

    /// The witness answered a probe at `at`.
    pub fn witness_answer(&mut self, now: Millis, at: Millis) {
        self.ha.witness_answer(now, at);
        self.after(now);
    }

    /// BFD found the peer silent: probe the witness now (the takeover
    /// waits for its answer).
    pub fn wants_witness_probe(&self) -> bool {
        self.ha.wants_witness_probe()
    }

    /// Runs the timers; hellos due go to the outputs.
    pub fn tick(&mut self, now: Millis) {
        let in_sync = self.publisher.is_none()
            && self.replica.complete()
            && self.replica.status().stream == self.peer_stream;
        self.ha.synced(now, in_sync);
        self.ha.tick(now);
        self.after(now);
        let view = self.ha.view();
        if (now >= self.next_hello || self.last_view != Some(view)) && !self.ha.silent() {
            self.next_hello = now + self.cfg.role.hello_ms;
            self.last_view = Some(view);
            self.hello_seq += 1;
            if self.link_up() {
                let hb = self.heartbeat();
                self.send(&Msg::Heartbeat(hb));
            }
            if self.cfg.role.access_path {
                let mut body = Vec::with_capacity(crate::hello::BODY);
                HelloFrame {
                    view,
                    seq: self.hello_seq,
                }
                .encode(&self.cfg.hello_key, &mut body);
                self.access_out.push((body, self.ha.answering()));
            }
        }
        if let Some(r) = self.replica.next_deadline()
            && now >= r
            && self.link_up()
        {
            let mut acks = Vec::new();
            self.replica.poll(now, &mut acks);
            for a in acks {
                self.send(&a);
            }
        }
    }

    /// The sync messages that fit in `budget` bytes (what the connection's
    /// write buffer takes now), appended to the output.
    pub fn poll(&mut self, now: Millis, budget: usize) {
        if !self.link_up() {
            return;
        }
        let mut msgs = Vec::new();
        if let Some(p) = &mut self.publisher {
            p.poll(budget, &mut msgs);
        } else {
            self.replica.poll(now, &mut msgs);
        }
        for m in msgs {
            self.send(&m);
        }
    }

    /// Bytes to write on the sync connection (moved out).
    pub fn take_output(&mut self, out: &mut Vec<u8>) {
        out.append(&mut self.out);
    }

    pub fn output_len(&self) -> usize {
        self.out.len()
    }

    /// Access hello bodies to send on every access port, with "from the
    /// virtual MAC" (the active's: the gratuitous MAC update).
    pub fn take_access(&mut self, out: &mut Vec<(Vec<u8>, bool)>) {
        out.append(&mut self.access_out);
    }

    pub fn take_events(&mut self, out: &mut Vec<Event>) {
        out.append(&mut self.events);
    }

    /// Session changes (only the active node publishes; elsewhere ignored).
    pub fn upsert(&mut self, now: Millis, key: Key, value: Arc<[u8]>) {
        if let Some(p) = &mut self.publisher {
            p.upsert(now, key, value);
        }
    }

    pub fn remove(&mut self, now: Millis, key: Key) {
        if let Some(p) = &mut self.publisher {
            p.remove(now, key);
        }
    }

    pub fn counters(&mut self, now: Millis, key: Key, c: Counters) {
        if let Some(p) = &mut self.publisher {
            p.counters(now, key, c);
        }
    }

    pub fn switchover(&mut self, now: Millis, force: bool) -> Result<(), Refused> {
        // The publisher's acks prove the replica complete sooner than the
        // peer's next heartbeat says so.
        let caught_up = self.publisher.as_ref().is_some_and(|p| {
            let s = p.status();
            s.connected && s.snapshot.is_none() && s.acked == s.seq && s.snapshots > 0
        }) && self.link_up();
        let r = self.ha.switchover(now, force || caught_up);
        self.after(now);
        r
    }

    pub fn simulate_failure(&mut self, now: Millis, ms: u64) -> Result<(), Refused> {
        let r = self.ha.simulate_failure(now, ms);
        self.after(now);
        r
    }

    /// The role machine's actions: publisher on the way in, replica on the
    /// way out, hellos at once on every change.
    fn after(&mut self, now: Millis) {
        let mut acts = Vec::new();
        self.ha.take_actions(&mut acts);
        for a in acts {
            match a {
                Action::Role(t) => {
                    self.streams += 1;
                    let stream = (self.cfg.role.incarnation.rotate_left(20)
                        ^ self.streams.wrapping_mul(0x9e37_79b9_7f4a_7c15))
                        | 1;
                    match t.to {
                        Role::Active => {
                            if self.publisher.is_none() {
                                let mut p = if t.stateful {
                                    Publisher::from_replica(
                                        stream,
                                        self.cfg.sync.clone(),
                                        &self.replica,
                                    )
                                } else {
                                    Publisher::new(stream, self.cfg.sync.clone())
                                };
                                if let Some(h) = &self.peer_hello {
                                    p.connect(h);
                                }
                                self.publisher = Some(p);
                                self.replica.clear();
                            }
                        }
                        Role::Yielding => {}
                        _ => {
                            if self.publisher.take().is_some() {
                                self.replica.clear();
                            }
                        }
                    }
                    self.next_hello = now;
                    if self.link_up() {
                        let h = self.hello_msg();
                        self.send(&Msg::Hello(h));
                    }
                    self.events.push(Event::Role(t));
                }
                Action::Handover { epoch } => self.send(&Msg::Handover { epoch }),
                Action::HandoverRequest { epoch } => self.send(&Msg::HandoverRequest { epoch }),
            }
        }
    }

    pub fn status(&self, now: Millis) -> NodeStatus {
        NodeStatus {
            role: self.ha.status(now),
            publisher: self.publisher.as_ref().map(Publisher::status),
            replica: self.replica.status(),
            link: match self.link {
                Link::Up { peer } => Some(peer),
                _ => None,
            },
            peer_priority: self.peer_priority,
            peer_sessions: self.peer_sessions,
            peer_seq: self.peer_seq,
            drift: self.drift.clone(),
            bad_hellos: self.bad_hellos,
            bytes_in: self.bytes_in,
            bytes_out: self.bytes_out,
        }
    }
}

/// A config section for drift detection: its name and a stable hash of
/// its canonical bytes (SHA-256, first 8 bytes: the same on every build
/// and machine, unlike `std`'s hasher).
pub fn section(name: &str, bytes: &[u8]) -> Section {
    use sha2::Digest;
    let d = Sha256::digest(bytes);
    let mut h = [0u8; 8];
    for (o, i) in h.iter_mut().zip(d.iter()) {
        *o = *i;
    }
    Section {
        name: name.into(),
        hash: u64::from_le_bytes(h),
    }
}

/// Names of the sections whose hash differs or that one side lacks.
fn drift(ours: &[Section], theirs: &[Section]) -> Vec<String> {
    let mut d: Vec<String> = ours
        .iter()
        .filter(|s| !theirs.iter().any(|t| t.name == s.name && t.hash == s.hash))
        .map(|s| s.name.to_string())
        .collect();
    for t in theirs {
        if !ours.iter().any(|s| s.name == t.name) {
            d.push(t.name.to_string());
        }
    }
    d.sort();
    d.dedup();
    d
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hello::derive;

    fn cfg(id: u64, secret: &[u8]) -> NodeConfig {
        NodeConfig {
            role: RoleConfig {
                node_id: id,
                incarnation: id * 100,
                priority: if id == 1 { 200 } else { 100 },
                ..RoleConfig::default()
            },
            sync: SyncConfig::default(),
            hello_key: derive("hello", secret),
            link_key: derive("link", secret),
            sections: vec![Section {
                name: "ppp.profile".into(),
                hash: id,
            }],
        }
    }

    /// Moves everything both ways until quiet.
    fn pump(a: &mut Node, b: &mut Node, now: Millis) -> Result<(), LinkError> {
        for _ in 0..1000 {
            let (mut x, mut y) = (Vec::new(), Vec::new());
            a.poll(now, 1 << 20);
            b.poll(now, 1 << 20);
            a.take_output(&mut x);
            b.take_output(&mut y);
            if x.is_empty() && y.is_empty() {
                return Ok(());
            }
            b.input(now, &x)?;
            a.input(now, &y)?;
        }
        Ok(())
    }

    #[test]
    fn the_handshake_authenticates_both_ends_and_shows_drift() {
        let mut a = Node::new(cfg(1, b"segredo"), 0);
        let mut b = Node::new(cfg(2, b"segredo"), 0);
        a.connected(0, [1; 32]);
        b.connected(0, [2; 32]);
        pump(&mut a, &mut b, 0).unwrap();
        assert!(a.link_up() && b.link_up());
        let mut ev = Vec::new();
        a.take_events(&mut ev);
        assert_eq!(ev, vec![Event::PeerUp { node_id: 2 }]);
        assert_eq!(a.status(0).drift, ["ppp.profile"]);
    }

    /// G4.3hb: a request and its answer cross the link; nothing goes to a
    /// peer before its Hello says it takes them, nor without a link.
    #[test]
    fn a_forwarded_request_and_its_answer_cross_the_link() {
        let mut a = Node::new(cfg(1, b"segredo"), 0);
        let mut b = Node::new(cfg(2, b"segredo"), 0);
        assert!(!a.forward(1, b"x".to_vec()), "no link");
        a.connected(0, [1; 32]);
        b.connected(0, [2; 32]);
        pump(&mut a, &mut b, 0).unwrap();
        let mut ev = Vec::new();
        a.take_events(&mut ev);
        b.take_events(&mut ev);
        ev.clear();
        assert!(a.can_forward());
        assert!(a.forward(7, b"coa".to_vec()));
        pump(&mut a, &mut b, 1).unwrap();
        b.take_events(&mut ev);
        assert_eq!(
            ev,
            vec![Event::Forward {
                id: 7,
                body: b"coa".to_vec()
            }]
        );
        b.forward_reply(7, b"ack".to_vec());
        pump(&mut a, &mut b, 2).unwrap();
        ev.clear();
        a.take_events(&mut ev);
        assert_eq!(
            ev,
            vec![Event::ForwardReply {
                id: 7,
                body: b"ack".to_vec()
            }]
        );
        // A peer whose Hello has no features (an older version): not sent.
        let old = Hello {
            features: 0,
            ..a.peer_hello.clone().unwrap()
        };
        a.peer_hello = Some(old);
        assert!(!a.can_forward() && !a.forward(8, b"coa".to_vec()));
    }

    #[test]
    fn a_wrong_secret_or_a_reflected_challenge_is_refused() {
        let mut a = Node::new(cfg(1, b"segredo"), 0);
        let mut b = Node::new(cfg(2, b"outro"), 0);
        a.connected(0, [1; 32]);
        b.connected(0, [2; 32]);
        assert!(matches!(pump(&mut a, &mut b, 0), Err(LinkError::Auth(_))));
        let mut c = Node::new(cfg(1, b"segredo"), 0);
        c.connected(0, [5; 32]);
        let mut echo = Vec::new();
        c.take_output(&mut echo);
        assert_eq!(
            c.input(0, &echo),
            Err(LinkError::Auth("our own challenge came back"))
        );
        // Data before the handshake.
        let mut d = Node::new(cfg(1, b"segredo"), 0);
        d.connected(0, [5; 32]);
        let mut early = Vec::new();
        Msg::Ack { stream: 1, seq: 1 }.encode(&mut early).unwrap();
        assert_eq!(d.input(0, &early), Err(LinkError::Early));
    }

    #[test]
    fn two_nodes_elect_sync_and_fail_over() {
        let mut a = Node::new(cfg(1, b"segredo"), 0);
        let mut b = Node::new(cfg(2, b"segredo"), 0);
        for n in [&mut a, &mut b] {
            n.witness(0, true);
        }
        a.connected(0, [1; 32]);
        b.connected(0, [2; 32]);
        let mut now = 0;
        while now < 2000 {
            now += 10;
            a.tick(now);
            b.tick(now);
            pump(&mut a, &mut b, now).unwrap();
            if now == 500 {
                for i in 0..1000u32 {
                    a.upsert(
                        now,
                        Key::new(&i.to_le_bytes()).unwrap(),
                        Arc::from(&b"rec"[..]),
                    );
                }
            }
        }
        assert_eq!((a.role(), b.role()), (Role::Active, Role::Standby));
        assert!(b.replica().same_as(a.publisher().unwrap()));
        // a dies: b takes over with the sessions.
        b.disconnected();
        while now < 4000 {
            now += 10;
            b.tick(now);
        }
        assert_eq!(b.role(), Role::Active);
        assert_eq!(b.publisher().unwrap().len(), 1000);
        let mut ev = Vec::new();
        b.take_events(&mut ev);
        assert!(
            ev.iter()
                .any(|e| matches!(e, Event::Role(t) if t.to == Role::Active && t.stateful))
        );
    }
}
