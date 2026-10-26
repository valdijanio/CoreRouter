//! Who of the pair is active: a sans-IO role machine with fencing.
//!
//! The rule that keeps both nodes from answering the same subscribers is
//! a **majority of three**: this node, the peer and a **witness** (the
//! gateway, probed by the caller). A node is active only while it hears
//! the peer (and the pair agrees it is the active one) or, with the peer
//! silent on every path, while it reaches the witness. An active node that
//! loses both is isolated and fences itself: the peer, which reaches the
//! witness, takes over.
//!
//! The peer is heard on up to two **paths**: the sync stream (TLS, often
//! across the core) and an authenticated **hello on the access network**
//! (`hello`), the same L2 the subscribers use. Silence on both is needed to
//! take over: a cut sync link alone never makes two actives, and two nodes
//! that cannot hear each other on the access side do not share
//! subscribers either. Without a witness, the access path is the arbiter.
//!
//! - **Init** waits `init_hold` to hear an active peer before claiming the
//!   role (a node that boots never steals it).
//! - **Election** (nobody active, both heard): the one with a complete
//!   replica, then the higher priority, then the higher node id.
//! - **Split brain** (both active, seen after a partition heals): the
//!   higher epoch (the more recent takeover) stays, then priority, then
//!   node id. Every takeover raises the epoch.
//! - **Switchover**: the active stops answering first (Yielding), hands
//!   over, and becomes standby once the peer is active with a higher
//!   epoch; if the peer does not take over in time, it resumes. Never two
//!   actives, at most one handover round-trip with none.
//! - **Hold timers**: a fenced node leaves only after its witness has been
//!   stable for `recover_hold`; preemption waits `preempt_delay` in sync.

use std::collections::VecDeque;

use crate::Millis;
use crate::msg::Role;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleConfig {
    pub node_id: u64,
    /// Random per start of the process: tells this run of the node from
    /// the one before a restart (the peer's hellos say which one it hears).
    pub incarnation: u64,
    /// Higher wins an election (RouterOS VRRP: 1..254, default 100).
    pub priority: u8,
    /// A standby of higher priority takes the role back when in sync.
    pub preempt: bool,
    pub preempt_delay_ms: u64,
    pub hello_ms: u64,
    /// The peer is dead after this long without a hello on any path.
    pub dead_ms: u64,
    pub init_hold_ms: u64,
    pub recover_hold_ms: u64,
    pub handover_timeout_ms: u64,
    /// A witness is configured (fencing needs it reachable to take over).
    pub witness: bool,
    /// The access-side hello runs (a second path to hear the peer).
    pub access_path: bool,
    /// Hot standby: a takeover keeps the sessions (else they redial).
    pub hot_standby: bool,
}

impl Default for RoleConfig {
    fn default() -> Self {
        RoleConfig {
            node_id: 1,
            incarnation: 1,
            priority: 100,
            preempt: false,
            preempt_delay_ms: 60_000,
            hello_ms: 300,
            dead_ms: 1200,
            init_hold_ms: 5000,
            recover_hold_ms: 3000,
            handover_timeout_ms: 2000,
            witness: true,
            access_path: true,
            hot_standby: true,
        }
    }
}

/// Where a peer hello came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Path {
    Sync,
    Access,
}

impl Path {
    fn idx(self) -> usize {
        match self {
            Path::Sync => 0,
            Path::Access => 1,
        }
    }
}

/// What a hello says about its sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerView {
    pub node_id: u64,
    pub incarnation: u64,
    /// The incarnation of the peer the sender hears now (0: none).
    pub hears: u64,
    /// Grows each time the sender's role or eligibility changes.
    pub view_seq: u64,
    /// The latest `view_seq` of the peer the sender has seen. An election
    /// is won only once the loser says "standby (or I cannot serve), I hear
    /// you, and I saw your latest view": decisions on views that crossed in
    /// flight never count.
    pub acked: u64,
    pub epoch: u64,
    pub role: Role,
    pub priority: u8,
    pub witness: bool,
    pub in_sync: bool,
    /// Could serve (tracked ports up, no simulated failure): a fenced peer
    /// that is not eligible never takes the role.
    pub eligible: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Boot,
    PeerDead,
    PeerFenced,
    PeerActive,
    Election,
    Switchover,
    Preempt,
    SplitBrainLost,
    Isolated,
    TrackDown,
    SimulatedFailure,
    HandoverTimeout,
    Recovered,
}

impl Reason {
    /// English key (i18n, MCP).
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::Boot => "boot",
            Reason::PeerDead => "peer-dead",
            Reason::PeerFenced => "peer-fenced",
            Reason::PeerActive => "peer-active",
            Reason::Election => "election",
            Reason::Switchover => "switchover",
            Reason::Preempt => "preempt",
            Reason::SplitBrainLost => "split-brain-lost",
            Reason::Isolated => "isolated",
            Reason::TrackDown => "track-down",
            Reason::SimulatedFailure => "simulated-failure",
            Reason::HandoverTimeout => "handover-timeout",
            Reason::Recovered => "recovered",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transition {
    pub at: Millis,
    pub from: Role,
    pub to: Role,
    pub epoch: u64,
    pub reason: Reason,
    /// Becoming active with a complete replica: keep the sessions.
    pub stateful: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// The role changed: start or stop answering, fill or empty the data
    /// plane, announce the virtual MAC.
    Role(Transition),
    /// Tell the peer to take over (switchover).
    Handover { epoch: u64 },
    /// Ask the active peer to yield (preemption).
    HandoverRequest { epoch: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    NotActive,
    NoPeer,
    PeerNotStandby,
    PeerNotInSync,
    Busy,
}

impl Refused {
    pub fn as_str(self) -> &'static str {
        match self {
            Refused::NotActive => "this node is not the active one",
            Refused::NoPeer => "the peer is not heard",
            Refused::PeerNotStandby => "the peer is not standby",
            Refused::PeerNotInSync => {
                "the peer's replica is not complete (force=yes switches anyway; sessions not synced redial)"
            }
            Refused::Busy => "a switchover or a simulated failure is under way",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleStatus {
    pub role: Role,
    pub epoch: u64,
    pub since: Millis,
    pub peer: Option<PeerView>,
    /// The peer is heard on [sync, access] now.
    pub paths: [bool; 2],
    pub witness: bool,
    pub track: bool,
    pub synced: bool,
    pub simulating_until: Option<Millis>,
    /// A hello carried our own node id (misconfigured pair).
    pub duplicate_node_id: bool,
    pub history: Vec<Transition>,
}

const HISTORY: usize = 32;

pub struct Ha {
    cfg: RoleConfig,
    role: Role,
    epoch: u64,
    since: Millis,
    started: Millis,
    heard: [Option<(Millis, PeerView)>; 2],
    max_epoch_seen: u64,
    witness_up: bool,
    witness_changed: Millis,
    track_up: bool,
    synced: bool,
    synced_since: Millis,
    sim_until: Option<Millis>,
    yield_deadline: Option<Millis>,
    preempt_asked: Option<Millis>,
    duplicate_node_id: bool,
    /// The peer incarnation heard at the last evaluation, and its latest
    /// view number.
    hears: u64,
    peer_view_seq: u64,
    view_seq: u64,
    material: (Role, bool),
    actions: Vec<Action>,
    history: VecDeque<Transition>,
}

impl Ha {
    pub fn new(cfg: RoleConfig, now: Millis) -> Ha {
        Ha {
            cfg,
            role: Role::Init,
            epoch: 0,
            since: now,
            started: now,
            heard: [None, None],
            max_epoch_seen: 0,
            witness_up: false,
            witness_changed: now,
            track_up: true,
            synced: false,
            synced_since: now,
            sim_until: None,
            yield_deadline: None,
            preempt_asked: None,
            duplicate_node_id: false,
            hears: 0,
            peer_view_seq: 0,
            view_seq: 1,
            material: (Role::Init, true),
            actions: Vec::new(),
            history: VecDeque::new(),
        }
    }

    pub fn config(&self) -> &RoleConfig {
        &self.cfg
    }

    pub fn role(&self) -> Role {
        self.role
    }

    /// When the current role began.
    pub fn since(&self) -> Millis {
        self.since
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Answer subscribers now (only the active node does).
    pub fn answering(&self) -> bool {
        self.role == Role::Active
    }

    /// Send no hellos (a simulated failure: the peer must see us dead).
    pub fn silent(&self) -> bool {
        self.sim_until.is_some()
    }

    /// What our hellos say.
    pub fn view(&self) -> PeerView {
        PeerView {
            node_id: self.cfg.node_id,
            incarnation: self.cfg.incarnation,
            hears: self.hears,
            view_seq: self.view_seq,
            acked: self.peer_view_seq,
            epoch: self.epoch,
            role: self.role,
            priority: self.cfg.priority,
            witness: self.witness_up,
            in_sync: self.synced,
            eligible: self.track_up && self.sim_until.is_none(),
        }
    }

    pub fn take_actions(&mut self, out: &mut Vec<Action>) {
        out.append(&mut self.actions);
    }

    fn peer(&self, now: Millis) -> Option<PeerView> {
        self.heard
            .iter()
            .flatten()
            .filter(|(at, _)| now.saturating_sub(*at) < self.cfg.dead_ms)
            .max_by_key(|(at, _)| *at)
            .map(|(_, v)| *v)
    }

    fn path_alive(&self, now: Millis, p: Path) -> bool {
        self.heard
            .get(p.idx())
            .copied()
            .flatten()
            .is_some_and(|(at, _)| now.saturating_sub(at) < self.cfg.dead_ms)
    }

    pub fn peer_heard(&mut self, now: Millis, path: Path, v: PeerView) {
        if self.sim_until.is_some() {
            return;
        }
        if v.node_id == self.cfg.node_id {
            // Our own hello looped back is not news; another node with our
            // id is a misconfigured pair.
            if v.incarnation != self.cfg.incarnation {
                self.duplicate_node_id = true;
            }
            return;
        }
        self.max_epoch_seen = self.max_epoch_seen.max(v.epoch);
        if let Some(slot) = self.heard.get_mut(path.idx()) {
            *slot = Some((now, v));
        }
        self.evaluate(now);
    }

    /// The caller's witness probe (already debounced: N misses = down).
    pub fn witness(&mut self, now: Millis, ok: bool) {
        if ok != self.witness_up {
            self.witness_up = ok;
            self.witness_changed = now;
        }
        self.evaluate(now);
    }

    /// The tracked access ports are up (all of them).
    pub fn track(&mut self, now: Millis, ok: bool) {
        self.track_up = ok;
        self.evaluate(now);
    }

    /// The replica is complete for the active's stream.
    pub fn synced(&mut self, now: Millis, ok: bool) {
        if ok != self.synced {
            self.synced = ok;
            self.synced_since = now;
        }
        self.evaluate(now);
    }

    pub fn tick(&mut self, now: Millis) {
        self.evaluate(now);
    }

    /// The peer handed the role over (its switchover or our preemption).
    pub fn handover(&mut self, now: Millis, epoch: u64) {
        if self.sim_until.is_some() || !self.track_up || self.role != Role::Standby {
            return;
        }
        self.max_epoch_seen = self.max_epoch_seen.max(epoch);
        self.set(now, Role::Active, Reason::Switchover);
    }

    /// The standby peer asks for the role (preemption: configured on the
    /// preferred node, as in VRRP; the active yields to a higher priority
    /// that is in sync).
    pub fn handover_request(&mut self, now: Millis, _epoch: u64) {
        let Some(p) = self.peer(now) else {
            return;
        };
        if self.role == Role::Active
            && p.priority > self.cfg.priority
            && (p.in_sync || !self.cfg.hot_standby)
        {
            self.yield_role(now, Reason::Preempt);
        }
    }

    /// Manual switchover: hand the role to the standby peer.
    pub fn switchover(&mut self, now: Millis, force: bool) -> Result<(), Refused> {
        if self.sim_until.is_some() || self.role == Role::Yielding {
            return Err(Refused::Busy);
        }
        if self.role != Role::Active {
            return Err(Refused::NotActive);
        }
        let p = self.peer(now).ok_or(Refused::NoPeer)?;
        if p.role != Role::Standby {
            return Err(Refused::PeerNotStandby);
        }
        if self.cfg.hot_standby && !p.in_sync && !force {
            return Err(Refused::PeerNotInSync);
        }
        self.yield_role(now, Reason::Switchover);
        Ok(())
    }

    fn yield_role(&mut self, now: Millis, reason: Reason) {
        self.set(now, Role::Yielding, reason);
        self.yield_deadline = Some(now + self.cfg.handover_timeout_ms);
        self.actions.push(Action::Handover { epoch: self.epoch });
    }

    /// "Simular falha": behave as a dead node for `ms` (stop answering and
    /// stop the hellos), then start over as at boot.
    pub fn simulate_failure(&mut self, now: Millis, ms: u64) -> Result<(), Refused> {
        if self.sim_until.is_some() || self.role == Role::Yielding {
            return Err(Refused::Busy);
        }
        self.sim_until = Some(now + ms);
        self.heard = [None, None];
        self.set(now, Role::Fenced, Reason::SimulatedFailure);
        Ok(())
    }

    /// When [`Ha::tick`] has something to decide.
    pub fn next_deadline(&self) -> Millis {
        let mut d = self.since + self.cfg.hello_ms;
        let mut at = |t: Millis| d = d.min(t);
        for (h, _) in self.heard.iter().flatten() {
            at(h + self.cfg.dead_ms);
        }
        if self.role == Role::Init {
            at(self.started + self.cfg.init_hold_ms);
        }
        if let Some(t) = self.sim_until {
            at(t);
        }
        if let Some(t) = self.yield_deadline {
            at(t);
        }
        if self.role == Role::Fenced {
            at(self.witness_changed.max(self.since) + self.cfg.recover_hold_ms);
        }
        if self.cfg.preempt && self.role == Role::Standby {
            at(self.synced_since.max(self.since) + self.cfg.preempt_delay_ms);
        }
        d
    }

    /// (complete replica, priority, node id): the election order.
    fn beats(&self, p: &PeerView) -> bool {
        (self.synced, self.cfg.priority, self.cfg.node_id) > (p.in_sync, p.priority, p.node_id)
    }

    /// (epoch, priority, node id): who stays when both are active.
    fn outranks(&self, p: &PeerView) -> bool {
        (self.epoch, self.cfg.priority, self.cfg.node_id) > (p.epoch, p.priority, p.node_id)
    }

    fn stable(&self, now: Millis) -> bool {
        now.saturating_sub(self.since) >= self.cfg.recover_hold_ms
            && now.saturating_sub(self.witness_changed) >= self.cfg.recover_hold_ms
    }

    fn set(&mut self, now: Millis, to: Role, reason: Reason) {
        if to == self.role {
            return;
        }
        if to == Role::Active && reason != Reason::HandoverTimeout {
            self.epoch = self.epoch.max(self.max_epoch_seen) + 1;
        }
        if to != Role::Yielding {
            self.yield_deadline = None;
        }
        let t = Transition {
            at: now,
            from: self.role,
            to,
            epoch: self.epoch,
            reason,
            stateful: to == Role::Active && self.cfg.hot_standby && self.synced,
        };
        self.role = to;
        self.since = now;
        let m = (self.role, self.track_up && self.sim_until.is_none());
        if m != self.material {
            self.material = m;
            self.view_seq += 1;
        }
        if self.history.len() >= HISTORY {
            self.history.pop_front();
        }
        self.history.push_back(t);
        self.actions.push(Action::Role(t));
    }

    fn evaluate(&mut self, now: Millis) {
        self.decide(now);
        let m = (self.role, self.track_up && self.sim_until.is_none());
        if m != self.material {
            self.material = m;
            self.view_seq += 1;
        }
    }

    fn decide(&mut self, now: Millis) {
        if let Some(until) = self.sim_until {
            if now < until {
                return;
            }
            self.sim_until = None;
            self.started = now;
            self.set(now, Role::Init, Reason::Recovered);
        }
        if !self.track_up {
            if self.role != Role::Fenced {
                self.set(now, Role::Fenced, Reason::TrackDown);
            }
            return;
        }
        let peer = self.peer(now);
        self.hears = peer.map_or(0, |p| p.incarnation);
        self.peer_view_seq = peer.map_or(0, |p| p.view_seq);
        if self.role == Role::Yielding {
            match peer {
                Some(p) if p.role == Role::Active && p.epoch > self.epoch => {
                    self.set(now, Role::Standby, Reason::Switchover);
                }
                _ if self.yield_deadline.is_none_or(|d| now >= d) => {
                    self.set(now, Role::Active, Reason::HandoverTimeout);
                }
                _ => {}
            }
            return;
        }
        let may_take = if self.cfg.witness {
            self.witness_up
        } else {
            self.cfg.access_path
        };
        let Some(p) = peer else {
            match self.role {
                Role::Active => {
                    if self.cfg.witness && !self.witness_up {
                        self.set(now, Role::Fenced, Reason::Isolated);
                    }
                }
                Role::Init => {
                    if now.saturating_sub(self.started) >= self.cfg.init_hold_ms {
                        if may_take {
                            self.set(now, Role::Active, Reason::Boot);
                        } else {
                            self.set(now, Role::Fenced, Reason::Isolated);
                        }
                    }
                }
                Role::Standby => {
                    if may_take {
                        self.set(now, Role::Active, Reason::PeerDead);
                    } else {
                        self.set(now, Role::Fenced, Reason::Isolated);
                    }
                }
                Role::Fenced => {
                    if may_take && self.stable(now) {
                        self.set(now, Role::Active, Reason::PeerDead);
                    }
                }
                Role::Yielding => {}
            }
            return;
        };
        match p.role {
            Role::Active => match self.role {
                Role::Active => {
                    if !self.outranks(&p) {
                        self.set(now, Role::Standby, Reason::SplitBrainLost);
                    }
                }
                Role::Standby => self.maybe_preempt(now, &p),
                _ => self.set(now, Role::Standby, Reason::PeerActive),
            },
            // The peer is handing over: wait for its Handover.
            Role::Yielding => {
                if matches!(self.role, Role::Init | Role::Fenced) {
                    self.set(now, Role::Standby, Reason::PeerActive);
                }
            }
            Role::Standby | Role::Init | Role::Fenced => {
                if self.role == Role::Active {
                    return;
                }
                let win = !p.eligible || self.beats(&p);
                if !win {
                    if matches!(self.role, Role::Init | Role::Fenced) {
                        self.set(now, Role::Standby, Reason::Election);
                    }
                    return;
                }
                if self.role == Role::Fenced && !self.stable(now) {
                    return;
                }
                // Both may compute a win from views that crossed in flight:
                // the winner takes the role only once the peer says it is
                // standby and hears this run of us (the loser says so at
                // once), or cannot serve.
                let current = p.hears == self.cfg.incarnation && p.acked >= self.view_seq;
                if current && (p.role == Role::Standby || !p.eligible) {
                    let why = if p.eligible {
                        Reason::Election
                    } else {
                        Reason::PeerFenced
                    };
                    self.set(now, Role::Active, why);
                }
            }
        }
    }

    fn maybe_preempt(&mut self, now: Millis, p: &PeerView) {
        if !self.cfg.preempt || self.cfg.priority <= p.priority {
            return;
        }
        if self.cfg.hot_standby && !self.synced {
            return;
        }
        let ready = self.synced_since.max(self.since) + self.cfg.preempt_delay_ms;
        let again = self
            .preempt_asked
            .is_none_or(|t| now.saturating_sub(t) >= self.cfg.preempt_delay_ms);
        if now >= ready && again {
            self.preempt_asked = Some(now);
            self.actions
                .push(Action::HandoverRequest { epoch: p.epoch });
        }
    }

    pub fn status(&self, now: Millis) -> RoleStatus {
        RoleStatus {
            role: self.role,
            epoch: self.epoch,
            since: self.since,
            peer: self.peer(now),
            paths: [
                self.path_alive(now, Path::Sync),
                self.path_alive(now, Path::Access),
            ],
            witness: self.witness_up,
            track: self.track_up,
            synced: self.synced,
            simulating_until: self.sim_until,
            duplicate_node_id: self.duplicate_node_id,
            history: self.history.iter().copied().collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(id: u64) -> RoleConfig {
        RoleConfig {
            node_id: id,
            ..RoleConfig::default()
        }
    }

    fn view(id: u64, role: Role, epoch: u64) -> PeerView {
        PeerView {
            node_id: id,
            incarnation: id * 10,
            hears: 1,
            view_seq: 1,
            acked: u64::MAX,
            epoch,
            role,
            priority: 100,
            witness: true,
            in_sync: true,
            eligible: true,
        }
    }

    #[test]
    fn a_booting_node_waits_and_never_steals_the_role() {
        let mut a = Ha::new(cfg(1), 0);
        a.witness(0, true);
        a.peer_heard(100, Path::Sync, view(2, Role::Active, 7));
        assert_eq!(a.role(), Role::Standby);
        // Alone: active only after init_hold, and only with the witness.
        let mut b = Ha::new(cfg(1), 0);
        b.witness(0, true);
        b.tick(4999);
        assert_eq!(b.role(), Role::Init);
        b.tick(5000);
        assert_eq!(b.role(), Role::Active);
        let mut c = Ha::new(cfg(1), 0);
        c.tick(6000);
        assert_eq!(c.role(), Role::Fenced, "no witness, no peer: isolated");
    }

    #[test]
    fn the_standby_takes_over_after_dead_interval_with_a_higher_epoch() {
        let mut a = Ha::new(cfg(1), 0);
        a.witness(0, true);
        a.synced(0, true);
        a.peer_heard(10, Path::Sync, view(2, Role::Active, 7));
        a.peer_heard(10, Path::Access, view(2, Role::Active, 7));
        a.tick(1209);
        assert_eq!(a.role(), Role::Standby);
        a.tick(1210);
        assert_eq!(a.role(), Role::Active);
        assert_eq!(a.epoch(), 8);
        let mut acts = Vec::new();
        a.take_actions(&mut acts);
        assert!(
            acts.iter().any(
                |x| matches!(x, Action::Role(t) if t.reason == Reason::PeerDead && t.stateful)
            )
        );
    }

    #[test]
    fn a_cut_sync_link_alone_is_not_a_failover() {
        let mut a = Ha::new(cfg(1), 0);
        a.witness(0, true);
        let mut t = 0;
        while t < 10_000 {
            if t < 1000 {
                a.peer_heard(t, Path::Sync, view(2, Role::Active, 3));
            }
            a.peer_heard(t, Path::Access, view(2, Role::Active, 3));
            a.tick(t);
            assert_ne!(a.role(), Role::Active, "at {t}");
            t += 300;
        }
    }

    #[test]
    fn an_isolated_active_fences_itself_but_a_dead_witness_alone_does_not() {
        let mut a = Ha::new(cfg(1), 0);
        a.witness(0, true);
        a.tick(5000);
        assert_eq!(a.role(), Role::Active);
        a.peer_heard(5100, Path::Sync, view(2, Role::Standby, 0));
        a.witness(5200, false);
        a.tick(5300);
        assert_eq!(a.role(), Role::Active, "the peer is heard: majority");
        a.tick(7000);
        assert_eq!(a.role(), Role::Fenced, "peer and witness gone");
        a.witness(7100, true);
        a.tick(9000);
        assert_eq!(a.role(), Role::Fenced, "recover hold");
        a.tick(10_200);
        assert_eq!(a.role(), Role::Active);
    }

    #[test]
    fn split_brain_resolves_to_the_higher_epoch() {
        let mut a = Ha::new(cfg(1), 0);
        a.witness(0, true);
        a.tick(5000);
        assert_eq!((a.role(), a.epoch()), (Role::Active, 1));
        a.peer_heard(6000, Path::Access, view(2, Role::Active, 2));
        assert_eq!(a.role(), Role::Standby);
        let mut b = Ha::new(cfg(9), 0);
        b.witness(0, true);
        b.tick(5000);
        b.peer_heard(6000, Path::Access, view(2, Role::Active, 1));
        assert_eq!(b.role(), Role::Active, "same epoch: higher node id stays");
    }

    #[test]
    fn switchover_yields_first_and_resumes_if_nobody_takes_it() {
        let mut a = Ha::new(cfg(1), 0);
        a.witness(0, true);
        a.tick(5000);
        a.peer_heard(
            5000,
            Path::Sync,
            PeerView {
                in_sync: false,
                ..view(2, Role::Standby, 0)
            },
        );
        assert_eq!(a.switchover(5001, false), Err(Refused::PeerNotInSync));
        a.peer_heard(5002, Path::Sync, view(2, Role::Standby, 0));
        assert_eq!(a.switchover(5003, false), Ok(()));
        assert_eq!(a.role(), Role::Yielding);
        assert!(!a.answering());
        let mut acts = Vec::new();
        a.take_actions(&mut acts);
        assert!(acts.contains(&Action::Handover { epoch: 1 }));
        a.peer_heard(5100, Path::Sync, view(2, Role::Active, 2));
        assert_eq!(a.role(), Role::Standby);
        // Nobody answers the handover: resume.
        let mut c = Ha::new(cfg(1), 0);
        c.witness(0, true);
        c.tick(5000);
        c.peer_heard(5000, Path::Sync, view(2, Role::Standby, 0));
        c.switchover(5000, false).unwrap();
        c.peer_heard(6000, Path::Sync, view(2, Role::Standby, 0));
        c.tick(7000);
        assert_eq!((c.role(), c.epoch()), (Role::Active, 1));
    }

    #[test]
    fn simulated_failure_goes_silent_then_starts_over() {
        let mut a = Ha::new(cfg(1), 0);
        a.witness(0, true);
        a.tick(5000);
        a.simulate_failure(5000, 3000).unwrap();
        assert!(a.silent() && !a.answering());
        a.peer_heard(6000, Path::Sync, view(2, Role::Active, 2));
        assert_eq!(a.role(), Role::Fenced, "peer ignored while dead");
        a.tick(8000);
        assert_eq!(a.role(), Role::Init);
        a.peer_heard(8100, Path::Sync, view(2, Role::Active, 2));
        assert_eq!(a.role(), Role::Standby);
    }

    #[test]
    fn election_prefers_the_complete_replica_then_priority() {
        let mut a = Ha::new(cfg(1), 0);
        a.witness(0, true);
        a.peer_heard(
            10,
            Path::Sync,
            PeerView {
                in_sync: true,
                ..view(2, Role::Standby, 0)
            },
        );
        assert_eq!(a.role(), Role::Standby);
        let mut b = Ha::new(
            RoleConfig {
                priority: 200,
                ..cfg(1)
            },
            0,
        );
        b.peer_heard(
            10,
            Path::Sync,
            PeerView {
                in_sync: false,
                ..view(2, Role::Init, 0)
            },
        );
        assert_eq!(
            b.role(),
            Role::Init,
            "the winner waits for the loser to say standby"
        );
        b.peer_heard(
            15,
            Path::Sync,
            PeerView {
                in_sync: false,
                ..view(2, Role::Standby, 0)
            },
        );
        assert_eq!(b.role(), Role::Active);
        // A peer that cannot serve (a tracked port down) is not waited for.
        let mut c = Ha::new(cfg(1), 0);
        c.peer_heard(
            10,
            Path::Sync,
            PeerView {
                eligible: false,
                ..view(2, Role::Fenced, 0)
            },
        );
        assert_eq!(c.role(), Role::Active);
    }

    #[test]
    fn a_tracked_port_down_fences_and_our_own_id_is_flagged() {
        let mut a = Ha::new(cfg(1), 0);
        a.witness(0, true);
        a.tick(5000);
        a.track(5001, false);
        assert_eq!(a.role(), Role::Fenced);
        a.peer_heard(5002, Path::Sync, view(1, Role::Active, 3));
        assert!(a.status(5002).duplicate_node_id);
    }

    #[test]
    fn preemption_asks_after_the_delay_in_sync() {
        let mut a = Ha::new(
            RoleConfig {
                priority: 200,
                preempt: true,
                preempt_delay_ms: 1000,
                ..cfg(1)
            },
            0,
        );
        a.synced(0, true);
        let mut acts = Vec::new();
        for t in (0..=2000).step_by(100) {
            a.peer_heard(t, Path::Sync, view(2, Role::Active, 4));
            a.take_actions(&mut acts);
        }
        assert_eq!(
            acts.iter()
                .filter(|x| matches!(x, Action::HandoverRequest { .. }))
                .count(),
            2,
            "at 1000 and 2000"
        );
        let mut p = Ha::new(
            RoleConfig {
                preempt: true,
                ..cfg(2)
            },
            0,
        );
        p.witness(0, true);
        p.tick(5000);
        p.peer_heard(
            5000,
            Path::Sync,
            PeerView {
                priority: 200,
                ..view(1, Role::Standby, 0)
            },
        );
        p.handover_request(5001, 1);
        assert_eq!(p.role(), Role::Yielding);
    }
}
