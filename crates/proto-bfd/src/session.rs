//! One BFD session: the state variables of RFC 5880 §6.8.1, reception
//! (§6.8.6), transmission (§6.8.7), the timer rules (§6.8.2–§6.8.4) and
//! Poll/Final (§6.5). Asynchronous mode; the Echo function and local
//! Demand mode are not offered (both optional, §6.4/§6.6), but a peer in
//! Demand mode is honoured (§6.8.7: periodic transmission stops).
//!
//! Sans-IO: times are microseconds of a monotonic clock the caller gives,
//! and the caller sends what [`Session::build`] writes.

use crate::auth::{self, AuthConfig, RcvSeq};
use crate::packet::{Diag, MAX_LEN, Packet, State};

/// §6.8.3: "When bfd.SessionState is not Up, the system MUST set
/// bfd.DesiredMinTxInterval to a value of not less than one second".
pub const SLOW_TX_US: u32 = 1_000_000;

/// What the operator sets (a profile, `routing.bfd.profile`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// bfd.DesiredMinTxInterval once Up, µs.
    pub desired_min_tx: u32,
    /// bfd.RequiredMinRxInterval, µs (0: "do not send me periodic packets").
    pub required_min_rx: u32,
    /// bfd.DetectMult.
    pub detect_mult: u8,
    pub auth: Option<AuthConfig>,
    /// §6.1 passive role: send nothing until the peer spoke.
    pub passive: bool,
    /// bfd.SessionState forced to AdminDown (§6.8.16).
    pub admin_down: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            desired_min_tx: 300_000,
            required_min_rx: 300_000,
            detect_mult: 3,
            auth: None,
            passive: false,
            admin_down: false,
        }
    }
}

/// A packet the session refused (counted by the caller).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// §6.8.6: Your Discriminator zero while the peer says Init or Up.
    ZeroYourDiscr,
    /// The A bit and the session's auth disagree, or the check failed.
    Auth(auth::AuthError),
}

/// A state change, for the clients (BGP, OSPF, routes) and the history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Change {
    pub from: State,
    pub to: State,
    pub diag: Diag,
}

/// What a received packet asks of the caller.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Received {
    /// §6.8.6: "If the Poll (P) bit is set, send a BFD Control packet to
    /// the remote system with the Poll (P) bit clear, and the Final (F) bit
    /// set" — now, outside the periodic schedule.
    pub send_final: bool,
    /// Send a packet now (a state change: the 3-way handshake would
    /// otherwise wait for the slow 1 s timer).
    pub send_now: bool,
    pub change: Option<Change>,
}

/// What a timer asks of the caller.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Fired {
    /// Send the periodic packet; `late_us` is how far after its due time
    /// (the engine's own scheduling jitter).
    pub send: bool,
    pub late_us: u64,
    pub change: Option<Change>,
}

#[derive(Debug, Clone)]
pub struct Session {
    pub cfg: Config,
    state: State,
    remote_state: State,
    local_discr: u32,
    remote_discr: u32,
    local_diag: Diag,
    /// What we advertise (Desired Min TX / Required Min RX fields).
    adv_tx: u32,
    adv_rx: u32,
    /// What our own timers use until a Poll Sequence ends (§6.8.3).
    tx_used: u32,
    rx_for_detect: u32,
    remote_min_rx: u32,
    remote_desired_tx: u32,
    remote_mult: u8,
    remote_demand: bool,
    /// The C bit of the peer's last packet (RFC 5880 §4.1: its BFD does not
    /// share fate with its control plane). G3.9fj: `bfdd` hands it to
    /// `bgpd` for RFC 5882 §4.3.
    remote_cpi: bool,
    /// The peer's Desired Min TX before it advertised a smaller one, kept
    /// in the Detection Time until it really sends at the new rate (0:
    /// none). See [`Session::detection_time`].
    remote_tx_hold: u32,
    /// When the last packet that can prove the new rate arrived (one
    /// sent on the peer's periodic schedule, after the decrease).
    hold_rx_at: Option<u64>,
    poll_active: bool,
    rcv_seq: RcvSeq,
    xmit_seq: u32,
    next_tx: Option<u64>,
    detect_at: Option<u64>,
    forget_auth_at: Option<u64>,
    rng: u64,
    pub tx_packets: u64,
    pub rx_packets: u64,
}

impl Session {
    /// A Down session. `seed` feeds the jitter and the first sequence
    /// number (§6.8.1: bfd.XmitAuthSeq "MUST be initialized to a random
    /// 32-bit value").
    pub fn new(local_discr: u32, cfg: Config, now: u64, seed: u64) -> Self {
        let mut s = Self {
            state: State::Down,
            remote_state: State::Down,
            local_discr,
            remote_discr: 0,
            local_diag: Diag::None,
            adv_tx: cfg.desired_min_tx.max(SLOW_TX_US),
            adv_rx: cfg.required_min_rx,
            tx_used: cfg.desired_min_tx.max(SLOW_TX_US),
            rx_for_detect: cfg.required_min_rx,
            // §6.8.1: "This variable MUST be initialized to 1."
            remote_min_rx: 1,
            remote_desired_tx: 0,
            remote_mult: 0,
            remote_demand: false,
            remote_cpi: false,
            remote_tx_hold: 0,
            hold_rx_at: None,
            poll_active: false,
            rcv_seq: RcvSeq::default(),
            xmit_seq: 0,
            next_tx: None,
            detect_at: None,
            forget_auth_at: None,
            rng: seed | 1,
            tx_packets: 0,
            rx_packets: 0,
            cfg,
        };
        s.xmit_seq = s.random();
        if s.cfg.admin_down {
            s.state = State::AdminDown;
            s.local_diag = Diag::AdministrativelyDown;
        }
        // The first packet goes out at once (jittered), not after 1 s.
        s.next_tx = s.periodic_allowed().then_some(now);
        s
    }

    fn random(&mut self) -> u32 {
        // xorshift64*: jitter needs no cryptographic quality.
        self.rng ^= self.rng >> 12;
        self.rng ^= self.rng << 25;
        self.rng ^= self.rng >> 27;
        (self.rng.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 32) as u32
    }

    pub fn state(&self) -> State {
        self.state
    }
    pub fn remote_state(&self) -> State {
        self.remote_state
    }
    pub fn local_discr(&self) -> u32 {
        self.local_discr
    }
    pub fn remote_discr(&self) -> u32 {
        self.remote_discr
    }
    pub fn local_diag(&self) -> Diag {
        self.local_diag
    }
    pub fn poll_active(&self) -> bool {
        self.poll_active
    }
    pub fn remote_min_rx(&self) -> u32 {
        self.remote_min_rx
    }
    pub fn remote_desired_tx(&self) -> u32 {
        self.remote_desired_tx
    }
    pub fn remote_mult(&self) -> u8 {
        self.remote_mult
    }
    pub fn remote_cpi(&self) -> bool {
        self.remote_cpi
    }
    /// The periodic interval before jitter (§6.8.7): the larger of our
    /// bfd.DesiredMinTxInterval and the peer's Required Min RX.
    pub fn tx_interval(&self) -> u32 {
        self.tx_used.max(self.remote_min_rx)
    }

    /// §6.8.4, asynchronous mode: the received Detect Mult times the
    /// larger of our bfd.RequiredMinRxInterval and the last received
    /// Desired Min TX. 0 before the peer spoke.
    ///
    /// G3.9b: after the peer lowers its Desired Min TX (the 1 s → fast
    /// step right after Up, §6.8.3), the old value stays in the formula
    /// until a packet proves the new rate ([`Session::remote_tx_hold`]).
    pub fn detection_time(&self) -> u64 {
        let tx = self.remote_desired_tx.max(self.remote_tx_hold);
        u64::from(self.remote_mult) * u64::from(self.rx_for_detect.max(tx))
    }

    /// The peer's former, larger Desired Min TX still held in the
    /// Detection Time (0: none, the advertised value rules).
    pub fn remote_tx_hold(&self) -> u32 {
        self.remote_tx_hold
    }

    /// G3.9b, the peer's side of RFC 5880 §6.8.3. The RFC protects the
    /// receiver when *we* lower bfd.RequiredMinRxInterval: "the previous
    /// value … MUST be used when calculating the Detection Time … to
    /// ensure that the remote system is transmitting packets at the higher
    /// rate (and those packets are being received) prior to the Detection
    /// Time being reduced". When the *peer* lowers its Desired Min TX the
    /// RFC applies the change at once, which trusts the peer to speed up
    /// at once. RouterOS 7.25 does not: right after Up it advertises
    /// 100 ms but keeps sending at ~1 s for a while, so 3 × 100 ms expires
    /// and every new session flaps (15 downs in 30 s, **measured**; FRR's
    /// `bfdd`, which follows the letter, 13). So the same principle runs
    /// on our side: the old, larger value stays in the Detection Time
    /// until two packets on the peer's periodic schedule arrive no further
    /// apart than the new interval. The cost is a slower detection for
    /// that one interval transition, never a false Down.
    ///
    /// `prev` is the Desired Min TX received before `p`; `same_state`
    /// whether `p` kept the peer's state (a state change is sent at once,
    /// outside the schedule, as is a Final: §6.8.6 / §6.8.7).
    fn track_remote_tx(&mut self, prev: u32, p: &Packet, same_state: bool, now: u64) {
        let new = p.desired_min_tx;
        if prev != 0 && new < prev {
            // The announcing packet itself may be triggered (a Poll or a
            // state change sent at once): it never starts the proof.
            self.remote_tx_hold = self.remote_tx_hold.max(prev);
            self.hold_rx_at = None;
            return;
        }
        if self.remote_tx_hold == 0 {
            return;
        }
        if new >= self.remote_tx_hold {
            self.remote_tx_hold = 0;
            self.hold_rx_at = None;
            return;
        }
        if p.final_ || !same_state {
            return;
        }
        // The peer's interval at the new rate (§6.8.7: the larger of its
        // Desired Min TX and our Required Min RX, minus 0–25 % jitter).
        let interval = u64::from(new.max(self.adv_rx));
        if let Some(at) = self.hold_rx_at
            && now.saturating_sub(at) <= interval
        {
            self.remote_tx_hold = 0;
            self.hold_rx_at = None;
        } else {
            self.hold_rx_at = Some(now);
        }
    }

    /// The earliest time [`Session::on_timer`] has work.
    pub fn next_deadline(&self) -> Option<u64> {
        [self.next_tx, self.detect_at, self.forget_auth_at]
            .into_iter()
            .flatten()
            .min()
    }

    /// §6.8.7: no periodic packets when the peer asks for none (Required
    /// Min RX 0), when it is in Demand mode with both sides Up (and no
    /// Poll of ours is running), or (§6.1, passive) before it spoke.
    fn periodic_allowed(&self) -> bool {
        if self.remote_min_rx == 0 {
            return false;
        }
        if self.remote_demand
            && self.state == State::Up
            && self.remote_state == State::Up
            && !self.poll_active
        {
            return false;
        }
        !(self.cfg.passive && self.remote_discr == 0)
    }

    /// §6.8.7 jitter: the interval reduced by 0–25 %, or by 10–25 % when
    /// bfd.DetectMult is 1 ("between 75% and 90%").
    fn schedule_tx(&mut self, now: u64) {
        if !self.periodic_allowed() {
            self.next_tx = None;
            return;
        }
        let top = if self.cfg.detect_mult == 1 { 900 } else { 1000 };
        let permille = 750 + u64::from(self.random()) % (top - 750 + 1);
        self.next_tx = Some(now + u64::from(self.tx_interval()) * permille / 1000);
    }

    fn set_state(&mut self, to: State, diag: Diag) -> Option<Change> {
        let from = self.state;
        if from == to {
            return None;
        }
        self.state = to;
        self.local_diag = diag;
        if to == State::Up {
            // Fast timers now need a Poll Sequence (§6.8.3): a smaller
            // transmit interval applies at once, a larger one after it.
            let before = self.adv_tx;
            self.adv_tx = self.cfg.desired_min_tx;
            if self.adv_tx <= self.tx_used {
                self.tx_used = self.adv_tx;
            }
            self.poll_active = self.adv_tx != before;
        } else if to != State::Init {
            // Leaving Up: back to at least 1 s, at once (not Up, no Poll).
            self.adv_tx = self.cfg.desired_min_tx.max(SLOW_TX_US);
            self.tx_used = self.adv_tx;
            self.rx_for_detect = self.adv_rx;
            self.poll_active = false;
        }
        Some(Change { from, to, diag })
    }

    /// §6.8.6 from "If the Your Discriminator field is zero…" on: the
    /// caller already decoded `p` from `raw` (the byte checks), matched it
    /// to this session (Your Discriminator, or the addresses when zero)
    /// and checked the TTL (RFC 5881 §5 / RFC 5883 §5).
    pub fn receive(&mut self, raw: &[u8], p: &Packet, now: u64) -> Result<Received, Refused> {
        if p.your_discr == 0 && !matches!(p.state, State::Down | State::AdminDown) {
            return Err(Refused::ZeroYourDiscr);
        }
        match (&p.auth, &self.cfg.auth) {
            (None, None) => {}
            (Some(_), Some(cfg)) => {
                // Erratum 7083: the state moves only after the hash passed.
                self.rcv_seq = auth::verify(raw, p, cfg, self.rcv_seq).map_err(Refused::Auth)?;
            }
            _ => return Err(Refused::Auth(auth::AuthError::Mismatch)),
        }
        self.rx_packets += 1;
        let before_rx = self.remote_min_rx;
        let prev_tx = self.remote_desired_tx;
        let same_state = p.state == self.remote_state;
        self.track_remote_tx(prev_tx, p, same_state, now);
        self.remote_discr = p.my_discr;
        self.remote_state = p.state;
        self.remote_demand = p.demand;
        self.remote_min_rx = p.required_min_rx;
        self.remote_desired_tx = p.desired_min_tx;
        self.remote_mult = p.detect_mult;
        self.remote_cpi = p.cpi;
        let mut out = Received::default();
        // §6.5: the Final ends our Poll Sequence; the held values apply.
        if p.final_ && self.poll_active {
            self.poll_active = false;
            self.tx_used = self.adv_tx;
            self.rx_for_detect = self.adv_rx;
        }
        let detect = self.detection_time();
        self.detect_at = (detect > 0).then_some(now + detect);
        // §6.8.1 bfd.AuthSeqKnown: forgotten after two Detection Times of silence.
        self.forget_auth_at = (self.cfg.auth.is_some() && detect > 0).then_some(now + 2 * detect);
        if self.state != State::AdminDown {
            out.change = if p.state == State::AdminDown {
                if self.state != State::Down {
                    self.set_state(State::Down, Diag::NeighborSignaledDown)
                } else {
                    None
                }
            } else {
                match (self.state, p.state) {
                    (State::Down, State::Down) => self.set_state(State::Init, Diag::None),
                    (State::Down, State::Init) => self.set_state(State::Up, Diag::None),
                    (State::Init, State::Init | State::Up) => self.set_state(State::Up, Diag::None),
                    (State::Up, State::Down) => {
                        self.set_state(State::Down, Diag::NeighborSignaledDown)
                    }
                    _ => None,
                }
            };
        }
        out.send_final = p.poll;
        out.send_now = out.change.is_some();
        if out.send_now || !self.periodic_allowed() {
            self.schedule_tx(now);
        } else if before_rx != self.remote_min_rx || self.next_tx.is_none() {
            // A new interval asked by the peer, or periodic packets allowed
            // again: reschedule, keeping an earlier timer already set.
            let old = self.next_tx;
            self.schedule_tx(now);
            if let (Some(o), Some(n)) = (old, self.next_tx)
                && o < n
            {
                self.next_tx = Some(o);
            }
        }
        Ok(out)
    }

    /// Runs the timers due at `now`.
    pub fn on_timer(&mut self, now: u64) -> Fired {
        let mut out = Fired::default();
        if let Some(at) = self.detect_at
            && at <= now
        {
            self.detect_at = None;
            // §6.8.4: Down with Diag 1 when Init or Up; §6.8.1:
            // bfd.RemoteDiscr back to zero after a Detection Time of silence.
            if matches!(self.state, State::Init | State::Up) {
                out.change = self.set_state(State::Down, Diag::ControlDetectionTimeExpired);
            }
            self.remote_discr = 0;
            self.remote_state = State::Down;
            self.remote_demand = false;
            self.remote_tx_hold = 0;
            self.hold_rx_at = None;
            if out.change.is_some() {
                out.send = true;
                self.schedule_tx(now);
            }
        }
        if let Some(at) = self.forget_auth_at
            && at <= now
        {
            self.forget_auth_at = None;
            self.rcv_seq.known = false;
        }
        if let Some(at) = self.next_tx
            && at <= now
            && !out.send
        {
            out.send = true;
            out.late_us = now - at;
            self.schedule_tx(now);
        }
        out
    }

    /// Writes the next packet (§6.8.7 contents). `final_` answers a Poll.
    pub fn build(&mut self, final_: bool, out: &mut [u8; MAX_LEN]) -> usize {
        let mut p = Packet::new(self.local_discr);
        p.diag = self.local_diag;
        p.state = self.state;
        // §6.5: never Poll and Final together.
        p.poll = self.poll_active && !final_;
        p.final_ = final_;
        p.detect_mult = self.cfg.detect_mult;
        p.your_discr = self.remote_discr;
        p.desired_min_tx = self.adv_tx;
        p.required_min_rx = self.adv_rx;
        self.tx_packets += 1;
        match &self.cfg.auth {
            Some(a) => {
                let a = a.clone();
                let seq = self.xmit_seq;
                self.xmit_seq = self.xmit_seq.wrapping_add(1);
                auth::sign(&mut p, &a, seq, out)
            }
            None => p.encode(out),
        }
    }

    /// New operator settings. Up: the intervals change through a Poll
    /// Sequence (§6.8.3: a larger transmit interval and a smaller receive
    /// one wait for the Final). Returns the change of an admin toggle.
    pub fn set_config(&mut self, cfg: Config, now: u64) -> Option<Change> {
        let auth_changed = cfg.auth != self.cfg.auth;
        let admin = cfg.admin_down;
        self.cfg = cfg;
        if auth_changed {
            self.rcv_seq = RcvSeq::default();
        }
        if admin && self.state != State::AdminDown {
            let c = self.set_state(State::AdminDown, Diag::AdministrativelyDown);
            self.remote_discr = 0;
            self.schedule_tx(now);
            return c;
        }
        if !admin && self.state == State::AdminDown {
            let c = self.set_state(State::Down, Diag::None);
            self.next_tx = Some(now);
            return c;
        }
        if self.state == State::Up {
            self.adv_tx = self.cfg.desired_min_tx;
            if self.adv_tx <= self.tx_used {
                self.tx_used = self.adv_tx;
            }
            self.adv_rx = self.cfg.required_min_rx;
            if self.adv_rx >= self.rx_for_detect {
                self.rx_for_detect = self.adv_rx;
            }
            self.poll_active = true;
            self.next_tx = Some(now);
        } else {
            self.adv_tx = self.cfg.desired_min_tx.max(SLOW_TX_US);
            self.tx_used = self.adv_tx;
            self.adv_rx = self.cfg.required_min_rx;
            self.rx_for_detect = self.adv_rx;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: u64 = 1_000;

    fn fast() -> Config {
        Config {
            desired_min_tx: 50_000,
            required_min_rx: 50_000,
            detect_mult: 3,
            ..Config::default()
        }
    }

    /// Two sessions wired back to back with a fake clock: delivers what
    /// each sends, drops the link when `cut`.
    struct Wire {
        a: Session,
        b: Session,
        now: u64,
        cut: bool,
        changes: Vec<(char, Change)>,
    }

    impl Wire {
        fn new(ca: Config, cb: Config) -> Self {
            Self {
                a: Session::new(0x1111, ca, 0, 1),
                b: Session::new(0x2222, cb, 0, 2),
                now: 0,
                cut: false,
                changes: vec![],
            }
        }

        fn deliver(&mut self, from_a: bool, final_: bool) {
            let mut buf = [0u8; MAX_LEN];
            let (src, dst, tag) = if from_a {
                (&mut self.a, &mut self.b, 'b')
            } else {
                (&mut self.b, &mut self.a, 'a')
            };
            let n = src.build(final_, &mut buf);
            if self.cut {
                return;
            }
            let p = Packet::decode(&buf[..n]).unwrap();
            let r = dst.receive(&buf[..n], &p, self.now).unwrap();
            if let Some(c) = r.change {
                self.changes.push((tag, c));
            }
            if r.send_final {
                self.deliver(!from_a, true);
            } else if r.send_now {
                self.deliver(!from_a, false);
            }
        }

        /// Advances 1 ms at a time to `until`.
        fn run(&mut self, until: u64) {
            while self.now < until {
                self.now += MS;
                for from_a in [true, false] {
                    let s = if from_a { &mut self.a } else { &mut self.b };
                    let f = s.on_timer(self.now);
                    if let Some(c) = f.change {
                        self.changes.push((if from_a { 'a' } else { 'b' }, c));
                    }
                    if f.send {
                        self.deliver(from_a, false);
                    }
                }
            }
        }
    }

    /// G3.9fj, RFC 5880 §4.1: the peer's C bit is kept from its packets.
    #[test]
    fn the_peers_c_bit_is_kept() {
        let mut a = Session::new(0x1111, fast(), 0, 1);
        let mut b = Session::new(0x2222, fast(), 0, 2);
        let mut buf = [0u8; MAX_LEN];
        let n = b.build(false, &mut buf);
        let mut p = Packet::decode(&buf[..n]).unwrap();
        p.cpi = true;
        let mut raw = [0u8; MAX_LEN];
        let m = p.encode(&mut raw);
        let p = Packet::decode(&raw[..m]).unwrap();
        a.receive(&raw[..m], &p, MS).unwrap();
        assert!(a.remote_cpi());
    }

    #[test]
    fn three_way_handshake_comes_up() {
        let mut w = Wire::new(fast(), fast());
        w.run(20 * MS);
        assert_eq!(w.a.state(), State::Up);
        assert_eq!(w.b.state(), State::Up);
        assert_eq!(w.a.remote_discr(), 0x2222);
        // G3.9fj: CoreRouter's engine sends C = 0 (it shares fate with the
        // daemon, not with the kernel's forwarding).
        assert!(!w.a.remote_cpi());
        // §6.8.3: once Up and the Poll answered, the fast interval rules.
        w.run(200 * MS);
        assert!(!w.a.poll_active() && !w.b.poll_active());
        assert_eq!(w.a.tx_interval(), 50_000);
        assert_eq!(w.a.detection_time(), 150_000);
    }

    #[test]
    fn slow_timer_while_down() {
        // §6.8.3: not Up → advertised Desired Min TX ≥ 1 s.
        let mut s = Session::new(5, fast(), 0, 3);
        let mut buf = [0u8; MAX_LEN];
        let n = s.build(false, &mut buf);
        let p = Packet::decode(&buf[..n]).unwrap();
        assert_eq!(p.desired_min_tx, SLOW_TX_US);
        assert_eq!(p.required_min_rx, 50_000);
        assert_eq!(p.your_discr, 0);
    }

    #[test]
    fn detection_time_expiry_goes_down_with_diag_1() {
        let mut w = Wire::new(fast(), fast());
        w.run(500 * MS);
        assert_eq!(w.a.state(), State::Up);
        w.cut = true;
        let cut_at = w.now;
        w.changes.clear();
        w.run(cut_at + 400 * MS);
        let (_, c) = w.changes.iter().find(|(t, _)| *t == 'a').copied().unwrap();
        assert_eq!(c.to, State::Down);
        assert_eq!(c.diag, Diag::ControlDetectionTimeExpired);
        assert_eq!(w.a.remote_discr(), 0, "§6.8.1: RemoteDiscr reset");
        assert_eq!(w.a.state(), State::Down);
    }

    #[test]
    fn detection_happens_within_detect_time() {
        let mut w = Wire::new(fast(), fast());
        w.run(500 * MS);
        w.cut = true;
        let cut_at = w.now;
        let mut down_at = None;
        while w.now < cut_at + 400 * MS && down_at.is_none() {
            w.run(w.now + MS);
            if w.a.state() == State::Down {
                down_at = Some(w.now);
            }
        }
        let took = down_at.unwrap() - cut_at;
        // Last packet arrived at most one (jittered) interval before the
        // cut: detection in (150 − 50, 150] ms.
        assert!((100 * MS..=151 * MS).contains(&took), "{took}");
    }

    #[test]
    fn neighbor_admin_down_is_diag_3() {
        let mut w = Wire::new(fast(), fast());
        w.run(300 * MS);
        let mut cb = fast();
        cb.admin_down = true;
        let c = w.b.set_config(cb, w.now).unwrap();
        assert_eq!(c.to, State::AdminDown);
        w.deliver(false, false);
        assert_eq!(w.a.state(), State::Down);
        assert_eq!(w.a.local_diag(), Diag::NeighborSignaledDown);
        assert_eq!(w.a.remote_state(), State::AdminDown);
        // Back from AdminDown: comes up again.
        w.b.set_config(fast(), w.now);
        w.run(w.now + 3_000 * MS);
        assert_eq!(w.a.state(), State::Up);
    }

    #[test]
    fn zero_your_discr_only_while_down() {
        let mut s = Session::new(9, fast(), 0, 3);
        let mut p = Packet::new(44);
        p.state = State::Up;
        let mut buf = [0u8; MAX_LEN];
        let n = p.encode(&mut buf);
        assert_eq!(s.receive(&buf[..n], &p, 0), Err(Refused::ZeroYourDiscr));
    }

    #[test]
    fn auth_presence_must_match() {
        let mut s = Session::new(9, fast(), 0, 3);
        let mut p = Packet::new(44);
        let mut buf = [0u8; MAX_LEN];
        let a = AuthConfig::new(false, 1, b"k").unwrap();
        let n = auth::sign(&mut p, &a, 1, &mut buf);
        let back = Packet::decode(&buf[..n]).unwrap();
        assert!(matches!(
            s.receive(&buf[..n], &back, 0),
            Err(Refused::Auth(_))
        ));
        let mut cfg = fast();
        cfg.auth = Some(a);
        let mut s = Session::new(9, cfg, 0, 3);
        assert!(s.receive(&buf[..n], &back, 0).is_ok());
    }

    #[test]
    fn authenticated_pair_comes_up_and_stays() {
        let mut ca = fast();
        ca.auth = AuthConfig::new(true, 3, b"shared-key");
        let mut w = Wire::new(ca.clone(), ca);
        w.run(2_000 * MS);
        assert_eq!(w.a.state(), State::Up);
        assert_eq!(w.b.state(), State::Up);
        assert!(w.changes.iter().all(|(_, c)| c.to != State::Down));
    }

    #[test]
    fn jitter_stays_in_75_to_100_percent() {
        // §6.8.7, with DetectMult 1 at most 90 %.
        for (mult, top) in [(3u8, 1000u64), (1, 900)] {
            let mut cfg = fast();
            cfg.detect_mult = mult;
            let mut s = Session::new(1, cfg, 0, 99);
            // Pretend Up with the peer asking 50 ms.
            s.state = State::Up;
            s.tx_used = 100_000;
            s.remote_min_rx = 100_000;
            let (mut lo, mut hi) = (u64::MAX, 0);
            for i in 0..5000u64 {
                s.schedule_tx(i);
                let d = s.next_tx.unwrap() - i;
                lo = lo.min(d);
                hi = hi.max(d);
            }
            assert!((75_000..76_000).contains(&lo), "{lo}");
            assert!(hi <= top * 100 && hi > top * 100 - 1_000, "{hi}");
        }
    }

    #[test]
    fn remote_required_min_rx_zero_stops_periodic() {
        let mut s = Session::new(1, fast(), 0, 1);
        let mut p = Packet::new(7);
        p.required_min_rx = 0;
        let mut buf = [0u8; MAX_LEN];
        let n = p.encode(&mut buf);
        s.receive(&buf[..n], &p, 10).unwrap();
        assert_eq!(s.next_tx, None);
        // Only the 3 s detection expiry would send (a state change).
        assert!(!s.on_timer(1_000_000).send);
    }

    #[test]
    fn remote_demand_mode_stops_periodic_when_both_up() {
        let mut w = Wire::new(fast(), fast());
        w.run(300 * MS);
        let mut p = Packet::new(0x2222);
        p.state = State::Up;
        p.demand = true;
        p.your_discr = 0x1111;
        p.desired_min_tx = 50_000;
        p.required_min_rx = 50_000;
        let mut buf = [0u8; MAX_LEN];
        let n = p.encode(&mut buf);
        w.a.receive(&buf[..n], &p, w.now).unwrap();
        assert_eq!(w.a.next_tx, None);
    }

    #[test]
    fn poll_sequence_on_interval_change() {
        let mut w = Wire::new(fast(), fast());
        w.run(500 * MS);
        // Raise A's TX to 200 ms: the old 50 ms stays until the Final.
        let mut c = fast();
        c.desired_min_tx = 200_000;
        w.a.set_config(c, w.now);
        assert!(w.a.poll_active());
        assert_eq!(w.a.tx_used, 50_000);
        w.run(w.now + 300 * MS);
        assert!(!w.a.poll_active());
        assert_eq!(w.a.tx_interval(), 200_000);
        // B detects with A's new Desired Min TX: 3 × 200 ms.
        assert_eq!(w.b.detection_time(), 600_000);
        assert!(w.changes.iter().all(|(_, c)| c.to != State::Down));
    }

    /// A peer driven by hand: what RouterOS 7.25 does around Up.
    struct Scripted {
        discr: u32,
        state: State,
        desired_tx: u32,
    }

    impl Scripted {
        fn send(&self, to: &mut Session, now: u64, poll: bool, final_: bool) -> Received {
            let mut p = Packet::new(self.discr);
            p.state = self.state;
            p.your_discr = if self.state == State::Down {
                0
            } else {
                to.local_discr()
            };
            p.desired_min_tx = self.desired_tx;
            p.required_min_rx = 100_000;
            p.detect_mult = 3;
            p.poll = poll;
            p.final_ = final_;
            let mut buf = [0u8; MAX_LEN];
            let n = p.encode(&mut buf);
            let back = Packet::decode(&buf[..n]).unwrap();
            to.receive(&buf[..n], &back, now).unwrap()
        }
    }

    /// Runs `s`'s timers 1 ms at a time over (from, to]; the first change.
    fn tick(s: &mut Session, from: u64, to: u64) -> Option<(u64, Change)> {
        let mut t = from;
        while t < to {
            t += MS;
            if let Some(c) = s.on_timer(t).change {
                return Some((t, c));
            }
        }
        None
    }

    fn hundred() -> Config {
        Config {
            desired_min_tx: 100_000,
            required_min_rx: 100_000,
            detect_mult: 3,
            ..Config::default()
        }
    }

    /// Brings `a` Up against a RouterOS-like peer: Down at 1 s, then Up
    /// announcing 100 ms (with a Poll) at `t0`. Returns the peer.
    fn up_with_routeros(a: &mut Session, t0: u64) -> Scripted {
        let mut r = Scripted {
            discr: 0x7e57,
            state: State::Down,
            desired_tx: SLOW_TX_US,
        };
        r.send(a, t0 - 10 * MS, false, false);
        assert_eq!(a.state(), State::Init);
        r.state = State::Up;
        r.desired_tx = 100_000;
        r.send(a, t0, true, false);
        assert_eq!(a.state(), State::Up);
        r
    }

    #[test]
    fn routeros_slow_start_after_up_does_not_flap() {
        // RFC 5880 §6.8.3 (G3.9b): the peer announces 100 ms at Up but
        // keeps sending at ~1 s for 5 s. The Detection Time keeps the old
        // 1 s (3 s) until two periodic packets 100 ms apart arrive.
        let mut a = Session::new(0xa, hundred(), 0, 7);
        let r = up_with_routeros(&mut a, 20 * MS);
        assert_eq!(a.remote_tx_hold(), SLOW_TX_US);
        assert_eq!(a.detection_time(), 3_000_000);
        let mut t = 20 * MS;
        // Slow phase: one packet every ~950 ms (a jittered 1 s), 5 s long.
        for _ in 0..5 {
            assert_eq!(
                tick(&mut a, t, t + 950 * MS),
                None,
                "flapped at the slow rate"
            );
            t += 950 * MS;
            r.send(&mut a, t, false, false);
            assert_eq!(a.detection_time(), 3_000_000, "held while slow");
        }
        // The peer speeds up: the first periodic packet 100 ms after the
        // previous one proves the new rate.
        t += 90 * MS;
        r.send(&mut a, t, false, false);
        assert_eq!(a.remote_tx_hold(), 0);
        assert_eq!(a.detection_time(), 300_000);
        // Now a silence goes Down in the fast Detection Time, not 3 s.
        let (at, c) = tick(&mut a, t, t + 1_000 * MS).unwrap();
        assert_eq!(c.diag, Diag::ControlDetectionTimeExpired);
        assert_eq!(at - t, 300 * MS);
    }

    #[test]
    fn hold_ignores_out_of_schedule_packets() {
        // A Final (§6.8.6: sent at once) right after a periodic packet,
        // or the triggered packet that announces the decrease, does not
        // prove the new rate.
        let mut a = Session::new(0xa, hundred(), 0, 7);
        let r = up_with_routeros(&mut a, 20 * MS);
        r.send(&mut a, 30 * MS, false, true);
        assert_eq!(
            a.remote_tx_hold(),
            SLOW_TX_US,
            "Final 10 ms after the announcing packet"
        );
        r.send(&mut a, 980 * MS, false, false);
        r.send(&mut a, 985 * MS, false, true);
        assert_eq!(
            a.remote_tx_hold(),
            SLOW_TX_US,
            "Final 5 ms after a periodic packet"
        );
        // A later decrease while held keeps the largest value.
        let mut r2 = Scripted {
            desired_tx: 50_000,
            ..r
        };
        r2.send(&mut a, 1_900 * MS, true, false);
        assert_eq!(a.remote_tx_hold(), SLOW_TX_US);
        // An increase back to (or above) the held value ends the hold.
        r2.desired_tx = SLOW_TX_US;
        r2.send(&mut a, 2_800 * MS, true, false);
        assert_eq!(a.remote_tx_hold(), 0);
        assert_eq!(a.state(), State::Up);
    }

    #[test]
    fn a_prompt_peer_gets_the_fast_detection_in_two_packets() {
        // Two CoreRouters: each speeds up at once, so the hold lasts two
        // fast packets and detection matches the strict §6.8.4 formula.
        let mut w = Wire::new(fast(), fast());
        w.run(20 * MS);
        assert_eq!(w.a.state(), State::Up);
        w.run(w.now + 150 * MS);
        assert_eq!(w.a.remote_tx_hold(), 0);
        assert_eq!(w.b.remote_tx_hold(), 0);
        assert_eq!(w.a.detection_time(), 150_000);
    }

    #[test]
    fn passive_waits_for_the_peer() {
        let mut c = fast();
        c.passive = true;
        let s = Session::new(1, c, 0, 1);
        assert_eq!(s.next_tx, None);
        let mut w = Wire::new(fast(), {
            let mut c = fast();
            c.passive = true;
            c
        });
        w.run(1_500 * MS);
        assert_eq!(w.b.state(), State::Up);
    }
}
