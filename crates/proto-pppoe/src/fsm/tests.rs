//! RFC 1661 §4 transitions, against a toy layer with one option (kind 1, a
//! u16 the peer accepts inside a range).

use super::*;
use crate::ppp::{options, parse_control, put_opt};
use std::collections::VecDeque;

const PROTO: u16 = 0x8021;

struct Toy {
    want: u16,
    accept: std::ops::RangeInclusive<u16>,
    peer_value: Option<u16>,
    acked: Option<u16>,
    send_option: bool,
    must: bool,
}

impl Toy {
    fn new(want: u16, accept: std::ops::RangeInclusive<u16>) -> Toy {
        Toy {
            want,
            accept,
            peer_value: None,
            acked: None,
            send_option: true,
            must: true,
        }
    }
}

fn val(d: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes(d.try_into().ok()?))
}

impl Layer for Toy {
    const PROTOCOL: u16 = PROTO;
    fn request(&mut self, out: &mut Vec<u8>) {
        if self.send_option {
            put_opt(out, 1, &self.want.to_be_bytes()).unwrap();
        }
    }
    fn classify(
        &mut self,
        opts: &[u8],
        nak: &mut Vec<u8>,
        rej: &mut Vec<u8>,
    ) -> Result<(), WireError> {
        for o in options(opts) {
            let o = o?;
            match (o.kind, val(o.data)) {
                (1, Some(v)) if self.accept.contains(&v) => {}
                (1, Some(_)) => put_opt(nak, 1, &self.accept.start().to_be_bytes())?,
                _ => put_opt(rej, o.kind, o.data)?,
            }
        }
        Ok(())
    }
    fn peer_acked(&mut self, opts: &[u8]) {
        self.peer_value = options(opts)
            .flatten()
            .find(|o| o.kind == 1)
            .and_then(|o| val(o.data));
    }
    fn acked(&mut self, opts: &[u8]) {
        self.acked = options(opts)
            .flatten()
            .find(|o| o.kind == 1)
            .and_then(|o| val(o.data));
    }
    fn naked(&mut self, opts: &[u8]) {
        if let Some(v) = options(opts)
            .flatten()
            .find(|o| o.kind == 1)
            .and_then(|o| val(o.data))
        {
            self.want = v;
        }
    }
    fn rejected(&mut self, opts: &[u8]) -> bool {
        if options(opts).flatten().any(|o| o.kind == 1) {
            self.send_option = false;
            return !self.must;
        }
        true
    }
}

/// Collects sent packets as (code, id, body).
#[derive(Default)]
struct Wire(VecDeque<(u8, u8, Vec<u8>)>);

impl Tx for Wire {
    fn send(&mut self, protocol: u16, code: u8, id: u8, body: &[u8]) {
        assert_eq!(protocol, PROTO);
        self.0.push_back((code, id, body.to_vec()));
    }
}

struct End {
    fsm: Fsm,
    layer: Toy,
    wire: Wire,
    scratch: Scratch,
    sig: Signals,
}

impl End {
    fn new(id: u8, layer: Toy) -> End {
        End {
            fsm: Fsm::new(id),
            layer,
            wire: Wire::default(),
            scratch: Scratch::default(),
            sig: Signals::default(),
        }
    }

    fn with<R>(&mut self, now: Millis, f: impl FnOnce(&mut Fsm, &mut Ctx<'_>, &mut Toy) -> R) -> R {
        let cfg = FsmConfig::default();
        let mut ctx = Ctx {
            now,
            cfg: &cfg,
            tx: &mut self.wire,
            scratch: &mut self.scratch,
        };
        f(&mut self.fsm, &mut ctx, &mut self.layer)
    }

    fn note(&mut self, s: Signals) {
        self.sig.tld |= s.tld;
        self.sig.tlu |= s.tlu;
        self.sig.tls |= s.tls;
        self.sig.tlf |= s.tlf;
        self.sig.refused |= s.refused;
    }

    fn start(&mut self, now: Millis) {
        let s = self.with(now, |f, c, l| {
            f.open(c, l);
            f.up(c, l)
        });
        self.note(s);
    }

    fn deliver(&mut self, now: Millis, code: u8, id: u8, body: &[u8]) {
        let mut raw = vec![code, id, 0, 0];
        raw.extend_from_slice(body);
        let n = raw.len() as u16;
        raw[2..4].copy_from_slice(&n.to_be_bytes());
        let pkt = parse_control(&raw).unwrap();
        let s = self.with(now, |f, c, l| f.receive(c, l, pkt)).unwrap();
        self.note(s);
    }

    fn tick(&mut self, now: Millis) {
        let s = self.with(now, |f, c, l| f.timeout(c, l));
        self.note(s);
    }
}

/// Moves packets both ways until both wires are quiet.
fn pump(a: &mut End, b: &mut End, now: Millis) {
    for _ in 0..100 {
        let mut moved = false;
        while let Some((c, i, d)) = a.wire.0.pop_front() {
            b.deliver(now, c, i, &d);
            moved = true;
        }
        while let Some((c, i, d)) = b.wire.0.pop_front() {
            a.deliver(now, c, i, &d);
            moved = true;
        }
        if !moved {
            return;
        }
    }
    panic!("no convergence");
}

#[test]
fn rfc1661_4_two_ends_reach_opened() {
    let mut a = End::new(1, Toy::new(1492, 1000..=1500));
    let mut b = End::new(100, Toy::new(1480, 1000..=1500));
    a.start(0);
    b.start(0);
    pump(&mut a, &mut b, 0);
    assert_eq!(a.fsm.state(), State::Opened);
    assert_eq!(b.fsm.state(), State::Opened);
    assert!(a.sig.tlu && b.sig.tlu);
    assert_eq!(a.layer.peer_value, Some(1480));
    assert_eq!(b.layer.acked, Some(1480));
    assert_eq!(a.fsm.deadline(), None, "§4.6: no restart timer in Opened");
}

#[test]
fn rfc1661_5_3_nak_moves_the_next_request() {
    let mut a = End::new(1, Toy::new(9000, 1000..=1500));
    let mut b = End::new(50, Toy::new(1400, 1400..=1400));
    a.start(0);
    b.start(0);
    pump(&mut a, &mut b, 0);
    assert_eq!(a.fsm.state(), State::Opened);
    assert_eq!(a.layer.want, 1400, "a took b's Nak suggestion");
    assert_eq!(b.layer.peer_value, Some(1400));
}

#[test]
fn rfc1661_4_6_max_configure_then_tlf() {
    let mut a = End::new(1, Toy::new(1492, 0..=u16::MAX));
    a.start(0);
    let mut now = 0;
    for _ in 0..20 {
        now += 3000;
        a.tick(now);
    }
    let crs = a
        .wire
        .0
        .iter()
        .filter(|p| p.0 == code::CONFIGURE_REQUEST)
        .count();
    assert_eq!(crs, 10, "Max-Configure = 10 requests");
    assert!(a.sig.tlf);
    assert_eq!(a.fsm.state(), State::Stopped);
    assert_eq!(a.fsm.deadline(), None);
}

#[test]
fn rfc1661_4_6_restart_timer_is_three_seconds() {
    let mut a = End::new(1, Toy::new(1, 0..=9));
    a.start(1000);
    assert_eq!(a.fsm.deadline(), Some(4000));
    a.tick(3999);
    assert_eq!(a.wire.0.len(), 1, "not yet");
    a.tick(4000);
    assert_eq!(a.wire.0.len(), 2);
}

#[test]
fn rfc1661_5_2_ack_must_match_id_and_options() {
    let mut a = End::new(7, Toy::new(1492, 0..=u16::MAX));
    a.start(0);
    let (_, id, body) = a.wire.0.pop_front().unwrap();
    a.deliver(0, code::CONFIGURE_ACK, id.wrapping_add(1), &body);
    assert_eq!(a.fsm.state(), State::ReqSent, "wrong id ignored");
    let mut changed = body.clone();
    changed[3] ^= 1;
    a.deliver(0, code::CONFIGURE_ACK, id, &changed);
    assert_eq!(a.fsm.state(), State::ReqSent, "modified options ignored");
    a.deliver(0, code::CONFIGURE_ACK, id, &body);
    assert_eq!(a.fsm.state(), State::AckRcvd);
}

#[test]
fn rfc1661_5_4_reject_must_be_a_subset_of_the_request() {
    let mut a = End::new(7, Toy::new(1492, 0..=u16::MAX));
    a.start(0);
    let (_, id, _) = a.wire.0.pop_front().unwrap();
    a.deliver(0, code::CONFIGURE_REJECT, id, &[9, 2]);
    assert_eq!(a.fsm.state(), State::ReqSent);
    assert!(a.wire.0.is_empty(), "invalid reject dropped silently");
}

#[test]
fn rejecting_a_required_option_closes() {
    let mut a = End::new(7, Toy::new(1492, 0..=u16::MAX));
    a.start(0);
    let (_, id, body) = a.wire.0.pop_front().unwrap();
    a.deliver(0, code::CONFIGURE_REJECT, id, &body);
    assert!(a.sig.refused);
    assert_eq!(a.fsm.state(), State::Closing);
    assert_eq!(a.wire.0.front().unwrap().0, code::TERMINATE_REQUEST);
}

#[test]
fn rfc1661_4_6_max_failure_turns_naks_into_rejects() {
    let mut a = End::new(1, Toy::new(1492, 1000..=1500));
    a.start(0);
    a.wire.0.clear();
    let mut codes = Vec::new();
    for id in 0..8u8 {
        a.deliver(0, code::CONFIGURE_REQUEST, id, &[1, 4, 0x23, 0x28]); // 9000
        codes.push(a.wire.0.pop_back().unwrap().0);
    }
    let naks = codes.iter().filter(|c| **c == code::CONFIGURE_NAK).count();
    assert_eq!(naks, 5, "Max-Failure = 5: {codes:?}");
    assert!(codes[5..].iter().all(|c| *c == code::CONFIGURE_REJECT));
}

#[test]
fn rfc1661_4_1_unknown_option_is_rejected_verbatim() {
    let mut a = End::new(1, Toy::new(1492, 0..=u16::MAX));
    a.start(0);
    a.wire.0.clear();
    a.deliver(0, code::CONFIGURE_REQUEST, 5, &[1, 4, 5, 0xd4, 42, 3, 9]);
    let (c, id, body) = a.wire.0.pop_back().unwrap();
    assert_eq!((c, id), (code::CONFIGURE_REJECT, 5));
    assert_eq!(body, vec![42, 3, 9]);
}

#[test]
fn malformed_request_is_dropped() {
    let mut a = End::new(1, Toy::new(1492, 0..=u16::MAX));
    a.start(0);
    a.wire.0.clear();
    a.deliver(0, code::CONFIGURE_REQUEST, 5, &[1, 9, 5]);
    assert!(a.wire.0.is_empty());
}

fn opened_pair() -> (End, End) {
    let mut a = End::new(1, Toy::new(1492, 0..=u16::MAX));
    let mut b = End::new(100, Toy::new(1492, 0..=u16::MAX));
    a.start(0);
    b.start(0);
    pump(&mut a, &mut b, 0);
    a.sig = Signals::default();
    b.sig = Signals::default();
    (a, b)
}

#[test]
fn rfc1661_4_1_opened_terminate_request_goes_to_stopping_then_stopped() {
    let (mut a, _) = opened_pair();
    a.deliver(10, code::TERMINATE_REQUEST, 77, &[]);
    assert!(a.sig.tld);
    assert_eq!(a.fsm.state(), State::Stopping);
    let (c, i, _) = a.wire.0.pop_back().unwrap();
    assert_eq!((c, i), (code::TERMINATE_ACK, 77));
    // zrc: one restart period, then TO- → tlf.
    a.tick(3010);
    assert!(a.sig.tlf);
    assert_eq!(a.fsm.state(), State::Stopped);
}

#[test]
fn rfc1661_4_6_close_sends_max_terminate_requests() {
    let (mut a, _) = opened_pair();
    let s = a.with(0, |f, c, _| f.close::<Toy>(c));
    a.note(s);
    assert!(a.sig.tld);
    for t in 1..=4 {
        a.tick(3000 * t);
    }
    let trs = a
        .wire
        .0
        .iter()
        .filter(|p| p.0 == code::TERMINATE_REQUEST)
        .count();
    assert_eq!(trs, 2, "Max-Terminate = 2");
    assert!(a.sig.tlf);
    assert_eq!(a.fsm.state(), State::Closed);
}

#[test]
fn close_handshake_between_two_ends() {
    let (mut a, mut b) = opened_pair();
    let s = a.with(0, |f, c, _| f.close::<Toy>(c));
    a.note(s);
    pump(&mut a, &mut b, 0);
    assert_eq!(a.fsm.state(), State::Closed);
    assert!(a.sig.tlf);
    assert_eq!(b.fsm.state(), State::Stopping);
    assert!(b.sig.tld);
}

#[test]
fn rfc1661_4_1_opened_rcr_renegotiates() {
    let (mut a, mut b) = opened_pair();
    b.deliver(0, code::CONFIGURE_REQUEST, 200, &[1, 4, 5, 0xd4]);
    assert!(b.sig.tld);
    assert_eq!(b.fsm.state(), State::AckSent);
    pump(&mut b, &mut a, 0);
    assert_eq!(b.fsm.state(), State::Opened);
}

#[test]
fn rfc1661_5_6_code_reject_of_a_needed_code_is_fatal() {
    let (mut a, _) = opened_pair();
    a.deliver(0, code::CODE_REJECT, 1, &[code::CONFIGURE_REQUEST, 1, 0, 4]);
    assert!(a.sig.tld);
    assert_eq!(a.fsm.state(), State::Stopping);
    let (mut b, _) = opened_pair();
    b.deliver(
        0,
        code::CODE_REJECT,
        1,
        &[code::ECHO_REQUEST, 1, 0, 8, 0, 0, 0, 0],
    );
    assert_eq!(b.fsm.state(), State::Opened, "RXJ+ changes nothing");
}

#[test]
fn rfc1661_4_1_closed_answers_with_terminate_ack() {
    let mut a = End::new(1, Toy::new(1, 0..=9));
    let s = a.with(0, |f, c, l| f.up(c, l));
    a.note(s);
    assert_eq!(a.fsm.state(), State::Closed);
    a.deliver(0, code::CONFIGURE_REQUEST, 9, &[]);
    let (c, i, _) = a.wire.0.pop_back().unwrap();
    assert_eq!((c, i), (code::TERMINATE_ACK, 9));
}

#[test]
fn packets_before_up_are_dropped() {
    let mut a = End::new(1, Toy::new(1, 0..=9));
    a.deliver(0, code::CONFIGURE_REQUEST, 9, &[]);
    assert!(a.wire.0.is_empty());
    assert_eq!(a.fsm.state(), State::Initial);
}

#[test]
fn down_from_opened_raises_tld() {
    let (mut a, _) = opened_pair();
    let s = a.fsm.down();
    assert!(s.tld);
    assert_eq!(a.fsm.state(), State::Starting);
}

#[test]
fn unknown_code_is_left_to_the_caller_and_code_rejected() {
    let (mut a, _) = opened_pair();
    let raw = [0x55, 1, 0, 4];
    let pkt = parse_control(&raw).unwrap();
    assert!(a.with(0, |f, c, l| f.receive(c, l, pkt)).is_none());
    a.with(0, |f, c, _| f.code_reject::<Toy>(c, &raw, 1492));
    let (c, _, body) = a.wire.0.pop_back().unwrap();
    assert_eq!(c, code::CODE_REJECT);
    assert_eq!(body, raw);
}

#[test]
fn rfc1661_5_2_a_duplicated_ack_does_not_renegotiate() {
    let mut a = End::new(1, Toy::new(1492, 0..=u16::MAX));
    let mut b = End::new(100, Toy::new(1492, 0..=u16::MAX));
    a.start(0);
    b.start(0);
    // Keep a copy of a's request and b's Ack to it.
    let (_, id, req) = a.wire.0.front().cloned().unwrap();
    pump(&mut a, &mut b, 0);
    assert_eq!(a.fsm.state(), State::Opened);
    a.sig = Signals::default();
    a.deliver(0, code::CONFIGURE_ACK, id, &req);
    assert_eq!(a.fsm.state(), State::Opened, "late duplicate Ack tossed");
    assert!(!a.sig.tld);
    a.deliver(0, code::CONFIGURE_NAK, id, &req);
    assert_eq!(a.fsm.state(), State::Opened, "and a late Nak for it too");
}
