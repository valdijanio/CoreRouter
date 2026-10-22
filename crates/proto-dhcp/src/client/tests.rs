//! The state machine against the lab server, on a simulated clock.

use std::net::Ipv4Addr;

use corerouter_hal::dhcp::{Datagram, Dest, DhcpResponder};
use corerouter_model::IfName;
use dhcproto::v4::{DhcpOption, Message, MessageType, OptionCode};
use dhcproto::{Decodable, Decoder};

use super::*;
use crate::lab::{Knobs, LabServer};

const MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];

/// A client wired to a lab server; records what the engine would see.
struct Net {
    server: LabServer,
    port: IfName,
    client: Client,
    sent: Vec<(MessageType, Dest, Ipv4Addr)>,
    events: Vec<Event>,
    bound: Option<Lease>,
    binds: usize,
    probing: bool,
}

fn settings() -> Settings {
    Settings {
        mac: MAC,
        client_id: vec![1, 2, 0, 0, 0, 0, 1],
        host_name: "cpe".into(),
        vendor_class: Vec::new(),
        extra: Vec::new(),
    }
}

impl Net {
    fn new(knobs: Knobs) -> Self {
        Self::with_filter(knobs, |_, _| true)
    }

    fn with_filter(
        knobs: Knobs,
        allowed: impl Fn(&[Ipv4Addr], Option<[u8; 6]>) -> bool + Send + 'static,
    ) -> Self {
        Self {
            server: LabServer::new(knobs),
            port: "ether1".parse().unwrap(),
            client: Client::new(settings(), allowed, 42),
            sent: Vec::new(),
            events: Vec::new(),
            bound: None,
            binds: 0,
            probing: false,
        }
    }

    fn run(&mut self, now: u64, actions: Vec<Action>) {
        for a in actions {
            match a {
                Action::Send { payload, src, dest } => {
                    let m = Message::decode(&mut Decoder::new(&payload)).unwrap();
                    self.sent.push((m.opts().msg_type().unwrap(), dest, src));
                    let answers = self.server.answer(&self.port, MAC, &payload, dest);
                    for d in answers {
                        let next = self.client.input(now, &d);
                        self.run(now, next);
                    }
                }
                Action::Probe(ip) => {
                    self.probing = true;
                    if let Some(by) = self.server.conflict(&self.port, ip) {
                        let next = self.client.conflict(now, by);
                        self.run(now, next);
                    }
                }
                Action::EndProbe => self.probing = false,
                Action::Bind(l) => {
                    self.bound = Some(*l);
                    self.binds += 1;
                }
                Action::Unbind => self.bound = None,
                Action::Log(e) => self.events.push(e),
            }
        }
    }

    fn start(&mut self, now: u64) {
        let a = self.client.start(now);
        self.run(now, a);
    }

    /// Poll every 250 ms from `from` to `to` (inclusive).
    fn advance(&mut self, from: u64, to: u64) {
        let mut t = from;
        while t <= to {
            let a = self.client.poll(t);
            self.run(t, a);
            t += 250;
        }
    }

    fn kinds(&self) -> Vec<MessageType> {
        self.sent.iter().map(|(k, _, _)| *k).collect()
    }

    fn take_sent(&mut self) -> Vec<(MessageType, Dest, Ipv4Addr)> {
        std::mem::take(&mut self.sent)
    }
}

fn bound_at_1s() -> Net {
    let mut n = Net::new(Knobs::default());
    n.start(0);
    assert_eq!(n.client.state(), State::Probing);
    n.advance(0, 1_000);
    assert_eq!(n.client.state(), State::Bound);
    n
}

#[test]
fn acquires_a_lease_with_discover_offer_request_ack() {
    let n = bound_at_1s();
    assert_eq!(n.kinds(), vec![MessageType::Discover, MessageType::Request]);
    assert!(
        n.sent
            .iter()
            .all(|(_, d, src)| *d == Dest::Broadcast && src.is_unspecified())
    );
    let l = n.bound.clone().unwrap();
    assert_eq!(
        l.address.to_string(),
        format!("{}/24", LabServer::address_for(&n.port, MAC))
    );
    assert_eq!(l.server, Ipv4Addr::new(100, 64, 1, 1));
    assert_eq!(l.gateway(), Some(Ipv4Addr::new(100, 64, 1, 1)));
    assert_eq!(l.classless.len(), 2);
    assert_eq!(l.lease_secs, 600);
    // Bound after the 1 s probe, at the first poll past it.
    assert_eq!(l.t1_ms, 300_000);
    assert_eq!(l.t2_ms, 525_000);
    assert_eq!(l.expires_ms, Some(600_000));
    assert_eq!(l.server_mac, Some([0x02, 0xdc, 0, 0, 0, 1]));
    assert!(l.options.iter().any(|(c, _)| *c == 121));
    assert!(matches!(n.events.first(), Some(Event::Searching)));
    assert!(n.events.iter().any(|e| matches!(
        e,
        Event::Bound {
            lease_secs: 600,
            ..
        }
    )));
    assert!(!n.probing, "probe ended");
}

#[test]
fn renews_at_t1_by_unicast() {
    let mut n = bound_at_1s();
    n.take_sent();
    n.advance(1_250, 299_750);
    assert!(n.sent.is_empty(), "quiet until T1");
    n.advance(300_000, 300_000);
    let sent = n.take_sent();
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].0, MessageType::Request);
    assert_eq!(sent[0].1, Dest::Unicast(Ipv4Addr::new(100, 64, 1, 1)));
    assert_eq!(sent[0].2, n.bound.as_ref().unwrap().address.addr());
    assert_eq!(n.client.state(), State::Bound);
    assert!(n.events.iter().any(|e| matches!(e, Event::Renewed { .. })));
    let l = n.bound.clone().unwrap();
    assert_eq!(l.t1_ms, 600_000);
    assert_eq!(l.expires_ms, Some(900_000));
    assert_eq!(n.binds, 2, "the refresh is a Bind of the same address");
}

#[test]
fn a_dead_server_means_renewing_then_rebinding_then_losing_the_lease() {
    let mut n = bound_at_1s();
    n.server.set(|k| k.silent = true);
    n.take_sent();
    n.advance(300_000, 524_750);
    let renew: Vec<_> = n.take_sent();
    assert!(renew.len() >= 2, "{renew:?}");
    assert!(
        renew
            .iter()
            .all(|(k, d, _)| *k == MessageType::Request && matches!(d, Dest::Unicast(_)))
    );
    assert_eq!(n.client.state(), State::Renewing);
    n.advance(525_000, 599_750);
    assert_eq!(n.client.state(), State::Rebinding);
    let rebind = n.take_sent();
    assert!(!rebind.is_empty());
    assert!(
        rebind
            .iter()
            .all(|(_, d, src)| *d == Dest::Broadcast && !src.is_unspecified())
    );
    assert!(n.bound.is_some(), "still ours until it expires");
    n.advance(600_000, 600_000);
    assert!(n.bound.is_none());
    assert!(
        n.events
            .iter()
            .any(|e| matches!(e, Event::Lost { reason, .. } if reason.contains("expired")))
    );
    assert_eq!(n.client.state(), State::Selecting);
    assert_eq!(n.take_sent()[0].0, MessageType::Discover);
}

#[test]
fn discover_backs_off_up_to_64_seconds() {
    let mut n = Net::new(Knobs {
        silent: true,
        ..Knobs::default()
    });
    let mut times = Vec::new();
    let mut t = 0;
    n.start(0);
    while t <= 300_000 {
        let before = n.sent.len();
        let a = n.client.poll(t);
        n.run(t, a);
        if n.sent.len() > before || t == 0 {
            times.push(t);
        }
        t += 250;
    }
    let gaps: Vec<u64> = times.windows(2).map(|w| w[1] - w[0]).collect();
    // 4, 8, 16, 32, 64, 64 … seconds, each ±1 s.
    for (gap, want) in gaps
        .iter()
        .zip([4_000u64, 8_000, 16_000, 32_000, 64_000, 64_000])
    {
        assert!(gap.abs_diff(want) <= 1_250, "gaps {gaps:?}");
    }
    assert_eq!(n.client.state(), State::Selecting);
}

#[test]
fn nak_while_renewing_drops_the_lease_and_starts_over() {
    let mut n = bound_at_1s();
    n.server.set(|k| k.nak = true);
    n.advance(300_000, 300_000);
    assert!(n.bound.is_none());
    assert!(
        n.events
            .iter()
            .any(|e| matches!(e, Event::Nak { message: Some(m), .. } if m.contains("lab")))
    );
    assert!(
        n.events
            .iter()
            .any(|e| matches!(e, Event::Lost { reason, .. } if reason.contains("NAK")))
    );
    // Started over at once: DISCOVER, OFFER, REQUEST, NAK again.
    assert_eq!(
        n.client.state(),
        State::Init,
        "second NAK waits before trying again"
    );
    let waits_until = n.client.deadline();
    assert!(waits_until > 300_000);
    n.server.set(|k| k.nak = false);
    n.advance(300_250, waits_until + 1_000);
    assert_eq!(n.client.state(), State::Bound);
}

#[test]
fn servers_outside_the_allowed_list_are_ignored_and_reported_once() {
    let mut n = Net::with_filter(Knobs::default(), |ips, _| {
        ips.contains(&Ipv4Addr::new(192, 0, 2, 1))
    });
    n.start(0);
    n.advance(0, 10_000);
    assert_eq!(n.client.state(), State::Selecting);
    assert!(n.bound.is_none());
    let refused: Vec<_> = n
        .events
        .iter()
        .filter(|e| matches!(e, Event::Refused { .. }))
        .collect();
    assert_eq!(refused.len(), 1, "{:?}", n.events);
    // The allowed server shows up: taken.
    n.server
        .set(|k| k.server = Some(Ipv4Addr::new(192, 0, 2, 1)));
    n.advance(10_250, 80_000);
    assert_eq!(n.client.state(), State::Bound);
    assert_eq!(n.bound.unwrap().server, Ipv4Addr::new(192, 0, 2, 1));
}

#[test]
fn filter_by_mac_sees_the_frame_source() {
    let mut n = Net::with_filter(Knobs::default(), |_, mac| {
        mac == Some([0x02, 0xdc, 0, 0, 0, 1])
    });
    n.start(0);
    n.advance(0, 1_000);
    assert_eq!(n.client.state(), State::Bound);
}

#[test]
fn an_address_in_use_is_declined() {
    let mut n = Net::new(Knobs {
        squatter: Some([0xaa; 6]),
        ..Knobs::default()
    });
    n.start(0);
    assert_eq!(n.client.state(), State::Declined);
    assert_eq!(
        n.kinds(),
        vec![
            MessageType::Discover,
            MessageType::Request,
            MessageType::Decline
        ]
    );
    assert!(n.bound.is_none());
    assert!(
        n.events
            .iter()
            .any(|e| matches!(e, Event::Declined { by: [0xaa, ..], .. }))
    );
    n.server.set(|k| k.squatter = None);
    n.advance(250, 9_750);
    assert_eq!(n.client.state(), State::Declined, "waits 10 s");
    n.advance(10_000, 11_250);
    assert_eq!(n.client.state(), State::Bound);
}

#[test]
fn release_tells_the_server_and_starts_over() {
    let mut n = bound_at_1s();
    let addr = n.bound.as_ref().unwrap().address.addr();
    n.take_sent();
    let a = n.client.release(5_000);
    n.run(5_000, a);
    let sent = n.take_sent();
    assert_eq!(
        sent[0],
        (
            MessageType::Release,
            Dest::Unicast(Ipv4Addr::new(100, 64, 1, 1)),
            addr
        )
    );
    assert_eq!(sent[1].0, MessageType::Discover);
    assert!(
        n.events
            .iter()
            .any(|e| matches!(e, Event::Lost { reason, .. } if reason == "released"))
    );
    // The lab answers at once, so it is acquiring again.
    assert_eq!(n.client.state(), State::Probing);
}

#[test]
fn stop_drops_the_lease_silently() {
    let mut n = bound_at_1s();
    n.take_sent();
    let a = n.client.stop("disabled");
    n.run(2_000, a);
    assert!(n.sent.is_empty(), "no RELEASE on disable");
    assert!(n.bound.is_none());
    n.advance(2_000, 700_000);
    assert!(n.sent.is_empty());
    assert_eq!(n.client.state(), State::Stopped);
}

#[test]
fn renew_command_renews_now() {
    let mut n = bound_at_1s();
    n.take_sent();
    let a = n.client.renew(60_000);
    n.run(60_000, a);
    assert_eq!(n.take_sent()[0].0, MessageType::Request);
    assert_eq!(n.bound.as_ref().unwrap().t1_ms, 360_000);
}

#[test]
fn requests_without_an_answer_start_over_after_four_tries() {
    let mut n2 = Net::new(Knobs::default());
    let a = n2.client.start(0);
    // Deliver only the OFFER: answer DISCOVER, drop what follows.
    for act in a {
        if let Action::Send { payload, dest, .. } = act {
            for d in n2.server.answer(&n2.port, MAC, &payload, dest) {
                let _ = n2.client.input(0, &d);
            }
        }
    }
    assert_eq!(n2.client.state(), State::Requesting);
    n2.server.set(|k| k.silent = true);
    n2.advance(0, 70_000);
    let requests = n2
        .kinds()
        .iter()
        .filter(|k| **k == MessageType::Request)
        .count();
    assert_eq!(requests, 3, "3 retries after the first REQUEST");
    assert_eq!(n2.client.state(), State::Selecting);
}

#[test]
fn foreign_transactions_and_garbage_are_ignored() {
    let mut n = Net::new(Knobs {
        silent: true,
        ..Knobs::default()
    });
    n.start(0);
    let mut bad = |payload: Vec<u8>| {
        let d = Datagram {
            payload,
            src: Ipv4Addr::new(192, 0, 2, 1),
            src_mac: None,
        };
        assert!(n.client.input(10, &d).is_empty());
    };
    bad(vec![0; 300]);
    bad(Vec::new());
    // A real OFFER for another MAC.
    let lab = LabServer::default();
    let discover = crate::v4::Outgoing {
        kind: MessageType::Discover,
        xid: 1,
        secs: 0,
        mac: [9; 6],
        ciaddr: Ipv4Addr::UNSPECIFIED,
        broadcast: true,
        requested: None,
        server_id: None,
        client_id: &[],
        host_name: None,
        vendor_class: None,
        extra: &[],
    }
    .encode()
    .unwrap();
    let offer = lab.answer(
        &"ether1".parse().unwrap(),
        [9; 6],
        &discover,
        Dest::Broadcast,
    );
    bad(offer[0].payload.clone());
    assert_eq!(n.client.state(), State::Selecting);
}

#[test]
fn odd_timers_and_masks_from_the_server() {
    let ack = |opts: Vec<DhcpOption>| -> Incoming {
        let mut i = Incoming {
            kind: MessageType::Ack,
            xid: 1,
            chaddr: MAC,
            yiaddr: Ipv4Addr::new(192, 0, 2, 50),
            server_id: Some(Ipv4Addr::new(192, 0, 2, 1)),
            mask: Some(Ipv4Addr::new(255, 255, 255, 0)),
            routers: vec![],
            dns: vec![],
            ntp: vec![],
            domain: None,
            lease_secs: Some(100),
            renew_secs: None,
            rebind_secs: None,
            classless: vec![],
            message: None,
        };
        for o in opts {
            match o {
                DhcpOption::Renewal(s) => i.renew_secs = Some(s),
                DhcpOption::Rebinding(s) => i.rebind_secs = Some(s),
                DhcpOption::SubnetMask(m) => i.mask = Some(m),
                DhcpOption::AddressLeaseTime(s) => i.lease_secs = Some(s),
                _ => {}
            }
        }
        i
    };
    let d = Datagram {
        payload: vec![],
        src: Ipv4Addr::new(192, 0, 2, 1),
        src_mac: None,
    };
    let server = Ipv4Addr::new(192, 0, 2, 1);
    // T1 after T2 and T2 after the lease: RFC defaults.
    let l = lease_from(
        0,
        &ack(vec![DhcpOption::Renewal(90), DhcpOption::Rebinding(500)]),
        &d,
        server,
    )
    .unwrap();
    assert_eq!((l.t1_ms, l.t2_ms), (50_000, 87_500));
    let l = lease_from(
        0,
        &ack(vec![DhcpOption::AddressLeaseTime(u32::MAX)]),
        &d,
        server,
    )
    .unwrap();
    assert_eq!(l.expires_ms, None);
    // A 2-second lease still waits a second before renewing.
    let l = lease_from(0, &ack(vec![DhcpOption::AddressLeaseTime(2)]), &d, server).unwrap();
    assert_eq!(l.t1_ms, 1_000);
    assert!(
        lease_from(
            0,
            &ack(vec![DhcpOption::SubnetMask(Ipv4Addr::new(255, 0, 255, 0))]),
            &d,
            server
        )
        .unwrap_err()
        .contains("contiguous")
    );
    let mut i = ack(vec![]);
    i.yiaddr = Ipv4Addr::new(192, 0, 2, 0);
    assert!(
        lease_from(0, &i, &d, server)
            .unwrap_err()
            .contains("network")
    );
    i.yiaddr = Ipv4Addr::new(224, 0, 0, 1);
    assert!(lease_from(0, &i, &d, server).is_err());
    let _ = OptionCode::End;
}
