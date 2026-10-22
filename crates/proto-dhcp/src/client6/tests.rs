//! The DHCPv6 client against the lab server on a simulated clock. Each test
//! names the RFC 9915 (ex-8415) rule it checks.

use corerouter_hal::dhcp::{Datagram6, Dhcp6Responder};
use corerouter_model::IfName;

use super::*;
use crate::lab6::{Knobs, LabServer6};
use crate::v6::decode_client;

const MAC: [u8; 6] = [2, 0, 0, 0, 0, 7];

struct Net {
    c: Client,
    server: LabServer6,
    port: IfName,
    now: u64,
    /// (time, message type) of everything sent.
    sent: Vec<(u64, u8)>,
    /// Server ids of what was sent.
    sent_server: Vec<Option<Vec<u8>>>,
    log: Vec<Event>,
    binds: Vec<Lease>,
    unbinds: usize,
    inbox: Vec<Datagram6>,
    /// Drop everything the server says.
    deaf: bool,
}

fn settings() -> Settings {
    Settings {
        duid: v6::duid_ll(MAC),
        iaid: 7,
        address: true,
        prefix: true,
        prefix_hint: Some("::/56".parse().unwrap()),
        rapid_commit: true,
        require_both: false,
    }
}

impl Net {
    fn new(knobs: Knobs, s: Settings) -> Self {
        Self {
            c: Client::new(s, |_, _, _| true, 42),
            server: LabServer6::new(knobs),
            port: "ether1".parse().unwrap(),
            now: 0,
            sent: Vec::new(),
            sent_server: Vec::new(),
            log: Vec::new(),
            binds: Vec::new(),
            unbinds: 0,
            inbox: Vec::new(),
            deaf: false,
        }
    }

    fn take(&mut self, actions: Vec<Action>) {
        for a in actions {
            match a {
                Action::Send(p) => {
                    let m = decode_client(&p).unwrap();
                    self.sent.push((self.now, m.kind));
                    self.sent_server.push(m.server_id.clone());
                    if !self.deaf {
                        self.inbox.extend(self.server.answer(&self.port, MAC, &p));
                    }
                }
                Action::Bind(l) => self.binds.push(*l),
                Action::Unbind => self.unbinds += 1,
                Action::Log(e) => self.log.push(e),
            }
        }
    }

    fn start(&mut self) {
        let a = self.c.start(self.now);
        self.take(a);
    }

    /// Run in steps of 10 ms for `ms`, delivering answers at once.
    fn run(&mut self, ms: u64) {
        let end = self.now + ms;
        while self.now < end {
            for d in std::mem::take(&mut self.inbox) {
                let a = self.c.input(self.now, &d);
                self.take(a);
            }
            let a = self.c.poll(self.now);
            self.take(a);
            self.now += 10;
        }
    }

    fn kinds(&self) -> Vec<u8> {
        self.sent.iter().map(|(_, k)| *k).collect()
    }

    fn lease(&self) -> &Lease {
        self.c.lease().expect("a lease")
    }
}

#[test]
fn rapid_commit_binds_address_and_prefix_in_two_messages() {
    let mut n = Net::new(Knobs::default(), settings());
    n.start();
    n.run(1_100);
    // §18.2.1: the first Solicit waits 0..=SOL_MAX_DELAY.
    assert!(n.sent[0].0 <= SOL_MAX_DELAY_MS);
    assert_eq!(n.kinds(), vec![msg::SOLICIT]);
    assert_eq!(n.c.state(), State::Bound);
    let l = n.lease();
    assert_eq!(
        l.address.unwrap().value,
        LabServer6::address_for(&n.port, MAC)
    );
    assert_eq!(l.prefix.unwrap().value.to_string(), "2001:db8:1:100::/56");
    assert_eq!(l.dns.len(), 1);
    assert_eq!(l.domains, vec!["lab.test"]);
    assert_eq!(l.server_addr.to_string(), "fe80::dc:ff:fe00:1");
    assert_eq!(l.t1_ms - l.granted_ms, 900_000);
    assert_eq!(l.t2_ms - l.granted_ms, 1_440_000);
    assert!(n.log.iter().any(|e| matches!(e, Event::Bound { .. })));
}

#[test]
fn advertises_are_collected_for_the_first_rt_then_requested() {
    let k = Knobs {
        rapid_commit: false,
        ..Knobs::default()
    };
    let mut n = Net::new(k, settings());
    n.start();
    n.run(3_000);
    assert_eq!(n.kinds(), vec![msg::SOLICIT, msg::REQUEST]);
    // §18.2.1: the Request waits for the first RT, strictly above IRT.
    let gap = n.sent[1].0 - n.sent[0].0;
    assert!(
        gap > SOL_TIMEOUT_MS && gap <= SOL_TIMEOUT_MS * 11 / 10 + 10,
        "{gap}"
    );
    assert_eq!(n.sent_server[1], Some(LabServer6::duid_of(&n.port)));
    assert_eq!(n.c.state(), State::Bound);
}

#[test]
fn preference_255_is_requested_at_once() {
    let k = Knobs {
        rapid_commit: false,
        preference: 255,
        ..Knobs::default()
    };
    let mut n = Net::new(k, settings());
    n.start();
    n.run(1_100);
    assert_eq!(n.kinds(), vec![msg::SOLICIT, msg::REQUEST]);
    // The harness answers on its next 10 ms step.
    assert!(
        n.sent[1].0 - n.sent[0].0 <= 10,
        "§18.2.9: no waiting for others"
    );
}

#[test]
fn solicit_retransmission_follows_section_15() {
    let mut n = Net::new(Knobs::default(), settings());
    n.deaf = true;
    n.start();
    n.run(20_000_000);
    let t: Vec<u64> = n.sent.iter().map(|(t, _)| *t).collect();
    let gaps: Vec<u64> = t.windows(2).map(|w| w[1] - w[0]).collect();
    // First RT strictly greater than IRT (RAND > 0), at most +10 %.
    assert!(gaps[0] > 1_000 && gaps[0] <= 1_110, "{gaps:?}");
    // Then about twice the previous (±10 %), until SOL_MAX_RT ± 10 %.
    for w in gaps.windows(2).take(8) {
        let ratio = w[1] as f64 / w[0] as f64;
        assert!((1.85..=2.15).contains(&ratio), "{gaps:?}");
    }
    let last = *gaps.last().unwrap();
    assert!((3_240_000..=3_960_000).contains(&last), "{last}");
    assert!(n.sent.iter().all(|(_, k)| *k == msg::SOLICIT));
}

#[test]
fn renew_at_t1_to_the_same_server() {
    let mut n = Net::new(Knobs::default(), settings());
    n.start();
    n.run(1_100);
    let granted = n.lease().granted_ms;
    n.run(900_000);
    let renew = n.sent.iter().position(|(_, k)| *k == msg::RENEW).unwrap();
    assert!(n.sent[renew].0 >= granted + 900_000);
    // §18.2.4: Renew names the server that gave the lease.
    assert_eq!(n.sent_server[renew], Some(LabServer6::duid_of(&n.port)));
    assert_eq!(n.c.state(), State::Bound);
    assert!(n.log.iter().any(|e| matches!(e, Event::Renewed { .. })));
    assert_eq!(n.unbinds, 0);
}

#[test]
fn a_dead_server_means_renew_then_rebind_then_loss() {
    let mut n = Net::new(Knobs::default(), settings());
    n.start();
    n.run(1_100);
    let granted = n.lease().granted_ms;
    n.deaf = true;
    n.run(3_700_000);
    let first_rebind = n.sent.iter().find(|(_, k)| *k == msg::REBIND).unwrap().0;
    // §18.2.5: Rebind starts at T2 and carries no Server Identifier.
    assert!(first_rebind >= granted + 1_440_000 && first_rebind < granted + 1_441_000);
    let i = n.sent.iter().position(|(_, k)| *k == msg::REBIND).unwrap();
    assert_eq!(n.sent_server[i], None);
    // Renews between T1 and T2: REN_TIMEOUT doubling up to REN_MAX_RT.
    let renews: Vec<u64> = n
        .sent
        .iter()
        .filter(|(_, k)| *k == msg::RENEW)
        .map(|(t, _)| *t)
        .collect();
    assert!(renews.len() >= 5, "{renews:?}");
    assert!(
        renews
            .windows(2)
            .all(|w| w[1] - w[0] <= REN_MAX_RT_MS * 11 / 10)
    );
    // §18.2.5: all valid lifetimes over → Solicit again.
    assert!(n.log.iter().any(|e| matches!(e, Event::Lost { .. })));
    assert!(n.unbinds >= 1);
    assert_eq!(n.kinds().last(), Some(&msg::SOLICIT));
}

#[test]
fn no_binding_on_renew_sends_a_request() {
    let mut n = Net::new(Knobs::default(), settings());
    n.start();
    n.run(1_100);
    n.server.set(|k| k.no_binding = true);
    let a = n.c.renew(n.now);
    n.take(a);
    n.server.set(|k| k.no_binding = false);
    n.run(100);
    // §18.2.10.1: NoBinding → Request with the IAs.
    let k = n.kinds();
    assert_eq!(&k[k.len() - 2..], &[msg::RENEW, msg::REQUEST]);
    assert_eq!(n.c.state(), State::Bound);
}

#[test]
fn a_prefix_without_an_address_is_kept_unless_both_are_required() {
    let k = Knobs {
        no_address: true,
        ..Knobs::default()
    };
    let mut n = Net::new(k.clone(), settings());
    n.start();
    n.run(1_100);
    let l = n.lease();
    assert!(l.address.is_none() && l.prefix.is_some());
    assert!(l.missing[0].contains("NoAddrsAvail"), "{:?}", l.missing);
    // accept-prefix-without-address=no: nothing is bound, it keeps asking.
    let mut s = settings();
    s.require_both = true;
    let mut n = Net::new(k, s);
    n.start();
    n.run(5_000);
    assert!(n.c.lease().is_none());
    assert_ne!(n.c.state(), State::Bound);
}

#[test]
fn nothing_granted_backs_off() {
    let k = Knobs {
        no_address: true,
        no_prefix: true,
        rapid_commit: false,
        ..Knobs::default()
    };
    let mut n = Net::new(k, settings());
    n.start();
    n.run(60_000);
    // §18.2.9: Advertises with nothing are ignored; Solicit goes on.
    assert!(n.kinds().iter().all(|k| *k == msg::SOLICIT));
    assert!(
        n.log
            .iter()
            .any(|e| matches!(e, Event::Ignored { why, .. } if why.contains("NoAddrsAvail")))
    );
}

#[test]
fn release_stops_using_then_tells_the_server() {
    let mut n = Net::new(Knobs::default(), settings());
    n.start();
    n.run(1_100);
    n.deaf = true;
    let a = n.c.release(n.now);
    n.take(a);
    assert_eq!(n.unbinds, 1, "§18.2.7: stop using the bindings first");
    assert_eq!(n.kinds().last(), Some(&msg::RELEASE));
    n.run(30_000);
    let releases = n.kinds().iter().filter(|k| **k == msg::RELEASE).count();
    assert_eq!(releases as u32, REL_MAX_RC, "REL_MAX_RC tries");
    assert_eq!(n.kinds().last(), Some(&msg::SOLICIT));
    // With a server that answers, the Reply ends it at once.
    let mut n = Net::new(Knobs::default(), settings());
    n.start();
    n.run(1_100);
    let a = n.c.release(n.now);
    n.take(a);
    n.run(2_000);
    assert_eq!(n.kinds().iter().filter(|k| **k == msg::RELEASE).count(), 1);
}

#[test]
fn stop_drops_without_release() {
    let mut n = Net::new(Knobs::default(), settings());
    n.start();
    n.run(1_100);
    let a = n.c.stop("client disabled");
    n.take(a);
    // RFC 9096 WPD-9: no Release on a restart or stop.
    assert!(!n.kinds().contains(&msg::RELEASE));
    assert_eq!(n.unbinds, 1);
    assert_eq!(n.c.state(), State::Stopped);
}

#[test]
fn servers_outside_the_allowed_list_are_refused() {
    let mut n = Net::new(Knobs::default(), settings());
    n.c.set_allowed(|duid, _, _| duid == [0, 3, 0, 1, 9, 9, 9, 9, 9, 9]);
    n.start();
    n.run(10_000);
    assert!(n.c.lease().is_none());
    let refused = n
        .log
        .iter()
        .filter(|e| matches!(e, Event::Refused { .. }))
        .count();
    assert_eq!(refused, 1, "said once per exchange");
}

#[test]
fn lifetimes_and_timers() {
    // §21.4: T1 = T2 = 0 → the client picks 0.5 and 0.8 of the shortest
    // preferred lifetime.
    let k = Knobs {
        t1: 0,
        t2: 0,
        ..Knobs::default()
    };
    let mut n = Net::new(k, settings());
    n.start();
    n.run(1_100);
    let l = n.lease();
    assert_eq!(l.t1_ms - l.granted_ms, 900_000);
    assert_eq!(l.t2_ms - l.granted_ms, 1_440_000);
    // §21.4: T1 > T2 → the IA is discarded (here: both IAs, nothing bound).
    let k = Knobs {
        t1: 2_000,
        t2: 1_000,
        ..Knobs::default()
    };
    let mut n = Net::new(k, settings());
    n.start();
    n.run(1_100);
    assert!(n.c.lease().is_none());
    // Infinite lifetimes: never renew, never expire.
    let k = Knobs {
        t1: INFINITY,
        t2: INFINITY,
        preferred: INFINITY,
        valid: INFINITY,
        ..Knobs::default()
    };
    let mut n = Net::new(k, settings());
    n.start();
    n.run(1_100);
    assert_eq!(n.lease().t1_ms, u64::MAX);
    assert_eq!(n.lease().expires_ms(), None);
}

#[test]
fn a_zero_valid_lifetime_revokes() {
    let mut n = Net::new(Knobs::default(), settings());
    n.start();
    n.run(1_100);
    n.server.set(|k| k.valid = 0);
    n.server.set(|k| k.preferred = 0);
    let a = n.c.renew(n.now);
    n.take(a);
    n.run(100);
    // §18.2.10.1: leases with valid lifetime 0 are dropped.
    assert!(n.c.lease().is_none());
    assert!(n.unbinds >= 1);
}

#[test]
fn hostile_or_foreign_answers_change_nothing() {
    let mut n = Net::new(Knobs::default(), settings());
    n.start();
    n.run(1_100);
    let before = n.c.lease().cloned();
    let xid_wrong = Datagram6 {
        payload: v6::Builder::new(msg::REPLY, 0xdead)
            .opt(v6::opt::SERVERID, &[0, 3, 0, 1, 1, 1, 1, 1, 1, 1])
            .opt(v6::opt::CLIENTID, &v6::duid_ll(MAC))
            .bytes(),
        src: "fe80::66".parse().unwrap(),
        src_mac: None,
    };
    let a = n.c.input(n.now, &xid_wrong);
    assert!(a.is_empty());
    for junk in [&[][..], &[7][..], &[7, 0, 0, 0, 0, 1, 0, 200][..]] {
        let d = Datagram6 {
            payload: junk.to_vec(),
            src: "fe80::66".parse().unwrap(),
            src_mac: None,
        };
        assert!(n.c.input(n.now, &d).is_empty());
    }
    assert_eq!(n.c.lease().cloned(), before);
}

#[test]
fn the_rate_limit_holds_back_a_storm() {
    let mut n = Net::new(Knobs::default(), settings());
    n.start();
    n.run(1_100);
    n.deaf = true;
    // An operator (or a script) hammering `renew`.
    for _ in 0..30 {
        let a = n.c.renew(n.now);
        n.take(a);
        n.now += 10;
    }
    let in_window = n
        .sent
        .iter()
        .filter(|(t, _)| *t + RATE_WINDOW_MS > n.now)
        .count();
    assert!(in_window <= RATE_MAX, "{in_window}");
    assert!(
        n.log
            .iter()
            .any(|e| matches!(e, Event::Error(m) if m.contains("rate limit")))
    );
}
