//! The DHCPv6 server against our own client's encoder and decoder.

use corerouter_model::dhcp6_server::{Dhcp6Binding, Dhcp6Server, Ipv6Pool};
use corerouter_model::{Config, Interface, InterfaceKind, ItemId};
use proptest::prelude::*;

use super::*;
use crate::v6::{IaReq, Incoming, Outgoing};

const MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];

fn cfg() -> Config {
    let mut c = Config::default();
    let port: IfName = "ether2".parse().unwrap();
    c.interfaces.insert(
        port.clone(),
        Interface::new(port.clone(), InterfaceKind::Ethernet),
    );
    let d = &mut c.ipv6.dhcp_server;
    d.pools.push(Ipv6Pool {
        id: ItemId(1),
        name: "addrs".into(),
        prefix: "2001:db8:1::/64".parse().unwrap(),
        prefix_length: 128,
        comment: String::new(),
    });
    d.pools.push(Ipv6Pool {
        id: ItemId(2),
        name: "cpe".into(),
        prefix: "2001:db8:100::/54".parse().unwrap(),
        prefix_length: 56,
        comment: String::new(),
    });
    let mut s = Dhcp6Server::new(ItemId(3), "v6".into(), port);
    s.address_pool = Some("addrs".into());
    s.prefix_pool = Some("cpe".into());
    s.lease_time = 3600;
    s.dns_server = vec!["2001:db8:1::1".parse().unwrap()];
    s.domain = "lan.example".into();
    s.dns_zone = Some("lan.example".into());
    s.rapid_commit = false;
    d.servers.push(s);
    c
}

fn client(n: u8) -> Vec<u8> {
    v6::duid_ll([2, 0, 0, 0, 1, n])
}

fn ll(n: u8) -> Ipv6Addr {
    corerouter_hal::dhcp::link_local([2, 0, 0, 0, 1, n])
}

struct Lab {
    srv: Server6,
    now: Now,
}

impl Lab {
    fn new(c: &Config) -> Self {
        Self {
            srv: Server6::new(Plan6::from_config(c)),
            now: Now { ms: 0, unix: 1000 },
        }
    }

    fn send(&mut self, from: Ipv6Addr, bytes: &[u8]) -> Vec<Effect6> {
        self.srv
            .handle(self.now, &"ether2".parse().unwrap(), MAC, from, bytes)
    }
}

fn out(
    kind: u8,
    n: u8,
    server: Option<&[u8]>,
    rapid: bool,
    addr: Option<Ipv6Addr>,
    prefix: Option<Ipv6Net>,
) -> Vec<u8> {
    let duid = client(n);
    Outgoing {
        kind,
        xid: 0x1234,
        client_id: &duid,
        server_id: server,
        elapsed_cs: 0,
        rapid_commit: rapid,
        ia_na: Some(IaReq {
            iaid: 7,
            addrs: addr.into_iter().collect(),
            prefixes: vec![],
        }),
        ia_pd: Some(IaReq {
            iaid: 7,
            addrs: vec![],
            prefixes: prefix.into_iter().collect(),
        }),
        oro: &[v6::opt::DNS_SERVERS, v6::opt::DOMAIN_LIST],
    }
    .encode()
}

fn sent(fx: &[Effect6]) -> Option<(Incoming, Ipv6Addr, u16)> {
    fx.iter().find_map(|e| match e {
        Effect6::Send {
            payload, to, port, ..
        } => Some((v6::decode(payload).ok()?, *to, *port)),
        _ => None,
    })
}

fn me() -> Vec<u8> {
    v6::duid_ll(MAC)
}

#[test]
fn solicit_advertise_request_reply() {
    let mut lab = Lab::new(&cfg());
    let fx = lab.send(ll(1), &out(msg::SOLICIT, 1, None, false, None, None));
    let (adv, to, port) = sent(&fx).unwrap();
    assert_eq!((adv.kind, to, port), (msg::ADVERTISE, ll(1), 546));
    assert_eq!(adv.preference, 255);
    assert_eq!(adv.server_id.as_deref(), Some(me().as_slice()));
    let a = adv.ia_na[0].addrs[0];
    let p = adv.ia_pd[0].prefixes[0];
    assert!(
        "2001:db8:1::/64"
            .parse::<Ipv6Net>()
            .unwrap()
            .contains(&a.addr)
    );
    assert_eq!(p.prefix, "2001:db8:100::/56".parse::<Ipv6Net>().unwrap());
    // §21.4: valid 3600, preferred ⅔ = 2400, T1 0.5, T2 0.8.
    assert_eq!((a.preferred, a.valid), (2400, 3600));
    assert_eq!((adv.ia_na[0].t1, adv.ia_na[0].t2), (1200, 1920));
    assert_eq!(adv.dns, ["2001:db8:1::1".parse::<Ipv6Addr>().unwrap()]);
    assert_eq!(adv.domains, ["lan.example"]);
    assert!(
        !fx.iter().any(|e| matches!(e, Effect6::Bound(_))),
        "an Advertise binds nothing"
    );

    let fx = lab.send(
        ll(1),
        &out(
            msg::REQUEST,
            1,
            Some(&me()),
            false,
            Some(a.addr),
            Some(p.prefix),
        ),
    );
    let (rep, _, _) = sent(&fx).unwrap();
    assert_eq!(rep.kind, msg::REPLY);
    assert_eq!(rep.ia_na[0].addrs[0].addr, a.addr, "the advertised one");
    let bound: Vec<&Bound6> = fx
        .iter()
        .filter_map(|e| match e {
            Effect6::Bound(b) => Some(b),
            _ => None,
        })
        .collect();
    assert_eq!(bound.len(), 2);
    let pd = bound.iter().find(|b| b.lease.kind == IaKind::Pd).unwrap();
    assert_eq!(pd.lease.via, ll(1), "route via the client");
    // The address gets the same hash on another server: deterministic.
    let mut other = Lab::new(&cfg());
    let fx = other.send(ll(1), &out(msg::SOLICIT, 1, None, false, None, None));
    assert_eq!(sent(&fx).unwrap().0.ia_na[0].addrs[0].addr, a.addr);
}

#[test]
fn rapid_commit_renew_rebind_release() {
    let mut c = cfg();
    c.ipv6.dhcp_server.servers[0].rapid_commit = true;
    let mut lab = Lab::new(&c);
    let fx = lab.send(ll(2), &out(msg::SOLICIT, 2, None, true, None, None));
    let (rep, _, _) = sent(&fx).unwrap();
    assert_eq!(rep.kind, msg::REPLY);
    assert!(rep.rapid_commit);
    let a = rep.ia_na[0].addrs[0].addr;
    let p = rep.ia_pd[0].prefixes[0].prefix;
    lab.now.unix += 1200;
    let fx = lab.send(
        ll(2),
        &out(msg::RENEW, 2, Some(&me()), false, Some(a), Some(p)),
    );
    let (rep, _, _) = sent(&fx).unwrap();
    assert_eq!(rep.ia_na[0].addrs[0].valid, 3600);
    assert!(
        fx.iter().any(|e| matches!(e, Effect6::Bound(b) if !b.new)),
        "a renewal"
    );
    // §18.3.4: Renew of an unknown IA: NoBinding.
    let fx = lab.send(ll(3), &out(msg::RENEW, 3, Some(&me()), false, None, None));
    assert_eq!(
        sent(&fx).unwrap().0.ia_na[0].status_code(),
        status::NO_BINDING
    );
    // §18.3.5: Rebind with an address from elsewhere: lifetimes 0.
    let fx = lab.send(
        ll(3),
        &out(
            msg::REBIND,
            3,
            None,
            false,
            Some("2001:db8:99::5".parse().unwrap()),
            None,
        ),
    );
    let (rep, _, _) = sent(&fx).unwrap();
    assert!(
        rep.ia_na[0].addrs.is_empty() || rep.ia_na[0].addrs[0].valid == 0,
        "{rep:?}"
    );
    // Release: gone, and the same client gets it back (affinity).
    let fx = lab.send(
        ll(2),
        &out(msg::RELEASE, 2, Some(&me()), false, Some(a), Some(p)),
    );
    assert_eq!(sent(&fx).unwrap().0.status_code(), status::SUCCESS);
    assert_eq!(
        fx.iter().filter(|e| matches!(e, Effect6::Gone(_))).count(),
        2
    );
    let fx = lab.send(ll(2), &out(msg::SOLICIT, 2, None, true, None, None));
    assert_eq!(sent(&fx).unwrap().0.ia_pd[0].prefixes[0].prefix, p);
}

#[test]
fn identifiers_confirm_information_and_decline() {
    let mut lab = Lab::new(&cfg());
    // §16.2: a Solicit with a Server Identifier is dropped; a Request for
    // another server too.
    assert!(
        lab.send(ll(1), &out(msg::SOLICIT, 1, Some(&me()), false, None, None))
            .is_empty()
    );
    assert!(
        lab.send(
            ll(1),
            &out(
                msg::REQUEST,
                1,
                Some(&[0, 3, 0, 1, 9, 9, 9, 9, 9, 9]),
                false,
                None,
                None
            )
        )
        .is_empty()
    );
    let fx = lab.send(
        ll(1),
        &out(
            msg::CONFIRM,
            1,
            None,
            false,
            Some("2001:db8:1::77".parse().unwrap()),
            None,
        ),
    );
    assert_eq!(sent(&fx).unwrap().0.status_code(), status::SUCCESS);
    let fx = lab.send(
        ll(1),
        &out(
            msg::CONFIRM,
            1,
            None,
            false,
            Some("2001:db8:2::77".parse().unwrap()),
            None,
        ),
    );
    assert_eq!(sent(&fx).unwrap().0.status_code(), status::NOT_ON_LINK);
    let duid = client(1);
    let info = Outgoing {
        kind: msg::INFORMATION_REQUEST,
        xid: 9,
        client_id: &duid,
        server_id: None,
        elapsed_cs: 0,
        rapid_commit: false,
        ia_na: None,
        ia_pd: None,
        oro: &[],
    }
    .encode();
    let (rep, _, _) = sent(&lab.send(ll(1), &info)).unwrap();
    assert!(rep.ia_na.is_empty());
    assert_eq!(rep.domains, ["lan.example"]);
    // Decline: the address is held.
    let fx = lab.send(ll(1), &out(msg::SOLICIT, 1, None, false, None, None));
    let a = sent(&fx).unwrap().0.ia_na[0].addrs[0].addr;
    lab.send(
        ll(1),
        &out(msg::REQUEST, 1, Some(&me()), false, Some(a), None),
    );
    lab.send(
        ll(1),
        &out(msg::DECLINE, 1, Some(&me()), false, Some(a), None),
    );
    let held = lab
        .srv
        .leases()
        .get(&Ipv6Net::new(a, 128).unwrap())
        .unwrap();
    assert_eq!(held.state, State::Declined);
    let fx = lab.send(ll(1), &out(msg::SOLICIT, 1, None, false, None, None));
    assert_ne!(sent(&fx).unwrap().0.ia_na[0].addrs[0].addr, a);
}

#[test]
fn static_bindings_hints_and_exhaustion() {
    let mut c = cfg();
    c.ipv6.dhcp_server.bindings.push(Dhcp6Binding {
        id: ItemId(9),
        server: None,
        duid: format!("0x{}", hex(&client(5))),
        iaid: None,
        address: Some("2001:db8:1::55".parse().unwrap()),
        prefix: Some("2001:db8:100:300::/56".parse().unwrap()),
        disabled: false,
        comment: String::new(),
    });
    // A /54 cut in /56: four prefixes.
    let mut lab = Lab::new(&c);
    let fx = lab.send(ll(5), &out(msg::SOLICIT, 5, None, false, None, None));
    let (adv, _, _) = sent(&fx).unwrap();
    assert_eq!(
        adv.ia_na[0].addrs[0].addr,
        "2001:db8:1::55".parse::<Ipv6Addr>().unwrap()
    );
    assert_eq!(
        adv.ia_pd[0].prefixes[0].prefix,
        "2001:db8:100:300::/56".parse::<Ipv6Net>().unwrap()
    );
    // A hint for a free prefix is honoured.
    let fx = lab.send(
        ll(6),
        &out(
            msg::SOLICIT,
            6,
            None,
            false,
            None,
            Some("2001:db8:100:200::/56".parse().unwrap()),
        ),
    );
    assert_eq!(
        sent(&fx).unwrap().0.ia_pd[0].prefixes[0].prefix,
        "2001:db8:100:200::/56".parse::<Ipv6Net>().unwrap()
    );
    for n in 7..9 {
        lab.send(ll(n), &out(msg::SOLICIT, n, None, false, None, None));
    }
    // Four prefixes: one static, three offered; the fifth client gets none.
    let fx = lab.send(ll(9), &out(msg::SOLICIT, 9, None, false, None, None));
    assert_eq!(
        sent(&fx).unwrap().0.ia_pd[0].status_code(),
        status::NO_PREFIX_AVAIL
    );
}

#[test]
fn relayed_messages_are_answered_through_the_relays() {
    let mut c = cfg();
    let relay: Ipv6Addr = "2001:db8:77::1".parse().unwrap();
    c.ipv6.dhcp_server.servers[0].relay = Some(relay);
    let mut lab = Lab::new(&c);
    let inner = out(msg::SOLICIT, 1, None, false, None, None);
    let once = relay_forward(relay, ll(1), b"vlan20", &inner).unwrap();
    // Two relays deep.
    let twice = relay_forward(
        Ipv6Addr::UNSPECIFIED,
        "2001:db8:77::1".parse().unwrap(),
        b"up",
        &once,
    )
    .unwrap();
    let fx = lab.send("2001:db8:ff::2".parse().unwrap(), &twice);
    let Some(Effect6::Send {
        payload, to, port, ..
    }) = fx.into_iter().find(|e| matches!(e, Effect6::Send { .. }))
    else {
        panic!("no reply");
    };
    assert_eq!((to, port), ("2001:db8:ff::2".parse().unwrap(), 547));
    let (peer, id, inner) = relay_unwrap_reply(&payload).unwrap();
    assert_eq!(id.as_deref(), Some(&b"up"[..]));
    assert_eq!(peer, relay);
    let (peer, id, inner) = relay_unwrap_reply(&inner).unwrap();
    assert_eq!((peer, id.as_deref()), (ll(1), Some(&b"vlan20"[..])));
    assert_eq!(v6::decode(&inner).unwrap().kind, msg::ADVERTISE);
    // Hop limit.
    let mut deep = inner_solicit();
    for _ in 0..=HOP_COUNT_LIMIT + 1 {
        match relay_forward(relay, ll(1), b"x", &deep) {
            Some(m) => deep = m,
            None => return,
        }
    }
    panic!("the hop limit stopped nothing");
}

fn inner_solicit() -> Vec<u8> {
    out(msg::SOLICIT, 1, None, false, None, None)
}

#[test]
fn the_journal_brings_bindings_back() {
    let c = cfg();
    let mut lab = Lab::new(&c);
    let mut lines = String::new();
    let fx = lab.send(ll(1), &out(msg::SOLICIT, 1, None, false, None, None));
    let (adv, _, _) = sent(&fx).unwrap();
    let fx = lab.send(
        ll(1),
        &out(
            msg::REQUEST,
            1,
            Some(&me()),
            false,
            Some(adv.ia_na[0].addrs[0].addr),
            None,
        ),
    );
    for e in &fx {
        if let Effect6::Journal(r) = e {
            lines.push_str(&serde_json::to_string(r).unwrap());
            lines.push('\n');
        }
    }
    let mut back = Server6::new(Plan6::from_config(&c));
    assert_eq!(back.replay(lines.lines()), 0);
    assert_eq!(
        back.leases()
            .iter()
            .filter(|l| l.state == State::Bound)
            .count(),
        2
    );
    assert_eq!(back.compact(lab.now.unix).lines().count(), 2);
    // Expiry.
    lab.now.unix += 3601;
    let fx = lab.srv.tick(lab.now);
    assert_eq!(
        fx.iter().filter(|e| matches!(e, Effect6::Gone(_))).count(),
        2
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Hostile bytes, plain or relayed, never panic.
    #[test]
    fn hostile_messages_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..600), kind in 0u8..16) {
        let mut lab = Lab::new(&cfg());
        let _ = lab.send(ll(1), &bytes);
        let mut b = bytes.clone();
        if let Some(k) = b.first_mut() { *k = kind; }
        let _ = lab.send(ll(1), &b);
        let _ = unwrap_relay(&b);
        let _ = relay_unwrap_reply(&b);
        let _ = relay_forward(Ipv6Addr::UNSPECIFIED, ll(1), b"x", &b);
        let _ = lab.srv.tick(lab.now);
    }
}

/// RFC 4704: the client's name (option 39) names its address in the DNS.
#[test]
fn the_fqdn_names_the_address() {
    let mut c = cfg();
    c.ipv6.dhcp_server.servers[0].rapid_commit = true;
    let mut lab = Lab::new(&c);
    let mut m = out(msg::SOLICIT, 1, None, true, None, None);
    let mut name = vec![0u8];
    v6::encode_name("CPE-Garage.example.net", &mut name);
    v6::put(&mut m, opt::CLIENT_FQDN, &name);
    let fx = lab.send(ll(1), &m);
    let b = fx
        .iter()
        .find_map(|e| match e {
            Effect6::Bound(b) if b.lease.kind == IaKind::Na => Some(b.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(b.dns, Some(("lan.example".into(), "cpe-garage".into())));
    assert_eq!(b.ttl, 1200, "a third of the lease");
}

// ---- audit of G4.2 (hostile clients) ----------------------------------

fn flood_solicit(n: u32, na: bool) -> Vec<u8> {
    let [a, b, c, d] = n.to_be_bytes();
    let duid = v6::duid_ll([2, 0x66, a, b, c, d]);
    let ia = IaReq {
        iaid: 1,
        addrs: vec![],
        prefixes: vec![],
    };
    Outgoing {
        kind: msg::SOLICIT,
        xid: n,
        client_id: &duid,
        server_id: None,
        elapsed_cs: 0,
        rapid_commit: false,
        ia_na: na.then(|| ia.clone()),
        ia_pd: (!na).then_some(ia),
        oro: &[],
    }
    .encode()
}

/// A SOLICIT flood from random DUIDs on an IA_NA /64 (a space of 2^64):
/// the table stays under its cap, and offers nobody took are gone once
/// their hold is over (RFC 9915 §18.3.1 binds nothing on a Solicit).
#[test]
fn a_solicit_flood_cannot_fill_memory() {
    let mut c = cfg();
    c.ipv6.dhcp_server.servers[0].prefix_pool = None;
    let mut lab = Lab::new(&c);
    let n = u32::try_from(MAX_BINDINGS6).unwrap() + 20_000;
    for i in 0..n {
        lab.send(ll(1), &flood_solicit(i, true));
    }
    assert!(
        lab.srv.leases().len() <= MAX_BINDINGS6,
        "{} records",
        lab.srv.leases().len()
    );
    assert!(lab.srv.stats().dropped.contains_key("table-full"));
    // The holds run out: nothing is left (they were never bound).
    lab.now.unix += OFFER_HOLD + 1;
    lab.srv.tick(lab.now);
    assert_eq!(lab.srv.leases().len(), 0);
    // A real client gets an address again.
    let fx = lab.send(ll(1), &out(msg::SOLICIT, 1, None, false, None, None));
    assert!(!sent(&fx).unwrap().0.ia_na[0].addrs.is_empty());
}

/// RFC 9915 §18.3.6: an Information-request without a Client Identifier
/// is answered (stateless clients); §11.1: a DUID is at least its 2-byte
/// type, an empty one identifies nobody.
#[test]
fn information_request_without_client_id_and_empty_duids() {
    let mut lab = Lab::new(&cfg());
    let info = Outgoing {
        kind: msg::INFORMATION_REQUEST,
        xid: 9,
        client_id: &[],
        server_id: None,
        elapsed_cs: 0,
        rapid_commit: false,
        ia_na: None,
        ia_pd: None,
        oro: &[],
    }
    .encode();
    // `Outgoing` always writes option 1: take it out (an empty one here).
    let mut bare = info.get(..4).unwrap().to_vec();
    let mut budget = v6::MAX_OPTIONS;
    for (code, data) in v6::split(&info[4..], &mut budget).unwrap() {
        if code != opt::CLIENTID {
            v6::put(&mut bare, code, data);
        }
    }
    let (rep, _, _) = sent(&lab.send(ll(1), &bare)).unwrap_or_else(|| panic!("no reply"));
    assert_eq!(rep.kind, msg::REPLY);
    assert_eq!(rep.domains, ["lan.example"]);
    // A Solicit with an empty option 1: dropped.
    let empty = Outgoing {
        kind: msg::SOLICIT,
        xid: 9,
        client_id: &[],
        server_id: None,
        elapsed_cs: 0,
        rapid_commit: false,
        ia_na: Some(IaReq {
            iaid: 1,
            addrs: vec![],
            prefixes: vec![],
        }),
        ia_pd: None,
        oro: &[],
    }
    .encode();
    assert!(lab.send(ll(1), &empty).is_empty());
}

/// A PD pool known to be full is not scanned again for every SOLICIT,
/// and a prefix that comes free is found at once.
#[test]
fn a_full_pd_pool_is_remembered_until_a_prefix_frees() {
    let mut c = cfg();
    c.ipv6.dhcp_server.servers[0].address_pool = None;
    c.ipv6.dhcp_server.servers[0].rapid_commit = true;
    let mut lab = Lab::new(&c);
    // The /54 holds four /56: all bound.
    for n in 1..=4u8 {
        let fx = lab.send(ll(n), &out(msg::SOLICIT, n, None, true, None, None));
        assert!(!sent(&fx).unwrap().0.ia_pd[0].prefixes.is_empty());
    }
    for n in 5..=7u8 {
        let fx = lab.send(ll(n), &out(msg::SOLICIT, n, None, false, None, None));
        assert_eq!(
            sent(&fx).unwrap().0.ia_pd[0].status_code(),
            status::NO_PREFIX_AVAIL
        );
    }
    lab.send(ll(2), &out(msg::RELEASE, 2, Some(&me()), false, None, None));
    let fx = lab.send(ll(8), &out(msg::SOLICIT, 8, None, false, None, None));
    assert!(
        !sent(&fx).unwrap().0.ia_pd[0].prefixes.is_empty(),
        "the released prefix"
    );
}
/// A bound client that moves to another address leaves a free record
/// (affinity), which the cap may evict before refusing anyone.
#[test]
fn the_cap_evicts_free_records_first() {
    let mut c = cfg();
    c.ipv6.dhcp_server.servers[0].prefix_pool = None;
    c.ipv6.dhcp_server.servers[0].rapid_commit = true;
    let mut lab = Lab::new(&c);
    // One bound client, then released: a free record.
    lab.send(ll(1), &out(msg::SOLICIT, 1, None, true, None, None));
    lab.send(ll(1), &out(msg::RELEASE, 1, Some(&me()), false, None, None));
    assert_eq!(lab.srv.leases().len(), 1);
    let mut s = lab.srv;
    s.leases.cap = 1;
    let mut lab = Lab {
        srv: s,
        now: lab.now,
    };
    let fx = lab.send(ll(2), &flood_solicit(7, true));
    assert!(
        !sent(&fx).unwrap().0.ia_na[0].addrs.is_empty(),
        "the free record made room"
    );
    assert_eq!(lab.srv.leases().len(), 1);
}
