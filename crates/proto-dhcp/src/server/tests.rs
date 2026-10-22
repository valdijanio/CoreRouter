//! The server against our own client's encoder and decoder.

use std::net::Ipv4Addr;

use corerouter_hal::dhcp_server::{Heard, ReplyTo};
use corerouter_model::dhcp_server::{
    Alert, Authoritative, DhcpNetwork, DhcpServer, Matcher, OptionDef, OptionSet, StaticLease,
};
use corerouter_model::dns_zone::Zone;
use corerouter_model::ip_pool::IpPool;
use corerouter_model::{AddressEntry, Config, Interface, InterfaceKind, ItemId, MacAddr};
use dhcproto::v4::MessageType;
use proptest::prelude::*;

use super::checks::{Level as CheckLevel, checks};
use super::*;
use crate::v4::{self, Outgoing};

const SQUATTER: [u8; 6] = [0x0e, 0, 0, 0, 0, 0x99];

fn mac(n: u8) -> [u8; 6] {
    [2, 0, 0, 0, 0, n]
}

fn ip(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

fn cfg() -> Config {
    let mut c = Config::default();
    for n in ["ether1", "ether2"] {
        c.interfaces.insert(
            n.parse().unwrap(),
            Interface::new(n.parse().unwrap(), InterfaceKind::Ethernet),
        );
    }
    c.ip.addresses.push(AddressEntry {
        id: ItemId(1),
        address: "192.168.88.1/24".parse().unwrap(),
        interface: "ether2".parse().unwrap(),
        disabled: false,
        comment: String::new(),
        from_pool: None,
    });
    c.ip.pools.pools.push(IpPool {
        id: ItemId(1),
        name: "lan".into(),
        ranges: vec!["192.168.88.10-192.168.88.20".parse().unwrap()],
        next_pool: None,
        comment: String::new(),
    });
    let d = &mut c.ip.dhcp_server;
    let mut s = DhcpServer::new(ItemId(1), "dhcp1".into(), "ether2".parse().unwrap());
    s.address_pool = Some("lan".into());
    d.servers.push(s);
    let mut n = DhcpNetwork::new(ItemId(2), "192.168.88.0/24".parse().unwrap());
    n.gateway = vec![ip("192.168.88.1")];
    n.dns_server = vec![ip("192.168.88.1")];
    n.domain = "lan.example".into();
    n.dns_zone = Some("lan.example".into());
    d.networks.push(n);
    d.next_id = 10;
    c.ip.dns_zones
        .zones
        .push(Zone::new(ItemId(1), "lan.example"));
    c
}

struct Lab {
    srv: Server,
    now: Now,
}

impl Lab {
    fn new(c: &Config) -> Self {
        assert!(
            super::checks::validate(c).is_empty(),
            "{:?}",
            super::checks::validate(c)
        );
        Self {
            srv: Server::new(Plan::from_config(c), 1_000_000),
            now: Now {
                ms: 10_000,
                unix: 1_000_000,
            },
        }
    }

    fn later(&mut self, ms: u64) -> Vec<Effect> {
        self.now.ms += ms;
        self.now.unix += ms / 1000;
        self.srv.tick(self.now)
    }

    fn send(&mut self, payload: Vec<u8>, dst: Ipv4Addr) -> Vec<Effect> {
        let heard = Heard {
            payload,
            src: Ipv4Addr::UNSPECIFIED,
            dst,
            src_mac: mac(0),
            to_server: true,
        };
        self.srv
            .handle(self.now, &"ether2".parse().unwrap(), &heard)
    }

    fn discover(&mut self, m: [u8; 6]) -> Vec<Effect> {
        self.send(
            msg(MessageType::Discover, m, None, None, Ipv4Addr::UNSPECIFIED),
            Ipv4Addr::BROADCAST,
        )
    }

    /// DISCOVER, the probe's wait, the OFFER.
    fn offered(&mut self, m: [u8; 6]) -> (Ipv4Addr, Vec<Effect>) {
        let mut fx = self.discover(m);
        fx.extend(self.later(PROBE_WAIT_MS));
        let offer = sent(&fx, Kind::Offer).unwrap_or_else(|| panic!("no offer in {fx:?}"));
        (v4::decode(&offer.0).unwrap().yiaddr, fx)
    }

    fn select(&mut self, m: [u8; 6], at: Ipv4Addr) -> Vec<Effect> {
        self.send(
            msg(
                MessageType::Request,
                m,
                Some(at),
                Some(ip("192.168.88.1")),
                Ipv4Addr::UNSPECIFIED,
            ),
            Ipv4Addr::BROADCAST,
        )
    }

    fn dora(&mut self, m: [u8; 6]) -> Ipv4Addr {
        let (yi, _) = self.offered(m);
        let fx = self.select(m, yi);
        assert!(sent(&fx, Kind::Ack).is_some(), "{fx:?}");
        yi
    }
}

fn msg(
    kind: MessageType,
    m: [u8; 6],
    requested: Option<Ipv4Addr>,
    server: Option<Ipv4Addr>,
    ciaddr: Ipv4Addr,
) -> Vec<u8> {
    Outgoing {
        kind,
        xid: 7,
        secs: 0,
        mac: m,
        ciaddr,
        broadcast: false,
        requested,
        server_id: server,
        client_id: &[],
        host_name: Some("Laptop_1"),
        vendor_class: None,
        extra: &[],
    }
    .encode()
    .unwrap()
}

/// Option 82 added as a relay does (last, before the end marker).
fn with_82(mut bytes: Vec<u8>, data: &[u8]) -> Vec<u8> {
    while bytes.last() == Some(&0) {
        bytes.pop();
    }
    assert_eq!(bytes.pop(), Some(255));
    bytes.push(82);
    bytes.push(u8::try_from(data.len()).unwrap());
    bytes.extend_from_slice(data);
    bytes.push(255);
    bytes
}

fn sent(fx: &[Effect], kind: Kind) -> Option<(Vec<u8>, ReplyTo)> {
    fx.iter().find_map(|e| match e {
        Effect::Send {
            payload,
            to,
            kind: k,
            ..
        } if *k == kind => Some((payload.clone(), *to)),
        _ => None,
    })
}

fn probes(fx: &[Effect]) -> Vec<Ipv4Addr> {
    fx.iter()
        .filter_map(|e| match e {
            Effect::Probe { ip, .. } => Some(*ip),
            _ => None,
        })
        .collect()
}

#[test]
fn dora_probes_offers_and_binds_with_the_network() {
    let mut lab = Lab::new(&cfg());
    let fx = lab.discover(mac(1));
    // RFC 2131 §3.1: the new address is probed before it is offered.
    assert_eq!(probes(&fx), [ip("192.168.88.10")]);
    assert!(
        sent(&fx, Kind::Offer).is_none(),
        "the offer waits for the probe"
    );
    assert!(lab.later(PROBE_WAIT_MS - 1).is_empty());
    let fx = lab.later(1);
    let (bytes, to) = sent(&fx, Kind::Offer).unwrap();
    // §4.1: no broadcast bit, no ciaddr: unicast to chaddr/yiaddr.
    assert_eq!(
        to,
        ReplyTo::Client {
            ip: ip("192.168.88.10"),
            mac: mac(1)
        }
    );
    let o = v4::decode(&bytes).unwrap();
    assert_eq!(o.kind, MessageType::Offer);
    assert_eq!(o.yiaddr, ip("192.168.88.10"));
    assert_eq!(o.server_id, Some(ip("192.168.88.1")));
    assert_eq!(o.lease_secs, Some(1800));
    // §4.4.5: T1 = 0.5, T2 = 0.875 of the lease.
    assert_eq!(o.renew_secs, Some(900));
    assert_eq!(o.rebind_secs, Some(1575));
    assert_eq!(o.mask, Some(ip("255.255.255.0")));
    assert_eq!(o.routers, [ip("192.168.88.1")]);
    assert_eq!(o.dns, [ip("192.168.88.1")]);
    assert_eq!(o.domain.as_deref(), Some("lan.example"));
    assert_eq!(
        lab.srv.leases().get(o.yiaddr).unwrap().state,
        State::Offered
    );
    // No journal line nor DNS for an offer (RFC 4702 §4.1: not on DISCOVER).
    assert!(
        !fx.iter()
            .any(|e| matches!(e, Effect::Journal(_) | Effect::Bound(_)))
    );

    let fx = lab.select(mac(1), o.yiaddr);
    let (ack, _) = sent(&fx, Kind::Ack).unwrap();
    assert_eq!(v4::decode(&ack).unwrap().yiaddr, o.yiaddr);
    let bound = fx
        .iter()
        .find_map(|e| match e {
            Effect::Bound(b) => Some(b.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(bound.dns, Some(("lan.example".into(), "laptop-1".into())));
    assert_eq!(bound.ttl, 600, "a third of 1800 is under the 600 s floor");
    assert!(
        fx.iter()
            .any(|e| matches!(e, Effect::Journal(Record::Lease(l)) if l.state == State::Bound))
    );
    let l = lab.srv.leases().get(o.yiaddr).unwrap();
    assert_eq!((l.state, l.host_name.as_str()), (State::Bound, "Laptop_1"));
    assert_eq!(lab.srv.stats().sent_of(Kind::Ack), 1);
    assert_eq!(lab.srv.stats().received_of(Kind::Discover), 1);
}

#[test]
fn a_conflict_is_marked_and_another_address_offered() {
    let mut lab = Lab::new(&cfg());
    let fx = lab.discover(mac(1));
    assert_eq!(probes(&fx), [ip("192.168.88.10")]);
    let fx = lab.srv.probe_reply(
        lab.now,
        &"ether2".parse().unwrap(),
        ip("192.168.88.10"),
        SQUATTER,
    );
    assert_eq!(
        probes(&fx),
        [ip("192.168.88.11")],
        "the next address is probed"
    );
    let held = lab.srv.leases().get(ip("192.168.88.10")).unwrap();
    assert_eq!(held.state, State::Conflict);
    assert_eq!(held.mac, SQUATTER);
    assert!(held.reason.contains("0E:00:00:00:00:99"), "{}", held.reason);
    assert!(fx.iter().any(|e| matches!(e, Effect::Journal(_))));
    let fx = lab.later(PROBE_WAIT_MS);
    let (bytes, _) = sent(&fx, Kind::Offer).unwrap();
    assert_eq!(v4::decode(&bytes).unwrap().yiaddr, ip("192.168.88.11"));
    assert_eq!(lab.srv.stats().conflicts, 1);
    // Held for the lease time, then free again.
    lab.later(1_801_000);
    assert_eq!(
        lab.srv.leases().get(ip("192.168.88.10")).unwrap().state,
        State::Expired
    );
}

#[test]
fn renew_rebind_release_and_affinity() {
    let mut lab = Lab::new(&cfg());
    let a = lab.dora(mac(1));
    lab.later(900_000);
    // RENEWING: unicast with ciaddr; the ACK goes back to ciaddr.
    let fx = lab.send(
        msg(MessageType::Request, mac(1), None, None, a),
        ip("192.168.88.1"),
    );
    let (_, to) = sent(&fx, Kind::Ack).unwrap();
    assert_eq!(to, ReplyTo::Unicast(a));
    let renewed = fx
        .iter()
        .any(|e| matches!(e, Effect::Log { text, .. } if text.contains("assigned")));
    assert!(!renewed, "a renewal is not logged as a new assignment");
    assert_eq!(
        lab.srv.leases().get(a).unwrap().expires,
        lab.now.unix + 1800
    );
    // RELEASE: the record stays and remembers the client.
    let fx = lab.send(
        msg(
            MessageType::Release,
            mac(1),
            None,
            Some(ip("192.168.88.1")),
            a,
        ),
        ip("192.168.88.1"),
    );
    assert!(
        fx.iter()
            .any(|e| matches!(e, Effect::Gone(l) if l.address == a))
    );
    assert_eq!(lab.srv.leases().get(a).unwrap().state, State::Released);
    lab.dora(mac(2));
    assert_eq!(lab.dora(mac(1)), a, "§4.3.1: the client's previous address");
}

#[test]
fn init_reboot_and_authority() {
    let mut c = cfg();
    let mut lab = Lab::new(&c);
    let a = lab.dora(mac(1));
    // INIT-REBOOT for its own address: ACK.
    let fx = lab.send(
        msg(
            MessageType::Request,
            mac(1),
            Some(a),
            None,
            Ipv4Addr::UNSPECIFIED,
        ),
        Ipv4Addr::BROADCAST,
    );
    assert!(sent(&fx, Kind::Ack).is_some());
    // Wrong network: NAK, broadcast (§4.3.2, §4.1).
    let fx = lab.send(
        msg(
            MessageType::Request,
            mac(1),
            Some(ip("10.9.9.9")),
            None,
            Ipv4Addr::UNSPECIFIED,
        ),
        Ipv4Addr::BROADCAST,
    );
    let (nak, to) = sent(&fx, Kind::Nak).unwrap();
    assert_eq!(to, ReplyTo::Broadcast);
    let n = v4::decode(&nak).unwrap();
    assert_eq!(n.yiaddr, Ipv4Addr::UNSPECIFIED);
    assert_eq!(n.message.as_deref(), Some("wrong network"));
    // Another client's address: NAK.
    let fx = lab.send(
        msg(
            MessageType::Request,
            mac(2),
            Some(a),
            None,
            Ipv4Addr::UNSPECIFIED,
        ),
        Ipv4Addr::BROADCAST,
    );
    assert!(sent(&fx, Kind::Nak).is_some());
    // Unknown client, free address, authoritative: ACK (the table rebuilds).
    let fx = lab.send(
        msg(
            MessageType::Request,
            mac(3),
            Some(ip("192.168.88.15")),
            None,
            Ipv4Addr::UNSPECIFIED,
        ),
        Ipv4Addr::BROADCAST,
    );
    assert!(sent(&fx, Kind::Ack).is_some(), "{fx:?}");

    c.ip.dhcp_server.servers[0].authoritative = Authoritative::No;
    let mut lab = Lab::new(&c);
    let fx = lab.send(
        msg(
            MessageType::Request,
            mac(4),
            Some(ip("192.168.88.16")),
            None,
            Ipv4Addr::UNSPECIFIED,
        ),
        Ipv4Addr::BROADCAST,
    );
    assert!(fx.is_empty(), "§4.3.2: no record of the client: silent");
    assert_eq!(lab.srv.stats().dropped_of(Drop::NotAuthoritative), 1);
}

#[test]
fn a_request_for_another_server_frees_the_offer() {
    let mut lab = Lab::new(&cfg());
    let (yi, _) = lab.offered(mac(1));
    let fx = lab.send(
        msg(
            MessageType::Request,
            mac(1),
            Some(ip("192.168.88.200")),
            Some(ip("192.168.88.254")),
            Ipv4Addr::UNSPECIFIED,
        ),
        Ipv4Addr::BROADCAST,
    );
    assert!(fx.is_empty());
    assert_eq!(lab.srv.leases().get(yi).unwrap().state, State::Expired);
    assert_eq!(lab.srv.stats().dropped_of(Drop::OtherServer), 1);
}

#[test]
fn decline_holds_the_address() {
    let mut lab = Lab::new(&cfg());
    let a = lab.dora(mac(1));
    let fx = lab.send(
        msg(
            MessageType::Decline,
            mac(1),
            Some(a),
            Some(ip("192.168.88.1")),
            Ipv4Addr::UNSPECIFIED,
        ),
        Ipv4Addr::BROADCAST,
    );
    assert!(fx.iter().any(|e| matches!(
        e,
        Effect::Log {
            level: Level::Warning,
            ..
        }
    )));
    assert_eq!(lab.srv.leases().get(a).unwrap().state, State::Declined);
    assert_ne!(lab.dora(mac(1)), a);
}

#[test]
fn static_leases_and_static_only() {
    let mut c = cfg();
    let mut st = StaticLease::new(ItemId(20), ip("192.168.88.50"));
    st.mac_address = Some(MacAddr(mac(9)));
    st.host_name = "printer".into();
    st.block_access = true;
    c.ip.dhcp_server.leases.push(st);
    let mut lab = Lab::new(&c);
    let fx = lab.discover(mac(9));
    assert!(probes(&fx).is_empty(), "static leases are not probed");
    let (bytes, _) = sent(&fx, Kind::Offer).unwrap();
    let o = v4::decode(&bytes).unwrap();
    assert_eq!(o.yiaddr, ip("192.168.88.50"));
    assert!(
        o.routers.is_empty() && o.dns.is_empty(),
        "block-access: no gateway nor DNS"
    );
    let fx = lab.select(mac(9), o.yiaddr);
    let b = fx
        .iter()
        .find_map(|e| match e {
            Effect::Bound(b) => Some(b.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(b.dns.unwrap().1, "printer", "the static name wins");

    c.ip.dhcp_server.servers[0].address_pool = None;
    let mut lab = Lab::new(&c);
    assert!(lab.discover(mac(1)).is_empty());
    assert_eq!(lab.srv.stats().dropped_of(Drop::StaticOnly), 1);
    assert!(sent(&lab.discover(mac(9)), Kind::Offer).is_some());
}

#[test]
fn pools_run_out_then_chain() {
    let mut c = cfg();
    c.ip.pools.pools[0].ranges = vec!["192.168.88.10-192.168.88.11".parse().unwrap()];
    let mut lab = Lab::new(&c);
    lab.dora(mac(1));
    lab.dora(mac(2));
    let fx = lab.discover(mac(3));
    assert!(sent(&fx, Kind::Offer).is_none());
    assert_eq!(lab.srv.stats().dropped_of(Drop::PoolExhausted), 1);
    c.ip.pools.pools.push(IpPool {
        id: ItemId(2),
        name: "more".into(),
        ranges: vec!["192.168.88.30".parse().unwrap()],
        next_pool: None,
        comment: String::new(),
    });
    c.ip.pools.pools[0].next_pool = Some("more".into());
    lab.srv.configure(Plan::from_config(&c));
    assert_eq!(lab.dora(mac(3)), ip("192.168.88.30"));
    let u = lab.srv.pool_use();
    assert_eq!(u[0].percent(), 100);
    assert_eq!((u[1].size, u[1].bound), (1, 1));
}

#[test]
fn a_full_pool_reuses_the_longest_idle_address() {
    let mut c = cfg();
    c.ip.pools.pools[0].ranges = vec!["192.168.88.10-192.168.88.11".parse().unwrap()];
    let mut lab = Lab::new(&c);
    let a = lab.dora(mac(1));
    lab.dora(mac(2));
    lab.send(
        msg(MessageType::Release, mac(1), None, None, a),
        ip("192.168.88.1"),
    );
    lab.later(70_000);
    assert_eq!(lab.dora(mac(3)), a);
}

#[test]
fn floods_are_limited_per_client() {
    let mut c = cfg();
    c.ip.dhcp_server.servers[0].client_rate_limit = 2;
    let mut lab = Lab::new(&c);
    for _ in 0..10 {
        lab.discover(mac(1));
    }
    // A burst of 2 × 2 = 4, then nothing until tokens come back.
    assert_eq!(lab.srv.stats().dropped_of(Drop::RateLimited), 6);
    c.ip.dhcp_server.servers[0].client_rate_limit = 0;
    c.ip.dhcp_server.servers[0].client_mac_limit = Some(1);
    let mut lab = Lab::new(&c);
    lab.dora(mac(1));
    let other_id = [0xff, 1, 2, 3];
    let m = Outgoing {
        kind: MessageType::Discover,
        xid: 9,
        secs: 0,
        mac: mac(1),
        ciaddr: Ipv4Addr::UNSPECIFIED,
        broadcast: true,
        requested: None,
        server_id: None,
        client_id: &other_id,
        host_name: None,
        vendor_class: None,
        extra: &[],
    }
    .encode()
    .unwrap();
    assert!(lab.send(m, Ipv4Addr::BROADCAST).is_empty());
    assert_eq!(lab.srv.stats().dropped_of(Drop::MacLimit), 1);
}

#[test]
fn leases_expire_and_leave_the_dns() {
    let mut lab = Lab::new(&cfg());
    let a = lab.dora(mac(1));
    let fx = lab.later(1_800_000);
    assert!(
        fx.iter()
            .any(|e| matches!(e, Effect::Gone(l) if l.address == a))
    );
    assert_eq!(lab.srv.leases().get(a).unwrap().state, State::Expired);
}

#[test]
fn options_matchers_and_relay_echo() {
    let mut c = cfg();
    let d = &mut c.ip.dhcp_server;
    d.options.push(OptionDef {
        id: ItemId(30),
        name: "tftp".into(),
        code: 66,
        value: "'tftp.lan'".into(),
        force: false,
        comment: String::new(),
    });
    d.options.push(OptionDef {
        id: ItemId(31),
        name: "acs".into(),
        code: 43,
        value: "0x0102".into(),
        force: true,
        comment: String::new(),
    });
    d.option_sets.push(OptionSet {
        id: ItemId(32),
        name: "cpe".into(),
        options: vec!["acs".into()],
        comment: String::new(),
    });
    d.networks[0].dhcp_option = vec!["tftp".into()];
    d.matchers.push(Matcher {
        id: ItemId(33),
        name: "onu".into(),
        server: None,
        code: 60,
        value: "'ONU'".into(),
        matching_type: corerouter_model::dhcp_server::MatchingType::Substring,
        option_set: Some("cpe".into()),
        address_pool: None,
        disabled: false,
        comment: String::new(),
    });
    let mut lab = Lab::new(&c);
    let (_, fx) = lab.offered(mac(1));
    let raw = v4::raw_options(&sent(&fx, Kind::Offer).unwrap().0);
    assert!(
        !raw.iter().any(|(c, _)| *c == 66),
        "66 was not asked for (55)"
    );
    assert!(!raw.iter().any(|(c, _)| *c == 43), "no matcher hit");

    let vendor = b"GPON-ONU-1".to_vec();
    let req = Outgoing {
        kind: MessageType::Discover,
        xid: 1,
        secs: 0,
        mac: mac(2),
        ciaddr: Ipv4Addr::UNSPECIFIED,
        broadcast: true,
        requested: None,
        server_id: None,
        client_id: &[1, 2, 0, 0, 0, 0, 2],
        host_name: None,
        vendor_class: Some(&vendor),
        extra: &[],
    }
    .encode()
    .unwrap();
    let mut fx = lab.send(with_82(req, &[1, 3, b'p', b'o', b'n']), Ipv4Addr::BROADCAST);
    fx.extend(lab.later(PROBE_WAIT_MS));
    let (bytes, to) = sent(&fx, Kind::Offer).unwrap();
    assert_eq!(to, ReplyTo::Broadcast, "broadcast bit");
    let raw = v4::raw_options(&bytes);
    let get = |code| raw.iter().find(|(c, _)| *c == code).map(|(_, d)| d.clone());
    assert_eq!(get(43), Some(vec![1, 2]), "matcher's set, forced");
    assert_eq!(get(61), Some(vec![1, 2, 0, 0, 0, 0, 2]), "RFC 6842 echo");
    assert_eq!(get(82), Some(vec![1, 3, b'p', b'o', b'n']), "RFC 3046 echo");
    assert_eq!(raw.last().map(|(c, _)| *c), Some(82), "option 82 last");
}

#[test]
fn relayed_requests_go_back_to_the_relay() {
    let mut c = cfg();
    c.ip.pools.pools.push(IpPool {
        id: ItemId(5),
        name: "far".into(),
        ranges: vec!["10.50.0.10-10.50.0.20".parse().unwrap()],
        next_pool: None,
        comment: String::new(),
    });
    let mut s = DhcpServer::new(ItemId(6), "relay50".into(), "ether2".parse().unwrap());
    s.address_pool = Some("far".into());
    s.relay = Some(ip("10.50.0.1"));
    c.ip.dhcp_server.servers.push(s);
    let mut n = DhcpNetwork::new(ItemId(7), "10.50.0.0/24".parse().unwrap());
    n.gateway = vec![ip("10.50.0.1")];
    c.ip.dhcp_server.networks.push(n);
    let mut lab = Lab::new(&c);
    let mut m = msg(
        MessageType::Discover,
        mac(1),
        None,
        None,
        Ipv4Addr::UNSPECIFIED,
    );
    m[24..28].copy_from_slice(&[10, 50, 0, 1]);
    let fx = lab.send(m, ip("192.168.88.1"));
    assert!(probes(&fx).is_empty(), "no ARP across a relay");
    let (bytes, to) = sent(&fx, Kind::Offer).unwrap();
    assert_eq!(to, ReplyTo::Relay(ip("10.50.0.1")));
    assert_eq!(v4::decode(&bytes).unwrap().yiaddr, ip("10.50.0.10"));
}

#[test]
fn inform_gets_options_without_a_lease() {
    let mut lab = Lab::new(&cfg());
    let fx = lab.send(
        msg(MessageType::Inform, mac(1), None, None, ip("192.168.88.77")),
        ip("192.168.88.1"),
    );
    let (bytes, to) = sent(&fx, Kind::Ack).unwrap();
    assert_eq!(to, ReplyTo::Unicast(ip("192.168.88.77")));
    let a = v4::decode(&bytes).unwrap();
    assert_eq!(a.lease_secs, None, "§4.3.5: no lease time");
    assert_eq!(a.yiaddr, Ipv4Addr::UNSPECIFIED);
    assert_eq!(a.routers, [ip("192.168.88.1")]);
}

#[test]
fn the_journal_brings_leases_back_after_a_restart() {
    let c = cfg();
    let mut lab = Lab::new(&c);
    let a = lab.dora(mac(1));
    let mut lines = String::new();
    lab.discover(mac(2));
    let text = lab.srv.compact(lab.now.unix);
    lines.push_str(&text);
    lines.push_str("{\"torn\n");
    let mut fresh = Server::new(Plan::from_config(&c), lab.now.unix);
    assert_eq!(fresh.replay(lines.lines()), 1, "the torn line is skipped");
    let l = fresh.leases().get(a).unwrap();
    assert_eq!(l.state, State::Bound);
    assert_eq!(fresh.leases().len(), 1, "offers are not kept");
}

#[test]
fn alerts_log_unknown_servers_once() {
    let mut c = cfg();
    c.ip.dhcp_server.alerts.push(Alert {
        id: ItemId(40),
        interface: "ether1".parse().unwrap(),
        valid_server: vec![MacAddr([0xaa; 6])],
        alert_timeout: 3600,
        disabled: false,
        comment: String::new(),
    });
    let mut lab = Lab::new(&c);
    let lab_server = crate::lab::LabServer::default();
    use corerouter_hal::dhcp::DhcpResponder;
    let offer = lab_server.answer(
        &"ether1".parse().unwrap(),
        mac(1),
        &msg(
            MessageType::Discover,
            mac(1),
            None,
            None,
            Ipv4Addr::UNSPECIFIED,
        ),
        corerouter_hal::dhcp::Dest::Broadcast,
    );
    let rogue = |from: [u8; 6]| Heard {
        payload: offer[0].payload.clone(),
        src: ip("100.64.1.1"),
        dst: Ipv4Addr::BROADCAST,
        src_mac: from,
        to_server: false,
    };
    let iface: IfName = "ether1".parse().unwrap();
    let fx = lab.srv.handle(lab.now, &iface, &rogue([0xbb; 6]));
    assert!(
        matches!(&fx[..], [Effect::Log { level: Level::Critical, text }] if text.contains("100.64.1.1")),
        "{fx:?}"
    );
    assert!(
        lab.srv
            .handle(lab.now, &iface, &rogue([0xbb; 6]))
            .is_empty(),
        "logged once"
    );
    assert!(
        lab.srv
            .handle(lab.now, &iface, &rogue([0xaa; 6]))
            .is_empty(),
        "a valid server"
    );
    assert_eq!(lab.srv.seen().count(), 1);
    lab.later(3_601_000);
    assert_eq!(lab.srv.seen().count(), 0, "timed out");
}

#[test]
fn check_status_frees_a_conflict_nobody_answers() {
    let mut lab = Lab::new(&cfg());
    lab.discover(mac(1));
    lab.srv.probe_reply(
        lab.now,
        &"ether2".parse().unwrap(),
        ip("192.168.88.10"),
        SQUATTER,
    );
    let fx = lab.srv.check_status(ip("192.168.88.10"), lab.now).unwrap();
    assert_eq!(probes(&fx), [ip("192.168.88.10")]);
    lab.later(PROBE_WAIT_MS);
    assert_eq!(
        lab.srv.leases().get(ip("192.168.88.10")).unwrap().state,
        State::Expired
    );
}

#[test]
fn operator_mistakes_are_caught() {
    let mut c = cfg();
    let ok = checks(&c);
    assert!(ok.iter().all(|k| k.level != CheckLevel::Error), "{ok:?}");
    assert!(
        ok.iter()
            .any(|k| k.label == "gateway" && k.level == CheckLevel::Ok)
    );
    assert!(
        ok.iter()
            .any(|k| k.label == "LAN" && k.level == CheckLevel::Ok)
    );
    // The pool takes in the gateway and the router.
    c.ip.pools.pools[0].ranges = vec!["192.168.88.1-192.168.88.20".parse().unwrap()];
    let bad = super::checks::validate(&c);
    assert!(
        bad.iter()
            .any(|i| i.message.contains("includes the gateway")),
        "{bad:?}"
    );
    assert!(
        bad.iter().any(|i| i.message.contains("router's address")),
        "{bad:?}"
    );
    // Two pools sharing addresses.
    let mut c = cfg();
    c.ip.pools.pools.push(IpPool {
        id: ItemId(2),
        name: "b".into(),
        ranges: vec!["192.168.88.20-192.168.88.30".parse().unwrap()],
        next_pool: None,
        comment: String::new(),
    });
    assert!(
        super::checks::validate(&c)
            .iter()
            .any(|i| i.message.contains("overlaps"))
    );
    // A server where the DHCP client runs: a warning, not an error.
    let mut c = cfg();
    c.ip.dhcp_clients.push(corerouter_model::DhcpClient::new(
        ItemId(1),
        "ether2".parse().unwrap(),
    ));
    assert!(super::checks::validate(&c).is_empty());
    assert!(
        checks(&c)
            .iter()
            .any(|k| k.label == "WAN?" && k.level == CheckLevel::Warn)
    );
}

#[test]
fn fqdn_flags_follow_rfc_4702() {
    let srv = Server::new(Plan::default(), 0);
    let f = request::Fqdn {
        flags: 0,
        name: "pc".into(),
    };
    // The client wants to do the A itself (S=0): we do it (S) and say we
    // overrode it (O).
    assert_eq!(srv.fqdn_reply(&f, Some("lan"))[0], FQDN_S | FQDN_O);
    let f = request::Fqdn {
        flags: FQDN_N | FQDN_E,
        name: "pc".into(),
    };
    assert_eq!(
        srv.fqdn_reply(&f, Some("lan")),
        [FQDN_N | FQDN_E, 255, 255, 2, b'p', b'c', 0]
    );
    let f = request::Fqdn {
        flags: FQDN_S,
        name: "pc".into(),
    };
    assert_eq!(srv.fqdn_reply(&f, None)[0], FQDN_N, "no zone: no update");
    assert_eq!(dns_label("My_Laptop.local"), "my-laptop");
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Hostile bytes never panic the reader nor the server.
    #[test]
    fn hostile_requests_never_panic(tail in proptest::collection::vec(any::<u8>(), 0..600), head in proptest::collection::vec(any::<u8>(), 0..240)) {
        let _ = request::parse(&tail);
        let _ = request::server_reply(&tail);
        // A real header and cookie, then hostile options.
        let mut bytes = msg(MessageType::Discover, mac(1), None, None, Ipv4Addr::UNSPECIFIED);
        bytes.truncate(240);
        for (i, b) in head.iter().enumerate().take(236) {
            if i != 0 && let Some(x) = bytes.get_mut(i) {
                *x = *b;
            }
        }
        bytes.extend_from_slice(&tail);
        let mut lab = Lab::new(&cfg());
        let _ = lab.send(bytes.clone(), Ipv4Addr::BROADCAST);
        let _ = lab.later(PROBE_WAIT_MS);
        let mut as_reply = bytes;
        as_reply[0] = 2;
        let heard = Heard { payload: as_reply, src: Ipv4Addr::UNSPECIFIED, dst: Ipv4Addr::BROADCAST, src_mac: mac(5), to_server: false };
        let _ = lab.srv.handle(lab.now, &"ether2".parse().unwrap(), &heard);
    }

    /// Option values (RouterOS syntax) parse or fail cleanly.
    #[test]
    fn option_values_never_panic(text in ".{0,300}") {
        let _ = super::checks::option_bytes(&text);
    }
}

/// G4.2b: a static lease by option 82 circuit id (a fixed address per OLT
/// port), reached through a relay; the renewal comes straight (no option
/// 82) and is still the same client's.
#[test]
fn static_leases_by_circuit_id_through_a_relay() {
    let mut c = cfg();
    c.ip.pools.pools.push(IpPool {
        id: ItemId(5),
        name: "far".into(),
        ranges: vec!["10.50.0.10-10.50.0.20".parse().unwrap()],
        next_pool: None,
        comment: String::new(),
    });
    let mut s = DhcpServer::new(ItemId(6), "relay50".into(), "ether2".parse().unwrap());
    s.address_pool = Some("far".into());
    s.relay = Some(ip("10.50.0.1"));
    c.ip.dhcp_server.servers.push(s);
    let mut n = DhcpNetwork::new(ItemId(7), "10.50.0.0/24".parse().unwrap());
    n.gateway = vec![ip("10.50.0.1")];
    c.ip.dhcp_server.networks.push(n);
    let mut st = StaticLease::new(ItemId(8), ip("10.50.0.77"));
    st.agent_circuit_id = "olt1 0/1/3".into();
    c.ip.dhcp_server.leases.push(st);
    let mut lab = Lab::new(&c);
    let relayed = |kind, requested: Option<Ipv4Addr>, server: Option<Ipv4Addr>| {
        let mut m = msg(kind, mac(4), requested, server, Ipv4Addr::UNSPECIFIED);
        m[24..28].copy_from_slice(&[10, 50, 0, 1]);
        with_82(m, &agent::build(b"olt1 0/1/3", b"line-9").unwrap())
    };
    let fx = lab.send(
        relayed(MessageType::Discover, None, None),
        ip("192.168.88.1"),
    );
    let (bytes, to) = sent(&fx, Kind::Offer).unwrap();
    assert_eq!(to, ReplyTo::Relay(ip("10.50.0.1")));
    assert_eq!(v4::decode(&bytes).unwrap().yiaddr, ip("10.50.0.77"));
    let fx = lab.send(
        relayed(
            MessageType::Request,
            Some(ip("10.50.0.77")),
            Some(ip("192.168.88.1")),
        ),
        ip("192.168.88.1"),
    );
    let b = fx
        .iter()
        .find_map(|e| match e {
            Effect::Bound(b) => Some(b.clone()),
            _ => None,
        })
        .unwrap();
    assert!(b.new);
    // RENEWING: unicast straight from the client, no relay, no option 82:
    // the lease says which server and that it is the same client.
    let fx = lab.send(
        msg(MessageType::Request, mac(4), None, None, ip("10.50.0.77")),
        ip("192.168.88.1"),
    );
    let (_, to) = sent(&fx, Kind::Ack).unwrap_or_else(|| panic!("{fx:?}"));
    assert_eq!(to, ReplyTo::Unicast(ip("10.50.0.77")));
    let b = fx
        .iter()
        .find_map(|e| match e {
            Effect::Bound(b) => Some(b.clone()),
            _ => None,
        })
        .unwrap();
    assert!(!b.new, "a renewal");
    // Another port: not the static address.
    let mut other = msg(
        MessageType::Discover,
        mac(5),
        None,
        None,
        Ipv4Addr::UNSPECIFIED,
    );
    other[24..28].copy_from_slice(&[10, 50, 0, 1]);
    let fx = lab.send(
        with_82(other, &agent::build(b"olt1 0/1/4", b"x").unwrap()),
        ip("192.168.88.1"),
    );
    assert_eq!(
        v4::decode(&sent(&fx, Kind::Offer).unwrap().0)
            .unwrap()
            .yiaddr,
        ip("10.50.0.10")
    );
}

#[test]
fn alerts_send_a_discover_a_minute() {
    let mut c = cfg();
    c.ip.dhcp_server.alerts.push(Alert {
        id: ItemId(40),
        interface: "ether1".parse().unwrap(),
        valid_server: vec![],
        alert_timeout: 3600,
        disabled: false,
        comment: String::new(),
    });
    let mut lab = Lab::new(&c);
    let probes = |fx: &[Effect]| {
        fx.iter()
            .filter(|e| matches!(e, Effect::Discover { .. }))
            .count()
    };
    assert_eq!(probes(&lab.later(1000)), 1);
    assert_eq!(probes(&lab.later(30_000)), 0);
    assert_eq!(probes(&lab.later(30_000)), 1);
}

#[test]
fn relayed_replies_heard_on_67_are_not_counted() {
    let mut lab = Lab::new(&cfg());
    let mut reply = msg(
        MessageType::Discover,
        mac(1),
        None,
        None,
        Ipv4Addr::UNSPECIFIED,
    );
    reply[0] = 2;
    assert!(lab.send(reply, ip("192.168.88.1")).is_empty());
    assert_eq!(lab.srv.stats().dropped_of(Drop::Malformed), 0);
}
