//! IPv6 of the BNG's sessions (G4.3e), the pieces `pppoe_bng.rs` calls:
//! the prefix allocator over `/ipv6 pool`, what RADIUS says about IPv6
//! (RFC 3162, RFC 4818, RFC 6911), and one session's IPv6 control plane —
//! its RA (RFC 4861, RDNSS from RFC 8106), the ND and Echo answers to our
//! link-local, and its DHCPv6 server (`proto_dhcp::sub6`). Without I/O,
//! like the rest of the BNG. Design and research: `docs/pppoe.md` §9.
//!
//! The /64 and the delegated prefix belong to the session: they are taken
//! when IPv6CP opens (before any Solicit, so Accounting knows them) and
//! given back when it ends.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::{HashMap, HashSet};
use std::net::Ipv6Addr;

use corerouter_model::dhcp6_server::Ipv6Pool;
use corerouter_model::radius::Attribute;
use corerouter_proto_dhcp::server6::IaKind;
use corerouter_proto_dhcp::sub6::{Event6, Grant6, Sub6, duid_ll};
use corerouter_proto_pppoe::eth::Vlans;
use corerouter_proto_pppoe::nd::{self, Inbound, PrefixInfo, RaConfig, RaTimer};
use corerouter_proto_pppoe::timer::Millis;
use corerouter_proto_pppoe::wire::Mac;
use ipnet::Ipv6Net;

/// RFC 4861 §6.2.1 defaults, shortened: MaxRtrAdvInterval 600 s (the
/// default), MinRtrAdvInterval 200 s (⅓ of it).
pub(crate) const RA_MAX_MS: u64 = 600_000;
pub(crate) const RA_MIN_MS: u64 = 200_000;
/// RFC 8106 §5.1: RDNSS/DNSSL lifetime ≥ 3 × MaxRtrAdvInterval.
pub(crate) const DNS_LIFETIME: u32 = 1800;
/// Router Lifetime: 3 × MaxRtrAdvInterval (RFC 4861 §6.2.1 default).
pub(crate) const ROUTER_LIFETIME: u16 = 1800;
/// Prefixes one pool hands out at most: as `ipv6.pool.add` allows.
const POOL_PIECES_MAX: u128 = 1 << 20;

/// Free and taken prefixes per `/ipv6 pool`, the BNG's own (the DHCPv6
/// server of G4.2c keeps its leases elsewhere; a pool is either one's or
/// the other's).
#[derive(Default)]
pub(crate) struct Pools6 {
    taken: HashSet<Ipv6Net>,
    /// Next index to try per pool (a ring over its pieces).
    next: HashMap<String, u128>,
    /// Given back, reused first (oldest first would be fairer for logs;
    /// a stack keeps it O(1)).
    free: HashMap<String, Vec<Ipv6Net>>,
}

/// Piece `i` of `p` (prefix-length `p.prefix_length`).
fn piece(p: &Ipv6Pool, i: u128) -> Option<Ipv6Net> {
    let len = p.prefix_length;
    if len < p.prefix.prefix_len() || len > 128 {
        return None;
    }
    let bits = u32::from(len - p.prefix.prefix_len());
    let count = if bits >= 127 {
        u128::MAX
    } else {
        1u128 << bits
    };
    if i >= count {
        return None;
    }
    let shift = 128 - u32::from(len);
    let base = p.prefix.network().to_bits();
    let off = i.checked_shl(shift).unwrap_or(0);
    Ipv6Net::new(Ipv6Addr::from_bits(base | off), len).ok()
}

fn pieces(p: &Ipv6Pool) -> u128 {
    let bits = u32::from(p.prefix_length.saturating_sub(p.prefix.prefix_len()));
    if bits >= 20 {
        POOL_PIECES_MAX
    } else {
        1u128 << bits
    }
}

impl Pools6 {
    /// A free prefix of pool `name`.
    pub(crate) fn take(&mut self, pools: &[Ipv6Pool], name: &str) -> Option<Ipv6Net> {
        let p = pools.iter().find(|p| p.name == name)?;
        if let Some(list) = self.free.get_mut(name) {
            while let Some(n) = list.pop() {
                if p.prefix.contains(&n)
                    && n.prefix_len() == p.prefix_length
                    && self.taken.insert(n)
                {
                    return Some(n);
                }
            }
        }
        let total = pieces(p);
        let start = self.next.get(name).copied().unwrap_or(0) % total.max(1);
        for k in 0..total {
            let i = (start + k) % total;
            // Piece 0 of a pool is skipped: `2001:db8::/64` read as the
            // pool's own address confuses operators (RouterOS also starts
            // at the second piece of a /64 pool).
            if i == 0 && total > 1 {
                continue;
            }
            let Some(n) = piece(p, i) else { continue };
            if self.taken.insert(n) {
                self.next.insert(name.to_owned(), i + 1);
                return Some(n);
            }
        }
        None
    }

    /// A fixed prefix (RADIUS): false when another session has it.
    pub(crate) fn hold(&mut self, n: Ipv6Net) -> bool {
        self.taken.insert(n)
    }

    pub(crate) fn give_back(&mut self, n: Ipv6Net, pool: Option<&str>) {
        if self.taken.remove(&n)
            && let Some(name) = pool
        {
            self.free.entry(name.to_owned()).or_default().push(n);
        }
    }

    /// Prefixes held (the tests' `Bng::check`).
    #[cfg(test)]
    pub(crate) fn taken(&self) -> usize {
        self.taken.len()
    }
}

/// What RADIUS said about the session's IPv6, by attribute name (the
/// RADIUS service gives `addr/len` text for `ipv6prefix`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RadiusV6 {
    /// RFC 3162 §2.3 `Framed-IPv6-Prefix`: the link's /64 (RA).
    pub framed_prefix: Option<Ipv6Net>,
    /// RFC 3162 §2.6 `Framed-IPv6-Pool`.
    pub framed_pool: Option<String>,
    /// RFC 4818 `Delegated-IPv6-Prefix`.
    pub delegated: Option<Ipv6Net>,
    /// RFC 6911 §3.4 `Delegated-IPv6-Prefix-Pool`, or MikroTik's
    /// `Mikrotik-Delegated-IPv6-Pool` (VSA 22).
    pub delegated_pool: Option<String>,
    /// RFC 6911 §3.2 `DNS-Server-IPv6-Address` (repeatable).
    pub dns: Vec<Ipv6Addr>,
}

fn prefix_text(v: &str) -> Option<Ipv6Net> {
    let n: Ipv6Net = v.trim().parse().ok()?;
    (n.prefix_len() <= 64 && n.network() == n.addr()).then_some(n)
}

impl RadiusV6 {
    /// From every attribute of an Access-Accept (`name`, text value).
    pub(crate) fn of<'a>(attrs: impl Iterator<Item = (&'a str, &'a str)>) -> RadiusV6 {
        let mut r = RadiusV6::default();
        for (name, v) in attrs {
            match name {
                "Framed-IPv6-Prefix" => {
                    r.framed_prefix = r
                        .framed_prefix
                        .or(prefix_text(v).filter(|n| n.prefix_len() == 64));
                }
                "Framed-IPv6-Pool" if r.framed_pool.is_none() => {
                    r.framed_pool = Some(v.chars().take(64).collect());
                }
                "Delegated-IPv6-Prefix" => r.delegated = r.delegated.or(prefix_text(v)),
                "Delegated-IPv6-Prefix-Pool" | "Mikrotik-Delegated-IPv6-Pool"
                    if r.delegated_pool.is_none() =>
                {
                    r.delegated_pool = Some(v.chars().take(64).collect());
                }
                "DNS-Server-IPv6-Address" if r.dns.len() < nd::MAX_DNS => {
                    if let Ok(a) = v.trim().parse::<Ipv6Addr>()
                        && !a.is_unspecified()
                        && !a.is_multicast()
                    {
                        r.dns.push(a);
                    }
                }
                _ => {}
            }
        }
        r
    }
}

/// Where a prefix of the session came from (pools give it back).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Source {
    Pool(String),
    Radius,
}

/// One session's IPv6.
pub(crate) struct V6 {
    pub local_iid: [u8; 8],
    pub peer_iid: [u8; 8],
    /// The link's /64 (RA PIO) and where it came from.
    pub link: Option<(Ipv6Net, Source)>,
    pub delegated: Option<(Ipv6Net, Source)>,
    pub dns: Vec<Ipv6Addr>,
    pub mtu: u16,
    pub ra: RaTimer,
    pub dhcp: Sub6,
    /// ND/DHCPv6 packets refused and why (the last reason), for `ppp.why`.
    pub dropped: u64,
    pub last_drop: Option<&'static str>,
}

/// What [`V6::handle`] produced.
#[derive(Default)]
pub(crate) struct V6Out {
    /// IPv6 packets for the subscriber (PPP protocol 0x0057).
    pub packets: Vec<Vec<u8>>,
    pub events: Vec<Event6>,
}

impl V6 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        now: Millis,
        local_iid: [u8; 8],
        peer_iid: [u8; 8],
        link: Option<(Ipv6Net, Source)>,
        delegated: Option<(Ipv6Net, Source)>,
        dns: Vec<Ipv6Addr>,
        lease_time: u32,
        mtu: u16,
        server_mac: [u8; 6],
    ) -> V6 {
        let grant = grant(
            server_mac,
            peer_iid,
            link.as_ref().map(|l| l.0),
            delegated.as_ref().map(|d| d.0),
            &dns,
            lease_time,
        );
        V6 {
            local_iid,
            peer_iid,
            link,
            delegated,
            dns,
            mtu,
            ra: RaTimer::new(now),
            dhcp: Sub6::new(grant),
            dropped: 0,
            last_drop: None,
        }
    }

    pub(crate) fn ours(&self) -> Ipv6Addr {
        nd::link_local(self.local_iid)
    }

    pub(crate) fn peer(&self) -> Ipv6Addr {
        nd::link_local(self.peer_iid)
    }

    /// The subscriber's address on the link's /64 (SLAAC with its IPv6CP
    /// identifier, and the IA_NA): what logs and "Who was?" can show.
    pub(crate) fn global(&self) -> Option<Ipv6Addr> {
        self.link
            .as_ref()
            .map(|(n, _)| nd::with_iid(n.network(), self.peer_iid))
    }

    /// The session's RA (RFC 4861 §6.2.3): the /64 with L and A, the MTU,
    /// RDNSS; O when DHCPv6 has something to give (a prefix, DNS), M when
    /// it hands out an address.
    pub(crate) fn ra_config(&self) -> RaConfig {
        let (_, _, preferred, valid) = self.dhcp.grant().lifetimes();
        RaConfig {
            managed: false,
            other: self.delegated.is_some() || !self.dns.is_empty(),
            router_lifetime: ROUTER_LIFETIME,
            mtu: Some(u32::from(self.mtu)),
            prefixes: self
                .link
                .iter()
                .map(|(n, _)| PrefixInfo {
                    prefix: n.network(),
                    len: n.prefix_len(),
                    on_link: true,
                    autonomous: true,
                    valid,
                    preferred,
                })
                .collect(),
            rdnss: self.dns.clone(),
            dns_lifetime: DNS_LIFETIME,
            ..RaConfig::default()
        }
    }

    fn ra(&mut self, now: Millis, to: Ipv6Addr, rand: u32) -> Vec<u8> {
        let mut p = Vec::with_capacity(160);
        nd::router_advert(&mut p, self.ours(), to, &self.ra_config());
        self.ra.sent(now, rand, RA_MIN_MS, RA_MAX_MS);
        p
    }

    /// The unsolicited RA when it is due (`ff02::1`, RFC 4861 §6.2.4).
    pub(crate) fn due(&mut self, now: Millis, rand: u32) -> Option<Vec<u8>> {
        (self.ra.next_at <= now).then(|| self.ra(now, nd::ALL_NODES, rand))
    }

    fn drop(&mut self, why: &'static str) {
        self.dropped += 1;
        self.last_drop = Some(why);
    }

    /// One IPv6 packet from the subscriber that the control plane answers.
    /// `None` = not ours (forwarded traffic: the data plane's).
    pub(crate) fn handle(&mut self, now: Millis, packet: &[u8], rand: u32) -> Option<V6Out> {
        let mut out = V6Out::default();
        match nd::classify(packet) {
            Inbound::RouterSolicit { src } => {
                // §6.2.6: on a point-to-point link the answer goes at once
                // and unicast, but never twice within 3 s.
                if self.ra.solicited_at(now) <= now {
                    let to = if src.is_unspecified() {
                        nd::ALL_NODES
                    } else {
                        src
                    };
                    out.packets.push(self.ra(now, to, rand));
                } else {
                    self.drop("RS within 3 s of the last RA");
                }
            }
            Inbound::NeighborSolicit { src, target } => {
                // Only our link-local is on the link (the /64 is the
                // subscriber's).
                if target == self.ours() {
                    let mut p = Vec::new();
                    if src.is_unspecified() {
                        nd::neighbor_advert(&mut p, self.ours(), nd::ALL_NODES, target, false);
                    } else {
                        nd::neighbor_advert(&mut p, self.ours(), src, target, true);
                    }
                    out.packets.push(p);
                }
            }
            Inbound::EchoRequest { src, dst, body } if dst == self.ours() => {
                let mut p = Vec::new();
                nd::echo_reply(&mut p, dst, src, body);
                out.packets.push(p);
            }
            Inbound::Dhcp6 {
                src,
                src_port,
                payload,
                ..
            } => {
                if src.segments()[0] != 0xfe80 {
                    // RFC 9915 §18.2: a client sends from its link-local.
                    self.drop("DHCPv6 not from a link-local address");
                    return Some(out);
                }
                let a = self.dhcp.handle(payload);
                if let Some(why) = a.dropped {
                    self.drop(why);
                }
                if let Some(reply) = a.reply {
                    let mut p = Vec::with_capacity(reply.len() + 48);
                    nd::udp6(
                        &mut p,
                        self.ours(),
                        src,
                        nd::DHCP6_SERVER_PORT,
                        src_port,
                        &reply,
                    );
                    out.packets.push(p);
                }
                out.events = a.events;
            }
            Inbound::Invalid(why) => self.drop(why),
            Inbound::EchoRequest { .. } | Inbound::Other => return None,
        }
        Some(out)
    }

    /// Whether the delegated prefix is held by the CPE's DHCPv6 client.
    pub(crate) fn pd_bound(&self) -> bool {
        self.dhcp.bound_prefix().is_some()
    }

    /// Accounting attributes (RFC 3162, RFC 4818, RFC 6911 §3: all may be
    /// in an Accounting-Request). RouterOS sends none of the delegated
    /// prefix; here it goes from the Start on.
    pub(crate) fn acct_attributes(&self) -> Vec<Attribute> {
        let mut v = vec![Attribute::new(
            "Framed-Interface-Id",
            format!("0x{}", hex8(self.peer_iid)),
        )];
        if let Some((n, _)) = &self.link {
            v.push(Attribute::new("Framed-IPv6-Prefix", n.to_string()));
        }
        if let Some((n, _)) = &self.delegated {
            v.push(Attribute::new("Delegated-IPv6-Prefix", n.to_string()));
        }
        v
    }
}

fn hex8(b: [u8; 8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The session's DHCPv6 grant: IA_NA = the /64 + the subscriber's
/// identifier (what SLAAC gives it), IA_PD = the delegated prefix.
pub(crate) fn grant(
    server_mac: [u8; 6],
    peer_iid: [u8; 8],
    link: Option<Ipv6Net>,
    delegated: Option<Ipv6Net>,
    dns: &[Ipv6Addr],
    lease_time: u32,
) -> Grant6 {
    Grant6 {
        server_duid: duid_ll(server_mac),
        address: link.map(|n| nd::with_iid(n.network(), peer_iid)),
        link,
        prefix: delegated,
        dns: dns.to_vec(),
        domains: Vec::new(),
        lease_time,
        rapid_commit: true,
    }
}

/// The PPPoE session frame of one IPv6 packet toward a subscriber.
pub(crate) fn frame(
    client: [u8; 6],
    server: [u8; 6],
    vlans: Vlans,
    sid: u16,
    packet: &[u8],
) -> Vec<u8> {
    session_frame(
        client,
        server,
        vlans,
        sid,
        corerouter_proto_pppoe::ppp::proto::IPV6,
        packet,
    )
}

/// A PPPoE session frame (RFC 2516 §4) to `client` carrying `packet` of
/// PPP protocol `protocol`, inside the line's tags (G4.3l: two in QinQ).
pub(crate) fn session_frame(
    client: [u8; 6],
    server: [u8; 6],
    vlans: Vlans,
    sid: u16,
    protocol: u16,
    packet: &[u8],
) -> Vec<u8> {
    let mut f = Vec::with_capacity(packet.len() + 30);
    corerouter_proto_pppoe::eth::put_header(
        &mut f,
        Mac(client),
        Mac(server),
        vlans,
        corerouter_proto_pppoe::eth::ETHERTYPE_SESSION,
    );
    f.extend_from_slice(&[0x11, 0x00]);
    f.extend_from_slice(&sid.to_be_bytes());
    let len = u16::try_from(packet.len() + 2).unwrap_or(u16::MAX);
    f.extend_from_slice(&len.to_be_bytes());
    f.extend_from_slice(&protocol.to_be_bytes());
    f.extend_from_slice(packet);
    f
}

/// The high 64 bits of a prefix, as the XDP map keeps it.
pub(crate) fn high64(n: Ipv6Net) -> [u8; 8] {
    ((n.network().to_bits() >> 64) as u64).to_be_bytes()
}

/// Whether an event changes what the PPP window shows.
pub(crate) fn pd_changed(ev: &[Event6]) -> bool {
    ev.iter().any(|e| {
        matches!(
            e,
            Event6::Bound {
                kind: IaKind::Pd,
                ..
            } | Event6::Released {
                kind: IaKind::Pd,
                ..
            }
        )
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use corerouter_model::ItemId;

    fn pool(name: &str, prefix: &str, len: u8) -> Ipv6Pool {
        Ipv6Pool {
            id: ItemId(1),
            name: name.into(),
            prefix: prefix.parse().unwrap(),
            prefix_length: len,
            comment: String::new(),
        }
    }

    #[test]
    fn pools_hand_out_distinct_pieces_and_take_them_back() {
        let pools = vec![
            pool("pd", "2001:db8:8000::/46", 48),
            pool("wan", "2001:db8::/62", 64),
        ];
        let mut p = Pools6::default();
        let a = p.take(&pools, "pd").unwrap();
        let b = p.take(&pools, "pd").unwrap();
        let c = p.take(&pools, "pd").unwrap();
        assert_ne!(a, b);
        assert_eq!(a, "2001:db8:8001::/48".parse().unwrap(), "piece 0 skipped");
        assert!(
            p.take(&pools, "pd").is_none(),
            "4 pieces, the first skipped"
        );
        p.give_back(b, Some("pd"));
        assert_eq!(p.take(&pools, "pd"), Some(b));
        assert!(!p.hold(c), "taken");
        p.give_back(c, Some("pd"));
        assert!(p.hold(c), "a RADIUS prefix may take a free one");
        assert_eq!(p.take(&pools, "wan").unwrap().prefix_len(), 64);
        assert!(p.take(&pools, "nope").is_none());
        assert_eq!(p.taken(), 4);
    }

    #[test]
    fn huge_pools_are_walked_lazily() {
        let pools = vec![pool("big", "2001:db8::/32", 64)];
        let mut p = Pools6::default();
        let t = std::time::Instant::now();
        let mut seen = HashSet::new();
        for _ in 0..10_000 {
            assert!(seen.insert(p.take(&pools, "big").unwrap()));
        }
        assert!(t.elapsed().as_millis() < 2_000);
    }

    #[test]
    fn radius_attributes_rfc3162_rfc4818_rfc6911() {
        let attrs = [
            ("Framed-IPv6-Prefix", "2001:db8:0:9::/64"),
            ("Delegated-IPv6-Prefix", "2001:db8:9900::/56"),
            ("DNS-Server-IPv6-Address", "2001:db8::53"),
            ("DNS-Server-IPv6-Address", "ff02::1"),
            ("Mikrotik-Delegated-IPv6-Pool", "pd-radius"),
            ("Framed-IPv6-Pool", "wan"),
        ];
        let r = RadiusV6::of(attrs.iter().map(|(a, b)| (*a, *b)));
        assert_eq!(r.framed_prefix, Some("2001:db8:0:9::/64".parse().unwrap()));
        assert_eq!(r.delegated, Some("2001:db8:9900::/56".parse().unwrap()));
        assert_eq!(r.dns, vec!["2001:db8::53".parse::<Ipv6Addr>().unwrap()]);
        assert_eq!(r.delegated_pool.as_deref(), Some("pd-radius"));
        assert_eq!(r.framed_pool.as_deref(), Some("wan"));
        // Not a /64, host bits set, or junk: ignored.
        let r = RadiusV6::of(
            [
                ("Framed-IPv6-Prefix", "2001:db8::/48"),
                ("Delegated-IPv6-Prefix", "2001:db8::1/56"),
                ("DNS-Server-IPv6-Address", "zz"),
            ]
            .into_iter(),
        );
        assert_eq!(r, RadiusV6::default());
    }

    fn session() -> V6 {
        V6::new(
            0,
            [0x02, 0, 0, 0, 0, 0, 0, 1],
            [0x02, 0, 0, 0, 0, 0, 0, 2],
            Some((
                "2001:db8:0:5::/64".parse().unwrap(),
                Source::Pool("wan".into()),
            )),
            Some(("2001:db8:8800::/56".parse().unwrap(), Source::Radius)),
            vec!["2001:db8::53".parse().unwrap()],
            86_400,
            1492,
            [0x02, 0xaa, 0, 0, 0, 1],
        )
    }

    #[test]
    fn ra_carries_the_prefix_mtu_and_dns() {
        let mut s = session();
        let p = s.due(0, 7).unwrap();
        let ra = nd::parse_ra(&p).unwrap();
        assert_eq!(ra.src, s.ours());
        assert!(ra.other && !ra.managed);
        assert_eq!(ra.mtu, Some(1492));
        assert_eq!(
            ra.prefixes[0].prefix,
            "2001:db8:0:5::".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(ra.prefixes[0].valid, 86_400);
        assert_eq!(ra.rdnss, s.dns);
        assert_eq!(ra.dns_lifetime, Some(DNS_LIFETIME));
        assert!(s.due(1, 7).is_none(), "next one later");
        assert_eq!(s.global(), Some("2001:db8:0:5:200::2".parse().unwrap()));
    }

    #[test]
    fn rs_ns_echo_and_dhcpv6_are_answered() {
        let mut s = session();
        let mut rs = Vec::new();
        nd::router_solicit(&mut rs, s.peer());
        let out = s.handle(0, &rs, 1).unwrap();
        assert_eq!(
            nd::parse_ipv6(&out.packets[0]).unwrap().dst,
            s.peer(),
            "unicast"
        );
        // A second RS right away: rate limited.
        assert!(s.handle(100, &rs, 1).unwrap().packets.is_empty());
        assert_eq!(s.dropped, 1);
        // DHCPv6 Solicit with Rapid Commit → Reply with the session's PD.
        let sol = corerouter_proto_dhcp::v6::Outgoing {
            kind: corerouter_proto_dhcp::v6::msg::SOLICIT,
            xid: 9,
            client_id: &[0, 3, 0, 1, 2, 0, 0, 0, 0, 2],
            server_id: None,
            elapsed_cs: 0,
            rapid_commit: true,
            ia_na: None,
            ia_pd: Some(corerouter_proto_dhcp::v6::IaReq {
                iaid: 1,
                ..Default::default()
            }),
            oro: &[23],
        }
        .encode();
        let mut p = Vec::new();
        nd::udp6(&mut p, s.peer(), nd::ALL_DHCP, 546, 547, &sol);
        let out = s.handle(0, &p, 1).unwrap();
        assert!(pd_changed(&out.events));
        assert!(s.pd_bound());
        let h = nd::parse_ipv6(&out.packets[0]).unwrap();
        assert_eq!((h.src, h.dst), (s.ours(), s.peer()));
        let r = corerouter_proto_dhcp::v6::decode(&h.payload[8..]).unwrap();
        assert_eq!(
            r.ia_pd[0].prefixes[0].prefix,
            "2001:db8:8800::/56".parse().unwrap()
        );
        // Echo to our link-local is answered; to elsewhere it is traffic.
        let mut e = Vec::new();
        nd::echo_reply(&mut e, s.peer(), s.ours(), &[0, 1, 0, 1]);
        e[40] = nd::icmp::ECHO_REQUEST;
        let c = nd::checksum(s.peer(), s.ours(), 58, &{
            let mut m = e[40..].to_vec();
            m[2] = 0;
            m[3] = 0;
            m
        });
        e[42..44].copy_from_slice(&c.to_be_bytes());
        assert_eq!(s.handle(0, &e, 1).unwrap().packets.len(), 1);
        let mut u = Vec::new();
        nd::udp6(
            &mut u,
            "2001:db8:0:5::9".parse().unwrap(),
            "2001:db8:ffff::1".parse().unwrap(),
            1,
            53,
            b"x",
        );
        assert!(s.handle(0, &u, 1).is_none());
    }

    #[test]
    fn accounting_names_both_prefixes() {
        let a = session().acct_attributes();
        let names: Vec<_> = a
            .iter()
            .map(|x| (x.name.as_str(), x.value.as_str()))
            .collect();
        assert!(names.contains(&("Framed-IPv6-Prefix", "2001:db8:0:5::/64")));
        assert!(names.contains(&("Delegated-IPv6-Prefix", "2001:db8:8800::/56")));
        assert!(names.contains(&("Framed-Interface-Id", "0x0200000000000002")));
    }

    #[test]
    fn frame_is_a_pppoe_session_of_protocol_0x0057() {
        let f = frame(
            [2, 0, 0, 0, 0, 2],
            [2, 0, 0, 0, 0, 1],
            Vlans::single(100),
            0x51,
            &[0x60; 40],
        );
        assert_eq!(&f[12..16], &[0x81, 0x00, 0x00, 100]);
        assert_eq!(&f[16..18], &[0x88, 0x64]);
        assert_eq!(&f[20..22], &[0, 0x51]);
        assert_eq!(u16::from_be_bytes([f[22], f[23]]), 42);
        assert_eq!(&f[24..26], &[0x00, 0x57]);
        assert_eq!(
            high64("2001:db8:1:2::/64".parse().unwrap()),
            [0x20, 1, 0xd, 0xb8, 0, 1, 0, 2]
        );
        // G4.3l: QinQ, 802.1ad outside, 802.1Q inside.
        let f = session_frame(
            [2; 6],
            [4; 6],
            Vlans::qinq(120, 3044),
            7,
            0x0021,
            &[0x45; 20],
        );
        assert_eq!(
            &f[12..22],
            &[0x88, 0xa8, 0, 120, 0x81, 0x00, 0x0b, 0xe4, 0x88, 0x64]
        );
        assert_eq!(&f[26..30], &[0, 22, 0x00, 0x21]);
    }
}
