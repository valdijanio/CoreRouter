//! The option logic of LCP, IPCP and IPv6CP ([`Layer`] implementations) for
//! both ends: the access concentrator ([`Role::Server`]) and the subscriber
//! ([`Role::Client`], the load generator).

use crate::fsm::Layer;
use crate::lcp::{AuthProto, LcpOpt, opt as lcpopt};
use crate::ncp::{IpcpOpt, Ipv6cpOpt, ipcp as ipcpopt, ipv6cp as v6opt};
use crate::ppp::{Opt, options, proto, put_opt};
use crate::wire::WireError;
use std::net::Ipv4Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Role {
    #[default]
    Server,
    Client,
}

/// The smallest MRU we take: below it an IPv4 + TCP header pair does not fit.
pub const MIN_MRU: u16 = 128;

/// A tiny xorshift for values that must merely differ (a fresh Magic-Number
/// to Nak with, RFC 1661 §6.4); seeded per session from the server's
/// generator.
#[derive(Debug, Clone, Copy)]
pub struct Xorshift(pub u32);

impl Xorshift {
    pub fn next_nonzero(&mut self) -> u32 {
        let mut x = self.0.max(1);
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.0 = x;
        x
    }
}

/// Authentication protocols in preference order (at most the four known).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct AuthSet {
    order: [Option<AuthProto>; 4],
}

impl AuthSet {
    pub fn new(list: &[AuthProto]) -> AuthSet {
        let mut s = AuthSet::default();
        let mut n = 0;
        for a in list {
            if !s.contains(*a)
                && let Some(slot) = s.order.get_mut(n)
            {
                *slot = Some(*a);
                n += 1;
            }
        }
        s
    }

    /// RouterOS v7 default: mschap2, mschap1, chap, pap.
    pub fn routeros_default() -> AuthSet {
        AuthSet::new(&[
            AuthProto::MsChapV2,
            AuthProto::MsChapV1,
            AuthProto::ChapMd5,
            AuthProto::Pap,
        ])
    }

    pub fn contains(&self, a: AuthProto) -> bool {
        self.order.contains(&Some(a))
    }

    pub fn first(&self) -> Option<AuthProto> {
        self.order.iter().flatten().next().copied()
    }

    pub fn is_empty(&self) -> bool {
        self.first().is_none()
    }

    /// The next protocol after `a` in preference order.
    pub fn after(&self, a: AuthProto) -> Option<AuthProto> {
        self.order
            .iter()
            .flatten()
            .skip_while(|x| **x != a)
            .nth(1)
            .copied()
    }
}

// ------------------------------------------------------------------ LCP

/// LCP for one session.
#[derive(Debug, Clone)]
pub struct Lcp {
    pub role: Role,
    /// What we offer as our MRU (RouterOS `max-mru`).
    pub our_mru: u16,
    /// Largest MRU of the peer we send to (RouterOS `max-mtu`, raised by
    /// RFC 4638 when PPP-Max-Payload was agreed).
    pub max_mtu: u16,
    pub our_magic: u32,
    send_mru: bool,
    send_magic: bool,
    /// Server: the protocol we currently ask for; client: unused.
    pub auth: Option<AuthProto>,
    /// Server: what we may ask for; client: what we accept.
    pub allowed: AuthSet,
    /// The server ran out of protocols the peer accepts.
    pub auth_refused: bool,
    /// The peer's MRU (what our frames must fit); 1492 until agreed.
    pub peer_mru: u16,
    pub peer_magic: u32,
    /// Client: the protocol the server asked us to authenticate with.
    pub peer_auth: Option<AuthProto>,
    /// Our request (auth, MRU) was acked.
    pub auth_agreed: Option<AuthProto>,
    rng: Xorshift,
}

impl Lcp {
    pub fn new(role: Role, our_mru: u16, max_mtu: u16, allowed: AuthSet, magic: u32) -> Lcp {
        Lcp {
            role,
            our_mru,
            max_mtu,
            our_magic: magic.max(1),
            send_mru: true,
            send_magic: true,
            auth: match role {
                Role::Server => allowed.first(),
                Role::Client => None,
            },
            allowed,
            auth_refused: false,
            peer_mru: crate::discovery::DEFAULT_MRU,
            peer_magic: 0,
            peer_auth: None,
            auth_agreed: None,
            rng: Xorshift(magic ^ 0x9e37_79b9),
        }
    }

    /// The Magic-Number for Echo/Discard bodies: zero unless negotiated
    /// (RFC 1661 §5.8).
    pub fn echo_magic(&self) -> u32 {
        if self.send_magic { self.our_magic } else { 0 }
    }
}

impl Layer for Lcp {
    const PROTOCOL: u16 = proto::LCP;

    fn request(&mut self, out: &mut Vec<u8>) {
        if self.send_mru {
            let _ = LcpOpt::Mru(self.our_mru).put(out);
        }
        if self.role == Role::Server
            && let Some(a) = self.auth
        {
            let _ = LcpOpt::Auth(a).put(out);
        }
        if self.send_magic {
            let _ = LcpOpt::Magic(self.our_magic).put(out);
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
            match LcpOpt::parse(o)? {
                // RFC 1661 §6.1; RFC 2516 §7: at most 1492 unless RFC 4638.
                LcpOpt::Mru(v) => {
                    if v > self.max_mtu {
                        LcpOpt::Mru(self.max_mtu).put(nak)?;
                    } else if v < MIN_MRU {
                        LcpOpt::Mru(MIN_MRU).put(nak)?;
                    }
                }
                // RFC 1661 §6.4: zero "MUST always be Nak'd"; our own value
                // back means a looped link: Nak with a fresh one.
                LcpOpt::Magic(v) => {
                    if v == 0 || (self.send_magic && v == self.our_magic) {
                        LcpOpt::Magic(self.rng.next_nonzero()).put(nak)?;
                    }
                }
                LcpOpt::Auth(a) => match self.role {
                    // The subscriber never authenticates the BNG.
                    Role::Server => put_opt(rej, o.kind, o.data)?,
                    Role::Client => {
                        if !self.allowed.contains(a) {
                            match self.allowed.first() {
                                // RFC 1661 §6.2: Nak with the protocol we want.
                                Some(w) => LcpOpt::Auth(w).put(nak)?,
                                None => put_opt(rej, o.kind, o.data)?,
                            }
                        }
                    }
                },
                LcpOpt::AuthOther(_) => match (self.role, self.allowed.first()) {
                    (Role::Client, Some(w)) => LcpOpt::Auth(w).put(nak)?,
                    _ => put_opt(rej, o.kind, o.data)?,
                },
                // RFC 2516 §7: ACCM, ACFC and FCS-Alternatives MUST be
                // rejected; PFC is NOT RECOMMENDED (rejected: the data
                // plane reads a two-octet Protocol field). Multilink
                // (RFC 1990), callback and quality protocols: rejected.
                LcpOpt::Accm(_)
                | LcpOpt::Acfc
                | LcpOpt::Pfc
                | LcpOpt::FcsAlternatives(_)
                | LcpOpt::Quality(_)
                | LcpOpt::Callback(_)
                | LcpOpt::Mrru(_)
                | LcpOpt::ShortSequence
                | LcpOpt::EndpointDiscriminator { .. }
                | LcpOpt::Unknown(_) => put_opt(rej, o.kind, o.data)?,
            }
        }
        Ok(())
    }

    fn peer_acked(&mut self, opts: &[u8]) {
        self.peer_mru = crate::discovery::DEFAULT_MRU.min(self.max_mtu);
        self.peer_magic = 0;
        if self.role == Role::Client {
            self.peer_auth = None;
        }
        for o in options(opts).flatten() {
            match LcpOpt::parse(o) {
                Ok(LcpOpt::Mru(v)) => self.peer_mru = v,
                Ok(LcpOpt::Magic(v)) => self.peer_magic = v,
                Ok(LcpOpt::Auth(a)) if self.role == Role::Client => self.peer_auth = Some(a),
                _ => {}
            }
        }
    }

    fn acked(&mut self, opts: &[u8]) {
        self.auth_agreed = None;
        for o in options(opts).flatten() {
            if let Ok(LcpOpt::Auth(a)) = LcpOpt::parse(o) {
                self.auth_agreed = Some(a);
            }
        }
    }

    fn naked(&mut self, opts: &[u8]) {
        for o in options(opts).flatten() {
            match LcpOpt::parse(o) {
                Ok(LcpOpt::Mru(v)) => {
                    if (MIN_MRU..=self.our_mru).contains(&v) {
                        self.our_mru = v;
                    } else {
                        // A value we cannot use: stop offering (default 1500
                        // for the peer, which PPPoE clamps to 1492 anyway).
                        self.send_mru = false;
                    }
                }
                // §6.4: a Nak'd magic means a possible loop: pick a new one.
                Ok(LcpOpt::Magic(_)) => self.our_magic = self.rng.next_nonzero(),
                Ok(LcpOpt::Auth(a)) if self.role == Role::Server => {
                    // The peer's suggestion if we allow it, else our next.
                    let cur = self.auth;
                    self.auth = if self.allowed.contains(a) {
                        Some(a)
                    } else {
                        cur.and_then(|c| self.allowed.after(c))
                    };
                    if self.auth.is_none() {
                        self.auth_refused = true;
                    }
                }
                Ok(LcpOpt::AuthOther(_)) if self.role == Role::Server => {
                    self.auth = self.auth.and_then(|c| self.allowed.after(c));
                    if self.auth.is_none() {
                        self.auth_refused = true;
                    }
                }
                _ => {}
            }
        }
    }

    fn rejected(&mut self, opts: &[u8]) -> bool {
        for o in options(opts).flatten() {
            match o.kind {
                lcpopt::MRU => self.send_mru = false,
                lcpopt::MAGIC_NUMBER => self.send_magic = false,
                // The BNG cannot let a subscriber in unauthenticated.
                lcpopt::AUTH_PROTOCOL => return false,
                _ => {}
            }
        }
        true
    }
}

// ------------------------------------------------------------------ IPCP

/// IPCP for one session.
#[derive(Debug, Clone, Default)]
pub struct Ipcp {
    pub role: Role,
    /// Server: our address (sent as IP-Address; unset = unnumbered).
    /// Client: what we ask for (0.0.0.0 first, then the Nak'd value).
    pub local: Option<Ipv4Addr>,
    /// Server: the subscriber's address; client: the BNG's.
    pub peer: Option<Ipv4Addr>,
    /// Server: the DNS/NBNS we give; client: what we got.
    pub dns: [Option<Ipv4Addr>; 2],
    pub nbns: [Option<Ipv4Addr>; 2],
    /// Client: ask for DNS (RFC 1877 §1.1/§1.3).
    pub want_dns: bool,
    rejected_dns: [bool; 2],
}

impl Ipcp {
    pub fn server(local: Option<Ipv4Addr>) -> Ipcp {
        Ipcp {
            role: Role::Server,
            local,
            ..Ipcp::default()
        }
    }

    pub fn client(want_dns: bool) -> Ipcp {
        Ipcp {
            role: Role::Client,
            local: Some(Ipv4Addr::UNSPECIFIED),
            want_dns,
            ..Ipcp::default()
        }
    }
}

/// Server side of an address option: accept the value we hold, Nak a
/// request for anything else with ours, Reject when we hold none.
fn offer(
    nak: &mut Vec<u8>,
    rej: &mut Vec<u8>,
    o: &Opt<'_>,
    got: Ipv4Addr,
    ours: Option<Ipv4Addr>,
) -> Result<(), WireError> {
    match ours {
        Some(a) if a == got => Ok(()),
        Some(a) => put_opt(nak, o.kind, &a.octets()),
        None => put_opt(rej, o.kind, o.data),
    }
}

impl Layer for Ipcp {
    const PROTOCOL: u16 = proto::IPCP;

    fn request(&mut self, out: &mut Vec<u8>) {
        if let Some(a) = self.local {
            let _ = IpcpOpt::IpAddress(a).put(out);
        }
        if self.role == Role::Client && self.want_dns {
            for (i, kind) in [ipcpopt::PRIMARY_DNS, ipcpopt::SECONDARY_DNS].into_iter().enumerate() {
                if !self.rejected_dns.get(i).copied().unwrap_or(true) {
                    let v = self.dns.get(i).copied().flatten().unwrap_or(Ipv4Addr::UNSPECIFIED);
                    let _ = put_opt(out, kind, &v.octets());
                }
            }
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
            let parsed = IpcpOpt::parse(o)?;
            match (self.role, parsed) {
                // RFC 1332 §3.3: 0.0.0.0 asks us to assign; any other value is
                // Nak'd with the address the subscriber gets.
                (Role::Server, IpcpOpt::IpAddress(a)) => match self.peer {
                    Some(p) if p == a => {}
                    Some(p) => put_opt(nak, o.kind, &p.octets())?,
                    None => put_opt(rej, o.kind, o.data)?,
                },
                (Role::Server, IpcpOpt::PrimaryDns(a)) => offer(nak, rej, &o, a, self.dns[0])?,
                (Role::Server, IpcpOpt::SecondaryDns(a)) => offer(nak, rej, &o, a, self.dns[1])?,
                (Role::Server, IpcpOpt::PrimaryNbns(a)) => offer(nak, rej, &o, a, self.nbns[0])?,
                (Role::Server, IpcpOpt::SecondaryNbns(a)) => {
                    offer(nak, rej, &o, a, self.nbns[1])?
                }
                // The BNG's own address: any non-zero value.
                (Role::Client, IpcpOpt::IpAddress(a)) if !a.is_unspecified() => {}
                // RFC 1332 §3.1/§3.2: IP-Addresses and VJ compression are
                // refused (the XDP data plane carries plain IP).
                _ => put_opt(rej, o.kind, o.data)?,
            }
        }
        Ok(())
    }

    fn peer_acked(&mut self, opts: &[u8]) {
        if self.role == Role::Client {
            for o in options(opts).flatten() {
                if let Ok(IpcpOpt::IpAddress(a)) = IpcpOpt::parse(o) {
                    self.peer = Some(a);
                }
            }
        }
    }

    fn acked(&mut self, opts: &[u8]) {
        if self.role == Role::Client {
            for o in options(opts).flatten() {
                match IpcpOpt::parse(o) {
                    Ok(IpcpOpt::IpAddress(a)) => self.local = Some(a),
                    Ok(IpcpOpt::PrimaryDns(a)) => self.dns[0] = Some(a),
                    Ok(IpcpOpt::SecondaryDns(a)) => self.dns[1] = Some(a),
                    _ => {}
                }
            }
        }
    }

    fn naked(&mut self, opts: &[u8]) {
        // The server keeps its own address; the client takes what it is
        // given (RFC 1332 §3.3, RFC 1877 §1).
        if self.role == Role::Client {
            for o in options(opts).flatten() {
                match IpcpOpt::parse(o) {
                    Ok(IpcpOpt::IpAddress(a)) => self.local = Some(a),
                    Ok(IpcpOpt::PrimaryDns(a)) => self.dns[0] = Some(a),
                    Ok(IpcpOpt::SecondaryDns(a)) => self.dns[1] = Some(a),
                    _ => {}
                }
            }
        }
    }

    fn rejected(&mut self, opts: &[u8]) -> bool {
        for o in options(opts).flatten() {
            match o.kind {
                ipcpopt::IP_ADDRESS => {
                    if self.role == Role::Client {
                        // No address, no IPv4 service.
                        return false;
                    }
                    self.local = None;
                }
                ipcpopt::PRIMARY_DNS => self.rejected_dns[0] = true,
                ipcpopt::SECONDARY_DNS => self.rejected_dns[1] = true,
                _ => {}
            }
        }
        true
    }
}

// ------------------------------------------------------------------ IPv6CP

/// IPv6CP for one session (RFC 5072 §4.1: interface identifiers only; the
/// prefix comes later from RA/DHCPv6, G4.3e).
#[derive(Debug, Clone)]
pub struct Ipv6cp {
    pub local_iid: [u8; 8],
    pub peer_iid: Option<[u8; 8]>,
    send_iid: bool,
    rng: Xorshift,
}

impl Ipv6cp {
    pub fn new(local_iid: [u8; 8], seed: u32) -> Ipv6cp {
        Ipv6cp {
            local_iid,
            peer_iid: None,
            send_iid: true,
            rng: Xorshift(seed),
        }
    }

    fn fresh(&mut self, not: [u8; 8]) -> [u8; 8] {
        loop {
            let a = self.rng.next_nonzero().to_be_bytes();
            let b = self.rng.next_nonzero().to_be_bytes();
            let iid = [a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]];
            if iid != not && iid != [0; 8] {
                return iid;
            }
        }
    }
}

impl Layer for Ipv6cp {
    const PROTOCOL: u16 = proto::IPV6CP;

    fn request(&mut self, out: &mut Vec<u8>) {
        if self.send_iid {
            let _ = Ipv6cpOpt::InterfaceId(self.local_iid).put(out);
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
            match Ipv6cpOpt::parse(o)? {
                // RFC 5072 §4.1: an all-zero identifier, or one equal to ours,
                // is Nak'd with a fresh one.
                Ipv6cpOpt::InterfaceId(i) => {
                    if i == [0; 8] || i == self.local_iid {
                        let f = self.fresh(self.local_iid);
                        Ipv6cpOpt::InterfaceId(f).put(nak)?;
                    }
                }
                Ipv6cpOpt::Compression(_) | Ipv6cpOpt::Unknown(_) => {
                    put_opt(rej, o.kind, o.data)?
                }
            }
        }
        Ok(())
    }

    fn peer_acked(&mut self, opts: &[u8]) {
        for o in options(opts).flatten() {
            if let Ok(Ipv6cpOpt::InterfaceId(i)) = Ipv6cpOpt::parse(o) {
                self.peer_iid = Some(i);
            }
        }
    }

    fn acked(&mut self, _opts: &[u8]) {}

    fn naked(&mut self, opts: &[u8]) {
        for o in options(opts).flatten() {
            if let Ok(Ipv6cpOpt::InterfaceId(i)) = Ipv6cpOpt::parse(o) {
                // RFC 5072 §4.1: take the suggestion unless it collides.
                self.local_iid = if i != [0; 8] && Some(i) != self.peer_iid {
                    i
                } else {
                    let not = self.peer_iid.unwrap_or([0; 8]);
                    self.fresh(not)
                };
            }
        }
    }

    fn rejected(&mut self, opts: &[u8]) -> bool {
        if options(opts)
            .flatten()
            .any(|o| o.kind == v6opt::INTERFACE_IDENTIFIER)
        {
            self.send_iid = false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify<L: Layer>(l: &mut L, opts: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let (mut n, mut r) = (Vec::new(), Vec::new());
        l.classify(opts, &mut n, &mut r).unwrap();
        (n, r)
    }

    fn server_lcp() -> Lcp {
        Lcp::new(Role::Server, 1480, 1480, AuthSet::routeros_default(), 0x1234_5678)
    }

    #[test]
    fn rfc2516_7_accm_acfc_fcs_and_pfc_are_rejected() {
        let mut l = server_lcp();
        let opts = [2, 6, 0, 0, 0, 0, 7, 2, 8, 2, 9, 3, 1];
        let (n, r) = classify(&mut l, &opts);
        assert!(n.is_empty());
        assert_eq!(r, opts);
    }

    #[test]
    fn rfc2516_7_mru_above_max_is_naked_down() {
        let mut l = server_lcp();
        let (n, r) = classify(&mut l, &[1, 4, 0x05, 0xdc]); // 1500
        assert!(r.is_empty());
        assert_eq!(n, [1, 4, 0x05, 0xc8]); // 1480
        let (n, _) = classify(&mut l, &[1, 4, 0x05, 0xc8]);
        assert!(n.is_empty());
    }

    #[test]
    fn rfc1661_6_4_magic_zero_and_own_magic_are_naked() {
        let mut l = server_lcp();
        let (n, _) = classify(&mut l, &[5, 6, 0, 0, 0, 0]);
        assert_eq!(n.len(), 6);
        assert_ne!(&n[2..], &[0, 0, 0, 0]);
        let (n, _) = classify(&mut l, &[5, 6, 0x12, 0x34, 0x56, 0x78]);
        assert_eq!(n.len(), 6, "looped link");
        let (n, _) = classify(&mut l, &[5, 6, 1, 2, 3, 4]);
        assert!(n.is_empty());
    }

    #[test]
    fn rfc1990_multilink_options_are_parsed_and_rejected() {
        let mut l = server_lcp();
        let opts = [17, 4, 0x05, 0xd4, 18, 2, 19, 3, 0];
        let (_, r) = classify(&mut l, &opts);
        assert_eq!(r, opts);
    }

    #[test]
    fn server_never_authenticates_to_the_subscriber() {
        let mut l = server_lcp();
        let (_, r) = classify(&mut l, &[3, 4, 0xc0, 0x23]);
        assert_eq!(r, [3, 4, 0xc0, 0x23]);
    }

    #[test]
    fn server_auth_order_and_nak_fallback() {
        let mut l = server_lcp();
        let mut out = Vec::new();
        l.request(&mut out);
        assert_eq!(&out[4..9], &[3, 5, 0xc2, 0x23, 0x81], "mschap2 first");
        // Peer suggests PAP: allowed, so we take it.
        l.naked(&[3, 4, 0xc0, 0x23]);
        assert_eq!(l.auth, Some(AuthProto::Pap));
        // Peer suggests EAP: unknown; nothing after PAP → refused.
        l.naked(&[3, 4, 0xc2, 0x27]);
        assert!(l.auth_refused);
    }

    #[test]
    fn rejecting_auth_is_fatal_for_the_server() {
        let mut l = server_lcp();
        assert!(!l.rejected(&[3, 5, 0xc2, 0x23, 0x81]));
        assert!(l.rejected(&[5, 6, 0x12, 0x34, 0x56, 0x78]));
        assert_eq!(l.echo_magic(), 0, "§5.8: zero once magic is rejected");
    }

    #[test]
    fn client_naks_an_auth_it_does_not_allow() {
        let mut l = Lcp::new(Role::Client, 1492, 1492, AuthSet::new(&[AuthProto::Pap]), 9);
        let (n, r) = classify(&mut l, &[3, 5, 0xc2, 0x23, 0x81]);
        assert!(r.is_empty());
        assert_eq!(n, [3, 4, 0xc0, 0x23]);
        l.peer_acked(&[3, 4, 0xc0, 0x23]);
        assert_eq!(l.peer_auth, Some(AuthProto::Pap));
    }

    #[test]
    fn rfc1332_3_3_server_naks_with_the_assigned_address() {
        let mut l = Ipcp::server(Some(Ipv4Addr::new(10, 0, 0, 1)));
        l.peer = Some(Ipv4Addr::new(100, 64, 1, 2));
        l.dns = [Some(Ipv4Addr::new(1, 1, 1, 1)), None];
        let (n, r) = classify(&mut l, &[3, 6, 0, 0, 0, 0, 129, 6, 0, 0, 0, 0, 131, 6, 0, 0, 0, 0]);
        assert_eq!(n, [3, 6, 100, 64, 1, 2, 129, 6, 1, 1, 1, 1]);
        assert_eq!(r, [131, 6, 0, 0, 0, 0], "RFC 1877: no secondary DNS → reject");
        let (n, r) = classify(&mut l, &[3, 6, 100, 64, 1, 2, 129, 6, 1, 1, 1, 1]);
        assert!(n.is_empty() && r.is_empty());
    }

    #[test]
    fn rfc1332_vj_compression_and_ip_addresses_are_rejected() {
        let mut l = Ipcp::server(None);
        let opts = [2, 6, 0, 0x2d, 15, 1, 1, 10, 1, 2, 3, 4, 5, 6, 7, 8];
        let (_, r) = classify(&mut l, &opts);
        assert_eq!(r, opts);
    }

    #[test]
    fn ipcp_client_takes_naked_values() {
        let mut c = Ipcp::client(true);
        let mut out = Vec::new();
        c.request(&mut out);
        assert_eq!(out, [3, 6, 0, 0, 0, 0, 129, 6, 0, 0, 0, 0, 131, 6, 0, 0, 0, 0]);
        c.naked(&[3, 6, 100, 64, 0, 9, 129, 6, 8, 8, 8, 8]);
        assert!(c.rejected(&[131, 6, 0, 0, 0, 0]));
        out.clear();
        c.request(&mut out);
        assert_eq!(out, [3, 6, 100, 64, 0, 9, 129, 6, 8, 8, 8, 8]);
        assert!(!c.rejected(&[3, 6, 100, 64, 0, 9]));
    }

    #[test]
    fn rfc5072_4_1_zero_or_equal_iid_is_naked() {
        let mut l = Ipv6cp::new([1, 2, 3, 4, 5, 6, 7, 8], 77);
        let (n, _) = classify(&mut l, &[1, 10, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(n.len(), 10);
        assert_ne!(&n[2..], &[0u8; 8]);
        let (n, _) = classify(&mut l, &[1, 10, 1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(n.len(), 10);
        let (n, r) = classify(&mut l, &[1, 10, 9, 9, 9, 9, 9, 9, 9, 9, 2, 4, 0, 0]);
        assert!(n.is_empty());
        assert_eq!(r, [2, 4, 0, 0], "§4.2 compression rejected");
    }

    #[test]
    fn auth_set_order() {
        let s = AuthSet::routeros_default();
        assert_eq!(s.first(), Some(AuthProto::MsChapV2));
        assert_eq!(s.after(AuthProto::ChapMd5), Some(AuthProto::Pap));
        assert_eq!(s.after(AuthProto::Pap), None);
        assert!(AuthSet::new(&[]).is_empty());
    }
}
