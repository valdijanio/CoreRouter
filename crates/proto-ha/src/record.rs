//! What a standby must know to take a subscriber session over without the
//! subscriber noticing: the PPPoE session (RFC 2516 §4: SESSION_ID and the
//! MAC pair), the LCP state that the peer checks (RFC 1661 §6.4: both Magic
//! Numbers, the MRU), the NCP results (IPCP address and DNS, IPv6CP
//! interface identifiers, the /64 and the delegated prefix), the
//! authorization (rate limit, timeouts, profile) and the accounting state
//! (RFC 2866 Acct-Session-Id, the RADIUS Class to echo, RFC 2865 §5.25,
//! the start time and the counters).
//!
//! Encoded as TLVs (type u8, length u16, value) so a node of a newer
//! version can sync with an older one: unknown types are kept as they came
//! ([`SessionRecord::extra`]) and written back, a duplicate type is an error.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::msg::{Counters, Key, MAX_VALUE};
use crate::wire::{Error, Reader, Result, put_bytes16, put_u16, put_u32, put_u64};

/// RFC 2865 §5.25: a Class attribute is at most 253 bytes; a server sends
/// few (**estimado**: 4 is generous).
pub const MAX_CLASS: usize = 4;
/// Text and opaque fields (usernames, circuit ids, names).
pub const MAX_FIELD: usize = 253;
/// A DHCP option's value ([`Lease4`]: RFC 2132 §2, a length octet).
pub const MAX_OPTION: usize = 255;
/// IPv6 DNS servers (a profile lists at most 4).
pub const MAX_DNS6: usize = 4;
/// Routed blocks per session.
pub const MAX_ROUTES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Kind {
    #[default]
    Pppoe,
    /// An IPoE (DHCP) subscriber (G4.3f): no SID, no LCP.
    Ipoe,
}

/// An IPv6 prefix and its length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prefix6 {
    pub addr: Ipv6Addr,
    pub len: u8,
}

/// The DHCPv4 binding of an IPoE session (G4.3hd), as the DHCP server
/// keeps it: the node that takes over knows the client (its key is the
/// client id, else `hw` or the MAC, RFC 2131 §4.2) and answers its renewal
/// with the same lease.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Lease4 {
    /// Unix seconds the lease ends; its length; the client's last message.
    pub expires: u64,
    pub lease_time: u32,
    pub last_seen: u64,
    /// Option 61 as sent.
    pub client_id: Option<Box<[u8]>>,
    /// Option 82 as received.
    pub relay_info: Option<Box<[u8]>>,
    /// `htype` + `chaddr` of a client that is not Ethernet.
    pub hw: Option<Box<[u8]>>,
    pub host_name: Box<[u8]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionRecord {
    pub kind: Kind,
    pub ifindex: u32,
    /// Outer and inner tags as the data plane encodes them (0 or
    /// `TAGGED | VID`), and the outer TPID (0 = 0x88a8).
    pub vlan: u16,
    pub inner_vlan: u16,
    pub outer_tpid: u16,
    pub sid: u16,
    pub client_mac: [u8; 6],
    /// The AC's MAC the subscriber talks to: the pair's virtual MAC, so
    /// the standby answers on it after a takeover.
    pub server_mac: [u8; 6],
    /// RFC 1661 §6.4: our Magic-Number and the peer's (the peer drops an
    /// Echo-Reply carrying another one, and loop detection uses ours).
    pub our_magic: u32,
    pub peer_magic: u32,
    /// The subscriber's MRU (our MTU toward it) and the MRU we announced.
    pub mru: u16,
    pub our_mru: u16,
    /// The authentication protocol used (the PPP protocol number:
    /// 0xc023 PAP, 0xc223 CHAP; with `auth_algo` 5 = MD5, 0x80 MS-CHAPv1,
    /// 0x81 MS-CHAPv2).
    pub auth_proto: u16,
    pub auth_algo: u8,
    pub username: Box<[u8]>,
    pub service_name: Box<[u8]>,
    pub ipv4: Option<Ipv4Addr>,
    pub local_ipv4: Option<Ipv4Addr>,
    pub dns: [Option<Ipv4Addr>; 2],
    /// RFC 5072: the subscriber's and our IPv6CP interface identifiers.
    pub ipv6_iid: Option<[u8; 8]>,
    pub local_iid: Option<[u8; 8]>,
    pub ipv6_prefix: Option<Prefix6>,
    pub delegated: Option<Prefix6>,
    /// The rate limit in force, RouterOS text (`10M/50M`).
    pub rate_limit: Option<Box<str>>,
    pub session_timeout: Option<u32>,
    pub idle_timeout: Option<u32>,
    pub circuit_id: Option<Box<[u8]>>,
    pub remote_id: Option<Box<[u8]>>,
    /// RFC 2866 §5.5: kept across the takeover, so Start and Stop pair up
    /// in the RADIUS server and no duplicate Stop is sent.
    pub acct_session_id: Box<str>,
    /// RFC 2865 §5.25: echoed in every Accounting-Request.
    pub class: Vec<Box<[u8]>>,
    pub radius: bool,
    pub acct_interim: Option<u32>,
    pub profile: Box<str>,
    pub server: Box<str>,
    /// The pool the address came from (returned to it at the end).
    pub pool: Option<Box<str>>,
    pub address_list: Option<Box<str>>,
    /// The `/ipv6 pool`s the /64 and the delegated prefix came from (back
    /// to them at the end); `None`: fixed or from RADIUS.
    pub pool6: Option<Box<str>>,
    pub pd_pool: Option<Box<str>>,
    /// IPv6 DNS given (RA RDNSS, DHCPv6), at most [`MAX_DNS6`].
    pub dns6: Vec<Ipv6Addr>,
    pub nbns: [Option<Ipv4Addr>; 2],
    /// Routed blocks (G4.3cd), as text (`10.0.0.0/24 [gw] [metric]` and
    /// where it came from), at most [`MAX_ROUTES`].
    pub routes: Vec<Box<str>>,
    /// `limit-bytes-in/out` of the secret (0: none).
    pub limit_in: u64,
    pub limit_out: u64,
    /// The profile the session's Service-Name row gave (G4.3k), in the
    /// server's `default_profile` place.
    pub fallback_profile: Box<str>,
    /// Unix seconds.
    pub started_at: u64,
    /// The counters when the record was written; [`crate::msg::Op::Counters`]
    /// updates them between records.
    pub counters: Counters,
    /// IPoE: the DHCP binding (G4.3hd).
    pub lease: Option<Lease4>,
    /// TLVs of a newer version, kept and written back unchanged.
    pub extra: Vec<(u8, Box<[u8]>)>,
}

mod t {
    pub const CORE: u8 = 1;
    pub const LCP: u8 = 2;
    pub const AUTH: u8 = 3;
    pub const USERNAME: u8 = 4;
    pub const SERVICE: u8 = 5;
    pub const IPV4: u8 = 6;
    pub const LOCAL_IPV4: u8 = 7;
    pub const DNS: u8 = 8;
    pub const IID: u8 = 9;
    pub const LOCAL_IID: u8 = 10;
    pub const PREFIX: u8 = 11;
    pub const DELEGATED: u8 = 12;
    pub const RATE: u8 = 13;
    pub const SESSION_TIMEOUT: u8 = 14;
    pub const IDLE_TIMEOUT: u8 = 15;
    pub const CIRCUIT: u8 = 16;
    pub const REMOTE: u8 = 17;
    pub const ACCT_ID: u8 = 18;
    pub const CLASS: u8 = 19;
    pub const ACCT: u8 = 20;
    pub const PROFILE: u8 = 21;
    pub const SERVER: u8 = 22;
    pub const POOL: u8 = 23;
    pub const ADDRESS_LIST: u8 = 24;
    pub const COUNTERS: u8 = 25;
    pub const POOL6: u8 = 26;
    pub const PD_POOL: u8 = 27;
    pub const DNS6: u8 = 28;
    pub const NBNS: u8 = 29;
    pub const ROUTE: u8 = 30;
    pub const LIMITS: u8 = 31;
    pub const FALLBACK: u8 = 32;
    /// G4.3hd: [`super::Lease4`] (an older reader keeps them as `extra`).
    pub const LEASE: u8 = 33;
    pub const LEASE_CLIENT_ID: u8 = 34;
    pub const LEASE_RELAY: u8 = 35;
    pub const LEASE_HW: u8 = 36;
    pub const LEASE_HOST: u8 = 37;
    /// Types up to this one are known (a newer one is kept).
    pub const LAST_KNOWN: u8 = 37;
    // The decoder's bitmask of seen types is a u64.
    const _: () = assert!(LAST_KNOWN < 64);
}

fn tlv(out: &mut Vec<u8>, ty: u8, v: &[u8]) -> Result<()> {
    out.push(ty);
    put_bytes16(out, "field", v, MAX_FIELD.max(64))
}

fn tlv_option(out: &mut Vec<u8>, ty: u8, v: &[u8]) -> Result<()> {
    out.push(ty);
    put_bytes16(out, "option", v, MAX_OPTION)
}

fn tlv_with(out: &mut Vec<u8>, ty: u8, f: impl FnOnce(&mut Vec<u8>)) {
    out.push(ty);
    let at = out.len();
    out.extend_from_slice(&[0, 0]);
    f(out);
    let len = u16::try_from(out.len() - at - 2).unwrap_or(u16::MAX);
    if let Some(d) = out.get_mut(at..at + 2) {
        d.copy_from_slice(&len.to_le_bytes());
    }
}

fn text(v: &[u8], what: &'static str) -> Result<Box<str>> {
    std::str::from_utf8(v)
        .map(Into::into)
        .map_err(|_| Error::BadValue(what))
}

fn prefix(v: &[u8]) -> Result<Prefix6> {
    let mut r = Reader::new(v);
    let addr = Ipv6Addr::from(r.array::<16>()?);
    let len = r.u8()?;
    r.end()?;
    if len > 128 {
        return Err(Error::BadValue("prefix length"));
    }
    Ok(Prefix6 { addr, len })
}

fn put_prefix(out: &mut Vec<u8>, ty: u8, p: &Prefix6) {
    tlv_with(out, ty, |o| {
        o.extend_from_slice(&p.addr.octets());
        o.push(p.len);
    });
}

fn ipv4(v: &[u8]) -> Result<Ipv4Addr> {
    let mut r = Reader::new(v);
    let a = Ipv4Addr::from(r.array::<4>()?);
    r.end()?;
    Ok(a)
}

fn iid(v: &[u8]) -> Result<[u8; 8]> {
    let mut r = Reader::new(v);
    let a = r.array()?;
    r.end()?;
    Ok(a)
}

fn u32_of(v: &[u8]) -> Result<u32> {
    let mut r = Reader::new(v);
    let x = r.u32()?;
    r.end()?;
    Ok(x)
}

impl SessionRecord {
    /// The replication key: kind, server, tags, SESSION_ID and client MAC
    /// (RFC 2516 §4 identifies the session by the SID and the MAC pair;
    /// the server and tags make it unique across access networks). The
    /// server by name, not the port index: the index differs between the
    /// two machines, and the new active must remove what the old one put.
    pub fn key(&self) -> Key {
        let kind = [match self.kind {
            Kind::Pppoe => 1,
            Kind::Ipoe => 2,
        }];
        let parts: [&[u8]; 6] = [
            &kind,
            &fnv32(self.server.as_bytes()).to_le_bytes(),
            &self.vlan.to_le_bytes(),
            &self.inner_vlan.to_le_bytes(),
            &self.sid.to_le_bytes(),
            &self.client_mac,
        ];
        let mut b = [0u8; 17];
        for (d, s) in b.iter_mut().zip(parts.iter().flat_map(|p| p.iter())) {
            *d = *s;
        }
        Key::truncated(&b)
    }

    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        let r = self.encode_inner(out);
        let len = out.len() - start;
        if r.is_err() || len > MAX_VALUE {
            out.truncate(start);
            return r.and(Err(Error::TooLong {
                what: "record",
                len,
                max: MAX_VALUE,
            }));
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut v = Vec::with_capacity(256);
        self.encode(&mut v)?;
        Ok(v)
    }

    fn encode_inner(&self, out: &mut Vec<u8>) -> Result<()> {
        tlv_with(out, t::CORE, |o| {
            o.push(match self.kind {
                Kind::Pppoe => 1,
                Kind::Ipoe => 2,
            });
            put_u32(o, self.ifindex);
            put_u16(o, self.vlan);
            put_u16(o, self.inner_vlan);
            put_u16(o, self.outer_tpid);
            put_u16(o, self.sid);
            o.extend_from_slice(&self.client_mac);
            o.extend_from_slice(&self.server_mac);
            put_u64(o, self.started_at);
        });
        if self.kind == Kind::Pppoe {
            tlv_with(out, t::LCP, |o| {
                put_u32(o, self.our_magic);
                put_u32(o, self.peer_magic);
                put_u16(o, self.mru);
                put_u16(o, self.our_mru);
            });
        }
        if self.auth_proto != 0 {
            tlv_with(out, t::AUTH, |o| {
                put_u16(o, self.auth_proto);
                o.push(self.auth_algo);
                o.push(u8::from(self.radius));
            });
        }
        if !self.username.is_empty() {
            tlv(out, t::USERNAME, &self.username)?;
        }
        if !self.service_name.is_empty() {
            tlv(out, t::SERVICE, &self.service_name)?;
        }
        if let Some(a) = self.ipv4 {
            tlv(out, t::IPV4, &a.octets())?;
        }
        if let Some(a) = self.local_ipv4 {
            tlv(out, t::LOCAL_IPV4, &a.octets())?;
        }
        if self.dns.iter().any(Option::is_some) {
            tlv_with(out, t::DNS, |o| {
                for d in self.dns {
                    o.extend_from_slice(&d.unwrap_or(Ipv4Addr::UNSPECIFIED).octets());
                }
            });
        }
        if let Some(i) = self.ipv6_iid {
            tlv(out, t::IID, &i)?;
        }
        if let Some(i) = self.local_iid {
            tlv(out, t::LOCAL_IID, &i)?;
        }
        if let Some(p) = &self.ipv6_prefix {
            put_prefix(out, t::PREFIX, p);
        }
        if let Some(p) = &self.delegated {
            put_prefix(out, t::DELEGATED, p);
        }
        if let Some(r) = &self.rate_limit {
            tlv(out, t::RATE, r.as_bytes())?;
        }
        if let Some(s) = self.session_timeout {
            tlv(out, t::SESSION_TIMEOUT, &s.to_le_bytes())?;
        }
        if let Some(s) = self.idle_timeout {
            tlv(out, t::IDLE_TIMEOUT, &s.to_le_bytes())?;
        }
        if let Some(c) = &self.circuit_id {
            tlv(out, t::CIRCUIT, c)?;
        }
        if let Some(c) = &self.remote_id {
            tlv(out, t::REMOTE, c)?;
        }
        if !self.acct_session_id.is_empty() {
            tlv(out, t::ACCT_ID, self.acct_session_id.as_bytes())?;
        }
        if self.class.len() > MAX_CLASS {
            return Err(Error::TooLong {
                what: "class",
                len: self.class.len(),
                max: MAX_CLASS,
            });
        }
        for c in &self.class {
            tlv(out, t::CLASS, c)?;
        }
        if let Some(i) = self.acct_interim {
            tlv(out, t::ACCT, &i.to_le_bytes())?;
        }
        if !self.profile.is_empty() {
            tlv(out, t::PROFILE, self.profile.as_bytes())?;
        }
        if !self.server.is_empty() {
            tlv(out, t::SERVER, self.server.as_bytes())?;
        }
        if let Some(p) = &self.pool {
            tlv(out, t::POOL, p.as_bytes())?;
        }
        if let Some(p) = &self.address_list {
            tlv(out, t::ADDRESS_LIST, p.as_bytes())?;
        }
        if let Some(p) = &self.pool6 {
            tlv(out, t::POOL6, p.as_bytes())?;
        }
        if let Some(p) = &self.pd_pool {
            tlv(out, t::PD_POOL, p.as_bytes())?;
        }
        if !self.dns6.is_empty() {
            if self.dns6.len() > MAX_DNS6 {
                return Err(Error::TooLong {
                    what: "dns6",
                    len: self.dns6.len(),
                    max: MAX_DNS6,
                });
            }
            tlv_with(out, t::DNS6, |o| {
                for d in &self.dns6 {
                    o.extend_from_slice(&d.octets());
                }
            });
        }
        if self.nbns.iter().any(Option::is_some) {
            tlv_with(out, t::NBNS, |o| {
                for d in self.nbns {
                    o.extend_from_slice(&d.unwrap_or(Ipv4Addr::UNSPECIFIED).octets());
                }
            });
        }
        if self.routes.len() > MAX_ROUTES {
            return Err(Error::TooLong {
                what: "routes",
                len: self.routes.len(),
                max: MAX_ROUTES,
            });
        }
        for r in &self.routes {
            tlv(out, t::ROUTE, r.as_bytes())?;
        }
        if self.limit_in != 0 || self.limit_out != 0 {
            tlv_with(out, t::LIMITS, |o| {
                put_u64(o, self.limit_in);
                put_u64(o, self.limit_out);
            });
        }
        if !self.fallback_profile.is_empty() {
            tlv(out, t::FALLBACK, self.fallback_profile.as_bytes())?;
        }
        if self.counters != Counters::default() {
            tlv_with(out, t::COUNTERS, |o| {
                put_u64(o, self.counters.rx_bytes);
                put_u64(o, self.counters.tx_bytes);
                put_u64(o, self.counters.rx_packets);
                put_u64(o, self.counters.tx_packets);
            });
        }
        if let Some(l) = &self.lease {
            tlv_with(out, t::LEASE, |o| {
                put_u64(o, l.expires);
                put_u32(o, l.lease_time);
                put_u64(o, l.last_seen);
            });
            for (ty, v) in [
                (t::LEASE_CLIENT_ID, l.client_id.as_deref()),
                (t::LEASE_RELAY, l.relay_info.as_deref()),
                (t::LEASE_HW, l.hw.as_deref()),
            ] {
                if let Some(v) = v {
                    tlv_option(out, ty, v)?;
                }
            }
            if !l.host_name.is_empty() {
                tlv_option(out, t::LEASE_HOST, &l.host_name)?;
            }
        }
        for (ty, v) in &self.extra {
            if *ty <= t::LAST_KNOWN {
                return Err(Error::BadValue("extra type"));
            }
            tlv(out, *ty, v)?;
        }
        Ok(())
    }

    pub fn decode(buf: &[u8]) -> Result<SessionRecord> {
        if buf.len() > MAX_VALUE {
            return Err(Error::TooLong {
                what: "record",
                len: buf.len(),
                max: MAX_VALUE,
            });
        }
        let mut r = Reader::new(buf);
        let mut s = SessionRecord::default();
        // Bit per known type: a duplicate is refused (except Class).
        let mut seen: u64 = 0;
        while r.remaining() > 0 {
            let ty = r.u8()?;
            let v = r.bytes16("field", MAX_OPTION)?;
            if ty <= t::LAST_KNOWN && ty != t::CLASS && ty != t::ROUTE {
                let bit = 1u64 << ty;
                if seen & bit != 0 {
                    return Err(Error::Duplicate(ty));
                }
                seen |= bit;
            }
            match ty {
                t::CORE => {
                    let mut c = Reader::new(v);
                    s.kind = match c.u8()? {
                        1 => Kind::Pppoe,
                        2 => Kind::Ipoe,
                        _ => return Err(Error::BadValue("kind")),
                    };
                    s.ifindex = c.u32()?;
                    s.vlan = c.u16()?;
                    s.inner_vlan = c.u16()?;
                    s.outer_tpid = c.u16()?;
                    s.sid = c.u16()?;
                    s.client_mac = c.array()?;
                    s.server_mac = c.array()?;
                    s.started_at = c.u64()?;
                    c.end()?;
                }
                t::LCP => {
                    let mut c = Reader::new(v);
                    s.our_magic = c.u32()?;
                    s.peer_magic = c.u32()?;
                    s.mru = c.u16()?;
                    s.our_mru = c.u16()?;
                    c.end()?;
                }
                t::AUTH => {
                    let mut c = Reader::new(v);
                    s.auth_proto = c.u16()?;
                    s.auth_algo = c.u8()?;
                    s.radius = c.bool()?;
                    c.end()?;
                }
                t::USERNAME => s.username = v.into(),
                t::SERVICE => s.service_name = v.into(),
                t::IPV4 => s.ipv4 = Some(ipv4(v)?),
                t::LOCAL_IPV4 => s.local_ipv4 = Some(ipv4(v)?),
                t::DNS => {
                    let mut c = Reader::new(v);
                    for d in &mut s.dns {
                        let a = Ipv4Addr::from(c.array::<4>()?);
                        *d = (!a.is_unspecified()).then_some(a);
                    }
                    c.end()?;
                }
                t::IID => s.ipv6_iid = Some(iid(v)?),
                t::LOCAL_IID => s.local_iid = Some(iid(v)?),
                t::PREFIX => s.ipv6_prefix = Some(prefix(v)?),
                t::DELEGATED => s.delegated = Some(prefix(v)?),
                t::RATE => s.rate_limit = Some(text(v, "rate limit")?),
                t::SESSION_TIMEOUT => s.session_timeout = Some(u32_of(v)?),
                t::IDLE_TIMEOUT => s.idle_timeout = Some(u32_of(v)?),
                t::LEASE => {
                    let mut c = Reader::new(v);
                    let l = s.lease.get_or_insert_with(Lease4::default);
                    l.expires = c.u64()?;
                    l.lease_time = c.u32()?;
                    l.last_seen = c.u64()?;
                    c.end()?;
                }
                t::LEASE_CLIENT_ID => {
                    s.lease.get_or_insert_with(Lease4::default).client_id = Some(v.into());
                }
                t::LEASE_RELAY => {
                    s.lease.get_or_insert_with(Lease4::default).relay_info = Some(v.into());
                }
                t::LEASE_HW => s.lease.get_or_insert_with(Lease4::default).hw = Some(v.into()),
                t::LEASE_HOST => s.lease.get_or_insert_with(Lease4::default).host_name = v.into(),
                t::CIRCUIT => s.circuit_id = Some(v.into()),
                t::REMOTE => s.remote_id = Some(v.into()),
                t::ACCT_ID => s.acct_session_id = text(v, "acct session id")?,
                t::CLASS => {
                    if s.class.len() >= MAX_CLASS {
                        return Err(Error::TooLong {
                            what: "class",
                            len: s.class.len() + 1,
                            max: MAX_CLASS,
                        });
                    }
                    s.class.push(v.into());
                }
                t::ACCT => s.acct_interim = Some(u32_of(v)?),
                t::PROFILE => s.profile = text(v, "profile")?,
                t::SERVER => s.server = text(v, "server")?,
                t::POOL => s.pool = Some(text(v, "pool")?),
                t::ADDRESS_LIST => s.address_list = Some(text(v, "address list")?),
                t::POOL6 => s.pool6 = Some(text(v, "ipv6 pool")?),
                t::PD_POOL => s.pd_pool = Some(text(v, "pd pool")?),
                t::DNS6 => {
                    if v.len() % 16 != 0 || v.len() / 16 > MAX_DNS6 {
                        return Err(Error::BadValue("dns6"));
                    }
                    let mut c = Reader::new(v);
                    while c.remaining() > 0 {
                        s.dns6.push(Ipv6Addr::from(c.array::<16>()?));
                    }
                }
                t::NBNS => {
                    let mut c = Reader::new(v);
                    for d in &mut s.nbns {
                        let a = Ipv4Addr::from(c.array::<4>()?);
                        *d = (!a.is_unspecified()).then_some(a);
                    }
                    c.end()?;
                }
                t::ROUTE => {
                    if s.routes.len() >= MAX_ROUTES {
                        return Err(Error::TooLong {
                            what: "routes",
                            len: s.routes.len() + 1,
                            max: MAX_ROUTES,
                        });
                    }
                    s.routes.push(text(v, "route")?);
                }
                t::LIMITS => {
                    let mut c = Reader::new(v);
                    s.limit_in = c.u64()?;
                    s.limit_out = c.u64()?;
                    c.end()?;
                }
                t::FALLBACK => s.fallback_profile = text(v, "fallback profile")?,
                t::COUNTERS => {
                    let mut c = Reader::new(v);
                    s.counters = Counters {
                        rx_bytes: c.u64()?,
                        tx_bytes: c.u64()?,
                        rx_packets: c.u64()?,
                        tx_packets: c.u64()?,
                    };
                    c.end()?;
                }
                0 => return Err(Error::BadValue("field type")),
                ty if ty > t::LAST_KNOWN => {
                    if s.extra.len() >= 16 {
                        return Err(Error::TooLong {
                            what: "unknown fields",
                            len: 17,
                            max: 16,
                        });
                    }
                    s.extra.push((ty, v.into()));
                }
                _ => {}
            }
        }
        if seen & (1 << t::CORE) == 0 {
            return Err(Error::Missing("core"));
        }
        Ok(s)
    }
}

/// FNV-1a, 32 bits: a stable hash of a name for the key.
fn fnv32(b: &[u8]) -> u32 {
    b.iter().fold(0x811c_9dc5u32, |h, x| {
        (h ^ u32::from(*x)).wrapping_mul(0x0100_0193)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn sample() -> SessionRecord {
        SessionRecord {
            kind: Kind::Pppoe,
            ifindex: 4,
            vlan: 0x1064,
            inner_vlan: 0,
            outer_tpid: 0,
            sid: 0x1234,
            client_mac: [2, 0, 0, 0, 0, 9],
            server_mac: [2, 0, 0x5e, 0, 1, 1],
            our_magic: 0xdead_beef,
            peer_magic: 0x0bad_cafe,
            mru: 1492,
            our_mru: 1480,
            auth_proto: 0xc223,
            auth_algo: 0x81,
            username: (*b"joao").into(),
            service_name: Box::default(),
            ipv4: Some(Ipv4Addr::new(100, 64, 0, 9)),
            local_ipv4: Some(Ipv4Addr::new(100, 64, 0, 1)),
            dns: [Some(Ipv4Addr::new(1, 1, 1, 1)), None],
            ipv6_iid: Some([1, 2, 3, 4, 5, 6, 7, 8]),
            local_iid: None,
            ipv6_prefix: Some(Prefix6 {
                addr: "2001:db8:1::".parse().unwrap(),
                len: 64,
            }),
            delegated: None,
            rate_limit: Some("10M/50M".into()),
            session_timeout: Some(86_400),
            idle_timeout: None,
            circuit_id: Some((*b"olt1/1/3").into()),
            remote_id: None,
            acct_session_id: "81000a2f".into(),
            class: vec![(*b"plano-50").into()],
            radius: true,
            acct_interim: Some(300),
            profile: "plano".into(),
            server: "pppoe1".into(),
            pool: Some("clientes".into()),
            address_list: None,
            pool6: Some("v6".into()),
            pd_pool: Some("pd".into()),
            dns6: vec!["2001:db8::53".parse().unwrap()],
            nbns: [None, Some(Ipv4Addr::new(10, 0, 0, 9))],
            routes: vec![
                "10.10.0.0/24|secret".into(),
                "2001:db8:99::/48|framed-ipv6-route".into(),
            ],
            limit_in: 1_000_000,
            limit_out: 0,
            fallback_profile: "voip".into(),
            started_at: 1_790_000_000,
            counters: Counters {
                rx_bytes: 10,
                tx_bytes: 20,
                rx_packets: 1,
                tx_packets: 2,
            },
            lease: None,
            extra: vec![],
        }
    }

    /// G4.3hd: an IPoE session and its DHCP binding go through the record
    /// (a client id of 255 bytes, the most option 61 holds, included).
    #[test]
    fn an_ipoe_session_carries_its_dhcp_binding() {
        let r = SessionRecord {
            kind: Kind::Ipoe,
            client_mac: [2, 0x1a, 0xb0, 2, 0, 1],
            username: (*b"02:1A:B0:02:00:01").into(),
            ipv4: Some(Ipv4Addr::new(10, 64, 0, 20)),
            server: "ipoe1".into(),
            acct_session_id: "6720ABCD0001".into(),
            started_at: 1_700_000_000,
            lease: Some(Lease4 {
                expires: 1_700_000_600,
                lease_time: 600,
                last_seen: 1_700_000_300,
                client_id: Some(vec![0xff; MAX_OPTION].into()),
                relay_info: Some((*b"\x01\x04olt1").into()),
                hw: None,
                host_name: (*b"cpe-1").into(),
            }),
            ..SessionRecord::default()
        };
        let b = r.to_bytes().unwrap();
        assert_eq!(SessionRecord::decode(&b).unwrap(), r);
        let mut long = r.clone();
        if let Some(l) = &mut long.lease {
            l.client_id = Some(vec![0; MAX_OPTION + 1].into());
        }
        assert!(long.to_bytes().is_err());
        // Without a lease (PPPoE) nothing of it is written.
        let mut p = r.clone();
        p.lease = None;
        assert!(p.to_bytes().unwrap().len() < b.len() - MAX_OPTION);
    }

    #[test]
    fn a_full_record_round_trips_in_about_two_hundred_bytes() {
        let s = sample();
        let b = s.to_bytes().unwrap();
        assert_eq!(SessionRecord::decode(&b).unwrap(), s);
        assert!(b.len() < 380, "{} bytes", b.len());
    }

    #[test]
    fn unknown_fields_of_a_newer_version_are_kept() {
        let mut b = sample().to_bytes().unwrap();
        b.extend_from_slice(&[200, 2, 0, 7, 7]);
        let s = SessionRecord::decode(&b).unwrap();
        assert_eq!(s.extra, vec![(200, (*b"\x07\x07").into())]);
        assert_eq!(s.to_bytes().unwrap(), b, "written back as it came");
    }

    #[test]
    fn every_known_type_twice_is_an_error_not_a_panic() {
        let core = sample().to_bytes().unwrap();
        for ty in 1..=t::LAST_KNOWN {
            let mut b = core.clone();
            b.extend_from_slice(&[ty, 1, 0, 0, ty, 1, 0, 0]);
            let _ = SessionRecord::decode(&b);
        }
    }

    #[test]
    fn hostile_records_are_refused() {
        let b = sample().to_bytes().unwrap();
        let mut dup = b.clone();
        dup.extend_from_slice(&[t::IPV4, 4, 0, 1, 2, 3, 4]);
        assert_eq!(SessionRecord::decode(&dup), Err(Error::Duplicate(t::IPV4)));
        assert_eq!(
            SessionRecord::decode(&[t::IPV4, 4, 0, 1, 2, 3, 4]),
            Err(Error::Missing("core"))
        );
        let mut bad = b.clone();
        bad.extend_from_slice(&[t::DELEGATED, 17, 0]);
        bad.extend_from_slice(&[0; 16]);
        bad.push(129);
        assert_eq!(
            SessionRecord::decode(&bad),
            Err(Error::BadValue("prefix length"))
        );
        let mut short = b;
        short.extend_from_slice(&[t::IID, 3, 0, 1, 2, 3]);
        assert!(SessionRecord::decode(&short).is_err());
    }

    #[test]
    fn the_key_names_server_tags_sid_and_mac_not_the_port_index() {
        let a = sample();
        let mut b = sample();
        assert_eq!(a.key(), b.key());
        b.ifindex = 99;
        assert_eq!(a.key(), b.key(), "the other machine's port index");
        b.server = "pppoe2".into();
        assert_ne!(a.key(), b.key());
        let mut b = sample();
        b.sid += 1;
        assert_ne!(a.key(), b.key());
        let mut c = sample();
        c.inner_vlan = 0x1001;
        assert_ne!(a.key(), c.key());
        assert_eq!(a.key().as_bytes().len(), 17);
    }
}
