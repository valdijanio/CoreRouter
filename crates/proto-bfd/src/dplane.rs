//! FRR's distributed BFD data plane protocol (`bfddp`, `bfdd/bfddp_packet.h`
//! of FRR 10.7.1, MIT): `bfdd --dplaneaddr` hands every session to an
//! external data plane — CoreRouter's engine — and keeps telling `bgpd`,
//! `ospfd` and `staticd` what the data plane reports. Messages are a header
//! of 8 bytes and a payload, all integers in network order; the layouts are
//! the C structs of the header (with their padding).
//!
//! What the data plane gets: `DP_ADD_SESSION` (also an update),
//! `DP_DELETE_SESSION`, `DP_REQUEST_SESSION_COUNTERS`, `ECHO_REQUEST`.
//! What it sends: `BFD_STATE_CHANGE`, `BFD_SESSION_COUNTERS`, `ECHO_REPLY`.
//! The protocol has no authentication (a TODO in FRR 10.7.1): CoreRouter
//! applies its own profile's (`routing.bfd.profile`) to the session.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// `BFD_DP_VERSION`.
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 8;
/// `struct bfddp_session`: flags, src, dst, lid, five timers, ttl,
/// detect_mult, zero, ifindex, ifname[64].
pub const SESSION_LEN: usize = 4 + 16 + 16 + 4 * 6 + 1 + 1 + 2 + 4 + 64;
/// `struct bfddp_state_change`: six u32 and three u8, padded to 4.
pub const STATE_LEN: usize = 28;
/// `struct bfddp_session_counters`: u32 lid, 4 bytes of padding, eight u64.
pub const COUNTERS_LEN: usize = 8 + 8 * 8;
pub const ECHO_LEN: usize = 16;
/// Longest message accepted (a session message).
pub const MAX_MESSAGE: usize = HEADER_LEN + SESSION_LEN;

pub const ECHO_REQUEST: u16 = 0;
pub const ECHO_REPLY: u16 = 1;
pub const DP_ADD_SESSION: u16 = 2;
pub const DP_DELETE_SESSION: u16 = 3;
pub const BFD_STATE_CHANGE: u16 = 4;
pub const DP_REQUEST_SESSION_COUNTERS: u16 = 5;
pub const BFD_SESSION_COUNTERS: u16 = 6;

pub const SESSION_MULTIHOP: u32 = 1 << 0;
pub const SESSION_DEMAND: u32 = 1 << 1;
pub const SESSION_CBIT: u32 = 1 << 2;
pub const SESSION_ECHO: u32 = 1 << 3;
pub const SESSION_IPV6: u32 = 1 << 4;
pub const SESSION_PASSIVE: u32 = 1 << 5;
pub const SESSION_SHUTDOWN: u32 = 1 << 6;

pub const RBIT_CPI: u32 = 1 << 0;
pub const RBIT_DEMAND: u32 = 1 << 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub kind: u16,
    /// Pairs a request with its answer; 0 for unrequested messages.
    pub id: u16,
    /// The whole message, header included.
    pub length: u16,
}

/// A session as `bfdd` describes it (intervals in µs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpSession {
    pub flags: u32,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub lid: u32,
    pub min_tx: u32,
    pub min_rx: u32,
    pub min_echo_tx: u32,
    pub min_echo_rx: u32,
    /// Milliseconds to wait before starting.
    pub hold_time: u32,
    /// Multihop: the minimum TTL; single hop: 255.
    pub ttl: u8,
    pub detect_mult: u8,
    pub ifindex: u32,
    pub ifname: String,
}

impl DpSession {
    pub fn multihop(&self) -> bool {
        self.flags & SESSION_MULTIHOP != 0
    }
    pub fn passive(&self) -> bool {
        self.flags & SESSION_PASSIVE != 0
    }
    pub fn shutdown(&self) -> bool {
        self.flags & SESSION_SHUTDOWN != 0
    }
}

/// A message from `bfdd`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FromBfdd {
    Echo {
        id: u16,
        bfdd_time: u64,
    },
    AddSession(DpSession),
    DeleteSession(DpSession),
    RequestCounters {
        id: u16,
        lid: u32,
    },
    /// A type a data plane does not take (counted, skipped).
    Other(u16),
}

/// What a state change tells `bfdd` (the local state and what the peer said).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StateChange {
    pub lid: u32,
    pub rid: u32,
    pub remote_flags: u32,
    pub desired_tx: u32,
    pub required_rx: u32,
    pub required_echo_rx: u32,
    /// The session's state as the clients must see it (0–3, RFC 5880 Sta).
    pub state: u8,
    pub diagnostics: u8,
    pub detect_mult: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counters {
    pub lid: u32,
    pub control_input_bytes: u64,
    pub control_input_packets: u64,
    pub control_output_bytes: u64,
    pub control_output_packets: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DpError {
    #[error("version {0}, not 1")]
    Version(u8),
    #[error("length {0} below the header or above {MAX_MESSAGE}")]
    Length(u16),
    #[error("payload too short for its type")]
    Short,
}

fn be16(b: &[u8], at: usize) -> u16 {
    let mut w = [0u8; 2];
    if let Some(s) = b.get(at..at + 2) {
        w.copy_from_slice(s);
    }
    u16::from_be_bytes(w)
}

fn be32(b: &[u8], at: usize) -> u32 {
    let mut w = [0u8; 4];
    if let Some(s) = b.get(at..at + 4) {
        w.copy_from_slice(s);
    }
    u32::from_be_bytes(w)
}

fn be64(b: &[u8], at: usize) -> u64 {
    let mut w = [0u8; 8];
    if let Some(s) = b.get(at..at + 8) {
        w.copy_from_slice(s);
    }
    u64::from_be_bytes(w)
}

/// The header of the next message in `buf`; `Ok(None)` until 8 bytes are there.
pub fn header(buf: &[u8]) -> Result<Option<Header>, DpError> {
    if buf.len() < HEADER_LEN {
        return Ok(None);
    }
    let version = buf.first().copied().unwrap_or(0);
    if version != VERSION {
        return Err(DpError::Version(version));
    }
    let length = be16(buf, 6);
    if usize::from(length) < HEADER_LEN || usize::from(length) > MAX_MESSAGE {
        return Err(DpError::Length(length));
    }
    Ok(Some(Header {
        kind: be16(buf, 2),
        id: be16(buf, 4),
        length,
    }))
}

/// `in6_addr` holding IPv4 in its first 4 bytes (as `bfdd` copies it).
fn addr(b: &[u8], at: usize, v6: bool) -> IpAddr {
    let mut a = [0u8; 16];
    if let Some(s) = b.get(at..at + 16) {
        a.copy_from_slice(s);
    }
    if v6 {
        IpAddr::V6(Ipv6Addr::from(a))
    } else {
        IpAddr::V4(Ipv4Addr::new(a[0], a[1], a[2], a[3]))
    }
}

fn put_addr(out: &mut [u8], at: usize, a: IpAddr) {
    let bytes: [u8; 16] = match a {
        IpAddr::V4(v) => {
            let mut x = [0u8; 16];
            x[..4].copy_from_slice(&v.octets());
            x
        }
        IpAddr::V6(v) => v.octets(),
    };
    if let Some(s) = out.get_mut(at..at + 16) {
        s.copy_from_slice(&bytes);
    }
}

fn session(p: &[u8]) -> Result<DpSession, DpError> {
    if p.len() < SESSION_LEN {
        return Err(DpError::Short);
    }
    let flags = be32(p, 0);
    let v6 = flags & SESSION_IPV6 != 0;
    let name = p.get(68..132).unwrap_or(&[]);
    let end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
    Ok(DpSession {
        flags,
        src: addr(p, 4, v6),
        dst: addr(p, 20, v6),
        lid: be32(p, 36),
        min_tx: be32(p, 40),
        min_rx: be32(p, 44),
        min_echo_tx: be32(p, 48),
        min_echo_rx: be32(p, 52),
        hold_time: be32(p, 56),
        ttl: p.get(60).copied().unwrap_or(255),
        detect_mult: p.get(61).copied().unwrap_or(3),
        ifindex: be32(p, 64),
        ifname: String::from_utf8_lossy(name.get(..end).unwrap_or(&[])).into_owned(),
    })
}

/// One whole message (`msg` is `header.length` bytes).
pub fn decode(h: &Header, msg: &[u8]) -> Result<FromBfdd, DpError> {
    let p = msg
        .get(HEADER_LEN..usize::from(h.length))
        .ok_or(DpError::Short)?;
    Ok(match h.kind {
        ECHO_REQUEST => {
            if p.len() < ECHO_LEN {
                return Err(DpError::Short);
            }
            FromBfdd::Echo {
                id: h.id,
                bfdd_time: be64(p, 8),
            }
        }
        DP_ADD_SESSION => FromBfdd::AddSession(session(p)?),
        DP_DELETE_SESSION => FromBfdd::DeleteSession(session(p)?),
        DP_REQUEST_SESSION_COUNTERS => {
            if p.len() < 4 {
                return Err(DpError::Short);
            }
            FromBfdd::RequestCounters {
                id: h.id,
                lid: be32(p, 0),
            }
        }
        other => FromBfdd::Other(other),
    })
}

fn put_header(out: &mut Vec<u8>, kind: u16, id: u16, payload: usize) {
    let len = (HEADER_LEN + payload) as u16;
    out.extend_from_slice(&[VERSION, 0]);
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
}

pub fn encode_state(s: &StateChange, out: &mut Vec<u8>) {
    put_header(out, BFD_STATE_CHANGE, 0, STATE_LEN);
    for v in [
        s.lid,
        s.rid,
        s.remote_flags,
        s.desired_tx,
        s.required_rx,
        s.required_echo_rx,
    ] {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out.extend_from_slice(&[s.state, s.diagnostics, s.detect_mult, 0]);
}

pub fn encode_counters(id: u16, c: &Counters, out: &mut Vec<u8>) {
    put_header(out, BFD_SESSION_COUNTERS, id, COUNTERS_LEN);
    out.extend_from_slice(&c.lid.to_be_bytes());
    out.extend_from_slice(&[0; 4]);
    for v in [
        c.control_input_bytes,
        c.control_input_packets,
        c.control_output_bytes,
        c.control_output_packets,
        0,
        0,
        0,
        0,
    ] {
        out.extend_from_slice(&v.to_be_bytes());
    }
}

/// `ECHO_REPLY`: `bfdd_time` back, with ours.
pub fn encode_echo_reply(id: u16, dp_time: u64, bfdd_time: u64, out: &mut Vec<u8>) {
    put_header(out, ECHO_REPLY, id, ECHO_LEN);
    out.extend_from_slice(&dp_time.to_be_bytes());
    out.extend_from_slice(&bfdd_time.to_be_bytes());
}

/// `DP_ADD_SESSION` / `DP_DELETE_SESSION` as `bfdd` writes them (tests and
/// the fake `bfdd` of the daemon's tests).
pub fn encode_session(kind: u16, s: &DpSession, out: &mut Vec<u8>) {
    put_header(out, kind, 0, SESSION_LEN);
    let mut p = [0u8; SESSION_LEN];
    p[0..4].copy_from_slice(&s.flags.to_be_bytes());
    put_addr(&mut p, 4, s.src);
    put_addr(&mut p, 20, s.dst);
    for (i, v) in [
        s.lid,
        s.min_tx,
        s.min_rx,
        s.min_echo_tx,
        s.min_echo_rx,
        s.hold_time,
    ]
    .iter()
    .enumerate()
    {
        let at = 36 + 4 * i;
        if let Some(d) = p.get_mut(at..at + 4) {
            d.copy_from_slice(&v.to_be_bytes());
        }
    }
    p[60] = s.ttl;
    p[61] = s.detect_mult;
    p[64..68].copy_from_slice(&s.ifindex.to_be_bytes());
    let name = s.ifname.as_bytes();
    let n = name.len().min(63);
    if let (Some(d), Some(src)) = (p.get_mut(68..68 + n), name.get(..n)) {
        d.copy_from_slice(src);
    }
    out.extend_from_slice(&p);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> DpSession {
        DpSession {
            flags: SESSION_PASSIVE,
            src: "10.0.0.1".parse().unwrap(),
            dst: "10.0.0.2".parse().unwrap(),
            lid: 0xdead_beef,
            min_tx: 300_000,
            min_rx: 300_000,
            min_echo_tx: 50_000,
            min_echo_rx: 50_000,
            hold_time: 0,
            ttl: 255,
            detect_mult: 3,
            ifindex: 7,
            ifname: "ether1".into(),
        }
    }

    #[test]
    fn layouts_match_the_c_structs() {
        // 8 + sizeof(struct bfddp_session) = 140; state 8 + 28; counters 8 + 72.
        assert_eq!(MAX_MESSAGE, 140);
        let mut v = Vec::new();
        encode_session(DP_ADD_SESSION, &sample(), &mut v);
        assert_eq!(v.len(), 140);
        assert_eq!(&v[..8], &[1, 0, 0, 2, 0, 0, 0, 140]);
        // IPv4 in the first bytes of the in6_addr.
        assert_eq!(&v[12..16], &[10, 0, 0, 1]);
        assert_eq!(&v[44..48], &0xdead_beefu32.to_be_bytes());
        let mut s = Vec::new();
        encode_state(
            &StateChange {
                lid: 1,
                rid: 2,
                remote_flags: 0,
                desired_tx: 3,
                required_rx: 4,
                required_echo_rx: 0,
                state: 3,
                diagnostics: 0,
                detect_mult: 3,
            },
            &mut s,
        );
        assert_eq!(s.len(), 36);
        assert_eq!(s[32], 3);
        let mut c = Vec::new();
        encode_counters(9, &Counters::default(), &mut c);
        assert_eq!(c.len(), 80);
    }

    #[test]
    fn session_round_trip() {
        let mut v = Vec::new();
        encode_session(DP_ADD_SESSION, &sample(), &mut v);
        let h = header(&v).unwrap().unwrap();
        assert_eq!(h.kind, DP_ADD_SESSION);
        assert_eq!(decode(&h, &v).unwrap(), FromBfdd::AddSession(sample()));
        let mut six = sample();
        six.flags |= SESSION_IPV6 | SESSION_MULTIHOP;
        six.src = "2001:db8::1".parse().unwrap();
        six.dst = "2001:db8::2".parse().unwrap();
        let mut v = Vec::new();
        encode_session(DP_DELETE_SESSION, &six, &mut v);
        let h = header(&v).unwrap().unwrap();
        let FromBfdd::DeleteSession(back) = decode(&h, &v).unwrap() else {
            panic!()
        };
        assert!(back.multihop());
        assert_eq!(back, six);
    }

    #[test]
    fn hostile_headers() {
        assert_eq!(header(&[1, 0, 0]), Ok(None));
        assert_eq!(
            header(&[2, 0, 0, 2, 0, 0, 0, 140]),
            Err(DpError::Version(2))
        );
        assert_eq!(header(&[1, 0, 0, 2, 0, 0, 0, 4]), Err(DpError::Length(4)));
        assert_eq!(
            header(&[1, 0, 0, 2, 0, 0, 0xff, 0xff]),
            Err(DpError::Length(0xffff))
        );
        // A session type with a short payload.
        let h = header(&[1, 0, 0, 2, 0, 0, 0, 12]).unwrap().unwrap();
        assert_eq!(
            decode(&h, &[1, 0, 0, 2, 0, 0, 0, 12, 0, 0, 0, 0]),
            Err(DpError::Short)
        );
        let h = header(&[1, 0, 0, 9, 0, 0, 0, 8]).unwrap().unwrap();
        assert_eq!(
            decode(&h, &[1, 0, 0, 9, 0, 0, 0, 8]),
            Ok(FromBfdd::Other(9))
        );
    }

    proptest::proptest! {
        #[test]
        fn decode_never_panics(b in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..200)) {
            if let Ok(Some(h)) = header(&b) {
                let _ = decode(&h, &b);
            }
        }
    }
}
