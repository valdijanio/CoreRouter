//! Conntrack over ctnetlink, without the `conntrack` program (G2.2).
//!
//! A dump (`IPCTNL_MSG_CT_GET` + `NLM_F_DUMP`) lists every connection, a
//! delete (`IPCTNL_MSG_CT_DELETE`) kills one by its tuple and id, and
//! `IPCTNL_MSG_CT_GET_STATS(_CPU)` gives the table's size and its trouble
//! counters. The codec is pure and bounded: a hostile or truncated message
//! yields fewer fields or no connection, never a panic (the attribute
//! walker stops at the first malformed attribute, `genl::attrs`).
//! Addresses and ports are in network order, counters big-endian.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use corerouter_hal::conntrack::{Conn, Stats, Tuple};

use crate::genl::{Attr, attrs, find};

pub const NFNL_SUBSYS_CTNETLINK: u16 = 1;
const IPCTNL_MSG_CT_GET: u16 = 1;
const IPCTNL_MSG_CT_DELETE: u16 = 2;
const IPCTNL_MSG_CT_GET_STATS_CPU: u16 = 4;
const IPCTNL_MSG_CT_GET_STATS: u16 = 5;

const CTA_TUPLE_ORIG: u16 = 1;
const CTA_TUPLE_REPLY: u16 = 2;
const CTA_STATUS: u16 = 3;
const CTA_PROTOINFO: u16 = 4;
const CTA_TIMEOUT: u16 = 7;
const CTA_MARK: u16 = 8;
const CTA_COUNTERS_ORIG: u16 = 9;
const CTA_COUNTERS_REPLY: u16 = 10;
const CTA_ID: u16 = 12;
const CTA_TUPLE_IP: u16 = 1;
const CTA_TUPLE_PROTO: u16 = 2;
const CTA_IP_V4_SRC: u16 = 1;
const CTA_IP_V4_DST: u16 = 2;
const CTA_IP_V6_SRC: u16 = 3;
const CTA_IP_V6_DST: u16 = 4;
const CTA_PROTO_NUM: u16 = 1;
const CTA_PROTO_SRC_PORT: u16 = 2;
const CTA_PROTO_DST_PORT: u16 = 3;
const CTA_PROTO_ICMP_ID: u16 = 4;
const CTA_PROTO_ICMP_TYPE: u16 = 5;
const CTA_PROTO_ICMP_CODE: u16 = 6;
const CTA_PROTO_ICMPV6_ID: u16 = 7;
const CTA_PROTO_ICMPV6_TYPE: u16 = 8;
const CTA_PROTO_ICMPV6_CODE: u16 = 9;
const CTA_PROTOINFO_TCP: u16 = 1;
const CTA_PROTOINFO_TCP_STATE: u16 = 1;
const CTA_COUNTERS_PACKETS: u16 = 1;
const CTA_COUNTERS_BYTES: u16 = 2;
const CTA_STATS_GLOBAL_ENTRIES: u16 = 1;
const CTA_STATS_GLOBAL_MAX_ENTRIES: u16 = 2;
const CTA_STATS_INSERT_FAILED: u16 = 9;
const CTA_STATS_DROP: u16 = 10;
const CTA_STATS_EARLY_DROP: u16 = 11;

const NLA_HDR: usize = 4;
const NLA_F_NESTED: u16 = 1 << 15;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_DUMP: u16 = 0x300;

fn be16(a: &Attr<'_>) -> Option<u16> {
    Some(u16::from_be_bytes(a.data.get(..2)?.try_into().ok()?))
}

fn be32(a: &Attr<'_>) -> Option<u32> {
    Some(u32::from_be_bytes(a.data.get(..4)?.try_into().ok()?))
}

fn be64(a: &Attr<'_>) -> Option<u64> {
    Some(u64::from_be_bytes(a.data.get(..8)?.try_into().ok()?))
}

fn addr(a: &Attr<'_>) -> Option<IpAddr> {
    match a.data.len() {
        4 => Some(IpAddr::V4(Ipv4Addr::from(
            <[u8; 4]>::try_from(a.data).ok()?,
        ))),
        16 => Some(IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(a.data).ok()?,
        ))),
        _ => None,
    }
}

/// A `CTA_TUPLE_*` nest: the tuple and the protocol number.
fn tuple(nest: &Attr<'_>) -> Option<(Tuple, u8)> {
    let ip = find(nest.nested(), CTA_TUPLE_IP)?;
    let mut src = None;
    let mut dst = None;
    for a in ip.nested() {
        match a.kind {
            CTA_IP_V4_SRC | CTA_IP_V6_SRC => src = addr(&a),
            CTA_IP_V4_DST | CTA_IP_V6_DST => dst = addr(&a),
            _ => {}
        }
    }
    let proto = find(nest.nested(), CTA_TUPLE_PROTO)?;
    let mut num = 0u8;
    let (mut sport, mut dport) = (0u16, 0u16);
    for a in proto.nested() {
        match a.kind {
            CTA_PROTO_NUM => num = a.u8().unwrap_or(0),
            CTA_PROTO_SRC_PORT => sport = be16(&a).unwrap_or(0),
            CTA_PROTO_DST_PORT => dport = be16(&a).unwrap_or(0),
            CTA_PROTO_ICMP_ID | CTA_PROTO_ICMPV6_ID => sport = be16(&a).unwrap_or(0),
            // Type and code ride in `dst_port` (type << 8 | code): a delete
            // must send them back, the kernel refuses an ICMP tuple without.
            CTA_PROTO_ICMP_TYPE | CTA_PROTO_ICMPV6_TYPE => {
                dport = (dport & 0x00ff) | (u16::from(a.u8().unwrap_or(0)) << 8);
            }
            CTA_PROTO_ICMP_CODE | CTA_PROTO_ICMPV6_CODE => {
                dport = (dport & 0xff00) | u16::from(a.u8().unwrap_or(0));
            }
            _ => {}
        }
    }
    Some((
        Tuple {
            src: src?,
            dst: dst?,
            src_port: sport,
            dst_port: dport,
        },
        num,
    ))
}

fn counters(nest: Option<Attr<'_>>) -> (u64, u64) {
    let Some(n) = nest else { return (0, 0) };
    let p = find(n.nested(), CTA_COUNTERS_PACKETS).and_then(|a| be64(&a));
    let b = find(n.nested(), CTA_COUNTERS_BYTES).and_then(|a| be64(&a));
    (p.unwrap_or(0), b.unwrap_or(0))
}

/// One conntrack message's attributes (after the nfgenmsg header) as a
/// connection; `None` without both tuples.
pub fn parse_conn(body: &[u8]) -> Option<Conn> {
    let all = attrs(body);
    let (orig, protocol) = tuple(&find(all.clone(), CTA_TUPLE_ORIG)?)?;
    let (reply, _) = tuple(&find(all.clone(), CTA_TUPLE_REPLY)?)?;
    let tcp_state = find(all.clone(), CTA_PROTOINFO)
        .and_then(|p| find(p.nested(), CTA_PROTOINFO_TCP))
        .and_then(|t| find(t.nested(), CTA_PROTOINFO_TCP_STATE))
        .and_then(|s| s.u8());
    let (orig_packets, orig_bytes) = counters(find(all.clone(), CTA_COUNTERS_ORIG));
    let (reply_packets, reply_bytes) = counters(find(all.clone(), CTA_COUNTERS_REPLY));
    let get32 = |kind| find(all.clone(), kind).and_then(|a| be32(&a));
    Some(Conn {
        id: get32(CTA_ID).unwrap_or(0),
        protocol,
        orig,
        reply,
        status: get32(CTA_STATUS).unwrap_or(0),
        timeout: get32(CTA_TIMEOUT).unwrap_or(0),
        tcp_state: if protocol == 6 { tcp_state } else { None },
        mark: get32(CTA_MARK).unwrap_or(0),
        orig_packets,
        orig_bytes,
        reply_packets,
        reply_bytes,
    })
}

/// Fold one stats message into `s` (`GET_STATS` holds the global count
/// and maximum; each `GET_STATS_CPU` message one CPU's counters).
pub fn add_stats(s: &mut Stats, body: &[u8]) {
    for a in attrs(body) {
        let v = u64::from(be32(&a).unwrap_or(0));
        match a.kind {
            CTA_STATS_GLOBAL_ENTRIES if body.len() <= 16 => s.count = v,
            CTA_STATS_GLOBAL_MAX_ENTRIES if body.len() <= 16 => s.max = v,
            CTA_STATS_INSERT_FAILED => s.insert_failed = s.insert_failed.saturating_add(v),
            CTA_STATS_DROP => s.drop = s.drop.saturating_add(v),
            CTA_STATS_EARLY_DROP => s.early_drop = s.early_drop.saturating_add(v),
            _ => {}
        }
    }
}

/// A ctnetlink request being built.
struct Req {
    buf: Vec<u8>,
    open: Vec<usize>,
}

impl Req {
    fn new(msg: u16, flags: u16, family: u8, seq: u32) -> Self {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf.extend_from_slice(&((NFNL_SUBSYS_CTNETLINK << 8) | msg).to_ne_bytes());
        buf.extend_from_slice(&(NLM_F_REQUEST | flags).to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf.extend_from_slice(&[family, 0, 0, 0]);
        Self {
            buf,
            open: Vec::new(),
        }
    }

    fn put(&mut self, kind: u16, data: &[u8]) {
        let len = u16::try_from(NLA_HDR + data.len()).unwrap_or(u16::MAX);
        self.buf.extend_from_slice(&len.to_ne_bytes());
        self.buf.extend_from_slice(&kind.to_ne_bytes());
        self.buf.extend_from_slice(data);
        self.buf.resize(self.buf.len().div_ceil(4) * 4, 0);
    }

    fn begin(&mut self, kind: u16) {
        self.open.push(self.buf.len());
        self.put(kind | NLA_F_NESTED, &[]);
    }

    fn end(&mut self) {
        if let Some(start) = self.open.pop() {
            let len = u16::try_from(self.buf.len().saturating_sub(start)).unwrap_or(u16::MAX);
            if let Some(slot) = self.buf.get_mut(start..start + 2) {
                slot.copy_from_slice(&len.to_ne_bytes());
            }
        }
    }

    fn tuple(&mut self, kind: u16, t: &Tuple, protocol: u8) {
        self.begin(kind);
        self.begin(CTA_TUPLE_IP);
        match (t.src, t.dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                self.put(CTA_IP_V4_SRC, &s.octets());
                self.put(CTA_IP_V4_DST, &d.octets());
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                self.put(CTA_IP_V6_SRC, &s.octets());
                self.put(CTA_IP_V6_DST, &d.octets());
            }
            _ => {}
        }
        self.end();
        self.begin(CTA_TUPLE_PROTO);
        self.put(CTA_PROTO_NUM, &[protocol]);
        match protocol {
            // The kernel wants id, type and code of an ICMP tuple (EINVAL
            // otherwise); type and code come from `dst_port`.
            1 => {
                let [ty, code] = t.dst_port.to_be_bytes();
                self.put(CTA_PROTO_ICMP_ID, &t.src_port.to_be_bytes());
                self.put(CTA_PROTO_ICMP_TYPE, &[ty]);
                self.put(CTA_PROTO_ICMP_CODE, &[code]);
            }
            58 => {
                let [ty, code] = t.dst_port.to_be_bytes();
                self.put(CTA_PROTO_ICMPV6_ID, &t.src_port.to_be_bytes());
                self.put(CTA_PROTO_ICMPV6_TYPE, &[ty]);
                self.put(CTA_PROTO_ICMPV6_CODE, &[code]);
            }
            6 | 17 | 132 | 136 | 33 => {
                self.put(CTA_PROTO_SRC_PORT, &t.src_port.to_be_bytes());
                self.put(CTA_PROTO_DST_PORT, &t.dst_port.to_be_bytes());
            }
            _ => {}
        }
        self.end();
        self.end();
    }

    fn finish(mut self) -> Vec<u8> {
        while !self.open.is_empty() {
            self.end();
        }
        let len = u32::try_from(self.buf.len()).unwrap_or(u32::MAX);
        if let Some(slot) = self.buf.get_mut(..4) {
            slot.copy_from_slice(&len.to_ne_bytes());
        }
        self.buf
    }
}

/// `NFPROTO_UNSPEC`: a dump of both families.
const AF_UNSPEC: u8 = 0;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

pub fn dump_request(seq: u32) -> Vec<u8> {
    Req::new(IPCTNL_MSG_CT_GET, NLM_F_DUMP, AF_UNSPEC, seq).finish()
}

pub fn stats_requests(seq: u32) -> [Vec<u8>; 2] {
    [
        Req::new(IPCTNL_MSG_CT_GET_STATS, NLM_F_ACK, AF_UNSPEC, seq).finish(),
        Req::new(
            IPCTNL_MSG_CT_GET_STATS_CPU,
            NLM_F_DUMP,
            AF_UNSPEC,
            seq.wrapping_add(1),
        )
        .finish(),
    ]
}

/// Delete the connection with this original tuple (and id, so a newer
/// connection that reused the tuple is not the one killed).
pub fn delete_request(c: &Conn, seq: u32) -> Vec<u8> {
    let family = if c.orig.src.is_ipv4() {
        AF_INET
    } else {
        AF_INET6
    };
    let mut r = Req::new(IPCTNL_MSG_CT_DELETE, NLM_F_ACK, family, seq);
    r.tuple(CTA_TUPLE_ORIG, &c.orig, c.protocol);
    if c.id != 0 {
        r.put(CTA_ID, &c.id.to_be_bytes());
    }
    r.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn conn() -> Conn {
        Conn {
            id: 0x1234,
            protocol: 6,
            orig: Tuple {
                src: "100.64.0.9".parse().unwrap(),
                dst: "192.0.2.2".parse().unwrap(),
                src_port: 40000,
                dst_port: 443,
            },
            reply: Tuple {
                src: "192.0.2.2".parse().unwrap(),
                dst: "203.0.113.1".parse().unwrap(),
                src_port: 443,
                dst_port: 2100,
            },
            status: 0x19e,
            timeout: 431_999,
            tcp_state: Some(3),
            mark: 0,
            orig_packets: 10,
            orig_bytes: 1000,
            reply_packets: 9,
            reply_bytes: 9000,
        }
    }

    /// A message as the kernel sends it, built with the request encoder
    /// plus the fields only replies carry.
    fn reply_bytes(c: &Conn) -> Vec<u8> {
        let mut r = Req::new(IPCTNL_MSG_CT_GET, 0, AF_INET, 1);
        r.tuple(CTA_TUPLE_ORIG, &c.orig, c.protocol);
        r.tuple(CTA_TUPLE_REPLY, &c.reply, c.protocol);
        r.put(CTA_STATUS, &c.status.to_be_bytes());
        r.put(CTA_TIMEOUT, &c.timeout.to_be_bytes());
        r.put(CTA_MARK, &c.mark.to_be_bytes());
        r.begin(CTA_COUNTERS_ORIG);
        r.put(CTA_COUNTERS_PACKETS, &c.orig_packets.to_be_bytes());
        r.put(CTA_COUNTERS_BYTES, &c.orig_bytes.to_be_bytes());
        r.end();
        r.begin(CTA_COUNTERS_REPLY);
        r.put(CTA_COUNTERS_PACKETS, &c.reply_packets.to_be_bytes());
        r.put(CTA_COUNTERS_BYTES, &c.reply_bytes.to_be_bytes());
        r.end();
        r.put(CTA_ID, &c.id.to_be_bytes());
        r.begin(CTA_PROTOINFO);
        r.begin(CTA_PROTOINFO_TCP);
        r.put(CTA_PROTOINFO_TCP_STATE, &[3]);
        r.end();
        r.end();
        r.finish()
    }

    #[test]
    fn a_connection_round_trips() {
        let c = conn();
        let bytes = reply_bytes(&c);
        let back = parse_conn(&bytes[20..]).unwrap();
        assert_eq!(back, c);
        assert_eq!(back.state(), "established");
        assert_eq!(back.via(), corerouter_hal::conntrack::Via::Rules);
    }

    /// An ICMP echo keeps id, type and code (the kernel refuses a delete
    /// whose ICMP tuple lacks type or code: a killed ping must not stop
    /// the kill of the connections after it).
    #[test]
    fn an_icmp_tuple_carries_type_and_code() {
        let mut c = conn();
        c.protocol = 1;
        c.tcp_state = None;
        c.orig.src_port = 12955;
        c.orig.dst_port = 8 << 8; // echo request, code 0
        c.reply.src_port = 2542;
        c.reply.dst_port = 0; // echo reply
        let back = parse_conn(&reply_bytes(&c)[20..]).unwrap();
        assert_eq!(back, c);
        let req = delete_request(&c, 7);
        let has = |kind: u16, data: &[u8]| {
            let mut a = Vec::new();
            a.extend_from_slice(&((NLA_HDR + data.len()) as u16).to_ne_bytes());
            a.extend_from_slice(&kind.to_ne_bytes());
            a.extend_from_slice(data);
            req.windows(a.len()).any(|w| w == a.as_slice())
        };
        assert!(has(CTA_PROTO_ICMP_ID, &12955u16.to_be_bytes()));
        assert!(has(CTA_PROTO_ICMP_TYPE, &[8]));
        assert!(has(CTA_PROTO_ICMP_CODE, &[0]));
    }

    proptest! {
        /// Hostile bytes never panic, and a cut message gives no conn or a
        /// partial one, never garbage tuples.
        #[test]
        fn hostile_bytes_never_panic(junk in proptest::collection::vec(any::<u8>(), 0..512), cut in 0usize..400) {
            let _ = parse_conn(&junk);
            let mut s = Stats::default();
            add_stats(&mut s, &junk);
            let good = reply_bytes(&conn());
            let body = &good[20..];
            let cut = cut.min(body.len());
            if let Some(c) = parse_conn(&body[..cut]) {
                prop_assert_eq!(c.orig, conn().orig);
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub use io::{delete, dump, stats};

#[cfg(target_os = "linux")]
mod io {
    use std::os::fd::AsFd;
    use std::time::{Duration, Instant};

    use corerouter_hal::HalError;
    use corerouter_hal::conntrack::{Conn, MAX_READ, Stats};
    use netlink_sys::{Socket, protocols::NETLINK_NETFILTER};
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

    /// A dump of a million connections takes about a second (**estimado**);
    /// past this it is a stuck kernel.
    const DEADLINE: Duration = Duration::from_secs(20);

    fn io(e: impl std::fmt::Display) -> HalError {
        HalError::Io(format!("conntrack netlink: {e}"))
    }

    fn open() -> Result<Socket, HalError> {
        let mut sock = Socket::new(NETLINK_NETFILTER).map_err(io)?;
        sock.bind_auto().map_err(io)?;
        // Dumps arrive faster than we parse: a big receive buffer.
        use nix::sys::socket::{setsockopt, sockopt};
        if setsockopt(&sock.as_fd(), sockopt::RcvBufForce, &(8usize << 20)).is_err() {
            let _ = setsockopt(&sock.as_fd(), sockopt::RcvBuf, &(8usize << 20));
        }
        Ok(sock)
    }

    /// Messages of a reply until `NLMSG_DONE` (or the ACK/error of a
    /// request), each handed to `each` as (type, body after nfgenmsg).
    fn read(
        sock: &mut Socket,
        seq: u32,
        mut each: impl FnMut(u16, &[u8]) -> bool,
    ) -> Result<(), HalError> {
        let start = Instant::now();
        let mut buf = vec![0u8; 1 << 17];
        loop {
            let left = DEADLINE.saturating_sub(start.elapsed());
            if left.is_zero() {
                return Err(HalError::Io(
                    "conntrack: the kernel did not finish in time".into(),
                ));
            }
            let ms = u16::try_from(left.as_millis().min(1000)).unwrap_or(1000);
            let mut fds = [PollFd::new(sock.as_fd(), PollFlags::POLLIN)];
            if poll(&mut fds, PollTimeout::from(ms)).map_err(io)? == 0 {
                continue;
            }
            let n = sock.recv(&mut &mut buf[..], 0).map_err(io)?;
            let mut rest = buf.get(..n).unwrap_or(&[]);
            while let Some(hdr) = rest.get(..16) {
                let word = |at: usize| {
                    hdr.get(at..at + 4)
                        .and_then(|b| b.try_into().ok())
                        .map(u32::from_ne_bytes)
                };
                let (Some(len), Some(mseq)) = (word(0), word(8)) else {
                    break;
                };
                let kind = hdr
                    .get(4..6)
                    .and_then(|b| b.try_into().ok())
                    .map_or(0, u16::from_ne_bytes);
                let len = usize::try_from(len).unwrap_or(0);
                if len < 16 {
                    break;
                }
                let msg = rest.get(..len).unwrap_or(rest);
                rest = rest.get(len.div_ceil(4) * 4..).unwrap_or(&[]);
                if mseq != seq {
                    continue;
                }
                match kind {
                    3 => return Ok(()),
                    2 => {
                        let code = msg
                            .get(16..20)
                            .and_then(|b| b.try_into().ok())
                            .map_or(0, i32::from_ne_bytes);
                        return if code == 0 {
                            Ok(())
                        } else {
                            Err(HalError::Rejected(format!(
                                "conntrack: {}",
                                std::io::Error::from_raw_os_error(code.saturating_neg())
                            )))
                        };
                    }
                    _ => {
                        if !each(kind & 0xff, msg.get(20..).unwrap_or(&[])) {
                            return Ok(());
                        }
                    }
                }
            }
        }
    }

    /// Every connection (at most [`MAX_READ`]).
    pub fn dump() -> Result<Vec<Conn>, HalError> {
        let mut sock = open()?;
        let seq = 1;
        sock.send(&super::dump_request(seq), 0).map_err(io)?;
        let mut out = Vec::new();
        read(&mut sock, seq, |_, body| {
            if let Some(c) = super::parse_conn(body) {
                out.push(c);
            }
            out.len() < MAX_READ
        })?;
        Ok(out)
    }

    pub fn stats() -> Result<Stats, HalError> {
        let mut sock = open()?;
        let [global, cpu] = super::stats_requests(1);
        let mut s = Stats::default();
        sock.send(&global, 0).map_err(io)?;
        read(&mut sock, 1, |_, body| {
            super::add_stats(&mut s, body);
            true
        })?;
        sock.send(&cpu, 0).map_err(io)?;
        let mut per_cpu = Stats::default();
        read(&mut sock, 2, |_, body| {
            super::add_stats(&mut per_cpu, body);
            true
        })?;
        s.insert_failed = per_cpu.insert_failed;
        s.drop = per_cpu.drop;
        s.early_drop = per_cpu.early_drop;
        Ok(s)
    }

    /// Kill `conns` (one request each); how many the kernel removed (one
    /// already gone is not an error). One the kernel refuses does not stop
    /// the others: the first refusal is returned after all were tried.
    pub fn delete(conns: &[Conn]) -> Result<usize, HalError> {
        let mut sock = open()?;
        let mut done = 0;
        let mut refused: Option<HalError> = None;
        for (i, c) in conns.iter().enumerate() {
            let seq = u32::try_from(i).unwrap_or(u32::MAX).wrapping_add(10);
            sock.send(&super::delete_request(c, seq), 0).map_err(io)?;
            match read(&mut sock, seq, |_, _| true) {
                Ok(()) => done += 1,
                Err(HalError::Rejected(e)) if e.contains("No such file") => {}
                Err(e @ HalError::Rejected(_)) => {
                    refused.get_or_insert(e);
                }
                Err(e) => return Err(e),
            }
        }
        match refused {
            Some(e) if done == 0 => Err(e),
            Some(e) => {
                log::warn!("conntrack: {done} of {} killed; {e}", conns.len());
                Ok(done)
            }
            None => Ok(done),
        }
    }
}
