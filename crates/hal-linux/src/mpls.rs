//! MPLS label switching over rtnetlink (G3.5), without `ip -f mpls` and
//! without the async `rtnetlink` crate: one blocking socket, messages built
//! and parsed in place.
//!
//! - the label table: `RTM_GETROUTE` + `NLM_F_DUMP` with family
//!   `AF_MPLS` (each entry: `RTA_DST` the incoming label, `RTA_VIA` the next
//!   router, `RTA_NEWDST` the outgoing stack, `RTA_OIF`, or several ways out
//!   in `RTA_MULTIPATH`);
//! - `/mpls static`: `RTM_NEWROUTE`/`RTM_DELROUTE`, **many per send**
//!   (one `sendmsg` carries up to [`BATCH_BYTES`] of requests, the ACKs are
//!   read after it): 10 000 labels in one batch instead of 10 000 round
//!   trips (`benches/netns_mpls.rs`);
//! - the knobs: `/proc/sys/net/mpls/platform_labels`, `ip_ttl_propagate`
//!   and `conf/<if>/input`, which exist only with `mpls_router` loaded —
//!   [`available`] checks for them without opening an `AF_MPLS` request
//!   (so nothing asks the kernel to load the module).
//!
//! Label stack entries are RFC 3032 §2.1: label (20 bits), TC (3), bottom
//! of stack (1), TTL (8), big-endian. The codec is pure and bounded: a
//! hostile or truncated message yields no entry, never a panic.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use corerouter_hal::mpls::Origin;
use corerouter_model::mpls::{MAX_LABEL, MAX_PUSH};

pub const AF_MPLS: u8 = 28;
pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;
pub const RTM_GETROUTE: u16 = 26;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RTA_MULTIPATH: u16 = 9;
const RTA_VIA: u16 = 18;
const RTA_NEWDST: u16 = 19;
const RT_TABLE_MAIN: u8 = 254;
const RTN_UNICAST: u8 = 1;
const RTPROT_ZEBRA: u8 = 11;
const RTPROT_STATIC: u8 = 4;
const RTPROT_BGP: u8 = 186;
const RTPROT_LDP: u8 = 193;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_HDR: usize = 16;
const RTMSG: usize = 12;
/// `struct rtnexthop`: len, flags, hops, ifindex.
const RTNH: usize = 8;
/// One `sendmsg` of requests at most: the kernel takes the whole buffer in
/// one go (`netlink_rcv_skb`) and the ACKs fit the receive buffer.
pub const BATCH_BYTES: usize = 64 << 10;
/// Ways out of one entry kept from a dump (hostile input).
const MAX_NEXTHOPS: usize = 64;

/// One label stack entry (RFC 3032 §2.1), TC and TTL zero as the kernel
/// wants them in requests.
pub fn encode_label(label: u32, bottom: bool) -> [u8; 4] {
    ((label & MAX_LABEL) << 12 | u32::from(bottom) << 8).to_be_bytes()
}

/// The labels of a stack attribute, top first, up to the bottom-of-stack
/// bit; `None` if malformed (a stack without its bottom).
pub fn decode_stack(b: &[u8]) -> Option<Vec<u32>> {
    let mut out = Vec::new();
    for chunk in b.chunks_exact(4) {
        let v = u32::from_be_bytes(chunk.try_into().ok()?);
        out.push(v >> 12);
        if v & 0x100 != 0 {
            return Some(out);
        }
        if out.len() > MAX_PUSH {
            return None;
        }
    }
    None
}

/// An entry of the table as netlink has it (interfaces by index).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRoute {
    pub label: u32,
    pub protocol: u8,
    pub nexthops: Vec<RawNexthop>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RawNexthop {
    pub via: Option<IpAddr>,
    pub ifindex: Option<u32>,
    pub out_labels: Vec<u32>,
}

pub fn origin(protocol: u8) -> Origin {
    match protocol {
        RTPROT_STATIC => Origin::Static,
        RTPROT_LDP | RTPROT_ZEBRA => Origin::Ldp,
        RTPROT_BGP => Origin::Bgp,
        _ => Origin::Other,
    }
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// The attributes of `b`: (type, payload), stopping at the first malformed one.
fn rtattrs(mut b: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    std::iter::from_fn(move || {
        let len = usize::from(u16_at(b, 0)?);
        let kind = u16_at(b, 2)? & 0x3fff;
        if len < 4 {
            return None;
        }
        let data = b.get(4..len)?;
        b = b.get(len.div_ceil(4) * 4..).unwrap_or(&[]);
        Some((kind, data))
    })
}

/// `struct rtvia`: the family (u16, host order) and the address.
fn via(b: &[u8]) -> Option<IpAddr> {
    match u16_at(b, 0)? {
        AF_INET => {
            let o: [u8; 4] = b.get(2..6)?.try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(o)))
        }
        AF_INET6 => {
            let o: [u8; 16] = b.get(2..18)?.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(o)))
        }
        _ => None,
    }
}

fn nexthop_attrs(attrs: &[u8], nh: &mut RawNexthop) {
    for (kind, data) in rtattrs(attrs) {
        match kind {
            RTA_VIA => nh.via = via(data),
            RTA_NEWDST => nh.out_labels = decode_stack(data).unwrap_or_default(),
            RTA_OIF => nh.ifindex = u32_at(data, 0),
            _ => {}
        }
    }
}

/// One `RTM_NEWROUTE` body (after the netlink header) of family `AF_MPLS`.
pub fn parse(body: &[u8]) -> Option<RawRoute> {
    let head = body.get(..RTMSG)?;
    if head.first() != Some(&AF_MPLS) {
        return None;
    }
    let protocol = *head.get(5)?;
    let mut label = None;
    let mut single = RawNexthop::default();
    let mut multi = Vec::new();
    for (kind, data) in rtattrs(body.get(RTMSG..)?) {
        match kind {
            RTA_DST => label = decode_stack(data)?.first().copied(),
            RTA_MULTIPATH => {
                let mut rest = data;
                while let Some(len) = u16_at(rest, 0).map(usize::from) {
                    if len < RTNH || multi.len() >= MAX_NEXTHOPS {
                        break;
                    }
                    let Some(one) = rest.get(..len) else { break };
                    let mut nh = RawNexthop {
                        ifindex: u32_at(one, 4).filter(|i| *i != 0),
                        ..RawNexthop::default()
                    };
                    nexthop_attrs(one.get(RTNH..).unwrap_or(&[]), &mut nh);
                    multi.push(nh);
                    rest = rest.get(len.div_ceil(4) * 4..).unwrap_or(&[]);
                }
            }
            _ => {}
        }
    }
    nexthop_attrs(body.get(RTMSG..)?, &mut single);
    let nexthops = if multi.is_empty() { vec![single] } else { multi };
    Some(RawRoute {
        label: label?,
        protocol,
        nexthops,
    })
}

fn header(buf: &mut Vec<u8>, kind: u16, flags: u16, seq: u32) -> usize {
    let at = buf.len();
    buf.extend_from_slice(&0u32.to_ne_bytes());
    buf.extend_from_slice(&kind.to_ne_bytes());
    buf.extend_from_slice(&flags.to_ne_bytes());
    buf.extend_from_slice(&seq.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes());
    at
}

fn rtmsg(buf: &mut Vec<u8>, protocol: u8) {
    // family, dst_len (20 bits), src_len, tos, table, protocol, scope, type
    buf.extend_from_slice(&[AF_MPLS, 20, 0, 0, RT_TABLE_MAIN, protocol, 0, RTN_UNICAST]);
    buf.extend_from_slice(&0u32.to_ne_bytes());
}

fn attr(buf: &mut Vec<u8>, kind: u16, data: &[u8]) {
    let len = u16::try_from(4 + data.len()).unwrap_or(u16::MAX);
    buf.extend_from_slice(&len.to_ne_bytes());
    buf.extend_from_slice(&kind.to_ne_bytes());
    buf.extend_from_slice(data);
    while !buf.len().is_multiple_of(4) {
        buf.push(0);
    }
}

/// Write the message length into the header that starts at `at`.
fn close(buf: &mut [u8], at: usize) {
    let len = u32::try_from(buf.len() - at).unwrap_or(u32::MAX).to_ne_bytes();
    if let Some(head) = buf.get_mut(at..at + 4) {
        head.copy_from_slice(&len);
    }
}

fn via_bytes(ip: IpAddr) -> Vec<u8> {
    let mut v = Vec::with_capacity(18);
    match ip {
        IpAddr::V4(a) => {
            v.extend_from_slice(&AF_INET.to_ne_bytes());
            v.extend_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            v.extend_from_slice(&AF_INET6.to_ne_bytes());
            v.extend_from_slice(&a.octets());
        }
    }
    v
}

fn stack_bytes(labels: &[u32]) -> Vec<u8> {
    let last = labels.len().saturating_sub(1);
    labels
        .iter()
        .enumerate()
        .flat_map(|(i, l)| encode_label(*l, i == last))
        .collect()
}

/// Append "create or replace `r`" to `buf` (one entry, one way out).
pub fn push_set(buf: &mut Vec<u8>, r: &RawRoute, seq: u32) {
    let at = header(
        buf,
        RTM_NEWROUTE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        seq,
    );
    rtmsg(buf, r.protocol);
    attr(buf, RTA_DST, &encode_label(r.label, true));
    if let [nh] = r.nexthops.as_slice() {
        if let Some(v) = nh.via {
            attr(buf, RTA_VIA, &via_bytes(v));
        }
        if !nh.out_labels.is_empty() {
            attr(buf, RTA_NEWDST, &stack_bytes(&nh.out_labels));
        }
        if let Some(i) = nh.ifindex {
            attr(buf, RTA_OIF, &i.to_ne_bytes());
        }
    }
    close(buf, at);
}

/// Append "remove the entry of `label`" to `buf`.
pub fn push_remove(buf: &mut Vec<u8>, label: u32, seq: u32) {
    let at = header(buf, RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK, seq);
    rtmsg(buf, RTPROT_STATIC);
    attr(buf, RTA_DST, &encode_label(label, true));
    close(buf, at);
}

/// Dump the whole label table.
pub fn dump_request(seq: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(NLMSG_HDR + RTMSG);
    let at = header(&mut b, RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP, seq);
    b.extend_from_slice(&[AF_MPLS, 0, 0, 0, 0, 0, 0, 0]);
    b.extend_from_slice(&0u32.to_ne_bytes());
    close(&mut b, at);
    b
}

/// The protocol id static entries carry.
pub const STATIC_PROTOCOL: u8 = RTPROT_STATIC;

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "linux")]
mod linux {
    use std::os::fd::AsFd;
    use std::path::Path;
    use std::time::{Duration, Instant};

    use corerouter_hal::HalError;
    use corerouter_hal::mpls::{MplsNexthop, MplsReader, MplsRoute, StaticOp};
    use corerouter_model::{Config, IfName};
    use netlink_sys::{Socket, protocols::NETLINK_ROUTE};
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

    use super::{BATCH_BYTES, RTM_NEWROUTE, RawNexthop, RawRoute, STATIC_PROTOCOL};
    use crate::neigh::{Names, nlmsg_header};

    const NLMSG_ERROR: u16 = 2;
    const NLMSG_DONE: u16 = 3;
    const NLM_F_DUMP_INTR: u16 = 0x10;
    const ENOENT: i32 = 2;
    /// 8 MiB: the ACKs of a whole batch and a dump's parts fit with room.
    const RCVBUF: usize = 8 << 20;
    /// A dump of the whole label space (10⁶) takes about a second
    /// (**estimado** from the 100 k measurement).
    const DEADLINE: Duration = Duration::from_secs(20);
    /// Entries kept from one dump at most (the 20-bit label space).
    const MAX_DUMP: usize = 1 << 20;
    pub(crate) const SYS: &str = "/proc/sys/net/mpls";

    fn io(e: impl std::fmt::Display) -> HalError {
        HalError::Io(format!("MPLS netlink: {e}"))
    }

    /// The kernel of this network namespace switches labels: `mpls_router`
    /// is loaded (its sysctls exist). Reading a file never loads a module.
    pub fn available() -> bool {
        Path::new(SYS).join("platform_labels").exists()
    }

    fn open() -> Result<Socket, HalError> {
        let mut sock = Socket::new(NETLINK_ROUTE).map_err(io)?;
        sock.bind_auto().map_err(io)?;
        use nix::sys::socket::{setsockopt, sockopt};
        if setsockopt(&sock.as_fd(), sockopt::RcvBufForce, &RCVBUF).is_err() {
            let _ = setsockopt(&sock.as_fd(), sockopt::RcvBuf, &RCVBUF);
        }
        Ok(sock)
    }

    fn wait(sock: &Socket, start: Instant) -> Result<bool, HalError> {
        let left = DEADLINE.saturating_sub(start.elapsed());
        if left.is_zero() {
            return Err(HalError::Io(
                "MPLS: the kernel did not answer in time".into(),
            ));
        }
        let ms = u16::try_from(left.as_millis().min(1000)).unwrap_or(1000);
        let mut fds = [PollFd::new(sock.as_fd(), PollFlags::POLLIN)];
        Ok(poll(&mut fds, PollTimeout::from(ms)).map_err(io)? > 0)
    }

    fn errno(msg: &[u8]) -> i32 {
        msg.get(16..20)
            .and_then(|b| b.try_into().ok())
            .map_or(0, i32::from_ne_bytes)
            .saturating_neg()
    }

    fn os_error(code: i32) -> String {
        std::io::Error::from_raw_os_error(code).to_string()
    }

    /// Reads the table; keeps its socket and the index → name map.
    pub struct Reader {
        sock: Socket,
        buf: Vec<u8>,
        names: Names,
        seq: u32,
    }

    impl Reader {
        pub fn open() -> Result<Self, HalError> {
            Ok(Self {
                sock: open()?,
                buf: vec![0u8; 1 << 17],
                names: Names::default(),
                seq: 0x4d50_0000,
            })
        }

        /// The raw entries; a dump the kernel marks interrupted is read
        /// again (three times at most).
        pub fn raw(&mut self) -> Result<Vec<RawRoute>, HalError> {
            if !available() {
                return Err(HalError::Unsupported(corerouter_hal::mpls::NO_MPLS.into()));
            }
            let mut out = Vec::new();
            for _ in 0..3 {
                out.clear();
                self.seq = self.seq.wrapping_add(1);
                let seq = self.seq;
                self.sock
                    .send(&super::dump_request(seq), 0)
                    .map_err(io)?;
                let start = Instant::now();
                let mut torn = false;
                'read: loop {
                    if !wait(&self.sock, start)? {
                        continue;
                    }
                    let n = self.sock.recv(&mut &mut self.buf[..], 0).map_err(io)?;
                    let mut rest = self.buf.get(..n).unwrap_or(&[]);
                    while let Some((len, kind, flags, mseq)) = nlmsg_header(rest) {
                        let msg = rest.get(..len).unwrap_or(rest);
                        rest = rest.get(len.div_ceil(4) * 4..).unwrap_or(&[]);
                        if mseq != seq {
                            continue;
                        }
                        torn |= flags & NLM_F_DUMP_INTR != 0;
                        match kind {
                            NLMSG_DONE => break 'read,
                            NLMSG_ERROR => {
                                return Err(HalError::Rejected(os_error(errno(msg))));
                            }
                            RTM_NEWROUTE if out.len() < MAX_DUMP => {
                                if let Some(r) = super::parse(msg.get(16..).unwrap_or(&[])) {
                                    out.push(r);
                                }
                            }
                            _ => {}
                        }
                    }
                }
                if !torn {
                    break;
                }
            }
            out.sort_by_key(|r| r.label);
            Ok(out)
        }
    }

    impl MplsReader for Reader {
        fn routes(&mut self) -> Result<Vec<MplsRoute>, HalError> {
            let raw = self.raw()?;
            let _ = self.names.refresh();
            Ok(raw
                .into_iter()
                .map(|r| MplsRoute {
                    label: r.label,
                    origin: super::origin(r.protocol),
                    nexthops: r
                        .nexthops
                        .into_iter()
                        .map(|n| MplsNexthop {
                            via: n.via,
                            interface: n.ifindex.and_then(|i| self.names.name(i)),
                            out_labels: n.out_labels,
                        })
                        .collect(),
                })
                .collect())
        }
    }

    /// One request of a batch: what it does, to undo it.
    struct Sent {
        seq: u32,
        op: usize,
    }

    /// Send `ops` in batches of [`BATCH_BYTES`]; the index of the first
    /// refused one and why, or `Ok` with every one done. A removal of an
    /// entry already gone is not a refusal.
    fn send_batched(
        sock: &mut Socket,
        ops: &[StaticOp],
        names: &mut Names,
    ) -> Result<(), (usize, HalError)> {
        let mut buf = Vec::with_capacity(BATCH_BYTES + 512);
        let mut rbuf = vec![0u8; 1 << 16];
        let mut i = 0;
        let mut seq: u32 = 0x4d53_0000;
        while i < ops.len() {
            buf.clear();
            let mut sent: Vec<Sent> = Vec::new();
            while let Some(op) = ops.get(i) {
                if buf.len() >= BATCH_BYTES {
                    break;
                }
                seq = seq.wrapping_add(1);
                match op {
                    StaticOp::Remove(label) => super::push_remove(&mut buf, *label, seq),
                    StaticOp::Set(r) => {
                        let raw = raw_of(r, names).map_err(|e| (i, e))?;
                        super::push_set(&mut buf, &raw, seq);
                    }
                }
                sent.push(Sent { seq, op: i });
                i += 1;
            }
            let first = sent.first().map_or(0, |s| s.op);
            sock.send(&buf, 0).map_err(|e| (first, io(e)))?;
            // One ACK per request, in order.
            let start = Instant::now();
            let mut acked = 0;
            let mut refused: Option<(usize, HalError)> = None;
            while acked < sent.len() {
                if !wait(sock, start).map_err(|e| (first, e))? {
                    continue;
                }
                let n = sock
                    .recv(&mut &mut rbuf[..], 0)
                    .map_err(|e| (first, io(e)))?;
                let mut rest = rbuf.get(..n).unwrap_or(&[]);
                while let Some((len, kind, _, mseq)) = nlmsg_header(rest) {
                    let msg = rest.get(..len).unwrap_or(rest);
                    rest = rest.get(len.div_ceil(4) * 4..).unwrap_or(&[]);
                    let Some(s) = sent.iter().find(|s| s.seq == mseq) else {
                        continue;
                    };
                    if kind != NLMSG_ERROR {
                        continue;
                    }
                    acked += 1;
                    let code = errno(msg);
                    let gone = code == ENOENT
                        && matches!(ops.get(s.op), Some(StaticOp::Remove(_)));
                    if code != 0 && !gone && refused.as_ref().is_none_or(|(o, _)| s.op < *o) {
                        let what = match ops.get(s.op) {
                            Some(StaticOp::Remove(l)) => format!("removing label {l}"),
                            Some(StaticOp::Set(r)) => format!("label {}", r.label),
                            None => String::new(),
                        };
                        refused = Some((s.op, HalError::Rejected(format!("MPLS {what}: {}", os_error(code)))));
                    }
                }
            }
            if let Some(r) = refused {
                return Err(r);
            }
        }
        Ok(())
    }

    fn raw_of(r: &MplsRoute, names: &mut Names) -> Result<RawRoute, HalError> {
        let mut nexthops = Vec::with_capacity(r.nexthops.len());
        for n in &r.nexthops {
            let ifindex = match &n.interface {
                Some(name) => Some(names.index(name).ok_or_else(|| {
                    HalError::Rejected(format!("MPLS label {}: no interface {name}", r.label))
                })?),
                None => None,
            };
            nexthops.push(RawNexthop {
                via: n.via,
                ifindex,
                out_labels: n.out_labels.clone(),
            });
        }
        Ok(RawRoute {
            label: r.label,
            protocol: STATIC_PROTOCOL,
            nexthops,
        })
    }

    /// Run `ops` (the static entries' changes) in batches, all or nothing:
    /// on a refusal the ones done before it are undone with `undo`'s
    /// entries (what was there before).
    pub fn apply_static(ops: &[StaticOp], before: &[MplsRoute]) -> Result<(), HalError> {
        if ops.is_empty() {
            return Ok(());
        }
        let mut sock = open()?;
        let mut names = Names::default();
        names.refresh()?;
        match send_batched(&mut sock, ops, &mut names) {
            Ok(()) => Ok(()),
            Err((at, e)) => {
                let undo: Vec<StaticOp> = ops
                    .get(..at)
                    .unwrap_or(&[])
                    .iter()
                    .rev()
                    .map(|op| {
                        let label = match op {
                            StaticOp::Remove(l) => *l,
                            StaticOp::Set(r) => r.label,
                        };
                        before
                            .iter()
                            .find(|b| b.label == label)
                            .map_or(StaticOp::Remove(label), |b| StaticOp::Set(b.clone()))
                    })
                    .collect();
                if let Err((_, back)) = send_batched(&mut sock, &undo, &mut names) {
                    log::error!("MPLS: undoing the static labels: {back}");
                }
                Err(e)
            }
        }
    }

    /// The same changes, one request and one ACK at a time (the benchmark's
    /// baseline; not used by `apply`).
    pub fn apply_one_by_one(ops: &[StaticOp]) -> Result<(), HalError> {
        let mut sock = open()?;
        let mut names = Names::default();
        names.refresh()?;
        for op in ops {
            send_batched(&mut sock, std::slice::from_ref(op), &mut names).map_err(|(_, e)| e)?;
        }
        Ok(())
    }

    fn write(path: &Path, value: &str) -> Result<(), HalError> {
        if std::fs::read_to_string(path).is_ok_and(|v| v.trim() == value) {
            return Ok(());
        }
        std::fs::write(path, value)
            .map_err(|e| HalError::Rejected(format!("{}: {e}", path.display())))
    }

    /// The kernel knobs of `cfg`: the size of the label table, TTL
    /// propagation and which managed interfaces accept labeled packets.
    /// Without MPLS in use nothing is written (a host without
    /// `mpls_router` runs everything else).
    pub fn sysctls(cfg: &Config, managed: &dyn Fn(&IfName) -> bool) -> Result<(), HalError> {
        let mpls = &cfg.routing.mpls;
        if !available() {
            return if mpls.in_use() {
                Err(HalError::Unsupported(corerouter_hal::mpls::NO_MPLS.into()))
            } else {
                Ok(())
            };
        }
        let sys = Path::new(SYS);
        if mpls.in_use() {
            write(
                &sys.join("platform_labels"),
                &mpls.settings.platform_labels().to_string(),
            )?;
        }
        write(
            &sys.join("ip_ttl_propagate"),
            if mpls.settings.propagate_ttl { "1" } else { "0" },
        )?;
        for name in cfg.interfaces.keys().filter(|n| managed(n)) {
            let p = sys.join("conf").join(name.as_str()).join("input");
            if p.exists() {
                write(&p, if mpls.input_on(name) { "1" } else { "0" })?;
            }
        }
        Ok(())
    }

    /// `/mpls` from `from` to `to`: the knobs, then the static entries.
    pub fn sync(from: &Config, to: &Config, managed: &dyn Fn(&IfName) -> bool) -> Result<(), HalError> {
        let (a, b) = (&from.routing.mpls, &to.routing.mpls);
        if a == b && from.interfaces == to.interfaces {
            return Ok(());
        }
        sysctls(to, managed)?;
        let ops = corerouter_hal::mpls::static_diff(a, b);
        if !ops.is_empty() {
            if !available() {
                return Err(HalError::Unsupported(corerouter_hal::mpls::NO_MPLS.into()));
            }
            if let Err(e) = apply_static(&ops, &corerouter_hal::mpls::static_routes(a)) {
                if let Err(back) = sysctls(from, managed) {
                    log::error!("MPLS: restoring the previous settings: {back}");
                }
                return Err(e);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn body_of(msg: &[u8]) -> &[u8] {
        &msg[NLMSG_HDR..]
    }

    #[test]
    fn label_entries_follow_rfc_3032() {
        // RFC 3032 §2.1: label 16, bottom of stack → 0x00010100.
        assert_eq!(encode_label(16, true), [0x00, 0x01, 0x01, 0x00]);
        assert_eq!(encode_label(MAX_LABEL, false), [0xff, 0xff, 0xf0, 0x00]);
        assert_eq!(decode_stack(&[0, 1, 1, 0]), Some(vec![16]));
        let two: Vec<u8> = [encode_label(100, false), encode_label(200, true)].concat();
        assert_eq!(decode_stack(&two), Some(vec![100, 200]));
        // No bottom of stack: malformed.
        assert_eq!(decode_stack(&encode_label(100, false)), None);
    }

    #[test]
    fn a_set_request_parses_back() {
        let r = RawRoute {
            label: 1000,
            protocol: STATIC_PROTOCOL,
            nexthops: vec![RawNexthop {
                via: Some(IpAddr::from([10, 0, 0, 2])),
                ifindex: Some(7),
                out_labels: vec![2000, 3000],
            }],
        };
        let mut buf = Vec::new();
        push_set(&mut buf, &r, 9);
        assert_eq!(buf.len() % 4, 0);
        assert_eq!(usize::try_from(u32_at(&buf, 0).unwrap()).unwrap(), buf.len());
        assert_eq!(parse(body_of(&buf)), Some(r));
        let v6 = RawRoute {
            label: 17,
            protocol: RTPROT_LDP,
            nexthops: vec![RawNexthop {
                via: Some("fe80::1".parse().unwrap()),
                ifindex: None,
                out_labels: vec![],
            }],
        };
        let mut b = Vec::new();
        push_set(&mut b, &v6, 1);
        assert_eq!(parse(body_of(&b)), Some(v6));
        assert_eq!(origin(RTPROT_LDP), Origin::Ldp);
    }

    #[test]
    fn many_requests_share_one_buffer() {
        let mut buf = Vec::new();
        for l in 16..116 {
            push_remove(&mut buf, l, l);
        }
        let mut rest = &buf[..];
        let mut n = 0;
        while let Some(len) = u32_at(rest, 0) {
            let len = usize::try_from(len).unwrap();
            assert_eq!(u16_at(rest, 4), Some(RTM_DELROUTE));
            rest = &rest[len..];
            n += 1;
        }
        assert_eq!(n, 100);
    }

    #[test]
    fn multipath_entries_have_every_way_out() {
        // rtmsg + RTA_DST + RTA_MULTIPATH with two rtnexthops.
        let mut b = Vec::new();
        b.extend_from_slice(&[AF_MPLS, 20, 0, 0, 254, RTPROT_ZEBRA, 0, 1, 0, 0, 0, 0]);
        attr(&mut b, RTA_DST, &encode_label(50, true));
        let mut mp = Vec::new();
        for (i, ip) in [(3u32, [10, 0, 0, 1]), (4, [10, 0, 1, 1])] {
            let mut nh = Vec::new();
            attr(&mut nh, RTA_VIA, &via_bytes(IpAddr::from(ip)));
            attr(&mut nh, RTA_NEWDST, &encode_label(60, true));
            let len = u16::try_from(RTNH + nh.len()).unwrap();
            mp.extend_from_slice(&len.to_ne_bytes());
            mp.extend_from_slice(&[0, 0]);
            mp.extend_from_slice(&i.to_ne_bytes());
            mp.extend_from_slice(&nh);
        }
        attr(&mut b, RTA_MULTIPATH, &mp);
        let r = parse(&b).unwrap();
        assert_eq!(r.label, 50);
        assert_eq!(r.nexthops.len(), 2);
        assert_eq!(r.nexthops[1].ifindex, Some(4));
        assert_eq!(r.nexthops[1].out_labels, vec![60]);
        assert_eq!(r.nexthops[0].via, Some(IpAddr::from([10, 0, 0, 1])));
    }

    #[test]
    fn other_families_are_not_labels() {
        let mut b = vec![2u8, 24, 0, 0, 254, 4, 0, 1, 0, 0, 0, 0];
        attr(&mut b, RTA_DST, &[10, 0, 0, 0]);
        assert_eq!(parse(&b), None);
        assert!(dump_request(1).len() == NLMSG_HDR + RTMSG);
    }

    proptest! {
        #[test]
        fn hostile_bytes_never_panic(junk in proptest::collection::vec(any::<u8>(), 0..512)) {
            let _ = parse(&junk);
            let _ = decode_stack(&junk);
            let mut b = vec![AF_MPLS, 20, 0, 0, 254, 4, 0, 1, 0, 0, 0, 0];
            b.extend_from_slice(&junk);
            let _ = parse(&b);
        }

        #[test]
        fn any_stack_round_trips(labels in proptest::collection::vec(16u32..=MAX_LABEL, 1..=MAX_PUSH)) {
            prop_assert_eq!(decode_stack(&stack_bytes(&labels)), Some(labels));
        }
    }
}
