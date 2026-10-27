//! The netfilter queue of first packets (G2.3c), over nfnetlink
//! (`NFNL_SUBSYS_QUEUE`), without libnetfilter_queue.
//!
//! A blocks-mode pool's rule sends the first packet of a subscriber
//! without a block to queue [`corerouter_hal::cgnat::QUEUE_NUM`]. We bind
//! to it, copy only the first 20 bytes (the IPv4 header: the source is
//! all we need), and answer each packet with a verdict once the engine
//! allocated the block. Without a listener the kernel drops the packets
//! (the rule has no `bypass`), so a subscriber is never let out with its
//! private address.
//!
//! The codec is pure and bounded (hostile or truncated messages yield no
//! packet, never a panic); the socket is Linux-only and safe.

use std::net::Ipv4Addr;

use crate::genl::{attrs, find};

pub const NFNL_SUBSYS_QUEUE: u16 = 3;
const NFQNL_MSG_PACKET: u16 = 0;
const NFQNL_MSG_VERDICT: u16 = 1;
const NFQNL_MSG_CONFIG: u16 = 2;
const NFQA_PACKET_HDR: u16 = 1;
const NFQA_VERDICT_HDR: u16 = 2;
const NFQA_PAYLOAD: u16 = 10;
const NFQA_CT: u16 = 11;
const NFQA_CFG_CMD: u16 = 1;
const NFQA_CFG_PARAMS: u16 = 2;
const NFQA_CFG_QUEUE_MAXLEN: u16 = 3;
const NFQA_CFG_MASK: u16 = 4;
const NFQA_CFG_FLAGS: u16 = 5;
/// `NFQA_CFG_F_FAIL_OPEN`: the queue full, packets go on instead of
/// being dropped.
pub const F_FAIL_OPEN: u32 = 1;
/// `NFQA_CFG_F_CONNTRACK`: each packet comes with its connection
/// (`NFQA_CT`), both tuples as the NAT left them.
pub const F_CONNTRACK: u32 = 2;
const NFQNL_CFG_CMD_BIND: u8 = 1;
const NFQNL_COPY_PACKET: u8 = 2;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const AF_INET: u16 = 2;
/// The bytes of each packet we look at: the IPv4 header.
pub const COPY_RANGE: u32 = 20;
/// The bytes kept of a packet that may be refused with an ICMP error: what
/// RFC 1812 §4.3.2.3 lets the error quote (576 bytes in all).
pub const COPY_QUOTE: u32 = 548;
/// Packets one exhaustion queue holds at most (the kernel's limit;
/// [`F_FAIL_OPEN`] lets the rest go on).
pub const MAXLEN: u32 = 4096;
pub const NF_DROP: u32 = 0;
pub const NF_ACCEPT: u32 = 1;

fn msg(
    kind: u16,
    flags: u16,
    family: u8,
    res_id: u16,
    seq: u32,
    attrs: &[(u16, Vec<u8>)],
) -> Vec<u8> {
    let mut b = Vec::with_capacity(64);
    b.extend_from_slice(&0u32.to_ne_bytes());
    b.extend_from_slice(&((NFNL_SUBSYS_QUEUE << 8) | kind).to_ne_bytes());
    b.extend_from_slice(&(NLM_F_REQUEST | flags).to_ne_bytes());
    b.extend_from_slice(&seq.to_ne_bytes());
    b.extend_from_slice(&0u32.to_ne_bytes());
    b.push(family);
    b.push(0);
    b.extend_from_slice(&res_id.to_be_bytes());
    for (kind, data) in attrs {
        let len = u16::try_from(4 + data.len()).unwrap_or(u16::MAX);
        b.extend_from_slice(&len.to_ne_bytes());
        b.extend_from_slice(&kind.to_ne_bytes());
        b.extend_from_slice(data);
        b.resize(b.len().div_ceil(4) * 4, 0);
    }
    let len = u32::try_from(b.len()).unwrap_or(u32::MAX);
    if let Some(slot) = b.get_mut(..4) {
        slot.copy_from_slice(&len.to_ne_bytes());
    }
    b
}

/// Bind to queue `num` (IPv4).
pub fn bind_request(num: u16, seq: u32) -> Vec<u8> {
    let mut cmd = vec![NFQNL_CFG_CMD_BIND, 0];
    cmd.extend_from_slice(&AF_INET.to_be_bytes());
    msg(
        NFQNL_MSG_CONFIG,
        NLM_F_ACK,
        0,
        num,
        seq,
        &[(NFQA_CFG_CMD, cmd)],
    )
}

/// Copy the first [`COPY_RANGE`] bytes of each packet.
pub fn params_request(num: u16, seq: u32) -> Vec<u8> {
    let mut p = COPY_RANGE.to_be_bytes().to_vec();
    p.push(NFQNL_COPY_PACKET);
    msg(
        NFQNL_MSG_CONFIG,
        NLM_F_ACK,
        0,
        num,
        seq,
        &[(NFQA_CFG_PARAMS, p)],
    )
}

/// Copy the first `copy` bytes of each packet.
pub fn params_request_with(num: u16, seq: u32, copy: u32) -> Vec<u8> {
    let mut p = copy.to_be_bytes().to_vec();
    p.push(NFQNL_COPY_PACKET);
    msg(
        NFQNL_MSG_CONFIG,
        NLM_F_ACK,
        0,
        num,
        seq,
        &[(NFQA_CFG_PARAMS, p)],
    )
}

/// Set `flags` (and the queue's length) on queue `num`.
pub fn flags_request(num: u16, seq: u32, flags: u32, maxlen: u32) -> Vec<u8> {
    msg(
        NFQNL_MSG_CONFIG,
        NLM_F_ACK,
        0,
        num,
        seq,
        &[
            (NFQA_CFG_QUEUE_MAXLEN, maxlen.to_be_bytes().to_vec()),
            (NFQA_CFG_FLAGS, flags.to_be_bytes().to_vec()),
            (NFQA_CFG_MASK, flags.to_be_bytes().to_vec()),
        ],
    )
}

pub fn verdict_request(num: u16, id: u32, accept: bool) -> Vec<u8> {
    let mut v = (if accept { NF_ACCEPT } else { NF_DROP })
        .to_be_bytes()
        .to_vec();
    v.extend_from_slice(&id.to_be_bytes());
    msg(NFQNL_MSG_VERDICT, 0, 0, num, 0, &[(NFQA_VERDICT_HDR, v)])
}

/// The packets of one `recv` buffer: (id, IPv4 source).
pub fn packets(buf: &[u8]) -> Vec<(u32, Option<Ipv4Addr>)> {
    let mut out = Vec::new();
    let mut rest = buf;
    while let Some(hdr) = rest.get(..16) {
        let len = hdr
            .get(..4)
            .and_then(|b| b.try_into().ok())
            .map_or(0, u32::from_ne_bytes);
        let kind = hdr
            .get(4..6)
            .and_then(|b| b.try_into().ok())
            .map_or(0, u16::from_ne_bytes);
        let len = usize::try_from(len).unwrap_or(0);
        if len < 20 {
            break;
        }
        let Some(m) = rest.get(..len) else { break };
        rest = rest.get(len.div_ceil(4) * 4..).unwrap_or(&[]);
        if kind != ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET) {
            continue;
        }
        let body = m.get(20..).unwrap_or(&[]);
        let Some(id) = find(attrs(body), NFQA_PACKET_HDR)
            .and_then(|a| a.data.get(..4).and_then(|b| b.try_into().ok()))
            .map(u32::from_be_bytes)
        else {
            continue;
        };
        let src = find(attrs(body), NFQA_PAYLOAD).and_then(|a| {
            let ip = a.data;
            (ip.first().map(|v| v >> 4) == Some(4))
                .then(|| {
                    ip.get(12..16)
                        .and_then(|b| <[u8; 4]>::try_from(b).ok())
                        .map(Ipv4Addr::from)
                })
                .flatten()
        });
        out.push((id, src));
    }
    out
}

/// One queued packet with what came along.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet<'a> {
    pub id: u32,
    /// The first bytes of the packet (as it is at the hook: after the NAT
    /// in postrouting).
    pub payload: &'a [u8],
    /// Its connection, when the queue asked for it ([`F_CONNTRACK`]).
    pub ct: Option<corerouter_hal::conntrack::Conn>,
}

/// The packets of one `recv` buffer with payload and connection; hostile
/// or truncated messages yield nothing, never a panic.
pub fn packets_with(buf: &[u8]) -> Vec<Packet<'_>> {
    let mut out = Vec::new();
    let mut rest = buf;
    while let Some(hdr) = rest.get(..16) {
        let len = hdr
            .get(..4)
            .and_then(|b| b.try_into().ok())
            .map_or(0, u32::from_ne_bytes);
        let kind = hdr
            .get(4..6)
            .and_then(|b| b.try_into().ok())
            .map_or(0, u16::from_ne_bytes);
        let len = usize::try_from(len).unwrap_or(0);
        if len < 20 {
            break;
        }
        let Some(m) = rest.get(..len) else { break };
        rest = rest.get(len.div_ceil(4) * 4..).unwrap_or(&[]);
        if kind != ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET) {
            continue;
        }
        let body = m.get(20..).unwrap_or(&[]);
        let Some(id) = find(attrs(body), NFQA_PACKET_HDR)
            .and_then(|a| a.data.get(..4).and_then(|b| b.try_into().ok()))
            .map(u32::from_be_bytes)
        else {
            continue;
        };
        let payload = find(attrs(body), NFQA_PAYLOAD).map_or(&[][..], |a| a.data);
        let ct = find(attrs(body), NFQA_CT).and_then(|a| crate::ctnl::parse_conn(a.data));
        out.push(Packet { id, payload, ct });
    }
    out
}

/// The IPv4 source of a packet's first bytes.
pub fn ipv4_source(payload: &[u8]) -> Option<Ipv4Addr> {
    (payload.first().map(|v| v >> 4) == Some(4))
        .then(|| {
            payload
                .get(12..16)
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .map(Ipv4Addr::from)
        })
        .flatten()
}

#[cfg(target_os = "linux")]
pub use io::{Bound, Queue};

#[cfg(target_os = "linux")]
mod io {
    use std::collections::{HashMap, VecDeque};
    use std::os::fd::AsFd;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use corerouter_hal::HalError;
    use corerouter_hal::cgnat::{CgnatQueue, Exhaustion, Pending};
    use netlink_sys::{Socket, protocols::NETLINK_NETFILTER};
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

    fn io(e: impl std::fmt::Display) -> HalError {
        HalError::Io(format!("netfilter queue: {e}"))
    }

    /// A socket bound to one queue: receive packets, give verdicts.
    pub struct Bound {
        sock: Socket,
        num: u16,
        buf: Vec<u8>,
    }

    impl Bound {
        /// Bind to queue `num`, copying `copy` bytes of each packet, with
        /// `flags` ([`super::F_CONNTRACK`], [`super::F_FAIL_OPEN`]) if any.
        pub fn open(num: u16, copy: u32, flags: u32) -> Result<Self, HalError> {
            let mut sock = Socket::new(NETLINK_NETFILTER).map_err(io)?;
            sock.bind_auto().map_err(io)?;
            let mut q = Self {
                sock,
                num,
                buf: vec![0u8; 1 << 16],
            };
            let mut reqs = vec![
                (1, super::bind_request(num, 1)),
                (2, super::params_request_with(num, 2, copy)),
            ];
            if flags != 0 {
                reqs.push((3, super::flags_request(num, 3, flags, super::MAXLEN)));
            }
            for (seq, req) in reqs {
                q.sock.send(&req, 0).map_err(io)?;
                q.ack(seq)?;
            }
            Ok(q)
        }

        pub fn num(&self) -> u16 {
            self.num
        }

        /// Wait for the ACK of `seq` (a refusal is the error: another
        /// program owns the queue, or no CAP_NET_ADMIN).
        fn ack(&mut self, seq: u32) -> Result<(), HalError> {
            for _ in 0..16 {
                let mut fds = [PollFd::new(self.sock.as_fd(), PollFlags::POLLIN)];
                if poll(&mut fds, PollTimeout::from(1000u16)).map_err(io)? == 0 {
                    return Err(HalError::Io(
                        "netfilter queue: no answer to the bind".into(),
                    ));
                }
                let n = self.sock.recv(&mut &mut self.buf[..], 0).map_err(io)?;
                let mut rest = self.buf.get(..n).unwrap_or(&[]);
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
                    if kind == 2 && mseq == seq {
                        let code = rest
                            .get(16..20)
                            .and_then(|b| b.try_into().ok())
                            .map_or(0, i32::from_ne_bytes);
                        return if code == 0 {
                            Ok(())
                        } else {
                            Err(HalError::Rejected(format!(
                                "netfilter queue {}: {}",
                                self.num,
                                std::io::Error::from_raw_os_error(code.saturating_neg())
                            )))
                        };
                    }
                    rest = rest.get(len.div_ceil(4) * 4..).unwrap_or(&[]);
                }
            }
            Err(HalError::Io("netfilter queue: no ACK".into()))
        }

        /// Wait at most `wait` for packets; the received bytes (parse them
        /// with [`super::packets_with`]), empty when none came.
        pub fn recv(&mut self, wait: Duration) -> Result<&[u8], HalError> {
            let ms = u16::try_from(wait.as_millis()).unwrap_or(u16::MAX);
            let mut fds = [PollFd::new(self.sock.as_fd(), PollFlags::POLLIN)];
            if poll(&mut fds, PollTimeout::from(ms)).map_err(io)? == 0 {
                return Ok(&[]);
            }
            let n = self.sock.recv(&mut &mut self.buf[..], 0).map_err(io)?;
            Ok(self.buf.get(..n).unwrap_or(&[]))
        }

        pub fn verdict(&self, id: u32, accept: bool) -> Result<(), HalError> {
            self.sock
                .send(&super::verdict_request(self.num, id, accept), 0)
                .map(|_| ())
                .map_err(io)
        }
    }

    /// The blocks queue (G2.3c): first packets of subscribers without a
    /// block. Keeps each held packet's first bytes so a refusal can quote
    /// it in the ICMP (G2.7).
    pub struct Queue {
        bound: Bound,
        ready: VecDeque<Pending>,
        heads: HashMap<u32, Vec<u8>>,
        icmp: Option<(Arc<Exhaustion>, Option<crate::cgnat_icmp::Sender>)>,
        clock: Instant,
    }

    impl Queue {
        pub fn open(num: u16) -> Result<Self, HalError> {
            Ok(Self {
                bound: Bound::open(num, super::COPY_QUOTE, 0)?,
                ready: VecDeque::new(),
                heads: HashMap::new(),
                icmp: None,
                clock: Instant::now(),
            })
        }

        /// Refusals answer with ICMP within `shared`'s limits.
        pub fn with_icmp(mut self, shared: Arc<Exhaustion>) -> Self {
            let sender = crate::cgnat_icmp::Sender::open()
                .map_err(|e| log::warn!("cgnat: no ICMP for refused subscribers: {e}"))
                .ok();
            self.icmp = Some((shared, sender));
            self
        }
    }

    impl CgnatQueue for Queue {
        fn recv(&mut self, wait: Duration) -> Result<Option<Pending>, HalError> {
            if let Some(p) = self.ready.pop_front() {
                return Ok(Some(p));
            }
            let mut pass = Vec::new();
            for p in super::packets_with(self.bound.recv(wait)?) {
                match super::ipv4_source(p.payload) {
                    Some(subscriber) => {
                        self.ready.push_back(Pending { id: p.id, subscriber });
                        if self.icmp.is_some() {
                            self.heads.insert(p.id, p.payload.to_vec());
                        }
                    }
                    // Not IPv4 or unreadable: let it go (it is no CGNAT
                    // subscriber of ours).
                    None => pass.push(p.id),
                }
            }
            for id in pass {
                self.bound.verdict(id, true)?;
            }
            Ok(self.ready.pop_front())
        }

        fn verdict(&mut self, id: u32, accept: bool) -> Result<(), HalError> {
            self.heads.remove(&id);
            // Bounded by the queue: ids the daemon never answered.
            if self.heads.len() > 4096 {
                self.heads.clear();
            }
            self.bound.verdict(id, accept)
        }

        fn refuse(&mut self, id: u32) -> Result<bool, HalError> {
            let head = self.heads.remove(&id);
            self.bound.verdict(id, false)?;
            let (Some((shared, sender)), Some(head)) = (self.icmp.as_mut(), head) else {
                return Ok(false);
            };
            let Some(sub) = super::ipv4_source(&head) else {
                return Ok(false);
            };
            let ms = u64::try_from(self.clock.elapsed().as_millis()).unwrap_or(u64::MAX);
            if !shared.refused(sub, ms) {
                return Ok(false);
            }
            // Before the NAT: the packet is as the subscriber sent it.
            let Some(sender) = sender.as_mut() else { return Ok(false) };
            let Some(msg) = crate::cgnat_icmp::unreachable(&head, sub, None) else {
                return Ok(false);
            };
            match sender.send(sub, &msg) {
                Ok(()) => {
                    shared.sent(sub);
                    Ok(true)
                }
                Err(e) => {
                    log::debug!("cgnat: ICMP to {sub}: {e}");
                    Ok(false)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// A packet message as the kernel sends it.
    fn packet(id: u32, src: [u8; 4]) -> Vec<u8> {
        let mut hdr = id.to_be_bytes().to_vec();
        hdr.extend_from_slice(&0x0800u16.to_be_bytes());
        hdr.push(4);
        let mut ip = vec![0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0];
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&[192, 0, 2, 2]);
        msg(
            NFQNL_MSG_PACKET,
            0,
            2,
            7422,
            0,
            &[(NFQA_PACKET_HDR, hdr), (NFQA_PAYLOAD, ip)],
        )
    }

    #[test]
    fn packets_give_their_id_and_source() {
        let mut buf = packet(7, [100, 64, 0, 9]);
        buf.extend(packet(8, [100, 64, 0, 10]));
        assert_eq!(
            packets(&buf),
            [
                (7, Some(Ipv4Addr::new(100, 64, 0, 9))),
                (8, Some(Ipv4Addr::new(100, 64, 0, 10)))
            ]
        );
        // A verdict carries the id big-endian after the verdict.
        let v = verdict_request(7422, 7, true);
        assert_eq!(&v[v.len() - 8..], &[0, 0, 0, 1, 0, 0, 0, 7]);
        assert_eq!(
            u16::from_be_bytes([v[18], v[19]]),
            7422,
            "res_id is the queue"
        );
    }

    proptest! {
        #[test]
        fn hostile_bytes_never_panic(junk in proptest::collection::vec(any::<u8>(), 0..300)) {
            let _ = packets(&junk);
        }
    }
}
