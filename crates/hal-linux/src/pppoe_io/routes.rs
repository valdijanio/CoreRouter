//! The slow path's routes to `bng0` in batches (G4.3hh): many
//! `RTM_NEWROUTE`/`RTM_DELROUTE` per `sendmsg` on one blocking socket, the
//! way `mpls.rs` writes the label table.
//!
//! Only the last request of a send asks for an ACK. The kernel answers a
//! refused request anyway (`netlink_rcv_skb` acks on error) and handles a
//! socket's requests in order, so the last ACK means the whole send is
//! done and every refusal before it has arrived. That halves what comes
//! back next to one ACK per route (**medido** in `benches/netns_routes_batch.rs`).
//!
//! A refusal is tried once more, alone in a second pass; a send whose
//! answers were lost (`ENOBUFS` on our side) is sent again whole, which is
//! safe: an add is a replace and a removal of a route already gone is not
//! a refusal.

use std::io;
use std::net::IpAddr;
use std::os::fd::AsFd;
use std::time::{Duration, Instant};

use netlink_sys::{Socket, protocols::NETLINK_ROUTE};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;
const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_CREATE: u16 = 0x400;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_STATIC: u8 = 4;
const RTN_UNICAST: u8 = 1;
/// What `rtnetlink` answers a removal of a route that is not there.
const ESRCH: i32 = 3;
const ENOBUFS: i32 = 105;
/// One `sendmsg` at most (as `mpls::BATCH_BYTES`): ≈ 1400 IPv4 routes.
const BATCH_BYTES: usize = 64 << 10;
/// Room for the refusals of a whole send (each echoes its request).
const RCVBUF: usize = 4 << 20;
/// The kernel answers a send in milliseconds; this is a stuck kernel.
const DEADLINE: Duration = Duration::from_secs(10);

/// One route to the subscribers' device: `dst/len`, added or removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteOp {
    pub dst: IpAddr,
    pub len: u8,
    pub add: bool,
}

/// What [`RouteBatch::apply`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Applied {
    /// Requests the kernel took (the count checked at the end).
    pub done: usize,
    /// Requests that went a second time (refused or answers lost).
    pub retried: usize,
    /// Still refused after the second try: the op's index and the errno.
    pub refused: Vec<(usize, i32)>,
}

/// A blocking `NETLINK_ROUTE` socket of one worker for its routes to
/// `bng0` (the `ifindex` given).
pub struct RouteBatch {
    sock: Socket,
    ifindex: u32,
    buf: Vec<u8>,
    rbuf: Vec<u8>,
    seq: u32,
}

fn io_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("route netlink: {e}"))
}

impl RouteBatch {
    pub fn open(ifindex: u32) -> io::Result<Self> {
        let mut sock = Socket::new(NETLINK_ROUTE)?;
        sock.bind_auto()?;
        use nix::sys::socket::{setsockopt, sockopt};
        if setsockopt(&sock.as_fd(), sockopt::RcvBufForce, &RCVBUF).is_err() {
            let _ = setsockopt(&sock.as_fd(), sockopt::RcvBuf, &RCVBUF);
        }
        Ok(Self {
            sock,
            ifindex,
            buf: Vec::with_capacity(BATCH_BYTES + 128),
            rbuf: vec![0u8; 1 << 16],
            seq: 0x4247_0000,
        })
    }

    /// Apply `ops` in sends of up to [`BATCH_BYTES`], try the refused ones
    /// once more, and say how many the kernel took. An error is the socket
    /// itself failing; a refused route is in [`Applied::refused`].
    pub fn apply(&mut self, ops: &[RouteOp]) -> io::Result<Applied> {
        let mut out = Applied::default();
        let all: Vec<usize> = (0..ops.len()).collect();
        let again = self.pass(ops, &all, &mut out.done)?;
        out.retried = again.len();
        let idx: Vec<usize> = again.iter().map(|(i, _)| *i).collect();
        out.refused = self.pass(ops, &idx, &mut out.done)?;
        Ok(out)
    }

    /// Send the ops at `which`; the ones refused, with their errno.
    fn pass(
        &mut self,
        ops: &[RouteOp],
        which: &[usize],
        done: &mut usize,
    ) -> io::Result<Vec<(usize, i32)>> {
        let mut refused = Vec::new();
        let mut at = 0;
        while at < which.len() {
            let base = self.seq;
            self.buf.clear();
            let start = at;
            while let Some(&i) = which.get(at) {
                // The last of the send asks for the ACK (a request is ≤ 56 B).
                let last = at + 1 == which.len() || self.buf.len() + 2 * 64 >= BATCH_BYTES;
                let seq = base.wrapping_add(u32::try_from(at - start).unwrap_or(u32::MAX));
                match ops.get(i) {
                    Some(op) => push(&mut self.buf, op, self.ifindex, seq, last),
                    // Not an op: a request that removes nothing keeps the
                    // positions (never happens; `which` comes from `ops`).
                    None => return Err(io_err(format!("no route op {i}"))),
                }
                at += 1;
                if last {
                    break;
                }
            }
            let sent = at - start;
            let last_seq = base.wrapping_add(u32::try_from(sent.saturating_sub(1)).unwrap_or(0));
            self.seq = base.wrapping_add(u32::try_from(sent).unwrap_or(0));
            self.sock.send(&self.buf, 0).map_err(io_err)?;
            match self.answers(base, last_seq, sent)? {
                Some(errs) => {
                    let mut bad = 0;
                    for (k, code) in errs {
                        let Some(&i) = which.get(start + k) else {
                            continue;
                        };
                        let gone = code == ESRCH && ops.get(i).is_some_and(|o| !o.add);
                        if !gone {
                            refused.push((i, code));
                            bad += 1;
                        }
                    }
                    *done += sent - bad;
                }
                // Answers lost: the whole send goes again (idempotent).
                None => {
                    refused.extend(
                        which
                            .get(start..at)
                            .unwrap_or(&[])
                            .iter()
                            .map(|&i| (i, ENOBUFS)),
                    );
                }
            }
        }
        Ok(refused)
    }

    /// Read until the ACK of `last_seq`; the refusals by position in the
    /// send, or `None` when some answers were lost.
    fn answers(
        &mut self,
        base: u32,
        last_seq: u32,
        sent: usize,
    ) -> io::Result<Option<Vec<(usize, i32)>>> {
        let start = Instant::now();
        let mut errs = Vec::new();
        loop {
            let left = DEADLINE.saturating_sub(start.elapsed());
            if left.is_zero() {
                return Err(io_err("the kernel did not answer in time"));
            }
            let ms = u16::try_from(left.as_millis().min(1000)).unwrap_or(1000);
            let mut fds = [PollFd::new(self.sock.as_fd(), PollFlags::POLLIN)];
            if poll(&mut fds, PollTimeout::from(ms)).map_err(io_err)? == 0 {
                continue;
            }
            let n = match self.sock.recv(&mut &mut self.rbuf[..], 0) {
                Ok(n) => n,
                Err(e) if e.raw_os_error() == Some(ENOBUFS) => {
                    drain(&self.sock, &mut self.rbuf);
                    return Ok(None);
                }
                Err(e) => return Err(io_err(e)),
            };
            let mut rest = self.rbuf.get(..n).unwrap_or(&[]);
            let mut finished = false;
            while let Some((len, kind, seq)) = header(rest) {
                let msg = rest.get(..len).unwrap_or(rest);
                rest = rest.get(len.div_ceil(4) * 4..).unwrap_or(&[]);
                let k = seq.wrapping_sub(base) as usize;
                if kind != NLMSG_ERROR || k >= sent {
                    continue;
                }
                let code = msg
                    .get(16..20)
                    .and_then(|b| b.try_into().ok())
                    .map_or(0, i32::from_ne_bytes)
                    .saturating_neg();
                if code != 0 {
                    errs.push((k, code));
                }
                if seq == last_seq {
                    finished = true;
                }
            }
            if finished {
                return Ok(Some(errs));
            }
        }
    }
}

/// Throw away what is queued (after `ENOBUFS`, before sending again).
fn drain(sock: &Socket, buf: &mut [u8]) {
    for _ in 0..1024 {
        let mut fds = [PollFd::new(sock.as_fd(), PollFlags::POLLIN)];
        if !matches!(poll(&mut fds, PollTimeout::ZERO), Ok(n) if n > 0) {
            return;
        }
        if sock.recv(&mut &mut buf[..], 0).is_err() {
            return;
        }
    }
}

/// `(len, type, seq)` of the message at the start of `b`.
fn header(b: &[u8]) -> Option<(usize, u16, u32)> {
    let len = u32::from_ne_bytes(b.get(0..4)?.try_into().ok()?) as usize;
    let kind = u16::from_ne_bytes(b.get(4..6)?.try_into().ok()?);
    let seq = u32::from_ne_bytes(b.get(8..12)?.try_into().ok()?);
    (len >= 16 && len <= b.len()).then_some((len, kind, seq))
}

/// Append the request of `op` to `buf` (an ACK asked only when `ack`).
pub(crate) fn push(buf: &mut Vec<u8>, op: &RouteOp, ifindex: u32, seq: u32, ack: bool) {
    let at = buf.len();
    let (kind, mut flags) = if op.add {
        (RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE)
    } else {
        (RTM_DELROUTE, NLM_F_REQUEST)
    };
    if ack {
        flags |= NLM_F_ACK;
    }
    buf.extend_from_slice(&0u32.to_ne_bytes());
    buf.extend_from_slice(&kind.to_ne_bytes());
    buf.extend_from_slice(&flags.to_ne_bytes());
    buf.extend_from_slice(&seq.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes());
    let family = if op.dst.is_ipv4() { AF_INET } else { AF_INET6 };
    // family, dst_len, src_len, tos, table, protocol, scope, type, flags:
    // what `rtnetlink`'s builder sends (`SlowTx::prefixes`, the same route).
    buf.extend_from_slice(&[
        family,
        op.len,
        0,
        0,
        RT_TABLE_MAIN,
        RTPROT_STATIC,
        0,
        RTN_UNICAST,
    ]);
    buf.extend_from_slice(&0u32.to_ne_bytes());
    match op.dst {
        IpAddr::V4(a) => attr(buf, RTA_DST, &a.octets()),
        IpAddr::V6(a) => attr(buf, RTA_DST, &a.octets()),
    }
    attr(buf, RTA_OIF, &ifindex.to_ne_bytes());
    let len = u32::try_from(buf.len() - at)
        .unwrap_or(u32::MAX)
        .to_ne_bytes();
    if let Some(head) = buf.get_mut(at..at + 4) {
        head.copy_from_slice(&len);
    }
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn a_request_is_one_route_with_its_device() {
        let mut b = Vec::new();
        let op = RouteOp {
            dst: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9)),
            len: 32,
            add: true,
        };
        push(&mut b, &op, 7, 42, false);
        // header 16 + rtmsg 12 + RTA_DST 8 + RTA_OIF 8
        assert_eq!(b.len(), 44);
        assert_eq!(header(&b), Some((44, RTM_NEWROUTE, 42)));
        assert_eq!(
            u16::from_ne_bytes([b[6], b[7]]) & NLM_F_ACK,
            0,
            "no ACK but the last"
        );
        assert_eq!(&b[16..20], &[AF_INET, 32, 0, 0]);
        assert_eq!(&b[32..36], &[100, 64, 0, 9]);
        assert_eq!(u32::from_ne_bytes(b[40..44].try_into().unwrap()), 7);
        let mut c = Vec::new();
        let del = RouteOp {
            dst: IpAddr::V6(Ipv6Addr::LOCALHOST),
            len: 64,
            add: false,
        };
        push(&mut c, &del, 7, 43, true);
        assert_eq!(header(&c), Some((56, RTM_DELROUTE, 43)));
        assert_ne!(u16::from_ne_bytes([c[6], c[7]]) & NLM_F_ACK, 0);
    }

    #[test]
    fn hostile_answers_never_panic() {
        for junk in [
            &[][..],
            &[1, 2, 3][..],
            &[255; 40][..],
            &[16, 0, 0, 0, 2, 0][..],
        ] {
            let _ = header(junk);
        }
        assert_eq!(
            header(&[8, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            None,
            "len < header"
        );
    }
}
