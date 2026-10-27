//! The answer when a CGNAT subscriber's ports run out (G2.7, RFC 6888
//! REQ-11): the ICMP destination unreachable, code 1, and the exhaustion
//! queues that decide when to send it.
//!
//! The kernel's NAT never fails. With no free port in the subscriber's
//! slot it keeps a tuple already in use (`nf_nat_l4proto_unique_tuple`,
//! 128 + 64 + 32 + 16 tries from random offsets), and conntrack drops the
//! packet when it confirms the connection, after every hook, counting only
//! `insert_failed`. Neither an nftables `reject` (it never sees the
//! failure) nor XDP/TC (the drop happens inside netfilter) can answer.
//!
//! So the table sends, right after the NAT, the new connections of the few
//! subscribers near the end of their ports (set `full`, kept by the
//! engine) to [`EXHAUSTED_QUEUES`] queues, with `bypass`. Each queue thread
//! asks conntrack whether the reply tuple the NAT chose is taken (one
//! `IPCTNL_MSG_CT_GET`; the kernel hashes both directions of every
//! connection). Taken: the packet is dropped here (REQ-11a, what conntrack
//! would do) and the subscriber gets the ICMP within the limits of
//! [`Exhaustion`] (REQ-11b). Free: the packet goes on untouched.
//!
//! The ICMP quotes the packet as the subscriber sent it (RFC 792; as much
//! as fits in 576 bytes, RFC 1812 §4.3.2.3): the queue sees it after the
//! NAT, so the source address and port are put back from the connection's
//! original tuple, with the checksums adjusted (RFC 1624). Code 1 (host
//! unreachable) is a soft error (RFC 1122 §4.2.3.9): TCP keeps trying,
//! which is what RFC 6888 REQ-11 wants.
//!
//! [`EXHAUSTED_QUEUES`]: corerouter_hal::cgnat::EXHAUSTED_QUEUES
//! [`Exhaustion`]: corerouter_hal::cgnat::Exhaustion

use std::net::Ipv4Addr;

use corerouter_hal::icmp_ext::checksum;

const ICMP_UNREACH: u8 = 3;
/// RFC 792: host unreachable; RFC 6888 REQ-11b asks this one.
const CODE_HOST: u8 = 1;
/// RFC 1812 §4.3.2.3: the error, IP header included, fits in 576 bytes.
pub const MAX_QUOTE: usize = 576 - 20 - 8;

/// RFC 1624 eq. 3: the checksum `hc` after a 16-bit word went from `old` to
/// `new`.
fn adjust(hc: u16, old: u16, new: u16) -> u16 {
    let mut sum = u32::from(!hc) + u32::from(!old) + u32::from(new);
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn word(b: &[u8], at: usize) -> Option<u16> {
    b.get(at..at + 2)
        .and_then(|w| w.try_into().ok())
        .map(u16::from_be_bytes)
}

fn put(b: &mut [u8], at: usize, v: u16) {
    if let Some(w) = b.get_mut(at..at + 2) {
        w.copy_from_slice(&v.to_be_bytes());
    }
}

/// The ICMP destination unreachable (code 1) about `packet` (its first
/// bytes, IPv4), to send to `subscriber`. `original_port`: the source port
/// (or ICMP query id) the subscriber used, when the NAT changed it; the
/// source address is put back to `subscriber` either way.
///
/// `None` when no error may be sent about it (RFC 1812 §4.3.2.7): not
/// IPv4, truncated, a fragment other than the first, or itself an ICMP
/// error.
pub fn unreachable(
    packet: &[u8],
    subscriber: Ipv4Addr,
    original_port: Option<u16>,
) -> Option<Vec<u8>> {
    let first = *packet.first()?;
    if first >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(first & 0x0f) * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }
    let total = usize::from(word(packet, 2)?);
    let frag = word(packet, 6)?;
    if frag & 0x1fff != 0 {
        return None;
    }
    let proto = *packet.get(9)?;
    if proto == 1 && packet.get(ihl).is_some_and(|t| ![0, 8, 13, 14].contains(t)) {
        // An ICMP error (or anything but a query) never gets one back.
        return None;
    }
    let len = packet.len().min(total.max(ihl)).min(MAX_QUOTE);
    let mut quote = packet.get(..len)?.to_vec();

    // Put the source back as the subscriber sent it.
    let old_src = [word(&quote, 12)?, word(&quote, 14)?];
    let o = subscriber.octets();
    let new_src = [
        u16::from_be_bytes([o[0], o[1]]),
        u16::from_be_bytes([o[2], o[3]]),
    ];
    if let Some(s) = quote.get_mut(12..16) {
        s.copy_from_slice(&o);
    }
    put(&mut quote, 10, 0);
    let ip_sum = checksum(quote.get(..ihl)?);
    put(&mut quote, 10, ip_sum);

    let (port_at, sum_at, pseudo) = match proto {
        6 => (ihl, ihl + 16, true),
        17 => (ihl, ihl + 6, true),
        // ICMP query: the id, no pseudo-header (RFC 5508 §3.1).
        1 => (ihl + 4, ihl + 2, false),
        _ => (usize::MAX, usize::MAX, false),
    };
    if let Some(mut sum) = word(&quote, sum_at)
        && !(proto == 17 && sum == 0)
    {
        if pseudo {
            sum = adjust(sum, old_src[0], new_src[0]);
            sum = adjust(sum, old_src[1], new_src[1]);
        }
        if let (Some(new), Some(old)) = (original_port, word(&quote, port_at)) {
            sum = adjust(sum, old, new);
        }
        put(&mut quote, sum_at, sum);
    }
    if let (Some(new), Some(_)) = (original_port, word(&quote, port_at)) {
        put(&mut quote, port_at, new);
    }

    let mut msg = Vec::with_capacity(8 + quote.len());
    msg.extend_from_slice(&[ICMP_UNREACH, CODE_HOST, 0, 0, 0, 0, 0, 0]);
    msg.extend_from_slice(&quote);
    let sum = checksum(&msg);
    put(&mut msg, 2, sum);
    Some(msg)
}

#[cfg(target_os = "linux")]
pub use io::{ExhaustQueue, Sender};

#[cfg(target_os = "linux")]
mod io {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use corerouter_hal::HalError;
    use corerouter_hal::cgnat::{Exhaustion, ExhaustionQueue};
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};

    use crate::ctnl::Lookup;
    use crate::nfqueue::{self, Bound};

    /// A raw ICMP socket (`CAP_NET_RAW`): the kernel writes the IP header,
    /// with the source address of the route back to the subscriber (the
    /// router's inside address). Non-blocking: a full send buffer drops an
    /// ICMP, never stalls a queue thread.
    pub struct Sender(Socket);

    impl Sender {
        pub fn open() -> Result<Self, HalError> {
            let s = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
                .map_err(|e| HalError::Io(format!("raw ICMP socket: {e}")))?;
            s.set_nonblocking(true)
                .map_err(|e| HalError::Io(format!("raw ICMP socket: {e}")))?;
            Ok(Self(s))
        }

        pub fn send(&mut self, to: Ipv4Addr, msg: &[u8]) -> Result<(), HalError> {
            let to = SockAddr::from(SocketAddr::V4(SocketAddrV4::new(to, 0)));
            self.0
                .send_to(msg, &to)
                .map(|_| ())
                .map_err(|e| HalError::Io(format!("ICMP to the subscriber: {e}")))
        }
    }

    /// One exhaustion queue and what it needs to answer, owned by one
    /// daemon thread: its own queue socket, conntrack socket and ICMP
    /// socket; only the counters and limiter are shared.
    pub struct ExhaustQueue {
        bound: Bound,
        lookup: Lookup,
        sender: Option<Sender>,
        shared: Arc<Exhaustion>,
        clock: Instant,
        warned: bool,
    }

    impl ExhaustQueue {
        pub fn open(num: u16, shared: Arc<Exhaustion>) -> Result<Self, HalError> {
            let bound = Bound::open(
                num,
                nfqueue::COPY_QUOTE,
                nfqueue::F_CONNTRACK | nfqueue::F_FAIL_OPEN,
            )?;
            let sender = Sender::open()
                .map_err(|e| log::warn!("cgnat: no ICMP for subscribers out of ports: {e}"))
                .ok();
            Ok(Self {
                bound,
                lookup: Lookup::open()?,
                sender,
                shared,
                clock: Instant::now(),
                warned: false,
            })
        }

        /// Whether this connection's reply tuple is already someone's.
        fn clashes(&mut self, ct: &corerouter_hal::conntrack::Conn) -> bool {
            match self.lookup.taken(&ct.reply, ct.protocol) {
                Ok(t) => t,
                Err(e) => {
                    // Unsure: let the kernel decide, as without us.
                    if !self.warned {
                        log::warn!("cgnat: exhaustion queue {}: {e}", self.bound.num());
                        self.warned = true;
                    }
                    false
                }
            }
        }
    }

    impl ExhaustionQueue for ExhaustQueue {
        fn serve(&mut self, wait: Duration) -> Result<usize, HalError> {
            // Copy what the batch needs out of the receive buffer, which the
            // verdicts and lookups do not touch but the borrow does.
            let batch: Vec<(u32, Vec<u8>, Option<corerouter_hal::conntrack::Conn>)> =
                nfqueue::packets_with(self.bound.recv(wait)?)
                    .into_iter()
                    .map(|p| (p.id, p.payload.to_vec(), p.ct))
                    .collect();
            let n = batch.len();
            for (id, payload, ct) in batch {
                let Some(ct) = ct.filter(|c| c.reply.dst.is_ipv4()) else {
                    self.bound.verdict(id, true)?;
                    continue;
                };
                if !self.clashes(&ct) {
                    self.shared.passed();
                    self.bound.verdict(id, true)?;
                    continue;
                }
                self.bound.verdict(id, false)?;
                let IpAddr::V4(sub) = ct.orig.src else { continue };
                let ms = u64::try_from(self.clock.elapsed().as_millis()).unwrap_or(u64::MAX);
                if !self.shared.refused(sub, ms) {
                    continue;
                }
                let Some(sender) = self.sender.as_mut() else { continue };
                // The NAT changed the source port (or ICMP id): give back
                // the one the subscriber used.
                let port = matches!(ct.protocol, 6 | 17 | 1).then_some(ct.orig.src_port);
                let Some(msg) = super::unreachable(&payload, sub, port) else {
                    continue;
                };
                match sender.send(sub, &msg) {
                    Ok(()) => self.shared.sent(sub),
                    Err(e) => log::debug!("cgnat: {e}"),
                }
            }
            Ok(n)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// A UDP datagram 203.0.113.1:2100 → 192.0.2.2:53 (after the NAT), with
    /// a correct UDP checksum.
    fn udp_after_nat() -> Vec<u8> {
        let mut p = vec![
            0x45, 0, 0, 30, 0x12, 0x34, 0x40, 0, 64, 17, 0, 0, 203, 0, 113, 1, 192, 0, 2, 2,
        ];
        let s = checksum(&p);
        p[10..12].copy_from_slice(&s.to_be_bytes());
        p.extend_from_slice(&[0x08, 0x34, 0, 53, 0, 10, 0, 0, b'h', b'i']);
        let sum = l4_checksum(&p, 17);
        p[26..28].copy_from_slice(&sum.to_be_bytes());
        p
    }

    /// The checksum a fresh computation gives (pseudo-header included).
    fn l4_checksum(p: &[u8], proto: u8) -> u16 {
        let mut ph = Vec::new();
        ph.extend_from_slice(&p[12..20]);
        ph.extend_from_slice(&[0, proto]);
        let l4 = &p[20..];
        ph.extend_from_slice(&u16::try_from(l4.len()).unwrap().to_be_bytes());
        let mut seg = l4.to_vec();
        let at = if proto == 17 { 6 } else { 16 };
        seg[at..at + 2].copy_from_slice(&[0, 0]);
        ph.extend_from_slice(&seg);
        checksum(&ph)
    }

    #[test]
    fn the_quote_is_the_packet_the_subscriber_sent() {
        let p = udp_after_nat();
        let sub = Ipv4Addr::new(100, 64, 0, 1);
        let m = unreachable(&p, sub, Some(40000)).unwrap();
        // RFC 6888 REQ-11b: type 3, code 1, a valid ICMP checksum.
        assert_eq!(&m[..2], &[3, 1]);
        assert_eq!(checksum(&m), 0, "the whole message sums to zero");
        let q = &m[8..];
        assert_eq!(q.len(), p.len());
        assert_eq!(&q[12..16], &[100, 64, 0, 1], "the private source back");
        assert_eq!(checksum(&q[..20]), 0, "IP header checksum redone");
        assert_eq!(u16::from_be_bytes([q[20], q[21]]), 40000, "the original port");
        // RFC 1624: the incremental UDP checksum equals a fresh one.
        let fresh = l4_checksum(q, 17);
        assert_eq!(u16::from_be_bytes([q[26], q[27]]), fresh);
    }

    #[test]
    fn a_tcp_syn_keeps_a_correct_checksum() {
        let mut p = vec![
            0x45, 0, 0, 40, 0, 1, 0x40, 0, 64, 6, 0, 0, 203, 0, 113, 1, 192, 0, 2, 2,
        ];
        let s = checksum(&p);
        p[10..12].copy_from_slice(&s.to_be_bytes());
        p.extend_from_slice(&[
            0x08, 0x34, 0, 80, 0, 0, 0, 1, 0, 0, 0, 0, 0x50, 0x02, 0xff, 0xff, 0, 0, 0, 0,
        ]);
        let sum = l4_checksum(&p, 6);
        p[36..38].copy_from_slice(&sum.to_be_bytes());
        let m = unreachable(&p, Ipv4Addr::new(100, 64, 0, 9), Some(51000)).unwrap();
        let q = &m[8..];
        assert_eq!(u16::from_be_bytes([q[36], q[37]]), l4_checksum(q, 6));
    }

    #[test]
    fn no_error_about_errors_or_later_fragments() {
        let sub = Ipv4Addr::new(100, 64, 0, 1);
        let mut err = udp_after_nat();
        err[9] = 1;
        err[20] = 3;
        assert!(unreachable(&err, sub, None).is_none(), "ICMP error");
        let mut frag = udp_after_nat();
        frag[7] = 1;
        assert!(unreachable(&frag, sub, None).is_none(), "not the first fragment");
        assert!(unreachable(&[0x60, 0, 0, 0], sub, None).is_none(), "IPv6");
        assert!(unreachable(&[], sub, None).is_none());
        // An echo request does get one; its id goes back too.
        let mut echo = udp_after_nat();
        echo[9] = 1;
        echo[20] = 8;
        let m = unreachable(&echo, sub, Some(77)).unwrap();
        assert_eq!(u16::from_be_bytes([m[8 + 24], m[8 + 25]]), 77);
    }

    #[test]
    fn the_quote_stops_at_576_bytes() {
        let mut p = udp_after_nat();
        p[2..4].copy_from_slice(&1500u16.to_be_bytes());
        p.resize(1500, 0xab);
        let m = unreachable(&p, Ipv4Addr::new(100, 64, 0, 1), None).unwrap();
        assert_eq!(m.len() + 20, 576);
    }

    proptest! {
        #[test]
        fn hostile_bytes_never_panic(
            junk in proptest::collection::vec(any::<u8>(), 0..700),
            port in proptest::option::of(any::<u16>()),
        ) {
            let _ = unreachable(&junk, Ipv4Addr::new(100, 64, 0, 1), port);
        }
    }
}
