//! The CGNAT fast path's bookkeeping (G2.5b), pure: which conntrack
//! connections go to the XDP flow map, as which two flow directions, and
//! when the kernel's timeout of a connection the fast path carries must be
//! renewed (conntrack sees none of those packets).
//!
//! The kernel stays in charge: a connection enters only after its NAT is
//! decided and both directions were seen (`ASSURED`; for TCP, also
//! `established`), leaves when conntrack destroys it, and SYN/FIN/RST
//! never take the fast path (`fastnat::admit`), so conntrack follows the
//! connection's life. The daemon's service (`xdp-nat`) drives this
//! through a [`NatLink`].

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use crate::HalError;
use crate::conntrack::{Conn, Event, EventKind, status};

/// One direction of a NATed connection: the 5-tuple as it arrives and
/// what it becomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NatFlow {
    pub proto: u8,
    pub src: (Ipv4Addr, u16),
    pub dst: (Ipv4Addr, u16),
    pub new_src: (Ipv4Addr, u16),
    pub new_dst: (Ipv4Addr, u16),
}

/// What the fast path did with a flow direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FlowUse {
    /// Last packet, monotonic nanoseconds (0: none yet).
    pub last_ns: u64,
    pub packets: u64,
}

/// Connections the fast path carries at most: the XDP flow map holds two
/// directions each (`dataplane-ebpf-common::maps::NAT_FLOWS_MAX`, checked
/// by a test in hal-linux). Past it, new ones stay in the kernel.
pub const MAX_CARRIED: usize = 1 << 18;

const TCP: u8 = 6;
const UDP: u8 = 17;
/// `TCP_CONNTRACK_ESTABLISHED`.
const ESTABLISHED: u8 = 3;

fn v4(a: IpAddr) -> Option<Ipv4Addr> {
    match a {
        IpAddr::V4(a) => Some(a),
        IpAddr::V6(_) => None,
    }
}

/// Whether the fast path should carry `c` now: IPv4 TCP/UDP with NAT
/// (source or destination), both directions seen, TCP established, not
/// dying.
pub fn offloadable(c: &Conn) -> bool {
    matches!(c.protocol, TCP | UDP)
        && c.has(status::ASSURED)
        && (c.has(status::SRC_NAT) || c.has(status::DST_NAT))
        && !c.has(status::DYING)
        && (c.protocol != TCP || c.tcp_state == Some(ESTABLISHED))
        && v4(c.orig.src).is_some()
        && v4(c.reply.src).is_some()
}

/// The two directions of `c`: what the subscriber sends (orig) and what
/// comes back (reply), each rewritten to the other's view. `None` when
/// not IPv4.
pub fn flows_of(c: &Conn) -> Option<[NatFlow; 2]> {
    let (o, r) = (&c.orig, &c.reply);
    let (os, od, rs, rd) = (v4(o.src)?, v4(o.dst)?, v4(r.src)?, v4(r.dst)?);
    Some([
        NatFlow {
            proto: c.protocol,
            src: (os, o.src_port),
            dst: (od, o.dst_port),
            new_src: (rd, r.dst_port),
            new_dst: (rs, r.src_port),
        },
        NatFlow {
            proto: c.protocol,
            src: (rs, r.src_port),
            dst: (rd, r.dst_port),
            new_src: (od, o.dst_port),
            new_dst: (os, o.src_port),
        },
    ])
}

/// What to do to the flow map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Install([NatFlow; 2]),
    Remove([NatFlow; 2]),
}

/// One carried connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Carried {
    pub conn: Conn,
    pub flows: [NatFlow; 2],
    /// Newest fast-path packet already reported to conntrack (ns).
    pub refreshed_ns: u64,
}

/// The connections the fast path carries, by `(protocol, orig tuple)`.
#[derive(Debug, Default)]
pub struct Book {
    carried: BTreeMap<(u8, NatFlow), Carried>,
    /// At most this many (the flow map holds two directions each).
    pub limit: usize,
}

fn id(flows: &[NatFlow; 2]) -> (u8, NatFlow) {
    let [o, _] = flows;
    (o.proto, *o)
}

impl Book {
    pub fn new(limit: usize) -> Self {
        Self {
            carried: BTreeMap::new(),
            limit,
        }
    }

    pub fn len(&self) -> usize {
        self.carried.len()
    }

    pub fn is_empty(&self) -> bool {
        self.carried.is_empty()
    }

    pub fn carried(&self) -> impl Iterator<Item = &Carried> {
        self.carried.values()
    }

    /// One conntrack event; what the map must do.
    pub fn event(&mut self, e: &Event) -> Option<Action> {
        let flows = flows_of(&e.conn)?;
        let key = id(&flows);
        match e.kind {
            EventKind::Destroy => self.carried.remove(&key).map(|c| Action::Remove(c.flows)),
            EventKind::New if offloadable(&e.conn) => {
                if let Some(c) = self.carried.get_mut(&key) {
                    // Same connection, new state (counters, timeout).
                    c.conn = e.conn.clone();
                    return None;
                }
                if self.carried.len() >= self.limit {
                    return None;
                }
                self.carried.insert(
                    key,
                    Carried {
                        conn: e.conn.clone(),
                        flows,
                        refreshed_ns: 0,
                    },
                );
                Some(Action::Install(flows))
            }
            // An update that makes it not offloadable (FIN seen: TCP left
            // established): back to the kernel for its last packets.
            EventKind::New => self.carried.remove(&key).map(|c| Action::Remove(c.flows)),
        }
    }

    /// After a full table read (startup, or events were lost): carry
    /// exactly the offloadable connections of `table` (up to the limit).
    pub fn resync(&mut self, table: &[Conn]) -> Vec<Action> {
        let want: BTreeMap<(u8, NatFlow), &Conn> = table
            .iter()
            .filter(|c| offloadable(c))
            .filter_map(|c| flows_of(c).map(|f| (id(&f), c)))
            .take(self.limit)
            .collect();
        let mut out = Vec::new();
        self.carried.retain(|k, c| {
            let keep = want.contains_key(k);
            if !keep {
                out.push(Action::Remove(c.flows));
            }
            keep
        });
        for (k, c) in want {
            if self.carried.contains_key(&k) {
                continue;
            }
            if let Some(flows) = flows_of(c) {
                self.carried.insert(
                    k,
                    Carried {
                        conn: c.clone(),
                        flows,
                        refreshed_ns: 0,
                    },
                );
                out.push(Action::Install(flows));
            }
        }
        out
    }

    /// The connections whose fast-path packets conntrack has not heard of
    /// yet, given each direction's use: their timeout must be renewed.
    /// Marks them refreshed.
    pub fn due(&mut self, uses: &dyn Fn(&NatFlow) -> Option<FlowUse>) -> Vec<Conn> {
        let mut out = Vec::new();
        for c in self.carried.values_mut() {
            let newest = c
                .flows
                .iter()
                .filter_map(uses)
                .map(|u| u.last_ns)
                .max()
                .unwrap_or(0);
            if newest > c.refreshed_ns {
                c.refreshed_ns = newest;
                out.push(c.conn.clone());
            }
        }
        out
    }

    /// Forget everything (the fast path went off; the map is gone).
    pub fn clear(&mut self) {
        self.carried.clear();
    }
}

/// How the daemon's service reaches the fast path and conntrack.
pub trait NatLink: Send {
    /// Which flow map is there now (`ip.firewall.xdp.set fast_nat=yes`
    /// with XDP attached), `None` while there is none. A new number is a
    /// new, empty map: forget what was installed and read the table again.
    fn generation(&self) -> Option<u64>;
    /// Conntrack events (new, updated, destroyed) arriving within
    /// `wait_ms`, at most `max`. A full socket buffer drops events: counted
    /// in [`NatLink::lost`], and the caller reads the table again.
    fn events(&mut self, wait_ms: u32, max: usize, out: &mut Vec<Event>) -> Result<(), HalError>;
    fn lost(&self) -> u64;
    /// The whole conntrack table.
    fn table(&mut self) -> Result<Vec<Conn>, HalError>;
    fn install(&mut self, flows: &[NatFlow]) -> Result<(), HalError>;
    fn remove(&mut self, flows: &[NatFlow]) -> Result<(), HalError>;
    fn used(&self, flow: &NatFlow) -> Option<FlowUse>;
    /// Renew the timeout of `conns` (each to its protocol's default for
    /// its state); how many the kernel still had.
    fn refresh(&mut self, conns: &[Conn]) -> Result<usize, HalError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conntrack::Tuple;

    fn conn(proto: u8, status_bits: u32, tcp: Option<u8>) -> Conn {
        let ip = |s: &str| -> IpAddr { s.parse().unwrap() };
        Conn {
            id: 1,
            protocol: proto,
            orig: Tuple {
                src: ip("100.64.0.2"),
                dst: ip("198.51.100.2"),
                src_port: 5000,
                dst_port: 443,
            },
            reply: Tuple {
                src: ip("198.51.100.2"),
                dst: ip("203.0.113.1"),
                src_port: 443,
                dst_port: 20000,
            },
            status: status_bits,
            timeout: 120,
            tcp_state: tcp,
            mark: 0,
            orig_packets: 0,
            orig_bytes: 0,
            reply_packets: 0,
            reply_bytes: 0,
        }
    }

    fn ev(kind: EventKind, c: Conn) -> Event {
        Event {
            kind,
            conn: c,
            start_ns: None,
            stop_ns: None,
        }
    }

    const NAT: u32 = status::ASSURED | status::SRC_NAT | status::CONFIRMED;

    #[test]
    fn directions_are_each_others_view() {
        let [out, back] = flows_of(&conn(TCP, NAT, Some(ESTABLISHED))).unwrap();
        assert_eq!(out.src, ("100.64.0.2".parse().unwrap(), 5000));
        assert_eq!(out.new_src, ("203.0.113.1".parse().unwrap(), 20000));
        assert_eq!(out.new_dst, ("198.51.100.2".parse().unwrap(), 443));
        assert_eq!(back.src, ("198.51.100.2".parse().unwrap(), 443));
        assert_eq!(back.dst, ("203.0.113.1".parse().unwrap(), 20000));
        assert_eq!(back.new_dst, ("100.64.0.2".parse().unwrap(), 5000));
    }

    #[test]
    fn only_assured_nat_tcp_established_or_udp() {
        assert!(offloadable(&conn(TCP, NAT, Some(ESTABLISHED))));
        assert!(offloadable(&conn(UDP, NAT, None)));
        assert!(!offloadable(&conn(TCP, NAT, Some(1))), "syn-sent");
        assert!(!offloadable(&conn(
            TCP,
            NAT & !status::ASSURED,
            Some(ESTABLISHED)
        )));
        assert!(!offloadable(&conn(UDP, status::ASSURED, None)), "no NAT");
        assert!(!offloadable(&conn(UDP, NAT | status::DYING, None)));
        assert!(!offloadable(&conn(1, NAT, None)), "ICMP");
    }

    #[test]
    fn lifecycle_new_update_destroy() {
        let mut b = Book::new(10);
        // Confirmed, not yet assured: nothing.
        assert_eq!(
            b.event(&ev(EventKind::New, conn(UDP, NAT & !status::ASSURED, None))),
            None
        );
        let c = conn(UDP, NAT, None);
        let flows = flows_of(&c).unwrap();
        assert_eq!(
            b.event(&ev(EventKind::New, c.clone())),
            Some(Action::Install(flows))
        );
        assert_eq!(b.event(&ev(EventKind::New, c.clone())), None, "once");
        // The fast path carried packets: the timeout is due, once.
        let uses = |f: &NatFlow| {
            (f == &flows[0]).then_some(FlowUse {
                last_ns: 50,
                packets: 3,
            })
        };
        assert_eq!(b.due(&uses).len(), 1);
        assert!(b.due(&uses).is_empty());
        assert_eq!(
            b.event(&ev(EventKind::Destroy, c)),
            Some(Action::Remove(flows))
        );
        assert!(b.is_empty());
    }

    #[test]
    fn tcp_leaving_established_goes_back_to_the_kernel() {
        let mut b = Book::new(10);
        let c = conn(TCP, NAT, Some(ESTABLISHED));
        let flows = flows_of(&c).unwrap();
        b.event(&ev(EventKind::New, c.clone()));
        let closing = Conn {
            tcp_state: Some(4),
            ..c
        };
        assert_eq!(
            b.event(&ev(EventKind::New, closing)),
            Some(Action::Remove(flows))
        );
    }

    #[test]
    fn resync_and_limit() {
        let mut b = Book::new(1);
        let a = conn(UDP, NAT, None);
        let mut other = conn(UDP, NAT, None);
        other.orig.src_port = 6000;
        let acts = b.resync(&[a.clone(), other.clone()]);
        assert_eq!(acts.len(), 1, "limit 1");
        assert_eq!(b.len(), 1);
        let gone = b.resync(&[]);
        assert_eq!(gone.len(), 1);
        assert!(matches!(gone[0], Action::Remove(_)));
    }
}
