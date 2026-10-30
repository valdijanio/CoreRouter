//! The kernel's link list, read lean (G1.3f): one `RTM_GETLINK` dump on a
//! plain netlink socket, and of each `RTM_NEWLINK` only the attributes a
//! [`KernelLink`] keeps. The daemon reads it every second, and a BNG has a
//! `ppp` link per subscriber: `rtnetlink` decodes every attribute of every
//! link (the `IFLA_AF_SPEC` tables, the queues, the XDP state), and its
//! parser formats each link's counters as text on the way, error or not
//! (`format!("… {payload:?}")`, netlink-packet-route 0.33.0
//! `src/link/attribute.rs:674` and `:684`; upstream PR
//! rust-netlink/netlink-packet-route#298). 10 000 links took 194–271 ms
//! that way (**medido**, see `docs/changes/G1.3f.md`).
//!
//! The parser is pure and hostile-input safe (proptest below); the socket
//! is Linux only. `apply` and the interface dialog still use `rtnetlink`.

use crate::owner::KernelLink;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const RTM_NEWLINK: u16 = 16;
/// `NLM_F_DUMP_INTR`: the list changed while the kernel was sending it.
const NLM_F_DUMP_INTR: u16 = 0x10;
const NLMSG_HDR: usize = 16;
/// `struct ifinfomsg`.
const IFINFOMSG: usize = 16;
const IFNAMSIZ: usize = 16;

const IFLA_ADDRESS: u16 = 1;
const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_MASTER: u16 = 10;
const IFLA_OPERSTATE: u16 = 16;
const IFLA_LINKINFO: u16 = 18;
const IFLA_STATS64: u16 = 23;
const IFLA_LINK_NETNSID: u16 = 37;
const IFLA_PARENT_DEV_BUS_NAME: u16 = 57;
const IFLA_INFO_KIND: u16 = 1;
/// The type bits of `nla_type` (no `NLA_F_NESTED`, `NLA_F_NET_BYTEORDER`).
const NLA_TYPE_MASK: u16 = 0x3fff;

const IFF_UP: u32 = 0x1;
const IFF_LOWER_UP: u32 = 0x1_0000;
const IF_OPER_UNKNOWN: u8 = 0;
const IF_OPER_UP: u8 = 6;

/// Links per dump at most (a hostile or broken kernel answer stops here).
pub const MAX_LINKS: usize = 65_536;

/// What one `recv` of a dump said.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Part {
    /// More messages follow.
    More,
    /// `NLMSG_DONE`; `true` when the kernel marked the dump interrupted.
    Done { interrupted: bool },
    /// `NLMSG_ERROR` with this errno.
    Error(i32),
}

/// The `RTM_NEWLINK` messages of one `recv` of a dump, as [`KernelLink`]s
/// appended to `out`. Messages of another sequence, malformed ones and
/// links without a valid name are skipped; `interrupted` notes
/// `NLM_F_DUMP_INTR` on any of them.
pub fn parse(buf: &[u8], seq: u32, out: &mut Vec<KernelLink>, interrupted: &mut bool) -> Part {
    let mut rest = buf;
    while rest.len() >= NLMSG_HDR {
        let len = u32_at(rest, 0).unwrap_or(0) as usize;
        if len < NLMSG_HDR || len > rest.len() {
            return Part::More;
        }
        let kind = u16_at(rest, 4).unwrap_or(0);
        let flags = u16_at(rest, 6).unwrap_or(0);
        let mseq = u32_at(rest, 8).unwrap_or(0);
        let msg = rest.get(..len).unwrap_or(&[]);
        rest = rest.get(len.div_ceil(4) * 4..).unwrap_or(&[]);
        if mseq != seq {
            continue;
        }
        *interrupted |= flags & NLM_F_DUMP_INTR != 0;
        match kind {
            NLMSG_DONE => {
                return Part::Done {
                    interrupted: *interrupted,
                };
            }
            NLMSG_ERROR => {
                // `struct nlmsgerr`: a negative errno, then the request.
                let errno = msg
                    .get(NLMSG_HDR..NLMSG_HDR + 4)
                    .and_then(|b| b.try_into().ok())
                    .map_or(0, i32::from_ne_bytes);
                if errno != 0 {
                    return Part::Error(errno.saturating_neg());
                }
            }
            RTM_NEWLINK if out.len() < MAX_LINKS => {
                if let Some(l) = link(msg.get(NLMSG_HDR..).unwrap_or(&[])) {
                    out.push(l);
                }
            }
            _ => {}
        }
    }
    Part::More
}

/// One `RTM_NEWLINK` body (`ifinfomsg` and attributes), as the old
/// `rtnetlink` path read it (`netlink::kernel_link`).
fn link(body: &[u8]) -> Option<KernelLink> {
    let arphrd = u16_at(body, 2)?;
    let index = u32_at(body, 4)?;
    let flags = u32_at(body, 8)?;
    let mut l = KernelLink {
        index,
        arphrd,
        up: flags & IFF_UP != 0,
        ..KernelLink::default()
    };
    let mut oper = None;
    let mut named = false;
    for (kind, v) in attrs(body.get(IFINFOMSG..)?) {
        match kind {
            IFLA_IFNAME => {
                l.name = text(v, IFNAMSIZ)?;
                named = !l.name.is_empty();
            }
            IFLA_MTU => l.mtu = u32_at(v, 0).unwrap_or(0),
            IFLA_MASTER => l.master = u32_at(v, 0).filter(|m| *m != 0),
            IFLA_LINK_NETNSID => l.peer_elsewhere = true,
            IFLA_PARENT_DEV_BUS_NAME => l.bus = text(v, 33).filter(|b| !b.is_empty()),
            IFLA_OPERSTATE => oper = v.first().copied(),
            IFLA_ADDRESS => l.mac = mac_text(v),
            IFLA_STATS64 => {
                // `struct rtnl_link_stats64`; a short one reads as zeros,
                // like rtnetlink's `expand_buffer_if_small`.
                let c = |i: usize| u64_at(v, i * 8).unwrap_or(0);
                l.rx_packets = c(0);
                l.tx_packets = c(1);
                l.rx_bytes = c(2);
                l.tx_bytes = c(3);
                l.errors = Some(corerouter_hal::LinkErrors {
                    rx_errors: c(4),
                    tx_errors: c(5),
                    rx_dropped: c(6),
                    tx_dropped: c(7),
                });
            }
            IFLA_LINKINFO => {
                for (k, kv) in attrs(v) {
                    if k == IFLA_INFO_KIND {
                        l.kind = text(kv, 64).filter(|k| !k.is_empty());
                    }
                }
            }
            _ => {}
        }
    }
    if !named {
        return None;
    }
    // Like `ip link`: dummy/loopback report UNKNOWN but carry traffic while
    // up and with carrier (`IFF_LOWER_UP`).
    l.running = match oper {
        Some(IF_OPER_UP) => true,
        Some(IF_OPER_UNKNOWN) | None => l.up && flags & IFF_LOWER_UP != 0,
        Some(_) => false,
    };
    Some(l)
}

/// The `(type, value)` attributes of `buf`; stops at the first malformed one.
fn attrs(mut buf: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    std::iter::from_fn(move || {
        let len = usize::from(u16_at(buf, 0)?);
        let kind = u16_at(buf, 2)? & NLA_TYPE_MASK;
        if len < 4 || len > buf.len() {
            return None;
        }
        let v = buf.get(4..len)?;
        buf = buf.get(len.div_ceil(4) * 4..).unwrap_or(&[]);
        Some((kind, v))
    })
}

/// A NUL-terminated string of fewer than `max` bytes; `None` when it is
/// not UTF-8 or too long (rtnetlink refused the whole dump then).
fn text(v: &[u8], max: usize) -> Option<String> {
    let v = v.split(|b| *b == 0).next().unwrap_or(v);
    if v.len() >= max {
        return None;
    }
    std::str::from_utf8(v).ok().map(str::to_owned)
}

/// `AA:BB:CC:DD:EE:FF` for a non-zero 6-byte address.
pub(crate) fn mac_text(mac: &[u8]) -> Option<String> {
    use std::fmt::Write;
    if mac.len() != 6 || mac.iter().all(|b| *b == 0) {
        return None;
    }
    let mut s = String::with_capacity(17);
    for (i, b) in mac.iter().enumerate() {
        if i > 0 {
            s.push(':');
        }
        let _ = write!(s, "{b:02X}");
    }
    Some(s)
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_ne_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

#[cfg(target_os = "linux")]
pub use linux::{DUMPS, dump};

#[cfg(target_os = "linux")]
mod linux {
    use corerouter_hal::HalError;
    use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};

    use super::{IFINFOMSG, NLMSG_HDR, Part};
    use crate::owner::KernelLink;

    const RTM_GETLINK: u16 = 18;
    const NLM_F_REQUEST: u16 = 0x1;
    const NLM_F_DUMP: u16 = 0x300;
    /// A dump the kernel marked interrupted is read again this many times.
    const TRIES: usize = 3;
    /// One `recv`: the kernel fills up to the reader's buffer (32 KiB at
    /// first, more as `recvmsg` asks for more).
    const BUF: usize = 256 << 10;

    fn io(e: impl std::fmt::Display) -> HalError {
        HalError::Io(format!("listing links: {e}"))
    }

    /// Dumps read in this process (the netns test checks a tick reads one).
    pub static DUMPS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    /// Every link of the current network namespace.
    pub fn dump() -> Result<Vec<KernelLink>, HalError> {
        DUMPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut sock = Socket::new(NETLINK_ROUTE).map_err(io)?;
        sock.bind_auto().map_err(io)?;
        let mut buf = vec![0u8; BUF];
        let mut last = Vec::new();
        for seq in 1..=TRIES {
            let seq = u32::try_from(seq).unwrap_or(1);
            let (links, interrupted) = once(&sock, seq, &mut buf)?;
            if !interrupted {
                return Ok(links);
            }
            last = links;
        }
        // Still changing (links coming and going all the time): the last
        // list is as good as any; the next poll reads again.
        Ok(last)
    }

    fn once(sock: &Socket, seq: u32, buf: &mut [u8]) -> Result<(Vec<KernelLink>, bool), HalError> {
        let len = NLMSG_HDR + IFINFOMSG;
        let mut req = Vec::with_capacity(len);
        req.extend_from_slice(&u32::try_from(len).unwrap_or(0).to_ne_bytes());
        req.extend_from_slice(&RTM_GETLINK.to_ne_bytes());
        req.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
        req.extend_from_slice(&seq.to_ne_bytes());
        req.extend_from_slice(&0u32.to_ne_bytes());
        // `struct ifinfomsg`, AF_UNSPEC: every link.
        req.extend_from_slice(&[0u8; IFINFOMSG]);
        sock.send_to(&req, &SocketAddr::new(0, 0), 0).map_err(io)?;
        let mut out = Vec::new();
        let mut interrupted = false;
        loop {
            let n = sock.recv(&mut &mut buf[..], 0).map_err(io)?;
            if n == 0 {
                return Err(io("the kernel closed the dump"));
            }
            match super::parse(buf.get(..n).unwrap_or(&[]), seq, &mut out, &mut interrupted) {
                Part::More => {}
                Part::Done { interrupted } => return Ok((out, interrupted)),
                Part::Error(errno) => {
                    return Err(io(std::io::Error::from_raw_os_error(errno)));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn attr(kind: u16, v: &[u8]) -> Vec<u8> {
        let mut a = Vec::new();
        a.extend_from_slice(&u16::try_from(4 + v.len()).unwrap().to_ne_bytes());
        a.extend_from_slice(&kind.to_ne_bytes());
        a.extend_from_slice(v);
        while a.len() % 4 != 0 {
            a.push(0);
        }
        a
    }

    fn nlmsg(kind: u16, flags: u16, seq: u32, body: &[u8]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(&u32::try_from(NLMSG_HDR + body.len()).unwrap().to_ne_bytes());
        m.extend_from_slice(&kind.to_ne_bytes());
        m.extend_from_slice(&flags.to_ne_bytes());
        m.extend_from_slice(&seq.to_ne_bytes());
        m.extend_from_slice(&0u32.to_ne_bytes());
        m.extend_from_slice(body);
        while m.len() % 4 != 0 {
            m.push(0);
        }
        m
    }

    /// An `RTM_NEWLINK` of an Ethernet port as the kernel sends it.
    fn newlink(seq: u32, index: u32, name: &str, flags: u32, oper: u8) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&1u16.to_ne_bytes()); // ARPHRD_ETHER
        b.extend_from_slice(&index.to_ne_bytes());
        b.extend_from_slice(&flags.to_ne_bytes());
        b.extend_from_slice(&0u32.to_ne_bytes());
        let mut n = name.as_bytes().to_vec();
        n.push(0);
        b.extend(attr(IFLA_IFNAME, &n));
        b.extend(attr(IFLA_MTU, &1500u32.to_ne_bytes()));
        b.extend(attr(IFLA_MASTER, &7u32.to_ne_bytes()));
        b.extend(attr(IFLA_OPERSTATE, &[oper]));
        b.extend(attr(IFLA_ADDRESS, &[0x02, 0, 0, 0, 0, 0x0a]));
        b.extend(attr(IFLA_PARENT_DEV_BUS_NAME, b"usb\0"));
        let stats: Vec<u8> = (1..=24u64).flat_map(u64::to_ne_bytes).collect();
        b.extend(attr(IFLA_STATS64, &stats));
        // Nested: IFLA_LINKINFO { IFLA_INFO_KIND "vlan" }, NLA_F_NESTED set.
        b.extend(attr(
            IFLA_LINKINFO | 0x8000,
            &attr(IFLA_INFO_KIND, b"vlan\0"),
        ));
        nlmsg(RTM_NEWLINK, 0x2, seq, &b)
    }

    #[test]
    fn reads_what_a_kernel_link_keeps() {
        let mut buf = newlink(5, 3, "vlan10", IFF_UP | IFF_LOWER_UP, IF_OPER_UP);
        buf.extend(newlink(4, 9, "stale", 0, 0)); // another request's
        buf.extend(nlmsg(NLMSG_DONE, 0x2, 5, &0i32.to_ne_bytes()));
        let (mut out, mut intr) = (Vec::new(), false);
        assert_eq!(
            parse(&buf, 5, &mut out, &mut intr),
            Part::Done { interrupted: false }
        );
        let want = KernelLink {
            index: 3,
            name: "vlan10".into(),
            kind: Some("vlan".into()),
            arphrd: 1,
            master: Some(7),
            peer_elsewhere: false,
            mtu: 1500,
            up: true,
            running: true,
            mac: Some("02:00:00:00:00:0A".into()),
            rx_packets: 1,
            tx_packets: 2,
            rx_bytes: 3,
            tx_bytes: 4,
            errors: Some(corerouter_hal::LinkErrors {
                rx_errors: 5,
                tx_errors: 6,
                rx_dropped: 7,
                tx_dropped: 8,
            }),
            bus: Some("usb".into()),
        };
        assert_eq!(out, [want]);
    }

    #[test]
    fn running_follows_operstate_and_carrier() {
        let run = |flags, oper| {
            let (mut out, mut i) = (Vec::new(), false);
            parse(&newlink(1, 1, "d0", flags, oper), 1, &mut out, &mut i);
            out.first().unwrap().running
        };
        assert!(run(0, IF_OPER_UP));
        assert!(
            run(IFF_UP | IFF_LOWER_UP, IF_OPER_UNKNOWN),
            "dummy, loopback"
        );
        assert!(!run(IFF_UP, IF_OPER_UNKNOWN), "no carrier");
        assert!(!run(IFF_UP | IFF_LOWER_UP, 2), "IF_OPER_DOWN");
    }

    #[test]
    fn interrupted_and_errors_are_told() {
        let (mut out, mut intr) = (Vec::new(), false);
        let mut buf = newlink(2, 1, "a", 0, 0);
        buf[6] |= NLM_F_DUMP_INTR as u8;
        assert_eq!(parse(&buf, 2, &mut out, &mut intr), Part::More);
        let done = nlmsg(NLMSG_DONE, 0, 2, &0i32.to_ne_bytes());
        assert_eq!(
            parse(&done, 2, &mut out, &mut intr),
            Part::Done { interrupted: true }
        );
        let err = nlmsg(NLMSG_ERROR, 0, 2, &(-1i32).to_ne_bytes());
        assert_eq!(parse(&err, 2, &mut Vec::new(), &mut false), Part::Error(1));
    }

    #[test]
    fn truncated_messages_and_bad_names_are_skipped() {
        let m = newlink(1, 1, "ether1", 0, 0);
        for cut in 0..m.len() {
            let (mut out, mut i) = (Vec::new(), false);
            parse(m.get(..cut).unwrap(), 1, &mut out, &mut i);
            assert!(out.is_empty(), "cut at {cut}: {out:?}");
        }
        for bad in ["", "0123456789abcdef"] {
            let (mut out, mut i) = (Vec::new(), false);
            parse(&newlink(1, 1, bad, 0, 0), 1, &mut out, &mut i);
            assert!(out.is_empty(), "{bad:?}");
        }
    }

    proptest! {
        /// Hostile bytes never panic, never pass the cap, and every link
        /// read has a name the kernel could have given.
        #[test]
        fn parse_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..1024), seq: u32) {
            let (mut out, mut i) = (Vec::new(), false);
            let _ = parse(&bytes, seq, &mut out, &mut i);
            prop_assert!(out.len() <= MAX_LINKS);
            prop_assert!(out.iter().all(|l| !l.name.is_empty() && l.name.len() < IFNAMSIZ));
        }
    }
}
