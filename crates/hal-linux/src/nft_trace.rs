//! The packet trace (G2.1c): `meta nftrace` for one filter, and the
//! kernel's trace events, over nfnetlink (no `nft monitor trace`).
//!
//! - [`table`]: table `inet corerouter_trace` of our own, so a commit (which
//!   replaces `inet corerouter`) never touches it: chains at priority -301
//!   (before raw) on `prerouting` and `output` mark the packets that match
//!   the filter, at most [`RATE`] a second (`limit`, in the kernel: a flood
//!   that matches cannot flood the trace). Removed when the trace ends.
//! - [`parse_event`]: one `NFT_MSG_TRACE` (group `NFNLGRP_NFTRACE`): the
//!   table, chain and rule handle a marked packet went through, the
//!   verdict, the interfaces and the first bytes of its headers.
//!
//! Attribute numbers: `include/uapi/linux/netfilter/nf_tables.h`
//! (`NFTA_TRACE_*`, `nft_trace_types`). Pure and bounded; the socket half is
//! Linux-only.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use corerouter_firewall::program::{
    Base, Chain, ChainType, Expr, Family, Hook, MetaKey, REG_1, REG32_0, Rule, Table,
};

use crate::genl::{Attr, attrs, find};

/// Our trace table.
pub const TABLE: &str = "corerouter_trace";
/// Packets marked per second at most.
pub const RATE: u64 = 20;
/// `NFNLGRP_NFTRACE`.
pub const GROUP: u32 = 9;
const NFT_MSG_TRACE: u16 = 17;

const NFTA_TRACE_TABLE: u16 = 1;
const NFTA_TRACE_CHAIN: u16 = 2;
const NFTA_TRACE_RULE_HANDLE: u16 = 3;
const NFTA_TRACE_TYPE: u16 = 4;
const NFTA_TRACE_VERDICT: u16 = 5;
const NFTA_TRACE_ID: u16 = 6;
const NFTA_TRACE_NETWORK_HEADER: u16 = 8;
const NFTA_TRACE_TRANSPORT_HEADER: u16 = 9;
const NFTA_TRACE_IIF: u16 = 10;
const NFTA_TRACE_OIF: u16 = 12;
const NFTA_TRACE_NFPROTO: u16 = 15;
const NFTA_TRACE_POLICY: u16 = 16;
const NFTA_VERDICT_CODE: u16 = 1;
const NFTA_VERDICT_CHAIN: u16 = 2;

/// What to mark (a field `None` matches anything).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Match {
    /// `Some(false)` IPv4, `Some(true)` IPv6.
    pub v6: Option<bool>,
    /// Address and prefix length.
    pub src: Option<(IpAddr, u8)>,
    pub dst: Option<(IpAddr, u8)>,
    pub protocol: Option<u8>,
    pub dport: Option<u16>,
    pub iif: Option<String>,
}

fn addr_bytes(a: IpAddr) -> Vec<u8> {
    match a {
        IpAddr::V4(v) => v.octets().to_vec(),
        IpAddr::V6(v) => v.octets().to_vec(),
    }
}

fn mask(len: usize, prefix: u8) -> Vec<u8> {
    let bits = usize::from(prefix).min(len * 8);
    (0..len)
        .map(|i| {
            let take = bits.saturating_sub(i * 8).min(8);
            if take == 0 { 0 } else { 0xffu8 << (8 - take) }
        })
        .collect()
}

fn addr_match(out: &mut Vec<Expr>, text: &mut Vec<String>, what: &str, a: IpAddr, prefix: u8) {
    let v6 = a.is_ipv6();
    let (offset, len) = match (v6, what) {
        (false, "saddr") => (12, 4),
        (false, _) => (16, 4),
        (true, "saddr") => (8, 16),
        (true, _) => (24, 16),
    };
    out.push(Expr::Payload {
        base: Base::Network,
        offset,
        len,
        dreg: REG_1,
    });
    let full = usize::from(prefix) >= len as usize * 8;
    let bytes = addr_bytes(a);
    let m = mask(len as usize, prefix);
    if !full {
        out.push(Expr::And {
            sreg: REG_1,
            dreg: REG_1,
            mask: m.clone(),
        });
    }
    out.push(Expr::Cmp {
        sreg: REG_1,
        eq: true,
        data: bytes.iter().zip(&m).map(|(b, k)| b & k).collect(),
    });
    let fam = if v6 { "ip6" } else { "ip" };
    text.push(format!("{fam} {what} {a}/{prefix}"));
}

/// The rule that marks packets matching `m` (the `prerouting` one also
/// looks at the input interface).
fn mark_rule(chain: &str, m: &Match, incoming: bool) -> Rule {
    let mut e = Vec::new();
    let mut text = Vec::new();
    let v6 =
        m.v6.or(m.src.map(|(a, _)| a.is_ipv6()))
            .or(m.dst.map(|(a, _)| a.is_ipv6()));
    if let Some(v6) = v6 {
        e.push(Expr::Meta {
            key: MetaKey::NfProto,
            dreg: REG32_0,
        });
        e.push(Expr::Cmp {
            sreg: REG32_0,
            eq: true,
            data: vec![if v6 { 10 } else { 2 }],
        });
        text.push(format!("meta nfproto {}", if v6 { "ipv6" } else { "ipv4" }));
    }
    if incoming && let Some(i) = &m.iif {
        let mut name = i.as_bytes().iter().take(15).copied().collect::<Vec<u8>>();
        name.resize(16, 0);
        e.push(Expr::Meta {
            key: MetaKey::IifName,
            dreg: REG_1,
        });
        e.push(Expr::Cmp {
            sreg: REG_1,
            eq: true,
            data: name,
        });
        text.push(format!("iifname \"{i}\""));
    }
    if let Some((a, p)) = m.src {
        addr_match(&mut e, &mut text, "saddr", a, p);
    }
    if let Some((a, p)) = m.dst {
        addr_match(&mut e, &mut text, "daddr", a, p);
    }
    if let Some(proto) = m.protocol {
        e.push(Expr::Meta {
            key: MetaKey::L4Proto,
            dreg: REG32_0,
        });
        e.push(Expr::Cmp {
            sreg: REG32_0,
            eq: true,
            data: vec![proto],
        });
        text.push(format!("meta l4proto {proto}"));
    }
    if let Some(port) = m.dport {
        e.push(Expr::Payload {
            base: Base::Transport,
            offset: 2,
            len: 2,
            dreg: REG32_0,
        });
        e.push(Expr::Cmp {
            sreg: REG32_0,
            eq: true,
            data: port.to_be_bytes().to_vec(),
        });
        text.push(format!("th dport {port}"));
    }
    e.push(Expr::Limit {
        rate: RATE,
        unit_secs: 1,
        burst: 5,
    });
    e.push(Expr::Immediate {
        dreg: REG32_0,
        data: vec![1, 0, 0, 0],
    });
    e.push(Expr::MetaSet {
        key: MetaKey::NfTrace,
        sreg: REG32_0,
    });
    text.push(format!(
        "limit rate {RATE}/second burst 5 packets meta nftrace set 1"
    ));
    Rule {
        chain: chain.to_owned(),
        exprs: e,
        text: text.join(" "),
        nft: None,
    }
}

/// The trace table for `m`: chains `pre` (packets that arrive) and, when
/// no input interface is asked for, `out` (packets the router sends).
pub fn table(m: &Match) -> Table {
    let chain = |name: &str, hook| Chain {
        name: name.to_owned(),
        kind: ChainType::Filter,
        hook,
        priority: -301,
        priority_text: "raw - 1".into(),
    };
    let mut t = Table {
        family: Family::Inet,
        name: TABLE.to_owned(),
        chains: vec![chain("pre", Hook::Prerouting)],
        rules: vec![mark_rule("pre", m, true)],
        ..Table::default()
    };
    if m.iif.is_none() {
        t.chains.push(chain("out", Hook::Output));
        t.rules.push(mark_rule("out", m, false));
    }
    t
}

/// One trace event, as the kernel sends it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub id: u32,
    pub table: String,
    pub chain: String,
    pub handle: Option<u64>,
    /// `rule`, `return` or `policy`.
    pub kind: &'static str,
    /// `accept`, `drop`, `continue`, `jump <chain>`, `return`…
    pub verdict: String,
    pub iif: Option<u32>,
    pub oif: Option<u32>,
    pub src: Option<IpAddr>,
    pub dst: Option<IpAddr>,
    pub protocol: Option<u8>,
    pub sport: Option<u16>,
    pub dport: Option<u16>,
}

fn be32(a: &Attr<'_>) -> Option<u32> {
    Some(u32::from_be_bytes(a.data.get(..4)?.try_into().ok()?))
}

fn verdict_name(code: i32, chain: Option<String>) -> String {
    match (code, chain) {
        (0, _) => "drop".into(),
        (1, _) => "accept".into(),
        (2, _) => "stolen".into(),
        (3, _) => "queue".into(),
        (-1, _) => "continue".into(),
        (-2, _) => "break".into(),
        (-3, Some(c)) => format!("jump {c}"),
        (-4, Some(c)) => format!("goto {c}"),
        (-3, None) => "jump".into(),
        (-4, None) => "goto".into(),
        (-5, _) => "return".into(),
        (c, _) => format!("verdict {c}"),
    }
}

/// Addresses and protocol of a network header (`nfproto` 2 or 10).
fn network(h: &[u8], nfproto: Option<u32>) -> (Option<IpAddr>, Option<IpAddr>, Option<u8>) {
    let v4 = |at: usize| -> Option<IpAddr> {
        let b: [u8; 4] = h.get(at..at + 4)?.try_into().ok()?;
        Some(IpAddr::V4(Ipv4Addr::from(b)))
    };
    let v6 = |at: usize| -> Option<IpAddr> {
        let b: [u8; 16] = h.get(at..at + 16)?.try_into().ok()?;
        Some(IpAddr::V6(Ipv6Addr::from(b)))
    };
    let version = h.first().map(|b| b >> 4);
    match (nfproto, version) {
        (Some(10), _) | (None, Some(6)) => (v6(8), v6(24), h.get(6).copied()),
        _ if version == Some(4) => (v4(12), v4(16), h.get(9).copied()),
        _ => (None, None, None),
    }
}

/// One `NFT_MSG_TRACE` body (after `nfgenmsg`).
pub fn parse_event(kind: u16, body: &[u8]) -> Option<Event> {
    if kind != NFT_MSG_TRACE {
        return None;
    }
    let all = attrs(body);
    let s = |k| find(all.clone(), k).and_then(|a| a.str());
    let num = |k| find(all.clone(), k).as_ref().and_then(be32);
    let kind = match num(NFTA_TRACE_TYPE)? {
        1 => "policy",
        2 => "return",
        3 => "rule",
        _ => return None,
    };
    let verdict = if kind == "policy" {
        verdict_name(num(NFTA_TRACE_POLICY).map_or(1, |v| v as i32), None)
    } else {
        let v = find(all.clone(), NFTA_TRACE_VERDICT);
        let code = v
            .and_then(|v| find(v.nested(), NFTA_VERDICT_CODE))
            .as_ref()
            .and_then(be32)
            .map_or(-1, |c| c as i32);
        let chain = v
            .and_then(|v| find(v.nested(), NFTA_VERDICT_CHAIN))
            .and_then(|a| a.str());
        verdict_name(code, chain)
    };
    let nfproto = num(NFTA_TRACE_NFPROTO);
    let (src, dst, protocol) = find(all.clone(), NFTA_TRACE_NETWORK_HEADER)
        .map_or((None, None, None), |a| network(a.data, nfproto));
    let th = find(all.clone(), NFTA_TRACE_TRANSPORT_HEADER).map(|a| a.data);
    let port = |at: usize| {
        th.and_then(|t| t.get(at..at + 2))
            .and_then(|b| b.try_into().ok())
            .map(u16::from_be_bytes)
    };
    let ports = matches!(protocol, Some(6 | 17 | 132 | 136));
    Some(Event {
        id: num(NFTA_TRACE_ID)?,
        table: s(NFTA_TRACE_TABLE)?,
        chain: s(NFTA_TRACE_CHAIN)?,
        handle: find(all.clone(), NFTA_TRACE_RULE_HANDLE)
            .and_then(|a| Some(u64::from_be_bytes(a.data.get(..8)?.try_into().ok()?))),
        kind,
        verdict,
        iif: num(NFTA_TRACE_IIF),
        oif: num(NFTA_TRACE_OIF),
        src,
        dst,
        protocol,
        sport: if ports { port(0) } else { None },
        dport: if ports { port(2) } else { None },
    })
}

#[cfg(target_os = "linux")]
pub use io::{Listener, ifname};

#[cfg(target_os = "linux")]
mod io {
    use std::os::fd::AsFd;

    use corerouter_hal::HalError;
    use netlink_sys::{Socket, protocols::NETLINK_NETFILTER};
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

    use super::{Event, GROUP, parse_event};
    use crate::nft_counters::NFNL_SUBSYS_NFTABLES;

    fn io(e: impl std::fmt::Display) -> HalError {
        HalError::Io(format!("nftables trace: {e}"))
    }

    /// The name of interface `index` (trace events carry indexes).
    pub fn ifname(index: u32) -> Option<String> {
        let sock = std::net::UdpSocket::bind("127.0.0.1:0")
            .or_else(|_| std::net::UdpSocket::bind("[::1]:0"))
            .ok()?;
        rustix::net::netdevice::index_to_name(&sock, index).ok()
    }

    /// Subscribed to the kernel's trace events.
    pub struct Listener {
        sock: Socket,
        buf: Vec<u8>,
    }

    impl Listener {
        pub fn open() -> Result<Self, HalError> {
            let mut sock = Socket::new(NETLINK_NETFILTER).map_err(io)?;
            sock.bind_auto().map_err(io)?;
            use nix::sys::socket::{setsockopt, sockopt};
            if setsockopt(&sock.as_fd(), sockopt::RcvBufForce, &(1usize << 20)).is_err() {
                let _ = setsockopt(&sock.as_fd(), sockopt::RcvBuf, &(1usize << 20));
            }
            sock.add_membership(GROUP).map_err(io)?;
            sock.set_non_blocking(true).map_err(io)?;
            Ok(Self {
                sock,
                buf: vec![0u8; 1 << 16],
            })
        }

        /// Wait up to `wait_ms` and add up to `max` events to `out`.
        pub fn recv(
            &mut self,
            wait_ms: u16,
            max: usize,
            out: &mut Vec<Event>,
        ) -> Result<(), HalError> {
            let mut fds = [PollFd::new(self.sock.as_fd(), PollFlags::POLLIN)];
            if poll(&mut fds, PollTimeout::from(wait_ms)).map_err(io)? == 0 {
                return Ok(());
            }
            let start = out.len();
            while out.len() - start < max {
                let n = match self.sock.recv(&mut &mut self.buf[..], 0) {
                    Ok(n) => n,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    // ENOBUFS: we fell behind; the next datagrams still come.
                    Err(e) if e.raw_os_error() == Some(105) => continue,
                    Err(e) => return Err(io(e)),
                };
                let mut rest = self.buf.get(..n).unwrap_or(&[]);
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
                    if len < 16 {
                        break;
                    }
                    let msg = rest.get(..len).unwrap_or(rest);
                    rest = rest.get(len.div_ceil(4) * 4..).unwrap_or(&[]);
                    if kind >> 8 == NFNL_SUBSYS_NFTABLES
                        && let Some(e) = parse_event(kind & 0xff, msg.get(20..).unwrap_or(&[]))
                        && out.len() - start < max
                    {
                        out.push(e);
                    }
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn nla(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
        v.extend_from_slice(&kind.to_ne_bytes());
        v.extend_from_slice(data);
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v
    }

    fn event() -> Vec<u8> {
        let ip: Vec<u8> = [
            &[0x45, 0, 0, 60, 0, 0, 0x40, 0, 64, 6, 0, 0][..],
            &[203, 0, 113, 9],
            &[192, 0, 2, 1],
        ]
        .concat();
        let tcp = [0x9c, 0x40, 0, 22, 0, 0, 0, 0];
        [
            nla(NFTA_TRACE_TABLE, b"corerouter\0"),
            nla(NFTA_TRACE_CHAIN, b"filter_input\0"),
            nla(NFTA_TRACE_RULE_HANDLE, &7u64.to_be_bytes()),
            nla(NFTA_TRACE_TYPE, &3u32.to_be_bytes()),
            nla(
                NFTA_TRACE_VERDICT | 0x8000,
                &nla(NFTA_VERDICT_CODE, &0u32.to_be_bytes()),
            ),
            nla(NFTA_TRACE_ID, &0xdead_beefu32.to_be_bytes()),
            nla(NFTA_TRACE_NETWORK_HEADER, &ip),
            nla(NFTA_TRACE_TRANSPORT_HEADER, &tcp),
            nla(NFTA_TRACE_IIF, &3u32.to_be_bytes()),
            nla(NFTA_TRACE_NFPROTO, &2u32.to_be_bytes()),
        ]
        .concat()
    }

    #[test]
    fn a_rule_event_is_read() {
        let e = parse_event(NFT_MSG_TRACE, &event()).unwrap();
        assert_eq!(e.id, 0xdead_beef);
        assert_eq!(
            (e.table.as_str(), e.chain.as_str()),
            ("corerouter", "filter_input")
        );
        assert_eq!(
            (e.handle, e.kind, e.verdict.as_str()),
            (Some(7), "rule", "drop")
        );
        assert_eq!(e.src, Some("203.0.113.9".parse().unwrap()));
        assert_eq!(e.dst, Some("192.0.2.1".parse().unwrap()));
        assert_eq!(
            (e.protocol, e.sport, e.dport),
            (Some(6), Some(40_000), Some(22))
        );
        assert_eq!(e.iif, Some(3));
    }

    #[test]
    fn the_trace_table_matches_the_filter() {
        let m = Match {
            src: Some(("203.0.113.0".parse().unwrap(), 24)),
            protocol: Some(6),
            dport: Some(22),
            ..Match::default()
        };
        let t = table(&m);
        assert_eq!(t.name, TABLE);
        assert_eq!(t.chains.len(), 2, "pre and out");
        let r = &t.rules[0];
        assert!(r.text.contains("ip saddr 203.0.113.0/24"), "{}", r.text);
        assert!(r.text.contains("meta nftrace set 1"));
        assert!(
            r.exprs
                .iter()
                .any(|e| matches!(e, Expr::Limit { rate: RATE, .. }))
        );
        let with_iif = table(&Match {
            iif: Some("ether1".into()),
            ..m
        });
        assert_eq!(
            with_iif.chains.len(),
            1,
            "an input interface: arriving packets only"
        );
        assert_eq!(mask(4, 20), [255, 255, 240, 0]);
    }

    proptest! {
        #[test]
        fn hostile_events_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512), cut in 0usize..300) {
            let _ = parse_event(NFT_MSG_TRACE, &bytes);
            let e = event();
            let _ = parse_event(NFT_MSG_TRACE, e.get(..cut.min(e.len())).unwrap_or(&[]));
        }
    }
}
