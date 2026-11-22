//! Rule counters of an nftables table over nfnetlink (G2.1c), without the
//! `nft` program: **one** dump request (`NFT_MSG_GETRULE` + `NLM_F_DUMP`
//! with the table's name) answers every rule of every chain, with its
//! handle, its comment (`cr:*N`, the CoreRouter rule) and the values of its
//! `counter` expression. The firewall's counters and the packet trace (to
//! map a rule handle to our rule) read it.
//!
//! The decoder is pure and bounded: a hostile or truncated message gives
//! fewer fields or no rule, never a panic. Numbers in nf_tables
//! attributes are big-endian; the netlink header is native-endian.
//! Attribute numbers: `include/uapi/linux/netfilter/nf_tables.h`; the
//! comment is libnftnl's user data (`NFTNL_UDATA_RULE_COMMENT`, TLV of
//! type u8, length u8, NUL-terminated text).

use crate::genl::{Attr, attrs};

pub const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFT_MSG_NEWRULE: u16 = 6;
const NFT_MSG_GETRULE: u16 = 7;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_DUMP: u16 = 0x300;
/// `NFPROTO_INET`.
pub const NFPROTO_INET: u8 = 1;

const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_HANDLE: u16 = 3;
const NFTA_RULE_EXPRESSIONS: u16 = 4;
const NFTA_RULE_USERDATA: u16 = 7;
const NFTA_LIST_ELEM: u16 = 1;
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;
const NFTA_COUNTER_BYTES: u16 = 1;
const NFTA_COUNTER_PACKETS: u16 = 2;
const NFTNL_UDATA_RULE_COMMENT: u8 = 0;

/// At most this many rules from one dump (a hostile kernel): every table
/// full (`MAX_RULES` each, G0.31j) with two kernel rules per rule.
pub const MAX_RULES: usize = corerouter_firewall::validate::MAX_RULES * 8;

/// One kernel rule, as far as counters need it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelRule {
    pub chain: String,
    pub handle: u64,
    pub comment: Option<String>,
    pub packets: u64,
    pub bytes: u64,
}

fn be64(a: &Attr<'_>) -> Option<u64> {
    Some(u64::from_be_bytes(a.data.get(..8)?.try_into().ok()?))
}

/// The dump request for `table` of family `family` (`seq` to match the
/// answers).
pub fn request(family: u8, table: &str, seq: u32) -> Vec<u8> {
    let name: Vec<u8> = table.bytes().take(255).chain(std::iter::once(0)).collect();
    let attr_len = 4 + name.len();
    let total = 16 + 4 + attr_len.div_ceil(4) * 4;
    let mut b = Vec::with_capacity(total);
    b.extend_from_slice(&(total as u32).to_ne_bytes());
    b.extend_from_slice(&((NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETRULE).to_ne_bytes());
    b.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    b.extend_from_slice(&seq.to_ne_bytes());
    b.extend_from_slice(&0u32.to_ne_bytes());
    // nfgenmsg: family, version 0, res_id 0 (big-endian).
    b.extend_from_slice(&[family, 0, 0, 0]);
    b.extend_from_slice(&(attr_len as u16).to_ne_bytes());
    b.extend_from_slice(&NFTA_RULE_TABLE.to_ne_bytes());
    b.extend_from_slice(&name);
    b.resize(total, 0);
    b
}

/// The comment in a rule's user data.
fn comment(udata: &[u8]) -> Option<String> {
    let mut rest = udata;
    while let (Some(kind), Some(len)) = (rest.first(), rest.get(1)) {
        let len = usize::from(*len);
        let value = rest.get(2..2 + len)?;
        if *kind == NFTNL_UDATA_RULE_COMMENT {
            let end = value.iter().position(|b| *b == 0).unwrap_or(value.len());
            return Some(String::from_utf8_lossy(value.get(..end)?).into_owned());
        }
        rest = rest.get(2 + len..)?;
    }
    None
}

/// A `NFT_MSG_NEWRULE` body (after `nfgenmsg`); `None` when it is not one
/// or has no chain. Rules without a counter count zero.
pub fn parse_rule(kind: u16, body: &[u8]) -> Option<KernelRule> {
    if kind != NFT_MSG_NEWRULE {
        return None;
    }
    let mut rule = KernelRule {
        chain: String::new(),
        handle: 0,
        comment: None,
        packets: 0,
        bytes: 0,
    };
    for a in attrs(body) {
        match a.kind {
            NFTA_RULE_CHAIN => rule.chain = a.str()?,
            NFTA_RULE_HANDLE => rule.handle = be64(&a)?,
            NFTA_RULE_USERDATA => rule.comment = comment(a.data),
            NFTA_RULE_EXPRESSIONS => {
                for elem in a.nested().filter(|e| e.kind == NFTA_LIST_ELEM) {
                    let mut name = None;
                    let mut data = None;
                    for f in elem.nested() {
                        match f.kind {
                            NFTA_EXPR_NAME => name = f.str(),
                            NFTA_EXPR_DATA => data = Some(f),
                            _ => {}
                        }
                    }
                    if name.as_deref() == Some("counter")
                        && let Some(d) = data
                    {
                        for c in d.nested() {
                            match c.kind {
                                NFTA_COUNTER_PACKETS => {
                                    rule.packets = rule.packets.saturating_add(be64(&c)?);
                                }
                                NFTA_COUNTER_BYTES => {
                                    rule.bytes = rule.bytes.saturating_add(be64(&c)?);
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    (!rule.chain.is_empty()).then_some(rule)
}

#[cfg(target_os = "linux")]
pub use io::dump;

#[cfg(target_os = "linux")]
mod io {
    use std::os::fd::AsFd;
    use std::time::{Duration, Instant};

    use corerouter_hal::HalError;
    use netlink_sys::{Socket, protocols::NETLINK_NETFILTER};
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

    use super::{KernelRule, MAX_RULES, NFNL_SUBSYS_NFTABLES, parse_rule, request};

    const DEADLINE: Duration = Duration::from_secs(10);
    /// `ENOENT`: the table does not exist (no firewall): no rules.
    const ENOENT: i32 = 2;

    fn io(e: impl std::fmt::Display) -> HalError {
        HalError::Io(format!("nftables netlink: {e}"))
    }

    /// Every rule of table `table` (family `family`), in one dump.
    pub fn dump(family: u8, table: &str) -> Result<Vec<KernelRule>, HalError> {
        let mut sock = Socket::new(NETLINK_NETFILTER).map_err(io)?;
        sock.bind_auto().map_err(io)?;
        use nix::sys::socket::{setsockopt, sockopt};
        if setsockopt(&sock.as_fd(), sockopt::RcvBufForce, &(4usize << 20)).is_err() {
            let _ = setsockopt(&sock.as_fd(), sockopt::RcvBuf, &(4usize << 20));
        }
        let seq = 1;
        sock.send(&request(family, table, seq), 0).map_err(io)?;
        let start = Instant::now();
        let mut buf = vec![0u8; 1 << 17];
        let mut out = Vec::new();
        loop {
            let left = DEADLINE.saturating_sub(start.elapsed());
            if left.is_zero() {
                return Err(io("the dump did not finish in time"));
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
                    3 => return Ok(out),
                    2 => {
                        let code = msg
                            .get(16..20)
                            .and_then(|b| b.try_into().ok())
                            .map_or(0, i32::from_ne_bytes)
                            .saturating_neg();
                        return match code {
                            0 => Ok(out),
                            ENOENT => Ok(Vec::new()),
                            e => Err(HalError::Rejected(format!(
                                "reading the firewall counters: {}",
                                std::io::Error::from_raw_os_error(e)
                            ))),
                        };
                    }
                    k if k >> 8 == NFNL_SUBSYS_NFTABLES => {
                        if let Some(r) = parse_rule(k & 0xff, msg.get(20..).unwrap_or(&[])) {
                            if out.len() >= MAX_RULES {
                                return Ok(out);
                            }
                            out.push(r);
                        }
                    }
                    _ => {}
                }
            }
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

    /// A NEWRULE body as the kernel sends it for
    /// `… counter packets 7 bytes 900 drop comment "cr:*5"`.
    fn body() -> Vec<u8> {
        let counter = [
            nla(NFTA_COUNTER_BYTES, &900u64.to_be_bytes()),
            nla(NFTA_COUNTER_PACKETS, &7u64.to_be_bytes()),
        ]
        .concat();
        let expr = |name: &str, data: &[u8]| {
            let n: Vec<u8> = name.bytes().chain(std::iter::once(0)).collect();
            nla(
                NFTA_LIST_ELEM | 0x8000,
                &[nla(NFTA_EXPR_NAME, &n), nla(NFTA_EXPR_DATA | 0x8000, data)].concat(),
            )
        };
        let exprs = [
            expr("meta", &[]),
            expr("counter", &counter),
            expr("immediate", &[]),
        ]
        .concat();
        let udata = [&[NFTNL_UDATA_RULE_COMMENT, 6][..], b"cr:*5\0"].concat();
        [
            nla(NFTA_RULE_TABLE, b"corerouter\0"),
            nla(NFTA_RULE_CHAIN, b"filter_input\0"),
            nla(NFTA_RULE_HANDLE, &42u64.to_be_bytes()),
            nla(NFTA_RULE_EXPRESSIONS | 0x8000, &exprs),
            nla(NFTA_RULE_USERDATA, &udata),
        ]
        .concat()
    }

    #[test]
    fn a_rule_with_counter_and_comment_is_read() {
        let r = parse_rule(NFT_MSG_NEWRULE, &body()).unwrap();
        assert_eq!(
            r,
            KernelRule {
                chain: "filter_input".into(),
                handle: 42,
                comment: Some("cr:*5".into()),
                packets: 7,
                bytes: 900,
            }
        );
        assert_eq!(parse_rule(NFT_MSG_GETRULE, &body()), None, "not a rule");
    }

    #[test]
    fn the_request_names_the_table() {
        let b = request(NFPROTO_INET, "corerouter", 9);
        assert_eq!(b.len() % 4, 0);
        assert_eq!(
            u32::from_ne_bytes(b[..4].try_into().unwrap()) as usize,
            b.len()
        );
        assert_eq!(
            u16::from_ne_bytes(b[4..6].try_into().unwrap()),
            (10 << 8) | 7,
            "NFNL_SUBSYS_NFTABLES / NFT_MSG_GETRULE"
        );
        assert_eq!(b[16], NFPROTO_INET);
        assert!(b.windows(11).any(|w| w == b"corerouter\0"));
    }

    proptest! {
        /// Hostile bytes: no panic, at most one rule.
        #[test]
        fn hostile_messages_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..512), cut in 0usize..200) {
            let _ = parse_rule(NFT_MSG_NEWRULE, &bytes);
            let b = body();
            let _ = parse_rule(NFT_MSG_NEWRULE, b.get(..cut.min(b.len())).unwrap_or(&[]));
        }
    }
}
