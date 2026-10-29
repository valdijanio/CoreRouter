//! Reading an nf_tables table back over nfnetlink (G2.8), without `nft -j`
//! (and so without nftables built with JSON): its chains, sets, set
//! elements and rules, decoded into the same `program` objects the
//! encoder (`nfnl`) sends, so "what we loaded" and "what the kernel holds"
//! compare with `==`.
//!
//! - the firewall's commit diffs rules by their kernel handles (a rule
//!   that did not change keeps its counters);
//! - a table replace re-adds the dynamic address-list entries it reads
//!   here (with the time they have left);
//! - the tests load a table and check that the kernel holds exactly it.
//!
//! Every decoder is pure and bounded: a hostile or truncated message gives
//! fewer fields or nothing, never a panic. Numbers inside nf_tables
//! attributes are big-endian; the netlink header is native-endian.
//! Attribute numbers: `include/uapi/linux/netfilter/nf_tables.h`.

use std::collections::BTreeMap;

use corerouter_firewall::program::{
    AnonSet, Base, Chain, ChainType, CtKey, Dir, Expr, FwElement, FwSet, Hook, KernelElement,
    KeyKind, MetaKey, NatKind, Order, Rule, SET_ANONYMOUS, SET_EVAL, SET_INTERVAL, SET_TIMEOUT,
};

use crate::genl::{Attr, attrs};

pub const NFNL_SUBSYS_NFTABLES: u16 = 10;
pub const NFT_MSG_NEWCHAIN: u16 = 3;
pub const NFT_MSG_GETCHAIN: u16 = 4;
pub const NFT_MSG_NEWRULE: u16 = 6;
pub const NFT_MSG_GETRULE: u16 = 7;
pub const NFT_MSG_NEWSET: u16 = 9;
pub const NFT_MSG_GETSET: u16 = 10;
pub const NFT_MSG_NEWSETELEM: u16 = 12;
pub const NFT_MSG_GETSETELEM: u16 = 13;

/// At most this many objects of one kind from one dump (a hostile kernel,
/// or a table far beyond what the validator lets through).
pub const MAX_OBJECTS: usize = 1_000_000;

fn be32(a: &Attr<'_>) -> Option<u32> {
    Some(u32::from_be_bytes(a.data.get(..4)?.try_into().ok()?))
}

fn be64(a: &Attr<'_>) -> Option<u64> {
    Some(u64::from_be_bytes(a.data.get(..8)?.try_into().ok()?))
}

/// The bytes of an `NFTA_DATA_VALUE` inside `a`.
fn value(a: &Attr<'_>) -> Option<Vec<u8>> {
    a.nested().find(|v| v.kind == 1).map(|v| v.data.to_vec())
}

/// A dump request: `msg` with `NLM_F_DUMP`, and string attributes.
pub fn request(msg: u16, family: u8, seq: u32, strings: &[(u16, &str)]) -> Vec<u8> {
    let mut b = Vec::with_capacity(64);
    b.extend_from_slice(&0u32.to_ne_bytes());
    b.extend_from_slice(&((NFNL_SUBSYS_NFTABLES << 8) | msg).to_ne_bytes());
    // NLM_F_REQUEST | NLM_F_DUMP
    b.extend_from_slice(&(0x1u16 | 0x300).to_ne_bytes());
    b.extend_from_slice(&seq.to_ne_bytes());
    b.extend_from_slice(&0u32.to_ne_bytes());
    b.extend_from_slice(&[family, 0, 0, 0]);
    for (kind, s) in strings {
        let data: Vec<u8> = s.bytes().take(255).chain(std::iter::once(0)).collect();
        let len = u16::try_from(4 + data.len()).unwrap_or(u16::MAX);
        b.extend_from_slice(&len.to_ne_bytes());
        b.extend_from_slice(&kind.to_ne_bytes());
        b.extend_from_slice(&data);
        b.resize(b.len().div_ceil(4) * 4, 0);
    }
    let total = u32::try_from(b.len()).unwrap_or(u32::MAX);
    if let Some(slot) = b.get_mut(..4) {
        slot.copy_from_slice(&total.to_ne_bytes());
    }
    b
}

/// nft's spelling of a base chain priority: the nearest standard one,
/// with the offset (`dstnat - 5`).
pub fn priority_text(p: i32) -> String {
    const NAMES: [(&str, i32); 5] = [
        ("raw", -300),
        ("mangle", -150),
        ("dstnat", -100),
        ("filter", 0),
        ("srcnat", 100),
    ];
    let (name, base) = NAMES
        .iter()
        .min_by_key(|(_, b)| (i64::from(p) - i64::from(*b)).abs())
        .copied()
        .unwrap_or(("filter", 0));
    let off = i64::from(p) - i64::from(base);
    match off {
        0 => name.to_owned(),
        o if o > 0 => format!("{name} + {o}"),
        o => format!("{name} - {}", -o),
    }
}

/// A `NEWCHAIN` body: its table and the chain.
pub fn parse_chain(body: &[u8]) -> Option<(String, Chain)> {
    let mut table = None;
    let mut name = None;
    let mut hook = Hook::Regular;
    let mut priority = 0;
    let mut kind = ChainType::Filter;
    for a in attrs(body) {
        match a.kind {
            1 => table = a.str(),
            3 => name = a.str(),
            4 => {
                for h in a.nested() {
                    match h.kind {
                        1 => {
                            hook = match be32(&h)? {
                                0 => Hook::Prerouting,
                                1 => Hook::Input,
                                2 => Hook::Forward,
                                3 => Hook::Output,
                                4 => Hook::Postrouting,
                                _ => return None,
                            }
                        }
                        2 => priority = i32::from_be_bytes(h.data.get(..4)?.try_into().ok()?),
                        _ => {}
                    }
                }
            }
            7 => {
                kind = match a.str()?.as_str() {
                    "nat" => ChainType::Nat,
                    "route" => ChainType::Route,
                    _ => ChainType::Filter,
                }
            }
            _ => {}
        }
    }
    let regular = hook == Hook::Regular;
    Some((
        table?,
        Chain {
            name: name?,
            kind: if regular { ChainType::Filter } else { kind },
            hook,
            priority: if regular { 0 } else { priority },
            priority_text: if regular {
                String::new()
            } else {
                priority_text(priority)
            },
        },
    ))
}

/// What a `NEWSET` says: the set (without elements) and whether it is
/// anonymous; `None` for a key type we do not use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetInfo {
    pub table: String,
    pub set: FwSet,
    pub anonymous: bool,
    pub udata: Vec<u8>,
}

/// nft's user data TLV `kind` as a u32.
fn udata_u32(udata: &[u8], kind: u8) -> Option<u32> {
    let mut rest = udata;
    while let (Some(k), Some(len)) = (rest.first(), rest.get(1)) {
        let len = usize::from(*len);
        let v = rest.get(2..2 + len)?;
        if *k == kind && len == 4 {
            return Some(u32::from_le_bytes(v.try_into().ok()?));
        }
        rest = rest.get(2 + len..)?;
    }
    None
}

pub fn parse_set(body: &[u8]) -> Option<SetInfo> {
    let mut table = None;
    let mut name = None;
    let mut flags = 0;
    let mut key = None;
    let mut size = None;
    let mut udata = Vec::new();
    for a in attrs(body) {
        match a.kind {
            1 => table = a.str(),
            2 => name = a.str(),
            3 => flags = be32(&a)?,
            4 => key = KeyKind::from_nft_id(be32(&a)?),
            9 => size = a.nested().find(|d| d.kind == 1).and_then(|d| be32(&d)),
            13 => udata = a.data.to_vec(),
            _ => {}
        }
    }
    let anonymous = flags & SET_ANONYMOUS != 0;
    Some(SetInfo {
        table: table?,
        set: FwSet {
            name: name?,
            key: key?,
            interval: flags & SET_INTERVAL != 0,
            timeout: flags & SET_TIMEOUT != 0,
            dynamic: flags & SET_EVAL != 0,
            // An anonymous set's size is its element count, not a bound.
            size: if anonymous { None } else { size },
            auto_merge: udata_u32(&udata, 2) == Some(1),
            elements: Vec::new(),
        },
        anonymous,
        udata,
    })
}

/// One element as read: as the kernel holds it, and the time it has left.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadElement {
    pub element: KernelElement,
    pub expires_ms: Option<u64>,
}

/// The elements of a `NEWSETELEM` body.
pub fn parse_elements(body: &[u8]) -> Vec<ReadElement> {
    let mut out = Vec::new();
    for a in attrs(body).filter(|a| a.kind == 3) {
        for e in a.nested().filter(|e| e.kind == 1) {
            let mut key = None;
            let mut end = false;
            let mut timeout_ms = None;
            let mut expires_ms = None;
            for f in e.nested() {
                match f.kind {
                    1 => key = value(&f),
                    3 => end = be32(&f).is_some_and(|v| v & 1 != 0),
                    4 => timeout_ms = be64(&f),
                    5 => expires_ms = be64(&f),
                    _ => {}
                }
            }
            if let Some(key) = key {
                out.push(ReadElement {
                    element: KernelElement {
                        key,
                        end,
                        timeout_ms,
                    },
                    expires_ms,
                });
            }
        }
    }
    out
}

/// Interval elements back into ranges (sorted; an end element closes the
/// range before it; the leading end at zero is nft's, not a range).
/// `remaining`: timeouts are the time left instead of the original one.
pub fn ranges(mut read: Vec<ReadElement>, remaining: bool) -> Vec<FwElement> {
    // End before start at the same key (ranges that touch).
    read.sort_by(|a, b| (&a.element.key, !a.element.end).cmp(&(&b.element.key, !b.element.end)));
    let mut out: Vec<FwElement> = Vec::new();
    let mut open: Option<FwElement> = None;
    for r in read {
        let e = r.element;
        if e.end {
            if let Some(mut o) = open.take() {
                let last = predecessor(&e.key);
                o.last = last.filter(|l| *l != o.key);
                out.push(o);
            }
        } else {
            if let Some(mut o) = open.take() {
                // Two starts in a row: the first runs to just before.
                o.last = predecessor(&e.key).filter(|l| *l != o.key);
                out.push(o);
            }
            open = Some(FwElement {
                key: e.key,
                last: None,
                timeout_ms: if remaining {
                    r.expires_ms.or(e.timeout_ms)
                } else {
                    e.timeout_ms
                },
            });
        }
    }
    if let Some(mut o) = open {
        // Up to the last value of the key.
        let all = vec![0xff; o.key.len()];
        o.last = (all != o.key).then_some(all);
        out.push(o);
    }
    out
}

fn predecessor(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut out = bytes.to_vec();
    for b in out.iter_mut().rev() {
        if *b == 0 {
            *b = 0xff;
        } else {
            *b -= 1;
            return Some(out);
        }
    }
    None
}

/// One kernel rule: the rule (exprs, comment) and its handle. A lookup of
/// an anonymous set comes back as a named [`Expr::Lookup`] of `__setN`
/// until [`resolve_anon`] puts the set in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadRule {
    pub table: String,
    pub rule: Rule,
    pub handle: u64,
    /// An expression this decoder does not know (the rule cannot be
    /// compared: the caller replaces the table).
    pub unknown: bool,
}

/// The comment in a rule's user data.
fn comment(udata: &[u8]) -> Option<String> {
    let mut rest = udata;
    while let (Some(kind), Some(len)) = (rest.first(), rest.get(1)) {
        let len = usize::from(*len);
        let v = rest.get(2..2 + len)?;
        if *kind == 0 {
            let end = v.iter().position(|b| *b == 0).unwrap_or(v.len());
            return Some(String::from_utf8_lossy(v.get(..end)?).into_owned());
        }
        rest = rest.get(2 + len..)?;
    }
    None
}

pub fn parse_rule(body: &[u8]) -> Option<ReadRule> {
    let mut table = None;
    let mut chain = None;
    let mut handle = 0;
    let mut exprs = Vec::new();
    let mut unknown = false;
    let mut cmt = None;
    for a in attrs(body) {
        match a.kind {
            1 => table = a.str(),
            2 => chain = a.str(),
            3 => handle = be64(&a)?,
            4 => {
                for elem in a.nested().filter(|e| e.kind == 1) {
                    match parse_expr(&elem) {
                        Some(e) => exprs.push(e),
                        None => unknown = true,
                    }
                }
            }
            7 => cmt = comment(a.data),
            _ => {}
        }
    }
    Some(ReadRule {
        table: table?,
        rule: Rule {
            chain: chain?,
            exprs,
            text: String::new(),
            nft: None,
            comment: cmt,
        },
        handle,
        unknown,
    })
}

/// The attributes of an expression's data, by number (every expression
/// we read numbers its attributes below 16). An array, not a map: a dump
/// of 10 000 rules decodes ~100 000 expressions.
#[derive(Default)]
struct Fields<'a>([Option<Attr<'a>>; 16]);

impl<'a> Fields<'a> {
    fn get(&self, k: &u16) -> Option<&Attr<'a>> {
        self.0.get(usize::from(*k)).and_then(Option::as_ref)
    }
}

fn fields<'a>(data: Option<Attr<'a>>) -> Fields<'a> {
    let mut f = Fields::default();
    for a in data.into_iter().flat_map(|d| d.nested()) {
        if let Some(slot) = f.0.get_mut(usize::from(a.kind)) {
            *slot = Some(a);
        }
    }
    f
}

fn meta_key(n: u32) -> Option<MetaKey> {
    Some(match n {
        3 => MetaKey::Mark,
        6 => MetaKey::IifName,
        7 => MetaKey::OifName,
        12 => MetaKey::NfTrace,
        15 => MetaKey::NfProto,
        16 => MetaKey::L4Proto,
        _ => return None,
    })
}

fn ct_key(n: u32) -> Option<CtKey> {
    Some(match n {
        0 => CtKey::State,
        2 => CtKey::Status,
        3 => CtKey::Mark,
        11 => CtKey::ProtoSrc,
        12 => CtKey::ProtoDst,
        19 => CtKey::SrcIp,
        20 => CtKey::DstIp,
        _ => return None,
    })
}

/// One `NFTA_LIST_ELEM` of a rule's expressions; `None` when unknown.
fn parse_expr(elem: &Attr<'_>) -> Option<Expr> {
    let mut name = None;
    let mut data = None;
    for f in elem.nested() {
        match f.kind {
            1 => name = f.str(),
            2 => data = Some(f),
            _ => {}
        }
    }
    let f = fields(data);
    let u = |k: u16| f.get(&k).and_then(be32);
    let v = |k: u16| f.get(&k).and_then(value);
    Some(match name?.as_str() {
        "payload" => Expr::Payload {
            base: match u(2)? {
                1 => Base::Network,
                2 => Base::Transport,
                _ => return None,
            },
            offset: u(3)?,
            len: u(4)?,
            dreg: u(1)?,
        },
        "meta" => {
            let key = meta_key(u(2)?)?;
            match (u(1), u(3)) {
                (Some(dreg), _) => Expr::Meta { key, dreg },
                (None, Some(sreg)) => Expr::MetaSet { key, sreg },
                _ => return None,
            }
        }
        "cmp" => {
            let (sreg, op, data) = (u(1)?, u(2)?, v(3)?);
            match op {
                0 | 1 => Expr::Cmp {
                    sreg,
                    eq: op == 0,
                    data,
                },
                n => Expr::Order {
                    sreg,
                    op: Order::from_number(n)?,
                    data,
                },
            }
        }
        "bitwise" => {
            // Only the boolean form (`NFT_BITWISE_BOOL`, op 0).
            if u(6).is_some_and(|op| op != 0) {
                return None;
            }
            let (sreg, dreg, mask, xor) = (u(1)?, u(2)?, v(4)?, v(5)?);
            if xor.iter().all(|b| *b == 0) {
                Expr::And { sreg, dreg, mask }
            } else {
                Expr::Bitwise {
                    sreg,
                    dreg,
                    mask,
                    xor,
                }
            }
        }
        "range" => Expr::Range {
            sreg: u(1)?,
            eq: u(2)? == 0,
            from: v(3)?,
            to: v(4)?,
        },
        "ct" => {
            let key = ct_key(u(2)?)?;
            match (u(1), u(4)) {
                (Some(dreg), _) => Expr::Ct {
                    key,
                    dir: f
                        .get(&3)
                        .and_then(|d| d.u8())
                        .map(|d| if d == 1 { Dir::Reply } else { Dir::Original }),
                    dreg,
                },
                (None, Some(sreg)) => Expr::CtSet { key, sreg },
                _ => return None,
            }
        }
        "lookup" => Expr::Lookup {
            set: f.get(&1)?.str()?,
            sreg: u(2)?,
            dreg: u(3),
            inv: u(5).is_some_and(|x| x & 1 != 0),
        },
        "immediate" => {
            let dreg = u(1)?;
            let d = f.get(&2)?;
            if let Some(verdict) = d.nested().find(|x| x.kind == 2) {
                let mut code = None;
                let mut chain = None;
                for x in verdict.nested() {
                    match x.kind {
                        1 => code = be32(&x),
                        2 => chain = x.str(),
                        _ => {}
                    }
                }
                match code? {
                    0 => Expr::Drop,
                    1 => Expr::Accept,
                    0xffff_fffb => Expr::Return,
                    0xffff_fffd => Expr::Jump { chain: chain? },
                    _ => return None,
                }
            } else {
                Expr::Immediate {
                    dreg,
                    data: value(d)?,
                }
            }
        }
        "counter" => Expr::Counter,
        "notrack" => Expr::Notrack,
        "reject" => Expr::Reject {
            kind: u(1)?,
            code: f.get(&2).and_then(|c| c.u8()).unwrap_or(0),
        },
        "log" => Expr::Log {
            prefix: f.get(&2).and_then(Attr::str),
        },
        "limit" => {
            // Packets only (`NFT_LIMIT_PKTS`), no inversion.
            if u(4).is_some_and(|t| t != 0) || u(5).is_some_and(|x| x != 0) {
                return None;
            }
            Expr::Limit {
                rate: f.get(&1).and_then(be64)?,
                unit_secs: f.get(&2).and_then(be64)?,
                burst: u(3).unwrap_or(0),
            }
        }
        // The kernel echoes a missing maximum as the minimum and adds
        // `NF_NAT_RANGE_MAP_IPS` (1) itself: read back what was sent.
        "masq" => Expr::Masq {
            proto_min: u(2),
            proto_max: u(3).filter(|m| Some(*m) != u(2)),
            flags: u(1).unwrap_or(0),
        },
        "redir" => Expr::Redir {
            proto_min: u(1),
            proto_max: u(2).filter(|m| Some(*m) != u(1)),
            flags: u(3).unwrap_or(0),
        },
        "nat" => Expr::NatRange {
            kind: if u(1)? == 0 {
                NatKind::Snat
            } else {
                NatKind::Dnat
            },
            family: u8::try_from(u(2)?).ok()?,
            addr_min: u(3),
            addr_max: u(4).filter(|m| Some(*m) != u(3)),
            proto_min: u(5),
            proto_max: u(6).filter(|m| Some(*m) != u(5)),
            flags: u(7).unwrap_or(0) & !1,
        },
        "fib" => Expr::Fib {
            dreg: u(1)?,
            result: u(2)?,
            flags: u(3)?,
        },
        "dynset" => {
            let set = f.get(&1)?.str()?;
            match u(3)? {
                0 => Expr::DynsetAdd {
                    set,
                    sreg_key: u(4)?,
                    timeout_ms: f.get(&6).and_then(be64).filter(|t| *t != 0),
                },
                1 => Expr::Update {
                    set,
                    sreg_key: u(4)?,
                    sreg_data: u(5)?,
                },
                _ => return None,
            }
        }
        _ => return None,
    })
}

/// Put anonymous sets into the lookups that name them (`__setN`).
pub fn resolve_anon(rule: &mut Rule, anon: &BTreeMap<String, AnonSet>) {
    for e in &mut rule.exprs {
        if let Expr::Lookup {
            set,
            sreg,
            dreg: None,
            inv,
        } = e
            && let Some(a) = anon.get(set.as_str())
        {
            *e = Expr::LookupAnon {
                set: a.clone(),
                sreg: *sreg,
                inv: *inv,
            };
        }
    }
}

/// Whether kernel rule `k` is rule `ours`, comparing an unresolved
/// anonymous lookup only by its register and inversion (its elements are
/// another dump each; the commit diff does without them).
pub fn same_shape(k: &Rule, ours: &Rule) -> bool {
    k.chain == ours.chain
        && k.comment == ours.comment
        && k.exprs.len() == ours.exprs.len()
        && k.exprs.iter().zip(&ours.exprs).all(|(a, b)| match (a, b) {
            (
                Expr::Lookup {
                    set,
                    sreg,
                    dreg: None,
                    inv,
                },
                Expr::LookupAnon {
                    sreg: s2, inv: i2, ..
                },
            ) => set.starts_with("__set") && sreg == s2 && inv == i2,
            _ => a == b,
        })
}

/// An anonymous set from its info and elements.
pub fn anon_set(info: &SetInfo, read: Vec<ReadElement>) -> AnonSet {
    let mut elements: Vec<(Vec<u8>, bool)> = read
        .into_iter()
        .map(|r| (r.element.key, r.element.end))
        .collect();
    elements.sort_by(|a, b| (&a.0, !a.1).cmp(&(&b.0, !b.1)));
    AnonSet {
        key: info.set.key,
        interval: info.set.interval,
        elements,
        udata: info.udata.clone(),
    }
}

#[cfg(target_os = "linux")]
pub use io::{Dump, Reader, read_table, with_reader};

#[cfg(target_os = "linux")]
mod io {
    use std::collections::BTreeMap;
    use std::os::fd::AsFd;
    use std::time::{Duration, Instant};

    use corerouter_firewall::program::{AnonSet, Chain, FwSet};
    use corerouter_hal::HalError;
    use netlink_sys::{Socket, protocols::NETLINK_NETFILTER};
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

    use super::*;

    const DEADLINE: Duration = Duration::from_secs(30);
    /// `ENOENT`: the table (or set) does not exist.
    const ENOENT: i32 = 2;

    fn io(e: impl std::fmt::Display) -> HalError {
        HalError::Io(format!("nftables netlink: {e}"))
    }

    /// The firewall's reader, kept open (G0.31f): closing a netfilter
    /// socket makes the kernel wait for the release of what the last
    /// commit deleted (an RCU grace period, see `nfnl`'s batch socket).
    static SHARED: std::sync::Mutex<Option<Reader>> = std::sync::Mutex::new(None);

    /// Run `f` with the shared reader (opened on first use, dropped after
    /// an error: it may hold the rest of an answer).
    pub fn with_reader<T>(
        f: impl FnOnce(&mut Reader) -> Result<T, HalError>,
    ) -> Result<T, HalError> {
        let mut shared = SHARED.lock().unwrap_or_else(|e| e.into_inner());
        let rd = match &mut *shared {
            Some(r) => r,
            None => shared.insert(Reader::open()?),
        };
        let out = f(rd);
        if out.is_err() {
            *shared = None;
        }
        out
    }

    /// One socket for a series of dumps.
    pub struct Reader {
        sock: Socket,
        seq: u32,
        buf: Vec<u8>,
    }

    impl Reader {
        pub fn open() -> Result<Self, HalError> {
            let mut sock = Socket::new(NETLINK_NETFILTER).map_err(io)?;
            sock.bind_auto().map_err(io)?;
            use nix::sys::socket::{setsockopt, sockopt};
            if setsockopt(&sock.as_fd(), sockopt::RcvBufForce, &(8usize << 20)).is_err() {
                let _ = setsockopt(&sock.as_fd(), sockopt::RcvBuf, &(8usize << 20));
            }
            Ok(Self {
                sock,
                seq: 0,
                buf: vec![0u8; 1 << 17],
            })
        }

        /// Run dump `msg` and hand every answer's body (after `nfgenmsg`)
        /// to `each`; `Ok(false)` when the object does not exist.
        pub fn dump(
            &mut self,
            msg: u16,
            family: u8,
            strings: &[(u16, &str)],
            mut each: impl FnMut(u16, &[u8]),
        ) -> Result<bool, HalError> {
            self.seq = self.seq.wrapping_add(1);
            let seq = self.seq;
            self.sock
                .send(&request(msg, family, seq, strings), 0)
                .map_err(io)?;
            let start = Instant::now();
            let mut count = 0usize;
            loop {
                let left = DEADLINE.saturating_sub(start.elapsed());
                if left.is_zero() {
                    return Err(io("the dump did not finish in time"));
                }
                let ms = u16::try_from(left.as_millis().min(1000)).unwrap_or(1000);
                let mut fds = [PollFd::new(self.sock.as_fd(), PollFlags::POLLIN)];
                if poll(&mut fds, PollTimeout::from(ms)).map_err(io)? == 0 {
                    continue;
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
                    let m = rest.get(..len).unwrap_or(rest);
                    rest = rest.get(len.div_ceil(4) * 4..).unwrap_or(&[]);
                    if mseq != seq {
                        continue;
                    }
                    match kind {
                        3 => return Ok(true),
                        2 => {
                            let code = m
                                .get(16..20)
                                .and_then(|b| b.try_into().ok())
                                .map_or(0, i32::from_ne_bytes)
                                .saturating_neg();
                            return match code {
                                0 => Ok(true),
                                ENOENT => Ok(false),
                                e => Err(HalError::Rejected(format!(
                                    "reading nftables: {}",
                                    std::io::Error::from_raw_os_error(e)
                                ))),
                            };
                        }
                        k if k >> 8 == NFNL_SUBSYS_NFTABLES => {
                            count += 1;
                            if count > MAX_OBJECTS {
                                return Err(io("the dump is too large"));
                            }
                            each(k & 0xff, m.get(20..).unwrap_or(&[]));
                        }
                        _ => {}
                    }
                }
            }
        }

        pub fn chains(&mut self, family: u8, table: &str) -> Result<Vec<Chain>, HalError> {
            let mut out = Vec::new();
            self.dump(NFT_MSG_GETCHAIN, family, &[(1, table)], |k, body| {
                if k == NFT_MSG_NEWCHAIN
                    && let Some((t, c)) = parse_chain(body)
                    && t == table
                {
                    out.push(c);
                }
            })?;
            Ok(out)
        }

        pub fn sets(&mut self, family: u8, table: &str) -> Result<Vec<SetInfo>, HalError> {
            let mut out = Vec::new();
            self.dump(NFT_MSG_GETSET, family, &[(1, table)], |k, body| {
                if k == NFT_MSG_NEWSET
                    && let Some(s) = parse_set(body)
                    && s.table == table
                {
                    out.push(s);
                }
            })?;
            Ok(out)
        }

        pub fn elements(
            &mut self,
            family: u8,
            table: &str,
            set: &str,
        ) -> Result<Vec<ReadElement>, HalError> {
            let mut out = Vec::new();
            self.dump(
                NFT_MSG_GETSETELEM,
                family,
                &[(1, table), (2, set)],
                |k, body| {
                    if k == NFT_MSG_NEWSETELEM {
                        out.extend(parse_elements(body));
                    }
                },
            )?;
            Ok(out)
        }

        pub fn rules(&mut self, family: u8, table: &str) -> Result<Vec<ReadRule>, HalError> {
            let mut out = Vec::new();
            self.dump(NFT_MSG_GETRULE, family, &[(1, table)], |k, body| {
                if k == NFT_MSG_NEWRULE
                    && let Some(r) = parse_rule(body)
                    && r.table == table
                {
                    out.push(r);
                }
            })?;
            Ok(out)
        }
    }

    /// A table as the kernel holds it.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct Dump {
        pub chains: Vec<Chain>,
        /// Named sets; with their elements when asked for.
        pub sets: Vec<FwSet>,
        pub rules: Vec<ReadRule>,
    }

    /// Read table `table`: chains, named sets (elements when `elements`)
    /// and rules (their anonymous sets resolved when `anon`, one more dump
    /// each). `None` when the table does not exist.
    pub fn read_table(
        family: u8,
        table: &str,
        elements: bool,
        anon: bool,
    ) -> Result<Option<Dump>, HalError> {
        let mut r = Reader::open()?;
        let mut exists = false;
        r.dump(1, family, &[(1, table)], |k, body| {
            // NEWTABLE: the name is attribute 1.
            if k == 0 && attrs(body).any(|a| a.kind == 1 && a.str().as_deref() == Some(table)) {
                exists = true;
            }
        })?;
        if !exists {
            return Ok(None);
        }
        let chains = r.chains(family, table)?;
        let infos = r.sets(family, table)?;
        let mut sets = Vec::new();
        let mut anons: BTreeMap<String, AnonSet> = BTreeMap::new();
        for info in infos {
            if info.anonymous {
                if anon {
                    let els = r.elements(family, table, &info.set.name)?;
                    anons.insert(info.set.name.clone(), anon_set(&info, els));
                }
                continue;
            }
            let mut set = info.set;
            if elements {
                let els = r.elements(family, table, &set.name)?;
                set.elements = if set.interval {
                    ranges(els, false)
                } else {
                    let mut v: Vec<FwElement> = els
                        .into_iter()
                        .filter(|e| !e.element.end)
                        .map(|e| FwElement {
                            key: e.element.key,
                            last: None,
                            timeout_ms: e.element.timeout_ms,
                        })
                        .collect();
                    v.sort();
                    v
                };
            }
            sets.push(set);
        }
        let mut rules = r.rules(family, table)?;
        if anon {
            for rr in &mut rules {
                resolve_anon(&mut rr.rule, &anons);
            }
        }
        Ok(Some(Dump {
            chains,
            sets,
            rules,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_firewall::program::interval_encoding;
    use proptest::prelude::*;

    fn el(key: &[u8], last: Option<&[u8]>, t: Option<u64>) -> FwElement {
        FwElement {
            key: key.to_vec(),
            last: last.map(<[u8]>::to_vec),
            timeout_ms: t,
        }
    }

    #[test]
    fn priorities_read_like_nft_writes_them() {
        assert_eq!(priority_text(-300), "raw");
        assert_eq!(priority_text(-105), "dstnat - 5");
        assert_eq!(priority_text(-5), "filter - 5");
        assert_eq!(priority_text(110), "srcnat + 10");
        assert_eq!(priority_text(-150), "mangle");
    }

    /// Ranges survive encoding and reading back, in any dump order.
    #[test]
    fn ranges_round_trip() {
        let elems = vec![
            el(&[1, 0, 0, 0], Some(&[1, 0, 0, 9]), None),
            el(&[1, 0, 0, 10], Some(&[1, 0, 0, 20]), Some(60_000)),
            el(&[9, 9, 9, 9], None, None),
            el(&[255, 0, 0, 0], Some(&[255, 255, 255, 255]), None),
        ];
        let mut read: Vec<ReadElement> = interval_encoding(&elems)
            .into_iter()
            .map(|element| ReadElement {
                element,
                expires_ms: None,
            })
            .collect();
        read.reverse();
        assert_eq!(ranges(read, false), elems);
    }

    proptest! {
        /// Hostile bytes: no panic.
        #[test]
        fn hostile_messages_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
            let _ = parse_rule(&bytes);
            let _ = parse_set(&bytes);
            let _ = parse_chain(&bytes);
            let _ = parse_elements(&bytes);
        }

        /// Any disjoint ranges come back as they were.
        #[test]
        fn any_ranges_round_trip(starts in proptest::collection::btree_set(any::<u16>(), 0..40), lens in proptest::collection::vec(0u16..300, 40)) {
            let mut elems = Vec::new();
            let mut floor = 0u32;
            for (s, l) in starts.iter().zip(&lens) {
                let lo = u32::from(*s).max(floor);
                let hi = (lo + u32::from(*l)).min(u32::from(u16::MAX));
                if lo > u32::from(u16::MAX) { break; }
                let k = |v: u32| (v as u16).to_be_bytes().to_vec();
                elems.push(FwElement { key: k(lo), last: (hi != lo).then(|| k(hi)), timeout_ms: None });
                floor = hi + 1;
            }
            let read: Vec<ReadElement> = interval_encoding(&elems)
                .into_iter()
                .map(|element| ReadElement { element, expires_ms: None })
                .collect();
            prop_assert_eq!(ranges(read, false), elems);
        }
    }
}
