//! An nftables table as data (G2.3b): what `hal-linux` encodes into
//! nfnetlink messages and what "View generated rules" prints, from one
//! description, so the text shown is what the kernel holds.
//!
//! Only what our tables need is modelled: base chains, sets and maps with
//! IPv4 address (and address . port) keys, and the expressions of the
//! nf_tables VM those rules use (payload, meta, cmp, bitwise, ct, lookup,
//! nat, dynset, counter, verdicts). Register numbers follow the kernel:
//! `REG_1` is the 16-byte register over the 32-bit `REG32_00..03` (8..11).

use std::fmt::Write as _;
use std::net::Ipv4Addr;

/// The 16-byte register 1 (`NFT_REG_1`), over 32-bit registers 8..=11.
pub const REG_1: u32 = 1;
/// 32-bit registers (`NFT_REG32_00` = 8).
pub const REG32_0: u32 = 8;
pub const REG32_1: u32 = 9;
pub const REG32_2: u32 = 10;
pub const REG32_3: u32 = 11;

/// `NFPROTO_IPV4`.
pub const FAMILY_IPV4: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hook {
    Prerouting,
    Forward,
    Postrouting,
}

impl Hook {
    /// `NF_INET_*`.
    pub fn number(self) -> u32 {
        match self {
            Hook::Prerouting => 0,
            Hook::Forward => 2,
            Hook::Postrouting => 4,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Hook::Prerouting => "prerouting",
            Hook::Forward => "forward",
            Hook::Postrouting => "postrouting",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainType {
    Filter,
    Nat,
}

impl ChainType {
    pub fn name(self) -> &'static str {
        match self {
            ChainType::Filter => "filter",
            ChainType::Nat => "nat",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    pub name: String,
    pub kind: ChainType,
    pub hook: Hook,
    pub priority: i32,
    /// How `nft` writes the priority (`srcnat + 10`).
    pub priority_text: String,
}

/// Key or data type of a set: what one value is made of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    Addr,
    /// `ipv4_addr . inet_service` (each field padded to 4 bytes).
    AddrPort,
    /// Map data `interval ipv4_addr . inet_service`: min address . port,
    /// then max address . port (16 bytes; nft's encoding of ranged data).
    AddrPortRange,
}

impl Type {
    /// Bytes in the kernel.
    pub fn len(self) -> u32 {
        match self {
            Type::Addr => 4,
            Type::AddrPort => 8,
            Type::AddrPortRange => 16,
        }
    }

    pub fn is_empty(self) -> bool {
        false
    }

    /// nft's datatype id (`ipv4_addr` 7, `inet_service` 13, a concat is
    /// `(a << 6) | b`); the kernel stores it for `nft list`.
    pub fn nft_id(self) -> u32 {
        match self {
            Type::Addr => 7,
            Type::AddrPort | Type::AddrPortRange => (7 << 6) | 13,
        }
    }

    fn text(self) -> &'static str {
        match self {
            Type::Addr => "ipv4_addr",
            Type::AddrPort => "ipv4_addr . inet_service",
            Type::AddrPortRange => "interval ipv4_addr . inet_service",
        }
    }
}

/// One value of a set key or map data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Value {
    Addr(Ipv4Addr),
    AddrPort(Ipv4Addr, u16),
    AddrPortRange(Ipv4Addr, u16, u16),
}

impl Value {
    /// Packet-order bytes, each field padded to 4 (`NFT_REG32` slots).
    pub fn bytes(&self) -> Vec<u8> {
        let port = |p: u16| {
            let b = p.to_be_bytes();
            [b[0], b[1], 0, 0]
        };
        match *self {
            Value::Addr(a) => a.octets().to_vec(),
            Value::AddrPort(a, p) => [a.octets(), port(p)].concat(),
            Value::AddrPortRange(a, lo, hi) => {
                [a.octets(), port(lo), a.octets(), port(hi)].concat()
            }
        }
    }

    fn text(&self) -> String {
        match self {
            Value::Addr(a) => a.to_string(),
            Value::AddrPort(a, p) => format!("{a} . {p}"),
            Value::AddrPortRange(a, lo, hi) => format!("{a} . {lo}-{hi}"),
        }
    }
}

/// One element: a key (or, in an interval set, a range of addresses) and,
/// in a map, its data.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Element {
    pub key: Value,
    /// Interval sets: the last address of the range (inclusive).
    pub key_last: Option<Ipv4Addr>,
    pub data: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Set {
    pub name: String,
    pub key: Type,
    pub data: Option<Type>,
    /// Elements are address ranges (rbtree).
    pub interval: bool,
    /// Filled by the data path (`dynset`), with this timeout in seconds.
    pub dynamic_timeout: Option<u32>,
    pub size: Option<u32>,
    pub elements: Vec<Element>,
}

impl Set {
    /// `NFT_SET_*` flags.
    pub fn flags(&self) -> u32 {
        let mut f = 0;
        if self.interval {
            f |= 0x4;
        }
        if self.data.is_some() {
            f |= 0x8;
        }
        if self.dynamic_timeout.is_some() {
            f |= 0x10 | 0x20;
        }
        f
    }

    /// The rbtree encoding of an interval set: each range is a start
    /// element and an end element at `last + 1` (flag `INTERVAL_END`); a
    /// first range not starting at 0.0.0.0 is preceded by an end element
    /// at 0.0.0.0, as `nft` sends it. The elements must be sorted,
    /// disjoint and not adjacent ([`merge`] makes them so).
    pub fn interval_elements(&self) -> Vec<(Vec<u8>, bool)> {
        let mut out = Vec::new();
        for (i, e) in self.elements.iter().enumerate() {
            let Value::Addr(start) = e.key else { continue };
            let last = e.key_last.unwrap_or(start);
            if i == 0 && u32::from(start) != 0 {
                out.push((vec![0; 4], true));
            }
            out.push((start.octets().to_vec(), false));
            if let Some(end) = u32::from(last).checked_add(1) {
                out.push((end.to_be_bytes().to_vec(), true));
            }
        }
        out
    }
}

/// Address ranges sorted, with overlapping and adjacent ones joined.
pub fn merge(mut ranges: Vec<(Ipv4Addr, Ipv4Addr)>) -> Vec<(Ipv4Addr, Ipv4Addr)> {
    ranges.sort();
    let mut out: Vec<(Ipv4Addr, Ipv4Addr)> = Vec::with_capacity(ranges.len());
    for (a, b) in ranges {
        if let Some(last) = out.last_mut()
            && u64::from(u32::from(a)) <= u64::from(u32::from(last.1)) + 1
        {
            if b > last.1 {
                last.1 = b;
            }
            continue;
        }
        out.push((a, b));
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetaKey {
    L4Proto,
    OifName,
}

impl MetaKey {
    /// `NFT_META_*`.
    pub fn number(self) -> u32 {
        match self {
            MetaKey::OifName => 7,
            MetaKey::L4Proto => 16,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CtKey {
    State,
    Status,
    SrcIp,
    DstIp,
    ProtoSrc,
    ProtoDst,
}

impl CtKey {
    /// `NFT_CT_*`.
    pub fn number(self) -> u32 {
        match self {
            CtKey::State => 0,
            CtKey::Status => 2,
            CtKey::ProtoSrc => 11,
            CtKey::ProtoDst => 12,
            CtKey::SrcIp => 19,
            CtKey::DstIp => 20,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    Original,
    Reply,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatKind {
    Snat,
    Dnat,
}

/// `NFT_PAYLOAD_*` bases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base {
    Network,
    Transport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    Payload {
        base: Base,
        offset: u32,
        len: u32,
        dreg: u32,
    },
    Meta {
        key: MetaKey,
        dreg: u32,
    },
    /// `NFT_CMP_EQ` / `NFT_CMP_NEQ` against `data`.
    Cmp {
        sreg: u32,
        eq: bool,
        data: Vec<u8>,
    },
    /// `dreg = (sreg & mask) ^ 0`.
    And {
        sreg: u32,
        dreg: u32,
        mask: Vec<u8>,
    },
    Ct {
        key: CtKey,
        dir: Option<Dir>,
        dreg: u32,
    },
    Lookup {
        set: String,
        sreg: u32,
        dreg: Option<u32>,
    },
    Nat {
        kind: NatKind,
        addr_min: u32,
        addr_max: Option<u32>,
        proto_min: Option<u32>,
        proto_max: Option<u32>,
    },
    /// `update @set { key : data }` (`NFT_DYNSET_OP_UPDATE`).
    Update {
        set: String,
        sreg_key: u32,
        sreg_data: u32,
    },
    Counter,
    Drop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub chain: String,
    pub exprs: Vec<Expr>,
    /// The rule as `nft list` writes it.
    pub text: String,
    /// How `nft -f` must spell it, when that differs (`nft` refuses some
    /// rules the kernel accepts).
    pub nft: Option<String>,
}

/// A whole table of family `ip`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Table {
    pub name: String,
    pub sets: Vec<Set>,
    pub chains: Vec<Chain>,
    pub rules: Vec<Rule>,
}

impl Table {
    /// Static elements of every set.
    pub fn elements(&self) -> u64 {
        self.sets.iter().map(|s| s.elements.len() as u64).sum()
    }

    /// The table with no set elements: two tables with the same skeleton
    /// differ only in elements, which can then change one by one.
    pub fn skeleton(&self) -> Table {
        let mut t = self.clone();
        for s in &mut t.sets {
            s.elements.clear();
        }
        t
    }

    /// Whether `other` is this table but for set elements (what
    /// [`Self::skeleton`] compares, without copying the elements).
    pub fn same_skeleton(&self, other: &Table) -> bool {
        self.name == other.name
            && self.chains == other.chains
            && self.rules == other.rules
            && self.sets.len() == other.sets.len()
            && self.sets.iter().zip(&other.sets).all(|(a, b)| {
                a.name == b.name
                    && a.key == b.key
                    && a.data == b.data
                    && a.interval == b.interval
                    && a.dynamic_timeout == b.dynamic_timeout
                    && a.size == b.size
            })
    }

    /// The table as `nft list table` writes it (and `nft -f` reads it).
    pub fn text(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "table ip {} {{", self.name);
        for set in &self.sets {
            let what = if set.data.is_some() { "map" } else { "set" };
            let _ = writeln!(s, "\t{what} {} {{", set.name);
            match set.data {
                Some(d) => {
                    let _ = writeln!(s, "\t\ttype {} : {}", set.key.text(), d.text());
                }
                None => {
                    let _ = writeln!(s, "\t\ttype {}", set.key.text());
                }
            }
            let mut flags = Vec::new();
            if set.interval {
                flags.push("interval");
            }
            if set.dynamic_timeout.is_some() {
                flags.push("dynamic");
                flags.push("timeout");
            }
            if !flags.is_empty() {
                let _ = writeln!(s, "\t\tflags {}", flags.join(", "));
            }
            if let Some(t) = set.dynamic_timeout {
                let _ = writeln!(s, "\t\ttimeout {t}s");
            }
            if let Some(n) = set.size {
                let _ = writeln!(s, "\t\tsize {n}");
            }
            if !set.elements.is_empty() {
                let items: Vec<String> = set
                    .elements
                    .iter()
                    .map(|e| {
                        let key = match (e.key, e.key_last) {
                            (Value::Addr(a), Some(b)) if b != a => format!("{a}-{b}"),
                            (k, _) => k.text(),
                        };
                        match &e.data {
                            Some(d) => format!("{key} : {}", d.text()),
                            None => key,
                        }
                    })
                    .collect();
                let _ = writeln!(s, "\t\telements = {{ {} }}", items.join(",\n\t\t\t     "));
            }
            let _ = writeln!(s, "\t}}");
        }
        for c in &self.chains {
            let _ = writeln!(
                s,
                "\tchain {} {{\n\t\ttype {} hook {} priority {}; policy accept;",
                c.name,
                c.kind.name(),
                c.hook.name(),
                c.priority_text
            );
            for r in self.rules.iter().filter(|r| r.chain == c.name) {
                let _ = writeln!(s, "\t\t{}", r.text);
            }
            let _ = writeln!(s, "\t}}");
        }
        let _ = writeln!(s, "}}");
        s
    }
}

/// Expressions that load `ip saddr` (or daddr) into `dreg`.
pub fn ip_addr(src: bool, dreg: u32) -> Expr {
    Expr::Payload {
        base: Base::Network,
        offset: if src { 12 } else { 16 },
        len: 4,
        dreg,
    }
}

/// `udp sport` / `udp dport` (any transport with ports at 0/2).
pub fn l4_port(src: bool, dreg: u32) -> Expr {
    Expr::Payload {
        base: Base::Transport,
        offset: if src { 0 } else { 2 },
        len: 2,
        dreg,
    }
}

/// `meta l4proto <proto>`.
pub fn l4proto_is(proto: u8) -> [Expr; 2] {
    [
        Expr::Meta {
            key: MetaKey::L4Proto,
            dreg: REG_1,
        },
        Expr::Cmp {
            sreg: REG_1,
            eq: true,
            data: vec![proto],
        },
    ]
}

/// `oifname "<name>"`: interface names are compared as 16 NUL-padded bytes.
pub fn oifname_is(name: &str) -> [Expr; 2] {
    let mut data = name.as_bytes().to_vec();
    data.resize(16, 0);
    data.truncate(16);
    [
        Expr::Meta {
            key: MetaKey::OifName,
            dreg: REG_1,
        },
        Expr::Cmp {
            sreg: REG_1,
            eq: true,
            data,
        },
    ]
}

/// `ct <key> & mask != 0` on a 4-byte ct value (state bits, status bits).
pub fn ct_bits(key: CtKey, mask: u32) -> [Expr; 3] {
    // ct state/status are host-order u32 in the register.
    [
        Expr::Ct {
            key,
            dir: None,
            dreg: REG_1,
        },
        Expr::And {
            sreg: REG_1,
            dreg: REG_1,
            mask: mask.to_ne_bytes().to_vec(),
        },
        Expr::Cmp {
            sreg: REG_1,
            eq: false,
            data: vec![0; 4],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(ranges: &[(&str, &str)]) -> Set {
        Set {
            name: "s".into(),
            key: Type::Addr,
            data: None,
            interval: true,
            dynamic_timeout: None,
            size: None,
            elements: ranges
                .iter()
                .map(|(a, b)| Element {
                    key: Value::Addr(a.parse().unwrap()),
                    key_last: Some(b.parse().unwrap()),
                    data: None,
                })
                .collect(),
        }
    }

    fn hex(v: &[(Vec<u8>, bool)]) -> Vec<String> {
        v.iter()
            .map(|(k, end)| {
                format!(
                    "{}{}",
                    Ipv4Addr::from(<[u8; 4]>::try_from(k.as_slice()).unwrap()),
                    if *end { " end" } else { "" }
                )
            })
            .collect()
    }

    /// What `nft --debug=netlink` sends for the same sets.
    #[test]
    fn interval_elements_match_nft() {
        let s = set(&[("203.0.113.0", "203.0.113.3")]);
        assert_eq!(
            hex(&s.interval_elements()),
            ["0.0.0.0 end", "203.0.113.0", "203.0.113.4 end"]
        );
        let s = set(&[("10.0.0.0", "10.0.0.255"), ("10.0.2.0", "10.0.2.9")]);
        assert_eq!(
            hex(&s.interval_elements()),
            [
                "0.0.0.0 end",
                "10.0.0.0",
                "10.0.1.0 end",
                "10.0.2.0",
                "10.0.2.10 end"
            ]
        );
        let s = set(&[("0.0.0.0", "0.0.0.9"), ("1.0.0.0", "255.255.255.255")]);
        assert_eq!(
            hex(&s.interval_elements()),
            ["0.0.0.0", "0.0.0.10 end", "1.0.0.0"]
        );
    }

    #[test]
    fn ranges_merge() {
        let r = |a: &str, b: &str| {
            (
                a.parse::<Ipv4Addr>().unwrap(),
                b.parse::<Ipv4Addr>().unwrap(),
            )
        };
        assert_eq!(
            merge(vec![
                r("10.0.1.0", "10.0.1.9"),
                r("10.0.0.0", "10.0.0.255"),
                r("10.0.5.0", "10.0.5.0"),
                r("10.0.0.5", "10.0.0.6")
            ]),
            [r("10.0.0.0", "10.0.1.9"), r("10.0.5.0", "10.0.5.0")]
        );
    }

    #[test]
    fn values_are_padded_like_registers() {
        let v = Value::AddrPortRange("203.0.113.1".parse().unwrap(), 1024, 1523);
        assert_eq!(
            v.bytes(),
            [203, 0, 113, 1, 4, 0, 0, 0, 203, 0, 113, 1, 5, 0xf3, 0, 0]
        );
        assert_eq!(Type::AddrPortRange.nft_id(), 461);
    }
}
