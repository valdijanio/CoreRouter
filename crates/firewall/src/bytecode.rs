//! The firewall's rules as nf_tables expressions (G2.8): what `nft`
//! would compile our text into, so `hal-linux` loads the table over
//! nfnetlink without the `nft` program and `nft list` prints exactly what
//! "View generated rules" shows.
//!
//! The encodings follow what `nft --debug=netlink` (nftables 1.0.9) sends
//! for the same text; the vectors are in the tests below:
//!
//! - a prefix on a byte boundary loads only its bytes (`ip daddr
//!   192.0.2.0/24` is a 3-byte load); any other prefix loads the whole
//!   address and masks it (`bitwise`);
//! - `a-b` is `cmp gte a` + `cmp lte b`, and `!= a-b` one `range neq`;
//! - a port list is a set shared by every rule with the same list
//!   (`th dport @ports_22_80`) and `ct state a,b` a mask: not one anonymous
//!   set per rule, which costs the kernel O(sets) each (see
//!   [`port_set_name`]); the subscriber notices' `meta l4proto { tcp, udp }`
//!   is an anonymous set, with nft's user data so `nft list` prints it;
//! - `th sport X th dport Y` and `icmp type X icmp code Y` become one load
//!   of both fields (nft merges adjacent payload matches);
//! - `ip saddr …` in an `inet` table first matches `meta nfproto`, and
//!   `tcp dport`/`icmp type` `meta l4proto`, unless the rule already did
//!   (nft's implicit dependencies, which `nft list` hides).

use std::net::IpAddr;

use corerouter_model::firewall::{AddrMatch, ConnState, Flags, NatState, Neg, PortRange, PortSet};

use crate::program::{
    AnonSet, Base, CtKey, Expr, FwElement, FwSet, KeyKind, MetaKey, Order, REG_1,
};

/// `NFPROTO_IPV4` / `NFPROTO_IPV6`.
pub const NFPROTO_IPV4: u8 = 2;
pub const NFPROTO_IPV6: u8 = 10;
/// The 16-byte registers after `REG_1` (NAT and mark statements).
pub const REG_2: u32 = 2;
pub const REG_3: u32 = 3;
pub const REG_4: u32 = 4;
/// `NF_NAT_RANGE_PROTO_SPECIFIED`.
pub const NAT_PROTO_SPECIFIED: u32 = 0x2;
/// `NFT_FIB_F_DADDR` and `NFT_FIB_RESULT_ADDRTYPE`; `RTN_LOCAL`.
pub const FIB_F_DADDR: u32 = 0x2;
pub const FIB_RESULT_ADDRTYPE: u32 = 3;
pub const RTN_LOCAL: u32 = 2;
/// `enum nft_reject_types`, and the ICMPX codes.
pub const REJECT_TCP_RST: u32 = 1;
pub const REJECT_ICMPX: u32 = 2;
pub const ICMPX_NO_ROUTE: u8 = 0;
pub const ICMPX_PORT_UNREACH: u8 = 1;
pub const ICMPX_HOST_UNREACH: u8 = 2;
pub const ICMPX_ADMIN_PROHIBITED: u8 = 3;

/// One rule under construction: its words and its expressions, side by
/// side, and the protocol matches already made (for the dependencies).
#[derive(Debug, Default)]
pub struct RuleBuild {
    pub text: Vec<String>,
    pub exprs: Vec<Expr>,
    nfproto: Option<u8>,
    l4proto: Option<u8>,
}

impl RuleBuild {
    /// Append a statement: its text (empty: none) and its expressions.
    pub fn push(&mut self, text: impl Into<String>, exprs: Vec<Expr>) {
        let text = text.into();
        if !text.is_empty() {
            self.text.push(text);
        }
        // Remember positive protocol matches (meta load + cmp eq).
        let mut last_meta = None;
        for e in &exprs {
            match e {
                Expr::Meta { key, dreg } if *dreg == REG_1 => last_meta = Some(*key),
                Expr::Cmp { eq: true, data, .. } if data.len() == 1 => {
                    match last_meta {
                        Some(MetaKey::NfProto) => self.nfproto = data.first().copied(),
                        Some(MetaKey::L4Proto) => self.l4proto = data.first().copied(),
                        _ => {}
                    }
                    last_meta = None;
                }
                _ => last_meta = None,
            }
        }
        self.exprs.extend(exprs);
    }

    /// `meta nfproto ipv4|ipv6`, unless already matched (nft's implicit
    /// dependency of `ip`/`ip6` payload).
    pub fn need_nfproto(&mut self, v6: bool) {
        let want = if v6 { NFPROTO_IPV6 } else { NFPROTO_IPV4 };
        if self.nfproto != Some(want) {
            self.push("", meta_cmp(MetaKey::NfProto, true, vec![want]));
        }
    }

    /// `meta l4proto <p>`, unless already matched.
    pub fn need_l4proto(&mut self, p: u8) {
        if self.l4proto != Some(p) {
            self.push("", meta_cmp(MetaKey::L4Proto, true, vec![p]));
        }
    }

    pub fn finish(self) -> (String, Vec<Expr>) {
        (self.text.join(" "), self.exprs)
    }
}

pub fn meta_cmp(key: MetaKey, eq: bool, data: Vec<u8>) -> Vec<Expr> {
    vec![
        Expr::Meta { key, dreg: REG_1 },
        Expr::Cmp {
            sreg: REG_1,
            eq,
            data,
        },
    ]
}

/// An interface name as the kernel compares it: 16 NUL-padded bytes.
pub fn ifname_bytes(name: &str) -> Vec<u8> {
    let mut data = name.as_bytes().to_vec();
    data.resize(16, 0);
    data.truncate(16);
    data
}

fn ip_bytes(a: IpAddr) -> Vec<u8> {
    match a {
        IpAddr::V4(v) => v.octets().to_vec(),
        IpAddr::V6(v) => v.octets().to_vec(),
    }
}

/// `ip|ip6 saddr|daddr` into `REG_1`, `len` bytes.
fn addr_load(v6: bool, src: bool, len: u32) -> Expr {
    let offset = match (v6, src) {
        (false, true) => 12,
        (false, false) => 16,
        (true, true) => 8,
        (true, false) => 24,
    };
    Expr::Payload {
        base: Base::Network,
        offset,
        len,
        dreg: REG_1,
    }
}

/// `ip saddr [!=] <a>` (the `nfproto` dependency is the caller's).
pub fn addr_exprs(src: bool, not: bool, a: &AddrMatch) -> Vec<Expr> {
    let v6 = matches!(a.bounds().0, IpAddr::V6(_));
    let full: u32 = if v6 { 16 } else { 4 };
    match a {
        AddrMatch::Net(n) => {
            let prefix = u32::from(n.prefix_len());
            let bytes = ip_bytes(n.network());
            if prefix == full * 8 {
                vec![
                    addr_load(v6, src, full),
                    Expr::Cmp {
                        sreg: REG_1,
                        eq: !not,
                        data: bytes,
                    },
                ]
            } else if prefix % 8 == 0 && prefix > 0 {
                let len = prefix / 8;
                vec![
                    addr_load(v6, src, len),
                    Expr::Cmp {
                        sreg: REG_1,
                        eq: !not,
                        data: bytes.get(..len as usize).unwrap_or(&[]).to_vec(),
                    },
                ]
            } else {
                let mask = prefix_mask(full as usize, prefix as usize);
                let data = bytes.iter().zip(&mask).map(|(b, m)| b & m).collect();
                vec![
                    addr_load(v6, src, full),
                    Expr::And {
                        sreg: REG_1,
                        dreg: REG_1,
                        mask,
                    },
                    Expr::Cmp {
                        sreg: REG_1,
                        eq: !not,
                        data,
                    },
                ]
            }
        }
        AddrMatch::Range(lo, hi) => {
            let mut out = vec![addr_load(v6, src, full)];
            out.extend(range_exprs(not, ip_bytes(*lo), ip_bytes(*hi)));
            out
        }
    }
}

fn prefix_mask(len: usize, prefix: usize) -> Vec<u8> {
    (0..len)
        .map(|i| {
            let take = prefix.saturating_sub(i * 8).min(8);
            if take == 0 { 0 } else { 0xffu8 << (8 - take) }
        })
        .collect()
}

fn range_exprs(not: bool, lo: Vec<u8>, hi: Vec<u8>) -> Vec<Expr> {
    if not {
        vec![Expr::Range {
            sreg: REG_1,
            eq: false,
            from: lo,
            to: hi,
        }]
    } else {
        vec![
            Expr::Order {
                sreg: REG_1,
                op: Order::Gte,
                data: lo,
            },
            Expr::Order {
                sreg: REG_1,
                op: Order::Lte,
                data: hi,
            },
        ]
    }
}

/// `ip saddr [!=] @set`.
pub fn addr_set_exprs(v6: bool, src: bool, not: bool, set: &str) -> Vec<Expr> {
    vec![
        addr_load(v6, src, if v6 { 16 } else { 4 }),
        Expr::Lookup {
            set: set.to_owned(),
            sreg: REG_1,
            dreg: None,
            inv: not,
        },
    ]
}

/// `iifname|oifname [!=] @set`.
pub fn ifname_set_exprs(out: bool, not: bool, set: &str) -> Vec<Expr> {
    vec![
        Expr::Meta {
            key: if out {
                MetaKey::OifName
            } else {
                MetaKey::IifName
            },
            dreg: REG_1,
        },
        Expr::Lookup {
            set: set.to_owned(),
            sreg: REG_1,
            dreg: None,
            inv: not,
        },
    ]
}

/// nft's set user data (`NFTNL_UDATA_SET_*` TLVs: type, length, value).
fn udata_u32(kind: u8, v: u32) -> [u8; 6] {
    let b = v.to_le_bytes();
    [kind, 4, b[0], b[1], b[2], b[3]]
}

/// `NFTNL_UDATA_SET_KEYBYTEORDER`: 1 host, 2 big-endian.
pub fn udata_byteorder(big: bool) -> [u8; 6] {
    udata_u32(0, if big { 2 } else { 1 })
}

/// `NFTNL_UDATA_SET_MERGE_ELEMENTS` (`auto-merge`).
pub fn udata_merge() -> [u8; 6] {
    udata_u32(2, 1)
}

/// `NFTNL_UDATA_SET_KEY_TYPEOF` for expression `expr` (nft's id) with
/// `fields` (each a u32 TLV, numbered from 0).
fn udata_typeof(expr: u32, fields: &[u32]) -> Vec<u8> {
    let mut data = Vec::new();
    for (i, f) in fields.iter().enumerate() {
        data.extend_from_slice(&udata_u32(u8::try_from(i).unwrap_or(0), *f));
    }
    let mut inner = udata_u32(0, expr).to_vec();
    inner.push(1);
    inner.push(u8::try_from(data.len()).unwrap_or(0));
    inner.extend(data);
    let mut out = vec![3, u8::try_from(inner.len()).unwrap_or(0)];
    out.extend(inner);
    out
}

/// nft's expression ids in `typeof` user data.
const TYPEOF_META: u32 = 9;

/// A port as two big-endian bytes.
fn port(p: u16) -> Vec<u8> {
    p.to_be_bytes().to_vec()
}

/// Port ranges sorted, overlapping and adjacent ones joined.
pub fn merged_ports(ports: &PortSet) -> Vec<PortRange> {
    let mut v = ports.0.clone();
    v.sort();
    let mut out: Vec<PortRange> = Vec::with_capacity(v.len());
    for r in v {
        if let Some(last) = out.last_mut()
            && u32::from(r.first) <= u32::from(last.last) + 1
        {
            last.last = last.last.max(r.last);
            continue;
        }
        out.push(r);
    }
    out
}

/// The shared set of a port list (`ports_22_80_443`): one per distinct
/// list in the whole table, whatever rules use it. An anonymous set per
/// rule cost the kernel a scan of every set of the table per set: 10 000
/// rules with `th dport { 22, 80, 443 }` took 22 s to load (nft too),
/// with one shared set as long as rules without a list (**medido**, G2.8).
pub fn port_set_name(ports: &PortSet) -> String {
    let items: Vec<String> = merged_ports(ports)
        .iter()
        .map(ToString::to_string)
        .collect();
    let name = format!("ports_{}", items.join("_"));
    if name.len() <= 64 {
        return name;
    }
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in name.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("ports_{h:016x}")
}

/// The port ranges of a set made by [`port_set`].
pub fn merged_ports_of(s: &FwSet) -> Vec<PortRange> {
    let p = |b: &[u8]| {
        u16::from_be_bytes([
            b.first().copied().unwrap_or(0),
            b.get(1).copied().unwrap_or(0),
        ])
    };
    s.elements
        .iter()
        .map(|e| PortRange {
            first: p(&e.key),
            last: e.last.as_deref().map_or(p(&e.key), p),
        })
        .collect()
}

/// The set [`port_set_name`] names.
pub fn port_set(ports: &PortSet) -> FwSet {
    FwSet {
        name: port_set_name(ports),
        key: KeyKind::Port,
        interval: true,
        timeout: false,
        dynamic: false,
        size: None,
        auto_merge: false,
        elements: merged_ports(ports)
            .iter()
            .map(|r| FwElement {
                key: port(r.first),
                last: (r.last != r.first).then(|| port(r.last)),
                timeout_ms: None,
            })
            .collect(),
    }
}

/// `th sport|dport [!=] <ports>`.
pub fn port_exprs(src: bool, not: bool, ports: &PortSet) -> Vec<Expr> {
    let load = Expr::Payload {
        base: Base::Transport,
        offset: if src { 0 } else { 2 },
        len: 2,
        dreg: REG_1,
    };
    match ports.0.as_slice() {
        [one] if one.first == one.last => vec![
            load,
            Expr::Cmp {
                sreg: REG_1,
                eq: !not,
                data: port(one.first),
            },
        ],
        [one] => {
            let mut out = vec![load];
            out.extend(range_exprs(not, port(one.first), port(one.last)));
            out
        }
        _ => vec![
            load,
            Expr::Lookup {
                set: port_set_name(ports),
                sreg: REG_1,
                dreg: None,
                inv: not,
            },
        ],
    }
}

/// A single port `p` of `n`, positive: what nft can merge with its
/// neighbour.
pub fn single_port(n: &Neg<PortSet>) -> Option<u16> {
    match n.value.0.as_slice() {
        [one] if !n.not && one.first == one.last => Some(one.first),
        _ => None,
    }
}

/// `th sport S th dport D`: one 4-byte load (nft merges them).
pub fn ports_merged(sport: u16, dport: u16) -> Vec<Expr> {
    vec![
        Expr::Payload {
            base: Base::Transport,
            offset: 0,
            len: 4,
            dreg: REG_1,
        },
        Expr::Cmp {
            sreg: REG_1,
            eq: true,
            data: [port(sport), port(dport)].concat(),
        },
    ]
}

/// `icmp type T [icmp code C]` (with code: one 2-byte load). The
/// `l4proto` dependency is the caller's.
pub fn icmp_exprs(kind: u8, code: Option<u8>) -> Vec<Expr> {
    let (len, data) = match code {
        Some(c) => (2, vec![kind, c]),
        None => (1, vec![kind]),
    };
    vec![
        Expr::Payload {
            base: Base::Transport,
            offset: 0,
            len,
            dreg: REG_1,
        },
        Expr::Cmp {
            sreg: REG_1,
            eq: true,
            data,
        },
    ]
}

/// The kernel's `ct state` bit of `s` (`NF_CT_STATE_BIT`).
pub fn state_bit(s: ConnState) -> u32 {
    match s {
        ConnState::Invalid => 1,
        ConnState::Established => 2,
        ConnState::Related => 4,
        ConnState::New => 8,
        ConnState::Untracked => 0x40,
    }
}

/// `x & mask != 0` (or `== 0`) on a 4-byte host-order ct value.
fn ct_mask(key: CtKey, mask: u32, nonzero: bool) -> Vec<Expr> {
    vec![
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
            eq: !nonzero,
            data: vec![0; 4],
        },
    ]
}

/// `ct state a,b` (`& (a | b) != 0`) or `ct state & (a | b) == 0`: the
/// state is one bit, so a mask is the set `{ a, b }` without an anonymous
/// set per rule (each one costs the kernel a scan of every set of the
/// table: 10 000 rules with `ct state { … }` took 3.2 s to load, with the
/// mask 68 ms, **medido**). nft compiles `ct state a,b` the same way.
pub fn ct_state_exprs(f: &Neg<Flags<ConnState>>) -> Vec<Expr> {
    let all = f.value.0.iter().fold(0, |a, s| a | state_bit(*s));
    ct_mask(CtKey::State, all, !f.not)
}

/// `ct status & (snat | dnat) != 0` (`== 0` negated): `IPS_SRC_NAT`,
/// `IPS_DST_NAT`.
pub fn ct_nat_exprs(f: &Neg<Flags<NatState>>) -> Vec<Expr> {
    let mask = f.value.0.iter().fold(0u32, |a, s| {
        a | match s {
            NatState::Srcnat => 0x10,
            NatState::Dstnat => 0x20,
        }
    });
    ct_mask(CtKey::Status, mask, !f.not)
}

/// `meta l4proto { tcp, udp }` (the subscriber notices' DNS pass).
pub fn l4proto_set(protos: &[u8]) -> Vec<Expr> {
    let mut udata = udata_byteorder(false).to_vec();
    udata.extend(udata_typeof(TYPEOF_META, &[MetaKey::L4Proto.number()]));
    vec![
        Expr::Meta {
            key: MetaKey::L4Proto,
            dreg: REG_1,
        },
        Expr::LookupAnon {
            set: AnonSet {
                key: KeyKind::L4Proto,
                interval: false,
                elements: protos.iter().map(|p| (vec![*p], false)).collect(),
                udata,
            },
            sreg: REG_1,
            inv: false,
        },
    ]
}

/// `meta mark & mask ==|!= value` (host-order u32).
pub fn mark_match(mask: u32, value: u32, eq: bool) -> Vec<Expr> {
    vec![
        Expr::Meta {
            key: MetaKey::Mark,
            dreg: REG_1,
        },
        Expr::And {
            sreg: REG_1,
            dreg: REG_1,
            mask: mask.to_ne_bytes().to_vec(),
        },
        Expr::Cmp {
            sreg: REG_1,
            eq,
            data: value.to_ne_bytes().to_vec(),
        },
    ]
}

/// `meta mark set meta mark & keep | value`.
pub fn mark_set(keep: u32, value: u32) -> Vec<Expr> {
    vec![
        Expr::Meta {
            key: MetaKey::Mark,
            dreg: REG_1,
        },
        Expr::Bitwise {
            sreg: REG_1,
            dreg: REG_1,
            mask: keep.to_ne_bytes().to_vec(),
            xor: value.to_ne_bytes().to_vec(),
        },
        Expr::MetaSet {
            key: MetaKey::Mark,
            sreg: REG_1,
        },
    ]
}

/// `ct mark [!=] value`.
pub fn ct_mark_match(not: bool, value: u32) -> Vec<Expr> {
    vec![
        Expr::Ct {
            key: CtKey::Mark,
            dir: None,
            dreg: REG_1,
        },
        Expr::Cmp {
            sreg: REG_1,
            eq: !not,
            data: value.to_ne_bytes().to_vec(),
        },
    ]
}

/// `ct mark set value`.
pub fn ct_mark_set(value: u32) -> Vec<Expr> {
    vec![
        Expr::Immediate {
            dreg: REG_1,
            data: value.to_ne_bytes().to_vec(),
        },
        Expr::CtSet {
            key: CtKey::Mark,
            sreg: REG_1,
        },
    ]
}

/// `snat|dnat ip|ip6 to first[-last][:p[-q]]`: the values in registers
/// 1.., then the statement.
pub fn nat_exprs(
    kind: crate::program::NatKind,
    first: IpAddr,
    last: IpAddr,
    ports: Option<PortRange>,
) -> Vec<Expr> {
    let v6 = first.is_ipv6();
    let mut out = vec![Expr::Immediate {
        dreg: REG_1,
        data: ip_bytes(first),
    }];
    let mut next = REG_2;
    let addr_max = (first != last).then(|| {
        out.push(Expr::Immediate {
            dreg: REG_2,
            data: ip_bytes(last),
        });
        next = REG_3;
        REG_2
    });
    let (proto_min, proto_max) = port_regs(&mut out, next, ports);
    out.push(Expr::NatRange {
        kind,
        family: if v6 { NFPROTO_IPV6 } else { NFPROTO_IPV4 },
        addr_min: Some(REG_1),
        addr_max,
        proto_min,
        proto_max,
        flags: if ports.is_some() {
            NAT_PROTO_SPECIFIED
        } else {
            0
        },
    });
    out
}

/// The ports of a NAT statement in registers from `reg` on.
fn port_regs(
    out: &mut Vec<Expr>,
    reg: u32,
    ports: Option<PortRange>,
) -> (Option<u32>, Option<u32>) {
    let Some(p) = ports else {
        return (None, None);
    };
    out.push(Expr::Immediate {
        dreg: reg,
        data: port(p.first),
    });
    if p.last != p.first {
        out.push(Expr::Immediate {
            dreg: reg + 1,
            data: port(p.last),
        });
        (Some(reg), Some(reg + 1))
    } else {
        (Some(reg), None)
    }
}

/// `masquerade [to :ports]`.
pub fn masq_exprs(ports: Option<PortRange>) -> Vec<Expr> {
    let mut out = Vec::new();
    let (proto_min, proto_max) = port_regs(&mut out, REG_1, ports);
    out.push(Expr::Masq {
        proto_min,
        proto_max,
        flags: if ports.is_some() {
            NAT_PROTO_SPECIFIED
        } else {
            0
        },
    });
    out
}

/// `redirect to :port`.
pub fn redir_exprs(p: u16) -> Vec<Expr> {
    vec![
        Expr::Immediate {
            dreg: REG_1,
            data: port(p),
        },
        Expr::Redir {
            proto_min: Some(REG_1),
            proto_max: None,
            flags: NAT_PROTO_SPECIFIED,
        },
    ]
}

/// `fib daddr type != local`.
pub fn fib_not_local() -> Vec<Expr> {
    vec![
        Expr::Fib {
            flags: FIB_F_DADDR,
            result: FIB_RESULT_ADDRTYPE,
            dreg: REG_1,
        },
        Expr::Cmp {
            sreg: REG_1,
            eq: false,
            data: RTN_LOCAL.to_ne_bytes().to_vec(),
        },
    ]
}

/// An address as a number, and its length in bytes.
fn num(a: IpAddr) -> (u128, usize) {
    match a {
        IpAddr::V4(v) => (u128::from(u32::from(v)), 4),
        IpAddr::V6(v) => (u128::from(v), 16),
    }
}

fn bytes_of(n: u128, len: usize) -> Vec<u8> {
    n.to_be_bytes()
        .get(16usize.saturating_sub(len)..)
        .unwrap_or(&[])
        .to_vec()
}

/// The elements of an address-list set (`flags interval, timeout`,
/// `auto-merge`): `statics` merged where they overlap or touch, as nft's
/// auto-merge does; timed entries keep their own timeout, lose what a
/// static entry already covers (it never expires) and, overlapping each
/// other, merge with the longer timeout. Sorted and disjoint. All
/// addresses must be of one family. Numbers, not byte vectors: 100 000
/// entries merge in ~4 ms (**medido**, G2.8).
pub fn interval_elements(statics: &[&AddrMatch], timed: &[(&AddrMatch, u64)]) -> Vec<FwElement> {
    let mut len = 4;
    let mut bounds = |a: &AddrMatch| {
        let (lo, hi) = a.bounds();
        let (l, n) = num(lo);
        len = n;
        (l, num(hi).0)
    };
    // Static ranges: sorted, overlapping and adjacent ones joined.
    let mut st: Vec<(u128, u128)> = statics.iter().map(|a| bounds(a)).collect();
    let mut tm: Vec<(u128, u128, u64)> = timed
        .iter()
        .map(|(a, t)| {
            let (l, h) = bounds(a);
            (l, h, (*t).max(1))
        })
        .collect();
    st.sort_unstable();
    let mut merged: Vec<(u128, u128)> = Vec::with_capacity(st.len());
    for (lo, hi) in st {
        if let Some(last) = merged.last_mut()
            && last.1.checked_add(1).is_none_or(|next| lo <= next)
        {
            last.1 = last.1.max(hi);
            continue;
        }
        merged.push((lo, hi));
    }
    // Timed ranges: overlapping ones joined (longest timeout).
    tm.sort_unstable();
    let mut tmerged: Vec<(u128, u128, u64)> = Vec::with_capacity(tm.len());
    for (lo, hi, t) in tm {
        if let Some(last) = tmerged.last_mut()
            && lo <= last.1
        {
            last.1 = last.1.max(hi);
            last.2 = last.2.max(t);
            continue;
        }
        tmerged.push((lo, hi, t));
    }
    // What the statics leave of each timed range (both lists sorted: one
    // walk).
    let mut pieces: Vec<(u128, u128, u64)> = Vec::with_capacity(tmerged.len());
    let mut first_static = 0;
    for (mut lo, hi, t) in tmerged {
        let mut alive = true;
        while merged.get(first_static).is_some_and(|s| s.1 < lo) {
            first_static += 1;
        }
        for (slo, shi) in merged.get(first_static..).unwrap_or(&[]) {
            if *slo > hi {
                break;
            }
            // Overlap: the part before the static range survives.
            if *slo > lo {
                pieces.push((lo, slo - 1, t));
            }
            match shi.checked_add(1) {
                Some(after) if after <= hi => lo = after,
                _ => {
                    alive = false;
                    break;
                }
            }
        }
        if alive {
            pieces.push((lo, hi, t));
        }
    }
    let mut out: Vec<(u128, u128, Option<u64>)> = merged
        .into_iter()
        .map(|(l, h)| (l, h, None))
        .chain(
            pieces
                .into_iter()
                .map(|(l, h, t)| (l, h, Some(t.saturating_mul(1000)))),
        )
        .collect();
    out.sort_unstable();
    out.into_iter()
        .map(|(l, h, timeout_ms)| FwElement {
            key: bytes_of(l, len),
            last: (h != l).then(|| bytes_of(h, len)),
            timeout_ms,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::program::interval_encoding;

    fn a(s: &str) -> AddrMatch {
        s.parse().unwrap()
    }

    fn hex(v: &[u8]) -> String {
        v.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// `nft --debug=netlink` for `ip saddr 10.16.0.0/12`, `/20`, `/0`,
    /// `ip daddr 192.0.2.0/24`, `ip saddr != 10.0.0.0/8`, `10.0.0.1`.
    #[test]
    fn prefixes_load_like_nft() {
        let e = addr_exprs(true, false, &a("10.16.0.0/12"));
        assert_eq!(e.len(), 3);
        assert!(matches!(
            &e[0],
            Expr::Payload {
                offset: 12,
                len: 4,
                ..
            }
        ));
        assert!(matches!(&e[1], Expr::And { mask, .. } if hex(mask) == "fff00000"));
        assert!(matches!(&e[2], Expr::Cmp { data, eq: true, .. } if hex(data) == "0a100000"));
        let e = addr_exprs(true, false, &a("10.16.0.0/20"));
        assert!(matches!(&e[1], Expr::And { mask, .. } if hex(mask) == "fffff000"));
        let e = addr_exprs(true, false, &a("0.0.0.0/0"));
        assert!(matches!(&e[1], Expr::And { mask, .. } if hex(mask) == "00000000"));
        let e = addr_exprs(false, false, &a("192.0.2.0/24"));
        assert!(matches!(
            &e[0],
            Expr::Payload {
                offset: 16,
                len: 3,
                ..
            }
        ));
        assert!(matches!(&e[1], Expr::Cmp { data, .. } if hex(data) == "c00002"));
        let e = addr_exprs(true, true, &a("10.0.0.0/8"));
        assert!(matches!(&e[0], Expr::Payload { len: 1, .. }));
        assert!(matches!(&e[1], Expr::Cmp { data, eq: false, .. } if hex(data) == "0a"));
        let e = addr_exprs(true, false, &a("10.0.0.1"));
        assert!(matches!(&e[1], Expr::Cmp { data, .. } if hex(data) == "0a000001"));
        // ip6 saddr 2001:db8::/33: 16 bytes and a mask.
        let e = addr_exprs(true, false, &a("2001:db8::/33"));
        assert!(matches!(
            &e[0],
            Expr::Payload {
                offset: 8,
                len: 16,
                ..
            }
        ));
        assert!(
            matches!(&e[1], Expr::And { mask, .. } if hex(mask) == "ffffffff800000000000000000000000")
        );
    }

    /// `ip saddr 10.0.0.1-10.0.0.9` is gte/lte; negated, `range neq`.
    #[test]
    fn ranges_like_nft() {
        let e = addr_exprs(true, false, &a("10.0.0.1-10.0.0.9"));
        assert!(
            matches!(&e[1], Expr::Order { op: Order::Gte, data, .. } if hex(data) == "0a000001")
        );
        assert!(
            matches!(&e[2], Expr::Order { op: Order::Lte, data, .. } if hex(data) == "0a000009")
        );
        let e = addr_exprs(false, true, &a("2001:db8::1-2001:db8::9"));
        assert!(matches!(
            &e[0],
            Expr::Payload {
                offset: 24,
                len: 16,
                ..
            }
        ));
        assert!(matches!(&e[1], Expr::Range { eq: false, .. }));
        let p: PortSet = PortSet(vec!["1000-2000".parse().unwrap()]);
        let e = port_exprs(false, true, &p);
        assert!(
            matches!(&e[1], Expr::Range { from, to, .. } if hex(from) == "03e8" && hex(to) == "07d0")
        );
    }

    /// A port list is a shared interval set, its ranges merged.
    #[test]
    fn port_lists_are_shared_sets() {
        let p = PortSet(vec![
            "443".parse().unwrap(),
            "22".parse().unwrap(),
            "1000-2000".parse().unwrap(),
            "1500-2500".parse().unwrap(),
            "2501".parse().unwrap(),
        ]);
        assert_eq!(port_set_name(&p), "ports_22_443_1000-2501");
        let e = port_exprs(false, true, &p);
        assert!(
            matches!(&e[1], Expr::Lookup { set, inv: true, .. } if set == "ports_22_443_1000-2501")
        );
        let s = port_set(&p);
        assert!(s.interval);
        let keys: Vec<String> = s
            .encoded()
            .iter()
            .map(|e| format!("{}{}", hex(&e.key), if e.end { "e" } else { "" }))
            .collect();
        assert_eq!(
            keys,
            ["0000e", "0016", "0017e", "01bb", "01bce", "03e8", "09c6e"]
        );
        // Long lists get a hashed name.
        let many = PortSet(
            (0..32)
                .map(|i| PortRange {
                    first: 100 * i,
                    last: 100 * i,
                })
                .collect(),
        );
        let name = port_set_name(&many);
        assert!(name.len() <= 64 && name.starts_with("ports_"), "{name}");
    }

    #[test]
    fn ct_states_are_masks() {
        let f = |not: bool, s: &[ConnState]| Neg {
            not,
            value: Flags(s.to_vec()),
        };
        let e = ct_state_exprs(&f(
            false,
            &[
                ConnState::Established,
                ConnState::Related,
                ConnState::Untracked,
            ],
        ));
        assert!(matches!(&e[1], Expr::And { mask, .. } if mask == &0x46u32.to_ne_bytes()));
        assert!(matches!(&e[2], Expr::Cmp { eq: false, .. }));
        // & (new | invalid) == 0
        let e = ct_state_exprs(&f(true, &[ConnState::New, ConnState::Invalid]));
        assert!(matches!(&e[1], Expr::And { mask, .. } if mask == &9u32.to_ne_bytes()));
        assert!(matches!(&e[2], Expr::Cmp { eq: true, .. }));
    }

    #[test]
    fn l4proto_set_udata_like_nft() {
        let e = l4proto_set(&[6, 17]);
        let Expr::LookupAnon { set, .. } = &e[1] else {
            panic!("{e:?}")
        };
        assert_eq!(
            hex(&set.udata),
            "000401000000030e0004090000000106000410000000"
        );
    }

    #[test]
    fn interval_elements_merge_and_clip() {
        let s1 = a("10.0.0.0/24");
        let s2 = a("10.0.1.0/24");
        let s3 = a("10.0.0.5");
        let t1 = a("10.0.0.200-10.0.2.10");
        let t2 = a("192.0.2.1");
        let el = interval_elements(&[&s1, &s2, &s3], &[(&t1, 60), (&t2, 5)]);
        let show: Vec<String> = el
            .iter()
            .map(|e| {
                format!(
                    "{}-{}:{:?}",
                    hex(&e.key),
                    hex(e.last.as_ref().unwrap_or(&e.key)),
                    e.timeout_ms
                )
            })
            .collect();
        assert_eq!(
            show,
            [
                "0a000000-0a0001ff:None",
                "0a000200-0a00020a:Some(60000)",
                "c0000201-c0000201:Some(5000)"
            ]
        );
        let enc = interval_encoding(&el);
        // 0-end, 10.0.0.0, 10.0.2.0 end + 10.0.2.0 start (they touch), …
        assert_eq!(enc.len(), 1 + 2 + 2 + 2);
        // A timed entry wholly inside a static one is gone.
        let el = interval_elements(&[&s1], &[(&s3, 60)]);
        assert_eq!(el.len(), 1);
        // One that sticks out on both sides is cut in two.
        let mid = a("10.0.0.10-10.0.0.20");
        let wide = a("10.0.0.0-10.0.0.255");
        let el = interval_elements(&[&mid], &[(&wide, 60)]);
        assert_eq!(el.len(), 3, "{el:?}");
    }
}
