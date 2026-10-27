//! The CGNAT pools as an nftables table (G2.3): what "View generated
//! rules" shows and what `hal-linux` sends to the kernel over nfnetlink
//! (one description, `program::Table`, for both).
//!
//! Everything lives in table `ip corerouter_cgnat`, apart from the
//! firewall's `inet corerouter`, so the two never replace each other. Per
//! pool, **one map and a handful of rules**, never a rule per subscriber
//! (the RouterOS scripts make two per subscriber, 76 000 for a /21 of
//! subscribers):
//!
//! - `d_<id>`: subscriber → public address . port range, one element per
//!   subscriber (`Layout::entries`), used by **one** `snat` for every
//!   protocol: TCP and UDP ports and ICMP query ids get the range (the
//!   kernel applies it to ids too, `nf_nat_l4proto_unique_tuple`; RFC 5508
//!   §3.1, RFC 7422 §2), GRE, ESP and the rest the address only (the
//!   kernel ignores a port range for protocols without ports), so the
//!   pairing of RFC 6888 REQ-2 holds for all. `nft` itself refuses a port
//!   range without a protocol match; the kernel does not, which is one
//!   reason we speak netlink (G2.3b);
//! - `pub_<id>`: the public ranges (interval set): packets for them that no
//!   connection claims are dropped in `forward` (the block is routed to
//!   the router; without that rule they would be routed back);
//! - `eim_<id>` / `eimr_<id>`: the live UDP mappings, public → subscriber
//!   and back, filled after the translation by a filter chain (a second
//!   nat chain never runs once the first bound the connection), read by
//!   `dnat` (endpoint-independent filtering, RFC 4787 REQ-8, and
//!   hairpinning, REQ-9) and by `snat` (the same public port for every
//!   destination, REQ-1), with the RFC 4787 REQ-5 timer (5 min);
//! - exceptions: `x_1to1` / `x_1to1_in`, subscriber ↔ its own public
//!   address, ahead of every pool, ports kept.

use std::net::Ipv4Addr;

use corerouter_model::ItemId;
use corerouter_model::cgnat::{Cgnat, Mode, Pool};

use crate::program::{
    Chain, ChainType, CtKey, Dir, Element, Expr, Hook, NatKind, REG_1, REG32_1, REG32_2, REG32_3,
    Rule, Set, Table, Type, Value, ct_bits, ip_addr, l4_port, l4proto_is, merge, oifname_is,
};

const UDP: u8 = 17;
/// `ct state new` (`NF_CT_STATE_BIT(IP_CT_NEW)`).
const CT_STATE_NEW: u32 = 1 << 3;
/// `IPS_SRC_NAT` / `IPS_DST_NAT`.
const IPS_SRC_NAT: u32 = 1 << 4;
const IPS_DST_NAT: u32 = 1 << 5;

fn name(prefix: &str, p: &Pool) -> String {
    format!("{prefix}_{:x}", p.id.0)
}

fn chain(name: &str, kind: ChainType, hook: Hook, priority: i32, text: &str) -> Chain {
    Chain {
        name: name.into(),
        kind,
        hook,
        priority,
        priority_text: text.into(),
    }
}

fn rule(chain: &str, exprs: Vec<Expr>, text: String) -> Rule {
    Rule {
        chain: chain.into(),
        exprs,
        text,
        nft: None,
        comment: None,
    }
}

/// `snat ip to ip saddr map @<d>`: the formula's slot, for every protocol
/// (TCP and UDP ports, ICMP query ids; others take the address only:
/// the kernel ignores a port range for protocols without ports).
fn formula(d: &str) -> Vec<Expr> {
    vec![
        ip_addr(true, REG_1),
        Expr::Lookup {
            set: d.into(),
            sreg: REG_1,
            dreg: Some(REG_1),
            inv: false,
        },
        Expr::Nat {
            kind: NatKind::Snat,
            addr_min: REG_1,
            addr_max: Some(REG32_2),
            proto_min: Some(REG32_1),
            proto_max: Some(REG32_3),
        },
    ]
}

/// Pools that reach the kernel: enabled, laid out. Blocks-mode pools get
/// their map filled by the block allocator (G2.3c), not here.
pub fn active(c: &Cgnat) -> impl Iterator<Item = &Pool> {
    c.pools.iter().filter(|p| !p.disabled && p.layout().is_ok())
}

/// The whole table, or `None` when nothing is configured (the table is
/// then deleted).
pub fn table(c: &Cgnat) -> Option<Table> {
    let pools: Vec<&Pool> = active(c).collect();
    let exceptions: Vec<_> = c.exceptions.iter().filter(|e| !e.disabled).collect();
    if pools.is_empty() && exceptions.is_empty() {
        return None;
    }
    let mut t = Table {
        name: TABLE.into(),
        ..Table::default()
    };
    let addr_map = |name: &str, elements: Vec<Element>| Set {
        name: name.into(),
        key: Type::Addr,
        data: Some(Type::Addr),
        interval: false,
        dynamic_timeout: None,
        size: None,
        elements,
    };
    if !exceptions.is_empty() {
        t.sets.push(addr_map(
            "x_1to1",
            exceptions
                .iter()
                .map(|e| Element {
                    key: Value::Addr(e.subscriber),
                    key_last: None,
                    data: Some(Value::Addr(e.public)),
                })
                .collect(),
        ));
        t.sets.push(addr_map(
            "x_1to1_in",
            exceptions
                .iter()
                .map(|e| Element {
                    key: Value::Addr(e.public),
                    key_last: None,
                    data: Some(Value::Addr(e.subscriber)),
                })
                .collect(),
        ));
    }
    for p in &pools {
        let Ok(layout) = p.layout() else { continue };
        let elements: Vec<Element> = if p.mode == Mode::Deterministic {
            layout
                .entries()
                .filter(|(sub, _)| c.exception_of(*sub).is_none())
                .map(|(sub, slot)| Element {
                    key: Value::Addr(sub),
                    key_last: None,
                    data: Some(Value::AddrPortRange(
                        slot.public,
                        slot.first_port,
                        slot.last_port,
                    )),
                })
                .collect()
        } else {
            Vec::new()
        };
        t.sets.push(Set {
            name: name("d", p),
            key: Type::Addr,
            data: Some(Type::AddrPortRange),
            interval: false,
            dynamic_timeout: None,
            // No size hint: the hash grows with the pool, so more
            // subscribers are new elements, not a new table.
            size: None,
            elements,
        });
        t.sets.push(Set {
            name: name("pub", p),
            key: Type::Addr,
            data: None,
            interval: true,
            dynamic_timeout: None,
            size: None,
            elements: merge(p.outside.iter().map(|r| (r.start, r.end)).collect())
                .into_iter()
                .map(|(a, b)| Element {
                    key: Value::Addr(a),
                    key_last: Some(b),
                    data: None,
                })
                .collect(),
        });
        if p.mode == Mode::Blocks {
            t.sets.push(Set {
                name: name("in", p),
                key: Type::Addr,
                data: None,
                interval: true,
                dynamic_timeout: None,
                size: None,
                elements: merge(p.inside.iter().map(|r| (r.start, r.end)).collect())
                    .into_iter()
                    .map(|(a, b)| Element {
                        key: Value::Addr(a),
                        key_last: Some(b),
                        data: None,
                    })
                    .collect(),
            });
        }
        if p.endpoint_independent_mapping {
            for prefix in ["eim", "eimr"] {
                t.sets.push(Set {
                    name: name(prefix, p),
                    key: Type::AddrPort,
                    data: Some(Type::AddrPort),
                    interval: false,
                    dynamic_timeout: Some(EIM_TIMEOUT_SECS),
                    size: Some(EIM_SIZE),
                    elements: Vec::new(),
                });
            }
        }
    }
    let exhaustion = c.settings.icmp_unreachable && !pools.is_empty();
    if exhaustion {
        // Filled by the engine with the subscribers near the end of their
        // ports (G2.7); empty, the rule below matches nothing.
        t.sets.push(Set {
            name: FULL.into(),
            key: Type::Addr,
            data: None,
            interval: false,
            dynamic_timeout: None,
            size: None,
            elements: Vec::new(),
        });
    }
    t.chains.push(chain(
        "prerouting",
        ChainType::Nat,
        Hook::Prerouting,
        -100,
        "dstnat",
    ));
    t.chains.push(chain(
        "postrouting",
        ChainType::Nat,
        Hook::Postrouting,
        100,
        "srcnat",
    ));
    if pools.iter().any(|p| p.endpoint_independent_mapping) {
        t.chains.push(chain(
            "mappings",
            ChainType::Filter,
            Hook::Postrouting,
            110,
            "srcnat + 10",
        ));
    }
    if pools.iter().any(|p| p.mode == Mode::Blocks) {
        t.chains.push(chain(
            "blocks",
            ChainType::Filter,
            Hook::Postrouting,
            90,
            "srcnat - 10",
        ));
    }
    if exhaustion {
        t.chains.push(chain(
            "exhausted",
            ChainType::Filter,
            Hook::Postrouting,
            105,
            "srcnat + 5",
        ));
    }
    t.chains.push(chain(
        "forward",
        ChainType::Filter,
        Hook::Forward,
        -5,
        "filter - 5",
    ));

    // dstnat: the 1:1 exceptions inbound, then live UDP mappings.
    if !exceptions.is_empty() {
        t.rules.push(rule(
            "prerouting",
            vec![
                ip_addr(false, REG_1),
                Expr::Lookup {
                    set: "x_1to1_in".into(),
                    sreg: REG_1,
                    dreg: Some(REG_1),
                    inv: false,
                },
                Expr::Nat {
                    kind: NatKind::Dnat,
                    addr_min: REG_1,
                    addr_max: None,
                    proto_min: None,
                    proto_max: None,
                },
            ],
            "dnat ip to ip daddr map @x_1to1_in".into(),
        ));
    }
    for p in pools.iter().filter(|p| p.endpoint_independent_mapping) {
        // EIF (RFC 4787 REQ-8): anyone reaches a live mapping; otherwise
        // only hairpin (REQ-9: a subscriber of the pool) uses the map.
        let mut exprs = Vec::new();
        let mut text = String::new();
        if !p.endpoint_independent_filtering {
            if !p.hairpin {
                continue;
            }
            exprs.push(ip_addr(true, REG_1));
            exprs.push(Expr::Lookup {
                set: name("d", p),
                sreg: REG_1,
                dreg: None,
                inv: false,
            });
            text.push_str(&format!("ip saddr @{} ", name("d", p)));
        }
        exprs.extend(l4proto_is(UDP));
        exprs.extend([
            ip_addr(false, REG_1),
            l4_port(false, REG32_1),
            Expr::Lookup {
                set: name("eim", p),
                sreg: REG_1,
                dreg: Some(REG_1),
                inv: false,
            },
            Expr::Nat {
                kind: NatKind::Dnat,
                addr_min: REG_1,
                addr_max: None,
                proto_min: Some(REG32_1),
                proto_max: None,
            },
        ]);
        text.push_str(&format!(
            "dnat ip to ip daddr . udp dport map @{}",
            name("eim", p)
        ));
        t.rules.push(rule("prerouting", exprs, text));
    }

    // srcnat: the exceptions, then per pool live UDP mappings (EIM, REQ-1)
    // and the formula.
    if !exceptions.is_empty() {
        t.rules.push(rule(
            "postrouting",
            vec![
                ip_addr(true, REG_1),
                Expr::Lookup {
                    set: "x_1to1".into(),
                    sreg: REG_1,
                    dreg: Some(REG_1),
                    inv: false,
                },
                Expr::Nat {
                    kind: NatKind::Snat,
                    addr_min: REG_1,
                    addr_max: None,
                    proto_min: None,
                    proto_max: None,
                },
            ],
            "snat ip to ip saddr map @x_1to1".into(),
        ));
    }
    for p in &pools {
        let d = name("d", p);
        let (oif, oif_text): (Vec<Expr>, String) = match &p.out_interface {
            Some(i) => (oifname_is(i.as_str()).to_vec(), format!("oifname \"{i}\" ")),
            None => (Vec::new(), String::new()),
        };
        if p.endpoint_independent_mapping {
            let mut exprs = oif.clone();
            exprs.extend(l4proto_is(UDP));
            exprs.extend([
                ip_addr(true, REG_1),
                l4_port(true, REG32_1),
                Expr::Lookup {
                    set: name("eimr", p),
                    sreg: REG_1,
                    dreg: Some(REG_1),
                    inv: false,
                },
                Expr::Nat {
                    kind: NatKind::Snat,
                    addr_min: REG_1,
                    addr_max: None,
                    proto_min: Some(REG32_1),
                    proto_max: None,
                },
            ]);
            t.rules.push(rule(
                "postrouting",
                exprs,
                format!(
                    "{oif_text}snat ip to ip saddr . udp sport map @{}",
                    name("eimr", p)
                ),
            ));
        }
        let mut exprs = oif;
        exprs.extend(formula(&d));
        let mut r = rule(
            "postrouting",
            exprs,
            format!("{oif_text}snat ip to ip saddr map @{d}"),
        );
        // `nft` refuses a port range without a protocol match (the kernel
        // does not): its spelling, for the comparison benchmark.
        r.nft = Some(format!(
            "{oif_text}meta l4proto {{ tcp, udp, icmp }} snat ip to ip saddr map @{d}"
        ));
        t.rules.push(r);
        if p.hairpin && p.out_interface.is_some() {
            // A hairpinned packet leaves through the inside interface and is
            // translated all the same (REQ-9b: the receiver sees the
            // sender's public address and port).
            let mut exprs = ct_bits(CtKey::Status, IPS_DST_NAT).to_vec();
            exprs.extend(formula(&d));
            let mut r = rule(
                "postrouting",
                exprs,
                format!("ct status dnat snat ip to ip saddr map @{d}"),
            );
            r.nft = Some(format!(
                "ct status dnat meta l4proto {{ tcp, udp, icmp }} snat ip to ip saddr map @{d}"
            ));
            t.rules.push(r);
        }
    }

    // After the translation (a filter chain: a second nat chain never runs
    // once the first bound the connection): record the UDP mappings.
    for p in pools.iter().filter(|p| p.endpoint_independent_mapping) {
        let ct = |key, dir, dreg| Expr::Ct {
            key,
            dir: Some(dir),
            dreg,
        };
        let mut exprs = l4proto_is(UDP).to_vec();
        exprs.extend(ct_bits(CtKey::State, CT_STATE_NEW));
        exprs.extend(ct_bits(CtKey::Status, IPS_SRC_NAT));
        exprs.extend([
            ct(CtKey::SrcIp, Dir::Original, REG_1),
            Expr::Lookup {
                set: name("d", p),
                sreg: REG_1,
                dreg: None,
                inv: false,
            },
            // public . port : subscriber . port
            ct(CtKey::DstIp, Dir::Reply, REG_1),
            ct(CtKey::ProtoDst, Dir::Reply, REG32_1),
            ct(CtKey::SrcIp, Dir::Original, REG32_2),
            ct(CtKey::ProtoSrc, Dir::Original, REG32_3),
            Expr::Update {
                set: name("eim", p),
                sreg_key: REG_1,
                sreg_data: REG32_2,
            },
            // subscriber . port : public . port
            ct(CtKey::SrcIp, Dir::Original, REG_1),
            ct(CtKey::ProtoSrc, Dir::Original, REG32_1),
            ct(CtKey::DstIp, Dir::Reply, REG32_2),
            ct(CtKey::ProtoDst, Dir::Reply, REG32_3),
            Expr::Update {
                set: name("eimr", p),
                sreg_key: REG_1,
                sreg_data: REG32_2,
            },
        ]);
        t.rules.push(rule(
            "mappings",
            exprs,
            format!(
                "meta l4proto udp ct state new ct status snat ct original ip saddr @{d} \
                 update @{eim} {{ ct reply ip daddr . ct reply proto-dst : ct original ip saddr . ct original proto-src }} \
                 update @{eimr} {{ ct original ip saddr . ct original proto-src : ct reply ip daddr . ct reply proto-dst }}",
                d = name("d", p),
                eim = name("eim", p),
                eimr = name("eimr", p),
            ),
        ));
    }

    // Blocks mode (G2.3c): a subscriber without a block waits in the queue
    // until the daemon allocates one; then its packet goes on to srcnat.
    for p in pools.iter().filter(|p| p.mode == Mode::Blocks) {
        let mut exprs = vec![
            ip_addr(true, REG_1),
            Expr::Lookup {
                set: name("in", p),
                sreg: REG_1,
                dreg: None,
                inv: false,
            },
            Expr::Lookup {
                set: name("d", p),
                sreg: REG_1,
                dreg: None,
                inv: true,
            },
        ];
        let mut text = format!("ip saddr @{} ip saddr != @{}", name("in", p), name("d", p));
        if !exceptions.is_empty() {
            exprs.push(Expr::Lookup {
                set: "x_1to1".into(),
                sreg: REG_1,
                dreg: None,
                inv: true,
            });
            text.push_str(" ip saddr != @x_1to1");
        }
        exprs.push(Expr::Queue {
            num: QUEUE_NUM,
            total: 1,
            bypass: false,
        });
        t.rules.push(rule(
            "blocks",
            exprs,
            format!("{text} queue num {QUEUE_NUM}"),
        ));
    }

    // Port exhaustion (G2.7, RFC 6888 REQ-11). The kernel's NAT never
    // fails: with no free port in the slot it keeps a tuple already in use
    // (nf_nat_core.c, `nf_nat_l4proto_unique_tuple`: 128 + 64 + 32 + 16
    // tries), and conntrack drops the packet at confirmation, after every
    // hook, counting only `insert_failed`. So right after the NAT, the new
    // connections of the few subscribers near the end of their ports go to
    // userspace, which looks the chosen reply tuple up: taken means refused,
    // and the subscriber gets the ICMP (REQ-11b). `bypass`: nobody serving,
    // the kernel decides as before. Everyone else never leaves the kernel.
    if exhaustion {
        let mut exprs = ct_bits(CtKey::State, CT_STATE_NEW).to_vec();
        exprs.extend([
            Expr::Ct {
                key: CtKey::SrcIp,
                dir: Some(Dir::Original),
                dreg: REG_1,
            },
            Expr::Lookup {
                set: FULL.into(),
                sreg: REG_1,
                dreg: None,
                inv: false,
            },
            Expr::Queue {
                num: EXHAUSTED_QUEUE,
                total: EXHAUSTED_QUEUES,
                bypass: true,
            },
        ]);
        t.rules.push(rule(
            "exhausted",
            exprs,
            format!(
                "ct state new ct original ip saddr @{FULL} queue num {}-{} bypass",
                EXHAUSTED_QUEUE,
                EXHAUSTED_QUEUE + EXHAUSTED_QUEUES - 1
            ),
        ));
    }

    // Nothing unclaimed reaches the public blocks.
    for p in &pools {
        t.rules.push(rule(
            "forward",
            vec![
                ip_addr(false, REG_1),
                Expr::Lookup {
                    set: name("pub", p),
                    sreg: REG_1,
                    dreg: None,
                    inv: false,
                },
                Expr::Counter,
                Expr::Drop,
            ],
            format!("ip daddr @{} counter drop", name("pub", p)),
        ));
    }
    Some(t)
}

/// The netfilter queue that holds the first packet of a blocks-mode
/// subscriber without a block until the daemon allocates one (RFC 7422,
/// as a number to remember).
pub const QUEUE_NUM: u16 = 7422;
/// The first of the queues of nearly full subscribers' new connections
/// (G2.7), right after [`QUEUE_NUM`].
pub const EXHAUSTED_QUEUE: u16 = 7423;
/// How many: the kernel spreads them by flow hash, the daemon serves each
/// with a thread.
pub const EXHAUSTED_QUEUES: u16 = 4;
/// The set of subscribers near the end of their ports (G2.7).
pub const FULL: &str = "full";

/// The table every CGNAT object lives in.
pub const TABLE: &str = "corerouter_cgnat";
/// RFC 4787 REQ-5: UDP mapping timer ≥ 2 min, 5 min recommended.
pub const EIM_TIMEOUT_SECS: u32 = 300;
/// Live UDP mappings one pool keeps (the map's size bound).
pub const EIM_SIZE: u32 = 1 << 20;

/// What "View generated rules" shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    pub script: String,
    /// Static map elements (deterministic slots + exceptions).
    pub elements: u64,
    pub rules: u32,
}

/// The table (`only`: one pool's part, for display).
pub fn render(c: &Cgnat, only: Option<ItemId>) -> Rendered {
    let mut c = c.clone();
    if let Some(id) = only {
        c.pools.retain(|p| p.id == id);
        c.exceptions.clear();
    }
    match table(&c) {
        Some(t) => Rendered {
            script: t.text(),
            elements: t.elements(),
            rules: u32::try_from(t.rules.len()).unwrap_or(u32::MAX),
        },
        None => Rendered {
            script: String::new(),
            elements: 0,
            rules: 0,
        },
    }
}

/// The same table as an `nft -f` script that replaces it in one
/// transaction (create, delete, recreate): what the comparison benchmark
/// loads with the `nft` program. Rules `nft` spells differently use its
/// spelling.
pub fn nft_script(c: &Cgnat) -> String {
    let mut s = format!("table ip {TABLE}\ndelete table ip {TABLE}\n");
    if let Some(mut t) = table(c) {
        for r in &mut t.rules {
            if let Some(n) = r.nft.take() {
                r.text = n;
            }
        }
        s.push_str(&t.text());
    }
    s
}

/// Where `subscriber` goes out under `c`: its public address and ports.
fn mapping_of(
    c: &Cgnat,
    layouts: &[(&Pool, corerouter_model::cgnat::Layout)],
    sub: Ipv4Addr,
) -> Option<(Ipv4Addr, u16, u16)> {
    if let Some(e) = c.exception_of(sub) {
        return Some((e.public, 0, u16::MAX));
    }
    let (_, l) = layouts
        .iter()
        .find(|(p, _)| p.inside.iter().any(|r| r.contains(sub)))?;
    l.forward(sub)
        .map(|s| (s.public, s.first_port, s.last_port))
}

fn laid(c: &Cgnat) -> Vec<(&Pool, corerouter_model::cgnat::Layout)> {
    active(c)
        .filter(|p| p.mode == Mode::Deterministic)
        .filter_map(|p| p.layout().ok().map(|l| (p, l)))
        .collect()
}

/// Subscribers whose public address or ports differ between `from` and
/// `to` (or who lost their mapping): their live connections still carry
/// the old translation, so the kernel backend kills them after the
/// change, and "who was" stays exact (the new mapping holds from the
/// commit on). Blocks-mode pools are not here: their blocks live on.
pub fn remapped(from: &Cgnat, to: &Cgnat) -> Vec<Ipv4Addr> {
    let (old, new) = (laid(from), laid(to));
    let mut out: Vec<Ipv4Addr> = Vec::new();
    let subscribers = old
        .iter()
        .flat_map(|(_, l)| (0..l.subscribers()).filter_map(|i| l.subscriber(i)))
        .chain(
            from.exceptions
                .iter()
                .filter(|e| !e.disabled)
                .map(|e| e.subscriber),
        );
    for sub in subscribers {
        if mapping_of(from, &old, sub) != mapping_of(to, &new, sub) {
            out.push(sub);
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Whether the part of the config the kernel sees changed.
pub fn changed(from: &Cgnat, to: &Cgnat) -> bool {
    from.pools != to.pools
        || from.exceptions != to.exceptions
        || from.settings.icmp_unreachable != to.settings.icmp_unreachable
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_model::cgnat::Exception;

    pub(crate) fn pool(id: u32, inside: &str, outside: &str, ports: u16) -> Pool {
        serde_json::from_value(serde_json::json!({
            "id": format!("*{id:x}"), "name": format!("p{id}"),
            "inside": [inside], "outside": [outside], "ports_per_subscriber": ports,
        }))
        .unwrap()
    }

    #[test]
    fn one_map_and_a_few_rules_per_pool() {
        let mut c = Cgnat::default();
        c.pools.push(pool(1, "100.64.0.0/30", "203.0.113.1", 1000));
        c.exceptions.push(Exception {
            id: ItemId(2),
            subscriber: "100.64.0.3".parse().unwrap(),
            public: "198.51.100.7".parse().unwrap(),
            disabled: false,
            comment: String::new(),
        });
        let r = render(&c, None);
        // Three subscribers in the map (the fourth has a 1:1), the
        // exception both ways, the public range.
        assert_eq!(r.elements, 3 + 2 + 1, "{}", r.script);
        assert!(
            r.script.contains("100.64.0.1 : 203.0.113.1 . 2024-3023"),
            "{}",
            r.script
        );
        assert!(
            !r.script.contains("100.64.0.3 : 203.0.113.1"),
            "{}",
            r.script
        );
        assert!(
            r.script.contains("100.64.0.3 : 198.51.100.7"),
            "{}",
            r.script
        );
        assert!(
            r.script.contains("\t\tsnat ip to ip saddr map @d_1\n"),
            "{}",
            r.script
        );
        // exceptions in and out, hairpin dnat, EIM snat, formula, the
        // mapping recorder, the exhaustion queue, the forward drop.
        assert_eq!(r.rules, 8, "{}", r.script);
        let t = table(&c).unwrap();
        let formula = t
            .rules
            .iter()
            .find(|r| r.text.ends_with("map @d_1"))
            .unwrap();
        assert!(matches!(
            formula.exprs.last(),
            Some(Expr::Nat {
                addr_max: Some(_),
                proto_max: Some(_),
                ..
            })
        ));
        assert!(
            nft_script(&c).contains("meta l4proto { tcp, udp, icmp } snat ip to ip saddr map @d_1")
        );
    }

    #[test]
    fn nothing_configured_only_deletes() {
        let c = Cgnat::default();
        assert!(table(&c).is_none());
        assert_eq!(
            nft_script(&c),
            format!("table ip {TABLE}\ndelete table ip {TABLE}\n")
        );
        let mut c = Cgnat::default();
        let mut p = pool(1, "100.64.0.0/30", "203.0.113.1", 1000);
        p.disabled = true;
        c.pools.push(p);
        assert!(table(&c).is_none());
    }

    #[test]
    fn out_interface_and_hairpin_add_the_hairpin_rule() {
        let mut c = Cgnat::default();
        let mut p = pool(1, "100.64.0.0/30", "203.0.113.1", 1000);
        p.out_interface = Some("ether1".parse().unwrap());
        p.endpoint_independent_filtering = true;
        c.pools.push(p);
        let r = render(&c, None);
        assert!(
            r.script
                .contains("oifname \"ether1\" snat ip to ip saddr map @d_1"),
            "{}",
            r.script
        );
        assert!(
            r.script
                .contains("ct status dnat snat ip to ip saddr map @d_1")
        );
        assert!(
            r.script
                .contains("\t\tdnat ip to ip daddr . udp dport map @eim_1"),
            "{}",
            r.script
        );
    }

    #[test]
    fn remapped_subscribers_are_the_moved_ones() {
        let mut a = Cgnat::default();
        a.pools.push(pool(1, "100.64.0.0/30", "203.0.113.1", 1000));
        // A 1:1 for .2 moves only .2.
        let mut b = a.clone();
        b.exceptions.push(Exception {
            id: ItemId(2),
            subscriber: "100.64.0.2".parse().unwrap(),
            public: "198.51.100.7".parse().unwrap(),
            disabled: false,
            comment: String::new(),
        });
        assert_eq!(
            remapped(&a, &b),
            ["100.64.0.2".parse::<Ipv4Addr>().unwrap()]
        );
        assert_eq!(
            remapped(&b, &a),
            ["100.64.0.2".parse::<Ipv4Addr>().unwrap()]
        );
        // Other ports per subscriber: everyone moves.
        let mut c = a.clone();
        c.pools[0].ports_per_subscriber = 2000;
        assert_eq!(remapped(&a, &c).len(), 4);
        // A comment moves nobody; removing the pool moves everyone.
        let mut d = a.clone();
        d.pools[0].comment = "x".into();
        assert!(remapped(&a, &d).is_empty());
        assert_eq!(remapped(&a, &Cgnat::default()).len(), 4);
    }

    #[test]
    fn an_element_change_keeps_the_skeleton() {
        let mut a = Cgnat::default();
        a.pools.push(pool(1, "100.64.0.0/30", "203.0.113.1", 1000));
        let mut b = a.clone();
        b.exceptions.push(Exception {
            id: ItemId(2),
            subscriber: "100.64.0.3".parse().unwrap(),
            public: "198.51.100.7".parse().unwrap(),
            disabled: false,
            comment: String::new(),
        });
        // An exception adds maps and rules: a new skeleton.
        assert_ne!(table(&a).unwrap().skeleton(), table(&b).unwrap().skeleton());
        let mut c = a.clone();
        c.pools[0].ports_per_subscriber = 2000;
        assert_eq!(table(&a).unwrap().skeleton(), table(&c).unwrap().skeleton());
    }

    /// G2.7: right after the NAT (srcnat + 5), only the new connections of
    /// the subscribers in `full` go to the exhaustion queues, with bypass;
    /// turned off, neither the set nor the chain exist.
    #[test]
    fn exhaustion_queues_only_the_full_subscribers() {
        let mut c = Cgnat::default();
        c.pools.push(pool(1, "100.64.0.0/30", "203.0.113.1", 1000));
        let t = table(&c).unwrap();
        let r = t.rules.iter().find(|r| r.chain == "exhausted").unwrap();
        assert_eq!(
            r.text,
            "ct state new ct original ip saddr @full queue num 7423-7426 bypass"
        );
        assert!(matches!(
            r.exprs.last(),
            Some(Expr::Queue {
                num: 7423,
                total: 4,
                bypass: true
            })
        ));
        let ch = t.chains.iter().find(|ch| ch.name == "exhausted").unwrap();
        assert_eq!((ch.hook, ch.priority), (Hook::Postrouting, 105));
        assert!(
            t.sets
                .iter()
                .any(|s| s.name == FULL && s.elements.is_empty())
        );
        let mut off = c.clone();
        off.settings.icmp_unreachable = false;
        assert!(changed(&c, &off));
        let t = table(&off).unwrap();
        assert!(t.rules.iter().all(|r| r.chain != "exhausted"));
        assert!(t.sets.iter().all(|s| s.name != FULL));
        // The blocks queue keeps no bypass: never out untranslated.
        let mut b = Cgnat::default();
        let mut p = pool(1, "100.64.0.0/30", "203.0.113.1", 1000);
        p.mode = Mode::Blocks;
        b.pools.push(p);
        let t = table(&b).unwrap();
        let q = t.rules.iter().find(|r| r.chain == "blocks").unwrap();
        assert!(matches!(
            q.exprs.last(),
            Some(Expr::Queue {
                num: QUEUE_NUM,
                total: 1,
                bypass: false
            })
        ));
    }
}
