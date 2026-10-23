//! The nftables a CGNAT config becomes, as text: what "View generated
//! rules" shows and what the kernel backend loads (G2.3).
//!
//! Everything lives in table `ip corerouter_cgnat`, apart from the
//! firewall's `inet corerouter`, so the two never replace each other. Per
//! pool, **one map and a handful of rules**, never a rule per subscriber
//! (the RouterOS scripts make two per subscriber, 76 000 for a /21 of
//! subscribers):
//!
//! - `d_<id>`: subscriber → public address . port range, one element per
//!   subscriber (`Layout::entries`), used by one `snat` for TCP, UDP and
//!   ICMP: the kernel applies the port range to ICMP query ids as well
//!   (`nf_nat_l4proto_unique_tuple`; RFC 5508 §3.1, RFC 7422 §2);
//! - `a_<id>`: subscriber → public address, for the other protocols (GRE,
//!   ESP…), so the pairing (RFC 6888 REQ-2) holds for them too;
//! - `eim_<id>` / `eimr_<id>`: the live UDP mappings, public → subscriber
//!   and back, filled after the translation by a filter chain (a second
//!   nat chain never runs once the first bound the connection), read by
//!   `dnat` (endpoint-independent filtering, RFC 4787 REQ-8, and
//!   hairpinning, REQ-9) and by `snat` (the same public port for every
//!   destination, REQ-1), with the RFC 4787 REQ-5 timer (5 min);
//! - exceptions: `x_1to1`, subscriber → its own public address, ahead of
//!   every pool, ports kept.
//!
//! Packets for a pool's public addresses that no connection claims are
//! dropped in `forward`: the block is routed to the router, and without
//! that rule they would be routed back where they came from.

use std::fmt::Write as _;

use corerouter_model::ItemId;
use corerouter_model::cgnat::{Cgnat, Mode, Pool};

/// The table every CGNAT object lives in.
pub const TABLE: &str = "corerouter_cgnat";
/// RFC 4787 REQ-5: UDP mapping timer ≥ 2 min, 5 min recommended.
pub const EIM_TIMEOUT_SECS: u32 = 300;
/// Live UDP mappings one pool keeps (the map's size bound).
pub const EIM_SIZE: u32 = 1 << 20;

/// The rendered script and what it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendered {
    pub script: String,
    /// Static map elements (deterministic slots + exceptions).
    pub elements: u64,
    pub rules: u32,
}

pub fn map_name(prefix: &str, id: ItemId) -> String {
    format!("{prefix}_{:x}", id.0)
}

/// Pools that reach the kernel: enabled, laid out. Blocks-mode pools get
/// their map filled by the block allocator, not here.
pub fn active(c: &Cgnat) -> impl Iterator<Item = &Pool> {
    c.pools.iter().filter(|p| !p.disabled && p.layout().is_ok())
}

fn oif(p: &Pool) -> String {
    p.out_interface
        .as_ref()
        .map(|i| format!("oifname \"{i}\" "))
        .unwrap_or_default()
}

/// The whole table (`only`: one pool's part, for display), or a script
/// that only deletes it when nothing is configured.
pub fn render(c: &Cgnat, only: Option<ItemId>) -> Rendered {
    let mut s = String::new();
    let mut elements = 0u64;
    let mut rules = 0u32;
    let pools: Vec<&Pool> = active(c)
        .filter(|p| only.is_none_or(|o| o == p.id))
        .collect();
    let exceptions: Vec<_> = c.exceptions.iter().filter(|e| !e.disabled).collect();
    let _ = writeln!(s, "table ip {TABLE} {{");
    if only.is_none() && !exceptions.is_empty() {
        let _ = writeln!(s, "\tmap x_1to1 {{\n\t\ttype ipv4_addr : ipv4_addr");
        let items: Vec<String> = exceptions
            .iter()
            .map(|e| format!("{} : {}", e.subscriber, e.public))
            .collect();
        elements += items.len() as u64;
        let _ = writeln!(s, "\t\telements = {{ {} }}\n\t}}", items.join(", "));
        let _ = writeln!(s, "\tmap x_1to1_in {{\n\t\ttype ipv4_addr : ipv4_addr");
        let back: Vec<String> = exceptions
            .iter()
            .map(|e| format!("{} : {}", e.public, e.subscriber))
            .collect();
        let _ = writeln!(s, "\t\telements = {{ {} }}\n\t}}", back.join(", "));
    }
    for p in &pools {
        let Ok(layout) = p.layout() else { continue };
        let d = map_name("d", p.id);
        let a = map_name("a", p.id);
        let _ = writeln!(
            s,
            "\tmap {d} {{\n\t\ttype ipv4_addr : interval ipv4_addr . inet_service\n\t\tflags interval"
        );
        let _ = writeln!(s, "\t\tsize {}", layout.subscribers().max(1));
        if p.mode == Mode::Deterministic {
            let items: Vec<String> = layout
                .entries()
                .filter(|(sub, _)| c.exception_of(*sub).is_none())
                .map(|(sub, slot)| {
                    format!(
                        "{sub} : {} . {}-{}",
                        slot.public, slot.first_port, slot.last_port
                    )
                })
                .collect();
            elements += items.len() as u64;
            if !items.is_empty() {
                let _ = writeln!(s, "\t\telements = {{ {} }}", items.join(",\n\t\t\t"));
            }
        }
        let _ = writeln!(s, "\t}}");
        let _ = writeln!(
            s,
            "\tmap {a} {{\n\t\ttype ipv4_addr : ipv4_addr\n\t\tsize {}",
            layout.subscribers().max(1)
        );
        if p.mode == Mode::Deterministic {
            let items: Vec<String> = layout
                .entries()
                .filter(|(sub, _)| c.exception_of(*sub).is_none())
                .map(|(sub, slot)| format!("{sub} : {}", slot.public))
                .collect();
            if !items.is_empty() {
                let _ = writeln!(s, "\t\telements = {{ {} }}", items.join(",\n\t\t\t"));
            }
        }
        let _ = writeln!(s, "\t}}");
        let inside: Vec<String> = p.inside.iter().map(ToString::to_string).collect();
        let _ = writeln!(
            s,
            "\tset in_{:x} {{\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\telements = {{ {} }}\n\t}}",
            p.id.0,
            inside.join(", ")
        );
        let outside: Vec<String> = p.outside.iter().map(ToString::to_string).collect();
        let _ = writeln!(
            s,
            "\tset pub_{:x} {{\n\t\ttype ipv4_addr\n\t\tflags interval\n\t\telements = {{ {} }}\n\t}}",
            p.id.0,
            outside.join(", ")
        );
        if p.endpoint_independent_mapping {
            let _ = writeln!(
                s,
                "\tmap {} {{\n\t\ttype ipv4_addr . inet_service : ipv4_addr . inet_service\n\t\tflags dynamic, timeout\n\t\ttimeout {EIM_TIMEOUT_SECS}s\n\t\tsize {EIM_SIZE}\n\t}}",
                map_name("eim", p.id)
            );
            let _ = writeln!(
                s,
                "\tmap {} {{\n\t\ttype ipv4_addr . inet_service : ipv4_addr . inet_service\n\t\tflags dynamic, timeout\n\t\ttimeout {EIM_TIMEOUT_SECS}s\n\t\tsize {EIM_SIZE}\n\t}}",
                map_name("eimr", p.id)
            );
        }
    }
    // dstnat: exceptions inbound, then live UDP mappings (EIF / hairpin).
    let _ = writeln!(
        s,
        "\tchain prerouting {{\n\t\ttype nat hook prerouting priority dstnat; policy accept;"
    );
    if only.is_none() && !exceptions.is_empty() {
        let _ = writeln!(s, "\t\tdnat ip to ip daddr map @x_1to1_in");
        rules += 1;
    }
    for p in pools.iter().filter(|p| p.endpoint_independent_mapping) {
        let eim = map_name("eim", p.id);
        // EIF: anyone may reach a live mapping. Without it, only hairpin
        // (a subscriber of the pool reaching another) uses the map.
        let from = if p.endpoint_independent_filtering {
            String::new()
        } else if p.hairpin {
            format!("ip saddr @{} ", map_name("in", p.id))
        } else {
            continue;
        };
        let _ = writeln!(
            s,
            "\t\t{from}meta l4proto udp dnat ip to ip daddr . udp dport map @{eim}"
        );
        rules += 1;
    }
    let _ = writeln!(s, "\t}}");
    // srcnat: exceptions, live UDP mappings (EIM), then the formula.
    let _ = writeln!(
        s,
        "\tchain postrouting {{\n\t\ttype nat hook postrouting priority srcnat; policy accept;"
    );
    if only.is_none() && !exceptions.is_empty() {
        let _ = writeln!(s, "\t\tsnat ip to ip saddr map @x_1to1");
        rules += 1;
    }
    for p in &pools {
        let d = map_name("d", p.id);
        let a = map_name("a", p.id);
        let out = oif(p);
        if p.endpoint_independent_mapping {
            let _ = writeln!(
                s,
                "\t\t{out}meta l4proto udp snat ip to ip saddr . udp sport map @{}",
                map_name("eimr", p.id)
            );
            rules += 1;
        }
        let _ = writeln!(
            s,
            "\t\t{out}meta l4proto {{ tcp, udp, icmp }} snat ip to ip saddr map @{d}"
        );
        let _ = writeln!(s, "\t\t{out}snat ip to ip saddr map @{a}");
        rules += 2;
        if p.hairpin && p.out_interface.is_some() {
            // A hairpinned packet leaves through the inside interface:
            // translated all the same (RFC 4787 REQ-9b: the receiver sees
            // the sender's public address and port).
            let _ = writeln!(
                s,
                "\t\tct status dnat meta l4proto {{ tcp, udp, icmp }} snat ip to ip saddr map @{d}"
            );
            rules += 1;
        }
    }
    let _ = writeln!(s, "\t}}");
    // After the translation: record the UDP mappings.
    let eim: Vec<&&Pool> = pools
        .iter()
        .filter(|p| p.endpoint_independent_mapping)
        .collect();
    if !eim.is_empty() {
        let _ = writeln!(
            s,
            "\tchain mappings {{\n\t\ttype filter hook postrouting priority srcnat + 10; policy accept;"
        );
        for p in eim {
            let _ = writeln!(
                s,
                "\t\tmeta l4proto udp ct state new ct status snat ct original ip saddr @{inside} \
                 update @{eim} {{ ct reply ip daddr . ct reply proto-dst : ct original ip saddr . ct original proto-src }} \
                 update @{eimr} {{ ct original ip saddr . ct original proto-src : ct reply ip daddr . ct reply proto-dst }}",
                inside = map_name("in", p.id),
                eim = map_name("eim", p.id),
                eimr = map_name("eimr", p.id),
            );
            rules += 1;
        }
        let _ = writeln!(s, "\t}}");
    }
    // Nothing unclaimed reaches the public blocks.
    let _ = writeln!(
        s,
        "\tchain forward {{\n\t\ttype filter hook forward priority filter - 5; policy accept;"
    );
    for p in &pools {
        let _ = writeln!(s, "\t\tip daddr @pub_{:x} counter drop", p.id.0);
        rules += 1;
    }
    let _ = writeln!(s, "\t}}\n}}");
    Rendered {
        script: s,
        elements,
        rules,
    }
}

/// The script that replaces the table in one transaction: create it (so
/// the delete never fails), delete it, then the new one; or only the
/// delete when there is nothing to load.
pub fn script(c: &Cgnat) -> String {
    let mut s = format!("table ip {TABLE}\ndelete table ip {TABLE}\n");
    if active(c).next().is_some() || c.exceptions.iter().any(|e| !e.disabled) {
        s.push_str(&render(c, None).script);
    }
    s
}

/// Whether the part of the config the kernel sees changed.
pub fn changed(from: &Cgnat, to: &Cgnat) -> bool {
    from.pools != to.pools || from.exceptions != to.exceptions
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_model::cgnat::{Exception, Pool};

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
        // Three subscribers in the map (the fourth has a 1:1), plus the exception.
        assert_eq!(r.elements, 4, "{}", r.script);
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
            r.script
                .contains("meta l4proto { tcp, udp, icmp } snat ip to ip saddr map @d_1")
        );
        // exceptions in and out, EIM snat, formula, others, hairpin dnat,
        // the mapping recorder, the forward drop.
        assert_eq!(r.rules, 8, "{}", r.script);
    }

    #[test]
    fn nothing_configured_only_deletes() {
        let c = Cgnat::default();
        assert_eq!(
            script(&c),
            format!("table ip {TABLE}\ndelete table ip {TABLE}\n")
        );
        let mut c = Cgnat::default();
        let mut p = pool(1, "100.64.0.0/30", "203.0.113.1", 1000);
        p.disabled = true;
        c.pools.push(p);
        assert_eq!(script(&c).lines().count(), 2);
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
                .contains("oifname \"ether1\" meta l4proto { tcp, udp, icmp }")
        );
        assert!(r.script.contains("ct status dnat meta l4proto"));
        assert!(
            r.script
                .contains("\t\tmeta l4proto udp dnat ip to ip daddr . udp dport map @eim_1")
        );
    }
}
