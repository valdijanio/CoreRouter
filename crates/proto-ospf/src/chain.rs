//! An instance's `out_filter_chain` (RouterOS `out-filter-chain`): the
//! `/routing filter` chain of G3.2b, compiled by the same compiler the BGP
//! policy uses, typed into `ospfd`/`ospf6d` under names of their own.
//!
//! The BGP render goes to `bgpd` only, and a route-map with a BGP-only
//! line (`match community`, `set local-preference`) is refused by the OSPF
//! daemons. So the chain is compiled again here, its lists renamed
//! `CR-O2-…`/`CR-O3-…` (the owned context `hal-frr` sends to `ospfd` and
//! `ospf6d`), and a chain that tests or sets anything but the prefix and
//! the metric is refused by [`problems`] before the commit.

use std::collections::{BTreeSet, HashMap};
use std::fmt::Write as _;

use corerouter_model::Config;
use corerouter_proto_bgp::filter::eval::parsed_chains;
use corerouter_proto_bgp::filter::frr::{self, Entry, Exit, Lists, Match, Set};
use corerouter_proto_bgp::filter::parse::Stmt;

pub use corerouter_proto_bgp::filter::frr::END_SEQ;

/// A chain compiled for OSPF.
#[derive(Debug, Clone, Default)]
pub struct Compiled {
    pub entries: Vec<Entry>,
    pub lists: Lists,
    /// What OSPF cannot apply, or what the compiler refused.
    pub problems: Vec<String>,
}

/// An OSPF-side name of a generated list (`CR-P-…` → `CR-O2-P-…` for
/// ospfd, `CR-O3-P-…` for ospf6d).
fn ospf_list(name: &str, v6: bool) -> String {
    let rest = name.strip_prefix("CR-").unwrap_or(name);
    format!("CR-O{}-{rest}", if v6 { 3 } else { 2 })
}

impl Compiled {
    /// The prefix-lists, renamed.
    pub fn lists_text(&self, s: &mut String, v6: bool) {
        let (kw, map) = if v6 {
            ("ipv6", &self.lists.prefix6)
        } else {
            ("ip", &self.lists.prefix4)
        };
        for (name, entries) in map {
            for (i, e) in entries.iter().enumerate() {
                let _ = writeln!(
                    s,
                    "{kw} prefix-list {} seq {} permit {e}",
                    ospf_list(name, v6),
                    (i + 1) * 5
                );
            }
        }
    }

    /// The route-map `name` (entries from sequence 10, the end 65535).
    pub fn map_text(&self, name: &str, s: &mut String) {
        let n = self.entries.len();
        for (i, e) in self.entries.iter().enumerate() {
            let _ = writeln!(
                s,
                "route-map {name} {} {}",
                if e.permit { "permit" } else { "deny" },
                frr::seq(i, n)
            );
            for m in &e.matches {
                if let Match::Plist { v6, name } = m {
                    let kw = if *v6 { "ipv6" } else { "ip" };
                    let _ = writeln!(
                        s,
                        " match {kw} address prefix-list {}",
                        ospf_list(name, *v6)
                    );
                }
            }
            if e.permit {
                for x in &e.sets {
                    if let Set::Med(v) = x {
                        let _ = writeln!(s, " set metric {v}");
                    }
                }
                match e.exit {
                    Exit::Done => {}
                    Exit::Next => {
                        let _ = writeln!(s, " on-match next");
                    }
                    Exit::Goto(j) => {
                        let _ = writeln!(s, " on-match goto {}", frr::seq(j, n));
                    }
                }
            }
            let _ = writeln!(s, "exit");
        }
    }
}

/// Compile `chain` for OSPF.
pub fn compile(cfg: &Config, chain: &str) -> Compiled {
    let filter = &cfg.routing.filter;
    let (parsed, parse_problems) = parsed_chains(filter);
    let chains: HashMap<&str, &[Stmt]> = parsed
        .iter()
        .map(|(n, b)| (n.as_str(), b.as_slice()))
        .collect();
    if !chains.contains_key(chain) {
        return Compiled {
            problems: vec![format!("no /routing filter rule has chain {chain}")],
            ..Compiled::default()
        };
    }
    let mut lists = Lists::default();
    let (entries, mut problems) = frr::compile(filter, &chains, chain, None, &mut lists);
    // A rule of this chain that does not parse leaves the chain short.
    for p in parse_problems {
        let ours = filter
            .rules
            .iter()
            .any(|r| r.chain == chain && r.id.to_string() == p.item);
        if ours {
            problems.push(format!("rule {}: {}", p.item, p.message));
        }
    }
    for e in &entries {
        for m in &e.matches {
            if !matches!(m, Match::Plist { .. }) {
                problems.push(format!(
                    "chain {chain} tests {}, which OSPF routes do not carry (only dst and the prefix lists)",
                    match m {
                        Match::AsPath(_) => "the AS path",
                        Match::Comm { .. } | Match::Large { .. } => "communities",
                        _ => "the protocol",
                    }
                ));
            }
        }
        for x in &e.sets {
            if !matches!(x, Set::Med(_)) {
                problems.push(format!(
                    "chain {chain} sets a BGP attribute; OSPF takes only set bgp-med (the external metric)"
                ));
            }
        }
    }
    problems.dedup();
    Compiled {
        entries,
        lists,
        problems,
    }
}

/// Every chain an enabled instance names, compiled once.
pub fn compile_used(cfg: &Config) -> HashMap<String, Compiled> {
    let used: BTreeSet<&str> = cfg
        .routing
        .ospf
        .instances
        .values()
        .filter(|i| !i.disabled)
        .filter_map(|i| i.out_filter_chain.as_deref())
        .collect();
    used.into_iter()
        .map(|c| (c.to_owned(), compile(cfg, c)))
        .collect()
}
