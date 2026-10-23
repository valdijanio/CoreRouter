//! What the CGNAT config gets wrong, before it is committed.
//!
//! Each [`Check`] is about one pool or exception and is an error (the
//! commit is refused), a warning (an amber chip in the GUI and a line in
//! the commands' replies) or a check that passed (a green chip with the
//! pool's numbers). The usual mistakes are here: subscribers in two pools,
//! two pools handing out the same public ports, not enough public
//! addresses for the ports asked, a public address that is also the
//! router's own.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use corerouter_model::cgnat::{
    Cgnat, FIRST_DYNAMIC, LayoutError, MAX_BLOCKS, MAX_EXCEPTIONS, MAX_POOLS, MAX_RANGES,
    MAX_SUBSCRIBERS, Mode, Pool, Range,
};
use corerouter_model::{Config, ItemId};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Level {
    Ok,
    Warn,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    /// Config path, as validation issues name it.
    pub path: String,
    pub item: ItemId,
    /// Short chip text (`capacity`, `overlap`, `router address`).
    pub label: &'static str,
    pub level: Level,
    pub text: String,
}

/// Below this many ports a subscriber with a few browser tabs and a phone
/// runs out (**estimado**: a page opens 20–80 connections; RFC 6888 §5
/// leaves the number to the operator).
pub const FEW_PORTS: u16 = 300;

const SHARED: Range = Range {
    start: Ipv4Addr::new(100, 64, 0, 0),
    end: Ipv4Addr::new(100, 127, 255, 255),
};
const PRIVATE: [Range; 3] = [
    Range {
        start: Ipv4Addr::new(10, 0, 0, 0),
        end: Ipv4Addr::new(10, 255, 255, 255),
    },
    Range {
        start: Ipv4Addr::new(172, 16, 0, 0),
        end: Ipv4Addr::new(172, 31, 255, 255),
    },
    Range {
        start: Ipv4Addr::new(192, 168, 0, 0),
        end: Ipv4Addr::new(192, 168, 255, 255),
    },
];

fn private(r: &Range) -> bool {
    std::iter::once(&SHARED)
        .chain(PRIVATE.iter())
        .any(|p| p.start <= r.start && r.end <= p.end)
}

fn touches_private(r: &Range) -> bool {
    std::iter::once(&SHARED)
        .chain(PRIVATE.iter())
        .any(|p| p.overlaps(r))
}

struct Out(Vec<Check>);

impl Out {
    fn push(
        &mut self,
        path: String,
        item: ItemId,
        label: &'static str,
        level: Level,
        text: String,
    ) {
        self.0.push(Check {
            path,
            item,
            label,
            level,
            text,
        });
    }
}

fn pool_path(p: &Pool, field: &str) -> String {
    format!("ip.cgnat.pools[{}].{field}", p.id)
}

/// The router's own IPv4 addresses.
fn router_addresses(cfg: &Config) -> Vec<Ipv4Addr> {
    cfg.ip
        .addresses
        .iter()
        .filter_map(|a| match a.address.addr() {
            std::net::IpAddr::V4(v4) => Some(v4),
            std::net::IpAddr::V6(_) => None,
        })
        .collect()
}

/// Every check of the CGNAT section.
pub fn checks(cfg: &Config) -> Vec<Check> {
    let c: &Cgnat = &cfg.ip.cgnat;
    let mut out = Out(Vec::new());
    if c.pools.len() > MAX_POOLS {
        out.push(
            "ip.cgnat.pools".into(),
            ItemId(0),
            "too many",
            Level::Error,
            format!("at most {MAX_POOLS} pools"),
        );
    }
    if c.exceptions.len() > MAX_EXCEPTIONS {
        out.push(
            "ip.cgnat.exceptions".into(),
            ItemId(0),
            "too many",
            Level::Error,
            format!("at most {MAX_EXCEPTIONS} exceptions"),
        );
    }
    let mut names: BTreeMap<&str, ItemId> = BTreeMap::new();
    let mut total = 0u64;
    let router = router_addresses(cfg);
    for (i, p) in c.pools.iter().enumerate() {
        pool_checks(cfg, p, &router, &mut out);
        let name = p.name.trim();
        if name.is_empty() || name.chars().count() > 63 {
            out.push(
                pool_path(p, "name"),
                p.id,
                "name",
                Level::Error,
                "1 to 63 characters".into(),
            );
        } else if let Some(other) = names.insert(name, p.id) {
            out.push(
                pool_path(p, "name"),
                p.id,
                "name",
                Level::Error,
                format!("pool {other} already has the name '{name}'"),
            );
        }
        if !p.disabled {
            total = total.saturating_add(p.subscribers());
        }
        // Against the pools after it (each pair once).
        for q in c.pools.iter().skip(i + 1) {
            if p.disabled || q.disabled {
                continue;
            }
            if let Some((a, b)) = overlap(&p.inside, &q.inside) {
                out.push(
                    pool_path(q, "inside"),
                    q.id,
                    "overlap",
                    Level::Error,
                    format!("subscribers {b} are also in pool '{}' ({a})", p.name),
                );
            }
            if let Some((a, b)) = overlap(&p.outside, &q.outside) {
                out.push(
                    pool_path(q, "outside"),
                    q.id,
                    "overlap",
                    Level::Error,
                    format!(
                        "public addresses {b} are also pool '{}''s ({a}): both would hand out the same ports",
                        p.name
                    ),
                );
            }
            for (x, y) in [(p, q), (q, p)] {
                if let Some((a, b)) = overlap(&x.inside, &y.outside) {
                    out.push(
                        pool_path(y, "outside"),
                        y.id,
                        "overlap",
                        Level::Error,
                        format!(
                            "public addresses {b} are subscribers of pool '{}' ({a})",
                            x.name
                        ),
                    );
                }
            }
        }
    }
    if total > MAX_SUBSCRIBERS {
        out.push(
            "ip.cgnat.pools".into(),
            ItemId(0),
            "too many",
            Level::Error,
            format!("{total} subscribers in all pools; at most {MAX_SUBSCRIBERS}"),
        );
    }
    exception_checks(c, &mut out);
    out.0
}

/// The first pair of overlapping ranges between `a` and `b`.
fn overlap(a: &[Range], b: &[Range]) -> Option<(Range, Range)> {
    a.iter()
        .find_map(|x| b.iter().find(|y| x.overlaps(y)).map(|y| (*x, *y)))
}

fn self_overlap(rs: &[Range]) -> Option<(Range, Range)> {
    rs.iter().enumerate().find_map(|(i, x)| {
        rs.iter()
            .skip(i + 1)
            .find(|y| x.overlaps(y))
            .map(|y| (*x, *y))
    })
}

fn pool_checks(cfg: &Config, p: &Pool, router: &[Ipv4Addr], out: &mut Out) {
    let err = |out: &mut Out, field: &str, label: &'static str, text: String| {
        out.push(pool_path(p, field), p.id, label, Level::Error, text);
    };
    let warn = |out: &mut Out, field: &str, label: &'static str, text: String| {
        out.push(pool_path(p, field), p.id, label, Level::Warn, text);
    };
    for (field, rs) in [("inside", &p.inside), ("outside", &p.outside)] {
        if rs.len() > MAX_RANGES {
            err(
                out,
                field,
                "too many",
                format!("at most {MAX_RANGES} ranges"),
            );
        }
        if let Some((a, b)) = self_overlap(rs) {
            err(out, field, "overlap", format!("{a} and {b} overlap"));
        }
    }
    if let Some((a, b)) = overlap(&p.inside, &p.outside) {
        err(
            out,
            "outside",
            "overlap",
            format!("public {b} overlaps subscribers {a}"),
        );
    }
    if p.port_range.first == 0 {
        err(
            out,
            "port_range",
            "port 0",
            "port 0 cannot be handed out".into(),
        );
    } else if p.port_range.first < FIRST_DYNAMIC {
        // RFC 4787 §4.1 REQ-3 / RFC 6888 §5: well-known ports are not
        // handed out by default.
        warn(
            out,
            "port_range",
            "well-known",
            format!(
                "ports below {FIRST_DYNAMIC} are well-known (RFC 4787 REQ-3): a subscriber gets \
                 a port a server would listen on"
            ),
        );
    }
    if p.alert_percent > 100 {
        err(out, "alert_percent", "percent", "0 to 100".into());
    }
    if p.mode == Mode::Blocks {
        if p.max_blocks == 0 || p.max_blocks > MAX_BLOCKS {
            err(out, "max_blocks", "blocks", format!("1 to {MAX_BLOCKS}"));
        }
        if p.block_timeout == 0 {
            err(out, "block_timeout", "timeout", "at least 1 s".into());
        }
    }
    if p.endpoint_independent_filtering && !p.endpoint_independent_mapping {
        // RFC 4787 §5: filtering is defined over the mapping; EIF without
        // EIM would admit packets to a mapping that changes per destination.
        err(
            out,
            "endpoint_independent_filtering",
            "EIF needs EIM",
            "endpoint-independent filtering needs endpoint-independent mapping".into(),
        );
    }
    if let Some(i) = &p.out_interface
        && !cfg.interfaces.contains_key(i)
    {
        err(
            out,
            "out_interface",
            "interface",
            format!("no interface '{i}'"),
        );
    }
    for r in &p.inside {
        if !private(r) {
            warn(
                out,
                "inside",
                "not shared space",
                format!(
                    "{r} is not in 100.64.0.0/10 (RFC 6598) nor in private space: are these \
                     really subscribers?"
                ),
            );
            break;
        }
    }
    for r in &p.outside {
        if touches_private(r) {
            warn(
                out,
                "outside",
                "private public",
                format!("{r} is shared or private space: it is not reachable from the Internet"),
            );
            break;
        }
    }
    if let Some(a) = router
        .iter()
        .find(|a| p.outside.iter().any(|r| r.contains(**a)))
    {
        warn(
            out,
            "outside",
            "router address",
            format!(
                "{a} is also an address of the router: its own connections (DNS, NTP) take \
                 ports the pool hands out; route a separate block to the router instead"
            ),
        );
    }
    match p.layout() {
        Ok(l) => {
            if p.mode == Mode::Blocks && l.subscribers() > l.capacity() {
                // Blocks are handed out on demand: more subscribers than
                // blocks is the point, while not all are online at once.
                warn(
                    out,
                    "outside",
                    "oversubscribed",
                    format!(
                        "{} subscribers for {} blocks ({} per public address): fine while at most {} are online at once",
                        l.subscribers(),
                        l.capacity(),
                        l.per_address(),
                        l.capacity()
                    ),
                );
            }
            if p.ports_per_subscriber < FEW_PORTS {
                warn(
                    out,
                    "ports_per_subscriber",
                    "few ports",
                    format!(
                        "{} ports per subscriber run out with a few browser tabs (at least {FEW_PORTS} is usual)",
                        p.ports_per_subscriber
                    ),
                );
            }
            let unused = l.public_addresses().saturating_sub(l.public_used());
            let what = if p.mode == Mode::Blocks {
                "blocks"
            } else {
                "subscribers"
            };
            out.push(
                pool_path(p, "outside"),
                p.id,
                "capacity",
                Level::Ok,
                format!(
                    "{} subscribers, {} {what} per public address, {} of {} public addresses used{}",
                    l.subscribers(),
                    l.per_address(),
                    l.public_used(),
                    l.public_addresses(),
                    if unused > 0 && p.mode == Mode::Deterministic {
                        format!(" ({unused} spare)")
                    } else {
                        String::new()
                    }
                ),
            );
        }
        Err(e) => {
            let field = match e {
                LayoutError::NoInside => "inside",
                LayoutError::NoOutside | LayoutError::Capacity { .. } => "outside",
                LayoutError::PortsTooMany { .. } | LayoutError::PortsTooFew { .. } => {
                    "ports_per_subscriber"
                }
                LayoutError::TooBig => "inside",
            };
            // Blocks mode may oversubscribe: blocks are handed out on
            // demand, so more subscribers than blocks is the point.
            if p.mode == Mode::Blocks && matches!(e, LayoutError::Capacity { .. }) {
                warn(
                    out,
                    field,
                    "oversubscribed",
                    format!("{e}: fine in blocks mode while not everyone is online"),
                );
            } else {
                err(out, field, "capacity", e.to_string());
            }
        }
    }
}

fn exception_checks(c: &Cgnat, out: &mut Out) {
    let mut subs: BTreeMap<Ipv4Addr, ItemId> = BTreeMap::new();
    let mut pubs: BTreeMap<Ipv4Addr, ItemId> = BTreeMap::new();
    for e in &c.exceptions {
        let at = |f: &str| format!("ip.cgnat.exceptions[{}].{f}", e.id);
        if e.disabled {
            continue;
        }
        if let Some(o) = subs.insert(e.subscriber, e.id) {
            out.push(
                at("subscriber"),
                e.id,
                "duplicate",
                Level::Error,
                format!("exception {o} already maps {}", e.subscriber),
            );
        }
        if let Some(o) = pubs.insert(e.public, e.id) {
            out.push(
                at("public"),
                e.id,
                "duplicate",
                Level::Error,
                format!("exception {o} already uses {}", e.public),
            );
        }
        for p in c.pools.iter().filter(|p| !p.disabled) {
            if p.outside.iter().any(|r| r.contains(e.public)) {
                out.push(
                    at("public"),
                    e.id,
                    "in a pool",
                    Level::Error,
                    format!("{} is a public address of pool '{}'", e.public, p.name),
                );
            }
            if p.inside.iter().any(|r| r.contains(e.public)) {
                out.push(
                    at("public"),
                    e.id,
                    "subscriber",
                    Level::Error,
                    format!("{} is a subscriber of pool '{}'", e.public, p.name),
                );
            }
        }
    }
    for e in c.exceptions.iter().filter(|e| !e.disabled) {
        if pubs.contains_key(&e.subscriber) {
            out.push(
                format!("ip.cgnat.exceptions[{}].subscriber", e.id),
                e.id,
                "loop",
                Level::Error,
                format!(
                    "{} is the public address of another exception",
                    e.subscriber
                ),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_model::cgnat::{Exception, Pool};
    use corerouter_model::firewall::PortRange;

    fn pool(id: u32, name: &str, inside: &str, outside: &str, ports: u16) -> Pool {
        Pool {
            id: ItemId(id),
            name: name.into(),
            disabled: false,
            mode: Mode::Deterministic,
            inside: inside.split(',').map(|r| r.parse().unwrap()).collect(),
            outside: outside.split(',').map(|r| r.parse().unwrap()).collect(),
            ports_per_subscriber: ports,
            port_range: PortRange {
                first: 1024,
                last: 65535,
            },
            max_blocks: 4,
            block_timeout: 120,
            out_interface: None,
            endpoint_independent_mapping: true,
            endpoint_independent_filtering: false,
            hairpin: true,
            alert_percent: 90,
            comment: String::new(),
        }
    }

    fn cfg(pools: Vec<Pool>, exceptions: Vec<Exception>) -> Config {
        let mut c = Config::default();
        c.ip.cgnat.pools = pools;
        c.ip.cgnat.exceptions = exceptions;
        c
    }

    fn labels(c: &Config, level: Level) -> Vec<&'static str> {
        checks(c)
            .into_iter()
            .filter(|x| x.level == level)
            .map(|x| x.label)
            .collect()
    }

    #[test]
    fn a_good_pool_passes_with_its_numbers() {
        let c = cfg(
            vec![pool(1, "a", "100.64.0.0/22", "203.0.113.0/28", 1000)],
            vec![],
        );
        assert!(validate_ok(&c), "{:?}", checks(&c));
        let ok = checks(&c);
        let cap = ok.iter().find(|x| x.label == "capacity").unwrap();
        assert_eq!(cap.level, Level::Ok);
        assert_eq!(
            cap.text,
            "1024 subscribers, 64 subscribers per public address, 16 of 16 public addresses used"
        );
    }

    fn validate_ok(c: &Config) -> bool {
        crate::validate(c).is_empty()
    }

    #[test]
    fn not_enough_public_addresses_is_refused_with_the_fix() {
        let c = cfg(
            vec![pool(1, "a", "100.64.0.0/22", "203.0.113.0/30", 1000)],
            vec![],
        );
        let issues = crate::validate(&c);
        assert_eq!(issues.len(), 1, "{issues:?}");
        assert!(
            issues[0].message.contains("16 public addresses needed"),
            "{}",
            issues[0]
        );
        assert_eq!(issues[0].path, "ip.cgnat.pools[*1].outside");
        // In blocks mode that is oversubscription: a warning.
        let mut p = pool(1, "a", "100.64.0.0/22", "203.0.113.0/30", 1000);
        p.mode = Mode::Blocks;
        let c = cfg(vec![p], vec![]);
        assert!(validate_ok(&c));
        assert_eq!(labels(&c, Level::Warn), ["oversubscribed"]);
    }

    #[test]
    fn pools_must_not_share_subscribers_or_public_ports() {
        let c = cfg(
            vec![
                pool(1, "a", "100.64.0.0/24", "203.0.113.0/29", 1000),
                pool(2, "b", "100.64.0.128/25", "203.0.113.4/30", 1000),
            ],
            vec![],
        );
        assert_eq!(labels(&c, Level::Error), ["overlap", "overlap"]);
        let c = cfg(
            vec![
                pool(1, "a", "100.64.0.0/24", "203.0.113.0/29", 1000),
                pool(2, "a", "100.64.1.0/24", "198.51.100.0/29", 1000),
            ],
            vec![],
        );
        assert_eq!(labels(&c, Level::Error), ["name"]);
        // A disabled pool does not count.
        let mut b = pool(2, "b", "100.64.0.0/24", "203.0.113.0/29", 1000);
        b.disabled = true;
        let c = cfg(
            vec![pool(1, "a", "100.64.0.0/24", "203.0.113.0/29", 1000), b],
            vec![],
        );
        assert!(validate_ok(&c));
    }

    #[test]
    fn warnings_for_odd_but_legal_pools() {
        let mut p = pool(1, "a", "198.51.100.0/24", "10.1.1.0/29", 200);
        p.port_range.first = 100;
        let c = cfg(vec![p], vec![]);
        assert!(validate_ok(&c), "{:?}", crate::validate(&c));
        assert_eq!(
            labels(&c, Level::Warn),
            [
                "well-known",
                "not shared space",
                "private public",
                "few ports"
            ]
        );
    }

    #[test]
    fn eif_needs_eim_and_blocks_need_limits() {
        let mut p = pool(1, "a", "100.64.0.0/24", "203.0.113.0/29", 1000);
        p.endpoint_independent_mapping = false;
        p.endpoint_independent_filtering = true;
        p.mode = Mode::Blocks;
        p.max_blocks = 0;
        p.block_timeout = 0;
        p.alert_percent = 101;
        p.out_interface = Some("ether9".parse().unwrap());
        let c = cfg(vec![p], vec![]);
        assert_eq!(
            labels(&c, Level::Error),
            ["percent", "blocks", "timeout", "EIF needs EIM", "interface"]
        );
    }

    #[test]
    fn exceptions_stay_out_of_the_pools() {
        let ex = |id, s: &str, p: &str| Exception {
            id: ItemId(id),
            subscriber: s.parse().unwrap(),
            public: p.parse().unwrap(),
            disabled: false,
            comment: String::new(),
        };
        let c = cfg(
            vec![pool(1, "a", "100.64.0.0/24", "203.0.113.0/29", 1000)],
            vec![
                ex(10, "100.64.0.9", "198.51.100.9"),
                ex(11, "100.64.0.9", "203.0.113.2"),
                ex(12, "100.64.0.10", "198.51.100.9"),
                ex(13, "198.51.100.9", "198.51.100.10"),
            ],
        );
        assert_eq!(
            labels(&c, Level::Error),
            ["duplicate", "in a pool", "duplicate", "loop"]
        );
    }

    #[test]
    fn the_routers_own_address_in_a_pool_is_a_warning() {
        let mut c = cfg(
            vec![pool(1, "a", "100.64.0.0/24", "203.0.113.0/29", 1000)],
            vec![],
        );
        c.ip.addresses.push(corerouter_model::AddressEntry {
            id: ItemId(1),
            address: "203.0.113.1/29".parse().unwrap(),
            interface: "ether1".parse().unwrap(),
            disabled: false,
            comment: String::new(),
            from_pool: None,
        });
        assert_eq!(labels(&c, Level::Warn), ["router address"]);
    }
}
