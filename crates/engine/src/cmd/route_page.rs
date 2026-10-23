//! `ip.route.page` (G1.27c): IP › Routes for a full table. The same rows
//! as `ip.route.list`, but filtered, searched by prefix and cut into pages
//! in the engine, from the lines it keeps (`route_table::RouteCache`), with
//! the counts of the whole table. With `aggregate`, the routes longer than
//! /16 (IPv6: /32) come as one line per /16 with their counts, opened on
//! demand by asking for that prefix with `match: longer`.
//!
//! Prefix search, as Junos' `show route … exact | longer | orlonger` and
//! Linux's `ip route show match | root | exact`:
//! - `exact`: that prefix only;
//! - `longer`: the more specific routes inside it (not itself);
//! - `orlonger`: it and every route inside it ("contained in");
//! - `covering`: every route that contains it ("contains"; for an address,
//!   the candidates of a longest-prefix lookup, RFC 1812 §5.2.4.3).

use corerouter_model::{RoutingTable, parse_destination};
use ipnet::IpNet;
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_str, opt_u32};
use super::{CommandSpec, always};
use crate::route_table::{Line, Origin, RouteWatch, State, Summary};
use crate::{EngineError, Result, Session};

/// Rows of one page at most (hostile input; the GUI asks for 500).
pub const MAX_LIMIT: u32 = 5_000;
const DEFAULT_LIMIT: u32 = 500;
/// Aggregation: IPv4 routes longer than this go into one line per /16.
pub const AGGREGATE_V4: u8 = 16;
pub const AGGREGATE_V6: u8 = 32;

pub(super) const COMMANDS: &[CommandSpec] = &[cmd!(query "ip.route.page", "Routes (page)", [], None,
    "{routing_table?: string, family?: string (ipv4 | ipv6), state?: string (active | standby | inactive), origin?: string (connected | static | dhcp | ra; several comma-separated), prefix?: cidr | ip, match?: string (exact | longer | orlonger | covering; default orlonger for a prefix, covering for an address), aggregate?: bool (routes longer than /16, IPv6 /32, as one line per /16 with their counts), offset?: u32, limit?: u32 (1..=5000, default 500)} → {total (lines that match), offset, rows: [ip.route.list rows | {key, bucket: true, dst_address, family, routing_table, routes, active, standby, inactive, state}], summary: {total, active, standby, inactive, ipv4, ipv6, origins: {origin: n}, tables: {table: n}}, generation}",
    always, page)];

/// How a route's prefix must relate to the one searched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Match {
    Exact,
    Longer,
    OrLonger,
    Covering,
}

impl Match {
    pub fn holds(self, route: &IpNet, prefix: &IpNet) -> bool {
        if route.addr().is_ipv4() != prefix.addr().is_ipv4() {
            return false;
        }
        match self {
            Self::Exact => route == prefix,
            Self::OrLonger => prefix.contains(route),
            Self::Longer => route != prefix && prefix.contains(route),
            Self::Covering => route.contains(prefix),
        }
    }
}

fn choice<'a>(p: &'a Value, key: &str, choices: &[&str]) -> Result<Option<&'a str>> {
    match opt_str(p, key)? {
        Some(v) if choices.contains(&v) => Ok(Some(v)),
        Some(v) => Err(EngineError::bad(
            key,
            format!(
                "'{}' is not one of {}",
                v.chars().take(32).collect::<String>(),
                choices.join(", ")
            ),
        )),
        None => Ok(None),
    }
}

const ORIGINS: [&str; 4] = ["connected", "static", "dhcp", "ra"];

/// The origins asked for (`static,dhcp`); `None`: all.
fn origins(p: &Value) -> Result<Option<Vec<Origin>>> {
    let Some(raw) = opt_str(p, "origin")? else {
        return Ok(None);
    };
    let mut out = Vec::new();
    for o in raw.split(',').map(str::trim).filter(|o| !o.is_empty()).take(ORIGINS.len()) {
        out.push(match o {
            "connected" => Origin::Connected,
            "static" => Origin::Static,
            "dhcp" => Origin::Dhcp,
            "ra" => Origin::Ra,
            other => {
                return Err(EngineError::bad(
                    "origin",
                    format!(
                        "'{}' is not one of {}",
                        other.chars().take(32).collect::<String>(),
                        ORIGINS.join(", ")
                    ),
                ));
            }
        });
    }
    Ok(Some(out))
}

/// The filters of one request.
struct Filter {
    table: Option<RoutingTable>,
    v4: Option<bool>,
    state: Option<State>,
    origins: Option<Vec<Origin>>,
    prefix: Option<(IpNet, Match)>,
}

impl Filter {
    fn keeps(&self, l: &Line) -> bool {
        self.table.as_ref().is_none_or(|t| *t == l.table)
            && self.v4.is_none_or(|v4| v4 == l.dst.addr().is_ipv4())
            && self.state.is_none_or(|s| s == l.state)
            && self.origins.as_ref().is_none_or(|o| o.contains(&l.origin))
            && self.prefix.is_none_or(|(p, m)| m.holds(&l.dst, &p))
    }
}

/// One line of an aggregated page: the routes inside one /16 (/32).
struct Bucket {
    table: RoutingTable,
    prefix: IpNet,
    /// Its first route: a bucket of one is shown as that route.
    first: usize,
    routes: usize,
    active: usize,
    standby: usize,
    inactive: usize,
}

impl Bucket {
    fn json(&self) -> Value {
        let state = if self.active > 0 {
            "active"
        } else if self.standby > 0 {
            "standby"
        } else {
            "inactive"
        };
        json!({
            "key": format!("bucket {} {}", self.table, self.prefix),
            "bucket": true,
            "dst_address": self.prefix.to_string(),
            "family": if self.prefix.addr().is_ipv4() { "ipv4" } else { "ipv6" },
            "routing_table": self.table,
            "routes": self.routes,
            "active": self.active,
            "standby": self.standby,
            "inactive": self.inactive,
            "state": state,
        })
    }
}

/// The /16 (IPv6 /32) a route longer than that goes into, if it does.
fn bucket_of(dst: &IpNet) -> Option<IpNet> {
    let at = if dst.addr().is_ipv4() {
        AGGREGATE_V4
    } else {
        AGGREGATE_V6
    };
    if dst.prefix_len() <= at {
        return None;
    }
    IpNet::new(dst.addr(), at).ok().map(|n| n.trunc())
}

/// What a page holds: a route (by index) or a bucket.
enum Entry {
    Line(usize),
    Bucket(Bucket),
}

fn summary_json(s: &Summary) -> Value {
    json!({
        "total": s.total,
        "active": s.active,
        "standby": s.standby,
        "inactive": s.inactive,
        "ipv4": s.ipv4,
        "ipv6": s.ipv6,
        "origins": s.origins,
        "tables": s.tables,
    })
}

fn page(s: &mut Session, p: &Value) -> Result<Value> {
    let table: Option<RoutingTable> = opt_parse(p, "routing_table")?;
    let v4 = choice(p, "family", &["ipv4", "ipv6"])?.map(|f| f == "ipv4");
    let state = choice(p, "state", &["active", "standby", "inactive"])?.map(|s| match s {
        "active" => State::Active,
        "standby" => State::Standby,
        _ => State::Inactive,
    });
    let origins = origins(p)?;
    let prefix = opt_str(p, "prefix")?
        .map(|s| parse_destination(s).map_err(|e| EngineError::bad("prefix", e.to_string())))
        .transpose()?;
    let mode = choice(p, "match", &["exact", "longer", "orlonger", "covering"])?;
    let prefix = prefix.map(|net| {
        let host = net.prefix_len() == net.max_prefix_len();
        let m = match mode {
            Some("exact") => Match::Exact,
            Some("longer") => Match::Longer,
            Some("covering") => Match::Covering,
            Some(_) => Match::OrLonger,
            None if host => Match::Covering,
            None => Match::OrLonger,
        };
        (net.trunc(), m)
    });
    if mode.is_some() && prefix.is_none() {
        return Err(EngineError::bad("match", "needs a prefix"));
    }
    let aggregate = opt_bool(p, "aggregate")?.unwrap_or(false);
    let offset = opt_u32(p, "offset")?.unwrap_or(0) as usize;
    let limit = match opt_u32(p, "limit")? {
        Some(l) if (1..=MAX_LIMIT).contains(&l) => l as usize,
        Some(_) => return Err(EngineError::bad("limit", format!("must be 1..={MAX_LIMIT}"))),
        None => DEFAULT_LIMIT as usize,
    };
    let filter = Filter {
        table,
        v4,
        state,
        origins,
        prefix,
    };
    let (lines, summary, generation) = s.cached_routes();
    let now = s.now();
    // One pass: count what matches, keep only this page's entries.
    let mut total = 0usize;
    let mut kept: Vec<Entry> = Vec::with_capacity(limit.min(lines.len()));
    let mut open: Option<Bucket> = None;
    let push = |e: Entry, total: &mut usize, kept: &mut Vec<Entry>| {
        // Nothing to fold in a bucket of one route: the route itself.
        let e = match e {
            Entry::Bucket(b) if b.routes == 1 => Entry::Line(b.first),
            e => e,
        };
        if *total >= offset && kept.len() < limit {
            kept.push(e);
        }
        *total += 1;
    };
    for (i, l) in lines.iter().enumerate() {
        if !filter.keeps(l) {
            continue;
        }
        let into = aggregate.then(|| bucket_of(&l.dst)).flatten();
        match into {
            Some(b) => {
                let same = open.as_ref().is_some_and(|o| o.prefix == b && o.table == l.table);
                if !same {
                    if let Some(done) = open.take() {
                        push(Entry::Bucket(done), &mut total, &mut kept);
                    }
                    open = Some(Bucket {
                        table: l.table.clone(),
                        prefix: b,
                        first: i,
                        routes: 0,
                        active: 0,
                        standby: 0,
                        inactive: 0,
                    });
                }
                if let Some(o) = open.as_mut() {
                    o.routes += 1;
                    match l.state {
                        State::Active => o.active += 1,
                        State::Standby => o.standby += 1,
                        State::Inactive => o.inactive += 1,
                    }
                }
            }
            None => {
                if let Some(done) = open.take() {
                    push(Entry::Bucket(done), &mut total, &mut kept);
                }
                push(Entry::Line(i), &mut total, &mut kept);
            }
        }
    }
    if let Some(done) = open.take() {
        push(Entry::Bucket(done), &mut total, &mut kept);
    }
    let watch = s.ext::<RouteWatch>();
    let rows: Vec<Value> = kept
        .iter()
        .filter_map(|e| match e {
            Entry::Line(i) => lines.get(*i).map(|l| super::route::row(l, watch, now)),
            Entry::Bucket(b) => Some(b.json()),
        })
        .collect();
    Ok(json!({
        "total": total,
        "offset": offset,
        "rows": rows,
        "summary": summary_json(&summary),
        "generation": generation,
    }))
}
