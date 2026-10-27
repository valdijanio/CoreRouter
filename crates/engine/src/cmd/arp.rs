//! `/ip arp` and `/ipv6 neighbor` (G1.27d): the neighbor tables, static
//! ARP entries, the ARP mode of each interface and ARP ping.
//!
//! Names and behavior follow RouterOS v7 (`/ip arp`: `address`,
//! `mac-address`, `interface`, `published`; status `reachable`, `stale`,
//! `delay`, `probe`, `incomplete`, `failed`, `permanent`; interface `arp`
//! = enabled, disabled, reply-only, proxy-arp, local-proxy-arp;
//! `arp-timeout`). States are RFC 4861 §7.3.2's (Linux uses them for ARP
//! too).
//!
//! Lists are paginated in the engine like `ip.route.page` (G1.27c): the
//! table can hold a hundred thousand neighbors on a BNG, and the GUI asks
//! for one page with the counts of the whole table. Flush never removes
//! the gateway of an active route nor the neighbor the management
//! connection comes through: on a `reply-only` port such an entry would
//! never be learned again.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use corerouter_hal::neigh::{ArpPinger, NeighState, mac_text};
use corerouter_model::arp::{ArpEntry, ArpInterface, ArpMode, MAX_ENTRIES, MAX_TIMEOUT_SECS, unicast_mac};
use corerouter_model::{Config, IfName, InterfaceKind, ItemId, MacAddr};
use ipnet::IpNet;
use serde_json::{Map, Value, json};

use super::args::{opt_bool, opt_parse, opt_str, opt_text, opt_u32, req_parse};
use super::{CommandSpec, always};
use crate::neigh_table::{NEAR_FULL_PCT, Row, suggest_gc};
use crate::tasks::can_start;
use crate::{EngineError, Result, Session};

/// Rows of one page at most (the GUI asks for 500).
pub const MAX_LIMIT: u32 = 5_000;
const DEFAULT_LIMIT: u32 = 500;
/// Longest search text.
const MAX_SEARCH: usize = 64;
const GC: [&str; 6] = [
    "net.ipv4.neigh.default.gc_thresh1",
    "net.ipv4.neigh.default.gc_thresh2",
    "net.ipv4.neigh.default.gc_thresh3",
    "net.ipv6.neigh.default.gc_thresh1",
    "net.ipv6.neigh.default.gc_thresh2",
    "net.ipv6.neigh.default.gc_thresh3",
];


pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "ip.arp.list", "ARP", ["IP", "ARP"], None,
        "{search?: string (an IP, a CIDR, a MAC prefix as 00:50:56, or text in interface, state, comment), interface?: string, state?: string (reachable | stale | delay | probe | incomplete | failed | permanent | noarp; several comma-separated), source?: string (dynamic | static | dhcp), offset?: u32, limit?: u32 (1..=5000, default 500)} → {rows: [{id (static entry, else null), address, mac_address, interface, state, source (dynamic | static | dhcp: DHCP add-arp), flags (X disabled, I invalid, H dhcp, D dynamic, P published, C complete), router, published, disabled, invalid, comment, last_seen_secs, mac_since, vendor, host}], total, matched, offset, counts: {states: {state: n}, interfaces: {name: n}, sources: {source: n}}, table: {ipv4, ipv6, gc_thresh3, near_full, suggest, source, fed, lost}, generation}",
        always, list_v4),
    cmd!(query "ipv6.neighbor.list", "IPv6 Neighbors", ["IPv6", "Neighbors"], None,
        "{search?: string (an IP, a CIDR, a MAC prefix as 00:50:56, or text in interface, state, comment), interface?: string, state?: string (reachable | stale | delay | probe | incomplete | failed | permanent | noarp; several comma-separated), source?: string (dynamic | static | dhcp), offset?: u32, limit?: u32 (1..=5000, default 500)} → {rows: [{id (static entry, else null), address, mac_address, interface, state, source (dynamic | static | dhcp: DHCP add-arp), flags (X disabled, I invalid, H dhcp, D dynamic, P published, C complete), router, published, disabled, invalid, comment, last_seen_secs, mac_since, vendor, host}], total, matched, offset, counts: {states: {state: n}, interfaces: {name: n}, sources: {source: n}}, table: {ipv4, ipv6, gc_thresh3, near_full, suggest, source, fed, lost}, generation}",
        always, list_v6),
    cmd!(
        "ip.arp.add",
        "Add Static ARP",
        [],
        None,
        "{address: ipv4, mac_address: mac, interface: string, published?: bool (answer ARP for it, proxy for one host), disabled?: bool, comment?: string} → {id}",
        always,
        add
    ),
    cmd!(
        "ip.arp.set",
        "Set Static ARP",
        [],
        None,
        "{id: *hex, address?: ipv4, mac_address?: mac, interface?: string, published?: bool, disabled?: bool, comment?: string} → {id}",
        has_static,
        set
    ),
    cmd!(
        "ip.arp.remove",
        "Remove Static ARP",
        [],
        None,
        "{id: *hex} → {id}",
        has_static,
        remove
    ),
    cmd!(
        "ip.arp.make-static",
        "Make Static",
        [],
        None,
        "{address: ipv4, interface?: string, comment?: string} → {id, mac_address, interface}",
        always,
        make_static
    ),
    cmd!(query "ip.arp.flush", "Flush ARP", [], None,
        "{interface?: string, state?: string (several comma-separated)} → {removed, kept: [{address, interface, why}]}",
        always, flush_v4),
    cmd!(query "ipv6.neighbor.flush", "Flush IPv6 Neighbors", [], None,
        "{interface?: string, state?: string (several comma-separated)} → {removed, kept: [{address, interface, why}]}",
        always, flush_v6),
    cmd!(query "ip.arp.ping", "ARP Ping", [], None,
        "{address: ipv4, interface?: string (default: the one whose subnet holds the address), count?: int 1..1000 (default 4), interval_ms?: int 100..10000 (default 1000), timeout_ms?: int 10..5000 (default 1000)} → {id, task_id, interface, src_address, columns}",
        can_start, ping)
    .task(),
    cmd!(query "ip.arp.check", "Check Static ARP", [], None,
        "{address?: string, mac_address?: string, interface?: string, published?: bool, disabled?: bool, comment?: string, id?: string (the entry being edited)} → {computed: [{label, value}], checks: [{level (ok | warning | error | info), check, message, param}], commands: [{command, params}], risk}",
        always, check),
    cmd!(query "ip.arp.detail", "Neighbor Detail", [], None,
        "{address: ip, interface?: string} → {row (as ip.arp.list), history: [{mac_address, since}], routes: [{dst_address, routing_table, state}], subnet (the router's address whose network holds it, or null)}",
        always, detail),
    cmd!(query "ip.arp.settings.print", "ARP Settings", [], None,
        "{} → {interfaces: [{interface, arp (enabled | disabled | reply-only | proxy-arp | local-proxy-arp), arp_timeout (auto | seconds), entries, reachable, stale, unresolved, static}], kernel: {ipv4: {gc_thresh1, gc_thresh2, gc_thresh3, entries, configured}, ipv6: {…}}, near_full, suggest}",
        always, settings_print),
    cmd!(
        "ip.arp.settings.set",
        "Set ARP Mode",
        [],
        None,
        "{interface: string, arp?: string (enabled | disabled | reply-only | proxy-arp | local-proxy-arp), arp_timeout?: string (auto | seconds 1..86400), confirm?: bool (needed for disabled, reply-only and proxy-arp), force?: bool (even if it cuts your management connection)} → {interface, arp, arp_timeout, without_static}",
        always,
        settings_set
    ),
];

fn has_static(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ip.arp.entries.is_empty() {
        Err("there are no static ARP entries".into())
    } else {
        Ok(())
    }
}

/// What a search asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Search {
    Any,
    Address(IpAddr),
    Net(IpNet),
    /// Hex digits of a MAC prefix (`0050 56` for `00:50:56`).
    Mac(Vec<u8>),
    Text(String),
}

fn search(raw: &str) -> Search {
    let t = raw.trim();
    if t.is_empty() {
        return Search::Any;
    }
    if let Ok(a) = t.parse::<IpAddr>() {
        return Search::Address(a);
    }
    if let Ok(n) = t.parse::<IpNet>() {
        return Search::Net(n);
    }
    let sep = |c: char| matches!(c, ':' | '-' | '.');
    if t.contains(sep) && t.chars().all(|c| c.is_ascii_hexdigit() || sep(c)) {
        let hex: Vec<u8> = t
            .chars()
            .filter(char::is_ascii_hexdigit)
            .filter_map(|c| c.to_digit(16).and_then(|d| u8::try_from(d).ok()))
            .collect();
        if !hex.is_empty() && hex.len() <= 12 {
            return Search::Mac(hex);
        }
    }
    Search::Text(t.to_lowercase())
}

fn mac_nibbles(mac: [u8; 6]) -> [u8; 12] {
    let mut out = [0u8; 12];
    for (i, b) in mac.iter().enumerate() {
        if let Some(o) = out.get_mut(i * 2..i * 2 + 2) {
            o.copy_from_slice(&[b >> 4, b & 0x0f]);
        }
    }
    out
}

/// A line of the list: a kernel entry, or a static entry the kernel does
/// not hold (disabled, or on an interface that is not there).
struct View<'a> {
    address: IpAddr,
    iface: &'a IfName,
    row: Option<&'a Row>,
    entry: Option<&'a ArpEntry>,
    /// Put in by a DHCP server's `add-arp` (RouterOS flag H).
    dhcp: bool,
}

impl View<'_> {
    fn state(&self) -> Option<NeighState> {
        self.row.map(|r| r.state)
    }

    fn source(&self) -> &'static str {
        if self.entry.is_some() {
            "static"
        } else if self.dhcp {
            "dhcp"
        } else {
            "dynamic"
        }
    }

    fn mac(&self) -> Option<[u8; 6]> {
        self.entry.map(|e| e.mac.0).or_else(|| self.row.and_then(Row::mac))
    }

    fn matches(&self, q: &Search) -> bool {
        match q {
            Search::Any => true,
            Search::Address(a) => self.address == *a,
            Search::Net(n) => n.contains(&self.address),
            Search::Mac(hex) => self
                .mac()
                .is_some_and(|m| mac_nibbles(m).starts_with(hex)),
            // No allocation per row: names and states compared in place,
            // the address and MAC printed only for a search that could
            // be part of one (a text search was 21 ms on 100 k rows).
            Search::Text(t) => {
                let addr_like = t.bytes().all(|b| b.is_ascii_hexdigit() || b == b'.' || b == b':');
                contains_ci(self.iface.as_str(), t)
                    || self.state().is_some_and(|s| s.as_str().contains(t.as_str()))
                    || self.entry.is_some_and(|e| contains_ci(&e.comment, t))
                    || (addr_like && self.address.to_string().contains(t.as_str()))
                    || (addr_like
                        && self.mac().is_some_and(|m| contains_ci(&mac_text(m), t)))
            }
        }
    }
}

/// `needle` (lower case) in `hay`, ignoring ASCII case.
fn contains_ci(hay: &str, needle: &str) -> bool {
    let n = needle.as_bytes();
    n.is_empty()
        || hay
            .as_bytes()
            .windows(n.len())
            .any(|w| w.iter().zip(n).all(|(a, b)| a.to_ascii_lowercase() == *b))
}

fn states(p: &Value) -> Result<Option<Vec<NeighState>>> {
    let Some(raw) = opt_str(p, "state")? else {
        return Ok(None);
    };
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| {
            NeighState::parse(s).ok_or_else(|| {
                let shown: String = s.chars().take(32).collect();
                EngineError::bad(
                    "state",
                    format!("'{shown}' is not one of reachable, stale, delay, probe, incomplete, failed, permanent, noarp"),
                )
            })
        })
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

fn list_v4(s: &mut Session, p: &Value) -> Result<Value> {
    list(s, p, true)
}

fn list_v6(s: &mut Session, p: &Value) -> Result<Value> {
    list(s, p, false)
}

fn list(s: &mut Session, p: &Value, v4: bool) -> Result<Value> {
    let q = match opt_str(p, "search")? {
        Some(t) if t.len() > MAX_SEARCH => {
            return Err(EngineError::bad("search", format!("at most {MAX_SEARCH} characters")));
        }
        Some(t) => search(t),
        None => Search::Any,
    };
    let iface: Option<IfName> = opt_parse(p, "interface")?;
    let want_states = states(p)?;
    let source = match opt_str(p, "source")? {
        None => None,
        Some(x @ ("dynamic" | "static" | "dhcp")) => Some(x),
        Some(_) => return Err(EngineError::bad("source", "must be dynamic, static or dhcp")),
    };
    let offset = opt_u32(p, "offset")?.unwrap_or(0);
    let limit = opt_u32(p, "limit")?.unwrap_or(DEFAULT_LIMIT);
    if !(1..=MAX_LIMIT).contains(&limit) {
        return Err(EngineError::bad("limit", format!("must be 1..={MAX_LIMIT}")));
    }
    let gc = s.hal_mut().sysctls(&GC).unwrap_or_default();
    let now = s.now().unwrap_or(0);
    let neigh = s.neigh_fresh();
    let cfg = s.store().candidate().clone();
    let t = neigh.lock();
    let now = now.max(t.clock);

    // Static entries by (interface, address): they name kernel rows.
    let statics: HashMap<(&IfName, IpAddr), &ArpEntry> = if v4 {
        cfg.ip
            .arp
            .entries
            .iter()
            .map(|e| ((&e.interface, IpAddr::V4(e.address)), e))
            .collect()
    } else {
        HashMap::new()
    };
    let mut views: Vec<View<'_>> = Vec::new();
    let mut seen: HashSet<(&IfName, IpAddr)> = HashSet::new();
    for r in t.rows() {
        if r.address.is_ipv4() != v4 {
            continue;
        }
        let Some(name) = t.name(r.iface) else { continue };
        let entry = statics.get(&(name, r.address)).copied();
        if entry.is_some() {
            seen.insert((name, r.address));
        }
        let dhcp = match r.address {
            IpAddr::V4(a) => entry.is_none() && s.dhcp_arp_of(name, a),
            IpAddr::V6(_) => false,
        };
        views.push(View {
            address: r.address,
            iface: name,
            row: Some(r),
            entry,
            dhcp,
        });
    }
    for ((name, addr), e) in &statics {
        if !seen.contains(&(*name, *addr)) {
            views.push(View {
                address: *addr,
                iface: name,
                row: None,
                entry: Some(e),
                dhcp: false,
            });
        }
    }

    // The counts are of the whole table (the chips), not of the filter.
    // Counted in arrays and by pointer, named once at the end: a map
    // lookup by name per row was half the cost of a page (**medido**).
    let mut states_n = [0u64; NeighState::ALL.len() + 1];
    let mut iface_n: HashMap<*const IfName, (&str, u64)> = HashMap::new();
    let mut static_n = 0u64;
    let mut dhcp_n = 0u64;
    for v in &views {
        let at = v
            .state()
            .and_then(|st| NeighState::ALL.iter().position(|x| *x == st))
            .unwrap_or(NeighState::ALL.len());
        if let Some(c) = states_n.get_mut(at) {
            *c += 1;
        }
        iface_n
            .entry(std::ptr::from_ref(v.iface))
            .or_insert((v.iface.as_str(), 0))
            .1 += 1;
        static_n += u64::from(v.entry.is_some());
        dhcp_n += u64::from(v.dhcp);
    }
    let by_state: BTreeMap<&str, u64> = NeighState::ALL
        .iter()
        .map(|s| s.as_str())
        .chain(std::iter::once("none"))
        .zip(states_n)
        .filter(|(_, n)| *n > 0)
        .collect();
    let mut by_iface: BTreeMap<&str, u64> = BTreeMap::new();
    for (name, n) in iface_n.into_values() {
        *by_iface.entry(name).or_default() += n;
    }
    let dynamic_n = u64::try_from(views.len()).unwrap_or(u64::MAX) - static_n - dhcp_n;
    let by_source: BTreeMap<&str, u64> = [("dhcp", dhcp_n), ("dynamic", dynamic_n), ("static", static_n)]
        .into_iter()
        .filter(|(_, n)| *n > 0)
        .collect();
    let total = views.len();
    let mut hits: Vec<&View<'_>> = views
        .iter()
        .filter(|v| iface.as_ref().is_none_or(|i| i == v.iface))
        .filter(|v| {
            want_states
                .as_ref()
                .is_none_or(|w| v.state().is_some_and(|st| w.contains(&st)))
        })
        .filter(|v| source.is_none_or(|x| x == v.source()))
        .filter(|v| v.matches(&q))
        .collect();
    let matched = hits.len();
    let start = usize::try_from(offset).unwrap_or(usize::MAX).min(matched);
    let end = start.saturating_add(usize::try_from(limit).unwrap_or(500)).min(matched);
    // Only the page needs order: select it, then sort just that part.
    let order = |a: &&View<'_>, b: &&View<'_>| {
        (a.address, a.iface.as_str()).cmp(&(b.address, b.iface.as_str()))
    };
    if end < matched && end > 0 {
        hits.select_nth_unstable_by(end - 1, order);
    }
    let page = hits.get_mut(..end).unwrap_or_default();
    page.sort_unstable_by(order);
    let rows: Vec<Value> = page
        .get(start..)
        .unwrap_or_default()
        .iter()
        .map(|v| row(v, &cfg, now))
        .collect();

    let (n4, n6) = t.rows().iter().fold((0u64, 0u64), |(a, b), r| {
        if r.address.is_ipv4() { (a + 1, b) } else { (a, b + 1) }
    });
    let fam = if v4 { "ipv4" } else { "ipv6" };
    let t3 = gc
        .get(&format!("net.{fam}.neigh.default.gc_thresh3"))
        .copied()
        .flatten()
        .and_then(|v| u64::try_from(v).ok());
    let used = if v4 { n4 } else { n6 };
    let near = t3.is_some_and(|t3| t3 > 0 && used.saturating_mul(100) >= t3.saturating_mul(NEAR_FULL_PCT));
    Ok(json!({
        "rows": rows,
        "total": total,
        "matched": matched,
        "offset": start,
        "counts": {"states": by_state, "interfaces": by_iface, "sources": by_source},
        "table": {
            "ipv4": n4,
            "ipv6": n6,
            "gc_thresh3": t3,
            "near_full": near,
            "suggest": near.then(|| suggest_gc(used)),
            "source": t.source,
            "fed": t.fed,
            "lost": t.lost,
        },
        "generation": t.generation,
    }))
}

fn row(v: &View<'_>, cfg: &Config, now: u64) -> Value {
    let e = v.entry;
    let invalid = e.is_some_and(|e| !cfg.interfaces.contains_key(&e.interface));
    let disabled = e.is_some_and(|e| e.disabled);
    let complete = v.row.is_some_and(|r| r.state.resolved() && r.has_mac);
    let mut flags = String::new();
    if disabled {
        flags.push('X');
    }
    if invalid {
        flags.push('I');
    }
    if v.dhcp {
        flags.push('H');
    }
    if e.is_none() {
        flags.push('D');
    }
    if e.is_some_and(|e| e.published) {
        flags.push('P');
    }
    if complete {
        flags.push('C');
    }
    let seen = v.row.map(|r| r.seen).filter(|s| *s > 0);
    json!({
        "id": e.map(|e| e.id),
        "address": v.address.to_string(),
        "mac_address": v.mac().map(mac_text),
        "interface": v.iface.as_str(),
        "state": v.state().map(NeighState::as_str),
        "source": v.source(),
        "flags": flags,
        "router": v.row.is_some_and(|r| r.router),
        "published": e.is_some_and(|e| e.published),
        "disabled": disabled,
        "invalid": invalid,
        "comment": e.map(|e| e.comment.as_str()).unwrap_or_default(),
        "last_seen_secs": seen.map(|s| now.saturating_sub(s)),
        "mac_since": v.row.map(|r| r.mac_since).filter(|s| *s > 0),
        "vendor": Value::Null,
        "host": Value::Null,
    })
}

fn check_entry(cfg: &Config, e: &ArpEntry, skip: Option<ItemId>) -> Result<()> {
    if !unicast_mac(e.mac) {
        return Err(EngineError::bad(
            "mac_address",
            format!("{} is not a host's address (zero, multicast or broadcast)", e.mac),
        ));
    }
    let Some(iface) = cfg.interfaces.get(&e.interface) else {
        return Err(EngineError::bad("interface", format!("no interface '{}'", e.interface)));
    };
    if iface.kind == InterfaceKind::Loopback {
        return Err(EngineError::bad("interface", "a loopback has no neighbors"));
    }
    let a = e.address;
    if a.is_unspecified() || a.is_broadcast() || a.is_multicast() || a.is_loopback() {
        return Err(EngineError::bad("address", format!("{a} is not a host address")));
    }
    if cfg.ip.addresses.iter().any(|x| x.address.addr() == IpAddr::V4(a)) {
        return Err(EngineError::bad("address", format!("{a} is one of the router's own addresses")));
    }
    if let Some(dup) = cfg
        .ip
        .arp
        .entries
        .iter()
        .find(|x| Some(x.id) != skip && x.address == a && x.interface == e.interface)
    {
        return Err(EngineError::bad(
            "address",
            format!("{a} on {} has a static entry already ({})", e.interface, dup.id),
        ));
    }
    Ok(())
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let address: Ipv4Addr = req_parse(p, "address")?;
    let mac: MacAddr = req_parse(p, "mac_address")?;
    let interface: IfName = req_parse(p, "interface")?;
    let published = opt_bool(p, "published")?.unwrap_or(false);
    let disabled = opt_bool(p, "disabled")?.unwrap_or(false);
    let comment = opt_text(p, "comment", 256)?.unwrap_or_default();
    let cfg = s.store_mut().candidate_mut();
    if cfg.ip.arp.entries.len() >= MAX_ENTRIES {
        return Err(EngineError::bad("address", format!("at most {MAX_ENTRIES} static entries")));
    }
    let mut e = ArpEntry {
        id: ItemId(0),
        address,
        mac,
        interface,
        published,
        disabled,
        comment,
    };
    check_entry(cfg, &e, None)?;
    e.id = cfg.ip.arp.next_id();
    let id = e.id;
    cfg.ip.arp.entries.push(e);
    Ok(json!({ "id": id }))
}

fn pos(cfg: &Config, id: ItemId) -> Result<usize> {
    cfg.ip
        .arp
        .entries
        .iter()
        .position(|e| e.id == id)
        .ok_or_else(|| EngineError::bad("id", format!("no static ARP entry {id} (see ip.arp.list)")))
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let id: ItemId = req_parse(p, "id")?;
    let address: Option<Ipv4Addr> = opt_parse(p, "address")?;
    let mac: Option<MacAddr> = opt_parse(p, "mac_address")?;
    let interface: Option<IfName> = opt_parse(p, "interface")?;
    let published = opt_bool(p, "published")?;
    let disabled = opt_bool(p, "disabled")?;
    let comment = opt_text(p, "comment", 256)?;
    let cfg = s.store_mut().candidate_mut();
    let at = pos(cfg, id)?;
    let mut e = cfg
        .ip
        .arp
        .entries
        .get(at)
        .cloned()
        .ok_or_else(|| EngineError::bad("id", format!("no static ARP entry {id}")))?;
    if let Some(v) = address {
        e.address = v;
    }
    if let Some(v) = mac {
        e.mac = v;
    }
    if let Some(v) = interface {
        e.interface = v;
    }
    if let Some(v) = published {
        e.published = v;
    }
    if let Some(v) = disabled {
        e.disabled = v;
    }
    if let Some(v) = comment {
        e.comment = v;
    }
    check_entry(cfg, &e, Some(id))?;
    if let Some(slot) = cfg.ip.arp.entries.get_mut(at) {
        *slot = e;
    }
    Ok(json!({ "id": id }))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let id: ItemId = req_parse(p, "id")?;
    let cfg = s.store_mut().candidate_mut();
    let at = pos(cfg, id)?;
    cfg.ip.arp.entries.remove(at);
    Ok(json!({ "id": id }))
}

/// RouterOS "Make Static": the learned MAC of a neighbor becomes a
/// static entry.
fn make_static(s: &mut Session, p: &Value) -> Result<Value> {
    let address: Ipv4Addr = req_parse(p, "address")?;
    let interface: Option<IfName> = opt_parse(p, "interface")?;
    let comment = opt_text(p, "comment", 256)?.unwrap_or_default();
    let neigh = s.neigh_fresh();
    let found = {
        let t = neigh.lock();
        t.rows()
            .iter()
            .filter(|r| r.address == IpAddr::V4(address))
            .filter_map(|r| Some((t.name(r.iface)?.clone(), *r)))
            .filter(|(n, _)| interface.as_ref().is_none_or(|i| i == n))
            .find(|(_, r)| r.has_mac && r.state.resolved())
    };
    let Some((iface, r)) = found else {
        return Err(EngineError::bad(
            "address",
            format!("{address} has no resolved neighbor entry to copy (try ip.arp.ping first)"),
        ));
    };
    let params = json!({
        "address": address.to_string(),
        "mac_address": MacAddr(r.mac).to_string(),
        "interface": iface.as_str(),
        "comment": comment,
    });
    let out = add(s, &params)?;
    Ok(json!({
        "id": out.get("id"),
        "mac_address": MacAddr(r.mac).to_string(),
        "interface": iface.as_str(),
    }))
}

/// Why the entry of `address` must stay: it carries the management
/// connection or an active route.
fn protected(s: &mut Session) -> HashMap<IpAddr, String> {
    let mut out = HashMap::new();
    for l in s.route_lines().iter() {
        if l.state != crate::route_table::State::Active {
            continue;
        }
        if let Some(crate::route_table::Via {
            gateway: Some(gw), ..
        }) = &l.via
        {
            out.entry(*gw)
                .or_insert_with(|| format!("gateway of the active route {}", l.dst));
        }
    }
    if let Some(link) = s.caller().link {
        let peer = match link.peer.ip() {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
            v4 => v4,
        };
        out.insert(peer, "your management connection comes from it".into());
    }
    out
}

fn flush_v4(s: &mut Session, p: &Value) -> Result<Value> {
    flush(s, p, true)
}

fn flush_v6(s: &mut Session, p: &Value) -> Result<Value> {
    flush(s, p, false)
}

fn flush(s: &mut Session, p: &Value, v4: bool) -> Result<Value> {
    let iface: Option<IfName> = opt_parse(p, "interface")?;
    let want = states(p)?;
    let keep = protected(s);
    let neigh = s.neigh_fresh();
    let mut items = Vec::new();
    let mut kept = Vec::new();
    {
        let t = neigh.lock();
        for r in t.rows() {
            let Some(name) = t.name(r.iface) else { continue };
            let learned = !matches!(r.state, NeighState::Permanent | NeighState::Noarp);
            if r.address.is_ipv4() != v4
                || !learned
                || iface.as_ref().is_some_and(|i| i != name)
                || want.as_ref().is_some_and(|w| !w.contains(&r.state))
            {
                continue;
            }
            if let Some(why) = keep.get(&r.address) {
                kept.push(json!({"address": r.address.to_string(), "interface": name.as_str(), "why": why}));
                continue;
            }
            items.push((name.clone(), r.address));
        }
    }
    let removed = s.hal_mut().neighbor_remove(&items).map_err(|e| EngineError::Hal(e.to_string()))?;
    let now = s.now().unwrap_or(0);
    let gone: Vec<_> = items
        .into_iter()
        .map(|(interface, address)| corerouter_hal::neigh::NeighEvent::Remove { interface, address })
        .collect();
    neigh.lock().apply(&gone, now);
    Ok(json!({ "removed": removed, "kept": kept }))
}

/// The router's address on `iface` in the subnet of `target`, and the
/// interface itself when not given.
fn source_for(cfg: &Config, target: Ipv4Addr, iface: Option<&IfName>) -> Option<(IfName, Ipv4Addr)> {
    cfg.ip
        .addresses
        .iter()
        .filter(|a| !a.disabled)
        .filter(|a| iface.is_none_or(|i| *i == a.interface))
        .filter_map(|a| match a.address {
            IpNet::V4(n) => Some((a, n)),
            IpNet::V6(_) => None,
        })
        .find(|(_, n)| n.contains(&target))
        .map(|(a, n)| (a.interface.clone(), n.addr()))
}

fn ranged(p: &Value, key: &str, lo: u32, hi: u32, default: u32) -> Result<u32> {
    let v = opt_u32(p, key)?.unwrap_or(default);
    if !(lo..=hi).contains(&v) {
        return Err(EngineError::bad(key, format!("must be {lo}..={hi}")));
    }
    Ok(v)
}

fn ping(s: &mut Session, p: &Value) -> Result<Value> {
    let target: Ipv4Addr = req_parse(p, "address")?;
    let iface: Option<IfName> = opt_parse(p, "interface")?;
    let count = ranged(p, "count", 1, 1000, 4)?;
    let interval = Duration::from_millis(u64::from(ranged(p, "interval_ms", 100, 10_000, 1000)?));
    let timeout = Duration::from_millis(u64::from(ranged(p, "timeout_ms", 10, 5000, 1000)?));
    let cfg = s.store().running().clone();
    let (iface, src) = source_for(&cfg, target, iface.as_ref()).ok_or_else(|| {
        EngineError::bad(
            "address",
            format!("{target} is in no subnet of the router{}: ARP reaches only the link", iface.map(|i| format!(" on {i}")).unwrap_or_default()),
        )
    })?;
    let mut pinger = s
        .hal_mut()
        .arp_pinger(&iface)
        .map_err(|e| EngineError::Hal(e.to_string()))?;
    let title = format!("arp-ping {target} on {iface}");
    let name = iface.clone();
    let id = s.start_task("arp-ping", title, move |ctx| {
        arp_ping(pinger.as_mut(), src, target, &name, count, interval, timeout, ctx)
    })?;
    Ok(json!({
        "id": id,
        "task_id": id,
        "interface": iface.as_str(),
        "src_address": src.to_string(),
        "columns": ["seq", "host", "mac_address", "interface", "rtt_ms", "status"],
    }))
}

#[allow(clippy::too_many_arguments)]
fn arp_ping(
    pinger: &mut dyn ArpPinger,
    src: Ipv4Addr,
    target: Ipv4Addr,
    iface: &IfName,
    count: u32,
    interval: Duration,
    timeout: Duration,
    ctx: &crate::tasks::TaskCtx<'_>,
) -> std::result::Result<(), String> {
    let (mut sent, mut got) = (0u32, 0u32);
    let mut rtts: Vec<f64> = Vec::new();
    let summary = |sent: u32, got: u32, rtts: &[f64]| {
        let loss = sent.saturating_sub(got).saturating_mul(100).checked_div(sent).unwrap_or(0);
        let avg = if rtts.is_empty() { None } else { Some(rtts.iter().sum::<f64>() / rtts.len() as f64) };
        json!({
            "sent": sent,
            "received": got,
            "packet_loss": loss,
            "min_rtt_ms": rtts.iter().copied().reduce(f64::min),
            "avg_rtt_ms": avg,
            "max_rtt_ms": rtts.iter().copied().reduce(f64::max),
        })
    };
    for seq in 0..count {
        if ctx.stopped() {
            break;
        }
        let started = ctx.now();
        sent += 1;
        let reply = pinger.ping(src, target, timeout).map_err(|e| e.to_string())?;
        let mut ev = Map::new();
        ev.insert("host".into(), json!(target.to_string()));
        ev.insert("interface".into(), json!(iface.as_str()));
        match reply {
            Some(r) => {
                got += 1;
                let ms = r.rtt.as_secs_f64() * 1000.0;
                rtts.push(ms);
                ev.insert("mac_address".into(), json!(mac_text(r.mac)));
                ev.insert("rtt_ms".into(), json!((ms * 1000.0).round() / 1000.0));
                ev.insert("status".into(), json!("reply"));
            }
            None => {
                ev.insert("status".into(), json!("timeout"));
            }
        }
        ev.insert("icmp_seq".into(), json!(seq));
        ctx.emit(Value::Object(ev));
        ctx.summary(summary(sent, got, &rtts));
        if seq + 1 < count && !ctx.sleep(interval.saturating_sub(ctx.now().saturating_sub(started))) {
            break;
        }
    }
    ctx.summary(summary(sent, got, &rtts));
    Ok(())
}

fn timeout_text(t: Option<u32>) -> Value {
    t.map_or(json!("auto"), |s| json!(s))
}

fn settings_print(s: &mut Session, _p: &Value) -> Result<Value> {
    let gc = s.hal_mut().sysctls(&GC).unwrap_or_default();
    let neigh = s.neigh_fresh();
    let cfg = s.store().candidate().clone();
    let t = neigh.lock();
    let mut per: HashMap<&str, [u64; 4]> = HashMap::new();
    for r in t.rows().iter().filter(|r| r.address.is_ipv4()) {
        let Some(n) = t.name(r.iface) else { continue };
        let c = per.entry(n.as_str()).or_default();
        c[0] += 1;
        match r.state {
            NeighState::Reachable => c[1] += 1,
            NeighState::Stale | NeighState::Delay | NeighState::Probe => c[2] += 1,
            NeighState::Incomplete | NeighState::Failed => c[3] += 1,
            _ => {}
        }
    }
    let interfaces: Vec<Value> = cfg
        .interfaces
        .values()
        .filter(|i| i.kind != InterfaceKind::Loopback)
        .map(|i| {
            let set = cfg.ip.arp.interface(&i.name);
            let c = per.get(i.name.as_str()).copied().unwrap_or_default();
            json!({
                "interface": i.name.as_str(),
                "arp": set.mode.as_str(),
                "arp_timeout": timeout_text(set.timeout_secs),
                "entries": c[0],
                "reachable": c[1],
                "stale": c[2],
                "unresolved": c[3],
                "static": cfg.ip.arp.entries.iter().filter(|e| e.interface == i.name).count(),
            })
        })
        .collect();
    let (n4, n6) = t.rows().iter().fold((0u64, 0u64), |(a, b), r| {
        if r.address.is_ipv4() { (a + 1, b) } else { (a, b + 1) }
    });
    let kernel = |fam: &str, used: u64| {
        let get = |k: &str| {
            gc.get(&format!("net.{fam}.neigh.default.{k}")).copied().flatten()
        };
        let configured = |k: &str| {
            cfg.system
                .tuning
                .sysctl
                .get(&format!("net.{fam}.neigh.default.{k}"))
                .copied()
        };
        let t3 = get("gc_thresh3").and_then(|v| u64::try_from(v).ok());
        let near = t3.is_some_and(|t3| t3 > 0 && used.saturating_mul(100) >= t3.saturating_mul(NEAR_FULL_PCT));
        json!({
            "gc_thresh1": get("gc_thresh1"),
            "gc_thresh2": get("gc_thresh2"),
            "gc_thresh3": get("gc_thresh3"),
            "configured": configured("gc_thresh3").is_some(),
            "entries": used,
            "near_full": near,
            "suggest": near.then(|| suggest_gc(used)),
        })
    };
    let v4 = kernel("ipv4", n4);
    let v6 = kernel("ipv6", n6);
    let near = v4.get("near_full") == Some(&json!(true)) || v6.get("near_full") == Some(&json!(true));
    Ok(json!({
        "interfaces": interfaces,
        "kernel": {"ipv4": v4, "ipv6": v6},
        "near_full": near,
    }))
}

fn settings_set(s: &mut Session, p: &Value) -> Result<Value> {
    let name: IfName = req_parse(p, "interface")?;
    let mode: Option<ArpMode> = opt_parse(p, "arp")?;
    let timeout = match opt_str(p, "arp_timeout")? {
        None => None,
        Some("auto") => Some(None),
        Some(t) => match t.trim().parse::<u32>() {
            Ok(v) if (1..=MAX_TIMEOUT_SECS).contains(&v) => Some(Some(v)),
            _ => {
                return Err(EngineError::bad(
                    "arp_timeout",
                    format!("must be auto or 1..={MAX_TIMEOUT_SECS} seconds"),
                ));
            }
        },
    };
    let confirm = opt_bool(p, "confirm")?.unwrap_or(false);
    crate::lockout::take_force(s, p)?;
    let cfg = s.store().candidate();
    let Some(iface) = cfg.interfaces.get(&name) else {
        return Err(EngineError::bad("interface", format!("no interface '{name}'")));
    };
    if iface.kind == InterfaceKind::Loopback {
        return Err(EngineError::bad("interface", "a loopback has no ARP"));
    }
    let old = cfg.ip.arp.interface(&name);
    let new = ArpInterface {
        mode: mode.unwrap_or(old.mode),
        timeout_secs: timeout.unwrap_or(old.timeout_secs),
    };
    if new.mode != old.mode && new.mode.risky() && !confirm {
        let what = match new.mode {
            ArpMode::Disabled => "hosts without a static entry stop being reachable",
            ArpMode::ReplyOnly => "only static entries (and DHCP add-arp) reach hosts: the others stop being reachable",
            _ => "the router answers ARP for addresses it routes elsewhere (RFC 1027), which can pull traffic of the whole segment",
        };
        return Err(EngineError::bad(
            "confirm",
            format!("arp={} on {name}: {what}; repeat with confirm=true", new.mode),
        ));
    }
    // Hosts that would lose the router: learned, without a static entry.
    let statics: HashSet<Ipv4Addr> = cfg
        .ip
        .arp
        .entries
        .iter()
        .filter(|e| e.interface == name && !e.disabled)
        .map(|e| e.address)
        .collect();
    let cuts = matches!(new.mode, ArpMode::Disabled | ArpMode::ReplyOnly) && new.mode != old.mode;
    let neigh = s.neigh_fresh();
    // (address, resolved now): one that does not resolve is not cut.
    let without: Vec<(IpAddr, bool)> = {
        let t = neigh.lock();
        t.rows()
            .iter()
            .filter(|r| t.name(r.iface) == Some(&name))
            .filter(|r| match r.address {
                IpAddr::V4(a) => !statics.contains(&a) && r.state != NeighState::Permanent,
                IpAddr::V6(_) => false,
            })
            .map(|r| (r.address, r.state.resolved()))
            .collect()
    };
    if cuts {
        let keep = protected(s);
        if let Some((ip, why)) = without
            .iter()
            .filter(|(_, up)| *up)
            .find_map(|(a, _)| keep.get(a).map(|w| (a, w)))
            && !s.lockout_ack
            && !s.in_safe_mode()
        {
            return Err(EngineError::Lockout(format!(
                "arp={} on {name} would cut {ip} ({why}): add a static entry for it first \
                 (ip.arp.make-static), enter Safe Mode (config.safe-mode.enter), or repeat with force=true",
                new.mode
            )));
        }
    }
    s.store_mut().candidate_mut().ip.arp.set_interface(name.clone(), new);
    Ok(json!({
        "interface": name.as_str(),
        "arp": new.mode.as_str(),
        "arp_timeout": timeout_text(new.timeout_secs),
        "without_static": if cuts { without.len() } else { 0 },
    }))
}

/// One check of the add/edit modal's preview (G0.24).
fn chk(level: &str, check: &str, message: impl Into<String>, param: &str) -> Value {
    json!({"level": level, "check": check, "message": message.into(), "param": param})
}

/// The add/edit modal's preview: never fails on bad input, says what is
/// wrong as a check, and the command OK sends.
fn check(s: &mut Session, p: &Value) -> Result<Value> {
    let text = |k: &str| p.get(k).and_then(Value::as_str).map(str::trim).filter(|t| !t.is_empty());
    let mut checks = Vec::new();
    let mut computed = Vec::new();
    let cfg = s.store().candidate().clone();
    let editing: Option<ArpEntry> = text("id")
        .and_then(|i| i.parse::<ItemId>().ok())
        .and_then(|id| cfg.ip.arp.entries.iter().find(|e| e.id == id).cloned());
    let address = match text("address").or(editing.as_ref().map(|_| "")) {
        Some("") => editing.as_ref().map(|e| e.address),
        Some(t) => match t.parse::<Ipv4Addr>() {
            Ok(a) => Some(a),
            Err(_) => {
                checks.push(chk("error", "address", "an IPv4 address, as 192.168.88.10", "address"));
                None
            }
        },
        None => {
            checks.push(chk("error", "address", "type the neighbor's IPv4 address", "address"));
            None
        }
    };
    let mac = match text("mac_address") {
        Some(t) => match t.parse::<MacAddr>() {
            Ok(m) => Some(m),
            Err(_) => {
                checks.push(chk("error", "mac", "a MAC as 00:11:22:33:44:55", "mac_address"));
                None
            }
        },
        None => editing.as_ref().map(|e| e.mac).or_else(|| {
            checks.push(chk("error", "mac", "type the neighbor's MAC address", "mac_address"));
            None
        }),
    };
    let interface = match text("interface") {
        Some(t) => t.parse::<IfName>().ok().or_else(|| {
            checks.push(chk("error", "interface", "not an interface name", "interface"));
            None
        }),
        None => editing.as_ref().map(|e| e.interface.clone()).or_else(|| {
            checks.push(chk("error", "interface", "pick an interface", "interface"));
            None
        }),
    };
    let flag = |k: &str| p.get(k).and_then(Value::as_bool);
    let mut commands = Vec::new();
    if let (Some(address), Some(mac), Some(interface)) = (address, mac, interface) {
        let e = ArpEntry {
            id: editing.as_ref().map_or(ItemId(0), |e| e.id),
            address,
            mac,
            interface: interface.clone(),
            published: flag("published").unwrap_or(editing.as_ref().is_some_and(|e| e.published)),
            disabled: flag("disabled").unwrap_or(editing.as_ref().is_some_and(|e| e.disabled)),
            comment: text("comment").map(str::to_owned).or(editing.as_ref().map(|e| e.comment.clone())).unwrap_or_default(),
        };
        match check_entry(&cfg, &e, editing.as_ref().map(|e| e.id)) {
            Err(EngineError::BadParam { param, reason }) => {
                let param = if param == "mac_address" || param == "interface" { param } else { "address".into() };
                checks.push(chk("error", "entry", reason, &param));
            }
            Err(other) => checks.push(chk("error", "entry", other.to_string(), "address")),
            Ok(()) => {}
        }
        // Not in a subnet of the interface: ARP never asks for it there.
        match source_for(&cfg, address, Some(&interface)) {
            Some((_, own)) => {
                computed.push(json!({"label": "Router address", "value": own.to_string()}));
                checks.push(chk("ok", "subnet", format!("{address} is in a network of {interface}"), "address"));
            }
            None => checks.push(chk(
                "warning",
                "subnet",
                format!("{address} is in no network of {interface}: the router never sends to it there unless a route says so"),
                "address",
            )),
        }
        // What the network says about it now.
        let neigh = s.neigh_fresh();
        let seen = neigh.lock().get(&interface, IpAddr::V4(address)).copied();
        match seen {
            Some(r) if r.has_mac && r.mac != mac.0 && r.state != NeighState::Permanent => checks.push(chk(
                "warning",
                "learned",
                format!("{address} answers from {} now: a static entry with another MAC cuts it off", mac_text(r.mac)),
                "mac_address",
            )),
            Some(r) if r.has_mac && r.mac == mac.0 => {
                checks.push(chk("ok", "learned", format!("{address} answers from this MAC now"), "mac_address"));
            }
            _ => checks.push(chk("info", "learned", format!("{address} is not in the table now"), "address")),
        }
        if e.published {
            checks.push(chk(
                "info",
                "published",
                "the router answers ARP for this address with its own MAC when it has a route to it elsewhere (proxy for one host)",
                "published",
            ));
        }
        let mut params = Map::new();
        if let Some(ed) = &editing {
            params.insert("id".into(), json!(ed.id));
        }
        params.insert("address".into(), json!(address.to_string()));
        params.insert("mac_address".into(), json!(mac.to_string()));
        params.insert("interface".into(), json!(interface.as_str()));
        params.insert("published".into(), json!(e.published));
        params.insert("disabled".into(), json!(e.disabled));
        if !e.comment.is_empty() {
            params.insert("comment".into(), json!(e.comment));
        }
        let cmd = if editing.is_some() { "ip.arp.set" } else { "ip.arp.add" };
        commands.push(json!({"command": cmd, "params": params}));
    }
    let ok = !checks.iter().any(|c| c.get("level") == Some(&json!("error")));
    Ok(json!({
        "computed": computed,
        "checks": checks,
        "commands": if ok { commands } else { Vec::new() },
        "risk": Value::Null,
    }))
}

/// The detail panel under the table: the MACs the address had, the
/// routes through it, and the row itself.
fn detail(s: &mut Session, p: &Value) -> Result<Value> {
    let address: IpAddr = req_parse(p, "address")?;
    let iface: Option<IfName> = opt_parse(p, "interface")?;
    let now = s.now().unwrap_or(0);
    let lines = s.route_lines();
    let neigh = s.neigh_fresh();
    let cfg = s.store().candidate().clone();
    let t = neigh.lock();
    let now = now.max(t.clock);
    let found = t
        .rows()
        .iter()
        .filter(|r| r.address == address)
        .filter_map(|r| Some((t.name(r.iface)?, r)))
        .find(|(n, _)| iface.as_ref().is_none_or(|i| i == *n));
    let entry = cfg.ip.arp.entries.iter().find(|e| {
        IpAddr::V4(e.address) == address && iface.as_ref().is_none_or(|i| *i == e.interface)
    });
    let Some(name) = found.map(|(n, _)| n).or(entry.map(|e| &e.interface)) else {
        return Err(EngineError::bad("address", format!("{address} is not in the neighbor table")));
    };
    let dhcp = match address {
        IpAddr::V4(a) => entry.is_none() && s.dhcp_arp_of(name, a),
        IpAddr::V6(_) => false,
    };
    let view = View {
        address,
        iface: name,
        row: found.map(|(_, r)| r),
        entry,
        dhcp,
    };
    let history: Vec<Value> = t
        .history(address)
        .into_iter()
        .filter(|c| c.interface == *name)
        .map(|c| json!({"mac_address": mac_text(c.mac), "since": c.since, "ago_secs": now.saturating_sub(c.since)}))
        .collect();
    let routes: Vec<Value> = lines
        .iter()
        .filter(|l| matches!(&l.via, Some(crate::route_table::Via { gateway: Some(g), link }) if *g == address && link == name))
        .take(100)
        .map(|l| json!({"dst_address": l.dst.to_string(), "routing_table": l.table.to_string(), "state": l.state.as_str()}))
        .collect();
    let subnet = match address {
        IpAddr::V4(a) => source_for(&cfg, a, Some(name)).map(|(_, own)| own.to_string()),
        IpAddr::V6(_) => None,
    };
    Ok(json!({
        "row": row(&view, &cfg, now),
        "history": history,
        "routes": routes,
        "subnet": subnet,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn searches_say_what_they_look_for() {
        assert_eq!(search("10.0.0.1"), Search::Address("10.0.0.1".parse().unwrap()));
        assert_eq!(search("10.0.0.0/24"), Search::Net("10.0.0.0/24".parse().unwrap()));
        assert_eq!(search("00:50:56"), Search::Mac(vec![0, 0, 5, 0, 5, 6]));
        assert_eq!(search(" Ether1 "), Search::Text("ether1".into()));
        assert_eq!(search(""), Search::Any);
        // Too long for a MAC: text.
        assert!(matches!(search("00:11:22:33:44:55:66"), Search::Text(_)));
    }

}
