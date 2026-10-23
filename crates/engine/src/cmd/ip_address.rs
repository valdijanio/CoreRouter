//! `/ip address` beyond add/remove/print (G1.28): `set` (edit, enable,
//! disable, comment) and `preview`, the query behind the GUI's add/edit
//! modal (`docs/ui-style.md`): what an address gives (network, broadcast,
//! hosts), a series by range, the checks (repeated address, overlap with
//! another interface, ARP use on the wire, access of this session) and the
//! commands it would run. The rules live here, not in the GUI.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use corerouter_model::route;
use corerouter_model::{AddressEntry, Config, IfName, ItemId};
use ipnet::IpNet;
use serde_json::{Map, Value, json};

use super::args::{opt_bool, opt_parse, opt_str, opt_text, req_parse};
use super::{CommandSpec, always};
use crate::address_probe::{Found, WAIT_SECS, mac_text};
use crate::dhcp_client::is_dynamic;
use crate::lockout::take_force;
use crate::validate::v6_twice;
use crate::{EngineError, Result, Session};

/// Most addresses one series (`to`) adds in one transaction.
pub const MAX_SERIES: u128 = 256;
/// Overlaps listed by name; the rest are counted.
const SHOWN_OVERLAPS: usize = 3;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "ip.address.set",
        "Set Address",
        [],
        None,
        "{id: *hex, address?: cidr, interface?: string, disabled?: bool (true: kept in the config, removed from the kernel), comment?: string, force?: bool (apply even if it cuts this session's own connection)} → {id}",
        has_static,
        set
    ),
    cmd!(query "ip.address.check", "Check Address", [], None,
        "{address?: string, interface?: string, to?: string (last address of a series: one entry per address from address to to, at most 256), id?: string (the address being edited), disabled?: bool, comment?: string, from_pool?: string, arp?: bool (default true: ARP probe for an IPv4 address, RFC 5227)} → {computed: [{label, value}], checks: [{level (ok | warning | error | pending | info), check, message, param}], commands: [{command, params}], risk, count}",
        always, preview),
];

fn has_static(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ip.addresses.is_empty() {
        Err("there are no IP addresses".into())
    } else {
        Ok(())
    }
}

/// Why a dynamic address cannot be changed here.
pub(super) fn dynamic_error(id: ItemId) -> EngineError {
    EngineError::bad(
        "id",
        format!(
            "{id} is dynamic (a DHCP client's lease or a Router Advertisement); release, \
             disable or remove the client instead (ip.dhcp-client.*, ipv6.dhcp-client.*), or \
             stop accepting RA (ipv6.settings.set)"
        ),
    )
}

/// The address `entry` would clash with among `others` on the same
/// interface: the same prefix, or (IPv6) the same address from the same pool.
fn clash(entry: &AddressEntry, others: &[AddressEntry]) -> Option<String> {
    for a in others.iter().filter(|a| a.id != entry.id && a.interface == entry.interface) {
        if a.address == entry.address {
            return Some(format!("{} already exists on {}", entry.address, entry.interface));
        }
        if let IpNet::V6(net) = entry.address
            && a.address.addr() == entry.address.addr()
            && a.from_pool == entry.from_pool
        {
            return Some(v6_twice(net.addr(), &entry.interface, a.address));
        }
    }
    None
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let id: ItemId = req_parse(p, "id")?;
    if is_dynamic(id) {
        return Err(dynamic_error(id));
    }
    take_force(s, p)?;
    super::interface::refuse_unmanaged(s, p, &["interface"])?;
    let address: Option<IpNet> = opt_parse(p, "address")?;
    let interface: Option<IfName> = opt_parse(p, "interface")?;
    let disabled = opt_bool(p, "disabled")?;
    let comment = opt_text(p, "comment", 256)?;
    let cfg = s.store_mut().candidate_mut();
    let Some(mut entry) = cfg.ip.addresses.iter().find(|a| a.id == id).cloned() else {
        return Err(EngineError::bad("id", format!("no address {id}")));
    };
    if let Some(i) = interface {
        if !cfg.interfaces.contains_key(&i) {
            return Err(EngineError::bad(
                "interface",
                format!("no interface '{i}' (see interface.list)"),
            ));
        }
        entry.interface = i;
    }
    if let Some(a) = address {
        if entry.from_pool.is_some() && !matches!(a, IpNet::V6(_)) {
            return Err(EngineError::bad(
                "address",
                "only IPv6 addresses come from a pool (write ::1/64)",
            ));
        }
        entry.address = a;
    }
    if let Some(d) = disabled {
        entry.disabled = d;
    }
    if let Some(c) = comment {
        entry.comment = c;
    }
    if let Some(why) = clash(&entry, &cfg.ip.addresses) {
        return Err(EngineError::bad("address", why));
    }
    if let Some(slot) = cfg.ip.addresses.iter_mut().find(|a| a.id == id) {
        *slot = entry;
    }
    Ok(json!({ "id": id }))
}

/// One check of a preview.
fn check(level: &str, check: &str, message: impl Into<String>, param: &str) -> Value {
    json!({"level": level, "check": check, "message": message.into(), "param": param})
}

fn computed(label: &str, value: impl Into<String>) -> Value {
    json!({"label": label, "value": value.into()})
}

/// What the preview answers.
#[derive(Default)]
struct Preview {
    computed: Vec<Value>,
    checks: Vec<Value>,
    commands: Vec<Value>,
    risk: Option<String>,
    count: u128,
}

impl Preview {
    fn error(&mut self, name: &str, message: impl Into<String>, param: &str) {
        self.checks.push(check("error", name, message, param));
    }

    fn has_error(&self) -> bool {
        self.checks.iter().any(|c| c["level"] == "error")
    }

    fn done(self) -> Value {
        let ok = !self.has_error();
        json!({
            "computed": self.computed,
            "checks": self.checks,
            "commands": if ok { self.commands } else { Vec::new() },
            "risk": if ok { self.risk } else { None },
            "count": u64::try_from(self.count).unwrap_or(u64::MAX),
        })
    }
}

/// Hosts a prefix holds: all of them for /31 and /32 (RFC 3021), less the
/// network and broadcast addresses below that; as text, since a /64 has
/// 2^64.
fn hosts_text(net: IpNet) -> String {
    match net {
        IpNet::V4(n) => {
            let bits = 32 - u32::from(n.prefix_len());
            let all = 1u64 << bits;
            let usable = if bits <= 1 { all } else { all - 2 };
            usable.to_string()
        }
        IpNet::V6(n) => {
            let bits = 128 - u32::from(n.prefix_len());
            if bits >= 64 {
                format!("2^{bits}")
            } else {
                (1u128 << bits).to_string()
            }
        }
    }
}

fn add_ip(a: IpAddr, n: u128) -> Option<IpAddr> {
    match a {
        IpAddr::V4(v4) => u32::try_from(u128::from(u32::from(v4)).checked_add(n)?)
            .ok()
            .map(|x| IpAddr::V4(Ipv4Addr::from(x))),
        IpAddr::V6(v6) => u128::from(v6)
            .checked_add(n)
            .map(|x| IpAddr::V6(Ipv6Addr::from(x))),
    }
}

fn ip_num(a: IpAddr) -> u128 {
    match a {
        IpAddr::V4(v4) => u128::from(u32::from(v4)),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

/// Calculated fields of one address.
fn describe(net: IpNet, p: &mut Preview) {
    p.computed.push(computed("Network", net.trunc().to_string()));
    if let IpNet::V4(n) = net {
        p.computed.push(computed("Netmask", n.netmask().to_string()));
        if n.prefix_len() < 31 {
            p.computed.push(computed("Broadcast", n.broadcast().to_string()));
        }
    }
    p.computed.push(computed("Hosts", hosts_text(net)));
    if let IpNet::V4(n) = net
        && n.prefix_len() < 31
    {
        let first = add_ip(IpAddr::V4(n.network()), 1);
        let last = u32::from(n.broadcast()).checked_sub(1).map(Ipv4Addr::from);
        if let (Some(f), Some(l)) = (first, last) {
            p.computed.push(computed("Host range", format!("{f} – {l}")));
        }
    }
}

/// The routing table of `iface` (VRF), as overlaps count only inside one.
fn table_name(cfg: &Config, iface: &IfName) -> String {
    route::table_of(cfg, iface).to_string()
}

/// Repeated addresses and overlapping networks of `items` (on `iface`)
/// against the rest of `cfg`, the edited entry `editing` left out.
fn conflicts(cfg: &Config, items: &[IpNet], iface: &IfName, editing: Option<ItemId>, p: &mut Preview) {
    let table = table_name(cfg, iface);
    let mut overlaps: Vec<String> = Vec::new();
    let mut repeated: Vec<String> = Vec::new();
    let mut secondary = false;
    for a in cfg.ip.addresses.iter().filter(|a| Some(a.id) != editing) {
        let same_table = table_name(cfg, &a.interface) == table;
        for item in items {
            if a.address.addr() == item.addr() {
                if a.interface == *iface || same_table {
                    repeated.push(format!("{} is already on {}", item.addr(), a.interface));
                }
                continue;
            }
            let overlap = a.address.trunc().contains(&item.trunc().network())
                || item.trunc().contains(&a.address.trunc().network());
            if !overlap || !same_table {
                continue;
            }
            if a.interface == *iface {
                secondary = true;
            } else {
                overlaps.push(format!("{} on {}", a.address, a.interface));
            }
        }
    }
    repeated.dedup();
    overlaps.sort();
    overlaps.dedup();
    if let Some(first) = repeated.first() {
        let more = repeated.len() - 1;
        let tail = if more > 0 { format!(" (and {more} more)") } else { String::new() };
        p.error("duplicate", format!("{first}{tail}"), "address");
    } else if !overlaps.is_empty() {
        let shown: Vec<&str> = overlaps.iter().take(SHOWN_OVERLAPS).map(String::as_str).collect();
        let more = overlaps.len().saturating_sub(SHOWN_OVERLAPS);
        let tail = if more > 0 { format!(" and {more} more") } else { String::new() };
        p.error(
            "overlap",
            format!(
                "the network overlaps {}{tail} (table {table}): two interfaces would claim the \
                 same addresses and the connected route would go to only one; use another \
                 network, or a VRF",
                shown.join(", ")
            ),
            "address",
        );
    } else {
        p.checks.push(check(
            "ok",
            "overlap",
            if secondary {
                format!("another address of {iface} is in this network (a secondary address: fine)")
            } else {
                format!("no other interface uses this network (table {table})")
            },
            "address",
        ));
    }
}

fn preview(s: &mut Session, p: &Value) -> Result<Value> {
    let mut out = Preview::default();
    // Bad input is a check, never an error: the modal shows it by the field.
    let text = |k: &str| opt_str(p, k).ok().flatten().map(str::trim).filter(|t| !t.is_empty());
    let editing = match text("id") {
        None => None,
        Some(t) => match t.parse::<ItemId>() {
            Ok(id) if is_dynamic(id) => {
                out.error("id", dynamic_error(id).to_string(), "id");
                return Ok(out.done());
            }
            Ok(id) => match s.store().candidate().ip.addresses.iter().find(|a| a.id == id) {
                Some(a) => Some(a.clone()),
                None => {
                    out.error("id", format!("no address {id}"), "id");
                    return Ok(out.done());
                }
            },
            Err(e) => {
                out.error("id", e.to_string(), "id");
                return Ok(out.done());
            }
        },
    };
    let from_pool = text("from_pool").map(str::to_owned);
    let comment = text("comment").map(str::to_owned);
    let disabled = opt_bool(p, "disabled").ok().flatten();
    let address = match text("address") {
        Some(t) => match t.parse::<IpNet>() {
            Ok(a) => Some(a),
            Err(_) => {
                let hint = if t.parse::<IpAddr>().is_ok() {
                    format!("add the prefix length: {t}/24 (a bare address would be a /32)")
                } else {
                    format!("'{}' is not an address: write 10.0.0.1/24 or 2001:db8::1/64", t.chars().take(64).collect::<String>())
                };
                out.error("address", hint, "address");
                None
            }
        },
        None => editing.as_ref().map(|e| e.address),
    };
    let Some(address) = address else {
        if !out.has_error() {
            out.checks.push(check("info", "address", "type an address: 10.0.0.1/24", "address"));
        }
        return Ok(out.done());
    };
    describe(address, &mut out);

    // A series by range: `to` is the last address, same family, inside the
    // network.
    let mut items = vec![address];
    if let Some(t) = text("to") {
        match t.parse::<IpAddr>() {
            _ if editing.is_some() => out.error("series", "a series adds new addresses: not when editing one", "to"),
            Ok(last) if last.is_ipv4() != address.addr().is_ipv4() => {
                out.error("series", "the last address is of the other family", "to");
            }
            Ok(last) if !address.trunc().contains(&last) => {
                out.error("series", format!("{last} is outside {}", address.trunc()), "to");
            }
            Ok(last) if ip_num(last) < ip_num(address.addr()) => {
                out.error("series", format!("{last} comes before {}", address.addr()), "to");
            }
            Ok(last) => {
                let count = ip_num(last) - ip_num(address.addr()) + 1;
                out.count = count;
                if count > MAX_SERIES {
                    out.error(
                        "series",
                        format!("{count} addresses: at most {MAX_SERIES} in one go (split the range)"),
                        "to",
                    );
                } else {
                    items = (0..count)
                        .filter_map(|i| add_ip(address.addr(), i))
                        .filter_map(|a| IpNet::new(a, address.prefix_len()).ok())
                        .collect();
                    out.computed.push(computed("Series", format!("{count} addresses, one transaction")));
                }
            }
            Err(_) => out.error("series", "write the last address of the range: 10.20.0.5", "to"),
        }
    }
    out.count = out.count.max(1);
    if let IpNet::V4(n) = address
        && n.prefix_len() < 31
    {
        let edge = items.iter().find_map(|i| match i.addr() {
            IpAddr::V4(a) if a == n.network() => Some(format!("{a} is the network address of {}", n.trunc())),
            IpAddr::V4(a) if a == n.broadcast() => Some(format!("{a} is the broadcast address of {}", n.trunc())),
            _ => None,
        });
        if let Some(e) = edge {
            out.checks.push(check("warning", "edge", format!("{e}: hosts cannot use it"), "address"));
        }
    }
    if from_pool.is_some() && !address.addr().is_ipv6() {
        out.error("pool", "only IPv6 addresses come from a pool (write ::1/64)", "from_pool");
    }

    // The interface.
    let interface = text("interface")
        .map(str::to_owned)
        .or_else(|| editing.as_ref().map(|e| e.interface.as_str().to_owned()));
    let candidate = s.store().candidate().clone();
    let iface: Option<IfName> = match interface {
        None => {
            out.error("interface", "pick an interface", "interface");
            None
        }
        Some(t) => match t.parse::<IfName>() {
            Ok(i) if candidate.interfaces.contains_key(&i) => Some(i),
            Ok(i) => {
                out.error("interface", format!("no interface '{i}'"), "interface");
                None
            }
            Err(e) => {
                out.error("interface", e.to_string(), "interface");
                None
            }
        },
    };
    let Some(iface) = iface else {
        return Ok(out.done());
    };
    if candidate.interfaces.get(&iface).is_some_and(|i| i.disabled) {
        out.checks.push(check(
            "warning",
            "interface",
            format!("{iface} is disabled: the address stays inactive until it is enabled"),
            "interface",
        ));
    }
    let effective = s.effective(&candidate).into_owned();
    conflicts(&effective, &items, &iface, editing.as_ref().map(|e| e.id), &mut out);

    // Used on the wire? One address, IPv4, not ours already.
    let ours = effective.ip.addresses.iter().any(|a| a.address.addr() == address.addr());
    let arp = opt_bool(p, "arp").ok().flatten().unwrap_or(true);
    match address.addr() {
        IpAddr::V4(v4) if arp && items.len() == 1 && !ours && !out.has_error() => {
            let found = s.arp_check(&iface, v4);
            out.checks.push(match found {
                Found::Running => check("pending", "arp", format!("ARP probe for {v4} on {iface}…"), "address"),
                Found::Free => check(
                    "ok",
                    "arp",
                    format!("nobody answered an ARP probe for {v4} on {iface} within {WAIT_SECS} s (RFC 5227)"),
                    "address",
                ),
                Found::Taken(mac) => check(
                    "warning",
                    "arp",
                    format!("{v4} is in use on {iface}: {} answered an ARP probe (RFC 5227)", mac_text(mac)),
                    "address",
                ),
                Found::Failed(why) => check("info", "arp", format!("ARP check not done: {why}"), "address"),
            });
        }
        IpAddr::V4(_) if arp && items.len() > 1 => out.checks.push(check(
            "info",
            "arp",
            "ARP check: one address at a time (not for a series)",
            "address",
        )),
        IpAddr::V6(_) => out.checks.push(check(
            "info",
            "dad",
            "IPv6: the kernel checks the address itself after adding it (DAD, RFC 4862 §5.4): \
             tentative for about a second, then active, or dad-failed if another host has it",
            "address",
        )),
        _ => {}
    }

    // The commands, and what they would do to this session.
    match &editing {
        None => {
            for item in &items {
                let mut params = Map::new();
                params.insert("address".into(), json!(item.to_string()));
                params.insert("interface".into(), json!(iface));
                if disabled == Some(true) {
                    params.insert("disabled".into(), json!(true));
                }
                if let Some(c) = &comment {
                    params.insert("comment".into(), json!(c));
                }
                if let Some(pool) = &from_pool {
                    params.insert("from_pool".into(), json!(pool));
                }
                out.commands.push(json!({"command": "ip.address.add", "params": params}));
            }
        }
        Some(e) => {
            let mut params = Map::new();
            params.insert("id".into(), json!(e.id));
            let mut after = e.clone();
            if address != e.address {
                params.insert("address".into(), json!(address.to_string()));
                after.address = address;
            }
            if iface != e.interface {
                params.insert("interface".into(), json!(iface));
                after.interface = iface.clone();
            }
            if let Some(d) = disabled.filter(|d| *d != e.disabled) {
                params.insert("disabled".into(), json!(d));
                after.disabled = d;
            }
            let c = comment.clone().unwrap_or_default();
            if p.get("comment").is_some() && c != e.comment {
                params.insert("comment".into(), json!(c));
            }
            if params.len() == 1 {
                out.checks.push(check("info", "change", "nothing changed", ""));
            } else {
                out.commands.push(json!({"command": "ip.address.set", "params": params}));
                let mut next = candidate.clone();
                if let Some(slot) = next.ip.addresses.iter_mut().find(|a| a.id == e.id) {
                    *slot = after;
                }
                out.risk = access_risk(s, &next);
                if out.risk.is_none() && s.in_safe_mode() {
                    out.checks.push(check("info", "access", "Safe Mode is on: a change that cuts this session is undone", ""));
                }
            }
        }
    }
    Ok(out.done())
}

/// Why committing `next` would cut this session (`None`: it would not,
/// Safe Mode is on, or the caller has no connection).
pub(super) fn access_risk(s: &Session, next: &Config) -> Option<String> {
    if s.in_safe_mode() {
        return None;
    }
    let running = s.effective(s.store().running()).into_owned();
    let after = s.effective(next).into_owned();
    let dynamic = s.dynamic_now();
    s.lockout_reason(&running, &after, &dynamic, &dynamic)
}
