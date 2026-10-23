//! /ip firewall xdp (G2.5a): the filter in the NIC driver (XDP). Where it
//! runs (`interface.*`), what it drops (`set`/`print`), what it dropped
//! (`interface.list` with packets per second, `top`), and `reset-counters`.
//! The data plane is `hal-linux` + `dataplane-ebpf`; see docs/xdp.md.

use corerouter_hal::xdp::{REASONS, XdpStatus};
use corerouter_model::firewall::Name;
use corerouter_model::xdp::{self, XdpInterface, XdpMode};
use corerouter_model::{Config, IfName, InterfaceKind};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, opt_text, opt_u32, req_parse};
use super::{CommandSpec, always};
use crate::lockout::take_force;
use crate::xdp::XdpRates;
use crate::{EngineError, Result, Session};

/// Most dropped sources `top` returns at most.
const MAX_TOP: u32 = 1000;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "ip.firewall.xdp.interface.add",
        "Add XDP Interface",
        ["IP", "Firewall", "XDP"],
        None,
        "{interface: string, mode?: auto|native|generic (default auto: native where the driver has it), disabled?: bool, comment?: string, force?: bool (commit even if it cuts this management connection)} → {interface, mode}",
        always,
        add
    ),
    cmd!(
        "ip.firewall.xdp.interface.set",
        "Set XDP Interface",
        [],
        None,
        "{interface: string, mode?: auto|native|generic, disabled?: bool, comment?: string, force?: bool} → {interface, mode}",
        always,
        set_interface
    ),
    cmd!(
        "ip.firewall.xdp.interface.remove",
        "Remove XDP Interface",
        [],
        None,
        "{interface: string} → {interface}",
        always,
        remove
    ),
    cmd!(query "ip.firewall.xdp.interface.list", "XDP Interfaces", ["IP", "Firewall", "XDP"], None,
        "{} → [{interface, mode, disabled, comment, active: native|generic|null, note, pass_pps, drop_pps, counters: {pass|blocked|rate-limit|malformed|tcp-flags: {packets, bytes, pps}}}]",
        always, list),
    cmd!(
        "ip.firewall.xdp.set",
        "Set XDP Filter",
        [],
        None,
        "{block_lists?: [string] | string (comma-separated address lists; empty clears), allow_lists?: [string] | string, rate_limit?: u32 (packets/s per source, 0 = off), rate_burst?: u32 (0 = one second's worth), drop_malformed?: bool, drop_invalid_tcp_flags?: bool, force?: bool (commit even if it cuts this management connection)} → {block_lists, allow_lists, rate_limit, rate_burst, drop_malformed, drop_invalid_tcp_flags, warnings}",
        always,
        set
    ),
    cmd!(query "ip.firewall.xdp.print", "XDP Filter", ["IP", "Firewall", "XDP"], None,
        "{} → {block_lists, allow_lists, rate_limit, rate_burst, drop_malformed, drop_invalid_tcp_flags, block_prefixes, allow_prefixes, available, unavailable, lists: [{name, entries}]}",
        always, print),
    cmd!(query "ip.firewall.xdp.top", "XDP Top Sources", [], None,
        "{count?: u32 (1..=1000, default 20)} → [{address, packets, bytes, reason, list, last_secs}]",
        always, top),
    cmd!(
        "ip.firewall.xdp.reset-counters",
        "Reset XDP Counters",
        [],
        None,
        "{} → {}",
        always,
        reset
    ),
];

fn mode_param(p: &Value) -> Result<Option<XdpMode>> {
    opt_str(p, "mode")?
        .map(|m| {
            XdpMode::parse(m).ok_or_else(|| {
                EngineError::bad("mode", "must be auto, native or generic")
            })
        })
        .transpose()
}

/// Native mode lives in the NIC driver: a VLAN, bridge, VRF or loopback
/// has no driver of its own to run it.
fn check_mode(cfg: &Config, name: &IfName, mode: XdpMode) -> Result<()> {
    let Some(iface) = cfg.interfaces.get(name) else {
        return Err(EngineError::bad(
            "interface",
            format!("no interface '{name}' (see interface.list)"),
        ));
    };
    let kind = &iface.kind;
    if matches!(kind, InterfaceKind::Loopback | InterfaceKind::Vrf { .. }) {
        return Err(EngineError::bad(
            "interface",
            format!(
                "'{name}' is a {}: no packets arrive on it from a wire",
                kind.label()
            ),
        ));
    }
    if mode == XdpMode::Native
        && !matches!(kind, InterfaceKind::Ethernet | InterfaceKind::Bonding { .. })
    {
        return Err(EngineError::bad(
            "mode",
            format!(
                "native XDP runs in a NIC driver; '{name}' is a {} (use generic, or attach to its physical port)",
                kind.label()
            ),
        ));
    }
    Ok(())
}

fn position(cfg: &Config, name: &IfName) -> Result<usize> {
    cfg.ip
        .xdp
        .interfaces
        .iter()
        .position(|i| &i.interface == name)
        .ok_or_else(|| {
            EngineError::bad(
                "interface",
                format!("XDP is not on '{name}' (see ip.firewall.xdp.interface.list)"),
            )
        })
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    super::interface::refuse_unmanaged(s, p, &["interface"])?;
    take_force(s, p)?;
    let name: IfName = req_parse(p, "interface")?;
    let mode = mode_param(p)?.unwrap_or_default();
    let disabled = opt_bool(p, "disabled")?.unwrap_or(false);
    let comment = opt_text(p, "comment", 256)?.unwrap_or_default();
    let cfg = s.store_mut().candidate_mut();
    check_mode(cfg, &name, mode)?;
    let x = &mut cfg.ip.xdp;
    if x.interfaces.iter().any(|i| i.interface == name) {
        return Err(EngineError::bad(
            "interface",
            format!("XDP is already on '{name}' (ip.firewall.xdp.interface.set changes it)"),
        ));
    }
    if x.interfaces.len() >= xdp::MAX_INTERFACES {
        return Err(EngineError::bad(
            "interface",
            format!("at most {} interfaces", xdp::MAX_INTERFACES),
        ));
    }
    x.interfaces.push(XdpInterface {
        interface: name.clone(),
        mode,
        disabled,
        comment,
    });
    Ok(json!({"interface": name, "mode": mode.name()}))
}

fn set_interface(s: &mut Session, p: &Value) -> Result<Value> {
    take_force(s, p)?;
    let name: IfName = req_parse(p, "interface")?;
    let mode = mode_param(p)?;
    let disabled = opt_bool(p, "disabled")?;
    let comment = opt_text(p, "comment", 256)?;
    let cfg = s.store_mut().candidate_mut();
    let i = position(cfg, &name)?;
    let current = cfg.ip.xdp.interfaces.get(i).map(|e| e.mode).unwrap_or_default();
    let mode = mode.unwrap_or(current);
    check_mode(cfg, &name, mode)?;
    let Some(e) = cfg.ip.xdp.interfaces.get_mut(i) else {
        return Err(EngineError::bad("interface", "gone"));
    };
    e.mode = mode;
    if let Some(d) = disabled {
        e.disabled = d;
    }
    if let Some(c) = comment {
        e.comment = c;
    }
    Ok(json!({"interface": name, "mode": mode.name()}))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let name: IfName = req_parse(p, "interface")?;
    let cfg = s.store_mut().candidate_mut();
    let i = position(cfg, &name)?;
    cfg.ip.xdp.interfaces.remove(i);
    Ok(json!({"interface": name}))
}

/// `key` as address-list names: `[string]` or a comma-separated string
/// (empty clears), each at most once.
fn opt_lists(p: &Value, key: &str) -> Result<Option<Vec<Name>>> {
    let raw: Vec<String> = match p.get(key) {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(t)) => t
            .split(',')
            .map(str::trim)
            .filter(|x| !x.is_empty())
            .map(str::to_owned)
            .collect(),
        Some(Value::Array(a)) => a
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| EngineError::bad(key, "each list name must be a string"))
            })
            .collect::<Result<_>>()?,
        Some(_) => {
            return Err(EngineError::bad(
                key,
                "must be a list of names or a comma-separated string",
            ));
        }
    };
    if raw.len() > xdp::MAX_LISTS {
        return Err(EngineError::bad(
            key,
            format!("at most {} address lists", xdp::MAX_LISTS),
        ));
    }
    let mut out: Vec<Name> = Vec::new();
    for r in raw {
        let n: Name = r
            .parse()
            .map_err(|e: corerouter_model::ParseError| EngineError::bad(key, e.to_string()))?;
        if !out.contains(&n) {
            out.push(n);
        }
    }
    Ok(Some(out))
}

fn entries(cfg: &Config, list: &Name) -> usize {
    cfg.ip
        .firewall
        .address_lists
        .iter()
        .filter(|e| &e.list == list)
        .count()
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    take_force(s, p)?;
    let block = opt_lists(p, "block_lists")?;
    let allow = opt_lists(p, "allow_lists")?;
    let rate = opt_u32(p, "rate_limit")?;
    let burst = opt_u32(p, "rate_burst")?;
    let malformed = opt_bool(p, "drop_malformed")?;
    let flags = opt_bool(p, "drop_invalid_tcp_flags")?;
    if rate.is_some_and(|r| r > xdp::MAX_RATE) {
        return Err(EngineError::bad(
            "rate_limit",
            format!("at most {} packets/s", xdp::MAX_RATE),
        ));
    }
    if burst.is_some_and(|b| b > xdp::MAX_BURST) {
        return Err(EngineError::bad(
            "rate_burst",
            format!("at most {} packets", xdp::MAX_BURST),
        ));
    }
    let cfg = s.store_mut().candidate_mut();
    let mut f = cfg.ip.xdp.filter.clone();
    if let Some(b) = block {
        f.block_lists = b;
    }
    if let Some(a) = allow {
        f.allow_lists = a;
    }
    if let Some(both) = f.block_lists.iter().find(|b| f.allow_lists.contains(b)) {
        return Err(EngineError::bad(
            "block_lists",
            format!("'{both}' is both a block and an allow list; the allow list would win, so the block does nothing"),
        ));
    }
    if let Some(r) = rate {
        f.rate_limit = r;
    }
    if let Some(b) = burst {
        f.rate_burst = b;
    }
    if let Some(m) = malformed {
        f.drop_malformed = m;
    }
    if let Some(t) = flags {
        f.drop_invalid_tcp_flags = t;
    }
    let mut warnings: Vec<String> = f
        .block_lists
        .iter()
        .chain(&f.allow_lists)
        .filter(|l| entries(cfg, l) == 0)
        .map(|l| format!("address list '{l}' has no entries yet (it matches nothing until it does)"))
        .collect();
    if f.rate_limit > 0 && f.rate_limit < 100 {
        warnings.push(format!(
            "{} packets/s per source is low: one busy client behind NAT, a resolver or a BGP peer can exceed it (put those in an allow list)",
            f.rate_limit
        ));
    }
    cfg.ip.xdp.filter = f.clone();
    Ok(json!({
        "block_lists": f.block_lists,
        "allow_lists": f.allow_lists,
        "rate_limit": f.rate_limit,
        "rate_burst": f.rate_burst,
        "drop_malformed": f.drop_malformed,
        "drop_invalid_tcp_flags": f.drop_invalid_tcp_flags,
        "warnings": warnings,
    }))
}

/// The data plane's status; `Unsupported` (the backend has no XDP) as an
/// empty status that says why.
fn status(s: &mut Session, top: usize) -> XdpStatus {
    match s.hal_mut().xdp_status(top) {
        Ok(st) => st,
        Err(e) => XdpStatus {
            unavailable: Some(e.to_string()),
            ..XdpStatus::default()
        },
    }
}

fn print(s: &mut Session, _: &Value) -> Result<Value> {
    let st = status(s, 0);
    let cfg = s.store().candidate();
    let f = &cfg.ip.xdp.filter;
    let lists: Vec<Value> = f
        .block_lists
        .iter()
        .chain(&f.allow_lists)
        .map(|l| json!({"name": l, "entries": entries(cfg, l)}))
        .collect();
    Ok(json!({
        "block_lists": f.block_lists,
        "allow_lists": f.allow_lists,
        "rate_limit": f.rate_limit,
        "rate_burst": f.rate_burst,
        "drop_malformed": f.drop_malformed,
        "drop_invalid_tcp_flags": f.drop_invalid_tcp_flags,
        "block_prefixes": st.block_prefixes,
        "allow_prefixes": st.allow_prefixes,
        "available": st.unavailable.is_none(),
        "unavailable": st.unavailable,
        "lists": lists,
    }))
}

fn list(s: &mut Session, _: &Value) -> Result<Value> {
    let st = status(s, 0);
    // The session clock: the platform's, else the one the daemon ticks.
    let now = s.now();
    if let Some(r) = s.ext_mut::<XdpRates>() {
        r.sample(&st, now);
    }
    let rates = s.ext::<XdpRates>();
    let cfg = s.store().candidate();
    let rows = cfg
        .ip
        .xdp
        .interfaces
        .iter()
        .map(|i| {
            let port = st.ports.iter().find(|p| p.interface == i.interface);
            let pps = |r: usize| rates.map_or(0, |x| x.pps(&i.interface, r));
            let counters: serde_json::Map<String, Value> = REASONS
                .iter()
                .enumerate()
                .map(|(r, name)| {
                    let (packets, bytes) = port
                        .and_then(|p| p.counters.get(r).copied())
                        .unwrap_or((0, 0));
                    (
                        (*name).to_owned(),
                        json!({"packets": packets, "bytes": bytes, "pps": pps(r)}),
                    )
                })
                .collect();
            let note = match (port, &st.unavailable) {
                (Some(p), _) => p.note.clone(),
                (None, Some(why)) => Some(why.clone()),
                (None, None) if i.disabled => None,
                (None, None) if !cfg.interfaces.contains_key(&i.interface) => {
                    Some("the interface no longer exists".to_owned())
                }
                (None, None) => Some("not attached".to_owned()),
            };
            json!({
                "interface": i.interface,
                "mode": i.mode.name(),
                "disabled": i.disabled,
                "comment": i.comment,
                "active": port.and_then(|p| p.active),
                "note": note,
                "pass_pps": pps(0),
                "drop_pps": rates.map_or(0, |x| x.drop_pps(&i.interface)),
                "counters": counters,
            })
        })
        .collect();
    Ok(Value::Array(rows))
}

fn top(s: &mut Session, p: &Value) -> Result<Value> {
    let count = opt_u32(p, "count")?.unwrap_or(20);
    if !(1..=MAX_TOP).contains(&count) {
        return Err(EngineError::bad(
            "count",
            format!("must be 1..={MAX_TOP}"),
        ));
    }
    let st = status(s, count as usize);
    Ok(Value::Array(
        st.top
            .iter()
            .take(count as usize)
            .map(|t| {
                json!({
                    "address": t.address,
                    "packets": t.packets,
                    "bytes": t.bytes,
                    "reason": t.reason,
                    "list": t.list,
                    "last_secs": t.last_secs,
                })
            })
            .collect(),
    ))
}

fn reset(s: &mut Session, _: &Value) -> Result<Value> {
    s.hal_mut()
        .xdp_reset()
        .map_err(|e| EngineError::bad("", e.to_string()))?;
    if let Some(r) = s.ext_mut::<XdpRates>() {
        *r = XdpRates::default();
    }
    Ok(json!({}))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lab() -> Session {
        Session::virtual_lab()
    }

    #[test]
    fn attach_list_and_detach() {
        let mut s = lab();
        let out = s
            .execute("ip.firewall.xdp.interface.add", &json!({"interface": "ether1"}))
            .unwrap();
        assert_eq!(out["mode"], "auto");
        let rows = s.execute("ip.firewall.xdp.interface.list", &json!({})).unwrap();
        assert_eq!(rows[0]["interface"], "ether1");
        assert_eq!(rows[0]["active"], "native");
        assert!(rows[0]["counters"]["blocked"]["packets"].is_u64());
        // Twice: refused, nothing changes.
        let err = s
            .execute("ip.firewall.xdp.interface.add", &json!({"interface": "ether1"}))
            .unwrap_err();
        assert!(err.to_string().contains("already"), "{err}");
        s.execute(
            "ip.firewall.xdp.interface.set",
            &json!({"interface": "ether1", "mode": "generic"}),
        )
        .unwrap();
        let rows = s.execute("ip.firewall.xdp.interface.list", &json!({})).unwrap();
        assert_eq!(rows[0]["active"], "generic");
        s.execute("ip.firewall.xdp.interface.remove", &json!({"interface": "ether1"}))
            .unwrap();
        let rows = s.execute("ip.firewall.xdp.interface.list", &json!({})).unwrap();
        assert_eq!(rows, json!([]));
    }

    #[test]
    fn validation() {
        let mut s = lab();
        for (params, needle) in [
            (json!({"interface": "nope"}), "no interface"),
            (json!({"interface": "ether1", "mode": "turbo"}), "auto, native or generic"),
        ] {
            let err = s
                .execute("ip.firewall.xdp.interface.add", &params)
                .unwrap_err();
            assert!(err.to_string().contains(needle), "{err}");
        }
        s.execute(
            "interface.vlan.add",
            &json!({"name": "vlan10", "vlan_id": 10, "parent": "ether1"}),
        )
        .unwrap();
        let err = s
            .execute(
                "ip.firewall.xdp.interface.add",
                &json!({"interface": "vlan10", "mode": "native"}),
            )
            .unwrap_err();
        assert!(err.to_string().contains("NIC driver"), "{err}");
        s.execute(
            "ip.firewall.xdp.interface.add",
            &json!({"interface": "vlan10", "mode": "generic"}),
        )
        .unwrap();
        for (params, needle) in [
            (json!({"rate_limit": 200_000_000}), "at most"),
            (json!({"block_lists": "a,b", "allow_lists": ["b"]}), "both a block and an allow"),
            (json!({"block_lists": "bad name!"}), "allowed"),
            (json!({"block_lists": 7}), "list of names"),
        ] {
            let err = s.execute("ip.firewall.xdp.set", &params).unwrap_err();
            assert!(err.to_string().contains(needle), "{params}: {err}");
        }
        let err = s
            .execute("ip.firewall.xdp.top", &json!({"count": 0}))
            .unwrap_err();
        assert!(err.to_string().contains("1..="), "{err}");
    }

    #[test]
    fn filter_settings_reach_the_data_plane() {
        let mut s = lab();
        s.execute(
            "ip.firewall.address-list.add",
            &json!({"list": "bogons", "address": "198.18.0.0/15"}),
        )
        .unwrap();
        s.execute("ip.firewall.xdp.interface.add", &json!({"interface": "ether2"}))
            .unwrap();
        let out = s
            .execute(
                "ip.firewall.xdp.set",
                &json!({"block_lists": "bogons, empty", "rate_limit": 50, "drop_malformed": false}),
            )
            .unwrap();
        let warnings = out["warnings"].to_string();
        assert!(warnings.contains("'empty' has no entries"), "{warnings}");
        assert!(warnings.contains("is low"), "{warnings}");
        let p = s.execute("ip.firewall.xdp.print", &json!({})).unwrap();
        assert_eq!(p["block_lists"], json!(["bogons", "empty"]));
        assert_eq!(p["block_prefixes"], 1);
        assert_eq!(p["drop_malformed"], false);
        assert_eq!(p["available"], true);
        assert_eq!(p["lists"][0], json!({"name": "bogons", "entries": 1}));
        // The lab's counters grow with its polls; the top source is the
        // blocked prefix.
        s.execute("ip.firewall.xdp.interface.list", &json!({})).unwrap();
        let top = s.execute("ip.firewall.xdp.top", &json!({})).unwrap();
        assert!(top.as_array().is_some_and(|t| t.len() <= 1));
        s.execute("ip.firewall.xdp.reset-counters", &json!({})).unwrap();
    }

    #[test]
    fn rollback_puts_the_filter_back() {
        let mut s = lab();
        s.execute("config.mode.set", &json!({"mode": "transactional"}))
            .unwrap();
        s.execute("ip.firewall.xdp.interface.add", &json!({"interface": "ether1"}))
            .unwrap();
        s.execute("ip.firewall.xdp.set", &json!({"rate_limit": 1000}))
            .unwrap();
        s.execute("config.discard", &json!({})).unwrap();
        assert!(s.store().candidate().ip.xdp.is_default());
    }
}
