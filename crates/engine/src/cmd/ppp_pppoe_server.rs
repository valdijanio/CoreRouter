//! `/interface pppoe-server server` (G4.3d, RouterOS v7): a PPPoE access
//! concentrator on one access interface, served by the daemon's `pppoe`
//! service (`proto-pppoe` + the XDP session map of G4.3c). Defaults follow
//! RouterOS, plus the safe ones it lacks (AC-Cookie, PADI limits, a cap on
//! new sessions per second, `pado_delay_by_load`). A change that ends
//! sessions (interface, disable, remove) says how many and needs
//! `force=yes`.

use corerouter_model::ppp::{
    LoadDelay, MAX_MTU, MAX_PADO_DELAY, MAX_PPPOE_SERVERS, MIN_MTU, PppAuth, PppoeServer,
    VlanRange,
};
use corerouter_model::{IfName, ItemId};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_str, opt_text, opt_u32};
use super::dhcp_client::opt_list;
use super::dhcp_server::find;
use super::ppp_common::{guard_drops, opt_name};
use corerouter_model::pppoe_services::{from_service_name, normalize};
use corerouter_model::pppoe_vlans::{self, MAX_OUTER_VLANS, MAX_PAYLOAD, Tpid, VlanMode};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!("interface.pppoe-server.server.add", "Add PPPoE Server", [], None,
        "{interface: string, name?: string (default pppoe-<interface>), service_name?: string (RouterOS: this name and the empty one; empty: any), services?: [{name, profile?, action?, pado_delay?, max_sessions?, padi_limit?}] | string (the Service-Name table, G4.3k: name is a Service-Name, empty or any; action terminate|delay|drop; the same list as JSON text), max_mtu?: int 64..1492 (default 1480), max_mru?: int 64..1492 (default 1480), mrru?: int 512..65535 | disabled, authentication?: [mschap2|mschap1|chap|pap] | string (default all four), keepalive_timeout?: int 1..3600 (s; disabled: no LCP echo) , one_session_per_host?: bool (default yes), max_sessions?: int 0..65534 (0: no limit), pado_delay?: int 0..30000 (ms), default_profile?: string (default default), pppoe_over_vlan_range?: string (100-115,120) | [string], accept_untagged?: bool (default yes), vlan_mode?: single|stacked (G4.3l: stacked = QinQ, two tags), outer_vlan_range?: string (stacked: the S-tags, 100-199,300; at most 512) | [string], inner_vlan_range?: string (stacked: the C-tags; any or empty: all) | [string], outer_tpid?: 0x88a8|0x8100 (stacked: the S-tag's, default 0x88a8), max_sessions_per_vlan?: int (sessions per VLAN, the pair in stacked mode; 1 = TR-101 1:1; 0: no limit), max_payload?: int 1493..1500 | none (RFC 4638 PPP-Max-Payload accepted; none: 1492), ac_cookie?: bool (default yes, RFC 2516 §9), padi_limit?: int (PADIs answered per second, default 2000; 0: none), mac_padi_limit?: int (per MAC per second, default 1; 0: none), new_session_rate?: int | auto (sessions accepted per second, default 2000; 0: none; auto: follows the RADIUS server's health, 1000 up to 20000), pado_delay_by_load?: string (sessions:ms,… as 5000:100,20000:300) | [string], disabled?: bool, comment?: string} → {id, name, warnings}",
        always, add),
    cmd!("interface.pppoe-server.server.set", "Set PPPoE Server", [], None,
        "{id: *hex | name, interface?: string, name?: string, service_name?: string, services?: [{name, profile?, action?, pado_delay?, max_sessions?, padi_limit?}] | string, max_mtu?: int 64..1492, max_mru?: int 64..1492, mrru?: int 512..65535 | disabled, authentication?: [mschap2|mschap1|chap|pap] | string, keepalive_timeout?: int 1..3600 | disabled, one_session_per_host?: bool, max_sessions?: int 0..65534, pado_delay?: int 0..30000, default_profile?: string, pppoe_over_vlan_range?: string | [string], accept_untagged?: bool, vlan_mode?: single|stacked, outer_vlan_range?: string | [string], inner_vlan_range?: string | [string], outer_tpid?: 0x88a8|0x8100, max_sessions_per_vlan?: int, max_payload?: int 1493..1500 | none, ac_cookie?: bool, padi_limit?: int, mac_padi_limit?: int, new_session_rate?: int | auto, pado_delay_by_load?: string | [string], disabled?: bool, comment?: string, force?: bool (apply even if it drops active sessions)} → {id, name, warnings, dropped}",
        has_servers, set),
    cmd!("interface.pppoe-server.server.remove", "Remove PPPoE Server", [], None,
        "{id: *hex | name, force?: bool (remove even with sessions up)} → {id, name, dropped}",
        has_servers, remove),
    cmd!("interface.pppoe-server.server.enable", "Enable PPPoE Server", [], None,
        "{id: *hex | name} → {id, name}", has_servers, enable),
    cmd!("interface.pppoe-server.server.disable", "Disable PPPoE Server", [], None,
        "{id: *hex | name, force?: bool (disable even with sessions up)} → {id, name, dropped}",
        has_servers, disable),
    cmd!(query "interface.pppoe-server.server.list", "PPPoE Servers", [], None,
        "{} → [{id, name, interface, service_name? (the names served, comma-separated), services (the Service-Name table as JSON text, as services= takes it; per row with sessions: interface.pppoe-server.server.service.list), max_mtu, max_mru, mrru, authentication, keepalive_timeout, one_session_per_host, max_sessions, pado_delay, default_profile, pppoe_over_vlan_range, accept_untagged, vlan_mode, outer_vlan_range, inner_vlan_range (empty: any), outer_tpid, max_sessions_per_vlan, max_payload (none or the RFC 4638 cap), ac_cookie, padi_limit, mac_padi_limit, new_session_rate, pado_delay_by_load, disabled, comment?, flags (X disabled), sessions (up now), admission_rate? (new_session_rate=auto: the rate now), admission_reason?, warnings}]",
        always, list),
    cmd!(query "interface.pppoe-server.server.preview", "PPPoE Server Preview", [], None,
        "{id?: *hex | name, interface?: string, name?: string, service_name?: string, max_mtu?: string, max_mru?: string, mrru?: string, authentication?: string, keepalive_timeout?: string, one_session_per_host?: bool, max_sessions?: string, pado_delay?: string, default_profile?: string, pppoe_over_vlan_range?: string, accept_untagged?: bool, vlan_mode?: string, outer_vlan_range?: string, inner_vlan_range?: string, outer_tpid?: string, max_sessions_per_vlan?: string, max_payload?: string, ac_cookie?: bool, padi_limit?: string, mac_padi_limit?: string, new_session_rate?: string, pado_delay_by_load?: string, disabled?: bool, comment?: string} → {computed: [{label, value}], checks: [{level, check, message, param}], commands: [{command, params}], risk?}",
        always, preview),
    cmd!(query "interface.pppoe-server.monitor", "PPPoE Server Monitor", [], None,
        "{} → {running, sessions, padi, pado, padr, pads, padt_rx, padt_tx, auth_accept, auth_reject, throttled, dataplane, admission_rate (new_session_rate=auto now; 0: no server uses it), admission_reason?, last_error?, ipv6_sessions (IPv6CP up), delegated (DHCPv6-PD held), ipv6_dropped (ND/DHCPv6 refused), rx_dropped (frames lost before the BNG read them: a burst past its queues)}",
        always, monitor),
];

fn has_servers(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ppp.pppoe_servers.is_empty() {
        Err("there are no PPPoE servers (interface.pppoe-server.server.add)".into())
    } else {
        Ok(())
    }
}

fn mtu(p: &Value, key: &str) -> Result<Option<u16>> {
    opt_u32(p, key)?
        .map(|v| {
            u16::try_from(v)
                .ok()
                .filter(|v| (MIN_MTU..=MAX_MTU).contains(v))
                .ok_or_else(|| {
                    EngineError::bad(key, format!("{MIN_MTU}..={MAX_MTU} (RFC 2516 §7: at most 1492 over Ethernet)"))
                })
        })
        .transpose()
}

/// An integer, or `disabled` (`Some(None)`).
fn int_or_disabled(p: &Value, key: &str, range: std::ops::RangeInclusive<u32>) -> Result<Option<Option<u32>>> {
    if let Some(Value::String(t)) = p.get(key) {
        let t = t.trim();
        if t == "disabled" || t == "none" || t.is_empty() {
            return Ok(Some(None));
        }
        return t
            .parse::<u32>()
            .ok()
            .filter(|v| range.contains(v))
            .map(|v| Some(Some(v)))
            .ok_or_else(|| EngineError::bad(key, format!("{}..={} or disabled", range.start(), range.end())));
    }
    opt_u32(p, key)?
        .map(|v| {
            range
                .contains(&v)
                .then_some(Some(v))
                .ok_or_else(|| EngineError::bad(key, format!("{}..={} or disabled", range.start(), range.end())))
        })
        .transpose()
}

fn auths(p: &Value) -> Result<Option<Vec<PppAuth>>> {
    let Some(items) = opt_list(p, "authentication")? else {
        return Ok(None);
    };
    let mut out = Vec::new();
    for t in items {
        let a = PppAuth::parse(&t).ok_or_else(|| {
            let shown: String = t.chars().take(32).collect();
            EngineError::bad("authentication", format!("'{shown}': mschap2, mschap1, chap or pap"))
        })?;
        if !out.contains(&a) {
            out.push(a);
        }
    }
    if out.is_empty() {
        return Err(EngineError::bad(
            "authentication",
            "at least one method (a server without authentication would let anyone in)",
        ));
    }
    out.sort();
    Ok(Some(out))
}

fn vlans(p: &Value, key: &str) -> Result<Option<Vec<VlanRange>>> {
    let Some(items) = opt_list(p, key)? else {
        return Ok(None);
    };
    // `any` (the inner range): every VLAN id, kept as an empty list.
    if items.iter().any(|t| t.trim() == "any") {
        return Ok(Some(Vec::new()));
    }
    let mut out = items
        .iter()
        .map(|t| t.parse::<VlanRange>().map_err(|e| EngineError::bad(key, e.to_string())))
        .collect::<Result<Vec<_>>>()?;
    out.sort();
    out.dedup();
    Ok(Some(out))
}

fn tiers(p: &Value) -> Result<Option<Vec<LoadDelay>>> {
    let Some(items) = opt_list(p, "pado_delay_by_load")? else {
        return Ok(None);
    };
    if items.len() > 8 {
        return Err(EngineError::bad("pado_delay_by_load", "at most 8 tiers"));
    }
    let mut out = items
        .iter()
        .map(|t| t.parse::<LoadDelay>().map_err(|e| EngineError::bad("pado_delay_by_load", e.to_string())))
        .collect::<Result<Vec<_>>>()?;
    out.sort();
    Ok(Some(out))
}

fn apply(s: &Session, v: &mut PppoeServer, p: &Value) -> Result<()> {
    let cfg = s.store().candidate();
    if let Some(i) = opt_parse::<IfName>(p, "interface")? {
        if !cfg.interfaces.contains_key(&i) {
            return Err(EngineError::bad("interface", format!("no interface '{i}'")));
        }
        v.interface = i;
    }
    if let Some(n) = opt_name(p, "name")? {
        v.name = n;
    }
    // G4.3k: the table, or RouterOS' one name (which means a table). Any
    // change writes the table: a config from before it migrates here.
    if let Some(rows) = super::ppp_pppoe_service::opt_services(p)? {
        v.services = normalize(rows).map_err(|e| EngineError::bad("services", e))?;
    } else if let Some(t) = opt_text(p, "service_name", 64)? {
        v.services = from_service_name(&t);
    } else if v.services.is_empty() {
        v.services = v.service_table();
    }
    v.service_name.clear();
    if let Some(m) = mtu(p, "max_mtu")? {
        v.max_mtu = m;
    }
    if let Some(m) = mtu(p, "max_mru")? {
        v.max_mru = m;
    }
    if let Some(m) = int_or_disabled(p, "mrru", 512..=65535)? {
        v.mrru = m.and_then(|m| u16::try_from(m).ok());
    }
    if let Some(a) = auths(p)? {
        v.authentication = a;
    }
    if let Some(k) = int_or_disabled(p, "keepalive_timeout", 1..=3600)? {
        v.keepalive_timeout = k;
    }
    for (key, slot) in [
        ("one_session_per_host", &mut v.one_session_per_host),
        ("accept_untagged", &mut v.accept_untagged),
        ("ac_cookie", &mut v.ac_cookie),
        ("disabled", &mut v.disabled),
    ] {
        if let Some(b) = opt_bool(p, key)? {
            *slot = b;
        }
    }
    if let Some(n) = opt_u32(p, "max_sessions")? {
        if n > u32::from(proto_max_sid()) {
            return Err(EngineError::bad("max_sessions", "0..=65534 (RFC 2516 §4: one SESSION_ID space)"));
        }
        v.max_sessions = n;
    }
    if let Some(n) = opt_u32(p, "pado_delay")? {
        if n > MAX_PADO_DELAY {
            return Err(EngineError::bad("pado_delay", format!("0..={MAX_PADO_DELAY} ms")));
        }
        v.pado_delay = n;
    }
    // `auto`: the rate follows the RADIUS server's health (G4.3g).
    if p.get("new_session_rate").and_then(Value::as_str).is_some_and(|t| t.trim() == "auto") {
        v.new_session_rate_auto = true;
    } else if p.get("new_session_rate").is_some_and(|x| !x.is_null()) {
        v.new_session_rate_auto = false;
    }
    let fixed_rate = (!v.new_session_rate_auto)
        .then_some(("new_session_rate", &mut v.new_session_rate));
    for (key, slot) in [
        ("padi_limit", &mut v.padi_limit),
        ("mac_padi_limit", &mut v.mac_padi_limit),
    ]
    .into_iter()
    .chain(fixed_rate)
    {
        if let Some(n) = opt_u32(p, key)? {
            if n > 1_000_000 {
                return Err(EngineError::bad(key, "0..=1000000 per second"));
            }
            *slot = n;
        }
    }
    if let Some(t) = opt_str(p, "default_profile")? {
        let t = t.trim();
        if cfg.ppp.profile(t).is_none() {
            let shown: String = t.chars().take(64).collect();
            return Err(EngineError::bad("default_profile", format!("no profile '{shown}' (ppp.profile.add)")));
        }
        t.clone_into(&mut v.default_profile);
    }
    if let Some(r) = vlans(p, "pppoe_over_vlan_range")? {
        v.pppoe_over_vlan_range = r;
    }
    // G4.3l: QinQ.
    if let Some(t) = opt_str(p, "vlan_mode")? {
        v.vlan_mode = VlanMode::parse(t).ok_or_else(|| EngineError::bad("vlan_mode", "single (one 802.1Q tag) or stacked (QinQ)"))?;
    }
    if let Some(r) = vlans(p, "outer_vlan_range")? {
        v.outer_vlan_range = r;
    }
    if let Some(r) = vlans(p, "inner_vlan_range")? {
        v.inner_vlan_range = r;
    }
    if let Some(t) = opt_parse::<Tpid>(p, "outer_tpid")? {
        v.outer_tpid = t;
    }
    if let Some(n) = opt_u32(p, "max_sessions_per_vlan")? {
        if n > u32::from(proto_max_sid()) {
            return Err(EngineError::bad("max_sessions_per_vlan", "0..=65534"));
        }
        v.max_sessions_per_vlan = n;
    }
    if let Some(m) = int_or_disabled(p, "max_payload", 1492..=u32::from(MAX_PAYLOAD))? {
        // 1492 is RFC 2516's own: nothing to agree on.
        v.max_payload = m.and_then(|m| u16::try_from(m).ok()).filter(|m| *m > 1492);
    }
    if let Some(t) = tiers(p)? {
        v.pado_delay_by_load = t;
    }
    if let Some(c) = opt_text(p, "comment", 256)? {
        v.comment = c;
    }
    Ok(())
}

fn proto_max_sid() -> u16 {
    65_534
}

/// Conflicts refuse; risks come back as warnings.
fn check(s: &Session, v: &PppoeServer) -> Result<Vec<String>> {
    let cfg = s.store().candidate();
    let others = cfg.ppp.pppoe_servers.iter().filter(|o| o.id != v.id);
    for o in others {
        if o.name == v.name {
            return Err(EngineError::bad("name", format!("server '{}' exists", v.name)));
        }
        // One SESSION_ID space per port (RFC 2516 §4): two servers on one
        // interface would hand out the same ids. Several service names on
        // one port are a later gap.
        if !o.disabled && !v.disabled && o.interface == v.interface {
            return Err(EngineError::bad(
                "interface",
                format!("server {} already serves {} (one enabled PPPoE server per interface)", o.name, v.interface),
            ));
        }
    }
    let mut w = super::ppp_pppoe_service::check_rows(s, &v.service_table())?;
    // G4.3l: the two VLAN modes do not mix.
    match v.vlan_mode {
        VlanMode::Single => {
            if !v.outer_vlan_range.is_empty() || !v.inner_vlan_range.is_empty() {
                return Err(EngineError::bad("vlan_mode", "outer_vlan_range and inner_vlan_range are for vlan_mode=stacked"));
            }
        }
        VlanMode::Stacked => {
            if !v.pppoe_over_vlan_range.is_empty() {
                return Err(EngineError::bad("pppoe_over_vlan_range", "vlan_mode=stacked takes outer_vlan_range and inner_vlan_range instead"));
            }
            if v.outer_vlan_range.is_empty() {
                return Err(EngineError::bad("outer_vlan_range", "vlan_mode=stacked needs the S-tags (outer_vlan_range=100-199)"));
            }
            let n = pppoe_vlans::count(&v.outer_vlan_range);
            if n > MAX_OUTER_VLANS {
                return Err(EngineError::bad("outer_vlan_range", format!("{n} S-tags: at most {MAX_OUTER_VLANS} (one socket each for the PPPoE discovery)")));
            }
            for (key, r) in [("outer_vlan_range", &v.outer_vlan_range), ("inner_vlan_range", &v.inner_vlan_range)] {
                if let Some(o) = pppoe_vlans::overlap(r) {
                    return Err(EngineError::bad(key, format!("{o} overlap")));
                }
            }
            if v.outer_tpid == Tpid::Dot1q {
                w.push("outer_tpid=0x8100: both tags look like 802.1Q; a switch in between must not take the outer one for a customer VLAN".into());
            }
        }
    }
    if let Some(m) = v.max_payload {
        // RFC 4638 §5.1: the PPP payload is capped at the interface MTU
        // less 8 (PPPoE header and PPP Protocol field).
        if let Some(i) = cfg.interfaces.get(&v.interface)
            && u32::from(i.mtu) < u32::from(m) + 8
        {
            return Err(EngineError::bad(
                "max_payload",
                format!("{} has MTU {}: max_payload at most {} (RFC 4638 §5.1: MTU - 8); raise the MTU to {} first", v.interface, i.mtu, i.mtu.saturating_sub(8), m + 8),
            ));
        }
        w.push(format!("max_payload={m} (RFC 4638): the access network must carry {}-byte PPPoE frames end to end, or big packets vanish", m + 8));
    }
    if cfg.ip.addresses.iter().any(|a| a.interface == v.interface && !a.disabled) {
        w.push(format!("{} has an IP address: PPPoE does not need one there, and the subscribers' LAN sees the router (RouterOS advises against it)", v.interface));
    }
    if !v.ac_cookie {
        w.push("ac_cookie=no: forged PADRs create sessions (RFC 2516 §9)".into());
    }
    if !v.one_session_per_host {
        w.push("one_session_per_host=no: a CPE that reboots without PADT holds two addresses until the keepalive notices".into());
    }
    if v.authentication.contains(&PppAuth::Pap) && v.authentication.len() == 1 {
        w.push("only pap: the password crosses the access network in clear".into());
    }
    if v.keepalive_timeout.is_none() {
        w.push("keepalive disabled: a dead CPE keeps its session and address until session_timeout".into());
    }
    if let Some(vid) = v.pppoe_over_vlan_range.iter().chain(&v.outer_vlan_range).find_map(|r| {
        cfg.interfaces.values().find_map(|i| match &i.kind {
            corerouter_model::InterfaceKind::Vlan {
                vlan_id: id,
                parent,
                ..
            }
                if *parent == v.interface && (r.first..=r.last).contains(&id.get()) =>
            {
                Some(id.get())
            }
            _ => None,
        })
    }) {
        w.push(format!("VLAN {vid} of {} is also a VLAN interface: its frames go to that interface, not to this server", v.interface));
    }
    Ok(w)
}

fn index(s: &Session, p: &Value) -> Result<usize> {
    find(&s.store().candidate().ppp.pppoe_servers, p, |x| x.id, |x| Some(x.name.as_str()), "PPPoE server")
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let interface: IfName = opt_parse(p, "interface")?.ok_or_else(|| EngineError::bad("interface", "is required"))?;
    if s.store().candidate().ppp.pppoe_servers.len() >= MAX_PPPOE_SERVERS {
        return Err(EngineError::bad("interface", format!("at most {MAX_PPPOE_SERVERS} PPPoE servers")));
    }
    let mut v: PppoeServer = serde_json::from_value(json!({"id": "*0", "interface": interface.as_str()}))
        .map_err(|e| EngineError::bad("interface", e.to_string()))?;
    v.name = format!("pppoe-{interface}");
    apply(s, &mut v, p)?;
    let ppp = &mut s.store_mut().candidate_mut().ppp;
    v.id = ppp.next_id();
    let w = check(s, &v)?;
    let out = json!({"id": v.id, "name": v.name, "warnings": w});
    s.store_mut().candidate_mut().ppp.pppoe_servers.push(v);
    Ok(out)
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let i = index(s, p)?;
    let Some(old) = s.store().candidate().ppp.pppoe_servers.get(i).cloned() else {
        return Err(EngineError::bad("id", "no such server"));
    };
    let mut v = old.clone();
    apply(s, &mut v, p)?;
    let w = check(s, &v)?;
    // What restarts the server's sockets ends its sessions; the rest
    // applies to new sessions.
    let restarts = v.interface != old.interface
        || (v.disabled && !old.disabled)
        || v.pppoe_over_vlan_range != old.pppoe_over_vlan_range
        || v.accept_untagged != old.accept_untagged
        || v.vlan_mode != old.vlan_mode
        || v.outer_vlan_range != old.outer_vlan_range
        || v.outer_tpid != old.outer_tpid;
    let dropped = if restarts {
        guard_drops(s, p, &format!("this change to {}", old.name), |a| a.server == old.name)?
    } else {
        0
    };
    let out = json!({"id": v.id, "name": v.name, "warnings": w, "dropped": dropped});
    if let Some(slot) = s.store_mut().candidate_mut().ppp.pppoe_servers.get_mut(i) {
        *slot = v;
    }
    Ok(out)
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let i = index(s, p)?;
    let Some(v) = s.store().candidate().ppp.pppoe_servers.get(i).cloned() else {
        return Err(EngineError::bad("id", "no such server"));
    };
    let dropped = guard_drops(s, p, &format!("removing {}", v.name), |a| a.server == v.name)?;
    s.store_mut().candidate_mut().ppp.pppoe_servers.retain(|x| x.id != v.id);
    Ok(json!({"id": v.id, "name": v.name, "dropped": dropped}))
}

fn toggle(s: &mut Session, p: &Value, disabled: bool) -> Result<(ItemId, String, usize)> {
    let i = index(s, p)?;
    let Some(mut v) = s.store().candidate().ppp.pppoe_servers.get(i).cloned() else {
        return Err(EngineError::bad("id", "no such server"));
    };
    let dropped = if disabled && !v.disabled {
        guard_drops(s, p, &format!("disabling {}", v.name), |a| a.server == v.name)?
    } else {
        0
    };
    v.disabled = disabled;
    check(s, &v)?;
    let out = (v.id, v.name.clone(), dropped);
    if let Some(slot) = s.store_mut().candidate_mut().ppp.pppoe_servers.get_mut(i) {
        *slot = v;
    }
    Ok(out)
}

fn enable(s: &mut Session, p: &Value) -> Result<Value> {
    let (id, name, _) = toggle(s, p, false)?;
    Ok(json!({"id": id, "name": name}))
}

fn disable(s: &mut Session, p: &Value) -> Result<Value> {
    let (id, name, dropped) = toggle(s, p, true)?;
    Ok(json!({"id": id, "name": name, "dropped": dropped}))
}

fn list(s: &mut Session, _: &Value) -> Result<Value> {
    let backend = s.ppp_backend();
    let counts = backend.as_ref().map(|b| b.sessions_by_server()).unwrap_or_default();
    let stats = backend.as_ref().map(|b| b.stats());
    let servers = s.store().candidate().ppp.pppoe_servers.clone();
    let rows: Vec<Value> = servers
        .iter()
        .map(|v| {
            let table = v.service_table();
            let served: Vec<String> = table
                .iter()
                .filter(|r| !r.name.is_special() && r.accepts())
                .map(|r| r.name.to_string())
                .collect();
            let mut row = json!({
                "id": v.id,
                "name": v.name,
                "interface": v.interface,
                // As `services=` takes it (and `/export` writes it).
                "services": serde_json::to_string(&table).unwrap_or_default(),
                "max_mtu": v.max_mtu,
                "max_mru": v.max_mru,
                "mrru": v.mrru.map_or_else(|| json!("disabled"), |m| json!(m)),
                "authentication": v.authentication.iter().map(|a| a.as_str()).collect::<Vec<_>>(),
                "keepalive_timeout": v.keepalive_timeout.map_or_else(|| json!("disabled"), |k| json!(k)),
                "one_session_per_host": v.one_session_per_host,
                "max_sessions": v.max_sessions,
                "pado_delay": v.pado_delay,
                "default_profile": v.default_profile,
                "pppoe_over_vlan_range": v.pppoe_over_vlan_range.iter().map(ToString::to_string).collect::<Vec<_>>().join(","),
                "accept_untagged": v.accept_untagged,
                "vlan_mode": v.vlan_mode.as_str(),
                "outer_vlan_range": v.outer_vlan_range.iter().map(ToString::to_string).collect::<Vec<_>>().join(","),
                "inner_vlan_range": if v.inner_vlan_range.is_empty() { "any".to_owned() } else { v.inner_vlan_range.iter().map(ToString::to_string).collect::<Vec<_>>().join(",") },
                "outer_tpid": v.outer_tpid.to_string(),
                "max_sessions_per_vlan": v.max_sessions_per_vlan,
                "max_payload": v.max_payload.map_or_else(|| json!("none"), |m| json!(m)),
                "ac_cookie": v.ac_cookie,
                "padi_limit": v.padi_limit,
                "mac_padi_limit": v.mac_padi_limit,
                "new_session_rate": if v.new_session_rate_auto { json!("auto") } else { json!(v.new_session_rate) },
                "pado_delay_by_load": v.pado_delay_by_load.iter().map(ToString::to_string).collect::<Vec<_>>().join(","),
                "disabled": v.disabled,
                "flags": if v.disabled { "X" } else { "" },
                "sessions": counts.get(&v.name).copied().unwrap_or(0),
                "warnings": check(s, v).unwrap_or_default(),
            });
            if let Some(o) = row.as_object_mut() {
                if !served.is_empty() {
                    o.insert("service_name".into(), json!(served.join(",")));
                }
                if !v.comment.is_empty() {
                    o.insert("comment".into(), json!(v.comment));
                }
                // new_session_rate=auto: the rate now and why.
                if v.new_session_rate_auto
                    && let Some(st) = stats.as_ref().filter(|st| st.admission_rate > 0)
                {
                    o.insert("admission_rate".into(), json!(st.admission_rate));
                    if let Some(r) = &st.admission_reason {
                        o.insert("admission_reason".into(), json!(r));
                    }
                }
            }
            row
        })
        .collect();
    Ok(Value::Array(rows))
}

/// The modal's preview. The modal sends numbers as text: they go to the
/// command as numbers.
fn preview(s: &mut Session, p: &Value) -> Result<Value> {
    let mut q = p.clone();
    if let Some(o) = q.as_object_mut() {
        for k in ["max_mtu", "max_mru", "max_sessions", "pado_delay", "padi_limit", "mac_padi_limit", "new_session_rate", "keepalive_timeout", "mrru", "max_sessions_per_vlan", "max_payload"] {
            if let Some(n) = o.get(k).and_then(Value::as_str).and_then(|t| t.trim().parse::<u64>().ok()) {
                o.insert(k.into(), json!(n));
            }
        }
    }
    super::ppp_common::preview(
        s,
        &q,
        ("interface.pppoe-server.server.add", "interface.pppoe-server.server.set"),
        (add, set),
        |s, v| {
            let name = v.get("name").and_then(Value::as_str).unwrap_or_default();
            let Some(srv) = s.store().candidate().ppp.pppoe_servers.iter().find(|x| x.name == name).cloned() else {
                return Vec::new();
            };
            let vlans: usize = srv.pppoe_over_vlan_range.iter().map(|r| usize::from(r.last - r.first) + 1).sum();
            let join = |r: &[VlanRange]| r.iter().map(ToString::to_string).collect::<Vec<_>>().join(",");
            let vlan_text = match srv.vlan_mode {
                VlanMode::Stacked => format!(
                    "QinQ: S-tag {} ({}) × C-tag {} — {} sockets for the discovery",
                    join(&srv.outer_vlan_range),
                    srv.outer_tpid,
                    if srv.inner_vlan_range.is_empty() { "any".to_owned() } else { join(&srv.inner_vlan_range) },
                    pppoe_vlans::count(&srv.outer_vlan_range) + usize::from(srv.accept_untagged)
                ),
                VlanMode::Single if vlans == 0 => "untagged only".to_owned(),
                VlanMode::Single => format!("{vlans} VLAN ids ({} sockets)", vlans + usize::from(srv.accept_untagged)),
            };
            let keep = srv.keepalive_timeout.map_or_else(
                || "off".to_owned(),
                |t| format!("LCP echo after {} s quiet, down after {t} s", t.div_ceil(2)),
            );
            let tiers = if srv.pado_delay_by_load.is_empty() {
                format!("{} ms", srv.pado_delay)
            } else {
                srv.pado_delay_by_load
                    .iter()
                    .map(|t| format!("{} ms from {} sessions", srv.pado_delay_at(t.sessions), t.sessions))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            vec![
                json!({"label": "VLANs", "value": vlan_text}),
                json!({"label": "Keepalive", "value": keep}),
                json!({"label": "PADO delay", "value": tiers}),
                json!({"label": "Sessions up", "value": s.ppp_active().iter().filter(|a| a.server == srv.name).count().to_string()}),
            ]
        },
    )
}

fn monitor(s: &mut Session, _: &Value) -> Result<Value> {
    let Some(b) = s.ppp_backend() else {
        return Ok(json!({"running": false, "sessions": 0, "padi": 0, "pado": 0, "padr": 0, "pads": 0,
            "padt_rx": 0, "padt_tx": 0, "auth_accept": 0, "auth_reject": 0, "throttled": 0, "dataplane": false, "admission_rate": 0,
            "ipv6_sessions": 0, "delegated": 0, "ipv6_dropped": 0, "rx_dropped": 0}));
    };
    let st = b.stats();
    let mut v = serde_json::to_value(&st).map_err(|e| EngineError::bad("stats", e.to_string()))?;
    if let Some(o) = v.as_object_mut() {
        o.insert("running".into(), json!(true));
    }
    Ok(v)
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;

    use corerouter_model::MacAddr;
    use corerouter_model::ppp::{ActiveSession, HistoryEntry, ServiceStats, Why};

    use super::*;
    use crate::ppp::PppBackend;

    pub(crate) struct Fake(pub Vec<ActiveSession>);

    impl PppBackend for Fake {
        fn active(&self) -> Vec<ActiveSession> {
            self.0.clone()
        }
        fn terminate(&self, ids: &[String]) -> usize {
            self.0.iter().filter(|a| ids.contains(&a.id)).count()
        }
        fn history(&self) -> Vec<HistoryEntry> {
            Vec::new()
        }
        fn why(&self, _: Option<&str>, _: Option<MacAddr>) -> Why {
            Why::default()
        }
        fn stats(&self) -> ServiceStats {
            ServiceStats { sessions: self.0.len() as u64, ..ServiceStats::default() }
        }
    }

    #[test]
    fn add_list_set_remove() {
        let mut s = Session::virtual_lab();
        let r = s
            .execute("interface.pppoe-server.server.add", &json!({
                "interface": "ether2", "service_name": "isp", "authentication": "pap,chap",
                "pppoe_over_vlan_range": "100-115,120", "pado_delay_by_load": "5000:100,1000:20",
                "keepalive_timeout": "disabled"
            }))
            .unwrap();
        assert_eq!(r["name"], "pppoe-ether2");
        assert!(r["warnings"].to_string().contains("keepalive disabled"), "{r}");
        let l = s.execute("interface.pppoe-server.server.list", &json!({})).unwrap();
        let row = &l[0];
        assert_eq!(row["authentication"], json!(["chap", "pap"]));
        assert_eq!(row["pppoe_over_vlan_range"], "100-115,120");
        assert_eq!(row["pado_delay_by_load"], "1000:20,5000:100");
        assert_eq!(row["keepalive_timeout"], "disabled");
        assert_eq!(row["max_mtu"], 1480);
        assert_eq!(row["ac_cookie"], true);
        s.execute("interface.pppoe-server.server.set", &json!({"id": "pppoe-ether2", "max_mru": 1492, "keepalive_timeout": 30})).unwrap();
        let v = &s.store().running().ppp.pppoe_servers[0];
        assert_eq!((v.max_mru, v.keepalive_timeout), (1492, Some(30)));
        s.execute("interface.pppoe-server.server.disable", &json!({"id": "pppoe-ether2"})).unwrap();
        assert!(s.store().running().ppp.pppoe_servers[0].disabled);
        s.execute("interface.pppoe-server.server.remove", &json!({"id": "pppoe-ether2"})).unwrap();
        assert!(s.store().running().ppp.pppoe_servers.is_empty());
    }

    #[test]
    fn new_session_rate_auto_and_back() {
        let mut s = Session::virtual_lab();
        s.execute("interface.pppoe-server.server.add", &json!({"interface": "ether2", "new_session_rate": "auto"})).unwrap();
        let row = &s.execute("interface.pppoe-server.server.list", &json!({})).unwrap()[0];
        assert_eq!(row["new_session_rate"], "auto");
        assert!(s.store().running().ppp.pppoe_servers[0].new_session_rate_auto);
        // Other changes keep it.
        s.execute("interface.pppoe-server.server.set", &json!({"id": "pppoe-ether2", "padi_limit": 500})).unwrap();
        assert!(s.store().running().ppp.pppoe_servers[0].new_session_rate_auto);
        // A number turns it off.
        s.execute("interface.pppoe-server.server.set", &json!({"id": "pppoe-ether2", "new_session_rate": 300})).unwrap();
        let v = &s.store().running().ppp.pppoe_servers[0];
        assert_eq!((v.new_session_rate_auto, v.new_session_rate), (false, 300));
        // Anything else is refused.
        let e = s.execute("interface.pppoe-server.server.set", &json!({"id": "pppoe-ether2", "new_session_rate": "fast"})).unwrap_err();
        assert!(e.to_string().contains("new_session_rate"), "{e}");
        // The saved config keeps "auto" out when it is off.
        let j = serde_json::to_value(&s.store().running().ppp.pppoe_servers[0]).unwrap();
        assert!(j.get("new_session_rate_auto").is_none(), "{j}");
    }

    #[test]
    fn bad_values_and_conflicts_are_refused() {
        let mut s = Session::virtual_lab();
        s.execute("interface.pppoe-server.server.add", &json!({"interface": "ether2"})).unwrap();
        for p in [
            json!({"interface": "nope0"}),
            json!({"interface": "ether2", "name": "other"}),
            json!({"interface": "ether2", "name": "other", "service_name": "x"}),
            json!({"interface": "ether3", "max_mtu": 1500}),
            json!({"interface": "ether3", "authentication": ""}),
            json!({"interface": "ether3", "authentication": "eap"}),
            json!({"interface": "ether3", "max_sessions": 70000}),
            json!({"interface": "ether3", "pado_delay": 60000}),
            json!({"interface": "ether3", "pppoe_over_vlan_range": "0-10"}),
            json!({"interface": "ether3", "default_profile": "nope"}),
            json!({"interface": "ether3", "mrru": 100}),
            json!({"interface": "ether3", "pado_delay_by_load": "x"}),
            json!({"interface": "ether3", "name": "pppoe-ether2"}),
        ] {
            let err = s.execute("interface.pppoe-server.server.add", &p).unwrap_err();
            assert!(matches!(err, EngineError::BadParam { .. }), "{p}: {err}");
        }
        assert_eq!(s.store().candidate().ppp.pppoe_servers.len(), 1);
    }

    #[test]
    fn changes_that_drop_sessions_need_force_and_rollback_restores() {
        let mut s = Session::virtual_lab();
        s.execute("interface.pppoe-server.server.add", &json!({"interface": "ether2"})).unwrap();
        let up = |i: u16| ActiveSession { id: format!("*1-{i}"), name: format!("u{i}"), server: "pppoe-ether2".into(), ..ActiveSession::default() };
        s.set_ppp_backend(Arc::new(Fake((1..=3).map(up).collect())));
        let err = s.execute("interface.pppoe-server.server.disable", &json!({"id": "pppoe-ether2"})).unwrap_err();
        assert!(err.to_string().contains("drops 3 active session"), "{err}");
        assert!(s.execute("interface.pppoe-server.server.set", &json!({"id": "pppoe-ether2", "interface": "ether3"})).is_err());
        assert!(s.execute("interface.pppoe-server.server.remove", &json!({"id": "pppoe-ether2"})).is_err());
        // Changes for new sessions only go through.
        s.execute("interface.pppoe-server.server.set", &json!({"id": "pppoe-ether2", "max_mtu": 1400})).unwrap();
        let l = s.execute("interface.pppoe-server.server.list", &json!({})).unwrap();
        assert_eq!(l[0]["sessions"], 3);
        assert_eq!(s.execute("interface.pppoe-server.monitor", &json!({})).unwrap()["sessions"], 3);
        s.execute("config.mode.set", &json!({"mode": "transactional"})).unwrap();
        let r = s.execute("interface.pppoe-server.server.remove", &json!({"id": "pppoe-ether2", "force": true})).unwrap();
        assert_eq!(r["dropped"], 3);
        s.execute("config.discard", &json!({})).unwrap();
        assert_eq!(s.store().candidate().ppp.pppoe_servers.len(), 1);
    }

    /// G4.3l: QinQ, the RFC 4638 cap and sessions per VLAN.
    #[test]
    fn stacked_vlans_payload_and_per_vlan_limit() {
        let mut s = Session::virtual_lab();
        // RFC 4638 §5.1: 1500 needs an MTU of 1508 on the port.
        let e = s
            .execute("interface.pppoe-server.server.add", &json!({"interface": "ether2", "max_payload": 1500}))
            .unwrap_err();
        assert!(e.to_string().contains("MTU - 8"), "{e}");
        s.execute("interface.set", &json!({"name": "ether2", "mtu": 1508})).unwrap();
        let r = s
            .execute("interface.pppoe-server.server.add", &json!({
                "interface": "ether2", "vlan_mode": "stacked", "outer_vlan_range": "100-109,200",
                "max_sessions_per_vlan": 1, "max_payload": 1500, "accept_untagged": false
            }))
            .unwrap();
        assert!(r["warnings"].to_string().contains("1508-byte"), "{r}");
        let row = &s.execute("interface.pppoe-server.server.list", &json!({})).unwrap()[0];
        assert_eq!(row["vlan_mode"], "stacked");
        assert_eq!(row["outer_vlan_range"], "100-109,200");
        assert_eq!(row["inner_vlan_range"], "any");
        assert_eq!(row["outer_tpid"], "0x88a8");
        assert_eq!(row["max_payload"], 1500);
        assert_eq!(row["max_sessions_per_vlan"], 1);
        s.execute("interface.pppoe-server.server.set", &json!({"id": "pppoe-ether2", "inner_vlan_range": "1-2000", "outer_tpid": "0x8100", "max_payload": "none"})).unwrap();
        let v = &s.store().running().ppp.pppoe_servers[0];
        assert_eq!(v.inner_vlan_range.len(), 1);
        assert_eq!((v.outer_tpid, v.max_payload), (Tpid::Dot1q, None));
        let p = s.execute("interface.pppoe-server.server.preview", &json!({"id": "pppoe-ether2"})).unwrap();
        assert!(p.to_string().contains("QinQ: S-tag 100-109,200 (0x8100) × C-tag 1-2000 — 11 sockets"), "{p}");
        // Back to `any`.
        s.execute("interface.pppoe-server.server.set", &json!({"id": "pppoe-ether2", "inner_vlan_range": "any"})).unwrap();
        assert!(s.store().running().ppp.pppoe_servers[0].inner_vlan_range.is_empty());
        for bad in [
            json!({"vlan_mode": "triple"}),
            json!({"outer_vlan_range": ""}),
            json!({"outer_vlan_range": "1-600"}),
            json!({"outer_vlan_range": "100-120,110-130"}),
            json!({"pppoe_over_vlan_range": "300"}),
            json!({"outer_tpid": "0x9100"}),
            json!({"max_payload": 9000}),
            json!({"vlan_mode": "single"}),
        ] {
            let mut p = bad.clone();
            p["id"] = json!("pppoe-ether2");
            let e = s.execute("interface.pppoe-server.server.set", &p).unwrap_err();
            assert!(matches!(e, EngineError::BadParam { .. }), "{bad}: {e}");
        }
        // Back to one tag, emptying the stacked ranges (the BNG lab does).
        s.execute("interface.pppoe-server.server.set", &json!({"id": "pppoe-ether2", "vlan_mode": "single", "outer_vlan_range": "", "inner_vlan_range": "", "max_sessions_per_vlan": 0, "services": [], "force": true})).unwrap();
        let v = &s.store().running().ppp.pppoe_servers[0];
        assert!(v.outer_vlan_range.is_empty() && v.vlan_mode == VlanMode::Single);
                // A single-tag server cannot take the stacked ranges.
        let e = s.execute("interface.pppoe-server.server.add", &json!({"interface": "ether3", "inner_vlan_range": "5"})).unwrap_err();
        assert!(e.to_string().contains("vlan_mode=stacked"), "{e}");
    }
}
