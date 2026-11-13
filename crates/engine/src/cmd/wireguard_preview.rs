//! The previews of the WireGuard window's modals (G1.31a, the list modal
//! of `docs/ui-style.md`): the interface's and the peer's. Each takes the
//! form as typed (texts, `yes`/`no`), runs the real `add`/`set` on a copy of
//! the candidate (same validation, same errors, shown under the field) and
//! adds what the commands do not refuse but the operator should see:
//!
//! - the port: free, or a router service's;
//! - the input firewall: does UDP to the port reach the router from the WAN
//!   side (`ip.firewall.test` from a host on the Internet, in through the
//!   interface of the route there)?
//! - the MTU: the tunnel's against the WAN's minus the WireGuard overhead
//!   (80 bytes over IPv6, whitepaper §5.4.6; 1420 over 1500, 1412 over a
//!   1492 PPPoE);
//! - the peer's prefixes: not another peer's (the kernel would move one in
//!   silence), and a route to its endpoint that goes into the tunnel itself
//!   (a loop);
//! - the commands OK sends.
//!
//! A preview never fails on bad input (it becomes a check) and never
//! changes the candidate (it runs on a copy).

use std::net::{IpAddr, Ipv4Addr};

use corerouter_model::route::table_of;
use corerouter_model::wireguard::{OVERHEAD_V6, WgPeer};
use corerouter_model::{Config, IfName, InterfaceKind};
use ipnet::IpNet;
use serde_json::{Value, json};

use super::mpls::normalize;
use super::wireguard::{add_on, set_on};
use super::wireguard_peer;
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "interface.wireguard.preview", "Check WireGuard", [], None,
        "{id?: string (the interface being edited), name?: string, listen_port?: u16 | string, mtu?: u16 | string, private_key?: string, disabled?: bool | yes | no, comment?: string} → {computed: [{label, value}], checks: [{level, check, message, param}], commands: [{command, params}]} (form texts accepted; never an error: bad input is a check)",
        always, interface_preview),
    cmd!(query "interface.wireguard.peers.preview", "Check WireGuard Peer", [], None,
        "{id?: string (the peer being edited), interface?: string, name?: string, public_key?: string (empty on a new peer: the router makes the key pair), preshared_key?: bool | yes | no (a preshared key: made on the router, kept when editing), allowed_address?: string, endpoint_address?: string, endpoint_port?: u16 | string, persistent_keepalive?: u16 | string, responder?: bool | yes | no, disabled?: bool | yes | no, comment?: string} → {computed: [{label, value}], checks: [{level, check, message, param}], commands: [{command, params}]} (form texts accepted; never an error: bad input is a check)",
        always, peer_preview),
];

/// A host on the Internet: the route to it names the WAN side the peers
/// come in through, and the firewall is tested from it when no peer of the
/// interface has an endpoint.
const INTERNET: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

fn check(level: &str, name: &str, message: impl Into<String>, param: &str) -> Value {
    json!({"level": level, "check": name, "message": message.into(), "param": param})
}

fn computed(label: &str, value: impl Into<String>) -> Value {
    json!({"label": label, "value": value.into()})
}

#[derive(Default)]
struct Preview {
    computed: Vec<Value>,
    checks: Vec<Value>,
    commands: Vec<Value>,
}

impl Preview {
    fn has_error(&self, param: Option<&str>) -> bool {
        self.checks
            .iter()
            .any(|c| c["level"] == "error" && param.is_none_or(|p| c["param"] == p))
    }

    /// The outcome of the real command on the copy: its error under the
    /// field it names, its warnings as warnings (notes as info).
    fn ran(&mut self, r: &Result<Value>) {
        match r {
            Err(EngineError::BadParam { param, reason }) => self.checks.push(check("error", "param", reason.clone(), param)),
            Err(e) => self.checks.push(check("error", "param", e.to_string(), "")),
            Ok(v) => {
                for w in v.get("warnings").and_then(Value::as_array).into_iter().flatten() {
                    let text = w.as_str().unwrap_or_default();
                    let level = if text.starts_with("next:") || text.contains(" is taken as ") { "info" } else { "warning" };
                    self.checks.push(check(level, "command", text, ""));
                }
            }
        }
    }

    fn done(self) -> Value {
        let ok = !self.has_error(None);
        json!({
            "computed": self.computed,
            "checks": self.checks,
            "commands": if ok { self.commands } else { Vec::new() },
        })
    }
}

fn text<'a>(p: &'a Value, k: &str) -> Option<&'a str> {
    p.get(k).and_then(Value::as_str).map(str::trim).filter(|t| !t.is_empty())
}

/// The interface and gateway side of the route to `dst` in `cfg`'s main
/// table, with the router's address there.
fn wan_of(cfg: &Config, dst: IpAddr) -> Option<(IfName, Option<IpAddr>)> {
    let out = crate::lockout::route_out(cfg, dst, &corerouter_model::RoutingTable::Main)?;
    let link: IfName = out.parse().ok()?;
    let mine = cfg
        .ip
        .addresses
        .iter()
        .find(|a| !a.disabled && a.interface == link && a.address.addr().is_ipv4() == dst.is_ipv4())
        .map(|a| a.address.addr());
    Some((link, mine))
}

/// Does UDP to `port` reach the router from the WAN? Tested as a packet
/// from `from` (a peer's endpoint, or a host on the Internet).
fn firewall_check(s: &mut Session, cfg: &Config, me: Option<&IfName>, port: u16, from: IpAddr, out: &mut Preview) {
    let Some((wan, Some(dst))) = wan_of(cfg, from) else {
        out.checks.push(check(
            "info",
            "firewall",
            format!("no route to {from} with an address on its interface: the input firewall cannot be checked for UDP {port}"),
            "listen_port",
        ));
        return;
    };
    if me.is_some_and(|m| *m == wan) {
        return;
    }
    let packet = json!({"src": from, "dst": dst, "protocol": "udp", "dst_port": port, "in_interface": wan});
    let Ok(v) = super::firewall_diag::test(s, &packet) else {
        return;
    };
    let fate = v.get("fate").and_then(Value::as_str).unwrap_or("");
    let by = v
        .pointer("/decided_by/summary")
        .and_then(Value::as_str)
        .map(|r| format!(" (rule: {r})"))
        .unwrap_or_default();
    if fate == "delivered" {
        out.checks.push(check(
            "ok",
            "firewall",
            format!("the input firewall lets UDP {port} in from {wan}{by}"),
            "listen_port",
        ));
    } else {
        out.checks.push(check(
            "warning",
            "firewall",
            format!(
                "the input firewall drops UDP {port} coming in on {wan}{by}: peers cannot reach \
                 this interface; accept it before the drop (IP › Firewall)"
            ),
            "listen_port",
        ));
    }
}

/// The tunnel's MTU against the WAN's minus the WireGuard overhead.
fn mtu_check(cfg: &Config, mtu: u16, toward: IpAddr, out: &mut Preview) {
    let Some((wan, _)) = wan_of(cfg, toward) else {
        return;
    };
    let Some(under) = cfg.interfaces.get(&wan).map(|i| i.mtu) else {
        return;
    };
    let fits = under.saturating_sub(OVERHEAD_V6);
    if mtu <= fits {
        out.checks.push(check(
            "ok",
            "mtu",
            format!("MTU {mtu} fits {under} on {wan} minus the {OVERHEAD_V6} bytes of WireGuard"),
            "mtu",
        ));
    } else {
        out.checks.push(check(
            "warning",
            "mtu",
            format!(
                "MTU {mtu} is more than {under} on {wan} minus the {OVERHEAD_V6} bytes of WireGuard: \
                 full-size packets get fragmented or lost (TCP stalls); use {fits}"
            ),
            "mtu",
        ));
    }
}

fn wireguard_on<'a>(cfg: &'a Config, name: &IfName) -> Option<&'a corerouter_model::wireguard::Wireguard> {
    match cfg.interfaces.get(name).map(|i| &i.kind) {
        Some(InterfaceKind::Wireguard(w)) => Some(w),
        _ => None,
    }
}

fn interface_preview(s: &mut Session, raw: &Value) -> Result<Value> {
    let mut p = normalize(raw, &["listen_port", "mtu"], &[]);
    let mut out = Preview::default();
    let editing = text(raw, "id").map(str::to_owned);
    let generated = text(&p, "private_key").is_none_or(|k| k == "auto");
    let command = if let Some(id) = &editing {
        if let Some(o) = p.as_object_mut() {
            o.remove("id");
            o.insert("name".into(), json!(id));
        }
        "interface.wireguard.set"
    } else {
        "interface.wireguard.add"
    };
    let seal = match crate::sealing::key(s) {
        Ok(k) => k,
        Err(e) => {
            out.checks.push(check("error", "key", e, "private_key"));
            return Ok(out.done());
        }
    };
    let mut cfg = s.store().candidate().clone();
    let r = if editing.is_some() { set_on(&mut cfg, &seal, &p) } else { add_on(&mut cfg, &seal, &p) };
    out.ran(&r);
    let Ok(v) = r else {
        return Ok(out.done());
    };
    let name: Option<IfName> = v.get("name").and_then(Value::as_str).and_then(|n| n.parse().ok());
    let Some((name, w, iface)) = name.and_then(|n| {
        let i = cfg.interfaces.get(&n)?;
        Some((n.clone(), wireguard_on(&cfg, &n)?.clone(), i.clone()))
    }) else {
        return Ok(out.done());
    };
    // The public key: the one the router keeps, or the pasted key's; a key
    // generated now is thrown away with the copy, so it is not shown.
    let public = if editing.is_some() && generated {
        wireguard_on(s.store().candidate(), &name).map(|w| w.public_key.to_string())
    } else if !generated {
        Some(w.public_key.to_string())
    } else {
        None
    };
    out.computed.push(computed(
        "Public key",
        public.unwrap_or_else(|| "generated on the router when applied".to_owned()),
    ));
    if p.get("listen_port").is_none() && editing.is_none() {
        out.computed.push(computed("Listen port", format!("{} (the first free from 13231)", w.listen_port)));
    }
    if !out.has_error(Some("listen_port")) {
        out.checks.push(check(
            "ok",
            "port",
            format!("UDP {} is no other WireGuard interface's", w.listen_port),
            "listen_port",
        ));
    }
    // The firewall and the MTU from where the peers are (their endpoints),
    // else from the Internet.
    let from = w
        .peers
        .iter()
        .filter_map(|p| p.endpoint_address)
        .find(|a| !a.is_loopback() && !a.is_unspecified())
        .unwrap_or(INTERNET);
    firewall_check(s, &cfg, Some(&name), w.listen_port, from, &mut out);
    mtu_check(&cfg, iface.mtu, from, &mut out);
    if !cfg.ip.addresses.iter().any(|a| a.interface == name) {
        out.checks.push(check(
            "info",
            "address",
            format!("no address on {name} yet: add one in IP › Addresses (10.9.0.1/24)"),
            "",
        ));
    }
    out.commands.push(json!({"command": command, "params": p}));
    Ok(out.done())
}

/// The first host of the interface's IPv4 networks that neither the router
/// nor a peer holds: what to give a new peer.
fn next_free(cfg: &Config, iface: &IfName, peers: &[WgPeer]) -> Option<(IpNet, IpNet)> {
    const MAX_TRIED: u32 = 4096;
    for a in cfg.ip.addresses.iter().filter(|a| a.interface == *iface && !a.disabled) {
        let IpNet::V4(net) = a.address.trunc() else {
            continue;
        };
        let base = u32::from(net.network());
        let size = net.hosts().count().min(MAX_TRIED as usize);
        let size = u32::try_from(size).unwrap_or(MAX_TRIED);
        for i in 1..=size {
            let ip = IpAddr::V4(Ipv4Addr::from(base.saturating_add(i)));
            let taken = ip == a.address.addr()
                || cfg.ip.addresses.iter().any(|x| x.address.addr() == ip)
                || peers.iter().any(|p| p.allowed_address.iter().any(|n| n.contains(&ip)));
            if !taken {
                return Some((IpNet::from(ip), IpNet::V4(net)));
            }
        }
    }
    None
}

fn peer_preview(s: &mut Session, raw: &Value) -> Result<Value> {
    let mut p = normalize(raw, &["endpoint_port", "persistent_keepalive"], &[]);
    let mut out = Preview::default();
    let editing = text(raw, "id").map(str::to_owned);
    let cand = s.store().candidate();
    let before: Option<(IfName, WgPeer)> = editing.as_deref().and_then(|id| {
        crate::wireguard::peers(cand).find(|(_, x)| x.name == id).map(|(i, x)| (i.clone(), x.clone()))
    });
    if let (Some(id), None) = (&editing, &before) {
        out.checks.push(check("error", "id", format!("no WireGuard peer '{}'", id.chars().take(64).collect::<String>()), "name"));
        return Ok(out.done());
    }
    let Some(o) = p.as_object_mut() else {
        return Ok(out.done());
    };
    // The form's psk checkbox: make one, keep it, or clear it.
    let had_psk = before.as_ref().is_some_and(|(_, x)| !x.preshared_key.is_empty());
    match (o.remove("preshared_key").and_then(|v| v.as_bool()), had_psk) {
        (Some(true), false) => {
            o.insert("preshared_key".into(), json!("auto"));
        }
        (Some(false), true) => {
            o.insert("preshared_key".into(), json!("none"));
        }
        _ => {}
    }
    let mut generated = false;
    let command = if let Some((_, old)) = &before {
        o.remove("id");
        o.remove("interface");
        o.insert("name".into(), json!(old.name));
        if let Some(n) = raw.get("name").and_then(Value::as_str).map(str::trim).filter(|n| !n.is_empty() && *n != old.name) {
            o.insert("new_name".into(), json!(n));
        }
        // The key shown unchanged (or emptied) keeps the peer's pair: sent,
        // it would forget a key the router made for the client.
        let same = o.get("public_key").and_then(Value::as_str).map(str::trim);
        if same.is_none_or(|k| k.is_empty() || k == old.public_key.as_str()) {
            o.remove("public_key");
        }
        "interface.wireguard.peers.set"
    } else {
        if o.get("public_key").and_then(Value::as_str).is_none_or(|k| k.trim().is_empty()) {
            o.remove("public_key");
            o.insert("private_key".into(), json!("auto"));
            generated = true;
        }
        "interface.wireguard.peers.add"
    };
    let seal = match wireguard_peer::seal_for(s, &p) {
        Ok(k) => k,
        Err(e) => {
            out.checks.push(check("error", "key", e.to_string(), "public_key"));
            return Ok(out.done());
        }
    };
    let mut cfg = s.store().candidate().clone();
    let r = if before.is_some() {
        wireguard_peer::set_on(&mut cfg, seal.as_deref(), &p)
    } else {
        wireguard_peer::add_on(&mut cfg, seal.as_deref(), &p)
    };
    let iface: Option<IfName> = before
        .as_ref()
        .map(|(i, _)| i.clone())
        .or_else(|| text(raw, "interface").and_then(|n| n.parse().ok()));
    // Before the command's checks: what to type into the empty field.
    if let Some(i) = &iface
        && let Some(w) = wireguard_on(s.store().candidate(), i)
    {
        out.computed.push(computed(&format!("Public key of {i}"), w.public_key.to_string()));
        if text(raw, "allowed_address").is_none()
            && let Some((ip, net)) = next_free(s.store().candidate(), i, &w.peers)
        {
            out.computed.push(computed("Next free address", format!("{ip} (in {net})")));
        }
    }
    if generated {
        out.computed.push(computed(
            "Keys",
            "the router makes the peer's key pair and seals it, for the client's configuration",
        ));
    }
    // A new form without prefixes yet: say what to type, not an error.
    if before.is_none()
        && text(raw, "allowed_address").is_none()
        && matches!(&r, Err(EngineError::BadParam { param, .. }) if param == "allowed_address")
    {
        out.checks.push(check(
            "info",
            "allowed",
            "type the prefixes this peer may use: 10.9.0.2/32 for a notebook, the networks behind a site",
            "allowed_address",
        ));
        return Ok(out.done());
    }
    out.ran(&r);
    let Ok(v) = r else {
        return Ok(out.done());
    };
    let name = v.get("name").and_then(Value::as_str).unwrap_or_default();
    let found = iface.as_ref().and_then(|i| wireguard_on(&cfg, i).and_then(|w| w.peer(name)).map(|x| (i.clone(), x.clone())));
    if let Some((iface, peer)) = found {
        if !out.has_error(Some("allowed_address")) {
            let nets: Vec<String> = peer.allowed_address.iter().map(ToString::to_string).collect();
            out.checks.push(check(
                "ok",
                "allowed",
                format!("{} not used by another peer of {iface}", nets.join(", ")),
                "allowed_address",
            ));
        }
        if let Some(e) = peer.endpoint_address {
            let table = table_of(&cfg, &iface);
            if crate::lockout::route_out(&cfg, e, &table).as_deref() == Some(iface.as_str()) {
                out.checks.push(check(
                    "warning",
                    "loop",
                    format!(
                        "the route to the endpoint {e} goes into {iface} itself: the handshake would \
                         be sent through the tunnel it builds; add a route to {e}/32 through the WAN \
                         gateway"
                    ),
                    "endpoint_address",
                ));
            }
            if peer.persistent_keepalive == 0 && !peer.responder {
                out.checks.push(check(
                    "info",
                    "keepalive",
                    "behind a NAT, a persistent keepalive of 25 s keeps the way back open",
                    "persistent_keepalive",
                ));
            }
        }
    }
    out.commands.push(json!({"command": command, "params": p}));
    Ok(out.done())
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use crate::Session;

    const K1: &str = "YAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";

    fn lab() -> Session {
        let mut s = Session::virtual_lab();
        s.execute("ip.address.add", &json!({"address": "203.0.113.2/24", "interface": "ether1"})).unwrap();
        s.execute("ip.route.add", &json!({"dst_address": "0.0.0.0/0", "gateway": "203.0.113.1"})).unwrap();
        s.execute("interface.wireguard.add", &json!({"name": "wg0"})).unwrap();
        s.execute("ip.address.add", &json!({"address": "10.9.0.1/24", "interface": "wg0"})).unwrap();
        s
    }

    fn checks(v: &Value, level: &str) -> Vec<String> {
        v["checks"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|c| c["level"] == level)
            .map(|c| format!("{}: {}", c["param"].as_str().unwrap(), c["message"].as_str().unwrap()))
            .collect()
    }

    #[test]
    fn interface_preview_checks_port_firewall_and_mtu() {
        let mut s = lab();
        let before = s.store().candidate().clone();
        let v = s.execute("interface.wireguard.preview", &json!({"name": "wg1", "mtu": "1420"})).unwrap();
        assert_eq!(&before, s.store().candidate(), "the preview runs on a copy");
        let ok = checks(&v, "ok").join("\n");
        assert!(ok.contains("UDP 13232 is no other"), "{ok}");
        assert!(ok.contains("lets UDP 13232 in from ether1"), "{ok}");
        assert!(ok.contains("MTU 1420 fits 1500 on ether1"), "{ok}");
        assert_eq!(v["commands"][0]["command"], "interface.wireguard.add");
        assert!(v["computed"].to_string().contains("generated on the router"), "{v}");
        // A taken port: the command's own error, under the field.
        let v = s.execute("interface.wireguard.preview", &json!({"name": "wg1", "listen_port": "13231"})).unwrap();
        assert_eq!(checks(&v, "error").len(), 1, "{v}");
        assert!(checks(&v, "error")[0].starts_with("listen_port:"), "{v}");
        assert_eq!(v["commands"], json!([]));
        // Over a PPPoE-sized WAN the MTU warns; the firewall drop is seen.
        s.execute("interface.set", &json!({"name": "ether1", "mtu": 1492})).unwrap();
        s.execute("ip.firewall.filter.add", &json!({"chain": "input", "action": "drop", "in_interface": "ether1"})).unwrap();
        let v = s.execute("interface.wireguard.preview", &json!({"id": "wg0", "mtu": "1420"})).unwrap();
        let warn = checks(&v, "warning").join("\n");
        assert!(warn.contains("use 1412"), "{warn}");
        assert!(warn.contains("drops UDP 13231 coming in on ether1"), "{warn}");
        assert_eq!(v["commands"][0]["command"], "interface.wireguard.set");
        assert_eq!(v["commands"][0]["params"]["name"], "wg0");
        let own = s.execute("interface.wireguard.list", &json!({})).unwrap()[0]["public_key"].clone();
        assert!(v["computed"].to_string().contains(own.as_str().unwrap()), "{v}");
    }

    #[test]
    fn peer_preview_suggests_an_address_and_refuses_a_taken_prefix() {
        let mut s = lab();
        let v = s.execute("interface.wireguard.peers.preview", &json!({"interface": "wg0", "name": "notebook"})).unwrap();
        assert!(v["computed"].to_string().contains("10.9.0.2/32 (in 10.9.0.0/24)"), "{v}");
        // A new form without prefixes: what to type, no error yet.
        assert_eq!(checks(&v, "error"), Vec::<String>::new(), "{v}");
        assert!(checks(&v, "info").join("").contains("allowed_address: type the prefixes"), "{v}");
        assert_eq!(v["commands"], json!([]));
        // A new peer without a key: the router makes the pair; a psk too.
        let v = s
            .execute("interface.wireguard.peers.preview", &json!({"interface": "wg0", "name": "notebook", "allowed_address": "10.9.0.2/32", "preshared_key": true}))
            .unwrap();
        assert_eq!(checks(&v, "error"), Vec::<String>::new(), "{v}");
        let p = &v["commands"][0]["params"];
        assert_eq!(p["private_key"], "auto");
        assert_eq!(p["preshared_key"], "auto");
        s.execute("interface.wireguard.peers.add", p).unwrap();
        // Another peer may not take the same prefix.
        let v = s
            .execute("interface.wireguard.peers.preview", &json!({"interface": "wg0", "public_key": K1, "allowed_address": "10.9.0.2/32"}))
            .unwrap();
        assert!(checks(&v, "error").join("").contains("peer 'notebook'"), "{v}");
        let v = s.execute("interface.wireguard.peers.preview", &json!({"interface": "wg0"})).unwrap();
        assert!(v["computed"].to_string().contains("10.9.0.3/32"), "next free skips notebook's: {v}");
    }

    #[test]
    fn peer_edit_keeps_the_keys_and_warns_about_a_loop() {
        let mut s = lab();
        s.execute("interface.wireguard.peers.add", &json!({"interface": "wg0", "name": "site", "private_key": "auto", "preshared_key": "auto", "allowed_address": "10.20.0.0/16"})).unwrap();
        let public = s.execute("interface.wireguard.peers.list", &json!({})).unwrap()[0]["public_key"].clone();
        // The form as opened: the key shown, the psk box on.
        let form = json!({"id": "site", "name": "site", "public_key": public, "preshared_key": true,
                          "allowed_address": "10.20.0.0/16, 0.0.0.0/0", "endpoint_address": "198.51.100.7",
                          "endpoint_port": "13231", "persistent_keepalive": "", "comment": ""});
        let v = s.execute("interface.wireguard.peers.preview", &form).unwrap();
        let p = &v["commands"][0]["params"];
        assert_eq!(v["commands"][0]["command"], "interface.wireguard.peers.set");
        assert!(p.get("public_key").is_none() && p.get("private_key").is_none() && p.get("preshared_key").is_none(), "{p}");
        assert!(p.get("new_name").is_none(), "{p}");
        // 0.0.0.0/0 on the peer + the endpoint inside it: the engine's
        // warning, and the route loop once a default goes into wg0.
        assert!(checks(&v, "warning").join("\n").contains("inside its own allowed address"), "{v}");
        assert!(checks(&v, "info").join("\n").contains("keepalive"), "{v}");
        s.execute("ip.route.remove", &json!({"dst_address": "0.0.0.0/0"})).ok();
        s.execute("ip.route.add", &json!({"dst_address": "198.51.100.0/24", "gateway": "wg0"})).unwrap();
        let v = s.execute("interface.wireguard.peers.preview", &form).unwrap();
        assert!(checks(&v, "warning").join("\n").contains("goes into wg0 itself"), "{v}");
        // Unticking the psk clears it; a new name renames.
        let mut f = form.clone();
        f["preshared_key"] = json!(false);
        f["name"] = json!("site2");
        let v = s.execute("interface.wireguard.peers.preview", &f).unwrap();
        assert_eq!(v["commands"][0]["params"]["preshared_key"], "none");
        assert_eq!(v["commands"][0]["params"]["new_name"], "site2");
        let v = s.execute("interface.wireguard.peers.preview", &json!({"id": "nope"})).unwrap();
        assert!(checks(&v, "error").join("").contains("no WireGuard peer"), "{v}");
    }
}
