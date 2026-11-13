//! /interface wireguard (G1.31): WireGuard tunnel interfaces. One is an
//! interface of type `wireguard` (`InterfaceKind::Wireguard`), so
//! `interface.remove`, `interface.set` (rename, MTU), `ip.address.add` and
//! the firewall name it like any other. Names and defaults are RouterOS
//! v7.25's (`listen-port=13231`, `mtu=1420`, the private key generated on
//! the router). The peers are in `wireguard_peer.rs`; the push to the data
//! plane in `crate::wireguard`.

use corerouter_model::wireguard::{DEFAULT_LISTEN_PORT, DEFAULT_MTU, PeerState, Wireguard};
use corerouter_model::{Config, IfName, Interface, InterfaceKind};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, opt_text, opt_u32, req_parse};
use super::interface::{new_name, refuse_unmanaged};
use super::{CommandSpec, always};
use crate::sealing::SealKey;
use crate::wireguard as wg;
use crate::{EngineError, Result, Session};

/// `wireguardN` names tried for an interface added without a name.
const MAX_DEFAULT_NAMES: usize = 64;
/// MTU bounds: IPv6 inside the tunnel needs 1280 (RFC 8200 §5); the top is
/// the model's.
const MIN_MTU: u32 = 1280;
const MAX_MTU: u32 = 9216;
/// UDP ports the router's own services may use: a WireGuard port there
/// gets a warning (the bind would fail while the service runs).
const SERVICE_PORTS: &[(u16, &str)] = &[
    (53, "DNS"),
    (67, "the DHCP server"),
    (68, "the DHCP client"),
    (123, "NTP"),
    (500, "IPsec (IKE)"),
    (546, "the DHCPv6 client"),
    (547, "the DHCPv6 server"),
    (1701, "L2TP"),
    (1812, "RADIUS"),
    (1813, "RADIUS accounting"),
    (3799, "RADIUS CoA"),
    (4500, "IPsec (NAT-T)"),
];

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "interface.wireguard.add",
        "Add WireGuard",
        ["Interfaces", "WireGuard"],
        None,
        "{name?: string (default the first free wireguardN, as RouterOS), listen_port?: int 1..65535 (UDP port of the encrypted packets; default 13231, or the first free one above), mtu?: int 1280..9216 (default 1420: 1500 minus the 80 bytes of WireGuard over IPv6), private_key?: string (base64, as wg genkey prints it; default auto: generated on the router and sealed), disabled?: bool, comment?: string} → {name, public_key, warnings}",
        always,
        add
    ),
    cmd!(
        "interface.wireguard.set",
        "Set WireGuard",
        [],
        None,
        "{name: string, listen_port?: int 1..65535, mtu?: int 1280..9216, private_key?: string (base64, or auto: a new key pair; every peer must then get the new public key), disabled?: bool, comment?: string} → {name, public_key, warnings}",
        has_interfaces,
        set
    ),
    cmd!(
        "interface.wireguard.remove",
        "Remove WireGuard",
        [],
        None,
        "{name: string} → {name}",
        has_interfaces,
        remove
    ),
    cmd!(
        "interface.wireguard.enable",
        "Enable WireGuard",
        [],
        None,
        "{name: string} → {name}",
        has_interfaces,
        enable
    ),
    cmd!(
        "interface.wireguard.disable",
        "Disable WireGuard",
        [],
        None,
        "{name: string} → {name}",
        has_interfaces,
        disable
    ),
    cmd!(query "interface.wireguard.list", "WireGuard", ["Interfaces", "WireGuard"], None,
        "{show_sensitive?: bool (the private keys in base64; group full)} → [{name, listen_port, mtu, public_key, private_key, disabled, running, peers, peers_up, error, comment}]",
        always, list),
];

fn has_interfaces(s: &Session) -> std::result::Result<(), String> {
    if wg::interfaces(s.store().candidate()).next().is_none() {
        Err("there are no WireGuard interfaces".into())
    } else {
        Ok(())
    }
}

/// The settings of WireGuard interface `name` of `cfg`.
pub(super) fn wireguard_of<'a>(cfg: &'a Config, key: &str, name: &IfName) -> Result<&'a Wireguard> {
    match cfg.interfaces.get(name).map(|i| &i.kind) {
        Some(InterfaceKind::Wireguard(w)) => Ok(w),
        Some(k) => Err(EngineError::bad(
            key,
            format!("'{name}' is a {}, not a WireGuard interface", k.label()),
        )),
        None => Err(EngineError::bad(
            key,
            format!("no WireGuard interface '{name}' (see interface.wireguard.list)"),
        )),
    }
}

/// Mutable access for a command that already checked `name` with
/// [`wireguard_of`].
pub(super) fn wireguard_mut<'a>(cfg: &'a mut Config, name: &IfName) -> Option<&'a mut Wireguard> {
    match cfg.interfaces.get_mut(name).map(|i| &mut i.kind) {
        Some(InterfaceKind::Wireguard(w)) => Some(w),
        _ => None,
    }
}

fn default_name(cfg: &Config) -> String {
    (1..=MAX_DEFAULT_NAMES)
        .map(|n| format!("wireguard{n}"))
        .find(|n| n.parse::<IfName>().is_ok_and(|n| !cfg.interfaces.contains_key(&n)))
        .unwrap_or_else(|| "wireguard1".to_owned())
}

fn free_port(cfg: &Config) -> u16 {
    (DEFAULT_LISTEN_PORT..=u16::MAX)
        .find(|port| wg::interfaces(cfg).all(|(_, _, w)| w.listen_port != *port))
        .unwrap_or(DEFAULT_LISTEN_PORT)
}

fn port_of(p: &Value) -> Result<Option<u16>> {
    opt_u32(p, "listen_port")?
        .map(|v| {
            u16::try_from(v)
                .ok()
                .filter(|v| *v >= 1)
                .ok_or_else(|| EngineError::bad("listen_port", format!("must be 1..=65535, not {v}")))
        })
        .transpose()
}

fn mtu_of(p: &Value) -> Result<Option<u16>> {
    opt_u32(p, "mtu")?
        .map(|v| {
            if (MIN_MTU..=MAX_MTU).contains(&v) {
                u16::try_from(v).map_err(|_| EngineError::bad("mtu", "1280..=9216"))
            } else {
                Err(EngineError::bad(
                    "mtu",
                    format!("must be {MIN_MTU}..={MAX_MTU} (IPv6 needs 1280), not {v}"),
                ))
            }
        })
        .transpose()
}

/// Refuse a port another WireGuard interface listens on (the kernel would
/// refuse the bind: `EADDRINUSE`, `drivers/net/wireguard/socket.c`);
/// warn about a router service's port.
fn check_port(cfg: &Config, me: &IfName, port: u16, warnings: &mut Vec<String>) -> Result<()> {
    if let Some((other, _, _)) = wg::interfaces(cfg).find(|(n, _, w)| *n != me && w.listen_port == port) {
        return Err(EngineError::bad(
            "listen_port",
            format!("UDP {port} is already the port of WireGuard interface '{other}'"),
        ));
    }
    if let Some((_, svc)) = SERVICE_PORTS.iter().find(|(p, _)| *p == port) {
        warnings.push(format!(
            "UDP {port} is the port of {svc}: the interface cannot listen while that service runs"
        ));
    }
    Ok(())
}

/// The private key asked for: `Some((key, generated))`, or `None` when the
/// parameter is absent.
fn private_of(p: &Value) -> Result<Option<(wg::Key, bool)>> {
    match opt_str(p, "private_key")? {
        None => Ok(None),
        Some(t) if t.trim().is_empty() || t.trim() == "auto" => wg::generate_private()
            .map(|k| Some((k, true)))
            .map_err(EngineError::Internal),
        Some(t) => wg::parse_private(t)
            .map(|k| Some((k, false)))
            .ok_or_else(|| {
                EngineError::bad(
                    "private_key",
                    "must be a WireGuard key: 44 characters of base64 ending in = (wg genkey), or auto",
                )
            }),
    }
}

/// Seal `key` and store it with its public key on `w`.
fn store_key(seal: &SealKey, w: &mut Wireguard, key: &wg::Key) -> Result<()> {
    w.private_key = seal.seal(&wg::encode(key)).map_err(EngineError::Internal)?;
    w.public_key = wg::wg_key(&wg::public_of(key));
    Ok(())
}

/// A peer of the interface itself would be ignored by the kernel in
/// silence (`set_peer`: "we silently ignore peers that have the same public
/// key as the device").
fn check_own_key(w: &Wireguard) -> Result<()> {
    if let Some(p) = w.peers.iter().find(|p| p.public_key == w.public_key) {
        return Err(EngineError::bad(
            "private_key",
            format!(
                "its public key would be the one of peer '{}': the kernel ignores such a peer",
                p.name
            ),
        ));
    }
    Ok(())
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    refuse_unmanaged(s, p, &["name"])?;
    let seal = crate::sealing::key(s).map_err(EngineError::Internal)?;
    add_on(s.store_mut().candidate_mut(), &seal, p)
}

/// `interface.wireguard.add` on `cfg` (the candidate, or a copy for the
/// preview).
pub(super) fn add_on(cfg: &mut Config, seal: &SealKey, p: &Value) -> Result<Value> {
    let comment = opt_text(p, "comment", 256)?.unwrap_or_default();
    let disabled = opt_bool(p, "disabled")?.unwrap_or(false);
    let mut named = p.clone();
    if p.get("name").is_none_or(|v| v.as_str().is_some_and(|t| t.trim().is_empty()))
        && let Some(o) = named.as_object_mut()
    {
        o.insert("name".into(), json!(default_name(cfg)));
    }
    let name = new_name(cfg, &named)?;
    // RouterOS 7.14 refuses a port two interfaces share; without one asked
    // for, the first free from 13231 up.
    let port = match port_of(p)? {
        Some(port) => port,
        None => free_port(cfg),
    };
    let mtu = mtu_of(p)?.unwrap_or(DEFAULT_MTU);
    let mut warnings = Vec::new();
    check_port(cfg, &name, port, &mut warnings)?;
    let (key, _) = match private_of(p)? {
        Some(k) => k,
        None => (wg::generate_private().map_err(EngineError::Internal)?, true),
    };
    let mut w = Wireguard::new(port);
    store_key(seal, &mut w, &key)?;
    let public = w.public_key.to_string();
    warnings.push(format!(
        "next: give {name} an address (ip.address.add) and add its peers \
         (interface.wireguard.peers.add); the peers need this public key"
    ));
    let mut iface = Interface::new(name.clone(), InterfaceKind::Wireguard(Box::new(w)));
    iface.mtu = mtu;
    iface.disabled = disabled;
    iface.comment = comment;
    cfg.interfaces.insert(name.clone(), iface);
    Ok(json!({ "name": name, "public_key": public, "warnings": warnings }))
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let name: IfName = req_parse(p, "name")?;
    wireguard_of(s.store().candidate(), "name", &name)?;
    let seal = crate::sealing::key(s).map_err(EngineError::Internal)?;
    set_on(s.store_mut().candidate_mut(), &seal, p)
}

/// `interface.wireguard.set` on `cfg`.
pub(super) fn set_on(cfg: &mut Config, seal: &SealKey, p: &Value) -> Result<Value> {
    let name: IfName = req_parse(p, "name")?;
    wireguard_of(cfg, "name", &name)?;
    let port = port_of(p)?;
    let mtu = mtu_of(p)?;
    let comment = opt_text(p, "comment", 256)?;
    let disabled = opt_bool(p, "disabled")?;
    let mut warnings = Vec::new();
    if let Some(port) = port {
        check_port(cfg, &name, port, &mut warnings)?;
    }
    let key = private_of(p)?;
    let mut w = wireguard_of(cfg, "name", &name)?.clone();
    if let Some(port) = port {
        w.listen_port = port;
    }
    if let Some((k, _)) = &key {
        let before = w.public_key.clone();
        store_key(seal, &mut w, k)?;
        check_own_key(&w)?;
        if w.public_key != before && !w.peers.is_empty() {
            warnings.push(format!(
                "new key pair: the {} peer(s) of {name} must get the new public key {} \
                 (every tunnel of {name} handshakes again)",
                w.peers.len(),
                w.public_key
            ));
        }
    }
    let public = w.public_key.to_string();
    if let Some(i) = cfg.interfaces.get_mut(&name) {
        i.kind = InterfaceKind::Wireguard(Box::new(w));
        if let Some(m) = mtu {
            i.mtu = m;
        }
        if let Some(c) = comment {
            i.comment = c;
        }
        if let Some(d) = disabled {
            i.disabled = d;
        }
    }
    Ok(json!({ "name": name, "public_key": public, "warnings": warnings }))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let name: IfName = req_parse(p, "name")?;
    wireguard_of(s.store().candidate(), "name", &name)?;
    super::interface::remove(s, &json!({ "name": name }))
}

fn toggle(s: &mut Session, p: &Value, off: bool) -> Result<Value> {
    let name: IfName = req_parse(p, "name")?;
    wireguard_of(s.store().candidate(), "name", &name)?;
    if let Some(i) = s.store_mut().candidate_mut().interfaces.get_mut(&name) {
        i.disabled = off;
    }
    Ok(json!({ "name": name }))
}

fn enable(s: &mut Session, p: &Value) -> Result<Value> {
    toggle(s, p, false)
}

fn disable(s: &mut Session, p: &Value) -> Result<Value> {
    toggle(s, p, true)
}

/// The sealing key when `show_sensitive` asks for the keys in clear (group
/// full only: whoever has a private key can be this router).
pub(super) fn sensitive(s: &mut Session, p: &Value, id: &str) -> Result<Option<std::sync::Arc<crate::sealing::SealKey>>> {
    if !opt_bool(p, "show_sensitive")?.unwrap_or(false) {
        return Ok(None);
    }
    s.permit(crate::auth::Group::Full).map_err(|reason| EngineError::Denied {
        id: id.into(),
        reason: format!("show_sensitive: {reason}"),
    })?;
    Ok(Some(crate::sealing::key(s).map_err(EngineError::Internal)?))
}

/// A sealed value for a listing: in clear with the key, `***` without.
pub(super) fn shown(key: Option<&crate::sealing::SealKey>, v: &corerouter_model::sealed::Sealed) -> Value {
    match key {
        _ if v.is_empty() => Value::from(""),
        Some(k) => Value::from(k.open(v).unwrap_or_default()),
        None => Value::from("***"),
    }
}

fn list(s: &mut Session, p: &Value) -> Result<Value> {
    let key = sensitive(s, p, "interface.wireguard.list")?;
    let cfg = s.store().candidate().clone();
    let now = s.now().unwrap_or(0);
    let mut rows = Vec::new();
    for (name, iface) in cfg.interfaces.iter() {
        let InterfaceKind::Wireguard(w) = &iface.kind else {
            continue;
        };
        let committed = s.store().running().interfaces.contains_key(name);
        let (status, error) = if iface.disabled || !committed {
            (None, None)
        } else {
            s.wireguard_status(name)
        };
        let by_key = wg::status_by_key(status.as_ref());
        let up = w
            .peers
            .iter()
            .filter(|peer| wg::peer_view(peer, iface.disabled, &by_key, now).0 == PeerState::Up)
            .count();
        rows.push(json!({
            "name": name,
            "listen_port": w.listen_port,
            "mtu": iface.mtu,
            "public_key": w.public_key,
            "private_key": shown(key.as_deref(), &w.private_key),
            "disabled": iface.disabled,
            "running": status.is_some(),
            "peers": w.peers.len(),
            "peers_up": up,
            "error": error,
            "comment": iface.comment,
        }));
    }
    Ok(Value::Array(rows))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::Session;

    pub(crate) fn lab() -> Session {
        Session::virtual_lab()
    }

    #[test]
    fn add_generates_a_key_pair_and_seals_the_private_key() {
        let mut s = lab();
        let v = s.execute("interface.wireguard.add", &json!({})).unwrap();
        assert_eq!(v["name"], "wireguard1");
        let public = v["public_key"].as_str().unwrap().to_owned();
        assert_eq!(public.len(), 44);
        let i = s.store().running().interfaces.get(&"wireguard1".parse().unwrap()).unwrap();
        assert_eq!(i.mtu, 1420);
        let text = serde_json::to_string(&i.kind).unwrap();
        assert!(text.contains("\"listen_port\":13231"), "{text}");
        assert!(text.contains("$cr1$"), "private key not sealed: {text}");
        // The list shows the public key, never the private one.
        let l = s.execute("interface.wireguard.list", &json!({})).unwrap();
        assert_eq!(l[0]["public_key"], public);
        assert_eq!(l[0]["private_key"], "***");
        assert_eq!(l[0]["running"], true);
        // Group full reads it back, and it gives the same public key.
        let l = s.execute("interface.wireguard.list", &json!({"show_sensitive": true})).unwrap();
        let private = l[0]["private_key"].as_str().unwrap();
        let k = crate::wireguard::parse_private(private).unwrap();
        assert_eq!(crate::wireguard::encode(&crate::wireguard::public_of(&k)), public);
    }

    #[test]
    fn a_pasted_key_gives_its_public_key() {
        let mut s = lab();
        // RFC 7748 §6.1 Alice, in base64.
        let v = s
            .execute(
                "interface.wireguard.add",
                &json!({"name": "wg0", "private_key": "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=", "listen_port": 51820}),
            )
            .unwrap();
        assert_eq!(v["public_key"], "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=");
    }

    #[test]
    fn validation_refuses_bad_values_and_a_taken_port() {
        let mut s = lab();
        s.execute("interface.wireguard.add", &json!({"name": "wg0"})).unwrap();
        for (p, key) in [
            (json!({"name": "wg1", "listen_port": 13231}), "listen_port"),
            (json!({"name": "wg1", "listen_port": 0}), "listen_port"),
            (json!({"name": "wg1", "listen_port": 70000}), "listen_port"),
            (json!({"name": "wg1", "mtu": 1000}), "mtu"),
            (json!({"name": "wg1", "private_key": "abc"}), "private_key"),
            (json!({"name": "wg0"}), "name"),
        ] {
            let e = s.execute("interface.wireguard.add", &p).unwrap_err().to_string();
            assert!(e.contains(key), "{p} → {e}");
        }
        let v = s.execute("interface.wireguard.add", &json!({"name": "wg1", "listen_port": 53})).unwrap();
        assert!(v["warnings"].to_string().contains("DNS"), "{v}");
        let e = s.execute("interface.wireguard.set", &json!({"name": "ether1", "mtu": 1400})).unwrap_err();
        assert!(e.to_string().contains("not a WireGuard"), "{e}");
    }

    #[test]
    fn set_changes_port_and_key_and_rollback_restores() {
        let mut s = lab();
        let first = s.execute("interface.wireguard.add", &json!({"name": "wg0"})).unwrap()["public_key"].clone();
        let rev = s.store().current_revision();
        let v = s
            .execute("interface.wireguard.set", &json!({"name": "wg0", "listen_port": 13300, "private_key": "auto", "mtu": 1412}))
            .unwrap();
        assert_ne!(v["public_key"], first);
        let l = s.execute("interface.wireguard.list", &json!({})).unwrap();
        assert_eq!(l[0]["listen_port"], 13300);
        assert_eq!(l[0]["mtu"], 1412);
        s.execute("config.rollback", &json!({"revision": rev})).unwrap();
        let l = s.execute("interface.wireguard.list", &json!({})).unwrap();
        assert_eq!(l[0]["listen_port"], 13231);
        assert_eq!(l[0]["public_key"], first);
        // Disable, enable, remove.
        s.execute("interface.wireguard.disable", &json!({"name": "wg0"})).unwrap();
        let l = s.execute("interface.wireguard.list", &json!({})).unwrap();
        assert_eq!(l[0]["running"], false);
        s.execute("interface.wireguard.enable", &json!({"name": "wg0"})).unwrap();
        s.execute("interface.wireguard.remove", &json!({"name": "wg0"})).unwrap();
        assert_eq!(s.execute("interface.wireguard.list", &json!({})).unwrap(), json!([]));
    }
}
