//! /interface wireguard peers (G1.31): the peers of a WireGuard interface.
//! A peer is named (RouterOS 7.15+: `peer1`, `peer2`… when not given) and
//! the name is unique on the router, so `set`/`remove` take it alone.
//!
//! The checks are stricter than RouterOS's warnings, because the kernel
//! hides the mistakes:
//! - the same prefix in two peers of one interface is refused: the kernel
//!   moves it to the last one in silence (`drivers/net/wireguard/
//!   allowedips.c`, `add()`), so the first peer stops receiving it;
//! - a peer with the interface's own public key is refused: the kernel
//!   ignores it in silence (`netlink.c`, `set_peer`);
//! - one public key twice on one interface is refused (the kernel would
//!   merge them into one peer).
//!
//! `allowed_address` adds no route, as in RouterOS: routes to a peer's
//! networks go in `/ip route` (G1.31 PR 3 offers to create them).

use std::collections::BTreeSet;
use std::net::IpAddr;

use corerouter_model::wireguard::{ClientConfig, WgHost};

use corerouter_model::wireguard::{MAX_ALLOWED, MAX_NAME, MAX_PEERS, PeerState, WgKey, WgPeer, Wireguard};
use corerouter_model::{Config, IfName, InterfaceKind};
use ipnet::IpNet;
use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, opt_text, opt_u32, req_parse, req_str};
use super::wireguard::{sensitive, shown, wireguard_mut, wireguard_of};
use super::{CommandSpec, always};
use crate::sealing::SealKey;
use crate::wireguard as wg;
use crate::{EngineError, Result, Session};

/// `peerN` names tried for a peer added without a name.
const MAX_DEFAULT_NAMES: usize = 100_000;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "interface.wireguard.peers.add",
        "Add WireGuard Peer",
        ["Interfaces", "WireGuard"],
        None,
        "{interface: string, name?: string (unique on the router; default the first free peerN), public_key?: string (the peer's key, base64; or leave it out and use private_key), private_key?: string (auto: the router makes the peer's key pair, to hand it the client config; or the peer's private key in base64), preshared_key?: string (auto | a key in base64 | none; an extra symmetric key, whitepaper §5.2), endpoint_address?: string (IP address or DNS name the first handshake goes to; a name is resolved by the router and again when the handshake is older than 180 s; empty = wait for the peer), endpoint_port?: int 1..65535, allowed_address: [string] | string (prefixes the peer may send from and that are sent to it, \"10.9.0.2/32,fd00::2/128\"; no route is added), persistent_keepalive?: int 0..65535 | off (seconds; 25 behind NAT), responder?: bool (never start a handshake), disabled?: bool, comment?: string, client_address?: [string] | string (client config: its own address; default the allowed address), client_dns?: [ip] | string (client config: DNS servers), client_endpoint?: string (client config: where the client finds this router, name or address[:port]; default the router's WAN address and the interface's port), client_allowed_address?: [string] | string (client config: what it sends into the tunnel; default 0.0.0.0/0, ::/0), client_keepalive?: int 0..65535 (client config), client_mtu?: int 0 | 1280..9216 (client config; 0 = its default), force?: bool (apply even if it cuts this session, which comes through this tunnel)} → {name, public_key, warnings}",
        always,
        add
    ),
    cmd!(
        "interface.wireguard.peers.set",
        "Set WireGuard Peer",
        [],
        None,
        "{name: string, new_name?: string, public_key?: string (the peer's key, base64; or leave it out and use private_key), private_key?: string (auto: the router makes the peer's key pair, to hand it the client config; or the peer's private key in base64), preshared_key?: string (auto | a key in base64 | none; an extra symmetric key, whitepaper §5.2), endpoint_address?: string (IP address or DNS name the first handshake goes to; a name is resolved by the router and again when the handshake is older than 180 s; empty = wait for the peer), endpoint_port?: int 1..65535, allowed_address?: [string] | string (prefixes the peer may send from and that are sent to it, \"10.9.0.2/32,fd00::2/128\"; no route is added), persistent_keepalive?: int 0..65535 | off (seconds; 25 behind NAT), responder?: bool (never start a handshake), disabled?: bool, comment?: string, client_address?: [string] | string (client config: its own address; default the allowed address), client_dns?: [ip] | string (client config: DNS servers), client_endpoint?: string (client config: where the client finds this router, name or address[:port]; default the router's WAN address and the interface's port), client_allowed_address?: [string] | string (client config: what it sends into the tunnel; default 0.0.0.0/0, ::/0), client_keepalive?: int 0..65535 (client config), client_mtu?: int 0 | 1280..9216 (client config; 0 = its default), force?: bool (apply even if it cuts this session, which comes through this tunnel)} → {name, public_key, warnings}",
        has_peers,
        set
    ),
    cmd!(
        "interface.wireguard.peers.remove",
        "Remove WireGuard Peer",
        [],
        None,
        "{name: string, force?: bool (apply even if it cuts this session, which comes through this peer)} → {name}",
        has_peers,
        remove
    ),
    cmd!(
        "interface.wireguard.peers.enable",
        "Enable WireGuard Peer",
        [],
        None,
        "{name: string, force?: bool (apply even if it cuts this session, which comes through this peer)} → {name}",
        has_peers,
        enable
    ),
    cmd!(
        "interface.wireguard.peers.disable",
        "Disable WireGuard Peer",
        [],
        None,
        "{name: string, force?: bool (apply even if it cuts this session, which comes through this peer)} → {name}",
        has_peers,
        disable
    ),
    cmd!(query "interface.wireguard.peers.list", "WireGuard Peers", ["Interfaces", "WireGuard"], None,
        "{interface?: string (only its peers), show_sensitive?: bool (private and preshared keys in clear; group full)} → [{name, interface, public_key, private_key, preshared_key, endpoint_address, endpoint_port, endpoint_resolved (the address a DNS name gave, null for an address), resolved_secs (seconds since it was resolved), resolve_error, current_endpoint_address, current_endpoint_port, roamed, allowed_address, persistent_keepalive, responder, disabled, comment, client_address, client_dns, client_endpoint, client_allowed_address, client_keepalive, client_mtu, state (up | idle | no-handshake | never | disabled), last_handshake_secs, rx, tx, hint}]",
        always, list),
];

fn has_peers(s: &Session) -> std::result::Result<(), String> {
    if wg::peers(s.store().candidate()).next().is_none() {
        Err("there are no WireGuard peers".into())
    } else {
        Ok(())
    }
}

/// The interface and index of peer `name`.
fn find(cfg: &Config, name: &str) -> Result<(IfName, usize)> {
    wg::interfaces(cfg)
        .find_map(|(n, _, w)| w.peers.iter().position(|p| p.name == name).map(|i| (n.clone(), i)))
        .ok_or_else(|| {
            EngineError::bad(
                "name",
                format!(
                    "no WireGuard peer '{}' (see interface.wireguard.peers.list)",
                    name.chars().take(MAX_NAME).collect::<String>()
                ),
            )
        })
}

fn name_of(p: &Value, key: &str) -> Result<Option<String>> {
    let Some(n) = opt_text(p, key, MAX_NAME)? else {
        return Ok(None);
    };
    let n = n.trim().to_owned();
    if n.is_empty() {
        return Err(EngineError::bad(key, "must not be empty"));
    }
    Ok(Some(n))
}

fn default_name(cfg: &Config) -> String {
    let taken: BTreeSet<&str> = wg::peers(cfg).map(|(_, p)| p.name.as_str()).collect();
    (1..=MAX_DEFAULT_NAMES)
        .map(|n| format!("peer{n}"))
        .find(|n| !taken.contains(n.as_str()))
        .unwrap_or_else(|| "peer".to_owned())
}

fn key_param(p: &Value, key: &str) -> Result<Option<String>> {
    opt_str(p, key).map(|v| v.map(|t| t.trim().to_owned()))
}

/// The prefixes asked for: a JSON list or `"a,b"`, normalized to their
/// network (`10.20.1.0/16` → `10.20.0.0/16`, as the kernel stores it),
/// duplicates dropped. Returns the list and the notes about normalized
/// entries.
fn allowed_of(p: &Value) -> Result<Option<(Vec<IpNet>, Vec<String>)>> {
    let raw: Vec<String> = match p.get("allowed_address") {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) => s.split(',').map(|x| x.trim().to_owned()).filter(|x| !x.is_empty()).collect(),
        Some(Value::Array(a)) => a
            .iter()
            .take(MAX_ALLOWED.saturating_add(1))
            .map(|v| {
                v.as_str()
                    .map(|t| t.trim().to_owned())
                    .ok_or_else(|| EngineError::bad("allowed_address", "must be a list of prefixes"))
            })
            .collect::<Result<_>>()?,
        Some(_) => return Err(EngineError::bad("allowed_address", "must be a list of prefixes or \"a,b\"")),
    };
    if raw.len() > MAX_ALLOWED {
        return Err(EngineError::bad("allowed_address", format!("at most {MAX_ALLOWED} prefixes")));
    }
    let mut out: Vec<IpNet> = Vec::new();
    let mut notes = Vec::new();
    for r in &raw {
        // A bare address is a host prefix (RouterOS takes `10.9.0.2`).
        let net = r
            .parse::<IpNet>()
            .or_else(|_| r.parse::<IpAddr>().map(IpNet::from))
            .map_err(|_| {
                EngineError::bad(
                    "allowed_address",
                    format!("'{}' is not a prefix (10.9.0.2/32, 10.20.0.0/16, fd00::/64)", r.chars().take(48).collect::<String>()),
                )
            })?;
        let t = net.trunc();
        if t != net {
            notes.push(format!("{net} is taken as {t} (the network of that prefix)"));
        }
        if !out.contains(&t) {
            out.push(t);
        }
    }
    Ok(Some((out, notes)))
}

fn keepalive_of(p: &Value) -> Result<Option<u16>> {
    match p.get("persistent_keepalive") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) if matches!(s.trim(), "off" | "disabled" | "") => Ok(Some(0)),
        Some(v) => v
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .map(Some)
            .ok_or_else(|| EngineError::bad("persistent_keepalive", "seconds 0..=65535, or off")),
    }
}

fn endpoint_address_of(p: &Value) -> Result<Option<Option<WgHost>>> {
    match opt_str(p, "endpoint_address")?.map(str::trim) {
        None => Ok(None),
        Some("") => Ok(Some(None)),
        Some(t) => WgHost::parse(t).map(|h| Some(Some(h))).ok_or_else(|| {
            EngineError::bad(
                "endpoint_address",
                format!(
                    "'{}' is neither an IP address nor a DNS name (vpn.example.com)",
                    t.chars().take(64).collect::<String>()
                ),
            )
        }),
    }
}

/// A list of prefixes (`[..]` or `"a,b"`), bare addresses as host
/// prefixes; `None`: absent.
fn nets_of(p: &Value, key: &str) -> Result<Option<Vec<IpNet>>> {
    let raw: Vec<String> = match p.get(key) {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) => s.split(',').map(|x| x.trim().to_owned()).filter(|x| !x.is_empty()).collect(),
        Some(Value::Array(a)) => a.iter().take(MAX_ALLOWED.saturating_add(1)).filter_map(|v| v.as_str().map(|t| t.trim().to_owned())).collect(),
        Some(_) => return Err(EngineError::bad(key, "must be a list of prefixes or \"a,b\"")),
    };
    if raw.len() > MAX_ALLOWED {
        return Err(EngineError::bad(key, format!("at most {MAX_ALLOWED} prefixes")));
    }
    raw.iter()
        .map(|r| {
            r.parse::<IpNet>()
                .or_else(|_| r.parse::<IpAddr>().map(IpNet::from))
                .map_err(|_| EngineError::bad(key, format!("'{}' is not a prefix", r.chars().take(48).collect::<String>())))
        })
        .collect::<Result<Vec<_>>>()
        .map(Some)
}

/// The `client_*` parameters onto `c`.
fn client_of(c: &mut ClientConfig, p: &Value) -> Result<()> {
    if let Some(v) = nets_of(p, "client_address")? {
        c.address = v;
    }
    if let Some(v) = nets_of(p, "client_allowed_address")? {
        c.allowed_address = v;
    }
    if let Some(v) = nets_of(p, "client_dns")? {
        const MAX_DNS: usize = 8;
        if v.len() > MAX_DNS || v.iter().any(|n| n.prefix_len() != n.max_prefix_len()) {
            return Err(EngineError::bad("client_dns", format!("at most {MAX_DNS} addresses (10.9.0.1, 2001:db8::53)")));
        }
        c.dns = v.iter().map(IpNet::addr).collect();
    }
    if let Some(t) = opt_text(p, "client_endpoint", 260)? {
        let t = t.trim();
        if !t.is_empty() && corerouter_model::wireguard_conf::parse_endpoint(t).is_none() && WgHost::parse(t).is_none() {
            return Err(EngineError::bad("client_endpoint", "a name or an address, with :port or not (vpn.example.com:13231)"));
        }
        c.endpoint = t.to_owned();
    }
    if let Some(k) = opt_u32(p, "client_keepalive")? {
        c.keepalive = u16::try_from(k).map_err(|_| EngineError::bad("client_keepalive", "seconds 0..=65535"))?;
    }
    if let Some(m) = opt_u32(p, "client_mtu")? {
        if m != 0 && !(1280..=9216).contains(&m) {
            return Err(EngineError::bad("client_mtu", "0 (the client's default) or 1280..=9216"));
        }
        c.mtu = u16::try_from(m).unwrap_or(0);
    }
    Ok(())
}

fn port_of(p: &Value) -> Result<Option<u16>> {
    opt_u32(p, "endpoint_port")?
        .map(|v| {
            u16::try_from(v)
                .ok()
                .filter(|v| *v >= 1)
                .ok_or_else(|| EngineError::bad("endpoint_port", format!("must be 1..=65535, not {v}")))
        })
        .transpose()
}

/// Apply the keys of `p` that need no sealing to `peer`; notes go to
/// `warnings`.
fn update(peer: &mut WgPeer, p: &Value, warnings: &mut Vec<String>) -> Result<()> {
    if let Some(a) = endpoint_address_of(p)? {
        let none = a.is_none();
        peer.endpoint_address = a;
        if none {
            peer.endpoint_port = 0;
        }
    }
    if let Some(port) = port_of(p)? {
        peer.endpoint_port = port;
    }
    if let Some((list, notes)) = allowed_of(p)? {
        peer.allowed_address = list;
        warnings.extend(notes);
    }
    if let Some(k) = keepalive_of(p)? {
        peer.persistent_keepalive = k;
    }
    if let Some(b) = opt_bool(p, "responder")? {
        peer.responder = b;
    }
    if let Some(b) = opt_bool(p, "disabled")? {
        peer.disabled = b;
    }
    if let Some(c) = opt_text(p, "comment", 256)? {
        peer.comment = c;
    }
    client_of(&mut peer.client, p)
}

/// Whether `p` brings a key to seal (a private key or a preshared key):
/// only then does the command need the sealing key.
pub(super) fn seals(p: &Value) -> bool {
    // Any private_key (empty = auto) is sealed; a preshared key unless it
    // clears it.
    p.get("private_key").and_then(Value::as_str).is_some()
        || p.get("preshared_key")
            .and_then(Value::as_str)
            .is_some_and(|t| !matches!(t.trim(), "" | "none"))
}

/// The sealing key, when `p` needs one.
pub(super) fn seal_for(s: &mut Session, p: &Value) -> Result<Option<std::sync::Arc<SealKey>>> {
    if seals(p) {
        crate::sealing::key(s).map(Some).map_err(EngineError::Internal)
    } else {
        Ok(None)
    }
}

fn sealed(seal: Option<&SealKey>, k: &wg::Key) -> Result<corerouter_model::sealed::Sealed> {
    let seal = seal.ok_or_else(|| EngineError::Internal("no sealing key for a WireGuard key".into()))?;
    seal.seal(&wg::encode(k)).map_err(EngineError::Internal)
}

/// Keys: `public_key`, `private_key` (auto or a key), `preshared_key`.
fn keys(seal: Option<&SealKey>, peer: &mut WgPeer, p: &Value, new: bool) -> Result<()> {
    let public = key_param(p, "public_key")?;
    let private = key_param(p, "private_key")?;
    if public.is_some() && private.is_some() {
        return Err(EngineError::bad(
            "private_key",
            "give public_key or private_key, not both (the public key comes from the private one)",
        ));
    }
    if let Some(t) = public {
        let k = WgKey::parse(&t).ok_or_else(|| {
            EngineError::bad("public_key", "must be a WireGuard key: 44 characters of base64 ending in = (wg pubkey)")
        })?;
        peer.public_key = k;
        peer.private_key = corerouter_model::sealed::Sealed::default();
    }
    if let Some(t) = private {
        let k = if t.is_empty() || t == "auto" {
            wg::generate_private().map_err(EngineError::Internal)?
        } else {
            wg::parse_private(&t).ok_or_else(|| {
                EngineError::bad("private_key", "must be auto or a WireGuard key (44 characters of base64)")
            })?
        };
        peer.private_key = sealed(seal, &k)?;
        peer.public_key = wg::wg_key(&wg::public_of(&k));
    }
    if new && peer.public_key.is_empty() {
        return Err(EngineError::bad(
            "public_key",
            "is required (the peer's key), or private_key=auto to make the pair here",
        ));
    }
    match key_param(p, "preshared_key")?.as_deref() {
        None => {}
        Some("" | "none") => peer.preshared_key = corerouter_model::sealed::Sealed::default(),
        Some(t) => {
            let k = if t == "auto" {
                wg::generate_private().map_err(EngineError::Internal)?
            } else {
                wg::decode(t).ok_or_else(|| {
                    EngineError::bad("preshared_key", "must be auto, none or a key of 44 characters of base64 (wg genpsk)")
                })?
            };
            peer.preshared_key = sealed(seal, &k)?;
        }
    }
    Ok(())
}

/// The checks of `peer` among the peers of interface `w` (`w` without
/// it); warnings for what is legal but likely a mistake.
fn check(iface: &IfName, w: &Wireguard, peer: &WgPeer, warnings: &mut Vec<String>) -> Result<()> {
    if peer.public_key == w.public_key {
        return Err(EngineError::bad(
            "public_key",
            format!("is the public key of {iface} itself: the kernel ignores such a peer"),
        ));
    }
    if let Some(o) = w.peers.iter().find(|o| o.public_key == peer.public_key) {
        return Err(EngineError::bad(
            "public_key",
            format!("peer '{}' of {iface} already has this key", o.name),
        ));
    }
    if peer.allowed_address.is_empty() {
        return Err(EngineError::bad(
            "allowed_address",
            "is required: nothing is sent to a peer without one, nor taken from it",
        ));
    }
    for net in &peer.allowed_address {
        if let Some(o) = w.peers.iter().find(|o| o.allowed_address.contains(net)) {
            return Err(EngineError::bad(
                "allowed_address",
                format!(
                    "{net} is already an allowed address of peer '{}' on {iface}: the kernel would \
                     move it to this one in silence and '{}' would stop getting it",
                    o.name, o.name
                ),
            ));
        }
    }
    if (peer.endpoint_address.is_some()) != (peer.endpoint_port != 0) {
        return Err(EngineError::bad(
            "endpoint_port",
            "endpoint_address and endpoint_port go together (both, or neither to wait for the peer)",
        ));
    }
    let everything = peer.allowed_address.iter().any(|n| n.prefix_len() == 0);
    if everything && !w.peers.is_empty() {
        warnings.push(format!(
            "{} sends this peer everything of {iface} that no narrower prefix of another peer matches",
            peer.allowed_address
                .iter()
                .filter(|n| n.prefix_len() == 0)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(" and ")
        ));
    }
    if let Some(e) = peer.endpoint_address.as_ref().and_then(WgHost::ip)
        && let Some(n) = peer.allowed_address.iter().find(|n| n.contains(&e))
    {
        warnings.push(format!(
            "the endpoint {e} is inside its own allowed address {n}: if a route sends {e} into \
             {iface}, the tunnel tries to reach its peer through itself"
        ));
    }
    if peer.responder && peer.endpoint_address.is_some() {
        warnings.push("responder: the endpoint is only used to answer; the router never calls it".to_owned());
    }
    Ok(())
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    crate::lockout::take_force(s, p)?;
    let seal = seal_for(s, p)?;
    add_on(s.store_mut().candidate_mut(), seal.as_deref(), p)
}

/// `interface.wireguard.peers.add` on `cfg` (the candidate, or a copy for
/// the preview). `seal`: needed when `p` brings a key ([`seal_for`]).
pub(super) fn add_on(cfg: &mut Config, seal: Option<&SealKey>, p: &Value) -> Result<Value> {
    let iface: IfName = req_parse(p, "interface")?;
    let w = wireguard_of(cfg, "interface", &iface)?;
    if w.peers.len() >= MAX_PEERS {
        return Err(EngineError::bad("interface", format!("{iface} has {MAX_PEERS} peers, the most one interface takes")));
    }
    let name = match name_of(p, "name")? {
        Some(n) => {
            if let Ok((other, _)) = find(cfg, &n) {
                return Err(EngineError::bad("name", format!("peer '{n}' already exists (on {other})")));
            }
            n
        }
        None => default_name(cfg),
    };
    let mut peer = WgPeer::new(name.clone(), WgKey::default());
    let mut warnings = Vec::new();
    update(&mut peer, p, &mut warnings)?;
    keys(seal, &mut peer, p, true)?;
    let w = wireguard_of(cfg, "interface", &iface)?;
    check(&iface, w, &peer, &mut warnings)?;
    let public = peer.public_key.to_string();
    if let Some(w) = wireguard_mut(cfg, &iface) {
        w.peers.push(peer);
    }
    Ok(json!({ "name": name, "public_key": public, "warnings": warnings }))
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    crate::lockout::take_force(s, p)?;
    let seal = seal_for(s, p)?;
    set_on(s.store_mut().candidate_mut(), seal.as_deref(), p)
}

/// `interface.wireguard.peers.set` on `cfg`.
pub(super) fn set_on(cfg: &mut Config, seal: Option<&SealKey>, p: &Value) -> Result<Value> {
    let name = req_str(p, "name")?.trim().to_owned();
    let (iface, at) = find(cfg, &name)?;
    let mut w = wireguard_of(cfg, "name", &iface)?.clone();
    let mut peer = w.peers.remove(at);
    if let Some(n) = name_of(p, "new_name")? {
        if n != peer.name
            && let Ok((other, _)) = find(cfg, &n)
        {
            return Err(EngineError::bad("new_name", format!("peer '{n}' already exists (on {other})")));
        }
        peer.name = n;
    }
    let mut warnings = Vec::new();
    update(&mut peer, p, &mut warnings)?;
    keys(seal, &mut peer, p, false)?;
    check(&iface, &w, &peer, &mut warnings)?;
    let out = json!({ "name": peer.name, "public_key": peer.public_key, "warnings": warnings });
    w.peers.insert(at, peer);
    if let Some(slot) = wireguard_mut(cfg, &iface) {
        *slot = w;
    }
    Ok(out)
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    crate::lockout::take_force(s, p)?;
    let name = req_str(p, "name")?.trim().to_owned();
    let (iface, at) = find(s.store().candidate(), &name)?;
    if let Some(w) = wireguard_mut(s.store_mut().candidate_mut(), &iface)
        && at < w.peers.len()
    {
        w.peers.remove(at);
    }
    Ok(json!({ "name": name }))
}

fn toggle(s: &mut Session, p: &Value, off: bool) -> Result<Value> {
    crate::lockout::take_force(s, p)?;
    let name = req_str(p, "name")?.trim().to_owned();
    let (iface, at) = find(s.store().candidate(), &name)?;
    if let Some(peer) = wireguard_mut(s.store_mut().candidate_mut(), &iface).and_then(|w| w.peers.get_mut(at)) {
        peer.disabled = off;
    }
    Ok(json!({ "name": name }))
}

fn enable(s: &mut Session, p: &Value) -> Result<Value> {
    toggle(s, p, false)
}

fn disable(s: &mut Session, p: &Value) -> Result<Value> {
    toggle(s, p, true)
}

fn hint(state: PeerState, port: u16) -> &'static str {
    match state {
        PeerState::NoHandshake if port > 0 => {
            "no answer: check the public keys on both sides, and that UDP reaches the peer (its firewall, a NAT on the way)"
        }
        PeerState::Never => "waiting for the peer to call (it needs this router's public key and address)",
        PeerState::Idle => "no traffic, so no handshake: normal for a peer without keepalive",
        _ => "",
    }
}

fn list(s: &mut Session, p: &Value) -> Result<Value> {
    let key = sensitive(s, p, "interface.wireguard.peers.list")?;
    let only = super::args::opt_parse::<IfName>(p, "interface")?;
    let cfg = s.store().candidate().clone();
    if let Some(i) = &only {
        wireguard_of(&cfg, "interface", i)?;
    }
    let now = s.now().unwrap_or(0);
    let resolved: std::collections::BTreeMap<String, wg::Resolved> = wg::peers(&cfg)
        .filter_map(|(_, p)| p.endpoint_address.as_ref().filter(|h| h.ip().is_none()))
        .filter_map(|h| s.ext::<wg::WgRuntime>().and_then(|rt| rt.resolved(h.as_str()).cloned()).map(|r| (h.to_string(), r)))
        .collect();
    let mut rows = Vec::new();
    for (iface, i) in cfg.interfaces.iter() {
        let InterfaceKind::Wireguard(w) = &i.kind else {
            continue;
        };
        if only.as_ref().is_some_and(|o| o != iface) {
            continue;
        }
        let committed = s.store().running().interfaces.contains_key(iface);
        let status = if i.disabled || !committed { None } else { s.wireguard_status(iface).0 };
        let by_key = wg::status_by_key(status.as_ref());
        for peer in &w.peers {
            let (state, age, st) = wg::peer_view(peer, i.disabled, &by_key, now);
            let current = st.and_then(|x| x.endpoint);
            let configured = wg::endpoint_of(peer, &resolved);
            let name = peer.endpoint_address.as_ref().filter(|h| h.ip().is_none());
            let res = name.and_then(|h| resolved.get(h.as_str()));
            rows.push(json!({
                "name": peer.name,
                "interface": iface,
                "public_key": peer.public_key,
                "private_key": shown(key.as_deref(), &peer.private_key),
                "preshared_key": shown(key.as_deref(), &peer.preshared_key),
                "endpoint_address": peer.endpoint_address,
                "endpoint_port": (peer.endpoint_port != 0).then_some(peer.endpoint_port),
                "endpoint_resolved": res.and_then(|r| r.ip),
                "resolved_secs": res.map(|r| now.saturating_sub(r.at_unix)),
                "resolve_error": res.and_then(|r| r.error.clone()),
                "current_endpoint_address": current.map(|e| e.ip()),
                "current_endpoint_port": current.map(|e| e.port()),
                "roamed": current.is_some() && configured.is_some() && current != configured,
                "allowed_address": peer.allowed_address,
                "persistent_keepalive": peer.persistent_keepalive,
                "responder": peer.responder,
                "disabled": peer.disabled,
                "comment": peer.comment,
                "client_address": peer.client.address,
                "client_dns": peer.client.dns,
                "client_endpoint": peer.client.endpoint,
                "client_allowed_address": peer.client.allowed_address,
                "client_keepalive": peer.client.keepalive,
                "client_mtu": peer.client.mtu,
                "state": state.as_str(),
                "last_handshake_secs": age,
                "rx": st.map_or(0, |x| x.rx_bytes),
                "tx": st.map_or(0, |x| x.tx_bytes),
                "hint": hint(state, w.listen_port),
            }));
        }
    }
    Ok(Value::Array(rows))
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use crate::Session;

    const K1: &str = "YAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const K2: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

    fn lab() -> Session {
        let mut s = Session::virtual_lab();
        s.execute("interface.wireguard.add", &json!({"name": "wg0"})).unwrap();
        s
    }

    fn add(s: &mut Session, p: Value) -> crate::Result<Value> {
        s.execute("interface.wireguard.peers.add", &p)
    }

    #[test]
    fn add_names_peers_and_lists_them() {
        let mut s = lab();
        let v = add(&mut s, json!({"interface": "wg0", "public_key": K1, "allowed_address": "10.9.0.2"})).unwrap();
        assert_eq!(v["name"], "peer1");
        let v = add(
            &mut s,
            json!({"interface": "wg0", "name": "filial", "public_key": K2, "allowed_address": ["10.20.1.0/16"],
                   "endpoint_address": "198.51.100.7", "endpoint_port": 13231, "persistent_keepalive": 25}),
        )
        .unwrap();
        assert!(v["warnings"].to_string().contains("10.20.0.0/16"), "{v}");
        let l = s.execute("interface.wireguard.peers.list", &json!({})).unwrap();
        assert_eq!(l.as_array().unwrap().len(), 2);
        assert_eq!(l[0]["allowed_address"], json!(["10.9.0.2/32"]));
        assert_eq!(l[0]["state"], "never");
        assert_eq!(l[1]["allowed_address"], json!(["10.20.0.0/16"]));
        // Keepalive and an endpoint that does not answer: the lab has no
        // peer there.
        assert_eq!(l[1]["state"], "no-handshake");
        assert!(l[1]["hint"].as_str().unwrap().contains("public keys"));
    }

    #[test]
    fn refuses_what_the_kernel_would_hide() {
        let mut s = lab();
        add(&mut s, json!({"interface": "wg0", "name": "a", "public_key": K1, "allowed_address": "10.9.0.0/24"})).unwrap();
        let own = s.execute("interface.wireguard.list", &json!({})).unwrap()[0]["public_key"].clone();
        for (p, want) in [
            // The same prefix as peer a: the kernel would move it.
            (json!({"interface": "wg0", "public_key": K2, "allowed_address": "10.9.0.0/24"}), "peer 'a'"),
            // Same key twice.
            (json!({"interface": "wg0", "public_key": K1, "allowed_address": "10.9.1.0/24"}), "already has this key"),
            // The interface's own key.
            (json!({"interface": "wg0", "public_key": own, "allowed_address": "10.9.1.0/24"}), "itself"),
            (json!({"interface": "wg0", "public_key": K2}), "allowed_address"),
            (json!({"interface": "wg0", "public_key": "nope", "allowed_address": "10.9.1.0/24"}), "public_key"),
            (json!({"interface": "wg0", "allowed_address": "10.9.1.0/24"}), "public_key"),
            (json!({"interface": "wg0", "public_key": K2, "allowed_address": "10.9.1.0/24", "endpoint_address": "198.51.100.7"}), "go together"),
            (json!({"interface": "wg0", "public_key": K2, "allowed_address": "10.9.1.0/24", "endpoint_address": "vpn example", "endpoint_port": 1}), "neither an IP"),
            (json!({"interface": "wg0", "name": "a", "public_key": K2, "allowed_address": "10.9.1.0/24"}), "already exists"),
            (json!({"interface": "ether1", "public_key": K2, "allowed_address": "10.9.1.0/24"}), "not a WireGuard"),
        ] {
            let e = add(&mut s, p.clone()).unwrap_err().to_string();
            assert!(e.contains(want), "{p} → {e}");
        }
        // A narrower prefix inside another peer's is legal (longest match).
        add(&mut s, json!({"interface": "wg0", "public_key": K2, "allowed_address": "10.9.0.128/25"})).unwrap();
    }

    #[test]
    fn auto_keys_are_sealed_and_shown_to_full_only() {
        let mut s = lab();
        let v = add(&mut s, json!({"interface": "wg0", "private_key": "auto", "preshared_key": "auto", "allowed_address": "10.9.0.2/32"})).unwrap();
        let public = v["public_key"].as_str().unwrap().to_owned();
        let l = s.execute("interface.wireguard.peers.list", &json!({})).unwrap();
        assert_eq!(l[0]["private_key"], "***");
        assert_eq!(l[0]["preshared_key"], "***");
        let text = serde_json::to_string(s.store().running()).unwrap();
        assert_eq!(text.matches("$cr1$").count(), 3, "interface key, peer key, psk sealed");
        let l = s.execute("interface.wireguard.peers.list", &json!({"show_sensitive": true})).unwrap();
        let k = crate::wireguard::parse_private(l[0]["private_key"].as_str().unwrap()).unwrap();
        assert_eq!(crate::wireguard::encode(&crate::wireguard::public_of(&k)), public);
        assert_eq!(l[0]["preshared_key"].as_str().unwrap().len(), 44);
    }

    #[test]
    fn two_lab_interfaces_that_know_each_other_come_up() {
        let mut s = lab();
        s.execute("interface.wireguard.add", &json!({"name": "wg1"})).unwrap();
        let l = s.execute("interface.wireguard.list", &json!({})).unwrap();
        let (k0, k1) = (l[0]["public_key"].clone(), l[1]["public_key"].clone());
        assert_eq!(l[1]["listen_port"], 13232, "first free port");
        add(&mut s, json!({"interface": "wg0", "name": "to-wg1", "public_key": k1, "allowed_address": "10.99.0.2/32",
                            "endpoint_address": "127.0.0.1", "endpoint_port": 13232})).unwrap();
        add(&mut s, json!({"interface": "wg1", "name": "to-wg0", "public_key": k0, "allowed_address": "10.99.0.1/32"})).unwrap();
        let l = s.execute("interface.wireguard.peers.list", &json!({"interface": "wg0"})).unwrap();
        assert_eq!(l.as_array().unwrap().len(), 1);
        assert_eq!(l[0]["state"], "up", "{l}");
        let i = s.execute("interface.wireguard.list", &json!({})).unwrap();
        assert_eq!(i[0]["peers_up"], 1);
    }

    #[test]
    fn set_rename_disable_remove_and_rollback() {
        let mut s = lab();
        add(&mut s, json!({"interface": "wg0", "name": "a", "public_key": K1, "allowed_address": "10.9.0.2/32"})).unwrap();
        add(&mut s, json!({"interface": "wg0", "name": "b", "public_key": K2, "allowed_address": "10.9.0.3/32"})).unwrap();
        let rev = s.store().current_revision();
        // b may not take a's prefix; a may keep its own on a set.
        let e = s.execute("interface.wireguard.peers.set", &json!({"name": "b", "allowed_address": "10.9.0.2/32"})).unwrap_err();
        assert!(e.to_string().contains("peer 'a'"), "{e}");
        s.execute("interface.wireguard.peers.set", &json!({"name": "a", "allowed_address": "10.9.0.2/32,fd00::2/128", "new_name": "a2", "persistent_keepalive": "off"})).unwrap();
        let e = s.execute("interface.wireguard.peers.set", &json!({"name": "b", "new_name": "a2"})).unwrap_err();
        assert!(e.to_string().contains("already exists"), "{e}");
        s.execute("interface.wireguard.peers.disable", &json!({"name": "b"})).unwrap();
        let l = s.execute("interface.wireguard.peers.list", &json!({})).unwrap();
        assert_eq!(l[0]["name"], "a2");
        assert_eq!(l[0]["allowed_address"], json!(["10.9.0.2/32", "fd00::2/128"]));
        assert_eq!(l[1]["state"], "disabled");
        s.execute("interface.wireguard.peers.remove", &json!({"name": "a2"})).unwrap();
        assert_eq!(s.execute("interface.wireguard.peers.list", &json!({})).unwrap().as_array().unwrap().len(), 1);
        s.execute("config.rollback", &json!({"revision": rev})).unwrap();
        let l = s.execute("interface.wireguard.peers.list", &json!({})).unwrap();
        assert_eq!(l[0]["name"], "a");
        assert_eq!(l[1]["state"], "never");
        // Removing the interface takes its peers.
        s.execute("interface.remove", &json!({"name": "wg0"})).unwrap();
        assert_eq!(s.execute("interface.wireguard.peers.list", &json!({})).unwrap(), json!([]));
    }
}
