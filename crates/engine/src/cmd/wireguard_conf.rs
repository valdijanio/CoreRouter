//! WireGuard and the `wg-quick` file (G1.31b): the client configuration of
//! a peer (RouterOS 7.12 `show-client-config`, the GUI draws it as a QR
//! code too), and `wg-import` / `wg-export` of a whole interface (RouterOS
//! `/interface wireguard wg-import file=`). The format is in
//! `corerouter_model::wireguard_conf`.
//!
//! Private and preshared keys leave the router only for group `full`:
//! whoever holds a client's private key is that client.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use corerouter_model::wireguard::{MAX_PEERS, WgKey, WgPeer};
use corerouter_model::wireguard_conf::{self, Conf, ConfInterface, ConfPeer, MAX_TEXT, parse_endpoint};
use corerouter_model::IfName;
use ipnet::IpNet;
use serde_json::{Value, json};

use super::args::{opt_str, req_parse, req_str};
use super::wireguard::{add_on, sensitive, wireguard_mut, wireguard_of};
use super::wireguard_preview::{INTERNET, wan_of};
use super::{CommandSpec, always};
use crate::wireguard as wg;
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "interface.wireguard.peers.show-client-config", "Client Config", ["Interfaces", "WireGuard"], None,
        "{name: string (the peer)} → {text (the client's wg-quick file: [Interface] with its private key, [Peer] this router), private_key_known (the router made the client's key; else the file says where it goes), warnings} (group full: it holds the client's private key)",
        always, client_config),
    cmd!(query "interface.wireguard.wg-export", "Export WireGuard", ["Interfaces", "WireGuard"], None,
        "{name: string, show_sensitive?: bool (the private and preshared keys; group full, else <hidden>)} → {text} (the interface as a wg-quick file: its key, port, addresses, MTU and every peer)",
        always, export),
    cmd!("interface.wireguard.wg-import", "Import WireGuard", ["Interfaces", "WireGuard"], None,
        "{text: string (a wg-quick file: [Interface] PrivateKey, ListenPort, Address, MTU; [Peer] PublicKey, PresharedKey, AllowedIPs, Endpoint (name or address), PersistentKeepalive; `# Name = x` names the next peer), name?: string (the new interface; default the first free wireguardN)} → {name, public_key, peers, addresses, warnings} (one transaction: the interface, its addresses and peers, or nothing)",
        always, import),
];

/// The router's WAN address is not one the Internet reaches.
fn private(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_private() || v4.is_link_local() || v4.is_loopback() || (a == 100 && (64..128).contains(&b))
        }
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments().first().is_some_and(|s| s & 0xfe00 == 0xfc00 || s & 0xffc0 == 0xfe80)),
    }
}

fn client_config(s: &mut Session, p: &Value) -> Result<Value> {
    let name = req_str(p, "name")?.trim().to_owned();
    s.permit(crate::auth::Group::Full).map_err(|reason| EngineError::Denied {
        id: "interface.wireguard.peers.show-client-config".into(),
        reason: format!("the client configuration holds the client's private key: {reason}"),
    })?;
    let seal = crate::sealing::key(s).map_err(EngineError::Internal)?;
    let cfg = s.store().candidate().clone();
    let Some((iface, peer)) = wg::peers(&cfg).find(|(_, x)| x.name == name).map(|(i, x)| (i.clone(), x.clone())) else {
        return Err(EngineError::bad(
            "name",
            format!("no WireGuard peer '{}' (see interface.wireguard.peers.list)", name.chars().take(64).collect::<String>()),
        ));
    };
    let w = wireguard_of(&cfg, "name", &iface)?;
    let mut warnings = Vec::new();
    let known = !peer.private_key.is_empty();
    let private_key = if known {
        seal.open(&peer.private_key)
    } else {
        warnings.push(format!(
            "the router does not hold this client's private key (its public key was pasted): put the client's own key in PrivateKey; for a key made here, set private_key=auto on peer '{name}'"
        ));
        Some("<the client's private key>".to_owned())
    };
    let c = &peer.client;
    let address = if c.address.is_empty() { peer.allowed_address.clone() } else { c.address.clone() };
    let allowed = if c.allowed_address.is_empty() {
        ["0.0.0.0/0", "::/0"].iter().filter_map(|t| t.parse::<IpNet>().ok()).collect()
    } else {
        c.allowed_address.clone()
    };
    let endpoint = if !c.endpoint.is_empty() {
        parse_endpoint(&c.endpoint)
            .or_else(|| corerouter_model::wireguard::WgHost::parse(&c.endpoint).map(|h| (h, w.listen_port)))
    } else {
        match wan_of(&cfg, INTERNET, &super::wireguard_preview::underlay(w)) {
            Some((wan, Some(ip))) => {
                if private(ip) {
                    warnings.push(format!(
                        "the router's address on {wan}, {ip}, is private (behind a NAT): set client_endpoint to the public name or address the client reaches"
                    ));
                }
                Some((ip.into(), w.listen_port))
            }
            _ => {
                warnings.push("no route to the Internet with an address: set client_endpoint to where the client finds this router".to_owned());
                None
            }
        }
    };
    let conf = Conf {
        interface: ConfInterface {
            private_key,
            listen_port: None,
            address,
            dns: c.dns.clone(),
            mtu: (c.mtu != 0).then_some(c.mtu),
        },
        peers: vec![ConfPeer {
            name: None,
            public_key: w.public_key.clone(),
            preshared_key: (!peer.preshared_key.is_empty()).then(|| seal.open(&peer.preshared_key)).flatten(),
            allowed,
            endpoint,
            keepalive: (c.keepalive != 0).then_some(c.keepalive),
        }],
        ignored: Vec::new(),
    };
    let text = format!("# {name} ({iface})\n{}", wireguard_conf::render(&conf));
    Ok(json!({ "text": text, "private_key_known": known, "warnings": warnings }))
}

fn export(s: &mut Session, p: &Value) -> Result<Value> {
    let key = sensitive(s, p, "interface.wireguard.wg-export")?;
    let name: IfName = req_parse(p, "name")?;
    let cfg = s.store().candidate().clone();
    let w = wireguard_of(&cfg, "name", &name)?;
    let hidden = || "<hidden>".to_owned();
    let open = |v: &corerouter_model::sealed::Sealed| key.as_deref().map_or_else(hidden, |k| k.open(v).unwrap_or_else(hidden));
    let conf = Conf {
        interface: ConfInterface {
            private_key: Some(open(&w.private_key)),
            listen_port: Some(w.listen_port),
            address: cfg.ip.addresses.iter().filter(|a| a.interface == name && !a.disabled).map(|a| a.address).collect(),
            dns: Vec::new(),
            mtu: cfg.interfaces.get(&name).map(|i| i.mtu),
        },
        peers: w
            .peers
            .iter()
            .filter(|x| !x.disabled)
            .map(|x| ConfPeer {
                name: Some(x.name.clone()),
                public_key: x.public_key.clone(),
                preshared_key: (!x.preshared_key.is_empty()).then(|| open(&x.preshared_key)),
                allowed: x.allowed_address.clone(),
                endpoint: x.endpoint_address.clone().filter(|_| x.endpoint_port != 0).map(|h| (h, x.endpoint_port)),
                keepalive: (x.persistent_keepalive != 0).then_some(x.persistent_keepalive),
            })
            .collect(),
        ignored: Vec::new(),
    };
    Ok(json!({ "text": format!("# {name}\n{}", wireguard_conf::render(&conf)) }))
}

/// Names `peerN` not in `taken`, in order.
fn free_names(taken: HashSet<String>) -> impl Iterator<Item = String> {
    (1..=MAX_PEERS.saturating_mul(5)).map(|n| format!("peer{n}")).filter(move |n| !taken.contains(n))
}

fn import(s: &mut Session, p: &Value) -> Result<Value> {
    let text = req_str(p, "text")?;
    if text.len() > MAX_TEXT {
        return Err(EngineError::bad("text", format!("at most {MAX_TEXT} bytes")));
    }
    let conf = wireguard_conf::parse(text).map_err(|e| EngineError::bad("text", e))?;
    let mut warnings: Vec<String> = Vec::new();
    if !conf.ignored.is_empty() {
        warnings.push(format!("ignored (wg-quick keys the router does not use): {}", conf.ignored.join(", ")));
    }
    if !conf.interface.dns.is_empty() {
        warnings.push("DNS ignored: the router uses its own resolver (ip.dns.set)".to_owned());
    }
    let seal = crate::sealing::key(s).map_err(EngineError::Internal)?;
    // The interface, through the same add as interface.wireguard.add.
    let mut add = serde_json::Map::new();
    if let Some(n) = opt_str(p, "name")?.map(str::trim).filter(|n| !n.is_empty()) {
        add.insert("name".into(), json!(n));
    }
    if let Some(port) = conf.interface.listen_port {
        add.insert("listen_port".into(), json!(port));
    }
    if let Some(m) = conf.interface.mtu {
        add.insert("mtu".into(), json!(m));
    }
    if let Some(k) = &conf.interface.private_key {
        add.insert("private_key".into(), json!(k));
    }
    super::interface::refuse_unmanaged(s, &Value::Object(add.clone()), &["name"])?;
    let made = add_on(s.store_mut().candidate_mut(), &seal, &Value::Object(add)).map_err(|e| match e {
        EngineError::BadParam { param, reason } => EngineError::bad("text", format!("{param}: {reason}")),
        e => e,
    })?;
    let name: IfName = req_parse(&made, "name")?;
    let own = made.get("public_key").and_then(Value::as_str).and_then(WgKey::parse).unwrap_or_default();
    // The peers, checked as a whole: one pass with sets, not a walk of
    // the others per peer (20 000 peers would be 2·10⁸ compares).
    let mut taken: HashSet<String> = wg::peers(s.store().candidate()).map(|(_, x)| x.name.clone()).collect();
    // Names the file gives are taken before the `peerN` ones are handed out.
    let given: HashSet<String> = conf.peers.iter().filter_map(|c| c.name.clone()).filter(|n| !taken.contains(n)).collect();
    let mut names = free_names(taken.iter().chain(&given).cloned().collect());
    let mut keys: HashSet<WgKey> = HashSet::new();
    let mut prefixes: HashMap<IpNet, String> = HashMap::new();
    let mut peers: Vec<WgPeer> = Vec::with_capacity(conf.peers.len());
    for (i, c) in conf.peers.iter().enumerate() {
        let n = i.saturating_add(1);
        let pname = match &c.name {
            Some(x) if !taken.contains(x) => x.clone(),
            _ => names.next().unwrap_or_else(|| format!("import{n}")),
        };
        taken.insert(pname.clone());
        if c.public_key == own {
            return Err(EngineError::bad("text", format!("peer {n} has the interface's own public key: the kernel ignores such a peer")));
        }
        if !keys.insert(c.public_key.clone()) {
            return Err(EngineError::bad("text", format!("peer {n}: its public key is there twice")));
        }
        let mut peer = WgPeer::new(pname.clone(), c.public_key.clone());
        for net in &c.allowed {
            let t = net.trunc();
            if let Some(other) = prefixes.insert(t, pname.clone()) {
                return Err(EngineError::bad(
                    "text",
                    format!("{t} is in peer '{other}' and peer '{pname}': the kernel would keep it only in the last"),
                ));
            }
            peer.allowed_address.push(t);
        }
        if peer.allowed_address.is_empty() {
            return Err(EngineError::bad("text", format!("peer {n} ('{pname}') has no AllowedIPs")));
        }
        if let Some(k) = &c.preshared_key {
            let k = wg::decode(k).ok_or_else(|| EngineError::bad("text", format!("peer {n}: PresharedKey is not a key")))?;
            peer.preshared_key = seal.seal(&wg::encode(&k)).map_err(EngineError::Internal)?;
        }
        if let Some((h, port)) = &c.endpoint {
            peer.endpoint_address = Some(h.clone());
            peer.endpoint_port = *port;
        }
        peer.persistent_keepalive = c.keepalive.unwrap_or(0);
        peers.push(peer);
    }
    let count = peers.len();
    if let Some(w) = wireguard_mut(s.store_mut().candidate_mut(), &name) {
        w.peers = peers;
    }
    // Its addresses, through ip.address.add.
    let mut addresses = Vec::new();
    for a in &conf.interface.address {
        super::ip::add(s, &json!({"address": a, "interface": name}))?;
        addresses.push(a.to_string());
    }
    let routed: Vec<String> = conf
        .peers
        .iter()
        .flat_map(|c| c.allowed.iter())
        .filter(|n| n.prefix_len() == 0)
        .map(ToString::to_string)
        .collect();
    if !routed.is_empty() {
        warnings.push(format!(
            "{} imported as allowed address only: wg-quick would also route it into the tunnel; add the route (ip.route.add gateway={name}) if you want that",
            routed.join(" and ")
        ));
    }
    Ok(json!({ "name": name, "public_key": own, "peers": count, "addresses": addresses, "warnings": warnings }))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::Session;

    const K1: &str = "YAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const K2: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
    // RFC 7748 §6.1 Alice.
    const PRIV: &str = "dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=";

    fn lab() -> Session {
        let mut s = Session::virtual_lab();
        s.execute("ip.address.add", &json!({"address": "203.0.113.2/24", "interface": "ether1"})).unwrap();
        s.execute("ip.route.add", &json!({"dst_address": "0.0.0.0/0", "gateway": "203.0.113.1"})).unwrap();
        s.execute("interface.wireguard.add", &json!({"name": "wg0"})).unwrap();
        s.execute("ip.address.add", &json!({"address": "10.9.0.1/24", "interface": "wg0"})).unwrap();
        s
    }

    #[test]
    fn the_client_config_carries_its_keys_and_the_router() {
        let mut s = lab();
        s.execute(
            "interface.wireguard.peers.add",
            &json!({"interface": "wg0", "name": "notebook", "private_key": "auto", "preshared_key": "auto",
                    "allowed_address": "10.9.0.2/32", "client_dns": "10.9.0.1", "client_keepalive": 25}),
        )
        .unwrap();
        let v = s.execute("interface.wireguard.peers.show-client-config", &json!({"name": "notebook"})).unwrap();
        let text = v["text"].as_str().unwrap();
        let own = s.execute("interface.wireguard.list", &json!({})).unwrap()[0]["public_key"].as_str().unwrap().to_owned();
        let keys = s.execute("interface.wireguard.peers.list", &json!({"show_sensitive": true})).unwrap();
        for want in [
            format!("PrivateKey = {}", keys[0]["private_key"].as_str().unwrap()),
            format!("PresharedKey = {}", keys[0]["preshared_key"].as_str().unwrap()),
            "Address = 10.9.0.2/32".into(),
            "DNS = 10.9.0.1".into(),
            format!("PublicKey = {own}"),
            "AllowedIPs = 0.0.0.0/0, ::/0".into(),
            "Endpoint = 203.0.113.2:13231".into(),
            "PersistentKeepalive = 25".into(),
        ] {
            assert!(text.contains(&want), "{want}\n{text}");
        }
        assert_eq!(v["private_key_known"], true);
        // The client's file parses back as wg-quick does.
        assert!(corerouter_model::wireguard_conf::parse(text).is_ok());
        // A named endpoint for the client; and a pasted key: a placeholder.
        s.execute("interface.wireguard.peers.set", &json!({"name": "notebook", "client_endpoint": "vpn.exemplo.com.br"})).unwrap();
        s.execute("interface.wireguard.peers.add", &json!({"interface": "wg0", "name": "tablet", "public_key": K1, "allowed_address": "10.9.0.3/32"})).unwrap();
        let v = s.execute("interface.wireguard.peers.show-client-config", &json!({"name": "notebook"})).unwrap();
        assert!(v["text"].as_str().unwrap().contains("Endpoint = vpn.exemplo.com.br:13231"), "{v}");
        let v = s.execute("interface.wireguard.peers.show-client-config", &json!({"name": "tablet"})).unwrap();
        assert!(v["text"].as_str().unwrap().contains("PrivateKey = <the client's private key>"));
        assert_eq!(v["private_key_known"], false);
        let e = s.execute("interface.wireguard.peers.show-client-config", &json!({"name": "nope"})).unwrap_err();
        assert!(e.to_string().contains("no WireGuard peer"), "{e}");
    }

    #[test]
    fn import_makes_the_interface_its_addresses_and_peers_at_once() {
        let mut s = Session::virtual_lab();
        let text = format!(
            "[Interface]\nPrivateKey = {PRIV}\nListenPort = 51820\nAddress = 10.30.0.1/24\nDNS = 1.1.1.1\nPostUp = echo\n\n\
             # Name = filial\n[Peer]\nPublicKey = {K1}\nAllowedIPs = 10.30.0.2/32, 10.40.0.0/16\nEndpoint = vpn.filial.example.com:51820\nPersistentKeepalive = 25\n\n\
             [Peer]\nPublicKey = {K2}\nAllowedIPs = 10.30.0.3/32\n"
        );
        let v = s.execute("interface.wireguard.wg-import", &json!({"text": text, "name": "wg-imp"})).unwrap();
        assert_eq!(v["name"], "wg-imp");
        assert_eq!(v["public_key"], "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=");
        assert_eq!(v["peers"], 2);
        assert!(v["warnings"].to_string().contains("PostUp") && v["warnings"].to_string().contains("DNS ignored"), "{v}");
        let l = s.execute("interface.wireguard.peers.list", &json!({})).unwrap();
        assert_eq!(l[0]["name"], "filial");
        assert_eq!(l[0]["endpoint_address"], "vpn.filial.example.com");
        assert_eq!(l[1]["name"], "peer1");
        let i = s.execute("interface.wireguard.list", &json!({})).unwrap();
        assert_eq!(i[0]["listen_port"], 51820);
        // Export gives it back; keys hidden but for show_sensitive.
        let out = s.execute("interface.wireguard.wg-export", &json!({"name": "wg-imp"})).unwrap()["text"].as_str().unwrap().to_owned();
        assert!(out.contains("PrivateKey = <hidden>") && out.contains("Address = 10.30.0.1/24") && out.contains("# Name = filial"), "{out}");
        let out = s.execute("interface.wireguard.wg-export", &json!({"name": "wg-imp", "show_sensitive": true})).unwrap()["text"].as_str().unwrap().to_owned();
        // The key as `wg` shows it (clamped, RFC 7748 §5): the same pair.
        assert!(!out.contains("<hidden>"), "{out}");
        // Into another router it reads the same key and peers.
        let mut t = Session::virtual_lab();
        let again = t.execute("interface.wireguard.wg-import", &json!({"text": out})).unwrap();
        assert_eq!(again["public_key"], v["public_key"]);
        let back = t.execute("interface.wireguard.peers.list", &json!({})).unwrap();
        assert_eq!(back[0]["allowed_address"], l[0]["allowed_address"]);
    }

    #[test]
    fn keys_never_reach_the_journal() {
        const PSK: &str = "c2VncmVkb3NlZ3JlZG9zZWdyZWRvc2VncmVkbzAxMjM=";
        let mut s = Session::virtual_lab();
        let text = format!("[Interface]\nPrivateKey = {PRIV}\n[Peer]\nPublicKey = {K1}\nPresharedKey = {PSK}\nAllowedIPs = 10.0.0.1\n");
        s.execute("interface.wireguard.wg-import", &json!({"text": text, "name": "wg0"})).unwrap();
        s.execute("interface.wireguard.peers.add", &json!({"interface": "wg0", "public_key": K2, "preshared_key": PSK, "allowed_address": "10.0.0.2"})).unwrap();
        let journal = s.inspect(Some("journal")).unwrap().to_string();
        let log = s.execute("log.print", &json!({})).unwrap().to_string();
        for t in [&journal, &log] {
            assert!(!t.contains(PRIV) && !t.contains(PSK), "a key in {t}");
        }
        assert!(journal.contains("PrivateKey = ***"), "{journal}");
    }

    #[test]
    fn a_bad_import_leaves_nothing_behind() {
        let mut s = Session::virtual_lab();
        let rev = s.store().current_revision();
        for (text, want) in [
            (format!("[Interface]\nPrivateKey = {PRIV}\n[Peer]\nPublicKey = {K1}\nAllowedIPs = 10.0.0.0/8\n[Peer]\nPublicKey = {K2}\nAllowedIPs = 10.0.0.0/8\n"), "kernel would keep it"),
            (format!("[Interface]\nPrivateKey = {PRIV}\n[Peer]\nPublicKey = {K1}\nAllowedIPs = 10.0.0.1\n[Peer]\nPublicKey = {K1}\nAllowedIPs = 10.0.0.2\n"), "twice"),
            (format!("[Interface]\nPrivateKey = {PRIV}\n[Peer]\nPublicKey = hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=\nAllowedIPs = 10.0.0.1\n"), "own public key"),
            ("[Interface]\nPrivateKey = nope\n".to_owned(), "private_key"),
            ("[Peer]\nAllowedIPs = 10.0.0.1\n".to_owned(), "no PublicKey"),
            (format!("[Interface]\nAddress = 10.0.0.1/24\nAddress = 10.0.0.1/24\n[Peer]\nPublicKey = {K1}\nAllowedIPs = 10.9.9.9\n"), "address"),
        ] {
            let e = s.execute("interface.wireguard.wg-import", &json!({"text": text})).unwrap_err().to_string();
            assert!(e.contains(want), "{want}: {e}");
            assert_eq!(s.store().current_revision(), rev);
            assert_eq!(s.execute("interface.wireguard.list", &json!({})).unwrap(), json!([]), "rolled back");
        }
    }
}
