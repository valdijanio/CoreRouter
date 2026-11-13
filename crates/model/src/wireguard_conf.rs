//! The `wg-quick` configuration file (G1.31b): what `wg-import` reads and
//! `wg-export` and `show-client-config` write. The format is wg(8)'s
//! (`[Interface]` and `[Peer]` sections of `Key = value` lines) plus the
//! `wg-quick(8)` keys `Address`, `DNS` and `MTU`; RouterOS's `wg-import`
//! and `show-client-config` use the same. `# Name = x` before a `[Peer]`
//! names it (as wg-quick front ends write it).
//!
//! The text is hostile: at most [`MAX_TEXT`] bytes and [`MAX_LINE`] per
//! line, unknown keys are listed (not fatal), errors name the line and cut
//! what they quote.

use std::net::IpAddr;

use ipnet::IpNet;

use crate::wireguard::{MAX_ALLOWED, MAX_NAME, MAX_PEERS, WgHost, WgKey};

/// Longest text taken: 20 000 peers of ~200 bytes.
pub const MAX_TEXT: usize = 4 * 1024 * 1024;
/// Longest line.
pub const MAX_LINE: usize = 8 * 1024;
/// DNS servers kept.
const MAX_DNS: usize = 8;

/// The `[Interface]` section.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfInterface {
    /// Base64, as written (the engine checks and seals it).
    pub private_key: Option<String>,
    pub listen_port: Option<u16>,
    pub address: Vec<IpNet>,
    pub dns: Vec<IpAddr>,
    pub mtu: Option<u16>,
}

/// One `[Peer]` section.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfPeer {
    pub name: Option<String>,
    pub public_key: WgKey,
    /// Base64, as written.
    pub preshared_key: Option<String>,
    pub allowed: Vec<IpNet>,
    pub endpoint: Option<(WgHost, u16)>,
    pub keepalive: Option<u16>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Conf {
    pub interface: ConfInterface,
    pub peers: Vec<ConfPeer>,
    /// Keys read but not used (`PostUp`, `Table`, `SaveConfig`…), once each.
    pub ignored: Vec<String>,
}

fn cut(t: &str) -> String {
    t.chars().take(48).collect()
}

/// `host:port`, `[v6]:port`.
pub fn parse_endpoint(text: &str) -> Option<(WgHost, u16)> {
    let t = text.trim();
    let (host, port) = if let Some(rest) = t.strip_prefix('[') {
        let (h, p) = rest.split_once("]:")?;
        (h, p)
    } else {
        t.rsplit_once(':')?
    };
    let port: u16 = port.trim().parse().ok().filter(|p| *p != 0)?;
    Some((WgHost::parse(host)?, port))
}

/// `host:port` with brackets around an IPv6 address.
pub fn endpoint_text(host: &WgHost, port: u16) -> String {
    match host.ip() {
        Some(IpAddr::V6(v6)) => format!("[{v6}]:{port}"),
        _ => format!("{host}:{port}"),
    }
}

fn nets(v: &str, line: usize) -> Result<Vec<IpNet>, String> {
    let mut out = Vec::new();
    for x in v.split(',').map(str::trim).filter(|x| !x.is_empty()) {
        let n = x
            .parse::<IpNet>()
            .or_else(|_| x.parse::<IpAddr>().map(IpNet::from))
            .map_err(|_| format!("line {line}: '{}' is not a prefix", cut(x)))?;
        if out.len() >= MAX_ALLOWED {
            return Err(format!("line {line}: more than {MAX_ALLOWED} prefixes"));
        }
        out.push(n);
    }
    Ok(out)
}

fn number<T: std::str::FromStr>(v: &str, key: &str, line: usize) -> Result<T, String> {
    v.trim().parse().map_err(|_| format!("line {line}: {key} '{}' is not a number", cut(v)))
}

#[derive(PartialEq)]
enum Section {
    None,
    Interface,
    Peer,
}

/// Read a `wg-quick` file.
pub fn parse(text: &str) -> Result<Conf, String> {
    if text.len() > MAX_TEXT {
        return Err(format!("the file has {} bytes; at most {MAX_TEXT}", text.len()));
    }
    let mut conf = Conf::default();
    let mut section = Section::None;
    let mut seen_interface = false;
    // A `# Name = x` comment names the next peer.
    let mut next_name: Option<String> = None;
    for (i, raw) in text.lines().enumerate() {
        let line = i.saturating_add(1);
        if raw.len() > MAX_LINE {
            return Err(format!("line {line}: longer than {MAX_LINE} bytes"));
        }
        let t = raw.trim();
        if let Some(c) = t.strip_prefix('#') {
            if let Some((k, v)) = c.split_once('=')
                && k.trim().eq_ignore_ascii_case("name")
            {
                let v: String = v.trim().chars().filter(|c| !c.is_control()).take(MAX_NAME).collect();
                next_name = (!v.is_empty()).then_some(v);
            }
            continue;
        }
        if t.is_empty() {
            continue;
        }
        if t.starts_with('[') {
            match t.to_ascii_lowercase().as_str() {
                "[interface]" if !seen_interface => {
                    seen_interface = true;
                    section = Section::Interface;
                }
                "[interface]" => return Err(format!("line {line}: a second [Interface]")),
                "[peer]" => {
                    if conf.peers.len() >= MAX_PEERS {
                        return Err(format!("line {line}: more than {MAX_PEERS} peers"));
                    }
                    conf.peers.push(ConfPeer { name: next_name.take(), ..ConfPeer::default() });
                    section = Section::Peer;
                }
                _ => return Err(format!("line {line}: unknown section '{}'", cut(t))),
            }
            continue;
        }
        let Some((k, v)) = t.split_once('=') else {
            return Err(format!("line {line}: expected Key = value, not '{}'", cut(t)));
        };
        let (k, v) = (k.trim(), v.trim());
        let key = k.to_ascii_lowercase();
        match section {
            Section::None => return Err(format!("line {line}: '{}' before [Interface] or [Peer]", cut(k))),
            Section::Interface => {
                let i = &mut conf.interface;
                match key.as_str() {
                    "privatekey" => i.private_key = Some(v.to_owned()),
                    "listenport" => i.listen_port = Some(number(v, k, line)?),
                    "address" => i.address.extend(nets(v, line)?),
                    "mtu" => i.mtu = Some(number(v, k, line)?),
                    "dns" => {
                        // Search domains (names) are wg-quick's too; only
                        // the servers are kept.
                        i.dns.extend(v.split(',').filter_map(|x| x.trim().parse::<IpAddr>().ok()).take(MAX_DNS));
                        i.dns.truncate(MAX_DNS);
                    }
                    _ => note(&mut conf.ignored, k),
                }
            }
            Section::Peer => {
                let Some(p) = conf.peers.last_mut() else {
                    continue;
                };
                match key.as_str() {
                    "publickey" => {
                        p.public_key = WgKey::parse(v).ok_or_else(|| format!("line {line}: PublicKey is not a WireGuard key"))?;
                    }
                    "presharedkey" => p.preshared_key = Some(v.to_owned()),
                    "allowedips" => {
                        let more = nets(v, line)?;
                        if p.allowed.len().saturating_add(more.len()) > MAX_ALLOWED {
                            return Err(format!("line {line}: more than {MAX_ALLOWED} prefixes"));
                        }
                        p.allowed.extend(more);
                    }
                    "endpoint" => {
                        p.endpoint = Some(parse_endpoint(v).ok_or_else(|| format!("line {line}: Endpoint '{}' is not host:port", cut(v)))?);
                    }
                    "persistentkeepalive" => {
                        p.keepalive = Some(if v.eq_ignore_ascii_case("off") { 0 } else { number(v, k, line)? });
                    }
                    _ => note(&mut conf.ignored, k),
                }
            }
        }
    }
    if let Some((n, _)) = conf.peers.iter().enumerate().find(|(_, p)| p.public_key.is_empty()) {
        return Err(format!("peer {} has no PublicKey", n.saturating_add(1)));
    }
    Ok(conf)
}

fn note(ignored: &mut Vec<String>, k: &str) {
    const MAX_IGNORED: usize = 16;
    let k = cut(k);
    if ignored.len() < MAX_IGNORED && !ignored.contains(&k) {
        ignored.push(k);
    }
}

fn join<T: ToString>(v: &[T]) -> String {
    v.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
}

/// Write a `wg-quick` file. Keys go as given (the caller puts a
/// placeholder where the reader may not see one).
pub fn render(c: &Conf) -> String {
    let mut out = String::from("[Interface]\n");
    let i = &c.interface;
    if let Some(k) = &i.private_key {
        out.push_str(&format!("PrivateKey = {k}\n"));
    }
    if let Some(p) = i.listen_port {
        out.push_str(&format!("ListenPort = {p}\n"));
    }
    if !i.address.is_empty() {
        out.push_str(&format!("Address = {}\n", join(&i.address)));
    }
    if !i.dns.is_empty() {
        out.push_str(&format!("DNS = {}\n", join(&i.dns)));
    }
    if let Some(m) = i.mtu {
        out.push_str(&format!("MTU = {m}\n"));
    }
    for p in &c.peers {
        out.push('\n');
        if let Some(n) = &p.name {
            out.push_str(&format!("# Name = {n}\n"));
        }
        out.push_str(&format!("[Peer]\nPublicKey = {}\n", p.public_key));
        if let Some(k) = &p.preshared_key {
            out.push_str(&format!("PresharedKey = {k}\n"));
        }
        if !p.allowed.is_empty() {
            out.push_str(&format!("AllowedIPs = {}\n", join(&p.allowed)));
        }
        if let Some((h, port)) = &p.endpoint {
            out.push_str(&format!("Endpoint = {}\n", endpoint_text(h, *port)));
        }
        if let Some(k) = p.keepalive.filter(|k| *k > 0) {
            out.push_str(&format!("PersistentKeepalive = {k}\n"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    const K1: &str = "YAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const K2: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";

    #[test]
    fn reads_a_wg_quick_file() {
        let text = format!(
            "[Interface]\nPrivateKey = {K1}\nListenPort = 51820\nAddress = 10.9.0.2/32, fd00::2/128\nDNS = 10.9.0.1, lan\nMTU = 1412\nPostUp = iptables -A x\n\n\
             # Name = matriz\n[Peer]\nPublicKey = {K2}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = vpn.exemplo.com.br:13231\nPersistentKeepalive = 25\n\
             [peer]\npublickey={K1}\nallowedips=10.0.0.1\nendpoint=[2001:db8::1]:51820\n"
        );
        let c = parse(&text).unwrap();
        assert_eq!(c.interface.listen_port, Some(51820));
        assert_eq!(c.interface.address.len(), 2);
        assert_eq!(c.interface.dns, vec!["10.9.0.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(c.interface.mtu, Some(1412));
        assert_eq!(c.ignored, vec!["PostUp".to_owned()]);
        assert_eq!(c.peers.len(), 2);
        assert_eq!(c.peers[0].name.as_deref(), Some("matriz"));
        assert_eq!(c.peers[0].endpoint.as_ref().map(|(h, p)| (h.as_str(), *p)), Some(("vpn.exemplo.com.br", 13231)));
        assert_eq!(c.peers[1].allowed, vec!["10.0.0.1/32".parse::<IpNet>().unwrap()]);
        assert_eq!(c.peers[1].endpoint.as_ref().map(|(h, p)| endpoint_text(h, *p)), Some("[2001:db8::1]:51820".into()));
        // What it writes reads back the same.
        assert_eq!(parse(&render(&c)).map(|mut b| {
            b.ignored = c.ignored.clone();
            b
        }), Ok(c));
    }

    #[test]
    fn refuses_what_it_cannot_use_and_says_the_line() {
        for (text, want) in [
            ("PrivateKey = x", "line 1"),
            ("[Interface]\n[Interface]", "second [Interface]"),
            ("[Wat]", "unknown section"),
            ("[Peer]\nAllowedIPs = 10.0.0.0/8", "no PublicKey"),
            ("[Peer]\nPublicKey = nope", "line 2: PublicKey"),
            ("[Interface]\nListenPort = 99999", "line 2"),
            ("[Peer]\nEndpoint = vpn.example.com", "host:port"),
            ("[Interface]\njust text", "Key = value"),
        ] {
            let e = parse(text).unwrap_err();
            assert!(e.contains(want), "{text:?} → {e}");
        }
        assert!(parse(&"#".repeat(MAX_LINE + 1)).is_err());
    }

    proptest! {
        /// Hostile text never panics, and an error never echoes more than
        /// a short cut of it.
        #[test]
        fn any_text_is_read_or_refused(text in "(\\[Interface\\]|\\[Peer\\]|[A-Za-z]{0,12} ?= ?[ -~]{0,60}|# Name = [ -~]{0,20}|[ -~]{0,80})(\n(\\[Interface\\]|\\[Peer\\]|[A-Za-z]{0,12} ?= ?[ -~]{0,60}|[ -~]{0,80})){0,12}") {
            if let Err(e) = parse(&text) {
                prop_assert!(e.len() < 200, "{e}");
            }
        }

        #[test]
        fn endpoints_round_trip(a in any::<[u8; 4]>(), port in 1u16..) {
            let ip = std::net::Ipv4Addr::from(a);
            let host = WgHost::from(IpAddr::V4(ip));
            let back = parse_endpoint(&endpoint_text(&host, port));
            prop_assert_eq!(back, Some((host, port)));
        }
    }
}
