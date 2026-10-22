//! L2 — DHCP.
//!
//! - [`v4`]: DHCPv4 codec over `dhcproto` (hostile input: bounded, never
//!   panics), shared by the client (G4.7) and the future server (G4.2);
//! - [`client`]: the DHCPv4 client state machine, pure (the engine runs
//!   it on its service clock, the HAL carries the bytes);
//! - [`optval`]: RouterOS' option value syntax;
//! - [`lab`]: the virtual lab's simulated DHCP server.
//!
//! Contract shared by every `proto-*` crate: `validate` inspects the
//! candidate and returns issues; the engine refuses to commit while any exist.

pub mod client;
pub mod lab;
pub mod optval;
pub mod v4;

use std::collections::BTreeSet;

use corerouter_model::dhcp_client::{
    MAX_ALLOWED, MAX_CLIENTS, MAX_EXTRA, MAX_HOST_NAME, MAX_VALUE_TEXT,
};
use corerouter_model::route::{table_id, table_of};
use corerouter_model::{Config, DhcpClient, InterfaceKind, Issue};

use crate::optval::Vars;

/// Option codes the client fills in itself (or that only a server sends);
/// `extra_options` may not use them. 12, 60 and 61 have their own fields.
pub const RESERVED_CODES: [u8; 11] = [0, 12, 50, 52, 53, 54, 55, 57, 60, 61, 255];

/// Validate this subsystem's part of the candidate: the DHCP clients.
pub fn validate(cfg: &Config) -> Vec<Issue> {
    let mut out = Vec::new();
    if cfg.ip.dhcp_clients.len() > MAX_CLIENTS {
        out.push(Issue::new(
            "ip.dhcp_clients",
            format!("at most {MAX_CLIENTS} DHCP clients"),
        ));
    }
    let mut seen = BTreeSet::new();
    for c in &cfg.ip.dhcp_clients {
        let at = |field: &str| format!("ip.dhcp_clients[{}].{field}", c.id);
        if !seen.insert(&c.interface) {
            out.push(Issue::new(
                at("interface"),
                format!("'{}' already has a DHCP client", c.interface),
            ));
        }
        for (field, why) in client_issues(cfg, c) {
            out.push(Issue::new(at(field), why));
        }
    }
    out
}

/// What is wrong with `c` in `cfg`, as (field, message). The engine's
/// `ip.dhcp-client.*` commands report the first one as a parameter error.
pub fn client_issues(cfg: &Config, c: &DhcpClient) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    match cfg.interfaces.get(&c.interface) {
        None => out.push((
            "interface",
            format!("interface '{}' does not exist", c.interface),
        )),
        Some(i) if matches!(i.kind, InterfaceKind::Vrf { .. }) => out.push((
            "interface",
            format!(
                "'{}' is a VRF; run the client on one of its members",
                c.interface
            ),
        )),
        Some(i) => {
            if let Some(b) = &i.bridge {
                out.push((
                    "interface",
                    format!(
                        "'{}' is a port of bridge '{b}'; run the client on '{b}' instead",
                        c.interface
                    ),
                ));
            }
        }
    }
    if c.default_route_distance == 0 {
        out.push(("default_route_distance", "must be 1..=255".into()));
    }
    if let Some(t) = &c.default_route_table {
        let own = table_of(cfg, &c.interface);
        if table_id(cfg, t).is_none() {
            out.push((
                "default_route_table",
                format!("routing table '{t}' does not exist (create it with ip.vrf.add)"),
            ));
        } else if *t != own {
            out.push((
                "default_route_table",
                format!(
                    "'{}' routes in table '{own}', so its routes go there; leave \
                     default_route_table empty or set it to '{own}'",
                    c.interface
                ),
            ));
        }
    }
    if let Err(why) = check_host_name(&c.host_name) {
        out.push(("host_name", why));
    }
    if let Err(e) = settings(c, "x", [0; 6]) {
        out.push(e);
    }
    if c.allowed_servers.len() > MAX_ALLOWED {
        out.push(("allowed_servers", format!("at most {MAX_ALLOWED} servers")));
    }
    out
}

/// Option 12 rules: letters, digits, `-`, `.`, `_`; at most 63 bytes.
pub fn check_host_name(h: &str) -> Result<(), String> {
    if h.len() > MAX_HOST_NAME {
        return Err(format!("at most {MAX_HOST_NAME} characters"));
    }
    if !h
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
    {
        return Err("only letters, digits, '-', '.' and '_'".into());
    }
    Ok(())
}

/// What client `c` sends, in bytes, on an interface with MAC `mac`
/// (`identity` is the host name when `host_name` is empty). The error names
/// the field to fix.
pub fn settings(
    c: &DhcpClient,
    identity: &str,
    mac: [u8; 6],
) -> Result<client::Settings, (&'static str, String)> {
    let host_name = if c.host_name.is_empty() {
        // The identity may hold anything; keep what option 12 allows.
        identity
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || ch == '-' {
                    ch
                } else {
                    '-'
                }
            })
            .take(MAX_HOST_NAME)
            .collect()
    } else {
        c.host_name.clone()
    };
    let vars = Vars {
        host_name: &host_name,
        mac,
    };
    let text = |field: &'static str, v: &str| -> Result<Vec<u8>, (&'static str, String)> {
        if v.len() > MAX_VALUE_TEXT {
            return Err((field, format!("at most {MAX_VALUE_TEXT} characters")));
        }
        optval::parse_or_text(v, &vars).map_err(|e| (field, e))
    };
    let client_id = if c.client_id.is_empty() {
        let mut id = vec![1u8];
        id.extend_from_slice(&mac);
        id
    } else {
        text("client_id", &c.client_id)?
    };
    let vendor_class = if c.vendor_class.is_empty() {
        Vec::new()
    } else {
        text("vendor_class", &c.vendor_class)?
    };
    if c.extra_options.len() > MAX_EXTRA {
        return Err(("extra_options", format!("at most {MAX_EXTRA} options")));
    }
    let mut extra: Vec<(u8, Vec<u8>)> = Vec::with_capacity(c.extra_options.len());
    for o in &c.extra_options {
        if RESERVED_CODES.contains(&o.code) {
            let why = match o.code {
                12 => "use host_name for option 12".to_owned(),
                60 => "use vendor_class for option 60".to_owned(),
                61 => "use client_id for option 61".to_owned(),
                n => format!("option {n} is set by the client itself"),
            };
            return Err(("extra_options", why));
        }
        if extra.iter().any(|(code, _)| *code == o.code) {
            return Err((
                "extra_options",
                format!("option {} is listed twice", o.code),
            ));
        }
        if o.value.len() > MAX_VALUE_TEXT {
            return Err((
                "extra_options",
                format!("option {}: at most {MAX_VALUE_TEXT} characters", o.code),
            ));
        }
        let bytes = optval::parse(&o.value, &vars)
            .map_err(|e| ("extra_options", format!("option {}: {e}", o.code)))?;
        extra.push((o.code, bytes));
    }
    Ok(client::Settings {
        mac,
        client_id,
        host_name,
        vendor_class,
        extra,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_model::{ExtraOption, Interface, ItemId, RoutingTable};

    fn cfg() -> Config {
        let mut cfg = Config::default();
        for n in ["ether1", "ether2"] {
            cfg.interfaces.insert(
                n.parse().unwrap(),
                Interface::new(n.parse().unwrap(), InterfaceKind::Ethernet),
            );
        }
        cfg
    }

    fn client(id: u32, iface: &str) -> DhcpClient {
        DhcpClient::new(ItemId(id), iface.parse().unwrap())
    }

    #[test]
    fn a_plain_client_is_valid() {
        let mut c = cfg();
        c.ip.dhcp_clients.push(client(1, "ether1"));
        assert!(validate(&c).is_empty(), "{:?}", validate(&c));
    }

    #[test]
    fn one_client_per_existing_interface() {
        let mut c = cfg();
        c.ip.dhcp_clients.push(client(1, "ether1"));
        c.ip.dhcp_clients.push(client(2, "ether1"));
        c.ip.dhcp_clients.push(client(3, "ether9"));
        let issues = validate(&c);
        assert!(issues.iter().any(
            |i| i.path == "ip.dhcp_clients[*2].interface" && i.message.contains("already has")
        ));
        assert!(issues.iter().any(|i| i.message.contains("does not exist")));
    }

    #[test]
    fn table_must_be_the_interfaces() {
        let mut c = cfg();
        let mut d = client(1, "ether1");
        d.default_route_table = Some(RoutingTable::Vrf("red".parse().unwrap()));
        c.ip.dhcp_clients.push(d);
        assert!(validate(&c)[0].message.contains("does not exist"));
        c.interfaces.insert(
            "red".parse().unwrap(),
            Interface::new("red".parse().unwrap(), InterfaceKind::Vrf { table: 1000 }),
        );
        assert!(validate(&c)[0].message.contains("routes in table 'main'"));
        c.interfaces
            .get_mut(&"ether1".parse().unwrap())
            .unwrap()
            .vrf = Some("red".parse().unwrap());
        assert!(validate(&c).is_empty(), "{:?}", validate(&c));
    }

    #[test]
    fn options_become_bytes() {
        let mut d = client(1, "ether1");
        d.client_id = "0xff00".into();
        d.vendor_class = "MSFT 5.0".into();
        d.extra_options = vec![ExtraOption {
            code: 77,
            value: "'wan'$(CLIENT_MAC)".into(),
        }];
        let s = settings(&d, "Core Router", [2, 0, 0, 0, 0, 7]).unwrap();
        assert_eq!(s.client_id, [0xff, 0]);
        assert_eq!(s.vendor_class, b"MSFT 5.0");
        assert_eq!(s.host_name, "Core-Router");
        assert_eq!(s.extra, vec![(77, b"wan\x02\0\0\0\0\x07".to_vec())]);
        d.client_id.clear();
        assert_eq!(
            settings(&d, "r", [2, 0, 0, 0, 0, 7]).unwrap().client_id,
            [1, 2, 0, 0, 0, 0, 7]
        );
        for code in [12, 53, 61] {
            d.extra_options = vec![ExtraOption {
                code,
                value: "0x00".into(),
            }];
            assert_eq!(settings(&d, "r", [0; 6]).unwrap_err().0, "extra_options");
        }
        d.extra_options = vec![ExtraOption {
            code: 77,
            value: "bare".into(),
        }];
        assert!(
            settings(&d, "r", [0; 6])
                .unwrap_err()
                .1
                .contains("in quotes")
        );
        d.extra_options.clear();
        d.host_name = "bad name!".into();
        let mut c = cfg();
        c.ip.dhcp_clients.push(d);
        assert!(validate(&c)[0].path.ends_with("host_name"));
    }
}
