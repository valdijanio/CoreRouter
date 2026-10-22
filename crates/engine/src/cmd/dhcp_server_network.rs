//! /ip dhcp-server network (G4.2a): what the clients of a subnet learn,
//! and the DNS zone their leases are named in. `print` carries the checks
//! of each network (the GUI's green and amber chips).

use corerouter_model::dhcp_server::DhcpNetwork;
use corerouter_proto_dhcp::server::checks;
use ipnet::Ipv4Net;
use serde_json::{Value, json};

use super::args::{opt_bool, opt_text, opt_u32, req_parse};
use super::dhcp_server::{check_rows, find, opt_ip, opt_ips, opt_ref, opt_strings, verdict};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "ip.dhcp-server.network.add",
        "Add DHCP Network",
        ["IP", "DHCP Server"],
        None,
        "{address: ipv4/prefix, gateway?: [ipv4] | string (option 3), netmask?: u32 (option 1 when it differs from the prefix; 0: the prefix's), dns_server?: [ipv4] | string (option 6; empty: the router itself when its DNS serves the LAN, else its own servers), dns_none?: bool (send no DNS server), domain?: string (option 15), ntp_server?: [ipv4] | string (option 42), wins_server?: [ipv4] | string (option 44), next_server?: ipv4 (siaddr, PXE), boot_file_name?: string (file, PXE; ≤127 bytes), dhcp_option?: [string] | string (option names), dhcp_option_set?: string, dns_zone?: string (a primary zone of ip.dns.zone: each lease gets <host>.<zone> and its PTR; empty: none), comment?: string} → {id, warnings}",
        always,
        add
    ),
    cmd!(
        "ip.dhcp-server.network.set",
        "Set DHCP Network",
        [],
        None,
        "{id: *hex | address, address?: ipv4/prefix, gateway?: [ipv4] | string, netmask?: u32, dns_server?: [ipv4] | string, dns_none?: bool, domain?: string, ntp_server?: [ipv4] | string, wins_server?: [ipv4] | string, next_server?: ipv4, boot_file_name?: string, dhcp_option?: [string] | string, dhcp_option_set?: string, dns_zone?: string, comment?: string} → {id, warnings}",
        has_networks,
        set
    ),
    cmd!(
        "ip.dhcp-server.network.remove",
        "Remove DHCP Network",
        [],
        None,
        "{id: *hex | address} → {id, address}",
        has_networks,
        remove
    ),
    cmd!(query "ip.dhcp-server.network.print", "DHCP Networks", [], None,
        "{} → [{id, address, gateway, netmask?, dns_server, dns_none, domain?, ntp_server, wins_server, next_server?, boot_file_name?, dhcp_option, dhcp_option_set?, dns_zone?, comment?, checks: [{label, level (ok | warn | error), text}]}]",
        always, print),
];

fn has_networks(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ip.dhcp_server.networks.is_empty() {
        Err("there are no DHCP networks (ip.dhcp-server.network.add)".into())
    } else {
        Ok(())
    }
}

fn apply(n: &mut DhcpNetwork, p: &Value) -> Result<()> {
    if p.get("address").is_some() {
        let a: Ipv4Net = req_parse(p, "address")?;
        n.address = a.trunc();
    }
    if let Some(v) = opt_ips(p, "gateway")? {
        n.gateway = v;
    }
    if let Some(m) = opt_u32(p, "netmask")? {
        if m > 32 {
            return Err(EngineError::bad("netmask", "0..=32"));
        }
        n.netmask = u8::try_from(m).ok().filter(|m| *m > 0);
    }
    if let Some(v) = opt_ips(p, "dns_server")? {
        n.dns_server = v;
    }
    if let Some(b) = opt_bool(p, "dns_none")? {
        n.dns_none = b;
    }
    if let Some(d) = opt_text(p, "domain", 255)? {
        n.domain = d.trim().trim_end_matches('.').to_owned();
    }
    if let Some(v) = opt_ips(p, "ntp_server")? {
        n.ntp_server = v;
    }
    if let Some(v) = opt_ips(p, "wins_server")? {
        n.wins_server = v;
    }
    if let Some(ip) = opt_ip(p, "next_server")? {
        n.next_server = ip;
    }
    if let Some(f) = opt_text(p, "boot_file_name", 127)? {
        n.boot_file_name = f;
    }
    if let Some(v) = opt_strings(p, "dhcp_option")? {
        n.dhcp_option = v;
    }
    if let Some(v) = opt_ref(p, "dhcp_option_set", &["none"])? {
        n.dhcp_option_set = v;
    }
    if let Some(z) = opt_ref(p, "dns_zone", &["none"])? {
        n.dns_zone = z.map(|z| corerouter_model::dns_zone::normalize_host(&z));
    }
    if let Some(c) = opt_text(p, "comment", 256)? {
        n.comment = c;
    }
    Ok(())
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let address: Ipv4Net = req_parse(p, "address")?;
    let d = &mut s.store_mut().candidate_mut().ip.dhcp_server;
    if d.networks.len() >= corerouter_model::dhcp_server::MAX_NETWORKS {
        return Err(EngineError::bad("address", "too many DHCP networks"));
    }
    let mut n = DhcpNetwork::new(d.next_id(), address);
    apply(&mut n, p)?;
    if d.networks.iter().any(|o| o.address == n.address) {
        return Err(EngineError::bad("address", format!("network {} exists", n.address)));
    }
    let id = n.id;
    d.networks.push(n);
    let warnings = verdict(s, "networks", id)?;
    Ok(json!({"id": id, "warnings": warnings}))
}

fn index(s: &Session, p: &Value) -> Result<usize> {
    // By id, or by the prefix as written.
    let nets = &s.store().candidate().ip.dhcp_server.networks;
    find(nets, p, |x| x.id, |_| None, "DHCP network").or_else(|e| {
        let want = super::args::opt_str(p, "id")?
            .and_then(|t| t.trim().parse::<Ipv4Net>().ok())
            .map(|n| n.trunc());
        want.and_then(|w| nets.iter().position(|n| n.address == w))
            .ok_or(e)
    })
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let i = index(s, p)?;
    let d = &mut s.store_mut().candidate_mut().ip.dhcp_server;
    let Some(mut n) = d.networks.get(i).cloned() else {
        return Err(EngineError::bad("id", "no such DHCP network"));
    };
    apply(&mut n, p)?;
    if d.networks.iter().enumerate().any(|(j, o)| j != i && o.address == n.address) {
        return Err(EngineError::bad("address", format!("network {} exists", n.address)));
    }
    let id = n.id;
    if let Some(slot) = d.networks.get_mut(i) {
        *slot = n;
    }
    let warnings = verdict(s, "networks", id)?;
    Ok(json!({"id": id, "warnings": warnings}))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let i = index(s, p)?;
    let n = s.store_mut().candidate_mut().ip.dhcp_server.networks.remove(i);
    Ok(json!({"id": n.id, "address": n.address}))
}

fn print(s: &mut Session, _: &Value) -> Result<Value> {
    let cand = s.store().candidate();
    let all = checks::checks(cand);
    let rows: Vec<Value> = cand
        .ip
        .dhcp_server
        .networks
        .iter()
        .map(|n| {
            let mut v = json!({
                "id": n.id,
                "address": n.address,
                "gateway": n.gateway,
                "dns_server": n.dns_server,
                "dns_none": n.dns_none,
                "ntp_server": n.ntp_server,
                "wins_server": n.wins_server,
                "dhcp_option": n.dhcp_option,
                "checks": check_rows(&all, "networks", n.id),
            });
            if let Some(o) = v.as_object_mut() {
                let mut put = |k: &str, val: Option<Value>| {
                    if let Some(val) = val {
                        o.insert(k.into(), val);
                    }
                };
                put("netmask", n.netmask.map(|m| json!(m)));
                put("domain", (!n.domain.is_empty()).then(|| json!(n.domain)));
                put("next_server", n.next_server.map(|a| json!(a)));
                put("boot_file_name", (!n.boot_file_name.is_empty()).then(|| json!(n.boot_file_name)));
                put("dhcp_option_set", n.dhcp_option_set.as_ref().map(|a| json!(a)));
                put("dns_zone", n.dns_zone.as_ref().map(|a| json!(a)));
                put("comment", (!n.comment.is_empty()).then(|| json!(n.comment)));
            }
            v
        })
        .collect();
    Ok(Value::Array(rows))
}
