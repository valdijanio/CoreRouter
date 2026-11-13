//! `/ip dns encrypted-service` (G4.1zf): DNS over TLS for the LAN (RFC
//! 7858), answered by the same forwarder, cache and `allowed_from` as UDP
//! and TCP 53. The daemon's `dns-tls` service listens; this area keeps its
//! settings, says what it is doing and what the operator should know.
//!
//! - `dot=yes` without a certificate makes `/certificate` `dns-server`
//!   (self-signed, the router's names and addresses) in the same change:
//!   Android's automatic Private DNS does not check it, and a certificate
//!   the operator imports replaces it with `certificate=<name>`.
//! - `get` adds the checks: the forwarder must answer the LAN
//!   (`allow_remote_requests`), the certificate (expiry, the router's LAN
//!   addresses in its SAN for verified discovery, RFC 9462 §4.2), and the
//!   input firewall from the LAN and from the Internet (`firewall_diag`).

use corerouter_model::RoutingTable;
use corerouter_model::dns_encrypted::{EncryptedService, EncryptedStatus, IDLE_SECS, MAX_SESSIONS};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, opt_u32};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

/// The certificate `dot=yes` makes when none is named.
pub(crate) const AUTO_CERTIFICATE: &str = "dns-server";
/// A host on the Internet, for the input firewall check (RFC 5737).
const INTERNET: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 7));

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "ip.dns.encrypted-service.set",
        "DNS Encrypted Service",
        ["IP", "DNS"],
        None,
        "{dot?: bool (DNS over TLS, RFC 7858; needs allow_remote_requests), dot_port?: int 1..65535 (default 853; never 53), certificate?: string (a /certificate with its key; empty with dot=yes: makes dns-server), idle_timeout_secs?: int 1..3600 (default 30), max_sessions?: int 1..100000 (default 1000; a quarter per address), announce_ddr?: bool (answer _dns.resolver.arpa, RFC 9462; default yes)} → {dot, dot_port, certificate, idle_timeout_secs, max_sessions, announce_ddr, notes: [string]}",
        always,
        set
    ),
    cmd!(query "ip.dns.encrypted-service.get", "DNS Encrypted Service", [], None,
        "{} → {dot, dot_port, certificate, idle_timeout_secs, max_sessions, announce_ddr, allow_remote_requests, status: stopped|listening|error, listening, last_error, fingerprint, sessions, accepted, handshakes, resumed, handshake_failures, queries, refused, over_limit, checks: [{level: ok|info|warning|error, check, message}]}",
        always, get),
];

fn settings(e: &EncryptedService) -> Value {
    json!({
        "dot": e.dot,
        "dot_port": e.dot_port,
        "certificate": e.certificate,
        "idle_timeout_secs": e.idle_timeout_secs,
        "max_sessions": e.max_sessions,
        "announce_ddr": e.announce_ddr,
    })
}

fn ranged(p: &Value, key: &str, range: std::ops::RangeInclusive<u32>) -> Result<Option<u32>> {
    match opt_u32(p, key)? {
        Some(v) if !range.contains(&v) => Err(EngineError::bad(key, format!("must be {range:?}"))),
        v => Ok(v),
    }
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let mut e = s.store().candidate().ip.dns.encrypted_service.clone();
    let mut notes = Vec::new();
    if let Some(v) = opt_bool(p, "dot")? {
        e.dot = v;
    }
    if let Some(port) = opt_u32(p, "dot_port")? {
        let port = u16::try_from(port)
            .ok()
            .filter(|p| *p != 0 && *p != 53)
            .ok_or_else(|| EngineError::bad("dot_port", "1..65535 and never 53 (RFC 7858 §3.1: 853 unless agreed)"))?;
        e.dot_port = port;
    }
    if let Some(v) = ranged(p, "idle_timeout_secs", IDLE_SECS)? {
        e.idle_timeout_secs = v;
    }
    if let Some(v) = ranged(p, "max_sessions", MAX_SESSIONS)? {
        e.max_sessions = v;
    }
    if let Some(v) = opt_bool(p, "announce_ddr")? {
        e.announce_ddr = v;
    }
    if let Some(name) = opt_str(p, "certificate")? {
        e.certificate = super::certificate::pick(&s.store().candidate().system.certificates, name)?;
    }
    if e.dot && e.dot_port == s.store().candidate().system.web.www_ssl.port && s.store().candidate().system.web.www_ssl.enabled {
        return Err(EngineError::bad("dot_port", format!("www-ssl already listens on {}", e.dot_port)));
    }
    if e.dot && e.certificate.is_empty() {
        // The router's own names and addresses, self-signed: what Android
        // takes; a certificate the operator imports replaces it.
        if s.store().candidate().system.certificates.get(AUTO_CERTIFICATE).is_none() {
            super::certificate::add(s, &json!({"name": AUTO_CERTIFICATE, "comment": "DNS over TLS (made by ip.dns.encrypted-service)"}))
                .map_err(|err| match err {
                    EngineError::BadParam { reason, .. } => EngineError::bad("certificate", format!("no certificate given and none could be made: {reason}")),
                    other => other,
                })?;
            notes.push(format!("made /certificate {AUTO_CERTIFICATE} (self-signed, the router's names and addresses)"));
        }
        e.certificate = super::certificate::pick(&s.store().candidate().system.certificates, AUTO_CERTIFICATE)?;
    }
    if e.dot && !s.store().candidate().ip.dns.allow_remote_requests {
        notes.push("allow_remote_requests is off: nothing answers until it is on (DNS over TLS uses the LAN forwarder)".to_owned());
    }
    if let Some(why) = e.problem() {
        return Err(EngineError::bad("dot", why));
    }
    let mut out = settings(&e);
    s.store_mut().candidate_mut().ip.dns.encrypted_service = e;
    if let Some(o) = out.as_object_mut() {
        o.insert("notes".into(), json!(notes));
    }
    Ok(out)
}

fn check(level: &str, check: &str, message: impl Into<String>) -> Value {
    json!({"level": level, "check": check, "message": message.into()})
}

/// What the operator should know about the service as configured.
fn checks(s: &mut Session) -> Vec<Value> {
    let cfg = s.store().candidate().clone();
    let e = &cfg.ip.dns.encrypted_service;
    let mut out = Vec::new();
    if !e.dot {
        return out;
    }
    if !cfg.ip.dns.allow_remote_requests {
        out.push(check("error", "forwarder", "allow_remote_requests is off: DNS over TLS answers nothing (it is the LAN forwarder, encrypted)"));
    }
    let nets = s.dns_allowed_networks(&cfg);
    // The router's own addresses on the networks that may ask: where the
    // LAN's clients reach it (and what DHCP hands them as their DNS).
    let mine: Vec<std::net::IpAddr> = cfg
        .ip
        .addresses
        .iter()
        .filter(|a| !a.disabled && nets.iter().any(|n| n.contains(&a.address.addr())))
        .map(|a| a.address.addr())
        .collect();
    if nets.is_empty() {
        out.push(check("warning", "allowed_from", "allowed_from stands for no network yet: only the router itself may ask"));
    }
    if let Some(c) = cfg.system.certificates.get(&e.certificate) {
        match crate::x509::inspect(&c.certificate) {
            Ok(info) => {
                let now = s.now().and_then(|n| i64::try_from(n).ok());
                if now.is_some_and(|n| n > info.not_after) {
                    out.push(check("error", "certificate", format!("{} expired: clients that check it fall back to plain DNS or fail (Android with a host name: no Internet)", e.certificate)));
                } else if now.is_some_and(|n| info.not_after - n < 30 * 86_400) {
                    out.push(check("warning", "certificate", format!("{} expires in under 30 days", e.certificate)));
                }
                let missing: Vec<String> = mine.iter().filter(|ip| !info.covers(&ip.to_string())).map(ToString::to_string).collect();
                if info.self_signed {
                    out.push(check(
                        "info",
                        "certificate",
                        format!(
                            "{} is self-signed: Android's automatic Private DNS uses it; iOS, macOS and Windows only after being told to trust it",
                            e.certificate
                        ),
                    ));
                }
                if !missing.is_empty() {
                    out.push(check(
                        "info",
                        "certificate",
                        format!(
                            "{} does not name {} in its subjectAltName: clients that verify discovery by address (RFC 9462 §4.2) will not use it",
                            e.certificate,
                            missing.join(", ")
                        ),
                    ));
                }
            }
            Err(err) => out.push(check("error", "certificate", err)),
        }
    }
    // The input firewall, as a TCP packet to the port: from the LAN it
    // must pass; from the Internet it should not (allowed_from still
    // closes it before any TLS, but the router is then a target).
    let port = e.dot_port;
    if let Some(dst) = mine.first().copied() {
        let lan_host = nets.iter().find(|n| n.contains(&dst)).and_then(|n| n.hosts().find(|h| *h != dst));
        let in_if = cfg.ip.addresses.iter().find(|a| a.address.addr() == dst).map(|a| a.interface.to_string());
        if let (Some(src), Some(iface)) = (lan_host, in_if) {
            let packet = json!({"src": src, "dst": dst, "protocol": "tcp", "dst_port": port, "in_interface": iface});
            if let Ok(v) = super::firewall_diag::test(s, &packet) {
                if v.get("fate").and_then(Value::as_str) == Some("delivered") {
                    out.push(check("ok", "firewall", format!("the input firewall lets TCP {port} in from the LAN ({iface})")));
                } else {
                    let by = v.pointer("/decided_by/summary").and_then(Value::as_str).unwrap_or("a rule");
                    out.push(check("warning", "firewall", format!("the input firewall drops TCP {port} from the LAN ({iface}, {by}): clients fall back to plain DNS")));
                }
            }
        }
    }
    if let Some((wan, Some(dst))) = super::wireguard_preview::wan_of(&cfg, INTERNET, &RoutingTable::Main) {
        let packet = json!({"src": INTERNET, "dst": dst, "protocol": "tcp", "dst_port": port, "in_interface": wan.to_string()});
        if let Ok(v) = super::firewall_diag::test(s, &packet)
            && v.get("fate").and_then(Value::as_str) == Some("delivered")
        {
            out.push(check(
                "warning",
                "firewall",
                format!(
                    "the input firewall lets TCP {port} in from the Internet ({wan}): allowed_from still closes strangers before TLS, but a drop rule on {wan} keeps them off the port"
                ),
            ));
        }
    }
    out
}

fn get(s: &mut Session, _: &Value) -> Result<Value> {
    let cfg = s.store().candidate();
    let e = cfg.ip.dns.encrypted_service.clone();
    let remote = cfg.ip.dns.allow_remote_requests;
    let running_on = s.store().running().ip.dns.encrypted_service.dot && s.store().running().ip.dns.allow_remote_requests;
    let status = if running_on {
        s.ext::<EncryptedStatus>().cloned().unwrap_or_default()
    } else {
        EncryptedStatus { status: "stopped".into(), ..EncryptedStatus::default() }
    };
    let status = if status.status.is_empty() { EncryptedStatus { status: "stopped".into(), ..status } } else { status };
    let mut out = settings(&e);
    if let (Some(o), Ok(Value::Object(st))) = (out.as_object_mut(), serde_json::to_value(&status)) {
        o.extend(st);
        o.insert("allow_remote_requests".into(), json!(remote));
    }
    let checks = checks(s);
    if let Some(o) = out.as_object_mut() {
        o.insert("checks".into(), json!(checks));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lab() -> Session {
        let mut s = Session::virtual_lab();
        s.tick(1_794_441_600);
        s.execute("ip.address.add", &json!({"address": "192.168.88.1/24", "interface": "ether2"})).unwrap();
        s.execute("interface.list.member.add", &json!({"list": "LAN", "interface": "ether2"})).ok();
        s
    }

    #[test]
    fn dot_on_makes_its_certificate_and_says_what_is_missing() {
        let mut s = lab();
        let r = s.execute("ip.dns.encrypted-service.set", &json!({"dot": true})).unwrap();
        assert_eq!(r["certificate"], AUTO_CERTIFICATE);
        assert!(r["notes"][0].as_str().unwrap().contains("made /certificate dns-server"), "{r}");
        assert!(r["notes"][1].as_str().unwrap().contains("allow_remote_requests is off"), "{r}");
        let rows = s.execute("certificate.print", &json!({})).unwrap();
        assert_eq!(rows[0]["used_by"], json!(["dns-encrypted-service"]));
        let g = s.execute("ip.dns.encrypted-service.get", &json!({})).unwrap();
        assert_eq!(g["status"], "stopped", "no daemon in the lab");
        let checks: Vec<String> = g["checks"].as_array().unwrap().iter().map(|c| c["message"].as_str().unwrap().to_owned()).collect();
        assert!(checks.iter().any(|c| c.contains("allow_remote_requests is off")), "{checks:?}");
        assert!(checks.iter().any(|c| c.contains("self-signed")), "{checks:?}");
        // A certificate in use cannot go; turning DoT off keeps the name.
        assert!(s.execute("certificate.remove", &json!({"id": AUTO_CERTIFICATE})).is_err());
        s.execute("ip.dns.encrypted-service.set", &json!({"dot": false})).unwrap();
        assert_eq!(s.store().candidate().ip.dns.encrypted_service.certificate, AUTO_CERTIFICATE);
    }

    #[test]
    fn a_named_certificate_is_used_and_checked() {
        let mut s = lab();
        s.execute("certificate.add", &json!({"name": "lan", "subject_alt_name": "router.lan"})).unwrap();
        s.execute("ip.dns.set", &json!({"allow_remote_requests": true})).unwrap();
        let r = s.execute("ip.dns.encrypted-service.set", &json!({"dot": true, "certificate": "lan", "dot_port": 8853})).unwrap();
        assert_eq!((r["certificate"].as_str(), r["dot_port"].as_u64()), (Some("lan"), Some(8853)));
        assert!(s.store().candidate().system.certificates.get(AUTO_CERTIFICATE).is_none(), "nothing made");
        let g = s.execute("ip.dns.encrypted-service.get", &json!({})).unwrap();
        let checks = g["checks"].to_string();
        assert!(checks.contains("does not name 192.168.88.1"), "{checks}");
        // Renaming the certificate follows into the service.
        s.execute("certificate.set", &json!({"id": "lan", "name": "lan2"})).unwrap();
        assert_eq!(s.store().candidate().ip.dns.encrypted_service.certificate, "lan2");
    }

    #[test]
    fn bad_values_change_nothing() {
        let mut s = lab();
        let before = s.store().candidate().clone();
        for p in [
            json!({"dot_port": 53}),
            json!({"dot_port": 0}),
            json!({"dot_port": 70000}),
            json!({"idle_timeout_secs": 0}),
            json!({"max_sessions": 0}),
            json!({"certificate": "nope"}),
        ] {
            assert!(s.execute("ip.dns.encrypted-service.set", &p).is_err(), "{p}");
        }
        assert_eq!(*s.store().candidate(), before);
        s.execute("ip.service.www-ssl.set", &json!({"enabled": true, "port": 853})).unwrap();
        assert!(s.execute("ip.dns.encrypted-service.set", &json!({"dot": true})).unwrap_err().to_string().contains("www-ssl"));
    }

    #[test]
    fn rollback_turns_it_off_again() {
        let mut s = lab();
        s.execute("config.mode.set", &json!({"mode": "transactional"})).unwrap();
        s.execute("ip.dns.encrypted-service.set", &json!({"dot": true})).unwrap();
        s.execute("config.discard", &json!({})).unwrap();
        assert!(!s.store().candidate().ip.dns.encrypted_service.dot);
        assert!(s.store().candidate().system.certificates.list.is_empty(), "the certificate it made went too");
    }
}
