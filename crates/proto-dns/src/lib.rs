//! L2 — DNS over `hickory-proto` messages: the router's own resolver
//! (G4.1a: TTL cache, server failover), and the LAN forwarder (G4.1b:
//! `server`, a chain of stages in front of the same resolver and cache).
//! The full server on `hickory-server` (G4.1c) builds on the same config
//! (`/ip dns`, docs/architecture.md "DNS", docs/dns.md).
//! PTR and the Team Cymru TXT answers give MTR hops a name and an AS
//! number (G6.3b).
//!
//! Contract shared by every `proto-*` crate: `validate` inspects the
//! candidate and returns issues; the engine refuses to commit while any exist.

pub mod adlist;
pub mod asn;
pub mod cache;
pub mod dig;
pub mod encrypted;
pub mod message;
pub mod resolver;
pub mod reverse;
pub mod server;

use corerouter_model::dns::AllowedFrom;
use corerouter_model::{Config, Issue};

/// Validate `/ip dns` and `/ip dns static` in the candidate.
pub fn validate(cfg: &Config) -> Vec<Issue> {
    let mut out: Vec<Issue> = cfg
        .ip
        .dns
        .problem()
        .map(|m| Issue::new("ip.dns", m))
        .into_iter()
        .collect();
    for item in &cfg.ip.dns.allowed_from {
        if let Ok(AllowedFrom::List(name)) = AllowedFrom::parse(item)
            && cfg.interface_lists.get(&name).is_none()
        {
            out.push(Issue::new(
                "ip.dns",
                format!("allowed_from: no interface list '{name}'"),
            ));
        }
    }
    if let Err(why) = check_secure(&cfg.ip.dns.use_doh_server) {
        out.push(Issue::new("ip.dns", format!("use_doh_server: {why}")));
    }
    if let Some(m) = cfg.ip.dns_forwarders.problem() {
        out.push(Issue::new("ip.dns.forwarders", m));
    }
    for g in &cfg.ip.dns_forwarders.entries {
        for u in &g.doh_servers {
            if let Err(why) = check_secure(u) {
                out.push(Issue::new(
                    "ip.dns.forwarders",
                    format!("forwarder {}: doh_servers: {why}", g.name),
                ));
            }
        }
    }
    for e in &cfg.ip.dns_static.entries {
        if !e.forwarder.is_empty() && cfg.ip.dns_forwarders.get(&e.forwarder).is_none() {
            out.push(Issue::new(
                "ip.dns.static",
                format!(
                    "static entry {}: no forwarders group '{}'",
                    e.id, e.forwarder
                ),
            ));
        }
    }
    if let Some(m) = cfg.ip.dns_adlist.problem() {
        out.push(Issue::new("ip.dns.adlist", m));
    }
    if let Some(m) = cfg.ip.dns_static.problem() {
        out.push(Issue::new("ip.dns.static", m));
    }
    for e in &cfg.ip.dns_static.entries {
        if !e.regexp.is_empty()
            && let Err(why) = check_regexp(&e.regexp)
        {
            out.push(Issue::new(
                "ip.dns.static",
                format!("static entry {}: regexp: {why}", e.id),
            ));
        }
    }
    out
}

/// Whether `url` is a usable encrypted server address (`""`: none).
pub fn check_secure(url: &str) -> Result<(), String> {
    if url.is_empty() {
        return Ok(());
    }
    encrypted::SecureServer::parse(url, true).map(|_| ())
}

/// Whether `pattern` compiles as a static entry's `regexp`.
pub fn check_regexp(pattern: &str) -> Result<(), String> {
    server::stage_statics_compile(pattern).map(|_| ())
}
