//! `/ip dns forwarders` (G4.1d, RouterOS 7.17): named groups of upstream
//! servers. A static FWD entry sends its names to a group
//! (`forward_to: <name>`): plain servers (`dns_servers`), encrypted ones
//! (`doh_servers`: DoH `https://…` or DoT `tls://…`), or both.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::dns::{MAX_SERVERS, secure_url_problem, usable_server};
use crate::types::ItemId;

pub const MAX_GROUPS: usize = 64;
/// Encrypted servers per group.
pub const MAX_DOH_SERVERS: usize = 4;

fn yes() -> bool {
    true
}

fn is_true(b: &bool) -> bool {
    *b
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwarderEntry {
    pub id: ItemId,
    pub name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns_servers: Vec<IpAddr>,
    /// `https://host/path` (DoH) or `tls://host[:port][#name]` (DoT).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub doh_servers: Vec<String>,
    /// RouterOS: yes for a group (no in `/ip dns`).
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub verify_doh_cert: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

impl ForwarderEntry {
    pub fn new(id: ItemId) -> Self {
        Self {
            id,
            name: String::new(),
            dns_servers: Vec::new(),
            doh_servers: Vec::new(),
            verify_doh_cert: true,
            disabled: false,
            comment: String::new(),
        }
    }

    pub fn problem(&self) -> Option<String> {
        if !name_ok(&self.name) {
            let shown: String = self.name.chars().take(64).collect();
            return Some(format!(
                "name '{shown}': letters, digits, - _ and ., 1..=64, not an address"
            ));
        }
        if self.dns_servers.is_empty() && self.doh_servers.is_empty() {
            return Some("needs dns_servers or doh_servers".into());
        }
        if self.dns_servers.len() > MAX_SERVERS {
            return Some(format!("at most {MAX_SERVERS} dns_servers"));
        }
        if let Some(bad) = self.dns_servers.iter().find(|ip| !usable_server(**ip)) {
            return Some(format!("{bad} cannot be a DNS server"));
        }
        if self.doh_servers.len() > MAX_DOH_SERVERS {
            return Some(format!("at most {MAX_DOH_SERVERS} doh_servers"));
        }
        self.doh_servers
            .iter()
            .find_map(|u| secure_url_problem(u).map(|w| format!("doh_servers: {w}")))
    }
}

/// A group name: like an interface list's, and never an address (a FWD
/// entry's `forward_to` takes both).
pub fn name_ok(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        && name.parse::<IpAddr>().is_err()
        && name.bytes().any(|b| b.is_ascii_alphabetic())
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsForwarders {
    pub entries: Vec<ForwarderEntry>,
    pub next_id: u32,
}

impl DnsForwarders {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.next_id == 0
    }

    pub fn next_id(&mut self) -> ItemId {
        self.next_id = self.next_id.saturating_add(1);
        ItemId(self.next_id)
    }

    pub fn get(&self, name: &str) -> Option<&ForwarderEntry> {
        self.entries.iter().find(|e| e.name == name)
    }

    pub fn problem(&self) -> Option<String> {
        if self.entries.len() > MAX_GROUPS {
            return Some(format!("at most {MAX_GROUPS} forwarders"));
        }
        for (i, e) in self.entries.iter().enumerate() {
            if let Some(p) = e.problem() {
                return Some(format!("forwarder {}: {p}", e.id));
            }
            if self.entries.iter().skip(i + 1).any(|o| o.name == e.name) {
                return Some(format!("two forwarders named '{}'", e.name));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_are_checked() {
        let mut e = ForwarderEntry::new(ItemId(1));
        e.name = "corp".into();
        assert!(e.problem().unwrap().contains("needs"));
        e.dns_servers = vec!["10.0.0.53".parse().unwrap()];
        e.doh_servers = vec!["https://dns.example/dns-query".into(), "tls://1.1.1.1#one.one.one.one".into()];
        assert_eq!(e.problem(), None);
        e.doh_servers.push("http://plain.example/".into());
        assert!(e.problem().is_some());
        for bad in ["", "10.0.0.1", "123", "a b", &"x".repeat(65)] {
            assert!(!name_ok(bad), "{bad}");
        }
        let mut all = DnsForwarders::default();
        e.doh_servers.pop();
        all.entries = vec![e.clone(), e];
        assert!(all.problem().unwrap().contains("two"));
    }

    #[test]
    fn defaults_and_serde() {
        let e: ForwarderEntry =
            serde_json::from_str(r#"{"id":"*1","name":"g","dns_servers":["9.9.9.9"]}"#).unwrap();
        assert!(e.verify_doh_cert);
        assert!(serde_json::to_value(&e).unwrap().get("verify_doh_cert").is_none());
    }
}
