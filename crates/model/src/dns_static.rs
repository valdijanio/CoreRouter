//! `/ip dns static` (G4.1b): names the router answers itself, before the
//! cache and the upstream servers. Fields and defaults follow RouterOS v7:
//! one flat entry whose `type` says which fields count. Entries are matched
//! top to bottom, `regexp` entries before `name` entries (RouterOS).

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::dns::MAX_TTL_SECS;
use crate::types::ItemId;

/// RouterOS `ttl` default: one day.
pub const DEFAULT_TTL_SECS: u32 = 86_400;
/// More entries than this is a hosts file, which is the adlist's job (G4.1d).
pub const MAX_ENTRIES: usize = 10_000;
pub const MAX_REGEXP_LEN: usize = 256;
/// RFC 1035 §3.3.14: TXT is strings of up to 255 bytes; one entry holds
/// a few of them.
pub const MAX_TEXT_LEN: usize = 1024;
pub const MAX_FORWARD_TO: usize = 4;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum StaticType {
    #[default]
    A,
    Aaaa,
    Cname,
    /// Ask `forward_to` instead of the configured servers.
    Fwd,
    Mx,
    Ns,
    /// The name does not exist (blocks it, and its subdomains with
    /// `match_subdomain`).
    Nxdomain,
    Srv,
    Txt,
}

impl StaticType {
    pub const ALL: [Self; 9] = [
        Self::A,
        Self::Aaaa,
        Self::Cname,
        Self::Fwd,
        Self::Mx,
        Self::Ns,
        Self::Nxdomain,
        Self::Srv,
        Self::Txt,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Cname => "CNAME",
            Self::Fwd => "FWD",
            Self::Mx => "MX",
            Self::Ns => "NS",
            Self::Nxdomain => "NXDOMAIN",
            Self::Srv => "SRV",
            Self::Txt => "TXT",
        }
    }
}

impl std::str::FromStr for StaticType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let up = s.trim().to_ascii_uppercase();
        Self::ALL
            .into_iter()
            .find(|t| t.as_str() == up)
            .ok_or_else(|| "must be A, AAAA, CNAME, FWD, MX, NS, NXDOMAIN, SRV or TXT".into())
    }
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_zero(n: &u16) -> bool {
    *n == 0
}

fn default_ttl() -> u32 {
    DEFAULT_TTL_SECS
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticEntry {
    pub id: ItemId,
    /// The name answered (lowercase, no final dot); empty with `regexp`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// A regular expression matched against the lowercase name instead.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub regexp: String,
    #[serde(default, rename = "type")]
    pub rtype: StaticType,
    /// A (IPv4) or AAAA (IPv6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cname: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forward_to: Vec<IpAddr>,
    /// FWD to a `/ip dns forwarders` group by name (G4.1d) instead of
    /// `forward_to` (RouterOS writes both as `forward-to`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub forwarder: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mx_exchange: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub mx_preference: u16,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ns: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub srv_target: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub srv_port: u16,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub srv_priority: u16,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub srv_weight: u16,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub text: String,
    #[serde(default = "default_ttl")]
    pub ttl_secs: u32,
    /// `name` also answers for every name under it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub match_subdomain: bool,
    /// Put the addresses answered for this entry in this firewall address
    /// list, for their TTL (+ `address_list_extra_time_secs`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub address_list: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

impl StaticEntry {
    pub fn new(id: ItemId) -> Self {
        Self {
            id,
            name: String::new(),
            regexp: String::new(),
            rtype: StaticType::A,
            address: None,
            cname: String::new(),
            forward_to: Vec::new(),
            forwarder: String::new(),
            mx_exchange: String::new(),
            mx_preference: 0,
            ns: String::new(),
            srv_target: String::new(),
            srv_port: 0,
            srv_priority: 0,
            srv_weight: 0,
            text: String::new(),
            ttl_secs: DEFAULT_TTL_SECS,
            match_subdomain: false,
            address_list: String::new(),
            disabled: false,
            comment: String::new(),
        }
    }

    /// Why this entry cannot be committed, if anything is wrong. The
    /// regular expression itself is compiled by `proto-dns`.
    pub fn problem(&self) -> Option<String> {
        match (self.name.is_empty(), self.regexp.is_empty()) {
            (true, true) => return Some("a static entry needs name or regexp".into()),
            (false, false) => return Some("name and regexp cannot both be set".into()),
            _ => {}
        }
        if !self.name.is_empty() && !host_name_ok(&self.name) {
            return Some(format!("name: '{}' is not a DNS name", shown(&self.name)));
        }
        if self.regexp.len() > MAX_REGEXP_LEN {
            return Some(format!("regexp longer than {MAX_REGEXP_LEN} characters"));
        }
        if self.ttl_secs > MAX_TTL_SECS {
            return Some(format!("ttl_secs must be at most {MAX_TTL_SECS} (RFC 2181 §8)"));
        }
        let target = |key: &str, v: &str| -> Option<String> {
            if v.is_empty() {
                Some(format!("type {} needs {key}", self.rtype.as_str()))
            } else if !host_name_ok(v) {
                Some(format!("{key}: '{}' is not a DNS name", shown(v)))
            } else {
                None
            }
        };
        match self.rtype {
            StaticType::A => match self.address {
                Some(IpAddr::V4(_)) => None,
                _ => Some("type A needs an IPv4 address".into()),
            },
            StaticType::Aaaa => match self.address {
                Some(IpAddr::V6(_)) => None,
                _ => Some("type AAAA needs an IPv6 address".into()),
            },
            StaticType::Cname => target("cname", &self.cname),
            StaticType::Mx => target("mx_exchange", &self.mx_exchange),
            StaticType::Ns => target("ns", &self.ns),
            StaticType::Srv => target("srv_target", &self.srv_target),
            StaticType::Fwd if !self.forwarder.is_empty() => {
                if self.forward_to.is_empty() {
                    None
                } else {
                    Some("forward_to: servers or one forwarders group, not both".into())
                }
            }
            StaticType::Fwd => {
                if self.forward_to.is_empty() || self.forward_to.len() > MAX_FORWARD_TO {
                    Some(format!("type FWD needs forward_to: 1..={MAX_FORWARD_TO} servers"))
                } else if self
                    .forward_to
                    .iter()
                    .any(|ip| !crate::dns::usable_server(*ip))
                {
                    Some("forward_to: unspecified, multicast or broadcast address".into())
                } else {
                    None
                }
            }
            StaticType::Txt => {
                if self.text.is_empty() || self.text.len() > MAX_TEXT_LEN {
                    Some(format!("type TXT needs text of 1..={MAX_TEXT_LEN} bytes"))
                } else {
                    None
                }
            }
            StaticType::Nxdomain => None,
        }
    }

    /// The value column of `print` (`192.0.2.1`, `10 mail.example`…).
    pub fn data(&self) -> String {
        match self.rtype {
            StaticType::A | StaticType::Aaaa => {
                self.address.map(|a| a.to_string()).unwrap_or_default()
            }
            StaticType::Cname => self.cname.clone(),
            StaticType::Fwd if !self.forwarder.is_empty() => self.forwarder.clone(),
            StaticType::Fwd => self
                .forward_to
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(","),
            StaticType::Mx => format!("{} {}", self.mx_preference, self.mx_exchange),
            StaticType::Ns => self.ns.clone(),
            StaticType::Nxdomain => String::new(),
            StaticType::Srv => format!(
                "{} {} {} {}",
                self.srv_priority, self.srv_weight, self.srv_port, self.srv_target
            ),
            StaticType::Txt => self.text.clone(),
        }
    }
}

fn shown(s: &str) -> String {
    s.chars().take(64).collect()
}

/// A host name as text: labels of 1..=63 letters, digits, `-` and `_`, at
/// most 253 characters (RFC 1035 §2.3.4; `_` for SRV-style names).
pub fn host_name_ok(name: &str) -> bool {
    let n = name.strip_suffix('.').unwrap_or(name);
    !n.is_empty()
        && n.len() <= 253
        && n.split('.').all(|l| {
            (1..=63).contains(&l.len())
                && l.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsStatic {
    /// A block list (G0.21).
    pub entries: crate::cow_list::CowList<StaticEntry>,
    pub next_id: u32,
}

impl DnsStatic {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.next_id == 0
    }

    pub fn next_id(&mut self) -> ItemId {
        self.next_id = self.next_id.saturating_add(1);
        ItemId(self.next_id)
    }

    /// The first problem, with the entry it is about.
    pub fn problem(&self) -> Option<String> {
        if self.entries.len() > MAX_ENTRIES {
            return Some(format!("at most {MAX_ENTRIES} static DNS entries"));
        }
        self.entries
            .iter()
            .find_map(|e| e.problem().map(|p| format!("static entry {}: {p}", e.id)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(f: impl FnOnce(&mut StaticEntry)) -> StaticEntry {
        let mut e = StaticEntry::new(ItemId(1));
        e.name = "nas.lan".into();
        e.address = Some("192.168.88.10".parse().unwrap());
        f(&mut e);
        e
    }

    #[test]
    fn entries_are_checked_by_type() {
        assert_eq!(entry(|_| {}).problem(), None);
        assert!(entry(|e| e.address = Some("2001:db8::1".parse().unwrap())).problem().is_some());
        assert!(entry(|e| e.regexp = ".*".into()).problem().is_some(), "both");
        assert!(entry(|e| e.name = "bad name".into()).problem().is_some());
        assert!(entry(|e| e.rtype = StaticType::Cname).problem().is_some());
        assert_eq!(
            entry(|e| {
                e.rtype = StaticType::Cname;
                e.cname = "nas2.lan".into();
            })
            .problem(),
            None
        );
        assert!(entry(|e| e.rtype = StaticType::Fwd).problem().is_some());
        assert_eq!(entry(|e| e.rtype = StaticType::Nxdomain).problem(), None);
    }

    #[test]
    fn config_stays_small() {
        let e = entry(|_| {});
        let v = serde_json::to_value(&e).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"id": "*1", "name": "nas.lan", "type": "A",
                "address": "192.168.88.10", "ttl_secs": 86400})
        );
        let back: StaticEntry = serde_json::from_value(v).unwrap();
        assert_eq!(back, e);
        assert_eq!("aaaa".parse::<StaticType>(), Ok(StaticType::Aaaa));
    }
}
