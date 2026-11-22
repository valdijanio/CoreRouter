//! The Service-Name table of a PPPoE server (G4.3k): one server per access
//! port with several services, each with its profile and what to do with a
//! PADI (Junos `service-name-tables`: terminate, delay, drop), plus the
//! rows for the empty name and for any other name.
//!
//! RouterOS has one `service-name` per server and one server per name; a
//! config with only `service_name` is read as the table it means
//! ([`PppoeServer::service_table`](crate::ppp::PppoeServer::service_table)),
//! and the first change through a command writes the table.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::ppp::MAX_PADO_DELAY;
use crate::types::ParseError;

/// Named rows per server (Junos: 512 on the whole router).
pub const MAX_SERVICES: usize = 64;
/// Longest Service-Name, bytes (it travels in a 16-bit TAG; access gear
/// rarely sends more than a few words).
pub const MAX_SERVICE_NAME: usize = 64;

/// What a row does with a PADI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceAction {
    /// PADO now.
    #[default]
    Terminate,
    /// PADO after the row's `pado_delay` (a backup BNG for the name).
    Delay,
    /// No PADO; a PADR gets Service-Name-Error (RFC 2516 §5.2, §5.4).
    Drop,
}

impl ServiceAction {
    pub const ALL: [Self; 3] = [Self::Terminate, Self::Delay, Self::Drop];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Terminate => "terminate",
            Self::Delay => "delay",
            Self::Drop => "drop",
        }
    }

    pub fn parse(t: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.as_str() == t.trim())
    }
}

/// The name a row matches: a Service-Name, the empty one, or any other
/// (Junos `empty` and `any`; those two words are not names here).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ServiceName {
    Name(String),
    Empty,
    Any,
}

impl ServiceName {
    pub fn is_special(&self) -> bool {
        !matches!(self, Self::Name(_))
    }
}

impl FromStr for ServiceName {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let t = s.trim();
        match t {
            "empty" | "" => Ok(Self::Empty),
            "any" | "*" => Ok(Self::Any),
            _ if t.len() > MAX_SERVICE_NAME => Err(ParseError::new(
                "service name",
                s,
                "at most 64 bytes",
            )),
            _ if t.chars().any(char::is_control) => Err(ParseError::new(
                "service name",
                s,
                "no control characters",
            )),
            _ => Ok(Self::Name(t.to_owned())),
        }
    }
}

impl fmt::Display for ServiceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(n) => f.write_str(n),
            Self::Empty => f.write_str("empty"),
            Self::Any => f.write_str("any"),
        }
    }
}

impl Serialize for ServiceName {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ServiceName {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?.parse().map_err(serde::de::Error::custom)
    }
}

/// One row of the table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PppoeService {
    pub name: ServiceName,
    /// The profile of its sessions (a secret's own profile still wins, as
    /// over `default_profile`); `None`: the server's `default_profile`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default)]
    pub action: ServiceAction,
    /// With `delay`: ms before the PADO, on top of the server's.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub pado_delay: u32,
    /// Sessions this row may hold; 0 = no limit (Junos `max-sessions`).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub max_sessions: u32,
    /// PADIs answered per second for this row; 0 = no limit.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub padi_limit: u32,
}

fn is_zero(v: &u32) -> bool {
    *v == 0
}

impl PppoeService {
    pub fn new(name: ServiceName, action: ServiceAction) -> Self {
        Self {
            name,
            profile: None,
            action,
            pado_delay: 0,
            max_sessions: 0,
            padi_limit: 0,
        }
    }

    /// Accepts the subscriber (a PADO comes, now or later).
    pub fn accepts(&self) -> bool {
        self.action != ServiceAction::Drop
    }

    /// What is wrong with the row alone.
    pub fn check(&self) -> Result<(), String> {
        if self.pado_delay > MAX_PADO_DELAY {
            return Err(format!("{}: pado_delay at most {MAX_PADO_DELAY} ms", self.name));
        }
        if self.action == ServiceAction::Delay && self.pado_delay == 0 {
            return Err(format!("{}: action=delay needs a pado_delay", self.name));
        }
        Ok(())
    }
}

/// The table RouterOS' `service-name` means: empty = every name served;
/// a name = that name and the empty one, nothing else.
pub fn from_service_name(service_name: &str) -> Vec<PppoeService> {
    let t = service_name.trim();
    let mut rows = Vec::new();
    if !t.is_empty() {
        rows.push(PppoeService::new(ServiceName::Name(t.to_owned()), ServiceAction::Terminate));
    }
    rows.push(PppoeService::new(ServiceName::Empty, ServiceAction::Terminate));
    rows.push(PppoeService::new(
        ServiceName::Any,
        if t.is_empty() { ServiceAction::Terminate } else { ServiceAction::Drop },
    ));
    rows
}

/// A table as stored: named rows in order, then exactly one `empty` and one
/// `any` row (added with their defaults when missing: terminate, as RFC
/// 2516 §9 recommends never refusing by name). Refuses duplicates.
pub fn normalize(rows: Vec<PppoeService>) -> Result<Vec<PppoeService>, String> {
    let mut named: Vec<PppoeService> = Vec::new();
    let (mut empty, mut any) = (None, None);
    for r in rows {
        r.check()?;
        match &r.name {
            ServiceName::Empty if empty.is_some() => {
                return Err("two rows for the empty Service-Name: which one answers would be a guess".into());
            }
            ServiceName::Any if any.is_some() => return Err("two 'any' rows".into()),
            ServiceName::Empty => empty = Some(r),
            ServiceName::Any => any = Some(r),
            ServiceName::Name(n) => {
                if named.iter().any(|x| x.name == r.name) {
                    return Err(format!("service name '{n}' twice"));
                }
                named.push(r);
            }
        }
    }
    if named.len() > MAX_SERVICES {
        return Err(format!("at most {MAX_SERVICES} service names per server"));
    }
    named.push(empty.unwrap_or_else(|| PppoeService::new(ServiceName::Empty, ServiceAction::Terminate)));
    named.push(any.unwrap_or_else(|| PppoeService::new(ServiceName::Any, ServiceAction::Terminate)));
    Ok(named)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_keywords() {
        assert_eq!("empty".parse::<ServiceName>().unwrap(), ServiceName::Empty);
        assert_eq!("".parse::<ServiceName>().unwrap(), ServiceName::Empty);
        assert_eq!("any".parse::<ServiceName>().unwrap(), ServiceName::Any);
        assert_eq!(" isp ".parse::<ServiceName>().unwrap(), ServiceName::Name("isp".into()));
        assert!("a\nb".parse::<ServiceName>().is_err());
        assert!("x".repeat(65).parse::<ServiceName>().is_err());
        let r: PppoeService = serde_json::from_str(r#"{"name":"any","action":"drop"}"#).unwrap();
        assert_eq!((r.name.clone(), r.action), (ServiceName::Any, ServiceAction::Drop));
        assert_eq!(serde_json::to_string(&r).unwrap(), r#"{"name":"any","action":"drop"}"#);
    }

    #[test]
    fn routeros_service_name_becomes_a_table() {
        let all = from_service_name("");
        assert_eq!(all.len(), 2);
        assert!(all.iter().all(PppoeService::accepts));
        let one = from_service_name("isp");
        assert_eq!(one.len(), 3);
        assert_eq!(one[0].name, ServiceName::Name("isp".into()));
        assert!(one[1].accepts() && !one[2].accepts());
    }

    #[test]
    fn normalize_orders_fills_and_refuses_duplicates() {
        let t = normalize(vec![
            PppoeService::new(ServiceName::Any, ServiceAction::Drop),
            PppoeService::new(ServiceName::Name("b".into()), ServiceAction::Terminate),
        ])
        .unwrap();
        assert_eq!(
            t.iter().map(|r| r.name.to_string()).collect::<Vec<_>>(),
            ["b", "empty", "any"]
        );
        assert_eq!(t[2].action, ServiceAction::Drop);
        let two_empty = vec![
            PppoeService::new(ServiceName::Empty, ServiceAction::Terminate),
            PppoeService::new(ServiceName::Empty, ServiceAction::Delay),
        ];
        assert!(normalize(two_empty).unwrap_err().contains("empty"));
        let dup = vec![
            PppoeService::new(ServiceName::Name("a".into()), ServiceAction::Terminate),
            PppoeService::new(ServiceName::Name("a".into()), ServiceAction::Drop),
        ];
        assert!(normalize(dup).is_err());
        let mut d = PppoeService::new(ServiceName::Name("a".into()), ServiceAction::Delay);
        assert!(normalize(vec![d.clone()]).is_err(), "delay without a delay");
        d.pado_delay = 200;
        assert!(normalize(vec![d]).is_ok());
    }
}
