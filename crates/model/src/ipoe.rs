//! IPoE subscribers (G4.3f): a DHCPv4 lease as a BNG session. The knobs
//! live on `/ip dhcp-server` (RouterOS' `use-radius`, and our `ipoe`,
//! `ipoe-username`, `ipoe-unknown`) and on `/ip dhcp-server lease`
//! (`rate-limit`); the local subscriber list is `/ppp secret` with
//! `service=ipoe` (the name is what [`IpoeUsername`] builds: the MAC by
//! default, or the circuit id of option 82).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::types::{MacAddr, ParseError};

/// RouterOS `use-radius` of `/ip dhcp-server`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UseRadius {
    /// No RADIUS (RouterOS' default).
    #[default]
    No,
    /// Each new client is asked about (Access-Request on its DISCOVER) and
    /// its lease is accounted.
    Yes,
    /// Leases are accounted, nobody is asked.
    Accounting,
}

impl UseRadius {
    pub const ALL: [Self; 3] = [Self::No, Self::Yes, Self::Accounting];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::No => "no",
            Self::Yes => "yes",
            Self::Accounting => "accounting",
        }
    }
}

impl fmt::Display for UseRadius {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for UseRadius {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|v| v.as_str() == s.trim())
            .ok_or_else(|| ParseError::new("use-radius", s, "expected no, yes or accounting"))
    }
}

/// What names an IPoE subscriber: the RADIUS `User-Name` and the `/ppp
/// secret` looked up (Juniper's `username-include`, in its common forms).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IpoeUsername {
    /// The client's MAC, `AA:BB:CC:DD:EE:FF` (RouterOS).
    #[default]
    Mac,
    /// Option 82's circuit id (RFC 3046 §3.1): the OLT port / ONU.
    CircuitId,
    /// Option 82's remote id (RFC 3046 §3.2).
    RemoteId,
    /// `<circuit-id>/<remote-id>`.
    CircuitRemote,
}

impl IpoeUsername {
    pub const ALL: [Self; 4] = [Self::Mac, Self::CircuitId, Self::RemoteId, Self::CircuitRemote];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mac => "mac",
            Self::CircuitId => "circuit-id",
            Self::RemoteId => "remote-id",
            Self::CircuitRemote => "circuit-remote",
        }
    }

    /// Whether the name comes from option 82.
    pub fn needs_agent(self) -> bool {
        self != Self::Mac
    }

    /// The name of a client with this MAC and option 82 ids (as text, see
    /// `proto_dhcp::server::agent::text`). `None`: the id it needs is not
    /// there (the client is not served: no name, no session).
    pub fn name(self, mac: MacAddr, circuit: Option<&str>, remote: Option<&str>) -> Option<String> {
        let some = |v: Option<&str>| v.filter(|t| !t.is_empty()).map(str::to_owned);
        match self {
            Self::Mac => Some(mac.to_string()),
            Self::CircuitId => some(circuit),
            Self::RemoteId => some(remote),
            Self::CircuitRemote => Some(format!("{}/{}", some(circuit)?, some(remote)?)),
        }
    }
}

impl fmt::Display for IpoeUsername {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for IpoeUsername {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL.into_iter().find(|v| v.as_str() == s.trim()).ok_or_else(|| {
            ParseError::new(
                "ipoe-username",
                s,
                "expected mac, circuit-id, remote-id or circuit-remote",
            )
        })
    }
}

/// What a client without a `/ppp secret` (service `ipoe`) gets when
/// RADIUS is not asked (`use-radius` not `yes`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IpoeUnknown {
    /// Served with the server's settings and the default profile (an open
    /// network that still gets sessions, accounting and the policer).
    #[default]
    Accept,
    /// Not served: only the secrets' clients get an address.
    Reject,
}

impl IpoeUnknown {
    pub const ALL: [Self; 2] = [Self::Accept, Self::Reject];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Reject => "reject",
        }
    }
}

impl fmt::Display for IpoeUnknown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for IpoeUnknown {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|v| v.as_str() == s.trim())
            .ok_or_else(|| ParseError::new("ipoe-unknown", s, "expected accept or reject"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_follow_the_choice() {
        let mac: MacAddr = "02:00:00:00:00:0a".parse().unwrap();
        assert_eq!(IpoeUsername::Mac.name(mac, None, None).unwrap(), "02:00:00:00:00:0A");
        assert_eq!(IpoeUsername::CircuitId.name(mac, Some("olt1/1/3"), None).unwrap(), "olt1/1/3");
        assert!(IpoeUsername::CircuitId.name(mac, None, Some("x")).is_none());
        assert!(IpoeUsername::RemoteId.name(mac, Some("c"), Some("")).is_none());
        assert_eq!(
            IpoeUsername::CircuitRemote.name(mac, Some("c"), Some("r")).unwrap(),
            "c/r"
        );
        for v in IpoeUsername::ALL {
            assert_eq!(v.as_str().parse::<IpoeUsername>().unwrap(), v);
        }
        for v in UseRadius::ALL {
            assert_eq!(v.as_str().parse::<UseRadius>().unwrap(), v);
        }
        assert!("maybe".parse::<UseRadius>().is_err());
        assert_eq!("reject".parse::<IpoeUnknown>().unwrap(), IpoeUnknown::Reject);
    }
}
