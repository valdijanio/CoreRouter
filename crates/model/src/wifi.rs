//! `/interface wifi` (G1.30): a Wi-Fi radio in station mode, the router as a
//! client of somebody's network (management, or an uplink). An interface of
//! type `wifi` ([`crate::InterfaceKind::Wifi`]) exists because the card
//! does, like an Ethernet port; what is stored here is the network it joins.
//! Names follow RouterOS v7's `/interface/wifi` (`mode`, `ssid`,
//! `passphrase`, `country`); one network per interface, as there.
//!
//! The passphrase is needed in clear (WPA2 derives the key from it and the
//! SSID, SAE proves knowledge of it), so it is sealed at rest like the PPP
//! secrets ([`crate::sealed`]).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::sealed::Sealed;
use crate::types::MacAddr;

/// IEEE 802.11: an SSID is at most 32 bytes.
pub const MAX_SSID: usize = 32;
/// IEEE 802.11i: a WPA passphrase is 8 to 63 printable ASCII characters…
pub const MIN_PASSPHRASE: usize = 8;
pub const MAX_PASSPHRASE: usize = 63;
/// …or the 256-bit key itself, as 64 hex digits (WPA2 only: SAE needs the
/// passphrase).
pub const PSK_HEX: usize = 64;

/// Why a station is never a bridge port (said by the command and by the
/// validation). The kernel refuses it too (`IFF_DONT_BRIDGE`,
/// `net/wireless/core.c`), and so do RouterOS (plain `station` mode) and
/// pfSense.
pub const NO_BRIDGE: &str = "a Wi-Fi station cannot be a bridge port: its frames carry three \
                             addresses, so only its own MAC gets through the access point. Route \
                             through it (with source NAT if the network behind the access point \
                             has no route back)";

/// Why an interface is not enabled with no country set (the validation's
/// message: a batch may set the two in any order).
pub const NO_COUNTRY: &str = "a Wi-Fi interface cannot be enabled before the country is set: it \
                              decides the channels and the power the radio may use. Set it: \
                              interface.wifi.country.set country=BR (your country's two letters)";

/// What the radio does. Only `station` for now (the AP is G1.30a); the
/// field is here so that a config written today reads the same then.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WifiMode {
    #[default]
    Station,
}

impl WifiMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Station => "station",
        }
    }
}

/// How the station proves itself to the network.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WifiSecurity {
    /// WPA3 where the access point offers it, else WPA2 (the access point's
    /// transition mode from the client's side). Never WEP or TKIP alone.
    #[default]
    Auto,
    /// WPA3-Personal only (SAE, management frame protection required).
    Wpa3,
    /// WPA2-Personal only.
    Wpa2,
    /// No encryption: anybody in range reads the traffic.
    Open,
}

impl WifiSecurity {
    pub const ALL: [Self; 4] = [Self::Auto, Self::Wpa3, Self::Wpa2, Self::Open];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Wpa3 => "wpa3",
            Self::Wpa2 => "wpa2",
            Self::Open => "open",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }

    /// The network has a passphrase.
    pub fn keyed(self) -> bool {
        self != Self::Open
    }
}

/// A band to stay in (`None`: whichever the network is on).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WifiBand {
    #[serde(rename = "2ghz")]
    Band2,
    #[serde(rename = "5ghz")]
    Band5,
    #[serde(rename = "6ghz")]
    Band6,
}

impl WifiBand {
    pub const ALL: [Self; 3] = [Self::Band2, Self::Band5, Self::Band6];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Band2 => "2ghz",
            Self::Band5 => "5ghz",
            Self::Band6 => "6ghz",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }

    /// The band of a channel's centre frequency, MHz.
    pub fn of_mhz(mhz: u32) -> Option<Self> {
        match mhz {
            2400..=2500 => Some(Self::Band2),
            5150..=5895 => Some(Self::Band5),
            5925..=7125 => Some(Self::Band6),
            _ => None,
        }
    }

    /// The frequencies a scan is kept to, MHz, inclusive.
    pub fn range_mhz(self) -> (u32, u32) {
        match self {
            Self::Band2 => (2400, 2500),
            Self::Band5 => (5150, 5895),
            Self::Band6 => (5925, 7125),
        }
    }
}

/// The settings of one Wi-Fi interface: `interface.wifi.set`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WifiStation {
    #[serde(skip_serializing_if = "is_station")]
    pub mode: WifiMode,
    /// The network's name; empty: none chosen yet, the radio stays idle.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub ssid: String,
    #[serde(skip_serializing_if = "is_auto")]
    pub security: WifiSecurity,
    /// Sealed at rest ([`crate::sealed`]).
    #[serde(skip_serializing_if = "Sealed::is_empty")]
    pub passphrase: Sealed,
    /// The network does not announce its name: probe for it by name.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub hidden: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub band: Option<WifiBand>,
    /// Only this access point (its BSSID).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bssid: Option<MacAddr>,
}

fn is_station(m: &WifiMode) -> bool {
    *m == WifiMode::Station
}

fn is_auto(s: &WifiSecurity) -> bool {
    *s == WifiSecurity::Auto
}

/// A country as the regulatory database names it: ISO 3166-1 alpha-2, two
/// upper-case letters (`BR`). Which channels and how much power the radio
/// may use depend on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Country([u8; 2]);

impl Country {
    pub fn as_str(&self) -> &str {
        // Two ASCII upper-case letters by construction.
        std::str::from_utf8(&self.0).unwrap_or("00")
    }
}

impl FromStr for Country {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let b = s.trim().as_bytes();
        match b {
            [a, c] if a.is_ascii_alphabetic() && c.is_ascii_alphabetic() => {
                Ok(Self([a.to_ascii_uppercase(), c.to_ascii_uppercase()]))
            }
            _ => Err(format!(
                "'{}' is not a country code: two letters, as in ISO 3166-1 (BR, US, DE)",
                s.chars().take(8).collect::<String>()
            )),
        }
    }
}

impl fmt::Display for Country {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for Country {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Country {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// What every radio of the router shares: `interface.wifi.country.set`.
/// Linux has one regulatory domain per system, not per card.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WifiSettings {
    /// `None`: not said. No interface is enabled without it: in the world
    /// domain the radio may not transmit on 5 GHz at all, and a wrong
    /// country is a radio transmitting where it must not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<Country>,
}

impl WifiSettings {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// Why `ssid` cannot be a network's name, if it cannot. Printable text
/// only: the name goes to logs, tables and the supplicant's text protocol.
pub fn ssid_problem(ssid: &str) -> Option<String> {
    if ssid.is_empty() {
        return Some("the network's name (SSID) is empty".into());
    }
    if ssid.len() > MAX_SSID {
        return Some(format!(
            "the SSID has {} bytes; IEEE 802.11 allows {MAX_SSID}",
            ssid.len()
        ));
    }
    if ssid.chars().any(char::is_control) {
        return Some("the SSID has a control character".into());
    }
    None
}

/// Why `key` cannot be this network's passphrase, if it cannot. `key` is
/// never part of the message.
pub fn passphrase_problem(key: &str, security: WifiSecurity) -> Option<String> {
    if !security.keyed() {
        return (!key.is_empty())
            .then(|| "an open network has no passphrase (security=open)".to_owned());
    }
    let hex = key.len() == PSK_HEX && key.bytes().all(|b| b.is_ascii_hexdigit());
    if hex {
        // SAE proves knowledge of the passphrase itself.
        return (security != WifiSecurity::Wpa2).then(|| {
            "a 64-digit key works with WPA2 only (WPA3 needs the passphrase): use the \
             passphrase, or security=wpa2"
                .to_owned()
        });
    }
    let n = key.len();
    if !(MIN_PASSPHRASE..=MAX_PASSPHRASE).contains(&n) {
        return Some(format!(
            "the passphrase has {n} characters; WPA takes {MIN_PASSPHRASE} to {MAX_PASSPHRASE} \
             (or the 64-digit key, with security=wpa2)"
        ));
    }
    if !key.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return Some("the passphrase has a character outside printable ASCII".into());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IfName, Interface, InterfaceKind};

    #[test]
    fn an_interface_round_trips_and_an_idle_radio_stores_nothing() {
        let idle = Interface::new(
            "wifi1".parse::<IfName>().unwrap(),
            InterfaceKind::Wifi(Box::default()),
        );
        let text = serde_json::to_string(&idle).unwrap();
        assert!(text.contains(r#""kind":{"type":"wifi"}"#), "{text}");
        assert_eq!(serde_json::from_str::<Interface>(&text).unwrap(), idle);
        assert_eq!(idle.kind.label(), "wifi");

        let st = WifiStation {
            ssid: "Casa".into(),
            security: WifiSecurity::Wpa3,
            passphrase: Sealed::from_box("$cr1$abc".into()),
            hidden: true,
            band: Some(WifiBand::Band5),
            bssid: Some("d8:47:32:aa:bb:cc".parse().unwrap()),
            ..WifiStation::default()
        };
        let i = Interface::new("wifi1".parse().unwrap(), InterfaceKind::Wifi(Box::new(st)));
        let text = serde_json::to_string(&i).unwrap();
        for want in [
            r#""ssid":"Casa""#,
            r#""security":"wpa3""#,
            r#""band":"5ghz""#,
            r#""hidden":true"#,
            r#""passphrase":"$cr1$abc""#,
        ] {
            assert!(text.contains(want), "{want} in {text}");
        }
        assert!(!text.contains("mode"), "the default mode is not written: {text}");
        assert_eq!(serde_json::from_str::<Interface>(&text).unwrap(), i);
        // A field this version does not know is refused, not dropped.
        let bad = text.replace(r#""hidden":true"#, r#""hiden":true"#);
        assert!(serde_json::from_str::<Interface>(&bad).is_err());
    }

    #[test]
    fn a_config_from_before_wifi_still_loads() {
        // `system` without `wifi`, and no interface of the new type.
        let old = r#"{"system":{"identity":"r1"},"interfaces":{"ether1":{"name":"ether1","kind":{"type":"ethernet"}}}}"#;
        let cfg: crate::Config = serde_json::from_str(old).unwrap();
        assert_eq!(cfg.system.wifi, WifiSettings::default());
        // And the default writes nothing: an older version reads it back.
        let text = serde_json::to_string(&cfg).unwrap();
        assert!(!text.contains("wifi"), "{text}");
    }

    #[test]
    fn countries() {
        assert_eq!("br".parse::<Country>().unwrap().as_str(), "BR");
        assert_eq!(" US ".parse::<Country>().unwrap().to_string(), "US");
        for bad in ["", "B", "BRA", "B1", "00", "ç", "\0\0"] {
            assert!(bad.parse::<Country>().is_err(), "{bad:?}");
        }
        let s = WifiSettings {
            country: Some("BR".parse().unwrap()),
        };
        let text = serde_json::to_string(&s).unwrap();
        assert_eq!(text, r#"{"country":"BR"}"#);
        assert_eq!(serde_json::from_str::<WifiSettings>(&text).unwrap(), s);
        assert!(serde_json::from_str::<WifiSettings>(r#"{"country":"brazil"}"#).is_err());
    }

    #[test]
    fn ssid_and_passphrase_rules() {
        assert!(ssid_problem("Casa do Valdi").is_none());
        assert!(ssid_problem(&"x".repeat(32)).is_none());
        assert!(ssid_problem("").is_some());
        assert!(ssid_problem(&"x".repeat(33)).is_some());
        assert!(ssid_problem("a\nb").is_some());
        // Bytes, not characters: 17 two-byte letters do not fit.
        assert!(ssid_problem(&"ç".repeat(17)).is_some());

        use WifiSecurity::{Auto, Open, Wpa2, Wpa3};
        assert!(passphrase_problem("12345678", Auto).is_none());
        assert!(passphrase_problem(&"p".repeat(63), Wpa3).is_none());
        for (key, sec) in [
            ("1234567", Auto),
            ("", Wpa2),
            (&*"p".repeat(64), Auto),
            ("senha com ç", Auto),
            ("tab\tinside", Wpa2),
            ("anything", Open),
        ] {
            let why = passphrase_problem(key, sec).unwrap();
            // The key never leaks into the message.
            assert!(key.is_empty() || !why.contains(key), "{why}");
        }
        let hex = "a".repeat(64);
        assert!(passphrase_problem(&hex, Wpa2).is_none());
        assert!(passphrase_problem(&hex, Auto).unwrap().contains("WPA2 only"));
        assert!(passphrase_problem(&hex, Wpa3).is_some());
        assert!(passphrase_problem("", Open).is_none());
    }

    #[test]
    fn bands() {
        assert_eq!(WifiBand::of_mhz(2437), Some(WifiBand::Band2));
        assert_eq!(WifiBand::of_mhz(5220), Some(WifiBand::Band5));
        assert_eq!(WifiBand::of_mhz(6115), Some(WifiBand::Band6));
        assert_eq!(WifiBand::of_mhz(900), None);
        for b in WifiBand::ALL {
            assert_eq!(WifiBand::parse(b.as_str()), Some(b));
            let (lo, hi) = b.range_mhz();
            assert_eq!(WifiBand::of_mhz(lo), Some(b));
            assert_eq!(WifiBand::of_mhz(hi), Some(b));
        }
        for s in WifiSecurity::ALL {
            assert_eq!(WifiSecurity::parse(s.as_str()), Some(s));
        }
    }
}
