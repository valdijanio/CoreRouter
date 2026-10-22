//! Network value types. Every constructor validates; parsing never panics.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid {kind} '{input}': {reason}")]
pub struct ParseError {
    pub kind: &'static str,
    pub input: String,
    pub reason: &'static str,
}

impl ParseError {
    pub(crate) fn new(kind: &'static str, input: &str, reason: &'static str) -> Self {
        // Hostile input may be huge: keep only a bounded prefix in the message.
        let input: String = input.chars().take(64).collect();
        Self {
            kind,
            input,
            reason,
        }
    }
}

/// Implements Display/Serialize/Deserialize through `Display` + `FromStr`.
macro_rules! string_serde {
    ($t:ty) => {
        impl Serialize for $t {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.collect_str(self)
            }
        }
        impl<'de> Deserialize<'de> for $t {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let raw = String::deserialize(d)?;
                raw.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

/// Autonomous System Number (RFC 6793, 4-byte). Accepts asplain (`65000`)
/// and asdot (`1.10`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Asn(pub u32);

impl Asn {
    /// AS_TRANS (RFC 6793) — never valid as a local or peer AS.
    pub const TRANS: Asn = Asn(23456);

    pub fn is_private(self) -> bool {
        (64512..=65534).contains(&self.0) || (4_200_000_000..=4_294_967_294).contains(&self.0)
    }

    pub fn is_reserved(self) -> bool {
        self.0 == 0 || self == Self::TRANS || self.0 == 65535 || self.0 == u32::MAX
    }
}

impl FromStr for Asn {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        let s = s
            .strip_prefix("AS")
            .or_else(|| s.strip_prefix("as"))
            .unwrap_or(s);
        if let Some((hi, lo)) = s.split_once('.') {
            let hi: u16 = hi
                .parse()
                .map_err(|_| ParseError::new("ASN", s, "asdot high part must be 0..=65535"))?;
            let lo: u16 = lo
                .parse()
                .map_err(|_| ParseError::new("ASN", s, "asdot low part must be 0..=65535"))?;
            return Ok(Asn((u32::from(hi) << 16) | u32::from(lo)));
        }
        s.parse::<u32>()
            .map(Asn)
            .map_err(|_| ParseError::new("ASN", s, "expected 0..=4294967295 or asdot X.Y"))
    }
}

impl fmt::Display for Asn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Serialize for Asn {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u32(self.0)
    }
}

impl<'de> Deserialize<'de> for Asn {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Raw {
            Num(u32),
            Text(String),
        }
        match Raw::deserialize(d)? {
            Raw::Num(n) => Ok(Asn(n)),
            Raw::Text(t) => t.parse().map_err(serde::de::Error::custom),
        }
    }
}

/// 802.1Q VLAN id, 1..=4094 (0 and 4095 are reserved).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct VlanId(u16);

impl VlanId {
    pub fn new(id: u16) -> Result<Self, ParseError> {
        if (1..=4094).contains(&id) {
            Ok(Self(id))
        } else {
            Err(ParseError::new(
                "VLAN id",
                &id.to_string(),
                "must be 1..=4094",
            ))
        }
    }
    pub fn get(self) -> u16 {
        self.0
    }
}

impl<'de> Deserialize<'de> for VlanId {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        VlanId::new(u16::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

/// EUI-48 MAC address, `AA:BB:CC:DD:EE:FF` (also accepts `-`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl FromStr for MacAddr {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut out = [0u8; 6];
        let mut parts = s.trim().split([':', '-']);
        for byte in out.iter_mut() {
            let part = parts
                .next()
                .ok_or_else(|| ParseError::new("MAC", s, "expected 6 octets"))?;
            if part.len() != 2 {
                return Err(ParseError::new("MAC", s, "each octet is 2 hex digits"));
            }
            *byte = u8::from_str_radix(part, 16)
                .map_err(|_| ParseError::new("MAC", s, "invalid hex digit"))?;
        }
        if parts.next().is_some() {
            return Err(ParseError::new("MAC", s, "expected 6 octets"));
        }
        Ok(MacAddr(out))
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02X}:{b:02X}:{c:02X}:{d:02X}:{e:02X}:{g:02X}")
    }
}
string_serde!(MacAddr);

/// Interface name with Linux rules: 1..=15 bytes (IFNAMSIZ - 1), ASCII
/// alphanumerics plus `-`, `_`, `.`; never `.` or `..`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IfName(String);

impl IfName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for IfName {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() || s.len() > 15 {
            return Err(ParseError::new("interface name", s, "must be 1..=15 bytes"));
        }
        if s == "." || s == ".." {
            return Err(ParseError::new("interface name", s, "reserved name"));
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        {
            return Err(ParseError::new(
                "interface name",
                s,
                "allowed: ASCII letters, digits, '-', '_', '.'",
            ));
        }
        Ok(IfName(s.to_owned()))
    }
}

impl fmt::Display for IfName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
string_serde!(IfName);

/// MikroTik-style item id, displayed as `*1`, `*2A` (hex).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ItemId(pub u32);

impl FromStr for ItemId {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex = s.trim().strip_prefix('*').unwrap_or(s.trim());
        u32::from_str_radix(hex, 16)
            .map(ItemId)
            .map_err(|_| ParseError::new("item id", s, "expected *<hex>"))
    }
}

impl fmt::Display for ItemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "*{:X}", self.0)
    }
}
string_serde!(ItemId);

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn asn_forms() {
        assert_eq!("65000".parse::<Asn>().unwrap(), Asn(65000));
        assert_eq!("AS65000".parse::<Asn>().unwrap(), Asn(65000));
        assert_eq!("1.10".parse::<Asn>().unwrap(), Asn(65546));
        assert!("1.70000".parse::<Asn>().is_err());
        assert!(Asn::TRANS.is_reserved());
        assert!(Asn(64512).is_private());
    }

    #[test]
    fn vlan_bounds() {
        assert!(VlanId::new(0).is_err());
        assert!(VlanId::new(4095).is_err());
        assert_eq!(VlanId::new(100).unwrap().get(), 100);
        assert!(serde_json::from_str::<VlanId>("4095").is_err());
    }

    #[test]
    fn ifname_rules() {
        assert!("ether1".parse::<IfName>().is_ok());
        assert!("vlan100.ether1".parse::<IfName>().is_ok());
        assert!("a-very-long-interface".parse::<IfName>().is_err());
        assert!("eth 0".parse::<IfName>().is_err());
        assert!("..".parse::<IfName>().is_err());
    }

    #[test]
    fn mac_and_item_roundtrip() {
        let mac: MacAddr = "aa:bb:cc:00:11:22".parse().unwrap();
        assert_eq!(mac.to_string(), "AA:BB:CC:00:11:22");
        assert!("aa:bb:cc:00:11".parse::<MacAddr>().is_err());
        let id: ItemId = "*1F".parse().unwrap();
        assert_eq!(id, ItemId(31));
        assert_eq!(id.to_string(), "*1F");
    }

    proptest! {
        #[test]
        fn parsers_never_panic(s in ".{0,64}") {
            let _ = s.parse::<Asn>();
            let _ = s.parse::<IfName>();
            let _ = s.parse::<MacAddr>();
            let _ = s.parse::<ItemId>();
        }
    }
}
