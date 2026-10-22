//! `/ip dns zone` (G4.1c): authoritative zones, like a BIND `zone` statement.
//! RouterOS v7 has no zones (only `/ip dns static`), so names follow BIND,
//! Knot and PowerDNS where RouterOS has nothing, in RouterOS style (flat
//! fields, `_secs` suffixes).
//!
//! - A **primary** zone's data is here: the SOA from the zone's own fields,
//!   the other records in [`DnsZones::records`]. Its serial moves by itself
//!   on every change (`serial_policy`, RFC 1982 arithmetic in [`serial_gt`]).
//! - A **secondary** zone has only where to transfer it from (`primaries`);
//!   the records it gets by AXFR/IXFR are run-time state of the daemon.
//!
//! Records are flat, like `/ip dns static`: `type` says which fields count.

use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::dns::MAX_TTL_SECS;
use crate::dns_static::host_name_ok;
use crate::types::ItemId;

/// Default TTL of the records and the SOA (BIND/Knot examples use 1 h).
pub const DEFAULT_TTL_SECS: u32 = 3600;
/// SOA timers: RIPE-203 recommendations.
pub const DEFAULT_REFRESH_SECS: u32 = 86_400;
pub const DEFAULT_RETRY_SECS: u32 = 7200;
pub const DEFAULT_EXPIRE_SECS: u32 = 3_600_000;
/// SOA MINIMUM, the negative-caching TTL (RFC 2308 §4). RIPE-203 says 2
/// days, from before RFC 2308 gave the field this meaning; §5 suggests 1 to
/// 3 hours.
pub const DEFAULT_MINIMUM_SECS: u32 = 3600;
pub const MAX_MINIMUM_SECS: u32 = 604_800;
pub const MAX_ZONES: usize = 1000;
/// Records of all primary zones together (each config revision keeps a
/// copy; a zone bigger than this belongs in a dedicated server).
pub const MAX_RECORDS: usize = 50_000;
pub const MAX_ALLOW_TRANSFER: usize = 32;
pub const MAX_NOTIFY: usize = 16;
pub const MAX_PRIMARIES: usize = 8;
/// RFC 1035 §3.3.14: TXT is strings of up to 255 bytes; one record holds
/// a few of them.
pub const MAX_TEXT_LEN: usize = 2048;
/// RFC 8659 §4.1: the tag is 1..=15 letters and digits.
pub const MAX_CAA_TAG_LEN: usize = 15;
pub const MAX_CAA_VALUE_LEN: usize = 1024;
/// RRSIG validity (Knot `rrsig-lifetime` 14 days); re-signed when half of
/// it is left. Shorter than a day leaves no room for a failed re-signing;
/// longer than 90 days keeps replayable answers around (RFC 6781 §4.4.2).
pub const DEFAULT_SIGNATURE_VALIDITY_SECS: u32 = 1_209_600;
pub const SIGNATURE_VALIDITY_SECS: std::ops::RangeInclusive<u32> = 86_400..=7_776_000;

fn is_default_validity(v: &u32) -> bool {
    *v == DEFAULT_SIGNATURE_VALIDITY_SECS
}

fn default_validity() -> u32 {
    DEFAULT_SIGNATURE_VALIDITY_SECS
}

fn is_default_algorithm(a: &crate::dnssec::DnssecAlgorithm) -> bool {
    *a == crate::dnssec::DnssecAlgorithm::default()
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_zero(n: &u16) -> bool {
    *n == 0
}

fn is_zero_u8(n: &u8) -> bool {
    *n == 0
}

fn shown(s: &str) -> String {
    s.chars().take(64).collect()
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ZoneType {
    /// The data is here; the router is the source of the zone.
    #[default]
    Primary,
    /// A copy transferred from `primaries` (AXFR/IXFR), kept fresh by the
    /// SOA timers and NOTIFY.
    Secondary,
}

impl ZoneType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Secondary => "secondary",
        }
    }
}

impl std::str::FromStr for ZoneType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim() {
            "primary" | "master" => Ok(Self::Primary),
            "secondary" | "slave" => Ok(Self::Secondary),
            _ => Err("must be primary or secondary".into()),
        }
    }
}

/// How the serial moves on a change (BIND `serial-update-method`, Knot
/// `serial-policy`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SerialPolicy {
    /// `YYYYMMDDnn` (RFC 1912 §2.2): today's date, `nn` counting changes;
    /// past 99 a day it runs into the next day's numbers (still larger).
    #[default]
    Date,
    /// +1.
    Increment,
    /// Seconds since 1970 (or +1 when that is not larger).
    Unixtime,
}

impl SerialPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Date => "date",
            Self::Increment => "increment",
            Self::Unixtime => "unixtime",
        }
    }
}

impl std::str::FromStr for SerialPolicy {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim() {
            "date" | "dateserial" => Ok(Self::Date),
            "increment" => Ok(Self::Increment),
            "unixtime" => Ok(Self::Unixtime),
            _ => Err("must be date, increment or unixtime".into()),
        }
    }
}

/// RFC 1982 §3.2: `a` is greater than `b` in serial number arithmetic.
pub fn serial_gt(a: u32, b: u32) -> bool {
    a != b && a.wrapping_sub(b) < (1 << 31)
}

/// Days since 1970-01-01 → (year, month, day), proleptic Gregorian
/// (H. Hinnant's `civil_from_days`).
fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

/// The serial after `old` under `policy`, at `now_unix`. Always greater
/// than `old` (RFC 1982), by less than 2^31 (RFC 1982 §3.1: a larger step
/// is undefined).
pub fn next_serial(policy: SerialPolicy, old: u32, now_unix: u64) -> u32 {
    let wanted = match policy {
        SerialPolicy::Increment => None,
        SerialPolicy::Unixtime => u32::try_from(now_unix).ok(),
        SerialPolicy::Date => {
            let days = i64::try_from(now_unix / 86_400).unwrap_or(0);
            let (y, m, d) = civil(days);
            u32::try_from((y * 10_000 + m * 100 + d) * 100).ok()
        }
    };
    match wanted {
        Some(w) if serial_gt(w, old) => w,
        _ => old.wrapping_add(1),
    }
}

/// The serial of a new zone.
pub fn first_serial(policy: SerialPolicy, now_unix: u64) -> u32 {
    match policy {
        SerialPolicy::Increment => 1,
        _ => next_serial(policy, 0, now_unix),
    }
}

/// An SOA RNAME as a DNS name: `hostmaster@example.com` →
/// `hostmaster.example.com` (RFC 1035 §8: the first label is the mailbox).
pub fn mailbox_name(text: &str) -> Result<String, String> {
    let t = text.trim().trim_end_matches('.').to_ascii_lowercase();
    let dotted = match t.split_once('@') {
        Some((local, domain)) => {
            if local.contains('.') {
                return Err(format!(
                    "admin: '{}': a mailbox with a dot before @ is not supported",
                    shown(text)
                ));
            }
            format!("{local}.{domain}")
        }
        None => t,
    };
    if host_name_ok(&dotted) {
        Ok(dotted)
    } else {
        Err(format!("admin: '{}' is not a mailbox or a DNS name", shown(text)))
    }
}

/// A zone name or a target name: [`host_name_ok`], lowercase, no final dot.
pub fn normalize_host(text: &str) -> String {
    text.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Zone {
    pub id: ItemId,
    /// The origin (`example.com`, `88.168.192.in-addr.arpa`): lowercase,
    /// no final dot.
    pub name: String,
    #[serde(default, rename = "type")]
    pub ztype: ZoneType,
    /// SOA MNAME: the primary name server.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub primary_ns: String,
    /// SOA RNAME, as a DNS name (`hostmaster.example.com`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub admin: String,
    /// Moves by itself on every change (`serial_policy`).
    #[serde(default)]
    pub serial: u32,
    #[serde(default)]
    pub serial_policy: SerialPolicy,
    pub refresh_secs: u32,
    pub retry_secs: u32,
    pub expire_secs: u32,
    /// SOA MINIMUM: how long resolvers cache "no such name" (RFC 2308).
    pub minimum_secs: u32,
    /// TTL of the SOA and of records without their own.
    pub ttl_secs: u32,
    /// Who may transfer the zone (AXFR/IXFR); empty: nobody.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_transfer: Vec<IpNet>,
    /// Told on every change (NOTIFY, RFC 1996), port 53.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notify: Vec<IpAddr>,
    /// Secondary: the servers the zone is transferred from (port 53); also
    /// the only ones whose NOTIFY is heard.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub primaries: Vec<IpAddr>,
    /// Sign the zone (G4.1c-2): KSK + ZSK made by the daemon, NSEC3 (RFC
    /// 9276: no extra iterations, no salt), re-signed on every change and
    /// before the signatures expire.
    #[serde(default, skip_serializing_if = "is_false")]
    pub dnssec: bool,
    #[serde(default, skip_serializing_if = "is_default_algorithm")]
    pub dnssec_algorithm: crate::dnssec::DnssecAlgorithm,
    #[serde(default = "default_validity", skip_serializing_if = "is_default_validity")]
    pub signature_validity_secs: u32,
    #[serde(default, skip_serializing_if = "is_false")]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

impl Zone {
    pub fn new(id: ItemId, name: &str) -> Self {
        Self {
            id,
            name: name.to_owned(),
            ztype: ZoneType::Primary,
            primary_ns: String::new(),
            admin: String::new(),
            serial: 0,
            serial_policy: SerialPolicy::Date,
            refresh_secs: DEFAULT_REFRESH_SECS,
            retry_secs: DEFAULT_RETRY_SECS,
            expire_secs: DEFAULT_EXPIRE_SECS,
            minimum_secs: DEFAULT_MINIMUM_SECS,
            ttl_secs: DEFAULT_TTL_SECS,
            allow_transfer: Vec::new(),
            notify: Vec::new(),
            primaries: Vec::new(),
            dnssec: false,
            dnssec_algorithm: crate::dnssec::DnssecAlgorithm::default(),
            signature_validity_secs: DEFAULT_SIGNATURE_VALIDITY_SECS,
            disabled: false,
            comment: String::new(),
        }
    }

    /// SOA MNAME: `primary_ns`, or `ns1.<zone>` when unset.
    pub fn mname(&self) -> String {
        if self.primary_ns.is_empty() {
            format!("ns1.{}", self.name)
        } else {
            self.primary_ns.clone()
        }
    }

    /// SOA RNAME: `admin`, or `hostmaster.<zone>` (RFC 2142) when unset.
    pub fn rname(&self) -> String {
        if self.admin.is_empty() {
            format!("hostmaster.{}", self.name)
        } else {
            self.admin.clone()
        }
    }

    /// The fully qualified owner of a record name of this zone (`@` is the
    /// apex).
    pub fn owner(&self, name: &str) -> String {
        if name == "@" || name.is_empty() {
            self.name.clone()
        } else {
            format!("{name}.{}", self.name)
        }
    }

    pub fn problem(&self) -> Option<String> {
        if !host_name_ok(&self.name) {
            return Some(format!("name: '{}' is not a DNS name", shown(&self.name)));
        }
        for (key, v) in [("primary_ns", &self.primary_ns), ("admin", &self.admin)] {
            if !v.is_empty() && !host_name_ok(v) {
                return Some(format!("{key}: '{}' is not a DNS name", shown(v)));
            }
        }
        for (key, v) in [
            ("refresh_secs", self.refresh_secs),
            ("retry_secs", self.retry_secs),
            ("expire_secs", self.expire_secs),
            ("ttl_secs", self.ttl_secs),
        ] {
            if v > MAX_TTL_SECS {
                return Some(format!("{key} must be at most {MAX_TTL_SECS} (RFC 2181 §8)"));
            }
        }
        if self.minimum_secs > MAX_MINIMUM_SECS {
            return Some(format!(
                "minimum_secs must be at most {MAX_MINIMUM_SECS} (RFC 2308 §5 suggests 1 to 3 hours)"
            ));
        }
        if self.refresh_secs == 0 || self.retry_secs == 0 {
            return Some("refresh_secs and retry_secs must be above 0".into());
        }
        // RFC 1912 §2.2: retry below refresh, expire well above both.
        if self.retry_secs > self.refresh_secs {
            return Some(format!(
                "retry_secs ({}) must not be above refresh_secs ({}) (RFC 1912 §2.2)",
                self.retry_secs, self.refresh_secs
            ));
        }
        if self.expire_secs < self.refresh_secs.saturating_add(self.retry_secs) {
            return Some(format!(
                "expire_secs ({}) must be at least refresh_secs + retry_secs ({}): the secondaries \
                 would drop the zone between two refreshes (RFC 1912 §2.2)",
                self.expire_secs,
                self.refresh_secs.saturating_add(self.retry_secs)
            ));
        }
        if self.allow_transfer.len() > MAX_ALLOW_TRANSFER {
            return Some(format!("allow_transfer takes at most {MAX_ALLOW_TRANSFER} prefixes"));
        }
        if self.notify.len() > MAX_NOTIFY {
            return Some(format!("notify takes at most {MAX_NOTIFY} addresses"));
        }
        if self.primaries.len() > MAX_PRIMARIES {
            return Some(format!("primaries takes at most {MAX_PRIMARIES} addresses"));
        }
        if let Some(bad) = self
            .notify
            .iter()
            .chain(&self.primaries)
            .find(|ip| !crate::dns::usable_server(**ip))
        {
            return Some(format!(
                "{bad} cannot be a DNS server (unspecified, multicast or broadcast)"
            ));
        }
        if !SIGNATURE_VALIDITY_SECS.contains(&self.signature_validity_secs) {
            return Some(format!(
                "signature_validity_secs must be {SIGNATURE_VALIDITY_SECS:?} (1 to 90 days)"
            ));
        }
        match self.ztype {
            ZoneType::Secondary if self.dnssec => Some(
                "dnssec is for primary zones: a secondary serves the signatures of its primary".into(),
            ),
            ZoneType::Secondary if self.primaries.is_empty() => {
                Some("a secondary zone needs primaries (where to transfer it from)".into())
            }
            ZoneType::Primary if !self.primaries.is_empty() => {
                Some("primaries is for secondary zones".into())
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RecordType {
    #[default]
    A,
    Aaaa,
    Caa,
    Cname,
    Mx,
    Ns,
    Ptr,
    Srv,
    Txt,
}

impl RecordType {
    pub const ALL: [Self; 9] = [
        Self::A,
        Self::Aaaa,
        Self::Caa,
        Self::Cname,
        Self::Mx,
        Self::Ns,
        Self::Ptr,
        Self::Srv,
        Self::Txt,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Caa => "CAA",
            Self::Cname => "CNAME",
            Self::Mx => "MX",
            Self::Ns => "NS",
            Self::Ptr => "PTR",
            Self::Srv => "SRV",
            Self::Txt => "TXT",
        }
    }
}

impl std::str::FromStr for RecordType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let up = s.trim().to_ascii_uppercase();
        Self::ALL
            .into_iter()
            .find(|t| t.as_str() == up)
            .ok_or_else(|| "must be A, AAAA, CAA, CNAME, MX, NS, PTR, SRV or TXT".into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneRecord {
    pub id: ItemId,
    /// The zone's name.
    pub zone: String,
    /// Relative to the zone: `@` (the apex), `www`, `*.dev` (RFC 4592),
    /// `_sip._udp`. Lowercase.
    pub name: String,
    #[serde(default, rename = "type")]
    pub rtype: RecordType,
    /// A (IPv4) or AAAA (IPv6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<IpAddr>,
    /// CNAME, NS, PTR target; MX exchange; SRV target. A fully qualified
    /// name, lowercase, no final dot.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target: String,
    /// MX preference, SRV priority.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub priority: u16,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub weight: u16,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub port: u16,
    /// TXT text; CAA value.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub text: String,
    /// CAA flags (128: critical) and tag (`issue`, `issuewild`, `iodef`).
    #[serde(default, skip_serializing_if = "is_zero_u8")]
    pub caa_flags: u8,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub caa_tag: String,
    /// Absent: the zone's `ttl_secs`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u32>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

/// A record owner relative to its zone: `@`, or labels of letters, digits,
/// `-` and `_`, the first one maybe `*` (RFC 4592 §2.1.1).
pub fn relative_name_ok(name: &str) -> bool {
    if name == "@" {
        return true;
    }
    let rest = match name.strip_prefix('*') {
        Some("") => return true,
        Some(r) => match r.strip_prefix('.') {
            Some(r) => r,
            None => return false,
        },
        None => name,
    };
    host_name_ok(rest) && !rest.ends_with('.')
}

impl ZoneRecord {
    pub fn new(id: ItemId, zone: &str, name: &str) -> Self {
        Self {
            id,
            zone: zone.to_owned(),
            name: name.to_owned(),
            rtype: RecordType::A,
            address: None,
            target: String::new(),
            priority: 0,
            weight: 0,
            port: 0,
            text: String::new(),
            caa_flags: 0,
            caa_tag: String::new(),
            ttl_secs: None,
            disabled: false,
            comment: String::new(),
        }
    }

    /// Why this record cannot be committed, if anything is wrong (alone;
    /// [`DnsZones::problem`] checks it against the zone and its neighbours).
    pub fn problem(&self) -> Option<String> {
        if !relative_name_ok(&self.name) {
            return Some(format!(
                "name: '{}' is not a record name (@, www, *.dev, _sip._udp)",
                shown(&self.name)
            ));
        }
        if self.ttl_secs.is_some_and(|t| t > MAX_TTL_SECS) {
            return Some(format!("ttl_secs must be at most {MAX_TTL_SECS} (RFC 2181 §8)"));
        }
        let target = || -> Option<String> {
            if self.target.is_empty() {
                Some(format!("type {} needs target", self.rtype.as_str()))
            } else if !host_name_ok(&self.target) {
                Some(format!("target: '{}' is not a DNS name", shown(&self.target)))
            } else {
                None
            }
        };
        match self.rtype {
            RecordType::A => match self.address {
                Some(IpAddr::V4(_)) => None,
                _ => Some("type A needs an IPv4 address".into()),
            },
            RecordType::Aaaa => match self.address {
                Some(IpAddr::V6(_)) => None,
                _ => Some("type AAAA needs an IPv6 address".into()),
            },
            RecordType::Cname | RecordType::Mx | RecordType::Ns | RecordType::Ptr => target(),
            RecordType::Srv => target(),
            _ if self.text.chars().any(char::is_control) => {
                Some("text: no control characters (tabs, line breaks)".into())
            }
            RecordType::Txt => {
                if self.text.is_empty() || self.text.len() > MAX_TEXT_LEN {
                    Some(format!("type TXT needs text of 1..={MAX_TEXT_LEN} bytes"))
                } else {
                    None
                }
            }
            RecordType::Caa => {
                let tag_ok = (1..=MAX_CAA_TAG_LEN).contains(&self.caa_tag.len())
                    && self.caa_tag.bytes().all(|b| b.is_ascii_alphanumeric());
                if !tag_ok {
                    Some(format!(
                        "type CAA needs caa_tag: 1..={MAX_CAA_TAG_LEN} letters and digits (issue, issuewild, iodef)"
                    ))
                } else if self.text.len() > MAX_CAA_VALUE_LEN {
                    Some(format!("CAA value longer than {MAX_CAA_VALUE_LEN} bytes"))
                } else {
                    None
                }
            }
        }
    }

    /// The value column of `print` (`192.0.2.1`, `10 mail.example.com`…),
    /// in zone file order (RFC 1035 §5.1).
    pub fn data(&self) -> String {
        match self.rtype {
            RecordType::A | RecordType::Aaaa => {
                self.address.map(|a| a.to_string()).unwrap_or_default()
            }
            RecordType::Cname | RecordType::Ns | RecordType::Ptr => format!("{}.", self.target),
            RecordType::Mx => format!("{} {}.", self.priority, self.target),
            RecordType::Srv => format!(
                "{} {} {} {}.",
                self.priority, self.weight, self.port, self.target
            ),
            RecordType::Txt => format!("{:?}", self.text),
            RecordType::Caa => format!("{} {} {:?}", self.caa_flags, self.caa_tag, self.text),
        }
    }

    /// Same owner, type and data (TTL, comment and state aside): RFC 2181
    /// §5 makes the second one a duplicate.
    pub fn same_data(&self, o: &Self) -> bool {
        self.zone == o.zone
            && self.name == o.name
            && self.rtype == o.rtype
            && self.address == o.address
            && self.target == o.target
            && self.priority == o.priority
            && self.weight == o.weight
            && self.port == o.port
            && self.text == o.text
            && self.caa_flags == o.caa_flags
            && self.caa_tag == o.caa_tag
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsZones {
    pub zones: Vec<Zone>,
    pub records: Vec<ZoneRecord>,
    pub next_id: u32,
    pub next_record_id: u32,
}

impl DnsZones {
    pub fn is_empty(&self) -> bool {
        self.zones.is_empty() && self.records.is_empty() && self.next_id == 0
    }

    pub fn next_id(&mut self) -> ItemId {
        self.next_id = self.next_id.saturating_add(1);
        ItemId(self.next_id)
    }

    pub fn next_record_id(&mut self) -> ItemId {
        self.next_record_id = self.next_record_id.saturating_add(1);
        ItemId(self.next_record_id)
    }

    pub fn zone(&self, name: &str) -> Option<&Zone> {
        self.zones.iter().find(|z| z.name == name)
    }

    /// The records of zone `name`, in config order.
    pub fn records_of<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a ZoneRecord> + 'a {
        self.records.iter().filter(move |r| r.zone == name)
    }

    /// The first problem, with the zone or record it is about.
    pub fn problem(&self) -> Option<String> {
        if self.zones.len() > MAX_ZONES {
            return Some(format!("at most {MAX_ZONES} zones"));
        }
        if self.records.len() > MAX_RECORDS {
            return Some(format!("at most {MAX_RECORDS} zone records"));
        }
        let mut names = std::collections::HashSet::new();
        for z in &self.zones {
            if let Some(p) = z.problem() {
                return Some(format!("zone {}: {p}", shown(&z.name)));
            }
            if !names.insert(z.name.as_str()) {
                return Some(format!("zone {}: defined twice", shown(&z.name)));
            }
        }
        // Owner+type → records, to check each name against its neighbours.
        let mut by_owner: std::collections::HashMap<(&str, &str), Vec<&ZoneRecord>> =
            std::collections::HashMap::new();
        for r in &self.records {
            let Some(z) = self.zone(&r.zone) else {
                return Some(format!("record {}: no zone {}", r.id, shown(&r.zone)));
            };
            let at = |p: String| Some(format!("record {} ({} in {}): {p}", r.id, r.name, z.name));
            if let Some(p) = r.problem() {
                return at(p);
            }
            if z.ztype == ZoneType::Secondary {
                return at("a secondary zone gets its records by transfer".into());
            }
            if z.owner(&r.name).len() > 253 {
                return at("the full name is longer than 253 characters (RFC 1035 §2.3.4)".into());
            }
            if r.rtype == RecordType::Cname && r.name == "@" {
                return at(
                    "no CNAME at the zone apex: it has the SOA and NS (RFC 1034 §3.6.2)".into(),
                );
            }
            if !r.disabled {
                by_owner.entry((&r.zone, &r.name)).or_default().push(r);
            }
        }
        for ((zone, name), recs) in &by_owner {
            let cname = recs.iter().filter(|r| r.rtype == RecordType::Cname).count();
            if cname > 1 || (cname == 1 && recs.len() > 1) {
                return Some(format!(
                    "{name} in {zone}: a CNAME cannot share its name with other records, \
                     not even another CNAME (RFC 2181 §10.1)"
                ));
            }
            for (i, a) in recs.iter().enumerate() {
                if recs.iter().skip(i + 1).any(|b| a.same_data(b)) {
                    return Some(format!(
                        "{name} in {zone}: {} {} is there twice (RFC 2181 §5)",
                        a.rtype.as_str(),
                        a.data()
                    ));
                }
            }
        }
        None
    }
}

/// What the daemon knows of a zone at run time (`ip.dns.zone.print`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneStatus {
    pub zone: String,
    /// The serial being served (a secondary: of its last transfer).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loaded_serial: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub records: Option<usize>,
    /// Secondary: the last time a primary was checked successfully.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refreshed_unix: Option<u64>,
    /// Secondary: when the next SOA check is due.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_refresh_unix: Option<u64>,
    /// The last failure (a transfer, a NOTIFY), if the last attempt failed.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub error: String,
    /// DNSSEC (G4.1c-2): the serial of the signed version being served.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_serial: Option<u32>,
    /// When the earliest signature of the served version expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signatures_expire_unix: Option<u64>,
    /// A transferred zone carries signatures (RRSIG, NSEC3).
    #[serde(default, skip_serializing_if = "is_false")]
    pub signed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serials_move_forward() {
        // 2026-10-22 12:00 UTC.
        let now = 1_792_670_400;
        assert_eq!(first_serial(SerialPolicy::Date, now), 2_026_102_200);
        assert_eq!(next_serial(SerialPolicy::Date, 2_026_102_200, now), 2_026_102_201);
        assert_eq!(next_serial(SerialPolicy::Date, 2_026_102_299, now), 2_026_102_300);
        assert_eq!(next_serial(SerialPolicy::Date, 7, now), 2_026_102_200);
        assert_eq!(first_serial(SerialPolicy::Increment, now), 1);
        assert_eq!(next_serial(SerialPolicy::Increment, u32::MAX, now), 0);
        assert_eq!(next_serial(SerialPolicy::Unixtime, 5, now), 1_792_670_400);
        assert_eq!(
            next_serial(SerialPolicy::Unixtime, 1_792_670_400, now),
            1_792_670_401
        );
        // A date far "behind" in serial space (old already ahead by a lot):
        // never goes back.
        let ahead = 4_000_000_000;
        assert!(serial_gt(next_serial(SerialPolicy::Date, ahead, now), ahead));
    }

    #[test]
    fn rfc1982_comparison() {
        assert!(serial_gt(1, 0));
        assert!(serial_gt(0, u32::MAX), "wraps around");
        assert!(!serial_gt(5, 5));
        assert!(!serial_gt(0, 1 << 31), "undefined pair is not greater");
        assert!(serial_gt(100, 100u32.wrapping_sub(1 << 30)));
    }

    #[test]
    fn civil_dates() {
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(11_016), (2000, 2, 29));
        assert_eq!(civil(20_748), (2026, 10, 22));
    }

    #[test]
    fn mailboxes() {
        assert_eq!(mailbox_name("Hostmaster@Example.com").unwrap(), "hostmaster.example.com");
        assert_eq!(mailbox_name("hostmaster.example.com.").unwrap(), "hostmaster.example.com");
        assert!(mailbox_name("john.doe@example.com").is_err());
        assert!(mailbox_name("bad name").is_err());
    }

    fn zones() -> DnsZones {
        let mut z = DnsZones::default();
        let id = z.next_id();
        z.zones.push(Zone::new(id, "example.com"));
        z
    }

    fn rec(f: impl FnOnce(&mut ZoneRecord)) -> ZoneRecord {
        let mut r = ZoneRecord::new(ItemId(1), "example.com", "www");
        r.address = Some("192.0.2.1".parse().unwrap());
        f(&mut r);
        r
    }

    #[test]
    fn records_are_checked() {
        assert_eq!(rec(|_| {}).problem(), None);
        assert!(rec(|r| r.name = "a..b".into()).problem().is_some());
        assert!(rec(|r| r.name = "a.*".into()).problem().is_some());
        assert_eq!(rec(|r| r.name = "*.dev".into()).problem(), None);
        assert_eq!(rec(|r| r.name = "*".into()).problem(), None);
        assert_eq!(rec(|r| r.name = "_sip._udp".into()).problem(), None);
        assert!(rec(|r| r.rtype = RecordType::Mx).problem().is_some());
        assert!(
            rec(|r| {
                r.rtype = RecordType::Caa;
                r.caa_tag = "is sue".into();
            })
            .problem()
            .is_some()
        );
        assert!(rec(|r| r.ttl_secs = Some(u32::MAX)).problem().is_some());
    }

    #[test]
    fn neighbours_are_checked() {
        let mut z = zones();
        z.records.push(rec(|_| {}));
        assert_eq!(z.problem(), None);
        z.records.push(rec(|r| r.id = ItemId(2)));
        assert!(z.problem().unwrap().contains("twice"), "{:?}", z.problem());
        z.records.pop();
        z.records.push(rec(|r| {
            r.id = ItemId(2);
            r.rtype = RecordType::Cname;
            r.address = None;
            r.target = "other.example.com".into();
        }));
        assert!(z.problem().unwrap().contains("CNAME"));
        z.records.pop();
        z.records.push(rec(|r| {
            r.name = "@".into();
            r.rtype = RecordType::Cname;
            r.address = None;
            r.target = "other.example.net".into();
        }));
        assert!(z.problem().unwrap().contains("apex"));
        z.records.pop();
        z.records.push(rec(|r| r.zone = "nowhere.example".into()));
        assert!(z.problem().unwrap().contains("no zone"));
    }

    #[test]
    fn zones_are_checked() {
        let ok = Zone::new(ItemId(1), "example.com");
        assert_eq!(ok.problem(), None);
        let mut z = ok.clone();
        z.retry_secs = z.refresh_secs + 1;
        assert!(z.problem().is_some());
        let mut z = ok.clone();
        z.expire_secs = 10;
        assert!(z.problem().is_some());
        let mut z = ok.clone();
        z.ztype = ZoneType::Secondary;
        assert!(z.problem().unwrap().contains("primaries"));
        z.primaries = vec!["192.0.2.53".parse().unwrap()];
        assert_eq!(z.problem(), None);
        z.notify = vec!["0.0.0.0".parse().unwrap()];
        assert!(z.problem().is_some());
        assert_eq!(ok.mname(), "ns1.example.com");
        assert_eq!(ok.rname(), "hostmaster.example.com");
        assert_eq!(ok.owner("@"), "example.com");
        assert_eq!(ok.owner("www"), "www.example.com");
    }

    #[test]
    fn config_stays_small() {
        let r = rec(|_| {});
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"id": "*1", "zone": "example.com", "name": "www",
                "type": "A", "address": "192.0.2.1"})
        );
        let back: ZoneRecord = serde_json::from_value(v).unwrap();
        assert_eq!(back, r);
        let z = Zone::new(ItemId(1), "example.com");
        let back: Zone = serde_json::from_value(serde_json::to_value(&z).unwrap()).unwrap();
        assert_eq!(back, z);
    }
}
