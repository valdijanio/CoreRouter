//! `/queue` (G4.9): bandwidth control per target, with RouterOS v7's names.
//!
//! - `/queue simple`: a target (addresses, prefixes or an interface) with
//!   `max-limit`, `limit-at`, the burst triple, `bucket-size`, `priority`
//!   and the queue type of each direction. Every pair is
//!   `upload/download`, as RouterOS prints it: upload is traffic *from* the
//!   target, download *to* it. Order matters: the first queue whose target
//!   holds the address wins (RouterOS's first match).
//! - `/queue type`: what a queue does with what waits (`pfifo`, `bfifo`,
//!   `fq-codel`, `cake`, `pcq`). The built-in types exist without an entry,
//!   like the built-in PPP profiles; editing one stores a copy.
//!
//! Dynamic queues (PPPoE and IPoE sessions, DHCP leases) are not config:
//! the engine derives them from what is up (`corerouter_engine::queue`).
//! Only the definitions live here.

use std::fmt;
use std::str::FromStr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::types::{IfName, ItemId, ParseError};

/// Simple queues in the config. RouterOS walks them in order per packet;
/// the data plane here looks them up in a trie, so the bound is memory
/// and the config size, not the per-packet cost (**estimado**: 100 k × ~200
/// B = 20 MB of config).
pub const MAX_SIMPLE: usize = 100_000;
/// Queue types (**estimado**, hostile-input bound).
pub const MAX_TYPES: usize = 1024;
/// Targets of one simple queue (RouterOS takes a list).
pub const MAX_TARGETS: usize = 64;
/// Names and comments, bytes.
pub const MAX_NAME: usize = 64;
pub const MAX_COMMENT: usize = 256;
/// Highest rate, bits per second (the same 10 Tbit/s typo guard as the
/// RADIUS `rate-limit`).
pub const MAX_RATE: u64 = 10_000_000_000_000;
/// Longest burst time, milliseconds (RouterOS has no stated bound; one hour
/// is far past any plan and keeps the window arithmetic small).
pub const MAX_BURST_TIME_MS: u32 = 3_600_000;
/// `bucket-size` is kept in thousandths (RouterOS: a ratio of the
/// max-limit, default 0.1, up to 10000 in v7.25).
pub const DEFAULT_BUCKET: u32 = 100;
pub const MAX_BUCKET: u32 = 10_000_000;
/// RouterOS priority: 1 (highest) to 8 (lowest, the default).
pub const DEFAULT_PRIORITY: u8 = 8;

/// The queue type a simple queue gets when none is given (RouterOS).
pub const DEFAULT_SIMPLE_TYPE: &str = "default-small";
/// The queue type dynamic queues get when the profile or server does not
/// say. RouterOS uses `default-small` (a 10-packet FIFO, short for any
/// rate above a few Mbit/s); CoreRouter recommends `fq-codel`.
pub const DEFAULT_DYNAMIC_TYPE: &str = "fq-codel-default";

/// How a dynamic queue holds its download rate (G4.9, CoreRouter's
/// addition to the PPP profile).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DownloadMode {
    /// The excess waits in a queue (EDT): TCP sees delay, not loss.
    #[default]
    Shaper,
    /// The excess is dropped in XDP (the G4.3c policer, the cheapest).
    Policer,
}

impl DownloadMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shaper => "shaper",
            Self::Policer => "policer",
        }
    }

    pub fn parse(t: &str) -> Option<Self> {
        match t.trim() {
            "shaper" => Some(Self::Shaper),
            "policer" => Some(Self::Policer),
            _ => None,
        }
    }
}

/// A pair of values, upload then download, RouterOS text `up/down` (one
/// value means both).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Pair<T> {
    pub upload: T,
    pub download: T,
}

impl<T: Copy> Pair<T> {
    pub fn both(v: T) -> Self {
        Self {
            upload: v,
            download: v,
        }
    }

    pub fn get(&self, download: bool) -> T {
        if download { self.download } else { self.upload }
    }
}

impl<T: Copy + PartialEq + fmt::Display> Pair<T> {
    fn show(&self, f: &mut fmt::Formatter<'_>, one: impl Fn(T) -> String) -> fmt::Result {
        write!(f, "{}/{}", one(self.upload), one(self.download))
    }
}

fn split_pair<T: Copy>(
    s: &str,
    one: impl Fn(&str) -> Result<T, ParseError>,
) -> Result<Pair<T>, ParseError> {
    let s = s.trim();
    match s.split_once('/') {
        Some((u, d)) => Ok(Pair {
            upload: one(u.trim())?,
            download: one(d.trim())?,
        }),
        None => Ok(Pair::both(one(s)?)),
    }
}

/// A rate in bits per second: `0` (no limit), `512k`, `10M`, `1.5G`
/// (RouterOS: k = 1000).
pub fn parse_rate(s: &str) -> Result<u64, ParseError> {
    let bad = || ParseError::new("rate", s, "a number with optional k, M or G (10M, 1.5G)");
    let t = s.trim();
    if t.is_empty() || t.len() > 24 {
        return Err(bad());
    }
    let (num, mul) = if let Some(n) = t.strip_suffix(['k', 'K']) {
        (n, 1_000u64)
    } else if let Some(n) = t.strip_suffix(['m', 'M']) {
        (n, 1_000_000)
    } else if let Some(n) = t.strip_suffix(['g', 'G']) {
        (n, 1_000_000_000)
    } else {
        (t, 1)
    };
    let (int, frac) = num.split_once('.').unwrap_or((num, ""));
    if int.is_empty()
        || int.len() > 14
        || frac.len() > 9
        || !int.bytes().chain(frac.bytes()).all(|b| b.is_ascii_digit())
    {
        return Err(bad());
    }
    let int: u64 = int.parse().map_err(|_| bad())?;
    let mut v = int.checked_mul(mul).ok_or_else(bad)?;
    let mut scale = mul;
    for d in frac.bytes() {
        scale /= 10;
        v = v
            .checked_add(u64::from(d - b'0') * scale)
            .ok_or_else(bad)?;
    }
    (v <= MAX_RATE).then_some(v).ok_or_else(bad)
}

/// A rate as RouterOS prints it: `10M`, `1500k`, `0`.
pub fn rate_text(v: u64) -> String {
    match v {
        0 => "0".into(),
        v if v % 1_000_000_000 == 0 => format!("{}G", v / 1_000_000_000),
        v if v % 1_000_000 == 0 => format!("{}M", v / 1_000_000),
        v if v % 1_000 == 0 => format!("{}k", v / 1_000),
        v => v.to_string(),
    }
}

/// A time in milliseconds: `8`, `8s`, `500ms`, `1m`.
pub fn parse_time_ms(s: &str) -> Result<u32, ParseError> {
    let bad = || ParseError::new("time", s, "seconds (8, 8s), 500ms or 1m");
    let t = s.trim();
    let (num, mul) = if let Some(n) = t.strip_suffix("ms") {
        (n, 1u64)
    } else if let Some(n) = t.strip_suffix('s') {
        (n, 1000)
    } else if let Some(n) = t.strip_suffix('m') {
        (n, 60_000)
    } else {
        (t, 1000)
    };
    if num.is_empty() || num.len() > 9 || !num.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad());
    }
    let v = num.parse::<u64>().map_err(|_| bad())?.saturating_mul(mul);
    u32::try_from(v)
        .ok()
        .filter(|v| *v <= MAX_BURST_TIME_MS)
        .ok_or_else(bad)
}

pub fn time_text(ms: u32) -> String {
    match ms {
        0 => "0s".into(),
        ms if ms % 60_000 == 0 && ms >= 60_000 => format!("{}m", ms / 60_000),
        ms if ms % 1000 == 0 => format!("{}s", ms / 1000),
        ms => format!("{ms}ms"),
    }
}

/// A ratio with up to three decimals, kept in thousandths: `0.1` → 100.
pub fn parse_ratio(s: &str) -> Result<u32, ParseError> {
    let bad = || ParseError::new("bucket size", s, "a ratio of the max-limit, 0..10000 (0.1)");
    let t = s.trim();
    let (int, frac) = t.split_once('.').unwrap_or((t, ""));
    if int.is_empty() && frac.is_empty()
        || int.len() > 5
        || frac.len() > 3
        || !int.bytes().chain(frac.bytes()).all(|b| b.is_ascii_digit())
    {
        return Err(bad());
    }
    let int: u32 = if int.is_empty() {
        0
    } else {
        int.parse().map_err(|_| bad())?
    };
    let mut milli = int.checked_mul(1000).ok_or_else(bad)?;
    let mut scale = 100;
    for d in frac.bytes() {
        milli += u32::from(d - b'0') * scale;
        scale /= 10;
    }
    (milli <= MAX_BUCKET).then_some(milli).ok_or_else(bad)
}

pub fn ratio_text(milli: u32) -> String {
    let (i, f) = (milli / 1000, milli % 1000);
    if f == 0 {
        return i.to_string();
    }
    let mut s = format!("{i}.{f:03}");
    while s.ends_with('0') {
        s.pop();
    }
    s
}

macro_rules! pair_serde {
    ($t:ty, $parse:expr, $show:expr) => {
        impl FromStr for Pair<$t> {
            type Err = ParseError;
            fn from_str(s: &str) -> Result<Self, ParseError> {
                split_pair(s, $parse)
            }
        }
        impl fmt::Display for Pair<$t> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.show(f, $show)
            }
        }
        impl Serialize for Pair<$t> {
            fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.collect_str(self)
            }
        }
        impl<'de> Deserialize<'de> for Pair<$t> {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let raw = String::deserialize(d)?;
                raw.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

/// Rates (bits per second).
pub type Rates = Pair<u64>;
pair_serde!(u64, parse_rate, rate_text);
/// Burst times (ms) and bucket sizes (thousandths) are both `u32`, so the
/// text form of a `Pair<u32>` is chosen by the field (`with`).
pub type Millis = Pair<u32>;

fn parse_prio(s: &str) -> Result<u8, ParseError> {
    match s.trim().parse::<u8>() {
        Ok(p @ 1..=8) => Ok(p),
        _ => Err(ParseError::new("priority", s, "1 (highest) to 8 (lowest)")),
    }
}
pair_serde!(u8, parse_prio, |v: u8| v.to_string());

pub fn parse_times(s: &str) -> Result<Pair<u32>, ParseError> {
    split_pair(s, parse_time_ms)
}

pub fn times_text(p: &Pair<u32>) -> String {
    format!("{}/{}", time_text(p.upload), time_text(p.download))
}

pub fn parse_ratios(s: &str) -> Result<Pair<u32>, ParseError> {
    split_pair(s, parse_ratio)
}

pub fn ratios_text(p: &Pair<u32>) -> String {
    format!("{}/{}", ratio_text(p.upload), ratio_text(p.download))
}

mod times_serde {
    use super::*;
    pub fn serialize<S: serde::Serializer>(p: &Pair<u32>, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(&times_text(p))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Pair<u32>, D::Error> {
        parse_times(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

mod ratios_serde {
    use super::*;
    pub fn serialize<S: serde::Serializer>(p: &Pair<u32>, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(&ratios_text(p))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Pair<u32>, D::Error> {
        parse_ratios(&String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

/// Queue type names of a simple queue, `upload/download`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct TypeNames {
    pub upload: String,
    pub download: String,
}

impl TypeNames {
    pub fn both(n: &str) -> Self {
        Self {
            upload: n.into(),
            download: n.into(),
        }
    }

    pub fn get(&self, download: bool) -> &str {
        if download { &self.download } else { &self.upload }
    }
}

impl FromStr for TypeNames {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, ParseError> {
        let p = |t: &str| {
            let t = t.trim();
            if name_ok(t) {
                Ok(t.to_owned())
            } else {
                Err(ParseError::new("queue type", t, "a /queue type name"))
            }
        };
        match s.split_once('/') {
            Some((u, d)) => Ok(Self {
                upload: p(u)?,
                download: p(d)?,
            }),
            None => {
                let n = p(s)?;
                Ok(Self {
                    upload: n.clone(),
                    download: n,
                })
            }
        }
    }
}

impl fmt::Display for TypeNames {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.upload, self.download)
    }
}

impl Serialize for TypeNames {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for TypeNames {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// A queue or type name: 1..=64 printable bytes, no `/` (the pair
/// separator) nor `,` (the list separator).
pub fn name_ok(t: &str) -> bool {
    !t.is_empty()
        && t.len() <= MAX_NAME
        && t
            .chars()
            .all(|c| !c.is_control() && c != '/' && c != ',' && c != '"')
}

/// What a simple queue limits: an address or prefix (IPv4 or IPv6), or
/// everything through an interface.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Target {
    Prefix(IpNet),
    Interface(IfName),
}

impl FromStr for Target {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, ParseError> {
        let t = s.trim();
        if let Ok(n) = t.parse::<IpNet>() {
            return Ok(Self::Prefix(n.trunc()));
        }
        if let Ok(a) = t.parse::<std::net::IpAddr>() {
            return Ok(Self::Prefix(IpNet::from(a)));
        }
        t.parse::<IfName>()
            .map(Self::Interface)
            .map_err(|_| ParseError::new("target", s, "an address, a prefix or an interface"))
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Prefix(n) if n.prefix_len() == n.max_prefix_len() => write!(f, "{}", n.addr()),
            Self::Prefix(n) => write!(f, "{n}"),
            Self::Interface(i) => write!(f, "{i}"),
        }
    }
}

impl Serialize for Target {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Target {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Targets as RouterOS lists them: `10.0.0.1,10.0.1.0/24`.
pub fn parse_targets(s: &str) -> Result<Vec<Target>, ParseError> {
    let parts: Vec<&str> = s.split(',').map(str::trim).filter(|t| !t.is_empty()).collect();
    if parts.is_empty() {
        return Err(ParseError::new("target", s, "at least one address, prefix or interface"));
    }
    if parts.len() > MAX_TARGETS {
        return Err(ParseError::new("target", s, "at most 64 targets"));
    }
    let mut out: Vec<Target> = Vec::with_capacity(parts.len());
    for p in parts {
        let t: Target = p.parse()?;
        if !out.contains(&t) {
            out.push(t);
        }
    }
    Ok(out)
}

pub fn targets_text(t: &[Target]) -> String {
    t.iter().map(ToString::to_string).collect::<Vec<_>>().join(",")
}

fn default_bucket() -> Pair<u32> {
    Pair::both(DEFAULT_BUCKET)
}

fn default_prio() -> Pair<u8> {
    Pair::both(DEFAULT_PRIORITY)
}

fn default_types() -> TypeNames {
    TypeNames::both(DEFAULT_SIMPLE_TYPE)
}

fn is_zero_rates(p: &Rates) -> bool {
    *p == Rates::default()
}

fn is_zero_times(p: &Pair<u32>) -> bool {
    *p == Pair::default()
}

/// One `/queue simple`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimpleQueue {
    pub id: ItemId,
    pub name: String,
    pub target: Vec<Target>,
    /// 0 = no limit in that direction.
    #[serde(default, skip_serializing_if = "is_zero_rates")]
    pub max_limit: Rates,
    /// The guaranteed rate (CIR). Kept for the queue tree (G4.9e); a
    /// single queue is shaped at its max-limit.
    #[serde(default, skip_serializing_if = "is_zero_rates")]
    pub limit_at: Rates,
    /// Rate while bursting; 0 or at most `max_limit` = no burst.
    #[serde(default, skip_serializing_if = "is_zero_rates")]
    pub burst_limit: Rates,
    /// Average over `burst_time` under which the burst is allowed; 0 = the
    /// max-limit (RouterOS).
    #[serde(default, skip_serializing_if = "is_zero_rates")]
    pub burst_threshold: Rates,
    /// Window of the average, ms; 0 = 1 s.
    #[serde(default, with = "times_serde", skip_serializing_if = "is_zero_times")]
    pub burst_time: Pair<u32>,
    /// Bucket of each direction as a ratio of its max-limit (burst-limit
    /// while bursting), thousandths: 100 = 0.1 = 100 ms of the rate.
    #[serde(default = "default_bucket", with = "ratios_serde")]
    pub bucket_size: Pair<u32>,
    #[serde(default = "default_prio")]
    pub priority: Pair<u8>,
    /// `/queue type` names.
    #[serde(default = "default_types")]
    pub queue: TypeNames,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

impl SimpleQueue {
    pub fn new(id: ItemId, name: String, target: Vec<Target>) -> Self {
        Self {
            id,
            name,
            target,
            max_limit: Rates::default(),
            limit_at: Rates::default(),
            burst_limit: Rates::default(),
            burst_threshold: Rates::default(),
            burst_time: Pair::default(),
            bucket_size: default_bucket(),
            priority: default_prio(),
            queue: default_types(),
            disabled: false,
            comment: String::new(),
        }
    }
}

/// `/queue type` kinds the shaper runs. RouterOS also has `red`, `sfq`,
/// `codel`, `mq-pfifo` and `none`; an import maps them (G4.3n).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Pfifo,
    Bfifo,
    Pcq,
    FqCodel,
    Cake,
}

impl Kind {
    pub const ALL: [Self; 5] = [Self::Pfifo, Self::Bfifo, Self::Pcq, Self::FqCodel, Self::Cake];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pfifo => "pfifo",
            Self::Bfifo => "bfifo",
            Self::Pcq => "pcq",
            Self::FqCodel => "fq-codel",
            Self::Cake => "cake",
        }
    }

    pub fn parse(t: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|k| k.as_str() == t.trim() || k.as_str().replace('-', "_") == t.trim())
    }
}

/// What identifies a PCQ sub-stream (RouterOS `pcq-classifier`; the
/// shaper keys by address).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Classifier {
    SrcAddress,
    DstAddress,
}

impl Classifier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SrcAddress => "src-address",
            Self::DstAddress => "dst-address",
        }
    }

    pub fn parse(t: &str) -> Option<Self> {
        match t.trim() {
            "src-address" | "src_address" => Some(Self::SrcAddress),
            "dst-address" | "dst_address" => Some(Self::DstAddress),
            _ => None,
        }
    }
}

/// RouterOS defaults of each kind's parameters.
pub const PFIFO_LIMIT: u32 = 50;
pub const BFIFO_LIMIT: u32 = 15_000;
/// PCQ limits are KiB in v7 (`pcq-limit` 50, `pcq-total-limit` 2000).
pub const PCQ_LIMIT_KIB: u32 = 50;
pub const PCQ_TOTAL_LIMIT_KIB: u32 = 2000;
pub const PCQ_BURST_TIME_MS: u32 = 10_000;
pub const CODEL_TARGET_MS: u32 = 5;
pub const CODEL_INTERVAL_MS: u32 = 100;
pub const FQ_CODEL_LIMIT: u32 = 10_240;
pub const CAKE_RTT_MS: u32 = 100;

/// One `/queue type`. Only the parameters of its kind are used; the rest
/// keep RouterOS's defaults so a kind change starts from sane values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueueType {
    #[serde(default)]
    pub id: ItemId,
    pub name: String,
    pub kind: Kind,
    /// Packets (pfifo).
    #[serde(default = "d_pfifo")]
    pub pfifo_limit: u32,
    /// Bytes (bfifo).
    #[serde(default = "d_bfifo")]
    pub bfifo_limit: u32,
    /// Per sub-stream, bits per second; 0 = share the queue's limit.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub pcq_rate: u64,
    #[serde(default = "d_classifier")]
    pub pcq_classifier: Classifier,
    /// KiB per sub-stream.
    #[serde(default = "d_pcq_limit")]
    pub pcq_limit: u32,
    /// KiB over all sub-streams.
    #[serde(default = "d_pcq_total")]
    pub pcq_total_limit: u32,
    #[serde(default = "d_mask4")]
    pub pcq_src_address_mask: u8,
    #[serde(default = "d_mask4")]
    pub pcq_dst_address_mask: u8,
    #[serde(default = "d_mask6")]
    pub pcq_src_address6_mask: u8,
    #[serde(default = "d_mask6")]
    pub pcq_dst_address6_mask: u8,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub pcq_burst_rate: u64,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub pcq_burst_threshold: u64,
    #[serde(default = "d_pcq_burst_time")]
    pub pcq_burst_time: u32,
    /// ms.
    #[serde(default = "d_target")]
    pub fq_codel_target: u32,
    /// ms.
    #[serde(default = "d_interval")]
    pub fq_codel_interval: u32,
    /// Packets.
    #[serde(default = "d_fq_limit")]
    pub fq_codel_limit: u32,
    /// Mark ECN-capable packets instead of dropping them (RFC 3168).
    #[serde(default = "yes")]
    pub fq_codel_ecn: bool,
    /// ms: CAKE's CoDel target and interval follow it (target = rtt/20).
    #[serde(default = "d_rtt")]
    pub cake_rtt: u32,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}
fn yes() -> bool {
    true
}
fn d_pfifo() -> u32 {
    PFIFO_LIMIT
}
fn d_bfifo() -> u32 {
    BFIFO_LIMIT
}
fn d_classifier() -> Classifier {
    Classifier::DstAddress
}
fn d_pcq_limit() -> u32 {
    PCQ_LIMIT_KIB
}
fn d_pcq_total() -> u32 {
    PCQ_TOTAL_LIMIT_KIB
}
fn d_mask4() -> u8 {
    32
}
fn d_mask6() -> u8 {
    128
}
fn d_pcq_burst_time() -> u32 {
    PCQ_BURST_TIME_MS
}
fn d_target() -> u32 {
    CODEL_TARGET_MS
}
fn d_interval() -> u32 {
    CODEL_INTERVAL_MS
}
fn d_fq_limit() -> u32 {
    FQ_CODEL_LIMIT
}
fn d_rtt() -> u32 {
    CAKE_RTT_MS
}

impl QueueType {
    /// A type of `kind` with RouterOS's defaults.
    pub fn new(name: &str, kind: Kind) -> Self {
        Self {
            id: ItemId::default(),
            name: name.into(),
            kind,
            pfifo_limit: PFIFO_LIMIT,
            bfifo_limit: BFIFO_LIMIT,
            pcq_rate: 0,
            pcq_classifier: Classifier::DstAddress,
            pcq_limit: PCQ_LIMIT_KIB,
            pcq_total_limit: PCQ_TOTAL_LIMIT_KIB,
            pcq_src_address_mask: 32,
            pcq_dst_address_mask: 32,
            pcq_src_address6_mask: 128,
            pcq_dst_address6_mask: 128,
            pcq_burst_rate: 0,
            pcq_burst_threshold: 0,
            pcq_burst_time: PCQ_BURST_TIME_MS,
            fq_codel_target: CODEL_TARGET_MS,
            fq_codel_interval: CODEL_INTERVAL_MS,
            fq_codel_limit: FQ_CODEL_LIMIT,
            fq_codel_ecn: true,
            cake_rtt: CAKE_RTT_MS,
            comment: String::new(),
        }
    }

    /// The built-in types (RouterOS's, plus `fq-codel-default` and
    /// `cake-default`, the recommended ones for dynamic queues). Ids
    /// count down from the top so they never meet stored ones.
    pub fn builtins() -> Vec<QueueType> {
        let mut small = Self::new("default-small", Kind::Pfifo);
        small.pfifo_limit = 10;
        let mut up = Self::new("pcq-upload-default", Kind::Pcq);
        up.pcq_classifier = Classifier::SrcAddress;
        let down = Self::new("pcq-download-default", Kind::Pcq);
        let mut v = vec![
            Self::new("default", Kind::Pfifo),
            Self::new("ethernet-default", Kind::Pfifo),
            small,
            up,
            down,
            Self::new(DEFAULT_DYNAMIC_TYPE, Kind::FqCodel),
            Self::new("cake-default", Kind::Cake),
        ];
        for (i, t) in v.iter_mut().enumerate() {
            t.id = ItemId(u32::MAX - u32::try_from(i).unwrap_or(0));
        }
        v
    }

    pub fn builtin(name: &str) -> Option<QueueType> {
        Self::builtins().into_iter().find(|t| t.name == name)
    }

    pub fn is_builtin_name(name: &str) -> bool {
        Self::builtin(name).is_some()
    }
}

/// `/queue`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Queues {
    /// In order: the first queue whose target holds an address wins.
    /// A block list (G0.21): 10 000 queues and more on a big BNG.
    #[serde(skip_serializing_if = "crate::cow_list::CowList::is_empty")]
    pub simple: crate::cow_list::CowList<SimpleQueue>,
    /// Types the operator added or changed (built-ins exist without an
    /// entry; an entry with a built-in's name is the edited copy).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub types: Vec<QueueType>,
    #[serde(skip_serializing_if = "is_zero32")]
    pub next_id: u32,
}

fn is_zero32(v: &u32) -> bool {
    *v == 0
}

impl Queues {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    pub fn next_id(&mut self) -> ItemId {
        self.next_id = self.next_id.saturating_add(1);
        ItemId(self.next_id)
    }

    /// Type `name`: the stored one, or the built-in.
    pub fn queue_type(&self, name: &str) -> Option<QueueType> {
        self.types
            .iter()
            .find(|t| t.name == name)
            .cloned()
            .or_else(|| QueueType::builtin(name))
    }

    /// Every type: built-ins (edited copies in their place), then the
    /// operator's.
    pub fn all_types(&self) -> Vec<QueueType> {
        let mut out: Vec<QueueType> = QueueType::builtins()
            .into_iter()
            .map(|b| {
                self.types
                    .iter()
                    .find(|t| t.name == b.name)
                    .cloned()
                    .map(|mut t| {
                        t.id = b.id;
                        t
                    })
                    .unwrap_or(b)
            })
            .collect();
        out.extend(
            self.types
                .iter()
                .filter(|t| !QueueType::is_builtin_name(&t.name))
                .cloned(),
        );
        out
    }

    /// Simple queues that use type `name`.
    pub fn type_users(&self, name: &str) -> Vec<String> {
        self.simple
            .iter()
            .filter(|q| q.queue.upload == name || q.queue.download == name)
            .map(|q| q.name.clone())
            .collect()
    }

    pub fn simple_by_name(&self, name: &str) -> Option<&SimpleQueue> {
        self.simple.iter().find(|q| q.name == name)
    }

    /// A free `queue<N>` name (RouterOS names new queues so).
    pub fn free_name(&self) -> String {
        (1..)
            .map(|i| format!("queue{i}"))
            .find(|n| self.simple_by_name(n).is_none())
            .unwrap_or_else(|| "queue".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_parse_and_print_like_routeros() {
        for (t, v) in [
            ("0", 0),
            ("512k", 512_000),
            ("10M", 10_000_000),
            ("1.5M", 1_500_000),
            ("1G", 1_000_000_000),
            ("2.25G", 2_250_000_000),
            ("64000", 64_000),
        ] {
            assert_eq!(parse_rate(t).unwrap(), v, "{t}");
        }
        for bad in ["", "M", "1.2.3M", "-1M", "10T", "1e6", "99999999999G", "1.0000000001k"] {
            assert!(parse_rate(bad).is_err(), "{bad}");
        }
        assert_eq!(rate_text(10_000_000), "10M");
        assert_eq!(rate_text(1_500_000), "1500k");
        assert_eq!(rate_text(1_234), "1234");
        let p: Rates = "10M/20M".parse().unwrap();
        assert_eq!((p.upload, p.download), (10_000_000, 20_000_000));
        assert_eq!(p.to_string(), "10M/20M");
        let one: Rates = "5M".parse().unwrap();
        assert_eq!(one.to_string(), "5M/5M");
    }

    #[test]
    fn times_ratios_priorities() {
        assert_eq!(parse_times("8s/16").unwrap(), Pair { upload: 8000, download: 16_000 });
        assert_eq!(parse_time_ms("500ms").unwrap(), 500);
        assert_eq!(parse_time_ms("2m").unwrap(), 120_000);
        assert!(parse_time_ms("2h").is_err());
        assert!(parse_time_ms("99999999").is_err());
        assert_eq!(parse_ratio("0.1").unwrap(), 100);
        assert_eq!(parse_ratio(".25").unwrap(), 250);
        assert_eq!(parse_ratio("10000").unwrap(), 10_000_000);
        assert!(parse_ratio("10001").is_err());
        assert!(parse_ratio("0.0001").is_err());
        assert!(parse_ratio(".").is_err());
        assert_eq!(ratio_text(100), "0.1");
        assert_eq!(ratio_text(1250), "1.25");
        assert_eq!(ratio_text(2000), "2");
        assert!("0/8".parse::<Pair<u8>>().is_err());
        assert_eq!("1/8".parse::<Pair<u8>>().unwrap().to_string(), "1/8");
    }

    #[test]
    fn targets() {
        let t = parse_targets("10.0.0.5, 10.0.1.0/24,ether2, 2001:db8::/56, 10.0.0.5").unwrap();
        assert_eq!(t.len(), 4);
        assert_eq!(targets_text(&t), "10.0.0.5,10.0.1.0/24,ether2,2001:db8::/56");
        // Host bits are dropped, as RouterOS does.
        assert_eq!(parse_targets("10.0.1.7/24").unwrap()[0].to_string(), "10.0.1.0/24");
        assert!(parse_targets(" , ").is_err());
        assert!(parse_targets("not an interface name at all").is_err());
    }

    #[test]
    fn config_round_trips_and_builtins() {
        let mut q = Queues::default();
        let id = q.next_id();
        let mut s = SimpleQueue::new(id, "cli".into(), parse_targets("10.0.0.5").unwrap());
        s.max_limit = "10M/20M".parse().unwrap();
        s.burst_time = parse_times("8s").unwrap();
        q.simple.push(s);
        let mut t = QueueType::new("pcq-20M", Kind::Pcq);
        t.pcq_rate = 20_000_000;
        q.types.push(t);
        let j = serde_json::to_string(&q).unwrap();
        assert!(j.contains("\"max_limit\":\"10M/20M\""), "{j}");
        assert!(j.contains("\"burst_time\":\"8s/8s\""), "{j}");
        assert!(j.contains("\"bucket_size\":\"0.1/0.1\""), "{j}");
        let back: Queues = serde_json::from_str(&j).unwrap();
        assert_eq!(back, q);
        assert_eq!(q.queue_type("default-small").unwrap().pfifo_limit, 10);
        assert_eq!(q.queue_type("pcq-20M").unwrap().pcq_rate, 20_000_000);
        assert_eq!(q.all_types().len(), QueueType::builtins().len() + 1);
        assert_eq!(q.type_users("default-small"), vec!["cli".to_string()]);
        assert_eq!(q.free_name(), "queue1");
    }
}
