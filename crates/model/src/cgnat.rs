//! `/ip firewall cgnat` (G2.3): carrier-grade NAT44 pools and the one
//! mapping function every user of them shares.
//!
//! A pool translates a set of subscriber (inside) addresses, usually from
//! the shared address space 100.64.0.0/10 (RFC 6598), to a set of public
//! (outside) addresses, giving each subscriber its own range of ports:
//!
//! - **deterministic** (the default, RFC 7422): subscriber → public address
//!   and port range by a formula ([`Layout`]), so nothing has to be logged
//!   per connection or per subscriber: who used a public address and port
//!   at a given time comes out of the formula and the pool definition in
//!   force then;
//! - **blocks** (port block allocation, RFC 6888 §5 REQ-14 and RFC 7422 §1):
//!   blocks of the same geometry are handed out on demand and each
//!   allocation and release is logged.
//!
//! [`Layout`] is the stable API shared by the engine (rules, "who was",
//! the planner), the kernel backend (`hal-linux`) and the XDP data path
//! (`dataplane-ebpf`, G2.5): it lives in L0 so all of them can use it, and
//! it is pure (no I/O, no clock), so it compiles to wasm as well.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

use crate::firewall::PortRange;
use crate::types::{IfName, ItemId, ParseError};

/// Pools in the config (**estimado**, hostile-input bound).
pub const MAX_POOLS: usize = 64;
/// Inside or outside ranges of one pool.
pub const MAX_RANGES: usize = 64;
/// Subscribers of all pools together: each is one element of a kernel map
/// (about 200 bytes each, **estimado**), so a /11 per router.
pub const MAX_SUBSCRIBERS: u64 = 1 << 21;
/// Public addresses of one pool (a /16).
pub const MAX_PUBLIC: u64 = 1 << 16;
/// 1:1 exceptions.
pub const MAX_EXCEPTIONS: usize = 4096;
/// Blocks one subscriber may hold at once (blocks mode).
pub const MAX_BLOCKS: u8 = 32;
/// The smallest port range a subscriber can get: below this, one web page
/// already exhausts it (RFC 6888 §5 notes per-subscriber limits; 64 is the
/// floor A10 and Juniper accept, **estimado**).
pub const MIN_PORTS: u16 = 64;
/// Ports below this are well-known: RFC 4787 REQ-3 (and RFC 6888 §5) keeps
/// them out of the pools by default.
pub const FIRST_DYNAMIC: u16 = 1024;

/// A contiguous range of IPv4 addresses: `100.64.0.0/22` (every address
/// of it: a routed block has no network or broadcast address to skip),
/// `203.0.113.10-203.0.113.20` or one address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Range {
    pub start: Ipv4Addr,
    pub end: Ipv4Addr,
}

impl Range {
    pub fn new(start: Ipv4Addr, end: Ipv4Addr) -> Option<Self> {
        (u32::from(start) <= u32::from(end)).then_some(Self { start, end })
    }

    pub fn len(&self) -> u64 {
        u64::from(u32::from(self.end)) - u64::from(u32::from(self.start)) + 1
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        (u32::from(self.start)..=u32::from(self.end)).contains(&u32::from(ip))
    }

    pub fn overlaps(&self, other: &Self) -> bool {
        u32::from(self.start) <= u32::from(other.end)
            && u32::from(other.start) <= u32::from(self.end)
    }

    /// The address `offset` places after `start`, if still in the range.
    pub fn nth(&self, offset: u64) -> Option<Ipv4Addr> {
        let at = u64::from(u32::from(self.start)).checked_add(offset)?;
        let at = u32::try_from(at).ok()?;
        (at <= u32::from(self.end)).then(|| Ipv4Addr::from(at))
    }

    /// The prefix this range is exactly, if it is one.
    pub fn as_prefix(&self) -> Option<Ipv4Net> {
        let len = self.len();
        if !len.is_power_of_two() {
            return None;
        }
        let bits = 32 - u8::try_from(len.trailing_zeros()).ok()?;
        let net = Ipv4Net::new(self.start, bits).ok()?;
        (net.network() == self.start).then_some(net)
    }

    /// The fewest prefixes covering exactly this range, in order.
    pub fn prefixes(&self) -> Vec<Ipv4Net> {
        let mut out = Vec::new();
        let mut at = u64::from(u32::from(self.start));
        let end = u64::from(u32::from(self.end));
        while at <= end {
            // The largest aligned block starting at `at` that still fits.
            let align = if at == 0 { 32 } else { at.trailing_zeros().min(32) };
            let mut size = 1u64 << align;
            while at + size - 1 > end {
                size >>= 1;
            }
            let bits = 32 - u8::try_from(size.trailing_zeros()).unwrap_or(0);
            let Ok(start) = u32::try_from(at) else { break };
            if let Ok(net) = Ipv4Net::new(Ipv4Addr::from(start), bits) {
                out.push(net);
            }
            at += size;
        }
        out
    }
}

impl FromStr for Range {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        const HOW: &str = "expected 100.64.0.0/22, 203.0.113.10-203.0.113.20 or one address";
        let t = s.trim();
        if let Some((a, b)) = t.split_once('-') {
            let (Ok(a), Ok(b)) = (a.trim().parse::<Ipv4Addr>(), b.trim().parse::<Ipv4Addr>())
            else {
                return Err(ParseError::new("address range", s, HOW));
            };
            return Self::new(a, b).ok_or_else(|| {
                ParseError::new("address range", s, "the first address is after the last")
            });
        }
        if t.contains('/') {
            let net: Ipv4Net = t
                .parse()
                .map_err(|_| ParseError::new("address range", s, HOW))?;
            if net.trunc() != net {
                return Err(ParseError::new(
                    "address range",
                    s,
                    "host bits set: write the network address (100.64.0.0/22)",
                ));
            }
            return Ok(Self {
                start: net.network(),
                end: net.broadcast(),
            });
        }
        let ip: Ipv4Addr = t
            .parse()
            .map_err(|_| ParseError::new("address range", s, HOW))?;
        Ok(Self { start: ip, end: ip })
    }
}

impl fmt::Display for Range {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else if let Some(net) = self.as_prefix() {
            write!(f, "{net}")
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
    }
}

impl TryFrom<String> for Range {
    type Error = ParseError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<Range> for String {
    fn from(r: Range) -> Self {
        r.to_string()
    }
}

/// How a pool hands out ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    /// RFC 7422: fixed by formula, nothing logged.
    #[default]
    Deterministic,
    /// Port block allocation on demand, one log line per block.
    Blocks,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Deterministic => "deterministic",
            Mode::Blocks => "blocks",
        }
    }
}

impl FromStr for Mode {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim() {
            "deterministic" => Ok(Mode::Deterministic),
            "blocks" | "pba" => Ok(Mode::Blocks),
            _ => Err(ParseError::new("mode", s, "expected deterministic or blocks")),
        }
    }
}

fn default_ports() -> u16 {
    1000
}

fn default_port_range() -> PortRange {
    PortRange {
        first: FIRST_DYNAMIC,
        last: u16::MAX,
    }
}

fn default_true() -> bool {
    true
}

fn default_max_blocks() -> u8 {
    4
}

fn default_block_timeout() -> u32 {
    120
}

fn default_alert() -> u8 {
    90
}

fn is_true(b: &bool) -> bool {
    *b
}

/// One CGNAT pool (`ip.firewall.cgnat.pool.*`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pool {
    pub id: ItemId,
    pub name: String,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub mode: Mode,
    /// Subscriber addresses, in mapping order.
    pub inside: Vec<Range>,
    /// Public addresses, in mapping order.
    pub outside: Vec<Range>,
    /// Ports of each subscriber (deterministic) or of each block (blocks).
    #[serde(default = "default_ports")]
    pub ports_per_subscriber: u16,
    /// The ports handed out on each public address (1024-65535).
    #[serde(default = "default_port_range")]
    pub port_range: PortRange,
    /// Blocks mode: blocks one subscriber may hold at once.
    #[serde(default = "default_max_blocks")]
    pub max_blocks: u8,
    /// Blocks mode: seconds a block without connections is kept before it
    /// is released (and the release logged).
    #[serde(default = "default_block_timeout")]
    pub block_timeout: u32,
    /// Only translate traffic leaving through this interface (empty: any).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub out_interface: Option<IfName>,
    /// RFC 4787 REQ-1: the same public address and port for every
    /// destination of one subscriber's UDP source (needed by games, VoIP,
    /// WebRTC). Off: Linux's address-and-port-dependent mapping.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub endpoint_independent_mapping: bool,
    /// RFC 4787 REQ-8: any host may reach a live UDP mapping (full cone);
    /// off: only the hosts the subscriber talked to (the default the RFC
    /// recommends when security matters more than reachability).
    #[serde(default)]
    pub endpoint_independent_filtering: bool,
    /// RFC 4787 REQ-9: subscribers reach each other through their public
    /// address and port.
    #[serde(default = "default_true", skip_serializing_if = "is_true")]
    pub hairpin: bool,
    /// Percent of a subscriber's ports in use that raises the
    /// "ports exhausted" alert (0: never).
    #[serde(default = "default_alert")]
    pub alert_percent: u8,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

impl Pool {
    pub fn subscribers(&self) -> u64 {
        self.inside.iter().map(Range::len).sum()
    }

    pub fn public_addresses(&self) -> u64 {
        self.outside.iter().map(Range::len).sum()
    }

    /// The pool's geometry. Blocks mode may have more subscribers than
    /// blocks (they are handed out on demand): no capacity check there.
    pub fn layout(&self) -> Result<Layout, LayoutError> {
        Layout::build(
            &self.inside,
            &self.outside,
            self.port_range,
            self.ports_per_subscriber,
            self.mode == Mode::Deterministic,
        )
    }
}

/// A subscriber with a public address of its own, outside every pool's
/// (RFC 6888 §5 does not forbid it; every CGN vendor has it as "static
/// NAT"/"1:1"). Its connections keep their ports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exception {
    pub id: ItemId,
    pub subscriber: Ipv4Addr,
    pub public: Ipv4Addr,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

fn default_retention() -> u32 {
    365
}

/// `ip.firewall.cgnat.set`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    /// Days the mapping history ("who was", block log) is kept. Marco Civil
    /// (Lei 12.965/2014, art. 13) asks a year of connection records.
    #[serde(default = "default_retention")]
    pub history_days: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            history_days: default_retention(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Cgnat {
    pub pools: Vec<Pool>,
    pub exceptions: Vec<Exception>,
    pub settings: Settings,
    pub next_id: u32,
}

impl Cgnat {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    pub fn next_id(&mut self) -> ItemId {
        self.next_id = self.next_id.saturating_add(1);
        ItemId(self.next_id)
    }

    pub fn pool(&self, name: &str) -> Option<&Pool> {
        self.pools.iter().find(|p| p.name == name)
    }

    /// The enabled pool whose inside ranges hold `subscriber`.
    pub fn pool_of(&self, subscriber: Ipv4Addr) -> Option<&Pool> {
        self.pools
            .iter()
            .filter(|p| !p.disabled)
            .find(|p| p.inside.iter().any(|r| r.contains(subscriber)))
    }

    pub fn exception_of(&self, subscriber: Ipv4Addr) -> Option<&Exception> {
        self.exceptions
            .iter()
            .find(|e| !e.disabled && e.subscriber == subscriber)
    }
}

/// What one subscriber gets: a public address and a range of ports. TCP,
/// UDP and ICMP query ids (RFC 5508 §3.1) share the range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct Slot {
    pub public: Ipv4Addr,
    pub first_port: u16,
    pub last_port: u16,
}

impl Slot {
    pub fn ports(&self) -> u32 {
        u32::from(self.last_port) - u32::from(self.first_port) + 1
    }

    pub fn contains(&self, public: Ipv4Addr, port: u16) -> bool {
        self.public == public && (self.first_port..=self.last_port).contains(&port)
    }
}

impl fmt::Display for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}-{}", self.public, self.first_port, self.last_port)
    }
}

/// Why a pool cannot be laid out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LayoutError {
    NoInside,
    NoOutside,
    /// The ports per subscriber do not fit the port range even once.
    PortsTooMany { ports: u16, range: u32 },
    PortsTooFew { ports: u16 },
    /// More subscribers than slots: with the numbers to fix it.
    Capacity {
        subscribers: u64,
        capacity: u64,
        per_address: u32,
        public_needed: u64,
    },
    TooBig,
}

impl fmt::Display for LayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LayoutError::NoInside => write!(f, "no subscriber (inside) range"),
            LayoutError::NoOutside => write!(f, "no public (outside) range"),
            LayoutError::PortsTooMany { ports, range } => write!(
                f,
                "{ports} ports per subscriber do not fit the {range} ports of the port range"
            ),
            LayoutError::PortsTooFew { ports } => write!(
                f,
                "{ports} ports per subscriber is too few (at least {MIN_PORTS})"
            ),
            LayoutError::Capacity {
                subscribers,
                capacity,
                per_address,
                public_needed,
            } => write!(
                f,
                "{subscribers} subscribers but only {capacity} slots ({per_address} per public \
                 address): {public_needed} public addresses needed, or fewer ports per subscriber"
            ),
            LayoutError::TooBig => write!(f, "too many addresses"),
        }
    }
}

/// Ranges laid end to end: the address at a global index and back.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Line {
    /// (range, index of its first address), sorted by address.
    ranges: Vec<(Range, u64)>,
    /// The same ranges in mapping (index) order.
    order: Vec<(Range, u64)>,
    len: u64,
}

impl Line {
    fn new(ranges: &[Range]) -> Self {
        let mut order = Vec::with_capacity(ranges.len());
        let mut len = 0u64;
        for r in ranges {
            order.push((*r, len));
            len = len.saturating_add(r.len());
        }
        let mut sorted = order.clone();
        sorted.sort_by_key(|(r, _)| u32::from(r.start));
        Self {
            ranges: sorted,
            order,
            len,
        }
    }

    fn index(&self, ip: Ipv4Addr) -> Option<u64> {
        let key = u32::from(ip);
        let at = self
            .ranges
            .partition_point(|(r, _)| u32::from(r.start) <= key);
        let (r, base) = self.ranges.get(at.checked_sub(1)?)?;
        r.contains(ip)
            .then(|| base + u64::from(key - u32::from(r.start)))
    }

    fn at(&self, index: u64) -> Option<Ipv4Addr> {
        let at = self.order.partition_point(|(_, base)| *base <= index);
        let (r, base) = self.order.get(at.checked_sub(1)?)?;
        r.nth(index - base)
    }
}

/// The deterministic geometry of a pool (RFC 7422 §2): subscribers and
/// public addresses each numbered in the order their ranges are written,
/// the port range cut into blocks of `ports_per_subscriber`, and
/// subscriber `i` given public address `i / blocks_per_address` and block
/// `i % blocks_per_address` on it. Consecutive subscribers share a public
/// address (RFC 7422 §2 leaves the order to the operator; this one keeps a
/// subscriber's neighbors on its address, so one public address answers
/// for one contiguous run of subscribers, which is what an abuse desk
/// reads). Blocks mode uses the same blocks, handed out on demand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    inside: Line,
    outside: Line,
    first_port: u16,
    ports: u16,
    per_address: u32,
}

impl Layout {
    pub fn new(
        inside: &[Range],
        outside: &[Range],
        port_range: PortRange,
        ports: u16,
    ) -> Result<Self, LayoutError> {
        Self::build(inside, outside, port_range, ports, true)
    }

    /// [`Layout::new`]; `capacity`: refuse more subscribers than slots
    /// (deterministic), or not (blocks on demand).
    pub fn build(
        inside: &[Range],
        outside: &[Range],
        port_range: PortRange,
        ports: u16,
        capacity: bool,
    ) -> Result<Self, LayoutError> {
        if inside.is_empty() {
            return Err(LayoutError::NoInside);
        }
        if outside.is_empty() {
            return Err(LayoutError::NoOutside);
        }
        let range = u32::from(port_range.last) + 1 - u32::from(port_range.first.min(port_range.last));
        if ports < MIN_PORTS {
            return Err(LayoutError::PortsTooFew { ports });
        }
        if u32::from(ports) > range {
            return Err(LayoutError::PortsTooMany { ports, range });
        }
        let per_address = range / u32::from(ports);
        let inside = Line::new(inside);
        let outside = Line::new(outside);
        if inside.len > MAX_SUBSCRIBERS || outside.len > MAX_PUBLIC {
            return Err(LayoutError::TooBig);
        }
        let slots = outside.len * u64::from(per_address);
        if capacity && inside.len > slots {
            return Err(LayoutError::Capacity {
                subscribers: inside.len,
                capacity: slots,
                per_address,
                public_needed: inside.len.div_ceil(u64::from(per_address)),
            });
        }
        Ok(Self {
            inside,
            outside,
            first_port: port_range.first,
            ports,
            per_address,
        })
    }

    pub fn subscribers(&self) -> u64 {
        self.inside.len
    }

    pub fn public_addresses(&self) -> u64 {
        self.outside.len
    }

    /// Blocks (subscribers, in deterministic mode) on each public address.
    pub fn per_address(&self) -> u32 {
        self.per_address
    }

    pub fn capacity(&self) -> u64 {
        self.outside.len * u64::from(self.per_address)
    }

    pub fn ports(&self) -> u16 {
        self.ports
    }

    /// Public addresses the subscribers actually use.
    pub fn public_used(&self) -> u64 {
        self.inside
            .len
            .div_ceil(u64::from(self.per_address))
            .min(self.outside.len)
    }

    /// The subscriber's number in the pool.
    pub fn subscriber_index(&self, subscriber: Ipv4Addr) -> Option<u64> {
        self.inside.index(subscriber)
    }

    pub fn subscriber(&self, index: u64) -> Option<Ipv4Addr> {
        (index < self.inside.len).then(|| self.inside.at(index))?
    }

    /// Block `block` of public address number `address`.
    pub fn block(&self, address: u64, block: u32) -> Option<Slot> {
        if block >= self.per_address {
            return None;
        }
        let public = self.outside.at(address)?;
        let first = u32::from(self.first_port) + block * u32::from(self.ports);
        let last = first + u32::from(self.ports) - 1;
        Some(Slot {
            public,
            first_port: u16::try_from(first).ok()?,
            last_port: u16::try_from(last).ok()?,
        })
    }

    /// The slot of subscriber number `index`.
    pub fn slot(&self, index: u64) -> Option<Slot> {
        if index >= self.inside.len {
            return None;
        }
        let per = u64::from(self.per_address);
        self.block(index / per, u32::try_from(index % per).ok()?)
    }

    /// Deterministic forward mapping: the subscriber's public address and
    /// ports.
    pub fn forward(&self, subscriber: Ipv4Addr) -> Option<Slot> {
        self.slot(self.subscriber_index(subscriber)?)
    }

    /// The (address number, block number) holding `port` on `public`.
    pub fn locate(&self, public: Ipv4Addr, port: u16) -> Option<(u64, u32)> {
        let address = self.outside.index(public)?;
        let off = u32::from(port).checked_sub(u32::from(self.first_port))?;
        let block = off / u32::from(self.ports);
        (block < self.per_address).then_some((address, block))
    }

    /// Deterministic reverse mapping (RFC 7422 §2: "who was"): the
    /// subscriber that owns `port` on `public`, if any.
    pub fn reverse(&self, public: Ipv4Addr, port: u16) -> Option<Ipv4Addr> {
        let (address, block) = self.locate(public, port)?;
        let index = address * u64::from(self.per_address) + u64::from(block);
        self.subscriber(index)
    }

    /// Every subscriber with its slot, in index order.
    pub fn entries(&self) -> impl Iterator<Item = (Ipv4Addr, Slot)> + '_ {
        (0..self.inside.len).filter_map(|i| Some((self.subscriber(i)?, self.slot(i)?)))
    }
}

/// The planner's arithmetic (Tools › IP Calculator › CGNAT planner): what
/// a pool with these numbers would give, without the address lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Plan {
    pub subscribers: u64,
    pub public: u64,
    pub ports_per_subscriber: u16,
    pub port_range: u32,
    /// Subscribers on one public address.
    pub per_address: u32,
    /// Subscribers the public addresses can hold.
    pub capacity: u64,
    /// Public addresses the subscribers need.
    pub public_needed: u64,
    /// Ports of each public address no subscriber gets (the remainder).
    pub ports_left_per_address: u32,
    /// Ports per subscriber if the public addresses were shared out
    /// evenly (rounded down; 0 when there are more subscribers than ports).
    pub ports_if_spread: u32,
}

pub fn plan(subscribers: u64, public: u64, ports: u16, port_range: PortRange) -> Plan {
    let range = u32::from(port_range.last) + 1 - u32::from(port_range.first.min(port_range.last));
    let per_address = if ports == 0 { 0 } else { range / u32::from(ports) };
    let capacity = public.saturating_mul(u64::from(per_address));
    let public_needed = if per_address == 0 {
        0
    } else {
        subscribers.div_ceil(u64::from(per_address))
    };
    let ports_left_per_address = range.saturating_sub(per_address.saturating_mul(u32::from(ports)));
    let ports_if_spread = if subscribers == 0 {
        0
    } else {
        let per = subscribers.div_ceil(public.max(1));
        u32::try_from(u64::from(range) / per).unwrap_or(0)
    };
    Plan {
        subscribers,
        public,
        ports_per_subscriber: ports,
        port_range: range,
        per_address,
        capacity,
        public_needed,
        ports_left_per_address,
        ports_if_spread,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(s: &str) -> Range {
        s.parse().unwrap()
    }

    fn ports(first: u16, last: u16) -> PortRange {
        PortRange { first, last }
    }

    #[test]
    fn ranges_parse_and_print() {
        assert_eq!(r("100.64.0.0/22").len(), 1024);
        assert_eq!(r("100.64.0.0/22").to_string(), "100.64.0.0/22");
        assert_eq!(r("203.0.113.10-203.0.113.20").len(), 11);
        assert_eq!(r("203.0.113.0-203.0.113.7").to_string(), "203.0.113.0/29");
        assert_eq!(r("203.0.113.9").len(), 1);
        assert!("100.64.0.1/22".parse::<Range>().is_err());
        assert!("10.0.0.9-10.0.0.1".parse::<Range>().is_err());
        assert!("nope".parse::<Range>().is_err());
        assert_eq!(
            r("10.0.0.1-10.0.0.6").prefixes(),
            ["10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/31", "10.0.0.6/32"]
                .map(|p| p.parse::<Ipv4Net>().unwrap())
        );
        assert_eq!(r("0.0.0.0/0").len(), 1 << 32);
    }

    /// RFC 7422 §2 example geometry: 1000 ports each on 1024-65535 gives
    /// 64 subscribers per public address, 1535 ports left over.
    #[test]
    fn deterministic_layout() {
        let l = Layout::new(
            &[r("100.64.0.0/24")],
            &[r("203.0.113.1-203.0.113.4")],
            ports(1024, 65535),
            1000,
        )
        .unwrap();
        assert_eq!(l.per_address(), 64);
        assert_eq!(l.capacity(), 256);
        assert_eq!(l.public_used(), 4);
        let first = l.forward("100.64.0.0".parse().unwrap()).unwrap();
        assert_eq!(first.to_string(), "203.0.113.1:1024-2023");
        let s = l.forward("100.64.0.65".parse().unwrap()).unwrap();
        assert_eq!(s.to_string(), "203.0.113.2:2024-3023");
        assert_eq!(
            l.reverse("203.0.113.2".parse().unwrap(), 2500),
            Some("100.64.0.65".parse().unwrap())
        );
        // Below the range, in the left-over tail, or another address: nobody.
        assert_eq!(l.reverse("203.0.113.2".parse().unwrap(), 80), None);
        assert_eq!(l.reverse("203.0.113.2".parse().unwrap(), 65535), None);
        assert_eq!(l.reverse("203.0.113.9".parse().unwrap(), 2000), None);
        assert_eq!(l.entries().count(), 256);
    }

    #[test]
    fn capacity_errors_say_how_to_fix() {
        let e = Layout::new(&[r("100.64.0.0/22")], &[r("203.0.113.1")], ports(1024, 65535), 500)
            .unwrap_err();
        assert_eq!(
            e,
            LayoutError::Capacity {
                subscribers: 1024,
                capacity: 129,
                per_address: 129,
                public_needed: 8
            }
        );
        assert!(e.to_string().contains("8 public addresses needed"), "{e}");
        assert!(matches!(
            Layout::new(&[r("100.64.0.0/30")], &[r("203.0.113.1")], ports(1024, 1100), 500),
            Err(LayoutError::PortsTooMany { .. })
        ));
        assert!(matches!(
            Layout::new(&[r("100.64.0.0/30")], &[r("203.0.113.1")], ports(1024, 65535), 8),
            Err(LayoutError::PortsTooFew { .. })
        ));
    }

    /// Ranges are numbered in the order written, not by address.
    #[test]
    fn written_order_is_mapping_order() {
        let l = Layout::new(
            &[r("100.64.1.0/31"), r("100.64.0.0/31")],
            &[r("203.0.113.9"), r("203.0.113.1")],
            ports(1024, 65535),
            32_256,
        )
        .unwrap();
        assert_eq!(l.per_address(), 2);
        let s = |a: &str| l.forward(a.parse().unwrap()).unwrap().to_string();
        assert_eq!(s("100.64.1.0"), "203.0.113.9:1024-33279");
        assert_eq!(s("100.64.1.1"), "203.0.113.9:33280-65535");
        assert_eq!(s("100.64.0.0"), "203.0.113.1:1024-33279");
        assert_eq!(s("100.64.0.1"), "203.0.113.1:33280-65535");
        assert_eq!(l.subscriber(3), Some("100.64.0.1".parse().unwrap()));
        assert_eq!(l.subscriber(4), None);
    }

    #[test]
    fn planner_numbers() {
        let p = plan(4096, 32, 500, ports(1024, 65535));
        assert_eq!(p.per_address, 129);
        assert_eq!(p.capacity, 4128);
        assert_eq!(p.public_needed, 32);
        assert_eq!(p.ports_left_per_address, 64512 - 129 * 500);
        assert_eq!(p.ports_if_spread, 64512 / 128);
        let none = plan(0, 0, 0, ports(1024, 65535));
        assert_eq!((none.per_address, none.capacity, none.ports_if_spread), (0, 0, 0));
    }

    #[test]
    fn config_round_trip_keeps_defaults_out() {
        let mut c = Cgnat::default();
        assert!(c.is_empty());
        let id = c.next_id();
        c.pools.push(Pool {
            id,
            name: "cgnat1".into(),
            disabled: false,
            mode: Mode::Deterministic,
            inside: vec![r("100.64.0.0/22")],
            outside: vec![r("203.0.113.0/29")],
            ports_per_subscriber: 1000,
            port_range: default_port_range(),
            max_blocks: 4,
            block_timeout: 120,
            out_interface: None,
            endpoint_independent_mapping: true,
            endpoint_independent_filtering: false,
            hairpin: true,
            alert_percent: 90,
            comment: String::new(),
        });
        let text = serde_json::to_string(&c).unwrap();
        assert!(!text.contains("hairpin"), "{text}");
        let back: Cgnat = serde_json::from_str(&text).unwrap();
        assert_eq!(back, c);
    }

    mod props {
        use super::*;
        use proptest::prelude::*;
        use std::collections::HashSet;

        /// Up to 4 disjoint ranges cut from `base` (gaps between them).
        fn ranges(base: u32, max_len: u32) -> impl Strategy<Value = Vec<Range>> {
            proptest::collection::vec((0u32..64, 1u32..max_len), 1..4).prop_map(move |parts| {
                let mut at = base;
                parts
                    .into_iter()
                    .map(|(gap, len)| {
                        let start = at + gap;
                        at = start + len;
                        Range::new(Ipv4Addr::from(start), Ipv4Addr::from(start + len - 1)).unwrap()
                    })
                    .collect()
            })
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            /// RFC 7422 §2: f2(f1(x)) = x for every port of every slot, no
            /// two subscribers share a port, nothing outside a slot maps.
            #[test]
            fn forward_and_reverse_agree(
                inside in ranges(u32::from(Ipv4Addr::new(100, 64, 0, 0)), 300),
                outside in ranges(u32::from(Ipv4Addr::new(203, 0, 113, 0)), 8),
                first in 1u16..30000,
                width in 64u32..35535,
                ports in 64u16..5000,
                rev in any::<bool>(),
            ) {
                let mut inside = inside;
                if rev { inside.reverse(); }
                let last = u16::try_from((u32::from(first) + width).min(65535)).unwrap();
                let range = PortRange { first, last };
                let Ok(l) = Layout::new(&inside, &outside, range, ports) else {
                    // Refused only for a reason the planner agrees with.
                    let p = plan(inside.iter().map(Range::len).sum(), outside.iter().map(Range::len).sum(), ports, range);
                    prop_assert!(p.capacity < p.subscribers || u32::from(ports) > p.port_range);
                    return Ok(());
                };
                let mut used: HashSet<(Ipv4Addr, u16)> = HashSet::new();
                for (i, (sub, slot)) in l.entries().enumerate() {
                    prop_assert_eq!(l.subscriber_index(sub), Some(i as u64));
                    prop_assert_eq!(slot.ports(), u32::from(ports));
                    prop_assert!(slot.first_port >= first && slot.last_port <= last);
                    prop_assert!(outside.iter().any(|r| r.contains(slot.public)));
                    for port in [slot.first_port, slot.first_port + ports / 2, slot.last_port] {
                        prop_assert_eq!(l.reverse(slot.public, port), Some(sub));
                    }
                    // Blocks never overlap: each block's first port is unique.
                    prop_assert!(used.insert((slot.public, slot.first_port)));
                }
                prop_assert_eq!(used.len() as u64, l.subscribers());
                // Edges: below the port range and past the last block.
                for r in &outside {
                    if first > 0 {
                        prop_assert_eq!(l.reverse(r.start, first - 1), None);
                    }
                    let tail = u32::from(first) + l.per_address() * u32::from(ports);
                    if let Ok(t) = u16::try_from(tail) && t <= last {
                        prop_assert_eq!(l.reverse(r.start, t), None);
                    }
                }
                // Addresses outside the ranges map to nothing.
                prop_assert_eq!(l.forward(Ipv4Addr::new(100, 63, 255, 255)), None);
                prop_assert_eq!(l.reverse(Ipv4Addr::new(203, 0, 112, 255), first), None);
            }

            /// Hostile range text never panics, and what parses prints back.
            #[test]
            fn range_text_round_trips(t in "\\PC{0,40}") {
                if let Ok(r) = t.parse::<Range>() {
                    prop_assert_eq!(r.to_string().parse::<Range>().ok(), Some(r));
                }
            }
        }
    }
}
