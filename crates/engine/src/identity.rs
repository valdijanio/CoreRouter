//! Subscriber identity (G0.25): the name an operator already wrote for an
//! address, from the sources of the config and the DHCP server, so a table
//! of addresses (Connections, Torch, Traffic Flow, CGNAT › Who Was) can put
//! "João da Silva" next to `100.64.3.7`.
//!
//! Only what the router already knows is shown: comments, lease host names
//! and the PTRs of its own zones. Nothing is resolved over the network and
//! no I/O happens here, so a lookup under the session lock costs memory
//! reads only.
//!
//! The config part (static leases, IP › Addresses, address lists, PTRs) is an
//! index built once per change of those sections and kept in the session
//! (`Session::ext`): the sections are copy-on-write `Arc`s, and the index
//! holds a clone of each, so a pointer comparison says whether it is still
//! current. Thousands of addresses cost one hash lookup each.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use corerouter_model::config::{AddressEntry, Config};
use corerouter_model::cow::CowArc;
use corerouter_model::cow_list::CowList;
use corerouter_model::dhcp_server::DhcpServers;
use corerouter_model::dns_zone::{DnsZones, RecordType};
use corerouter_model::firewall::{AddrMatch, AddressListEntry};
use serde_json::{Value, json};

/// Longest name kept (characters); longer ones end in `…`.
pub const MAX_NAME: usize = 64;
/// An address list entry or an interface network names the addresses in
/// it only when it is this small (a /24, a /120): a comment on a /16 is a
/// note about the block, not a subscriber's name.
pub const MAX_SPAN: u128 = 256;
/// The hosts of an interface network the comment of IP › Addresses names:
/// a /29 or smaller (a /30, /31 to a subscriber), never a LAN's /24.
pub const MAX_LINK: u128 = 8;
/// Addresses of one lookup.
pub const MAX_ADDRESSES: usize = 4096;

/// Where a name came from, in the default order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Source {
    /// The PPPoE login of the session holding the address (G4.3d).
    Pppoe,
    /// The comment of a static DHCP lease.
    DhcpStatic,
    /// The host name the client sent with its lease.
    DhcpDynamic,
    /// The comment of IP › Addresses (the router's side of a /30, /31…).
    Address,
    /// The comment of an address list entry.
    AddressList,
    /// The PTR of one of the router's own zones.
    DnsPtr,
}

impl Source {
    pub const ALL: [Self; 6] = [
        Self::Pppoe,
        Self::DhcpStatic,
        Self::DhcpDynamic,
        Self::Address,
        Self::AddressList,
        Self::DnsPtr,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pppoe => "pppoe",
            Self::DhcpStatic => "dhcp-static",
            Self::DhcpDynamic => "dhcp-dynamic",
            Self::Address => "address",
            Self::AddressList => "address-list",
            Self::DnsPtr => "dns-ptr",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.as_str() == text)
    }
}

/// One name for an address.
#[derive(Clone, Debug, PartialEq)]
pub struct Name {
    pub source: Source,
    pub name: String,
    /// What else helps to tell it apart (the MAC, the list, the network).
    pub detail: Option<String>,
    /// The item to open: `{window, tab?, id, zone?}`, window ids of the GUI.
    pub item: Value,
}

/// A name as typed by someone (a comment, a client's host name): control
/// and bidirectional-override characters out (a name must not reorder or
/// break the line it is drawn in), spaces collapsed, at most [`MAX_NAME`]
/// characters. Empty when nothing printable is left.
pub fn clean(raw: &str) -> String {
    let mut out = String::new();
    let mut count = 0;
    let mut space = false;
    for c in raw.chars() {
        let bidi = matches!(c, '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}');
        if c.is_control() || bidi {
            space = !out.is_empty();
            continue;
        }
        if c.is_whitespace() {
            space = !out.is_empty();
            continue;
        }
        if space {
            out.push(' ');
            count += 1;
            space = false;
        }
        if count == MAX_NAME {
            out.push('…');
            return out;
        }
        out.push(c);
        count += 1;
    }
    out
}

/// An address as a number with its family, so v4 and v6 never meet.
type Key = (bool, u128);

fn key(ip: IpAddr) -> Key {
    match ip {
        IpAddr::V4(a) => (false, u128::from(u32::from(a))),
        IpAddr::V6(a) => (true, u128::from(a)),
    }
}

/// The block of 256 addresses an address is in.
fn block((v6, n): Key) -> Key {
    (v6, n >> 8)
}

/// Names from the config, by address.
#[derive(Default)]
struct Index {
    addresses: Option<CowList<AddressEntry>>,
    lists: Option<CowList<AddressListEntry>>,
    dhcp: Option<CowArc<DhcpServers>>,
    zones: Option<CowArc<DnsZones>>,
    /// One address.
    exact: HashMap<Key, Vec<Name>>,
    /// Small spans, by every block they touch: (first, last, name).
    spans: HashMap<Key, Vec<(u128, u128, Name)>>,
    builds: u64,
}

impl Index {
    fn current(&self, c: &Config) -> bool {
        self.addresses.as_ref().is_some_and(|a| CowList::ptr_eq(a, &c.ip.addresses))
            && self.lists.as_ref().is_some_and(|a| CowList::ptr_eq(a, c.ip.firewall.address_lists.list()))
            && self.dhcp.as_ref().is_some_and(|a| CowArc::ptr_eq(a, &c.ip.dhcp_server))
            && self.zones.as_ref().is_some_and(|a| CowArc::ptr_eq(a, &c.ip.dns_zones))
    }

    fn build(c: &Config, builds: u64) -> Self {
        let mut ix = Index {
            addresses: Some(c.ip.addresses.clone()),
            lists: Some(c.ip.firewall.address_lists.list().clone()),
            dhcp: Some(c.ip.dhcp_server.clone()),
            zones: Some(c.ip.dns_zones.clone()),
            builds: builds.saturating_add(1),
            ..Index::default()
        };
        for l in c.ip.dhcp_server.leases.iter().filter(|l| !l.disabled) {
            let name = clean(&l.comment);
            if name.is_empty() {
                continue;
            }
            ix.exact.entry(key(IpAddr::V4(l.address))).or_default().push(Name {
                source: Source::DhcpStatic,
                name,
                detail: l.mac_address.map(|m| m.to_string()),
                item: json!({"window": "dhcp-server", "tab": "leases", "id": l.address.to_string()}),
            });
        }
        for a in c.ip.addresses.iter().filter(|a| !a.disabled) {
            let name = clean(&a.comment);
            if name.is_empty() {
                continue;
            }
            let item = json!({"window": "addresses", "id": a.id.to_string()});
            let n = Name {
                source: Source::Address,
                name,
                detail: Some(format!("{} {}", a.address, a.interface)),
                item,
            };
            // The router's own address, and the hosts of a small network
            // (the subscriber's side of a /30 or /31).
            let net = a.address.trunc();
            let span = (key(net.network()), key(net.broadcast()));
            if span.1.1 - span.0.1 < MAX_LINK {
                ix.span(span.0, span.1.1, n);
            } else {
                ix.exact.entry(key(a.address.addr())).or_default().push(n);
            }
        }
        for e in c.ip.firewall.address_lists.iter().filter(|e| !e.disabled) {
            let name = clean(&e.comment);
            if name.is_empty() {
                continue;
            }
            let (lo, hi) = match e.address {
                AddrMatch::Net(n) => (key(n.network()), key(n.broadcast())),
                AddrMatch::Range(a, b) => (key(a), key(b)),
            };
            if lo.0 != hi.0 || hi.1 < lo.1 || hi.1 - lo.1 >= MAX_SPAN {
                continue;
            }
            ix.span(
                lo,
                hi.1,
                Name {
                    source: Source::AddressList,
                    name,
                    detail: Some(e.list.as_str().to_owned()),
                    item: json!({"window": "firewall", "tab": "address-lists", "id": e.id.to_string()}),
                },
            );
        }
        let zones = &c.ip.dns_zones;
        for r in zones.records.iter().filter(|r| r.rtype == RecordType::Ptr && !r.disabled) {
            let off = zones.zones.iter().any(|z| z.name == r.zone && z.disabled);
            let fqdn = if r.name == "@" { r.zone.clone() } else { format!("{}.{}", r.name, r.zone) };
            let (false, Some(ip)) = (off, reverse_name(&fqdn)) else {
                continue;
            };
            let name = clean(&r.target);
            if name.is_empty() {
                continue;
            }
            ix.exact.entry(key(ip)).or_default().push(Name {
                source: Source::DnsPtr,
                name,
                detail: Some(r.zone.clone()),
                item: json!({"window": "dns-zones", "tab": "records", "zone": r.zone, "id": r.id.to_string()}),
            });
        }
        ix
    }

    fn span(&mut self, lo: Key, hi: u128, n: Name) {
        let first = block(lo);
        let last = block((lo.0, hi));
        let mut b = first.1;
        while b <= last.1 {
            self.spans.entry((lo.0, b)).or_default().push((lo.1, hi, n.clone()));
            b += 1;
        }
    }

    fn names(&self, ip: IpAddr) -> impl Iterator<Item = &Name> {
        let k = key(ip);
        let exact = self.exact.get(&k).into_iter().flatten();
        let spans = self
            .spans
            .get(&block(k))
            .into_iter()
            .flatten()
            .filter(move |(lo, hi, _)| (*lo..=*hi).contains(&k.1))
            .map(|(_, _, n)| n);
        exact.chain(spans)
    }
}

/// The address a reverse name stands for: `7.3.64.100.in-addr.arpa` →
/// `100.64.3.7` (RFC 1035 §3.5), and the 32 nibbles of `ip6.arpa` (RFC 3596
/// §2.5). Anything else (a partial name, a classless delegation label like
/// `0/26`, RFC 2317) is `None`.
pub fn reverse_name(fqdn: &str) -> Option<IpAddr> {
    let name = fqdn.trim_end_matches('.').to_ascii_lowercase();
    if let Some(rest) = name.strip_suffix(".in-addr.arpa") {
        let labels: Vec<&str> = rest.split('.').collect();
        if labels.len() != 4 {
            return None;
        }
        let mut octets = [0u8; 4];
        for (o, l) in octets.iter_mut().zip(labels.iter().rev()) {
            if l.is_empty() || l.len() > 3 || !l.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            *o = l.parse().ok()?;
        }
        return Some(IpAddr::V4(Ipv4Addr::from(octets)));
    }
    let rest = name.strip_suffix(".ip6.arpa")?;
    let labels: Vec<&str> = rest.split('.').collect();
    if labels.len() != 32 {
        return None;
    }
    let mut n: u128 = 0;
    for l in labels.iter().rev() {
        let [c] = l.as_bytes() else {
            return None;
        };
        let d = char::from(*c).to_digit(16)?;
        n = (n << 4) | u128::from(d);
    }
    Some(IpAddr::V6(Ipv6Addr::from(n)))
}

/// The index kept in the session (`Session::ext`).
#[derive(Default)]
pub struct IdentityCache {
    index: Index,
}

impl IdentityCache {
    /// Times the index was built (tests: a second lookup reuses it).
    pub fn builds(&self) -> u64 {
        self.index.builds
    }

    /// The config's names of `ip`, the index made current first.
    pub fn config_names(&mut self, c: &Config, ip: IpAddr) -> Vec<Name> {
        if !self.index.current(c) {
            self.index = Index::build(c, self.index.builds);
        }
        self.index.names(ip).cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_names_are_cut_and_cleaned() {
        assert_eq!(clean("  João\tda\nSilva  "), "João da Silva");
        assert_eq!(clean("evil\u{202E}gnp.exe"), "evil gnp.exe");
        assert_eq!(clean("\u{0}\u{7}"), "");
        let long = "x".repeat(200);
        let c = clean(&long);
        assert_eq!(c.chars().count(), MAX_NAME + 1);
        assert!(c.ends_with('…'));
    }

    #[test]
    fn reverse_names_become_addresses() {
        assert_eq!(reverse_name("7.3.64.100.in-addr.arpa"), Some("100.64.3.7".parse().unwrap()));
        assert_eq!(reverse_name("3.64.100.in-addr.arpa"), None);
        assert_eq!(reverse_name("0/26.3.64.100.in-addr.arpa"), None);
        assert_eq!(reverse_name("300.3.64.100.in-addr.arpa"), None);
        // RFC 3596 §2.5's example.
        let v6 = "b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.ip6.arpa";
        assert_eq!(reverse_name(v6), Some("4321:0:1:2:3:4:567:89ab".parse().unwrap()));
    }

    #[test]
    fn sources_round_trip() {
        for s in Source::ALL {
            assert_eq!(Source::parse(s.as_str()), Some(s));
        }
    }
}
