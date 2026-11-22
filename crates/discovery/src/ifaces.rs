//! Kernel interface index ↔ name, and the IPv6 link-local addresses, from
//! `/proc/net/if_inet6`.
//!
//! Why here and not in the `Hal`: CRDP needs the interface index to send on
//! one link (`ff02::1%index`) and to tell which link a datagram came from
//! (the scope id of its link-local source). `LinkInfo` has no index yet
//! (netlink discovery is G1.7). `/proc/net` belongs to the reader's network
//! namespace, unlike `/sys/class/net`, so this also works in the netns tests.

use std::collections::BTreeMap;
use std::net::Ipv6Addr;

/// `IFA_F_TENTATIVE`: duplicate address detection is still running.
const TENTATIVE: u32 = 0x40;
/// `IFA_F_DADFAILED`.
const DAD_FAILED: u32 = 0x08;
/// Lines read at most (one per address): hostile or broken files stay bounded.
const MAX_LINES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Iface {
    pub index: u32,
    /// Usable (not tentative) link-local addresses.
    pub link_local: Vec<Ipv6Addr>,
    /// Other usable IPv6 addresses.
    pub global: Vec<(Ipv6Addr, u8)>,
    /// Addresses still in duplicate address detection: not usable yet,
    /// but already this host's.
    pub tentative: Vec<Ipv6Addr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IfTable {
    by_name: BTreeMap<String, Iface>,
}

impl IfTable {
    pub fn get(&self, name: &str) -> Option<&Iface> {
        self.by_name.get(name)
    }

    pub fn name_of(&self, index: u32) -> Option<&str> {
        self.by_name
            .iter()
            .find(|(_, i)| i.index == index)
            .map(|(n, _)| n.as_str())
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &Iface)> {
        self.by_name.iter().map(|(n, i)| (n.as_str(), i))
    }

    /// True when `addr` is one of this host's IPv6 addresses, tentative
    /// ones included.
    pub fn has_address(&self, addr: &Ipv6Addr) -> bool {
        self.by_name.values().any(|i| {
            i.link_local.contains(addr)
                || i.tentative.contains(addr)
                || i.global.iter().any(|(a, _)| a == addr)
        })
    }
}

/// Parse the text of `/proc/net/if_inet6`:
/// `fe800000000000000000000000000001 03 40 20 80     eth0`
/// (address, index, prefix length, scope, flags, name; numbers in hex).
/// Bad lines are skipped.
pub fn parse(text: &str) -> IfTable {
    let mut table = IfTable::default();
    for line in text.lines().take(MAX_LINES) {
        let f: Vec<&str> = line.split_whitespace().collect();
        let [addr, index, plen, _scope, flags, name] = f.as_slice() else {
            continue;
        };
        let (Some(addr), Ok(index), Ok(plen), Ok(flags)) = (
            parse_addr(addr),
            u32::from_str_radix(index, 16),
            u8::from_str_radix(plen, 16),
            u32::from_str_radix(flags, 16),
        ) else {
            continue;
        };
        if name.len() > 64 || index == 0 {
            continue;
        }
        let entry = table
            .by_name
            .entry((*name).to_owned())
            .or_insert_with(|| Iface {
                index,
                ..Iface::default()
            });
        if flags & DAD_FAILED != 0 {
            continue;
        }
        if flags & TENTATIVE != 0 {
            entry.tentative.push(addr);
            continue;
        }
        if addr.is_unicast_link_local() {
            entry.link_local.push(addr);
        } else if !addr.is_loopback() {
            entry.global.push((addr, plen.min(128)));
        }
    }
    table
}

fn parse_addr(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 || !hex.is_ascii() {
        return None;
    }
    let mut octets = [0u8; 16];
    for (i, b) in octets.iter_mut().enumerate() {
        *b = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(Ipv6Addr::from(octets))
}

/// The table of this network namespace; empty where there is no `/proc`.
pub fn read() -> IfTable {
    match std::fs::read_to_string("/proc/net/if_inet6") {
        Ok(text) => parse(&text),
        Err(e) => {
            log::debug!("no /proc/net/if_inet6 ({e}): IPv6 discovery is off");
            IfTable::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proc_lines() {
        let text = "\
fe800000000000000000000000000001 03 40 20 80     eth0
20010db8000000000000000000000001 03 40 00 80     eth0
fe800000000000000000000000000002 04 40 20 c0     veth1
00000000000000000000000000000001 01 80 10 80       lo
garbage
zz800000000000000000000000000002 05 40 20 80     bad0
";
        let t = parse(text);
        let eth0 = t.get("eth0").unwrap();
        assert_eq!(eth0.index, 3);
        assert_eq!(eth0.link_local, ["fe80::1".parse::<Ipv6Addr>().unwrap()]);
        assert_eq!(eth0.global, [("2001:db8::1".parse().unwrap(), 64)]);
        // Tentative address: the interface is known, the address is not usable yet.
        let veth = t.get("veth1").unwrap();
        assert_eq!(veth.index, 4);
        assert!(veth.link_local.is_empty());
        assert!(t.has_address(&"fe80::2".parse().unwrap()));
        assert!(t.get("lo").unwrap().global.is_empty());
        assert!(t.get("bad0").is_none());
        assert_eq!(t.name_of(4), Some("veth1"));
        assert!(t.has_address(&"2001:db8::1".parse().unwrap()));
    }
}
