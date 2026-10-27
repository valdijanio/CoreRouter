//! The virtual lab's neighbor tables (G1.27d): made up from the applied
//! config, deterministic, so tests and screenshots repeat.
//!
//! Every IPv4 subnet of the router (prefix up to /30) has lab hosts at
//! host numbers 1 to 12 and 254 (the router's own addresses aside); every
//! IPv6 prefix hosts `::1` (a router) to `::3` and `fe80::1`. They answer
//! ARP and Neighbor Solicitations; any other address does not. So a
//! static route through a gateway the lab has is `reachable` and one
//! through any other address is `incomplete` (the router asked, nobody
//! answered), like a gateway that is down. Static entries (`ip.arp.add`)
//! are `permanent`; an interface whose `arp` is `disabled` or
//! `reply-only` learns nothing.
//!
//! The feed ([`LabNeigh::feed`]) sees what each apply changes, and the
//! entries age as on a real box: `reachable` → `stale` → `delay` →
//! `probe` → `reachable`, one step per entry every few reads.

use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use corerouter_model::arp::ArpMode;
use corerouter_model::{Config, IfName, InterfaceKind};
use ipnet::IpNet;

use crate::HalError;
use crate::neigh::{
    ArpPinger, ArpReply, MAX_NEIGHBORS, NeighEvent, NeighState, Neighbor, NeighborFeed,
};

/// Host numbers of the lab hosts in each IPv4 subnet.
const HOSTS_V4: [u32; 13] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 254];
/// Interface ids of the lab hosts in each IPv6 prefix.
const HOSTS_V6: [u16; 3] = [1, 2, 3];
/// Changes the feed holds for a slow reader before it counts them lost.
const MAX_PENDING: usize = 16_384;
/// Feed reads between two aging steps of one entry.
const AGE_EVERY: u64 = 8;

type Key = (IfName, IpAddr);

#[derive(Debug, Default)]
struct Inner {
    table: BTreeMap<Key, Neighbor>,
    /// Changes not read yet by the feed (only while one is open).
    pending: VecDeque<NeighEvent>,
    feeding: bool,
    lost: u64,
    reads: u64,
}

impl Inner {
    fn push(&mut self, e: NeighEvent) {
        if !self.feeding {
            return;
        }
        if self.pending.len() >= MAX_PENDING {
            self.lost += 1;
            return;
        }
        self.pending.push_back(e);
    }
}

/// The lab's neighbor tables, shared by the lab HAL and its feed.
#[derive(Debug, Clone, Default)]
pub struct LabNeigh(Arc<Mutex<Inner>>);

impl LabNeigh {
    fn with<T>(&self, f: impl FnOnce(&mut Inner) -> T) -> T {
        f(&mut self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Bring the tables to what `cfg` makes, as changes.
    pub fn sync(&self, cfg: &Config) {
        let want = table(cfg);
        self.with(|i| {
            let gone: Vec<Key> = i
                .table
                .keys()
                .filter(|k| !want.contains_key(*k))
                .cloned()
                .collect();
            for (interface, address) in gone {
                i.table.remove(&(interface.clone(), address));
                i.push(NeighEvent::Remove { interface, address });
            }
            for (k, n) in want {
                let same = i
                    .table
                    .get(&k)
                    .is_some_and(|o| o.mac == n.mac && kind(o.state) == kind(n.state));
                if !same {
                    i.table.insert(k, n.clone());
                    i.push(NeighEvent::Upsert(n));
                }
            }
        });
    }

    pub fn snapshot(&self) -> Vec<Neighbor> {
        self.with(|i| i.table.values().cloned().collect())
    }

    /// Flush: the entries go (until the next apply learns them again).
    pub fn remove(&self, items: &[(IfName, IpAddr)]) -> usize {
        self.with(|i| {
            let mut n = 0;
            for (interface, address) in items {
                if i.table.remove(&(interface.clone(), *address)).is_some() {
                    n += 1;
                    i.push(NeighEvent::Remove {
                        interface: interface.clone(),
                        address: *address,
                    });
                }
            }
            n
        })
    }

    pub fn feed(&self) -> Box<dyn NeighborFeed> {
        self.with(|i| {
            i.feeding = true;
            i.pending.clear();
        });
        Box::new(Feed(self.clone()))
    }

    /// The MAC of the lab host at `ip` on `name`, if one is there.
    pub fn answer(&self, name: &IfName, ip: IpAddr) -> Option<[u8; 6]> {
        self.with(|i| {
            i.table
                .get(&(name.clone(), ip))
                .filter(|n| n.state.resolved())
                .and_then(|n| n.mac)
        })
    }

    pub fn pinger(&self, name: &IfName) -> Box<dyn ArpPinger> {
        Box::new(Pinger {
            lab: self.clone(),
            name: name.clone(),
        })
    }
}

/// Learned entries age; static ones are not compared by state.
fn kind(s: NeighState) -> u8 {
    match s {
        NeighState::Permanent => 0,
        NeighState::Incomplete | NeighState::Failed => 1,
        _ => 2,
    }
}

struct Feed(LabNeigh);

impl NeighborFeed for Feed {
    fn dump(&mut self, out: &mut Vec<Neighbor>) -> Result<bool, HalError> {
        self.0.with(|i| {
            out.extend(i.table.values().take(MAX_NEIGHBORS).cloned());
            Ok(i.table.len() <= MAX_NEIGHBORS)
        })
    }

    fn recv(
        &mut self,
        _wait_ms: u32,
        max: usize,
        out: &mut Vec<NeighEvent>,
    ) -> Result<(), HalError> {
        self.0.with(|i| {
            i.reads = i.reads.wrapping_add(1);
            age(i);
            let n = i.pending.len().min(max);
            out.extend(i.pending.drain(..n));
        });
        Ok(())
    }

    fn lost(&self) -> u64 {
        self.0.with(|i| i.lost)
    }

    fn name(&self) -> &'static str {
        "lab"
    }
}

/// One aging step: the entries whose turn it is move on.
fn age(i: &mut Inner) {
    let reads = i.reads;
    let mut changed = Vec::new();
    for (k, n) in i.table.iter_mut() {
        let turn = (hash(&k.0, k.1) ^ reads) % AGE_EVERY == 0;
        if !turn {
            continue;
        }
        let next = match n.state {
            NeighState::Reachable => NeighState::Stale,
            NeighState::Stale => NeighState::Delay,
            NeighState::Delay => NeighState::Probe,
            NeighState::Probe => NeighState::Reachable,
            _ => continue,
        };
        n.state = next;
        n.updated_secs = Some(0);
        if next == NeighState::Reachable {
            n.confirmed_secs = Some(0);
        }
        changed.push(n.clone());
    }
    for n in changed {
        i.push(NeighEvent::Upsert(n));
    }
}

struct Pinger {
    lab: LabNeigh,
    name: IfName,
}

impl ArpPinger for Pinger {
    fn ping(
        &mut self,
        _src: Ipv4Addr,
        target: Ipv4Addr,
        _timeout: Duration,
    ) -> Result<Option<ArpReply>, HalError> {
        let ip = IpAddr::V4(target);
        Ok(self.lab.answer(&self.name, ip).map(|mac| ArpReply {
            mac,
            // 0.2–0.9 ms, by host: a switch away.
            rtt: Duration::from_micros(200 + hash(&self.name, ip) % 700),
        }))
    }
}

fn hash(name: &IfName, ip: IpAddr) -> u64 {
    // FNV-1a: stable across runs and platforms (the lab is deterministic).
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut eat = |b: u8| {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    };
    name.as_str().bytes().for_each(&mut eat);
    match ip {
        IpAddr::V4(a) => a.octets().into_iter().for_each(&mut eat),
        IpAddr::V6(a) => a.octets().into_iter().for_each(&mut eat),
    }
    // splitmix64's finalizer: FNV alone leaves the high bytes alike for
    // neighbors whose addresses differ in the last octet.
    h = (h ^ (h >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    h = (h ^ (h >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    h ^ (h >> 31)
}

/// A lab host's MAC: half of them on a VMware OUI (`00:50:56`, so the
/// vendor column has something to show), the rest locally administered.
fn mac_of(name: &IfName, ip: IpAddr) -> [u8; 6] {
    let h = hash(name, ip).to_be_bytes();
    if h[0] & 1 == 0 {
        [0x00, 0x50, 0x56, h[1] & 0x3f, h[2], h[3]]
    } else {
        [0x02, h[1], h[2], h[3], h[4], h[5]]
    }
}

fn learned(name: &IfName, ip: IpAddr, router: bool) -> Neighbor {
    let h = hash(name, ip);
    let state = match h % 10 {
        0..=5 => NeighState::Reachable,
        6 | 7 => NeighState::Stale,
        8 => NeighState::Delay,
        _ => NeighState::Probe,
    };
    Neighbor {
        interface: name.clone(),
        address: ip,
        mac: Some(mac_of(name, ip)),
        state,
        router,
        confirmed_secs: u32::try_from(h % 40).ok(),
        updated_secs: u32::try_from(h % 25).ok(),
    }
}

fn unresolved(name: &IfName, ip: IpAddr) -> Neighbor {
    Neighbor {
        interface: name.clone(),
        address: ip,
        mac: None,
        state: NeighState::Incomplete,
        router: false,
        confirmed_secs: None,
        updated_secs: Some(1),
    }
}

/// The lab hosts of one subnet of the router.
fn hosts(net: IpNet) -> Vec<IpAddr> {
    match net {
        IpNet::V4(n) if n.prefix_len() <= 30 => {
            let base = u32::from(n.network());
            let last = u32::from(n.broadcast());
            HOSTS_V4
                .iter()
                .filter_map(|h| base.checked_add(*h))
                .filter(|a| *a < last)
                .map(|a| IpAddr::V4(Ipv4Addr::from(a)))
                .collect()
        }
        IpNet::V6(n)
            if n.prefix_len() <= 126
                && !corerouter_model::route::is_link_local(IpAddr::V6(n.addr())) =>
        {
            let base = u128::from(n.network());
            let mut v: Vec<IpAddr> = HOSTS_V6
                .iter()
                .map(|h| IpAddr::V6(Ipv6Addr::from(base | u128::from(*h))))
                .collect();
            v.push(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)));
            v
        }
        _ => Vec::new(),
    }
}

/// The tables `cfg` makes.
fn table(cfg: &Config) -> BTreeMap<Key, Neighbor> {
    let mut out = BTreeMap::new();
    let up = |n: &IfName| {
        cfg.interfaces
            .get(n)
            .is_some_and(|i| !i.disabled && i.kind != InterfaceKind::Loopback)
    };
    let ours: Vec<IpAddr> = cfg.ip.addresses.iter().map(|a| a.address.addr()).collect();
    for a in cfg.ip.addresses.iter() {
        if a.disabled || !up(&a.interface) {
            continue;
        }
        let mode = cfg.ip.arp.interface(&a.interface).mode;
        let v4 = a.address.addr().is_ipv4();
        if v4 && matches!(mode, ArpMode::Disabled | ArpMode::ReplyOnly) {
            continue;
        }
        for ip in hosts(a.address.trunc()) {
            if ours.contains(&ip) {
                continue;
            }
            let router = match ip {
                IpAddr::V6(x) => x.segments()[7] == 1,
                IpAddr::V4(_) => false,
            };
            out.insert((a.interface.clone(), ip), learned(&a.interface, ip, router));
        }
    }
    // The router asked for each gateway: one the lab lacks never answers.
    for r in cfg.ip.routes.iter().filter(|r| !r.disabled) {
        let Some(gw) = r.gateway.address() else {
            continue;
        };
        let Some(on) = cfg
            .ip
            .addresses
            .iter()
            .filter(|a| !a.disabled && up(&a.interface))
            .find(|a| a.address.trunc().contains(&gw))
        else {
            continue;
        };
        out.entry((on.interface.clone(), gw))
            .or_insert_with(|| unresolved(&on.interface, gw));
    }
    for e in cfg.ip.arp.active(|n| cfg.interfaces.contains_key(n)) {
        let ip = IpAddr::V4(e.address);
        out.insert(
            (e.interface.clone(), ip),
            Neighbor {
                interface: e.interface.clone(),
                address: ip,
                mac: Some(e.mac.0),
                state: NeighState::Permanent,
                router: false,
                confirmed_secs: None,
                updated_secs: None,
            },
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_model::arp::ArpEntry;
    use corerouter_model::{
        AddressEntry, Gateway, Interface, ItemId, MacAddr, RouteEntry, RoutingTable,
    };

    fn ports(names: &[&str]) -> Config {
        let mut c = Config::default();
        for n in names {
            let n: IfName = n.parse().unwrap();
            c.interfaces
                .insert(n.clone(), Interface::new(n, InterfaceKind::Ethernet));
        }
        c
    }

    fn cfg() -> Config {
        let mut c = ports(&["ether1", "ether2"]);
        c.ip.addresses.push(AddressEntry {
            id: ItemId(1),
            address: "10.0.0.1/24".parse().unwrap(),
            interface: "ether1".parse().unwrap(),
            disabled: false,
            comment: String::new(),
            from_pool: None,
        });
        c
    }

    #[test]
    fn hosts_of_a_subnet_answer_and_others_do_not() {
        let mut c = cfg();
        let ip = &mut c.ip;
        for (id, gw) in [(1, "10.0.0.254"), (2, "10.0.0.77")] {
            ip.routes.push(RouteEntry {
                id: ItemId(id),
                dst_address: format!("192.168.{id}.0/24").parse().unwrap(),
                gateway: Gateway::ip(gw.parse().unwrap()),
                distance: 1,
                routing_table: RoutingTable::Main,
                disabled: false,
                comment: String::new(),
            });
        }
        let t = table(&c);
        let e1: IfName = "ether1".parse().unwrap();
        let get = |a: &str| t.get(&(e1.clone(), a.parse().unwrap())).map(|n| n.state);
        assert!(get("10.0.0.254").is_some_and(NeighState::resolved));
        assert_eq!(get("10.0.0.77"), Some(NeighState::Incomplete));
        // The router's own address is not a neighbor.
        assert_eq!(get("10.0.0.1"), None);
        assert_eq!(t.len(), 13);
    }

    #[test]
    fn static_entries_are_permanent_and_reply_only_learns_nothing() {
        let mut c = cfg();
        let ip = &mut c.ip;
        let e1: IfName = "ether1".parse().unwrap();
        ip.arp.entries.push(ArpEntry {
            id: ItemId(1),
            address: "10.0.0.50".parse().unwrap(),
            mac: MacAddr([2, 0, 0, 0, 0, 0x50]),
            interface: e1.clone(),
            published: false,
            disabled: false,
            comment: String::new(),
        });
        ip.arp.set_interface(
            e1.clone(),
            corerouter_model::arp::ArpInterface {
                mode: ArpMode::ReplyOnly,
                timeout_secs: None,
            },
        );
        let t = table(&c);
        assert_eq!(t.len(), 1);
        assert!(t.values().all(|n| n.state == NeighState::Permanent));
    }

    #[test]
    fn the_feed_sees_applies_and_aging() {
        let lab = LabNeigh::default();
        let mut feed = lab.feed();
        lab.sync(&cfg());
        let mut ev = Vec::new();
        feed.recv(0, 10_000, &mut ev).unwrap();
        assert!(
            ev.iter()
                .filter(|e| matches!(e, NeighEvent::Upsert(_)))
                .count()
                >= 13
        );
        ev.clear();
        for _ in 0..AGE_EVERY {
            feed.recv(0, 10_000, &mut ev).unwrap();
        }
        assert!(!ev.is_empty(), "entries age");
        lab.sync(&ports(&["ether1"]));
        ev.clear();
        feed.recv(0, 10_000, &mut ev).unwrap();
        assert!(ev.iter().any(|e| matches!(e, NeighEvent::Remove { .. })));
        assert_eq!(feed.lost(), 0);
    }

    #[test]
    fn arp_ping_answers_for_lab_hosts_only() {
        let lab = LabNeigh::default();
        lab.sync(&cfg());
        let mut p = lab.pinger(&"ether1".parse().unwrap());
        let src = Ipv4Addr::new(10, 0, 0, 1);
        let t = Duration::from_millis(100);
        assert!(
            p.ping(src, Ipv4Addr::new(10, 0, 0, 2), t)
                .unwrap()
                .is_some()
        );
        assert!(
            p.ping(src, Ipv4Addr::new(10, 0, 0, 99), t)
                .unwrap()
                .is_none()
        );
    }
}
