//! The router side of CRDP: announce on the interfaces where discovery is
//! active, listen on them, and keep the session's neighbor table.
//!
//! Two transports ([`Transport`]): the host's real interfaces (linux
//! backend) or, for the virtual lab, the host's loopback, where labs on
//! one machine see each other and nothing reaches the network.
//!
//! Three threads: one sender (also expires the table every second) and one
//! receiver per address family. When the agent stops ([`Agent::shutdown`],
//! or drop) the sender says goodbye (hold 0) on every interface it was
//! announcing on, so neighbors forget us now, not after the hold time. Nothing is ever sent in reply to a
//! datagram: a forged announcement costs the sender one table entry at most
//! (bounded by `MAX_NEIGHBORS`), never traffic from us.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use corerouter_engine::{Session, Shared, lock};
use corerouter_model::{
    Config, IfName, MgmtPorts, NeighborDiscovery, NeighborEntry, NeighborProtocol,
};
use corerouter_proto_discovery::{
    Announcement, MAX_ADDRESSES, MAX_PACKET, MAX_TEXT, NodeId, fit_text,
};
use ipnet::IpNet;
use serde_json::json;

use crate::ifaces::{self, IfTable};
use crate::sock;

/// How often the sender wakes up: expiry, settings changes, due announcements.
const TICK: Duration = Duration::from_secs(1);
/// Shortest pause between two re-reads of the interface table by a receiver.
const RESCAN: Duration = Duration::from_secs(1);
/// A link that just came up has no IPv6 link-local address for a moment
/// (duplicate address detection): complain only after this.
const SETTLE: Duration = Duration::from_secs(10);

/// Where announcements go and come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    /// The kernel interfaces named like the config's (`--backend linux`):
    /// `ff02::1` and directed IPv4 broadcast out of each active interface.
    Interfaces,
    /// The virtual lab (`--backend virtual`): its ports exist only in
    /// memory, so every announcement goes to `127.255.255.255` and only
    /// loopback sources are heard. Same-named ports of all labs on the host
    /// share one wire: an announcement sent out of `ether1` arrives on the
    /// receiver's `ether1`, if discovery is active there.
    Loopback,
}

/// Port of the virtual lab where discovery is on out of the box
/// ([`enable_lab_default`]).
pub const LAB_INTERFACE: &str = "ether1";

/// Factory default of a new virtual lab: announce on [`LAB_INTERFACE`], so
/// two labs on one machine see each other without any command. Loopback
/// never leaves the host. Goes through `Session::execute` (journaled, saved
/// with `--config-dir`); call it only on a config that was not restored, so
/// an operator's later choice wins. Never for the linux backend: there the
/// default stays "no interface" (never announce on the WAN).
pub fn enable_lab_default(session: &mut Session) -> Result<(), String> {
    session
        .execute(
            "ip.neighbor.discovery.set",
            &json!({ "interfaces": [LAB_INTERFACE] }),
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
}

#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// UDP port (`corerouter_proto_discovery::PORT` unless testing).
    pub port: u16,
    pub node_id: NodeId,
    pub control_port: Option<u16>,
    pub ws_port: Option<u16>,
    /// Hardware/board text, e.g. "x86_64 (virtual lab)".
    pub board: String,
    pub transport: Transport,
}

/// Running CRDP threads; dropping it stops them (after the goodbye, like
/// [`Agent::shutdown`] without a deadline).
pub struct Agent {
    stop: Arc<AtomicBool>,
    /// Dropping it wakes the sender at once (it sleeps on the channel).
    wake: Option<mpsc::Sender<()>>,
    /// The sender returns how many goodbyes it sent.
    sender: Option<JoinHandle<usize>>,
    receivers: Vec<JoinHandle<()>>,
}

impl Agent {
    /// Open the sockets and start the threads. Fails only when the port
    /// cannot be opened at all; per-interface problems are logged.
    pub fn spawn(session: Shared, cfg: AgentConfig) -> io::Result<Agent> {
        let rx4 = sock::listen_v4(cfg.port)?;
        let rx6 = sock::listen_v6(cfg.port)?;
        let tx6 = UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0))?;
        let join6 = rx6.try_clone()?;
        let lo = match cfg.transport {
            Transport::Loopback => Some(sock::loopback_sender()?),
            Transport::Interfaces => None,
        };
        let stop = Arc::new(AtomicBool::new(false));
        let (wake, asleep) = mpsc::channel();
        let cfg = Arc::new(cfg);
        let mut receivers = Vec::new();
        for (name, rx) in [("crdp-rx4", rx4), ("crdp-rx6", rx6)] {
            let (session, cfg, stop) = (session.clone(), cfg.clone(), stop.clone());
            receivers.push(
                thread::Builder::new()
                    .name(name.into())
                    .spawn(move || receive_loop(&rx, &session, &cfg, &stop))?,
            );
        }
        let cfg2 = cfg.clone();
        let sender = thread::Builder::new()
            .name("crdp-tx".into())
            .spawn(move || {
                let tx = Tx {
                    v6: &tx6,
                    lo: lo.as_ref(),
                };
                send_loop(&tx, &join6, &session, &cfg2, &asleep)
            })?;
        let via = match cfg.transport {
            Transport::Interfaces => "the host interfaces of the same name",
            Transport::Loopback => "this host's loopback only (virtual lab)",
        };
        log::info!(
            "CRDP on UDP {} (node {}); announcing only on the interfaces in \
             ip.neighbor.discovery.set, through {via}",
            cfg.port,
            cfg.node_id
        );
        Ok(Agent {
            stop,
            wake: Some(wake),
            sender: Some(sender),
            receivers,
        })
    }

    /// Stop announcing: send the goodbye (hold 0) on every interface we
    /// were announcing on and return how many, or `None` when the sender
    /// did not finish `within` (it is left to finish on its own). The
    /// receivers are not waited for: they stop within `sock::RECV_TIMEOUT`.
    pub fn shutdown(mut self, within: Duration) -> Option<usize> {
        self.stop.store(true, Ordering::Relaxed);
        self.wake = None;
        let deadline = Instant::now() + within;
        let sender = self.sender.take()?;
        while !sender.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        self.receivers.clear();
        if !sender.is_finished() {
            return None;
        }
        sender.join().ok()
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.wake = None;
        if let Some(t) = self.sender.take() {
            let _ = t.join();
        }
        for t in self.receivers.drain(..) {
            let _ = t.join();
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// What the sender needs from the running config, copied out of the lock.
struct Snapshot {
    identity: String,
    settings: NeighborDiscovery,
    ifaces: BTreeMap<IfName, IfaceInfo>,
}

struct IfaceInfo {
    disabled: bool,
    mac: Option<[u8; 6]>,
    v4: Vec<(Ipv4Addr, u8)>,
    v6: Vec<(Ipv6Addr, u8)>,
}

impl Snapshot {
    fn of(cfg: &Config) -> Self {
        let mut ifaces: BTreeMap<IfName, IfaceInfo> = cfg
            .interfaces
            .values()
            .map(|i| {
                (
                    i.name.clone(),
                    IfaceInfo {
                        disabled: i.disabled,
                        mac: i.mac.map(|m| m.0),
                        v4: Vec::new(),
                        v6: Vec::new(),
                    },
                )
            })
            .collect();
        for a in cfg.ip.addresses.iter().filter(|a| !a.disabled) {
            let Some(info) = ifaces.get_mut(&a.interface) else {
                continue;
            };
            match a.address {
                IpNet::V4(n) => info.v4.push((n.addr(), n.prefix_len())),
                IpNet::V6(n) => info.v6.push((n.addr(), n.prefix_len())),
            }
        }
        Self {
            identity: cfg.system.identity.clone(),
            settings: cfg.ip.neighbor_discovery.clone(),
            ifaces,
        }
    }
}

/// Log a problem once until it goes away, not every interval.
#[derive(Default)]
struct Once(BTreeSet<String>);

impl Once {
    fn warn(&mut self, key: String, msg: impl FnOnce() -> String) {
        if self.0.insert(key) {
            log::warn!("{}", msg());
        }
    }

    fn clear(&mut self, key: &str) {
        self.0.remove(key);
    }
}

/// The sending sockets: `lo` is set for [`Transport::Loopback`].
struct Tx<'a> {
    v6: &'a UdpSocket,
    lo: Option<&'a UdpSocket>,
}

/// Runs until `wake` is disconnected (the agent stops); returns the number
/// of goodbyes sent then.
fn send_loop(
    tx: &Tx<'_>,
    rx6: &UdpSocket,
    session: &Shared,
    cfg: &AgentConfig,
    wake: &mpsc::Receiver<()>,
) -> usize {
    let started = Instant::now();
    let mut last_sent: BTreeMap<IfName, Instant> = BTreeMap::new();
    let mut active_since: BTreeMap<IfName, Instant> = BTreeMap::new();
    let mut last_settings: Option<NeighborDiscovery> = None;
    let mut warned = Once::default();
    loop {
        let snap = {
            let mut s = lock(session);
            let gone = s.expire_neighbors(unix_now());
            if gone > 0 {
                log::debug!("{gone} neighbor(s) expired");
            }
            Snapshot::of(s.store().running())
        };
        let changed = last_settings.as_ref() != Some(&snap.settings);
        last_settings = Some(snap.settings.clone());
        let interval = Duration::from_secs(u64::from(snap.settings.interval_secs.max(1)));
        // The lab's ports are not kernel interfaces, even when a host
        // interface happens to have the same name.
        let kernel = match tx.lo {
            Some(_) => IfTable::default(),
            None => ifaces::read(),
        };
        let uptime = started.elapsed().as_secs();

        let active: Vec<&IfName> = snap
            .ifaces
            .iter()
            .filter(|(n, i)| snap.settings.active_on(n) && !i.disabled)
            .map(|(n, _)| n)
            .collect();
        // Interfaces that stopped: say goodbye once, so neighbors forget us
        // now instead of after the hold time.
        let stopped: Vec<IfName> = last_sent
            .keys()
            .filter(|n| !active.contains(n))
            .cloned()
            .collect();
        active_since.retain(|n, _| active.contains(&n));
        for name in stopped {
            last_sent.remove(&name);
            if let Some(info) = snap.ifaces.get(&name) {
                let out = Out {
                    name: &name,
                    info,
                    hold_secs: 0,
                    uptime,
                    settled: true,
                };
                announce(tx, cfg, &snap, &out, &kernel, &mut warned);
            }
        }
        let hold = u16::try_from(snap.settings.hold_secs()).unwrap_or(u16::MAX);
        for name in active {
            if let Some(k) = kernel.get(name.as_str()) {
                sock::join_all_nodes(rx6, k.index);
            }
            let due = changed || last_sent.get(name).is_none_or(|t| t.elapsed() >= interval);
            let Some(info) = snap.ifaces.get(name) else {
                continue;
            };
            let since = *active_since
                .entry(name.clone())
                .or_insert_with(Instant::now);
            if due {
                let settled = since.elapsed() >= SETTLE;
                let out = Out {
                    name,
                    info,
                    hold_secs: hold,
                    uptime,
                    settled,
                };
                announce(tx, cfg, &snap, &out, &kernel, &mut warned);
                last_sent.insert(name.clone(), Instant::now());
            }
        }
        match wake.recv_timeout(TICK) {
            Ok(()) | Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    goodbye(tx, session, cfg, last_sent.keys(), started, &mut warned)
}

/// Hold 0 on each interface in `on`, from the running config as it is now
/// (an interface removed since is skipped). Returns how many were sent.
fn goodbye<'a>(
    tx: &Tx<'_>,
    session: &Shared,
    cfg: &AgentConfig,
    on: impl Iterator<Item = &'a IfName>,
    started: Instant,
    warned: &mut Once,
) -> usize {
    let snap = Snapshot::of(lock(session).store().running());
    let kernel = match tx.lo {
        Some(_) => IfTable::default(),
        None => ifaces::read(),
    };
    let uptime = started.elapsed().as_secs();
    let mut sent = 0;
    for name in on {
        let Some(info) = snap.ifaces.get(name) else {
            continue;
        };
        let out = Out {
            name,
            info,
            hold_secs: 0,
            uptime,
            settled: true,
        };
        if announce(tx, cfg, &snap, &out, &kernel, warned) {
            sent += 1;
        }
    }
    sent
}

/// One announcement to send.
struct Out<'a> {
    name: &'a IfName,
    info: &'a IfaceInfo,
    hold_secs: u16,
    uptime: u64,
    /// Active long enough that a missing IPv6 link is worth a warning.
    settled: bool,
}

/// True when at least one datagram went out.
fn announce(
    tx: &Tx<'_>,
    cfg: &AgentConfig,
    snap: &Snapshot,
    out: &Out<'_>,
    kernel: &IfTable,
    warned: &mut Once,
) -> bool {
    let Out {
        name,
        info,
        hold_secs,
        uptime,
        settled,
    } = *out;
    let k = kernel.get(name.as_str());
    let mut v6: Vec<(Ipv6Addr, u8)> = info.v6.clone();
    if let Some(k) = k {
        for g in &k.global {
            if !v6.iter().any(|(a, _)| *a == g.0) {
                v6.push(*g);
            }
        }
        for ll in &k.link_local {
            v6.push((*ll, 64));
        }
    }
    v6.truncate(MAX_ADDRESSES);
    let mut v4 = info.v4.clone();
    v4.truncate(MAX_ADDRESSES);
    let a = Announcement {
        node_id: cfg.node_id,
        hold_secs,
        identity: fit_text(&snap.identity, MAX_TEXT),
        version: env!("CARGO_PKG_VERSION").into(),
        platform: "CoreRouter".into(),
        board: fit_text(&cfg.board, MAX_TEXT),
        uptime_secs: Some(uptime),
        interface: name.to_string(),
        mac: info.mac,
        ipv4: v4.clone(),
        ipv6: v6,
        control_port: cfg.control_port,
        ws_port: cfg.ws_port,
    };
    let packet = match a.encode() {
        Ok(p) => p,
        Err(e) => {
            warned.warn(format!("{name}/encode"), || {
                format!("CRDP: cannot build the announcement for {name}: {e}")
            });
            return false;
        }
    };
    if let Some(lo) = tx.lo {
        return match sock::send_loopback(lo, &packet, cfg.port) {
            Ok(()) => {
                warned.clear("lo");
                log::debug!("CRDP announced {name} on loopback (hold {hold_secs} s)");
                true
            }
            Err(e) => {
                warned.warn("lo".into(), || {
                    format!("CRDP: cannot broadcast on loopback (virtual lab): {e}")
                });
                false
            }
        };
    }
    let mut sent = false;
    match k {
        // Still in duplicate address detection: nothing to send from yet.
        Some(k) if k.link_local.is_empty() && !settled => {}
        Some(k) => match sock::send_v6(tx.v6, &packet, k.index, cfg.port) {
            Ok(()) => {
                sent = true;
                warned.clear(&format!("{name}/v6"));
            }
            Err(e) => warned.warn(format!("{name}/v6"), || {
                format!("CRDP: cannot send on {name} (IPv6 ff02::1): {e}")
            }),
        },
        None if !settled => {}
        None => warned.warn(format!("{name}/v6"), || {
            format!(
                "CRDP: {name} has no usable IPv6 link in this kernel (virtual backend, \
                 interface down, or IPv6 off); no IPv6 announcement"
            )
        }),
    }
    for (addr, len) in v4 {
        let Ok(net) = ipnet::Ipv4Net::new(addr, len) else {
            continue;
        };
        if len >= 31 {
            continue;
        }
        match sock::send_v4(addr, net.broadcast(), &packet, cfg.port) {
            Ok(()) => {
                sent = true;
                warned.clear(&format!("{name}/{addr}"));
            }
            Err(e) => warned.warn(format!("{name}/{addr}"), || {
                format!("CRDP: cannot broadcast from {addr} on {name}: {e}")
            }),
        }
    }
    if sent {
        log::debug!("CRDP announced on {name} (hold {hold_secs} s)");
    }
    sent
}

fn receive_loop(rx: &UdpSocket, session: &Shared, cfg: &AgentConfig, stop: &AtomicBool) {
    let mut buf = [0u8; MAX_PACKET + 1];
    let mut kernel = ifaces::read();
    let mut scanned = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        let Some((a, from)) = sock::receive(rx, &mut buf) else {
            continue;
        };
        if a.node_id == cfg.node_id {
            continue;
        }
        let scope = match from {
            SocketAddr::V6(v6) if v6.scope_id() != 0 => Some(v6.scope_id()),
            _ => None,
        };
        if let Some(index) = scope
            && kernel.name_of(index).is_none()
            && scanned.elapsed() >= RESCAN
        {
            kernel = ifaces::read();
            scanned = Instant::now();
        }
        let mut s = lock(session);
        let running = s.store().running();
        let interface = match cfg.transport {
            Transport::Loopback => lab_interface(running, &a.interface, from.ip()),
            // Loopback is the virtual labs' wire, never a link of ours.
            Transport::Interfaces if from.ip().is_loopback() => None,
            Transport::Interfaces => arrival_interface(running, &kernel, scope, from.ip()),
        };
        let Some(interface) = interface else {
            log::debug!("CRDP from {from}: not on any of our interfaces");
            continue;
        };
        let entry = to_entry(a, interface, from.ip(), unix_now());
        let key = entry.key();
        let new = !s.neighbors().iter().any(|e| e.key() == key);
        let (identity, iface) = (entry.identity.clone(), entry.interface.clone());
        if s.record_neighbor(entry) && new {
            log::info!("CRDP neighbor '{identity}' ({}) on {iface}", from.ip());
        }
    }
}

/// Which of our interfaces a datagram came in on: the scope of a
/// link-local source, else the configured subnet that holds the source.
fn arrival_interface(
    cfg: &Config,
    kernel: &IfTable,
    scope: Option<u32>,
    src: IpAddr,
) -> Option<IfName> {
    if let Some(index) = scope {
        return kernel.name_of(index).and_then(|n| n.parse().ok());
    }
    let mut matches = cfg
        .ip
        .addresses
        .iter()
        .filter(|a| !a.disabled && a.address.contains(&src) && a.address.addr() != src)
        .map(|a| &a.interface);
    let first = matches.next()?.clone();
    let active = &cfg.ip.neighbor_discovery;
    Some(
        std::iter::once(&first)
            .chain(matches)
            .find(|i| active.active_on(i))
            .cloned()
            .unwrap_or(first),
    )
}

/// Virtual lab: the announcement arrives on our port with the name it was
/// sent out of, when that port exists and is enabled. Only loopback sources:
/// the lab has no other wire. Whether discovery is active there is
/// `record_neighbor`'s check.
fn lab_interface(cfg: &Config, sent_on: &str, src: IpAddr) -> Option<IfName> {
    if !src.is_loopback() {
        return None;
    }
    let name: IfName = sent_on.parse().ok()?;
    cfg.interfaces
        .get(&name)
        .filter(|i| !i.disabled)
        .map(|_| name)
}

/// Announcement → table row (pure).
pub fn to_entry(a: Announcement, interface: IfName, src: IpAddr, now: u64) -> NeighborEntry {
    let mut addresses: Vec<IpAddr> = a
        .ipv4
        .iter()
        .map(|(ip, _)| IpAddr::V4(*ip))
        .chain(a.ipv6.iter().map(|(ip, _)| IpAddr::V6(*ip)))
        .collect();
    if !addresses.contains(&src) {
        addresses.push(src);
    }
    let mgmt = (a.control_port.is_some() || a.ws_port.is_some()).then_some(MgmtPorts {
        control: a.control_port,
        ws: a.ws_port,
    });
    NeighborEntry {
        interface,
        protocol: NeighborProtocol::Crdp,
        mac: a.mac.map(corerouter_model::MacAddr),
        addresses,
        identity: a.identity,
        version: a.version,
        platform: a.platform,
        board: a.board,
        uptime_secs: a.uptime_secs,
        node_id: Some(a.node_id.to_string()),
        remote_interface: (!a.interface.is_empty()).then_some(a.interface),
        mgmt,
        last_seen: now,
        hold_secs: u32::from(a.hold_secs),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_model::AddressEntry;
    use corerouter_model::ItemId;

    #[test]
    fn arrival_by_subnet_prefers_an_active_interface() {
        let mut cfg = Config::default();
        for (id, (addr, iface)) in [("10.0.0.1/24", "ether1"), ("10.0.0.9/16", "ether2")]
            .into_iter()
            .enumerate()
        {
            cfg.ip.addresses.push(AddressEntry {
                id: ItemId(id as u32),
                address: addr.parse().unwrap(),
                interface: iface.parse().unwrap(),
                disabled: false,
                comment: String::new(),
            });
        }
        let t = IfTable::default();
        let src: IpAddr = "10.0.0.2".parse().unwrap();
        assert_eq!(
            arrival_interface(&cfg, &t, None, src).unwrap().as_str(),
            "ether1"
        );
        cfg.ip
            .neighbor_discovery
            .interfaces
            .insert("ether2".parse().unwrap());
        assert_eq!(
            arrival_interface(&cfg, &t, None, src).unwrap().as_str(),
            "ether2"
        );
        assert!(arrival_interface(&cfg, &t, None, "192.0.2.1".parse().unwrap()).is_none());
    }

    #[test]
    fn lab_port_is_the_same_name_from_loopback_only() {
        let mut s = Session::virtual_lab();
        s.execute(
            "interface.set",
            &json!({ "name": "ether2", "disabled": true }),
        )
        .unwrap();
        let cfg = s.store().running();
        let lo: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(lab_interface(cfg, "ether1", lo).unwrap().as_str(), "ether1");
        assert!(lab_interface(cfg, "ether1", "::1".parse().unwrap()).is_some());
        // Real network, disabled port, unknown port, garbage name.
        assert!(lab_interface(cfg, "ether1", "10.0.0.2".parse().unwrap()).is_none());
        assert!(lab_interface(cfg, "ether2", lo).is_none());
        assert!(lab_interface(cfg, "ether99", lo).is_none());
        assert!(lab_interface(cfg, "", lo).is_none());
        assert!(lab_interface(cfg, "a b\n", lo).is_none());
    }

    #[test]
    fn entry_keeps_announced_addresses_first() {
        let a = Announcement {
            node_id: NodeId([1; 16]),
            hold_secs: 120,
            identity: "r2".into(),
            version: "0.1.0".into(),
            platform: "CoreRouter".into(),
            board: String::new(),
            uptime_secs: Some(5),
            interface: "ether3".into(),
            mac: None,
            ipv4: vec![(Ipv4Addr::new(10, 0, 0, 2), 24)],
            ipv6: Vec::new(),
            control_port: Some(7979),
            ws_port: None,
        };
        let e = to_entry(a, "ether1".parse().unwrap(), "fe80::2".parse().unwrap(), 9);
        assert_eq!(
            e.addresses,
            [
                "10.0.0.2".parse::<IpAddr>().unwrap(),
                "fe80::2".parse().unwrap()
            ]
        );
        assert_eq!(e.remote_interface.as_deref(), Some("ether3"));
        assert_eq!(e.mgmt.unwrap().control, Some(7979));
        assert_eq!(e.node_id.unwrap(), "01".repeat(16));
    }
}
