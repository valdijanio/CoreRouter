//! LLDP (sent and received) and MNDP (received only) into the neighbor
//! table (G5.2, docs/discovery.md §7).
//!
//! Glue between the frames/datagrams of `hal-linux::l2` (L1) and the codecs
//! of `proto-lldp` / `proto-mndp` (L2): only an app may use a platform
//! crate, so it lives here. One thread, non-blocking sockets:
//!
//! - every [`TICK`]: read what arrived, decode, `record_neighbor`;
//! - every second: re-read the running config, open/close LLDP ports to
//!   match the interfaces where discovery is active, send the LLDPDUs that
//!   are due (every `interval_secs`, TTL = `hold_secs()`, or at once when
//!   what we would say changed), and a shutdown LLDPDU (TTL 0) on a port
//!   that leaves discovery.
//!
//! MNDP is never sent: CoreRouter does not pretend to be a MikroTik.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use corerouter_engine::{Shared, lock};
use corerouter_hal_linux::l2::{LldpFrame, LldpIo, MndpListener, UdpDatagram};
use corerouter_model::{Config, IfName, InterfaceKind, MacAddr, NeighborEntry, NeighborProtocol};
use corerouter_proto_lldp::{Capabilities, ChassisId, Lldpdu, ManagementAddress, PortId};

/// How often the thread looks for received frames.
const TICK: Duration = Duration::from_millis(200);
/// How often it re-reads the config and sends what is due.
const CONFIG_EVERY: Duration = Duration::from_secs(1);
/// Retry opening LLDP ports that failed (missing interface, no permission).
const RETRY: Duration = Duration::from_secs(10);
/// MNDP carries no hold time. RouterOS announces every 30 s by default
/// (MikroTik "Neighbor discovery" manual); keep a MikroTik for 4 of its
/// intervals, like LLDP's TTL.
pub const MNDP_HOLD_SECS: u32 = 120;
/// Management addresses per LLDPDU (the PDU must fit one Ethernet frame).
const MAX_MGMT_ADDRS: usize = 8;
/// Longest text kept from a received LLDPDU/MNDP packet, in bytes.
const MAX_TEXT: usize = 128;

/// What goes into our LLDPDUs besides the per-port data.
#[derive(Debug, Clone)]
pub struct LocalSystem {
    /// Chassis ID (subtype "locally assigned"): the CRDP node id, so an LLDP
    /// row and a CRDP row of the same CoreRouter share `node_id`.
    pub chassis: String,
    /// System Description: `CoreRouter <version>`.
    pub description: String,
}

/// The running thread; dropping it sends the shutdown LLDPDUs and stops it.
pub struct LinkDiscovery {
    stop: Arc<AtomicBool>,
    /// Returns how many ports got the shutdown LLDPDU.
    thread: Option<JoinHandle<usize>>,
}

impl LinkDiscovery {
    /// Start the thread. Never fails the daemon: a socket that cannot be
    /// opened (no `CAP_NET_RAW`, port taken) is logged and that protocol
    /// stays off.
    pub fn spawn(session: Shared, local: LocalSystem, mndp_port: u16) -> std::io::Result<Self> {
        let mndp = match MndpListener::bind(mndp_port) {
            Ok(l) => {
                log::info!("MNDP: listening on UDP {mndp_port} (receive only, never sent)");
                Some(l)
            }
            Err(e) => {
                log::error!("MNDP is off: cannot listen on UDP {mndp_port}: {e}");
                None
            }
        };
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let thread = thread::Builder::new()
            .name("lldp-mndp".into())
            .spawn(move || run(&session, &local, mndp, &stop2))?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }

    /// Stop: the shutdown LLDPDU (TTL 0) on every open port; how many, or
    /// `None` when the thread did not finish `within`.
    pub fn shutdown(mut self, within: Duration) -> Option<usize> {
        self.stop.store(true, Ordering::Relaxed);
        let deadline = Instant::now() + within;
        let t = self.thread.take()?;
        while !t.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        if !t.is_finished() {
            return None;
        }
        t.join().ok()
    }
}

impl Drop for LinkDiscovery {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub identity: String,
    pub interval_secs: u32,
    pub ttl_secs: u16,
    /// Interfaces where discovery is active (and the interface enabled).
    pub active: BTreeMap<IfName, PortInfo>,
}

/// What our LLDPDU says about one port.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PortInfo {
    /// Configured addresses (Management Address TLVs).
    pub addresses: Vec<IpAddr>,
    /// Interface comment (Port Description), if any.
    pub comment: String,
    /// A bridge or a bridge port: the bridge capability is on.
    pub bridged: bool,
}

impl Snapshot {
    pub fn of(cfg: &Config) -> Self {
        let settings = &cfg.ip.neighbor_discovery;
        let mut active: BTreeMap<IfName, PortInfo> = cfg
            .interfaces
            .values()
            .filter(|i| !i.disabled && settings.active_on(&i.name))
            .map(|i| {
                let info = PortInfo {
                    addresses: Vec::new(),
                    comment: i.comment.clone(),
                    bridged: i.bridge.is_some() || i.kind == InterfaceKind::Bridge,
                };
                (i.name.clone(), info)
            })
            .collect();
        for a in cfg.ip.addresses.iter().filter(|a| !a.disabled) {
            if let Some(port) = active.get_mut(&a.interface) {
                port.addresses.push(a.address.addr());
            }
        }
        Self {
            identity: cfg.system.identity.clone(),
            interval_secs: settings.interval_secs.max(1),
            ttl_secs: u16::try_from(settings.hold_secs()).unwrap_or(u16::MAX),
            active,
        }
    }
}

/// Our LLDPDU for one port (pure).
pub fn local_lldpdu(
    local: &LocalSystem,
    identity: &str,
    port: &IfName,
    info: &PortInfo,
    if_index: u32,
    ttl_secs: u16,
) -> Lldpdu {
    let mut du = Lldpdu::new(
        ChassisId::Local(local.chassis.clone()),
        PortId::InterfaceName(port.to_string()),
        ttl_secs,
    );
    du.port_description = (!info.comment.is_empty()).then(|| fit(&info.comment, 255));
    du.system_name = (!identity.is_empty()).then(|| fit(identity, 255));
    du.system_description = Some(local.description.clone());
    du.capabilities = Some(Capabilities {
        system: Capabilities::ROUTER | Capabilities::BRIDGE,
        enabled: Capabilities::ROUTER
            | if info.bridged {
                Capabilities::BRIDGE
            } else {
                0
            },
    });
    du.management_addresses = info
        .addresses
        .iter()
        .take(MAX_MGMT_ADDRS)
        .map(|ip| ManagementAddress::ip(*ip, if_index))
        .collect();
    du
}

/// Received LLDPDU → table row (pure). `None` when it does not decode.
pub fn lldp_entry(frame: &LldpFrame, now: u64) -> Option<NeighborEntry> {
    let du = match corerouter_proto_lldp::decode(&frame.lldpdu) {
        Ok(du) => du,
        Err(e) => {
            log::debug!(
                "LLDP on {} from {}: dropped: {e}",
                frame.interface,
                corerouter_proto_lldp::format_mac(&frame.src_mac)
            );
            return None;
        }
    };
    let description = du
        .system_description
        .as_deref()
        .map(clean)
        .unwrap_or_default();
    // Our own System Description is "CoreRouter <version>": split it so an
    // LLDP row of a CoreRouter reads like its CRDP row. Anything else is
    // kept whole as the version text (that is what it usually holds).
    let (platform, version) = match description.split_once(' ') {
        Some(("CoreRouter", v)) => ("CoreRouter".to_owned(), v.to_owned()),
        _ => (String::new(), description),
    };
    let addresses = du
        .management_addresses
        .iter()
        .filter_map(|m| match m.address {
            corerouter_proto_lldp::MgmtAddr::Ip(ip) => Some(ip),
            corerouter_proto_lldp::MgmtAddr::Other { .. } => None,
        })
        .collect();
    let board = du
        .capabilities
        .map(|c| Capabilities::names(c.enabled).join(","))
        .unwrap_or_default();
    Some(NeighborEntry {
        interface: frame.interface.clone(),
        protocol: NeighborProtocol::Lldp,
        mac: Some(MacAddr(frame.src_mac)),
        addresses,
        identity: du.system_name.as_deref().map(clean).unwrap_or_default(),
        version,
        platform,
        board,
        uptime_secs: None,
        node_id: Some(clean(&du.chassis_id.to_string())),
        remote_interface: Some(clean(&du.port_id.to_string())),
        mgmt: None,
        last_seen: now,
        hold_secs: u32::from(du.ttl_secs),
    })
}

/// Received MNDP datagram → table row (pure). `None` when it does not
/// decode or its arrival interface is unknown.
pub fn mndp_entry(d: &UdpDatagram, now: u64) -> Option<NeighborEntry> {
    let interface = d.interface.clone()?;
    let a = match corerouter_proto_mndp::decode(&d.payload) {
        Ok(a) => a,
        Err(e) => {
            log::debug!("MNDP on {interface} from {}: dropped: {e}", d.src);
            return None;
        }
    };
    let mut addresses: Vec<IpAddr> = a
        .ipv4
        .map(IpAddr::V4)
        .into_iter()
        .chain(a.ipv6.map(IpAddr::V6))
        .collect();
    let src = match d.src {
        SocketAddr::V4(s) => IpAddr::V4(*s.ip()),
        SocketAddr::V6(s) => IpAddr::V6(*s.ip()),
    };
    if !addresses.contains(&src) {
        addresses.push(src);
    }
    let text = |t: &Option<String>| t.as_deref().map(clean).unwrap_or_default();
    Some(NeighborEntry {
        interface,
        protocol: NeighborProtocol::Mndp,
        mac: Some(MacAddr(a.mac)),
        addresses,
        identity: text(&a.identity),
        version: text(&a.version),
        platform: text(&a.platform),
        board: text(&a.board),
        uptime_secs: a.uptime_secs.map(u64::from),
        // No node id in MNDP: the row is keyed by the sender's MAC, so its
        // IPv4 and IPv6 announcements land in one row.
        node_id: None,
        remote_interface: a.interface_name.as_deref().map(clean),
        mgmt: None,
        last_seen: now,
        hold_secs: MNDP_HOLD_SECS,
    })
}

/// Hostile text → printable, bounded.
fn clean(s: &str) -> String {
    let s: String = s
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect();
    fit(&s, MAX_TEXT)
}

/// Cut `s` to at most `max` bytes on a char boundary.
fn fit(s: &str, max: usize) -> String {
    let mut end = s.len().min(max);
    while !s.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    s.get(..end).unwrap_or_default().to_owned()
}

/// Log a problem once until it goes away, not every second.
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

struct Lldp<'a> {
    io: LldpIo,
    local: &'a LocalSystem,
    /// What was last sent on each open port, to resend at once on change.
    sent: BTreeMap<IfName, Vec<u8>>,
    /// Ports wanted but not open, and when to try again.
    retry_at: Option<Instant>,
    warned: Once,
}

impl Lldp<'_> {
    /// Open/close ports to match `snap`; shutdown LLDPDU on ports leaving.
    fn reconcile(&mut self, snap: &Snapshot, now: Instant) {
        let open: Vec<IfName> = self.io.interfaces().into_iter().map(|(n, _)| n).collect();
        let leaving: Vec<&IfName> = open
            .iter()
            .filter(|n| !snap.active.contains_key(*n))
            .collect();
        for name in &leaving {
            self.send(snap, name, 0, now);
            self.sent.remove(*name);
        }
        let missing = snap.active.keys().any(|n| !open.contains(n));
        let retry = self.retry_at.is_none_or(|t| now >= t);
        if leaving.is_empty() && !(missing && retry) {
            return;
        }
        let wanted: Vec<IfName> = snap.active.keys().cloned().collect();
        let failed = self.io.set_interfaces(&wanted);
        self.retry_at = (!failed.is_empty()).then(|| now + RETRY);
        for name in &wanted {
            if !failed.iter().any(|(n, _)| n == name) {
                self.warned.clear(&format!("open/{name}"));
            }
        }
        for (name, e) in failed {
            self.warned.warn(format!("open/{name}"), || {
                if e.kind() == std::io::ErrorKind::PermissionDenied {
                    format!(
                        "LLDP is off on {name}: no permission for a raw socket ({e}); the \
                         daemon needs CAP_NET_RAW and CAP_NET_ADMIN (run as root, or \
                         `setcap cap_net_raw,cap_net_admin+ep` on the binary). CRDP and \
                         MNDP still work."
                    )
                } else {
                    format!(
                        "LLDP is off on {name}: {e} (retrying every {}s)",
                        RETRY.as_secs()
                    )
                }
            });
        }
    }

    /// Send what is due, or changed, on every open port.
    fn announce(&mut self, snap: &Snapshot, now: Instant) {
        self.io
            .set_interval(Duration::from_secs(u64::from(snap.interval_secs)));
        let due = self.io.due(now);
        for (name, _) in self.io.interfaces() {
            let Some(pdu) = self.encode(snap, &name, snap.ttl_secs) else {
                continue;
            };
            if due.contains(&name) || self.sent.get(&name) != Some(&pdu) {
                self.transmit(&name, &pdu, now);
            }
        }
    }

    fn encode(&mut self, snap: &Snapshot, name: &IfName, ttl: u16) -> Option<Vec<u8>> {
        let none = PortInfo::default();
        let info = snap.active.get(name).unwrap_or(&none);
        let index = self.io.ifindex(name).unwrap_or(0);
        let du = local_lldpdu(self.local, &snap.identity, name, info, index, ttl);
        match corerouter_proto_lldp::encode(&du) {
            Ok(p) => {
                self.warned.clear(&format!("encode/{name}"));
                Some(p)
            }
            Err(e) => {
                self.warned.warn(format!("encode/{name}"), || {
                    format!("LLDP: cannot build the LLDPDU for {name}: {e}")
                });
                None
            }
        }
    }

    fn send(&mut self, snap: &Snapshot, name: &IfName, ttl: u16, now: Instant) {
        if let Some(pdu) = self.encode(snap, name, ttl) {
            self.transmit(name, &pdu, now);
        }
    }

    fn transmit(&mut self, name: &IfName, pdu: &[u8], now: Instant) {
        match self.io.send(name, pdu, now) {
            Ok(()) => {
                self.warned.clear(&format!("send/{name}"));
                self.sent.insert(name.clone(), pdu.to_vec());
                log::debug!("LLDP sent on {name}");
            }
            Err(e) => self.warned.warn(format!("send/{name}"), || {
                format!("LLDP: cannot send on {name}: {e}")
            }),
        }
    }

    /// Shutdown LLDPDU on every open port, then close them; how many ports.
    fn close(&mut self, snap: &Snapshot, now: Instant) -> usize {
        let mut n = 0;
        for (name, _) in self.io.interfaces() {
            self.send(snap, &name, 0, now);
            n += 1;
        }
        self.io.set_interfaces(&[]);
        n
    }
}

/// Returns how many ports got the shutdown LLDPDU when `stop` is set.
fn run(
    session: &Shared,
    local: &LocalSystem,
    mut mndp: Option<MndpListener>,
    stop: &AtomicBool,
) -> usize {
    let mut lldp = Lldp {
        io: LldpIo::new(Duration::from_secs(u64::from(
            corerouter_proto_lldp::TX_INTERVAL_SECS,
        ))),
        local,
        sent: BTreeMap::new(),
        retry_at: None,
        warned: Once::default(),
    };
    let mut snap: Option<Snapshot> = None;
    let mut config_at: Option<Instant> = None;
    while !stop.load(Ordering::Relaxed) {
        let now = Instant::now();
        if config_at.is_none_or(|t| now.saturating_duration_since(t) >= CONFIG_EVERY) {
            config_at = Some(now);
            let s = {
                let mut s = lock(session);
                // CRDP's agent expires too; doing it here as well keeps
                // LLDP/MNDP rows expiring when the CRDP port did not open.
                s.expire_neighbors(unix_now());
                Snapshot::of(s.store().running())
            };
            lldp.reconcile(&s, now);
            lldp.announce(&s, now);
            snap = Some(s);
        }
        let frames = lldp.io.recv();
        let datagrams = mndp.as_mut().map(MndpListener::recv).unwrap_or_default();
        if !frames.is_empty() || !datagrams.is_empty() {
            let at = unix_now();
            let entries = frames
                .iter()
                .filter_map(|f| lldp_entry(f, at))
                .chain(datagrams.iter().filter_map(|d| mndp_entry(d, at)));
            let mut s = lock(session);
            for e in entries {
                let key = e.key();
                let new = e.hold_secs > 0 && !s.neighbors().iter().any(|x| x.key() == key);
                let (proto, identity, iface) =
                    (e.protocol, e.identity.clone(), e.interface.clone());
                if s.record_neighbor(e) && new {
                    log::info!("{proto} neighbor '{identity}' on {iface}");
                }
            }
        }
        thread::sleep(TICK);
    }
    match &snap {
        Some(s) => lldp.close(s, Instant::now()),
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_model::{AddressEntry, Interface, ItemId};
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn local() -> LocalSystem {
        LocalSystem {
            chassis: "0123456789abcdef0123456789abcdef".into(),
            description: "CoreRouter 0.1.0".into(),
        }
    }

    fn name(s: &str) -> IfName {
        s.parse().unwrap()
    }

    #[test]
    fn our_lldpdu_reads_back_as_a_corerouter_row() {
        let addrs: Vec<IpAddr> = vec!["10.0.0.1".parse().unwrap(), "2001:db8::1".parse().unwrap()];
        let info = PortInfo {
            addresses: addrs.clone(),
            comment: "uplink".into(),
            bridged: false,
        };
        let du = local_lldpdu(&local(), "r1", &name("ether2"), &info, 7, 120);
        assert_eq!(du.port_description.as_deref(), Some("uplink"));
        let frame = LldpFrame {
            interface: name("ether1"),
            src_mac: [2, 0, 0, 0, 0, 9],
            lldpdu: corerouter_proto_lldp::encode(&du).unwrap(),
        };
        let e = lldp_entry(&frame, 50).unwrap();
        assert_eq!(e.protocol, NeighborProtocol::Lldp);
        assert_eq!(e.interface, name("ether1"));
        assert_eq!(e.identity, "r1");
        assert_eq!(e.platform, "CoreRouter");
        assert_eq!(e.version, "0.1.0");
        assert_eq!(e.board, "router");
        assert_eq!(
            e.node_id.as_deref(),
            Some("0123456789abcdef0123456789abcdef")
        );
        assert_eq!(e.remote_interface.as_deref(), Some("ether2"));
        assert_eq!(e.addresses, addrs);
        assert_eq!(e.mac, Some(MacAddr([2, 0, 0, 0, 0, 9])));
        assert_eq!((e.last_seen, e.hold_secs), (50, 120));
    }

    #[test]
    fn shutdown_lldpdu_has_hold_zero_and_garbage_is_dropped() {
        let bridged = PortInfo {
            bridged: true,
            ..PortInfo::default()
        };
        let du = local_lldpdu(&local(), "", &name("ether1"), &bridged, 0, 0);
        assert!(du.system_name.is_none());
        assert!(du.port_description.is_none());
        assert_eq!(
            du.capabilities.unwrap().enabled,
            Capabilities::ROUTER | Capabilities::BRIDGE
        );
        let frame = LldpFrame {
            interface: name("ether1"),
            src_mac: [2; 6],
            lldpdu: corerouter_proto_lldp::encode(&du).unwrap(),
        };
        assert_eq!(lldp_entry(&frame, 1).unwrap().hold_secs, 0);
        let junk = LldpFrame {
            lldpdu: vec![0xff; 40],
            ..frame
        };
        assert!(lldp_entry(&junk, 1).is_none());
    }

    #[test]
    fn foreign_description_is_the_version_and_text_is_cleaned() {
        let mut du = Lldpdu::new(
            ChassisId::Mac([0, 1, 2, 3, 4, 5]),
            PortId::InterfaceName("Gi0/1".into()),
            120,
        );
        du.system_description = Some("Cisco IOS Software, 15.2".into());
        du.system_name = Some("sw\u{7}1".into());
        let frame = LldpFrame {
            interface: name("ether1"),
            src_mac: [2; 6],
            lldpdu: corerouter_proto_lldp::encode(&du).unwrap(),
        };
        let e = lldp_entry(&frame, 1).unwrap();
        assert_eq!(e.version, "Cisco IOS Software, 15.2");
        assert_eq!(e.platform, "");
        assert_eq!(e.identity, "sw?1");
        assert_eq!(e.node_id.as_deref(), Some("00:01:02:03:04:05"));
        assert_eq!(e.remote_interface.as_deref(), Some("Gi0/1"));
    }

    /// A RouterOS-like announcement, built by hand (no MNDP encoder exists).
    fn mndp_packet() -> Vec<u8> {
        let mut p = vec![0, 0, 0, 1];
        let mut tlv = |t: u16, v: &[u8]| {
            p.extend_from_slice(&t.to_be_bytes());
            p.extend_from_slice(&u16::try_from(v.len()).unwrap().to_be_bytes());
            p.extend_from_slice(v);
        };
        tlv(1, &[0x4c, 0x5e, 0x0c, 1, 2, 3]);
        tlv(5, b"MikroTik");
        tlv(7, b"7.16 (stable)");
        tlv(8, b"MikroTik");
        tlv(10, &3600u32.to_le_bytes());
        tlv(12, b"RB5009UG+S+");
        tlv(16, b"ether5");
        tlv(17, &[192, 168, 88, 1]);
        p
    }

    #[test]
    fn mndp_fields_map_one_to_one() {
        let d = UdpDatagram {
            interface: Some(name("ether1")),
            src: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 88, 1), 5678)),
            payload: mndp_packet(),
        };
        let e = mndp_entry(&d, 10).unwrap();
        assert_eq!(e.protocol, NeighborProtocol::Mndp);
        assert_eq!(e.identity, "MikroTik");
        assert_eq!(e.version, "7.16 (stable)");
        assert_eq!(e.platform, "MikroTik");
        assert_eq!(e.board, "RB5009UG+S+");
        assert_eq!(e.uptime_secs, Some(3600));
        assert_eq!(e.remote_interface.as_deref(), Some("ether5"));
        assert_eq!(e.mac, Some(MacAddr([0x4c, 0x5e, 0x0c, 1, 2, 3])));
        assert_eq!(e.addresses, ["192.168.88.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(e.hold_secs, MNDP_HOLD_SECS);
        // Keyed by MAC: the IPv6 copy of the same announcement is one row.
        assert_eq!(e.key().2, "4C:5E:0C:01:02:03");

        let unknown_iface = UdpDatagram {
            interface: None,
            ..d.clone()
        };
        assert!(mndp_entry(&unknown_iface, 10).is_none());
        let junk = UdpDatagram {
            payload: vec![1, 2],
            ..d
        };
        assert!(mndp_entry(&junk, 10).is_none());
    }

    #[test]
    fn snapshot_lists_only_active_enabled_interfaces() {
        let mut cfg = Config::default();
        for (i, n) in ["ether1", "ether2", "ether3"].iter().enumerate() {
            let mut iface = Interface::new(name(n), InterfaceKind::Ethernet);
            iface.disabled = i == 2;
            cfg.interfaces.insert(name(n), iface);
        }
        cfg.ip.addresses.push(AddressEntry {
            id: ItemId(1),
            address: "10.0.0.1/24".parse().unwrap(),
            interface: name("ether1"),
            disabled: false,
            comment: String::new(),
            from_pool: None,
        });
        let d = &mut cfg.ip.neighbor_discovery;
        d.interfaces = [name("ether1"), name("ether3")].into_iter().collect();
        let s = Snapshot::of(&cfg);
        assert_eq!(s.active.keys().collect::<Vec<_>>(), [&name("ether1")]);
        assert_eq!(
            s.active[&name("ether1")].addresses,
            ["10.0.0.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!((s.interval_secs, s.ttl_secs), (30, 120));
        cfg.ip.neighbor_discovery.enabled = false;
        assert!(Snapshot::of(&cfg).active.is_empty());
    }

    #[test]
    fn fit_cuts_on_a_char_boundary() {
        assert_eq!(fit("ação", 2), "a");
        assert_eq!(fit("abc", 10), "abc");
    }
}
