//! Packet capture for Tools › Torch and the packet sniffer (G6.4a).
//!
//! The engine never opens sockets: a [`Hal`](crate::Hal) hands out a
//! [`PacketCapture`] (`Send + Sync`, used from a task thread without the
//! session lock), which opens [`CaptureSocket`]s on an interface. A socket
//! fills a [`FrameBatch`] with the first bytes of every frame seen in either
//! direction, the frame's length on the wire, and when it was seen.
//!
//! Sampling (`1 in N`) is the socket's job, so a backend can do it where it
//! is cheapest: `hal-linux` in a classic BPF filter in the kernel (the
//! frame never reaches user space), a future XDP backend (G2.5) in its
//! program. The engine only asks for a rate and scales the counts.
//!
//! Also here, pure and shared by every backend: [`decode`] (Ethernet,
//! 802.1Q/802.1ad, IPv4, IPv6, TCP, UDP, SCTP headers — hostile input,
//! fuzzed by proptest), the classic pcap file format ([`pcap_header`],
//! [`pcap_record`]) and [`SimCapture`], deterministic traffic for the
//! virtual lab.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;

/// Most bytes of a frame a socket keeps (a jumbo frame and its tags).
pub const MAX_SNAPLEN: u16 = 9216;
/// What Torch needs: Ethernet + two tags + IPv6 + a few extension headers
/// + the ports.
pub const HEADERS_SNAPLEN: u16 = 128;
/// Interfaces one capture listens on (the interface and its VLANs).
pub const MAX_DEVICES: usize = 64;

/// Which way a frame crossed the interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Dir {
    /// Received on the interface.
    Rx,
    /// Sent out of it by the router.
    Tx,
}

/// One device a capture listens on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureDevice {
    pub name: String,
    /// The VLAN this device is (a VLAN interface on the captured one):
    /// its frames are counted under this id, and the parent drops its
    /// tagged copies so nothing is counted twice.
    pub vlan: Option<u16>,
}

/// What to capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureSpec {
    /// The interface first, then its VLAN interfaces when they are asked
    /// for (at most [`MAX_DEVICES`] in all).
    pub devices: Vec<CaptureDevice>,
    /// Bytes kept of each frame (at most [`MAX_SNAPLEN`]).
    pub snaplen: u16,
    /// Keep one frame in this many (1 = all).
    pub sample: u32,
}

/// Where one frame of a [`FrameBatch`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameMeta {
    /// Since the socket was opened.
    pub at: Duration,
    pub dir: Dir,
    /// The VLAN device it was seen on ([`CaptureDevice::vlan`]).
    pub vlan: Option<u16>,
    /// Its length on the wire (without the Ethernet FCS).
    pub wire_len: u32,
    start: usize,
    len: usize,
}

/// Frames read in one go, their bytes back to back in one buffer: no
/// allocation per frame on the hot path.
#[derive(Debug, Clone, Default)]
pub struct FrameBatch {
    buf: Vec<u8>,
    frames: Vec<FrameMeta>,
    capacity: usize,
}

impl FrameBatch {
    /// A batch of at most `frames` frames.
    pub fn new(frames: usize) -> Self {
        Self {
            buf: Vec::new(),
            frames: Vec::with_capacity(frames),
            capacity: frames.max(1),
        }
    }

    pub fn clear(&mut self) {
        self.buf.clear();
        self.frames.clear();
    }

    pub fn is_full(&self) -> bool {
        self.frames.len() >= self.capacity
    }

    pub fn len(&self) -> usize {
        self.frames.len()
    }

    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    /// Add a frame (its first `data.len()` bytes); ignored when full.
    pub fn push(&mut self, at: Duration, dir: Dir, vlan: Option<u16>, wire_len: u32, data: &[u8]) {
        if self.is_full() {
            return;
        }
        let start = self.buf.len();
        self.buf.extend_from_slice(data);
        self.frames.push(FrameMeta {
            at,
            dir,
            vlan,
            wire_len,
            start,
            len: data.len(),
        });
    }

    pub fn iter(&self) -> impl Iterator<Item = (&FrameMeta, &[u8])> + '_ {
        self.frames.iter().map(|m| {
            let data = self.buf.get(m.start..m.start + m.len).unwrap_or(&[]);
            (m, data)
        })
    }
}

/// The interface's own counters (all its traffic, before any sampling):
/// what the capture should have seen.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct LinkTotals {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CaptureError {
    /// No such interface.
    #[error("{0}")]
    NoDevice(String),
    /// The socket cannot be opened (no `CAP_NET_RAW`, unsupported…).
    #[error("{0}")]
    Unavailable(String),
    #[error("{0}")]
    Io(String),
}

/// An open capture.
pub trait CaptureSocket: Send {
    /// Append the frames that arrive within `wait` to `batch` (until it is
    /// full). Returns early once something arrived. A simulated socket
    /// does not block: it returns at once with `wait` worth of traffic, and
    /// [`Self::blocks`] says so, so the caller sleeps the rest.
    fn recv(&mut self, wait: Duration, batch: &mut FrameBatch) -> Result<(), CaptureError>;

    /// Keep one frame in `one_in` from now on (1 = all).
    fn set_sampling(&mut self, one_in: u32) -> Result<(), CaptureError>;

    /// The first device's counters, when the backend has them.
    fn totals(&mut self) -> Option<LinkTotals>;

    /// Whether [`Self::recv`] waits for traffic (false: simulated).
    fn blocks(&self) -> bool {
        true
    }
}

/// Opens captures. Shared with task threads, so `Send + Sync`.
pub trait PacketCapture: Send + Sync {
    /// "AF_PACKET (kernel BPF sampling)", "simulated traffic"…
    fn describe(&self) -> String;

    fn open(&self, spec: &CaptureSpec) -> Result<Box<dyn CaptureSocket>, CaptureError>;
}

pub type SharedCapture = Arc<dyn PacketCapture>;

// ---------------------------------------------------------------------------
// Header decoding.

pub const ETH_P_IPV4: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86DD;
pub const ETH_P_ARP: u16 = 0x0806;
const ETH_P_8021Q: u16 = 0x8100;
const ETH_P_8021AD: u16 = 0x88A8;
/// Pre-standard QinQ outer tag some switches still send.
const ETH_P_QINQ_OLD: u16 = 0x9100;
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMPV6: u8 = 58;
pub const PROTO_SCTP: u8 = 132;
/// Tags followed at most (QinQ is two; more is a broken or hostile frame).
const MAX_TAGS: usize = 4;
/// IPv6 extension headers followed at most before giving up on the ports.
const MAX_EXT: usize = 8;

/// The parts of a frame Torch groups by. Fields a frame does not carry are
/// `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Decoded {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    /// The outer 802.1Q / 802.1ad tag carried in the frame itself.
    pub vlan: Option<u16>,
    /// The EtherType after the tags.
    pub ethertype: u16,
    pub src: Option<IpAddr>,
    pub dst: Option<IpAddr>,
    /// IPv4 protocol / IPv6 next header (after the extension headers).
    pub proto: Option<u8>,
    pub dscp: Option<u8>,
    /// TCP, UDP and SCTP ports; none for a fragment that is not the first.
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}

fn be16(d: &[u8], at: usize) -> Option<u16> {
    let b = d.get(at..at + 2)?;
    Some(u16::from_be_bytes([*b.first()?, *b.get(1)?]))
}

fn mac(d: &[u8], at: usize) -> Option<[u8; 6]> {
    d.get(at..at + 6)?.try_into().ok()
}

/// Decode the headers of an Ethernet frame. Never panics: a short or
/// malformed frame yields what could be read (`None` when not even the
/// Ethernet header is there).
pub fn decode(frame: &[u8]) -> Option<Decoded> {
    let mut d = Decoded {
        dst_mac: mac(frame, 0)?,
        src_mac: mac(frame, 6)?,
        ethertype: be16(frame, 12)?,
        ..Decoded::default()
    };
    let mut at = 14;
    for _ in 0..MAX_TAGS {
        if !matches!(d.ethertype, ETH_P_8021Q | ETH_P_8021AD | ETH_P_QINQ_OLD) {
            break;
        }
        let Some(tci) = be16(frame, at) else {
            return Some(d);
        };
        if d.vlan.is_none() {
            d.vlan = Some(tci & 0x0FFF);
        }
        let Some(next) = be16(frame, at + 2) else {
            return Some(d);
        };
        d.ethertype = next;
        at += 4;
    }
    let ip = frame.get(at..).unwrap_or(&[]);
    match d.ethertype {
        ETH_P_IPV4 => ipv4(ip, &mut d),
        ETH_P_IPV6 => ipv6(ip, &mut d),
        _ => {}
    }
    Some(d)
}

fn ports(l4: &[u8], proto: u8, d: &mut Decoded) {
    if matches!(proto, PROTO_TCP | PROTO_UDP | PROTO_SCTP) {
        d.src_port = be16(l4, 0);
        d.dst_port = be16(l4, 2);
    }
}

// RFC 791 §3.1: version, IHL (32-bit words, at least 5), TOS (RFC 2474
// §3: DSCP is its upper six bits), fragment offset, protocol, addresses.
fn ipv4(p: &[u8], d: &mut Decoded) {
    let Some(&vihl) = p.first() else { return };
    if vihl >> 4 != 4 {
        return;
    }
    let ihl = usize::from(vihl & 0x0F) * 4;
    let (Some(src), Some(dst)) = (p.get(12..16), p.get(16..20)) else {
        return;
    };
    let (Ok(src), Ok(dst)) = (<[u8; 4]>::try_from(src), <[u8; 4]>::try_from(dst)) else {
        return;
    };
    d.src = Some(IpAddr::V4(Ipv4Addr::from(src)));
    d.dst = Some(IpAddr::V4(Ipv4Addr::from(dst)));
    d.dscp = p.get(1).map(|tos| tos >> 2);
    let Some(&proto) = p.get(9) else { return };
    d.proto = Some(proto);
    let frag_offset = be16(p, 6).map_or(0, |f| f & 0x1FFF);
    if ihl < 20 || frag_offset != 0 {
        return;
    }
    if let Some(l4) = p.get(ihl..) {
        ports(l4, proto, d);
    }
}

// RFC 8200 §3: version, traffic class (DSCP its upper six bits), next
// header, addresses; §4: extension headers (hop-by-hop 0, routing 43,
// fragment 44, destination options 60; length in 8-octet units past the
// first 8, fragment fixed at 8). An ESP/AH or unknown header ends the walk.
fn ipv6(p: &[u8], d: &mut Decoded) {
    let Some(&b0) = p.first() else { return };
    if b0 >> 4 != 6 {
        return;
    }
    let tc = ((b0 & 0x0F) << 4) | p.get(1).map_or(0, |b| b >> 4);
    let (Some(src), Some(dst)) = (p.get(8..24), p.get(24..40)) else {
        return;
    };
    let (Ok(src), Ok(dst)) = (<[u8; 16]>::try_from(src), <[u8; 16]>::try_from(dst)) else {
        return;
    };
    d.src = Some(IpAddr::V6(Ipv6Addr::from(src)));
    d.dst = Some(IpAddr::V6(Ipv6Addr::from(dst)));
    d.dscp = Some(tc >> 2);
    let Some(&first) = p.get(6) else { return };
    let mut next = first;
    let mut at = 40usize;
    for _ in 0..MAX_EXT {
        match next {
            0 | 43 | 60 => {
                let (Some(&n), Some(&len)) = (p.get(at), p.get(at + 1)) else {
                    d.proto = Some(next);
                    return;
                };
                next = n;
                at += 8 + usize::from(len) * 8;
            }
            44 => {
                let (Some(&n), Some(off)) = (p.get(at), be16(p, at + 2)) else {
                    d.proto = Some(next);
                    return;
                };
                next = n;
                at += 8;
                if off >> 3 != 0 {
                    // Not the first fragment: no transport header here.
                    d.proto = Some(next);
                    return;
                }
            }
            _ => break,
        }
    }
    d.proto = Some(next);
    if let Some(l4) = p.get(at..) {
        ports(l4, next, d);
    }
}

/// `tcp`, `udp`, `icmp`… for a protocol number (RouterOS names).
pub fn proto_name(p: u8) -> String {
    match p {
        PROTO_ICMP => "icmp".into(),
        2 => "igmp".into(),
        4 => "ipencap".into(),
        PROTO_TCP => "tcp".into(),
        PROTO_UDP => "udp".into(),
        41 => "ipv6-encap".into(),
        47 => "gre".into(),
        50 => "ipsec-esp".into(),
        51 => "ipsec-ah".into(),
        PROTO_ICMPV6 => "icmpv6".into(),
        89 => "ospf".into(),
        103 => "pim".into(),
        112 => "vrrp".into(),
        115 => "l2tp".into(),
        PROTO_SCTP => "sctp".into(),
        other => other.to_string(),
    }
}

/// A protocol by RouterOS name or number.
pub fn proto_number(name: &str) -> Option<u8> {
    let n = name.trim().to_ascii_lowercase();
    if let Ok(v) = n.parse::<u8>() {
        return Some(v);
    }
    (0..=255u8).find(|p| proto_name(*p) == n)
}

/// `ip`, `ipv6`, `arp`, `vlan` or `0x88cc` for an EtherType.
pub fn ethertype_name(t: u16) -> String {
    match t {
        ETH_P_IPV4 => "ip".into(),
        ETH_P_IPV6 => "ipv6".into(),
        ETH_P_ARP => "arp".into(),
        0x8863 => "pppoe-discovery".into(),
        0x8864 => "pppoe".into(),
        0x8847 => "mpls".into(),
        0x88CC => "lldp".into(),
        other => format!("0x{other:04x}"),
    }
}

/// `AA:BB:CC:DD:EE:FF`.
pub fn mac_text(m: &[u8; 6]) -> String {
    m.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

// ---------------------------------------------------------------------------
// pcap (draft-ietf-opsawg-pcap: the classic libpcap file format).

/// LINKTYPE_ETHERNET.
const LINKTYPE_ETHERNET: u32 = 1;
pub const PCAP_HEADER_LEN: usize = 24;
pub const PCAP_RECORD_HEADER_LEN: usize = 16;

/// The 24-byte file header: magic `0xA1B2C3D4` (microsecond timestamps),
/// version 2.4, SnapLen, LinkType Ethernet. Little-endian, as written by
/// the hosts readers expect (the magic tells them the order).
pub fn pcap_header(snaplen: u16) -> [u8; PCAP_HEADER_LEN] {
    let mut h = [0u8; PCAP_HEADER_LEN];
    let fields: [(usize, &[u8]); 5] = [
        (0, &0xA1B2_C3D4u32.to_le_bytes()),
        (4, &2u16.to_le_bytes()),
        (6, &4u16.to_le_bytes()),
        (16, &u32::from(snaplen).to_le_bytes()),
        (20, &LINKTYPE_ETHERNET.to_le_bytes()),
    ];
    for (at, bytes) in fields {
        if let Some(dst) = h.get_mut(at..at + bytes.len()) {
            dst.copy_from_slice(bytes);
        }
    }
    h
}

/// Append one packet record: timestamp (Unix seconds and microseconds),
/// captured length, original length, then the bytes.
pub fn pcap_record(out: &mut Vec<u8>, unix: Duration, data: &[u8], wire_len: u32) {
    let secs = u32::try_from(unix.as_secs()).unwrap_or(u32::MAX);
    let captured = u32::try_from(data.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&secs.to_le_bytes());
    out.extend_from_slice(&unix.subsec_micros().to_le_bytes());
    out.extend_from_slice(&captured.to_le_bytes());
    out.extend_from_slice(&wire_len.max(captured).to_le_bytes());
    out.extend_from_slice(data);
}

// ---------------------------------------------------------------------------
// Simulated traffic (the virtual lab).

/// One simulated conversation: a host on the interface and a far end.
struct SimFlow {
    host: IpAddr,
    far: IpAddr,
    proto: u8,
    host_port: u16,
    far_port: u16,
    vlan: Option<u16>,
    dscp: u8,
    /// Packets per second towards the host (Tx) and from it (Rx).
    tx_pps: f64,
    rx_pps: f64,
    tx_size: u16,
    rx_size: u16,
}

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

/// Deterministic traffic on any interface: a few subscribers (CGNAT and
/// private space) talking to far ends the simulated prober knows
/// (`sim.rs`: `198.19.x` are transit routers, the rest destinations), one
/// of them in VLAN 100 and one over IPv6. Rates swing slowly over time so
/// the window moves. A frame per packet, sampled like a real socket.
#[derive(Debug, Clone, Default)]
pub struct SimCapture;

impl PacketCapture for SimCapture {
    fn describe(&self) -> String {
        "simulated traffic".into()
    }

    fn open(&self, spec: &CaptureSpec) -> Result<Box<dyn CaptureSocket>, CaptureError> {
        if spec.devices.is_empty() {
            return Err(CaptureError::NoDevice("no interface to capture".into()));
        }
        let flows = vec![
            SimFlow {
                host: v4(100, 64, 0, 10),
                far: v4(198, 19, 3, 10),
                proto: PROTO_TCP,
                host_port: 51_000,
                far_port: 443,
                vlan: None,
                dscp: 0,
                tx_pps: 900.0,
                rx_pps: 450.0,
                tx_size: 1500,
                rx_size: 66,
            },
            SimFlow {
                host: v4(100, 64, 0, 11),
                far: v4(198, 19, 9, 20),
                proto: PROTO_TCP,
                host_port: 52_100,
                far_port: 443,
                vlan: None,
                dscp: 0,
                tx_pps: 420.0,
                rx_pps: 210.0,
                tx_size: 1400,
                rx_size: 66,
            },
            SimFlow {
                host: v4(100, 64, 0, 12),
                far: v4(8, 8, 8, 8),
                proto: PROTO_UDP,
                host_port: 40_053,
                far_port: 53,
                vlan: None,
                dscp: 0,
                tx_pps: 40.0,
                rx_pps: 40.0,
                tx_size: 120,
                rx_size: 74,
            },
            SimFlow {
                host: v4(192, 168, 88, 20),
                far: v4(1, 1, 1, 1),
                proto: PROTO_UDP,
                host_port: 50_000,
                far_port: 443,
                vlan: Some(100),
                dscp: 46,
                tx_pps: 300.0,
                rx_pps: 300.0,
                tx_size: 200,
                rx_size: 200,
            },
            SimFlow {
                host: "2001:db8:88::20"
                    .parse()
                    .unwrap_or(IpAddr::V6(Ipv6Addr::LOCALHOST)),
                far: "2001:db8:113::1"
                    .parse()
                    .unwrap_or(IpAddr::V6(Ipv6Addr::LOCALHOST)),
                proto: PROTO_TCP,
                host_port: 60_000,
                far_port: 80,
                vlan: None,
                dscp: 10,
                tx_pps: 150.0,
                rx_pps: 75.0,
                tx_size: 1280,
                rx_size: 74,
            },
        ];
        let owed = vec![0.0; flows.len() * 2];
        Ok(Box::new(SimSocket {
            flows,
            owed,
            t: Duration::ZERO,
            sample: spec.sample.max(1),
            counter: 0,
            snaplen: usize::from(spec.snaplen.clamp(14, MAX_SNAPLEN)),
            totals: LinkTotals::default(),
            frame: Vec::new(),
        }))
    }
}

struct SimSocket {
    flows: Vec<SimFlow>,
    /// Fractional packets each flow and direction still owes.
    owed: Vec<f64>,
    /// Simulated time: the sum of the waits asked for.
    t: Duration,
    sample: u32,
    counter: u64,
    snaplen: usize,
    totals: LinkTotals,
    frame: Vec<u8>,
}

/// Build an Ethernet frame for `f` in direction `dir` into `out`.
fn sim_frame(out: &mut Vec<u8>, f: &SimFlow, dir: Dir, size: u16) {
    out.clear();
    let host_mac = [0x02, 0x00, 0x5E, 0x10, 0x00, 0x01];
    let router_mac = [0x02, 0x00, 0x5E, 0x00, 0x00, 0xFE];
    let (dst_mac, src_mac) = match dir {
        Dir::Tx => (host_mac, router_mac),
        Dir::Rx => (router_mac, host_mac),
    };
    out.extend_from_slice(&dst_mac);
    out.extend_from_slice(&src_mac);
    if let Some(v) = f.vlan {
        out.extend_from_slice(&ETH_P_8021Q.to_be_bytes());
        out.extend_from_slice(&v.to_be_bytes());
    }
    let (src, dst, sport, dport) = match dir {
        Dir::Tx => (f.far, f.host, f.far_port, f.host_port),
        Dir::Rx => (f.host, f.far, f.host_port, f.far_port),
    };
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            out.extend_from_slice(&ETH_P_IPV4.to_be_bytes());
            out.extend_from_slice(&[0x45, f.dscp << 2]);
            out.extend_from_slice(&size.saturating_sub(14).to_be_bytes());
            out.extend_from_slice(&[0, 0, 0x40, 0, 64, f.proto, 0, 0]);
            out.extend_from_slice(&s.octets());
            out.extend_from_slice(&d.octets());
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            out.extend_from_slice(&ETH_P_IPV6.to_be_bytes());
            out.extend_from_slice(&[0x60 | (f.dscp >> 2), (f.dscp & 0x03) << 6, 0, 0]);
            out.extend_from_slice(&size.saturating_sub(54).to_be_bytes());
            out.extend_from_slice(&[f.proto, 64]);
            out.extend_from_slice(&s.octets());
            out.extend_from_slice(&d.octets());
        }
        _ => return,
    }
    out.extend_from_slice(&sport.to_be_bytes());
    out.extend_from_slice(&dport.to_be_bytes());
    if f.proto == PROTO_TCP {
        // Sequence, acknowledgment, data offset 5 words and ACK, window.
        out.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1, 0x50, 0x10, 0xFF, 0xFF, 0, 0, 0, 0]);
    } else {
        let headers = u16::try_from(out.len())
            .unwrap_or(u16::MAX)
            .saturating_sub(4);
        let len = size.saturating_sub(headers);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&[0u8; 14]);
    }
}

impl CaptureSocket for SimSocket {
    fn recv(&mut self, wait: Duration, batch: &mut FrameBatch) -> Result<(), CaptureError> {
        let secs = wait.as_secs_f64();
        let start = self.t;
        self.t = self.t.saturating_add(wait);
        let phase = start.as_secs_f64();
        for (i, f) in self.flows.iter().enumerate() {
            // Each flow swings ±50 % over about a minute, out of step.
            let swing = 1.0 + 0.5 * (phase / 9.0 + i as f64 * 1.3).sin();
            for (k, dir, pps, size) in [
                (i * 2, Dir::Tx, f.tx_pps, f.tx_size),
                (i * 2 + 1, Dir::Rx, f.rx_pps, f.rx_size),
            ] {
                let Some(owed) = self.owed.get_mut(k) else {
                    continue;
                };
                *owed += pps * swing * secs;
                let n = owed.floor();
                *owed -= n;
                let n = n as u64;
                let bytes = n.saturating_mul(u64::from(size));
                match dir {
                    Dir::Rx => {
                        self.totals.rx_packets += n;
                        self.totals.rx_bytes += bytes;
                    }
                    Dir::Tx => {
                        self.totals.tx_packets += n;
                        self.totals.tx_bytes += bytes;
                    }
                }
                for j in 0..n {
                    self.counter = self.counter.wrapping_add(1);
                    if !self.counter.is_multiple_of(u64::from(self.sample)) || batch.is_full() {
                        continue;
                    }
                    sim_frame(&mut self.frame, f, dir, size);
                    let keep = self.frame.len().min(self.snaplen);
                    let at = start + wait.mul_f64(j as f64 / n.max(1) as f64);
                    batch.push(
                        at,
                        dir,
                        None,
                        u32::from(size),
                        self.frame.get(..keep).unwrap_or(&[]),
                    );
                }
            }
        }
        Ok(())
    }

    fn set_sampling(&mut self, one_in: u32) -> Result<(), CaptureError> {
        self.sample = one_in.max(1);
        Ok(())
    }

    fn totals(&mut self) -> Option<LinkTotals> {
        Some(self.totals)
    }

    fn blocks(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn eth(ethertype: u16) -> Vec<u8> {
        let mut f = vec![0xAA; 6];
        f.extend_from_slice(&[0xBB; 6]);
        f.extend_from_slice(&ethertype.to_be_bytes());
        f
    }

    #[test]
    fn ipv4_tcp_with_dscp() {
        let mut f = eth(ETH_P_IPV4);
        f.extend_from_slice(&[0x45, 46 << 2, 0, 40, 0, 0, 0x40, 0, 64, 6, 0, 0]);
        f.extend_from_slice(&[10, 0, 0, 1, 8, 8, 4, 4]);
        f.extend_from_slice(&[0xC3, 0x50, 0x01, 0xBB]);
        let d = decode(&f).unwrap();
        assert_eq!(d.src, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(d.dst, Some("8.8.4.4".parse().unwrap()));
        assert_eq!((d.proto, d.dscp), (Some(6), Some(46)));
        assert_eq!((d.src_port, d.dst_port), (Some(50_000), Some(443)));
        assert_eq!(d.src_mac, [0xBB; 6]);
        assert_eq!(mac_text(&d.dst_mac), "AA:AA:AA:AA:AA:AA");
    }

    #[test]
    fn qinq_takes_the_outer_tag() {
        let mut f = eth(ETH_P_8021AD);
        f.extend_from_slice(&[0x20, 0x64, 0x81, 0x00, 0x00, 0x0A, 0x86, 0xDD]);
        f.extend_from_slice(&[0x60, 0, 0, 0, 0, 8, 17, 64]);
        f.extend_from_slice(&[0x20, 0x01, 0x0D, 0xB8].repeat(4));
        f.extend_from_slice(&[0xFE, 0x80, 0, 0].repeat(4));
        f.extend_from_slice(&[0x00, 0x35, 0x30, 0x39]);
        let d = decode(&f).unwrap();
        assert_eq!(d.vlan, Some(100), "PCP bits masked off");
        assert_eq!(d.ethertype, ETH_P_IPV6);
        assert_eq!(
            (d.proto, d.src_port, d.dst_port),
            (Some(17), Some(53), Some(12345))
        );
    }

    #[test]
    fn later_fragments_have_no_ports() {
        let mut f = eth(ETH_P_IPV4);
        // Offset 185 (×8 bytes): not the first fragment.
        f.extend_from_slice(&[0x45, 0, 0, 40, 0, 0, 0x00, 0xB9, 64, 17, 0, 0]);
        f.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2, 0x00, 0x35, 0x00, 0x35]);
        let d = decode(&f).unwrap();
        assert_eq!(d.proto, Some(17));
        assert_eq!(d.src_port, None);
        // IPv6: hop-by-hop, then a non-first fragment header.
        let mut f = eth(ETH_P_IPV6);
        f.extend_from_slice(&[0x60, 0, 0, 0, 0, 24, 0, 64]);
        f.extend_from_slice(&[0u8; 32]);
        f.extend_from_slice(&[44, 0, 0, 0, 0, 0, 0, 0]);
        f.extend_from_slice(&[6, 0, 0x01, 0x00, 0, 0, 0, 1]);
        f.extend_from_slice(&[0, 80, 0, 81]);
        let d = decode(&f).unwrap();
        assert_eq!((d.proto, d.src_port), (Some(6), None));
    }

    #[test]
    fn short_frames_say_what_they_can() {
        assert_eq!(decode(&[0; 13]), None);
        let d = decode(&eth(ETH_P_IPV4)).unwrap();
        assert_eq!((d.src, d.proto), (None, None));
        let mut f = eth(ETH_P_8021Q);
        f.push(0x00);
        assert_eq!(decode(&f).unwrap().vlan, None);
        let d = decode(&eth(ETH_P_ARP)).unwrap();
        assert_eq!(ethertype_name(d.ethertype), "arp");
    }

    #[test]
    fn protocol_names_round_trip() {
        for p in 0..=255u8 {
            assert_eq!(proto_number(&proto_name(p)), Some(p));
        }
        assert_eq!(proto_number("TCP"), Some(6));
        assert_eq!(proto_number("nope"), None);
    }

    #[test]
    fn pcap_layout() {
        let h = pcap_header(128);
        assert_eq!(&h[0..4], &[0xD4, 0xC3, 0xB2, 0xA1]);
        assert_eq!(&h[4..8], &[2, 0, 4, 0]);
        assert_eq!(&h[16..20], &[128, 0, 0, 0]);
        assert_eq!(&h[20..24], &[1, 0, 0, 0]);
        let mut out = Vec::new();
        pcap_record(
            &mut out,
            Duration::new(1_700_000_000, 123_456_000),
            &[1, 2, 3],
            60,
        );
        assert_eq!(out.len(), PCAP_RECORD_HEADER_LEN + 3);
        assert_eq!(&out[4..8], &123_456u32.to_le_bytes());
        assert_eq!(&out[8..12], &3u32.to_le_bytes());
        assert_eq!(&out[12..16], &60u32.to_le_bytes());
    }

    #[test]
    fn simulated_traffic_is_sampled_and_counted() {
        let spec = CaptureSpec {
            devices: vec![CaptureDevice {
                name: "ether1".into(),
                vlan: None,
            }],
            snaplen: HEADERS_SNAPLEN,
            sample: 1,
        };
        let mut s = SimCapture.open(&spec).unwrap();
        let mut b = FrameBatch::new(100_000);
        s.recv(Duration::from_secs(1), &mut b).unwrap();
        let t = s.totals().unwrap();
        assert_eq!(b.len() as u64, t.rx_packets + t.tx_packets);
        assert!(
            b.iter()
                .all(|(_, d)| decode(d).is_some_and(|d| d.src.is_some()))
        );
        assert!(b.iter().any(|(_, d)| decode(d).unwrap().vlan == Some(100)));
        s.set_sampling(10).unwrap();
        b.clear();
        s.recv(Duration::from_secs(1), &mut b).unwrap();
        let t2 = s.totals().unwrap();
        let seen = (t2.rx_packets + t2.tx_packets) - (t.rx_packets + t.tx_packets);
        assert!(
            (b.len() as u64).abs_diff(seen / 10) <= 1,
            "{} vs {seen}",
            b.len()
        );
    }

    #[test]
    fn a_full_batch_takes_no_more() {
        let mut b = FrameBatch::new(2);
        for _ in 0..3 {
            b.push(Duration::ZERO, Dir::Rx, None, 60, &[1, 2]);
        }
        assert_eq!(b.len(), 2);
        assert!(b.is_full());
        assert_eq!(b.iter().map(|(_, d)| d.len()).sum::<usize>(), 4);
    }

    proptest! {
        #[test]
        fn decoding_garbage_never_panics(f in proptest::collection::vec(any::<u8>(), 0..200)) {
            let _ = decode(&f);
        }

        #[test]
        fn decoding_tagged_ip_garbage_never_panics(
            tags in proptest::collection::vec(prop_oneof![Just(0x8100u16), Just(0x88A8u16)], 0..6),
            ethertype in prop_oneof![Just(0x0800u16), Just(0x86DDu16)],
            rest in proptest::collection::vec(any::<u8>(), 0..120),
        ) {
            let mut f = vec![0u8; 12];
            for t in &tags {
                f.extend_from_slice(&t.to_be_bytes());
                f.extend_from_slice(&[0, 1]);
            }
            f.extend_from_slice(&ethertype.to_be_bytes());
            f.extend_from_slice(&rest);
            let _ = decode(&f);
        }
    }
}
