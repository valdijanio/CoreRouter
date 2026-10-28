//! The sockets: [`HostLspProber`] (requests) and [`HostResponder`]
//! (answers), with the cached [`LsrView`] of this host.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::{AsFd, AsRawFd};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use corerouter_hal::HalError;
use corerouter_hal::lsp::{
    Heard, LspAnswer, LspPath, LspProber, LspRequest, LspResponderIo, LspSocket, LsrView, wire,
};
use corerouter_hal::mpls::{MplsNexthop, MplsReader, MplsRoute, Origin};
use corerouter_hal::probe::ProbeError;
use corerouter_model::IfName;
use ipnet::IpNet;
use netlink_sys::{Socket as NlSocket, protocols::NETLINK_ROUTE};
use nix::ifaddrs::getifaddrs;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::socket::{LinkAddr, MsgFlags, bind, recvfrom, send};
use socket2::{Domain, Protocol, Socket, Type};

use super::{
    ETH_P_IP, ETH_P_IPV6, ETH_P_MPLS_UC, FrameSpec, IP4_FILTER, IP6_FILTER, MAX_FRAME, MPLS_FILTER,
    RawFecRoute, build_frame, parse_frame, parse_route, route_request, sock_filter,
};
use crate::neigh::nlmsg_header;

/// How long what the LSR knows is kept (label table, links, FEC routes).
const FRESH: Duration = Duration::from_secs(1);
/// FEC routes kept at most.
const MAX_FECS: usize = 1024;
/// Frames read from one socket per wake-up (a flood cannot stall the loop).
const RECV_BUDGET: usize = 64;
/// Requests whose send time is kept (to match replies).
const MAX_SENT: usize = 4096;
const NLMSG_ERROR: u16 = 2;
const RTM_NEWROUTE: u16 = 24;
const ENETUNREACH: i32 = 101;
const EHOSTUNREACH: i32 = 113;
const ESRCH: i32 = 3;
const EMSGSIZE: i32 = 90;

fn ntp_now() -> (u32, u32) {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    wire::ntp(d.as_secs(), d.subsec_nanos())
}

fn io_hal(what: &str, e: impl std::fmt::Display) -> HalError {
    HalError::Io(format!("{what}: {e}"))
}

// --- links ------------------------------------------------------------------

/// One interface as the kernel reports it.
#[derive(Debug, Clone, Default)]
struct Link {
    index: u32,
    link: Option<LinkAddr>,
    mac: Option<[u8; 6]>,
    addrs: Vec<IpAddr>,
    mtu: Option<u16>,
}

#[derive(Default)]
struct Links {
    at: Option<Instant>,
    by_name: HashMap<IfName, Link>,
    by_index: HashMap<u32, IfName>,
}

impl Links {
    /// Read again when older than [`FRESH`]; `true` if it did.
    fn refresh(&mut self) -> bool {
        if self.at.is_some_and(|t| t.elapsed() < FRESH) {
            return false;
        }
        self.at = Some(Instant::now());
        let Ok(all) = getifaddrs() else { return true };
        let mut by_name: HashMap<IfName, Link> = HashMap::new();
        for a in all {
            let Ok(name) = a.interface_name.parse::<IfName>() else {
                continue;
            };
            let e = by_name.entry(name).or_default();
            let Some(addr) = a.address else { continue };
            if let Some(l) = addr.as_link_addr() {
                e.index = u32::try_from(l.ifindex()).unwrap_or(0);
                e.mac = l.addr();
                e.link = Some(*l);
            } else if let Some(v4) = addr.as_sockaddr_in() {
                e.addrs.push(IpAddr::V4(v4.ip()));
            } else if let Some(v6) = addr.as_sockaddr_in6() {
                e.addrs.push(IpAddr::V6(v6.ip()));
            }
        }
        for (name, l) in &mut by_name {
            l.mtu = std::fs::read_to_string(format!("/sys/class/net/{name}/mtu"))
                .ok()
                .and_then(|s| s.trim().parse::<u32>().ok())
                .map(|m| u16::try_from(m).unwrap_or(u16::MAX));
        }
        self.by_index = by_name.iter().map(|(n, l)| (l.index, n.clone())).collect();
        self.by_name = by_name;
        true
    }

    /// A source address of `name` for `v6` (a global one first).
    fn source(&self, name: &IfName, v6: bool) -> Option<IpAddr> {
        let l = self.by_name.get(name)?;
        let global = |a: &&IpAddr| match a {
            IpAddr::V6(x) => (x.segments().first().copied().unwrap_or(0) & 0xffc0) != 0xfe80,
            IpAddr::V4(_) => true,
        };
        l.addrs
            .iter()
            .filter(|a| a.is_ipv6() == v6)
            .find(global)
            .or_else(|| l.addrs.iter().find(|a| a.is_ipv6() == v6))
            .copied()
    }
}

// --- the route of a FEC -----------------------------------------------------

struct Routes {
    sock: NlSocket,
    buf: Vec<u8>,
    seq: u32,
}

impl Routes {
    fn open() -> io::Result<Self> {
        let mut sock = NlSocket::new(NETLINK_ROUTE)?;
        sock.bind_auto()?;
        Ok(Self {
            sock,
            buf: vec![0u8; 1 << 16],
            seq: 0x4c53_0000,
        })
    }

    /// The route of `dst` (`None`: no route).
    fn get(&mut self, dst: IpAddr) -> Result<Option<RawFecRoute>, String> {
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        self.sock
            .send(&route_request(dst, seq), 0)
            .map_err(|e| e.to_string())?;
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err("the kernel did not answer the route lookup".into());
            }
            let ms = u16::try_from(left.as_millis().min(1000)).unwrap_or(1000);
            let mut fds = [PollFd::new(self.sock.as_fd(), PollFlags::POLLIN)];
            if poll(&mut fds, PollTimeout::from(ms)).map_err(|e| e.to_string())? == 0 {
                continue;
            }
            let n = self
                .sock
                .recv(&mut &mut self.buf[..], 0)
                .map_err(|e| e.to_string())?;
            let mut rest = self.buf.get(..n).unwrap_or(&[]);
            while let Some((len, kind, _, mseq)) = nlmsg_header(rest) {
                let msg = rest.get(..len).unwrap_or(rest);
                rest = rest.get(len.div_ceil(4) * 4..).unwrap_or(&[]);
                if mseq != seq {
                    continue;
                }
                match kind {
                    RTM_NEWROUTE => return Ok(msg.get(16..).and_then(parse_route)),
                    NLMSG_ERROR => {
                        let code = msg
                            .get(16..20)
                            .and_then(|b| b.try_into().ok())
                            .map_or(0, i32::from_ne_bytes)
                            .saturating_neg();
                        return match code {
                            0 => Ok(None),
                            ENETUNREACH | EHOSTUNREACH | ESRCH => Ok(None),
                            c => Err(io::Error::from_raw_os_error(c).to_string()),
                        };
                    }
                    _ => {}
                }
            }
        }
    }
}

fn nexthops(r: &RawFecRoute, links: &Links) -> Vec<MplsNexthop> {
    r.nexthops
        .iter()
        .map(|nh| MplsNexthop {
            via: nh.gateway,
            interface: nh.ifindex.and_then(|i| links.by_index.get(&i).cloned()),
            out_labels: nh.labels.clone(),
        })
        .collect()
}

// --- neighbors --------------------------------------------------------------

#[derive(Default)]
struct Neighbors {
    at: Option<Instant>,
    map: HashMap<(IfName, IpAddr), [u8; 6]>,
}

impl Neighbors {
    fn refresh(&mut self, force: bool) {
        if !force && self.at.is_some_and(|t| t.elapsed() < FRESH) {
            return;
        }
        self.at = Some(Instant::now());
        if let Ok(all) = crate::neigh::neighbors() {
            self.map = all
                .into_iter()
                .filter_map(|n| Some(((n.interface, n.address), n.mac?)))
                .collect();
        }
    }

    /// The MAC of `ip` on `dev`: from the table, else after asking the
    /// kernel to resolve it (a datagram to the discard port makes it ARP
    /// or send a neighbor solicitation), waiting up to 300 ms.
    fn mac(&mut self, dev: &IfName, ip: IpAddr) -> Option<[u8; 6]> {
        self.refresh(false);
        if let Some(m) = self.map.get(&(dev.clone(), ip)) {
            return Some(*m);
        }
        let domain = if ip.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        };
        if let Ok(s) = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)) {
            let _ = s.bind_device(Some(dev.as_str().as_bytes()));
            let _ = s.send_to(&[0], &SocketAddr::new(ip, 9).into());
        }
        for _ in 0..6 {
            std::thread::sleep(Duration::from_millis(50));
            self.refresh(true);
            if let Some(m) = self.map.get(&(dev.clone(), ip)) {
                return Some(*m);
            }
        }
        None
    }
}

// --- sending ----------------------------------------------------------------

/// Opens [`HostLspSocket`]s. Needs `CAP_NET_RAW` (packet sockets).
#[derive(Debug, Default, Clone, Copy)]
pub struct HostLspProber;

impl LspProber for HostLspProber {
    fn describe(&self) -> String {
        "host MPLS (AF_PACKET frames to the FEC's next hop)".into()
    }
    fn open(&self) -> Result<Box<dyn LspSocket>, ProbeError> {
        Ok(Box::new(HostLspSocket::open()?))
    }
}

/// One task's socket: packet sockets per interface (opened when first
/// used), UDP sockets the replies come back to.
pub struct HostLspSocket {
    udp4: Socket,
    udp6: Option<Socket>,
    port4: u16,
    port6: u16,
    packet: HashMap<IfName, Socket>,
    links: Links,
    neighbors: Neighbors,
    routes: Routes,
    sent: BTreeMap<u32, Instant>,
    buf: Vec<u8>,
}

fn unavailable(what: &str, e: impl std::fmt::Display) -> ProbeError {
    ProbeError::Unavailable(format!("{what}: {e}"))
}

fn udp(v6: bool) -> io::Result<(Socket, u16)> {
    let (domain, any) = if v6 {
        (Domain::IPV6, SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)))
    } else {
        (Domain::IPV4, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
    };
    let s = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if v6 {
        s.set_only_v6(true)?;
    }
    s.set_nonblocking(true)?;
    s.bind(&any.into())?;
    let port = s.local_addr()?.as_socket().map_or(0, |a| a.port());
    Ok((s, port))
}

impl HostLspSocket {
    pub fn open() -> Result<Self, ProbeError> {
        let (udp4, port4) = udp(false).map_err(|e| unavailable("UDP socket", e))?;
        let (udp6, port6) = match udp(true) {
            Ok((s, p)) => (Some(s), p),
            Err(_) => (None, 0),
        };
        Ok(Self {
            udp4,
            udp6,
            port4,
            port6,
            packet: HashMap::new(),
            links: Links::default(),
            neighbors: Neighbors::default(),
            routes: Routes::open().map_err(|e| unavailable("route netlink", e))?,
            sent: BTreeMap::new(),
            buf: vec![0u8; MAX_FRAME],
        })
    }

    fn packet_socket(&mut self, dev: &IfName) -> Result<&Socket, ProbeError> {
        if !self.packet.contains_key(dev) {
            let link = self
                .links
                .by_name
                .get(dev)
                .and_then(|l| l.link)
                .ok_or_else(|| ProbeError::Unreachable(format!("{dev} has no link address")))?;
            // Protocol 0: this socket only sends, it hears nothing.
            let s = Socket::new(Domain::PACKET, Type::RAW, Some(Protocol::from(0)))
                .map_err(|e| unavailable("packet socket (needs CAP_NET_RAW)", e))?;
            bind(s.as_raw_fd(), &link).map_err(|e| unavailable("bind", e))?;
            self.packet.insert(dev.clone(), s);
        }
        self.packet
            .get(dev)
            .ok_or_else(|| ProbeError::Io("packet socket".into()))
    }
}

impl LspSocket for HostLspSocket {
    fn paths(&mut self, fec: IpNet) -> Result<Vec<LspPath>, ProbeError> {
        self.links.at = None;
        let _ = self.links.refresh();
        let Some(r) = self
            .routes
            .get(fec.addr())
            .map_err(|e| ProbeError::Io(format!("route of {fec}: {e}")))?
        else {
            return Ok(Vec::new());
        };
        if !r.unicast {
            return Ok(Vec::new());
        }
        let v6 = fec.addr().is_ipv6();
        let origin = if r.static_route {
            Origin::Static
        } else {
            Origin::Ldp
        };
        Ok(nexthops(&r, &self.links)
            .into_iter()
            .filter_map(|nh| {
                let interface = nh.interface?;
                Some(LspPath {
                    src: r
                        .prefsrc
                        .filter(|a| a.is_ipv6() == v6)
                        .or_else(|| self.links.source(&interface, v6)),
                    mtu: self.links.by_name.get(&interface).and_then(|l| l.mtu),
                    labels: nh.out_labels,
                    nexthop: nh.via,
                    interface,
                    origin,
                })
            })
            .collect())
    }

    fn send(&mut self, req: &LspRequest<'_>) -> Result<(), ProbeError> {
        let _ = self.links.refresh();
        let path = req.path;
        let v6 = req.dst.is_ipv6();
        let src = path
            .src
            .ok_or_else(|| ProbeError::Unreachable(format!("{} has no address", path.interface)))?;
        let src_mac = self
            .links
            .by_name
            .get(&path.interface)
            .and_then(|l| l.mac)
            .ok_or_else(|| {
                ProbeError::Unreachable(format!("{} is not an Ethernet link", path.interface))
            })?;
        let nexthop = path.nexthop.ok_or_else(|| {
            ProbeError::Unreachable(format!(
                "the route leaves {} without a next hop",
                path.interface
            ))
        })?;
        let dst_mac = self
            .neighbors
            .mac(&path.interface, nexthop)
            .ok_or_else(|| {
                ProbeError::Unreachable(format!(
                    "no ARP/ND entry for {nexthop} on {}",
                    path.interface
                ))
            })?;
        let mut payload = req.payload.to_vec();
        let (secs, frac) = ntp_now();
        if let Some(ts) = payload.get_mut(16..24) {
            ts.copy_from_slice(&[secs.to_be_bytes(), frac.to_be_bytes()].concat());
        }
        let seq = wire::ids(&payload).map_or(0, |(_, s)| s);
        let frame = build_frame(&FrameSpec {
            dst_mac,
            src_mac,
            labels: &path.labels,
            // An unlabeled request carries IP TTL 1 anyway (§4.3).
            ttl: req.ttl,
            tos: req.tos,
            src,
            dst: req.dst,
            src_port: if v6 { self.port6 } else { self.port4 },
            id: (seq & 0xffff) as u16,
            payload: &payload,
        })
        .ok_or(ProbeError::TooBig(path.mtu))?;
        let dev = path.interface.clone();
        let sock = self.packet_socket(&dev)?;
        match send(sock.as_raw_fd(), &frame, MsgFlags::empty()) {
            Ok(_) => {}
            Err(e) if e as i32 == EMSGSIZE => return Err(ProbeError::TooBig(path.mtu)),
            Err(e) => return Err(ProbeError::Unreachable(format!("{dev}: {e}"))),
        }
        self.sent.insert(seq, Instant::now());
        while self.sent.len() > MAX_SENT {
            self.sent.pop_first();
        }
        Ok(())
    }

    fn recv(&mut self, wait: Duration) -> Result<Option<LspAnswer>, ProbeError> {
        let ms = u16::try_from(wait.as_millis().min(1000)).unwrap_or(1000);
        let mut fds = vec![PollFd::new(self.udp4.as_fd(), PollFlags::POLLIN)];
        if let Some(s) = &self.udp6 {
            fds.push(PollFd::new(s.as_fd(), PollFlags::POLLIN));
        }
        if poll(&mut fds, PollTimeout::from(ms)).map_err(|e| ProbeError::Io(e.to_string()))? == 0 {
            return Ok(None);
        }
        for s in std::iter::once(&self.udp4).chain(self.udp6.iter()) {
            let (n, from) =
                match recvfrom::<nix::sys::socket::SockaddrStorage>(s.as_raw_fd(), &mut self.buf) {
                    Ok(r) => r,
                    Err(nix::Error::EAGAIN) => continue,
                    Err(e) => return Err(ProbeError::Io(e.to_string())),
                };
            let from = from.and_then(|a| {
                a.as_sockaddr_in()
                    .map(|v| SocketAddr::new(IpAddr::V4(v.ip()), v.port()))
                    .or_else(|| {
                        a.as_sockaddr_in6()
                            .map(|v| SocketAddr::new(IpAddr::V6(v.ip()), v.port()))
                    })
            });
            let Some(from) = from else { continue };
            // §4.5: replies come from port 3503.
            if from.port() != wire::PORT {
                continue;
            }
            let payload = self.buf.get(..n).unwrap_or(&[]).to_vec();
            let rtt = wire::ids(&payload)
                .and_then(|(_, seq)| self.sent.get(&seq))
                .map(Instant::elapsed);
            return Ok(Some(LspAnswer {
                from: from.ip(),
                payload,
                rtt,
            }));
        }
        Ok(None)
    }
}

// --- answering --------------------------------------------------------------

/// A FEC's route and when it was read.
type Cached = (Instant, Option<Vec<MplsNexthop>>);

/// What this host knows, cached ([`FRESH`]).
pub struct HostView {
    labels: BTreeMap<u32, MplsRoute>,
    labels_at: Option<Instant>,
    reader: Option<crate::mpls::Reader>,
    links: Links,
    locals: Vec<IpAddr>,
    fecs: RefCell<HashMap<IpNet, Cached>>,
    routes: RefCell<Option<Routes>>,
}

impl HostView {
    fn new() -> Self {
        Self {
            labels: BTreeMap::new(),
            labels_at: None,
            reader: crate::mpls::Reader::open().ok(),
            links: Links::default(),
            locals: Vec::new(),
            fecs: RefCell::new(HashMap::new()),
            routes: RefCell::new(Routes::open().ok()),
        }
    }

    /// Read again what is older than a second.
    fn refresh(&mut self) {
        if self.labels_at.is_none_or(|t| t.elapsed() >= FRESH) {
            self.labels_at = Some(Instant::now());
            if let Some(r) = self.reader.as_mut()
                && crate::mpls::available()
            {
                if let Ok(all) = r.routes() {
                    self.labels = all.into_iter().map(|r| (r.label, r)).collect();
                }
            } else {
                self.labels.clear();
            }
        }
        if self.links.refresh() {
            self.links_changed();
        }
    }

    /// Read the links now (the interfaces to listen on changed).
    fn reread_links(&mut self) {
        self.links.at = None;
        self.links.refresh();
        self.links_changed();
    }

    fn links_changed(&mut self) {
        self.locals = self
            .links
            .by_name
            .values()
            .flat_map(|l| l.addrs.iter().copied())
            .collect();
        self.fecs.borrow_mut().clear();
    }
}

impl LsrView for HostView {
    fn label_entry(&self, label: u32) -> Option<MplsRoute> {
        self.labels.get(&label).cloned()
    }

    fn fec_route(&self, prefix: IpNet) -> Option<Vec<MplsNexthop>> {
        if let Some((at, r)) = self.fecs.borrow().get(&prefix)
            && at.elapsed() < FRESH
        {
            return r.clone();
        }
        let got = self
            .routes
            .borrow_mut()
            .as_mut()
            .and_then(|rt| rt.get(prefix.addr()).ok().flatten())
            .filter(|r| r.unicast)
            .map(|r| nexthops(&r, &self.links));
        let mut cache = self.fecs.borrow_mut();
        if cache.len() >= MAX_FECS {
            cache.clear();
        }
        cache.insert(prefix, (Instant::now(), got.clone()));
        got
    }

    fn is_local(&self, prefix: IpNet) -> bool {
        self.locals.iter().any(|a| prefix.contains(a))
    }

    fn interface_addrs(&self, interface: &IfName) -> Vec<IpAddr> {
        self.links
            .by_name
            .get(interface)
            .map(|l| l.addrs.clone())
            .unwrap_or_default()
    }

    fn mtu(&self, interface: &IfName) -> Option<u16> {
        self.links.by_name.get(interface).and_then(|l| l.mtu)
    }
}

/// Three packet sockets of one interface.
struct Taps {
    socks: Vec<Socket>,
}

fn tap(link: &LinkAddr, ethertype: u16, prog: &[super::Insn]) -> io::Result<Socket> {
    let s = Socket::new(
        Domain::PACKET,
        Type::RAW,
        Some(Protocol::from(i32::from(ethertype.to_be()))),
    )?;
    s.set_nonblocking(true)?;
    s.attach_filter(&sock_filter(prog))?;
    bind(s.as_raw_fd(), link).map_err(|e| io::Error::from_raw_os_error(e as i32))?;
    // What came before the filter: drop it.
    let mut buf = [0u8; 64];
    for _ in 0..RECV_BUDGET {
        if recvfrom::<LinkAddr>(s.as_raw_fd(), &mut buf).is_err() {
            break;
        }
    }
    Ok(s)
}

/// The responder's sockets and view.
pub struct HostResponder {
    taps: BTreeMap<IfName, Taps>,
    udp4: Socket,
    udp6: Option<Socket>,
    view: HostView,
    queue: VecDeque<Heard>,
    buf: Vec<u8>,
}

fn reply_socket(v6: bool) -> io::Result<Socket> {
    let (domain, addr) = if v6 {
        (
            Domain::IPV6,
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, wire::PORT)),
        )
    } else {
        (
            Domain::IPV4,
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, wire::PORT)),
        )
    };
    let s = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if v6 {
        s.set_only_v6(true)?;
        s.set_unicast_hops_v6(255)?;
    } else {
        // §4.5: "The IP TTL is set to 255."
        s.set_ttl_v4(255)?;
    }
    s.set_nonblocking(true)?;
    s.bind(&addr.into())?;
    Ok(s)
}

impl HostResponder {
    /// The sockets: UDP port 3503 (IPv4, and IPv6 when the host has it).
    pub fn open() -> Result<Self, HalError> {
        let udp4 = reply_socket(false)
            .map_err(|e| HalError::Rejected(format!("UDP port {} (IPv4): {e}", wire::PORT)))?;
        Ok(Self {
            taps: BTreeMap::new(),
            udp4,
            udp6: reply_socket(true).ok(),
            view: HostView::new(),
            queue: VecDeque::new(),
            buf: vec![0u8; MAX_FRAME],
        })
    }

    /// Requests that reach port 3503 as plain UDP (sent to an address of
    /// this host instead of 127/8) are read and dropped: the RFC wants
    /// 127/8, and the queue must not fill.
    fn drain_udp(&mut self) {
        for s in std::iter::once(&self.udp4).chain(self.udp6.iter()) {
            for _ in 0..RECV_BUDGET {
                if recvfrom::<LinkAddr>(s.as_raw_fd(), &mut self.buf).is_err() {
                    break;
                }
            }
        }
    }
}

impl LspResponderIo for HostResponder {
    fn set_interfaces(&mut self, names: &[IfName]) -> Vec<(IfName, String)> {
        self.taps.retain(|n, _| names.contains(n));
        self.view.reread_links();
        let mut failed = Vec::new();
        for name in names {
            if self.taps.contains_key(name) {
                continue;
            }
            let Some(link) = self.view.links.by_name.get(name).and_then(|l| l.link) else {
                failed.push((name.clone(), "no such link".to_owned()));
                continue;
            };
            let socks: io::Result<Vec<Socket>> = [
                (ETH_P_MPLS_UC, MPLS_FILTER),
                (ETH_P_IP, IP4_FILTER),
                (ETH_P_IPV6, IP6_FILTER),
            ]
            .iter()
            .map(|(t, p)| tap(&link, *t, p))
            .collect();
            match socks {
                Ok(socks) => {
                    self.taps.insert(name.clone(), Taps { socks });
                }
                Err(e) => failed.push((name.clone(), e.to_string())),
            }
        }
        failed
    }

    fn recv(&mut self, wait: Duration) -> Result<Option<Heard>, HalError> {
        if let Some(h) = self.queue.pop_front() {
            return Ok(Some(h));
        }
        let ms = u16::try_from(wait.as_millis().min(1000)).unwrap_or(1000);
        let mut fds: Vec<PollFd<'_>> = self
            .taps
            .values()
            .flat_map(|t| t.socks.iter())
            .map(|s| PollFd::new(s.as_fd(), PollFlags::POLLIN))
            .collect();
        fds.push(PollFd::new(self.udp4.as_fd(), PollFlags::POLLIN));
        if poll(&mut fds, PollTimeout::from(ms)).map_err(|e| io_hal("poll", e))? == 0 {
            return Ok(None);
        }
        drop(fds);
        self.drain_udp();
        for (name, t) in &self.taps {
            for s in &t.socks {
                for _ in 0..RECV_BUDGET {
                    let n = match recvfrom::<LinkAddr>(s.as_raw_fd(), &mut self.buf) {
                        Ok((n, _)) => n,
                        Err(_) => break,
                    };
                    if let Some(h) = self.buf.get(..n).and_then(|f| parse_frame(f, name))
                        && self.queue.len() < RECV_BUDGET * 4
                    {
                        self.queue.push_back(h);
                    }
                }
            }
        }
        Ok(self.queue.pop_front())
    }

    fn send(
        &mut self,
        to: SocketAddr,
        _from: Option<IpAddr>,
        tos: Option<u8>,
        payload: &[u8],
    ) -> Result<(), HalError> {
        let s = match to {
            SocketAddr::V4(_) => &self.udp4,
            SocketAddr::V6(_) => self
                .udp6
                .as_ref()
                .ok_or_else(|| HalError::Unsupported("no IPv6 socket on port 3503".into()))?,
        };
        if let Some(t) = tos {
            let _ = match to {
                SocketAddr::V4(_) => s.set_tos_v4(u32::from(t)),
                SocketAddr::V6(_) => s.set_tclass_v6(u32::from(t)),
            };
        }
        s.send_to(payload, &to.into())
            .map_err(|e| io_hal("echo reply", e))?;
        Ok(())
    }

    fn view(&mut self) -> &dyn LsrView {
        self.view.refresh();
        &self.view
    }

    fn now_ntp(&self) -> (u32, u32) {
        ntp_now()
    }
}
