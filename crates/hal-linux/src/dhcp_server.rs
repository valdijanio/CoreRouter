//! DHCP server transport (G4.2a) on one interface, without `unsafe`:
//!
//! - receive: an `AF_PACKET` socket for IPv4 bound to the interface, with a
//!   classic BPF filter that keeps UDP to port 67 (requests, also relayed
//!   ones sent to our address) and UDP from 67 to 68 (other servers'
//!   replies, for `/ip dhcp-server alert`); unfragmented only. The kernel
//!   copies nothing else to us, and we hear clients that have no address;
//! - send: to a client without an address, a whole Ethernet frame to its
//!   MAC (RFC 2131 §4.1: unicast to `chaddr`, no ARP entry needed) or a
//!   broadcast; to a relay agent (port 67) or a client with an address
//!   (`ciaddr`, port 68), a UDP socket on port 67 bound to the device,
//!   routed by the kernel. When port 67 is taken (another DHCP server on
//!   the host) those go out as broadcast frames to that IP;
//! - probe: ARP requests from the server's address on an `AF_PACKET` ARP
//!   socket; any host that answers for (or claims) a probed address is
//!   reported.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;

use corerouter_hal::HalError;
use corerouter_hal::dhcp::{CLIENT_PORT, MAX_MESSAGE, SERVER_PORT};
use corerouter_hal::dhcp_server::{DhcpServerPort, Heard, ReplyTo};
use corerouter_model::IfName;
use nix::sys::socket::{LinkAddr, MsgFlags, bind, recvfrom, send};
use socket2::{Domain, Protocol, SockFilter, Socket, Type};

use crate::dhcp::{fold, packet_socket, sum16};
use crate::l2::{if_info, io_err};

const ETH_P_IP: u16 = 0x0800;
const ETH_P_ARP: u16 = 0x0806;
const ETH_HEADER: usize = 14;
const ETH_MIN_FRAME: usize = 60;
const BROADCAST_MAC: [u8; 6] = [0xff; 6];
/// `PACKET_OUTGOING`: a copy of a frame this host sent.
const PACKET_OUTGOING: u8 = 4;
/// Frames read per call.
const RECV_BUDGET: usize = 256;
/// Addresses being probed at once.
const MAX_PROBING: usize = 4096;

const LD_H_ABS: u16 = 0x28;
const LD_B_ABS: u16 = 0x30;
const LD_H_IND: u16 = 0x48;
const LDX_B_MSH: u16 = 0xb1;
const JEQ_K: u16 = 0x15;
const JSET_K: u16 = 0x45;
const RET_K: u16 = 0x06;

/// `ip and udp and not a fragment and (dst port 67 or (src port 67 and
/// dst port 68))`, on Ethernet frames.
fn server_filter() -> [SockFilter; 14] {
    let keep = 12;
    let drop = 13;
    let to = |at: u8, target: u8| target - at - 1;
    [
        /* 0 */ SockFilter::new(LD_H_ABS, 0, 0, 12),
        /* 1 */ SockFilter::new(JEQ_K, 0, to(1, drop), u32::from(ETH_P_IP)),
        /* 2 */ SockFilter::new(LD_B_ABS, 0, 0, 23),
        /* 3 */ SockFilter::new(JEQ_K, 0, to(3, drop), 17),
        /* 4 */ SockFilter::new(LD_H_ABS, 0, 0, 20),
        /* 5 */ SockFilter::new(JSET_K, to(5, drop), 0, 0x1fff),
        /* 6 */ SockFilter::new(LDX_B_MSH, 0, 0, 14),
        /* 7 */ SockFilter::new(LD_H_IND, 0, 0, 16), // UDP destination port
        /* 8 */ SockFilter::new(JEQ_K, to(8, keep), 0, u32::from(SERVER_PORT)),
        /* 9 */ SockFilter::new(JEQ_K, 0, to(9, drop), u32::from(CLIENT_PORT)),
        /* 10 */ SockFilter::new(LD_H_IND, 0, 0, 14), // UDP source port
        /* 11 */ SockFilter::new(JEQ_K, 0, to(11, drop), u32::from(SERVER_PORT)),
        /* 12 */ SockFilter::new(RET_K, 0, 0, 0xffff),
        /* 13 */ SockFilter::new(RET_K, 0, 0, 0),
    ]
}

fn ip_socket(link: &LinkAddr) -> io::Result<Socket> {
    let proto = Protocol::from(i32::from(ETH_P_IP.to_be()));
    let sock = Socket::new(Domain::PACKET, Type::RAW, Some(proto))?;
    sock.set_nonblocking(true)?;
    sock.attach_filter(&server_filter())?;
    bind(sock.as_raw_fd(), link).map_err(io_err)?;
    // Frames queued before the filter was attached: drop them.
    let mut buf = [0u8; 64];
    for _ in 0..RECV_BUDGET {
        if recvfrom::<LinkAddr>(sock.as_raw_fd(), &mut buf).is_err() {
            break;
        }
    }
    Ok(sock)
}

fn udp_socket(name: &IfName) -> io::Result<Socket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.set_broadcast(true)?;
    sock.set_nonblocking(true)?;
    sock.bind_device(Some(name.as_str().as_bytes()))?;
    sock.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, SERVER_PORT)).into())?;
    Ok(sock)
}

/// An Ethernet frame to `dst_mac` carrying `payload` from `src`:67 to
/// `dst`:68.
pub fn reply_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let udp_len = u16::try_from(payload.len().checked_add(8)?).ok()?;
    let ip_len = udp_len.checked_add(20)?;
    let mut ip = [0u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&ip_len.to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&src.octets());
    ip[16..20].copy_from_slice(&dst.octets());
    let csum = fold(sum16(&ip, 0));
    ip[10..12].copy_from_slice(&csum.to_be_bytes());
    let mut udp = Vec::with_capacity(usize::from(udp_len));
    udp.extend_from_slice(&SERVER_PORT.to_be_bytes());
    udp.extend_from_slice(&CLIENT_PORT.to_be_bytes());
    udp.extend_from_slice(&udp_len.to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(payload);
    let mut pseudo = Vec::with_capacity(12);
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&udp_len.to_be_bytes());
    let csum = match fold(sum16(&udp, sum16(&pseudo, 0))) {
        0 => 0xffff,
        c => c,
    };
    if let Some(field) = udp.get_mut(6..8) {
        field.copy_from_slice(&csum.to_be_bytes());
    }
    let mut frame = Vec::with_capacity(ETH_HEADER + usize::from(ip_len));
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&ETH_P_IP.to_be_bytes());
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&udp);
    if frame.len() < ETH_MIN_FRAME {
        frame.resize(ETH_MIN_FRAME, 0);
    }
    Some(frame)
}

/// The DHCP message in a frame: to port 67 (a request) or from 67 to 68
/// (another server's reply); `None` for anything else.
pub fn parse_frame(frame: &[u8]) -> Option<Heard> {
    let src_mac: [u8; 6] = frame.get(6..12)?.try_into().ok()?;
    if frame.get(12..14)? != ETH_P_IP.to_be_bytes() {
        return None;
    }
    let ip = frame.get(ETH_HEADER..)?;
    let first = *ip.first()?;
    let ihl = usize::from(first & 0x0f) * 4;
    if first >> 4 != 4 || ihl < 20 || *ip.get(9)? != 17 {
        return None;
    }
    let total = usize::from(u16::from_be_bytes(ip.get(2..4)?.try_into().ok()?));
    let ip = ip.get(..total)?;
    let src: [u8; 4] = ip.get(12..16)?.try_into().ok()?;
    let dst: [u8; 4] = ip.get(16..20)?.try_into().ok()?;
    let udp = ip.get(ihl..)?;
    let sport = u16::from_be_bytes(udp.get(0..2)?.try_into().ok()?);
    let dport = u16::from_be_bytes(udp.get(2..4)?.try_into().ok()?);
    let len = usize::from(u16::from_be_bytes(udp.get(4..6)?.try_into().ok()?));
    let to_server = dport == SERVER_PORT;
    if !(to_server || (sport == SERVER_PORT && dport == CLIENT_PORT)) || len < 8 {
        return None;
    }
    let payload = udp.get(8..len)?;
    if payload.len() > MAX_MESSAGE {
        return None;
    }
    Some(Heard {
        payload: payload.to_vec(),
        src: Ipv4Addr::from(src),
        dst: Ipv4Addr::from(dst),
        src_mac,
        to_server,
    })
}

/// An ARP request: who has `ip`, tell `src` (our address).
pub fn arp_request(mac: [u8; 6], src: Ipv4Addr, ip: Ipv4Addr) -> Vec<u8> {
    let mut f = Vec::with_capacity(ETH_MIN_FRAME);
    f.extend_from_slice(&BROADCAST_MAC);
    f.extend_from_slice(&mac);
    f.extend_from_slice(&ETH_P_ARP.to_be_bytes());
    f.extend_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
    f.extend_from_slice(&mac);
    f.extend_from_slice(&src.octets());
    f.extend_from_slice(&[0; 6]);
    f.extend_from_slice(&ip.octets());
    f.resize(ETH_MIN_FRAME, 0);
    f
}

/// [`DhcpServerPort`] of the Linux backend.
pub struct LinuxDhcpServerPort {
    name: IfName,
    mac: [u8; 6],
    raw: Socket,
    udp: Option<Socket>,
    arp: Socket,
    probing: Vec<Ipv4Addr>,
}

impl LinuxDhcpServerPort {
    pub fn open(name: &IfName) -> io::Result<Self> {
        let info = if_info(name)?;
        let raw = ip_socket(&info.link)?;
        let arp = packet_socket(&info.link, ETH_P_ARP)?;
        let udp = match udp_socket(name) {
            Ok(s) => Some(s),
            Err(e) => {
                log::warn!(
                    "dhcp-server {name}: UDP port 67 unavailable ({e}); replies to relays and \
                     to clients with an address go out as broadcast frames"
                );
                None
            }
        };
        Ok(Self {
            name: name.clone(),
            mac: info.mac,
            raw,
            udp,
            arp,
            probing: Vec::new(),
        })
    }

    fn send_frame(&self, frame: &[u8]) -> Result<(), HalError> {
        send(self.raw.as_raw_fd(), frame, MsgFlags::empty())
            .map(|_| ())
            .map_err(|e| HalError::Io(format!("{}: {e}", self.name)))
    }

    fn frame(
        &self,
        mac: [u8; 6],
        src: Ipv4Addr,
        dst: Ipv4Addr,
        payload: &[u8],
    ) -> Result<(), HalError> {
        let f = reply_frame(self.mac, mac, src, dst, payload).ok_or_else(|| {
            HalError::Rejected(format!("DHCP message of {} bytes", payload.len()))
        })?;
        self.send_frame(&f)
    }
}

impl DhcpServerPort for LinuxDhcpServerPort {
    fn mac(&self) -> [u8; 6] {
        self.mac
    }

    fn recv(&mut self) -> Result<Option<Heard>, HalError> {
        // The UDP socket exists to send (and so unicast requests do not
        // bring "port unreachable"); its copies of them go.
        if let Some(udp) = self.udp.as_ref() {
            let mut sink = [std::mem::MaybeUninit::<u8>::uninit(); 64];
            for _ in 0..RECV_BUDGET {
                if udp.recv(&mut sink).is_err() {
                    break;
                }
            }
        }
        let mut buf = vec![0u8; ETH_HEADER + 60 + 8 + MAX_MESSAGE];
        for _ in 0..RECV_BUDGET {
            let (n, from) = match recvfrom::<LinkAddr>(self.raw.as_raw_fd(), &mut buf) {
                Ok(r) => r,
                Err(nix::Error::EAGAIN) => return Ok(None),
                Err(e) => return Err(HalError::Io(format!("{}: {e}", self.name))),
            };
            if from.is_some_and(|a| a.pkttype() == PACKET_OUTGOING) {
                continue;
            }
            if let Some(h) = buf.get(..n).and_then(parse_frame) {
                return Ok(Some(h));
            }
        }
        Ok(None)
    }

    fn send(&mut self, payload: &[u8], src: Ipv4Addr, to: ReplyTo) -> Result<(), HalError> {
        match to {
            ReplyTo::Broadcast => self.frame(BROADCAST_MAC, src, Ipv4Addr::BROADCAST, payload),
            ReplyTo::Client { ip, mac } => self.frame(mac, src, ip, payload),
            ReplyTo::Relay(ip) | ReplyTo::Unicast(ip) => {
                let port = if matches!(to, ReplyTo::Relay(_)) {
                    SERVER_PORT
                } else {
                    CLIENT_PORT
                };
                match self.udp.as_ref() {
                    Some(udp) => udp
                        .send_to(payload, &SocketAddr::from((ip, port)).into())
                        .map(|_| ())
                        .map_err(|e| HalError::Io(format!("{} → {ip}:{port}: {e}", self.name))),
                    None => self.frame(BROADCAST_MAC, src, ip, payload),
                }
            }
        }
    }

    fn probe(&mut self, ip: Ipv4Addr, src: Ipv4Addr) -> Result<bool, HalError> {
        send(
            self.arp.as_raw_fd(),
            &arp_request(self.mac, src, ip),
            MsgFlags::empty(),
        )
        .map_err(|e| HalError::Io(format!("{}: ARP probe: {e}", self.name)))?;
        if !self.probing.contains(&ip) {
            if self.probing.len() >= MAX_PROBING {
                self.probing.remove(0);
            }
            self.probing.push(ip);
        }
        Ok(true)
    }

    fn probe_replies(&mut self) -> Result<Vec<(Ipv4Addr, [u8; 6])>, HalError> {
        let mut out = Vec::new();
        let mut buf = [0u8; 128];
        for _ in 0..RECV_BUDGET {
            let (n, from) = match recvfrom::<LinkAddr>(self.arp.as_raw_fd(), &mut buf) {
                Ok(r) => r,
                Err(_) => break,
            };
            if from.is_some_and(|a| a.pkttype() == PACKET_OUTGOING) || self.probing.is_empty() {
                continue;
            }
            let Some(frame) = buf.get(..n) else { continue };
            if let Some((ip, mac)) = self
                .probing
                .iter()
                .find_map(|ip| crate::dhcp::arp_claims(frame, *ip, self.mac).map(|m| (*ip, m)))
            {
                self.probing.retain(|p| *p != ip);
                out.push((ip, mac));
            }
        }
        Ok(out)
    }

    fn describe(&self) -> String {
        format!("udp 67 on {}", self.name)
    }

    fn send_discover(&mut self, payload: &[u8]) -> Result<(), HalError> {
        let frame = crate::dhcp::udp_frame(
            self.mac,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            payload,
        )
        .ok_or_else(|| HalError::Rejected(format!("DHCP message of {} bytes", payload.len())))?;
        self.send_frame(&frame)
    }
}

/// The relay's UDP socket on port 67, all interfaces (G4.2b). A server's
/// own sockets are bound to their interfaces, so they keep what reaches
/// them; this one gets the replies to the relay's `giaddr`.
pub struct LinuxDhcpUplink {
    udp: std::net::UdpSocket,
}

impl LinuxDhcpUplink {
    pub fn open() -> io::Result<Self> {
        let udp = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        udp.set_reuse_address(true)?;
        udp.set_nonblocking(true)?;
        udp.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, SERVER_PORT)).into())?;
        Ok(Self { udp: udp.into() })
    }
}

impl corerouter_hal::dhcp_server::DhcpUplink for LinuxDhcpUplink {
    fn recv(&mut self) -> Result<Option<Heard>, HalError> {
        let mut buf = vec![0u8; MAX_MESSAGE];
        match self.udp.recv_from(&mut buf) {
            Ok((n, from)) => {
                buf.truncate(n);
                let src = match from {
                    SocketAddr::V4(a) => *a.ip(),
                    SocketAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
                };
                Ok(Some(Heard {
                    payload: buf,
                    src,
                    dst: Ipv4Addr::UNSPECIFIED,
                    src_mac: [0; 6],
                    to_server: true,
                }))
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(HalError::Io(format!("relay uplink: {e}"))),
        }
    }

    fn send(&mut self, payload: &[u8], server: Ipv4Addr) -> Result<(), HalError> {
        self.udp
            .send_to(payload, SocketAddr::from((server, SERVER_PORT)))
            .map(|_| ())
            .map_err(|e| HalError::Io(format!("relay → {server}: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];

    #[test]
    fn replies_parse_back_and_requests_are_heard() {
        let f = reply_frame(
            MAC,
            [9; 6],
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 9),
            b"offer",
        )
        .unwrap();
        assert_eq!(&f[..6], &[9; 6], "to the client's MAC");
        let h = parse_frame(&f).unwrap();
        assert!(!h.to_server, "from 67 to 68: a server's reply");
        assert_eq!(h.payload, b"offer");
        assert_eq!(h.src_mac, MAC);
        assert_eq!(fold(sum16(&f[14..34], 0)), 0, "IP checksum");
        // The same frame the other way: a request to 67.
        let mut r = f.clone();
        r[34..36].copy_from_slice(&68u16.to_be_bytes());
        r[36..38].copy_from_slice(&67u16.to_be_bytes());
        assert!(parse_frame(&r).unwrap().to_server);
        // Neither: dropped.
        r[36..38].copy_from_slice(&53u16.to_be_bytes());
        assert!(parse_frame(&r).is_none());
        for n in 0..80 {
            let _ = parse_frame(&vec![0x45; n]);
        }
    }

    #[test]
    fn the_filter_jumps_land_inside_it() {
        let f = server_filter();
        assert_eq!(f.len(), 14);
    }

    #[test]
    fn arp_requests_say_who_asks() {
        let a = arp_request(MAC, Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 50));
        assert_eq!(&a[28..32], &[10, 0, 0, 1]);
        assert_eq!(&a[38..42], &[10, 0, 0, 50]);
        let mut reply = a.clone();
        reply[6..12].copy_from_slice(&[7; 6]);
        reply[21] = 2;
        reply[22..28].copy_from_slice(&[7; 6]);
        reply[28..32].copy_from_slice(&[10, 0, 0, 50]);
        assert_eq!(
            crate::dhcp::arp_claims(&reply, Ipv4Addr::new(10, 0, 0, 50), MAC),
            Some([7; 6])
        );
    }
}
