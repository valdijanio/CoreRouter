//! DHCP client transport (G4.7) on one interface, without `unsafe`:
//!
//! - receive: an `AF_PACKET` socket for IPv4 bound to the interface, with a
//!   classic BPF filter (`socket2::attach_filter`) that keeps only UDP to
//!   port 68 — so the kernel copies nothing else to us, the client hears
//!   its server before the interface has an address (no `rp_filter`, no
//!   "not for me" drop of a unicast OFFER) and sees the server's MAC (for
//!   `allowed_servers`);
//! - send: broadcasts as whole Ethernet frames on that socket (source
//!   0.0.0.0 before a lease); unicasts (renewing, release) through a UDP
//!   socket on port 68 bound to the device, routed by the kernel. When port
//!   68 is taken (another DHCP client on the host), unicasts go out as
//!   broadcasts, which servers accept (the REBINDING form);
//! - ARP probe (RFC 5227) before using an address: an `AF_PACKET` socket for
//!   ARP while probing.
//!
//! The `sockaddr_ll` both packet sockets are bound to comes from the kernel
//! (`getifaddrs`, see `l2::if_info`), never built by hand.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::AsRawFd;

use corerouter_hal::HalError;
use corerouter_hal::dhcp::{CLIENT_PORT, Datagram, Dest, DhcpPort, MAX_MESSAGE, SERVER_PORT};
use corerouter_model::IfName;
use nix::sys::socket::{LinkAddr, MsgFlags, bind, recvfrom, send};
use socket2::{Domain, Protocol, SockFilter, Socket, Type};

use crate::l2::{if_info, io_err};

const ETH_P_IP: u16 = 0x0800;
const ETH_P_ARP: u16 = 0x0806;
const ETH_HEADER: usize = 14;
const ETH_MIN_FRAME: usize = 60;
const BROADCAST_MAC: [u8; 6] = [0xff; 6];
/// `PACKET_OUTGOING`: a copy of a frame this host sent.
const PACKET_OUTGOING: u8 = 4;
/// Frames read per call (a flood cannot stall the service loop).
const RECV_BUDGET: usize = 64;

// Classic BPF opcodes (linux/filter.h).
const LD_H_ABS: u16 = 0x28;
const LD_B_ABS: u16 = 0x30;
const LD_H_IND: u16 = 0x48;
const LDX_B_MSH: u16 = 0xb1;
const JEQ_K: u16 = 0x15;
const JSET_K: u16 = 0x45;
const RET_K: u16 = 0x06;

/// `ip and udp dst port 68 and not a fragment`, on Ethernet frames.
fn dhcp_filter() -> [SockFilter; 11] {
    [
        SockFilter::new(LD_H_ABS, 0, 0, 12), // EtherType
        SockFilter::new(JEQ_K, 0, 8, u32::from(ETH_P_IP)),
        SockFilter::new(LD_B_ABS, 0, 0, 23), // IP protocol
        SockFilter::new(JEQ_K, 0, 6, 17),    // UDP
        SockFilter::new(LD_H_ABS, 0, 0, 20), // flags + fragment offset
        SockFilter::new(JSET_K, 4, 0, 0x1fff),
        SockFilter::new(LDX_B_MSH, 0, 0, 14), // X = IP header length
        SockFilter::new(LD_H_IND, 0, 0, 16),  // UDP destination port
        SockFilter::new(JEQ_K, 0, 1, u32::from(CLIENT_PORT)),
        SockFilter::new(RET_K, 0, 0, 0xffff),
        SockFilter::new(RET_K, 0, 0, 0),
    ]
}

fn packet_socket(link: &LinkAddr, ethertype: u16) -> io::Result<Socket> {
    let proto = Protocol::from(i32::from(ethertype.to_be()));
    let sock = Socket::new(Domain::PACKET, Type::RAW, Some(proto))?;
    sock.set_nonblocking(true)?;
    if ethertype == ETH_P_IP {
        sock.attach_filter(&dhcp_filter())?;
    }
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
    sock.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, CLIENT_PORT)).into())?;
    Ok(sock)
}

/// One's-complement sum of 16-bit words (IP and UDP checksums).
fn sum16(data: &[u8], mut acc: u32) -> u32 {
    let (words, rest) = data.as_chunks::<2>();
    for w in words {
        acc = acc.wrapping_add(u32::from(u16::from_be_bytes(*w)));
    }
    if let [last] = rest {
        acc = acc.wrapping_add(u32::from(*last) << 8);
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc > 0xffff {
        acc = (acc & 0xffff).wrapping_add(acc >> 16);
    }
    !(acc as u16)
}

/// An Ethernet frame carrying `payload` from `src`:68 to `dst`:67.
pub fn udp_frame(mac: [u8; 6], src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Option<Vec<u8>> {
    let udp_len = u16::try_from(payload.len().checked_add(8)?).ok()?;
    let ip_len = udp_len.checked_add(20)?;
    let mut ip = [0u8; 20];
    ip[0] = 0x45;
    ip[1] = 0x10; // low delay, as dhclient does
    ip[2..4].copy_from_slice(&ip_len.to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&src.octets());
    ip[16..20].copy_from_slice(&dst.octets());
    let csum = fold(sum16(&ip, 0));
    ip[10..12].copy_from_slice(&csum.to_be_bytes());

    let mut udp = Vec::with_capacity(usize::from(udp_len));
    udp.extend_from_slice(&CLIENT_PORT.to_be_bytes());
    udp.extend_from_slice(&SERVER_PORT.to_be_bytes());
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
    frame.extend_from_slice(&BROADCAST_MAC);
    frame.extend_from_slice(&mac);
    frame.extend_from_slice(&ETH_P_IP.to_be_bytes());
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&udp);
    if frame.len() < ETH_MIN_FRAME {
        frame.resize(ETH_MIN_FRAME, 0);
    }
    Some(frame)
}

/// The DHCP message in an Ethernet frame from UDP port 67 to 68, with the
/// IP source and the Ethernet source; `None` for anything else.
pub fn parse_frame(frame: &[u8]) -> Option<Datagram> {
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
    let udp = ip.get(ihl..)?;
    let sport = u16::from_be_bytes(udp.get(0..2)?.try_into().ok()?);
    let dport = u16::from_be_bytes(udp.get(2..4)?.try_into().ok()?);
    let len = usize::from(u16::from_be_bytes(udp.get(4..6)?.try_into().ok()?));
    if sport != SERVER_PORT || dport != CLIENT_PORT || len < 8 {
        return None;
    }
    let payload = udp.get(8..len)?;
    if payload.len() > MAX_MESSAGE {
        return None;
    }
    Some(Datagram {
        payload: payload.to_vec(),
        src: Ipv4Addr::from(src),
        src_mac: Some(src_mac),
    })
}

/// An ARP probe (RFC 5227): who has `ip`, from 0.0.0.0.
pub fn arp_probe(mac: [u8; 6], ip: Ipv4Addr) -> Vec<u8> {
    let mut f = Vec::with_capacity(ETH_MIN_FRAME);
    f.extend_from_slice(&BROADCAST_MAC);
    f.extend_from_slice(&mac);
    f.extend_from_slice(&ETH_P_ARP.to_be_bytes());
    f.extend_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
    f.extend_from_slice(&mac);
    f.extend_from_slice(&[0; 4]);
    f.extend_from_slice(&[0; 6]);
    f.extend_from_slice(&ip.octets());
    f.resize(ETH_MIN_FRAME, 0);
    f
}

/// The MAC of another host claiming `ip` in this ARP frame (a reply or
/// request from it, or its own probe for it).
pub fn arp_claims(frame: &[u8], ip: Ipv4Addr, me: [u8; 6]) -> Option<[u8; 6]> {
    if frame.get(12..14)? != ETH_P_ARP.to_be_bytes() {
        return None;
    }
    let arp = frame.get(ETH_HEADER..ETH_HEADER + 28)?;
    let sha: [u8; 6] = arp.get(8..14)?.try_into().ok()?;
    let spa: [u8; 4] = arp.get(14..18)?.try_into().ok()?;
    let tpa: [u8; 4] = arp.get(24..28)?.try_into().ok()?;
    if sha == me {
        return None;
    }
    let ip = ip.octets();
    let claims = spa == ip || (spa == [0; 4] && tpa == ip);
    claims.then_some(sha)
}

/// [`DhcpPort`] of the Linux backend.
pub struct LinuxDhcpPort {
    name: IfName,
    mac: [u8; 6],
    link: LinkAddr,
    raw: Socket,
    udp: Option<Socket>,
    arp: Option<(Socket, Ipv4Addr)>,
}

impl LinuxDhcpPort {
    pub fn open(name: &IfName) -> io::Result<Self> {
        let info = if_info(name)?;
        let raw = packet_socket(&info.link, ETH_P_IP)?;
        let udp = match udp_socket(name) {
            Ok(s) => Some(s),
            Err(e) => {
                log::warn!(
                    "dhcp-client {name}: UDP port 68 unavailable ({e}); renewals go out as \
                     broadcasts"
                );
                None
            }
        };
        Ok(Self {
            name: name.clone(),
            mac: info.mac,
            link: info.link,
            raw,
            udp,
            arp: None,
        })
    }

    fn send_frame(&self, frame: &[u8]) -> Result<(), HalError> {
        send(self.raw.as_raw_fd(), frame, MsgFlags::empty())
            .map(|_| ())
            .map_err(|e| HalError::Io(format!("{}: {e}", self.name)))
    }
}

impl DhcpPort for LinuxDhcpPort {
    fn mac(&self) -> [u8; 6] {
        self.mac
    }

    fn send(&mut self, payload: &[u8], src: Ipv4Addr, dest: Dest) -> Result<(), HalError> {
        if let (Dest::Unicast(server), Some(udp)) = (dest, self.udp.as_ref()) {
            let to = SocketAddr::from((server, SERVER_PORT));
            return udp
                .send_to(payload, &to.into())
                .map(|_| ())
                .map_err(|e| HalError::Io(format!("{} → {server}: {e}", self.name)));
        }
        let frame = udp_frame(self.mac, src, Ipv4Addr::BROADCAST, payload).ok_or_else(|| {
            HalError::Rejected(format!("DHCP message of {} bytes", payload.len()))
        })?;
        self.send_frame(&frame)
    }

    fn recv(&mut self) -> Result<Option<Datagram>, HalError> {
        // The UDP socket only exists to send (and so the kernel does not
        // answer unicast ACKs with "port unreachable"): its copies go.
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
            if let Some(d) = buf.get(..n).and_then(parse_frame) {
                return Ok(Some(d));
            }
        }
        Ok(None)
    }

    fn probe(&mut self, ip: Ipv4Addr) -> Result<bool, HalError> {
        let sock = packet_socket(&self.link, ETH_P_ARP)
            .map_err(|e| HalError::Io(format!("{}: ARP socket: {e}", self.name)))?;
        send(
            sock.as_raw_fd(),
            &arp_probe(self.mac, ip),
            MsgFlags::empty(),
        )
        .map_err(|e| HalError::Io(format!("{}: ARP probe: {e}", self.name)))?;
        self.arp = Some((sock, ip));
        Ok(true)
    }

    fn conflict(&mut self) -> Result<Option<[u8; 6]>, HalError> {
        let Some((sock, ip)) = self.arp.as_ref() else {
            return Ok(None);
        };
        let mut buf = [0u8; 128];
        for _ in 0..RECV_BUDGET {
            let (n, from) = match recvfrom::<LinkAddr>(sock.as_raw_fd(), &mut buf) {
                Ok(r) => r,
                Err(_) => break,
            };
            if from.is_some_and(|a| a.pkttype() == PACKET_OUTGOING) {
                continue;
            }
            if let Some(mac) = buf.get(..n).and_then(|f| arp_claims(f, *ip, self.mac)) {
                return Ok(Some(mac));
            }
        }
        Ok(None)
    }

    fn end_probe(&mut self) {
        self.arp = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: [u8; 6] = [2, 0, 0, 0, 0, 1];

    #[test]
    fn frames_round_trip_and_checksums_verify() {
        let payload = b"hello dhcp".to_vec();
        let mut frame =
            udp_frame(MAC, Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST, &payload).unwrap();
        assert_eq!(frame.len(), 60, "padded");
        // A received frame is the same shape with the ports swapped.
        frame[6..12].copy_from_slice(&[9; 6]);
        frame[34..36].copy_from_slice(&67u16.to_be_bytes());
        frame[36..38].copy_from_slice(&68u16.to_be_bytes());
        let d = parse_frame(&frame).unwrap();
        assert_eq!(d.payload, payload);
        assert_eq!(d.src_mac, Some([9; 6]));
        // IP header checksum: the sum over the header folds to zero.
        assert_eq!(fold(sum16(&frame[14..34], 0)), 0);
    }

    #[test]
    fn udp_checksum_matches_a_known_packet() {
        let f = udp_frame(
            MAC,
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 1),
            b"abc",
        )
        .unwrap();
        let udp_len = u16::from_be_bytes([f[38], f[39]]);
        let mut pseudo = vec![10, 0, 0, 2, 10, 0, 0, 1, 0, 17];
        pseudo.extend_from_slice(&udp_len.to_be_bytes());
        let udp = &f[34..34 + usize::from(udp_len)];
        assert_eq!(fold(sum16(udp, sum16(&pseudo, 0))), 0);
    }

    #[test]
    fn hostile_frames_are_dropped() {
        assert!(parse_frame(&[]).is_none());
        assert!(parse_frame(&[0; 13]).is_none());
        let mut f = udp_frame(MAC, Ipv4Addr::UNSPECIFIED, Ipv4Addr::BROADCAST, b"x").unwrap();
        f[34..36].copy_from_slice(&67u16.to_be_bytes());
        f[36..38].copy_from_slice(&68u16.to_be_bytes());
        let mut bad = f.clone();
        bad[16..18].copy_from_slice(&9000u16.to_be_bytes()); // total length past the end
        assert!(parse_frame(&bad).is_none());
        let mut bad = f.clone();
        bad[14] = 0x41; // IHL 4
        assert!(parse_frame(&bad).is_none());
        let mut bad = f;
        bad[38..40].copy_from_slice(&3u16.to_be_bytes()); // UDP length < 8
        assert!(parse_frame(&bad).is_none());
        for n in 0..80 {
            let _ = parse_frame(&vec![0x45; n]);
            let _ = arp_claims(&vec![0x08; n], Ipv4Addr::LOCALHOST, MAC);
        }
    }

    #[test]
    fn arp_conflicts() {
        let ip = Ipv4Addr::new(192, 0, 2, 50);
        let probe = arp_probe(MAC, ip);
        assert_eq!(arp_claims(&probe, ip, MAC), None, "our own probe");
        assert_eq!(
            arp_claims(&probe, ip, [7; 6]),
            Some(MAC),
            "someone else probing it"
        );
        let mut reply = probe.clone();
        reply[21] = 2;
        reply[28..32].copy_from_slice(&ip.octets());
        assert_eq!(arp_claims(&reply, ip, [7; 6]), Some(MAC));
        assert_eq!(
            arp_claims(&reply, Ipv4Addr::new(192, 0, 2, 51), [7; 6]),
            None
        );
    }
}
