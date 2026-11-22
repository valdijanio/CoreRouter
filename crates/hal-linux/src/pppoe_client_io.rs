//! The PPPoE client's port and relay (G3.9ga).
//!
//! A client's netdev (`pppoe-out1`) is one end of a veth pair the apply
//! creates (`LinkSpec::PppoeOut`); the other end (`pppoe-out1-r`) is the
//! relay's. What the kernel routes out of `pppoe-out1` arrives on the relay
//! end, where a packet socket reads it, puts the PPPoE and PPP headers on
//! and sends it on the Ethernet port; what the BNG sends for the session
//! goes the other way, written to the relay end so the kernel receives it
//! on `pppoe-out1` (prerouting, conntrack and `in-interface` see it like
//! any received packet). The kernel's own `ppp`/`pppoe` driver would need
//! `/dev/ppp` ioctls (`unsafe`); the veth is created over rtnetlink and
//! keeps the interface (and the firewall rules naming it) through redials.
//! Numbers and the comparison: `docs/pppoe-client.md`.
//!
//! Two threads per client, one per direction (`pppoe-rx-<name>`,
//! `pppoe-tx-<name>`), each blocking in `poll` with a 200 ms timeout to see
//! the stop flag. Control frames (Discovery, LCP, PAP/CHAP, IPCP/IPv6CP)
//! go to the engine through a bounded queue ([`MAX_INBOX`], the rest are
//! dropped and counted); the engine sends its own frames on a cloned
//! socket. The session the relay carries is read once per batch of frames,
//! not per packet.

use std::collections::VecDeque;
use std::io::{self, IoSliceMut};
use std::os::fd::{AsFd, AsRawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};

use corerouter_hal::HalError;
use corerouter_hal::pppoe_client::{
    MAX_FRAME, MAX_INBOX, PppoeClientPort, RelayCounters, SessionLink, clamp_mss,
};
use corerouter_model::IfName;
use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::socket::{LinkAddr, MsgFlags, bind, recvmsg, send};
use socket2::{Domain, Protocol, SockFilter, Socket, Type};

use crate::l2::{if_info, io_err};
use crate::pppoe_io::{ETH_P_PPP_SES, PortSender, PppoePort};

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const PPP_IP: u16 = 0x0021;
const PPP_IPV6: u16 = 0x0057;
/// Ethernet + PPPoE + PPP protocol.
const ENCAP: usize = 14 + 6 + 2;
/// Frames handled per wake-up before the session is read again.
const BATCH: usize = 256;
const POLL_MS: u16 = 200;
const RCVBUF: usize = 4 << 20;

// Classic BPF of the relay end: IPv4 or IPv6 the kernel sent through the
// client's netdev (it arrives as received here), never our own writes.
const LD_W_ABS: u16 = 0x20;
const LD_H_ABS: u16 = 0x28;
const JEQ_K: u16 = 0x15;
const RET_K: u16 = 0x06;
const SKF_AD_PKTTYPE: u32 = 0xFFFF_F000 + 4;
const PACKET_OUTGOING: u32 = 4;

fn relay_filter() -> Vec<SockFilter> {
    [
        (LD_W_ABS, 0, 0, SKF_AD_PKTTYPE),
        (JEQ_K, 4, 0, PACKET_OUTGOING),
        (LD_H_ABS, 0, 0, 12),
        (JEQ_K, 1, 0, u32::from(ETH_P_IP)),
        (JEQ_K, 0, 1, u32::from(ETH_P_IPV6)),
        (RET_K, 0, 0, 0x0004_0000),
        (RET_K, 0, 0, 0),
    ]
    .iter()
    .map(|&(c, t, f, k)| SockFilter::new(c, t, f, k))
    .collect()
}

#[derive(Default)]
struct Counters {
    rx_packets: AtomicU64,
    rx_bytes: AtomicU64,
    tx_packets: AtomicU64,
    tx_bytes: AtomicU64,
    dropped: AtomicU64,
    mss_clamped: AtomicU64,
}

impl Counters {
    fn add(c: &AtomicU64, n: u64) {
        c.fetch_add(n, Ordering::Relaxed);
    }
}

struct Shared {
    stop: AtomicBool,
    session: Mutex<Option<SessionLink>>,
    inbox: Mutex<VecDeque<Vec<u8>>>,
    counters: Counters,
}

impl Shared {
    fn session(&self) -> Option<SessionLink> {
        *self.session.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// A PPPoE client's port on Linux (see the module docs).
pub struct LinuxPppoeClientPort {
    mac: [u8; 6],
    tx: PortSender,
    shared: Arc<Shared>,
    threads: Vec<JoinHandle<()>>,
}

impl LinuxPppoeClientPort {
    /// Open the relay of client `client` (its veth's other end `relay`,
    /// created by the apply) on Ethernet port `uplink`.
    pub fn open(client: &IfName, relay: &str, uplink: &IfName) -> io::Result<Self> {
        let up = PppoePort::open(uplink, &[], true)?;
        let mac = up.mac();
        let tx = up.sender()?;
        let relay_name: IfName = relay
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{relay}: {e}")))?;
        let relay_info = if_info(&relay_name)?;
        let main_mac = if_info(client)?.mac;
        let rsock = Socket::new(
            Domain::PACKET,
            Type::RAW,
            Some(Protocol::from(i32::from(0x0003u16.to_be()))),
        )?;
        rsock.set_nonblocking(true)?;
        crate::l2::rcvbuf(&rsock, RCVBUF);
        rsock.attach_filter(&relay_filter())?;
        bind(rsock.as_raw_fd(), &relay_info.link).map_err(io_err)?;
        drain(&rsock);
        let rsend = rsock.try_clone()?;
        let shared = Arc::new(Shared {
            stop: AtomicBool::new(false),
            session: Mutex::new(None),
            inbox: Mutex::new(VecDeque::new()),
            counters: Counters::default(),
        });
        let to_kernel = Downstream {
            shared: Arc::clone(&shared),
            up,
            relay: rsend,
            hdr: eth_header(main_mac, relay_info.mac),
        };
        let to_wire = Upstream {
            shared: Arc::clone(&shared),
            relay: rsock,
            wire: tx.try_clone()?,
            mac,
        };
        let short: String = client.as_str().chars().take(8).collect();
        let threads = vec![
            thread::Builder::new()
                .name(format!("pppoe-rx-{short}"))
                .spawn(move || to_kernel.run())?,
            thread::Builder::new()
                .name(format!("pppoe-tx-{short}"))
                .spawn(move || to_wire.run())?,
        ];
        Ok(Self {
            mac,
            tx,
            shared,
            threads,
        })
    }
}

impl Drop for LinuxPppoeClientPort {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

impl PppoeClientPort for LinuxPppoeClientPort {
    fn mac(&self) -> [u8; 6] {
        self.mac
    }

    fn send(&mut self, frame: &[u8]) -> Result<(), HalError> {
        self.tx.send(frame).map_err(|e| HalError::Io(e.to_string()))
    }

    fn recv(&mut self) -> Result<Option<Vec<u8>>, HalError> {
        Ok(self
            .shared
            .inbox
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front())
    }

    fn set_session(&mut self, link: Option<SessionLink>) -> Result<(), HalError> {
        *self
            .shared
            .session
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = link;
        Ok(())
    }

    fn counters(&self) -> RelayCounters {
        let c = &self.shared.counters;
        let g = |a: &AtomicU64| a.load(Ordering::Relaxed);
        RelayCounters {
            rx_packets: g(&c.rx_packets),
            rx_bytes: g(&c.rx_bytes),
            tx_packets: g(&c.tx_packets),
            tx_bytes: g(&c.tx_bytes),
            dropped: g(&c.dropped),
            mss_clamped: g(&c.mss_clamped),
        }
    }
}

/// Drop what the socket queued before its filter and bind (see
/// `pppoe_io::drop_queued`).
fn drain(sock: &Socket) {
    let mut buf = [0u8; 64];
    for _ in 0..4096 {
        let mut iov = [IoSliceMut::new(&mut buf)];
        if recvmsg::<LinkAddr>(sock.as_raw_fd(), &mut iov, None, MsgFlags::MSG_DONTWAIT).is_err() {
            break;
        }
    }
}

/// Copy `bytes` into `buf` at `at` (nothing when it does not fit).
fn put(buf: &mut [u8], at: usize, bytes: &[u8]) {
    if let Some(d) = buf.get_mut(at..at + bytes.len()) {
        d.copy_from_slice(bytes);
    }
}

/// dst = the client's netdev, src = the relay end; the EtherType is filled
/// per packet.
fn eth_header(dst: [u8; 6], src: [u8; 6]) -> [u8; 14] {
    let mut h = [0u8; 14];
    put(&mut h, 0, &dst);
    put(&mut h, 6, &src);
    h
}

/// Whether `fd` is readable within the poll timeout.
fn readable(fd: std::os::fd::BorrowedFd<'_>) -> bool {
    let mut fds = [PollFd::new(fd, PollFlags::POLLIN)];
    matches!(poll(&mut fds, PollTimeout::from(POLL_MS)), Ok(n) if n > 0)
}

/// Wire → kernel: session data to the relay end, the rest to the engine.
struct Downstream {
    shared: Arc<Shared>,
    up: PppoePort,
    relay: Socket,
    hdr: [u8; 14],
}

impl Downstream {
    fn run(mut self) {
        let mut out = Vec::with_capacity(MAX_FRAME + 64);
        while !self.shared.stop.load(Ordering::Relaxed) {
            let ready = self.up.fds().first().is_some_and(|fd| readable(*fd));
            if !ready {
                continue;
            }
            let session = self.shared.session();
            let shared = Arc::clone(&self.shared);
            let relay = &self.relay;
            let hdr = self.hdr;
            let mut control: Vec<Vec<u8>> = Vec::new();
            let r = self.up.recv(|frame| {
                match session.and_then(|s| decap(frame, &s)) {
                    Some((ethertype, ip)) => {
                        out.clear();
                        out.extend_from_slice(&hdr);
                        put(&mut out, 12, &ethertype.to_be_bytes());
                        out.extend_from_slice(ip);
                        if let Some(s) = session
                            && let Some(mtu) = s.clamp_mtu
                            && let Some(ip) = out.get_mut(14..)
                            && clamp_mss(ip, mtu)
                        {
                            Counters::add(&shared.counters.mss_clamped, 1);
                        }
                        match send(relay.as_raw_fd(), &out, MsgFlags::empty()) {
                            Ok(_) => {
                                Counters::add(&shared.counters.rx_packets, 1);
                                Counters::add(&shared.counters.rx_bytes, ip.len() as u64);
                            }
                            Err(_) => Counters::add(&shared.counters.dropped, 1),
                        }
                    }
                    None if frame.len() <= MAX_FRAME && !is_data(frame) => {
                        control.push(frame.to_vec());
                    }
                    // Data of no session we know (a stale one): dropped.
                    None => Counters::add(&shared.counters.dropped, 1),
                }
            });
            if r.is_err() {
                Counters::add(&self.shared.counters.dropped, 1);
            }
            if !control.is_empty() {
                let mut q = self
                    .shared
                    .inbox
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner);
                for f in control {
                    if q.len() < MAX_INBOX {
                        q.push_back(f);
                    } else {
                        Counters::add(&self.shared.counters.dropped, 1);
                    }
                }
            }
        }
    }
}

/// Session frame `f` of session `s` carrying IPv4/IPv6: (EtherType, packet).
fn decap<'a>(f: &'a [u8], s: &SessionLink) -> Option<(u16, &'a [u8])> {
    let be = |i: usize| {
        f.get(i..i + 2)
            .and_then(|b| <[u8; 2]>::try_from(b).ok())
            .map(u16::from_be_bytes)
    };
    if be(12)? != ETH_P_PPP_SES || f.get(6..12)? != s.ac_mac || be(16)? != s.session_id {
        return None;
    }
    // RFC 2516 §4: VER/TYPE 0x11, CODE 0x00 for session data.
    if f.get(14..16)? != [0x11, 0x00] {
        return None;
    }
    let len = usize::from(be(18)?);
    let payload = f.get(20..20 + len)?;
    let ethertype = match u16::from_be_bytes(<[u8; 2]>::try_from(payload.get(..2)?).ok()?) {
        PPP_IP => ETH_P_IP,
        PPP_IPV6 => ETH_P_IPV6,
        _ => return None,
    };
    Some((ethertype, payload.get(2..)?))
}

/// A session frame carrying IPv4/IPv6 (not control): never for the engine.
fn is_data(f: &[u8]) -> bool {
    f.get(12..14) == Some(&ETH_P_PPP_SES.to_be_bytes())
        && matches!(f.get(20..22), Some(&[0x00, 0x21] | &[0x00, 0x57]))
}

/// Kernel → wire: what the client's netdev sent, encapsulated.
struct Upstream {
    shared: Arc<Shared>,
    relay: Socket,
    wire: PortSender,
    mac: [u8; 6],
}

impl Upstream {
    fn run(self) {
        let mut buf = vec![0u8; MAX_FRAME + ENCAP];
        while !self.shared.stop.load(Ordering::Relaxed) {
            if !readable(self.relay.as_fd()) {
                continue;
            }
            let session = self.shared.session();
            for _ in 0..BATCH {
                // Read at offset 8: the 14-byte Ethernet header lands on
                // 8..22 and the IP packet on 22.., where it stays; only the
                // 22 bytes in front are rewritten.
                let Some(dst) = buf.get_mut(8..) else { break };
                let mut iov = [IoSliceMut::new(dst)];
                let n = match recvmsg::<LinkAddr>(
                    self.relay.as_raw_fd(),
                    &mut iov,
                    None,
                    MsgFlags::MSG_DONTWAIT,
                ) {
                    Ok(m) => m.bytes,
                    Err(Errno::EAGAIN | Errno::EINTR) => break,
                    Err(_) => break,
                };
                let Some(s) = session else {
                    // No session: what the kernel sends is lost (routes
                    // via the client are gone soon after).
                    Counters::add(&self.shared.counters.dropped, 1);
                    continue;
                };
                let Some(ip_len) = n.checked_sub(14).filter(|l| *l > 0) else {
                    continue;
                };
                let proto = match buf.get(20..22) {
                    Some(&[0x08, 0x00]) => PPP_IP,
                    Some(&[0x86, 0xDD]) => PPP_IPV6,
                    _ => continue,
                };
                if let Some(mtu) = s.clamp_mtu
                    && let Some(ip) = buf.get_mut(ENCAP..ENCAP + ip_len)
                    && clamp_mss(ip, mtu)
                {
                    Counters::add(&self.shared.counters.mss_clamped, 1);
                }
                let Ok(plen) = u16::try_from(ip_len + 2) else {
                    Counters::add(&self.shared.counters.dropped, 1);
                    continue;
                };
                put(&mut buf, 0, &s.ac_mac);
                put(&mut buf, 6, &self.mac);
                put(&mut buf, 12, &ETH_P_PPP_SES.to_be_bytes());
                // RFC 2516 §4: VER 1, TYPE 1, CODE 0 (session data).
                put(&mut buf, 14, &[0x11, 0x00]);
                put(&mut buf, 16, &s.session_id.to_be_bytes());
                put(&mut buf, 18, &plen.to_be_bytes());
                put(&mut buf, 20, &proto.to_be_bytes());
                match buf.get(..ENCAP + ip_len).map(|f| self.wire.send(f)) {
                    Some(Ok(())) => {
                        Counters::add(&self.shared.counters.tx_packets, 1);
                        Counters::add(&self.shared.counters.tx_bytes, ip_len as u64);
                    }
                    _ => Counters::add(&self.shared.counters.dropped, 1),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link() -> SessionLink {
        SessionLink {
            session_id: 0x1234,
            ac_mac: [2, 0, 0, 0, 0, 0xAC],
            clamp_mtu: None,
        }
    }

    fn frame(sid: u16, proto: u16, body: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
        f.extend_from_slice(&[2, 0, 0, 0, 0, 0xAC]);
        f.extend_from_slice(&ETH_P_PPP_SES.to_be_bytes());
        f.extend_from_slice(&[0x11, 0x00]);
        f.extend_from_slice(&sid.to_be_bytes());
        f.extend_from_slice(&((body.len() + 2) as u16).to_be_bytes());
        f.extend_from_slice(&proto.to_be_bytes());
        f.extend_from_slice(body);
        f
    }

    #[test]
    fn only_the_sessions_ip_is_decapsulated() {
        let ip = [0x45u8, 0, 0, 20];
        assert_eq!(
            decap(&frame(0x1234, PPP_IP, &ip), &link()),
            Some((ETH_P_IP, &ip[..]))
        );
        assert_eq!(
            decap(&frame(0x1234, PPP_IPV6, &ip), &link()).map(|x| x.0),
            Some(ETH_P_IPV6)
        );
        // Another session, LCP, a lying length, a short frame: not data.
        assert_eq!(decap(&frame(0x9999, PPP_IP, &ip), &link()), None);
        assert_eq!(decap(&frame(0x1234, 0xC021, &ip), &link()), None);
        let mut lie = frame(0x1234, PPP_IP, &ip);
        lie[19] = 200;
        assert_eq!(decap(&lie, &link()), None);
        assert_eq!(decap(&lie[..15], &link()), None);
        assert!(is_data(&frame(1, PPP_IP, &ip)));
        assert!(!is_data(&frame(1, 0xC021, &ip)));
    }
}
