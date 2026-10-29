//! PPPoE client transport (G3.9ga): how a `/interface pppoe-client` talks
//! on its Ethernet port, as whole frames. The control plane (Discovery,
//! LCP, authentication, IPCP/IPv6CP) is `proto-pppoe`'s `Client`, driven by
//! the engine; the port carries its frames, and once the session is up it
//! also carries the session's packets between the wire and the client's
//! netdev without the engine (the relay of the Linux backend: one thread per
//! direction, `docs/pppoe-client.md`).
//!
//! Everything is non-blocking: the engine polls [`PppoeClientPort::recv`]
//! from its service tick. The virtual lab answers with a [`PppoeLab`] — a
//! simulated BNG the engine installs — so the lab, the GUI demo and the CI
//! get sessions without any network.

use std::collections::VecDeque;
use std::sync::Arc;

use corerouter_model::IfName;

use crate::HalError;

/// Control frames kept waiting per port (a flood cannot grow memory).
pub const MAX_INBOX: usize = 256;
/// Largest frame taken (hostile input: PPPoE needs at most 1500 + headers).
pub const MAX_FRAME: usize = 1600;

/// What the relay needs to carry a session's packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionLink {
    pub session_id: u16,
    /// The BNG's MAC (the AC of the session).
    pub ac_mac: [u8; 6],
    /// Clamp the MSS of TCP SYNs to fit this MTU (`None`: leave them).
    /// RouterOS `change-tcp-mss`; IPv4 and IPv6 both.
    pub clamp_mtu: Option<u16>,
}

/// Packets and bytes the relay carried, both ways.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RelayCounters {
    /// Wire → client netdev.
    pub rx_packets: u64,
    pub rx_bytes: u64,
    /// Client netdev → wire.
    pub tx_packets: u64,
    pub tx_bytes: u64,
    /// Dropped: too big, malformed, or a queue full.
    pub dropped: u64,
    /// TCP SYNs whose MSS was lowered.
    pub mss_clamped: u64,
}

/// A PPPoE client's port.
pub trait PppoeClientPort: Send {
    /// Source MAC of the client's frames (the Ethernet port's).
    fn mac(&self) -> [u8; 6];

    /// Send one Ethernet frame (Discovery or session control).
    fn send(&mut self, frame: &[u8]) -> Result<(), HalError>;

    /// Next control frame for the client (Discovery, LCP, PAP/CHAP,
    /// IPCP/IPv6CP), or `None` when nothing is waiting. Session data never
    /// comes here once [`PppoeClientPort::set_session`] took it.
    fn recv(&mut self) -> Result<Option<Vec<u8>>, HalError>;

    /// Start (`Some`) or stop carrying the session's packets.
    fn set_session(&mut self, link: Option<SessionLink>) -> Result<(), HalError>;

    fn counters(&self) -> RelayCounters {
        RelayCounters::default()
    }
}

/// A simulated BNG for the virtual lab and the tests.
pub trait PppoeLab: Send + Sync {
    /// Frames the BNG sends back for `frame`, sent by the client with MAC
    /// `mac` on lab port `port` at `now_ms`.
    fn answer(&self, port: &IfName, mac: [u8; 6], frame: &[u8], now_ms: u64) -> Vec<Vec<u8>>;
}

pub type SharedPppoeLab = Arc<dyn PppoeLab>;

/// The virtual lab's port: frames go to the simulated BNG, its answers
/// wait in a bounded inbox.
pub struct SimPppoePort {
    pub port: IfName,
    pub mac: [u8; 6],
    pub server: Option<SharedPppoeLab>,
    inbox: VecDeque<Vec<u8>>,
    session: Option<SessionLink>,
    /// Lab time: a frame sent is one millisecond.
    clock: u64,
}

impl SimPppoePort {
    pub fn new(port: IfName, mac: [u8; 6], server: Option<SharedPppoeLab>) -> Self {
        SimPppoePort {
            port,
            mac,
            server,
            inbox: VecDeque::new(),
            session: None,
            clock: 0,
        }
    }

    /// The session the relay would carry (tests).
    pub fn session(&self) -> Option<SessionLink> {
        self.session
    }
}

impl PppoeClientPort for SimPppoePort {
    fn mac(&self) -> [u8; 6] {
        self.mac
    }

    fn send(&mut self, frame: &[u8]) -> Result<(), HalError> {
        if frame.len() > MAX_FRAME {
            return Err(HalError::Rejected(format!(
                "frame of {} bytes (at most {MAX_FRAME})",
                frame.len()
            )));
        }
        self.clock = self.clock.saturating_add(1);
        if let Some(server) = &self.server {
            for f in server.answer(&self.port, self.mac, frame, self.clock) {
                if self.inbox.len() < MAX_INBOX {
                    self.inbox.push_back(f);
                }
            }
        }
        Ok(())
    }

    fn recv(&mut self) -> Result<Option<Vec<u8>>, HalError> {
        Ok(self.inbox.pop_front())
    }

    fn set_session(&mut self, link: Option<SessionLink>) -> Result<(), HalError> {
        self.session = link;
        Ok(())
    }
}

/// Lower the MSS option of a TCP SYN in `ip` (an IPv4 or IPv6 packet) so
/// a segment fits `mtu`; returns whether it changed. The TCP checksum is
/// fixed incrementally (RFC 1624). Anything else is left alone: fragments,
/// IPv6 extension headers, a malformed header (hostile input).
pub fn clamp_mss(ip: &mut [u8], mtu: u16) -> bool {
    let Some(&first) = ip.first() else {
        return false;
    };
    let (tcp_at, max_mss) = match first >> 4 {
        4 => {
            let ihl = usize::from(first & 0x0f) * 4;
            // Protocol TCP, not a fragment (offset 0, MF clear).
            let frag = ip
                .get(6..8)
                .and_then(|b| <[u8; 2]>::try_from(b).ok())
                .map(|b| u16::from_be_bytes(b) & 0x3fff);
            if ihl < 20 || ip.get(9) != Some(&6) || frag != Some(0) {
                return false;
            }
            (ihl, mtu.saturating_sub(40))
        }
        // Next header TCP right after the fixed header.
        6 if ip.get(6) == Some(&6) => (40, mtu.saturating_sub(60)),
        _ => return false,
    };
    let Some(tcp) = ip.get_mut(tcp_at..) else {
        return false;
    };
    let (Some(&off), Some(&flags)) = (tcp.get(12), tcp.get(13)) else {
        return false;
    };
    if flags & 0x02 == 0 {
        return false;
    }
    let hdr = usize::from(off >> 4) * 4;
    let mut i = 20;
    while i + 1 < hdr {
        match tcp.get(i).copied() {
            None | Some(0) => return false,
            Some(1) => i += 1,
            Some(kind) => {
                let len = usize::from(tcp.get(i + 1).copied().unwrap_or(0));
                if len < 2 || i + len > hdr {
                    return false;
                }
                if kind == 2 && len == 4 {
                    let (Some(&hi), Some(&lo)) = (tcp.get(i + 2), tcp.get(i + 3)) else {
                        return false;
                    };
                    let old = u16::from_be_bytes([hi, lo]);
                    if old <= max_mss {
                        return false;
                    }
                    let new = max_mss.to_be_bytes();
                    if let Some(m) = tcp.get_mut(i + 2..i + 4) {
                        m.copy_from_slice(&new);
                    }
                    if let Some(c) = tcp.get_mut(16..18)
                        && let Ok(hc) = <[u8; 2]>::try_from(&*c)
                    {
                        // RFC 1624 eq. 3: HC' = ~(~HC + ~m + m').
                        let hc = u16::from_be_bytes(hc);
                        let mut sum = u32::from(!hc) + u32::from(!old) + u32::from(max_mss);
                        sum = (sum & 0xffff) + (sum >> 16);
                        sum = (sum & 0xffff) + (sum >> 16);
                        let folded = u16::try_from(sum).unwrap_or(u16::MAX);
                        c.copy_from_slice(&(!folded).to_be_bytes());
                    }
                    return true;
                }
                i += len;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ones' complement sum over `parts`, folded.
    fn sum(parts: &[&[u8]]) -> u16 {
        let mut s: u32 = 0;
        for p in parts {
            for c in p.chunks(2) {
                s += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
            }
        }
        while s > 0xffff {
            s = (s & 0xffff) + (s >> 16);
        }
        s as u16
    }

    fn syn_v4(mss: u16) -> Vec<u8> {
        let mut p = vec![0u8; 44];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&44u16.to_be_bytes());
        p[8] = 64;
        p[9] = 6;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        let t = &mut p[20..];
        t[0..2].copy_from_slice(&1234u16.to_be_bytes());
        t[2..4].copy_from_slice(&80u16.to_be_bytes());
        t[12] = 6 << 4;
        t[13] = 0x02;
        t[20..24].copy_from_slice(&[2, 4, (mss >> 8) as u8, mss as u8]);
        let pseudo = [10, 0, 0, 1, 10, 0, 0, 2, 0, 6, 0, 24];
        let c = !sum(&[&pseudo, &p[20..]]);
        p[36..38].copy_from_slice(&c.to_be_bytes());
        p
    }

    #[test]
    fn syn_mss_is_lowered_and_checksum_stays_valid() {
        let mut p = syn_v4(1460);
        assert!(clamp_mss(&mut p, 1460));
        assert_eq!(u16::from_be_bytes([p[42], p[43]]), 1420);
        let pseudo = [10, 0, 0, 1, 10, 0, 0, 2, 0, 6, 0, 24];
        assert_eq!(sum(&[&pseudo, &p[20..]]), 0xffff, "checksum broken");
        // Already small enough: untouched.
        let mut q = syn_v4(1300);
        assert!(!clamp_mss(&mut q, 1460));
        assert_eq!(q, syn_v4(1300));
    }

    #[test]
    fn not_a_syn_or_malformed_is_left_alone() {
        let mut ack = syn_v4(1460);
        ack[33] = 0x10;
        assert!(!clamp_mss(&mut ack, 1460));
        let mut short = syn_v4(1460);
        short.truncate(30);
        assert!(!clamp_mss(&mut short, 1460));
        let mut bad_len = syn_v4(1460);
        bad_len[41] = 40;
        assert!(!clamp_mss(&mut bad_len, 1460));
        assert!(!clamp_mss(&mut [], 1460));
        assert!(!clamp_mss(&mut [0x60], 1460));
    }

    #[test]
    fn ipv6_syn_is_clamped_to_mtu_minus_60() {
        let v4 = syn_v4(1460);
        let mut p = vec![0u8; 40];
        p[0] = 0x60;
        p[6] = 6;
        p.extend_from_slice(&v4[20..]);
        assert!(clamp_mss(&mut p, 1460));
        assert_eq!(u16::from_be_bytes([p[62], p[63]]), 1400);
    }
}
