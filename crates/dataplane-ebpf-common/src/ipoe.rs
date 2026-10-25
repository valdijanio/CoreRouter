// SPDX-License-Identifier: GPL-2.0-or-later
//! IPoE subscribers (G4.3f) in the PPPoE session maps: a DHCP client the
//! daemon's `ipoe` service made a session of is one more entry of
//! `PPPOE_SESSIONS`, flagged [`F_IPOE`], keyed in `PPPOE_KEYS` by the access
//! port and the client's MAC with SESSION_ID 0 (RFC 2516 §5: a PPPoE session
//! never has id 0, discovery frames do, so the keys cannot collide) and by
//! its address in `PPPOE_V4`.
//!
//! Upstream, on a port of `IPOE_PORTS`: an untagged IPv4 frame from a
//! session's MAC to the BNG's MAC must come from the session's address
//! (TR-146 R-38: the IP↔MAC binding; else dropped as spoofed), is policed
//! and counted, and goes on untouched (no header to strip). DHCP to port 67
//! always passes (to the daemon's socket), and hosts the map does not know
//! are the kernel's business, as without IPoE.
//!
//! Downstream: the same policer and counters as PPPoE, then the kernel
//! forwards the packet as usual (its firewall and ARP see it): IPoE needs
//! no encapsulation, so the kernel path costs nothing to keep. Only a flow
//! conntrack already accepted (the CGNAT fast path) is sent from XDP, with
//! the MACs rewritten.
//!
//! Untagged frames only: on a VLAN per subscriber or per service, the
//! program is attached to the VLAN interface (generic XDP sees the frame
//! without its tag there).

use crate::nat::PacketMut;
use crate::packet::Packet;
use crate::parse::{ETH_HLEN, ETH_P_IP};
use crate::pppoe::{
    DownSession, F_ACTIVE, F_FAST_UP, F_IPV4, SessionKey, Sessions, Stat, Up, UpSession, View,
};

/// The session is an IPoE subscriber (a DHCP lease), not a PPPoE one.
pub const F_IPOE: u16 = 1 << 6;
/// SESSION_ID of an IPoE key.
pub const SID: u16 = 0;
/// Bit of the `SETTINGS` word `pppoe::SETTINGS_SLOT` that switches IPoE on
/// (bit 0 is PPPoE).
pub const SETTINGS_BIT: u64 = 1 << 1;
/// MTU toward an IPoE subscriber when the session says none.
pub const DEFAULT_MTU: u16 = 1500;
/// Access ports with IPoE subscribers (`IPOE_PORTS`: ifindex → flags).
pub const PORTS_MAX: u32 = 256;
/// DHCP server port (RFC 2131 §4.1).
const BOOTPS: u16 = 67;
const UDP: u8 = 17;

/// The upstream key of an IPoE subscriber.
pub fn key(ifindex: u32, client_mac: [u8; 6]) -> SessionKey {
    SessionKey {
        ifindex,
        vlan: 0,
        inner_vlan: 0,
        sid: SID,
        client_mac,
    }
}

/// Classify and police a frame that arrived on IPoE port `ifindex`
/// (`Up::NotPppoe` when it is not a known subscriber's IPv4: the rest of
/// the program decides as without IPoE).
#[inline(always)]
pub fn upstream<P: Packet + ?Sized, L: Sessions>(p: &P, ifindex: u32, l: &mut L, now: u64) -> Up {
    if !l.ipoe_port(ifindex) || p.be16(12) != Some(ETH_P_IP) {
        return Up::NotPppoe;
    }
    let Some([vi, _, l0, l1, _, _, _, _, _, proto, _, _, s0, s1, s2, s3]) = p.bytes::<16>(ETH_HLEN)
    else {
        return Up::NotPppoe;
    };
    let ihl = usize::from(vi & 0x0f) * 4;
    if vi >> 4 != 4 || ihl < 20 {
        return Up::NotPppoe;
    }
    // DHCP (a renewal from the subscriber's address, or a new client's
    // DISCOVER from 0.0.0.0) is the daemon's.
    if proto == UDP && p.be16(ETH_HLEN + ihl + 2) == Some(BOOTPS) {
        return Up::User(Stat::IpoeDhcp);
    }
    let (Some(dst), Some(src)) = (p.bytes::<6>(0), p.bytes::<6>(6)) else {
        return Up::NotPppoe;
    };
    let Some(idx) = l.by_key(&key(ifindex, src).to_bytes()) else {
        return Up::NotPppoe;
    };
    let Some(s) = l.session(idx).map(View::of) else {
        return Up::NotPppoe;
    };
    if !s.has(F_ACTIVE) || !s.has(F_IPOE) || s.ifindex != ifindex || s.client_mac != src {
        return Up::NotPppoe;
    }
    // A broadcast or a frame to another host of the segment: not routed by
    // us, nothing to police.
    if dst != s.server_mac {
        return Up::NotPppoe;
    }
    if !s.has(F_IPV4) || [s0, s1, s2, s3] != s.ipv4 {
        return Up::Drop(Stat::Spoofed, Some(idx));
    }
    let len = u16::from_be_bytes([l0, l1]);
    if usize::from(len) < ihl || usize::from(len) + ETH_HLEN > p.len() {
        return Up::Drop(Stat::Malformed, Some(idx));
    }
    if !crate::pppoe::police_up(l, idx, now, u64::from(len)) {
        return Up::Drop(Stat::UpPoliced, Some(idx));
    }
    Up::Session(UpSession {
        idx,
        tags: 0,
        v6: false,
        ip_len: len,
        fast: s.has(F_FAST_UP),
        ipoe: true,
    })
}

/// Point a packet toward the subscriber of `d` (the CGNAT fast path):
/// its MAC and ours. The TTL is already decremented.
#[inline(always)]
pub fn rewrite<P: PacketMut + ?Sized>(p: &mut P, d: &DownSession) -> Option<()> {
    let [c0, c1, c2, c3, c4, c5] = d.client_mac;
    let [m0, m1, m2, m3, m4, m5] = d.server_mac;
    p.store(0, [c0, c1, c2, c3, c4, c5, m0, m1, m2, m3, m4, m5])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipoe_keys_never_meet_pppoe_ones() {
        let k = key(3, [2, 0, 0, 0, 0, 1]);
        assert_eq!(k.sid, 0);
        assert_eq!(SessionKey::from_bytes(k.to_bytes()), k);
        assert_ne!(F_IPOE, crate::pppoe::F_FAST_DOWN);
        assert_eq!(SETTINGS_BIT & 1, 0, "bit 0 is PPPoE's");
    }
}
