//! What the BNG service (G4.3d) and the XDP data plane (G4.3c) need to
//! know about an established subscriber session.
//!
//! The field names follow `dataplane-ebpf-common::pppoe::{Session,
//! SessionKey}` (G4.3c) so the daemon fills the maps field by field:
//! `ifindex`, `sid`, `vlan`/`inner_vlan` (0 or `TAGGED | VID`),
//! `outer_tpid`, `mtu`, `client_mac`, `server_mac`, `ipv4`. The rate limit
//! is the `Mikrotik-Rate-Limit` type of `proto-radius` (G4.3b), the same for
//! a RADIUS attribute and a local `/ppp profile`.

use crate::eth::Vlans;
use crate::lcp::AuthProto;
use crate::wire::Mac;
use corerouter_proto_radius::rate_limit::RateLimit;
use std::net::Ipv4Addr;

/// A VLAN field of the descriptor: 0 = no tag, else `TAGGED | VID` (the
/// encoding of the data plane maps, where VID 0 is a priority tag).
pub const TAGGED: u16 = 0x1000;

/// Map-key fields of a session (RFC 2516 §4: the MAC pair plus SESSION_ID
/// define the session; the port and tags make it unique across access
/// networks).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionKey {
    pub ifindex: u32,
    pub vlan: u16,
    pub inner_vlan: u16,
    pub sid: u16,
    pub client_mac: Mac,
}

/// One established session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionDescriptor {
    pub ifindex: u32,
    pub sid: u16,
    /// Outer (or only) tag: 0 or `TAGGED | VID`.
    pub vlan: u16,
    /// Inner (QinQ customer) tag: 0 or `TAGGED | VID`.
    pub inner_vlan: u16,
    /// TPID of the outer tag when there are two; 0 = 0x88a8.
    pub outer_tpid: u16,
    /// Largest PPP payload toward the subscriber: its MRU (RFC 1661 §6.1,
    /// RFC 4638 above 1492).
    pub mtu: u16,
    pub client_mac: Mac,
    /// The BNG's MAC on the access port (PADO/PADS source).
    pub server_mac: Mac,
    pub ipv4: Option<Ipv4Addr>,
    /// The subscriber's IPv6 interface identifier (RFC 5072); the /64 and
    /// the delegated prefix come with G4.3e.
    pub ipv6_iid: Option<[u8; 8]>,
    /// Our link-local interface identifier.
    pub local_iid: Option<[u8; 8]>,
    pub rate_limit: Option<RateLimit>,
    pub username: Box<[u8]>,
    pub auth: Option<AuthProto>,
    /// RFC 4679 line identification from the access node, if any.
    pub circuit_id: Option<Box<[u8]>>,
    pub remote_id: Option<Box<[u8]>>,
    /// Session-Timeout (seconds) from the authorisation, if any.
    pub session_timeout: Option<u32>,
}

/// The descriptor encoding of a VLAN id (0 = untagged).
pub fn vlan_field(vid: u16) -> u16 {
    if vid == 0 { 0 } else { TAGGED | (vid & 0x0fff) }
}

impl SessionDescriptor {
    pub fn key(&self) -> SessionKey {
        SessionKey {
            ifindex: self.ifindex,
            vlan: self.vlan,
            inner_vlan: self.inner_vlan,
            sid: self.sid,
            client_mac: self.client_mac,
        }
    }

    /// The tags in this crate's form (0 = none).
    pub fn vlans(&self) -> Vlans {
        Vlans {
            outer: self.vlan & 0x0fff,
            inner: self.inner_vlan & 0x0fff,
            outer_tpid: self.outer_tpid,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vlan_encoding_matches_the_data_plane() {
        assert_eq!(vlan_field(0), 0);
        assert_eq!(vlan_field(100), 0x1064);
        assert_eq!(vlan_field(0x0fff), 0x1fff);
    }
}
