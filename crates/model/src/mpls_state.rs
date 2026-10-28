//! LDP's running state (G3.5), as the routing suite reports it: neighbors,
//! interfaces, label bindings and LDP-IGP synchronization. Read on the
//! routing service's thread and kept by the engine; never configuration.

use std::net::{IpAddr, Ipv4Addr};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LdpState {
    pub neighbors: Vec<LdpNeighborState>,
    pub interfaces: Vec<LdpInterfaceState>,
    /// By FEC, sorted.
    pub bindings: Vec<LdpBinding>,
    /// RFC 5443 state per IGP interface.
    pub igp_sync: Vec<IgpSyncState>,
}

/// One LDP session (or a peer being set up).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LdpNeighborState {
    pub lsr_id: Ipv4Addr,
    /// `ipv4` / `ipv6`: the family of the session's transport.
    pub afi: String,
    /// RFC 5036 §2.5.4 session state: `OPERATIONAL`, `OPENSENT`,
    /// `OPENREC`, `INITIALIZED`, `PRESENT` (FRR's names).
    pub state: String,
    pub transport: Option<IpAddr>,
    pub uptime: Option<String>,
}

impl LdpNeighborState {
    pub fn operational(&self) -> bool {
        self.state.eq_ignore_ascii_case("operational")
    }
}

/// LDP on one interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LdpInterfaceState {
    pub name: String,
    pub afi: String,
    /// `ACTIVE` / `DOWN` (FRR).
    pub state: String,
    /// Hello adjacencies on it.
    pub adjacencies: u32,
}

/// The labels of one FEC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LdpBinding {
    pub prefix: IpNet,
    /// What this router advertises (RFC 3032 §2.1 names for 0 and 3);
    /// `None`: no local label.
    pub local_label: Option<u32>,
    pub remote: Vec<RemoteLabel>,
}

impl LdpBinding {
    /// The remote label LDP installed (the IGP next hop's), if any.
    pub fn in_use(&self) -> Option<&RemoteLabel> {
        self.remote.iter().find(|r| r.in_use)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteLabel {
    pub neighbor: Ipv4Addr,
    pub label: u32,
    /// The neighbor is the IGP next hop: its label is the one used.
    pub in_use: bool,
}

/// RFC 5443 on one IGP interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IgpSyncState {
    pub interface: String,
    /// The IGP (`ospf`).
    pub igp: String,
    /// LDP is up there: the IGP uses the real cost.
    pub achieved: bool,
    /// Seconds of holddown left, when counting.
    pub holddown_left: Option<u32>,
}
