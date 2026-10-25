//! The PPPoE subscriber data plane (G4.3c) as the BNG service (G4.3d)
//! sees it: one session per slot index, with its rates, and its counters.
//! `hal-linux` writes them into the XDP maps; a HAL without XDP refuses
//! and the service carries the traffic itself (its slow path).

use std::net::Ipv4Addr;

/// A rate limit of one direction, RouterOS terms: bits per second, the
/// burst rate and threshold (bits per second) and the burst time
/// (seconds). All zero = no limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rate {
    pub rate_bps: u64,
    pub burst_bps: u64,
    pub threshold_bps: u64,
    pub burst_secs: u32,
}

/// One subscriber session for the XDP maps (names of
/// `dataplane-ebpf-common::pppoe::Session`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PppoeSession {
    pub ifindex: u32,
    pub sid: u16,
    /// 0 or `0x1000 | VID`.
    pub vlan: u16,
    pub inner_vlan: u16,
    /// 0 = 0x88a8.
    pub outer_tpid: u16,
    /// The subscriber's MRU.
    pub mtu: u16,
    pub client_mac: [u8; 6],
    pub server_mac: [u8; 6],
    pub ipv4: Option<Ipv4Addr>,
    /// Subscriber → network (rx of the router).
    pub up: Rate,
    /// Network → subscriber.
    pub down: Rate,
    /// Upstream may be forwarded in XDP (nothing in `forward` needs it).
    pub fast_up: bool,
    pub fast_down: bool,
}

/// What the data plane counted for a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PppoeCounters {
    pub up_packets: u64,
    pub up_bytes: u64,
    pub down_packets: u64,
    pub down_bytes: u64,
    pub up_policed: u64,
    pub down_policed: u64,
    pub spoofed: u64,
    pub to_kernel: u64,
}

/// One change of the session maps (applied in order, in one call).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PppoeOp {
    Upsert(u32, PppoeSession),
    Remove(u32),
}
