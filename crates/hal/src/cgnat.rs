//! CGNAT port blocks in the data plane (G2.3c): what the engine's block
//! allocator tells the kernel, and how a subscriber without a block asks
//! for one.
//!
//! In blocks mode (RFC 6888 §5) a pool's map `d_<id>` holds only the
//! subscribers that have a block. The first packet of a subscriber without
//! one is held in a netfilter queue ([`QUEUE_NUM`]) until the daemon
//! allocates a block and puts it in the map ([`CgnatQueue`]); then it goes
//! on and the NAT finds the element. The lab has no queue: it names the
//! subscribers it pretends are online ([`Hal::cgnat_waiting`]).
//!
//! [`Hal::cgnat_waiting`]: crate::Hal::cgnat_waiting

use std::net::Ipv4Addr;
use std::time::Duration;

use corerouter_model::ItemId;
use corerouter_model::cgnat::Slot;

use crate::HalError;

/// The netfilter queue of first packets (RFC 7422, as a number to
/// remember). Each blocks-mode pool's rule sends there.
pub const QUEUE_NUM: u16 = corerouter_firewall::cgnat::QUEUE_NUM;

/// One subscriber's block in pool `pool`: set (`Some`) or removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockChange {
    pub pool: ItemId,
    pub subscriber: Ipv4Addr,
    pub slot: Option<Slot>,
}

/// A subscriber waiting for a block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Waiting {
    pub pool: ItemId,
    pub subscriber: Ipv4Addr,
}

/// A packet held in the queue: its id (for the verdict) and its source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pending {
    pub id: u32,
    pub subscriber: Ipv4Addr,
}

/// The queue of first packets, served by a thread of the daemon outside
/// the session lock.
pub trait CgnatQueue: Send {
    /// The next held packet, waiting at most `wait`.
    fn recv(&mut self, wait: Duration) -> Result<Option<Pending>, HalError>;

    /// Let packet `id` go on (`accept`) or drop it (no block left: RFC 6888
    /// REQ-11).
    fn verdict(&mut self, id: u32, accept: bool) -> Result<(), HalError>;
}
