//! What the kernel says about a configured address (G1.28): IPv6 duplicate
//! address detection (RFC 4862 §5.4: an address is *tentative* until DAD
//! ends, and unusable if a duplicate answered) and the lifetimes it holds.
//! `ip.address.list` turns it into the `state` column.

use corerouter_model::IfName;
use ipnet::IpNet;

/// One address on one interface, as the data plane holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressState {
    pub interface: IfName,
    pub address: IpNet,
    /// DAD still running (RFC 4862 §5.4): not used as a source yet.
    pub tentative: bool,
    /// DAD found a duplicate (RFC 4862 §5.4.5): the kernel will not use it.
    pub dad_failed: bool,
    /// Its preferred lifetime ran out (RFC 4862 §5.5.4): kept for the
    /// connections it has, not used for new ones.
    pub deprecated: bool,
    /// Seconds left; `None`: forever.
    pub valid_secs: Option<u32>,
    pub preferred_secs: Option<u32>,
}
