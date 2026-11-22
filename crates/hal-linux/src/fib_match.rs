//! G3.4z: which FIB entry the replies to a management session take, and
//! who installed it (`RTM_GETROUTE` with `RTM_F_FIB_MATCH`). Read by the
//! daemon's `mgmt-guard` service, outside the session lock.

use std::net::IpAddr;

use corerouter_hal::HalError;
use corerouter_hal::route_get::FibEntry;
use corerouter_model::IfName;

/// The entry for each `(peer, our address)` in the main table, in order:
/// one netlink connection for the batch, one request per pair.
pub fn lookup(
    pairs: &[(IpAddr, Option<IpAddr>)],
) -> Result<Vec<Result<FibEntry, String>>, HalError> {
    let asks: Vec<_> = pairs.iter().map(|(d, s)| (*d, *s, None)).collect();
    crate::netlink::fib_entries(&asks)
}

/// G3.4za: [`lookup`] with a VRF per pair: the VRF device is the output
/// device of the request (`ip route get <peer> from <local> vrf <name>`), so
/// the `l3mdev` rule takes the lookup to the VRF's table, as for the
/// replies of a socket bound to that VRF. A VRF the kernel does not have is
/// that pair's error.
pub fn lookup_in(
    asks: &[(IpAddr, Option<IpAddr>, Option<IfName>)],
) -> Result<Vec<Result<FibEntry, String>>, HalError> {
    crate::netlink::fib_entries(asks)
}
