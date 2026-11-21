//! G3.4z: which FIB entry the replies to a management session take, and
//! who installed it (`RTM_GETROUTE` with `RTM_F_FIB_MATCH`). Read by the
//! daemon's `mgmt-guard` service, outside the session lock.

use std::net::IpAddr;

use corerouter_hal::HalError;
use corerouter_hal::route_get::FibEntry;

/// The entry for each `(peer, our address)`, in order: one netlink
/// connection for the batch, one request per pair.
pub fn lookup(
    pairs: &[(IpAddr, Option<IpAddr>)],
) -> Result<Vec<Result<FibEntry, String>>, HalError> {
    crate::netlink::fib_entries(pairs)
}
