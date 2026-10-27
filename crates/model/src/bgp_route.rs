//! BGP routes read from the routing daemons for the policy preview
//! (G3.2b): what a neighbor sent (before the input chain) or what this
//! router would send (its best routes, before the output chain). Running
//! state, never configuration.

use ipnet::IpNet;

/// One route with the attributes a `/routing filter` chain looks at.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BgpRouteEntry {
    pub prefix: Option<IpNet>,
    /// AS_PATH, the neighbor first (AS_SETs flattened).
    pub as_path: Vec<u32>,
    /// RFC 1997 communities, as 32-bit values.
    pub communities: Vec<u32>,
    /// RFC 8092 large communities.
    pub large: Vec<(u32, u32, u32)>,
    pub med: Option<u32>,
    pub local_pref: Option<u32>,
    /// The communities are not known (FRR 10 shows them only for the
    /// received routes the input chain accepted).
    pub partial: bool,
}
