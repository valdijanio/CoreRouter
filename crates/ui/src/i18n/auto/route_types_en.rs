//! English explanation of IP › Routes' route type (G1.5a).

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[(
    "routes.type",
    "## Type

What the route does with a packet, as RouterOS v6 `type` (v7: `blackhole`):

- `unicast`: on through the **Gateway** (the usual).
- `blackhole`: dropped silently. To null a pool, a CGNAT aggregate or the prefix BGP announces (at distance 254 it only counts when the real path goes).
- `unreachable`: dropped, and the sender gets ICMP \"network unreachable\" (Junos `reject`).
- `prohibit`: dropped, and the sender gets ICMP \"administratively prohibited\".

A route without gateway has nothing to check (no Check Gateway) and cannot share its distance with a route of another type to the same destination: the kernel holds one route per prefix, distance and table. A more specific route still wins (the longest prefix). With `redistribute static` in BGP or OSPF it is announced like the other static routes.",
)];
