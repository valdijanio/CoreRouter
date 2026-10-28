//! English explanations of IP › Routes' check-gateway (G1.27f), sorted by key.

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "routes.bfd_profile",
        "## BFD Profile

The BFD profile of the session to the gateway (Routing › BFD › Profiles): its intervals and multiplier give the detect time (`default`: 300 ms × 3 = 900 ms; `fast`: 50 ms × 3 = 150 ms). Empty is `default`.

The gateway must run BFD too (RFC 5880, single hop RFC 5881). A session that has not come up 5 s after the route asked for it counts as down.",
    ),
    (
        "routes.check_gateway",
        "## Check Gateway

Whether the route's gateway is alive, as RouterOS `check-gateway`:

- `none`: not checked; the route stays while its interface is up.
- `ping`: an ICMP echo every 10 s; 2 unanswered in a row and the gateway is down.
- `arp`: an ARP request every 10 s (IPv4 gateways on a link): sees a gateway that drops ping.
- `bfd`: a BFD session to the gateway; down in the profile's detect time (under a second).

While the gateway is down the route leaves the kernel and the route with the next distance takes over; at the first answer it comes back. A gateway that falls again within 15 minutes is held down for 10 s, then 20 s, 40 s… up to 5 min of answers before its routes return, so a flapping link does not move the traffic back and forth.

Routes through the same gateway share one check: a thousand routes, one probe.

**Status**: `checking` (no answer yet), `reachable`, `unreachable`, `not-checked` (no daemon runs the checks).",
    ),
];
