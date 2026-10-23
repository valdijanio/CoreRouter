//! English explanations of IP › Fast Path (G2.4), sorted by key.

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "fastpath.counters",
        "## Counters

Flowtable counters (kernel 5.7+): offloaded bytes still count on the connection. Default on.",
    ),
    (
        "fastpath.enabled",
        "## Enabled

Accepted, established TCP and UDP connections skip the forward rules, NAT included (RouterOS FastTrack). The chain runs after the firewall, so a drop rule always wins. Default off.",
    ),
    (
        "fastpath.fix",
        "## Fix

What to run for hardware offload: devlink switchdev (as root; the card restarts) or the hw-tc-offload setting.",
    ),
    (
        "fastpath.hw_offload",
        "## HW Offload

auto (default): ask the card, fall back to software. yes: refuse when refused. no: software. Needs mlx5 in switchdev mode with hw-tc-offload on.",
    ),
    (
        "fastpath.interfaces",
        "## Interfaces

The flowtable's ports; empty: every Ethernet and bond port. Name the port of a VLAN, not the VLAN.",
    ),
    (
        "fastpath.ports",
        "## Ports

Per port: hardware, software or off; the card; the eSwitch mode; why not hardware.",
    ),
    (
        "fastpath.window",
        "## Fast Path

The Linux flowtable: the fast path of accepted connections, in software or on the card.",
    ),
];
