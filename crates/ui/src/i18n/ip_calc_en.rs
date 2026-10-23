//! English explanations of Tools › IP Calculator (G6.9), sorted by key.

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "ipcalc.address",
        "## Address

An address with a prefix, a mask or IPv6. Shows network, broadcast, hosts (/31 has 2, RFC 3021), mask, wildcard, scope and overlaps with the configuration.",
    ),
    (
        "ipcalc.inside",
        "## Subscribers

A count (from 100.64.0.0) or the inside ranges. Same formula as the pools (RFC 7422).",
    ),
    (
        "ipcalc.outside",
        "## Public addresses

A count (from 203.0.113.0) or the public ranges. The planner says how many are missing.",
    ),
    (
        "ipcalc.pd_length",
        "## Delegate

The prefix each customer gets by DHCPv6-PD: /56 for homes, /48 for businesses (RFC 6177).",
    ),
    (
        "ipcalc.pd_prefix",
        "## Prefix

The IPv6 block to delegate from: how many delegations fit, and the DHCPv6-PD pools inside it.",
    ),
    (
        "ipcalc.range",
        "## Range to prefixes

The fewest prefixes covering exactly first – last.",
    ),
    (
        "ipcalc.split",
        "## Split

Splits the Address network into a prefix (`/26`) or a count of subnets (rounded up to a power of 2).",
    ),
    (
        "ipcalc.summarize",
        "## Summarize

Aggregates the prefixes and shows the supernet, with the addresses it adds.",
    ),
];
