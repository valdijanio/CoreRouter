//! English explanations of the CGNAT window (G2.3d), sorted by key.

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "cgnat.alert_percent",
        "## Alert %

A subscriber using this share of its ports raises an alert (one per crossing). Default 90 %, 0 off.",
    ),
    (
        "cgnat.alerts",
        "## Alerts

Subscribers near their port limit, with peak and count.",
    ),
    (
        "cgnat.block_timeout",
        "## Block Timeout

An idle block is released after this; then held 120 s (RFC 6888 REQ-8). Default 2 min.",
    ),
    (
        "cgnat.blocks",
        "## Blocks

Port blocks in use and the block log.",
    ),
    (
        "cgnat.comment",
        "## Comment

Free text.",
    ),
    (
        "cgnat.disabled",
        "## Disabled

Kept in the config, out of the kernel.",
    ),
    (
        "cgnat.endpoint_independent_filtering",
        "## Endpoint-Independent Filtering

Any host may reach a live UDP mapping (RFC 4787 REQ-8). Off by default; needs EIM.",
    ),
    (
        "cgnat.endpoint_independent_mapping",
        "## Endpoint-Independent Mapping

The same public port for every destination of one UDP source (RFC 4787 REQ-1). On by default.",
    ),
    (
        "cgnat.exception",
        "## Exceptions (1:1)

A subscriber with a public address of its own; its pool slot stays reserved, so nobody is remapped.",
    ),
    (
        "cgnat.exception.comment",
        "## Comment

Who it is.",
    ),
    (
        "cgnat.exception.public",
        "## Public

Its own public address, outside every pool.",
    ),
    (
        "cgnat.exception.subscriber",
        "## Subscriber

The subscriber's inside address.",
    ),
    (
        "cgnat.hairpin",
        "## Hairpin

Subscribers reach each other through their public address and port (RFC 4787 REQ-9).",
    ),
    (
        "cgnat.history_days",
        "## History kept

Days the mapping history and block log are kept (Marco Civil asks a year).",
    ),
    (
        "cgnat.inside",
        "## Inside

Subscriber ranges, in formula order. Default space: 100.64.0.0/10 (RFC 6598). Adding at the end remaps nobody.",
    ),
    (
        "cgnat.mapping",
        "## Mapping

Subscriber – public address and ports, 500 per page.",
    ),
    (
        "cgnat.max_blocks",
        "## Max Blocks

Blocks one subscriber may hold at once (a new one at 80 % use). Default 4.",
    ),
    (
        "cgnat.mode",
        "## Mode

- **deterministic** (default, RFC 7422): each subscriber gets a fixed public address and port range by formula; nothing is logged.
- **blocks** (PBA, RFC 6888 §5): blocks handed out on demand, one log line each.",
    ),
    (
        "cgnat.name",
        "## Name

The pool's name, unique.",
    ),
    (
        "cgnat.out_interface",
        "## Out. Interface

Translate only traffic leaving here (empty: any).",
    ),
    (
        "cgnat.outside",
        "## Outside

The public addresses, routed to the router. The check says how many are missing.",
    ),
    (
        "cgnat.port_range",
        "## Port Range

Ports handed out on each public address, 1024-65535 by default (RFC 4787 REQ-3).",
    ),
    (
        "cgnat.ports_per_subscriber",
        "## Ports per Subscriber

Ports of each subscriber (or block). 1000 by default; below ~300 a browser runs out. RFC 6888 REQ-4.",
    ),
    (
        "cgnat.who.port",
        "## Port

The source port at that time: without it a CGNAT address points to many subscribers.",
    ),
    (
        "cgnat.who.public",
        "## Public Address

The public address in the request.",
    ),
    (
        "cgnat.who.time",
        "## Date and Time

Unix or RFC 3339 with the offset (Brazil: -03:00); without it, UTC.",
    ),
];
