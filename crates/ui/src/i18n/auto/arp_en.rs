//! English explanations of IP › ARP (G1.27d), sorted by key.

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "arp.address",
        "## Address

The neighbor's IP address. The search takes an exact IP, a CIDR network (`10.0.0.0/24`), a MAC prefix (`00:50:56`) or text (interface, state, comment).",
    ),
    (
        "arp.detail",
        "## Selected neighbor

The address's MAC history (a MAC that comes and goes means a duplicate IP or ARP spoofing), the routes through this neighbor and the router's address on that network. Actions: Make Static, Add to Address List, ARP Ping, Ping and Torch.",
    ),
    (
        "arp.disabled",
        "## Disabled

The entry stays in the config but leaves the kernel.",
    ),
    (
        "arp.entries",
        "## Entries

IPv4 neighbors of the interface in the kernel table now, any state.",
    ),
    (
        "arp.flush",
        "## Flush

Forgets the **learned** entries (not the static ones). Never the gateway of an active route nor the neighbor your management session comes through; the answer lists them and why.",
    ),
    (
        "arp.gc_thresh",
        "## gc_thresh1/2/3

The kernel neighbor table's size (RouterOS `max-neighbor-entries`): gc_thresh3 is the ceiling. Linux default 128/512/1024. The log warns past 80 % with suggested values (RFC 6583). Changed in System › Tuning.",
    ),
    (
        "arp.interface",
        "## Interface

The port the neighbor is on; the chip colour comes from its name.",
    ),
    (
        "arp.last_seen",
        "## Last Seen

Time since the neighbor was last confirmed reachable.",
    ),
    (
        "arp.mac_address",
        "## MAC Address

The link-layer address that answered for this IP; empty while incomplete or failed. A changed MAC is logged (topic `arp`).",
    ),
    (
        "arp.mode",
        "## ARP mode

As RouterOS: enabled (default), disabled, reply-only (answers, learns nothing: only static entries reach hosts), proxy-arp (RFC 1027), local-proxy-arp. The risky ones ask to confirm; cutting your management session is refused.",
    ),
    (
        "arp.published",
        "## Published

The router answers ARP for this address with its own MAC when it routes it elsewhere: proxy ARP for one host. Default no.",
    ),
    (
        "arp.source",
        "## Source

dynamic (learned), static (yours; permanent) or **dhcp** (a DHCP server with `add_arp` put it: goes with the lease). published: a static entry the router answers for.",
    ),
    (
        "arp.state",
        "## State

RFC 4861 §7.3.2: reachable, stale, delay, probe, incomplete, failed, plus permanent (static) and noarp. The chips count the whole table; a click filters.",
    ),
    (
        "arp.static",
        "## Static ARP entry

A fixed IP → MAC pair on an interface (`/ip arp add`), permanent in the kernel. A wrong MAC cuts the host off: the modal warns when the host answers with another MAC now.",
    ),
    (
        "arp.static_count",
        "## Static

Static entries of the interface.",
    ),
    (
        "arp.tab.arp",
        "## ARP (IPv4)

The ARP table (RFC 826) with the static entries.",
    ),
    (
        "arp.tab.nd",
        "## ND (IPv6)

The IPv6 neighbor table (RFC 4861); router marks the R flag.",
    ),
    (
        "arp.tab.settings",
        "## Settings

Each interface's ARP mode and timeout, and the kernel table's size.",
    ),
    (
        "arp.timeout",
        "## ARP Timeout

How long a learned entry stays reachable without confirmation (`base_reachable_time`). Default auto: 30 s (RFC 4861 §10).",
    ),
    (
        "arp.unresolved",
        "## Unresolved

Neighbors of the interface incomplete or failed: nobody answered.",
    ),
    (
        "arp.vendor",
        "## Vendor

The card's maker from the MAC's first three bytes (IEEE OUI). Built in; Settings › Update vendors downloads a newer one.",
    ),
    (
        "arp.vendors",
        "## Vendors\n\nThe table naming the maker from a MAC's first three bytes: the IEEE MA-L public listing. One is built in (with its date); Update vendors downloads the current one, which wins and survives a restart. Source and terms: `docs/third-party.md`.",
    ),
];
