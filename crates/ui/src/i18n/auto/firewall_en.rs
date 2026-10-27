//! English explanations of IP › Firewall's tabs (G2.1c), sorted by key.

pub(super) const HELP: &[(&str, &str)] = &[
    (
        "firewall.tab.address-list",
        "## Address Lists\n\nNamed sets of addresses that rules match (`src-address-list=blocked`). Entries with a timeout are dynamic: not saved, they expire by themselves.",
    ),
    (
        "firewall.tab.connections",
        "## Connections\n\nThe connection-tracking table (conntrack): what the firewall knows about each flow, its NAT and its timeouts.",
    ),
    (
        "firewall.tab.filter",
        "## Filter Rules\n\nWhat may pass: chain `input` (to the router), `forward` (through it) and `output` (from it). The first rule that decides wins; nothing decides = accept.",
    ),
    (
        "firewall.tab.mangle",
        "## Mangle\n\nMarks connections, packets and routing (policy routing, queues). It decides nothing by itself unless `passthrough=no`.",
    ),
    (
        "firewall.tab.nat",
        "## NAT\n\n`srcnat` changes the source (masquerade to the internet), `dstnat` the destination (port forwarding).",
    ),
    (
        "firewall.tab.raw",
        "## Raw\n\nRules that run **before connection tracking**, chains `prerouting` (everything that arrives) and `output` (what the router sends). Actions: `accept`, `drop`, `notrack`, `jump`, `return`, `log`, `passthrough` and the address-list ones.\n\n- **drop** here costs less than in filter: the packet never becomes a connection, so a flood with spoofed sources does not fill the conntrack table.\n- **notrack**: the packet skips conntrack; filter then sees it as `connection-state=untracked` (accept `untracked` there, or it falls to your drop rules). Useful for high-rate stateless traffic (DNS of a resolver, BGP of a route server).\n\n**Careful:** no `connection-state`, `connection-mark`, `connection-nat-state` or `routing-mark` (nothing about the connection exists yet). A `notrack` in `output` breaks the router's own connections (their replies arrive untracked). NAT does not apply to untracked packets.\n\nTemplate: **Drop Bogons Before Conntrack**. Same as RouterOS `/ip firewall raw`; nftables priority `raw` (-300).",
    ),
    (
        "firewall.tab.zones",
        "## Zones\n\nThe simple mode: a matrix of which zone (interface list or the router) may open connections to which. It writes a block of filter rules.",
    ),
];
