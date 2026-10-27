//! English explanations of IP › Firewall's tabs (G2.1c), sorted by key.

pub(super) const HELP: &[(&str, &str)] = &[
    (
        "firewall.col.bytes",
        "## Bytes\n\nBytes the rule matched, read from the kernel's `counter` while this window is open (every 2 s). Not saved: they restart with the router; a commit does not reset them.",
    ),
    (
        "firewall.col.last-used",
        "## Last Used\n\nHow long since the rule last matched a packet. `— (3 d)`: not once since the counters started being read. An amber **stale** chip: unused for 30 days — maybe a rule nobody needs any more (check before removing: some rules wait for rare events).",
    ),
    (
        "firewall.col.packets",
        "## Packets\n\nPackets the rule matched (RouterOS `packets`), live from the kernel, one netlink read of the whole table every 2 s while the window is open. **Reset Counters** zeroes what is shown (the selected rules, or all).",
    ),
    (
        "firewall.col.rate",
        "## Rate\n\nPackets per second over the last read interval (2 s).",
    ),
    (
        "firewall.tab.address-list",
        "## Address Lists\n\nNamed sets of addresses that rules match (`src-address-list=blocked`). Entries with a timeout are dynamic: not saved, they expire by themselves.",
    ),
    (
        "firewall.tab.connections",
        "## Connections\n\nThe connection-tracking table (conntrack): what the firewall knows about each flow, its NAT and its timeouts.",
    ),
    (
        "firewall.tab.diff",
        "## Diff\n\nThe nftables table `inet corerouter` as the next **commit** would load it, against what the kernel holds now: `+` lines go in, `-` lines go out. Next to it, the pending config changes (`config.diff`). In immediate mode there is nothing pending: the diff is empty.",
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
        "firewall.tab.test",
        "## Test\n\n**Packet tester**: describe a packet and see its way through raw, mangle, NAT, the routing decision and filter, chain by chain, and the rule that decides. Nothing is sent. Assumptions: no marks, limits not exceeded, address lists with the router's entries only.\n\n**Trace real packets**: marks the real packets that match a filter (`meta nftrace`, at most 20/s) for a limited time and shows the way each one took in the kernel. Like Junos `packet-trace`; RouterOS has no equivalent.",
    ),
    (
        "firewall.tab.zones",
        "## Zones\n\nThe simple mode: a matrix of which zone (interface list or the router) may open connections to which. It writes a block of filter rules.",
    ),
    (
        "firewall.test.dst",
        "## Dst. Address\n\nThe packet's destination address (a router address: chain input).",
    ),
    (
        "firewall.test.dst_port",
        "## Dst. Port\n\nDestination port (default 80).",
    ),
    (
        "firewall.test.in_interface",
        "## In. Interface\n\nWhere it comes in. Empty: the router itself sends it (chain output).",
    ),
    (
        "firewall.test.protocol",
        "## Protocol\n\ntcp, udp, icmp, icmpv6 or a number (default tcp).",
    ),
    (
        "firewall.test.src",
        "## Src. Address\n\nThe packet's source address.",
    ),
    (
        "firewall.test.src_port",
        "## Src. Port\n\nSource port (default 40000).",
    ),
    (
        "firewall.test.state",
        "## State\n\nConnection state as conntrack sees it (default new). NAT chains only see `new`.",
    ),
    (
        "firewall.trace.dst",
        "## Dst. Address\n\nTrace packets to this address or prefix.",
    ),
    (
        "firewall.trace.duration",
        "## Duration\n\nSeconds, 1 to 300 (default 60). The trace ends by itself.",
    ),
    (
        "firewall.trace.in_interface",
        "## In. Interface\n\nOnly packets arriving here (then packets the router sends are not traced).",
    ),
    (
        "firewall.trace.max_events",
        "## Max Events\n\nStops after this many kernel events (default 1000, at most 10000). Each packet gives one event per rule it meets.",
    ),
    (
        "firewall.trace.port",
        "## Dst. Port\n\nOnly this destination port (needs tcp, udp, sctp or udp-lite).",
    ),
    (
        "firewall.trace.protocol",
        "## Protocol\n\nOnly this protocol.",
    ),
    (
        "firewall.trace.src",
        "## Src. Address\n\nTrace packets from this address or prefix.",
    ),
];
