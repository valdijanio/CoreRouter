//! English explanations of System › Tuning (G1.26), sorted by key.

/// Explanations by key (`tuning.<parameter>`, `tuning.<topic>`).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "tuning.kernel.panic",
        r##"## What it does
Seconds after a kernel panic before the machine reboots by itself; 0 waits forever on the panic screen.
## When to change
A router should come back on its own: 10 s leaves time to read the panic on a console.
## Careful
With 0, a remote router stays down until someone reaches it."##,
    ),
    (
        "tuning.kernel.panic_on_oops",
        r##"## What it does
Turns a kernel oops (a bug the kernel survived, maybe half broken) into a panic, so `kernel.panic` reboots the box.
## When to change
On a router a clean reboot is better than forwarding with a damaged kernel.
## Careful
A driver that oopses on start makes a reboot loop; the A/B image falls back to the previous one."##,
    ),
    (
        "tuning.net.core.dev_weight",
        r##"## What it does
Packets the backlog of one CPU (RPS, non-NAPI drivers) may process per turn inside a softirq round. NAPI drivers use their own weight (64).
## When to change
Rarely: only with RPS on single-queue ports and `time_squeeze` that the budget did not solve.
## Careful
It does not change the NIC queues of NAPI drivers; most routers never touch it."##,
    ),
    (
        "tuning.net.core.netdev_budget",
        r##"## What it does
How many packets one round of the receive softirq handles, across all the queues of a CPU, before it yields.
## When to raise
When `time_squeeze` grows (Summary tab): the round ends with work left and the rest waits for the next one. 600 is a common value for a router; 1000+ for 10/40 Gb/s ports.
## Careful
A longer round delays everything else on that CPU (user space, the routing daemon). Raise it together with `netdev_budget_usecs`."##,
    ),
    (
        "tuning.net.core.netdev_budget_usecs",
        r##"## What it does
The time limit of one receive softirq round, in microseconds: the round ends at the budget or at this time, whichever comes first.
## When to raise
Together with `netdev_budget`, when `time_squeeze` grows. The kernel's default depends on HZ (2000 µs with HZ=1000, 8000 µs with HZ=250).
## Careful
The low-latency profile keeps it short on purpose: a long round makes other work on the CPU wait."##,
    ),
    (
        "tuning.net.core.netdev_max_backlog",
        r##"## What it does
Packets each CPU may hold waiting for the receive softirq when they arrive faster than it drains them (RPS, veth, tunnels and drivers without NAPI queue here).
## When to raise
When `softnet_stat` counts drops (the Summary tab says so) or the ports are 10 Gb/s and up: a burst waits instead of being dropped.
## Careful
A huge backlog only hides a CPU that cannot keep up and adds delay (bufferbloat). Raise the budget first."##,
    ),
    (
        "tuning.net.core.rmem_max",
        r##"## What it does
The largest receive buffer a socket of the router itself may ask for. **Control plane only**: forwarded packets never touch socket buffers.
## When to raise
BGP with full tables and route reflectors: the daemon asks for big buffers so a burst of updates does not stall the session.
## Careful
It is a ceiling, not a default: memory is used only by sockets that ask."##,
    ),
    (
        "tuning.net.core.somaxconn",
        r##"## What it does
The longest queue of connections waiting for a service of the router (API, BGP, web) to accept them. **Control plane only.**
## When to change
Rarely: 4096 is the kernel's default since 5.4.
## Careful
It does not affect forwarded traffic."##,
    ),
    (
        "tuning.net.core.wmem_max",
        r##"## What it does
The largest send buffer a socket of the router itself may ask for. **Control plane only**: forwarded packets never touch socket buffers.
## When to raise
BGP with full tables and route reflectors: the daemon asks for big buffers so a burst of updates does not stall the session.
## Careful
It is a ceiling, not a default: memory is used only by sockets that ask."##,
    ),
    (
        "tuning.net.ipv4.conf.all.rp_filter",
        r##"## What it does
Reverse path filter: checks the source address of each packet against the routing table. Strict (1) drops it unless the route back leaves by the same interface; loose (2) only unless there is any route back. The kernel uses the larger of `all` and the interface's own value.
## When to change
Loose is the safe choice for an ISP router: it drops bogus sources and keeps asymmetric routing (two uplinks, BGP multihoming) working. Off saves a route lookup per packet when anti-spoofing is done in the firewall.
## Careful
Strict breaks asymmetric routing silently: replies come in by another uplink and are dropped. MikroTik's default is off."##,
    ),
    (
        "tuning.net.ipv4.conf.default.rp_filter",
        r##"## What it does
The reverse path filter an interface gets when it is created (a new VLAN, bond or tunnel). The kernel uses the larger of `all` and the interface's own value, so turning `all` off does nothing on an interface created with strict.
## When to change
Together with `net.ipv4.conf.all.rp_filter`, to the same value.
## Careful
Interfaces that exist already keep their own value (per-interface settings: G1.26b)."##,
    ),
    (
        "tuning.net.ipv4.fib_multipath_hash_policy",
        r##"## What it does
How IPv4 traffic is spread over equal-cost routes (ECMP): layer 3 hashes only the addresses, layer 4 adds protocol and ports, layer 3 inner looks inside tunnels.
## When to change
Layer 4 spreads many flows between the same two hosts (a CGNAT pool talking to a CDN) over all the paths; layer 3 sends them all down one.
## Careful
A packet of one flow always takes the same path either way; only fragments may differ with layer 4."##,
    ),
    (
        "tuning.net.ipv4.ip_forward",
        r##"## What it does
Whether the kernel forwards IPv4 packets between interfaces. A router needs it on; off, the box only answers for itself.
## When to change
Never on a router. Off is for a host.
## Careful
Turning it off stops all IPv4 routing at once. Turning it on also turns off LRO on every port (the kernel does it)."##,
    ),
    (
        "tuning.net.ipv4.neigh.default.gc_thresh1",
        r##"## What it does
Below this many IPv4 (ARP) neighbor entries the garbage collector leaves the table alone.
## When to raise
With many hosts on the LANs (a /22 of subscribers, a big VLAN): when the table fills, new neighbors are refused ("neighbour table overflow") and hosts lose connectivity. The Summary tab counts overflows.
## Careful
Keep gc_thresh1 ≤ gc_thresh2 ≤ gc_thresh3; each entry costs a few hundred bytes. MikroTik calls the limit `max-neighbor-entries`."##,
    ),
    (
        "tuning.net.ipv4.neigh.default.gc_thresh2",
        r##"## What it does
Above this many IPv4 (ARP) entries the collector removes stale ones within 5 seconds.
## When to raise
With many hosts on the LANs (a /22 of subscribers, a big VLAN): when the table fills, new neighbors are refused ("neighbour table overflow") and hosts lose connectivity. The Summary tab counts overflows.
## Careful
Keep gc_thresh1 ≤ gc_thresh2 ≤ gc_thresh3; each entry costs a few hundred bytes. MikroTik calls the limit `max-neighbor-entries`."##,
    ),
    (
        "tuning.net.ipv4.neigh.default.gc_thresh3",
        r##"## What it does
The most IPv4 (ARP) neighbor entries the table holds: the hard limit.
## When to raise
With many hosts on the LANs (a /22 of subscribers, a big VLAN): when the table fills, new neighbors are refused ("neighbour table overflow") and hosts lose connectivity. The Summary tab counts overflows.
## Careful
Keep gc_thresh1 ≤ gc_thresh2 ≤ gc_thresh3; each entry costs a few hundred bytes. MikroTik calls the limit `max-neighbor-entries`."##,
    ),
    (
        "tuning.net.ipv4.route.max_size",
        r##"## What it does
Nothing since Linux 3.6: the IPv4 route cache it limited is gone. Kept by the kernel for old scripts.
## When to change
Never: a full BGP table needs no change here.
## Careful
Guides that still raise it are from before 2012."##,
    ),
    (
        "tuning.net.ipv4.tcp_max_syn_backlog",
        r##"## What it does
Half-open connections to the router's own services the kernel remembers. **Control plane only.**
## When to change
Raise it when the router's API or BGP port is under SYN load and cookies are off.
## Careful
It does not affect forwarded traffic."##,
    ),
    (
        "tuning.net.ipv4.tcp_syncookies",
        r##"## What it does
Answers a SYN flood against the router's own services with cookies instead of queue entries. **Control plane only**: a flood passing through is the firewall's business.
## When to change
Keep "when needed" (1): cookies start only when the queue is full.
## Careful
"Always" (2) disables some TCP options for every connection to the router."##,
    ),
    (
        "tuning.net.ipv6.conf.all.forwarding",
        r##"## What it does
Whether the kernel forwards IPv6 packets. On, the interfaces also stop accepting Router Advertisements unless `accept_ra` is 2 (CoreRouter sets that where a DHCPv6 client needs it).
## When to change
Never on a router that routes IPv6.
## Careful
Off stops IPv6 routing at once."##,
    ),
    (
        "tuning.net.ipv6.fib_multipath_hash_policy",
        r##"## What it does
The same as the IPv4 setting, for IPv6 equal-cost routes: layer 3 (addresses and flow label), layer 4 (adds ports), layer 3 inner.
## When to change
Layer 4 when several paths carry traffic between few hosts.
## Careful
Keep IPv4 and IPv6 alike, or the two families load the links differently."##,
    ),
    (
        "tuning.net.ipv6.neigh.default.gc_thresh1",
        r##"## What it does
Below this many IPv6 (NDP) neighbor entries the garbage collector leaves the table alone.
## When to raise
With many hosts on the LANs (a /22 of subscribers, a big VLAN): when the table fills, new neighbors are refused ("neighbour table overflow") and hosts lose connectivity. The Summary tab counts overflows.
## Careful
Keep gc_thresh1 ≤ gc_thresh2 ≤ gc_thresh3; each entry costs a few hundred bytes. MikroTik calls the limit `max-neighbor-entries`."##,
    ),
    (
        "tuning.net.ipv6.neigh.default.gc_thresh2",
        r##"## What it does
Above this many IPv6 (NDP) entries the collector removes stale ones within 5 seconds.
## When to raise
With many hosts on the LANs (a /22 of subscribers, a big VLAN): when the table fills, new neighbors are refused ("neighbour table overflow") and hosts lose connectivity. The Summary tab counts overflows.
## Careful
Keep gc_thresh1 ≤ gc_thresh2 ≤ gc_thresh3; each entry costs a few hundred bytes. MikroTik calls the limit `max-neighbor-entries`."##,
    ),
    (
        "tuning.net.ipv6.neigh.default.gc_thresh3",
        r##"## What it does
The most IPv6 (NDP) neighbor entries the table holds: the hard limit.
## When to raise
With many hosts on the LANs (a /22 of subscribers, a big VLAN): when the table fills, new neighbors are refused ("neighbour table overflow") and hosts lose connectivity. The Summary tab counts overflows.
## Careful
Keep gc_thresh1 ≤ gc_thresh2 ≤ gc_thresh3; each entry costs a few hundred bytes. MikroTik calls the limit `max-neighbor-entries`."##,
    ),
    (
        "tuning.net.ipv6.route.max_size",
        r##"## What it does
Before Linux 6.3, the most IPv6 routes the kernel accepted (default 4096): a full IPv6 table (200 000+ routes) failed to install. Since 6.3 it is no longer a limit.
## When to raise
On a kernel before 6.3 that takes a full IPv6 table: 1048576 leaves room.
## Careful
Since Linux 6.3 changing it does nothing."##,
    ),
    (
        "tuning.net.netfilter.nf_conntrack_buckets",
        r##"## What it does
Size of the conntrack hash table. Each lookup walks one bucket's chain: with `nf_conntrack_max` four times the buckets, chains average four entries.
## When to raise
Together with `nf_conntrack_max`; the kernel sizes it from the RAM at boot and does not follow later changes of the maximum.
## Careful
Changing it rebuilds the table while traffic flows (a short CPU spike). Only the host's first network namespace can change it."##,
    ),
    (
        "tuning.net.netfilter.nf_conntrack_generic_timeout",
        r##"## What it does
Seconds a flow of another protocol (GRE, ESP, SCTP without its module) stays.
## When to change
Shorter on CGNAT; longer only for idle tunnels without keepalive.
## Careful
Too short breaks IPsec and GRE tunnels that go quiet."##,
    ),
    (
        "tuning.net.netfilter.nf_conntrack_icmp_timeout",
        r##"## What it does
Seconds an ICMP query (ping) stays in the table.
## When to change
RFC 5508 REQ-1 asks NATs to keep it at least 60 s; the kernel's 30 s is below.
## Careful
Each ping through CGNAT holds an identifier: very long timeouts exhaust them on busy pools."##,
    ),
    (
        "tuning.net.netfilter.nf_conntrack_max",
        r##"## What it does
The most connections the connection tracker holds: NAT, CGNAT and every stateful firewall rule need one entry per flow. A full table drops new connections ("table full, dropping packet" in the kernel log).
## When to raise
On CGNAT and busy NAT: each subscriber keeps hundreds of flows. The Summary tab warns at 80 % full.
## Careful
Each entry costs ~320 B of RAM that the kernel cannot give back: 4 million entries are ~1.3 GiB. The limit here is a quarter of the RAM."##,
    ),
    (
        "tuning.net.netfilter.nf_conntrack_tcp_timeout_close_wait",
        r##"## What it does
Seconds a TCP connection stays after the other side closed.
## When to change
Rarely.
## Careful
Like `fin_wait`."##,
    ),
    (
        "tuning.net.netfilter.nf_conntrack_tcp_timeout_established",
        r##"## What it does
Seconds an established TCP connection stays in the table with no packet. The kernel's default is 5 days.
## When to change
Shorter on CGNAT: a client that vanished leaves its entry (and its public port) for days. MikroTik uses 1 day.
## Careful
RFC 5382 REQ-5: never less than 2 h 4 min (7440 s), or idle SSH and database sessions break."##,
    ),
    (
        "tuning.net.netfilter.nf_conntrack_tcp_timeout_fin_wait",
        r##"## What it does
Seconds a closing TCP connection stays after the first FIN.
## When to change
Shorter frees CGNAT ports sooner on very busy pools.
## Careful
Below a minute, late packets of a closing connection may be dropped as invalid."##,
    ),
    (
        "tuning.net.netfilter.nf_conntrack_tcp_timeout_syn_recv",
        r##"## What it does
Seconds a TCP connection waits for the final ACK of the handshake.
## When to change
Rarely, like `syn_sent`.
## Careful
Too short drops slow handshakes over satellite or congested links."##,
    ),
    (
        "tuning.net.netfilter.nf_conntrack_tcp_timeout_syn_sent",
        r##"## What it does
Seconds a TCP connection waits for the answer to its SYN.
## When to change
Rarely: shorter only when SYN floods fill the table.
## Careful
RFC 5382 REQ-5 asks at least 4 minutes for connections still opening or closing; the kernel's 120 s is already below it."##,
    ),
    (
        "tuning.net.netfilter.nf_conntrack_tcp_timeout_time_wait",
        r##"## What it does
Seconds a closed TCP connection stays, to catch late packets.
## When to change
Shorter on CGNAT pools that run out of ports (MikroTik uses 10 s).
## Careful
Very short lets a new connection reuse a port while old packets still travel."##,
    ),
    (
        "tuning.net.netfilter.nf_conntrack_udp_timeout",
        r##"## What it does
Seconds a UDP flow that got no answer yet stays (DNS queries, scans).
## When to change
Shorter on CGNAT: each unanswered query holds a public port (MikroTik: 10 s).
## Careful
Below 10 s a slow DNS answer may find no entry."##,
    ),
    (
        "tuning.net.netfilter.nf_conntrack_udp_timeout_stream",
        r##"## What it does
Seconds an answered UDP flow (VoIP, games, QUIC, VPN) stays with no packet.
## When to change
Longer keeps VoIP and VPN through NAT without keepalives (MikroTik: 3 min).
## Careful
RFC 4787 REQ-5: a NAT mapping must last at least 2 minutes (5 recommended)."##,
    ),
    (
        "tuning.port.adaptive_rx",
        r##"## What it does
Adaptive interrupt coalescing on receive: the driver waits longer between interrupts when traffic is heavy and fires at once when it is light (Intel ITR, Mellanox DIM).
## When to change
On for most routers. Off, with `rx_usecs` = 0, for the lowest latency (an interrupt per packet).
## Careful
Off with a high `rx_usecs` delays every packet; off with 0 can use a whole CPU on interrupts at line rate."##,
    ),
    (
        "tuning.port.adaptive_tx",
        r##"## What it does
Adaptive interrupt coalescing on transmit: the driver waits longer between interrupts when traffic is heavy and fires at once when it is light (Intel ITR, Mellanox DIM).
## When to change
On for most routers. Off, with `tx_usecs` = 0, for the lowest latency (an interrupt per packet).
## Careful
Off with a high `tx_usecs` delays every packet; off with 0 can use a whole CPU on interrupts at line rate."##,
    ),
    (
        "tuning.port.combined_channels",
        r##"## What it does
Queue pairs (receive and transmit together) the port uses. Each queue has its own interrupt, served by one CPU: more queues spread the receive work (RSS hashes each flow to one queue).
## When to change
One queue per CPU of the port's NUMA node (`scaling.rst`): a CPU on the other node reaches the NIC across the interconnect. More queues than CPUs only add interrupts.
## Careful
Changing it **resets the port** (the link drops for a moment) and moves interrupts: CPU and IRQ affinity follows in G1.26c."##,
    ),
    (
        "tuning.port.gro",
        r##"## What it does
Generic Receive Offload: the kernel merges consecutive packets of a flow into one before routing them, and splits them again when sending. Fewer per-packet costs.
## When to change
Keep it on: it is reversible, so it is safe for routing and bridging (unlike LRO).
## Careful
Off only to debug packet captures."##,
    ),
    (
        "tuning.port.gso",
        r##"## What it does
Generic Segmentation Offload: big TCP packets the router itself sends are cut by the NIC (or late in the stack) instead of by the CPU.
## When to change
It does not matter for forwarded traffic, which arrives already cut to the wire's MTU. Leave it as the driver has it.
## Careful
It helps the router's own TCP (BGP with full tables, the API); turning it off only costs CPU."##,
    ),
    (
        "tuning.port.lro",
        r##"## What it does
Large Receive Offload: the NIC merges packets in hardware and rewrites their headers in a way that cannot be undone.
## When to change
Keep it off on a router: the kernel turns it off by itself when forwarding is on. Only a host that terminates the traffic gains from it.
## Careful
Forwarding LRO-merged packets breaks PMTU and TCP on the far end. CoreRouter refuses to turn it on here (`interface.ethernet.set force=yes` for a port that only terminates traffic)."##,
    ),
    (
        "tuning.port.qdisc",
        r##"## What it does
The root queueing discipline of the port: how packets wait to be sent.
- **mq**: one child qdisc per transmit queue (the kernel default for multi-queue NICs); no lock shared by all CPUs.
- **fq_codel**: fair queuing with CoDel AQM: low delay, no bufferbloat (the default child qdisc).
- **fq**: fair queuing with pacing, for hosts sending TCP.
- **pfifo_fast**: the old three-band FIFO.
- **noqueue**: no queue (virtual interfaces).
## When to change
A multi-queue port keeps mq; a single-queue port gets fq_codel. Shaping (HTB, CAKE) is a different feature.
## Careful
fq_codel at the root of a multi-queue NIC funnels every CPU through one lock: lower throughput."##,
    ),
    (
        "tuning.port.rp_filter",
        r##"## What it does
The reverse path filter of this port. The kernel uses the larger of `net.ipv4.conf.all.rp_filter` and this value: turning `all` off does nothing on a port left at strict.
## When to change
To the same value as `all` (the profile does so): loose (2) for an ISP with several uplinks, off (0) with anti-spoofing in the firewall.
## Careful
Strict (1) on an uplink drops replies that come back by another uplink (asymmetric routing)."##,
    ),
    (
        "tuning.port.rx_channels",
        r##"## What it does
Receive-only queues the port uses (NICs without combined queues, veth). Each queue has its own interrupt, served by one CPU: more queues spread the receive work (RSS hashes each flow to one queue).
## When to change
One queue per CPU of the port's NUMA node (`scaling.rst`): a CPU on the other node reaches the NIC across the interconnect. More queues than CPUs only add interrupts.
## Careful
Changing it **resets the port** (the link drops for a moment) and moves interrupts: CPU and IRQ affinity follows in G1.26c."##,
    ),
    (
        "tuning.port.rx_pause",
        r##"## What it does
802.3x flow control, receive: the port obeys pause frames from the other end and stops sending.
## When to change
Off on a router (Intel's ice default): a pause stops the whole port, so one slow receiver delays every flow (head-of-line blocking). Drops are cheaper than stalls; TCP handles them.
## Careful
Some switches and storage networks rely on pause; match the other end. Changing it may renegotiate the link."##,
    ),
    (
        "tuning.port.rx_ring",
        r##"## What it does
Descriptors in the port's RX ring: packets the NIC can hold for the kernel (receive) before it has to drop ("missed").
## When to raise
When `rx_missed_errors` grows (Summary tab) or the port takes bursts at 10 Gb/s and up. Intel and Mellanox guides raise it to the maximum for forwarding.
## Careful
Changing it **resets the port**: the link drops for a moment (use Safe Mode). A bigger ring uses more memory and lets a queue hold more delay under overload."##,
    ),
    (
        "tuning.port.rx_usecs",
        r##"## What it does
Microseconds the NIC waits after a receive packet before it interrupts the CPU (with adaptive coalescing off). Intel: 80 µs ≈ 12 500 interrupts per second per queue.
## When to change
0 for the lowest latency; 50–100 to save CPU at high packet rates. With adaptive on, the driver decides.
## Careful
Some drivers round it (to multiples of 2 or 4 µs); CoreRouter checks what the driver kept."##,
    ),
    (
        "tuning.port.tso",
        r##"## What it does
TCP Segmentation Offload: big TCP packets the router itself sends are cut by the NIC (or late in the stack) instead of by the CPU.
## When to change
It does not matter for forwarded traffic, which arrives already cut to the wire's MTU. Leave it as the driver has it.
## Careful
It helps the router's own TCP (BGP with full tables, the API); turning it off only costs CPU."##,
    ),
    (
        "tuning.port.tx_channels",
        r##"## What it does
Transmit-only queues the port uses (NICs without combined queues, veth). Each queue has its own interrupt, served by one CPU: more queues spread the receive work (RSS hashes each flow to one queue).
## When to change
One queue per CPU of the port's NUMA node (`scaling.rst`): a CPU on the other node reaches the NIC across the interconnect. More queues than CPUs only add interrupts.
## Careful
Changing it **resets the port** (the link drops for a moment) and moves interrupts: CPU and IRQ affinity follows in G1.26c."##,
    ),
    (
        "tuning.port.tx_pause",
        r##"## What it does
802.3x flow control, transmit: the port sends pause frames when its receive ring fills.
## When to change
Off on a router (Intel's ice default): a pause stops the whole port, so one slow receiver delays every flow (head-of-line blocking). Drops are cheaper than stalls; TCP handles them.
## Careful
Some switches and storage networks rely on pause; match the other end. Changing it may renegotiate the link."##,
    ),
    (
        "tuning.port.tx_ring",
        r##"## What it does
Descriptors in the port's TX ring: packets the NIC can queue for the wire (transmit) before it has to drop ("missed").
## When to raise
When transmit drops grow or the port takes bursts at 10 Gb/s and up. Intel and Mellanox guides raise it to the maximum for forwarding.
## Careful
Changing it **resets the port**: the link drops for a moment (use Safe Mode). A bigger ring uses more memory and lets a queue hold more delay under overload."##,
    ),
    (
        "tuning.port.tx_usecs",
        r##"## What it does
Microseconds the NIC waits after a transmit packet before it interrupts the CPU (with adaptive coalescing off). Intel: 80 µs ≈ 12 500 interrupts per second per queue.
## When to change
0 for the lowest latency; 50–100 to save CPU at high packet rates. With adaptive on, the driver decides.
## Careful
Some drivers round it (to multiples of 2 or 4 µs); CoreRouter checks what the driver kept."##,
    ),
    (
        "tuning.port.txqueuelen",
        r##"## What it does
Packets the kernel queues for the port when the NIC is busy (in the qdisc, before the TX ring). Default 1000.
## When to change
Rarely: with fq_codel the queue is kept short by the qdisc anyway. A virtual interface (VLAN, tunnel) with 0 has no queue at all.
## Careful
A big queue without an AQM qdisc is bufferbloat: seconds of delay under load."##,
    ),
    (
        "tuning.profiles",
        r##"## Profiles
Each profile is calculated from this machine (RAM, CPUs, port speeds), not copied from a table:
- **Conservative**: only what is safe everywhere (forwarding on, layer-4 ECMP, reboot on panic); the rest stays as the kernel has it.
- **Balanced**: a router with NAT: bigger receive budget and backlog, conntrack sized to 1/16 of the RAM, timeouts that free CGNAT ports sooner, neighbor tables for big LANs.
- **High throughput**: more of everything for 10/40/100 Gb/s and CGNAT: conntrack 1/8 of the RAM, the shortest timeouts the RFCs allow.
- **Low latency**: short receive rounds and a small backlog, so a packet waits less.
## Control plane
TCP settings (socket buffers, SYN cookies) only affect the router's own connections (BGP, the API), never forwarded traffic.
## Applying
"Apply with Safe Mode" enters Safe Mode first: if the connection to the router drops, every change goes back."##,
    ),
    (
        "tuning.vm.min_free_kbytes",
        r##"## What it does
Memory the kernel keeps free for allocations that cannot wait, like the NIC refilling its RX ring inside an interrupt.
## When to raise
With big rings and 10 Gb/s+ ports: when it runs short, the driver cannot refill the ring and drops packets ("page allocation failure" in the log).
## Careful
This memory is unavailable to programs; more than 5 % of the RAM is rarely useful. The limit here is a tenth of it."##,
    ),
];
