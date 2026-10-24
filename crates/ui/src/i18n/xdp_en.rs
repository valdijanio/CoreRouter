//! English explanations of IP › Firewall XDP (G2.5a), sorted by key.

/// Explanations by key (`xdp`, `xdp.<label>`).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "xdp",
        r##"## What it is
A filter that runs **inside the NIC driver** (XDP, eXpress Data Path), before the kernel spends anything on the packet: before `raw`, connection tracking and routing. It drops what an attack sends in volume: sources in block lists, sources over a rate, broken headers and TCP flag combinations no connection uses.
## Why
A NIC in native mode drops tens of millions of packets per second on a few CPUs (XDP paper, CoNEXT 2018: 24 Mpps per core on a ConnectX-5; **estimated** for your hardware until measured). In the same paper, the iptables raw table dropped 4.8 Mpps per core. The gain comes from not allocating the packet in the kernel, and shows only in native mode on a real NIC: on a veth pair, without a NIC, XDP did not beat nftables (**measured**, docs/xdp.md).
## RouterOS equivalent
RouterOS has no XDP. The closest is `/ip firewall raw add chain=prerouting src-address-list=… action=drop`, with `dst-limit=…,src-address` for the rate.
## Careful
A packet dropped here shows in no other firewall counter. The filter is the same on every interface it runs on."##,
    ),
    (
        "xdp.active",
        r##"## What it shows
How the filter is attached now: **native** (in the driver: the fast one), **generic** (after the driver, on the kernel's buffer: works on any interface, slower) or **off** (not attached; the Note column says why).
## With mode auto
Auto tries native and falls back to generic where the driver has no XDP; the Note says why native was refused."##,
    ),
    (
        "xdp.allow_lists",
        r##"## What it does
Firewall address lists (IP › Firewall › Address Lists) whose **sources the filter never drops** for a block list or the rate. Malformed packets still drop.
## What for
Put here what must not fall: BGP peers, the management network (NOC), DNS resolvers, monitoring. A block list feed or a rate set too low then cannot cut your own access.
## Protection
If a change would drop the address of your own management session, the commit is refused (as in the firewall) unless you confirm (force) or are in Safe Mode."##,
    ),
    (
        "xdp.block_lists",
        r##"## What it does
Firewall address lists whose **sources are dropped** in the driver. IPv4 and IPv6 prefixes, ranges (turned into exact CIDR blocks) and dynamic entries (with a timeout) count; disabled entries do not.
## How
The prefixes go into a longest-prefix-match trie in the kernel: one lookup per packet, whatever the number of entries (the cost by trie size is measured in docs/xdp.md).
## Examples
Bogons, reputation lists (Spamhaus DROP, FireHOL), the `ddos-attackers` list a firewall rule fills.
## Later
Entries an `add-src-to-address-list` rule puts in a list live in nftables only and do not reach XDP yet (G2.5c)."##,
    ),
    (
        "xdp.blocked",
        r##"## What it counts
Packets dropped because their source is in a block list (and in no allow list). Top Sources shows which sources, and from which list."##,
    ),
    (
        "xdp.drop",
        r##"## What it counts
Packets dropped per second on this interface, all reasons together (block, rate, malformed, TCP flags). From the counters' difference between two readings at least a second apart."##,
    ),
    (
        "xdp.fast_nat",
        r##"## What it does
The CGNAT fast path: the connections the kernel's CGNAT (nftables) already translated are translated and forwarded here, in the driver, without conntrack, the rules or the kernel's routing.
## How
The kernel still decides everything: the first packets of every connection go through nftables, which picks the port in the subscriber's deterministic range. When conntrack says the connection is established (both directions seen), the `xdp-nat` service copies its two directions into the XDP map; from then on XDP swaps address and port, fixes the checksums (RFC 1624), takes one off the TTL and sends the packet out of the interface the routing table names (`bpf_fib_lookup`). The service renews the conntrack timeout of the connections XDP carried and takes out of the map those conntrack ended.
## Stays in the kernel
IPv6, ICMP, fragments, VLAN-tagged frames, packets with IP options, SYN/FIN/RST (conntrack follows the opening and the closing), TTL 1, and what the routing table cannot resolve right away (a neighbor without a MAC yet, MTU). "Sent to the kernel" counts each reason.
## Needs
XDP on the subscribers' interfaces and on the ones toward the internet. Up to 262 144 connections at once; past that, new ones go through the kernel. "Who was?" stays exact: the kernel chose the port."##,
    ),
    (
        "xdp.malformed",
        r##"## What it drops
Frames with impossible headers: cut inside the Ethernet, VLAN, IP or transport header; an IP version that does not match the EtherType; an IHL under 20 bytes; a total length shorter than the header or longer than the frame; an impossible UDP length; a TCP data offset under 20 bytes.
## Fragments
A first fragment too short for the TCP/UDP header and a TCP fragment at offset 8 bytes (tiny-fragment and overlap attacks, RFC 1858 §3) count as malformed. Later fragments pass: they carry no transport header to check.
## Why it is safe
The kernel would drop these further on; here they leave before costing CPU."##,
    ),
    (
        "xdp.mode",
        r##"## Choices
- **auto**: native where the driver has XDP, generic where it does not. The default.
- **native**: in the driver, before the kernel allocates the packet. mlx5 (ConnectX-4 and later), i40e, ice, ixgbe, bnxt, ena, igb, igc, virtio_net and veth have it. Refused (and the commit undone) where the driver lacks it.
- **generic**: after the driver, on any interface (VLAN, bridge). A fraction of native's speed (8.4 against 19.8 Mpps on one core of an mlx5, **measured** by others).
## Tip
VLANs and bridges have no driver of their own: attach to the physical port, which sees the tagged frames."##,
    ),
    (
        "xdp.pass",
        r##"## What it counts
Packets per second the filter let through to the kernel on this interface (ARP, LLDP and non-IP included)."##,
    ),
    (
        "xdp.rate-limit",
        r##"## What it counts
Packets dropped because their source went over the per-source rate (Filter tab). Top Sources shows which."##,
    ),
    (
        "xdp.rate_burst",
        r##"## What it does
How many packets a source may send at once above the rate (the bucket size). 0 means one second's worth.
## Example
Rate 1000 and burst 5000: a source may send 5000 packets at once, then 1000 per second."##,
    ),
    (
        "xdp.rate_limit",
        r##"## What it does
A packets-per-second limit **per source**, one token bucket per address. 0 turns it off.
## RouterOS equivalent
`dst-limit=<rate>,<burst>,src-address` in a `raw` rule.
## Careful
One address can be many people: another provider's CGNAT, a resolver, a CDN, a BGP peer. Put those in an allow list. Under 100 pps the command warns.
## Limits
Up to 262 144 sources hold a bucket at once; past that the least recently seen loses its own and starts full again. Two CPUs updating the same source at once may gain or lose a token: the rate is approximate then."##,
    ),
    (
        "xdp.tcp-flags",
        r##"## What it drops
TCP segments with a flag combination no connection uses: SYN+FIN, SYN+RST, FIN+RST, FIN without ACK, no flags at all (null scan), FIN+PSH+URG (Xmas). The table is the kernel's `nf_conntrack` one, which would mark these packets invalid.
## Why it is safe
A correct TCP stack never sends these; they come from port scans and from attacks that try to get past stateless firewalls."##,
    ),
    (
        "xdp.top",
        r##"## What it shows
The sources with the most dropped packets, for any reason: address, packets, bytes, the reason and list of the last drop, and how many seconds ago.
## Limits
The filter remembers up to 16 384 dropped sources; past that the least recently seen leaves the table. Reset Counters clears the counters and this table."##,
    ),
    (
        "xdp.unavailable",
        r##"## Why
Loading an XDP program needs CAP_BPF and CAP_NET_ADMIN in the initial namespace: run `corerouter-daemon` as root, or give the binary the capabilities (`setcap cap_bpf,cap_net_admin,cap_perfmon+ep`). The kernel may also lack BPF support.
## In the virtual lab
The filter is simulated: the counters grow with what is turned on, with no real packets."##,
    ),
];
