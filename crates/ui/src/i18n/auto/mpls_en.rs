//! English explanations of MPLS › LDP and Forwarding Table (G3.5),
//! sorted by key (registered by `build.rs`).

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (r##"menu.mpls-forwarding"##, r##"## What it does
The label forwarding table: for each FEC (a prefix), the label this router gave it, the label the next hop asked for, and where it goes. A FEC without an outgoing label says why.

Static LSPs (labels set by hand, Cisco `mpls static binding`) are added here."##),
    (r##"menu.mpls-ldp"##, r##"## What it does
LDP (RFC 5036) hands out MPLS labels for the IGP's routes and learns the neighbors' labels, so traffic between the routers' loopbacks crosses the core label-switched. Run by FRR's ldpd.

## Careful
LDP follows the IGP (OSPF): set up OSPF first. IGP sync (RFC 5443) is on, so a link carries traffic only after LDP is up on it."##),
    (r##"mpls.afi"##, r##"## What it is
Address families: `ip` (IPv4), `ipv6` (RFC 7552) or both. Empty on an interface: the instance's."##),
    (r##"mpls.disabled"##, r##"## What it is
Kept in the config, not running."##),
    (r##"mpls.explicit_null"##, r##"## What it is
Advertise explicit NULL (label 0) instead of implicit NULL for this router's own prefixes: the last hop keeps the label, and its TC (QoS) bits reach this router (RFC 3032 §2.1)."##),
    (r##"mpls.fwd.fec"##, r##"## What it is
The Forwarding Equivalence Class: the prefix whose packets share this label (RFC 3031 §2.1). Empty for a label entry without a FEC (a static LSP)."##),
    (r##"mpls.fwd.in_label"##, r##"## What it is
The label this router advertised for the FEC: packets arriving with it are switched by this line. `implicit-null`: the FEC is this router's own (the previous hop pops)."##),
    (r##"mpls.fwd.interface"##, r##"## What it is
The interface the labeled packet leaves on."##),
    (r##"mpls.fwd.nexthop"##, r##"## What it is
The next router, from the IGP route to the FEC."##),
    (r##"mpls.fwd.origin"##, r##"## What it is
Who installed it: `ldp`, `static` (/mpls static), `bgp` (labeled unicast) or `other` (another program)."##),
    (r##"mpls.fwd.out_label"##, r##"## What it is
The label the next hop asked for. `implicit-null (pop)`: the next hop is the end of the LSP, the packet leaves as plain IP (penultimate hop popping, RFC 3031 §3.16). `-`: no label (see Reason)."##),
    (r##"mpls.fwd.reason"##, r##"## What it is
Why a FEC has no outgoing label (no LDP neighbor up, the next hop sent none, the route leaves on a link without LDP…), or a warning about the line (MTU)."##),
    (r##"mpls.fwd.unlabeled"##, r##"## What it is
Show only the FECs without an outgoing label: where the LSP breaks."##),
    (r##"mpls.gtsm"##, r##"## What it is
GTSM (RFC 6720): LDP packets of a directly connected neighbor must arrive with TTL 255, so a remote attacker cannot reach the session. Negotiated in the Hello; on by default. For IPv6 it is always on (RFC 7552 §9)."##),
    (r##"mpls.icmp_rate"##, r##"## What it is
How many ICMP errors about labeled packets (time exceeded and too big) this router sends per second at most, from all sources together (default 100). The rest are dropped and counted.

## Why
A flood of packets with TTL 1 must not keep the control plane busy (RFC 1812 §4.3.2.8 asks routers to limit ICMP errors). Each error goes only to the source of the packet it is about. Each source also has its own, smaller limit (ICMP Rate Per Source)."##),
    (r##"mpls.icmp_rate_per_source"##, r##"## What it is
How many of those ICMP errors one source gets per second at most (default 10; a traceroute needs 3 per hop). Checked before the total limit.

## Why
Without it, one host flooding TTL 1 used up the whole ICMP Rate and everyone else's traceroute showed `*` at this hop. Linux does the same for its own errors (`icmp_ratelimit`, per destination).

## Diagnosis
`mpls.settings.get` shows `icmp_counters.rate_limited_source` (refused by this limit) apart from `rate_limited` (the total one)."##),
    (r##"mpls.icmp_too_big"##, r##"## What it is
When a labeled packet is larger than the MTU of the link its label leaves by, sends the ICMP "fragmentation needed" (IPv4 with DF) or ICMPv6 "packet too big" back to its source, with the MTU that fits: the link MTU minus the labels that would leave (RFC 3032 §3.4–3.5). IPv4 carries the label stack it arrived with (RFC 4950).

## Why
The Linux MPLS forwarder drops these packets without an error, so Path MTU Discovery through the LSP failed: the connection opens and stalls at the first full-size packet. Only routers in the middle of an LSP need this; where the packet is first labeled the IP layer already answers.

## Not sent
IPv4 without DF (RFC 3032 §3.4 lets the router drop it), small IPv6 fragments, errors about ICMP errors.

## Diagnosis
`mpls.settings.get` shows `icmp_counters.too_big` (heard) and `too_big_sent`; `reasons` says why the others got none ("fits the way out", "DF not set…")."##),
    (r##"mpls.icmp_ttl_exceeded"##, r##"## What it is
When a labeled packet's TTL expires at this router, sends the ICMP "time exceeded" back to its source, with the label stack it arrived with (RFC 4950: traceroute shows `MPLS:L=…`).

## Why
The Linux MPLS forwarder drops these packets without an error, so a traceroute through the LSP showed `*` at this hop. RouterOS, Cisco and Junos answer.

## How it goes back
With one label and an IP route to the source, by the IP table. With more labels (a VPN), along the LSP itself, as RFC 3032 §2.3.2 describes: the egress routes it back to the source.

## Diagnosis
`mpls.settings.get` shows `icmp_counters`: expired packets heard, errors sent, dropped by the rates and by reason."##),
    (r##"mpls.if"##, r##"## What it is
LDP on one interface: link Hellos to 224.0.0.2 (IPv6 ff02::2) every hello interval, and the adjacencies they form (RFC 5036 §2.4.1)."##),
    (r##"mpls.if.adjacencies"##, r##"## What it is
Neighbors whose Hellos arrive on this interface."##),
    (r##"mpls.if.hello_interval"##, r##"## What it is
Seconds between link Hellos (default 5)."##),
    (r##"mpls.if.hold_time"##, r##"## What it is
Seconds a neighbor's Hello is held before the adjacency drops (default 15, RFC 5036 §3.5.2). The lower of the two sides is used; at least three Hellos must fit in it."##),
    (r##"mpls.if.interface"##, r##"## What it is
The link towards another LSR. Its MTU must fit a full IP packet plus 4 bytes per label."##),
    (r##"mpls.if.state"##, r##"## What it is
`active`: LDP sends Hellos there. `down`: the link is down or has no address. `no daemon`: no routing daemon."##),
    (r##"mpls.lsp_ping_rate"##, r##"## What it is
How many MPLS echo replies this router sends per second at most (default 100). The rest are dropped and counted.

## Why
RFC 8029 §5 asks for a rate limiter on UDP port 3503: without one a flood of requests fills the control plane. A reply is never larger than the request plus the mappings and goes only to the sender, so it cannot amplify."##),
    (r##"mpls.lsp_ping_responder"##, r##"## What it is
Answers LSP ping and LSP traceroute (MPLS echo request, RFC 8029) that reach this router, as the LSP's egress or as the transit LSR where the label TTL expired.

## Default
On, as on Cisco and Junos: off, a ping that reaches here looks like a broken LSP. It works on the interfaces that take MPLS (MPLS › Interface or LDP).

## Diagnosis
`mpls.settings.get` shows its counters (`lsp_ping_counters`): requests heard, answered, dropped by the rate and by return code."##),
    (r##"mpls.lsr_id"##, r##"## What it is
This router's LSR ID (RFC 5036 §2.2.2), usually the loopback address. Required to start LDP."##),
    (r##"mpls.mtu"##, r##"## What it is
The link's MTU. Each label adds 4 bytes (RFC 3032 §3): `MTU 1500 < 1504` means a 1500-byte IP packet with one label does not fit, and full-size packets are dropped. Raise the MTU of both ends."##),
    (r##"mpls.nbr"##, r##"## What it is
A configured LDP neighbor, named by its LSR ID: a TCP MD5 password for the session (RFC 5036 §2.9), targeted Hellos to a router that is not adjacent (§2.4.2), or a keepalive hold time."##),
    (r##"mpls.nbr.flags"##, r##"## What it is
`dynamic`: found by Hello, not configured. `targeted`: targeted Hellos. `MD5`: the session is signed."##),
    (r##"mpls.nbr.in_use"##, r##"## What it is
Of those labels, the ones in use: this neighbor is the IGP next hop of the FEC."##),
    (r##"mpls.nbr.keepalive_hold"##, r##"## What it is
Seconds without any LDP message before the session is closed (RFC 5036 §2.5.5). The lower of the two sides' values is used. Default 180 s (FRR and Cisco)."##),
    (r##"mpls.nbr.labels"##, r##"## What it is
FECs this neighbor sent a label for (liberal retention: all are kept)."##),
    (r##"mpls.nbr.lsr_id"##, r##"## What it is
The neighbor's LSR ID: the first four bytes of its LDP identifier (RFC 5036 §2.2.2), usually its loopback."##),
    (r##"mpls.nbr.password"##, r##"## What it is
TCP MD5 signature of the session (RFC 5036 §2.9, RFC 2385). Kept sealed in the config, never in clear. Both sides need the same key.

## Careful
Changing it resets the session."##),
    (r##"mpls.nbr.state"##, r##"## What it is
The session state (RFC 5036 §2.5.4): `operational` exchanges labels; `opensent`/`openrec`/`initialized` are being set up; `present` has only Hellos. `no daemon`: the routing daemon is not running (virtual lab)."##),
    (r##"mpls.nbr.targeted"##, r##"## What it is
Send targeted Hellos (unicast, UDP 646) to this address: a session to a router that is not on a shared link (RFC 5036 §2.4.2). Both sides must accept them; the hold time is 45 s."##),
    (r##"mpls.nbr.transport"##, r##"## What it is
The address the TCP session (port 646) runs to. The router with the higher transport address opens it (RFC 5036 §2.5.2)."##),
    (r##"mpls.nbr.uptime"##, r##"## What it is
How long the session has been up."##),
    (r##"mpls.payload_mtu"##, r##"## What it is
The IP packet size the MTU check assumes (default 1500): the check adds 4 bytes per label to it."##),
    (r##"mpls.preferred_afi"##, r##"## What it is
With both families, which one carries the single session to each neighbor (RFC 7552 §6.1.1). Default IPv6."##),
    (r##"mpls.propagate_ttl"##, r##"## What it is
Copy the IP TTL into the label and back (RFC 3032 §2.4.3, uniform model). Off: the core does not show in a customer's traceroute (pipe model, RFC 3443)."##),
    (r##"mpls.range"##, r##"## What it is
The labels LDP hands out (RouterOS `dynamic-label-range`, default 16-1048575; 0-15 are reserved, RFC 3032 §2.1). Static LSPs take labels above the range, so shrink it to use them. Linux sizes its label table from the end (`platform_labels`)."##),
    (r##"mpls.static"##, r##"## What it is
A label switching entry set by hand: packets arriving with the in label leave towards the next hop with the out labels (or popped). Cisco `mpls static binding`, Junos static LSP; RouterOS has none. The in label must be above the dynamic range, so LDP never hands it out."##),
    (r##"mpls.static.interface"##, r##"## What it is
The outgoing interface; empty: found from the next hop."##),
    (r##"mpls.static.label"##, r##"## What it is
The incoming label, above the dynamic range (Settings)."##),
    (r##"mpls.static.nexthop"##, r##"## What it is
The next router's address on a connected link."##),
    (r##"mpls.static.out_labels"##, r##"## What it is
The labels that replace the incoming one, top first (`100 200`, at most 30). Empty: pop (implicit NULL) and send plain IP. 0 and 2 are explicit NULL."##),
    (r##"mpls.sync"##, r##"## What it is
LDP-IGP synchronization (RFC 5443): while LDP is not up on a link, OSPF announces it at the highest cost, so traffic never takes a link without labels (it would be dropped or leave the LSP). `achieved`: LDP is up, the real cost is used. `waiting for LDP`: max cost.

On by default (RouterOS does not have it)."##),
    (r##"mpls.sync_holddown"##, r##"## What it is
Seconds the IGP waits for LDP before using the link anyway. Empty: wait as long as it takes (FRR, Cisco and Junos default; RFC 5443 sets none)."##),
    (r##"mpls.tab.interfaces"##, r##"## What it is
Where LDP sends Hellos and forms adjacencies: the links towards the other label switching routers."##),
    (r##"mpls.tab.neighbors"##, r##"## What it is
The LDP sessions: the routers found by Hello on LDP interfaces (dynamic) and the ones configured here (for a password or targeted Hellos)."##),
    (r##"mpls.tab.settings"##, r##"## What it is
The LDP instance (LSR ID, families, transport address, IGP sync, GTSM) and `/mpls settings` (label range, TTL). One Apply sends both as one transaction."##),
    (r##"mpls.transport"##, r##"## What it is
The address sessions start from, one per family (RFC 5036 §2.5.2). IPv4 default: the LSR ID. IPv6 needs a global address (RFC 7552 §6.1). It must be reachable through the IGP."##),
];
