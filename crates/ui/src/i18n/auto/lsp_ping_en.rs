//! English explanations of Tools › LSP Ping (G3.5b), sorted by key.

/// Explanations: (key, text).
pub(super) const HELP: &[(&str, &str)] = &[
    (r##"lsp_ping.col.code"##, r##"## What it is
The return code in one letter, as Cisco prints it:

- `!` egress (3): the LSP reaches the FEC's router;
- `L` label switched (8): a transit LSR;
- `.` no reply in time; `Q` not sent (no ARP entry, link down);
- `N` no label entry (11): the LSR does not know the label;
- `F` no mapping for the FEC (4); `f` the label is of another FEC (10);
- `D` downstream mapping mismatch (5): interface or label not what the previous hop said;
- `I` upstream interface unknown (6); `B` switched without MPLS (9); `M` malformed (1); `m` TLV not understood (2); `X` another code."##),
    (r##"lsp_ping.col.from"##, r##"## What it is
The router that answered (the source address of its echo reply)."##),
    (r##"lsp_ping.col.hop"##, r##"## What it is
The label TTL of the request: hop 0 is this router (what it pushes, where it sends)."##),
    (r##"lsp_ping.col.labels"##, r##"## What it is
The labels this hop hands to the next one (blue chips), or `implicit-null` when it pops them (the next is the egress: penultimate hop popping)."##),
    (r##"lsp_ping.col.mtu"##, r##"## What it is
The MTU of the link to the next LSR, as the hop reports it (Downstream Detailed Mapping, RFC 8029 §3.4)."##),
    (r##"lsp_ping.col.return_code"##, r##"## What it is
The return code in full (RFC 8029 §3.1) and, on a mismatch, the interface and labels the request really came in with."##),
    (r##"lsp_ping.col.seq"##, r##"## What it is
The request's sequence number."##),
    (r##"lsp_ping.col.time"##, r##"## What it is
Round trip: from sending the request to receiving its reply, measured by this router. The reply comes back over IP, not over the LSP."##),
    (r##"lsp_ping.count"##, r##"## What it is
Requests to send (default 5, like Cisco and Junos); 0 sends until Stop."##),
    (r##"lsp_ping.exp"##, r##"## What it is
Traffic class of the labels (the old EXP bits, 0–7, RFC 5462), also the DSCP of the packet: to test the LSP with the class of a service (voice in EXP 5, for example)."##),
    (r##"lsp_ping.fec"##, r##"## What it is
The Forwarding Equivalence Class to test: for LDP, the egress router's loopback (`10.255.0.3/32`). An address without length is a /32 (/128).

The request takes the route of the FEC with its labels (MPLS › Forwarding Table shows them); without a route there is nothing to send along."##),
    (r##"lsp_ping.fec_type"##, r##"## What it is
How the FEC is described to the LSRs (RFC 8029 §3.2): `ldp` (LDP IPv4/IPv6 prefix) for LSPs that LDP built; `generic` (Generic IPv4/IPv6 prefix) for a static LSP, whose labels no protocol announced."##),
    (r##"lsp_ping.interval"##, r##"## What it is
Time between two requests (100–60000 ms, default 1000). A request does not wait for the previous reply."##),
    (r##"lsp_ping.max_hops"##, r##"## What it is
Highest TTL a traceroute tries (1–64, default 30). It ends earlier at the egress or at the first error."##),
    (r##"lsp_ping.mode"##, r##"## Ping or Traceroute
**Ping** sends requests with the top label TTL at 255: the egress answers each one (code 3, `!`). **Traceroute** sends TTL 1, 2, 3…: each LSR where the TTL expires answers with the labels it hands downstream, which go into the next request, so every hop checks what the previous one announced."##),
    (r##"lsp_ping.path"##, r##"## What it is
How the request leaves this router: the labels the FEC's route pushes (blue chips; `implicit-null` when the next hop is the egress), the next hop and the interface, and the source address the replies come back to. The frame goes to 127.0.0.1 with IP TTL 1 (RFC 8029 §4.3), so no router forwards it as IP: it either follows the labels or reaches a control plane."##),
    (r##"lsp_ping.size"##, r##"## What it is
UDP payload size of each request (64–9000 bytes): a Pad TLV fills it (RFC 8029 §3.5). With the labels and headers, it finds the MPLS MTU of the path: a request too big for a link is lost. The reply leaves the padding out."##),
    (r##"lsp_ping.timeout"##, r##"## What it is
How long to wait for each reply (100–10000 ms, default 2000). A reply comes back over the IP route, which may be longer than the LSP."##),
    (r##"lsp_ping.ttl"##, r##"## What it is
TTL of the top label (1–255, default 255, RFC 8029 §4.3). Lower, the request stops at that hop (which answers "label switched")."##),
    (r##"lsp_ping.validate"##, r##"## What it is
The V flag (RFC 8029 §3): asks each LSR to check that the label it received is the one it bound to this FEC. A label of another FEC answers code 10 (`f`).

## Default
On: it is what finds a label that leaks to the wrong LSP."##),
    (r##"menu.lsp-ping"##, r##"## What it does
LSP ping and traceroute (RFC 8029): MPLS echo requests sent along the label switched path of a FEC, as data of that FEC would go, to check the LSP itself and not just the IP route. Cisco's `ping mpls ipv4` and `traceroute mpls ipv4`, Junos' `ping mpls ldp`. RouterOS has none: its traceroute only shows the labels routers put in their ICMP errors.

## When
An LDP or static LSP that should work and traffic that does not get through: ping says whether the far end gets it; traceroute says at which hop the LSP breaks and why."##),
];
