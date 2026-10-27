//! English explanations of Routing › BGP Routes and "Why this route?"
//! (G3.2c), sorted by key (registered by `build.rs`).

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (r##"bgp_routes.as_path"##, r##"## What it is
The ASes the route crossed, the neighbor first and the origin last. `{…}` is an AS_SET (aggregation), `(…)` confederation segments."##),
    (r##"bgp_routes.communities"##, r##"## What it is
The route's communities (RFC 1997, `asn:value`) and large communities (RFC 8092, `a:b:c`): tags that drive policies."##),
    (r##"bgp_routes.explain"##, r##"## What it is
Every path the router holds for this prefix, the one chosen, and for each other the step of the BGP decision that put it behind (RFC 4271 §9.1, in the order FRR's bgpd compares). Click a step to read what it compares.

When the daemon's choice cannot be reproduced step by step (deterministic-med, multipath), the window says so."##),
    (r##"bgp_routes.explain.lost_at"##, r##"## What it is
The step where this path lost to the best one, with the two values compared (winner first). Red: by our comparison this path should have won (see the note on top)."##),
    (r##"bgp_routes.explain.path"##, r##"## What it is
The neighbor (its connection) the path came from; `best` marks the chosen one."##),
    (r##"bgp_routes.history.connection"##, r##"## What it is
The BGP connection (or the neighbor address for a session FRR runs that no connection names)."##),
    (r##"bgp_routes.history.event"##, r##"## What it is
`down`: the session left Established. `up`: it came back. `flap`: it went down and up between two samples (its flap counter moved)."##),
    (r##"bgp_routes.history.reason"##, r##"## What it is
The last NOTIFICATION sent or received (RFC 4271 §6, RFC 4486 Cease subcodes) or the daemon's reason (hold timer expired, prefix limit, administrative reset)."##),
    (r##"bgp_routes.history.time"##, r##"## What it is
When the change was seen (the sample of the routing daemon's state, every 2 s)."##),
    (r##"bgp_routes.history.uptime"##, r##"## What it is
How long the session had been up before it went down."##),
    (r##"bgp_routes.local_pref"##, r##"## What it is
LOCAL_PREF: the AS's preference among exits; higher wins. Empty: none sent (eBGP), counts as 100."##),
    (r##"bgp_routes.med"##, r##"## What it is
MULTI_EXIT_DISC: the neighbor's hint about which of its links to use; lower wins between routes from the same neighboring AS."##),
    (r##"bgp_routes.next_hop"##, r##"## What it is
Where the traffic for the prefix goes next (BGP NEXT_HOP)."##),
    (r##"bgp_routes.origin"##, r##"## What it is
The ORIGIN attribute: `igp`, `egp` or `incomplete` (redistributed)."##),
    (r##"bgp_routes.origin_as"##, r##"## What it is
The AS that originated the route: the last AS of the AS path (RFC 6811 §2). Our own AS for our routes; none when the path ends in an AS_SET."##),
    (r##"bgp_routes.prefix"##, r##"## What it is
The destination prefix of the route."##),
    (r##"bgp_routes.rpki"##, r##"## What it is
The RPKI origin validation state (RFC 6811):

- `valid`: a ROA covers the prefix, allows its length and names its origin AS;
- `invalid`: ROAs cover it but none allows this origin or length (a hijack or a mistake); rejected unless the connection says `accept`;
- `unknown`: no ROA covers it (most of the table today);
- `unverified`: no validator is in sync, so nothing can be said."##),
    (r##"bgp_routes.rpki_share"##, r##"## What it is
The share of each RPKI state among this connection's routes. A full table today is roughly half valid and half unknown, with invalid well under 1 %; a high invalid share points at a leak or a hijack."##),
    (r##"bgp_routes.search"##, r##"## How to search
- **Prefix**: a prefix gives it and every route inside it (`orlonger`); an address gives the routes that contain it (`covering`).
- **AS path**: AS numbers one after the other; `^` anchors at the neighbor, `$` at the origin: `^64500`, `13335$`, `64500 3356`.
- **Community**: `65000:100`, `65000:1:2` or a well-known name (`no-export`).
- **RPKI** and **filtered only** narrow the list further.

The search runs on the router, over the whole table, and the answer comes a page at a time."##),
    (r##"bgp_routes.status"##, r##"## What it is
`best`: the daemon chose this path for the prefix. `filtered`: received but refused by the inbound policy (an RPKI-invalid route, a filter)."##),
    (r##"bgp_routes.step.as-path-length"##, r##"## The step
**AS_PATH length** (RFC 4271 §9.1.2.2 a): fewer ASes wins. An AS_SET counts as one; confederation segments do not count."##),
    (r##"bgp_routes.step.cluster-length"##, r##"## The step
**CLUSTER_LIST length** (RFC 4456 §9): the route reflected through fewer reflectors wins."##),
    (r##"bgp_routes.step.confed-peer-type"##, r##"## The step
Inside a confederation, a route from another member AS wins over one from our own member AS."##),
    (r##"bgp_routes.step.igp-metric"##, r##"## The step
**IGP cost to the next hop** (RFC 4271 §9.1.2.2 e): the closer exit wins (hot-potato routing)."##),
    (r##"bgp_routes.step.local-pref"##, r##"## The step
**LOCAL_PREF** (RFC 4271 §9.1.1): the higher wins. It is the iBGP way to say which exit the AS prefers; unset counts as 100."##),
    (r##"bgp_routes.step.local-route"##, r##"## The step
A route this router originates (network, redistribute, aggregate) wins over a received one."##),
    (r##"bgp_routes.step.med"##, r##"## The step
**MED** (RFC 4271 §9.1.2.2 c): the lower wins, compared only between routes from the same neighboring AS (unless always-compare-med). A missing MED counts as 0."##),
    (r##"bgp_routes.step.neighbor-address"##, r##"## The step
**Peer address** (RFC 4271 §9.1.2.2 g): the last tie-break, the lower neighbor address wins."##),
    (r##"bgp_routes.step.not-usable"##, r##"## The step
A path the daemon cannot use (next hop unreachable, AS loop, refused) is not a candidate (RFC 4271 §9.1.2)."##),
    (r##"bgp_routes.step.older-path"##, r##"## The step
Between two eBGP routes still tied, the one already chosen stays: a newer one does not displace it, which avoids flaps (FRR, Cisco)."##),
    (r##"bgp_routes.step.origin"##, r##"## The step
**ORIGIN** (RFC 4271 §9.1.2.2 b): IGP wins over EGP, which wins over incomplete (redistributed)."##),
    (r##"bgp_routes.step.peer-type"##, r##"## The step
**eBGP over iBGP** (RFC 4271 §9.1.2.2 d): a route learned from another AS wins over one learned inside ours."##),
    (r##"bgp_routes.step.router-id"##, r##"## The step
**BGP Identifier** (RFC 4271 §9.1.2.2 f): the lower router-id wins; for a reflected route its ORIGINATOR_ID counts (RFC 4456 §9)."##),
    (r##"bgp_routes.step.stale"##, r##"## The step
A route kept from a session that is restarting (graceful restart, RFC 4724) loses to a fresh one."##),
    (r##"bgp_routes.step.weight"##, r##"## The step
**Weight** is local to this router (FRR, Cisco): the higher wins. It is never sent to peers. CoreRouter sets none unless a policy does."##),
    (r##"bgp_routes.tab.advertised"##, r##"## What it is
The routes we send this neighbor, after the outbound policy (RouterOS `advertised`, Junos `advertising-protocol`)."##),
    (r##"bgp_routes.tab.history"##, r##"## What it is
When each session went down and came back, why (the last NOTIFICATION) and how long it had been up. Kept in memory (64 per session) until the daemon restarts; a down and up between two 2 s samples shows as `flap`."##),
    (r##"bgp_routes.tab.received"##, r##"## What it is
The routes this neighbor sent us. When CoreRouter keeps its Adj-RIB-In (it does on every connection that drops RPKI-invalid routes), the list is from **before** the inbound policy, and the refused routes appear flagged `filtered`; otherwise only the accepted ones."##),
];
