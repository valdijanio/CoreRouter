//! English explanations of the Routing › BGP window (G3.2a), sorted by key
//! (registered by `build.rs`).

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (r##"bgp.connection"##, r##"## What it is
One BGP neighbor (RouterOS `/routing bgp connection`). Empty fields inherit from the templates, then the defaults. The preview shows the values in force and what the change does."##),
    (r##"bgp.connection.disabled"##, r##"## What it is
Shutdown: the session is closed with a NOTIFICATION Cease (administrative shutdown, RFC 4486/RFC 8203) and stays down; the connection stays in the config."##),
    (r##"bgp.connection.instance"##, r##"## What it is
The BGP instance (local AS and router id) this neighbor belongs to. `default` is the main routing table."##),
    (r##"bgp.connection.name"##, r##"## What it is
The connection's name; FRR gets it as the neighbor's description, which is how a live session finds its connection. Letters, digits, `-`, `_`, `.`."##),
    (r##"bgp.connection.remote_address"##, r##"## What it is
The neighbor's address (RouterOS `remote.address`), IPv4 or IPv6. One connection per address in an instance."##),
    (r##"bgp.instance.asn"##, r##"## What it is
Our AS, asplain or asdot, 4-byte (RFC 6793). Reserved values are refused."##),
    (r##"bgp.instance.disabled"##, r##"## What it is
A disabled instance stops: bgpd closes every session of its connections (Cease, administrative shutdown) and their routes are withdrawn. The instance and its connections stay in the config.

## Careful
The preview says how many sessions stop."##),
    (r##"bgp.instance.graceful_defer_time"##, r##"## What it is
After our `bgpd` starts, how long the best-path selection waits for the End-of-RIB of the neighbors that announce graceful restart before installing and announcing routes (RFC 4724 §4.1; FRR `select-defer-time`). 0..3600 s; empty: 10 s (FRR's own 360 s held the routes of a RouterOS neighbor out of the kernel for 120 s, measured).

## Careful
A neighbor that never sends End-of-RIB (RouterOS 7.25; the health check `bgp.end-of-rib` names it) holds back its routes for the whole time after every `bgpd` start. 0 does not wait: routes may change while the neighbors resend their tables."##),
    (r##"bgp.instance.graceful_notification"##, r##"## What it is
The N bit of the graceful-restart capability (RFC 8538 §2). With it on both sides, a NOTIFICATION or a hold timer expiry is handled as a restart: the neighbor's routes stay (stale) for its Restart Time; only a Hard Reset (Cease 9, and in FRR also Maximum Prefixes, Shutdown, De-configured and BFD Down) drops them at once. On by default (FRR since 8.3).

## Careful
A silent failure (power, cut link) of a restarting neighbor then keeps its routes for the hold time plus the Restart Time. Use BFD on those connections (a BFD down is a Hard Reset); the preview and the health check `bgp.gr-bfd` warn. Off: a hold expiry or a NOTIFICATION drops the routes as before RFC 8538. RouterOS 7.25 does not document RFC 8538."##),
    (r##"bgp.instance.graceful_restart_time"##, r##"## What it is
The Restart Time we announce in the graceful-restart capability (RFC 4724 §3): how long the neighbor keeps our routes (stale) after our `bgpd` dies, waiting for it to come back. Only the connections with Graceful Restart = yes announce it. 1..4095 s (12 bits); empty: 120 s.

## Recommended
Below the hold time of those connections (RFC 4724 §3; the preview warns). Longer hides a real failure: the neighbor keeps forwarding to a router that will not return.

## Other routers
FRR `bgp graceful-restart restart-time` (120), Junos `restart-time` (120), Cisco `bgp graceful-restart restart-time` (120). RouterOS 7.25 has no parameter."##),
    (r##"bgp.instance.graceful_stale_time"##, r##"## What it is
As a helper: how long we keep the routes of a neighbor that restarted, marked stale, after it comes back and before its End-of-RIB (RFC 4724 §4.2). Stale routes the neighbor did not send again are removed when its End-of-RIB arrives or when this time ends. 1..4095 s; empty: 360 s.

## Careful
A neighbor that never sends End-of-RIB (RouterOS 7.25) keeps its old routes for the whole time. FRR `bgp graceful-restart stalepath-time`, Junos `stale-routes-time` (300)."##),
    (r##"bgp.instance.hard_admin_reset"##, r##"## What it is
Whether an administrative reset (Cease 4: `routing.bgp.session.clear`) goes as a Hard Reset (RFC 8538 §3) and drops the neighbor's routes. On by default. Off: a clear of a neighbor with the N bit is graceful, its routes stay stale until it sends them again (useful to apply a policy without a traffic hole). Shutdown always drops them."##),
    (r##"bgp.instance.llgr_stale_time"##, r##"## What it is
Long-Lived Graceful Restart (RFC 9494): after the Restart Time of a graceful restart ends, the neighbor keeps our routes this much longer, marked with the `llgr-stale` community and least preferred, so any live route wins over them. 1..16777215 s (24 bits); empty: off (§5: never on by default). FRR has one value for every address family (the RFC asks for it per AFI/SAFI). It is also the most we keep of a neighbor's routes: FRR keeps the smaller of the neighbor's time and ours, so set it on both sides.

## When to use
For routes with an alternative, or that are better old than gone (VPN, a default route from two upstreams). Routes tagged `no-llgr` (Routing › Filters, `append bgp-communities no-llgr`) are never kept.

## Careful
Hop by hop, a stale more-specific route still wins over a live less-specific one (§5): traffic may go to a dead next hop for the whole time. The preview shows the worst case (hold + Restart Time + LLGR). RouterOS 7.25 does not support LLGR: FRR does not send it stale routes (§4.3)."##),
    (r##"bgp.instance.name"##, r##"## What it is
The instance's name; `default` runs in the main table, another name is a separate FRR view."##),
    (r##"bgp.instance.router_id"##, r##"## What it is
Our BGP identifier, an IPv4 address unique in the AS (RFC 6286); usually the loopback."##),
    (r##"bgp.param.afi"##, r##"## What it is
RouterOS `afi`: the address families the session carries (multiprotocol BGP, RFC 4760): `ip` (IPv4 unicast), `ipv6`, or both. Default `ip`."##),
    (r##"bgp.param.bfd"##, r##"## What it is
The BFD profile (Routing › BFD) watching this session: when BFD sees the neighbor or the path die, BGP goes down at once instead of after the hold time (FRR `neighbor … bfd profile`). Empty: inherit from the templates; none: no BFD.

## Recommended
`default` (300 ms × 3) on eBGP to an upstream; the other side needs BFD too."##),
    (r##"bgp.param.graceful_restart"##, r##"## What it is
Graceful restart (RFC 4724) as the restarting speaker: when this router's `bgpd` dies and comes back, the neighbor keeps our routes (stale) up to the instance's Restart Time (120 s by default), and our kernel keeps its routes (`zebra` leaves them). Traffic flows while `bgpd` comes back. Without it the neighbor withdraws the routes as soon as the TCP session drops (106 ms, measured against RouterOS 7.25).

## Values
`yes`: announces the restart capability with the F bit (forwarding kept). Empty: helper only (keeps the neighbor's routes when it restarts), FRR's default. `no`: not even that.

## Mind
The neighbor must be a helper (RouterOS announces `gr`). The Restart Time should be below the hold time (RFC 4724 §3; the preview warns). The timers are the instance's (Instances tab, or `routing.bgp.instance.set` with `graceful_restart_time` and `graceful_stale_time` (1..4095 s) and `graceful_defer_time` (0..3600 s, default 10: how long the best path waits for End-of-RIBs after `bgpd` starts; FRR would use 360 s)).

## With MikroTik
RouterOS 7.25 announces graceful restart but keeps none of our routes when our `bgpd` dies, and sends no End-of-RIB (measured): no gain on its side. On ours the kernel still keeps its routes."##),
    (r##"bgp.param.hold_time"##, r##"## What it is
Seconds without a message from the neighbor before the session is closed (RFC 4271 §4.2). The smaller of the two sides' values is used.

## Values
0 (infinity) or 3..65535. Default 180 s."##),
    (r##"bgp.param.keepalive_time"##, r##"## What it is
Seconds between KEEPALIVEs. Empty: a third of the hold time (RFC 4271 §10). Must be shorter than the hold time."##),
    (r##"bgp.param.local_role"##, r##"## What it is
RouterOS `local.role`: `ibgp` (same AS), `ibgp-rr` (iBGP where this router reflects routes to the neighbor, its client, RFC 4456) or `ebgp`; the `ebgp-provider`, `-customer`, `-peer`, `-rs`, `-rs-client` roles are announced in the OPEN (RFC 9234) and let both sides catch a route leak.

## Default
Empty: from the remote AS (ours → ibgp, other → ebgp)."##),
    (r##"bgp.param.max_prefix"##, r##"## What it is
The most prefixes accepted from the neighbor, per family (RouterOS `input.limit-process-routes`). Protects the router from a full table sent by mistake. Empty or 0: no limit."##),
    (r##"bgp.param.max_prefix_action"##, r##"## What it is
What happens over the limit: `shutdown` (close the session until it is cleared; default), `warning` (log only) or `restart` (close and try again after the restart time)."##),
    (r##"bgp.param.max_prefix_restart"##, r##"## What it is
Minutes before a session closed by the prefix limit is opened again (action `restart`). Default 5."##),
    (r##"bgp.param.multihop"##, r##"## What it is
The eBGP neighbor is more than one hop away (a loopback): FRR `ebgp-multihop` (TTL 255). iBGP is always multihop."##),
    (r##"bgp.param.nexthop_choice"##, r##"## What it is
RouterOS `nexthop-choice`: `default` (the protocol's rule), `force-self` (always our address, also to iBGP: FRR `next-hop-self`) or `propagate` (keep the received next hop, also to eBGP)."##),
    (r##"bgp.param.output_network"##, r##"## What it is
RouterOS `output.network`: the name of a firewall address-list (`/ip firewall address-list`) whose networks this router announces to the neighbor. Each network goes out only while a route to it exists (connected, static or OSPF), as in RouterOS; `a-b` ranges are left out.

## Careful
FRR announces per instance: the list counts for the other connections of the same family. Those that should not get it filter in the Output Filter (eBGP without one gets nothing, RFC 8212)."##),
    (r##"bgp.param.output_redistribute"##, r##"## What it is
RouterOS `output.redistribute`: the router's own routes sent to the neighbor, comma-separated: `connected`, `static` (those of `/ip route`) and `ospf`.

## Careful
Like the Output Network, it counts for the whole instance; the Output Filter picks what each neighbor gets."##),
    (r##"bgp.param.remote_as"##, r##"## What it is
The neighbor's AS (RouterOS `remote.as`), asplain (`65100`) or asdot (`1.10`), 4-byte (RFC 6793). Empty: any AS — FRR `remote-as external` (eBGP) or `internal` (iBGP), by the role.

## Refused
0 (RFC 7607), 23456 (AS_TRANS, RFC 6793), 65535 and 4294967295 (RFC 7300)."##),
    (r##"bgp.param.tcp_md5_key"##, r##"## What it is
The TCP MD5 signature key (RFC 2385), the same on both sides; RouterOS `tcp-md5-key`. Stored sealed: it never appears in the config, the history, the journal, the logs or MCP.

## Editing
Empty keeps the key; the CLI clears it with `tcp_md5_key=""`."##),
    (r##"bgp.param.templates"##, r##"## What it is
Templates to inherit from, comma-separated, first wins. A value set here always wins over the templates."##),
    (r##"bgp.param.update_source"##, r##"## What it is
RouterOS `local.address`: the address (or interface) the TCP session leaves from — a loopback for iBGP between routers."##),
    (r##"bgp.session.bfd"##, r##"## What it is
BFD's state for the neighbor (RFC 5880/5882), when BFD watches it: it detects a dead link in a fraction of a second, long before the hold time."##),
    (r##"bgp.session.flaps"##, r##"## What it is
Times the session went down after being established. A count that grows points to a flapping link or neighbor."##),
    (r##"bgp.session.gr"##, r##"## What it is
This router's graceful-restart role with the neighbor (RFC 4724): `restart` (restarts without the neighbor withdrawing the routes), `helper` (only keeps the neighbor's routes when it restarts), `disable`. `EoR`: the neighbor sent its End-of-RIB (§2), its table is complete. `no EoR` (amber): we are `restart` and the neighbor never sent End-of-RIB; RouterOS 7.25 does so (measured): it announces the capability and sends no marker, and it does not keep our routes when our `bgpd` dies either. After a `bgpd` start its routes wait for the instance's Defer Time (10 s)."##),
    (r##"bgp.session.last_error"##, r##"## What it is
The last NOTIFICATION sent or received (RFC 4271 §4.5), or why the session last went down ("Reached received prefix count": the prefix limit)."##),
    (r##"bgp.session.messages"##, r##"## What it is
BGP messages received and sent (OPEN, UPDATE, KEEPALIVE, NOTIFICATION, ROUTE-REFRESH)."##),
    (r##"bgp.session.policy"##, r##"## What it is
The route-map applied in each direction. Without one, an eBGP session accepts and sends nothing (RFC 8212, on by default); policies come with G3.2b."##),
    (r##"bgp.session.prefixes_in"##, r##"## What it is
Prefixes accepted from the neighbor, all families. With eBGP and no policy it stays 0 (RFC 8212)."##),
    (r##"bgp.session.prefixes_out"##, r##"## What it is
Prefixes sent to the neighbor, all families."##),
    (r##"bgp.session.remote_id"##, r##"## What it is
The neighbor's BGP identifier (its router id), from its OPEN."##),
    (r##"bgp.session.state"##, r##"## What it is
The session's state (RFC 4271 §8.2.2): `established` is up; `idle`, `connect`, `active`, `opensent` and `openconfirm` are on the way (or failing); `disabled` is shut down; `no daemon` means no routing daemon is attached (virtual lab)."##),
    (r##"bgp.session.timers"##, r##"## What it is
The negotiated hold time and keepalive (the smaller hold of the two sides, RFC 4271 §4.2); before the session is up, the configured ones."##),
    (r##"bgp.session.uptime"##, r##"## What it is
How long the session has been established."##),
    (r##"bgp.tab.connections"##, r##"## What it is
The neighbors, as RouterOS `/routing bgp connection`: address, AS, role and the templates each one inherits from. A change goes to FRR as only the lines that changed: the other sessions stay up."##),
    (r##"bgp.tab.instances"##, r##"## What it is
Our side: the local AS (4 bytes, RFC 6793), the router id and the graceful-restart timers (RFC 4724). Connections belong to an instance (`default`). Double click edits; the preview says what a change does to the sessions (a new AS or router id resets them)."##),
    (r##"bgp.tab.sessions"##, r##"## What it shows
The BGP sessions FRR runs now, one per connection, as RouterOS `/routing bgp session` (read-only, live every 2 s): state, uptime, prefixes received and sent, BFD. Select one for its last error, timers, policies, flaps and the actions Refresh, Resend, Clear and Shutdown."##),
    (r##"bgp.tab.templates"##, r##"## What it is
Shared parameters, as RouterOS `/routing bgp template`. A connection lists templates; each parameter it leaves empty comes from the first template that sets it, and a template may list parents of its own (loops are refused)."##),
    (r##"bgp.template"##, r##"## What it is
Parameters shared by many connections (RouterOS `/routing bgp template`). A change reaches every connection that inherits the value; the preview lists them and refuses a change that would make one invalid."##),
    (r##"bgp.template.name"##, r##"## What it is
The template's name, as connections and other templates list it. A rename follows everywhere it is listed."##),
    (r##"bgp.template.used_by"##, r##"## What it is
The connections and templates that list this template: who changes when it changes. A template in use cannot be removed."##),
];
