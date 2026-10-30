//! English explanations of the Routing › OSPF window (G3.4), sorted by key
//! (registered by `build.rs`).

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (r##"ospf.area"##, r##"## What it is
An OSPF area (RouterOS `/routing ospf area`)."##),
    (r##"ospf.area.area_id"##, r##"## What it is
The 32-bit area id, dotted. 0.0.0.0 is the backbone."##),
    (r##"ospf.area.default_cost"##, r##"## What it is
Stub/NSSA: the cost of the default the ABR announces."##),
    (r##"ospf.area.instance"##, r##"## What it is
The instance the area belongs to."##),
    (r##"ospf.area.name"##, r##"## What it is
The area's name (templates refer to it)."##),
    (r##"ospf.area.no_summaries"##, r##"## What it is
Stub/NSSA: not even inter-area routes, just a default (totally stubby)."##),
    (r##"ospf.area.nssa_translate"##, r##"## What it is
NSSA: whether this ABR translates type-7 to type-5 (candidate: elected, RFC 3101 §3.1)."##),
    (r##"ospf.area.ranges"##, r##"## What it is
Area ranges: the area's networks summarized by the ABR (RFC 2328 §12.4.3)."##),
    (r##"ospf.area.type"##, r##"## What it is
default, stub (no externals) or nssa (externals of its own as type-7, RFC 3101). The backbone is always default."##),
    (r##"ospf.diagnose"##, r##"## What it is
Why a neighbor is not Full, from the config, the daemon's state and the packets seen, with the RFC section."##),
    (r##"ospf.disabled"##, r##"## What it is
Kept in the config, not running."##),
    (r##"ospf.frr.after"##, r##"## What it is
The path and cost after OSPF converges without the cut link."##),
    (r##"ospf.frr.backup"##, r##"## What it is
The backup next hop zebra installed (TI-LFA); in the virtual lab the computed one."##),
    (r##"ospf.frr.coverage"##, r##"## What it is
The share of OSPF routes with a backup installed (IOS-XR's fast-reroute prefix-summary)."##),
    (r##"ospf.frr.labels"##, r##"## What it is
The backup's label stack, top first: the repair segments, then the destination's SID."##),
    (r##"ospf.frr.primary"##, r##"## What it is
The primary next hop: address · interface."##),
    (r##"ospf.frr.protected"##, r##"## What it is
Whether the route has a backup ready."##),
    (r##"ospf.frr.reason"##, r##"## What it is
Why the route has no backup."##),
    (r##"ospf.frr.segments"##, r##"## What it is
The repair segments, computed as ospfd does."##),
    (r##"ospf.frr.views"##, r##"## What it is
Routes: primary and backup next hop with the label stack. Unprotected: the routes without a backup and why. Simulate Link Cut: the backup each affected route takes and the path after convergence, nothing changed."##),
    (r##"ospf.instance"##, r##"## What it is
An OSPF instance (RouterOS `/routing ospf instance`). The preview shows the interfaces it runs on and what the change does."##),
    (r##"ospf.instance.drain"##, r##"## What it is
Turns the selected instance's stub router on (Drain) or off (Undrain): `routing.ospf.instance.set {stub_router}`. Drained, every transit link of the router-LSA goes to cost 65535 and traffic goes around this router; its own networks stay reachable (RFC 6987).

## When
Before maintenance, or to bring a new router into the core without carrying traffic. In a Safe Mode or transactional session the change rolls back with the rest."##),
    (r##"ospf.instance.name"##, r##"## What it is
The instance's name."##),
    (r##"ospf.instance.originate_default"##, r##"## What it is
Announce a default route: never, if-installed (only while this router has one) or always."##),
    (r##"ospf.instance.out_filter_chain"##, r##"## What it is
The `/routing filter` chain the redistributed routes go through (prefix tests and `set bgp-med` as the external metric)."##),
    (r##"ospf.instance.redistribute"##, r##"## What it is
Routes announced into OSPF as externals: connected, static, bgp, kernel."##),
    (r##"ospf.instance.router_id"##, r##"## What it is
The router's 32-bit id in OSPF, unique in the AS.

## Recommended
A fixed one (a loopback address): changing it restarts every adjacency."##),
    (r##"ospf.instance.stub_router"##, r##"## What it is
Stub router (RFC 6987, FRR `max-metric router-lsa administrative`): the router-LSA describes every transit link (point-to-point, LAN with a DR, virtual link) at cost 65535, the loopback and passive networks at their cost. Other routers stop routing **through** this one but still reach it. OSPFv3 clears the R-bit instead: never transit, not even as the only path.

## Caveats
Cost 65535 is not infinity: where this router is the only path, traffic still crosses it (§4). A virtual link whose path crosses it goes down (errata 4685).

## Recommended
To enter the core: stub router on and the real costs on the templates, instead of cost 65535 on each one; take it off once the adjacencies, LDP and BFD are up."##),
    (r##"ospf.instance.stub_router_on_startup"##, r##"## What it is
Seconds (5–86400) as a stub router after each start of the instance (FRR `max-metric router-lsa on-startup`, counted per area from its first router-LSA). After a reboot the router forms its adjacencies and LDP comes up before it carries transit: RouterOS has no LDP-IGP sync (RFC 5443), so this is the way to avoid black-holing labelled traffic.

## Caveats
Added to an instance that already runs it waits for the next start. OSPFv2 only (ospf6d has no on-startup).

## Recommended
300 s on a core router; more if LDP takes longer to reach every neighbor."##),
    (r##"ospf.instance.subscriber_pools"##, r##"## What it is
Announce the PPPoE and IPoE address pools, each summarized into one external, withdrawn when its last subscriber goes (G4.3ce)."##),
    (r##"ospf.instance.version"##, r##"## What it is
2: OSPFv2 for IPv4 (RFC 2328). 3: OSPFv3 for IPv6 (RFC 5340)."##),
    (r##"ospf.instance.vrf"##, r##"## What it is
The VRF the instance routes in (`main` by default)."##),
    (r##"ospf.keychain"##, r##"## What it is
A key chain (several keys with windows)."##),
    (r##"ospf.keychain.keys"##, r##"## What it is
The keys: id and algorithm."##),
    (r##"ospf.keychain.name"##, r##"## What it is
The chain's name."##),
    (r##"ospf.keychain.rotation"##, r##"## What it is
Whether a rotation would drop a neighbor: a moment no key is sent, or the old key no longer accepted when the new one starts."##),
    (r##"ospf.keychain.sending"##, r##"## What it is
The key sent now (the router's clock, UTC)."##),
    (r##"ospf.keychain.used_by"##, r##"## What it is
The templates using the chain."##),
    (r##"ospf.lsa.age"##, r##"## What it is
Seconds since it was originated (refreshed every 30 min, gone at 60)."##),
    (r##"ospf.lsa.body"##, r##"## What it is
What the LSA says."##),
    (r##"ospf.lsa.id"##, r##"## What it is
The Link State ID."##),
    (r##"ospf.lsa.originator"##, r##"## What it is
The advertising router."##),
    (r##"ospf.lsa.sequence"##, r##"## What it is
The sequence number: higher is newer."##),
    (r##"ospf.lsa.type"##, r##"## What it is
router (1), network (2), summary (3), asbr-summary (4), external (5), nssa-external (7)."##),
    (r##"ospf.neighbor.address"##, r##"## What it is
The neighbor's address on the link (v3: link-local)."##),
    (r##"ospf.neighbor.interface"##, r##"## What it is
The interface the neighbor is on."##),
    (r##"ospf.neighbor.router_id"##, r##"## What it is
The neighbor's router id."##),
    (r##"ospf.neighbor.state"##, r##"## What it is
The adjacency state (RFC 2328 §10.1): Down, Init, 2-Way, ExStart, Exchange, Loading, Full; and the neighbor's role on the link (DR, BDR, DROther, ptp).

## Normal
Full with the DR and BDR; 2-Way with the others on a LAN."##),
    (r##"ospf.neighbor.uptime"##, r##"## What it is
Time in the current state (Full: the adjacency's uptime)."##),
    (r##"ospf.path"##, r##"## What it is
The shortest path to an address or router id over the LSDB, the cost added hop by hop, checked against the daemon's route."##),
    (r##"ospf.route.cost"##, r##"## What it is
The total cost (E2: the external metric, then the cost to the ASBR)."##),
    (r##"ospf.route.kind"##, r##"## What it is
intra-area, inter-area, ext-1, ext-2."##),
    (r##"ospf.route.nexthop"##, r##"## What it is
The next hop and interface."##),
    (r##"ospf.route.prefix"##, r##"## What it is
The destination."##),
    (r##"ospf.sid"##, r##"## What it is
A prefix SID of this router: the index of a loopback /32 in the SRGB (RFC 8665 §5). An index another router uses for another prefix is refused before the commit (Force takes it, for anycast)."##),
    (r##"ospf.sid.announced"##, r##"## What it is
Whether OSPF announces this loopback (an interface template of the instance takes it)."##),
    (r##"ospf.sid.behavior"##, r##"## What it is
What the hop before the last does with the label (RFC 8665 §5): php (pop, the default), no-php, explicit-null."##),
    (r##"ospf.sid.force"##, r##"## What it is
Take an index another router already announces for another prefix (anycast)."##),
    (r##"ospf.sid.index"##, r##"## What it is
The index in the SRGB, unique in the network (RFC 8402 §3.2). Empty or auto: picked."##),
    (r##"ospf.sid.interface"##, r##"## What it is
The loopback of the prefix, or where the label goes out."##),
    (r##"ospf.sid.label"##, r##"## What it is
The SID's label on a router with the same SRGB: start + index."##),
    (r##"ospf.sid.prefix"##, r##"## What it is
The /32 the SID names; FRR takes only a loopback's address."##),
    (r##"ospf.sr"##, r##"## What it is
Segment Routing of the OSPFv2 instance in VRF main (FRR runs SR there only, one per process, in every area of the instance). The preview lists what moves to labels, the short MTU, the interfaces without MPLS input and the clashing SIDs; use Safe Mode."##),
    (r##"ospf.sr.adjacencies"##, r##"## What it is
Adjacency SIDs the router announced (one per neighbor, in its SRLB)."##),
    (r##"ospf.sr.auto_sid"##, r##"## What it is
A prefix SID for every loopback /32 of the instance without one: the last octet when free, else the lowest free index."##),
    (r##"ospf.sr.conflicts"##, r##"## What it is
Clashing SIDs: one index for two prefixes, or one prefix with two indexes (RFC 8660 §2.5 leaves the fix to the operator)."##),
    (r##"ospf.sr.in_label"##, r##"## What it is
The label this router takes in for the SID."##),
    (r##"ospf.sr.instance"##, r##"## What it is
The OSPFv2 instance (VRF main) that runs SR."##),
    (r##"ospf.sr.ldp_block"##, r##"## What it is
The labels LDP uses while SR runs: outside the SR blocks (from 24000 with the defaults, as on IOS-XR)."##),
    (r##"ospf.sr.nexthop"##, r##"## What it is
The neighbor the labeled packet goes to."##),
    (r##"ospf.sr.node_msd"##, r##"## What it is
Maximum SID Depth (RFC 8476): how many labels this router pushes."##),
    (r##"ospf.sr.out_label"##, r##"## What it is
The label the packet leaves with; implicit-null (pop) when the next hop owns the SID."##),
    (r##"ospf.sr.router"##, r##"## What it is
The OSPF router id that announces it."##),
    (r##"ospf.sr.srgb"##, r##"## What it is
Segment Routing Global Block (RFC 8402 §2): the labels of the prefix SIDs (label = start + index). Default 16000-23999. It stays out of LDP's labels."##),
    (r##"ospf.sr.srlb"##, r##"## What it is
Segment Routing Local Block: the router's local labels (adjacency SIDs). Default 15000-15999."##),
    (r##"ospf.sr.ti_lfa"##, r##"## What it is
TI-LFA (RFC 9855) for the whole instance: link (the link to the next hop), node (the next-hop router; the route to it gets none) or off."##),
    (r##"ospf.sr.views"##, r##"## What it is
This Router: the configured prefix SIDs. Network SIDs: what ospfd learned, with the in and out labels. SR Routers: each router's SRGB and SRLB (amber when the SRGB differs from ours)."##),
    (r##"ospf.tab.areas"##, r##"## What it is
The areas of each instance. 0.0.0.0 is the backbone; the others connect to it through an ABR."##),
    (r##"ospf.tab.frr"##, r##"## What it is
Fast Reroute by TI-LFA (RFC 9855): FRR's ospfd computes a loop-free backup with an SR label stack for each route and zebra keeps it ready, used until OSPF converges. Needs Segment Routing and a SID on every router of the path; BFD makes the failure seen fast."##),
    (r##"ospf.tab.instances"##, r##"## What it is
One OSPF process per version (2: IPv4, 3: IPv6) and VRF: router id, redistribution and the default route."##),
    (r##"ospf.tab.keychains"##, r##"## What it is
Key chains: several keys, each with a window to be sent and to be accepted, so a key is replaced without dropping a neighbor (RFC 8177)."##),
    (r##"ospf.tab.lsdb"##, r##"## What it is
The link-state database (RouterOS `/routing ospf lsa`): every LSA the router holds, by type and area."##),
    (r##"ospf.tab.neighbors"##, r##"## What it is
The adjacencies OSPF formed (RouterOS `/routing ospf neighbor`), live. Select one and press Diagnose to see why it is not Full."##),
    (r##"ospf.tab.routes"##, r##"## What it is
The routes OSPF computed. Select one (or type an address) to see why its path is the one: the cost added hop by hop."##),
    (r##"ospf.tab.sr"##, r##"## What it is
Segment Routing MPLS over OSPFv2 (RFC 8665): each router announces an index for its loopback and every router forwards to it with the label SRGB start + index, without LDP. FRR's ospfd computes; here are the switch with its preview, this router's SIDs, the network's and the clashes."##),
    (r##"ospf.tab.templates"##, r##"## What it is
Which interfaces run OSPF and how: matched by name, interface list or network. The first template that matches an interface wins."##),
    (r##"ospf.tab.topology"##, r##"## What it is
The network as the LSDB describes it: routers, transit networks and the cost of each link. Click a router to see the path to it."##),
    (r##"ospf.template"##, r##"## What it is
An interface template (RouterOS `/routing ospf interface-template`). The preview lists the interfaces it takes now, the network type each suggests, missing authentication and the adjacencies that drop."##),
    (r##"ospf.template.area"##, r##"## What it is
The area the matched interfaces join."##),
    (r##"ospf.template.auth"##, r##"## What it is
simple, md5, sha1, sha256, sha384, sha512. sha256 is the default when only a key is given.

## Careful
simple and md5 are weak."##),
    (r##"ospf.template.auth_id"##, r##"## What it is
The key id on the wire (0..255 in v2). Must match the neighbors'."##),
    (r##"ospf.template.auth_key"##, r##"## What it is
One key, sealed at once; never shown back. Empty keeps the current one."##),
    (r##"ospf.template.bfd"##, r##"## What it is
The BFD profile that watches the adjacencies (sub-second failure detection, RFC 5882)."##),
    (r##"ospf.template.cost"##, r##"## What it is
The interface's cost (1..65535); empty: from the bandwidth."##),
    (r##"ospf.template.dead_interval"##, r##"## What it is
Seconds without a Hello before the neighbor is down (default 40). Must match."##),
    (r##"ospf.template.hello_interval"##, r##"## What it is
Seconds between Hellos (default 10). Must match the neighbors'."##),
    (r##"ospf.template.interfaces"##, r##"## What it is
Interface names or interface lists this template takes."##),
    (r##"ospf.template.keychain"##, r##"## What it is
A key chain instead of one key: rotation without a drop."##),
    (r##"ospf.template.matched"##, r##"## What it is
The interfaces this template takes now (a later template does not get them)."##),
    (r##"ospf.template.mtu_ignore"##, r##"## What it is
Accept a different MTU in the DD exchange (RFC 2328 §10.6)."##),
    (r##"ospf.template.networks"##, r##"## What it is
An interface with an address inside one of these networks matches."##),
    (r##"ospf.template.passive"##, r##"## What it is
Announce the networks but send no Hello.

## Recommended
On customer and loopback interfaces."##),
    (r##"ospf.template.priority"##, r##"## What it is
DR election priority (0: never DR)."##),
    (r##"ospf.template.type"##, r##"## What it is
broadcast (LAN, DR elected), ptp (two routers: /30, /31, PPP), nbma, ptmp, virtual-link.

## Recommended
ptp on a link with two routers: no DR election, adjacency sooner."##),
    (r##"ospf.template.warnings"##, r##"## What it is
What to look at: missing or weak authentication, a better network type, passive on a customer interface, a template hidden by an earlier one."##),
    (r##"ospf.topology.legend"##, r##"## What it is
Circles are routers (ours highlighted, neighbors green, ABR/ASBR with a ring), squares transit networks; numbers are link costs (a/b when the ends differ). Drag to pan, scroll to zoom, click a router for the path."##),
];
