//! English explanations of Tools › Network Simulator (G3.7b), sorted by
//! key (registered by `build.rs`).

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (r##"netsim.badge"##, r##"## What it is
A simulation: virtual routers in this router's memory, running simplified OSPF, BGP and BFD on a virtual clock. Nothing here is applied to this router or to the network, and it is gone when the daemon restarts.

## What it is for
Seeing what a failure or a change does **before** doing it: which routes move, how long it takes, how many prefixes are lost. Never a replacement for FRR in production."##),
    (r##"netsim.clock"##, r##"## What it is
The virtual clock. ⏯ plays and pauses, ⏭ runs to the next instant something happens, ⏮ starts the preset again at t = 0, ×N is how many virtual seconds pass per second.

## Good to know
Same seed, same commands: the same run, every time (it can become a test)."##),
    (r##"netsim.editor"##, r##"## What it is
Add a router (its own AS, a loopback and a BGP instance) or a link between two routers. A link gets a /30 typed into both routers, runs OSPF, and eBGP comes with it when the two ASes differ."##),
    (r##"netsim.link"##, r##"## What it is
A point-to-point link. **Cut** drops everything silently (both ports stay up: only BFD, hellos or the BGP hold timer notice). **Carrier down** takes both ports down at once. **Restore** repairs it. Cost is the OSPF cost of both ends; BFD (300 ms × 3) makes a cut visible in under a second."##),
    (r##"netsim.node"##, r##"## What it is
A virtual router: a CoreRouter of its own, with the same commands and validations. Its routes, OSPF neighbors and BGP sessions as the simulation has them now. **Router down** hangs it (its neighbors notice by BFD, hellos or hold timer); **Router up** boots it."##),
    (r##"netsim.presets"##, r##"## What it is
Ready topologies: **square** (an ISP of three routers with OSPF and iBGP, plus an upstream with eBGP), **ring**, **mesh**, **star** and **grid** (each router its own AS, eBGP on every link, OSPF for the loopbacks), up to 500 routers."##),
    (r##"netsim.timeline"##, r##"## What it is
What the protocols did and when, in virtual time: the fault, BFD, OSPF adjacencies and SPF, BGP sessions and best-path changes. The line on top sums up the last fault: when it was detected, when OSPF and BGP were done, and how many prefixes were lost."##),
    (r##"netsim.topology"##, r##"## What it is
Routers as chips (coloured by AS), links coloured by state: green OSPF Full, amber OSPF not up yet, blue eBGP only, red dashed cut, grey dashed carrier down. The number on a link is its OSPF cost. Click a router or a link to see it and act on it."##),
    (r##"netsim.whatif"##, r##"## What it is
Adds a virtual router with **this** router's addresses, BGP instance, templates, connections and routing filters (typed in as commands; the TCP MD5 key is not copied). Link virtual routers to its interfaces and try a cut or a cost change before doing it in production."##),
];
