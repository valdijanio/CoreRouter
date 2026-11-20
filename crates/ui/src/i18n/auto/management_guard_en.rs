//! English explanations of Routing › Management Guard (G3.4z), sorted by
//! key (registered by `build.rs`).

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (r##"management_guard"##, r##"## What it is
A network the router is managed from. No routing protocol may install a route inside it that is longer than it: an OSPF or BGP /32 inside the management /24 wins over the connected route (longest match, RFC 1812 §5.2.4.3) and takes the replies to the operator out of another port.

## How it works
The routing daemon refuses those routes from every protocol (FRR zebra `ip protocol any route-map`). They stay in the protocol's own table as inactive, and the link-state database is untouched (RFC 2328 §2). Connected and static routes are never refused.

## Careful
A host that really sits behind another router inside this network is refused as well: guard only the networks you manage from."##),
    (r##"management_guard.disabled"##, r##"## What it is
Kept in the config, not applied: learned routes inside the network go back to the kernel. Disabling the guard of your own session's network while a learned route covers you is refused as a lockout (use Safe Mode or force)."##),
    (r##"management_guard.interface"##, r##"## What it is
The port of the connected network with this address. Empty: the network is not connected here (it still refuses the learned routes inside it, for management reached through a static route)."##),
    (r##"management_guard.network"##, r##"## What it is
The management network, as on the port: `192.168.0.0/24`. Host bits are cleared. Learned prefixes inside it and longer (/25 to /32) are refused; the network itself and anything shorter are not, since the connected route wins over them anyway.

## Recommended
The networks under Management networks not guarded: the ones your sessions come from."##),
    (r##"management_guard.refused"##, r##"## What it is
Learned routes inside the network that the routing daemon holds and keeps out of the kernel, by protocol, read from its routing table (every 10 s while the window is open). `in kernel`: some are still installed (the guard is not applied yet)."##),
    (r##"management_guard.route_warning"##, r##"## What it is
A route learned by OSPF, BGP or another protocol is more specific than the connected network an operator manages from: the replies to that session leave by another port, and the session may already be gone.

## What to do
Protect the network (Routing › Management Guard, or the command in the tooltip), or filter the prefix on the neighbor that announces it. If the session is gone, come in through another network or the console."##),
    (r##"management_guard.sessions"##, r##"## What it is
Open management sessions (GUI, terminal, MCP, CLI over the network) whose peer is inside this network. Loopback sessions are not counted: no route can take them."##),
    (r##"management_guard.state"##, r##"## What it is
- `active`: the routing daemon runs it.
- `not-applied`: in the candidate, not committed yet.
- `disabled`: kept in the config only.
- `covered`: a learned route takes the replies to a session inside it now.
- `in kernel`: learned routes inside it are installed."##),
    (r##"management_guard.suggest"##, r##"## What it is
The connected networks your open management sessions come from, not guarded yet. Protect adds the network in one step (`routing.management-guard.add`)."##),
    (r##"menu.management-guard"##, r##"## What it does
Keeps learned routes (OSPF, BGP) from taking the management network: the router refuses a prefix inside it longer than it, and warns when a learned route covers an open session."##),
];
