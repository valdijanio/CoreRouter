//! English explanations of PPP › PPPoE Client (G3.9ga), sorted by key
//! (registered by `build.rs`).

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "interface.pppoe-client",
        r##"## What it is
A PPPoE client: the router dials the provider's PPPoE server (RFC 2516) over an Ethernet port or VLAN and gets its address and DNS through the session (RouterOS `/interface pppoe-client`).

## Before applying
The window checks for you: another default route (static, DHCP client, another PPPoE) at the same distance, which would share the traffic; no default route at all; an MTU above 1492 (RFC 4638 only). The commands it will run are listed at the bottom.

## Careful
Changing the port you manage the router through can drop your session: use **Safe Mode**."##,
    ),
    (
        "interface.pppoe-client.ac_name",
        r##"## What it is
Only offers from the access concentrator with this name. Empty: the first offer. Useful on a segment with more than one BNG."##,
    ),
    (
        "interface.pppoe-client.add_default_route",
        r##"## What it is
Install the default route (0.0.0.0/0) through the session while it is up. Default **no**, as RouterOS: turn it on for a provider uplink.

## Careful
If another uplink (DHCP client, another PPPoE, a static route) adds a default route at the **same distance**, both share the traffic (ECMP). For a backup link, give it a higher distance."##,
    ),
    (
        "interface.pppoe-client.address",
        r##"## What it is
The address the provider gave through the session (IPCP) and, after `peer`, the server's on the other side. Both also show in IP › Addresses and IP › Routes as dynamic entries."##,
    ),
    (
        "interface.pppoe-client.allow",
        r##"## What it is
The login methods accepted: `mschap2`, `mschap1`, `chap`, `pap`. Default all, as RouterOS; the server picks among them.

## Careful
`pap` sends the password in clear on the provider's network: drop it if the server takes CHAP."##,
    ),
    (
        "interface.pppoe-client.default_route_distance",
        r##"## What it is
The default route's distance (preference): lower wins. Default 1. On a backup link, use more than the main one's (2)."##,
    ),
    (
        "interface.pppoe-client.disabled",
        r##"## What it is
Disabled, the client stays in the configuration but does not dial. Disabling it ends the session on the provider at once (PADT)."##,
    ),
    (
        "interface.pppoe-client.interface",
        r##"## What it is
The Ethernet port, VLAN, bond or bridge the router looks for the PPPoE server on (the PADI is broadcast there).

## When to change
Many fibre providers deliver PPPoE in a VLAN (10, 600…): create the VLAN in Interfaces and pick it here."##,
    ),
    (
        "interface.pppoe-client.keepalive_timeout",
        r##"## What it is
Seconds without an answer to LCP echoes before the session is taken as down. Default 60 s (RouterOS); an echo goes every third of it. `disabled` turns it off.

## Careful
Too short drops the session under congestion; too long is slow to notice the provider is gone."##,
    ),
    (
        "interface.pppoe-client.max_mru",
        r##"## What it is
The largest packet the router accepts from the session (the MRU offered in LCP). Default 1460, as max-mtu."##,
    ),
    (
        "interface.pppoe-client.max_mtu",
        r##"## What it is
The largest packet the router sends through the session. Default 1460 (RouterOS). PPPoE takes 8 bytes of the Ethernet frame, so 1492 is the usual most (RFC 2516 §7).

## When to change
Above 1492 (up to 1500) only if the provider accepts RFC 4638 (PPP-Max-Payload) and the path to it carries bigger frames."##,
    ),
    (
        "interface.pppoe-client.name",
        r##"## What it is
The session's interface name, what firewall rules, routes and the DHCPv6 client use. Empty: the first free `pppoe-out1`, `pppoe-out2`… (as RouterOS)."##,
    ),
    (
        "interface.pppoe-client.password",
        r##"## What it is
The provider's password. CHAP and MS-CHAP need it in clear, so the router keeps it sealed (encrypted with a key outside the configuration); the list shows `***` and only group full sees it (show_sensitive).

When editing, leave it empty to keep the current one."##,
    ),
    (
        "interface.pppoe-client.profile",
        r##"## What it is
The session's PPP profile (`/ppp profile`). The client uses its `change-tcp-mss` (lower the MSS of TCP SYNs to the session's MTU, IPv4 and IPv6; on in `default`) and `use-ipv6` (IPv6CP for the link-local; the prefix comes from the DHCPv6 client on the interface)."##,
    ),
    (
        "interface.pppoe-client.service_name",
        r##"## What it is
The Service-Name asked for in the PADI (RFC 2516 §5.1). Empty: any server. Fill it only if the provider asks, or with several PPPoE servers on the segment."##,
    ),
    (
        "interface.pppoe-client.status",
        r##"## What it is
The session's state: **connected** (up, with an address); **dialing / connecting / authenticating** (negotiating); **disconnected** (went down or did not come up: the amber chip says why, and the row when it dials again); **disabled**.

## The wait between attempts
It grows from 1 s to 60 s, with some spread so clients do not redial together; when the provider refuses the password, at least 30 s, so a wrong password does not hammer its BNG. **Reconnect** dials at once."##,
    ),
    (
        "interface.pppoe-client.uptime",
        r##"## What it is
How long the session has been up."##,
    ),
    (
        "interface.pppoe-client.use_peer_dns",
        r##"## What it is
Use the DNS servers the provider sends in the negotiation (IPCP, RFC 1877) as dynamic servers of `/ip dns`. Default **no**, as RouterOS."##,
    ),
    (
        "interface.pppoe-client.user",
        r##"## What it is
The user name the provider gave (often `customer@provider`), sent with PAP, CHAP or MS-CHAP as the server asks."##,
    ),
    (
        "menu.pppoe-client",
        r##"## What it does
RouterOS `/interface pppoe-client`: the router dials the provider's PPPoE server and uses the session as its WAN. Each client is an interface (`pppoe-out1`) that firewall rules, routes and the DHCPv6 client name like any other.

CoreRouter's own dialer: RouterOS v7 names and defaults; redial with a growing wait (1 s to 60 s, at least 30 s after a refused login, so the provider's BNG is not hammered); after a reboot it closes the previous session on the BNG (PADT) before dialing again."##,
    ),
];
