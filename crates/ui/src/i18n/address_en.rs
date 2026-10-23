//! English explanations of IP › Addresses (G1.28), sorted by key.

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "ip.address",
        r##"## What it is
An IP address of one of the router's interfaces (RouterOS `/ip address`, `/ipv6 address`). Each one also makes the connected route of its network.

## Before applying
The window checks for you: the same address elsewhere, a network that overlaps another interface's (in the same VRF), whether a host on the wire already answers for it (ARP, RFC 5227), and whether the change would cut the session you manage the router through. The commands it will run are listed at the bottom.

## Careful
Removing or disabling the address you are connected through drops your session. Enter **Safe Mode** first: if the router stops hearing from you, it undoes the change."##,
    ),
    (
        "ip.address.address",
        r##"## What it is
The address and the length of its network prefix: `10.20.0.1/24`, `2001:db8::1/64`.

The network, the broadcast and how many hosts it holds are calculated below as you type.

## Careful
A bare address without `/len` would be a /32 (one host, no neighbours): write the prefix. A /31 (RFC 3021) is fine for point-to-point links."##,
    ),
    (
        "ip.address.arp",
        r##"## What it is
Before adding an IPv4 address, ask the wire whether someone already uses it: one ARP probe (RFC 5227: sender 0.0.0.0, so no cache learns it) and a short wait. In the virtual lab the lab router answers for its own address.

IPv6 needs no such check: the kernel runs Duplicate Address Detection (RFC 4862) by itself, and the list shows `tentative` meanwhile.

## Off
Uncheck it to skip the probe (one packet, up to 2 s)."##,
    ),
    (
        "ip.address.disabled",
        r##"## What it is
A disabled address stays in the configuration and leaves the data plane (the kernel): no traffic, no connected route. Enable it again with ✓.

Useful to keep a spare or an address you will move back."##,
    ),
    (
        "ip.address.from_pool",
        r##"## What it is
IPv6 only (RouterOS `from-pool`): the address is the bits after the prefix a DHCPv6 client got delegated into this pool. `::1/64` becomes `<delegated prefix>::1/64` and follows it when the ISP changes it."##,
    ),
    (
        "ip.address.interface",
        r##"## What it is
The interface (port, VLAN, bridge, bond, loopback) that gets the address. Its VRF decides the routing table the connected route goes to.

## Careful
Two interfaces in the same table with overlapping networks would claim the same hosts, and the connected route goes to only one of them: the window refuses it."##,
    ),
    (
        "ip.address.lifetime",
        r##"## What it is
For addresses that expire (SLAAC from Router Advertisements, DHCP leases): the valid lifetime, and after the slash the preferred one (RFC 4862 §5.5.4). Empty: forever (a static address)."##,
    ),
    (
        "ip.address.network",
        r##"## What it is
The network the address belongs to (the address with the host bits cleared). It is also the connected route the address creates in its interface's table."##,
    ),
    (
        "ip.address.state",
        r##"## What it says
- **active**: in the kernel and in use.
- **disabled**: kept in the configuration, out of the kernel (✓ brings it back).
- **invalid**: cannot be used: its interface is missing or disabled, or its pool has no prefix yet.
- **tentative**: IPv6 duplicate address detection is running (RFC 4862 §5.4), about a second.
- **dad-failed**: another host on the link has this IPv6 address; the kernel will not use it.
- **deprecated**: its preferred lifetime ran out (RFC 4862 §5.5.4): kept for open connections only.

An **access** chip marks the address this session depends on: removing or disabling it asks first."##,
    ),
    (
        "ip.address.to",
        r##"## What it is
Optional: the last address of a **series**. `10.20.0.1/24` to `10.20.0.5` adds five addresses, all in one transaction: all of them or none.

## Limits
Same family and inside the same network; at most 256 at a time."##,
    ),
    (
        "ip.address.vrf",
        r##"## What it is
The routing table (VRF) of the interface. Empty: the main table. Addresses in different VRFs may overlap; inside one they may not."##,
    ),
];
