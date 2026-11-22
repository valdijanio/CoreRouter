//! English explanations of Interfaces › WireGuard (G1.31a), sorted by key
//! (registered by `build.rs`).

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "menu.wireguard",
        r##"## What it does
RouterOS `/interface wireguard`: encrypted tunnels to other routers (site to site) and to notebooks and phones (remote access). Each WireGuard interface is an interface (`wg0`) that addresses, routes and firewall rules name like any other; its peers are the other ends.

## How CoreRouter does it
- The data plane is the kernel's WireGuard; the router hands it only what changed, so editing one peer never drops the others.
- Keys are made on the router and sealed in the configuration.
- Mistakes the kernel would hide are refused: a prefix two peers share, a peer with the interface's own key.
- Each peer has a state worked out from the protocol's timers: `up`, `idle`, `no-handshake`, `never`."##,
    ),
    (
        "wireguard.accept_firewall",
        r##"## What it is
When the input firewall drops UDP to the interface's port (the check says so), tick it: the same transaction adds an accept rule for the port right before the rule that drops it (the firewall assistant). Without it, peers cannot reach this interface."##,
    ),
    (
        "wireguard.disabled",
        r##"## What it is
Kept in the configuration, out of the kernel: a disabled interface takes its tunnels down; a disabled peer stops only that tunnel."##,
    ),
    (
        "wireguard.interface",
        r##"## What it is
A WireGuard interface: a UDP port where the encrypted packets arrive, a key pair, and the peers it talks to (RouterOS `/interface wireguard`).

## Before applying
The window checks the port (another interface's, a router service's), whether the input firewall lets UDP to it in from the WAN, and whether the MTU fits the WAN's minus the 80 bytes of WireGuard. The commands it will run are listed at the bottom.

## Next
Give it an address (IP › Addresses, `10.9.0.1/24`) and add its peers."##,
    ),
    (
        "wireguard.listen_port",
        r##"## What it is
The UDP port the encrypted packets arrive on. Default 13231 (RouterOS); a second interface takes the next free one.

## Careful
Peers must reach it: accept UDP to this port in the input firewall. Two interfaces cannot share a port, and a port of a router service (DNS 53, NTP 123, IPsec 500/4500…) fails while that service runs."##,
    ),
    (
        "wireguard.mtu",
        r##"## What it is
The largest packet the tunnel carries. Default 1420: 1500 minus the 80 bytes WireGuard adds over IPv6 (32 of its own, 8 of UDP, 40 of IPv6; whitepaper §5.4.6).

## When to change
Over a WAN with a smaller MTU, lower it by the same amount: over PPPoE (1492) use **1412**. Too big, and full-size packets are fragmented or lost: pages that start and stall."##,
    ),
    (
        "wireguard.name",
        r##"## What it is
The interface's name, used by addresses, routes and the firewall. Empty: the first free `wireguardN`, as RouterOS does. To rename it later, rename the interface."##,
    ),
    (
        "wireguard.peer",
        r##"## What it is
The other end of a tunnel: its public key, the prefixes it may send from and that are sent to it (Allowed Address), and where to find it (Endpoint) when this router calls first.

## Keys
Paste the peer's public key, or leave it empty: the router makes the peer's key pair, seals the private one, and later hands the client its configuration.

## Before applying
The window checks that no other peer of the interface has these prefixes (the kernel would move one away in silence), and whether the route to the endpoint would go into the tunnel itself."##,
    ),
    (
        "wireguard.peer.allowed_address",
        r##"## What it is
Prefixes this peer may send from, and that the interface sends to it (cryptokey routing): `10.9.0.2/32` for a notebook, the networks behind it for a site (`10.20.0.0/16`). Several separated by commas; IPv4 and IPv6.

## Careful
- Two peers of one interface cannot have the same prefix: the kernel would give it to the last one and the first would stop getting it. A narrower prefix inside another peer's is fine (longest match).
- It adds no route, as in RouterOS: route the peer's networks to the interface in IP › Routes.
- `0.0.0.0/0` sends this peer everything no other peer matches."##,
    ),
    (
        "wireguard.peer.client_allowed_address",
        r##"## What it is
What the client sends into the tunnel (`AllowedIPs` of its file). Empty: everything (`0.0.0.0/0, ::/0`), so all of its traffic goes through this router. Only some networks (`10.9.0.0/24, 192.168.88.0/24`): a split tunnel."##,
    ),
    (
        "wireguard.peer.client_dns",
        r##"## What it is
DNS servers written in the client's file (`DNS =`), for example this router's tunnel address. Empty: none (the client keeps its own)."##,
    ),
    (
        "wireguard.peer.client_endpoint",
        r##"## What it is
Where the client finds this router (`Endpoint =` of its file): a name (`vpn.example.com`) or an address, with `:port` or not (the interface's port then). Empty: the router's address on the WAN; behind a NAT that is a private address, so set the public name here."##,
    ),
    (
        "wireguard.peer.create_routes",
        r##"## What it is
A static route through this interface for each of the peer's prefixes that nothing routes there yet (`ip.route.add gateway=<wg>`), in the same transaction. The interface's own network and a route that already points here are skipped.

## Careful
`0.0.0.0/0` would send all the router's traffic without a narrower route into the tunnel: the window asks for an explicit yes. The routes are ordinary static routes: removing the peer does not remove them."##,
    ),
    (
        "wireguard.peer.endpoint_address",
        r##"## What it is
Where the first handshake goes: the peer's public address, or a DNS name (`vpn.example.com`) the router resolves, and resolves again when the handshake gets older than 3 minutes (the peer may have a new address). Empty: this router waits for the peer to call (a notebook or phone behind NAT). Once the peer talks, the kernel follows it when its address changes (roaming): the table then shows where it is now with the `roamed` chip.

## Careful
If a route sends the endpoint into this same interface (a default route through the tunnel), the handshake goes nowhere: add a host route to the endpoint through the WAN gateway."##,
    ),
    (
        "wireguard.peer.endpoint_port",
        r##"## What it is
The peer's UDP port (its listen port), with the endpoint address: both or neither."##,
    ),
    (
        "wireguard.peer.interface",
        r##"## What it is
The WireGuard interface this peer belongs to. A peer cannot move to another interface: remove it and add it there."##,
    ),
    (
        "wireguard.peer.last_handshake",
        r##"## What it is
When the two ends last agreed on session keys. A live tunnel does it every 2 minutes (REKEY_AFTER_TIME); past 3 minutes (REJECT_AFTER_TIME) no packet passes until the next one. `never`: not since the interface came up."##,
    ),
    (
        "wireguard.peer.name",
        r##"## What it is
A name for the peer, unique on the router (RouterOS 7.15+). Empty: the first free `peerN`."##,
    ),
    (
        "wireguard.peer.persistent_keepalive",
        r##"## What it is
Seconds between empty packets sent to the peer even with nothing to say. Off by default.

## When to set
Behind a NAT or a stateful firewall: **25 s** keeps the mapping open, so the other side can reach this end at any time. Without it, a peer that only answers looks `idle` when there is no traffic, which is normal."##,
    ),
    (
        "wireguard.peer.preshared_key",
        r##"## What it is
An extra symmetric key mixed into the handshake (whitepaper §5.2): a hedge against a future break of Curve25519, as by a quantum computer. Made on the router and sealed; both ends need it (the client configuration carries it).

## When editing
Ticked keeps the key the peer has; unticked removes it."##,
    ),
    (
        "wireguard.peer.public_key",
        r##"## What it is
The peer's public key (`wg pubkey`, 44 characters of base64 ending in `=`). It names the peer: the kernel knows peers by key, not by address.

## Empty
On a new peer, the router makes the peer's key pair (RouterOS `private-key=auto`) and keeps the private one sealed, to hand the client its configuration. When editing, an unchanged key keeps the pair."##,
    ),
    (
        "wireguard.peer.responder",
        r##"## What it is
The router never starts a handshake with this peer: it only answers (RouterOS 7.15). For a peer that should call in even when it has an endpoint."##,
    ),
    (
        "wireguard.peer.rx",
        r##"## What it is
Bytes received from this peer since the interface came up (decrypted, with the handshakes)."##,
    ),
    (
        "wireguard.peer.state",
        r##"## What it is
How the peer looks from its last handshake, by the protocol's timers (whitepaper §6.1):
- **up**: a handshake in the last 3 minutes; the tunnel carries traffic.
- **idle**: older, and nothing asks for a new one (no keepalive, no traffic): normal.
- **no-handshake**: the router tries (endpoint and keepalive, or traffic to send) and gets no answer. Usually a wrong public key on one side, or UDP blocked on the way.
- **never**: no handshake yet, and the router waits for the peer to call.
- **disabled**: the peer or its interface is disabled.

`responder`: the router only answers this peer."##,
    ),
    (
        "wireguard.peer.tx",
        r##"## What it is
Bytes sent to this peer since the interface came up (encrypted, with the handshake initiations: a peer that never answers still shows a few)."##,
    ),
    (
        "wireguard.peers",
        r##"## What it is
How many peers the interface has, and how many are `up` (a handshake in the last 3 minutes)."##,
    ),
    (
        "wireguard.private_key",
        r##"## What it is
The interface's private key (`wg genkey`). Empty: the router makes one and seals it; it is never shown again (only `export show-sensitive`, group full, shows it).

## When to set
To move a tunnel from another router keeping its key, paste it here. Typed when editing, it replaces the key: every peer must then get the new public key. To make a new pair, use Regenerate Keys… in the right-click menu."##,
    ),
    (
        "wireguard.public_key",
        r##"## What it is
The interface's public key, worked out from the private one. The peers need it: copy it from the right-click menu (Copy Public Key)."##,
    ),
    (
        "wireguard.state",
        r##"## What it is
- **running**: in the kernel with its keys and peers.
- **disabled**: kept in the configuration, out of the kernel.
- **error**: the kernel refused it (the reason shows under the table when it is selected), as a port already in use.
- **not running**: not committed yet, or the backend has no WireGuard."##,
    ),
    (
        "wireguard.tab.interfaces",
        r##"## What it is
The WireGuard interfaces: port, MTU, public key and how many peers are up. Double-click one to edit it; right-click to copy its public key, add a peer or make a new key pair."##,
    ),
    (
        "wireguard.tab.peers",
        r##"## What it is
Every peer of every WireGuard interface, with its handshake state, where it is, its prefixes and traffic. The chips filter by interface and by state; the line under the table says why the selected peer is in its state."##,
    ),
    (
        "wireguard.vrf",
        r##"## What it is
The VRF the **encrypted** packets go by (RouterOS 7.21 `vrf`; `main` = the main table): where the handshakes and the tunnel's UDP leave and arrive. It is not the VRF of the tunnel interface itself (that is the interface's own VRF, set in IP › VRF).

## How
The kernel's WireGuard socket cannot be bound to a device, so the router marks its packets with the VRF's routing mark and a rule looks that mark up in the VRF's table; both are made and removed in the same commit. To hear on the VRF's ports the router turns on `net.ipv4.udp_l3mdev_accept`.

## Careful
With it on, the router's UDP services that listen on every address (DNS, NTP...) also hear on the VRF's ports: filter them in IP › Firewall (input). The VRF needs a route to the peers' endpoints."##,
    ),
];
