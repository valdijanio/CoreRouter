//! English explanations of the station-bridge and peers of Interfaces ›
//! Wi-Fi (G1.30m), sorted by key.

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "interface.wifi.bridge_protocol",
        r##"## Bridge Protocol (station-bridge)
How the station-bridge agrees on four-address frames with the access point.

- **multi-ap** (the default): Wi-Fi EasyMesh backhaul. The association says so, and the access point gives four addresses. Between CoreRouters, and with EasyMesh access points.
- **wds**: plain four-address frames, on from the start, no negotiation. For OpenWrt (`option wds 1`) and others that speak WDS.

Neither talks to MikroTik's `station-bridge`, which is its own and only between RouterOS."##,
    ),
    (
        "interface.wifi.peer.airtime",
        r##"## Airtime
The share of the air the peer's link took between the last two reads (2 s apart): frames sent and received, from the driver's airtime counters. Amber from 60 %, red from 85 %: the channel is close to full, and the link will not go faster there (another channel, or another link in the bond)."##,
    ),
    (
        "interface.wifi.peer.link",
        r##"## Link
Where the peer's link goes: a bridge (the LAN reaches the other router) or a bond (several links between the same two routers, G1.30m part 2)."##,
    ),
    (
        "interface.wifi.peer.mac",
        r##"## MAC Address
The other router's station-bridge radio. Only a registered MAC gets four addresses; any other station that asks is sent away."##,
    ),
    (
        "interface.wifi.peer.name",
        r##"## Name
The peer's link is an interface with this name (type `wifi-peer`), there while the peer is associated: put it in a bridge or a bond like any port. While the peer is away, its configuration waits, as an unplugged port's does."##,
    ),
    (
        "interface.wifi.peer.radio",
        r##"## Radio
The access point the peer joins. It must take station-bridges: Station Bridge `yes` or `only`."##,
    ),
    (
        "interface.wifi.peer.state",
        r##"## State
- **up**: associated, its four-address link is there.
- **away**: not associated; its configuration waits for it.
- **disabled**: registered and turned off."##,
    ),
    (
        "interface.wifi.peers",
        r##"## Peers
The station-bridges of other routers this router's access points take: a point-to-point (or point-to-multipoint) Wi-Fi link that carries the LAN, with four-address frames.

Each peer is an interface of its own. Two links between the same two routers go in a bond, not both in a bridge: the bridges here run no spanning tree, and two would make a loop.

The backhaul is WPA3 only (SAE, protected management frames)."##,
    ),
    (
        "interface.wifi.station_bridge",
        r##"## Station Bridge (access point)
Whether this access point takes station-bridges, the other routers' links:

- **no** (the default): clients only; nobody gets four addresses.
- **yes**: clients and the registered peers (Peers tab).
- **only**: the registered peers only (a backhaul access point; Multi-AP stations only).

With yes or only, the access point is WPA3 for the peers, and only the registered MACs get four addresses."##,
    ),
];
