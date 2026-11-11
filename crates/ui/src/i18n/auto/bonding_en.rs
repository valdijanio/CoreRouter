//! English explanations of Interfaces › Bonding (G1.30m), sorted by key.

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[(
    "bonding.wifi_slave",
    "## Wi-Fi ports in a bond

A plain Wi-Fi client (mode `station`) does not join a bond or a bridge.

- Its frames carry three addresses: the access point only passes frames from the client's own MAC.
- A bond changes the MAC of its slaves, and a bridge forwards frames from other machines: the access point would drop both.
- The kernel refuses a client in a bridge too (`IFF_DONT_BRIDGE`).

**Between two CoreRouters**, use **station-bridge** (G1.30m, coming): the link carries four addresses (Multi-AP, or WDS for OpenWrt), so it joins a bridge, and a bond on top of several of these links.

Today: route through the Wi-Fi port (with source NAT if the network behind the access point has no route back).",
)];
