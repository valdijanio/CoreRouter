//! English explanations of Interfaces › Bonding (G1.30m), sorted by key.

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[(
    "bonding.wifi_slave",
    "## Wi-Fi ports in a bond

A plain Wi-Fi client (mode `station`) does not join a bond or a bridge.

- Its frames carry three addresses: the access point only passes frames from the client's own MAC.
- A bond changes the MAC of its slaves, and a bridge forwards frames from other machines: the access point would drop both.
- The kernel refuses a client in a bridge too (`IFF_DONT_BRIDGE`).

**Between two CoreRouters**, use **station-bridge** (G1.30m): the link carries four addresses (Multi-AP, or WDS for OpenWrt). A radio in `station-bridge` mode, and on the other router its peer's link (Interfaces › Wi-Fi › Peers), show among the slaves above like ports.

- **802.3ad** (LACP; the other end too) or **active-backup** suit Wi-Fi; **balance-rr** reorders TCP over links whose rates differ.
- The bond gives its slaves one MAC: on the station side, register the bond's MAC as the peers' MAC on the access point; on the access point side, the access points of one bond's peers share a MAC (the first's).

A plain Wi-Fi client: route through it (with source NAT if the network behind the access point has no route back).",
)];
