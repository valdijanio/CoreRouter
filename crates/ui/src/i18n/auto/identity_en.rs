//! English explanations of the subscriber chip (G0.25), sorted by key.

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "identity.chip",
        "## Subscriber identity

A chip with the subscriber's name next to an IP address, in the windows that list addresses (Connections, Torch, Traffic Flow, CGNAT › Who Was, DHCP leases, MTR).

- The chip shows the **first name found**, in the order of the sources; the other different names are **+N**.
- Hover it for **every name**, each with its source (and the MAC, list or zone).
- **Click** it to open the item the name comes from: the lease, the address, the address list entry or the PTR record.
- A public IP **with a port** goes through CGNAT: the chip shows the subscriber that had that port (the RFC 7422 mapping).

**Privacy:** the router only shows what is already in its config (comments, lease host names, PTRs of its own zones). Nothing is looked up on the network.

Command: `ip.identity.lookup`. A preference of this computer, not of the router.",
    ),
    (
        "identity.enabled",
        "## Show the subscriber's name

Turns the chip on or off in every window. Off, no name is asked for.

Names are asked in batches (up to 1024 addresses at a time) and kept for 30 s; the router answers from memory, with no disk or network access.",
    ),
    (
        "identity.places",
        "## Show in

The windows that show the chip. Useful to keep names out of a screenshot or a presentation.",
    ),
    (
        "identity.sources",
        "## Sources, in order

Where the name comes from, in the order the router looks. The first source with a name is the chip; the others are in the tooltip.

- **PPPoE login** — the user of the PPPoE session holding the IP (comes with the PPPoE server, G4.3).
- **Static lease comment** — the comment of a `/ip dhcp-server lease` without the D flag. At an instant (Who Was), only if the lease's MAC is the one that held the IP then.
- **Lease host name** — the name the client sent by DHCP (option 12/81). At an instant, from the lease history.
- **IP › Addresses comment** — the router's address and the hosts of a small network (/29 or smaller: a dedicated customer's /30 or /31). A LAN's /24 does not name every host.
- **Address list comment** — entries of up to 256 addresses.
- **PTR of own zones** — the PTR record of one of the router's `in-addr.arpa`/`ip6.arpa` zones.

Untick a source not to use it.",
    ),
];
