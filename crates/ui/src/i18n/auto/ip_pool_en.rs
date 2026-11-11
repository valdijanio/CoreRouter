//! English explanations of IP › Pool (G4.2i), sorted by key.

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "ip_pool.used",
        "## Used

Addresses of the pool in use now: the DHCP server's leases bound or on offer, plus the PPP sessions (PPPoE) that took their address from this pool. Conflicts and declined addresses are held apart and are not available either.

The percent chip turns amber from 80 %.",
    ),
    (
        "ip_pool.used.address",
        "## Address

The address handed out. With Settings › Subscriber identity on, the subscriber's name goes next to it.

One address on two rows is a **conflict**: a DHCP lease and a PPP session hold it.",
    ),
    (
        "ip_pool.used.info",
        "## Info

Who holds the address: for DHCP, the client's MAC and host name; for IPoE, the login too; for PPP, the user and the MAC (and the VLAN it came in on). A conflict adds who else holds it.",
    ),
    (
        "ip_pool.used.owner",
        "## Owner

The service that took the address, as `owner` in RouterOS's `/ip pool used`: the DHCP server (chip **DHCP**, or **IPoE** when the server makes subscriber sessions) or the PPP server (chip **PPP**).

The Owner filter asks the router for one kind only: with thousands of subscribers the list is a page (the first 10 000 by address) and the count says how many there are.",
    ),
    (
        "ip_pool.used.pool",
        "## Pool

The pool the address came from. A DHCP lease belongs to the pool whose ranges hold it; a PPP session to the pool it took the address from (after `next_pool`, the one that had room).",
    ),
    (
        "ip_pool.used.state",
        "## State

- **bound**: a DHCP client holds it.
- **offered**: offered, waiting for the client's REQUEST.
- **active**: a PPP session up holds it.
- **declined**: a client said the address was taken (DHCPDECLINE).
- **conflict**: someone else answers on it (ARP), or a DHCP lease and a PPP session hold it at once. The second kind comes from one pool used by the DHCP server and by a PPP profile: the two hand out addresses apart. Give each its own pool (the pool shows the **DHCP + PPP** check).",
    ),
    (
        "ip_pool.used_tab",
        "## Used Addresses

Every address of the pools in use, with who took it: the DHCP server's leases and the PPP sessions, as `/ip pool used` in RouterOS. A pool is shared, so the Pool window sits straight under IP, not inside DHCP.

Command: `ip.pool.used.print` (`pool`, `owner`, `find` and `limit` narrow it).",
    ),
];
