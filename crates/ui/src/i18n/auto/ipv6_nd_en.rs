//! English explanations of IPv6 › ND (G3.9ha), sorted by key (registered
//! by `build.rs`).

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (r##"ipv6_nd"##, r##"## What it is
One `/ipv6 nd` entry (RouterOS v7): the router sends Router Advertisements (RFC 4861 §6.2) on the interface, so hosts and routers behind it autoconfigure (SLAAC, RFC 4862) and take it as their IPv6 gateway. Linux never sends RAs itself.

## Careful
`all` leaves out the WAN (DHCPv6 client, RA accepted, default route), PPPoE server ports (the BNG advertises per session), bridge and bond ports and interfaces without a prefix. Unlike RouterOS, a new config has no `all` entry."##),
    (r##"ipv6_nd.advertise_dns"##, r##"## What it is
DNS servers (RDNSS, RFC 8106 §5.1) and search domains (DNSSL, §5.2) in the RA. From this entry's list; else this router (a global address of the interface) when it answers queries; else the IPv6 servers of `/ip dns` and those DHCPv6 learned. Lifetime 3 × the maximum interval; 0 in the final RA."##),
    (r##"ipv6_nd.advertise_mac_address"##, r##"## What it is
The Source Link-Layer Address option (RFC 4861 §4.6.1, SHOULD): the port's MAC in the RA. Default on."##),
    (r##"ipv6_nd.autonomous"##, r##"## What it is
A flag: hosts build an address in the prefix (SLAAC, RFC 4862 §5.5.3)."##),
    (r##"ipv6_nd.detail"##, r##"## What it is
Why the interface was left out, the last send error, or the disagreement with another router."##),
    (r##"ipv6_nd.disabled"##, r##"## What it is
Kept in the config, no RA. Disabling sends the final RA with Router Lifetime 0 (RFC 4861 §6.2.5): hosts drop the default route at once."##),
    (r##"ipv6_nd.dns"##, r##"## What it is
The DNS servers to announce (at most 8), comma-separated. Empty: automatic."##),
    (r##"ipv6_nd.dnssl"##, r##"## What it is
Search domains (DNSSL, RFC 8106 §5.2), at most 8."##),
    (r##"ipv6_nd.flags"##, r##"## What it is
The RA's M (addresses by DHCPv6) and O (other settings by DHCPv6) flags (RFC 4861 §4.2)."##),
    (r##"ipv6_nd.hop_limit"##, r##"## What it is
The Cur Hop Limit hosts use (RFC 4861 §4.2). Default 64; 0: unspecified."##),
    (r##"ipv6_nd.interface"##, r##"## What it is
Where the RA goes: an interface, or `all` (every LAN-looking interface with a prefix). One entry per interface; an interface's own entry wins over `all`.

## Careful
Never advertise on the WAN. An explicit entry there is accepted with a warning."##),
    (r##"ipv6_nd.managed"##, r##"## What it is
M flag: hosts get addresses from DHCPv6 (IA_NA)."##),
    (r##"ipv6_nd.mtu"##, r##"## What it is
The MTU option (RFC 4861 §4.6.4). Empty or `unspecified`: no option. At least 1280 (RFC 8200 §5)."##),
    (r##"ipv6_nd.on_link"##, r##"## What it is
L flag: the prefix is on the link."##),
    (r##"ipv6_nd.origin"##, r##"## What it is
`address`: from a /64 address of the interface. `dhcp-pd`: from an address taken from the DHCPv6-PD prefix; lifetimes follow the delegation, capped at 5400/2700 s (RFC 9096 §3.4). `static`: added here. `deprecated`: left the RA, still sent with lifetimes 0 (RFC 9096 §3.5)."##),
    (r##"ipv6_nd.other"##, r##"## What it is
O flag: hosts get other settings (DNS, domain) from stateless DHCPv6 (RFC 8415 §6.1)."##),
    (r##"ipv6_nd.port"##, r##"## What it is
An interface some entry reaches: sending, or left out with the reason."##),
    (r##"ipv6_nd.port_state"##, r##"## What it is
`sending`, `waiting` (link-local still in DAD, sender stopped), `failed` (see Detail), `skipped` (WAN, PPPoE port, no prefix), `conflict` (another router on the link sends different values, RFC 4861 §6.2.7)."##),
    (r##"ipv6_nd.ports"##, r##"## What it is
Every interface the entries reach, with the send state, prefixes, counters and why the others were left out."##),
    (r##"ipv6_nd.preferred_lifetime"##, r##"## What it is
Preferred Lifetime, default 1w, never above the valid one. 0: deprecated."##),
    (r##"ipv6_nd.prefix"##, r##"## What it is
The advertised prefix. SLAAC needs a /64 (RFC 4862 §5.5.3, RFC 2464 §4)."##),
    (r##"ipv6_nd.prefix_disabled"##, r##"## What it is
Kept in the config, left out of the RA. A disabled static prefix also hides the dynamic one from the address."##),
    (r##"ipv6_nd.prefix_flags"##, r##"## What it is
L (on-link) and A (autonomous, SLAAC) of the Prefix Information option."##),
    (r##"ipv6_nd.prefix_interface"##, r##"## What it is
The interface whose RA carries the prefix; it needs an `/ipv6 nd` entry (or `all`)."##),
    (r##"ipv6_nd.prefixes"##, r##"## What it is
The prefixes of the RA (Prefix Information, RFC 4861 §4.6.2). Dynamic ones come from each global /64 address of the interface; static ones are added here and replace (or, disabled, hide) a dynamic one with the same prefix. A prefix that leaves goes out three more times with lifetimes 0 (RFC 9096 §3.5)."##),
    (r##"ipv6_nd.ra_delay"##, r##"## What it is
The least time between two multicast RAs (MIN_DELAY_BETWEEN_RAS, RFC 4861 §10; default 3 s)."##),
    (r##"ipv6_nd.ra_interval"##, r##"## What it is
MinRtrAdvInterval-MaxRtrAdvInterval (RFC 4861 §6.2.1), default 3m20s-10m: each unsolicited RA goes out at a random time in the range. Max 4s..18h12m15s (RFC 8319); min at least 3 s and at most 0.75 × max. Up to 3 RAs at most 16 s apart when an interface starts or its RA changes (§6.2.4)."##),
    (r##"ipv6_nd.ra_lifetime"##, r##"## What it is
Router Lifetime (RFC 4861 §4.2), default 30m: how long hosts use this router as their default gateway. 0: not a default router. Otherwise from the maximum interval to 18h12m15s (RFC 8319)."##),
    (r##"ipv6_nd.ra_preference"##, r##"## What it is
Default Router Preference (RFC 4191 §2.2): with two routers on a link, hosts prefer `high`. Default `medium`."##),
    (r##"ipv6_nd.ra_sent"##, r##"## What it is
RAs sent on the interface since the daemon started."##),
    (r##"ipv6_nd.rdnss"##, r##"## What it is
The DNS servers this interface's RA carries now (RDNSS), resolved."##),
    (r##"ipv6_nd.reachable_time"##, r##"## What it is
Reachable Time, ms (RFC 4861 §6.3.2). 0: unspecified. At most 1 h."##),
    (r##"ipv6_nd.retransmit_interval"##, r##"## What it is
Retrans Timer, ms (RFC 4861 §6.3.2). 0: unspecified."##),
    (r##"ipv6_nd.rs_received"##, r##"## What it is
Valid Router Solicitations received (RFC 4861 §6.1.1). Each is answered within 0.5 s by a multicast RA, never sooner than `ra-delay` after the last one (§6.2.6)."##),
    (r##"ipv6_nd.sender"##, r##"## What it is
The daemon's RA sender: one thread and one raw ICMPv6 socket for every interface. Runs with `--backend linux` only."##),
    (r##"ipv6_nd.state"##, r##"## What it is
How many interfaces the entry advertises on (`advertising`; whether the RA went out is in Interfaces reached), how many were left out (the reason is in Interfaces reached), and whether there is a warning."##),
    (r##"ipv6_nd.tab_interfaces"##, r##"## What it is
The `/ipv6 nd` entries: where RAs go and with which values."##),
    (r##"ipv6_nd.tab_prefixes"##, r##"## What it is
`/ipv6 nd prefix`: the prefixes in each interface's RA."##),
    (r##"ipv6_nd.valid_lifetime"##, r##"## What it is
Valid Lifetime (RFC 4861 §4.6.2), default 4w2d; `infinity`: forever. Hosts never shorten a known prefix below 2 h from an RA (RFC 4862 §5.5.3 e)."##),
    (r##"menu.ipv6-nd"##, r##"## What it does
Router Advertisements (`/ipv6 nd`): the router announces the LANs' prefixes so hosts and routers behind it do SLAAC and use it as their IPv6 gateway. Linux sends no RAs itself."##),
];
