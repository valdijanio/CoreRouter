//! English explanations of the NTP windows (G4.6b), scope `ntp`, sorted by key.

/// Explanations.
pub(super) const HELP: &[(&str, &str)] = &[
    ("ntp.clock", "## What it is\nWhat the client is doing to the system clock.\n\n- `slewing`: the difference is small (under 128 ms) and the clock runs slightly fast or slow until it is gone, with no jump.\n- `stepped`: the last answer set the clock at once.\n- `holding-spike`: a clock already right got a big difference; it stays as it is for up to 900 s, in case the answer is wrong (RFC 5905 §11.3).\n- `awaiting-confirmation`: the difference is over 1000 s and changes only when you confirm.\n- `refused`: the answer would put the clock before 2026 and is never applied.\n- `not-set`: only measuring: switched off in Set System Clock, or this backend or process cannot touch the clock (Clock Error says why)."),
    ("ntp.clock_error", "## What it is\nWhy the clock could not be changed. Usually the process lacks `CAP_SYS_TIME`, or this is the virtual lab, which never touches the clock of the computer it runs on."),
    ("ntp.dynamic_servers", "## What it is\nServers received from DHCP clients with `use_peer_ntp` (option 42), used after the configured ones. At most 8 in total."),
    ("ntp.enabled", "## What it does\nTurns the NTP client on. Off by default.\n\n## Careful\nWith Set System Clock on, it takes charge of the system clock."),
    ("ntp.freq_drift", "## What it is\nHow far this router's crystal is off, learned measurement after measurement. Positive: the crystal is slow. Back to zero when the service restarts, and learned again in a few polls."),
    ("ntp.last_adjustment", "## What it is\nThe size of the last correction, by slew or step."),
    ("ntp.last_error", "## What it is\nWhy the last poll failed, one line per server."),
    ("ntp.last_sync", "## What it is\nWhen the last good answer arrived."),
    ("ntp.max_poll", "## What it is\nLongest interval between polls, as a power of two in seconds: 10 = 17 min. The interval doubles with each good answer, up to this."),
    ("ntp.min_poll", "## What it is\nShortest interval between polls, as a power of two in seconds: 6 = 64 s. RFC 4330 §5 does not allow less."),
    ("ntp.next_poll", "## What it is\nWhen the next poll comes."),
    ("ntp.round_trip", "## What it is\nThe round trip to the server. The measurement's error is at most half of it (RFC 5905 §8)."),
    ("ntp.servers", "## What it is\nOne per line: an IP address or a DNS name (`pool.ntp.org`). The client asks them all and keeps the answer with the smallest round trip.\n\n## When it may be empty\nWhen a DHCP client with `use_peer_ntp` brings the servers."),
    ("ntp.set_system_clock", "## What it does\nApplies what is measured to the system clock. Under 128 ms by slewing, above by stepping; above 1000 s it asks for confirmation.\n\n## When to turn it off\nOn a general-purpose computer where chrony or timesyncd already own the clock: two owners fight. RouterOS has no such option.\n\n## Default\nOn. Needs the linux backend and `CAP_SYS_TIME`."),
    ("ntp.status", "## What it is\n`synchronized`: the last poll got a good answer. `waiting`: on, no good answer. `stopped`: off, or no daemon runs the client."),
    ("ntp.synced_server", "## What it is\nThe server of the measurement in use, and its address."),
    ("ntp.synced_stratum", "## What it is\nHow far the server is from a time source: 1 is attached to a reference clock, 2 asks a stratum 1, and so on."),
    ("ntp.system_offset", "## What it is\nThe server's time minus ours, in the last measurement. Positive: our clock is behind."),
    ("ntp.vrf", "## What it is\nWhich VRF reaches the servers. `main` is the main table. Outside it the socket is bound to the VRF (`SO_BINDTODEVICE`).\n\n## Limit\nDNS names are resolved by the router's resolver, which uses the main table."),
];
