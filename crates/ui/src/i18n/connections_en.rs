//! English explanations of IP › Firewall › Connections (G2.2), sorted by key.

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
        "connections.generic_timeout",
        "## Generic Timeout

Protocols conntrack does not track in detail (GRE, ESP…). Linux 600 s.",
    ),
    (
        "connections.icmp_timeout",
        "## ICMP Timeout

An ICMP query (ping). Linux 30 s; RFC 5508 REQ-2 recommends ≥ 60 s in a NAT.",
    ),
    (
        "connections.max_entries",
        "## Max Entries

The table's size (`nf_conntrack_max`). About 300 bytes of RAM each; for CGNAT, 300–500 per active subscriber.",
    ),
    (
        "connections.table",
        "## Connection table

Every connection through the router (conntrack): what lets the firewall know replies and the NAT remember each translation. When full, new connections are dropped or evict old unreplied ones; `insert failed` counts connections that found no free NAT port. Above 70 %, raise `nf_conntrack_max` in System › Tuning or shorten the timeouts.",
    ),
    (
        "connections.tcp_close_wait_timeout",
        "## TCP Close Wait Timeout

After the other side's FIN. Linux 60 s.",
    ),
    (
        "connections.tcp_established_timeout",
        "## TCP Established Timeout

How long an idle established TCP connection stays. Linux 5 days, RouterOS 1 day; RFC 5382 REQ-5 asks at least 2 h 4 min in a NAT.",
    ),
    (
        "connections.tcp_fin_wait_timeout",
        "## TCP FIN Wait Timeout

After one side sent FIN. Linux 120 s; RFC 7857 §2.1 suggests ≥ 4 min of transitory time in a NAT.",
    ),
    (
        "connections.tcp_syn_received_timeout",
        "## TCP SYN Received Timeout

How long the last handshake step is waited for. Linux 60 s.",
    ),
    (
        "connections.tcp_syn_sent_timeout",
        "## TCP SYN Sent Timeout

How long a SYN waits for an answer. Linux 120 s.",
    ),
    (
        "connections.tcp_time_wait_timeout",
        "## TCP Time Wait Timeout

After both sides closed. Linux 120 s.",
    ),
    (
        "connections.top",
        "## Top subscribers

Who holds the most connections now, and how much of their CGNAT port block is in use. Near 100 % a subscriber cannot open new connections (the kernel drops them silently). Click one to filter the table.",
    ),
    (
        "connections.udp_stream_timeout",
        "## UDP Stream Timeout

A UDP flow with replies (DNS, VoIP, games, QUIC). Linux 120 s; RFC 4787 REQ-5: ≥ 2 min, 5 min recommended.",
    ),
    (
        "connections.udp_timeout",
        "## UDP Timeout

A UDP flow with no reply. Linux 30 s; RFC 4787 REQ-5 wants ≥ 2 min for a NAT mapping (CoreRouter keeps EIM mappings 5 min apart).",
    ),
    (
        "connections.via",
        "## Via

- **rules**: every packet goes through the firewall rules;
- **software**: the connection is in the flowtable (RouterOS fasttrack);
- **hardware**: the NIC forwards it by itself (offload).",
    ),
];
