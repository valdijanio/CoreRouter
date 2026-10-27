//! English explanations of IP › Firewall › CGNAT › Logging (G4.4j), sorted
//! by key.

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    ("nat-log.collectors", "## Collectors\n\nThe Traffic Flow collectors that receive NAT events (content all or nat). Add Collector opens one filled for IPFIX over TLS, NAT only."),
    ("nat-log.exporter", "## Exporter\n\nThe router's flow exporter (IP › Traffic Flow), which sends the NAT events."),
    ("nat-log.nat_events", "## Sessions\n\nOne record per NAT44 connection (natEvent 4/5). High volume; off by default."),
    ("nat-log.nat_events_destination", "## Session Destination\n\nThe destination in session records. Off by default (Marco Civil art. 14, RFC 6888)."),
    ("nat-log.nat_limits", "## Limits\n\nPool exhausted (3), subscriber out of ports (13), above its alert (18); at most one a minute each (RFC 8158 §5.2)."),
    ("nat-log.nat_port_blocks", "## Port Blocks\n\nBlock allocation and release (natEvent 16/17), with the pool, VLAN and login."),
    ("nat-log.queue", "## Queue\n\nBlock and limit events handed to the exporter, and those dropped for a full queue."),
];
