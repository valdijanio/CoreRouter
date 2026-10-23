//! English explanations of Tools › Bandwidth Test (G6.4b), sorted by key.

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    ("bandwidth.address", "## Address\n\nThe test's server: any `iperf3 -s` (3.x) or another CoreRouter with its Bandwidth Server on. An IP or a name (resolved by the router's DNS).\n\nThe test speaks the iperf3 protocol, not MikroTik's btest: a RouterOS does not answer."),
    ("bandwidth.bandwidth", "## Rate per stream\n\nHow much each stream sends, bit/s with `k`, `M` or `G` (`100M`). Empty: TCP sends what the path takes; UDP uses **10M** (iperf3's own default, 1 Mbit/s, measures nothing on a router's link).\n\nFor UDP it is the offered rate: what gets through and what is lost shows in Rx and Loss."),
    ("bandwidth.direction", "## Direction\n\n**send**: the router sends to the server (plain `iperf3`). **receive**: the server sends to the router (`-R`). **both**: both at once (`--bidir`).\n\nRouterOS: `transmit`, `receive`, `both`."),
    ("bandwidth.duration", "## Duration\n\nHow many seconds the test runs (1 to 300; default 10). The path is full all that time: start short. The server may refuse tests longer than its limit."),
    ("bandwidth.port", "## Port\n\nThe server's TCP port (default 5201, iperf3's). The data streams use the same port, TCP and UDP: a firewall on the way must allow both."),
    ("bandwidth.protocol", "## Protocol\n\n**TCP** measures what a real connection gets (with congestion control). **UDP** sends at a fixed rate and measures **loss** and **jitter** (RFC 1889 §6.3.1) — the right test for voice and video, and to find where a link drops."),
    ("bandwidth.results", "## Results\n\nPer direction: the receiver's **average** (at the end, the far side's number), the **peak** second, and for UDP the **loss** (datagrams that did not arrive ÷ sent) and **jitter**. Retransmits: the sender's TCP retransmissions, when it reports them.\n\n**router CPU**: all cores of this router during the test — near 100 %, the limit is the router, not the link."),
    ("bandwidth.server", "## Bandwidth Server\n\nThe router answers iperf3 tests (any `iperf3 -c` or another CoreRouter). **Off by default**; it turns on only with a list of who may test. One test at a time (others get \"server busy\"), each bounded in duration, streams and, if you want, rate.\n\nIt runs under the service supervisor (System › Services)."),
    ("bandwidth.server_allowed", "## Allowed addresses\n\nPrefixes that may start a test (`100.64.0.0/10, 192.168.88.0/24`). **Required to enable.** `0.0.0.0/0` and `::/0` allow anyone — careful: a test fills links, and anyone could fill your uplink.\n\nA client outside the list gets \"busy\" before anything is read, and counts as **refused**."),
    ("bandwidth.server_enabled", "## Enabled\n\nTurns the server on at the configured port (TCP and UDP). Off closes the port at once. Needs **Allowed addresses**."),
    ("bandwidth.server_max_duration", "## Max duration\n\nThe longest test accepted, seconds (1 to 3600; default 60). A client asking for more is refused with iperf3's code (\"test is longer than the server allows\"); a test that overruns is ended by the server."),
    ("bandwidth.server_max_rate", "## Max rate\n\nThe total one test may ask for (streams × rate × 2 when both ways), bit/s with k/M/G. `0` = no cap. With a cap, a TCP test without a rate (`-b`) is refused, as it would have no ceiling."),
    ("bandwidth.server_max_streams", "## Max streams\n\nHow many parallel streams (`-P`) a test may open (1 to 128; default 8). Each stream is a thread on the router."),
    ("bandwidth.server_port", "## Port\n\nThe server's TCP and UDP port (default 5201). Changing it rebinds the server."),
    ("bandwidth.streams", "## Streams\n\nHow many connections in parallel (iperf3's `-P`, 1 to 128). A single TCP stream may not fill a high-latency link (window); several spread the load over cores and queues."),
];
