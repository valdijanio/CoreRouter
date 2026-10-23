//! English explanations of System › Analytics (G4.4f), sorted by key.

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    ("analytics.batch_size", "## Batch Size\n\nRows per INSERT at most. ClickHouse prefers few large inserts: at least 1000 rows and about one insert per second; many small ones make 'too many parts' errors."),
    ("analytics.ca_certificate", "## CA Certificate\n\nThe CA that signed the server's certificate (PEM), for a server with its own CA. Empty: the public roots compiled into the router."),
    ("analytics.certificate", "## Client Certificate\n\nLogs in by certificate instead of password (ClickHouse user `IDENTIFIED WITH ssl_certificate CN '…'`). Needs `https://` and the private key."),
    ("analytics.compression", "## Compression\n\n`gzip` makes the body of each INSERT 5 to 10 times smaller for little CPU; `none` only for a server on the same machine."),
    ("analytics.database", "## Database\n\nThe ClickHouse database with the tables `metrics`, `logs`, `flows` and `nat_events` (tab Schema). Every router can write to the same one: each row carries its Router ID."),
    ("analytics.disk_queue", "## Disk Queue\n\nMiB on disk beyond the memory queue, so an outage of the server or a reboot loses nothing. Needs the daemon's `--analytics-spool <dir>`. 0: off.\n\nOn flash, keep it small: every batch there is written once."),
    ("analytics.enabled", "## Enabled\n\nTurns the export on. Needs a URL. Off, nothing is collected or sent; rows already queued wait."),
    ("analytics.flows", "## Flows\n\nIPFIX-like flow records (who talked to whom, how much). The source is Traffic Flow (G4.4b), still to come: until then this table stays empty."),
    ("analytics.flush_interval", "## Flush Interval\n\nHow long a row may wait for its batch to fill before it is sent anyway. Shorter: fresher data, more inserts."),
    ("analytics.logs", "## Logs\n\nThe router's log events that a logging rule sends to the `analytics` action (System › Logging), with severity, topic, origin, message and detail.\n\n**Add rules** creates rules for info, warning, error and critical."),
    ("analytics.metrics", "## Metrics\n\nThe counters of the `/metrics` endpoint (interfaces, commands, services, DHCP…) every Metrics Interval, one row per value."),
    ("analytics.metrics_interval", "## Metrics Interval\n\nSeconds between two samples of the metrics. 60 s is enough for capacity graphs; 10 s for troubleshooting."),
    ("analytics.nat_events", "## NAT Events\n\nWhat a CGNAT operator must be able to answer: who had this public address and port at that moment (RFC 8158 events, Marco Civil).\n\nToday: the port blocks CGNAT gives and takes back in blocks mode (IP › Firewall › CGNAT), one row each. Per-connection events come with Traffic Flow (G4.4b)."),
    ("analytics.password", "## Password\n\nSent in the `X-ClickHouse-Key` header, never in the URL (proxies log URLs). Over `http://` it crosses the network in clear text: use `https://` unless the server is on a trusted management network.\n\nNever shown back (`***`); typing replaces it."),
    ("analytics.private_key", "## Private Key\n\nThe key of the client certificate (PEM). Kept in the router's config, never shown back nor written to the log."),
    ("analytics.queue_size", "## Queue Size\n\nMemory for rows waiting for the server (compressed once batched). When full, the oldest batch is dropped and counted: the router never stops or slows for the exporter."),
    ("analytics.router_id", "## Router ID\n\nThe `router` column of every row. Empty: the system identity (System › Identity). Give each router a unique one, or the rows of two routers mix."),
    ("analytics.schema", "## Schema\n\nThe tables to create once on the server: MergeTree, one partition per day, ordered by router and time, and a TTL that deletes old days (metrics 395, logs 90, flows 30, NAT events 400: Marco Civil asks a year).\n\nThe `otel_logs` view shows the logs with the OpenTelemetry names, for Grafana. Details in docs/analytics.md."),
    ("analytics.state", "## State\n\n- **running**: the last INSERT worked;\n- **retrying**: the server is away or answers errors; rows wait and the next try comes after a pause that doubles up to 60 s;\n- **error**: cannot start (a bad certificate);\n- **stopped**: disabled.\n\n**dropped** counts rows thrown away (queue full, or refused by the server as bad)."),
    ("analytics.tls_verify", "## Verify Certificate\n\nChecks the server's certificate against the CA below (or the public roots). Off still encrypts but accepts any certificate: someone on the path could pose as the server."),
    ("analytics.url", "## URL\n\nClickHouse's HTTP interface: `http://host:8123`, or `https://host:8443` with TLS. Only scheme, host and port; user and password have their own fields.\n\nA host name is resolved by the router's DNS (IP › DNS)."),
    ("analytics.user", "## User\n\nThe ClickHouse user. Give it only `INSERT` on the database (and `SELECT` on `system.tables` for Test Connection); never the administrator."),
];
