//! English explanations of IP › DNS › Encrypted Service (G4.1zf), scope `dns_encrypted`, sorted by key.

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    ("dns_encrypted.accepted", "## Accepted\n\nTCP connections taken since the service opened (after **Allowed From**)."),
    ("dns_encrypted.announce_ddr", "## Announce (DDR)\n\nAnswers `_dns.resolver.arpa` SVCB (RFC 9462, Discovery of Designated Resolvers) with the router's DNS over TLS service: its name, port and addresses. Clients that support it find the encrypted service by themselves. iOS, macOS and Windows only take it when the certificate is trusted and names the address they asked (verified discovery, §4.2). `resolver.arpa` is always answered here and never forwarded."),
    ("dns_encrypted.certificate", "## Certificate\n\nThe `/certificate` it serves with (System › Certificates). Left empty, the first Apply with DNS over TLS on makes `dns-server`: self-signed, with the router's identity and addresses. Android's automatic mode does not check it; for clients that check, import a certificate they trust."),
    ("dns_encrypted.doh", "## DNS over HTTPS\n\nAnswers the LAN on HTTPS (RFC 8484): GET with `?dns=` and POST with `application/dns-message`, on HTTP/2 (what browsers and Windows use) and HTTP/1.1. The same forwarder as UDP/TCP 53; only **Allowed From** may connect."),
    ("dns_encrypted.doh_errors", "## DoH Errors\n\nRequests answered with an HTTP error: another path (404), method (405) or media type (415), a body over 64 KiB (413), a broken `dns=` (400)."),
    ("dns_encrypted.doh_path", "## Path\n\nThe path of the URI template (RFC 8484 §3). `/dns-query` is what every client expects; change it only to match a client already configured."),
    ("dns_encrypted.doh_port", "## HTTPS Port\n\nIts own listener. 443 is what clients expect (DDR leaves the port out on 443), but **www-ssl** usually holds 443: then pick another (8443) or move www-ssl. Clients take any port in the URL."),
    ("dns_encrypted.doh_queries", "## DoH Queries\n\nDNS messages answered over HTTPS since the service opened."),
    ("dns_encrypted.dot", "## DNS over TLS\n\nAnswers the LAN on TCP with TLS (RFC 7858). The queries go through the same chain as UDP/TCP 53: **Allow Remote Requests** must be on, and only **Allowed From** may connect (others are closed before any TLS)."),
    ("dns_encrypted.dot_port", "## Port\n\n853, the port of RFC 7858 §3.1, which clients try by themselves. Another one only when both sides agree (DDR announces it); never 53."),
    ("dns_encrypted.fingerprint", "## Fingerprint\n\nSHA-256 of the certificate being served, as browsers show it."),
    ("dns_encrypted.handshake_failures", "## Handshake Failures\n\nConnections whose TLS handshake failed or took over 10 s: a client that does not trust the certificate, plain DNS sent to the TLS port (never answered, RFC 7858 §3.1), a scanner."),
    ("dns_encrypted.handshakes", "## Handshakes\n\nTLS handshakes completed. Each costs ~0.1 ms of CPU with ECDSA P-256 (~0.5 ms with RSA-2048), **measured**; a query on an open connection, ~0.5 µs."),
    ("dns_encrypted.http2", "## HTTP/2 Connections\n\nDoH connections that chose HTTP/2 (ALPN `h2`); the rest used HTTP/1.1."),
    ("dns_encrypted.idle_timeout_secs", "## Idle Timeout\n\nA connection with no query waiting is closed after this long. Default 30 s: above Android's 20 s, so a phone reuses its connection instead of a new handshake for each burst (RFC 7858 §3.4). Lower it under load."),
    ("dns_encrypted.last_error", "## Last Error\n\nWhy the service could not open: a port in use, port 853 without the permission to bind it, a certificate without its key."),
    ("dns_encrypted.max_sessions", "## Max Sessions\n\nTLS connections at once, all clients. One address holds at most a quarter (several devices behind one NAT). When full, the connection idle the longest gives its place."),
    ("dns_encrypted.over_limit", "## Over Limit\n\nConnections closed at accept or evicted because of **Max Sessions** or the share of one address."),
    ("dns_encrypted.queries", "## DoT Queries\n\nQueries answered over DNS over TLS since the service opened. They also count as TCP in DNS Statistics."),
    ("dns_encrypted.refused", "## Refused\n\nConnections closed at accept, before any TLS: the client is not in **Allowed From**."),
    ("dns_encrypted.resumed", "## Resumed\n\nHandshakes resumed with a session ticket (stateless, RFC 8310 §9): the client came back without a full handshake."),
    ("dns_encrypted.sessions", "## Sessions\n\nTLS connections open now."),
    ("dns_encrypted.status", "## Status\n\n**listening**: the port is open. **stopped**: off, or the LAN forwarder is off. **error**: it could not open; see **Last Error**."),
    ("dns_encrypted.url", "## DoH URL\n\nWhat to give a client (browser, Windows, a profile): the URI template with the router's address. A client that checks the certificate needs one it trusts and that names this address."),
];
