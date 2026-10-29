//! English explanations of the connect screen's certificate modal (G0.3d),
//! sorted by key.

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[(
    "connect.certificate",
    "## Router certificate

Over the network the GUI talks to the router only over TLS. There is no certificate authority: the first time, you compare the fingerprint with the one the router prints at start-up, and the GUI remembers it (`known_hosts`). Later connections check it before sending anything.

**It changed?** Expected after reinstalling the router or giving it a new certificate. Otherwise someone between you and the router may be intercepting the connection.

- **Cancel** (the default; Enter and Esc cancel): nothing is sent.
- **Connect once**: connect with the new certificate now; `known_hosts` keeps the old one, so the next time asks again.
- **Trust and update**: replace the line in `known_hosts` (with today's date) and connect.

CLI and MCP: in a terminal they ask the same; without one they refuse and name `--accept-new-cert`.",
)];
