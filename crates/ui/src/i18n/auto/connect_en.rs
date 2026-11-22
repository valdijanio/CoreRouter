//! English explanations of the connect screen: the certificate modal
//! (G0.3d) and the saved password (G0.3e), sorted by key.

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (
    "connect.certificate",
    "## Router certificate

Over the network the GUI talks to the router only over TLS. There is no certificate authority: the first time, you compare the fingerprint with the one the router prints at start-up, and the GUI remembers it (`known_hosts`). Later connections check it before sending anything.

**It changed?** Expected after reinstalling the router or giving it a new certificate. Otherwise someone between you and the router may be intercepting the connection.

- **Cancel** (the default; Enter and Esc cancel): nothing is sent.
- **Connect once**: connect with the new certificate now; `known_hosts` keeps the old one, so the next time asks again.
- **Trust and update**: replace the line in `known_hosts` (with today's date) and connect.

CLI and MCP: in a terminal they ask the same; without one they refuse and name `--accept-new-cert`.",
),
    (
        "connect.saved_password",
        "## Saved password

With **Remember password** ticked, the GUI keeps the password in the operating system's secure store (keyring), per address and Login, never in a file of its own.

- When a password is saved for the address and Login on screen, it is put **in the Password field** (masked) with the `saved password` pill. Nothing is used behind your back: what the field holds is what the router gets.
- **Clear the field** to connect with an empty password (the `admin` of a new or reinstalled router has none). The pill turns into `saved password unused`.
- **Forget** (next to the pill) deletes it from this computer's store; the router is not touched.
- If the router refuses the saved password, the message says so and offers to forget it.
- Changed certificate (reinstalled router): **Trust and update** also forgets the saved password while its box is ticked (the default).",
    ),
];
