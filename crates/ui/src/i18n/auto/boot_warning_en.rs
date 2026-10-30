//! English explanation of the boot warning (G1.3e), sorted by key.

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[(
    "boot_warning.boot_apply",
    "## Config left out at boot

At boot the router applies the whole saved config at once. If the kernel refuses part of it (a firewall rule needing a module that did not load, a route, an MPLS entry, a port setting), it does **not** undo everything: interfaces and addresses go in first, so management stays reachable, then each section on top. A refused section stays out, with the kernel's error.

Sections: `ethernet` (speed/duplex), `routes`, `firewall` (filter, nat, mangle, raw, lists), `cgnat`, `fastpath`, `tuning`, `xdp`, `arp`, `mpls`. `core` means not even interfaces and addresses went in.

- The chip goes away once everything is in: the router retries on its own, with a growing wait (1, 2, 4… up to 60 s).
- **Fix or remove** the refused item and commit: a commit that touches the section applies it whole (all or nothing, as always). Commits elsewhere work as usual and leave the refused section as it is.
- **A firewall left out leaves the router unfiltered** until fixed: treat it first.

The same list is in the health checks (`boot.apply`), the router log, `state.inspect` (`storage.boot_apply_failed`) and the CLI and MCP warning.",
)];
