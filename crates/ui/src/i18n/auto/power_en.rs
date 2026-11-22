//! English explanations of System › Reboot and Shutdown (G1.6qh), scope `power`, sorted by key.

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    ("menu.reboot", "## What it does\nRestarts the router cleanly: the daemon saves its checkpoint, the routing suite stops, `/config` is synced and unmounted, and the machine boots again. RouterOS `/system reboot`.\n\n## Careful\nAll traffic through the router stops until the boot ends. A reboot during Safe Mode undoes the changes made since Safe Mode started."),
    ("menu.shutdown", "## What it does\nStops the router cleanly and powers the machine off. RouterOS `/system shutdown`.\n\n## Careful\nIt comes back **only by hand**: someone has to press the power button or use the out-of-band access. Do not use it on a router you cannot reach physically."),
    ("power.checks", "## Checks\n\nWhat the router refuses without **Force**. **Safe Mode on**: booting starts from the configuration of the moment Safe Mode began, which undoes everything since. **pending changes**: a transaction not committed is never saved. Each line has a button that clears it. **disk erase waiting** cannot be forced: PID 1 would take this power-off for the power button of the installer's confirmation."),
    ("power.comes_back", "## Connection\n\nThe GUI, the terminal and the browser try again by themselves. After a reboot this window shows when the router answers; there is nothing to do. If the address came from DHCP it may change: the console shows the current one."),
    ("power.force", "## Force\n\nReboots or shuts down even with Safe Mode on or changes not committed, losing them. Prefer the buttons above, which keep the work. The journal and the log record the command, and its result says what was lost."),
    ("power.impact", "## What goes down\n\nEverything that passes through the router and every connection to it. The counts are what is up right now: PPP subscribers, established BGP sessions and OSPF neighbors. They come back by themselves after the boot, as their timers allow."),
];
