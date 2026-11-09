//! English explanation of the Interfaces' network card problems (G1.6ja).

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[(
    "nic_problems.overview",
    "## Network card problems

The router looks at the machine's PCI and USB network cards every 10 seconds and at what the kernel said about them.

- **no driver**: the card is on the bus and nothing claimed it, so it has no port. If the image has a module for it, the module did not bind; otherwise, this image does not know the card (`docs/os-image.md` has the table).
- **firmware**: the driver asked for a file and could not load it. The port may not come up, or come up with less. The file's name is in the list.
- **safe mode**: the `ice` driver of the Intel E810 could not use its DDP package: one queue, no RSS, no XDP, no offloads. Traffic passes, on one core.
- **until installed**: on the ISO, which has no firmware files, this is normal. Nothing to do.

**Not counted:** Wi-Fi cards (out of the image's purpose), virtual functions without a driver (handed to a VM on purpose), and `regulatory.db`, which the kernel asks for whenever it has Wi-Fi support.

The same list is in the health checks (`interface.hardware`), the router log, and the CLI and MCP warning; `interface.hardware.problems` returns it.",
)];
