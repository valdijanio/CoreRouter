//! English explanations of the top bar's other-build chip (G0.32), sorted
//! by key.

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[(
    "version.other_build",
    "## Daemon and GUI from different builds

The bar shows the router daemon's version and this GUI's when they are not the same build (G0.32). A release is `0.1.0`; otherwise `0.1.0-dev.<N>`, N counting the commits behind the build (one per merged PR). When only the commit differs both appear in full (`0.1.0-dev.500+320cb9d`); `.dirty` means built with uncommitted changes. Hover for both builds and their commit dates.

- **Amber:** only the build differs. Everything works, but a fix may be on one side only: restart the GUI after building, or update the router in **System › Packages**.
- **Red:** the control protocol changed. Commands may be misread or refused: update the older side before changing the configuration.",
)];
