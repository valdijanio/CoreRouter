//! What this binary is: version and git commit. The daemon reports them in
//! `server.info`; the GUI shows them and warns when the daemon it manages was
//! built from another commit (a daemon left running after `cargo build`).

/// The workspace version (`Cargo.toml`).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Short git commit of the build, or `unknown` outside a git checkout.
pub const COMMIT: &str = env!("COREROUTER_COMMIT");

/// `0.1.0 (21911cb)`.
pub fn describe() -> String {
    format!("{VERSION} ({COMMIT})")
}

#[cfg(test)]
mod tests {
    #[test]
    fn describe_has_version_and_commit() {
        let d = super::describe();
        assert!(
            d.starts_with(super::VERSION) && d.contains(super::COMMIT),
            "{d}"
        );
    }
}
