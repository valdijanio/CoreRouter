//! What this binary is (G0.32): a readable version, the git commit it was
//! built from and the control protocol it speaks. The daemon reports them in
//! `server.info`; the GUI shows them and warns when the daemon it manages is
//! another build (a daemon left running after `cargo build`, an old router).

/// `0.1.0` on a release tag, else `0.1.0-dev.<N>`: N counts the commits
/// behind the build, so it grows by one per PR on the main and tells how far
/// apart two builds are.
pub const VERSION: &str = env!("COREROUTER_VERSION");

/// Short git commit of the build, or `unknown` outside a git checkout.
pub const COMMIT: &str = env!("COREROUTER_COMMIT");

/// The commit, with `.dirty` when the tree had uncommitted changes.
pub const BUILD: &str = env!("COREROUTER_BUILD");

/// Unix time of the commit (0 when unknown): the build's date, the same on
/// every machine that builds that commit.
pub const COMMIT_TIME: &str = env!("COREROUTER_COMMIT_TIME");

/// The control protocol (`docs/control-protocol.md`). Raised when a client
/// of the older one would misread or be refused: the GUI then warns in red
/// instead of amber.
pub const PROTOCOL: u32 = 1;

/// `0.1.0-dev.500+320cb9d` (SemVer 2.0: the part after `+` is build
/// metadata and does not order versions).
pub fn full() -> String {
    format!("{VERSION}+{BUILD}")
}

/// The commit time as Unix seconds, if known.
pub fn commit_unix() -> Option<u64> {
    COMMIT_TIME.parse().ok().filter(|t| *t > 0)
}

/// Unix seconds as `2026-10-30 07:54:10 UTC` (proleptic Gregorian, the
/// inverse of H. Hinnant's days-from-civil).
pub fn utc(secs: u64) -> String {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

/// What `--version` prints: `corerouter-cli 0.1.0-dev.500+320cb9d
/// (2026-10-30 07:54:10 UTC, protocol 1)`.
pub fn version_line(program: &str) -> String {
    let when = commit_unix().map_or_else(String::new, |t| format!("{}, ", utc(t)));
    format!("{program} {} ({when}protocol {PROTOCOL})", full())
}

/// The version's dev number (`0.1.0-dev.500` → 500); `None` for a release.
pub fn dev_number(version: &str) -> Option<u64> {
    version.rsplit_once("-dev.")?.1.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_full_version_is_semver_with_the_build_after_plus() {
        let f = full();
        assert!(
            f.starts_with(VERSION) && f.contains('+') && f.ends_with(BUILD),
            "{f}"
        );
        assert!(VERSION.starts_with(env!("CARGO_PKG_VERSION")), "{VERSION}");
        assert!(
            VERSION
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-')),
            "{VERSION}"
        );
    }

    #[test]
    fn utc_dates() {
        assert_eq!(utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(utc(1_793_337_250), "2026-10-30 05:14:10 UTC");
        assert!(version_line("x").starts_with(&format!("x {}", full())));
    }

    #[test]
    fn dev_numbers() {
        assert_eq!(dev_number("0.1.0-dev.500"), Some(500));
        assert_eq!(dev_number("0.1.0"), None);
        assert_eq!(dev_number("0.1.0-dev.x"), None);
    }
}
