//! Trust on first use (G0.3): the TLS certificates this user accepted, one
//! line per router, like SSH's `known_hosts`:
//!
//! ```text
//! # host:port fingerprint [accepted, unix seconds]
//! 10.0.0.1:8729 SHA256:AB:CD:… 1793233584
//! ```
//!
//! The third column (G0.3d) says when the operator accepted it, shown when
//! the certificate changes; lines without it (older files) still work.
//!
//! The file is `$COREROUTER_KNOWN_HOSTS`, else
//! `$XDG_CONFIG_HOME/corerouter/known_hosts` (`~/.config/…`, or
//! `%APPDATA%\corerouter\known_hosts`). The GUI, the CLI and the MCP
//! server share it.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Longest file read; more lines than fit are ignored.
const MAX_FILE: u64 = 1 << 20;

/// What the file says about a router's fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Check {
    /// Remembered and the same.
    Known,
    /// Never seen: ask the operator.
    New,
    /// Remembered with another fingerprint: refuse.
    Changed { expected: String },
}

#[derive(Debug, Clone, Default)]
pub struct KnownHosts {
    path: Option<PathBuf>,
    /// host → (fingerprint, accepted at, unix seconds).
    entries: BTreeMap<String, (String, Option<u64>)>,
}

pub fn default_path() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("COREROUTER_KNOWN_HOSTS").filter(|p| !p.is_empty()) {
        return Some(PathBuf::from(p));
    }
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .or_else(|| std::env::var_os("APPDATA").map(PathBuf::from))?;
    Some(base.join("corerouter").join("known_hosts"))
}

impl KnownHosts {
    /// Entries of the default file (empty when it does not exist yet).
    pub fn load_default() -> Self {
        match default_path() {
            Some(p) => Self::load(&p),
            None => Self::default(),
        }
    }

    /// Entries of `path`; a missing or unreadable file is empty (and the
    /// first [`KnownHosts::remember`] creates it).
    pub fn load(path: &Path) -> Self {
        let mut text = String::new();
        if let Ok(f) = fs::File::open(path) {
            let _ = f.take(MAX_FILE).read_to_string(&mut text);
        }
        let entries = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .filter_map(|l| {
                let mut parts = l.split_whitespace();
                let host = parts.next()?;
                let fp = parts.next()?;
                let since = parts.next().and_then(|t| t.parse::<u64>().ok());
                fp.starts_with("SHA256:")
                    .then(|| (host.to_owned(), (fp.to_owned(), since)))
            })
            .collect();
        Self {
            path: Some(path.to_owned()),
            entries,
        }
    }

    /// In memory only (tests, a browser).
    pub fn in_memory() -> Self {
        Self::default()
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub fn get(&self, host: &str) -> Option<&str> {
        self.entries.get(host).map(|(fp, _)| fp.as_str())
    }

    /// When the fingerprint of `host` was accepted (unix seconds), if the
    /// file says so.
    pub fn since(&self, host: &str) -> Option<u64> {
        self.entries.get(host).and_then(|(_, at)| *at)
    }

    pub fn check(&self, host: &str, fingerprint: &str) -> Check {
        match self.get(host) {
            None => Check::New,
            Some(e) if e == fingerprint => Check::Known,
            Some(e) => Check::Changed {
                expected: e.to_owned(),
            },
        }
    }

    /// Remember `fingerprint` for `host` (replacing what was there, with
    /// the date of now) and save the file.
    pub fn remember(&mut self, host: &str, fingerprint: &str) -> io::Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs());
        self.remember_at(host, fingerprint, now)
    }

    /// [`KnownHosts::remember`] with the acceptance time given.
    pub fn remember_at(
        &mut self,
        host: &str,
        fingerprint: &str,
        since: Option<u64>,
    ) -> io::Result<()> {
        if host.chars().any(char::is_whitespace) || !fingerprint.starts_with("SHA256:") {
            return Err(io::Error::other("bad host or fingerprint"));
        }
        self.entries
            .insert(host.to_owned(), (fingerprint.to_owned(), since));
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let mut text = String::from(
            "# CoreRouter known hosts: host:port SHA-256 fingerprint [accepted, unix seconds]\n",
        );
        for (h, (f, since)) in &self.entries {
            text.push_str(h);
            text.push(' ');
            text.push_str(f);
            if let Some(t) = since {
                text.push(' ');
                text.push_str(&t.to_string());
            }
            text.push('\n');
        }
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, text)?;
        fs::rename(&tmp, path)
    }
}

/// `2026-10-28 14:03 UTC` for an acceptance time; `unknown date` for a
/// line written before G0.3d.
pub fn format_since(since: Option<u64>) -> String {
    let Some(t) = since else {
        return "unknown date".into();
    };
    let days = i64::try_from(t / 86_400).unwrap_or(0);
    let secs = t % 86_400;
    // Days to civil date (H. Hinnant's algorithm, proleptic Gregorian).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        secs / 3600,
        secs % 3600 / 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_time_same_and_changed() {
        let dir = std::env::temp_dir().join(format!("cr-known-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("known_hosts");
        let mut k = KnownHosts::load(&path);
        assert_eq!(k.check("10.0.0.1:8729", "SHA256:AA"), Check::New);
        k.remember("10.0.0.1:8729", "SHA256:AA").unwrap();
        let k = KnownHosts::load(&path);
        assert_eq!(k.check("10.0.0.1:8729", "SHA256:AA"), Check::Known);
        assert_eq!(
            k.check("10.0.0.1:8729", "SHA256:BB"),
            Check::Changed {
                expected: "SHA256:AA".into()
            }
        );
        assert_eq!(k.check("10.0.0.2:8729", "SHA256:AA"), Check::New);
        fs::write(&path, "junk\n# c\nh:1 nothash\nh:2 SHA256:CC extra\n").unwrap();
        let k = KnownHosts::load(&path);
        assert_eq!((k.get("h:1"), k.get("h:2")), (None, Some("SHA256:CC")));
        assert!(KnownHosts::in_memory().remember("a b", "SHA256:x").is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    /// G0.3d: "Trust and update" replaces the line and dates it; "Connect
    /// once" and "Cancel" leave the file as it was.
    #[test]
    fn update_once_and_cancel() {
        let dir = std::env::temp_dir().join(format!("cr-known-upd-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("known_hosts");
        // An old file without dates.
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            &path,
            "10.0.0.1:8729 SHA256:OLD\n10.0.0.2:8729 SHA256:OTHER\n",
        )
        .unwrap();
        let k = KnownHosts::load(&path);
        assert_eq!(k.since("10.0.0.1:8729"), None);
        assert_eq!(format_since(k.since("10.0.0.1:8729")), "unknown date");
        // Once / Cancel: nothing written.
        let before = fs::read_to_string(&path).unwrap();
        let _ = KnownHosts::load(&path).check("10.0.0.1:8729", "SHA256:NEW");
        assert_eq!(fs::read_to_string(&path).unwrap(), before);
        // Update: the new fingerprint with its date, the other line kept.
        let mut k = KnownHosts::load(&path);
        k.remember_at("10.0.0.1:8729", "SHA256:NEW", Some(1_793_233_584))
            .unwrap();
        let k = KnownHosts::load(&path);
        assert_eq!(k.check("10.0.0.1:8729", "SHA256:NEW"), Check::Known);
        assert_eq!(k.since("10.0.0.1:8729"), Some(1_793_233_584));
        assert_eq!(k.get("10.0.0.2:8729"), Some("SHA256:OTHER"));
        assert_eq!(k.since("10.0.0.2:8729"), None);
        let text = fs::read_to_string(&path).unwrap();
        assert!(
            text.contains("10.0.0.1:8729 SHA256:NEW 1793233584\n"),
            "{text}"
        );
        assert!(!text.contains("SHA256:OLD"), "{text}");
        // remember() dates it now.
        let mut k = KnownHosts::load(&path);
        k.remember("10.0.0.3:8729", "SHA256:X").unwrap();
        assert!(k.since("10.0.0.3:8729").is_some_and(|t| t > 1_700_000_000));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn dates_read_like_dates() {
        assert_eq!(format_since(Some(0)), "1970-01-01 00:00 UTC");
        assert_eq!(format_since(Some(951_782_400)), "2000-02-29 00:00 UTC");
        assert_eq!(format_since(Some(1_793_233_584)), "2026-10-29 00:26 UTC");
    }
}
