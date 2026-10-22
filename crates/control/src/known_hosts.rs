//! Trust on first use (G0.3): the TLS certificates this user accepted, one
//! line per router, like SSH's `known_hosts`:
//!
//! ```text
//! # host:port fingerprint
//! 10.0.0.1:8729 SHA256:AB:CD:…
//! ```
//!
//! The file is `$COREROUTER_KNOWN_HOSTS`, else
//! `$XDG_CONFIG_HOME/corerouter/known_hosts` (`~/.config/…`, or
//! `%APPDATA%\corerouter\known_hosts`). The GUI, the CLI and the MCP
//! server share it.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

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
    entries: BTreeMap<String, String>,
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
                fp.starts_with("SHA256:")
                    .then(|| (host.to_owned(), fp.to_owned()))
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
        self.entries.get(host).map(String::as_str)
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

    /// Remember `fingerprint` for `host` and save the file.
    pub fn remember(&mut self, host: &str, fingerprint: &str) -> io::Result<()> {
        if host.chars().any(char::is_whitespace) || !fingerprint.starts_with("SHA256:") {
            return Err(io::Error::other("bad host or fingerprint"));
        }
        self.entries.insert(host.to_owned(), fingerprint.to_owned());
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let mut text = String::from("# CoreRouter known hosts: host:port SHA-256 fingerprint\n");
        for (h, f) in &self.entries {
            text.push_str(h);
            text.push(' ');
            text.push_str(f);
            text.push('\n');
        }
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, text)?;
        fs::rename(&tmp, path)
    }
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
}
