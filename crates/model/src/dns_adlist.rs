//! `/ip dns adlist` (G4.1d): block lists the LAN forwarder loads (hosts
//! files, domain lists), by URL or from a file. Names and defaults follow
//! RouterOS v7; the names themselves never enter the config (a list has
//! hundreds of thousands): the daemon downloads and holds them, and
//! `ip.dns.adlist.print` shows how many it loaded and matched.

use serde::{Deserialize, Serialize};

use crate::types::ItemId;

/// Lists at most (each is a download and a set in memory).
pub const MAX_LISTS: usize = 32;
pub const MAX_URL_LEN: usize = 1024;
pub const MAX_FILE_LEN: usize = 255;

fn yes() -> bool {
    true
}

fn is_true(b: &bool) -> bool {
    *b
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdlistEntry {
    pub id: ItemId,
    /// `http://` or `https://` address of the list.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub url: String,
    /// A file in the daemon's adlist directory, instead of `url`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub file: String,
    /// Check the HTTPS server's certificate (RouterOS `ssl-verify`).
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub ssl_verify: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

impl AdlistEntry {
    pub fn new(id: ItemId) -> Self {
        Self {
            id,
            url: String::new(),
            file: String::new(),
            ssl_verify: true,
            disabled: false,
            comment: String::new(),
        }
    }

    /// Where the list comes from, as shown.
    pub fn source(&self) -> &str {
        if self.url.is_empty() {
            &self.file
        } else {
            &self.url
        }
    }

    pub fn problem(&self) -> Option<String> {
        match (self.url.is_empty(), self.file.is_empty()) {
            (true, true) => return Some("needs a url or a file".into()),
            (false, false) => return Some("url and file cannot both be set".into()),
            _ => {}
        }
        if !self.url.is_empty() {
            return url_problem(&self.url);
        }
        file_problem(&self.file)
    }
}

/// Why `url` cannot be a list's address.
pub fn url_problem(url: &str) -> Option<String> {
    let shown: String = url.chars().take(64).collect();
    if url.len() > MAX_URL_LEN {
        return Some(format!("url: at most {MAX_URL_LEN} characters"));
    }
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"));
    let Some(rest) = rest else {
        return Some(format!("url: '{shown}' must start with http:// or https://"));
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if host.is_empty() || host.contains('@') {
        return Some(format!("url: '{shown}' has no host (user@ is not accepted)"));
    }
    if url.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Some(format!("url: '{shown}' has spaces or control characters"));
    }
    None
}

/// A file name in the adlist directory: no directories, nothing hidden.
pub fn file_problem(file: &str) -> Option<String> {
    let shown: String = file.chars().take(64).collect();
    let ok = !file.is_empty()
        && file.len() <= MAX_FILE_LEN
        && !file.starts_with('.')
        && file
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b));
    (!ok).then(|| {
        format!(
            "file: '{shown}' must be a file name (letters, digits, - _ and ., at most \
             {MAX_FILE_LEN}, not starting with .)"
        )
    })
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsAdlist {
    pub entries: Vec<AdlistEntry>,
    pub next_id: u32,
}

impl DnsAdlist {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.next_id == 0
    }

    pub fn next_id(&mut self) -> ItemId {
        self.next_id = self.next_id.saturating_add(1);
        ItemId(self.next_id)
    }

    pub fn problem(&self) -> Option<String> {
        if self.entries.len() > MAX_LISTS {
            return Some(format!("at most {MAX_LISTS} adlists"));
        }
        self.entries
            .iter()
            .find_map(|e| e.problem().map(|p| format!("adlist {}: {p}", e.id)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_are_checked() {
        let mut e = AdlistEntry::new(ItemId(1));
        assert!(e.problem().is_some(), "needs a source");
        e.url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts".into();
        assert_eq!(e.problem(), None);
        e.file = "hosts.txt".into();
        assert!(e.problem().is_some(), "not both");
        e.url.clear();
        assert_eq!(e.problem(), None);
        for bad in ["../etc/passwd", ".hidden", "a/b", "", "x y"] {
            assert!(file_problem(bad).is_some(), "{bad}");
        }
        for bad in ["ftp://x/y", "https://", "https://user@host/", "http://a b/", "x"] {
            assert!(url_problem(bad).is_some(), "{bad}");
        }
    }

    #[test]
    fn defaults_and_serde() {
        let e: AdlistEntry = serde_json::from_str(r#"{"id":"*1","url":"http://x/y"}"#).unwrap();
        assert!(e.ssl_verify && !e.disabled);
        let v = serde_json::to_value(&e).unwrap();
        assert!(v.get("ssl_verify").is_none(), "default not written");
        assert!(DnsAdlist::default().is_empty());
    }
}
