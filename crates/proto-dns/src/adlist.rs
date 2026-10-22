//! Adlist (G4.1d, `/ip dns adlist`): the names of downloaded block lists,
//! parsed and kept compact so a million names fit in a router's memory.
//!
//! The text is hostile (anyone serving the URL writes it): lines are
//! bounded, every name is checked against RFC 1035 §2.3.4 before it is
//! kept, and the number of names has a ceiling. Formats understood, mixed
//! freely in one file (Pi-hole, AdGuard Home and RouterOS read the same):
//!
//! - hosts: `0.0.0.0 ads.example tracker.example` (any address first; the
//!   names after it are blocked);
//! - plain domains: `ads.example`, one per line;
//! - the Adblock subset block lists use for whole domains:
//!   `||ads.example^`. Anything else in that syntax (paths, `$`
//!   options, `@@` exceptions, wildcards inside a label) is skipped and
//!   counted, never half-understood.
//!
//! `#` and `!` start comments (whole-line or after the names). Host names
//! that every hosts file lists for the machine itself (`localhost`,
//! `broadcasthost`, `ip6-*`…) are not blocked.
//!
//! A hosts or plain-domain line blocks that exact name; `||ads.example^`
//! blocks the name and every name under it (Pi-hole and AdGuard Home read
//! them the same way: hosts lists name each subdomain they mean, and some
//! list a parent whose other subdomains must keep working).

use std::net::IpAddr;

use crate::message::MAX_NAME_LEN;

/// Longest line read; longer ones are skipped (a hosts line with many
/// names is still far shorter).
pub const MAX_LINE: usize = 4096;

/// Names the hosts files list for the local machine, never blocked.
const LOCAL: [&str; 11] = [
    "localhost",
    "localhost.localdomain",
    "local",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
    "ip6-allhosts",
];

/// What parsing one list gave.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Parsed {
    /// Exact names: lowercase, without the final dot; may repeat (the set
    /// dedups).
    pub names: Vec<String>,
    /// Names blocked with every name under them (`||name^`).
    pub domains: Vec<String>,
    /// Lines that held something but no usable name.
    pub skipped: usize,
    /// The list had more names than `max` allowed; the rest were dropped.
    pub truncated: bool,
}

/// Parses a list, keeping at most `max` names.
pub fn parse(text: &str, max: usize) -> Parsed {
    let mut out = Parsed::default();
    for line in text.lines() {
        if out.names.len() + out.domains.len() >= max {
            out.truncated = true;
            break;
        }
        if line.len() > MAX_LINE {
            out.skipped += 1;
            continue;
        }
        let before = out.names.len() + out.domains.len();
        let had = parse_line(line, &mut out.names, &mut out.domains);
        if had && out.names.len() + out.domains.len() == before {
            out.skipped += 1;
        }
        if out.names.len() + out.domains.len() > max {
            out.names.truncate(max.saturating_sub(out.domains.len()));
            out.truncated = true;
        }
    }
    out
}

/// One line into `names`; whether it held anything but a comment.
fn parse_line(line: &str, names: &mut Vec<String>, domains: &mut Vec<String>) -> bool {
    let line = line.trim_start_matches('\u{feff}').trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
        return false;
    }
    if let Some(rule) = line.strip_prefix("||") {
        if let Some(n) = adblock(rule) {
            domains.push(n);
        }
        return true;
    }
    // `[Adblock Plus 2.0]` headers and the like.
    if line.starts_with('[') {
        return false;
    }
    let body = line.split('#').next().unwrap_or_default();
    let mut words = body.split_whitespace();
    let Some(first) = words.next() else {
        return true;
    };
    // `fe80::1%lo0`: an address with its zone.
    let addr = first.split('%').next().unwrap_or(first);
    if addr.parse::<IpAddr>().is_ok() {
        let words: Vec<&str> = words.collect();
        // The machine's own lines (`127.0.0.1 localhost`) are not junk.
        if words
            .iter()
            .all(|w| LOCAL.contains(&w.trim_end_matches('.').to_ascii_lowercase().as_str()))
        {
            return false;
        }
        names.extend(words.into_iter().filter_map(host));
    } else if words.next().is_none() {
        names.extend(host(first));
    }
    true
}

/// `ads.example^` (after `||`): the whole-domain rule, nothing fancier.
fn adblock(rule: &str) -> Option<String> {
    let name = rule.strip_suffix('^').or_else(|| rule.strip_suffix("^|"))?;
    host(name)
}

/// A name worth blocking: valid, not the machine's own, not a bare
/// top-level domain (a list blocking `com` is broken, not strict).
fn host(word: &str) -> Option<String> {
    let n = word.trim_end_matches('.').to_ascii_lowercase();
    let n = n.strip_prefix("*.").map(str::to_owned).unwrap_or(n);
    if !n.contains('.') || n.len() > MAX_NAME_LEN || LOCAL.contains(&n.as_str()) {
        return None;
    }
    let ok = n.split('.').all(|l| {
        (1..=63).contains(&l.len())
            && l.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    // A name of digits only is an address written as a name.
    let numeric = n.bytes().all(|b| b.is_ascii_digit() || b == b'.');
    (ok && !numeric).then_some(n)
}

/// A set of names, compact: one string arena, sorted, with offsets. About
/// 30 bytes per name (a `HashSet<String>` takes about 70), and a lookup is
/// a binary search per label of the name asked.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NameSet {
    arena: String,
    /// Start of each name in `arena`; the next start (or the end) ends it.
    starts: Vec<u32>,
}

impl NameSet {
    /// From names (lowercase, no final dot), deduplicated.
    pub fn new(mut names: Vec<String>) -> Self {
        names.sort_unstable();
        names.dedup();
        let kept = &names;
        let mut set = Self {
            arena: String::with_capacity(kept.iter().map(String::len).sum()),
            starts: Vec::with_capacity(kept.len()),
        };
        for n in kept {
            let Ok(start) = u32::try_from(set.arena.len()) else {
                break;
            };
            set.starts.push(start);
            set.arena.push_str(n);
        }
        set
    }

    pub fn len(&self) -> usize {
        self.starts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.starts.is_empty()
    }

    /// Bytes held (for the status shown to the operator).
    pub fn bytes(&self) -> usize {
        self.arena.len() + self.starts.len() * 4
    }

    fn get(&self, i: usize) -> &str {
        let start = self.starts.get(i).map_or(0, |s| *s as usize);
        let end = self
            .starts
            .get(i + 1)
            .map_or(self.arena.len(), |s| *s as usize);
        self.arena.get(start..end).unwrap_or_default()
    }

    /// Whether `name` (lowercase, no final dot) is in the set.
    pub fn has(&self, name: &str) -> bool {
        let (mut lo, mut hi) = (0usize, self.starts.len());
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            match self.get(mid).cmp(name) {
                std::cmp::Ordering::Equal => return true,
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
            }
        }
        false
    }

    /// Whether `name` or a name above it is in the set.
    pub fn covers(&self, name: &str) -> bool {
        self.has(name) || parents(name).any(|p| self.has(p))
    }
}

/// The names above `name`, nearest first, down to two labels
/// (`a.b.example.com` → `b.example.com`, `example.com`).
fn parents(name: &str) -> impl Iterator<Item = &str> {
    let mut rest = name;
    std::iter::from_fn(move || {
        let (_, up) = rest.split_once('.')?;
        if !up.contains('.') {
            return None;
        }
        rest = up;
        Some(up)
    })
}

/// One loaded list, as the forwarder matches it.
#[derive(Debug, Default)]
pub struct Loaded {
    /// The `/ip dns adlist` entry it came from.
    pub id: u32,
    /// Hosts and plain-domain lines: exact names.
    pub names: NameSet,
    /// `||name^` lines: with every name under them.
    pub domains: NameSet,
    /// Queries it blocked (RouterOS `match-count`).
    pub hits: std::sync::atomic::AtomicU64,
}

impl Loaded {
    pub fn new(id: u32, parsed: Parsed) -> Self {
        Self {
            id,
            names: NameSet::new(parsed.names),
            domains: NameSet::new(parsed.domains),
            hits: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn len(&self) -> usize {
        self.names.len() + self.domains.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn matches(&self, name: &str) -> bool {
        self.names.has(name) || self.domains.covers(name)
    }
}

/// The lists in use: the daemon's loader swaps them in whole, the
/// forwarder reads them without waiting on a download.
#[derive(Debug, Default)]
pub struct Adlists {
    lists: std::sync::RwLock<std::sync::Arc<Vec<std::sync::Arc<Loaded>>>>,
}

impl Adlists {
    pub fn set(&self, lists: Vec<std::sync::Arc<Loaded>>) {
        *self.lists.write().unwrap_or_else(|e| e.into_inner()) = std::sync::Arc::new(lists);
    }

    pub fn lists(&self) -> std::sync::Arc<Vec<std::sync::Arc<Loaded>>> {
        self.lists.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// The first list that blocks `name`.
    pub fn find(&self, name: &str) -> Option<std::sync::Arc<Loaded>> {
        self.lists().iter().find(|l| l.matches(name)).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn hosts_domains_and_adblock() {
        let text = "\u{feff}# StevenBlack-style header\n\
            127.0.0.1 localhost\n\
            ::1 ip6-localhost ip6-loopback\n\
            fe80::1%lo0 localhost\n\
            ff02::2 ip6-allrouters\n\
            0.0.0.0 0.0.0.0\n\
            0.0.0.0 Ads.Example.  tracker.example # inline comment\n\
            :: v6.example\n\
            plain.example\n\
            ||adblock.example^\n\
            ||path.example/banner.gif\n\
            @@||allowed.example^\n\
            ||opts.example^$third-party\n\
            [Adblock Plus 2.0]\n\
            ! comment\n\
            com\n\
            bad_label!.example\n\
            two words.example\n";
        let p = parse(text, 100);
        assert_eq!(
            p.names,
            [
                "ads.example",
                "tracker.example",
                "v6.example",
                "plain.example"
            ]
        );
        assert_eq!(p.domains, ["adblock.example"]);
        // 0.0.0.0 0.0.0.0, path, @@, $opts, com, bad label, two words.
        assert_eq!(p.skipped, 7);
        assert!(!p.truncated);
    }

    #[test]
    fn the_ceiling_holds() {
        let text: String = (0..50)
            .map(|i| format!("0.0.0.0 a{i}.example b{i}.example\n"))
            .collect();
        let p = parse(&text, 25);
        assert_eq!(p.names.len(), 25);
        assert!(p.truncated);
        let long = format!("{}.example\nok.example\n", "a".repeat(MAX_LINE));
        assert_eq!(parse(&long, 10).names, ["ok.example"]);
    }

    #[test]
    fn set_matches_names_and_subdomains() {
        let set = NameSet::new(vec![
            "ads.example".into(),
            "tracker.example.net".into(),
            "ads.example".into(),
        ]);
        assert_eq!(set.len(), 2, "duplicates dropped");
        assert!(set.has("ads.example") && set.covers("ads.example"));
        assert!(!set.has("x.ads.example"), "exact");
        assert!(set.covers("deep.x.ads.example"), "with subdomains");
        assert!(set.has("tracker.example.net"));
        assert!(!set.covers("example"));
        assert!(!set.covers("example.net"));
        assert!(!set.covers("notads.example"));
        assert!(!set.covers("ads.example.org"));
        assert!(!NameSet::default().covers("ads.example"));
    }

    proptest! {
        #[test]
        fn any_text_is_safe(text in "\\PC{0,400}") {
            let p = parse(&text, 64);
            prop_assert!(p.names.len() + p.domains.len() <= 64);
            for n in p.names.iter().chain(&p.domains) {
                prop_assert!(n.len() <= MAX_NAME_LEN && n.contains('.'));
                prop_assert_eq!(n.to_ascii_lowercase(), n.clone());
            }
            let set = NameSet::new(p.names.clone());
            for n in &p.names {
                prop_assert!(set.has(n));
            }
        }

        #[test]
        fn set_agrees_with_a_plain_search(
            listed in proptest::collection::vec("[a-c]{1,2}(\\.[a-c]{1,2}){1,3}", 0..40),
            asked in "[a-c]{1,2}(\\.[a-c]{1,2}){1,4}",
        ) {
            let set = NameSet::new(listed.clone());
            let expected = listed.iter().any(|l| asked == *l || asked.ends_with(&format!(".{l}")));
            prop_assert_eq!(set.covers(&asked), expected);
            prop_assert_eq!(set.has(&asked), listed.contains(&asked));
        }
    }
}
