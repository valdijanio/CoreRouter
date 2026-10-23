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

/// Where a listed name came from (G6.8, "Why this answer"): its line and
/// which of the list's line texts it was on ([`Parsed::forms`]).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Origin {
    /// 1-based; 0 when unknown.
    pub line: u32,
    /// Index into the forms; [`NO_FORM`] when that text was not kept.
    pub form: u8,
}

/// An [`Origin`] whose line text was not kept.
pub const NO_FORM: u8 = u8::MAX;
/// Distinct line texts kept per list (most lists are one form:
/// `0.0.0.0 <name>`).
const MAX_FORMS: usize = NO_FORM as usize;
/// Longest line text kept as a form.
const MAX_FORM_LEN: usize = 200;
/// Where the name stands in a form.
const HOLE: char = '\0';

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
    /// Where each of `names` came from (same order; shorter: unknown).
    pub name_origins: Vec<Origin>,
    /// Where each of `domains` came from.
    pub domain_origins: Vec<Origin>,
    /// The texts of the lines the names came from, trimmed, with NUL where
    /// the name stands; deduplicated, at most [`MAX_FORMS`].
    pub forms: Vec<String>,
}

/// Collects the forms of one list while it is parsed.
#[derive(Default)]
struct Forms {
    index: std::collections::HashMap<String, u8>,
    list: Vec<String>,
    /// The last form: (text before the name, after it, index). Most
    /// lines are the same form, found again without building a string.
    last: Option<(String, String, u8)>,
}

impl Forms {
    /// The form of `word` (a slice of `line`) on `line`.
    fn of(&mut self, line: &str, word: &str) -> u8 {
        let start = (word.as_ptr() as usize).wrapping_sub(line.as_ptr() as usize);
        let (Some(before), Some(after)) = (line.get(..start), line.get(start + word.len()..))
        else {
            return NO_FORM;
        };
        if line.len() > MAX_FORM_LEN {
            return NO_FORM;
        }
        if let Some((b, a, i)) = &self.last
            && b == before
            && a == after
        {
            return *i;
        }
        let form = format!("{before}{HOLE}{after}");
        if let Some(i) = self.index.get(&form).copied() {
            self.last = Some((before.to_owned(), after.to_owned(), i));
            return i;
        }
        let Ok(i) = u8::try_from(self.list.len()) else {
            return NO_FORM;
        };
        if self.list.len() >= MAX_FORMS {
            return NO_FORM;
        }
        self.index.insert(form.clone(), i);
        self.list.push(form);
        self.last = Some((before.to_owned(), after.to_owned(), i));
        i
    }
}

/// Parses a list, keeping at most `max` names.
pub fn parse(text: &str, max: usize) -> Parsed {
    let mut out = Parsed::default();
    let mut forms = Forms::default();
    for (n, line) in text.lines().enumerate() {
        if out.names.len() + out.domains.len() >= max {
            out.truncated = true;
            break;
        }
        if line.len() > MAX_LINE {
            out.skipped += 1;
            continue;
        }
        let before = out.names.len() + out.domains.len();
        let at = u32::try_from(n + 1).unwrap_or(u32::MAX);
        let had = parse_line(line, &mut |domain, name, word, line| {
            let origin = Origin {
                line: at,
                form: forms.of(line, word),
            };
            if domain {
                out.domains.push(name);
                out.domain_origins.push(origin);
            } else {
                out.names.push(name);
                out.name_origins.push(origin);
            }
        });
        if had && out.names.len() + out.domains.len() == before {
            out.skipped += 1;
        }
        if out.names.len() + out.domains.len() > max {
            out.names.truncate(max.saturating_sub(out.domains.len()));
            out.name_origins.truncate(out.names.len());
            out.truncated = true;
        }
    }
    out.forms = forms.list;
    out
}

/// One line: each name found goes to `push(domain, name, word, line)`
/// (`word` is the slice of `line` it was read from); whether the line held
/// anything but a comment.
fn parse_line(line: &str, push: &mut dyn FnMut(bool, String, &str, &str)) -> bool {
    let line = line.trim_start_matches('\u{feff}').trim();
    if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
        return false;
    }
    if let Some(rule) = line.strip_prefix("||") {
        if let Some((n, word)) = adblock(rule) {
            push(true, n, word, line);
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
        for w in words {
            if let Some(n) = host(w) {
                push(false, n, w, line);
            }
        }
    } else if words.next().is_none()
        && let Some(n) = host(first)
    {
        push(false, n, first, line);
    }
    true
}

/// `ads.example^` (after `||`): the whole-domain rule, nothing fancier;
/// the name and the slice it was read from.
fn adblock(rule: &str) -> Option<(String, &str)> {
    let name = rule.strip_suffix('^').or_else(|| rule.strip_suffix("^|"))?;
    host(name).map(|n| (n, name))
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
    /// Line of each name (parallel to `starts`; empty: not known). Apart
    /// from `forms` so a name costs 5 bytes more, not 8.
    lines: Vec<u32>,
    forms: Vec<u8>,
}

impl NameSet {
    /// From names (lowercase, no final dot), deduplicated.
    pub fn new(names: Vec<String>) -> Self {
        Self::with_origins(names, Vec::new())
    }

    /// From names and where each came from (`origins` parallel to `names`,
    /// shorter: unknown); a repeated name keeps its first line.
    pub fn with_origins(names: Vec<String>, origins: Vec<Origin>) -> Self {
        let keep = !origins.is_empty();
        let mut all: Vec<(String, Origin)> = names
            .into_iter()
            .enumerate()
            .map(|(i, n)| (n, origins.get(i).copied().unwrap_or_default()))
            .collect();
        drop(origins);
        all.sort_unstable_by(|a, b| a.0.cmp(&b.0).then(a.1.line.cmp(&b.1.line)));
        all.dedup_by(|b, a| a.0 == b.0);
        let mut set = Self {
            arena: String::with_capacity(all.iter().map(|n| n.0.len()).sum()),
            starts: Vec::with_capacity(all.len()),
            lines: Vec::with_capacity(if keep { all.len() } else { 0 }),
            forms: Vec::with_capacity(if keep { all.len() } else { 0 }),
        };
        for (n, o) in &all {
            let Ok(start) = u32::try_from(set.arena.len()) else {
                break;
            };
            set.starts.push(start);
            set.arena.push_str(n);
            if keep {
                set.lines.push(o.line);
                set.forms.push(o.form);
            }
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
        self.arena.len() + self.starts.len() * 4 + self.lines.len() * 4 + self.forms.len()
    }

    fn get(&self, i: usize) -> &str {
        let start = self.starts.get(i).map_or(0, |s| *s as usize);
        let end = self
            .starts
            .get(i + 1)
            .map_or(self.arena.len(), |s| *s as usize);
        self.arena.get(start..end).unwrap_or_default()
    }

    /// Where `name` (lowercase, no final dot) is in the set.
    fn position(&self, name: &str) -> Option<usize> {
        let (mut lo, mut hi) = (0usize, self.starts.len());
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            match self.get(mid).cmp(name) {
                std::cmp::Ordering::Equal => return Some(mid),
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
            }
        }
        None
    }

    /// Whether `name` (lowercase, no final dot) is in the set.
    pub fn has(&self, name: &str) -> bool {
        self.position(name).is_some()
    }

    /// Whether `name` or a name above it is in the set.
    pub fn covers(&self, name: &str) -> bool {
        self.has(name) || parents(name).any(|p| self.has(p))
    }

    /// The listed name that covers `name` (itself or the nearest above),
    /// and where it came from.
    pub fn covering<'a>(&self, name: &'a str) -> Option<(&'a str, Origin)> {
        std::iter::once(name)
            .chain(parents(name))
            .find_map(|n| self.position(n).map(|i| (n, self.origin(i))))
    }

    /// `name` itself, and where it came from.
    pub fn exact<'a>(&self, name: &'a str) -> Option<(&'a str, Origin)> {
        self.position(name).map(|i| (name, self.origin(i)))
    }

    fn origin(&self, i: usize) -> Origin {
        Origin {
            line: self.lines.get(i).copied().unwrap_or(0),
            form: self.forms.get(i).copied().unwrap_or(NO_FORM),
        }
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
    /// [`Parsed::forms`].
    forms: Vec<String>,
}

/// The line of a list that blocks a name (G6.8, "Why this answer").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blocked {
    /// The `/ip dns adlist` entry.
    pub list: u32,
    /// 1-based; 0 when unknown.
    pub line: u32,
    /// The line as the list had it (trimmed), or the rule rebuilt from the
    /// name when that text was not kept.
    pub text: String,
}

impl Loaded {
    pub fn new(id: u32, parsed: Parsed) -> Self {
        Self {
            id,
            names: NameSet::with_origins(parsed.names, parsed.name_origins),
            domains: NameSet::with_origins(parsed.domains, parsed.domain_origins),
            hits: std::sync::atomic::AtomicU64::new(0),
            forms: parsed.forms,
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

    /// The line that blocks `name`, if this list does.
    pub fn blocking(&self, name: &str) -> Option<Blocked> {
        let (listed, origin, domain) = match self.names.exact(name) {
            Some((n, o)) => (n, o, false),
            None => {
                let (n, o) = self.domains.covering(name)?;
                (n, o, true)
            }
        };
        let text = match self.forms.get(usize::from(origin.form)) {
            Some(form) => form.replace(HOLE, listed),
            None if domain => format!("||{listed}^"),
            None => listed.to_owned(),
        };
        Some(Blocked {
            list: self.id,
            line: origin.line,
            text,
        })
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

    /// G6.8: the line that blocks a name, as the list had it.
    #[test]
    fn a_blocked_name_knows_its_line() {
        let text = "# header\n0.0.0.0 ads.example\n\n0.0.0.0 Two.example three.example # pair\n||track.example^\nplain.example\n0.0.0.0 ads.example\n";
        let list = Loaded::new(4, parse(text, 100));
        let b = |n: &str| list.blocking(n).map(|b| (b.list, b.line, b.text));
        assert_eq!(
            b("ads.example"),
            Some((4, 2, "0.0.0.0 ads.example".into())),
            "the first line, not the repeat"
        );
        assert_eq!(
            b("two.example"),
            Some((4, 4, "0.0.0.0 two.example three.example # pair".into()))
        );
        assert_eq!(
            b("three.example"),
            Some((4, 4, "0.0.0.0 Two.example three.example # pair".into()))
        );
        assert_eq!(
            b("x.y.track.example"),
            Some((4, 5, "||track.example^".into()))
        );
        assert_eq!(b("plain.example"), Some((4, 6, "plain.example".into())));
        assert_eq!(b("other.example"), None);
        // Past the forms kept: the rule rebuilt from the name.
        let many: String = (0..300)
            .map(|i| format!("0.0.0.0 n{i}.example # {i}\n"))
            .collect();
        let list = Loaded::new(1, parse(&many, 1000));
        assert_eq!(
            list.blocking("n3.example").map(|b| b.text),
            Some("0.0.0.0 n3.example # 3".into())
        );
        assert_eq!(
            list.blocking("n299.example").map(|b| (b.line, b.text)),
            Some((300, "n299.example".into()))
        );
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
