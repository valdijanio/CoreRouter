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

use std::hash::{BuildHasher, RandomState};
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

/// A set of names, compact: one string arena, sorted, with offsets, and an
/// open-addressing index over it. About 44 bytes per name with its line
/// (37 of them without the index; a `HashSet<String>` takes about 70).
///
/// G4.1z: the lookup runs for every query of the LAN, against whatever
/// names the LAN asks at that moment, so its cost is cache and TLB misses,
/// not instructions. The binary search it replaced touched two or three
/// lines per level, twenty levels for a million names, most of them out of
/// the CPU cache when the names asked are spread over the list (~550 ns,
/// **medido**). The index looks at one byte per slot first: a name on no
/// list (nearly every query) reads one line of `fingerprints`, 1.5 bytes
/// per name, small enough to stay in the CPU's cache and TLB, and never
/// the slots or the names.
#[derive(Debug, Clone, Default)]
pub struct NameSet {
    arena: String,
    /// Start of each name in `arena`; the next start (or the end) ends it.
    starts: Vec<u32>,
    /// Line of each name (parallel to `starts`; empty: not known). Apart
    /// from `forms` so a name costs 5 bytes more, not 8.
    lines: Vec<u32>,
    forms: Vec<u8>,
    /// Linear probing over the names, 1.5 slots per name: a byte of the
    /// name's hash (never 0; 0 is an empty slot), so a slot of another
    /// name is passed over without reading anything else (1 in 255 is not).
    fingerprints: Vec<u8>,
    /// The name's position in the same slot.
    slots: Vec<u32>,
    /// Keyed per set: the list is written by whoever serves its URL, and
    /// names chosen to collide under a known hash would make every lookup
    /// walk a long run of slots.
    hasher: RandomState,
}

/// The index is derived from the names.
impl PartialEq for NameSet {
    fn eq(&self, other: &Self) -> bool {
        self.arena == other.arena
            && self.starts == other.starts
            && self.lines == other.lines
            && self.forms == other.forms
    }
}

impl Eq for NameSet {}

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
            ..Self::default()
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
        drop(all);
        set.index();
        set
    }

    /// Builds the index over the names.
    fn index(&mut self) {
        let n = self.starts.len();
        let cap = n + n / 2 + 1;
        let mut fingerprints = vec![0u8; cap];
        let mut slots = vec![0u32; cap];
        for i in 0..n {
            // Positions fit in u32: each name took a u32 offset.
            let Ok(pos) = u32::try_from(i) else {
                break;
            };
            let h = self.hasher.hash_one(self.get(i));
            let mut at = home(h, cap);
            // There are more slots than names: an empty one comes.
            while let Some(f) = fingerprints.get_mut(at) {
                if *f == 0 {
                    *f = fingerprint(h);
                    if let Some(s) = slots.get_mut(at) {
                        *s = pos;
                    }
                    break;
                }
                at = if at + 1 == cap { 0 } else { at + 1 };
            }
        }
        self.fingerprints = fingerprints;
        self.slots = slots;
    }

    pub fn len(&self) -> usize {
        self.starts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.starts.is_empty()
    }

    /// Bytes held (for the status shown to the operator).
    pub fn bytes(&self) -> usize {
        self.arena.len()
            + self.starts.len() * 4
            + self.lines.len() * 4
            + self.forms.len()
            + self.fingerprints.len()
            + self.slots.len() * 4
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
        if self.is_empty() {
            return None;
        }
        let cap = self.fingerprints.len();
        let h = self.hasher.hash_one(name);
        let fp = fingerprint(h);
        let mut at = home(h, cap);
        // At most every slot once (one is always empty: never all of them).
        for _ in 0..cap {
            let f = *self.fingerprints.get(at)?;
            if f == 0 {
                return None;
            }
            if f == fp {
                let i = *self.slots.get(at)? as usize;
                if self.get(i) == name {
                    return Some(i);
                }
            }
            at = if at + 1 == cap { 0 } else { at + 1 };
        }
        None
    }

    /// Whether `name` (lowercase, no final dot) is in the set.
    pub fn has(&self, name: &str) -> bool {
        self.position(name).is_some()
    }

    /// Whether `name` or a name above it is in the set.
    pub fn covers(&self, name: &str) -> bool {
        !self.is_empty() && (self.has(name) || parents(name).any(|p| self.has(p)))
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

/// The first slot to look at for hash `h` in `cap` slots: the high bits of
/// `h` scaled to `cap` (Lemire's multiply-shift; no division, any `cap`).
/// The fingerprint takes the low bits, so the two do not repeat each other.
fn home(h: u64, cap: usize) -> usize {
    ((u128::from(h) * cap as u128) >> 64) as usize
}

/// The byte of `h` kept in the slot: its low byte, 0 taken as 1 (0 is an
/// empty slot).
fn fingerprint(h: u64) -> u8 {
    (h as u8).max(1)
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
///
/// G4.1z: every query of the LAN reads them, from every listener thread at
/// once. One lock and one shared reference count made the threads take
/// turns on their cache line (36 ns a lookup alone, 186 ns each with four
/// threads, **medido**); each stripe of threads reads its own copy of the
/// list of lists, and only a blocked name clones a list's `Arc`.
#[derive(Debug)]
pub struct Adlists {
    lists: std::sync::RwLock<Lists>,
    stripes: Box<[ListsStripe]>,
}

type Lists = std::sync::Arc<Vec<std::sync::Arc<Loaded>>>;

/// One stripe's copy, on cache lines of its own.
#[derive(Debug, Default)]
#[repr(align(128))]
struct ListsStripe(std::sync::Mutex<Lists>);

impl Default for Adlists {
    fn default() -> Self {
        Self {
            lists: std::sync::RwLock::default(),
            stripes: (0..crate::server::STRIPES)
                .map(|_| ListsStripe::default())
                .collect(),
        }
    }
}

impl Adlists {
    pub fn set(&self, lists: Vec<std::sync::Arc<Loaded>>) {
        let lists = std::sync::Arc::new(lists);
        let mut all = self.lists.write().unwrap_or_else(|e| e.into_inner());
        // Under the write lock: two loaders never leave stripes apart.
        for s in &self.stripes {
            *s.0.lock().unwrap_or_else(|e| e.into_inner()) = lists.clone();
        }
        *all = lists;
    }

    pub fn lists(&self) -> Lists {
        self.lists.read().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// The first list that blocks `name`.
    pub fn find(&self, name: &str) -> Option<std::sync::Arc<Loaded>> {
        let find = |lists: &Lists| lists.iter().find(|l| l.matches(name)).cloned();
        match self.stripes.get(crate::server::my_stripe()) {
            Some(s) => find(&s.0.lock().unwrap_or_else(|e| e.into_inner())),
            None => find(&self.lists()),
        }
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

    /// G4.1z: the index finds every name of a big set, and nothing else,
    /// whatever the hash key of the set.
    #[test]
    fn the_index_finds_every_name_and_only_them() {
        let names: Vec<String> = (0..5000).map(|i| format!("n{i}.l{}.example", i % 7)).collect();
        let set = NameSet::new(names.clone());
        let other = NameSet::new(names.clone());
        assert_eq!(set, other, "equal names, equal sets (the keys differ)");
        assert_eq!(set.len(), 5000);
        for n in &names {
            assert!(set.has(n), "{n}");
            assert!(other.has(n), "{n}");
        }
        for i in 5000..10_000 {
            assert!(!set.has(&format!("n{i}.l{}.example", i % 7)));
        }
        assert!(!set.has("") && !set.has("example"));
        // One name, and the empty name (NameSet::new takes any string).
        let one = NameSet::new(vec!["a.example".into(), String::new()]);
        assert!(one.has("a.example") && one.has("") && !one.has("b.example"));
        assert!(!NameSet::default().has(""));
        assert_eq!(set.bytes() - set.arena.len() - 4 * 5000, 5 * set.slots.len());
        assert_eq!(set.slots.len(), 7501, "1.5 slots per name");
    }

    /// G4.1z: each stripe of threads reads its own copy; a new set of
    /// lists reaches every thread, also the ones that read the old one.
    #[test]
    fn a_new_set_reaches_every_stripe() {
        let lists = Adlists::default();
        let one = std::sync::Arc::new(Loaded::new(1, parse("0.0.0.0 ads.example\n", 10)));
        let two = std::sync::Arc::new(Loaded::new(2, parse("0.0.0.0 track.example\n", 10)));
        let threads = 2 * crate::server::STRIPES;
        let asked = |name: &str| {
            std::thread::scope(|s| {
                let all: Vec<_> = (0..threads)
                    .map(|_| s.spawn(|| lists.find(name).map(|l| l.id)))
                    .collect();
                all.into_iter().map(|t| t.join().unwrap()).collect::<Vec<_>>()
            })
        };
        assert!(asked("ads.example").iter().all(Option::is_none));
        lists.set(vec![one]);
        assert!(asked("ads.example").iter().all(|id| *id == Some(1)));
        lists.set(vec![two]);
        assert!(asked("ads.example").iter().all(Option::is_none));
        assert!(asked("track.example").iter().all(|id| *id == Some(2)));
        assert_eq!(lists.lists().len(), 1);
    }

    /// G4.1z: the forwarder's state through the stripes is one state,
    /// whichever thread made it and whether borrowed or cloned.
    #[test]
    fn the_forwarder_state_is_one_for_all_threads() {
        let f = crate::server::tests::forwarder(|_| {});
        let list = std::sync::Arc::new(Loaded::new(7, parse("0.0.0.0 ads.example\n", 10)));
        std::thread::scope(|s| {
            s.spawn(|| f.state::<Adlists>().set(vec![list.clone()]));
        });
        let seen: Vec<Option<u32>> = std::thread::scope(|s| {
            let all: Vec<_> = (0..2 * crate::server::STRIPES)
                .map(|i| {
                    let f = &f;
                    s.spawn(move || {
                        if i % 2 == 0 {
                            f.with_state(|l: &Adlists| l.find("ads.example").map(|l| l.id))
                        } else {
                            f.state::<Adlists>().find("ads.example").map(|l| l.id)
                        }
                    })
                })
                .collect();
            all.into_iter().map(|t| t.join().unwrap()).collect()
        });
        assert!(seen.iter().all(|id| *id == Some(7)), "{seen:?}");
        assert!(std::sync::Arc::ptr_eq(
            &f.state::<Adlists>(),
            &std::thread::scope(|s| s.spawn(|| f.state::<Adlists>()).join().unwrap())
        ));
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
