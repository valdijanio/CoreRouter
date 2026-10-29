//! `/routing filter` as FRR policy (G3.2b): each chain a route-map
//! `CR-<chain>`, each matcher a prefix-list, AS-path access-list or
//! community-list. Every name starts with `CR-`, so hand-written policy
//! of the operator is left alone (`hal-frr` owns only `CR-` contexts).
//!
//! RouterOS rules are programs (`if`/`else`, `&&`, `||`, `not`, `jump`);
//! a route-map is a list of entries tried in order. The program becomes
//! entries with forward jumps:
//!
//! - a test is `permit` + one `match` + `on-match goto <then>`; when the
//!   match fails FRR tries the next entry, the "else" side;
//! - `a && b`, `a || b` and `not a` are tests that jump past each other
//!   (short circuit, as the language evaluates them);
//! - an action is `permit` + `set …` + `on-match next`; `accept` is a
//!   `permit` that ends the map, `reject` a `deny`;
//! - `jump` inlines the other chain (FRR's `call` cannot tell "the called
//!   map accepted" from "it fell through", RouterOS can), `return` jumps
//!   past it;
//! - the end of the chain is `deny 65535`: RouterOS rejects what no rule
//!   accepted (and FRR's implicit deny says the same).
//!
//! Then a few rewrites shrink it: a test whose target always ends the
//! same way takes that ending (`if (dst in X) { reject }` is one `deny`
//! entry), actions merge into the entry after them, jumps to the next
//! entry and unreachable entries go. The property test at the bottom runs
//! random rules both ways — [`super::eval`] and a model of FRR's
//! route-map semantics — and wants the same verdict and attributes.
//!
//! Generated lists are named by their content (`CR-P-<hash>`), so the
//! same matcher in two chains is one list and inserting a rule does not
//! rename the others: the diff against the running config stays small.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;

#[cfg(doc)]
use corerouter_model::routing_filter::PrependCount;
use corerouter_model::routing_filter::{PrefixEntry, RoutingFilter};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use super::eval::{MAX_JUMP_DEPTH, Problem, parsed_chains};
use super::parse::{Atom, CommArg, CommHow, CommOp, Expr, Family, SetOp, Stmt};
use super::{CommunityValue, Large, Protocol, community_text, fnv};

/// The sequence of the final `deny` of every map.
pub const END_SEQ: u32 = 65_535;
/// The first sequence of a chain's entries: 1..=9 are left to the
/// prelude ([`render_with`]: the RPKI checks of G3.2c, `deny` before any
/// rule of the operator).
pub const FIRST_SEQ: usize = 10;
/// Most entries of one route-map (sequence numbers 10..65535).
pub const MAX_ENTRIES: usize = 65_525;

/// The route-map of chain `chain`.
pub fn route_map(chain: &str) -> String {
    format!("CR-{chain}")
}

/// A `match` of a route-map entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Match {
    Plist { v6: bool, name: String },
    AsPath(String),
    Comm { name: String, exact: bool },
    Large { name: String, exact: bool },
    Proto(Protocol),
}

/// A `set` of a route-map entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Set {
    LocalPref(u32),
    Med(u32),
    /// Our AS this many times.
    Prepend(u32, u8),
    /// The next hop (G3.9fh); the entry before it tests the family.
    Gw(std::net::IpAddr),
    Comm(CommHow, Vec<u32>, String),
    Large(CommHow, Vec<Large>, String),
}

impl Set {
    fn slot(&self) -> u8 {
        match self {
            Set::LocalPref(_) => 0,
            Set::Med(_) => 1,
            Set::Prepend(..) => 2,
            Set::Comm(..) => 3,
            Set::Large(..) => 4,
            Set::Gw(_) => 5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Exit {
    /// End of the map (with the entry's permit or deny).
    Done,
    /// `on-match next`.
    Next,
    /// `on-match goto` the entry at this index.
    Goto(usize),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Entry {
    pub permit: bool,
    /// All must match (FRR ANDs the matches of one entry); here at most one.
    pub matches: Vec<Match>,
    pub sets: Vec<Set>,
    pub exit: Exit,
    pub description: Option<String>,
}

impl Entry {
    fn reject() -> Self {
        Entry {
            permit: false,
            matches: Vec::new(),
            sets: Vec::new(),
            exit: Exit::Done,
            description: None,
        }
    }

    fn accept() -> Self {
        Entry {
            permit: true,
            ..Entry::reject()
        }
    }

    fn goto(l: usize) -> Self {
        Entry {
            permit: true,
            exit: Exit::Goto(l),
            ..Entry::reject()
        }
    }

    /// No match: it always applies when reached.
    fn always(&self) -> bool {
        self.matches.is_empty()
    }
}

/// The generated lists, by kind and name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Lists {
    pub prefix4: BTreeMap<String, Vec<PrefixEntry>>,
    pub prefix6: BTreeMap<String, Vec<PrefixEntry>>,
    pub aspath: BTreeMap<String, String>,
    /// Entries; one entry matches when the route has all its communities.
    pub comm: BTreeMap<String, Vec<Vec<u32>>>,
    pub large: BTreeMap<String, Vec<Vec<Large>>>,
}

/// The entry for prefix `p` and lengths `lo..=hi` (FRR wants len < ge <=
/// le <= max; the shortest spelling).
fn plist_entry(p: IpNet, lo: u8, hi: u8) -> PrefixEntry {
    let plen = p.prefix_len();
    let max = p.max_prefix_len();
    let ge = (lo > plen).then_some(lo);
    let le = match ge {
        Some(_) if hi == max => None,
        Some(_) => Some(hi),
        None if hi > plen => Some(hi),
        None => None,
    };
    PrefixEntry { prefix: p, ge, le }
}

fn any4() -> IpNet {
    IpNet::V4(Ipv4Net::default())
}

fn any6() -> IpNet {
    IpNet::V6(Ipv6Net::default())
}

/// What one matcher becomes: never true, always true, or true when any of
/// these FRR matches is.
enum Alt {
    Never,
    Always,
    Any(Vec<Match>),
}

/// The text of a matcher, for the entry's description.
fn atom_text(a: &Atom) -> String {
    let vals = |arg: &CommArg| match arg {
        CommArg::Values(v) => v
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(","),
        CommArg::List(n) => n.clone(),
    };
    match a {
        Atom::DstIn(n) => format!("dst in {n}"),
        Atom::DstEq(n) => format!("dst == {n}"),
        Atom::DstList(n) => format!("dst in {n}"),
        Atom::DstLen(lo, hi) => format!("dst-len in {lo}-{hi}"),
        Atom::Afi(Family::V4) => "afi ipv4".into(),
        Atom::Afi(Family::V6) => "afi ipv6".into(),
        Atom::Protocol(p) => format!("protocol {}", p.name()),
        Atom::AsPath(re) => format!("bgp-as-path {re}"),
        Atom::Comm { large, op, arg } => {
            let list = if matches!(arg, CommArg::List(_)) {
                "-list"
            } else {
                ""
            };
            let op = match op {
                CommOp::Includes => "includes",
                CommOp::Any => "any",
                CommOp::Equal => "equal",
            };
            let what = if *large {
                "bgp-large-communities"
            } else {
                "bgp-communities"
            };
            format!("{what} {op}{list} {}", vals(arg))
        }
    }
}

/// FRR keeps a description as typed; printable ASCII, bounded.
fn description(s: &str) -> String {
    let mut out: String = s
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(80)
        .collect();
    out.truncate(out.trim_end().len());
    out
}

enum Item {
    Label(usize),
    E(Entry),
}

struct Comp<'a> {
    filter: &'a RoutingFilter,
    chains: &'a HashMap<&'a str, &'a [Stmt]>,
    lists: &'a mut Lists,
    asn: Option<u32>,
    /// Copies of our AS the session adds on its own and that a `set
    /// bgp-path-prepend N` counts (G3.9fg: 1 on an eBGP output map).
    counted: u8,
    items: Vec<Item>,
    labels: usize,
    entries: usize,
    stack: Vec<&'a str>,
    problems: Vec<String>,
    too_big: bool,
}

impl<'a> Comp<'a> {
    fn label(&mut self) -> usize {
        self.labels += 1;
        self.labels - 1
    }

    fn place(&mut self, l: usize) {
        self.items.push(Item::Label(l));
    }

    fn emit(&mut self, e: Entry) {
        self.entries += 1;
        if self.entries > MAX_ENTRIES * 2 {
            self.too_big = true;
            return;
        }
        self.items.push(Item::E(e));
    }

    fn comm_values(&mut self, arg: &CommArg) -> Vec<CommunityValue> {
        match arg {
            CommArg::Values(v) => v.clone(),
            CommArg::List(name) => self
                .filter
                .community_lists
                .get(name)
                .map(|l| {
                    l.communities
                        .iter()
                        .filter_map(|c| super::parse_community(c).ok())
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    fn normal(&mut self, arg: &CommArg) -> Vec<u32> {
        let mut v: Vec<u32> = self
            .comm_values(arg)
            .into_iter()
            .filter_map(|c| {
                if let CommunityValue::Normal(n) = c {
                    Some(n)
                } else {
                    None
                }
            })
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    fn larges(&mut self, arg: &CommArg) -> Vec<Large> {
        let mut v: Vec<Large> = self
            .comm_values(arg)
            .into_iter()
            .filter_map(|c| {
                if let CommunityValue::Large(n) = c {
                    Some(n)
                } else {
                    None
                }
            })
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    fn plist(&mut self, net: IpNet, lo: u8, hi: u8) -> Match {
        let e = plist_entry(net, lo, hi);
        let v6 = matches!(net, IpNet::V6(_));
        let name = format!("CR-P-{:016x}", fnv(&e.to_string()));
        let map = if v6 {
            &mut self.lists.prefix6
        } else {
            &mut self.lists.prefix4
        };
        map.entry(name.clone()).or_insert_with(|| vec![e]);
        Match::Plist { v6, name }
    }

    fn comm_list(&mut self, entries: Vec<Vec<u32>>) -> String {
        let key: Vec<String> = entries
            .iter()
            .map(|e| {
                e.iter()
                    .map(|c| c.to_string())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect();
        let name = format!("CR-C-{:016x}", fnv(&key.join("|")));
        self.lists.comm.entry(name.clone()).or_insert(entries);
        name
    }

    fn large_list(&mut self, entries: Vec<Vec<Large>>) -> String {
        let key: Vec<String> = entries
            .iter()
            .map(|e| {
                e.iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect();
        let name = format!("CR-LC-{:016x}", fnv(&key.join("|")));
        self.lists.large.entry(name.clone()).or_insert(entries);
        name
    }

    fn alt(&mut self, a: &Atom) -> Alt {
        match a {
            Atom::DstIn(n) => Alt::Any(vec![self.plist(*n, n.prefix_len(), n.max_prefix_len())]),
            Atom::DstEq(n) => Alt::Any(vec![self.plist(*n, n.prefix_len(), n.prefix_len())]),
            Atom::DstLen(lo, hi) => {
                let mut out = Vec::new();
                if *lo <= 32 {
                    out.push(self.plist(any4(), *lo, (*hi).min(32)));
                }
                out.push(self.plist(any6(), *lo, (*hi).min(128)));
                Alt::Any(out)
            }
            Atom::Afi(Family::V4) => Alt::Any(vec![self.plist(any4(), 0, 32)]),
            Atom::Afi(Family::V6) => Alt::Any(vec![self.plist(any6(), 0, 128)]),
            Atom::Protocol(p) => Alt::Any(vec![Match::Proto(*p)]),
            Atom::DstList(name) => {
                let Some(l) = self.filter.prefix_lists.get(name) else {
                    return Alt::Never;
                };
                let name = format!("CR-L-{name}");
                let (v4, v6): (Vec<PrefixEntry>, Vec<PrefixEntry>) = l
                    .entries
                    .iter()
                    .partition(|e| matches!(e.prefix, IpNet::V4(_)));
                let mut out = Vec::new();
                for (v6flag, entries) in [(false, v4), (true, v6)] {
                    if entries.is_empty() {
                        continue;
                    }
                    let map = if v6flag {
                        &mut self.lists.prefix6
                    } else {
                        &mut self.lists.prefix4
                    };
                    map.insert(name.clone(), entries);
                    out.push(Match::Plist {
                        v6: v6flag,
                        name: name.clone(),
                    });
                }
                if out.is_empty() {
                    Alt::Never
                } else {
                    Alt::Any(out)
                }
            }
            Atom::AsPath(re) => {
                let name = format!("CR-A-{:016x}", fnv(re));
                self.lists
                    .aspath
                    .entry(name.clone())
                    .or_insert_with(|| re.clone());
                Alt::Any(vec![Match::AsPath(name)])
            }
            Atom::Comm {
                large: false,
                op,
                arg,
            } => {
                let v = self.normal(arg);
                if v.is_empty() {
                    return if *op == CommOp::Includes {
                        Alt::Always
                    } else {
                        Alt::Never
                    };
                }
                let (entries, exact) = match op {
                    CommOp::Includes => (vec![v], false),
                    CommOp::Any => (v.into_iter().map(|c| vec![c]).collect(), false),
                    CommOp::Equal => (vec![v], true),
                };
                let name = self.comm_list(entries);
                Alt::Any(vec![Match::Comm { name, exact }])
            }
            Atom::Comm {
                large: true,
                op,
                arg,
            } => {
                let v = self.larges(arg);
                if v.is_empty() {
                    return if *op == CommOp::Includes {
                        Alt::Always
                    } else {
                        Alt::Never
                    };
                }
                let (entries, exact) = match op {
                    CommOp::Includes => (vec![v], false),
                    CommOp::Any => (v.into_iter().map(|c| vec![c]).collect(), false),
                    CommOp::Equal => (vec![v], true),
                };
                let name = self.large_list(entries);
                Alt::Any(vec![Match::Large { name, exact }])
            }
        }
    }

    /// Code that goes on to `t` when `e` holds, to `f` when not.
    fn cond(&mut self, e: &Expr, t: usize, f: usize) {
        match e {
            Expr::Not(x) => self.cond(x, f, t),
            Expr::And(a, b) => {
                let mid = self.label();
                self.cond(a, mid, f);
                self.place(mid);
                self.cond(b, t, f);
            }
            Expr::Or(a, b) => {
                let mid = self.label();
                self.cond(a, t, mid);
                self.place(mid);
                self.cond(b, t, f);
            }
            Expr::Atom(a) => match self.alt(a) {
                Alt::Never => self.emit(Entry::goto(f)),
                Alt::Always => self.emit(Entry::goto(t)),
                Alt::Any(ms) => {
                    let text = description(&atom_text(a));
                    for m in ms {
                        self.emit(Entry {
                            permit: true,
                            matches: vec![m],
                            sets: Vec::new(),
                            exit: Exit::Goto(t),
                            description: Some(text.clone()),
                        });
                    }
                    self.emit(Entry::goto(f));
                }
            },
        }
    }

    fn set(&mut self, op: &SetOp) -> Option<Set> {
        Some(match op {
            SetOp::LocalPref(v) => Set::LocalPref(*v),
            SetOp::Med(v) => Set::Med(*v),
            SetOp::Gw(a) => Set::Gw(*a),
            // G3.9fg: N copies in all, the session's own included; none
            // left (N = 1 on eBGP), nothing to do.
            SetOp::Prepend(n) if *n <= self.counted => return None,
            SetOp::Prepend(n) => match self.asn {
                Some(a) => Set::Prepend(a, *n - self.counted),
                None => {
                    self.problems.push("set bgp-path-prepend needs the chain's own AS: use it from connections of one BGP instance".into());
                    return None;
                }
            },
            SetOp::Comm {
                large: false,
                how,
                arg,
            } => {
                let v = self.normal(arg);
                if v.is_empty() && *how != CommHow::Set {
                    return None;
                }
                let name = if *how == CommHow::Delete {
                    self.comm_list(v.iter().map(|c| vec![*c]).collect())
                } else {
                    String::new()
                };
                Set::Comm(*how, v, name)
            }
            SetOp::Comm {
                large: true,
                how,
                arg,
            } => {
                let v = self.larges(arg);
                if v.is_empty() && *how != CommHow::Set {
                    return None;
                }
                let name = if *how == CommHow::Delete {
                    self.large_list(v.iter().map(|c| vec![*c]).collect())
                } else {
                    String::new()
                };
                Set::Large(*how, v, name)
            }
        })
    }

    /// `body` in sequence; falls through at its end; `ret` is where
    /// `return` goes.
    fn stmts(&mut self, body: &'a [Stmt], ret: usize) {
        for s in body {
            if self.too_big {
                return;
            }
            match s {
                Stmt::If { cond, then, els } => {
                    let (lt, lf, end) = (self.label(), self.label(), self.label());
                    self.cond(cond, lt, lf);
                    self.place(lt);
                    self.stmts(then, ret);
                    self.emit(Entry::goto(end));
                    self.place(lf);
                    self.stmts(els, ret);
                    self.place(end);
                }
                Stmt::Accept => self.emit(Entry::accept()),
                Stmt::Reject => self.emit(Entry::reject()),
                Stmt::Return => self.emit(Entry::goto(ret)),
                Stmt::Jump(c) => {
                    let target = self.chains.get(c.as_str()).copied();
                    match target {
                        Some(sub)
                            if !self.stack.contains(&c.as_str())
                                && self.stack.len() <= MAX_JUMP_DEPTH =>
                        {
                            let back = self.label();
                            self.stack.push(
                                self.chains
                                    .get_key_value(c.as_str())
                                    .map_or("", |(k, _)| *k),
                            );
                            self.stmts(sub, back);
                            self.stack.pop();
                            self.place(back);
                        }
                        // No such chain, a loop, too deep: reject (as eval).
                        _ => self.emit(Entry::reject()),
                    }
                }
                // G3.9fh: `set gw` changes routes of its family only: FRR
                // would write an IPv6 next hop into an IPv4 route.
                Stmt::Set(SetOp::Gw(a)) => {
                    let fam = if a.is_ipv4() { Family::V4 } else { Family::V6 };
                    let (lt, end) = (self.label(), self.label());
                    self.cond(&Expr::Atom(Atom::Afi(fam)), lt, end);
                    self.place(lt);
                    self.emit(Entry {
                        permit: true,
                        matches: Vec::new(),
                        sets: vec![Set::Gw(*a)],
                        exit: Exit::Next,
                        description: None,
                    });
                    self.place(end);
                }
                Stmt::Set(op) => {
                    if let Some(set) = self.set(op) {
                        self.emit(Entry {
                            permit: true,
                            matches: Vec::new(),
                            sets: vec![set],
                            exit: Exit::Next,
                            description: None,
                        });
                    }
                }
            }
        }
    }
}

/// Labels resolved to entry indices; the last entry is the end (`deny`).
fn resolve(items: Vec<Item>, end: usize) -> Vec<Entry> {
    let mut at: HashMap<usize, usize> = HashMap::new();
    let mut n = 0;
    for it in &items {
        match it {
            Item::Label(l) => {
                at.insert(*l, n);
            }
            Item::E(_) => n += 1,
        }
    }
    at.insert(end, n);
    let mut out: Vec<Entry> = items
        .into_iter()
        .filter_map(|it| match it {
            Item::E(mut e) => {
                if let Exit::Goto(l) = e.exit {
                    e.exit = Exit::Goto(at.get(&l).copied().unwrap_or(n));
                }
                Some(e)
            }
            Item::Label(_) => None,
        })
        .collect();
    out.push(Entry::reject());
    out
}

/// Where control goes after entry `i` applies (`None`: the map ends).
fn after(e: &Entry, i: usize) -> Option<usize> {
    if !e.permit {
        return None;
    }
    match e.exit {
        Exit::Done => None,
        Exit::Next => Some(i + 1),
        Exit::Goto(j) => Some(j),
    }
}

/// The rewrites, until nothing changes (each pass shrinks or keeps the
/// map; bounded to be safe).
fn optimize(mut v: Vec<Entry>) -> Vec<Entry> {
    for _ in 0..64 {
        let before = v.clone();
        // 1. A transfer to an entry that only transfers goes straight on.
        for i in 0..v.len() {
            let mut hops = 0;
            while let Some(e) = v.get(i)
                && let Exit::Goto(j) = e.exit
                && let Some(t) = v.get(j)
                && t.permit
                && t.always()
                && t.sets.is_empty()
                && hops < 64
            {
                let next = match t.exit {
                    Exit::Goto(k) => k,
                    Exit::Next => j + 1,
                    Exit::Done => break,
                };
                if let Some(e) = v.get_mut(i) {
                    e.exit = Exit::Goto(next);
                }
                hops += 1;
            }
        }
        // 2. An entry whose next step always applies takes it over (its
        //    sets merge when they write different attributes).
        for i in 0..v.len() {
            let Some(e) = v.get(i) else { break };
            let Some(j) = after(e, i) else { continue };
            let Some(t) = v.get(j).cloned() else { continue };
            if !t.always() || j <= i {
                continue;
            }
            let slots_free = t
                .sets
                .iter()
                .all(|s| e.sets.iter().all(|x| x.slot() != s.slot()));
            if !t.permit {
                // Whatever was set, the route is rejected.
                if let Some(e) = v.get_mut(i) {
                    e.permit = false;
                    e.sets.clear();
                    e.exit = Exit::Done;
                }
            } else if slots_free {
                let exit = match t.exit {
                    Exit::Next => Exit::Goto(j + 1),
                    x => x,
                };
                if let Some(e) = v.get_mut(i) {
                    e.sets.extend(t.sets);
                    e.exit = exit;
                }
            }
        }
        // 3. `goto` the next entry is `next`.
        for (i, e) in v.iter_mut().enumerate() {
            if e.exit == Exit::Goto(i + 1) {
                e.exit = Exit::Next;
            }
        }
        // 4. Drop no-ops and unreachable entries (never the end).
        let last = v.len() - 1;
        let mut target = vec![false; v.len()];
        for e in &v {
            if let Exit::Goto(j) = e.exit
                && let Some(t) = target.get_mut(j)
            {
                *t = true;
            }
        }
        let mut keep = vec![true; v.len()];
        for i in 0..last {
            let Some(e) = v.get(i) else { break };
            // Also a plain deny right before the final one.
            let noop = (e.permit && e.sets.is_empty() && e.exit == Exit::Next)
                || (!e.permit && e.always() && i + 1 == last);
            let dead = i > 0
                && !target.get(i).copied().unwrap_or(true)
                && v.get(i - 1)
                    .is_some_and(|p| p.always() && (p.exit != Exit::Next || !p.permit))
                && !keep.get(i - 1).is_some_and(|k| !k);
            if (noop || dead)
                && let Some(k) = keep.get_mut(i)
            {
                *k = false;
            }
        }
        if keep.iter().any(|k| !k) {
            // New index of each old one: the next kept entry at or after it.
            let mut map = vec![0; v.len() + 1];
            let mut n = keep.iter().filter(|k| **k).count();
            for i in (0..v.len()).rev() {
                if keep.get(i).copied().unwrap_or(true) {
                    n -= 1;
                }
                if let Some(m) = map.get_mut(i) {
                    *m = n;
                }
            }
            let mut out = Vec::with_capacity(v.len());
            for (i, mut e) in v.into_iter().enumerate() {
                if !keep.get(i).copied().unwrap_or(true) {
                    continue;
                }
                if let Exit::Goto(j) = e.exit {
                    // A removed target: the next kept one.
                    let mut k = j;
                    while k < keep.len() && !keep.get(k).copied().unwrap_or(true) {
                        k += 1;
                    }
                    e.exit = Exit::Goto(map.get(k).copied().unwrap_or(0));
                }
                out.push(e);
            }
            v = out;
            for (i, e) in v.iter_mut().enumerate() {
                if e.exit == Exit::Goto(i + 1) {
                    e.exit = Exit::Next;
                }
            }
        }
        if v == before {
            break;
        }
    }
    v
}

/// One chain compiled (jumps inlined) and optimized; the problems.
pub fn compile(
    filter: &RoutingFilter,
    chains: &HashMap<&str, &[Stmt]>,
    chain: &str,
    asn: Option<u32>,
    lists: &mut Lists,
) -> (Vec<Entry>, Vec<String>) {
    compile_counted(filter, chains, chain, asn, 0, lists)
}

/// [`compile`] for a map whose session adds `counted` copies of our AS
/// that `set bgp-path-prepend` counts ([`prepend_counted`]).
pub fn compile_counted(
    filter: &RoutingFilter,
    chains: &HashMap<&str, &[Stmt]>,
    chain: &str,
    asn: Option<u32>,
    counted: u8,
    lists: &mut Lists,
) -> (Vec<Entry>, Vec<String>) {
    let body = chains.get(chain).copied().unwrap_or(&[]);
    let mut c = Comp {
        filter,
        chains,
        lists,
        asn,
        counted,
        items: Vec::new(),
        labels: 0,
        entries: 0,
        stack: vec![chains.get_key_value(chain).map_or("", |(k, _)| *k)],
        problems: Vec::new(),
        too_big: false,
    };
    let end = c.label();
    c.stmts(body, end);
    let mut problems = c.problems;
    if c.too_big {
        problems.push(format!("chain {chain} compiles to more than {MAX_ENTRIES} route-map entries (jumps are inlined)"));
        return (vec![Entry::reject()], problems);
    }
    let items = c.items;
    let v = optimize(resolve(items, end));
    if v.len() > MAX_ENTRIES + 1 {
        problems.push(format!(
            "chain {chain} compiles to {} route-map entries, more than FRR's {MAX_ENTRIES}",
            v.len()
        ));
        return (vec![Entry::reject()], problems);
    }
    (v, problems)
}

/// The sequence number of entry `i` of `n`.
pub fn seq(i: usize, n: usize) -> u32 {
    if i + 1 == n {
        END_SEQ
    } else {
        u32::try_from(i + FIRST_SEQ).unwrap_or(END_SEQ)
    }
}

fn set_line(s: &Set) -> Option<String> {
    let words = |v: &[u32]| {
        v.iter()
            .map(|c| community_text(*c))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let large = |v: &[Large]| {
        v.iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(" ")
    };
    Some(match s {
        Set::LocalPref(v) => format!("set local-preference {v}"),
        Set::Med(v) => format!("set metric {v}"),
        Set::Prepend(asn, n) => {
            let mut l = "set as-path prepend".to_owned();
            for _ in 0..*n {
                let _ = write!(l, " {asn}");
            }
            l
        }
        Set::Gw(std::net::IpAddr::V4(a)) => format!("set ip next-hop {a}"),
        Set::Gw(std::net::IpAddr::V6(a)) => format!("set ipv6 next-hop global {a}"),
        Set::Comm(CommHow::Set, v, _) if v.is_empty() => "set community none".into(),
        Set::Comm(CommHow::Set, v, _) => format!("set community {}", words(v)),
        Set::Comm(CommHow::Append, v, _) => format!("set community {} additive", words(v)),
        Set::Comm(CommHow::Delete, _, name) => format!("set comm-list {name} delete"),
        Set::Large(CommHow::Set, v, _) if v.is_empty() => "set large-community none".into(),
        Set::Large(CommHow::Set, v, _) => format!("set large-community {}", large(v)),
        Set::Large(CommHow::Append, v, _) => format!("set large-community {} additive", large(v)),
        Set::Large(CommHow::Delete, _, name) => format!("set large-comm-list {name} delete"),
    })
}

fn match_line(m: &Match) -> String {
    match m {
        Match::Plist { v6: false, name } => format!("match ip address prefix-list {name}"),
        Match::Plist { v6: true, name } => format!("match ipv6 address prefix-list {name}"),
        Match::AsPath(n) => format!("match as-path {n}"),
        Match::Comm { name, exact } => format!(
            "match community {name}{}",
            if *exact { " exact-match" } else { "" }
        ),
        Match::Large { name, exact } => format!(
            "match large-community {name}{}",
            if *exact { " exact-match" } else { "" }
        ),
        Match::Proto(p) => format!("match source-protocol {}", p.name()),
    }
}

/// FRR text of one compiled chain.
pub fn map_text(chain: &str, entries: &[Entry], out: &mut String) {
    map_text_named(&route_map(chain), entries, out);
}

/// [`map_text`] under the route-map name `name`.
pub fn map_text_named(name: &str, entries: &[Entry], out: &mut String) {
    let n = entries.len();
    for (i, e) in entries.iter().enumerate() {
        let _ = writeln!(
            out,
            "route-map {name} {} {}",
            if e.permit { "permit" } else { "deny" },
            seq(i, n)
        );
        if let Some(d) = e.description.as_deref().filter(|d| !d.is_empty()) {
            let _ = writeln!(out, " description {d}");
        }
        for m in &e.matches {
            let _ = writeln!(out, " {}", match_line(m));
        }
        if e.permit {
            for s in &e.sets {
                if let Some(l) = set_line(s) {
                    let _ = writeln!(out, " {l}");
                }
            }
            match e.exit {
                Exit::Done => {}
                Exit::Next => {
                    let _ = writeln!(out, " on-match next");
                }
                Exit::Goto(j) => {
                    let _ = writeln!(out, " on-match goto {}", seq(j, n));
                }
            }
        }
        let _ = writeln!(out, "exit");
    }
}

/// FRR text of the lists.
pub fn lists_text(l: &Lists, out: &mut String) {
    for (kw, map) in [("ip", &l.prefix4), ("ipv6", &l.prefix6)] {
        for (name, entries) in map {
            for (i, e) in entries.iter().enumerate() {
                let _ = writeln!(
                    out,
                    "{kw} prefix-list {name} seq {} permit {e}",
                    (i + 1) * 5
                );
            }
        }
    }
    for (name, re) in &l.aspath {
        let _ = writeln!(out, "bgp as-path access-list {name} seq 5 permit {re}");
    }
    for (name, entries) in &l.comm {
        for (i, e) in entries.iter().enumerate() {
            let words: Vec<String> = e.iter().map(|c| community_text(*c)).collect();
            let _ = writeln!(
                out,
                "bgp community-list standard {name} seq {} permit {}",
                (i + 1) * 5,
                words.join(" ")
            );
        }
    }
    for (name, entries) in &l.large {
        for (i, e) in entries.iter().enumerate() {
            let words: Vec<String> = e.iter().map(ToString::to_string).collect();
            let _ = writeln!(
                out,
                "bgp large-community-list standard {name} seq {} permit {}",
                (i + 1) * 5,
                words.join(" ")
            );
        }
    }
}

/// `part` over `roots`, in order: on threads when there are many chains
/// (10 000 rules in 100 chains render in 15 ms on 8 threads, parse
/// included, instead of 40 ms on one, **medido** in `benches/filter.rs`,
/// 2026-10-27); one thread on wasm.
fn render_parts<T: Send>(roots: &[&str], part: &(dyn Fn(&[&str]) -> T + Sync)) -> Vec<T> {
    let threads = if roots.len() < 8 {
        1
    } else {
        super::eval::threads_for(usize::MAX)
    };
    if threads <= 1 {
        return vec![part(roots)];
    }
    #[cfg(target_arch = "wasm32")]
    {
        vec![part(roots)]
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let size = roots.len().div_ceil(threads);
        std::thread::scope(|scope| {
            let handles: Vec<_> = roots
                .chunks(size)
                .map(|c| {
                    std::thread::Builder::new()
                        .name("filter-render".into())
                        .spawn_scoped(scope, move || part(c))
                })
                .collect();
            handles
                .into_iter()
                .zip(roots.chunks(size))
                .map(|(h, c)| match h.map(|h| h.join()) {
                    Ok(Ok(v)) => v,
                    _ => part(c),
                })
                .collect()
        })
    }
}

/// The whole `/routing filter` for FRR: the chains in `used` (those the
/// connections name) and the chains no other chain jumps to, each with
/// the AS `asn_of` gives it; the problems (with the chain's name).
pub fn render(
    filter: &RoutingFilter,
    used: &BTreeSet<String>,
    asn_of: &dyn Fn(&str) -> Option<u32>,
) -> (String, Vec<Problem>) {
    render_with(filter, used, asn_of, &|_| String::new())
}

/// [`render`] with a prelude per chain: FRR text of entries with sequence
/// 1..=9 of `route-map CR-<chain>` (G3.2c puts its RPKI `deny` there),
/// typed before the chain's own entries.
pub fn render_with(
    filter: &RoutingFilter,
    used: &BTreeSet<String>,
    asn_of: &dyn Fn(&str) -> Option<u32>,
    prelude: &dyn Fn(&str) -> String,
) -> (String, Vec<Problem>) {
    let legacy = Uses {
        legacy: true,
        ..Uses::default()
    };
    let (text, problems, _) = render_counted(filter, used, asn_of, prelude, &|_| legacy);
    (text, problems)
}

/// How the connections use a chain, for the count of `set
/// bgp-path-prepend` (G3.9fg).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Uses {
    /// The output chain of an eBGP connection.
    pub ebgp_out: bool,
    /// Any other use: input or iBGP output.
    pub other: bool,
    /// A filter of an older build ([`PrependCount::Legacy`]): N copies on
    /// top of whatever the session adds, everywhere.
    pub legacy: bool,
}

/// `counted` for a map where `set bgp-path-prepend` does nothing: RouterOS
/// 7.25 adds no copy on an iBGP output nor on input (**medido**, G3.9fg).
pub const PREPEND_IGNORED: u8 = u8::MAX;

impl Uses {
    /// `counted` of the chain's own map and, when it needs one, of its map
    /// for the eBGP outputs.
    pub fn counted(self) -> (u8, Option<u8>) {
        match (self.legacy, self.ebgp_out, self.other) {
            (true, ..) => (0, None),
            (false, true, false) => (1, None),
            (false, false, _) => (PREPEND_IGNORED, None),
            (false, true, true) => (PREPEND_IGNORED, Some(1)),
        }
    }
}

/// The route-map of `chain` on the output of an eBGP connection when the
/// chain is used both ways ([`render_counted`]): `+` cannot be in a chain
/// name, so it never meets another chain's map.
pub fn route_map_ebgp_out(chain: &str) -> String {
    format!("CR-{chain}+ebgp-out")
}

/// [`render_with`] with the count of `set bgp-path-prepend` of RouterOS
/// (G3.9fg): on an eBGP output the copy eBGP adds counts (`set
/// bgp-path-prepend 3` leaves with our AS 3 times); on input and iBGP
/// outputs it does nothing. A chain used both ways gets a second map for
/// the eBGP outputs, [`route_map_ebgp_out`], when that changes something.
/// The third value: the chains that got one.
pub fn render_counted(
    filter: &RoutingFilter,
    used: &BTreeSet<String>,
    asn_of: &dyn Fn(&str) -> Option<u32>,
    prelude: &dyn Fn(&str) -> String,
    uses_of: &dyn Fn(&str) -> Uses,
) -> (String, Vec<Problem>, BTreeSet<String>) {
    let (parsed, _) = parsed_chains(filter);
    let chains: HashMap<&str, &[Stmt]> = parsed
        .iter()
        .map(|(n, b)| (n.as_str(), b.as_slice()))
        .collect();
    let mut jumped: BTreeSet<String> = BTreeSet::new();
    for (_, b) in &parsed {
        let mut j = Vec::new();
        super::eval::jumps(b, &mut j);
        jumped.extend(j);
    }
    let roots: Vec<&str> = parsed
        .iter()
        .map(|(n, _)| n.as_str())
        .filter(|n| !jumped.contains(*n) || used.contains(*n))
        .collect();
    // Each chain compiles alone (the lists are named by content, so the
    // parts merge): many chains go on threads.
    let asns: HashMap<&str, Option<u32>> = roots.iter().map(|n| (*n, asn_of(n))).collect();
    let preludes: HashMap<&str, String> = roots.iter().map(|n| (*n, prelude(n))).collect();
    let uses: HashMap<&str, Uses> = roots.iter().map(|n| (*n, uses_of(n))).collect();
    type Part = (Lists, String, Vec<Problem>, Vec<String>);
    let part = |names: &[&str]| -> Part {
        let (mut lists, mut maps, mut problems, mut variants) =
            (Lists::default(), String::new(), Vec::new(), Vec::new());
        for name in names {
            let asn = asns.get(name).copied().flatten();
            let (counted, variant) = uses.get(name).copied().unwrap_or_default().counted();
            let (entries, probs) = compile_counted(filter, &chains, name, asn, counted, &mut lists);
            problems.extend(probs.into_iter().map(|message| Problem {
                item: format!("chain {name}"),
                message,
            }));
            let prelude = preludes.get(name).map_or("", String::as_str);
            maps.push_str(prelude);
            map_text_named(&route_map(name), &entries, &mut maps);
            if let Some(c2) = variant {
                // The same chain counting eBGP's copy; only when that
                // changes something (a chain with a prepend).
                let (e2, _) = compile_counted(filter, &chains, name, asn, c2, &mut lists);
                if e2 != entries {
                    maps.push_str(&prelude.replace(&route_map(name), &route_map_ebgp_out(name)));
                    map_text_named(&route_map_ebgp_out(name), &e2, &mut maps);
                    variants.push((*name).to_owned());
                }
            }
        }
        (lists, maps, problems, variants)
    };
    let parts: Vec<Part> = render_parts(&roots, &part);
    let mut lists = Lists::default();
    let mut maps = String::new();
    let mut problems = Vec::new();
    let mut variants = BTreeSet::new();
    for (l, m, p, v) in parts {
        lists.prefix4.extend(l.prefix4);
        lists.prefix6.extend(l.prefix6);
        lists.aspath.extend(l.aspath);
        lists.comm.extend(l.comm);
        lists.large.extend(l.large);
        maps.push_str(&m);
        problems.extend(p);
        variants.extend(v);
    }
    let mut text = String::new();
    lists_text(&lists, &mut text);
    text.push_str(&maps);
    (text, problems, variants)
}

#[cfg(test)]
pub(crate) mod tests {
    use corerouter_model::routing_filter::{CommunityList, FilterRule, PrefixList};
    use proptest::prelude::*;

    use super::super::eval::{Policy, PrefixSet, compile_regex};
    use super::super::{Route, parse};
    use super::*;

    fn filter(rules: &[(&str, &str)]) -> RoutingFilter {
        let mut f = RoutingFilter::default();
        for (chain, rule) in rules {
            let id = f.next_id();
            f.rules.push(FilterRule {
                id,
                chain: (*chain).into(),
                rule: (*rule).into(),
                disabled: false,
                comment: String::new(),
            });
        }
        f.prefix_lists.insert(
            "bogons".into(),
            PrefixList {
                name: "bogons".into(),
                entries: [
                    "10.0.0.0/8 le 32",
                    "192.168.0.0/16 le 32",
                    "fc00::/7 le 128",
                ]
                .iter()
                .map(|e| e.parse().unwrap())
                .collect(),
                comment: String::new(),
            },
        );
        f.community_lists.insert(
            "cl".into(),
            CommunityList {
                name: "cl".into(),
                communities: vec!["65000:1".into(), "65000:2".into(), "1:2:3".into()],
                comment: String::new(),
            },
        );
        f
    }

    fn one(rules: &[(&str, &str)]) -> (Vec<Entry>, Lists, String) {
        let f = filter(rules);
        let (parsed, probs) = parsed_chains(&f);
        assert_eq!(probs, []);
        let chains: HashMap<&str, &[Stmt]> = parsed
            .iter()
            .map(|(n, b)| (n.as_str(), b.as_slice()))
            .collect();
        let mut lists = Lists::default();
        let (v, p) = compile(&f, &chains, "in", Some(65000), &mut lists);
        assert_eq!(p, Vec::<String>::new());
        let mut text = String::new();
        map_text("in", &v, &mut text);
        (v, lists, text)
    }

    /// FRR's route-map semantics (lib/routemap.c `route_map_apply`), over
    /// the compiled entries: entries in order; all matches of an entry
    /// match → permit applies its sets then follows its exit, deny ends
    /// with deny; no match → the next entry; past the end → deny.
    pub(crate) fn frr_run(entries: &[Entry], lists: &Lists, r: &Route) -> Option<Route> {
        let mut r = r.clone();
        let mut i = 0;
        let mut steps = 0;
        while let Some(e) = entries.get(i) {
            steps += 1;
            assert!(steps < 100_000, "loop in the map");
            if e.matches.iter().all(|m| frr_match(m, lists, &r)) {
                if !e.permit {
                    return None;
                }
                for s in &e.sets {
                    frr_set(s, &mut r);
                }
                match e.exit {
                    Exit::Done => return Some(r),
                    Exit::Next => i += 1,
                    Exit::Goto(j) => {
                        assert!(j > i, "goto backwards: {i} → {j}");
                        i = j;
                    }
                }
            } else {
                i += 1;
            }
        }
        None
    }

    fn frr_match(m: &Match, l: &Lists, r: &Route) -> bool {
        match m {
            Match::Plist { v6, name } => {
                let fam = matches!(r.prefix, IpNet::V6(_));
                let map = if *v6 { &l.prefix6 } else { &l.prefix4 };
                fam == *v6
                    && map
                        .get(name)
                        .is_some_and(|e| PrefixSet::new(e).contains(&r.prefix))
            }
            Match::AsPath(n) => l
                .aspath
                .get(n)
                .is_some_and(|re| compile_regex(re).unwrap().is_match(&r.path_text())),
            Match::Comm { name, exact } => l.comm.get(name).is_some_and(|es| {
                es.iter().any(|e| {
                    if *exact {
                        *e == r.communities
                    } else {
                        e.iter().all(|c| r.communities.contains(c))
                    }
                })
            }),
            Match::Large { name, exact } => l.large.get(name).is_some_and(|es| {
                es.iter().any(|e| {
                    if *exact {
                        *e == r.large
                    } else {
                        e.iter().all(|c| r.large.contains(c))
                    }
                })
            }),
            Match::Proto(p) => r.protocol == *p,
        }
    }

    fn frr_set(s: &Set, r: &mut Route) {
        fn change<T: Ord + Copy>(how: CommHow, vals: &[T], have: &mut Vec<T>) {
            match how {
                CommHow::Set => *have = vals.to_vec(),
                CommHow::Append => {
                    have.extend_from_slice(vals);
                    have.sort_unstable();
                    have.dedup();
                }
                CommHow::Delete => have.retain(|c| !vals.contains(c)),
            }
        }
        match s {
            Set::LocalPref(v) => r.local_pref = Some(*v),
            Set::Med(v) => r.med = Some(*v),
            Set::Prepend(a, n) => {
                let mut p = vec![*a; usize::from(*n)];
                p.extend_from_slice(&r.as_path);
                r.as_path = p;
            }
            Set::Gw(a) => r.next_hop = Some(*a),
            Set::Comm(how, v, _) => change(*how, v, &mut r.communities),
            Set::Large(how, v, _) => change(*how, v, &mut r.large),
        }
    }

    #[test]
    fn a_reject_test_is_one_deny_entry() {
        let (v, lists, text) = one(&[
            ("in", "if (dst in 10.0.0.0/8) { reject }"),
            ("in", "accept"),
        ]);
        assert_eq!(v.len(), 3, "{text}");
        let name = lists.prefix4.keys().next().unwrap().clone();
        assert_eq!(
            text,
            format!(
                "route-map CR-in deny 10\n description dst in 10.0.0.0/8\n match ip address prefix-list {name}\nexit\n\
                 route-map CR-in permit 11\nexit\nroute-map CR-in deny 65535\nexit\n"
            )
        );
        assert_eq!(
            lists.prefix4.get(&name).unwrap()[0].to_string(),
            "10.0.0.0/8 le 32"
        );
    }

    #[test]
    fn sets_merge_and_accept_ends_the_map() {
        let (v, _, text) = one(&[(
            "in",
            "if (bgp-communities includes 65000:1) { set bgp-local-pref 200; set bgp-med 10; accept }",
        )]);
        assert_eq!(v.len(), 2, "{text}");
        assert!(
            text.contains(" set local-preference 200\n set metric 10\n"),
            "{text}"
        );
        assert!(!text.contains("on-match"), "{text}");
    }

    #[test]
    fn renders_lists_and_communities_like_frr() {
        let f = filter(&[(
            "out",
            "if (dst in bogons || bgp-as-path \"_64512_\") { reject } \
             if (bgp-communities any-list cl) { set bgp-path-prepend 2; append bgp-communities no-export,65000:9; delete bgp-large-communities 1:2:3; accept }",
        )]);
        let (text, problems) = render(&f, &BTreeSet::new(), &|_| Some(65000));
        assert_eq!(problems, []);
        for want in [
            "ip prefix-list CR-L-bogons seq 5 permit 10.0.0.0/8 le 32\n",
            "ip prefix-list CR-L-bogons seq 10 permit 192.168.0.0/16 le 32\n",
            "ipv6 prefix-list CR-L-bogons seq 5 permit fc00::/7 le 128\n",
            " match ipv6 address prefix-list CR-L-bogons\n",
            "permit _64512_\n",
            " set as-path prepend 65000 65000\n",
            " set community 65000:9 no-export additive\n",
            "bgp large-community-list standard CR-LC-",
            " seq 10 permit 65000:2\n",
        ] {
            assert!(text.contains(want), "{want:?} in\n{text}");
        }
        // The text reads back as an FRR tree.
        let conf = corerouter_model_free_parse(&text);
        assert!(conf > 5);
    }

    #[test]
    fn prepend_counts_the_copy_ebgp_adds_on_ebgp_outputs() {
        // G3.9fg, RouterOS 7.25 CHR (measured): `set bgp-path-prepend N` on
        // eBGP leaves with the AS N times in all; N = 1 adds nothing.
        let f = filter(&[
            (
                "out",
                "if (dst in 10.0.0.0/8) { set bgp-path-prepend 3; accept } set bgp-path-prepend 1; accept",
            ),
            ("plain", "set bgp-med 5; accept"),
        ]);
        let used: BTreeSet<String> = ["out".to_owned(), "plain".to_owned()].into();
        let only_ebgp = |_: &str| Uses {
            ebgp_out: true,
            ..Uses::default()
        };
        let (text, problems, variants) =
            render_counted(&f, &used, &|_| Some(65000), &|_| String::new(), &only_ebgp);
        assert_eq!(problems, []);
        assert!(variants.is_empty(), "{variants:?}");
        assert!(
            text.contains(" set as-path prepend 65000 65000\n"),
            "{text}"
        );
        assert!(!text.contains("prepend 65000 65000 65000"), "{text}");
        assert_eq!(
            text.matches("set as-path prepend").count(),
            1,
            "N = 1: nothing\n{text}"
        );
        // On input and iBGP outputs RouterOS adds nothing (measured).
        let other = |_: &str| Uses {
            other: true,
            ..Uses::default()
        };
        let (text, _, variants) =
            render_counted(&f, &used, &|_| Some(65000), &|_| String::new(), &other);
        assert!(variants.is_empty());
        assert!(!text.contains("prepend"), "{text}");
        // A legacy filter: N on top of what the session adds, everywhere.
        let legacy = |_: &str| Uses {
            ebgp_out: true,
            other: true,
            legacy: true,
        };
        let (text, _, variants) =
            render_counted(&f, &used, &|_| Some(65000), &|_| String::new(), &legacy);
        assert!(variants.is_empty());
        assert!(
            text.contains(" set as-path prepend 65000 65000 65000\n"),
            "{text}"
        );
        assert!(text.contains(" set as-path prepend 65000\n"), "{text}");
        // Both: a second map for the eBGP outputs, only for the chain
        // whose prepend differs.
        let both = |_: &str| Uses {
            ebgp_out: true,
            other: true,
            legacy: false,
        };
        let (text, _, variants) =
            render_counted(&f, &used, &|_| Some(65000), &|_| String::new(), &both);
        assert_eq!(variants, BTreeSet::from(["out".to_owned()]));
        assert!(text.contains("route-map CR-out permit"), "{text}");
        assert!(
            text.contains(&format!("route-map {} permit", route_map_ebgp_out("out"))),
            "{text}"
        );
        assert!(!text.contains("CR-plain+"), "{text}");
        // `+` is not in a chain name: no other chain can own that map.
        assert!(parse::check_chain("out+ebgp-out").is_err());
    }

    /// Lines that open a context (no leading space), as a sanity check
    /// without depending on `hal-frr`.
    fn corerouter_model_free_parse(text: &str) -> usize {
        text.lines()
            .filter(|l| !l.starts_with(' ') && *l != "exit")
            .count()
    }

    #[test]
    fn jumps_are_inlined_and_return_comes_back() {
        let f = filter(&[
            (
                "in",
                "jump tag; if (bgp-communities includes 65000:7) { accept }",
            ),
            (
                "tag",
                "if (dst-len > 24) { return } append bgp-communities 65000:7",
            ),
        ]);
        let (p, _) = Policy::build(&f);
        let (text, problems) = render(&f, &BTreeSet::new(), &|_| Some(1));
        assert_eq!(problems, []);
        assert!(
            text.contains("route-map CR-in ") && !text.contains("route-map CR-tag "),
            "{text}"
        );
        let (parsed, _) = parsed_chains(&f);
        let chains: HashMap<&str, &[Stmt]> = parsed
            .iter()
            .map(|(n, b)| (n.as_str(), b.as_slice()))
            .collect();
        let mut lists = Lists::default();
        let (v, _) = compile(&f, &chains, "in", Some(1), &mut lists);
        for (pfx, want) in [("192.0.2.0/24", true), ("192.0.2.0/25", false)] {
            let r = Route::bgp(pfx.parse().unwrap(), vec![1]);
            assert_eq!(frr_run(&v, &lists, &r).is_some(), want, "{pfx}");
            assert_eq!(p.eval(0, &r, 1).accepted, want);
        }
        // A chain both jumped to and used by a connection is rendered.
        let used: BTreeSet<String> = ["tag".to_owned()].into();
        assert!(
            render(&f, &used, &|_| Some(1))
                .0
                .contains("route-map CR-tag ")
        );
    }

    #[test]
    fn exponential_jumps_are_refused_not_built() {
        let mut rules = vec![("in", "jump c0".to_owned())];
        // 3^12 copies of the last chain, within the jump depth.
        let names: Vec<String> = (0..13).map(|i| format!("c{i}")).collect();
        for (i, name) in names.iter().enumerate().take(12) {
            rules.push((
                name.as_str(),
                format!("jump c{0}; jump c{0}; jump c{0}", i + 1),
            ));
        }
        rules.push(("c12", "set bgp-med 1".into()));
        let pairs: Vec<(&str, &str)> = rules.iter().map(|(a, b)| (*a, b.as_str())).collect();
        let f = filter(&pairs);
        let (_, problems) = render(&f, &BTreeSet::new(), &|_| Some(1));
        assert!(
            format!("{problems:?}").contains("more than"),
            "{problems:?}"
        );
    }

    // ---- equivalence: eval == FRR's semantics over the render ----

    fn atom() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("dst in 10.0.0.0/8".to_owned()),
            Just("dst in 192.0.2.0/24".to_owned()),
            Just("dst == 192.0.2.0/24".to_owned()),
            Just("dst != 10.1.0.0/16".to_owned()),
            Just("dst in bogons".to_owned()),
            Just("dst in 2001:db8::/32".to_owned()),
            (0u8..40, 0u8..40).prop_map(|(a, b)| format!("dst-len in {}-{}", a.min(b), a.max(b))),
            (1u8..33).prop_map(|n| format!("dst-len > {n}")),
            (1u8..33).prop_map(|n| format!("dst-len <= {n}")),
            Just("afi ipv4".to_owned()),
            Just("afi ipv6".to_owned()),
            Just("protocol bgp".to_owned()),
            Just("protocol static,connected".to_owned()),
            Just("bgp-as-path \"^64500_\"".to_owned()),
            Just("bgp-as-path \"_65000$\"".to_owned()),
            Just("bgp-as-path \"_6450[0-3]_\"".to_owned()),
            Just("bgp-communities includes 65000:1".to_owned()),
            Just("bgp-communities any 65000:1,65000:2".to_owned()),
            Just("bgp-communities equal 65000:1".to_owned()),
            Just("bgp-communities includes-list cl".to_owned()),
            Just("bgp-communities any-list cl".to_owned()),
            Just("bgp-communities equal-list cl".to_owned()),
            Just("bgp-large-communities includes 1:2:3".to_owned()),
            Just("bgp-large-communities any-list cl".to_owned()),
        ]
    }

    fn expr() -> impl Strategy<Value = String> {
        atom().prop_recursive(3, 12, 2, |inner| {
            prop_oneof![
                (inner.clone(), inner.clone()).prop_map(|(a, b)| format!("({a} && {b})")),
                (inner.clone(), inner.clone()).prop_map(|(a, b)| format!("({a} || {b})")),
                inner.prop_map(|a| format!("not {a}")),
            ]
        })
    }

    fn action() -> impl Strategy<Value = String> {
        prop_oneof![
            Just("accept".to_owned()),
            Just("reject".to_owned()),
            Just("return".to_owned()),
            Just("jump sub".to_owned()),
            (0u32..300).prop_map(|n| format!("set bgp-local-pref {n}")),
            (0u32..300).prop_map(|n| format!("set bgp-med {n}")),
            (1u8..4).prop_map(|n| format!("set bgp-path-prepend {n}")),
            prop_oneof![Just("set gw 192.0.2.9"), Just("set gw 2001:db8::9")].prop_map(str::to_owned),
            Just("set bgp-communities 65000:1".to_owned()),
            Just("set bgp-communities none".to_owned()),
            Just("append bgp-communities 65000:2,no-export".to_owned()),
            Just("delete bgp-communities 65000:1".to_owned()),
            Just("delete bgp-communities cl".to_owned()),
            Just("append bgp-large-communities 1:2:3".to_owned()),
            Just("set bgp-large-communities none".to_owned()),
        ]
    }

    fn stmt() -> impl Strategy<Value = String> {
        let leaf = action();
        leaf.prop_recursive(3, 16, 3, |inner| {
            (
                expr(),
                prop::collection::vec(inner.clone(), 0..3),
                prop::collection::vec(inner, 0..3),
            )
                .prop_map(|(c, t, e)| {
                    if e.is_empty() {
                        format!("if ({c}) {{ {} }}", t.join("; "))
                    } else {
                        format!(
                            "if ({c}) {{ {} }} else {{ {} }}",
                            t.join("; "),
                            e.join("; ")
                        )
                    }
                })
        })
    }

    fn route() -> impl Strategy<Value = Route> {
        let prefix = prop_oneof![
            Just("10.0.0.0/8"),
            Just("10.1.0.0/16"),
            Just("10.1.2.0/24"),
            Just("192.0.2.0/24"),
            Just("192.0.2.128/25"),
            Just("192.168.1.0/24"),
            Just("198.51.100.0/24"),
            Just("0.0.0.0/0"),
            Just("203.0.113.7/32"),
            Just("2001:db8::/32"),
            Just("2001:db8:1::/48"),
            Just("fd00::/8"),
            Just("::/0"),
        ];
        let asn = prop_oneof![
            Just(64500u32),
            Just(64501),
            Just(64503),
            Just(65000),
            Just(7)
        ];
        (
            prefix,
            prop::collection::vec(asn, 1..4),
            prop::sample::subsequence(vec![65000 << 16 | 1, 65000 << 16 | 2, 0xFFFF_FF01], 0..3),
            prop::sample::subsequence(vec![Large(1, 2, 3), Large(1, 2, 4)], 0..2),
            prop_oneof![
                Just(Protocol::Bgp),
                Just(Protocol::Static),
                Just(Protocol::Connected)
            ],
        )
            .prop_map(|(p, path, comms, large, protocol)| {
                let mut r = Route::bgp(p.parse().unwrap(), path);
                r.communities = comms;
                r.large = large;
                r.protocol = protocol;
                r
            })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(400))]
        #[test]
        fn frr_render_runs_like_the_policy(
            main in prop::collection::vec(stmt(), 1..4),
            sub in prop::collection::vec(stmt(), 0..3),
            routes in prop::collection::vec(route(), 1..12),
            counted in prop_oneof![Just(0u8), Just(1u8), Just(PREPEND_IGNORED)],
        ) {
            let main_text = main.join("; ");
            let mut rules = vec![("in", main_text.as_str())];
            // `sub` must not jump to itself (a loop is refused anyway).
            let sub_text = sub.join("; ").replace("jump sub", "return");
            if !sub_text.is_empty() {
                rules.push(("sub", sub_text.as_str()));
            }
            let f = filter(&rules);
            let (policy, _) = Policy::build(&f);
            let (parsed, _) = parsed_chains(&f);
            let chains: HashMap<&str, &[Stmt]> = parsed.iter().map(|(n, b)| (n.as_str(), b.as_slice())).collect();
            let mut lists = Lists::default();
            // G3.9fg: an eBGP output map (counted = 1) and any other.
            let (v, probs) = compile_counted(&f, &chains, "in", Some(65000), counted, &mut lists);
            prop_assert!(probs.is_empty(), "{:?}", probs);
            prop_assert!(v.len() <= MAX_ENTRIES);
            prop_assert!(v.last().is_some_and(|e| !e.permit && e.always()));
            let c = policy.chain("in").unwrap();
            for r in &routes {
                let want = policy.eval_counted(c, r, 65000, counted);
                let got = frr_run(&v, &lists, r);
                prop_assert_eq!(got.is_some(), want.accepted, "{}\n{:?}\n{:#?}", main_text, r, v);
                if let Some(g) = got {
                    prop_assert_eq!(&g, &*want.route, "{}", main_text);
                }
            }
        }

        #[test]
        fn hostile_rules_never_panic(src in "[ -~]{0,200}") {
            let _ = parse::parse(&src);
        }

        #[test]
        fn rule_like_text_never_panics(parts in prop::collection::vec(prop_oneof![
            Just("if"), Just("("), Just(")"), Just("{"), Just("}"), Just("dst"), Just("in"), Just("10.0.0.0/8"),
            Just("&&"), Just("||"), Just("not"), Just("accept"), Just("reject"), Just("set"), Just("bgp-med"),
            Just("5"), Just("dst-len"), Just(">"), Just("bgp-communities"), Just("any"), Just("1:2"), Just(";"),
            Just("else"), Just("jump"), Just("x"), Just("\""), Just("bgp-as-path"), Just("^1_"),
        ], 0..40)) {
            let src = parts.join(" ");
            if let Ok(stmts) = parse::parse(&src) {
                let f = filter(&[("in", src.as_str())]);
                let (p, _) = Policy::build(&f);
                let r = Route::bgp("10.1.0.0/16".parse().unwrap(), vec![1]);
                let _ = p.eval(0, &r, 1);
                let _ = render(&f, &BTreeSet::new(), &|_| Some(1));
                prop_assert!(!stmts.is_empty());
            }
        }
    }
}
