//! The firewall's commit without reading the kernel back (G0.31f).
//!
//! After a commit we keep what we loaded: the config's firewall (its rule
//! tables share blocks with the next config, so a copy is a few pointers),
//! the kernel handle of every rule and how many rules need each chain and
//! set. The next commit then:
//!
//! - finds the rules that changed from the blocks the two configs no
//!   longer share (`CowList::shared_blocks`), not by walking 10 000 rules;
//! - builds the kernel rules of those alone and diffs them (Myers), so a
//!   rule whose kernel form did not change keeps its counters;
//! - sends the deletes by handle and the inserts after the handle of the
//!   rule before them, in one batch that asks the kernel to echo the new
//!   rules (their handles) and that applies only while the nftables
//!   generation is still the one our last batch made
//!   (`NFNL_BATCH_GENID`, see [`crate::nfnl::stamp`]).
//!
//! **Drift.** Anyone else committing to nftables (`nft` by hand, another
//! program) moves the generation: the kernel refuses the batch whole
//! (`ERESTART`), nothing changes, and [`crate::firewall::apply`] goes the
//! old way — read the kernel, check it holds what we loaded, diff or
//! replace the table — and keeps what it loaded for the commit after. A
//! batch of ours that wrote our table outside the firewall commit (a test,
//! a table replace) shows in the table's write count and does the same.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use corerouter_firewall::TABLE;
use corerouter_firewall::bytecode::{port_set, port_set_name};
use corerouter_firewall::nft::{self as fwnft, Needs};
use corerouter_firewall::program::{Family, Rule};
use corerouter_model::Config;
use corerouter_model::cow::CowArc;
use corerouter_model::cow_list::CowList;
use corerouter_model::firewall::{Firewall, FirewallRule, Name, PortSet, Table as RuleTable};
use corerouter_model::interface_list::InterfaceLists;
use corerouter_model::subscriber_notice::SubscriberNotices;

use crate::firewall::{Applied, MAX_EDITS, Step, myers};
use crate::nfnl::{self, Batch, Place};

/// At most this many new kernel rules ask for their handle back in one
/// commit: the echo (some 600 bytes a rule) fills the socket's 4 MiB
/// receive buffer. Past it the commit still goes through, and the next
/// one reads the kernel.
pub(crate) const ECHO_MAX: usize = 2048;

/// Position of a rule table in `RuleTable::ALL`.
fn at(t: RuleTable) -> usize {
    RuleTable::ALL.iter().position(|x| *x == t).unwrap_or(0)
}

/// Kernel handles of each rule of one rule table, by its position.
#[derive(Debug, Clone, Default)]
struct Handles {
    /// `starts[i]..starts[i + 1]`: rule `i`'s handles in `all`.
    starts: Vec<u32>,
    all: Vec<u64>,
}

impl Handles {
    fn with_capacity(rules: usize) -> Self {
        let mut starts = Vec::with_capacity(rules + 1);
        starts.push(0);
        Self {
            starts,
            all: Vec::with_capacity(rules),
        }
    }

    fn of(&self, i: usize) -> &[u64] {
        let (Some(a), Some(b)) = (self.starts.get(i), self.starts.get(i + 1)) else {
            return &[];
        };
        self.all.get(*a as usize..*b as usize).unwrap_or(&[])
    }

    fn push(&mut self, hs: &[u64]) {
        if self.starts.is_empty() {
            self.starts.push(0);
        }
        self.all.extend_from_slice(hs);
        self.starts
            .push(u32::try_from(self.all.len()).unwrap_or(u32::MAX));
    }

    fn rules(&self) -> usize {
        self.starts.len().saturating_sub(1)
    }
}

/// How many rules need each chain and set (only these change with the
/// rules; the rest of the table needs the slow path).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Census {
    chains: BTreeMap<String, u32>,
    ports: BTreeMap<String, u32>,
    lists: BTreeMap<Name, u32>,
    fills: BTreeMap<Name, u32>,
}

fn bump<K: Ord>(m: &mut BTreeMap<K, u32>, k: K, up: bool) {
    let n = m.get(&k).copied().unwrap_or(0);
    let n = if up {
        n.saturating_add(1)
    } else {
        n.saturating_sub(1)
    };
    if n == 0 {
        m.remove(&k);
    } else {
        m.insert(k, n);
    }
}

impl Census {
    fn count(&mut self, n: Needs<'_>, up: bool) {
        for c in n.chains {
            bump(&mut self.chains, c, up);
        }
        for p in n.ports {
            bump(&mut self.ports, port_set_name(p), up);
        }
        for l in n.lists {
            bump(&mut self.lists, l.clone(), up);
        }
        if let Some(f) = n.fills {
            bump(&mut self.fills, f.clone(), up);
        }
    }

    fn of(fw: &Firewall) -> Self {
        let mut c = Self::default();
        for t in RuleTable::ALL {
            for r in fw.rules(t) {
                c.count(fwnft::needs(t, r), true);
            }
        }
        c
    }
}

/// What the firewall last loaded, and the kernel handles of its rules.
#[derive(Debug)]
pub(crate) struct Loaded {
    fw: CowArc<Firewall>,
    interface_lists: InterfaceLists,
    notice: SubscriberNotices,
    /// `nfnl::stamp(TABLE)` right after it was loaded.
    stamp: (u64, u64),
    handles: [Handles; 4],
    census: Census,
    /// Address lists with sets whatever the rules say.
    fixed: BTreeSet<Name>,
    /// The number of the next anonymous set (`__set<n>`).
    anon_next: u32,
}

/// The kernel rules of one chain, in order: comment and handle.
pub(crate) type ChainHandles = BTreeMap<String, Vec<(Option<String>, u64)>>;

impl Loaded {
    /// What `cfg` loaded, from the kernel rules of each chain (the table
    /// `cfg` makes, read back or echoed); `None` when they do not line up
    /// with its rules.
    pub(crate) fn from_kernel(
        cfg: &Config,
        chains: &ChainHandles,
        stamp: (u64, u64),
        anon_next: u32,
    ) -> Option<Box<Self>> {
        let fw = &cfg.ip.firewall;
        let mut cursor: HashMap<&str, usize> = HashMap::new();
        let mut handles: [Handles; 4] = Default::default();
        let mut hs: Vec<u64> = Vec::new();
        for t in RuleTable::ALL {
            let rules = fw.rules(t);
            let h = handles.get_mut(at(t))?;
            *h = Handles::with_capacity(rules.len());
            for r in rules {
                hs.clear();
                if fwnft::live(r) {
                    let kname = fwnft::chain_name(t, r.chain.as_str());
                    let tag = fwnft::rule_tag(r.id);
                    let (name, list) = chains.get_key_value(&kname)?;
                    let at = cursor.entry(name.as_str()).or_insert(0);
                    while let Some((c, handle)) = list.get(*at)
                        && c.as_deref() == Some(tag.as_str())
                    {
                        hs.push(*handle);
                        *at += 1;
                    }
                }
                h.push(&hs);
            }
        }
        // Every kernel rule of a rule chain belongs to a rule.
        for (name, list) in chains {
            if fwnft::table_of_chain(name).is_some()
                && cursor.get(name.as_str()).copied().unwrap_or(0) != list.len()
            {
                return None;
            }
        }
        Some(Box::new(Self {
            fw: fw.clone(),
            interface_lists: cfg.interface_lists.clone(),
            notice: cfg.ip.subscriber_notice.clone(),
            stamp,
            handles,
            census: Census::of(fw),
            fixed: fwnft::fixed_lists(cfg),
            anon_next,
        }))
    }
}

/// What [`apply`] did.
pub(crate) enum Outcome {
    /// Applied (or nothing to do), and what is loaded now when known.
    Done(Applied, Option<Box<Loaded>>),
    /// Not this way: read the kernel (nothing was changed).
    Slow,
}

/// What one rule table's commit does.
struct TableDelta {
    table: RuleTable,
    /// Per new position: the old position of the same rule, or [`NEW`].
    src: Vec<u32>,
    /// Old positions whose kernel rules go.
    deleted: Vec<usize>,
    /// New positions whose kernel rules come, in order.
    inserted: Vec<(usize, Vec<Rule>)>,
}

const NEW: u32 = u32::MAX;

/// The runs `(old range, new range)` of `new` that are not blocks shared
/// with `old` in order; the shared ones are marked kept in `src`.
fn regions<T>(
    old: &CowList<T>,
    new: &CowList<T>,
    src: &mut [u32],
) -> Vec<(std::ops::Range<usize>, std::ops::Range<usize>)> {
    let mut out = Vec::new();
    let (mut o, mut n, mut rn) = (0usize, 0usize, 0usize);
    let keep = |os: usize, ns: usize, len: usize, src: &mut [u32]| {
        for k in 0..len {
            if let Some(s) = src.get_mut(ns + k) {
                *s = u32::try_from(os + k).unwrap_or(NEW);
            }
        }
    };
    if CowList::ptr_eq(old, new) {
        keep(0, 0, new.len(), src);
        return out;
    }
    for (len, shared) in new.shared_blocks(old) {
        match shared {
            Some(os) if os >= o => {
                if os > o || n > rn {
                    out.push((o..os, rn..n));
                }
                keep(os, n, len, src);
                o = os + len;
                n += len;
                rn = n;
            }
            _ => n += len,
        }
    }
    if old.len() > o || new.len() > rn {
        out.push((o..old.len(), rn..new.len()));
    }
    out
}

/// The kernel form of each rule, for the diff.
fn kernel_forms(t: RuleTable, rules: &[&FirewallRule], filled: &BTreeSet<&Name>) -> Vec<Vec<Rule>> {
    rules
        .iter()
        .map(|r| fwnft::program_rules(t, r, filled))
        .collect()
}

/// Commit `from` → `to` from what is loaded, without reading the kernel.
pub(crate) fn apply(mut l: Box<Loaded>, from: &Config, to: &Config) -> Outcome {
    // What is loaded must be `from`, and nobody may have changed nftables
    // since (any other commit is checked again by the kernel, below).
    if nfnl::stamp(TABLE) != l.stamp
        || l.fw != from.ip.firewall
        || l.interface_lists != from.interface_lists
        || l.notice != from.ip.subscriber_notice
    {
        return Outcome::Slow;
    }
    // Only rules may differ; a table that goes away is the slow path's.
    let (ofw, nfw) = (&l.fw, &to.ip.firewall);
    if l.interface_lists != to.interface_lists
        || l.notice != to.ip.subscriber_notice
        || ofw.address_lists != nfw.address_lists
        || (nfw.is_empty() && !corerouter_firewall::notice::on(to))
    {
        return Outcome::Slow;
    }

    // 1. The rules that changed, and what they need.
    let mut census = l.census.clone();
    let mut middles = Vec::new();
    let mut src_of: Vec<Vec<u32>> = Vec::new();
    for t in RuleTable::ALL {
        let (old, new) = (ofw.rules(t), nfw.rules(t));
        let mut src = vec![NEW; new.len()];
        for (or, nr) in regions(old, new, &mut src) {
            let o: Vec<&FirewallRule> = old.range(or.start, or.len()).collect();
            let n: Vec<&FirewallRule> = new.range(nr.start, nr.len()).collect();
            let head = o.iter().zip(&n).take_while(|(a, b)| a == b).count();
            let tail = o
                .iter()
                .skip(head)
                .rev()
                .zip(n.iter().skip(head).rev())
                .take_while(|(a, b)| a == b)
                .count();
            // Equal head and tail: kept as they are.
            let pairs = (0..head).map(|k| (or.start + k, nr.start + k));
            let tails = (1..=tail).map(|k| (or.end - k, nr.end - k));
            for (op, np) in pairs.chain(tails) {
                if let Some(s) = src.get_mut(np) {
                    *s = u32::try_from(op).unwrap_or(NEW);
                }
            }
            let om = or.start + head..or.end - tail;
            let nm = nr.start + head..nr.end - tail;
            for r in old.range(om.start, om.len()) {
                census.count(fwnft::needs(t, r), false);
            }
            for r in new.range(nm.start, nm.len()) {
                census.count(fwnft::needs(t, r), true);
            }
            middles.push((t, om, nm));
        }
        src_of.push(src);
    }
    // A list filled by a rule (or no longer) changes every rule matching
    // it: the slow path rebuilds them all.
    if census.fills.keys().ne(l.census.fills.keys()) {
        return Outcome::Slow;
    }

    // 2. The kernel rules of those, diffed per region.
    let filled: BTreeSet<&Name> = l.census.fills.keys().collect();
    let mut deltas: Vec<TableDelta> = RuleTable::ALL
        .iter()
        .zip(src_of)
        .map(|(t, src)| TableDelta {
            table: *t,
            src,
            deleted: Vec::new(),
            inserted: Vec::new(),
        })
        .collect();
    for (t, om, nm) in middles {
        let Some(d) = deltas.get_mut(at(t)) else {
            return Outcome::Slow;
        };
        let o: Vec<&FirewallRule> = ofw.rules(t).range(om.start, om.len()).collect();
        let n: Vec<&FirewallRule> = nfw.rules(t).range(nm.start, nm.len()).collect();
        let (ok, nk) = (kernel_forms(t, &o, &filled), kernel_forms(t, &n, &filled));
        let mut ids: HashMap<&Vec<Rule>, usize> = HashMap::new();
        let mut key = |r| {
            let next = ids.len();
            *ids.entry(r).or_insert(next)
        };
        let a: Vec<usize> = ok.iter().map(&mut key).collect();
        let b: Vec<usize> = nk.iter().map(&mut key).collect();
        let script = myers(&a, &b, MAX_EDITS).unwrap_or_else(|| {
            let mut s = vec![Step::Delete; a.len()];
            s.extend(std::iter::repeat_n(Step::Insert, b.len()));
            s
        });
        let (mut i, mut j) = (0usize, 0usize);
        let mut nk = nk.into_iter();
        for st in script {
            match st {
                Step::Keep => {
                    if let Some(s) = d.src.get_mut(nm.start + j) {
                        *s = u32::try_from(om.start + i).unwrap_or(NEW);
                    }
                    nk.next();
                    i += 1;
                    j += 1;
                }
                Step::Delete => {
                    d.deleted.push(om.start + i);
                    i += 1;
                }
                Step::Insert => {
                    let rules = nk.next().unwrap_or_default();
                    if !rules.is_empty() {
                        d.inserted.push((nm.start + j, rules));
                    }
                    j += 1;
                }
            }
        }
        d.inserted.sort_by_key(|(p, _)| *p);
    }

    // 3. One batch: rules that go, new sets and chains, rules that come,
    // chains and sets that go.
    let mut done = Applied {
        cached: true,
        ..Applied::default()
    };
    let mut b = Batch::new(1);
    b.family(Family::Inet);
    b.name_anon_sets_from(l.anon_next);
    b.new_table(TABLE);
    for d in &deltas {
        let (old, h) = (ofw.rules(d.table), l.handles.get(at(d.table)));
        for &o in &d.deleted {
            let (Some(r), Some(h)) = (old.get(o), h) else {
                continue;
            };
            let hs = h.of(o);
            if hs.is_empty() {
                continue;
            }
            let kname = fwnft::chain_name(d.table, r.chain.as_str());
            for handle in hs {
                b.del_rule(TABLE, &kname, Some(*handle));
                done.rules_removed += 1;
            }
        }
    }
    let came = |old: &BTreeMap<String, u32>, new: &BTreeMap<String, u32>| -> Vec<String> {
        new.keys()
            .filter(|k| !old.contains_key(*k))
            .cloned()
            .collect()
    };
    let (new_chains, gone_chains) = (
        came(&l.census.chains, &census.chains),
        came(&census.chains, &l.census.chains),
    );
    let (new_ports, gone_ports) = (
        came(&l.census.ports, &census.ports),
        came(&census.ports, &l.census.ports),
    );
    let has_sets = |c: &Census, n: &Name| {
        l.fixed.contains(n) || c.lists.contains_key(n) || c.fills.contains_key(n)
    };
    let new_lists: Vec<&Name> = census
        .lists
        .keys()
        .filter(|n| !has_sets(&l.census, n))
        .collect();
    let gone_lists: Vec<&Name> = l
        .census
        .lists
        .keys()
        .filter(|n| !has_sets(&census, n))
        .collect();
    if !new_ports.is_empty() {
        // The port list behind each new set name, from the rules that came.
        let mut lists: HashMap<String, &PortSet> = HashMap::new();
        for d in &deltas {
            for (p, _) in &d.inserted {
                if let Some(r) = nfw.rules(d.table).get(*p) {
                    for ps in fwnft::needs(d.table, r).ports {
                        lists.entry(port_set_name(ps)).or_insert(ps);
                    }
                }
            }
        }
        for name in &new_ports {
            let Some(ps) = lists.get(name) else {
                return Outcome::Slow;
            };
            let s = port_set(ps);
            let id = b.new_fw_set(TABLE, &s);
            b.kernel_elements(TABLE, &s.name, Some(id), &s.encoded(), true);
            done.elements_changed += s.elements.len();
        }
    }
    for list in &new_lists {
        for s in fwnft::empty_list_sets(list) {
            b.new_fw_set(TABLE, &s);
        }
    }
    for kname in &new_chains {
        let Some((t, _)) = fwnft::table_of_chain(kname) else {
            return Outcome::Slow;
        };
        b.new_chain(TABLE, &fwnft::chain_object(t, kname));
    }
    // New rules: each after the kernel rule before it in its chain (kept,
    // so its handle is known), runs after the same one in reverse so they
    // land in order.
    let inserts: usize = deltas
        .iter()
        .flat_map(|d| &d.inserted)
        .map(|(_, rs)| rs.len())
        .sum();
    b.echo_rules(inserts <= ECHO_MAX);
    // (table, entry of `inserted`, kernel rule) of each rule sent, in order.
    let mut sent: Vec<(usize, usize, usize)> = Vec::with_capacity(inserts);
    for d in &deltas {
        let (new, h) = (nfw.rules(d.table), l.handles.get(at(d.table)));
        let mut group_of: HashMap<usize, usize> = HashMap::new();
        let mut groups: Vec<(Place, Vec<usize>)> = Vec::new();
        for (k, (p, _)) in d.inserted.iter().enumerate() {
            let Some(chain) = new.get(*p).map(|r| &r.chain) else {
                continue;
            };
            let mut place = Place::Start;
            let mut joins = None;
            for q in (0..*p).rev() {
                let Some(rq) = new.get(q) else { break };
                if rq.chain != *chain || !fwnft::live(rq) {
                    continue;
                }
                let from_old = d.src.get(q).copied().unwrap_or(NEW);
                if from_old != NEW {
                    if let Some(last) = h.and_then(|h| h.of(from_old as usize).last()) {
                        place = Place::After(*last);
                        break;
                    }
                } else if let Some(g) = group_of.get(&q) {
                    joins = Some(*g);
                    break;
                }
            }
            let g = match joins {
                Some(g) => g,
                None => {
                    groups.push((place, Vec::new()));
                    groups.len() - 1
                }
            };
            if let Some((_, members)) = groups.get_mut(g) {
                members.push(k);
            }
            group_of.insert(*p, g);
        }
        for (place, members) in &groups {
            for k in members.iter().rev() {
                let Some((_, rules)) = d.inserted.get(*k) else {
                    continue;
                };
                for (ri, r) in rules.iter().enumerate().rev() {
                    b.insert_rule(TABLE, r, *place);
                    sent.push((at(d.table), *k, ri));
                    done.rules_added += 1;
                }
            }
        }
    }
    for kname in &gone_chains {
        b.del_chain(TABLE, kname);
    }
    for name in &gone_ports {
        b.del_set(TABLE, name);
    }
    for list in &gone_lists {
        for s in fwnft::empty_list_sets(list) {
            b.del_set(TABLE, &s.name);
        }
    }
    let anon_next = b.next_anon_set().unwrap_or(l.anon_next);
    let echoed = b.echoed() > 0;
    let sends = b.messages() > 2;

    // 4. Send it (unless only the table message is in it).
    let committed = if !sends {
        nfnl::Committed::default()
    } else {
        match nfnl::apply_checked(b, "changing the firewall", Some(l.stamp.0)) {
            Ok(Some(c)) => c,
            // Someone else committed: nothing changed, read the kernel.
            Ok(None) => return Outcome::Slow,
            Err(e) => {
                log::info!("firewall: the change was refused ({e}); reading the kernel");
                return Outcome::Slow;
            }
        }
    };
    let stamp = nfnl::stamp(TABLE);
    let ours = stamp == (l.stamp.0, l.stamp.1.wrapping_add(u64::from(sends)));
    if !ours || (inserts > 0 && !echoed) {
        return Outcome::Done(done, None);
    }

    // 5. What is loaded now: kept rules keep their handles, new ones take
    // the echoed ones (which must be the rules sent, in order).
    if committed.rules.len() != sent.len() {
        return Outcome::Done(done, None);
    }
    let mut new_handles: HashMap<(usize, usize), Vec<u64>> = HashMap::new();
    for (echo, (t, k, ri)) in committed.rules.iter().zip(&sent) {
        let Some((p, want)) = deltas
            .get(*t)
            .and_then(|d| d.inserted.get(*k))
            .and_then(|(p, rs)| Some((p, rs.get(*ri)?)))
        else {
            return Outcome::Done(done, None);
        };
        if echo.rule.chain != want.chain || echo.rule.comment != want.comment {
            return Outcome::Done(done, None);
        }
        let v = new_handles.entry((*t, *p)).or_default();
        if v.len() <= *ri {
            v.resize(*ri + 1, 0);
        }
        if let Some(slot) = v.get_mut(*ri) {
            *slot = echo.handle;
        }
    }
    for d in &deltas {
        let i = at(d.table);
        let new = nfw.rules(d.table);
        let unchanged = d.deleted.is_empty()
            && d.inserted.is_empty()
            && d.src.len() == l.handles.get(i).map_or(0, Handles::rules)
            && d.src.iter().enumerate().all(|(p, s)| *s as usize == p);
        if unchanged {
            continue;
        }
        let Some(old) = l.handles.get(i) else {
            return Outcome::Done(done, None);
        };
        let mut h = Handles::with_capacity(new.len());
        for (p, s) in d.src.iter().enumerate() {
            if *s != NEW {
                h.push(old.of(*s as usize));
            } else {
                h.push(new_handles.get(&(i, p)).map_or(&[][..], Vec::as_slice));
            }
        }
        if let Some(slot) = l.handles.get_mut(i) {
            *slot = h;
        }
    }
    l.fw = nfw.clone();
    l.census = census;
    l.stamp = stamp;
    l.anon_next = anon_next;
    Outcome::Done(done, Some(l))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What `regions` keeps and leaves to diff, on lists edited in place.
    #[test]
    fn regions_leave_only_the_blocks_an_edit_touched() {
        let old: CowList<u32> = (0..1000).collect();
        let run = |new: &CowList<u32>| {
            let mut src = vec![NEW; new.len()];
            let r = regions(&old, new, &mut src);
            (r, src)
        };
        // Untouched: everything kept, nothing to diff.
        let (r, src) = run(&old.clone());
        assert!(r.is_empty());
        assert!(src.iter().enumerate().all(|(i, s)| *s as usize == i));

        // One item changed: one block to diff, the rest kept in place.
        let mut one = old.clone();
        if let Some(x) = one.get_mut(500) {
            *x = 9999;
        }
        let (r, src) = run(&one);
        assert_eq!(r.len(), 1);
        let (or, nr) = r.first().unwrap().clone();
        assert_eq!(or, nr);
        assert!(or.contains(&500) && or.len() <= corerouter_model::cow_list::BLOCK);
        for (i, s) in src.iter().enumerate() {
            assert_eq!(*s == NEW, or.contains(&i), "{i}");
        }

        // One item inserted at the front: kept items shift by one.
        let mut ins = old.clone();
        ins.insert(0, 7777);
        let (r, src) = run(&ins);
        assert!(r.iter().map(|(o, n)| o.len() + n.len()).sum::<usize>() < 2 * 256 + 1);
        for (i, s) in src.iter().enumerate() {
            if *s != NEW {
                assert_eq!(ins.get(i), old.get(*s as usize));
            }
        }

        // Nothing shared (a list rebuilt): one region, the whole list.
        let fresh: CowList<u32> = (0..1000).collect();
        let (r, _) = run(&fresh);
        assert_eq!(r, vec![(0..1000, 0..1000)]);
    }
}
