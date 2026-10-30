//! The firewall's table, `inet corerouter`, over nfnetlink (G2.8): no
//! `nft` program, and a commit sends only what changed.
//!
//! - **Commit** ([`apply`]): the rules that changed, by kernel handle
//!   (one `DELRULE` per rule gone, one `NEWRULE` at its place per rule
//!   new), the set elements that changed and the chains and sets that
//!   came or went, in **one** batch (`NFNL_MSG_BATCH_BEGIN`/`END`): the
//!   kernel commits it whole or not at all. A rule that did not change
//!   keeps its counters, and the dynamic sets (rule-filled address lists,
//!   timed entries) are never touched.
//! - **From what was loaded** (G0.31f, [`crate::fw_delta`]): when nobody
//!   else committed to nftables since the last commit, the next one starts
//!   from what that one loaded (rules, handles), without reading the
//!   kernel, and builds only the rules that changed.
//! - Otherwise (the first commit, or after a drift) the kernel's rules are
//!   read (one dump) and checked against what we believe we loaded;
//!   anything else (a table we did not load, a set whose definition
//!   changed, a refused diff) falls back to replacing the table whole,
//!   still one batch, after reading back the dynamic entries so they
//!   survive it.
//! - **Dynamic entries** ([`apply_dynamic`]): address-list entries with a
//!   timeout, any number of them in one batch of `NEWSETELEM`/`DELSETELEM`
//!   (it was one `nft` process per entry).
//!
//! Only table `inet corerouter` is ever named: rules of other owners are
//! not read or touched.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use corerouter_firewall::bytecode::interval_elements;
use corerouter_firewall::program::{FwElement, FwSet, KernelElement, KeyKind, Rule, Table};
use corerouter_firewall::{TABLE, nft as fwnft};
use corerouter_hal::HalError;
use corerouter_model::Config;
use corerouter_model::firewall::{AddrMatch, DynamicAddress, Family, Name};

use crate::fw_delta::{self, ChainHandles, ECHO_MAX, Loaded, Outcome};
use crate::nfnl::{self, Batch, Place};
use crate::nft_read::{self, ReadRule, Reader};

/// `NFPROTO_INET`.
pub const FAMILY: u8 = 1;

/// The most edits one chain's diff looks for before it rewrites the
/// chain's changed middle instead (the diff costs O(edits²) memory).
pub(crate) const MAX_EDITS: usize = 1024;

/// What one apply did (for the log and the benchmarks).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Applied {
    /// The table was replaced whole (no diff was possible).
    pub replaced: bool,
    pub rules_added: usize,
    pub rules_removed: usize,
    pub elements_changed: usize,
    /// Done from what the previous commit loaded, without reading the
    /// kernel (G0.31f).
    pub cached: bool,
}

/// What the kernel holds of our table, for the diff.
struct Held {
    chains: Vec<corerouter_firewall::program::Chain>,
    sets: Vec<nft_read::SetInfo>,
    rules: Vec<ReadRule>,
}

fn read_held() -> Result<Held, HalError> {
    nft_read::with_reader(|rd| {
        Ok(Held {
            chains: rd.chains(FAMILY, TABLE)?,
            sets: rd.sets(FAMILY, TABLE)?,
            rules: rd.rules(FAMILY, TABLE)?,
        })
    })
}

/// What the last commit loaded (G0.31f): the next one starts from it
/// instead of reading the kernel (see [`crate::fw_delta`]).
static LOADED: Mutex<Option<Box<Loaded>>> = Mutex::new(None);

fn loaded() -> std::sync::MutexGuard<'static, Option<Box<Loaded>>> {
    LOADED.lock().unwrap_or_else(|e| e.into_inner())
}

/// Take the firewall from `from` to `to`: from what the previous commit
/// loaded when nothing else changed nftables since ([`crate::fw_delta`]),
/// else by reading the kernel.
pub fn apply(from: &Config, to: &Config) -> Result<Applied, HalError> {
    let mut loaded = loaded();
    if let Some(l) = loaded.take() {
        match fw_delta::apply(l, from, to) {
            Outcome::Done(applied, next) => {
                *loaded = next;
                return Ok(applied);
            }
            Outcome::Slow => {}
        }
    }
    let (applied, next) = read_and_apply(from, to)?;
    *loaded = next;
    Ok(applied)
}

/// The commit that reads the kernel. The three inputs of the diff are
/// independent and run side by side: the old program, the new one and the
/// kernel's rules (10 000 rules: 15 + 15 + 38 ms one after the other,
/// **medido**; together, the longest of them).
fn read_and_apply(from: &Config, to: &Config) -> Result<(Applied, Option<Box<Loaded>>), HalError> {
    // Before the read: a commit by anyone else after it shows here.
    let stamp = nfnl::stamp(TABLE);
    let (old, new, held) = std::thread::scope(|s| {
        let old = std::thread::Builder::new()
            .name("fw-diff-old".into())
            .spawn_scoped(s, || fwnft::program(from, &[]));
        let held = std::thread::Builder::new()
            .name("fw-diff-read".into())
            .spawn_scoped(s, read_held);
        let new = fwnft::program(to, &[]);
        // A thread that could not start runs here instead.
        let old = match old {
            Ok(h) => h.join().ok().flatten(),
            Err(_) => fwnft::program(from, &[]),
        };
        let held = match held {
            Ok(h) => h
                .join()
                .unwrap_or_else(|_| Err(HalError::Io("reading the firewall".into()))),
            Err(_) => read_held(),
        };
        (old, new, held)
    });
    let Some(new) = new else {
        remove_table()?;
        return Ok((
            Applied {
                replaced: true,
                ..Applied::default()
            },
            None,
        ));
    };
    if let Some(old) = &old {
        match held.and_then(|h| diff_apply(old, &new, h)) {
            Ok(Some(a)) => {
                // Ours if the table's only write since the read was this
                // commit's (or none).
                let now = nfnl::stamp(TABLE);
                let next = a
                    .chains
                    .filter(|_| now == (stamp.0, stamp.1.wrapping_add(u64::from(a.sent))));
                let next = next.and_then(|(c, anon)| Loaded::from_kernel(to, &c, now, anon));
                return Ok((a.applied, next));
            }
            Ok(None) => {}
            Err(e) => log::info!("firewall: the diff was refused ({e}); replacing the table"),
        }
    }
    replace_table(to)?;
    Ok((
        Applied {
            replaced: true,
            rules_added: new.rules.len(),
            ..Applied::default()
        },
        None,
    ))
}

/// The empty table a check fills (G1.3g); never holds anything committed.
pub const SCRATCH: &str = "corerouter-check";

/// G1.3g: the rules of `cfg` the kernel would refuse, checked without
/// loading anything (sent as a check: see [`nfnl::CheckBatch`]), in the
/// order of the batch. A refusal that is no rule's (a set, a chain, the
/// table, the batch) is an `Err`, with what the kernel said.
///
/// Into an empty scratch table that exists before the check (committed
/// empty, removed after), not by replacing ours: what only the
/// whole-table validation finds (a `dst-nat` in `srcnat`, a jump loop)
/// is reported per rule on the kernel's replay only for a table that
/// was there before the batch. The abort that ends a check sets
/// `validate_state = DO` on the tables it validated, not on the netns
/// as the commit does (`nf_tables_api.c`: `__nf_tables_abort` against
/// `nf_tables_commit` step 0, kernel 6.18), and a table the batch
/// creates is born again on the replay with the netns' `SKIP`: the error
/// was lost (**medido**: a check of ours reported nothing).
///
/// With validation on, the refused rule stays in its chain for the rest
/// of the replay, so every rule after it is refused too: only the
/// **first** refusal is certain; the caller takes it out and checks
/// again.
pub fn check(cfg: &Config) -> Result<Vec<corerouter_hal::RefusedItem>, HalError> {
    let Some(mut t) = fwnft::program(cfg, &[]) else {
        return Ok(Vec::new());
    };
    t.name = SCRATCH.into();
    let scratch = |add: bool| {
        let mut b = Batch::new(1);
        b.family(t.family);
        b.new_table(SCRATCH);
        if !add {
            b.del_table(SCRATCH);
        }
        nfnl::apply(b, "the firewall check's scratch table")
    };
    scratch(true)?;
    let mut b = Batch::new(1);
    b.track_rules();
    let lookup = nfnl::fill(&t, b).finish_check();
    let refused = nfnl::check(&lookup, "checking the firewall");
    if let Err(e) = scratch(false) {
        log::warn!("firewall check: removing table {SCRATCH}: {e}");
    }
    let refused = refused?;
    // Only the first is certain (see above).
    let Some(&(seq, errno)) = refused.first() else {
        return Ok(Vec::new());
    };
    let why = std::io::Error::from_raw_os_error(errno).to_string();
    let id = lookup
        .rule_of(seq)
        .and_then(|r| r.comment.as_deref())
        .and_then(|c| c.strip_prefix("cr:"))
        .and_then(|c| c.parse().ok());
    match id {
        Some(id) => Ok(vec![corerouter_hal::RefusedItem { id, reason: why }]),
        None => Err(HalError::Rejected(format!(
            "nftables refused message {} of the firewall, which is no rule's ({why})",
            seq.wrapping_sub(lookup.seqs.start)
        ))),
    }
}

/// Replace the table whole with `cfg`'s, keeping the dynamic entries.
pub fn replace(cfg: &Config) -> Result<(), HalError> {
    let mut loaded = loaded();
    *loaded = None;
    replace_table(cfg)
}

fn replace_table(cfg: &Config) -> Result<(), HalError> {
    let dynamic = dynamic().unwrap_or_default();
    let Some(t) = fwnft::program(cfg, &dynamic) else {
        return remove_table();
    };
    nfnl::apply(nfnl::replace(&t, 1), "loading the firewall")
}

/// Delete our table (absent: nothing to do).
pub fn remove() -> Result<(), HalError> {
    let mut loaded = loaded();
    *loaded = None;
    remove_table()
}

fn remove_table() -> Result<(), HalError> {
    let mut b = Batch::new(1);
    b.family(corerouter_firewall::program::Family::Inet);
    b.new_table(TABLE);
    b.del_table(TABLE);
    nfnl::apply(b, "removing the firewall")
}

/// One step of a chain's diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Step {
    Keep,
    Delete,
    Insert,
}

/// The shortest edit script from `a` to `b` (Myers), or `None` past
/// `max` edits.
pub(crate) fn myers(a: &[usize], b: &[usize], max: usize) -> Option<Vec<Step>> {
    let (n, m) = (a.len(), b.len());
    let off = max + 1;
    let mut v = vec![0usize; 2 * off + 1];
    let mut trace: Vec<Vec<usize>> = Vec::new();
    for d in 0..=max {
        trace.push(v.clone());
        let d_i = d as isize;
        let mut k = -d_i;
        while k <= d_i {
            let idx = (k + off as isize) as usize;
            let down = k == -d_i || (k != d_i && v.get(idx - 1).copied() < v.get(idx + 1).copied());
            let mut x = if down {
                v.get(idx + 1).copied().unwrap_or(0)
            } else {
                v.get(idx - 1).copied().unwrap_or(0) + 1
            };
            let mut y = (x as isize - k) as usize;
            while x < n && y < m && a.get(x) == b.get(y) {
                x += 1;
                y += 1;
            }
            if let Some(s) = v.get_mut(idx) {
                *s = x;
            }
            if x >= n && y >= m {
                return Some(backtrack(&trace, a, b, d, off));
            }
            k += 2;
        }
    }
    None
}

fn backtrack(
    trace: &[Vec<usize>],
    a: &[usize],
    b: &[usize],
    d_end: usize,
    off: usize,
) -> Vec<Step> {
    let mut steps = Vec::new();
    let (mut x, mut y) = (a.len() as isize, b.len() as isize);
    for d in (0..=d_end).rev() {
        let Some(v) = trace.get(d) else { break };
        let k = x - y;
        let d_i = d as isize;
        let at = |k: isize| v.get((k + off as isize) as usize).copied().unwrap_or(0) as isize;
        let down = k == -d_i || (k != d_i && at(k - 1) < at(k + 1));
        let prev_k = if down { k + 1 } else { k - 1 };
        let prev_x = at(prev_k);
        let prev_y = prev_x - prev_k;
        while x > prev_x && y > prev_y {
            steps.push(Step::Keep);
            x -= 1;
            y -= 1;
        }
        if d > 0 {
            steps.push(if down { Step::Insert } else { Step::Delete });
        }
        x = prev_x;
        y = prev_y;
    }
    steps.reverse();
    steps
}

/// The steps from `old` to `new`: common head and tail kept, the middle
/// diffed (or, past [`MAX_EDITS`], deleted and inserted whole).
fn steps(old: &[&Rule], new: &[&Rule]) -> Vec<Step> {
    let head = old.iter().zip(new).take_while(|(a, b)| a == b).count();
    let (orest, nrest) = (
        old.get(head..).unwrap_or(&[]),
        new.get(head..).unwrap_or(&[]),
    );
    let tail = orest
        .iter()
        .rev()
        .zip(nrest.iter().rev())
        .take_while(|(a, b)| a == b)
        .count();
    let om = orest.get(..orest.len() - tail).unwrap_or(&[]);
    let nm = nrest.get(..nrest.len() - tail).unwrap_or(&[]);
    let mut ids: HashMap<&Rule, usize> = HashMap::new();
    let mut a: Vec<usize> = Vec::with_capacity(om.len());
    for r in om {
        let n = ids.len();
        a.push(*ids.entry(*r).or_insert(n));
    }
    let mut b: Vec<usize> = Vec::with_capacity(nm.len());
    for r in nm {
        let n = ids.len();
        b.push(*ids.entry(*r).or_insert(n));
    }
    let middle = myers(&a, &b, MAX_EDITS).unwrap_or_else(|| {
        let mut s = vec![Step::Delete; a.len()];
        s.extend(std::iter::repeat_n(Step::Insert, b.len()));
        s
    });
    let mut out = vec![Step::Keep; head];
    out.extend(middle);
    out.extend(std::iter::repeat_n(Step::Keep, tail));
    out
}

fn by_chain(rules: &[Rule]) -> BTreeMap<&str, Vec<&Rule>> {
    let mut out: BTreeMap<&str, Vec<&Rule>> = BTreeMap::new();
    for r in rules {
        out.entry(r.chain.as_str()).or_default().push(r);
    }
    out
}

/// What [`diff_apply`] did.
struct Diffed {
    applied: Applied,
    /// A batch went to the kernel.
    sent: bool,
    /// What the kernel then holds of each chain, when the new rules'
    /// handles came back, and the number of the next anonymous set.
    chains: Option<(ChainHandles, u32)>,
}

/// A rule of a chain after the diff: kept (its handle) or new (its place
/// among the rules sent).
#[derive(Clone, Copy)]
enum Slot {
    Kept(u64),
    New(usize),
}

/// The diff from `old` (what we loaded) to `new`, against the kernel's
/// handles; `Ok(None)` when the kernel does not hold `old` (or a set
/// changed definition): the caller replaces the table.
fn diff_apply(old: &Table, new: &Table, held: Held) -> Result<Option<Diffed>, HalError> {
    let Held {
        chains: kchains,
        sets: ksets,
        rules: krules,
    } = held;
    if kchains.is_empty() && !old.chains.is_empty() {
        return Ok(None);
    }
    // The kernel must hold `old`: same chains, sets and rules.
    if kchains != old.chains {
        return Ok(None);
    }
    let knamed: Vec<&FwSet> = ksets
        .iter()
        .filter(|s| !s.anonymous)
        .map(|s| &s.set)
        .collect();
    if knamed.len() != old.fw_sets.len()
        || knamed
            .iter()
            .zip(&old.fw_sets)
            .any(|(k, o)| !k.same_definition(o))
    {
        return Ok(None);
    }
    let mut handles: BTreeMap<&str, Vec<u64>> = BTreeMap::new();
    let old_rules = by_chain(&old.rules);
    let mut kby: BTreeMap<&str, Vec<&ReadRule>> = BTreeMap::new();
    for r in &krules {
        if r.unknown {
            return Ok(None);
        }
        kby.entry(r.rule.chain.as_str()).or_default().push(r);
    }
    for (chain, ours) in &old_rules {
        let theirs = kby.get(chain).map_or(&[][..], Vec::as_slice);
        if theirs.len() != ours.len()
            || !theirs
                .iter()
                .zip(ours)
                .all(|(k, o)| nft_read::same_shape(&k.rule, o))
        {
            return Ok(None);
        }
        handles.insert(chain, theirs.iter().map(|k| k.handle).collect());
    }
    if kby.keys().any(|c| !old_rules.contains_key(c)) {
        return Ok(None);
    }
    // Sets whose definition changed: replace (rules would hang on them).
    let old_sets: BTreeMap<&str, &FwSet> =
        old.fw_sets.iter().map(|s| (s.name.as_str(), s)).collect();
    let new_sets: BTreeMap<&str, &FwSet> =
        new.fw_sets.iter().map(|s| (s.name.as_str(), s)).collect();
    if new_sets
        .iter()
        .any(|(n, s)| old_sets.get(n).is_some_and(|o| !o.same_definition(s)))
    {
        return Ok(None);
    }
    let old_chains: BTreeMap<&str, _> = old.chains.iter().map(|c| (c.name.as_str(), c)).collect();
    let new_chains: BTreeMap<&str, _> = new.chains.iter().map(|c| (c.name.as_str(), c)).collect();
    if new_chains
        .iter()
        .any(|(n, c)| old_chains.get(n).is_some_and(|o| *o != *c))
    {
        return Ok(None);
    }

    let mut done = Applied::default();
    let mut b = Batch::new(1);
    b.family(corerouter_firewall::program::Family::Inet);
    // New anonymous sets after the numbers the table already uses.
    let first = ksets
        .iter()
        .filter_map(|s| s.set.name.strip_prefix("__set")?.parse::<u32>().ok())
        .max()
        .map_or(0, |n| n.saturating_add(1));
    b.name_anon_sets_from(first);
    b.new_table(TABLE);
    let new_rules = by_chain(&new.rules);
    // Every new rule, in the order it is first met.
    let mut tickets: Vec<&Rule> = Vec::new();
    let mut slots: BTreeMap<&str, Vec<Slot>> = BTreeMap::new();
    // 1. Rules that go (in kept chains; gone chains are flushed below).
    let mut inserts: Vec<(Place, Vec<usize>)> = Vec::new();
    for (chain, ours) in &old_rules {
        let Some(hs) = handles.get(chain) else {
            continue;
        };
        let Some(theirs) = new_rules.get(chain) else {
            continue;
        };
        if !new_chains.contains_key(chain) {
            continue;
        }
        let script = steps(ours, theirs);
        let (mut i, mut j) = (0usize, 0usize);
        let mut anchor = Place::Start;
        let mut pending: Vec<usize> = Vec::new();
        let slot = slots.entry(chain).or_default();
        for st in script {
            match st {
                Step::Keep => {
                    if !pending.is_empty() {
                        inserts.push((anchor, std::mem::take(&mut pending)));
                    }
                    if let Some(h) = hs.get(i) {
                        anchor = Place::After(*h);
                        slot.push(Slot::Kept(*h));
                    }
                    i += 1;
                    j += 1;
                }
                Step::Delete => {
                    if let Some(h) = hs.get(i) {
                        b.del_rule(TABLE, chain, Some(*h));
                        done.rules_removed += 1;
                    }
                    i += 1;
                }
                Step::Insert => {
                    if let Some(r) = theirs.get(j) {
                        pending.push(tickets.len());
                        slot.push(Slot::New(tickets.len()));
                        tickets.push(r);
                    }
                    j += 1;
                }
            }
        }
        if !pending.is_empty() {
            inserts.push((anchor, pending));
        }
    }
    // Chains kept whose rules all go.
    for (chain, ours) in &old_rules {
        if new_chains.contains_key(chain) && !new_rules.contains_key(chain) {
            for h in handles.get(chain).into_iter().flatten() {
                b.del_rule(TABLE, chain, Some(*h));
            }
            done.rules_removed += ours.len();
        }
    }
    // Chains that go: emptied first (a jump into one is a rule that went).
    let gone_chains: Vec<&str> = old
        .chains
        .iter()
        .map(|c| c.name.as_str())
        .filter(|n| !new_chains.contains_key(n))
        .collect();
    for c in &gone_chains {
        b.del_rule(TABLE, c, None);
        done.rules_removed += old_rules.get(c).map_or(0, Vec::len);
    }
    // Rules of new chains (and of kept chains that had none) go in whole.
    let mut at_end: Vec<usize> = Vec::new();
    for c in &new.chains {
        if old_chains.contains_key(c.name.as_str()) && old_rules.contains_key(c.name.as_str()) {
            continue;
        }
        let slot = slots.entry(c.name.as_str()).or_default();
        for r in new_rules.get(c.name.as_str()).into_iter().flatten() {
            at_end.push(tickets.len());
            slot.push(Slot::New(tickets.len()));
            tickets.push(r);
        }
    }
    // 2. New sets and chains, then elements.
    for s in &new.fw_sets {
        if !old_sets.contains_key(s.name.as_str()) {
            let id = b.new_fw_set(TABLE, s);
            let enc = s.encoded();
            done.elements_changed += enc.len();
            b.kernel_elements(TABLE, &s.name, Some(id), &enc, true);
        }
    }
    for c in &new.chains {
        if !old_chains.contains_key(c.name.as_str()) {
            b.new_chain(TABLE, c);
        }
    }
    for s in &new.fw_sets {
        let Some(o) = old_sets.get(s.name.as_str()) else {
            continue;
        };
        if o.elements == s.elements {
            continue;
        }
        let (gone, came) = element_diff(&o.encoded(), &s.encoded());
        done.elements_changed += gone.len() + came.len();
        b.kernel_elements(TABLE, &s.name, None, &gone, false);
        b.kernel_elements(TABLE, &s.name, None, &came, true);
    }
    // 3. New rules: at their place in kept chains (each group in reverse
    // after the same anchor lands in order), in full in new chains; echoed
    // back with their handles when not too many.
    b.echo_rules(tickets.len() <= ECHO_MAX);
    let mut sent: Vec<usize> = Vec::with_capacity(tickets.len());
    for (place, group) in &inserts {
        for t in group.iter().rev() {
            if let Some(r) = tickets.get(*t) {
                b.insert_rule(TABLE, r, *place);
                sent.push(*t);
                done.rules_added += 1;
            }
        }
    }
    for t in &at_end {
        if let Some(r) = tickets.get(*t) {
            b.insert_rule(TABLE, r, Place::End);
            sent.push(*t);
            done.rules_added += 1;
        }
    }
    // 4. What went: chains, then sets (nothing refers to them any more).
    for c in &gone_chains {
        b.del_chain(TABLE, c);
    }
    for s in &old.fw_sets {
        if !new_sets.contains_key(s.name.as_str()) {
            b.del_set(TABLE, &s.name);
        }
    }
    let anon_next = b.next_anon_set().unwrap_or(first);
    let echoed = b.echoed() == tickets.len();
    // Only the table message: nothing changed.
    let sends = b.messages() > 2;
    let committed = if sends {
        nfnl::apply_checked(b, "changing the firewall", None)?.unwrap_or_default()
    } else {
        nfnl::Committed::default()
    };
    let mut diffed = Diffed {
        applied: done,
        sent: sends,
        chains: None,
    };
    // The handle of each new rule, from the echo (the rules sent, in order).
    let mut new_handles: Vec<Option<u64>> = vec![None; tickets.len()];
    if echoed && committed.rules.len() == sent.len() {
        for (echo, t) in committed.rules.iter().zip(&sent) {
            let Some(r) = tickets.get(*t) else { continue };
            if echo.rule.chain == r.chain
                && echo.rule.comment == r.comment
                && let Some(slot) = new_handles.get_mut(*t)
            {
                *slot = Some(echo.handle);
            }
        }
    }
    let mut chains: ChainHandles = BTreeMap::new();
    for c in &new.chains {
        let rules = new_rules
            .get(c.name.as_str())
            .map_or(&[][..], Vec::as_slice);
        let slot = slots.get(c.name.as_str()).map_or(&[][..], Vec::as_slice);
        if slot.len() != rules.len() {
            return Ok(Some(diffed));
        }
        let mut list = Vec::with_capacity(rules.len());
        for (r, s) in rules.iter().zip(slot) {
            let h = match s {
                Slot::Kept(h) => Some(*h),
                Slot::New(t) => new_handles.get(*t).copied().flatten(),
            };
            let Some(h) = h else {
                return Ok(Some(diffed));
            };
            list.push((r.comment.clone(), h));
        }
        chains.insert(c.name.clone(), list);
    }
    diffed.chains = Some((chains, anon_next));
    Ok(Some(diffed))
}

/// Elements of `old` that go and of `new` that come.
fn element_diff(
    old: &[KernelElement],
    new: &[KernelElement],
) -> (Vec<KernelElement>, Vec<KernelElement>) {
    let o: std::collections::HashSet<&KernelElement> = old.iter().collect();
    let n: std::collections::HashSet<&KernelElement> = new.iter().collect();
    (
        old.iter().filter(|e| !n.contains(e)).cloned().collect(),
        new.iter().filter(|e| !o.contains(e)).cloned().collect(),
    )
}

/// An address list's set for `d` (`al4_x`/`al6_x`), as the ruleset
/// declares it.
fn list_set(list: &Name, v6: bool) -> FwSet {
    FwSet {
        name: format!("{}_{list}", if v6 { "al6" } else { "al4" }),
        key: if v6 { KeyKind::Ipv6 } else { KeyKind::Ipv4 },
        interval: true,
        timeout: true,
        dynamic: false,
        size: None,
        auto_merge: true,
        elements: Vec::new(),
    }
}

/// Add (`true`) and remove dynamic entries, all in one batch (creating our
/// table and the lists' sets if needed). Entries that overlap what the set
/// already holds make the kernel refuse the batch: then each touched set
/// is read, merged in user space (what nft's `auto-merge` does) and
/// rewritten, still in one batch.
pub fn apply_dynamic(changes: &[(bool, &DynamicAddress)]) -> Result<(), HalError> {
    if changes.is_empty() {
        return Ok(());
    }
    let mut sets: BTreeMap<(String, bool), SetChange<'_>> = BTreeMap::new();
    for (add, d) in changes {
        let v6 = d.address.family() == Family::Ipv6;
        let set = list_set(&d.list, v6);
        let e = sets
            .entry((set.name.clone(), v6))
            .or_insert_with(|| (set, Vec::new(), Vec::new()));
        if *add {
            e.1.push((&d.address, d.timeout_secs.max(1)));
        } else {
            e.2.push(&d.address);
        }
    }
    let mut b = Batch::new(1);
    b.family(corerouter_firewall::program::Family::Inet);
    b.new_table(TABLE);
    for (set, adds, dels) in sets.values() {
        b.new_fw_set(TABLE, set);
        let gone: Vec<KernelElement> = dels.iter().flat_map(|a| range_elements(a)).collect();
        b.kernel_elements(TABLE, &set.name, None, &gone, false);
        let came = corerouter_firewall::program::interval_encoding(&interval_elements(&[], adds));
        b.kernel_elements(TABLE, &set.name, None, &came, true);
    }
    match nfnl::apply(b, "changing dynamic address-list entries") {
        Ok(()) => Ok(()),
        Err(e) => {
            log::info!("dynamic entries: {e}; merging with what the sets hold");
            rewrite_sets(sets.into_values().collect())
        }
    }
}

/// The start and end element of one range (no leading end at zero).
fn range_elements(a: &AddrMatch) -> Vec<KernelElement> {
    let el = interval_elements(&[], &[(a, 1)]);
    corerouter_firewall::program::interval_encoding(&el)
        .into_iter()
        .filter(|e| !(e.end && e.key.iter().all(|b| *b == 0)))
        .map(|mut e| {
            e.timeout_ms = None;
            e
        })
        .collect()
}

type SetChange<'a> = (FwSet, Vec<(&'a AddrMatch, u64)>, Vec<&'a AddrMatch>);

/// Read each set, apply the changes in user space, flush and refill it
/// (one batch for all).
fn rewrite_sets(sets: Vec<SetChange<'_>>) -> Result<(), HalError> {
    let b = nft_read::with_reader(|rd| rewrite_batch(rd, &sets))?;
    nfnl::apply(b, "changing dynamic address-list entries")
}

fn rewrite_batch(rd: &mut Reader, sets: &[SetChange<'_>]) -> Result<Batch, HalError> {
    let mut b = Batch::new(1);
    b.family(corerouter_firewall::program::Family::Inet);
    b.new_table(TABLE);
    for (set, adds, dels) in sets {
        let now = nft_read::ranges(rd.elements(FAMILY, TABLE, &set.name)?, true);
        let mut statics: Vec<AddrMatch> = Vec::new();
        let mut timed: Vec<(AddrMatch, u64)> = Vec::new();
        for e in &now {
            let Some(a) = addr_of(&e.key, e.last.as_deref()) else {
                continue;
            };
            match e.timeout_ms {
                // Removing an entry removes the timed ranges it covers.
                Some(ms) => {
                    if !dels.iter().any(|d| d.covers(&a)) {
                        timed.push((a, ms.div_ceil(1000)));
                    }
                }
                None => statics.push(a),
            }
        }
        let st: Vec<&AddrMatch> = statics.iter().collect();
        let mut tm: Vec<(&AddrMatch, u64)> = timed.iter().map(|(a, t)| (a, *t)).collect();
        tm.extend(adds.iter().copied());
        b.new_fw_set(TABLE, set);
        b.flush_set(TABLE, &set.name);
        let enc = corerouter_firewall::program::interval_encoding(&interval_elements(&st, &tm));
        b.kernel_elements(TABLE, &set.name, None, &enc, true);
    }
    Ok(b)
}

/// An address, prefix or range from interval bounds (bytes of an IPv4 or
/// IPv6 address).
fn addr_of(lo: &[u8], hi: Option<&[u8]>) -> Option<AddrMatch> {
    let ip = |b: &[u8]| -> Option<std::net::IpAddr> {
        match b.len() {
            4 => Some(<[u8; 4]>::try_from(b).ok()?.into()),
            16 => Some(<[u8; 16]>::try_from(b).ok()?.into()),
            _ => None,
        }
    };
    let a = ip(lo)?;
    let Some(hi) = hi else {
        return Some(AddrMatch::Net(a.into()));
    };
    let z = ip(hi)?;
    // A whole prefix prints as one.
    let bits = lo.len() * 8;
    let (l, h) = (to_u128(lo), to_u128(hi));
    let span = h.wrapping_sub(l).wrapping_add(1);
    if span.is_power_of_two() && l & (span - 1) == 0 {
        let len = bits - span.trailing_zeros() as usize;
        if let Ok(n) = ipnet::IpNet::new(a, u8::try_from(len).unwrap_or(0)) {
            return Some(AddrMatch::Net(n));
        }
    }
    Some(AddrMatch::Range(a, z))
}

fn to_u128(b: &[u8]) -> u128 {
    b.iter().fold(0u128, |acc, x| (acc << 8) | u128::from(*x))
}

/// The dynamic entries of our address-list sets, with the time they have
/// left: timed entries of the `al*` sets (`address-list.add timeout=…`)
/// and every entry of the `ad*` sets (filled by `add-*-to-address-list`
/// rules). What a table replace puts back.
pub fn dynamic() -> Result<Vec<DynamicAddress>, HalError> {
    nft_read::with_reader(dynamic_in)
}

fn dynamic_in(rd: &mut Reader) -> Result<Vec<DynamicAddress>, HalError> {
    let sets = rd.sets(FAMILY, TABLE)?;
    let mut out = Vec::new();
    for info in sets {
        let name = &info.set.name;
        let (rest, by_rule) = match name.get(..4) {
            Some("al4_" | "al6_") => (name.get(4..), false),
            Some("ad4_" | "ad6_") => (name.get(4..), true),
            _ => continue,
        };
        let Some(list) = rest.and_then(|l| l.parse::<Name>().ok()) else {
            continue;
        };
        let read = rd.elements(FAMILY, TABLE, name)?;
        let elems: Vec<FwElement> = if info.set.interval {
            nft_read::ranges(read, true)
        } else {
            read.into_iter()
                .filter(|r| !r.element.end)
                .map(|r| FwElement {
                    key: r.element.key,
                    last: None,
                    timeout_ms: r.expires_ms.or(r.element.timeout_ms),
                })
                .collect()
        };
        for e in elems {
            if e.timeout_ms.is_none() && !by_rule {
                continue;
            }
            let Some(address) = addr_of(&e.key, e.last.as_deref()) else {
                continue;
            };
            out.push(DynamicAddress {
                list: list.clone(),
                address,
                timeout_secs: e.timeout_ms.map_or(0, |ms| ms.div_ceil(1000).max(1)),
                added_by_rule: by_rule,
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply_steps(a: &[usize], b: &[usize], s: &[Step]) -> Vec<usize> {
        let (mut i, mut j) = (0, 0);
        let mut out = Vec::new();
        for st in s {
            match st {
                Step::Keep => {
                    assert_eq!(a[i], b[j]);
                    out.push(a[i]);
                    i += 1;
                    j += 1;
                }
                Step::Delete => i += 1,
                Step::Insert => {
                    out.push(b[j]);
                    j += 1;
                }
            }
        }
        assert_eq!((i, j), (a.len(), b.len()));
        out
    }

    #[test]
    fn myers_finds_the_shortest_script() {
        let a = [1, 2, 3, 4, 5, 6];
        let b = [1, 3, 4, 7, 5, 6, 8];
        let s = myers(&a, &b, 100).unwrap();
        assert_eq!(apply_steps(&a, &b, &s), b);
        let edits = s.iter().filter(|x| **x != Step::Keep).count();
        assert_eq!(edits, 3, "{s:?}");
        // A rule moved from top to bottom: two edits, not a rewrite.
        let a = [1, 2, 3, 4];
        let b = [2, 3, 4, 1];
        let s = myers(&a, &b, 100).unwrap();
        assert_eq!(s.iter().filter(|x| **x != Step::Keep).count(), 2);
        assert!(myers(&[1, 2, 3], &[4, 5, 6], 2).is_none());
        assert_eq!(myers(&[], &[], 0).unwrap(), []);
    }

    proptest::proptest! {
        #[test]
        fn myers_scripts_turn_a_into_b(
            a in proptest::collection::vec(0usize..6, 0..40),
            b in proptest::collection::vec(0usize..6, 0..40),
        ) {
            let s = myers(&a, &b, 200).unwrap();
            proptest::prop_assert_eq!(apply_steps(&a, &b, &s), b);
        }
    }

    #[test]
    fn bounds_read_back_as_the_shortest_address() {
        assert_eq!(
            addr_of(&[10, 0, 0, 0], Some(&[10, 0, 0, 255])),
            Some("10.0.0.0/24".parse().unwrap())
        );
        assert_eq!(
            addr_of(&[10, 0, 0, 1], Some(&[10, 0, 0, 9])),
            Some("10.0.0.1-10.0.0.9".parse().unwrap())
        );
        assert_eq!(
            addr_of(&[192, 0, 2, 7], None),
            Some("192.0.2.7".parse().unwrap())
        );
        assert_eq!(
            addr_of(&[0; 4], Some(&[255; 4])),
            Some("0.0.0.0/0".parse().unwrap())
        );
    }
}
