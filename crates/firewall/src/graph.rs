//! Jumps between chains: which built-in chains reach a custom chain, and
//! loops (the kernel refuses a ruleset with one).

use std::collections::{BTreeMap, BTreeSet};

use corerouter_model::firewall::{Action, FirewallRule, Name, Table};

/// Jumps of one table: `chain → jump targets`.
pub type Edges<'a> = BTreeMap<&'a str, BTreeSet<&'a str>>;

/// Edges `chain → jump target` of one table (disabled rules included: a
/// later enable must not create a loop the validator never saw).
pub fn edges<'a>(rules: impl IntoIterator<Item = &'a FirewallRule>) -> Edges<'a> {
    let mut out: Edges<'a> = BTreeMap::new();
    for r in rules.into_iter().filter(|r| !r.section) {
        if let Action::Jump { jump_target } = &r.action {
            out.entry(r.chain.as_str())
                .or_default()
                .insert(jump_target.as_str());
        }
    }
    out
}

pub fn is_builtin(table: Table, chain: &str) -> bool {
    table.builtin_chains().contains(&chain)
}

/// Built-in chains from which `chain` can be reached (itself, if built-in).
/// Bounded by the number of chains, so hostile configs cannot hang it.
pub fn roots<'a>(table: Table, rules: &'a [FirewallRule], chain: &'a str) -> BTreeSet<&'a str> {
    roots_in(table, &edges(rules), chain)
}

/// [`roots`] over edges built once (the whole-table validation used to
/// rebuild them, from a copy of the table, for every rule: O(N²)).
pub fn roots_in<'a>(table: Table, edges: &Edges<'a>, chain: &'a str) -> BTreeSet<&'a str> {
    let mut out = BTreeSet::new();
    for root in table.builtin_chains() {
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let mut stack = vec![*root];
        while let Some(c) = stack.pop() {
            if !seen.insert(c) {
                continue;
            }
            if c == chain {
                out.insert(*root);
                break;
            }
            if let Some(next) = edges.get(c) {
                stack.extend(next.iter().copied());
            }
        }
    }
    if out.is_empty() && is_builtin(table, chain) {
        // `chain` is built-in but `table` lists it (always true): kept for clarity.
        out.insert(chain);
    }
    out
}

/// A chain that can jump back to itself, if any (as `a → b → a`).
pub fn find_loop(rules: &[FirewallRule]) -> Option<Vec<String>> {
    let edges = edges(rules);
    let next = |c: &str| -> Vec<&str> {
        edges
            .get(c)
            .map(|n| n.iter().copied().collect())
            .unwrap_or_default()
    };
    // Iterative depth-first search: no recursion depth to blow up.
    let mut done: BTreeSet<&str> = BTreeSet::new();
    for start in edges.keys().copied() {
        if done.contains(start) {
            continue;
        }
        let mut path: Vec<&str> = vec![start];
        let mut todo: Vec<Vec<&str>> = vec![next(start)];
        while let Some(top) = todo.last_mut() {
            match top.pop() {
                Some(n) => {
                    if let Some(pos) = path.iter().position(|p| *p == n) {
                        let mut cycle: Vec<String> =
                            path.iter().skip(pos).map(|s| (*s).to_owned()).collect();
                        cycle.push(n.to_owned());
                        return Some(cycle);
                    }
                    if !done.contains(n) {
                        path.push(n);
                        todo.push(next(n));
                    }
                }
                None => {
                    todo.pop();
                    if let Some(c) = path.pop() {
                        done.insert(c);
                    }
                }
            }
        }
    }
    None
}

/// Custom chains of a table: named by a rule or a jump.
pub fn custom_chains(table: Table, rules: &[FirewallRule]) -> BTreeSet<&Name> {
    let mut out = BTreeSet::new();
    for r in rules.iter().filter(|r| !r.section) {
        if !is_builtin(table, r.chain.as_str()) {
            out.insert(&r.chain);
        }
        if let Action::Jump { jump_target } = &r.action
            && !is_builtin(table, jump_target.as_str())
        {
            out.insert(jump_target);
        }
    }
    out
}
