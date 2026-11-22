//! The policy run on routes (G3.2b): what the preview and the commit
//! impact show, with the semantics FRR runs for the render of [`super::frr`]
//! (a property test holds the two together).
//!
//! The rules are compiled once into a [`Policy`]: names resolved to
//! indices, prefix lists into hash sets by length (a route checks at most
//! 33 or 129 lengths, whatever the size of the list), regexes compiled.
//! A route is copied only when an action changes it. Evaluating a full
//! table is split over threads by ranges of routes ([`preview`]): each
//! route is independent, the policy is shared read-only, nothing is locked.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use corerouter_model::routing_filter::{PrefixEntry, RoutingFilter};
use ipnet::IpNet;
use regex::Regex;

use super::parse::{
    self, Atom, CommArg, CommHow, CommOp, Expr, ExtArg, ExtHow, ExtOp, Family, SetOp, Stmt,
};
use super::{CommunityValue, Ext, ExtKind, Large, Protocol, Route};

/// Deepest chain of jumps followed at run time (loops are refused by
/// [`Policy::build`]; this is the guard behind it).
pub const MAX_JUMP_DEPTH: usize = 16;
/// Largest compiled regex (bytes of the automaton): a hostile pattern
/// cannot take the memory.
pub const REGEX_SIZE_LIMIT: usize = 1 << 20;

/// FRR's `_`: a separator between AS numbers, or either end of the path
/// (bgpd `bgp_regcomp`).
pub(crate) const UNDERSCORE: &str = "(^|[,{}() ]|$)";

/// Compile an AS-path expression as FRR does (`_` expanded).
pub fn compile_regex(re: &str) -> Result<Regex, String> {
    let expanded = re.replace('_', UNDERSCORE);
    regex::RegexBuilder::new(&expanded)
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_SIZE_LIMIT)
        .unicode(false)
        .build()
        .map_err(|e| {
            format!(
                "not a regular expression: {}",
                parse::cut(&e.to_string().replace('\n', " "))
            )
        })
}

/// Compile `sources` (expression, chain), in order: on threads when there
/// are many. With [`parse_all`], 10 000 rules (2 500 distinct expressions)
/// build in 30 ms on 8 threads instead of 90 ms on one (**medido**,
/// `benches/filter.rs`, 2026-10-27).
fn compile_all(sources: &[(String, String)]) -> Vec<Result<Regex, String>> {
    let threads = if sources.len() < 64 {
        1
    } else {
        threads_for(usize::MAX)
    };
    if threads <= 1 {
        return sources.iter().map(|(re, _)| compile_regex(re)).collect();
    }
    #[cfg(target_arch = "wasm32")]
    {
        sources.iter().map(|(re, _)| compile_regex(re)).collect()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let size = sources.len().div_ceil(threads);
        std::thread::scope(|scope| {
            let handles: Vec<_> = sources
                .chunks(size)
                .map(|chunk| {
                    std::thread::Builder::new()
                        .name("filter-regex".into())
                        .spawn_scoped(scope, move || {
                            chunk
                                .iter()
                                .map(|(re, _)| compile_regex(re))
                                .collect::<Vec<_>>()
                        })
                })
                .collect();
            handles
                .into_iter()
                .zip(sources.chunks(size))
                .flat_map(|(h, chunk)| match h.map(|h| h.join()) {
                    Ok(Ok(v)) => v,
                    // A thread that could not start or died: compile here.
                    _ => chunk.iter().map(|(re, _)| compile_regex(re)).collect(),
                })
                .collect()
        })
    }
}

/// A prefix list ready for lookups.
#[derive(Debug, Default, Clone)]
pub struct PrefixSet {
    v4: HashMap<(u32, u8), Vec<(u8, u8)>>,
    v6: HashMap<(u128, u8), Vec<(u8, u8)>>,
    /// The prefix lengths present, ascending.
    lens4: Vec<u8>,
    lens6: Vec<u8>,
}

fn mask4(a: u32, l: u8) -> u32 {
    if l == 0 {
        0
    } else {
        a & (u32::MAX << (32 - u32::from(l.min(32))))
    }
}

fn mask6(a: u128, l: u8) -> u128 {
    if l == 0 {
        0
    } else {
        a & (u128::MAX << (128 - u32::from(l.min(128))))
    }
}

impl PrefixSet {
    pub fn new(entries: &[PrefixEntry]) -> Self {
        let mut s = PrefixSet::default();
        for e in entries {
            let range = e.lengths();
            match e.prefix {
                IpNet::V4(n) => {
                    let l = n.prefix_len();
                    s.v4.entry((u32::from(n.network()), l))
                        .or_default()
                        .push(range);
                    s.lens4.push(l);
                }
                IpNet::V6(n) => {
                    let l = n.prefix_len();
                    s.v6.entry((u128::from(n.network()), l))
                        .or_default()
                        .push(range);
                    s.lens6.push(l);
                }
            }
        }
        s.lens4.sort_unstable();
        s.lens4.dedup();
        s.lens6.sort_unstable();
        s.lens6.dedup();
        s
    }

    pub fn contains(&self, net: &IpNet) -> bool {
        let len = net.prefix_len();
        let fits = |ranges: Option<&Vec<(u8, u8)>>| {
            ranges.is_some_and(|r| r.iter().any(|(lo, hi)| len >= *lo && len <= *hi))
        };
        match net {
            IpNet::V4(n) => {
                let a = u32::from(n.network());
                self.lens4
                    .iter()
                    .take_while(|l| **l <= len)
                    .any(|l| fits(self.v4.get(&(mask4(a, *l), *l))))
            }
            IpNet::V6(n) => {
                let a = u128::from(n.network());
                self.lens6
                    .iter()
                    .take_while(|l| **l <= len)
                    .any(|l| fits(self.v6.get(&(mask6(a, *l), *l))))
            }
        }
    }
}

#[derive(Debug, Clone)]
enum Test {
    DstIn(IpNet),
    DstEq(IpNet),
    DstSet(usize),
    DstLen(u8, u8),
    V6(bool),
    Proto(Protocol),
    AsPath(usize),
    Comm(CommOp, Vec<u32>),
    Large(CommOp, Vec<Large>),
    Ext(ExtOp, Vec<Ext>),
}

#[derive(Debug, Clone)]
enum Cond {
    T(Test),
    Not(Box<Cond>),
    And(Box<Cond>, Box<Cond>),
    Or(Box<Cond>, Box<Cond>),
}

#[derive(Debug, Clone)]
enum SetC {
    LocalPref(u32),
    Med(u32),
    Prepend(u8),
    Gw(std::net::IpAddr),
    Comm(CommHow, Vec<u32>),
    Large(CommHow, Vec<Large>),
    Ext(ExtHow, ExtSel),
}

/// What an extended-community action works on (G3.9fc).
#[derive(Debug, Clone)]
enum ExtSel {
    Values(Vec<Ext>),
    Kind(ExtKind),
}

#[derive(Debug, Clone)]
enum Op {
    If(Cond, Vec<Op>, Vec<Op>),
    Accept,
    Reject,
    Return,
    Jump(usize),
    Set(SetC),
}

/// A problem of one rule (or list), for validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// The rule id (`*1`), or the list name.
    pub item: String,
    pub message: String,
}

/// The compiled `/routing filter`.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    names: HashMap<String, usize>,
    chains: Vec<(String, Vec<Op>)>,
    sets: Vec<PrefixSet>,
    regexes: Vec<Option<Regex>>,
}

/// The parsed enabled rules of each chain, in order, and the problems.
pub fn parsed_chains(filter: &RoutingFilter) -> (Vec<(String, Vec<Stmt>)>, Vec<Problem>) {
    let mut chains: Vec<(String, Vec<Stmt>)> = Vec::new();
    let mut index: HashMap<&str, usize> = HashMap::new();
    let mut problems = Vec::new();
    let parsed = parse_all(&filter.rules);
    for (r, result) in filter.rules.iter().zip(parsed) {
        let i = *index.entry(r.chain.as_str()).or_insert_with(|| {
            chains.push((r.chain.clone(), Vec::new()));
            chains.len() - 1
        });
        let Some(result) = result else { continue };
        match result {
            Ok(stmts) => {
                if let Some((_, body)) = chains.get_mut(i) {
                    body.extend(stmts);
                }
            }
            Err(e) => problems.push(Problem {
                item: r.id.to_string(),
                message: e.to_string(),
            }),
        }
    }
    (chains, problems)
}

/// Every enabled rule parsed (`None`: disabled), in order; on threads when
/// there are many (each rule is independent).
fn parse_all(
    rules: &[corerouter_model::routing_filter::FilterRule],
) -> Vec<Option<Result<Vec<Stmt>, parse::ParseError>>> {
    let one = |r: &corerouter_model::routing_filter::FilterRule| {
        (!r.disabled).then(|| parse::parse(&r.rule))
    };
    let threads = if rules.len() < 1_000 {
        1
    } else {
        threads_for(usize::MAX)
    };
    if threads <= 1 {
        return rules.iter().map(one).collect();
    }
    #[cfg(target_arch = "wasm32")]
    {
        rules.iter().map(one).collect()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let size = rules.len().div_ceil(threads);
        std::thread::scope(|scope| {
            let handles: Vec<_> = rules
                .chunks(size)
                .map(|c| {
                    std::thread::Builder::new()
                        .name("filter-parse".into())
                        .spawn_scoped(scope, move || c.iter().map(one).collect::<Vec<_>>())
                })
                .collect();
            handles
                .into_iter()
                .zip(rules.chunks(size))
                .flat_map(|(h, c)| match h.map(|h| h.join()) {
                    Ok(Ok(v)) => v,
                    _ => c.iter().map(one).collect(),
                })
                .collect()
        })
    }
}

/// The chains every chain jumps to (directly).
pub fn jumps(body: &[Stmt], out: &mut Vec<String>) {
    for s in body {
        match s {
            Stmt::Jump(c) => out.push(c.clone()),
            Stmt::If { then, els, .. } => {
                jumps(then, out);
                jumps(els, out);
            }
            _ => {}
        }
    }
}

/// The next hops `set gw` writes in chain `chain` or a chain it jumps
/// to (G3.9fh), in rule order.
pub fn chain_gws(filter: &RoutingFilter, chain: &str) -> Vec<std::net::IpAddr> {
    fn walk(body: &[Stmt], out: &mut Vec<std::net::IpAddr>, next: &mut Vec<String>) {
        for s in body {
            match s {
                Stmt::Set(super::parse::SetOp::Gw(a)) => out.push(*a),
                Stmt::Jump(c) => next.push(c.clone()),
                Stmt::If { then, els, .. } => {
                    walk(then, out, next);
                    walk(els, out, next);
                }
                _ => {}
            }
        }
    }
    let (parsed, _) = parsed_chains(filter);
    let mut out = Vec::new();
    let mut seen = vec![chain.to_owned()];
    let mut i = 0;
    while let Some(name) = seen.get(i).cloned() {
        i += 1;
        let mut next = Vec::new();
        if let Some((_, b)) = parsed.iter().find(|(n, _)| *n == name) {
            walk(b, &mut out, &mut next);
        }
        for n in next {
            if !seen.contains(&n) {
                seen.push(n);
            }
        }
    }
    out
}

/// The chains in a jump loop (each reported once), as "a → b → a".
pub fn loops(chains: &[(String, Vec<Stmt>)]) -> Vec<String> {
    let index: HashMap<&str, usize> = chains
        .iter()
        .enumerate()
        .map(|(i, (n, _))| (n.as_str(), i))
        .collect();
    let edges: Vec<Vec<usize>> = chains
        .iter()
        .map(|(_, b)| {
            let mut j = Vec::new();
            jumps(b, &mut j);
            j.iter()
                .filter_map(|c| index.get(c.as_str()).copied())
                .collect()
        })
        .collect();
    // Iterative DFS with colors: 0 new, 1 on the stack, 2 done.
    let mut color = vec![0u8; chains.len()];
    let mut out = Vec::new();
    for start in 0..chains.len() {
        if color.get(start) != Some(&0) {
            continue;
        }
        let mut stack: Vec<(usize, usize)> = vec![(start, 0)];
        if let Some(c) = color.get_mut(start) {
            *c = 1;
        }
        while let Some(&mut (node, ref mut next)) = stack.last_mut() {
            let succ = edges.get(node).and_then(|e| e.get(*next)).copied();
            *next += 1;
            match succ {
                Some(s) => match color.get(s) {
                    Some(0) => {
                        if let Some(c) = color.get_mut(s) {
                            *c = 1;
                        }
                        stack.push((s, 0));
                    }
                    Some(1) => {
                        let names: Vec<&str> = stack
                            .iter()
                            .map(|(n, _)| *n)
                            .skip_while(|n| *n != s)
                            .chain(std::iter::once(s))
                            .filter_map(|n| chains.get(n).map(|(name, _)| name.as_str()))
                            .collect();
                        out.push(names.join(" → "));
                    }
                    _ => {}
                },
                None => {
                    if let Some(c) = color.get_mut(node) {
                        *c = 2;
                    }
                    stack.pop();
                }
            }
        }
    }
    out
}

struct Builder<'a> {
    filter: &'a RoutingFilter,
    names: &'a HashMap<String, usize>,
    sets: Vec<PrefixSet>,
    set_index: HashMap<String, usize>,
    /// The distinct expressions and the chain that first used each;
    /// compiled after the walk, on several threads when there are many.
    regexes: Vec<(String, String)>,
    regex_index: HashMap<String, usize>,
    problems: Vec<Problem>,
    chain: String,
}

impl Builder<'_> {
    fn problem(&mut self, message: String) {
        let p = Problem {
            item: format!("chain {}", self.chain),
            message,
        };
        if !self.problems.contains(&p) {
            self.problems.push(p);
        }
    }

    /// The values `arg` names; a list without any of the kind `wanted`
    /// (`normal`, `large`, `extended`) is a problem.
    fn values(&mut self, arg: &CommArg, wanted: &str) -> Vec<CommunityValue> {
        let kind = |v: &CommunityValue| match v {
            CommunityValue::Normal(_) => "normal",
            CommunityValue::Large(_) => "large",
            CommunityValue::Ext(_) => "extended",
        };
        match arg {
            CommArg::Values(v) => v.clone(),
            CommArg::List(name) => match self.filter.community_lists.get(name) {
                Some(l) => {
                    let vals: Vec<CommunityValue> = l
                        .communities
                        .iter()
                        .filter_map(|c| super::parse_community(c).ok())
                        .collect();
                    if !vals.iter().any(|v| kind(v) == wanted) {
                        self.problem(format!(
                            "community list {name:?} has no {wanted} communities"
                        ));
                    }
                    vals
                }
                None => {
                    let known: Vec<&str> = self
                        .filter
                        .community_lists
                        .keys()
                        .map(String::as_str)
                        .collect();
                    let hint = parse::did_you_mean(name, &known);
                    self.problem(format!("community list {name:?} does not exist{hint}"));
                    Vec::new()
                }
            },
        }
    }

    /// The extended communities `arg` names, sorted (G3.9fc).
    fn ext_values(&mut self, arg: &CommArg) -> Vec<Ext> {
        let mut v: Vec<Ext> = self
            .values(arg, "extended")
            .into_iter()
            .filter_map(|c| match c {
                CommunityValue::Ext(e) => Some(e),
                _ => None,
            })
            .collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    fn comm_values(&mut self, arg: &CommArg, large: bool) -> (Vec<u32>, Vec<Large>) {
        let values = self.values(arg, if large { "large" } else { "normal" });
        let mut n: Vec<u32> = values
            .iter()
            .filter_map(|v| {
                if let CommunityValue::Normal(c) = v {
                    Some(*c)
                } else {
                    None
                }
            })
            .collect();
        let mut l: Vec<Large> = values
            .iter()
            .filter_map(|v| {
                if let CommunityValue::Large(c) = v {
                    Some(*c)
                } else {
                    None
                }
            })
            .collect();
        n.sort_unstable();
        n.dedup();
        l.sort_unstable();
        l.dedup();
        (n, l)
    }

    fn cond(&mut self, e: &Expr) -> Cond {
        match e {
            Expr::Not(x) => Cond::Not(Box::new(self.cond(x))),
            Expr::And(a, b) => Cond::And(Box::new(self.cond(a)), Box::new(self.cond(b))),
            Expr::Or(a, b) => Cond::Or(Box::new(self.cond(a)), Box::new(self.cond(b))),
            Expr::Atom(a) => Cond::T(match a {
                Atom::DstIn(n) => Test::DstIn(*n),
                Atom::DstEq(n) => Test::DstEq(*n),
                Atom::DstLen(lo, hi) => Test::DstLen(*lo, *hi),
                Atom::Afi(f) => Test::V6(*f == Family::V6),
                Atom::Protocol(p) => Test::Proto(*p),
                Atom::DstList(name) => {
                    if let Some(i) = self.set_index.get(name) {
                        Test::DstSet(*i)
                    } else if let Some(l) = self.filter.prefix_lists.get(name) {
                        self.sets.push(PrefixSet::new(&l.entries));
                        let i = self.sets.len() - 1;
                        self.set_index.insert(name.clone(), i);
                        Test::DstSet(i)
                    } else {
                        let known: Vec<&str> = self
                            .filter
                            .prefix_lists
                            .keys()
                            .map(String::as_str)
                            .collect();
                        let hint = parse::did_you_mean(name, &known);
                        self.problem(format!("prefix list {name:?} does not exist{hint}"));
                        self.sets.push(PrefixSet::default());
                        Test::DstSet(self.sets.len() - 1)
                    }
                }
                Atom::AsPath(re) => {
                    if let Some(i) = self.regex_index.get(re) {
                        Test::AsPath(*i)
                    } else {
                        self.regexes.push((re.clone(), self.chain.clone()));
                        let i = self.regexes.len() - 1;
                        self.regex_index.insert(re.clone(), i);
                        Test::AsPath(i)
                    }
                }
                Atom::Comm { large, op, arg } => {
                    let (n, l) = self.comm_values(arg, *large);
                    if *large {
                        Test::Large(*op, l)
                    } else {
                        Test::Comm(*op, n)
                    }
                }
                Atom::Ext { op, arg } => {
                    let v = self.ext_values(arg);
                    Test::Ext(*op, v)
                }
            }),
        }
    }

    fn ops(&mut self, body: &[Stmt]) -> Vec<Op> {
        body.iter()
            .map(|s| match s {
                Stmt::If { cond, then, els } => {
                    let c = self.cond(cond);
                    Op::If(c, self.ops(then), self.ops(els))
                }
                Stmt::Accept => Op::Accept,
                Stmt::Reject => Op::Reject,
                Stmt::Return => Op::Return,
                Stmt::Jump(c) => match self.names.get(c) {
                    Some(i) => Op::Jump(*i),
                    None => {
                        let known: Vec<&str> = self.names.keys().map(String::as_str).collect();
                        let hint = parse::did_you_mean(c, &known);
                        self.problem(format!("jump to chain {c:?}, which has no rules{hint}"));
                        Op::Reject
                    }
                },
                Stmt::Set(op) => Op::Set(match op {
                    SetOp::LocalPref(v) => SetC::LocalPref(*v),
                    SetOp::Med(v) => SetC::Med(*v),
                    SetOp::Prepend(n) => SetC::Prepend(*n),
                    SetOp::Gw(a) => SetC::Gw(*a),
                    SetOp::Comm { large, how, arg } => {
                        let (n, l) = self.comm_values(arg, *large);
                        if *large {
                            SetC::Large(*how, l)
                        } else {
                            SetC::Comm(*how, n)
                        }
                    }
                    SetOp::Ext { how, arg } => SetC::Ext(
                        *how,
                        match arg {
                            ExtArg::Kind(k) => ExtSel::Kind(*k),
                            ExtArg::Values(v) => {
                                let mut v = v.clone();
                                v.sort_unstable();
                                v.dedup();
                                ExtSel::Values(v)
                            }
                            ExtArg::List(n) => {
                                ExtSel::Values(self.ext_values(&CommArg::List(n.clone())))
                            }
                        },
                    ),
                }),
            })
            .collect()
    }
}

impl Policy {
    /// Compile the filter; the problems found (bad rules, unknown chains
    /// and lists, loops). A problem never makes the policy accept more:
    /// a broken rule is left out, a jump nowhere rejects.
    pub fn build(filter: &RoutingFilter) -> (Policy, Vec<Problem>) {
        let (parsed, mut problems) = parsed_chains(filter);
        let names: HashMap<String, usize> = parsed
            .iter()
            .enumerate()
            .map(|(i, (n, _))| (n.clone(), i))
            .collect();
        for l in loops(&parsed) {
            problems.push(Problem {
                item: "jump".into(),
                message: format!("chains jump in a loop: {l}"),
            });
        }
        let mut b = Builder {
            filter,
            names: &names,
            sets: Vec::new(),
            set_index: HashMap::new(),
            regexes: Vec::new(),
            regex_index: HashMap::new(),
            problems: Vec::new(),
            chain: String::new(),
        };
        let mut chains = Vec::with_capacity(parsed.len());
        for (name, body) in &parsed {
            b.chain.clone_from(name);
            chains.push((name.clone(), b.ops(body)));
        }
        problems.extend(b.problems);
        let (sets, sources) = (b.sets, b.regexes);
        let compiled = compile_all(&sources);
        let mut regexes = Vec::with_capacity(compiled.len());
        for ((_, chain), r) in sources.iter().zip(compiled) {
            // A broken regex never matches (fail closed).
            match r {
                Ok(r) => regexes.push(Some(r)),
                Err(message) => {
                    problems.push(Problem {
                        item: format!("chain {chain}"),
                        message,
                    });
                    regexes.push(None);
                }
            }
        }
        let policy = Policy {
            names,
            chains,
            sets,
            regexes,
        };
        (policy, problems)
    }

    pub fn chain(&self, name: &str) -> Option<usize> {
        self.names.get(name).copied()
    }

    pub fn chain_names(&self) -> impl Iterator<Item = &str> {
        self.chains.iter().map(|(n, _)| n.as_str())
    }

    /// Run chain `chain` on `route`; `asn` is ours (`bgp-path-prepend`).
    pub fn eval<'r>(&self, chain: usize, route: &'r Route, asn: u32) -> Outcome<'r> {
        self.eval_counted(chain, route, asn, 0)
    }

    /// [`Policy::eval`] where the session adds `counted` copies of our AS
    /// that `set bgp-path-prepend N` counts (G3.9fg: 1 on the output of
    /// an eBGP connection, RouterOS's count): the chain prepends N −
    /// `counted`. The route is the one the chain hands on, before the
    /// session's own copy.
    pub fn eval_counted<'r>(
        &self,
        chain: usize,
        route: &'r Route,
        asn: u32,
        counted: u8,
    ) -> Outcome<'r> {
        let mut ctx = Ctx {
            route: Cow::Borrowed(route),
            path: None,
            counted,
        };
        let accepted = match self.run(chain, &mut ctx, asn, 0) {
            Flow::Accept => true,
            Flow::Reject | Flow::Next | Flow::Return => false,
        };
        Outcome {
            accepted,
            route: ctx.route,
        }
    }

    fn run(&self, chain: usize, ctx: &mut Ctx<'_>, asn: u32, depth: usize) -> Flow {
        if depth > MAX_JUMP_DEPTH {
            return Flow::Reject;
        }
        let Some((_, body)) = self.chains.get(chain) else {
            return Flow::Reject;
        };
        match self.block(body, ctx, asn, depth) {
            Flow::Return => Flow::Next,
            f => f,
        }
    }

    fn block(&self, ops: &[Op], ctx: &mut Ctx<'_>, asn: u32, depth: usize) -> Flow {
        for op in ops {
            let f = match op {
                Op::If(c, t, e) => {
                    if self.test(c, ctx) {
                        self.block(t, ctx, asn, depth)
                    } else {
                        self.block(e, ctx, asn, depth)
                    }
                }
                Op::Accept => Flow::Accept,
                Op::Reject => Flow::Reject,
                Op::Return => Flow::Return,
                Op::Jump(c) => self.run(*c, ctx, asn, depth + 1),
                Op::Set(s) => {
                    apply(s, ctx, asn);
                    Flow::Next
                }
            };
            if !matches!(f, Flow::Next) {
                return f;
            }
        }
        Flow::Next
    }

    fn test(&self, c: &Cond, ctx: &mut Ctx<'_>) -> bool {
        match c {
            Cond::Not(x) => !self.test(x, ctx),
            Cond::And(a, b) => self.test(a, ctx) && self.test(b, ctx),
            Cond::Or(a, b) => self.test(a, ctx) || self.test(b, ctx),
            Cond::T(t) => {
                let r = &*ctx.route;
                match t {
                    Test::DstIn(n) => n.contains(&r.prefix) && same_family(n, &r.prefix),
                    Test::DstEq(n) => *n == r.prefix,
                    Test::DstSet(i) => self.sets.get(*i).is_some_and(|s| s.contains(&r.prefix)),
                    Test::DstLen(lo, hi) => {
                        let l = r.prefix.prefix_len();
                        l >= *lo && l <= *hi
                    }
                    Test::V6(v6) => matches!(r.prefix, IpNet::V6(_)) == *v6,
                    Test::Proto(p) => r.protocol == *p,
                    Test::Comm(op, want) => comm_match(*op, want, &r.communities),
                    Test::Large(op, want) => comm_match(*op, want, &r.large),
                    Test::Ext(op, want) => ext_match(*op, want, &r.ext),
                    Test::AsPath(i) => {
                        if ctx.path.is_none() {
                            ctx.path = Some(r.path_text());
                        }
                        let path = ctx.path.as_deref().unwrap_or("");
                        self.regexes
                            .get(*i)
                            .and_then(Option::as_ref)
                            .is_some_and(|re| re.is_match(path))
                    }
                }
            }
        }
    }
}

fn same_family(a: &IpNet, b: &IpNet) -> bool {
    matches!(
        (a, b),
        (IpNet::V4(_), IpNet::V4(_)) | (IpNet::V6(_), IpNet::V6(_))
    )
}

/// `have` is sorted without repeats, as `want`.
fn comm_match<T: Ord>(op: CommOp, want: &[T], have: &[T]) -> bool {
    match op {
        CommOp::Includes => want.iter().all(|w| have.binary_search(w).is_ok()),
        CommOp::Any => want.iter().any(|w| have.binary_search(w).is_ok()),
        CommOp::Equal => want == have,
    }
}

/// G3.9fc: RouterOS's extended-community matchers.
fn ext_match(op: ExtOp, want: &[Ext], have: &[Ext]) -> bool {
    match op {
        ExtOp::Includes => comm_match(CommOp::Includes, want, have),
        ExtOp::Any => comm_match(CommOp::Any, want, have),
        ExtOp::Equal => comm_match(CommOp::Equal, want, have),
        ExtOp::Subset => have.iter().all(|h| want.binary_search(h).is_ok()),
    }
}

/// G3.9fc: `set` replaces, `append` adds, `delete` removes the values or
/// a kind, `filter` keeps only the values.
fn change_ext(how: ExtHow, sel: &ExtSel, have: &mut Vec<Ext>) {
    match (how, sel) {
        (ExtHow::Set, ExtSel::Values(v)) => *have = v.clone(),
        (ExtHow::Append, ExtSel::Values(v)) => {
            have.extend_from_slice(v);
            have.sort_unstable();
            have.dedup();
        }
        (ExtHow::Delete, ExtSel::Values(v)) => have.retain(|e| v.binary_search(e).is_err()),
        (ExtHow::Delete, ExtSel::Kind(k)) => have.retain(|e| e.kind() != *k),
        (ExtHow::Filter, ExtSel::Values(v)) => have.retain(|e| v.binary_search(e).is_ok()),
        // The parser gives a kind to delete only.
        (_, ExtSel::Kind(_)) => {}
    }
}

fn change<T: Ord + Copy>(how: CommHow, vals: &[T], have: &mut Vec<T>) {
    match how {
        CommHow::Set => {
            have.clear();
            have.extend_from_slice(vals);
        }
        CommHow::Append => {
            have.extend_from_slice(vals);
            have.sort_unstable();
            have.dedup();
        }
        CommHow::Delete => have.retain(|c| vals.binary_search(c).is_err()),
    }
}

fn apply(s: &SetC, ctx: &mut Ctx<'_>, asn: u32) {
    // G3.9fg: N copies in all, the session's own included; none left (N =
    // 1 on eBGP) leaves the route as it is.
    if let SetC::Prepend(n) = s
        && *n <= ctx.counted
    {
        return;
    }
    // G3.9fh: a next hop of the other family leaves the route alone.
    if let SetC::Gw(a) = s
        && a.is_ipv4() != matches!(ctx.route.prefix, ipnet::IpNet::V4(_))
    {
        return;
    }
    let counted = ctx.counted;
    let r = ctx.route.to_mut();
    match s {
        SetC::LocalPref(v) => r.local_pref = Some(*v),
        SetC::Med(v) => r.med = Some(*v),
        SetC::Prepend(n) => {
            let mut path = vec![asn; usize::from(*n - counted)];
            path.extend_from_slice(&r.as_path);
            r.as_path = path;
            ctx.path = None;
        }
        SetC::Gw(a) => r.next_hop = Some(*a),
        SetC::Comm(how, vals) => change(*how, vals, &mut r.communities),
        SetC::Large(how, vals) => change(*how, vals, &mut r.large),
        SetC::Ext(how, sel) => change_ext(*how, sel, &mut r.ext),
    }
}

struct Ctx<'r> {
    route: Cow<'r, Route>,
    /// The AS path as text, built on the first regex test.
    path: Option<String>,
    /// Copies of our AS a prepend counts ([`Policy::eval_counted`]).
    counted: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Flow {
    Next,
    Accept,
    Reject,
    Return,
}

/// What a chain did to one route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome<'r> {
    pub accepted: bool,
    /// The route after the actions (borrowed when none changed it).
    pub route: Cow<'r, Route>,
}

impl Outcome<'_> {
    pub fn modified(&self) -> bool {
        matches!(self.route, Cow::Owned(_))
    }
}

/// One side of a preview: a policy and the chain a connection uses.
#[derive(Clone, Copy)]
pub struct Side<'a> {
    pub policy: &'a Policy,
    /// `None`: the connection has no chain in this direction.
    pub chain: Option<usize>,
    /// What happens without a chain: iBGP accepts, eBGP rejects (RFC 8212).
    pub accept_without: bool,
    pub asn: u32,
    /// Copies of our AS the session adds that a prepend counts (G3.9fg).
    pub counted: u8,
}

impl Side<'_> {
    pub fn run<'r>(&self, r: &'r Route) -> Outcome<'r> {
        match self.chain {
            Some(c) => self.policy.eval_counted(c, r, self.asn, self.counted),
            None => Outcome {
                accepted: self.accept_without,
                route: Cow::Borrowed(r),
            },
        }
    }
}

/// One route of a preview.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub route: Route,
    pub accepted: bool,
    /// The route after the actions, when they changed it.
    pub changed: Option<Route>,
    /// What the policy in force did (`None`: no comparison).
    pub before: Option<bool>,
    /// The policy in force changed it differently.
    pub before_changed: Option<Route>,
}

/// What a chain does to a set of routes, and how that differs from the
/// policy in force.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Preview {
    pub total: usize,
    pub accepted: usize,
    pub rejected: usize,
    /// Accepted with an attribute changed.
    pub modified: usize,
    /// Accepted before, rejected now.
    pub newly_rejected: usize,
    /// Rejected before, accepted now.
    pub newly_accepted: usize,
    /// Accepted by both, changed differently.
    pub attrs_changed: usize,
    /// Routes to show: those whose fate changes first, then rejected and
    /// accepted ones, at most `limit` of each.
    pub changes: Vec<Row>,
    pub rejected_rows: Vec<Row>,
    pub accepted_rows: Vec<Row>,
}

impl Preview {
    fn merge(&mut self, o: Preview, limit: usize) {
        self.total += o.total;
        self.accepted += o.accepted;
        self.rejected += o.rejected;
        self.modified += o.modified;
        self.newly_rejected += o.newly_rejected;
        self.newly_accepted += o.newly_accepted;
        self.attrs_changed += o.attrs_changed;
        for (mine, theirs) in [
            (&mut self.changes, o.changes),
            (&mut self.rejected_rows, o.rejected_rows),
            (&mut self.accepted_rows, o.accepted_rows),
        ] {
            let room = limit.saturating_sub(mine.len());
            mine.extend(theirs.into_iter().take(room));
        }
    }
}

fn preview_chunk(
    new: &Side<'_>,
    old: Option<&Side<'_>>,
    routes: &[Route],
    limit: usize,
) -> Preview {
    let mut p = Preview {
        total: routes.len(),
        ..Preview::default()
    };
    for r in routes {
        let now = new.run(r);
        let then = old.map(|o| o.run(r));
        if now.accepted {
            p.accepted += 1;
            if now.modified() {
                p.modified += 1;
            }
        } else {
            p.rejected += 1;
        }
        let differs = match &then {
            Some(t) if t.accepted && !now.accepted => {
                p.newly_rejected += 1;
                true
            }
            Some(t) if !t.accepted && now.accepted => {
                p.newly_accepted += 1;
                true
            }
            Some(t) if t.accepted && now.accepted && t.route != now.route => {
                p.attrs_changed += 1;
                true
            }
            _ => false,
        };
        let list = if differs {
            &mut p.changes
        } else if now.accepted {
            &mut p.accepted_rows
        } else {
            &mut p.rejected_rows
        };
        if list.len() < limit {
            let changed = now.modified().then(|| now.route.clone().into_owned());
            list.push(Row {
                route: r.clone(),
                accepted: now.accepted,
                changed,
                before: then.as_ref().map(|t| t.accepted),
                before_changed: then
                    .as_ref()
                    .filter(|t| t.modified())
                    .map(|t| t.route.clone().into_owned()),
            });
        }
    }
    p
}

/// Threads worth using for `n` routes: one below ~20 000 (spawning costs
/// more than it saves, **medido** in `benches/filter.rs`), else the cores
/// up to 8. Always one on wasm (no threads there).
pub fn threads_for(n: usize) -> usize {
    #[cfg(target_arch = "wasm32")]
    {
        let _ = n;
        1
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        if n < 20_000 {
            return 1;
        }
        std::thread::available_parallelism().map_or(1, |c| c.get().min(8))
    }
}

/// Run `new` (and `old`, the policy in force) over `routes` on `threads`
/// threads, each a contiguous range; rows keep the order of `routes`.
pub fn preview(
    new: &Side<'_>,
    old: Option<&Side<'_>>,
    routes: &[Route],
    limit: usize,
    threads: usize,
) -> Preview {
    let threads = threads.clamp(1, 64);
    if threads == 1 || routes.len() < threads * 2 {
        return preview_chunk(new, old, routes, limit);
    }
    #[cfg(target_arch = "wasm32")]
    {
        preview_chunk(new, old, routes, limit)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let size = routes.len().div_ceil(threads);
        let parts: Vec<Preview> = std::thread::scope(|scope| {
            let handles: Vec<_> = routes
                .chunks(size)
                .map(|chunk| {
                    std::thread::Builder::new()
                        .name("filter-preview".into())
                        .spawn_scoped(scope, move || preview_chunk(new, old, chunk, limit))
                })
                .collect();
            handles
                .into_iter()
                .zip(routes.chunks(size))
                .map(|(h, chunk)| match h {
                    // A thread that could not start or died: that range here.
                    Ok(h) => h
                        .join()
                        .unwrap_or_else(|_| preview_chunk(new, old, chunk, limit)),
                    Err(_) => preview_chunk(new, old, chunk, limit),
                })
                .collect()
        });
        let mut out = Preview::default();
        for p in parts {
            out.merge(p, limit);
        }
        out
    }
}

/// The names of the chains a set of chains reaches by jumps (itself
/// included).
pub fn reachable(chains: &[(String, Vec<Stmt>)], from: &str) -> HashSet<String> {
    let index: HashMap<&str, &Vec<Stmt>> = chains.iter().map(|(n, b)| (n.as_str(), b)).collect();
    let mut seen = HashSet::new();
    let mut todo = vec![from.to_owned()];
    while let Some(c) = todo.pop() {
        if !seen.insert(c.clone()) {
            continue;
        }
        if let Some(b) = index.get(c.as_str()) {
            let mut j = Vec::new();
            jumps(b, &mut j);
            todo.extend(j);
        }
    }
    seen
}

#[cfg(test)]
mod tests {
    use corerouter_model::routing_filter::{CommunityList, FilterRule, PrefixList};
    use corerouter_model::types::ItemId;

    use super::*;

    pub(crate) fn filter(rules: &[(&str, &str)]) -> RoutingFilter {
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
        f
    }

    fn route(p: &str, path: &[u32], comms: &[u32]) -> Route {
        let mut r = Route::bgp(p.parse().unwrap(), path.to_vec());
        r.communities = comms.to_vec();
        r
    }

    #[test]
    fn runs_rules_in_order_with_jumps_and_default_reject() {
        let mut f = filter(&[
            ("in", "if (dst in bogons) { reject }"),
            ("in", "if (dst-len > 24) { reject }"),
            (
                "in",
                "if (bgp-as-path \"^64500_\") { set bgp-local-pref 200; jump tag }",
            ),
            ("in", "if (afi ipv4) { accept }"),
            (
                "tag",
                "append bgp-communities 65000:1; if (bgp-communities includes 65000:666) { reject } return",
            ),
        ]);
        f.prefix_lists.insert(
            "bogons".into(),
            PrefixList {
                name: "bogons".into(),
                entries: vec![
                    "10.0.0.0/8 le 32".parse().unwrap(),
                    "0.0.0.0/0".parse().unwrap(),
                ],
                comment: String::new(),
            },
        );
        let (p, problems) = Policy::build(&f);
        assert_eq!(problems, []);
        let c = p.chain("in").unwrap();
        let ok = |r: Route| p.eval(c, &r, 65000).accepted;
        assert!(!ok(route("10.1.0.0/16", &[64500], &[])));
        assert!(!ok(route("0.0.0.0/0", &[64500], &[])));
        assert!(!ok(route("192.0.2.0/25", &[64500], &[])));
        let r = route("192.0.2.0/24", &[64500, 1], &[]);
        let o = p.eval(c, &r, 65000);
        assert!(o.accepted);
        assert_eq!(o.route.local_pref, Some(200));
        assert_eq!(o.route.communities, [65000 << 16 | 1]);
        assert!(!ok(route("192.0.2.0/24", &[64500], &[65000 << 16 | 666])));
        let r = route("198.51.100.0/24", &[64501], &[]);
        let o = p.eval(c, &r, 65000);
        assert!(o.accepted && !o.modified());
        // IPv6 falls off the end: reject.
        assert!(!ok(route("2001:db8::/32", &[64501], &[])));
    }

    #[test]
    fn prepend_and_regex_see_the_changed_path() {
        let f = filter(&[(
            "out",
            "set bgp-path-prepend 2; if (bgp-as-path \"^65000_65000_\") { accept }",
        )]);
        let (p, _) = Policy::build(&f);
        let r = route("192.0.2.0/24", &[64500], &[]);
        let o = p.eval(0, &r, 65000);
        assert!(o.accepted);
        assert_eq!(o.route.as_path, [65000, 65000, 64500]);
    }

    #[test]
    fn problems_are_reported_and_fail_closed() {
        let mut f = filter(&[
            ("a", "jump b"),
            ("b", "jump a"),
            ("c", "jump nowhere"),
            ("d", "if (dst in nolist) { accept }"),
            ("e", "acept"),
            ("f", "if (bgp-communities any-list cl) { accept }"),
        ]);
        f.community_lists.insert(
            "cl".into(),
            CommunityList {
                name: "cl".into(),
                communities: vec!["1:2:3".into()],
                comment: String::new(),
            },
        );
        let (p, problems) = Policy::build(&f);
        let text = format!("{problems:?}");
        assert!(text.contains("loop: a → b → a"), "{text}");
        assert!(text.contains("nowhere"));
        assert!(text.contains("nolist"));
        assert!(text.contains("did you mean \\\"accept\\\""));
        assert!(text.contains("no normal communities"));
        let r = route("192.0.2.0/24", &[1], &[]);
        for chain in ["a", "c", "d"] {
            assert!(!p.eval(p.chain(chain).unwrap(), &r, 1).accepted, "{chain}");
        }
        assert_eq!(p.chain("e"), Some(4));
        let _ = ItemId(0);
    }

    #[test]
    fn prefix_sets_match_like_prefix_lists() {
        let entries: Vec<PrefixEntry> = [
            "10.0.0.0/8 le 24",
            "192.0.2.0/24",
            "0.0.0.0/0 ge 25",
            "2001:db8::/32 le 48",
        ]
        .iter()
        .map(|e| e.parse().unwrap())
        .collect();
        let s = PrefixSet::new(&entries);
        for (p, want) in [
            ("10.0.0.0/8", true),
            ("10.9.0.0/24", true),
            ("10.9.0.0/25", true),
            ("192.0.2.0/24", true),
            ("192.0.2.0/23", false),
            ("198.51.100.0/24", false),
            ("2001:db8:1::/48", true),
            ("2001:db8:1::/49", false),
        ] {
            let net: IpNet = p.parse().unwrap();
            assert_eq!(s.contains(&net), want, "{p}");
            assert_eq!(entries.iter().any(|e| e.matches(&net)), want, "{p}");
        }
    }

    #[test]
    fn preview_counts_and_compares_on_many_threads() {
        let (old, _) = Policy::build(&filter(&[("in", "accept")]));
        let (new, _) = Policy::build(&filter(&[(
            "in",
            "if (dst-len > 22) { reject } set bgp-med 5; accept",
        )]));
        let routes = super::super::sample::routes(50_000, 7, 64500);
        let side = |p| Side {
            policy: p,
            chain: Some(0),
            accept_without: false,
            asn: 65000,
            counted: 0,
        };
        let one = preview(&side(&new), Some(&side(&old)), &routes, 10, 1);
        let many = preview(&side(&new), Some(&side(&old)), &routes, 10, 4);
        assert_eq!(one, many);
        assert_eq!(one.total, 50_000);
        assert_eq!(one.accepted + one.rejected, 50_000);
        assert_eq!(one.newly_rejected, one.rejected);
        // A route that already had MED 5 is not changed.
        assert!(one.attrs_changed <= one.accepted && one.attrs_changed > one.accepted * 9 / 10);
        assert_eq!(one.changes.len(), 10);
        // No chain on eBGP: nothing passes (RFC 8212).
        let none = Side {
            policy: &new,
            chain: None,
            accept_without: false,
            asn: 65000,
            counted: 0,
        };
        assert_eq!(preview(&none, None, &routes, 0, 1).accepted, 0);
    }
}
