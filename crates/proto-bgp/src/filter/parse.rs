//! The RouterOS v7 filter language, parsed (G3.2b).
//!
//! ```text
//! rule    := stmt*
//! stmt    := "if" "(" expr ")" block ["else" (block | stmt-if)] | action [";"]
//! block   := "{" stmt* "}"
//! action  := accept | reject | return | jump CHAIN
//!          | set PROP VALUE | append PROP VALUE | delete PROP VALUE
//! expr    := and ("||" and)*        and := unary ("&&" unary)*
//! unary   := ("!" | "not") unary | "(" expr ")" | matcher
//! matcher := dst (in|==|!=) PREFIX|LIST | dst-len OP N|N-M | afi ipv4|ipv6
//!          | protocol NAME[,NAME…] | bgp-as-path REGEX
//!          | bgp-communities|bgp-large-communities CMOP VALUES|LIST
//! ```
//!
//! The text is hostile: it is bounded (length, nesting, tokens), and an
//! error says where (the column) and what was expected, with a "did you
//! mean" for a misspelt word.

use std::fmt;

use ipnet::IpNet;

use super::{CommunityValue, Protocol, parse_community};

/// Deepest nesting of blocks and parentheses.
pub const MAX_DEPTH: usize = 32;
/// Most tokens in one rule.
pub const MAX_TOKENS: usize = 2_048;
/// Longest AS-path regular expression.
pub const MAX_REGEX_LEN: usize = 256;
/// Most values in one community matcher or action.
pub const MAX_VALUES: usize = 64;
/// Most AS numbers one `set bgp-path-prepend` adds (RouterOS: 16).
pub const MAX_PREPEND: u8 = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// Byte offset of the offending token (its column is this + 1).
    pub pos: usize,
    pub msg: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "column {}: {}", self.pos + 1, self.msg)
    }
}

impl std::error::Error for ParseError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    V4,
    V6,
}

/// How a community matcher compares (RouterOS names).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommOp {
    /// All the given communities are on the route.
    Includes,
    /// At least one of them is.
    Any,
    /// The route carries exactly them.
    Equal,
}

/// The communities a matcher or an action names.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum CommArg {
    Values(Vec<CommunityValue>),
    /// A `/routing filter community-list`.
    List(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Atom {
    /// `dst in P`: the route is P or inside it.
    DstIn(IpNet),
    /// `dst == P`.
    DstEq(IpNet),
    /// `dst in LIST`: the route matches an entry of a prefix list.
    DstList(String),
    /// `dst-len`: the prefix length is in `lo..=hi`.
    DstLen(u8, u8),
    Afi(Family),
    Protocol(Protocol),
    /// FRR/Cisco AS-path regular expression (`_` is a separator).
    AsPath(String),
    Comm {
        large: bool,
        op: CommOp,
        arg: CommArg,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Expr {
    Atom(Atom),
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
}

/// How an action changes the communities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CommHow {
    /// Replace them (`set`; no values: remove all, `set bgp-communities none`).
    Set,
    /// Add to them (`append`).
    Append,
    /// Remove these (`delete`).
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SetOp {
    LocalPref(u32),
    Med(u32),
    /// Our AS this many times (RouterOS `bgp-path-prepend`).
    Prepend(u8),
    /// The next hop (RouterOS `set gw`, G3.9fh): a global address of the
    /// family of the routes it changes; routes of the other family pass
    /// unchanged.
    Gw(std::net::IpAddr),
    Comm {
        large: bool,
        how: CommHow,
        arg: CommArg,
    },
}

impl SetOp {
    /// Which attribute it writes (two actions on one attribute cannot share
    /// an FRR route-map entry: the order inside an entry is FRR's own).
    pub fn slot(&self) -> u8 {
        match self {
            SetOp::LocalPref(_) => 0,
            SetOp::Med(_) => 1,
            SetOp::Prepend(_) => 2,
            SetOp::Comm { large: false, .. } => 3,
            SetOp::Comm { large: true, .. } => 4,
            SetOp::Gw(_) => 5,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Stmt {
    If {
        cond: Expr,
        then: Vec<Stmt>,
        els: Vec<Stmt>,
    },
    Accept,
    Reject,
    /// Back to the chain that jumped here (at the top: the end of the chain).
    Return,
    Jump(String),
    Set(SetOp),
}

// ---- lexer ----

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Word(String),
    /// A "quoted" string (an AS-path regex with spaces or brackets).
    Quoted(String),
    LParen,
    RParen,
    LBrace,
    RBrace,
    Semi,
    And,
    Or,
    Not,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

fn describe(t: &Tok) -> String {
    match t {
        Tok::Word(w) => format!("{:?}", cut(w)),
        Tok::Quoted(w) => format!("\"{}\"", cut(w)),
        Tok::LParen => "\"(\"".into(),
        Tok::RParen => "\")\"".into(),
        Tok::LBrace => "\"{\"".into(),
        Tok::RBrace => "\"}\"".into(),
        Tok::Semi => "\";\"".into(),
        Tok::And => "\"&&\"".into(),
        Tok::Or => "\"||\"".into(),
        Tok::Not => "\"!\"".into(),
        Tok::Eq => "\"==\"".into(),
        Tok::Ne => "\"!=\"".into(),
        Tok::Lt => "\"<\"".into(),
        Tok::Le => "\"<=\"".into(),
        Tok::Gt => "\">\"".into(),
        Tok::Ge => "\">=\"".into(),
    }
}

/// At most 32 characters of `s`, for messages.
pub(crate) fn cut(s: &str) -> String {
    let mut out: String = s.chars().take(32).collect();
    if s.chars().nth(32).is_some() {
        out.push('…');
    }
    out
}

fn is_word(c: char) -> bool {
    !c.is_whitespace()
        && !matches!(
            c,
            '(' | ')' | '{' | '}' | ';' | '"' | '&' | '|' | '!' | '<' | '>' | '='
        )
}

fn lex(src: &str) -> Result<Vec<(usize, Tok)>, ParseError> {
    let err = |pos: usize, msg: String| ParseError { pos, msg };
    let mut out = Vec::new();
    let mut it = src.char_indices().peekable();
    while let Some(&(i, c)) = it.peek() {
        if out.len() > MAX_TOKENS {
            return Err(err(i, format!("longer than {MAX_TOKENS} words")));
        }
        if c.is_whitespace() {
            it.next();
            continue;
        }
        if !c.is_ascii() {
            return Err(err(i, format!("{c:?}: only ASCII is allowed")));
        }
        it.next();
        let next = it.peek().map(|&(_, n)| n);
        let two = |it: &mut std::iter::Peekable<std::str::CharIndices<'_>>| {
            it.next();
        };
        let tok = match (c, next) {
            ('(', _) => Tok::LParen,
            (')', _) => Tok::RParen,
            ('{', _) => Tok::LBrace,
            ('}', _) => Tok::RBrace,
            (';', _) => Tok::Semi,
            ('&', Some('&')) => {
                two(&mut it);
                Tok::And
            }
            ('|', Some('|')) => {
                two(&mut it);
                Tok::Or
            }
            ('=', Some('=')) => {
                two(&mut it);
                Tok::Eq
            }
            ('!', Some('=')) => {
                two(&mut it);
                Tok::Ne
            }
            ('<', Some('=')) => {
                two(&mut it);
                Tok::Le
            }
            ('>', Some('=')) => {
                two(&mut it);
                Tok::Ge
            }
            ('!', _) => Tok::Not,
            ('<', _) => Tok::Lt,
            ('>', _) => Tok::Gt,
            ('&', _) => return Err(err(i, "\"&\": did you mean \"&&\"?".into())),
            ('|', _) => return Err(err(i, "\"|\": did you mean \"||\"?".into())),
            ('=', _) => return Err(err(i, "\"=\": did you mean \"==\"?".into())),
            ('"', _) => {
                let mut s = String::new();
                let mut closed = false;
                while let Some((_, ch)) = it.next() {
                    match ch {
                        '"' => {
                            closed = true;
                            break;
                        }
                        '\\' => match it.next() {
                            Some((_, e @ ('"' | '\\'))) => s.push(e),
                            Some((j, _)) => {
                                return Err(err(j, "only \\\" and \\\\ are escapes".into()));
                            }
                            None => break,
                        },
                        ch if ch.is_control() || !ch.is_ascii() => {
                            return Err(err(i, "a quoted text holds printable ASCII only".into()));
                        }
                        ch => s.push(ch),
                    }
                }
                if !closed {
                    return Err(err(i, "the quote is not closed".into()));
                }
                Tok::Quoted(s)
            }
            _ => {
                let mut w = String::from(c);
                while let Some(&(_, n)) = it.peek() {
                    if !is_word(n) {
                        break;
                    }
                    w.push(n);
                    it.next();
                }
                if w.chars().any(|ch| ch.is_control() || !ch.is_ascii()) {
                    return Err(err(i, "only printable ASCII is allowed".into()));
                }
                Tok::Word(w)
            }
        };
        out.push((i, tok));
    }
    Ok(out)
}

// ---- did you mean ----

fn distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut cur = vec![i + 1];
        for (j, cb) in b.iter().enumerate() {
            let sub = prev.get(j).copied().unwrap_or(0) + usize::from(ca != *cb);
            let del = prev.get(j + 1).copied().unwrap_or(0) + 1;
            let ins = cur.get(j).copied().unwrap_or(0) + 1;
            cur.push(sub.min(del).min(ins));
        }
        prev = cur;
    }
    prev.last().copied().unwrap_or(0)
}

/// " (did you mean X?)" for the closest of `known`, if close enough.
pub fn did_you_mean(word: &str, known: &[&str]) -> String {
    if word.len() > 64 {
        return String::new();
    }
    let best = known
        .iter()
        .map(|k| (distance(word, k), *k))
        .min_by_key(|(d, _)| *d);
    match best {
        Some((d, k)) if d <= 2.max(word.len() / 3) => format!(" (did you mean {k:?}?)"),
        _ => String::new(),
    }
}

const MATCHERS: &[&str] = &[
    "dst",
    "dst-len",
    "afi",
    "protocol",
    "bgp-as-path",
    "bgp-communities",
    "bgp-large-communities",
];
const ACTIONS: &[&str] = &[
    "accept", "reject", "return", "jump", "set", "append", "delete", "if",
];
const PROPS: &[&str] = &[
    "bgp-local-pref",
    "bgp-med",
    "bgp-path-prepend",
    "bgp-communities",
    "bgp-large-communities",
    "gw",
];
const COMM_OPS: &[&str] = &[
    "includes",
    "any",
    "equal",
    "includes-list",
    "any-list",
    "equal-list",
];
/// Matchers of RouterOS that FRR cannot express (exactly) yet.
const UNSUPPORTED: &[(&str, &str)] = &[
    (
        "bgp-med",
        "FRR compares the MED only for equality and without a received MED it is 0: mark the routes with a community instead",
    ),
    (
        "bgp-local-pref",
        "the LOCAL_PREF of a received route is not known before the input chain: mark the routes with a community instead",
    ),
    (
        "bgp-path-len",
        "not supported yet: use bgp-as-path with a regular expression",
    ),
    (
        "bgp-ext-communities",
        "extended communities are not supported yet",
    ),
    ("rpki", "RPKI is G3.2c"),
    ("distance", "BGP routes have no distance in FRR's policy"),
];

// ---- parser ----

struct Parser<'a> {
    toks: &'a [(usize, Tok)],
    at: usize,
    end: usize,
    depth: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.at).map(|(_, t)| t)
    }

    fn pos(&self) -> usize {
        self.toks.get(self.at).map_or(self.end, |(p, _)| *p)
    }

    fn err<T>(&self, msg: impl Into<String>) -> Result<T, ParseError> {
        Err(ParseError {
            pos: self.pos(),
            msg: msg.into(),
        })
    }

    fn expect(&mut self, want: &Tok, what: &str) -> Result<(), ParseError> {
        match self.peek() {
            Some(t) if t == want => {
                self.at += 1;
                Ok(())
            }
            Some(t) => {
                let found = describe(t);
                self.err(format!("expected {what}, found {found}"))
            }
            None => self.err(format!("expected {what} at the end")),
        }
    }

    fn word(&mut self, what: &str) -> Result<String, ParseError> {
        match self.peek() {
            Some(Tok::Word(w)) => {
                let w = w.clone();
                self.at += 1;
                Ok(w)
            }
            Some(t) => {
                let found = describe(t);
                self.err(format!("expected {what}, found {found}"))
            }
            None => self.err(format!("expected {what} at the end")),
        }
    }

    /// A word or a quoted text.
    fn value(&mut self, what: &str) -> Result<String, ParseError> {
        match self.peek() {
            Some(Tok::Quoted(w)) => {
                let w = w.clone();
                self.at += 1;
                Ok(w)
            }
            _ => self.word(what),
        }
    }

    fn deeper(&mut self) -> Result<(), ParseError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return self.err(format!("nested deeper than {MAX_DEPTH}"));
        }
        Ok(())
    }

    fn stmts(&mut self, in_block: bool) -> Result<Vec<Stmt>, ParseError> {
        let mut out = Vec::new();
        loop {
            match self.peek() {
                None if in_block => return self.err("expected \"}\" to close the block"),
                None => return Ok(out),
                Some(Tok::RBrace) if in_block => return Ok(out),
                Some(Tok::Semi) => {
                    self.at += 1;
                }
                _ => out.push(self.stmt()?),
            }
        }
    }

    fn block(&mut self) -> Result<Vec<Stmt>, ParseError> {
        self.expect(&Tok::LBrace, "\"{\"")?;
        self.deeper()?;
        let body = self.stmts(true)?;
        self.depth -= 1;
        self.expect(&Tok::RBrace, "\"}\"")?;
        Ok(body)
    }

    fn stmt(&mut self) -> Result<Stmt, ParseError> {
        let start = self.at;
        let w = match self.peek() {
            Some(Tok::Word(w)) => w.clone(),
            Some(t) => {
                let found = describe(t);
                return self.err(format!(
                    "expected an action (accept, reject, set…) or if, found {found}"
                ));
            }
            None => return self.err("expected an action"),
        };
        self.at += 1;
        let s = match w.as_str() {
            "if" => {
                self.expect(&Tok::LParen, "\"(\" after if")?;
                self.deeper()?;
                let cond = self.expr()?;
                self.depth -= 1;
                self.expect(&Tok::RParen, "\")\" to close the condition")?;
                let then = self.block()?;
                let els = if self.peek() == Some(&Tok::Word("else".into())) {
                    self.at += 1;
                    if self.peek() == Some(&Tok::Word("if".into())) {
                        self.deeper()?;
                        let inner = self.stmt()?;
                        self.depth -= 1;
                        vec![inner]
                    } else {
                        self.block()?
                    }
                } else {
                    Vec::new()
                };
                Stmt::If { cond, then, els }
            }
            "accept" => Stmt::Accept,
            "reject" => Stmt::Reject,
            "return" => Stmt::Return,
            "jump" => {
                let c = self.word("a chain name after jump")?;
                check_chain(&c).map_err(|msg| ParseError {
                    pos: self.toks.get(self.at - 1).map_or(0, |t| t.0),
                    msg,
                })?;
                Stmt::Jump(c)
            }
            "set" | "append" | "delete" => Stmt::Set(self.set(&w)?),
            "else" => {
                self.at = start;
                return self.err("else without if (or a \";\" between \"}\" and else)");
            }
            "unset" => {
                self.at = start;
                return self
                    .err("unset is not supported: FRR cannot remove an attribute in a policy");
            }
            other => {
                self.at = start;
                let hint = did_you_mean(other, ACTIONS);
                return self.err(format!("{:?} is not an action{hint}", cut(other)));
            }
        };
        Ok(s)
    }

    fn set(&mut self, verb: &str) -> Result<SetOp, ParseError> {
        let prop_at = self.at;
        let prop =
            self.word("a property (bgp-local-pref, bgp-med, bgp-path-prepend, bgp-communities, gw…)")?;
        let back = |p: &mut Self| p.at = prop_at;
        let num = |p: &mut Self, max: u64| -> Result<u64, ParseError> {
            let v = p.word("a number")?;
            if v.starts_with('+') || v.starts_with('-') {
                p.at -= 1;
                return p.err("relative values (+N, -N) are not supported: set the value itself");
            }
            v.parse::<u64>()
                .ok()
                .filter(|n| *n <= max)
                .ok_or_else(|| ParseError {
                    pos: p.toks.get(p.at - 1).map_or(0, |t| t.0),
                    msg: format!("{:?}: expected a number 0..={max}", cut(&v)),
                })
        };
        let comm = |p: &mut Self, large: bool| -> Result<SetOp, ParseError> {
            let how = match verb {
                "set" => CommHow::Set,
                "append" => CommHow::Append,
                _ => CommHow::Delete,
            };
            let v = p.word("communities (65000:100,no-export), none or a community-list name")?;
            let arg = if how == CommHow::Set && v == "none" {
                CommArg::Values(Vec::new())
            } else {
                p.at -= 1;
                p.comm_arg(large, None)?
            };
            Ok(SetOp::Comm { large, how, arg })
        };
        match (verb, prop.as_str()) {
            ("set", "bgp-local-pref") => {
                Ok(SetOp::LocalPref(num(self, u64::from(u32::MAX))? as u32))
            }
            ("set", "bgp-med" | "bgp-out-med") => {
                Ok(SetOp::Med(num(self, u64::from(u32::MAX))? as u32))
            }
            ("set", "bgp-path-prepend") => {
                let n = num(self, u64::from(MAX_PREPEND))? as u8;
                if n == 0 {
                    self.at -= 1;
                    return self.err("prepend at least once (1..=16)");
                }
                Ok(SetOp::Prepend(n))
            }
            ("set", "gw") => {
                let v = self.word("an IPv4 or IPv6 address")?;
                match v.parse::<std::net::IpAddr>() {
                    Ok(a) => match gw_problem(a) {
                        None => Ok(SetOp::Gw(a)),
                        Some(why) => {
                            self.at -= 1;
                            self.err(why)
                        }
                    },
                    Err(_) => {
                        self.at -= 1;
                        self.err(format!("{:?}: expected an IPv4 or IPv6 address", cut(&v)))
                    }
                }
            }
            (_, "bgp-communities") => comm(self, false),
            (_, "bgp-large-communities") => comm(self, true),
            ("append" | "delete", _) => {
                back(self);
                let hint = did_you_mean(&prop, &["bgp-communities", "bgp-large-communities"]);
                self.err(format!(
                    "{verb} takes bgp-communities or bgp-large-communities, not {:?}{hint}",
                    cut(&prop)
                ))
            }
            _ => {
                back(self);
                let hint = did_you_mean(&prop, PROPS);
                self.err(format!(
                    "{:?} is not a property set can change{hint}",
                    cut(&prop)
                ))
            }
        }
    }

    fn expr(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.and()?;
        while self.peek() == Some(&Tok::Or) {
            self.at += 1;
            let right = self.and()?;
            left = Expr::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn and(&mut self) -> Result<Expr, ParseError> {
        let mut left = self.unary()?;
        while self.peek() == Some(&Tok::And) {
            self.at += 1;
            let right = self.unary()?;
            left = Expr::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn unary(&mut self) -> Result<Expr, ParseError> {
        self.deeper()?;
        let e = match self.peek() {
            Some(Tok::Not) => {
                self.at += 1;
                Expr::Not(Box::new(self.unary()?))
            }
            Some(Tok::Word(w)) if w == "not" => {
                self.at += 1;
                Expr::Not(Box::new(self.unary()?))
            }
            Some(Tok::LParen) => {
                self.at += 1;
                let e = self.expr()?;
                self.expect(&Tok::RParen, "\")\"")?;
                e
            }
            _ => self.matcher()?,
        };
        self.depth -= 1;
        Ok(e)
    }

    fn cmp(&mut self) -> Result<Tok, ParseError> {
        match self.peek() {
            Some(t @ (Tok::Eq | Tok::Ne | Tok::Lt | Tok::Le | Tok::Gt | Tok::Ge)) => {
                let t = t.clone();
                self.at += 1;
                Ok(t)
            }
            Some(Tok::Word(w)) if w == "in" => {
                self.at += 1;
                Ok(Tok::Word("in".into()))
            }
            Some(t) => {
                let found = describe(t);
                self.err(format!(
                    "expected an operator (in, ==, !=, <, <=, >, >=), found {found}"
                ))
            }
            None => self.err("expected an operator (in, ==, !=, <, <=, >, >=)"),
        }
    }

    fn matcher(&mut self) -> Result<Expr, ParseError> {
        let at = self.at;
        let name = match self.peek() {
            Some(Tok::Word(w)) => w.clone(),
            Some(t) => {
                let found = describe(t);
                return self.err(format!(
                    "expected a matcher (dst, dst-len, bgp-as-path…), found {found}"
                ));
            }
            None => return self.err("expected a matcher (dst, dst-len, bgp-as-path…)"),
        };
        self.at += 1;
        let atom = |a: Atom| Expr::Atom(a);
        match name.as_str() {
            "dst" => {
                let op = self.cmp()?;
                let v_at = self.at;
                let v = self.word("a prefix (10.0.0.0/8) or a prefix-list name")?;
                let parsed: Option<IpNet> = v.parse().ok();
                if let Some(net) = parsed
                    && net.trunc() != net
                {
                    self.at = v_at;
                    return self.err(format!(
                        "{net} has host bits set (did you mean {}?)",
                        net.trunc()
                    ));
                }
                let e = match (&op, parsed) {
                    (Tok::Word(_), Some(net)) => atom(Atom::DstIn(net)),
                    (Tok::Word(_), None) => {
                        if v.contains('/') || v.parse::<std::net::IpAddr>().is_ok() {
                            self.at = v_at;
                            return self.err(format!("{:?} is not a prefix (10.0.0.0/8)", cut(&v)));
                        }
                        check_name(&v).map_err(|msg| ParseError {
                            pos: self.toks.get(v_at).map_or(0, |t| t.0),
                            msg,
                        })?;
                        atom(Atom::DstList(v))
                    }
                    (Tok::Eq, Some(net)) => atom(Atom::DstEq(net)),
                    (Tok::Ne, Some(net)) => Expr::Not(Box::new(atom(Atom::DstEq(net)))),
                    (Tok::Eq | Tok::Ne, None) => {
                        self.at = v_at;
                        return self.err(format!(
                            "{:?} is not a prefix (10.0.0.0/8); a list goes with in",
                            cut(&v)
                        ));
                    }
                    _ => {
                        self.at = at + 1;
                        return self.err("dst takes in, == or != (use dst-len to compare lengths)");
                    }
                };
                Ok(e)
            }
            "dst-len" => {
                let op = self.cmp()?;
                let v_at = self.at;
                let v = self.word("a length (24) or a range (16-24)")?;
                let bad = |p: &Self| ParseError {
                    pos: p.toks.get(v_at).map_or(0, |t| t.0),
                    msg: format!("{:?}: expected a length 0..=128 or a range N-M", cut(&v)),
                };
                let n = |s: &str| s.parse::<u8>().ok().filter(|n| *n <= 128);
                let (lo, hi) = if let Tok::Word(_) = op {
                    let (a, b) = v
                        .split_once("..")
                        .or_else(|| v.split_once('-'))
                        .ok_or_else(|| bad(self))?;
                    let (a, b) = (
                        n(a).ok_or_else(|| bad(self))?,
                        n(b).ok_or_else(|| bad(self))?,
                    );
                    if a > b {
                        return Err(bad(self));
                    }
                    (a, b)
                } else {
                    let x = n(&v).ok_or_else(|| bad(self))?;
                    match op {
                        Tok::Eq | Tok::Ne => (x, x),
                        Tok::Lt if x == 0 => (1, 0),
                        Tok::Lt => (0, x - 1),
                        Tok::Le => (0, x),
                        Tok::Gt if x == 128 => (1, 0),
                        Tok::Gt => (x + 1, 128),
                        _ => (x, 128),
                    }
                };
                if lo > hi {
                    self.at = v_at;
                    return self.err("this length range is empty: the condition is never true");
                }
                let e = atom(Atom::DstLen(lo, hi));
                Ok(if op == Tok::Ne {
                    Expr::Not(Box::new(e))
                } else {
                    e
                })
            }
            "afi" => {
                if matches!(self.peek(), Some(Tok::Eq)) {
                    self.at += 1;
                }
                let v_at = self.at;
                let v = self.word("ipv4 or ipv6")?;
                match v.as_str() {
                    "ipv4" | "ip" => Ok(atom(Atom::Afi(Family::V4))),
                    "ipv6" => Ok(atom(Atom::Afi(Family::V6))),
                    _ => {
                        self.at = v_at;
                        let hint = did_you_mean(&v, &["ipv4", "ipv6"]);
                        self.err(format!(
                            "{:?}: this router filters ipv4 and ipv6{hint}",
                            cut(&v)
                        ))
                    }
                }
            }
            "protocol" => {
                if matches!(self.peek(), Some(Tok::Eq)) {
                    self.at += 1;
                }
                let v_at = self.at;
                let v = self.word("a protocol (bgp, connected, static, ospf)")?;
                let mut out: Option<Expr> = None;
                for name in v.split(',') {
                    let p = Protocol::parse(name).ok_or_else(|| {
                        let names: Vec<&str> = Protocol::ALL.iter().map(|p| p.name()).collect();
                        ParseError {
                            pos: self.toks.get(v_at).map_or(0, |t| t.0),
                            msg: format!(
                                "{:?} is not a protocol here ({}){}",
                                cut(name),
                                names.join(", "),
                                did_you_mean(name, &names)
                            ),
                        }
                    })?;
                    let a = atom(Atom::Protocol(p));
                    out = Some(match out {
                        None => a,
                        Some(prev) => Expr::Or(Box::new(prev), Box::new(a)),
                    });
                }
                out.map_or_else(|| self.err("expected a protocol"), Ok)
            }
            "bgp-as-path" => {
                let v_at = self.at;
                let re = self.value("a regular expression (\"^65000_\")")?;
                check_regex(&re).map_err(|msg| ParseError {
                    pos: self.toks.get(v_at).map_or(0, |t| t.0),
                    msg,
                })?;
                Ok(atom(Atom::AsPath(re)))
            }
            "bgp-communities" | "bgp-large-communities" => {
                let large = name == "bgp-large-communities";
                let op_at = self.at;
                let op = self.word("includes, any, equal (or -list)")?;
                let (op, list) = match op.as_str() {
                    "includes" => (CommOp::Includes, false),
                    "any" => (CommOp::Any, false),
                    "equal" => (CommOp::Equal, false),
                    "includes-list" => (CommOp::Includes, true),
                    "any-list" => (CommOp::Any, true),
                    "equal-list" => (CommOp::Equal, true),
                    other => {
                        self.at = op_at;
                        let hint = did_you_mean(other, COMM_OPS);
                        return self.err(format!("{:?} is not a community operator here (includes, any, equal, …-list){hint}", cut(other)));
                    }
                };
                let arg = self.comm_arg(large, Some(list))?;
                Ok(atom(Atom::Comm { large, op, arg }))
            }
            other => {
                self.at = at;
                if let Some((_, why)) = UNSUPPORTED.iter().find(|(m, _)| *m == other) {
                    return self.err(format!("{other}: {why}"));
                }
                if ACTIONS.contains(&other) {
                    return self.err(format!(
                        "{other} is an action: it goes in the {{ }} block, not in the condition"
                    ));
                }
                let hint = did_you_mean(other, MATCHERS);
                self.err(format!("{:?} is not a matcher{hint}", cut(other)))
            }
        }
    }

    /// Community values (`65000:1,no-export`) or a list name. `list`:
    /// `Some(true)` only a name, `Some(false)` only values, `None` either.
    fn comm_arg(&mut self, large: bool, list: Option<bool>) -> Result<CommArg, ParseError> {
        let v_at = self.at;
        let v = self.word(if large {
            "large communities (65000:1:2)"
        } else {
            "communities (65000:100, no-export)"
        })?;
        let pos = self.toks.get(v_at).map_or(0, |t| t.0);
        let looks_like_values = v.contains(':') || parse_community(&v).is_ok();
        if list == Some(true) || (list.is_none() && !looks_like_values) {
            check_name(&v).map_err(|msg| ParseError { pos, msg })?;
            return Ok(CommArg::List(v));
        }
        let mut out = Vec::new();
        for raw in v.split(',') {
            let c = parse_community(raw).map_err(|msg| ParseError { pos, msg })?;
            if matches!(c, CommunityValue::Large(_)) != large {
                let msg = if large {
                    format!("{:?} is a normal community: use bgp-communities", cut(raw))
                } else {
                    format!(
                        "{:?} is a large community: use bgp-large-communities",
                        cut(raw)
                    )
                };
                return Err(ParseError { pos, msg });
            }
            if !out.contains(&c) {
                out.push(c);
            }
        }
        if out.len() > MAX_VALUES {
            return Err(ParseError {
                pos,
                msg: format!("at most {MAX_VALUES} communities"),
            });
        }
        Ok(CommArg::Values(out))
    }
}

/// A chain or list name: 1..=64 of `[A-Za-z0-9_.-]` (it goes on FRR's vty).
pub fn check_name(s: &str) -> Result<(), String> {
    if s.is_empty()
        || s.len() > 64
        || !s
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(format!(
            "{:?}: a name is 1..=64 characters of [A-Za-z0-9_.-]",
            cut(s)
        ));
    }
    Ok(())
}

/// Why `a` cannot be a next hop set by a chain (G3.9fh), if it cannot.
pub fn gw_problem(a: std::net::IpAddr) -> Option<String> {
    use std::net::IpAddr;
    let bad = match a {
        IpAddr::V4(v) => v.is_unspecified() || v.is_multicast() || v.is_broadcast() || v.is_loopback(),
        IpAddr::V6(v) => v.is_unspecified() || v.is_multicast() || v.is_loopback(),
    };
    if bad {
        return Some(format!("{a} cannot be a next hop"));
    }
    if let IpAddr::V6(v) = a {
        if v.to_ipv4_mapped().is_some() {
            return Some(format!(
                "{a} is IPv4-mapped, the next hop the kernel cannot install: give the neighbor's global IPv6 address"
            ));
        }
        if v.is_unicast_link_local() {
            return Some(format!(
                "{a} is link-local: a link-local next hop needs its interface; give a global IPv6 address"
            ));
        }
    }
    None
}

pub fn check_chain(s: &str) -> Result<(), String> {
    check_name(s)
}

/// An AS-path regular expression as FRR takes it: printable ASCII, no
/// backslash (POSIX and Rust disagree on escapes), at most 256 bytes, and
/// it compiles.
pub fn check_regex(re: &str) -> Result<(), String> {
    if re.is_empty() || re.len() > MAX_REGEX_LEN {
        return Err(format!(
            "a regular expression of 1..={MAX_REGEX_LEN} characters"
        ));
    }
    if let Some(c) = re
        .chars()
        .find(|c| !(c.is_ascii_graphic() || *c == ' ') || *c == '\\' || *c == '"')
    {
        return Err(format!(
            "{c:?} is not allowed in an AS-path expression (digits, spaces and . * + ? ^ $ _ | ( ) [ ] {{ }} , -)"
        ));
    }
    let expanded = re.replace('_', super::eval::UNDERSCORE);
    regex_syntax::ParserBuilder::new()
        .unicode(false)
        .utf8(false)
        .nest_limit(64)
        .build()
        .parse(&expanded)
        .map(|_| ())
        .map_err(|e| {
            format!(
                "not a regular expression: {}",
                cut(&e.to_string().replace('\n', " "))
            )
        })
}

/// Parse one rule.
pub fn parse(src: &str) -> Result<Vec<Stmt>, ParseError> {
    if src.len() > corerouter_model::routing_filter::MAX_RULE_LEN {
        return Err(ParseError {
            pos: 0,
            msg: format!(
                "longer than {} characters",
                corerouter_model::routing_filter::MAX_RULE_LEN
            ),
        });
    }
    let toks = lex(src)?;
    let mut p = Parser {
        toks: &toks,
        at: 0,
        end: src.len(),
        depth: 0,
    };
    let out = p.stmts(false)?;
    if out.is_empty() {
        return Err(ParseError {
            pos: 0,
            msg: "an empty rule (accept, reject or if (…) { … })".into(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(src: &str) -> String {
        parse(src).unwrap_err().to_string()
    }

    #[test]
    fn parses_the_routeros_examples() {
        let r = parse("if (dst in 192.168.1.0/24 && dst-len>24) {set bgp-local-pref 200; accept} else {reject}").unwrap();
        let Stmt::If { cond, then, els } = &r[0] else {
            panic!("{r:?}")
        };
        assert_eq!(
            cond,
            &Expr::And(
                Box::new(Expr::Atom(Atom::DstIn("192.168.1.0/24".parse().unwrap()))),
                Box::new(Expr::Atom(Atom::DstLen(25, 128)))
            )
        );
        assert_eq!(then, &[Stmt::Set(SetOp::LocalPref(200)), Stmt::Accept]);
        assert_eq!(els, &[Stmt::Reject]);
        assert_eq!(parse("accept").unwrap(), [Stmt::Accept]);
        assert_eq!(
            parse("if ( not protocol bgp) {reject; }").unwrap(),
            [Stmt::If {
                cond: Expr::Not(Box::new(Expr::Atom(Atom::Protocol(Protocol::Bgp)))),
                then: vec![Stmt::Reject],
                els: vec![]
            }]
        );
        let r = parse("if (bgp-communities any 65000:666,blackhole || bgp-as-path \"_6450[0-9]_\") { append bgp-communities no-export; set bgp-path-prepend 2; jump customers } else if (dst in bogons) { reject }").unwrap();
        assert_eq!(r.len(), 1);
        assert!(parse("set bgp-large-communities 65000:1:2,65000:1:3; accept").is_ok());
        assert!(parse("delete bgp-communities 65000:1; set bgp-communities none; return").is_ok());
        assert!(parse("if (dst-len in 8-24 && afi ipv4) { accept }").is_ok());
        assert!(parse("if (dst != 0.0.0.0/0) { accept }").is_ok());
    }

    #[test]
    fn errors_say_where_and_suggest() {
        assert_eq!(
            err("acept"),
            "column 1: \"acept\" is not an action (did you mean \"accept\"?)"
        );
        assert!(err("if (dts in 10.0.0.0/8) {reject}").contains("did you mean \"dst\""));
        assert!(err("set bgp-local-prf 100").contains("did you mean \"bgp-local-pref\""));
        assert!(
            err("if (bgp-communities include 1:1) {reject}").contains("did you mean \"includes\"")
        );
        assert!(err("if (dst in 10.0.0.1/8) {reject}").contains("did you mean 10.0.0.0/8"));
        assert!(err("if (dst in 10.0.0.0/8 {reject}").contains("\")\""));
        assert!(err("if (dst in 10.0.0.0/8) {reject").contains("\"}\""));
        assert!(err("if (dst in 10.0.0.0/8 & dst-len > 8) {reject}").contains("\"&&\""));
        assert!(err("if (bgp-med > 10) {reject}").contains("FRR"));
        assert!(err("set bgp-path-prepend 17").contains("0..=16"));
        assert!(err("set bgp-med +10").contains("relative"));
        assert!(
            err("if (bgp-communities includes 1:2:3) {reject}").contains("bgp-large-communities")
        );
        assert!(err("if (bgp-as-path \"\\d\") {reject}").contains("escapes"));
        assert!(
            err("if (bgp-as-path \"(\") {reject}").contains("regular expression")
                || err("if (bgp-as-path \"(\") {reject}").contains("unclosed")
        );
        assert!(err("").contains("empty"));
        assert!(err("if (accept) {reject}").contains("is an action"));
        assert!(err("if (dst-len > 128) {reject}").contains("never true"));
    }

    #[test]
    fn hostile_text_is_bounded() {
        let deep = format!("{}accept{}", "if (afi ipv4) {".repeat(40), "}".repeat(40));
        assert!(err(&deep).contains("deeper"));
        let parens = format!(
            "if ({}afi ipv4{}) {{accept}}",
            "(".repeat(100),
            ")".repeat(100)
        );
        assert!(err(&parens).contains("deeper"));
        let many = "accept;".repeat(3000);
        assert!(err(&many).contains("longer"));
        assert!(err("accept \u{0}").contains("ASCII") || err("accept \u{0}").contains("action"));
        assert!(
            err("set bgp-communities \"é\"").contains("ASCII")
                || err("set bgp-communities \"é\"").contains("communities")
        );
    }

    #[test]
    fn did_you_mean_only_when_close() {
        assert_eq!(
            did_you_mean("rejet", ACTIONS),
            " (did you mean \"reject\"?)"
        );
        assert_eq!(did_you_mean("zzzzzz", ACTIONS), "");
    }
}
