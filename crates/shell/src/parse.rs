//! One statement → what to do, resolved against the menu tree and the
//! current menu. Pure: item numbers (`remove 0`) are resolved later, against
//! the last `print` (see `shell.rs`).
//!
//! Grammar (RouterOS's):
//!
//! ```text
//! statement := ['/'] path-word* [verb arg*] ['?']
//! path-word := menu | '..' ;  a leading '/' (or '/ip/address') starts at the root
//! arg       := key=value | value
//! print     := 'print' [detail] [as-json] [count-only] [show-ids]
//!              [proplist=a,b] [key=value…] ['where' cond]
//! cond      := term (('and' | 'or') term)* ; term := ['!']field[(=|!=|~|<|>|<=|>=)value]
//! ```
//!
//! Menu, command, parameter and property names may be abbreviated to any
//! unambiguous prefix (`/ip addr pr`); an exact name always wins.

use crate::doc::{self, kebab, snake};
use crate::lex::{self, Word};
use crate::registry::{Command, Menu, Registry};

/// Verbs every menu has besides its commands.
pub const EXPORT: &str = "export";
/// Root-only verbs.
pub const IMPORT: &str = "import";
pub const QUIT: &str = "quit";

/// Words `print` takes as flags.
pub const PRINT_FLAGS: &[&str] = &["detail", "as-json", "count-only", "show-ids", "where"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub message: String,
    /// 1-based column (characters) of the offending word.
    pub column: usize,
}

impl ParseError {
    fn at(line: &str, byte: usize, message: impl Into<String>) -> Self {
        let column = line.get(..byte).map_or(1, |s| s.chars().count() + 1);
        Self {
            message: message.into(),
            column,
        }
    }
}

/// An argument of a registry command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arg {
    /// `key=value`, key already in engine form (`vlan_id`).
    Pair { key: String, value: String },
    /// A word without `=`: an item (`0`, `0,2`, `*1`, `ether1`) or the
    /// next required parameter.
    Positional(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Eq,
    Ne,
    Contains,
    Lt,
    Gt,
    Le,
    Ge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Term {
    pub field: String,
    pub negate: bool,
    pub op: Option<(Op, String)>,
}

/// OR of ANDs.
pub type Cond = Vec<Vec<Term>>;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrintOpts {
    pub detail: bool,
    pub as_json: bool,
    pub count_only: bool,
    pub show_ids: bool,
    pub proplist: Option<Vec<String>>,
    /// Parameters of the read command itself (`interface=ether1`).
    pub params: Vec<(String, String)>,
    pub cond: Option<Cond>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Parsed {
    Empty,
    /// Enter a menu (`/ip address`, `..`, `/`).
    Navigate(Vec<String>),
    /// `?`: about a menu, or a command when `id` is set.
    Help {
        path: Vec<String>,
        id: Option<String>,
    },
    Command {
        path: Vec<String>,
        id: String,
        args: Vec<Arg>,
    },
    Print {
        path: Vec<String>,
        id: String,
        opts: PrintOpts,
    },
    Export {
        path: Vec<String>,
        file: Option<String>,
        /// `terse`: one line per item, menu in front, never wrapped.
        terse: bool,
    },
    Import {
        file: Option<String>,
    },
    Quit,
}

/// Outcome of picking a name among candidates.
pub enum Pick<'a> {
    One(&'a str),
    None,
    Many(Vec<&'a str>),
}

/// Exact name, else the only one starting with `word`.
pub fn pick<'a>(word: &str, names: &[&'a str]) -> Pick<'a> {
    if let Some(n) = names.iter().find(|n| **n == word) {
        return Pick::One(n);
    }
    let hits: Vec<&str> = names
        .iter()
        .copied()
        .filter(|n| n.starts_with(word))
        .collect();
    match hits.as_slice() {
        [one] => Pick::One(one),
        [] => Pick::None,
        _ => Pick::Many(hits),
    }
}

/// Closest name by edit distance, if close enough to be a typo.
pub fn suggest<'a>(word: &str, names: &[&'a str]) -> Option<&'a str> {
    let word: String = word.chars().take(64).collect();
    names
        .iter()
        .map(|n| (distance(&word, n), *n))
        .filter(|(d, n)| *d <= 2.max(n.chars().count() / 3))
        .min_by_key(|(d, _)| *d)
        .map(|(_, n)| n)
}

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

/// Names a menu offers at the path stage: sub-menus, its commands, the
/// built-in verbs and the registry's shortcuts (`ping`, from any menu).
pub fn names<'a>(reg: &'a Registry, menu: &'a Menu, root: bool) -> Vec<&'a str> {
    let mut out: Vec<&str> = menu.children.keys().map(String::as_str).collect();
    out.extend(menu.commands.keys().map(String::as_str));
    for a in reg.aliases.keys() {
        if !out.contains(&a.as_str()) {
            out.push(a);
        }
    }
    if !menu.commands.contains_key(EXPORT) {
        out.push(EXPORT);
    }
    if root {
        out.push(IMPORT);
        out.push(QUIT);
    }
    out
}

/// Where a walk over the words of a statement stopped.
pub enum Stage<'r> {
    /// Only menus so far: the menu reached.
    Path(Vec<String>),
    /// A verb was found at `words[next - 1]`.
    Verb {
        path: Vec<String>,
        verb: Verb<'r>,
        /// Index of the first argument word.
        next: usize,
    },
}

pub enum Verb<'r> {
    Command(&'r Command),
    Export,
    Import,
    Quit,
}

/// Path words of a statement: a leading `/` is the root and `/ip/address`
/// splits. `(word, byte offset)`.
fn path_words(words: &[Word]) -> (bool, Vec<(String, usize, usize)>) {
    let mut absolute = false;
    let mut out = Vec::new();
    for (i, w) in words.iter().enumerate() {
        if i == 0 && w.text.starts_with('/') && !w.is_pair() {
            absolute = true;
            let mut off = w.start;
            for part in w.text.split('/') {
                if !part.is_empty() {
                    out.push((part.to_owned(), off, i));
                }
                off += part.len() + 1;
            }
        } else {
            out.push((w.text.clone(), w.start, i));
        }
    }
    (absolute, out)
}

/// Walk the words from `cwd`. Errors carry the byte offset of the word.
pub fn walk<'r>(
    reg: &'r Registry,
    cwd: &[String],
    words: &[Word],
) -> Result<Stage<'r>, (usize, String)> {
    let (absolute, parts) = path_words(words);
    let mut path: Vec<String> = if absolute { Vec::new() } else { cwd.to_vec() };
    for (word, off, idx) in parts {
        let Some(w) = words.get(idx) else { break };
        // `/tool ping 8.8.8.8`, `/tool ping address=…`: a menu named like an
        // alias of one of its commands runs it when what follows is not a
        // name of the menu.
        if let Some(cmd) = menu_command(reg, &path)
            && (w.is_pair()
                || reg.menu(&path).is_some_and(|m| {
                    matches!(pick(&word, &names(reg, m, path.is_empty())), Pick::None)
                }))
        {
            return Ok(Stage::Verb {
                path,
                verb: Verb::Command(cmd),
                next: idx,
            });
        }
        if w.is_pair() {
            return Err((
                off,
                format!("expected a menu or command, got '{}'", clip(&w.text)),
            ));
        }
        if word == ".." {
            path.pop();
            continue;
        }
        let menu = reg
            .menu(&path)
            .ok_or_else(|| (off, "no such menu".to_owned()))?;
        let all = names(reg, menu, path.is_empty());
        let name = match pick(&word, &all) {
            Pick::One(n) => n,
            Pick::None => {
                // A typo gets a guess; anything else, what this menu has.
                let hint = suggest(&word, &all).map_or_else(
                    || format!("; here: {}", all.join(", ")),
                    |s| format!("; did you mean '{s}'?"),
                );
                return Err((off, format!("bad command name '{}'{hint}", clip(&word))));
            }
            Pick::Many(hits) => {
                return Err((
                    off,
                    format!(
                        "ambiguous command name '{}': {}",
                        clip(&word),
                        hits.join(", ")
                    ),
                ));
            }
        };
        if menu.children.contains_key(name) {
            path.push(name.to_owned());
            continue;
        }
        let verb = if let Some(cmd) = menu.commands.get(name) {
            Verb::Command(cmd)
        } else if let Some((cpath, cmd)) = reg.aliases.get(name).and_then(|id| reg.by_id(id)) {
            path = cpath.to_vec();
            Verb::Command(cmd)
        } else if name == EXPORT {
            Verb::Export
        } else if name == IMPORT {
            Verb::Import
        } else {
            Verb::Quit
        };
        return Ok(Stage::Verb {
            path,
            verb,
            next: idx + 1,
        });
    }
    Ok(Stage::Path(path))
}

/// The command a menu runs by its own name: one of its commands whose
/// alias is the menu's name (`/tool ping` → `tool.ping.start`).
pub fn menu_command<'r>(reg: &'r Registry, path: &[String]) -> Option<&'r Command> {
    let name = path.last()?;
    reg.menu(path)?
        .commands
        .values()
        .find(|c| c.alias.iter().any(|a| a == name))
}

pub fn clip(s: &str) -> String {
    let mut out: String = s.chars().take(64).collect();
    if s.chars().count() > 64 {
        out.push('…');
    }
    out
}

/// A parameter key as typed (`vlan-id`, `vl`) → engine key (`vlan_id`).
/// Unknown keys pass through in engine form: the engine rejects them with
/// its own "did you mean".
pub fn resolve_key(cmd: &Command, typed: &str) -> Result<String, String> {
    let shown: Vec<String> = cmd.params.iter().map(|p| kebab(&p.key)).collect();
    let refs: Vec<&str> = shown.iter().map(String::as_str).collect();
    let typed_kebab = kebab(typed);
    match pick(&typed_kebab, &refs) {
        Pick::One(k) => Ok(snake(k)),
        Pick::None => Ok(snake(typed)),
        Pick::Many(hits) => Err(format!(
            "ambiguous argument name '{}': {}",
            clip(typed),
            hits.join(", ")
        )),
    }
}

/// A property name of a row (`dst-a` → `dst_address`) among `fields`.
pub fn resolve_field(fields: &[String], typed: &str) -> Result<String, String> {
    let shown: Vec<String> = fields.iter().map(|f| kebab(f)).collect();
    let refs: Vec<&str> = shown.iter().map(String::as_str).collect();
    match pick(&kebab(typed), &refs) {
        Pick::One(k) => Ok(snake(k)),
        Pick::None => {
            let hint = suggest(&kebab(typed), &refs)
                .map(|s| format!("; did you mean '{s}'?"))
                .unwrap_or_default();
            Err(format!("no such property '{}'{hint}", clip(typed)))
        }
        Pick::Many(hits) => Err(format!(
            "ambiguous property '{}': {}",
            clip(typed),
            hits.join(", ")
        )),
    }
}

/// Parse one statement (no `;`) typed in menu `cwd`.
pub fn parse(reg: &Registry, cwd: &[String], line: &str) -> Result<Parsed, ParseError> {
    if line.len() > lex::MAX_LINE {
        return Err(ParseError {
            message: format!("line too long (at most {} bytes)", lex::MAX_LINE),
            column: 1,
        });
    }
    let trimmed = line.trim_end();
    if trimmed.trim_start().starts_with('#') {
        return Ok(Parsed::Empty);
    }
    let (body, help) = match trimmed.strip_suffix('?') {
        Some(b) => (b, true),
        None => (trimmed, false),
    };
    let words = lex::words(body);
    if let Some(w) = words.iter().find(|w| w.open_quote) {
        return Err(ParseError::at(line, w.start, "unterminated quote"));
    }
    if words.is_empty() && !help {
        return Ok(Parsed::Empty);
    }
    if words.len() >= lex::MAX_WORDS {
        return Err(ParseError::at(line, 0, "too many words"));
    }
    let stage = walk(reg, cwd, &words).map_err(|(at, m)| ParseError::at(line, at, m))?;
    match stage {
        Stage::Path(path) if help => Ok(Parsed::Help { path, id: None }),
        Stage::Path(path) => Ok(Parsed::Navigate(path)),
        Stage::Verb { path, verb, next } => {
            let args = words.get(next..).unwrap_or_default();
            if help {
                let id = match verb {
                    Verb::Command(c) => Some(c.id.clone()),
                    _ => None,
                };
                return Ok(Parsed::Help { path, id });
            }
            match verb {
                Verb::Quit => no_args(line, args).map(|()| Parsed::Quit),
                Verb::Export => {
                    let (file, terse) = export_args(line, args)?;
                    Ok(Parsed::Export { path, file, terse })
                }
                Verb::Import => {
                    let file = file_arg(line, args)?;
                    Ok(Parsed::Import { file })
                }
                Verb::Command(cmd) if cmd.verb == "print" => {
                    let opts = print_opts(line, cmd, args)?;
                    Ok(Parsed::Print {
                        path,
                        id: cmd.id.clone(),
                        opts,
                    })
                }
                Verb::Command(cmd) => {
                    let mut out = Vec::new();
                    for w in args {
                        match &w.key {
                            Some(k) => out.push(Arg::Pair {
                                key: resolve_key(cmd, k)
                                    .map_err(|m| ParseError::at(line, w.start, m))?,
                                value: w.value.clone(),
                            }),
                            None => out.push(Arg::Positional(w.text.clone())),
                        }
                    }
                    Ok(Parsed::Command {
                        path,
                        id: cmd.id.clone(),
                        args: out,
                    })
                }
            }
        }
    }
}

fn no_args(line: &str, args: &[Word]) -> Result<(), ParseError> {
    match args.first() {
        Some(w) => Err(ParseError::at(
            line,
            w.start,
            format!("unexpected argument '{}'", clip(&w.text)),
        )),
        None => Ok(()),
    }
}

/// `file=name` or a bare name.
fn file_arg(line: &str, args: &[Word]) -> Result<Option<String>, ParseError> {
    let mut file = None;
    for w in args {
        match w.key.as_deref() {
            Some(k) if "file".starts_with(k) => file = Some(w.value.clone()),
            None if file.is_none() => file = Some(w.text.clone()),
            _ => {
                return Err(ParseError::at(
                    line,
                    w.start,
                    format!("unexpected argument '{}' (only file=…)", clip(&w.text)),
                ));
            }
        }
    }
    Ok(file.filter(|f| !f.is_empty()))
}

/// `/export [file=…] [terse] [compact]` (`compact`, RouterOS's default
/// since v6, changes nothing).
fn export_args(line: &str, args: &[Word]) -> Result<(Option<String>, bool), ParseError> {
    let mut terse = false;
    let mut rest = Vec::new();
    for w in args {
        match (w.key.as_deref(), w.text.as_str()) {
            (None, "terse") => terse = true,
            (None, "compact") => {}
            // Not file names: RouterOS options this export does not have.
            (None, "verbose" | "show-sensitive") => {
                return Err(ParseError::at(
                    line,
                    w.start,
                    format!("{} is not supported (file=…, terse, compact)", w.text),
                ));
            }
            _ => rest.push(w.clone()),
        }
    }
    let file = file_arg(line, &rest).map_err(|mut e| {
        e.message = e.message.replace("(only file=…)", "(file=…, terse)");
        e
    })?;
    Ok((file, terse))
}

fn print_opts(line: &str, cmd: &Command, args: &[Word]) -> Result<PrintOpts, ParseError> {
    let mut o = PrintOpts::default();
    let fields = &cmd.shape.fields;
    for (i, w) in args.iter().enumerate() {
        let err = |m: String| ParseError::at(line, w.start, m);
        match &w.key {
            Some(k) if "proplist".starts_with(k.as_str()) && k.len() >= 2 => {
                let mut props = Vec::new();
                for p in w.value.split(',').filter(|p| !p.is_empty()) {
                    props.push(resolve_field(fields, p).map_err(err)?);
                }
                o.proplist = Some(props);
            }
            Some(k) => {
                let key = resolve_key(cmd, k).map_err(err)?;
                o.params.push((key, w.value.clone()));
            }
            None => {
                let flag = match pick(&w.text, PRINT_FLAGS) {
                    Pick::One(f) => f,
                    Pick::None => {
                        return Err(err(format!(
                            "unknown print option '{}' (detail, as-json, count-only, show-ids, proplist=, where)",
                            clip(&w.text)
                        )));
                    }
                    Pick::Many(h) => {
                        return Err(err(format!(
                            "ambiguous print option '{}': {}",
                            clip(&w.text),
                            h.join(", ")
                        )));
                    }
                };
                match flag {
                    "detail" => o.detail = true,
                    "as-json" => o.as_json = true,
                    "count-only" => o.count_only = true,
                    "show-ids" => o.show_ids = true,
                    _ => {
                        let rest = args.get(i + 1..).unwrap_or_default();
                        o.cond = Some(cond(line, fields, rest)?);
                        break;
                    }
                }
            }
        }
    }
    Ok(o)
}

const OPS: &[(&str, Op)] = &[
    ("!=", Op::Ne),
    ("<=", Op::Le),
    (">=", Op::Ge),
    ("=", Op::Eq),
    ("~", Op::Contains),
    ("<", Op::Lt),
    (">", Op::Gt),
];

fn cond(line: &str, fields: &[String], words: &[Word]) -> Result<Cond, ParseError> {
    let mut out: Cond = vec![Vec::new()];
    let mut want_term = true;
    for w in words {
        let err = |m: String| ParseError::at(line, w.start, m);
        if !want_term {
            match w.text.as_str() {
                "and" => {}
                "or" => out.push(Vec::new()),
                other => {
                    return Err(err(format!(
                        "expected 'and' or 'or', got '{}'",
                        clip(other)
                    )));
                }
            }
            want_term = true;
            continue;
        }
        // Raw text: `mtu>1400`, `comment~"up"`, `interface!=ether1`.
        let raw = line.get(w.start..w.end).unwrap_or("");
        let (negate, raw) = match raw.strip_prefix('!') {
            Some(r) => (true, r),
            None => (false, raw),
        };
        let split = raw.char_indices().find_map(|(i, _)| {
            OPS.iter().find_map(|(sym, op)| {
                raw.get(i..)
                    .filter(|r| r.starts_with(sym))
                    .map(|_| (i, *sym, *op))
            })
        });
        let term = match split {
            Some((at, sym, op)) => {
                let name = raw.get(..at).unwrap_or("");
                let value = lex::words(raw.get(at + sym.len()..).unwrap_or(""))
                    .first()
                    .map(|v| v.text.clone())
                    .unwrap_or_default();
                Term {
                    field: resolve_field(fields, name).map_err(err)?,
                    negate,
                    op: Some((op, value)),
                }
            }
            None => Term {
                field: resolve_field(fields, raw).map_err(err)?,
                negate,
                op: None,
            },
        };
        if let Some(last) = out.last_mut() {
            last.push(term);
        }
        want_term = false;
    }
    if want_term {
        let at = words.last().map_or(line.len(), |w| w.end);
        return Err(ParseError::at(line, at, "where needs a condition"));
    }
    Ok(out)
}

/// Every statement of a line, split at `;`, with their byte offsets.
pub fn split(line: &str) -> Vec<(usize, &str)> {
    lex::statements(line)
}

/// The type of a parameter, for completion and conversion.
pub fn param_ty<'c>(cmd: &'c Command, key: &str) -> Option<&'c doc::Ty> {
    cmd.param(key).map(|p| &p.ty)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn reg() -> Registry {
        Registry::from_list(&json!([
            {"id": "ip.address.add", "params": "{address: cidr, interface: string, disabled?: bool, comment?: string} → {id}", "kind": "action", "enabled": true},
            {"id": "ip.address.remove", "params": "{id: *hex} → {id}", "kind": "action", "enabled": true},
            {"id": "ip.address.list", "params": "{interface?: string} → [{id, address, network, interface, disabled, comment}]", "kind": "query", "enabled": true},
            {"id": "ip.arp.list", "params": "{} → [{address}]", "kind": "query", "enabled": true},
            {"id": "interface.vlan.add", "params": "{name: string, parent: string, vlan_id: u32} → {name}", "kind": "action", "enabled": true},
        ]))
    }

    fn p(cwd: &[&str], line: &str) -> Result<Parsed, ParseError> {
        let cwd: Vec<String> = cwd.iter().map(|s| (*s).to_owned()).collect();
        parse(&reg(), &cwd, line)
    }

    #[test]
    fn absolute_relative_and_abbreviated() {
        let want = Parsed::Command {
            path: vec!["ip".into(), "address".into()],
            id: "ip.address.add".into(),
            args: vec![
                Arg::Pair {
                    key: "address".into(),
                    value: "10.0.0.1/24".into(),
                },
                Arg::Pair {
                    key: "interface".into(),
                    value: "ether1".into(),
                },
            ],
        };
        assert_eq!(
            p(&[], "/ip address add address=10.0.0.1/24 interface=ether1").unwrap(),
            want
        );
        assert_eq!(
            p(&["ip"], "addr add addr=10.0.0.1/24 int=ether1").unwrap(),
            want
        );
        assert_eq!(
            p(
                &["interface"],
                "/ip/address/add address=10.0.0.1/24 interface=ether1"
            )
            .unwrap(),
            want
        );
        assert_eq!(
            p(
                &["ip", "address"],
                "add address=10.0.0.1/24 interface=ether1"
            )
            .unwrap(),
            want
        );
    }

    #[test]
    fn navigation() {
        assert_eq!(
            p(&[], "/ip address").unwrap(),
            Parsed::Navigate(vec!["ip".into(), "address".into()])
        );
        assert_eq!(
            p(&["ip", "address"], "..").unwrap(),
            Parsed::Navigate(vec!["ip".into()])
        );
        assert_eq!(p(&["ip"], "/").unwrap(), Parsed::Navigate(vec![]));
        assert_eq!(p(&["ip"], "").unwrap(), Parsed::Empty);
    }

    #[test]
    fn errors_point_at_the_word() {
        let e = p(&[], "/ip adress print").unwrap_err();
        assert!(
            e.message.contains("did you mean 'address'"),
            "{}",
            e.message
        );
        assert_eq!(e.column, 5);
        let e = p(&["ip"], "a").unwrap_err();
        assert!(e.message.contains("ambiguous"), "{}", e.message);
        assert!(p(&[], "/ip address add comment=\"x").is_err());
    }

    #[test]
    fn print_options_and_where() {
        let Parsed::Print { opts, .. } = p(
            &["ip", "address"],
            "pr det interface=ether1 where interface=ether1 and !disabled or comment~up",
        )
        .unwrap() else {
            panic!()
        };
        assert!(opts.detail);
        assert_eq!(opts.params, [("interface".to_owned(), "ether1".to_owned())]);
        let c = opts.cond.unwrap();
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].len(), 2);
        assert!(c[0][1].negate);
        assert_eq!(c[1][0].op, Some((Op::Contains, "up".into())));
        assert!(p(&["ip", "address"], "print where").is_err());
        assert!(p(&["ip", "address"], "print where bogus=1").is_err());
    }

    #[test]
    fn help_and_builtins() {
        assert_eq!(
            p(&[], "/ip address add ?").unwrap(),
            Parsed::Help {
                path: vec!["ip".into(), "address".into()],
                id: Some("ip.address.add".into())
            }
        );
        assert_eq!(
            p(&["ip"], "?").unwrap(),
            Parsed::Help {
                path: vec!["ip".into()],
                id: None
            }
        );
        assert_eq!(p(&[], "/quit").unwrap(), Parsed::Quit);
        assert_eq!(
            p(&[], "/import file=a.rsc").unwrap(),
            Parsed::Import {
                file: Some("a.rsc".into())
            }
        );
        assert_eq!(
            p(&["ip"], "export").unwrap(),
            Parsed::Export {
                path: vec!["ip".into()],
                file: None,
                terse: false
            }
        );
        assert_eq!(
            p(&[], "/export terse file=a.rsc").unwrap(),
            Parsed::Export {
                path: vec![],
                file: Some("a.rsc".into()),
                terse: true
            }
        );
        assert!(p(&[], "/export verbose").is_err());
        // `import` and `quit` are root verbs only.
        assert!(p(&["ip"], "import").is_err());
    }
}
