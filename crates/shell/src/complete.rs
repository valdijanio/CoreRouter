//! Tab completion and syntax colors, from the same menu tree and the
//! values the router last returned: menus and commands, parameter names,
//! and values — enumerations from the `params` doc (`type=vlan`), `yes`/`no`
//! for booleans, interface names, and the values the menu's own `print`
//! lists (names, `*ids`), or the same field elsewhere (`routing-table=`).

use std::collections::BTreeSet;

use serde_json::Value;

use crate::doc::{Ty, kebab, snake};
use crate::format::value_text;
use crate::lex::{self, Word};
use crate::parse::{self, Pick, Stage, Verb};
use crate::registry::Command;
use crate::shell::Shell;
use crate::style::{Span, Style};

/// Parameters whose values are interface names, besides any whose type
/// text says `interface`.
const INTERFACE_KEYS: &[&str] = &["interface", "interfaces", "parent", "bridge"];

/// At most this many candidates.
const MAX_CANDIDATES: usize = 200;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Replaces the line from [`Completion::start`] to the cursor.
    pub text: String,
    /// What a list shows.
    pub display: String,
    /// A short note (command label, parameter type).
    pub help: String,
    pub style: Style,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Completion {
    /// Byte offset where the replaced text starts.
    pub start: usize,
    pub candidates: Vec<Candidate>,
}

impl Completion {
    /// The longest text every candidate starts with.
    pub fn common_prefix(&self) -> String {
        let mut it = self.candidates.iter().map(|c| c.text.as_str());
        let Some(first) = it.next() else {
            return String::new();
        };
        let mut end = first.len();
        for t in it {
            end = first
                .char_indices()
                .zip(t.chars())
                .find(|((_, a), b)| a != b)
                .map_or(end.min(t.len()), |((i, _), _)| i.min(end));
        }
        first.get(..end).unwrap_or("").to_owned()
    }
}

fn cand(text: String, help: impl Into<String>, style: Style) -> Candidate {
    Candidate {
        display: text.trim_end().to_owned(),
        text,
        help: help.into(),
        style,
    }
}

fn floor_boundary(s: &str, mut i: usize) -> usize {
    i = i.min(s.len());
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

impl Shell {
    /// Candidates for the word at `cursor` (a byte offset into `line`).
    pub fn complete(&self, line: &str, cursor: usize) -> Completion {
        let cursor = floor_boundary(line, cursor);
        let before = line.get(..cursor).unwrap_or("");
        let Some(&(off, stmt)) = parse::split(before).last() else {
            return Completion::default();
        };
        let mut c = self.complete_stmt(stmt);
        c.start += off;
        c.candidates.truncate(MAX_CANDIDATES);
        c
    }

    fn complete_stmt(&self, stmt: &str) -> Completion {
        let words = lex::words(stmt);
        let ends_open = stmt.is_empty() || stmt.ends_with(char::is_whitespace);
        let (done, partial): (&[Word], Option<&Word>) = match words.split_last() {
            Some((last, rest)) if !ends_open || last.open_quote => (rest, Some(last)),
            _ => (words.as_slice(), None),
        };
        // `/ip/addr`: complete the segment after the last `/`.
        if done.is_empty()
            && let Some(p) = partial.filter(|p| p.text.starts_with('/') && !p.is_pair())
        {
            let cut = p.text.rfind('/').unwrap_or(0);
            let head = p.text.get(..cut).unwrap_or("");
            let seg = p.text.get(cut + 1..).unwrap_or("");
            let mut path_words = lex::words(&head.replace('/', " "));
            if let Some(first) = path_words.first_mut() {
                first.text.insert(0, '/');
            }
            let path = if path_words.is_empty() {
                Ok(Stage::Path(Vec::new()))
            } else {
                parse::walk(&self.reg, &self.cwd, &path_words)
            };
            return match path {
                Ok(Stage::Path(path)) => Completion {
                    start: p.start + cut + 1,
                    candidates: self.path_candidates(&path, seg, false),
                },
                _ => Completion::default(),
            };
        }
        let start = partial.map_or(stmt.len(), |p| p.start);
        let typed = partial.map_or("", |p| p.text.as_str());
        let Ok(stage) = parse::walk(&self.reg, &self.cwd, done) else {
            return Completion::default();
        };
        match stage {
            Stage::Path(path) => Completion {
                start,
                candidates: self.path_candidates(&path, typed, true),
            },
            Stage::Verb {
                path, verb, next, ..
            } => match verb {
                Verb::Command(cmd) => {
                    let given = done.get(next..).unwrap_or_default();
                    self.arg_candidates(&path, cmd, given, partial, start)
                }
                Verb::Export | Verb::Import => {
                    let mut opts = vec![("file=", "a file on this computer", Style::Key)];
                    if matches!(verb, Verb::Export) {
                        opts.push(("terse", "one line per item, menu in front", Style::Item));
                        opts.push((
                            "show-sensitive",
                            "passwords in clear (group full)",
                            Style::Item,
                        ));
                    }
                    Completion {
                        start,
                        candidates: opts
                            .into_iter()
                            .filter(|(f, _, _)| f.starts_with(typed))
                            .map(|(f, help, style)| cand(f.to_owned(), help, style))
                            .collect(),
                    }
                }
                Verb::Quit => Completion::default(),
            },
        }
    }

    fn path_candidates(&self, path: &[String], typed: &str, dotdot: bool) -> Vec<Candidate> {
        let Some(menu) = self.reg.menu(path) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for (name, child) in &menu.children {
            if name.starts_with(typed) {
                let about = child.print().map(|c| c.label.clone()).unwrap_or_default();
                out.push(cand(format!("{name} "), about, Style::Menu));
            }
        }
        for name in parse::names(&self.reg, menu, path.is_empty()) {
            if menu.children.contains_key(name) || !name.starts_with(typed) {
                continue;
            }
            let about = menu
                .commands
                .get(name)
                .or_else(|| {
                    self.reg
                        .aliases
                        .get(name)
                        .and_then(|id| self.reg.by_id(id))
                        .map(|(_, c)| c)
                })
                .map(|c| c.label.clone())
                .unwrap_or_else(|| {
                    match name {
                        parse::EXPORT => "script that recreates the configuration",
                        parse::IMPORT => "run a script as one atomic batch",
                        _ => "leave the terminal",
                    }
                    .to_owned()
                });
            out.push(cand(format!("{name} "), about, Style::Verb));
        }
        if dotdot && !path.is_empty() && "..".starts_with(typed) && !typed.is_empty() {
            out.push(cand(".. ".into(), "up one menu", Style::Menu));
        }
        out
    }

    fn arg_candidates(
        &self,
        path: &[String],
        cmd: &Command,
        given: &[Word],
        partial: Option<&Word>,
        start: usize,
    ) -> Completion {
        // A value: after `key=`.
        if let Some(p) = partial
            && let Some(k) = &p.key
        {
            let in_where = cmd.verb == "print" && given.iter().any(|w| w.text == "where");
            let key = if in_where {
                parse::resolve_field(&cmd.shape.fields, k.trim_end_matches(['!', '<', '>']))
                    .unwrap_or_else(|_| snake(k))
            } else if cmd.verb == "print" && "proplist".starts_with(k.as_str()) && k.len() >= 2 {
                return self.list_values(p, cmd.shape.fields.iter().map(|f| kebab(f)).collect());
            } else {
                parse::resolve_key(cmd, k).unwrap_or_else(|_| snake(k))
            };
            let values = self.values(path, cmd, &key);
            let comma = matches!(cmd.param(&key).map(|p| &p.ty), Some(Ty::List { .. }));
            if comma {
                return self.list_values(p, values);
            }
            let typed = p.value.as_str();
            return Completion {
                start: p.value_start,
                candidates: values
                    .into_iter()
                    .filter(|v| v.starts_with(typed))
                    .map(|v| cand(format!("{} ", lex::quote(&v)), "", Style::Value))
                    .collect(),
            };
        }
        let typed = partial.map_or("", |p| p.text.as_str());
        let mut out = Vec::new();
        if cmd.verb == "print" {
            if let Some(pos) = given.iter().position(|w| w.text == "where") {
                let after = given.len() - pos - 1;
                let want_term = after.is_multiple_of(2);
                if want_term {
                    for f in &cmd.shape.fields {
                        let f = kebab(f);
                        if f.starts_with(typed.trim_start_matches('!')) {
                            let bang = if typed.starts_with('!') { "!" } else { "" };
                            out.push(cand(format!("{bang}{f}"), "property", Style::Key));
                        }
                    }
                } else {
                    for w in ["and ", "or "] {
                        if w.starts_with(typed) {
                            out.push(cand(w.to_owned(), "", Style::Verb));
                        }
                    }
                }
                return Completion {
                    start,
                    candidates: out,
                };
            }
            for f in parse::PRINT_FLAGS {
                if f.starts_with(typed) && !given.iter().any(|w| w.text == *f) {
                    out.push(cand(format!("{f} "), "print option", Style::Verb));
                }
            }
            if "proplist=".starts_with(typed) {
                out.push(cand("proplist=".into(), "columns to show", Style::Key));
            }
        }
        let has = |k: &str| {
            given
                .iter()
                .filter_map(|w| w.key.as_deref())
                .any(|g| parse::resolve_key(cmd, g).is_ok_and(|r| r == k))
        };
        // The first plain word may name an item.
        let listed = self.reg.menu(path).is_some_and(|m| m.print().is_some());
        if cmd.verb != "add"
            && cmd.verb != "print"
            && listed
            && !given.iter().any(|w| !w.is_pair())
            && let Some(p) = cmd.required().next()
        {
            for v in self.own_values(path, &p.key) {
                if v.starts_with(typed) {
                    out.push(cand(
                        format!("{} ", lex::quote(&v)),
                        kebab(&p.key),
                        Style::Item,
                    ));
                }
            }
        }
        for p in &cmd.params {
            let k = kebab(&p.key);
            if !has(&p.key) && k.starts_with(typed) {
                let note = if p.required {
                    format!("required: {}", p.ty_text)
                } else {
                    p.ty_text.clone()
                };
                out.push(cand(format!("{k}="), note, Style::Key));
            }
        }
        Completion {
            start,
            candidates: out,
        }
    }

    /// Complete the item after the last comma of a list value.
    fn list_values(&self, p: &Word, values: Vec<String>) -> Completion {
        let typed = p.value.as_str();
        let (head, tail) = match typed.rfind(',') {
            Some(i) => (
                typed.get(..=i).unwrap_or(""),
                typed.get(i + 1..).unwrap_or(""),
            ),
            None => ("", typed),
        };
        let taken: Vec<&str> = head.split(',').collect();
        Completion {
            start: p.value_start + head.len(),
            candidates: values
                .into_iter()
                .filter(|v| v.starts_with(tail) && !taken.contains(&v.as_str()))
                .map(|v| cand(v, "", Style::Value))
                .collect(),
        }
    }

    /// Values of field `key` in the menu's own last listing.
    fn own_values(&self, path: &[String], key: &str) -> Vec<String> {
        let Some(print) = self.reg.menu(path).and_then(|m| m.print()) else {
            return Vec::new();
        };
        let mut out = BTreeSet::new();
        for row in self.rows(&print.id) {
            if let Some(v) = row.get(key).filter(|v| !v.is_null()) {
                out.insert(value_text(v));
            }
        }
        out.into_iter().collect()
    }

    fn rows(&self, id: &str) -> &[Value] {
        self.cache
            .get(id)
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    fn interface_names(&self) -> Vec<String> {
        let Some(print) = self
            .reg
            .menu(&["interface".to_owned()])
            .and_then(|m| m.print())
        else {
            return Vec::new();
        };
        self.rows(&print.id)
            .iter()
            .filter_map(|r| r.get("name").and_then(Value::as_str))
            .map(str::to_owned)
            .collect()
    }

    /// Values offered for `key` of `cmd`.
    fn values(&self, path: &[String], cmd: &Command, key: &str) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let add = |v: String, out: &mut Vec<String>| {
            if !v.is_empty() && !out.contains(&v) {
                out.push(v);
            }
        };
        let param = cmd.param(key);
        match param.map(|p| &p.ty) {
            Some(Ty::Enum(vals)) => vals.iter().for_each(|v| add(v.clone(), &mut out)),
            Some(Ty::Bool) => {
                add("yes".into(), &mut out);
                add("no".into(), &mut out);
            }
            _ => {}
        }
        // `print where`: a property of the rows.
        if param.is_none() && cmd.verb == "print" {
            for row in self.rows(&cmd.id) {
                if let Some(v) = row.get(key) {
                    match v {
                        Value::Bool(_) => {
                            add("yes".into(), &mut out);
                            add("no".into(), &mut out);
                        }
                        other => add(value_text(other), &mut out),
                    }
                }
            }
        }
        let interfaces =
            INTERFACE_KEYS.contains(&key) || param.is_some_and(|p| p.ty_text.contains("interface"));
        if interfaces {
            for n in self.interface_names() {
                add(n, &mut out);
            }
        }
        for v in self.own_values(path, key) {
            add(v, &mut out);
        }
        if !matches!(param.map(|p| &p.ty), Some(Ty::Bool | Ty::Enum(_))) {
            let mut elsewhere = BTreeSet::new();
            for v in self.cache.values() {
                for row in v.as_array().map(Vec::as_slice).unwrap_or_default() {
                    if let Some(x) = row.get(key).filter(|x| x.is_string()) {
                        elsewhere.insert(value_text(x));
                    }
                }
            }
            for v in elsewhere {
                add(v, &mut out);
            }
        }
        out
    }

    /// Colors for a line being typed: known menus, commands, keys and
    /// values; an unknown name and what follows it in red. The spans cover
    /// the whole line.
    pub fn highlight(&self, line: &str) -> Vec<Span> {
        let mut spans: Vec<Span> = Vec::new();
        let mut push = |style: Style, text: &str| {
            if text.is_empty() {
                return;
            }
            match spans.last_mut() {
                Some(s) if s.style == style => s.text.push_str(text),
                _ => spans.push(Span {
                    style,
                    text: text.to_owned(),
                }),
            }
        };
        let mut last = 0usize;
        for (off, stmt) in parse::split(line) {
            for (start, end, style) in self.styles(stmt) {
                let s = floor_boundary(line, off + start);
                let e = floor_boundary(line, off + end);
                if s < last || e < s {
                    continue;
                }
                push(Style::Plain, line.get(last..s).unwrap_or(""));
                push(style, line.get(s..e).unwrap_or(""));
                last = e;
            }
        }
        push(Style::Plain, line.get(last..).unwrap_or(""));
        spans
    }

    /// `(start, end, style)` of the words of one statement.
    fn styles(&self, stmt: &str) -> Vec<(usize, usize, Style)> {
        let words = lex::words(stmt);
        let mut out = Vec::new();
        let absolute = words.first().is_some_and(|w| w.text.starts_with('/'));
        let mut path: Vec<String> = if absolute {
            Vec::new()
        } else {
            self.cwd.clone()
        };
        let mut verb: Option<&Command> = None;
        let mut failed = false;
        let mut in_where = false;
        for (i, w) in words.iter().enumerate() {
            if failed {
                out.push((w.start, w.end, Style::Error));
                continue;
            }
            if let Some(cmd) = verb {
                if in_where {
                    out.push((w.start, w.end, Style::Value));
                } else if w.text == "where" && cmd.verb == "print" {
                    in_where = true;
                    out.push((w.start, w.end, Style::Verb));
                } else if let Some(_k) = &w.key {
                    let split = w.value_start;
                    out.push((w.start, split, Style::Key));
                    out.push((split, w.end, Style::Value));
                } else if cmd.verb == "print" {
                    out.push((w.start, w.end, Style::Key));
                } else {
                    out.push((w.start, w.end, Style::Item));
                }
                continue;
            }
            // Path words; the first may be `/ip/address`.
            let segs: Vec<(usize, &str)> = if i == 0 && absolute {
                let mut v = Vec::new();
                let mut o = w.start;
                for part in w.text.split('/') {
                    if !part.is_empty() {
                        v.push((o, part));
                    }
                    o += part.len() + 1;
                }
                if v.is_empty() {
                    out.push((w.start, w.end, Style::Menu));
                }
                v
            } else {
                vec![(w.start, w.text.as_str())]
            };
            if i == 0 && absolute {
                out.push((w.start, w.start + 1, Style::Menu));
            }
            let single = segs.len() == 1 && !(i == 0 && absolute);
            for (o, seg) in segs {
                let end = if single { w.end } else { o + seg.len() };
                if failed || verb.is_some() {
                    out.push((o, end, Style::Error));
                    continue;
                }
                if seg == ".." {
                    path.pop();
                    out.push((o, end, Style::Menu));
                    continue;
                }
                if seg == "?" {
                    out.push((o, end, Style::Plain));
                    continue;
                }
                let Some(menu) = self.reg.menu(&path) else {
                    failed = true;
                    out.push((o, end, Style::Error));
                    continue;
                };
                let names = parse::names(&self.reg, menu, path.is_empty());
                match parse::pick(seg.trim_end_matches('?'), &names) {
                    Pick::One(n) if menu.children.contains_key(n) => {
                        path.push(n.to_owned());
                        out.push((o, end, Style::Menu));
                    }
                    Pick::One(n) => {
                        verb = menu.commands.get(n).or_else(|| {
                            self.reg
                                .aliases
                                .get(n)
                                .and_then(|id| self.reg.by_id(id))
                                .map(|(_, c)| c)
                        });
                        out.push((o, end, Style::Verb));
                        if verb.is_none() {
                            // Arguments of a built-in: color them as keys.
                            for w2 in words.get(i + 1..).unwrap_or_default() {
                                out.push((w2.start, w2.value_start, Style::Key));
                                out.push((w2.value_start, w2.end, Style::Value));
                            }
                            return out;
                        }
                    }
                    Pick::Many(_)
                        if !stmt.ends_with(char::is_whitespace) && i + 1 == words.len() =>
                    {
                        out.push((o, end, Style::Plain));
                    }
                    _ => {
                        failed = true;
                        out.push((o, end, Style::Error));
                    }
                }
            }
        }
        out.sort_by_key(|(s, _, _)| *s);
        out
    }
}
