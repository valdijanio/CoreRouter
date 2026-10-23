//! Command registry. One file per area; each defines `COMMANDS` with `cmd!`.
//!
//! Adding behavior = adding a `CommandSpec` to an area (`cmd/<area>.rs`,
//! picked up by `build.rs`: a new area is a new file) + a test. The `params` string
//! is the contract read by humans, agents (`list_commands`) and the engine:
//! `check_params` rejects keys it does not declare and required keys missing.

use serde_json::{Value, json};

use crate::error::suggest;
use crate::{EngineError, Result, Session};

pub type Run = fn(&mut Session, &Value) -> Result<Value>;
pub type Enabled = fn(&Session) -> std::result::Result<(), String>;

pub struct CommandSpec {
    /// Dotted id, RouterOS menu style: "ip.address.add".
    pub id: &'static str,
    pub label: &'static str,
    /// UI menu path; empty = not shown in menus.
    pub menu: &'static [&'static str],
    pub shortcut: Option<&'static str>,
    /// Compact signature: `{key: type, opt?: type} → result`.
    pub params: &'static str,
    /// `Err(reason)` explains why the command cannot run now.
    pub enabled: Enabled,
    pub run: Run,
    /// false for queries: no journal entry, no auto-commit.
    pub journal: bool,
    /// Terminal: shortcuts usable from any menu (`ping` for
    /// `tool.ping.start`); several are comma-separated (`"traceroute,mtr"`).
    /// A menu named like one of its commands' aliases also runs it
    /// (`/tool ping 8.8.8.8`).
    pub alias: Option<&'static str>,
    /// Terminal: the parameter a bare value goes to (`ping 8.8.8.8`).
    pub positional: Option<&'static str>,
    /// Starts a background task: the result carries its `id`, read with
    /// `tool.task.poll` and ended with `tool.task.stop`.
    pub task: bool,
}

impl CommandSpec {
    /// Root shortcut in the terminal: `cmd!(…).alias("ping")`.
    pub const fn alias(mut self, alias: &'static str) -> Self {
        self.alias = Some(alias);
        self
    }

    /// Parameter that takes a bare value in the terminal.
    pub const fn positional(mut self, key: &'static str) -> Self {
        self.positional = Some(key);
        self
    }

    /// The command starts a background task.
    pub const fn task(mut self) -> Self {
        self.task = true;
        self
    }
}

/// One line per command:
/// `cmd!("ip.address.add", "Add Address", ["IP", "Addresses"], None, "{...} → {id}", always, add)`
/// Prefix with `query` for read-only commands.
macro_rules! cmd {
    (query $id:literal, $label:literal, [$($menu:literal),* $(,)?], $shortcut:expr, $params:literal, $enabled:path, $run:path) => {
        $crate::cmd::CommandSpec { id: $id, label: $label, menu: &[$($menu),*], shortcut: $shortcut,
            params: $params, enabled: $enabled, run: $run, journal: false,
            alias: None, positional: None, task: false }
    };
    ($id:literal, $label:literal, [$($menu:literal),* $(,)?], $shortcut:expr, $params:literal, $enabled:path, $run:path) => {
        $crate::cmd::CommandSpec { id: $id, label: $label, menu: &[$($menu),*], shortcut: $shortcut,
            params: $params, enabled: $enabled, run: $run, journal: true,
            alias: None, positional: None, task: false }
    };
}

// Every `cmd/<area>.rs` is a module and, when it defines `COMMANDS`, an
// area: `build.rs` lists them (file-name order), so a new area is just a new
// file. `args` (parameter helpers) is a module like the rest.
include!(concat!(env!("OUT_DIR"), "/cmd_areas.rs"));

pub fn all() -> impl Iterator<Item = &'static CommandSpec> {
    AREAS.iter().flat_map(|area| area.iter())
}

/// Every command by id, with its declared parameter keys, built once:
/// `execute` looked the id up by a linear scan of the registry (twice) and
/// re-parsed the `params` doc on every call (audit-perf).
type Index = std::collections::HashMap<&'static str, (&'static CommandSpec, Vec<(&'static str, bool)>)>;

fn index() -> &'static Index {
    static INDEX: std::sync::OnceLock<Index> = std::sync::OnceLock::new();
    INDEX.get_or_init(|| {
        let mut index = Index::new();
        for c in all() {
            // The first wins, as the scan did (ids are unique: tested).
            index.entry(c.id).or_insert_with(|| (c, doc_keys(c.params)));
        }
        index
    })
}

pub fn find(id: &str) -> Option<&'static CommandSpec> {
    index().get(id).map(|(c, _)| *c)
}

/// [`doc_keys`] of `spec`, parsed once for the registered commands.
fn declared_keys(spec: &CommandSpec) -> std::borrow::Cow<'static, [(&'static str, bool)]> {
    match index().get(spec.id) {
        Some((c, keys)) if c.params == spec.params => std::borrow::Cow::Borrowed(keys.as_slice()),
        _ => std::borrow::Cow::Owned(doc_keys(spec.params)),
    }
}

pub fn unknown_command(id: &str) -> EngineError {
    EngineError::UnknownCommand {
        id: id.chars().take(128).collect(),
        suggestion: suggest(id, all().map(|c| c.id)),
    }
}

/// Always enabled.
pub fn always(_: &Session) -> std::result::Result<(), String> {
    Ok(())
}

/// Declared parameter keys of a `params` doc, with `required` flags.
/// Only top-level keys of the first `{...}` before `→`/`->` count.
pub fn doc_keys(doc: &str) -> Vec<(&str, bool)> {
    let input = doc.split('→').next().unwrap_or(doc);
    let input = input.split("->").next().unwrap_or(input).trim();
    let Some(body) = input.strip_prefix('{').and_then(|s| s.strip_suffix('}')) else {
        return Vec::new();
    };
    let mut keys = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    let mut parts = Vec::new();
    for (i, ch) in body.char_indices() {
        match ch {
            '{' | '[' | '(' => depth += 1,
            '}' | ']' | ')' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(body.get(start..i).unwrap_or(""));
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(body.get(start..).unwrap_or(""));
    for part in parts {
        let name = part.split(':').next().unwrap_or("").trim();
        if name.is_empty() {
            continue;
        }
        match name.strip_suffix('?') {
            Some(opt) => keys.push((opt.trim(), false)),
            None => keys.push((name, true)),
        }
    }
    keys
}

/// Reject non-object params, unknown keys (with a suggestion) and missing
/// required keys — before the command runs.
pub fn check_params(spec: &CommandSpec, params: &Value) -> Result<()> {
    let declared = declared_keys(spec);
    let empty = serde_json::Map::new();
    let obj = match params {
        Value::Null => &empty,
        Value::Object(o) => o,
        _ => return Err(EngineError::bad("params", "must be a JSON object")),
    };
    for key in obj.keys() {
        if !declared.iter().any(|(k, _)| k == key) {
            return Err(EngineError::UnknownParam {
                param: key.chars().take(64).collect(),
                suggestion: suggest(key, declared.iter().map(|(k, _)| *k)),
            });
        }
    }
    for &(key, required) in declared.iter() {
        if required && obj.get(key).is_none_or(Value::is_null) {
            return Err(EngineError::bad(key, "is required"));
        }
    }
    Ok(())
}

/// Registry as JSON, for `list_commands` and the UI.
pub fn describe(session: &Session) -> Value {
    Value::Array(
        all()
            .map(|c| {
                let enabled = session
                    .permit(crate::auth::required_group(c.id, c.journal))
                    .and_then(|()| (c.enabled)(session));
                json!({
                    "id": c.id,
                    "label": c.label,
                    "menu": c.menu,
                    "shortcut": c.shortcut,
                    "params": c.params,
                    "kind": if c.journal { "action" } else { "query" },
                    "enabled": enabled.is_ok(),
                    "disabledReason": enabled.err(),
                    "alias": c.alias,
                    "positional": c.positional,
                    "task": c.task,
                })
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn ids_are_unique_and_well_formed() {
        let mut seen = HashSet::new();
        for c in all() {
            assert!(seen.insert(c.id), "duplicate id {}", c.id);
            let ok = c.id.split('.').count() >= 2
                && c.id.split('.').all(|seg| {
                    !seg.is_empty()
                        && seg
                            .bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                });
            assert!(ok, "bad id {}", c.id);
            assert!(!c.label.is_empty(), "{} has no label", c.id);
        }
    }

    #[test]
    fn every_params_doc_parses() {
        for c in all() {
            assert!(
                c.params.starts_with('{'),
                "{}: params must start with '{{'",
                c.id
            );
            assert!(
                c.params.contains('→'),
                "{}: params must document the result",
                c.id
            );
            for (k, _) in doc_keys(c.params) {
                assert!(
                    k.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                    "{}: bad key '{k}'",
                    c.id
                );
            }
        }
    }

    #[test]
    fn terminal_metadata_is_consistent() {
        let mut aliases = HashSet::new();
        let roots: HashSet<&str> = all().filter_map(|c| c.id.split('.').next()).collect();
        for c in all() {
            for a in c.alias.into_iter().flat_map(|a| a.split(',')) {
                assert!(aliases.insert(a), "alias {a} used twice");
                assert!(!roots.contains(a), "alias {a} hides the menu /{a}");
                assert!(
                    !a.is_empty() && a.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'),
                    "bad alias {a}"
                );
            }
            if let Some(p) = c.positional {
                assert!(
                    doc_keys(c.params).iter().any(|(k, _)| *k == p),
                    "{}: positional '{p}' is not a parameter",
                    c.id
                );
            }
        }
    }

    #[test]
    fn builders_set_the_metadata() {
        let c =
            cmd!(query "x.y.start", "X", [], None, "{address: ip} → {id}", always, describe_stub)
                .alias("xy")
                .positional("address")
                .task();
        assert_eq!(
            (c.alias, c.positional, c.task),
            (Some("xy"), Some("address"), true)
        );
    }

    fn describe_stub(_: &mut Session, _: &Value) -> Result<Value> {
        Ok(Value::Null)
    }

    #[test]
    fn doc_keys_handles_nesting() {
        let keys = doc_keys("{steps: [{command, params?}], atomic?: bool} → {results}");
        assert_eq!(keys, vec![("steps", true), ("atomic", false)]);
        assert!(doc_keys("{} → {}").is_empty());
    }
}
