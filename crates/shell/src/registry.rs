//! The menu tree, built from `engine.list` alone: the id `ip.address.add`
//! is the menu `/ip address` and the command `add`. Nothing here names a
//! command: a command the engine gains shows up in the terminal by itself.
//!
//! Verbs keep the id's last segment, except the read verbs, which take
//! RouterOS's name: `list` is `print`, and so is `get` in a menu without a
//! `list` (one-object menus such as `/ip neighbor discovery`).

use std::collections::BTreeMap;

use serde_json::Value;

use crate::doc::{self, Param, Shape};

/// Bounds on what a router may send (hostile input).
const MAX_COMMANDS: usize = 4096;
const MAX_ID: usize = 128;
const MAX_DEPTH: usize = 8;

#[derive(Debug, Clone)]
pub struct Command {
    /// Engine id: `ip.address.list`.
    pub id: String,
    /// The verb typed in the terminal: `print`.
    pub verb: String,
    pub label: String,
    /// The `params` doc as the engine wrote it.
    pub doc: String,
    pub params: Vec<Param>,
    pub shape: Shape,
    /// A query (no journal, no commit).
    pub query: bool,
    /// `Err(reason)` while the engine refuses it.
    pub enabled: Result<(), String>,
    /// Shortcut usable from any menu (`ping`).
    pub alias: Option<String>,
    /// The parameter a bare value goes to.
    pub positional: Option<String>,
    /// Starts a background task (`tool.task.poll` follows it).
    pub task: bool,
}

impl Command {
    pub fn param(&self, key: &str) -> Option<&Param> {
        self.params.iter().find(|p| p.key == key)
    }

    pub fn required(&self) -> impl Iterator<Item = &Param> {
        self.params.iter().filter(|p| p.required)
    }
}

#[derive(Debug, Clone, Default)]
pub struct Menu {
    pub children: BTreeMap<String, Menu>,
    /// By verb as typed.
    pub commands: BTreeMap<String, Command>,
}

impl Menu {
    /// The read command of this menu (`print`), if any.
    pub fn print(&self) -> Option<&Command> {
        self.commands.get("print")
    }

    /// A command by verb; the engine's `list` is accepted for `print`.
    pub fn command(&self, verb: &str) -> Option<&Command> {
        self.commands.get(verb).or_else(|| match verb {
            "list" => self.print().filter(|c| c.id.ends_with(".list")),
            _ => None,
        })
    }

    /// Menus below this one (itself included), depth first, with paths.
    pub fn walk<'a>(&'a self, path: &mut Vec<String>, out: &mut Vec<(Vec<String>, &'a Menu)>) {
        out.push((path.clone(), self));
        for (name, child) in &self.children {
            path.push(name.clone());
            child.walk(path, out);
            path.pop();
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct Registry {
    pub root: Menu,
    /// Command id → menu path, in `engine.list` order.
    pub order: Vec<(String, Vec<String>)>,
    /// Shortcut → command id (`ping` → `tool.ping.start`).
    pub aliases: BTreeMap<String, String>,
}

impl Registry {
    /// Build from an `engine.list` reply. Malformed entries are skipped.
    pub fn from_list(list: &Value) -> Self {
        let mut reg = Registry::default();
        let entries = list.as_array().map(Vec::as_slice).unwrap_or_default();
        let mut parsed: Vec<(Vec<String>, String, Command)> = Vec::new();
        for e in entries.iter().take(MAX_COMMANDS) {
            let Some(id) = e.get("id").and_then(Value::as_str) else {
                continue;
            };
            let segs: Vec<&str> = id.split('.').collect();
            let ok = id.len() <= MAX_ID
                && segs.len() >= 2
                && segs.len() <= MAX_DEPTH
                && segs.iter().all(|s| {
                    !s.is_empty()
                        && s.bytes()
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                });
            let Some((verb, menu)) = segs.split_last().filter(|_| ok) else {
                continue;
            };
            let text = |k: &str| e.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
            let doc_text = text("params");
            let word = |k: &str| {
                e.get(k)
                    .and_then(Value::as_str)
                    .filter(|a| a.len() <= 32 && !a.is_empty())
                    .map(str::to_owned)
            };
            let enabled = match e.get("enabled").and_then(Value::as_bool) {
                Some(false) => Err(e
                    .get("disabledReason")
                    .and_then(Value::as_str)
                    .unwrap_or("disabled")
                    .to_owned()),
                _ => Ok(()),
            };
            parsed.push((
                menu.iter().map(|s| (*s).to_owned()).collect(),
                (*verb).to_owned(),
                Command {
                    id: id.to_owned(),
                    verb: (*verb).to_owned(),
                    label: text("label"),
                    params: doc::params(&doc_text),
                    shape: doc::shape(&doc_text),
                    doc: doc_text,
                    query: e.get("kind").and_then(Value::as_str) == Some("query"),
                    enabled,
                    alias: word("alias")
                        .filter(|a| a.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')),
                    positional: word("positional"),
                    task: e.get("task").and_then(Value::as_bool) == Some(true),
                },
            ));
        }
        for (path, verb, mut cmd) in parsed.iter().cloned() {
            let has_list = parsed
                .iter()
                .any(|(p, v, _)| *p == path && v.as_str() == "list");
            cmd.verb = match verb.as_str() {
                "list" => "print".to_owned(),
                "get" if !has_list => "print".to_owned(),
                _ => verb,
            };
            let mut node = &mut reg.root;
            for seg in &path {
                node = node.children.entry(seg.clone()).or_default();
            }
            reg.order.push((cmd.id.clone(), path.clone()));
            node.commands.insert(cmd.verb.clone(), cmd);
        }
        // Shortcuts never hide a menu of the root.
        let aliases: Vec<(String, String)> = reg
            .commands()
            .filter_map(|(_, c)| c.alias.clone().map(|a| (a, c.id.clone())))
            .filter(|(a, _)| !reg.root.children.contains_key(a))
            .collect();
        for (a, id) in aliases {
            reg.aliases.entry(a).or_insert(id);
        }
        reg
    }

    pub fn menu(&self, path: &[String]) -> Option<&Menu> {
        let mut node = &self.root;
        for seg in path {
            node = node.children.get(seg)?;
        }
        Some(node)
    }

    /// A command by engine id, with its menu path.
    pub fn by_id(&self, id: &str) -> Option<(&[String], &Command)> {
        let (_, path) = self.order.iter().find(|(i, _)| i == id)?;
        let menu = self.menu(path)?;
        let cmd = menu.commands.values().find(|c| c.id == id)?;
        Some((path.as_slice(), cmd))
    }

    /// Every command with its path, in registry order.
    pub fn commands(&self) -> impl Iterator<Item = (&[String], &Command)> {
        self.order.iter().filter_map(|(id, _)| self.by_id(id))
    }

    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }
}

/// `/ip address` for a path.
pub fn path_text(path: &[String]) -> String {
    if path.is_empty() {
        "/".to_owned()
    } else {
        format!("/{}", path.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ids_become_menus_and_verbs() {
        let list = json!([
            {"id": "ip.address.add", "params": "{address: cidr, interface: string} → {id}", "kind": "action", "enabled": true},
            {"id": "ip.address.list", "params": "{} → [{id, address}]", "kind": "query", "enabled": true},
            {"id": "ip.neighbor.discovery.get", "params": "{} → {enabled}", "kind": "query", "enabled": true},
            {"id": "config.commit", "params": "{} → {revision}", "kind": "action", "enabled": false, "disabledReason": "no pending changes"},
            {"id": "BAD", "params": "{}"},
            {"params": "{}"},
        ]);
        let r = Registry::from_list(&list);
        let addr = r.menu(&["ip".into(), "address".into()]).unwrap();
        assert_eq!(addr.print().unwrap().id, "ip.address.list");
        assert_eq!(addr.command("list").unwrap().id, "ip.address.list");
        assert!(addr.command("add").is_some());
        let disc = r
            .menu(&["ip".into(), "neighbor".into(), "discovery".into()])
            .unwrap();
        assert_eq!(disc.print().unwrap().id, "ip.neighbor.discovery.get");
        let (_, commit) = r.by_id("config.commit").unwrap();
        assert_eq!(commit.enabled, Err("no pending changes".into()));
        assert_eq!(r.commands().count(), 4);
    }
}
