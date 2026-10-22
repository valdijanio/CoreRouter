//! `/export`: a script of terminal commands that rebuilds the running
//! configuration, read back from the router's own `print` commands.
//!
//! Nothing here names a command. For every menu with a `print` (and no
//! required parameter):
//!
//! - a list menu: each row becomes the menu's `add` — or the `add` of the
//!   sub-menu named by the row's `type` (`/interface` rows of type `vlan`
//!   use `/interface vlan add`) — with the parameters that `add` declares;
//!   fields `add` does not take but the menu's `set` does follow as a `set`
//!   (`/interface set name=vlan10 disabled=yes`). Rows without an `add`
//!   (physical ports, BGP instances) become a `set`, and so do rows the
//!   router marks `default=yes` (they exist in every new config, like the
//!   interface lists LAN and WAN, so `add` would fail on import). Dynamic
//!   rows (flag `D`, `dynamic=yes`) are not configuration and are skipped.
//! - a one-object menu (`get`): one `set` with every field `set` declares.
//!
//! Order is safe for import: each line comes after the lines creating the
//! names it mentions (a VLAN after its parent bridge, an address after its
//! VRF, a route after the VRF of its table), otherwise registry order.
//! Output is deterministic: no timestamps, stable order.
//!
//! Secrets never leave in plain text: a field whose name says it is one is
//! replaced by a commented line, and so is a row missing a required `add`
//! parameter (the router does not return passwords).
//!
//! Layout, as RouterOS prints it: a command wider than the terminal goes on
//! with ` \` and the next line indented four spaces ([`wrap`]), breaking
//! between arguments only (a quoted value is never cut); `/import` joins
//! them back. `/export terse` ([`terse`]) writes one line per item with its
//! menu in front, never wrapped, for scripts and grep.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::doc::kebab;
use crate::format::value_text;
use crate::lex::quote;
use crate::registry::{Command, Menu, Registry, path_text};

/// Field names never exported in clear.
const SECRET_WORDS: &[&str] = &["password", "secret", "psk", "token", "private"];

fn secret(key: &str) -> bool {
    SECRET_WORDS.iter().any(|w| key.contains(w))
}

/// The read commands an export needs, by id.
pub fn reads(reg: &Registry) -> Vec<String> {
    let mut all = Vec::new();
    let mut path = Vec::new();
    reg.root.walk(&mut path, &mut all);
    all.into_iter()
        .filter_map(|(_, menu)| {
            let p = menu.print()?;
            let writes = menu.commands.contains_key("add")
                || menu.commands.contains_key("set")
                || menu
                    .children
                    .values()
                    .any(|c| c.commands.contains_key("add"));
            (writes && p.required().next().is_none()).then(|| p.id.clone())
        })
        .collect()
}

#[derive(Debug, Clone)]
struct Out {
    path: Vec<String>,
    verb: String,
    args: Vec<(String, String)>,
    /// A commented line (not configuration).
    note: Option<String>,
    provides: Option<String>,
    requires: Vec<String>,
}

fn empty(v: &Value) -> bool {
    match v {
        Value::Null | Value::Bool(false) => true,
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        _ => false,
    }
}

/// The text a value is typed as.
fn arg_text(v: &Value) -> String {
    value_text(v)
}

/// Not configuration: dynamic rows, and rows the router says it does not
/// manage (`managed=no`: links of the host it leaves alone).
fn dynamic(row: &Value) -> bool {
    row.get("managed").and_then(Value::as_bool) == Some(false)
        || row.get("dynamic").and_then(Value::as_bool) == Some(true)
        || row
            .get("flags")
            .and_then(Value::as_str)
            .is_some_and(|f| f.contains('D'))
}

/// Arguments of `cmd` taken from `row`: required ones always, optional ones
/// unless empty (`all`: optional ones too, for one-object settings).
fn args_of(cmd: &Command, row: &Value, all: bool) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for p in &cmd.params {
        let v = row.get(&p.key).unwrap_or(&Value::Null);
        if secret(&p.key) {
            if p.required || !empty(v) {
                return Err(format!("{} is not exported", kebab(&p.key)));
            }
            continue;
        }
        if p.required && v.is_null() {
            return Err(format!("{} is not exported", kebab(&p.key)));
        }
        // `false` is the default of a bool, unless its doc says otherwise
        // (`passthrough?: bool (default true)`).
        let meaningful_false = v == &Value::Bool(false) && p.ty_text.contains("default true");
        let keep = p.required || meaningful_false || if all { !v.is_null() } else { !empty(v) };
        if keep {
            out.push((p.key.clone(), arg_text(v)));
        }
    }
    Ok(out)
}

fn requires_of(args: &[(String, String)], skip: Option<&str>) -> Vec<String> {
    let mut out = Vec::new();
    for (_, v) in args {
        for part in v.split([',', '%']) {
            if !part.is_empty() && Some(part) != skip && !out.iter().any(|o| o == part) {
                out.push(part.to_owned());
            }
        }
    }
    out
}

/// `generators`: sibling menus that create rows here (a row with
/// `<sibling>=true` was generated by that menu, whose own export recreates
/// it: `/ip firewall filter` rows with `zone=yes` come from
/// `/ip firewall zone`). Exporting them too would duplicate them on import.
fn rows_of(
    menu_path: &[String],
    menu: &Menu,
    generators: &[&str],
    value: &Value,
    out: &mut Vec<Out>,
) {
    let Some(print) = menu.print() else { return };
    let set = menu.commands.get("set");
    if !print.shape.list {
        if let Some(set) = set
            && value.is_object()
        {
            if args_of(set, value, true).is_err()
                && let Some(items) = set_items(set, value)
            {
                // A settings object holding a list of entries, each one
                // `set` (the zone matrix: `cells` of {from, to, action}).
                for item in items {
                    push(out, menu_path, set, item, false, false);
                }
            } else {
                push(out, menu_path, set, value, true, false);
            }
        }
        return;
    }
    for row in value.as_array().map(Vec::as_slice).unwrap_or_default() {
        if dynamic(row)
            || generators
                .iter()
                .any(|g| row.get(*g).and_then(Value::as_bool) == Some(true))
        {
            continue;
        }
        let typed = row
            .get("type")
            .and_then(Value::as_str)
            .and_then(|t| menu.children.get(t).map(|m| (t, m)))
            .and_then(|(t, m)| m.commands.get("add").map(|c| (t, c)));
        // Present in every new config: set, never add.
        let preset = row.get("default").and_then(Value::as_bool) == Some(true);
        let (add_path, add) = match typed {
            Some((t, c)) => {
                let mut p = menu_path.to_vec();
                p.push(t.to_owned());
                (p, Some(c))
            }
            None => (menu_path.to_vec(), menu.commands.get("add")),
        };
        let add = add.filter(|_| !preset);
        match (add, set) {
            (Some(add), _) => {
                if !push(out, &add_path, add, row, false, true) {
                    continue;
                }
                // What `add` cannot take, `set` sets afterwards.
                if let Some(set) = set {
                    let key = set.required().next().map(|p| p.key.clone());
                    let extra: Vec<(String, String)> = set
                        .params
                        .iter()
                        .filter(|p| add.param(&p.key).is_none() && !p.required)
                        .filter(|p| !secret(&p.key))
                        .filter_map(|p| row.get(&p.key).filter(|v| !empty(v)).map(|v| (p, v)))
                        .map(|(p, v)| (p.key.clone(), arg_text(v)))
                        .collect();
                    if let (Some(key), false) = (key, extra.is_empty()) {
                        let Some(item) = row.get(&key).map(arg_text) else {
                            continue;
                        };
                        let mut args = vec![(key.clone(), item.clone())];
                        args.extend(extra);
                        out.push(Out {
                            path: menu_path.to_vec(),
                            verb: set.verb.clone(),
                            requires: requires_of(&args, None),
                            args,
                            note: None,
                            provides: None,
                        });
                    }
                }
            }
            (None, Some(set)) => {
                push(out, menu_path, set, row, false, false);
            }
            (None, None) => {}
        }
    }
}

/// The entries of the first array in `value` whose items carry every
/// parameter `set` requires.
fn set_items<'a>(set: &Command, value: &'a Value) -> Option<&'a [Value]> {
    value.as_object()?.values().find_map(|v| {
        let items = v.as_array()?;
        let fits = |i: &Value| {
            set.required()
                .all(|p| i.get(&p.key).is_some_and(|v| !v.is_null()))
        };
        (!items.is_empty() && items.iter().all(fits)).then_some(items.as_slice())
    })
}

/// One line for `cmd` from `row`; a note instead when something cannot be
/// exported. Returns whether a real line was written.
fn push(
    out: &mut Vec<Out>,
    path: &[String],
    cmd: &Command,
    row: &Value,
    all: bool,
    creates: bool,
) -> bool {
    match args_of(cmd, row, all) {
        Ok(args) => {
            let provides = if creates {
                args.iter()
                    .find(|(k, _)| k == "name")
                    .map(|(_, v)| v.clone())
            } else {
                None
            };
            out.push(Out {
                path: path.to_vec(),
                verb: cmd.verb.clone(),
                requires: requires_of(&args, provides.as_deref()),
                provides,
                args,
                note: None,
            });
            true
        }
        Err(why) => {
            let name = row
                .get("name")
                .map(arg_text)
                .map(|n| format!(" name={}", quote(&n)))
                .unwrap_or_default();
            out.push(Out {
                path: path.to_vec(),
                verb: cmd.verb.clone(),
                args: Vec::new(),
                note: Some(format!("{}{name}: {why}", cmd.verb)),
                provides: None,
                requires: Vec::new(),
            });
            false
        }
    }
}

/// Stable topological order: a line waits for the lines providing the names
/// it requires; ties (and cycles) keep the original order.
fn order(lines: Vec<Out>) -> Vec<Out> {
    let provided: BTreeMap<String, usize> = lines
        .iter()
        .enumerate()
        .filter_map(|(i, l)| l.provides.clone().map(|p| (p, i)))
        .collect();
    let deps: Vec<Vec<usize>> = lines
        .iter()
        .enumerate()
        .map(|(i, l)| {
            l.requires
                .iter()
                .filter_map(|r| provided.get(r).copied())
                .filter(|&j| j != i)
                .collect()
        })
        .collect();
    let mut done = vec![false; lines.len()];
    let mut order = Vec::with_capacity(lines.len());
    while order.len() < lines.len() {
        let next = (0..lines.len()).find(|&i| {
            !done.get(i).copied().unwrap_or(true)
                && deps
                    .get(i)
                    .is_some_and(|d| d.iter().all(|&j| done.get(j).copied().unwrap_or(true)))
        });
        // A cycle: take the first line left, as listed.
        let Some(i) =
            next.or_else(|| (0..lines.len()).find(|&i| !done.get(i).copied().unwrap_or(true)))
        else {
            break;
        };
        if let Some(d) = done.get_mut(i) {
            *d = true;
        }
        order.push(i);
    }
    let mut slots: Vec<Option<Out>> = lines.into_iter().map(Some).collect();
    order
        .into_iter()
        .filter_map(|i| slots.get_mut(i).and_then(Option::take))
        .collect()
}

/// The script for the menus under `prefix` (all of them for `/`), from the
/// replies to [`reads`] (by command id).
pub fn script(
    reg: &Registry,
    prefix: &[String],
    results: &BTreeMap<String, Value>,
    version: &str,
) -> String {
    let mut all = Vec::new();
    let mut path = Vec::new();
    reg.root.walk(&mut path, &mut all);
    let mut lines = Vec::new();
    for (menu_path, menu) in all {
        let Some(print) = menu.print() else { continue };
        let Some(value) = results.get(&print.id) else {
            continue;
        };
        let parent = menu_path
            .split_last()
            .and_then(|(_, up)| up.iter().try_fold(&reg.root, |m, k| m.children.get(k)));
        let generators: Vec<&str> = parent
            .map(|p| {
                p.children
                    .iter()
                    .filter(|(name, m)| {
                        Some(*name) != menu_path.last() && m.commands.contains_key("set")
                    })
                    .map(|(name, _)| name.as_str())
                    .collect()
            })
            .unwrap_or_default();
        rows_of(&menu_path, menu, &generators, value, &mut lines);
    }
    let lines = order(lines);
    let mut s = String::new();
    s.push_str(&format!(
        "# CoreRouter {version} configuration: export of {}\n",
        path_text(prefix)
    ));
    s.push_str("# Import with /import file=<name> (or paste it): it runs as one atomic batch.\n");
    let mut cur: Option<Vec<String>> = None;
    for l in lines.iter().filter(|l| l.path.starts_with(prefix)) {
        if cur.as_ref() != Some(&l.path) {
            s.push_str(&path_text(&l.path));
            s.push('\n');
            cur = Some(l.path.clone());
        }
        if let Some(note) = &l.note {
            s.push_str(&format!("# {note}\n"));
            continue;
        }
        s.push_str(&l.verb);
        for (k, v) in &l.args {
            s.push(' ');
            s.push_str(&kebab(k));
            s.push('=');
            s.push_str(&quote(v));
        }
        s.push('\n');
    }
    s
}

/// Width of an export with no terminal (a file, a pipe): RouterOS's 80.
pub const DEFAULT_WIDTH: usize = 80;

/// Indent of a continued line.
const INDENT: &str = "    ";

/// `script` with every command line wider than `width` characters broken
/// between arguments: ` \` ends a broken line, the next starts with four
/// spaces. Comments and menu lines stay as they are, and so does an
/// argument wider than the whole line (it gets a line of its own).
pub fn wrap(script: &str, width: usize) -> String {
    let mut out = String::with_capacity(script.len() + script.len() / 16);
    for line in script.lines() {
        if line.starts_with('#') || line.starts_with('/') || line.chars().count() <= width {
            out.push_str(line);
            out.push('\n');
            continue;
        }
        let words = crate::lex::words(line);
        let n = words.len();
        let mut cur = String::new();
        for (i, w) in words.iter().enumerate() {
            let word = line.get(w.start..w.end).unwrap_or("");
            if cur.is_empty() {
                cur.push_str(word);
                continue;
            }
            // A broken line keeps room for its ` \`; the last one does not
            // need it.
            let room = if i + 1 == n {
                width
            } else {
                width.saturating_sub(2)
            };
            let fits = cur.chars().count() + 1 + word.chars().count() <= room;
            if fits {
                cur.push(' ');
                cur.push_str(word);
            } else {
                out.push_str(&cur);
                out.push_str(" \\\n");
                cur = format!("{INDENT}{word}");
            }
        }
        out.push_str(&cur);
        out.push('\n');
    }
    out
}

/// `script` with one line per item and the menu in front of each
/// (`/ip address add address=… interface=…`), as `/export terse`: what a
/// script or grep wants. Notes keep their menu too.
pub fn terse(script: &str) -> String {
    let mut out = String::with_capacity(script.len() * 2);
    let mut menu: Option<&str> = None;
    for line in script.lines() {
        match (menu, line.strip_prefix("# ")) {
            _ if line.starts_with('/') => {
                menu = Some(line);
                continue;
            }
            (Some(m), Some(note)) => out.push_str(&format!("# {m} {note}")),
            (Some(m), None) if !line.starts_with('#') => out.push_str(&format!("{m} {line}")),
            _ => out.push_str(line),
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn unmanaged_and_dynamic_rows_are_not_exported() {
        let reg = Registry::from_list(&json!([
            {"id": "interface.list", "params": "{} → [{name, type, managed, mtu}]", "kind": "query", "enabled": true},
            {"id": "interface.set", "params": "{name: string, mtu?: u32} → {name}", "kind": "action", "enabled": true},
            {"id": "interface.bridge.add", "params": "{name: string} → {name}", "kind": "action", "enabled": true},
        ]));
        let mut results = BTreeMap::new();
        results.insert(
            "interface.list".to_owned(),
            json!([
                {"name": "ether1", "type": "ether", "managed": true, "mtu": 1500},
                {"name": "docker0", "type": "bridge", "managed": false, "mtu": 1500},
                {"name": "br1", "type": "bridge", "managed": true, "mtu": 1500, "dynamic": false},
                {"name": "dyn", "type": "bridge", "dynamic": true},
            ]),
        );
        let s = script(&reg, &[], &results, "t");
        assert!(s.contains("set name=ether1 mtu=1500"), "{s}");
        assert!(s.contains("add name=br1"), "{s}");
        assert!(!s.contains("docker0") && !s.contains("dyn\n"), "{s}");
    }

    #[test]
    fn wrap_breaks_between_arguments_and_indents() {
        let line = "add interface=ether1 add-default-route=yes use-peer-dns=yes use-peer-ntp=yes comment=\"uplink to the ISP\"";
        let s = wrap(&format!("/ip dhcp-client\n{line}\n"), 40);
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(
            lines,
            [
                "/ip dhcp-client",
                "add interface=ether1 \\",
                "    add-default-route=yes \\",
                "    use-peer-dns=yes use-peer-ntp=yes \\",
                "    comment=\"uplink to the ISP\"",
            ]
        );
        for l in &lines {
            assert!(l.chars().count() <= 40, "{l:?}");
        }
        // Joined back as /import does, it is the same command.
        let joined: String = lines
            .iter()
            .skip(1)
            .map(|l| l.strip_suffix('\\').unwrap_or(l))
            .collect();
        let words = |t: &str| {
            crate::lex::words(t)
                .into_iter()
                .map(|w| w.text)
                .collect::<Vec<_>>()
        };
        assert_eq!(words(&joined), words(line));
    }

    #[test]
    fn wrap_never_cuts_a_value_and_leaves_short_lines_alone() {
        let long = "x".repeat(60);
        let s = wrap(
            &format!("set a=1 comment=\"{long} y\" b=2\nset c=3\n# {long}\n"),
            30,
        );
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(
            lines,
            [
                "set a=1 \\",
                &format!("    comment=\"{long} y\" \\"),
                "    b=2",
                "set c=3",
                &format!("# {long}"),
            ]
        );
        // Wide enough: unchanged.
        let one = "add name=br1 comment=\"a b\"\n";
        assert_eq!(wrap(one, 80), one);
    }

    #[test]
    fn terse_puts_the_menu_on_every_line() {
        let s = "# header\n/interface bridge\nadd name=br1\n# add name=x: password is not exported\n/ip address\nadd address=10.0.0.1/24 interface=br1\n";
        assert_eq!(
            terse(s),
            "# header\n/interface bridge add name=br1\n# /interface bridge add name=x: password is not exported\n/ip address add address=10.0.0.1/24 interface=br1\n"
        );
    }
}
