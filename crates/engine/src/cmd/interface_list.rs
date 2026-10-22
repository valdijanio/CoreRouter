//! /interface list — named groups of interfaces (G2.1). The firewall
//! matches them (`in_interface_list=WAN`); neighbor discovery may use them
//! later. New configs come with the empty lists LAN and WAN.

use corerouter_model::firewall::{Name, Table};
use corerouter_model::interface_list::{
    DEFAULT_LISTS, InterfaceList, InterfaceListMember, RESERVED,
};
use corerouter_model::{Config, IfName, ItemId};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_text, req_parse};
use super::{CommandSpec, always};
use corerouter_firewall::validate::{MAX_INTERFACE_LIST_MEMBERS, MAX_INTERFACE_LISTS};

use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "interface.list.add",
        "Add Interface List",
        ["Interfaces", "Interface List"],
        None,
        "{name: string (letters, digits, - _ .), comment?: string} → {name}",
        always,
        add
    ),
    cmd!(
        "interface.list.set",
        "Set Interface List",
        [],
        None,
        "{name: string, new_name?: string, comment?: string} → {name}",
        always,
        set
    ),
    cmd!(
        "interface.list.remove",
        "Remove Interface List",
        [],
        None,
        "{name: string (its members go too; refused while a firewall rule uses it)} → {name}",
        has_lists,
        remove
    ),
    cmd!(query "interface.list.list", "Interface Lists", ["Interfaces", "Interface List"], None,
        "{} → [{name, comment, default (LAN/WAN of a new config), members: [interface], used_by: [*id of firewall rules]}]",
        always, list),
    cmd!(
        "interface.list.member.add",
        "Add Interface List Member",
        ["Interfaces", "Interface List"],
        None,
        "{list: string, interface: string, disabled?: bool, comment?: string} → {id}",
        always,
        member_add
    ),
    cmd!(
        "interface.list.member.set",
        "Set Interface List Member",
        [],
        None,
        "{id: *hex, list?: string, interface?: string, disabled?: bool, comment?: string} → {id}",
        has_members,
        member_set
    ),
    cmd!(
        "interface.list.member.remove",
        "Remove Interface List Member",
        [],
        None,
        "{id: *hex} → {id}",
        has_members,
        member_remove
    ),
    cmd!(query "interface.list.member.list", "Interface List Members", ["Interfaces", "Interface List"], None,
        "{list?: string} → [{id, list, interface, flags (X disabled, I unknown interface), disabled, unknown, comment}]",
        always, member_list),
];

fn has_lists(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().interface_lists.lists.is_empty() {
        Err("there are no interface lists".into())
    } else {
        Ok(())
    }
}

fn has_members(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().interface_lists.members.is_empty() {
        Err("no interface is a member of a list".into())
    } else {
        Ok(())
    }
}

fn new_name(p: &Value, key: &str) -> Result<Name> {
    let name: Name = req_parse(p, key)?;
    if RESERVED.contains(&name.as_str()) {
        return Err(EngineError::bad(
            key,
            format!("'{name}' is reserved (RouterOS built-in list)"),
        ));
    }
    Ok(name)
}

fn existing_list(cfg: &Config, p: &Value, key: &str) -> Result<(usize, Name)> {
    let name: Name = req_parse(p, key)?;
    let pos = cfg
        .interface_lists
        .lists
        .iter()
        .position(|l| l.name == name)
        .ok_or_else(|| {
            EngineError::bad(
                key,
                format!("no interface list '{name}' (see interface.list.list)"),
            )
        })?;
    Ok((pos, name))
}

/// Firewall rules that name `list` (they would break without it).
fn used_by(cfg: &Config, list: &Name) -> Vec<String> {
    let mut out = Vec::new();
    for table in Table::ALL {
        for r in cfg.ip.firewall.rules(table) {
            let m = &r.matchers;
            if [&m.in_interface_list, &m.out_interface_list]
                .into_iter()
                .flatten()
                .any(|n| n.value == *list)
            {
                out.push(format!("{} {}", table.name(), r.id));
            }
        }
    }
    out
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let name = new_name(p, "name")?;
    let comment = opt_text(p, "comment", 256)?.unwrap_or_default();
    let cfg = s.store_mut().candidate_mut();
    if cfg.interface_lists.get(name.as_str()).is_some() {
        return Err(EngineError::bad(
            "name",
            format!("interface list '{name}' already exists"),
        ));
    }
    if cfg.interface_lists.lists.len() >= MAX_INTERFACE_LISTS {
        return Err(EngineError::bad(
            "name",
            format!("at most {MAX_INTERFACE_LISTS} lists"),
        ));
    }
    cfg.interface_lists.lists.push(InterfaceList {
        name: name.clone(),
        comment,
    });
    Ok(json!({ "name": name }))
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let renamed = match p.get("new_name") {
        None | Some(Value::Null) => None,
        Some(_) => Some(new_name(p, "new_name")?),
    };
    let comment = opt_text(p, "comment", 256)?;
    let cfg = s.store_mut().candidate_mut();
    let (pos, name) = existing_list(cfg, p, "name")?;
    let mut out = name.clone();
    if let Some(to) = renamed.filter(|to| *to != name) {
        if cfg.interface_lists.get(to.as_str()).is_some() {
            return Err(EngineError::bad(
                "new_name",
                format!("interface list '{to}' already exists"),
            ));
        }
        let users = used_by(cfg, &name);
        if !users.is_empty() {
            return Err(EngineError::bad(
                "new_name",
                format!(
                    "firewall rules use '{name}' ({}); change them first",
                    users.join(", ")
                ),
            ));
        }
        for m in &mut cfg.interface_lists.members {
            if m.list == name {
                m.list = to.clone();
            }
        }
        if let Some(l) = cfg.interface_lists.lists.get_mut(pos) {
            l.name = to.clone();
        }
        out = to;
    }
    if let Some(c) = comment
        && let Some(l) = cfg.interface_lists.lists.get_mut(pos)
    {
        l.comment = c;
    }
    Ok(json!({ "name": out }))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let cfg = s.store_mut().candidate_mut();
    let (pos, name) = existing_list(cfg, p, "name")?;
    if cfg.ipv6.settings.accept_router_advertisements_on == name {
        return Err(EngineError::bad(
            "name",
            format!(
                "ipv6 settings accept RA on '{name}'; set accept_router_advertisements_on to \
                 another list first (ipv6.settings.set)"
            ),
        ));
    }
    let users = used_by(cfg, &name);
    if !users.is_empty() {
        return Err(EngineError::bad(
            "name",
            format!(
                "firewall rules use '{name}' ({}); remove or change them first",
                users.join(", ")
            ),
        ));
    }
    cfg.interface_lists.lists.remove(pos);
    cfg.interface_lists.members.retain(|m| m.list != name);
    Ok(json!({ "name": name }))
}

fn list(s: &mut Session, _p: &Value) -> Result<Value> {
    let cfg = s.store().candidate();
    Ok(Value::Array(
        cfg.interface_lists
            .lists
            .iter()
            .map(|l| {
                let members: Vec<&IfName> =
                    cfg.interface_lists.interfaces_of(l.name.as_str()).collect();
                json!({
                    "name": l.name,
                    "comment": l.comment,
                    "default": DEFAULT_LISTS.contains(&l.name.as_str()),
                    "members": members,
                    "used_by": used_by(cfg, &l.name),
                })
            })
            .collect(),
    ))
}

fn member_pos(cfg: &Config, id: ItemId) -> Result<usize> {
    cfg.interface_lists
        .members
        .iter()
        .position(|m| m.id == id)
        .ok_or_else(|| {
            EngineError::bad(
                "id",
                format!("no interface list member {id} (see interface.list.member.list)"),
            )
        })
}

fn check_member(cfg: &Config, m: &InterfaceListMember, interface_changed: bool) -> Result<()> {
    if cfg.interface_lists.get(m.list.as_str()).is_none() {
        return Err(EngineError::bad(
            "list",
            format!("no interface list '{}' (see interface.list.list)", m.list),
        ));
    }
    if interface_changed && !cfg.interfaces.contains_key(&m.interface) {
        return Err(EngineError::bad(
            "interface",
            format!("interface '{}' does not exist", m.interface),
        ));
    }
    if cfg
        .interface_lists
        .members
        .iter()
        .any(|o| o.id != m.id && o.list == m.list && o.interface == m.interface)
    {
        return Err(EngineError::bad(
            "interface",
            format!("{} is already a member of {}", m.interface, m.list),
        ));
    }
    Ok(())
}

fn member_add(s: &mut Session, p: &Value) -> Result<Value> {
    let list: Name = req_parse(p, "list")?;
    let interface: IfName = req_parse(p, "interface")?;
    let disabled = opt_bool(p, "disabled")?.unwrap_or(false);
    let comment = opt_text(p, "comment", 256)?.unwrap_or_default();
    let cfg = s.store_mut().candidate_mut();
    if cfg.interface_lists.members.len() >= MAX_INTERFACE_LIST_MEMBERS {
        return Err(EngineError::bad(
            "list",
            format!("at most {MAX_INTERFACE_LIST_MEMBERS} members"),
        ));
    }
    let mut m = InterfaceListMember {
        id: ItemId(0),
        list,
        interface,
        disabled,
        comment,
    };
    check_member(cfg, &m, true)?;
    m.id = cfg.interface_lists.next_member_id();
    let id = m.id;
    cfg.interface_lists.members.push(m);
    Ok(json!({ "id": id }))
}

fn member_set(s: &mut Session, p: &Value) -> Result<Value> {
    let id: ItemId = req_parse(p, "id")?;
    let list: Option<Name> = opt_parse(p, "list")?;
    let interface: Option<IfName> = opt_parse(p, "interface")?;
    let disabled = opt_bool(p, "disabled")?;
    let comment = opt_text(p, "comment", 256)?;
    let cfg = s.store_mut().candidate_mut();
    let pos = member_pos(cfg, id)?;
    let mut m = cfg
        .interface_lists
        .members
        .get(pos)
        .cloned()
        .ok_or_else(|| EngineError::bad("id", format!("no member {id}")))?;
    let changed = interface.as_ref().is_some_and(|i| *i != m.interface);
    if let Some(l) = list {
        m.list = l;
    }
    if let Some(i) = interface {
        m.interface = i;
    }
    if let Some(d) = disabled {
        m.disabled = d;
    }
    if let Some(c) = comment {
        m.comment = c;
    }
    check_member(cfg, &m, changed)?;
    if let Some(slot) = cfg.interface_lists.members.get_mut(pos) {
        *slot = m;
    }
    Ok(json!({ "id": id }))
}

fn member_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let id: ItemId = req_parse(p, "id")?;
    let cfg = s.store_mut().candidate_mut();
    let pos = member_pos(cfg, id)?;
    cfg.interface_lists.members.remove(pos);
    Ok(json!({ "id": id }))
}

fn member_list(s: &mut Session, p: &Value) -> Result<Value> {
    let filter: Option<Name> = opt_parse(p, "list")?;
    let cfg = s.store().candidate();
    Ok(Value::Array(
        cfg.interface_lists
            .members
            .iter()
            .filter(|m| filter.as_ref().is_none_or(|f| *f == m.list))
            .map(|m| {
                let unknown = !cfg.interfaces.contains_key(&m.interface);
                let mut flags = String::new();
                if m.disabled {
                    flags.push('X');
                }
                if unknown {
                    flags.push('I');
                }
                json!({
                    "id": m.id,
                    "list": m.list,
                    "interface": m.interface,
                    "flags": flags,
                    "disabled": m.disabled,
                    "unknown": unknown,
                    "comment": m.comment,
                })
            })
            .collect(),
    ))
}
