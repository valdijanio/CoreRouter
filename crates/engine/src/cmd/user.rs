//! /user — router accounts (G0.3). All need group `full`
//! ([`crate::auth::required_group`]).
//!
//! Accounts change at once (no candidate, no commit) and are saved with the
//! config, outside its revisions: `config.rollback` never restores an old
//! password. Changes are refused in Safe Mode, which could not undo them.
//! Passwords are hashed here (Argon2id) and never echoed, journaled or
//! returned; `user.list` shows no hash either, only `no_password` for an
//! account that has none (the first `admin`, G0.3b). A password cannot be
//! taken away by a command: only `corerouter-daemon --reset-admin-password`
//! does that, at start-up.

use corerouter_model::users::check_name;
use corerouter_model::{Group, User};
use serde_json::{Value, json};

use super::CommandSpec;
use super::args::{opt_bool, opt_parse, opt_str, opt_text, req_parse, req_str};
use crate::auth::{check_password, hash_password};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "user.list", "Users", ["System", "Users"], None,
        "{} → [{name, group, disabled, no_password, comment}]",
        super::always, list),
    cmd!(query "user.active.list", "Active Users", ["System", "Users"], None,
        "{} → [{id, user, via, since, last_seen}]",
        super::always, active),
    cmd!(
        "user.add",
        "Add User",
        ["System", "Users"],
        None,
        "{name: string, group: read|write|full, password: string, disabled?: bool, comment?: string} → {name, group}",
        not_in_safe_mode,
        add
    ),
    cmd!(
        "user.set",
        "Edit User",
        ["System", "Users"],
        None,
        "{name: string, password?: string, group?: read|write|full, disabled?: bool, comment?: string} → {name, group, disabled}",
        not_in_safe_mode,
        set
    ),
    cmd!(
        "user.remove",
        "Remove User",
        ["System", "Users"],
        None,
        "{name: string} → {}",
        not_in_safe_mode,
        remove
    ),
];

fn not_in_safe_mode(s: &Session) -> std::result::Result<(), String> {
    if s.in_safe_mode() {
        return Err("leave Safe Mode first: user changes cannot be undone by it".into());
    }
    Ok(())
}

fn row(u: &User) -> Value {
    json!({
        "name": u.name,
        "group": u.group,
        "disabled": u.disabled,
        "no_password": u.password_hash.is_none(),
        "comment": u.comment,
    })
}

fn list(s: &mut Session, _: &Value) -> Result<Value> {
    Ok(Value::Array(s.users().iter().map(row).collect()))
}

fn active(s: &mut Session, _: &Value) -> Result<Value> {
    serde_json::to_value(s.logins()).map_err(|e| EngineError::Internal(e.to_string()))
}

fn password(p: &Value) -> Result<Option<String>> {
    let Some(pw) = opt_str(p, "password")? else {
        return Ok(None);
    };
    check_password(pw).map_err(|e| EngineError::bad("password", e))?;
    hash_password(pw)
        .map(Some)
        .map_err(|e| EngineError::bad("password", e))
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let name = req_str(p, "name")?;
    check_name(name).map_err(|e| EngineError::bad("name", e))?;
    let group: Group = req_parse(p, "group")?;
    let mut users = s.users().clone();
    if users.get(name).is_some() {
        return Err(EngineError::bad(
            "name",
            format!("user '{name}' already exists (user.set changes it)"),
        ));
    }
    if users.len() >= corerouter_model::users::MAX_USERS {
        return Err(EngineError::bad(
            "name",
            format!("at most {} users", corerouter_model::users::MAX_USERS),
        ));
    }
    let comment = opt_text(p, "comment", 256)?.unwrap_or_default();
    let disabled = opt_bool(p, "disabled")?.unwrap_or(false);
    let hash = password(p)?.ok_or_else(|| EngineError::bad("password", "is required"))?;
    users.put(User {
        name: name.to_owned(),
        group,
        password_hash: Some(hash),
        disabled,
        comment,
    });
    s.set_users(users);
    log::info!("user '{name}' added (group {group})");
    Ok(json!({ "name": name, "group": group }))
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let name = req_str(p, "name")?;
    let mut users = s.users().clone();
    let mut user = users.get(name).cloned().ok_or_else(|| unknown_user(name))?;
    if let Some(g) = opt_parse::<Group>(p, "group")? {
        user.group = g;
    }
    if let Some(d) = opt_bool(p, "disabled")? {
        user.disabled = d;
    }
    if let Some(c) = opt_text(p, "comment", 256)? {
        user.comment = c;
    }
    let new_password = password(p)?;
    let password_changed = new_password.is_some();
    if let Some(h) = new_password {
        user.password_hash = Some(h);
    }
    let out = json!({ "name": user.name, "group": user.group, "disabled": user.disabled });
    let user_disabled = user.disabled;
    users.put(user);
    if lockout(s, &users) {
        return Err(EngineError::bad(
            "name",
            "this would leave no enabled user in group full; nobody could manage users",
        ));
    }
    s.set_users(users);
    if user_disabled {
        s.logins_end_user(name);
    } else if password_changed {
        // A new password ends the account's other sessions; whoever set it
        // stays logged in (the first-login "set a password" dialog).
        s.logins_end_others(name);
    }
    log::info!("user '{name}' changed");
    Ok(out)
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let name = req_str(p, "name")?;
    let mut users = s.users().clone();
    users.remove(name).ok_or_else(|| unknown_user(name))?;
    if lockout(s, &users) {
        return Err(EngineError::bad(
            "name",
            "cannot remove the last enabled user in group full",
        ));
    }
    s.set_users(users);
    s.logins_end_user(name);
    log::info!("user '{name}' removed");
    Ok(json!({}))
}

/// The change would take away the last account that can manage users.
fn lockout(s: &Session, after: &corerouter_model::Users) -> bool {
    s.users().admins() > 0 && after.admins() == 0
}

fn unknown_user(name: &str) -> EngineError {
    EngineError::bad(
        "name",
        format!(
            "no user '{}' (see user.list)",
            name.chars().take(64).collect::<String>()
        ),
    )
}
