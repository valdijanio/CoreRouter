//! G0.3: accounts, groups and the permission check in the engine.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use corerouter_engine::{Caller, EngineError, MemoryStorage, Principal, Session};
use corerouter_hal::VirtualHal;
use serde_json::{Value, json};

const SECRET: &str = "s3cret-Passw0rd";

fn boot(storage: &MemoryStorage) -> Session {
    Session::with_storage(Box::new(VirtualHal::default()), Box::new(storage.clone()))
}

fn as_user(name: &str) -> Caller {
    Caller::new(42, "tcp 10.0.0.2:5000").with_principal(Principal::User(name.into()))
}

/// admin (full), op (write), noc (read).
fn with_team() -> (Session, MemoryStorage) {
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    for (name, group) in [("admin", "full"), ("op", "write"), ("noc", "read")] {
        s.execute(
            "user.add",
            &json!({"name": name, "group": group, "password": SECRET}),
        )
        .unwrap();
    }
    (s, storage)
}

fn denied(r: Result<Value, EngineError>) -> String {
    match r {
        Err(e @ EngineError::Denied { .. }) => e.to_string(),
        other => panic!("expected Denied, got {other:?}"),
    }
}

#[test]
fn read_group_looks_but_never_changes() {
    let (mut s, _) = with_team();
    let noc = as_user("noc");
    assert!(s.execute_as(&noc, "interface.list", &json!({})).is_ok());
    assert!(s.inspect_as(&noc, None).is_ok());
    let msg = denied(s.execute_as(
        &noc,
        "ip.address.add",
        &json!({"address": "10.0.0.1/24", "interface": "ether1"}),
    ));
    assert!(
        msg.contains("needs group write") && msg.contains("noc"),
        "{msg}"
    );
    denied(s.execute_as(&noc, "config.mode.set", &json!({"mode": "transactional"})));
    // A batch is checked step by step.
    let steps = json!([{"command": "system.identity.set", "params": {"name": "x"}}]);
    assert!(s.batch_as(&noc, &steps, true).is_err());
    assert_eq!(s.store().running().system.identity, "CoreRouter");
    // engine.list greys out what the group cannot do, with the reason.
    let list = s.list_as(&noc);
    let find = |id: &str| {
        list.as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == id)
            .unwrap()
            .clone()
    };
    assert_eq!(find("interface.list")["enabled"], true);
    assert_eq!(find("ip.address.add")["enabled"], false);
    assert!(
        find("ip.address.add")["disabledReason"]
            .as_str()
            .unwrap()
            .contains("write")
    );
}

#[test]
fn write_group_configures_but_does_not_manage_users() {
    let (mut s, _) = with_team();
    let op = as_user("op");
    s.execute_as(&op, "system.identity.set", &json!({"name": "edge"}))
        .unwrap();
    assert_eq!(s.store().running().system.identity, "edge");
    denied(s.execute_as(&op, "user.list", &json!({})));
    let msg = denied(s.execute_as(&op, "user.set", &json!({"name": "op", "group": "full"})));
    assert!(msg.contains("needs group full"), "{msg}");
    assert!(
        s.execute_as(&as_user("admin"), "user.list", &json!({}))
            .is_ok()
    );
}

#[test]
fn anonymous_and_vanished_users_have_no_rights() {
    let (mut s, _) = with_team();
    let anon = Caller::new(1, "tcp 127.0.0.1:1");
    let msg = denied(s.execute_as(&anon, "interface.list", &json!({})));
    assert!(msg.contains("auth.login"), "{msg}");
    assert!(s.inspect_as(&anon, None).is_err());
    // Demoting or disabling takes effect on the next command.
    s.execute("user.set", &json!({"name": "op", "disabled": true}))
        .unwrap();
    denied(s.execute_as(&as_user("op"), "interface.list", &json!({})));
    s.execute("user.remove", &json!({"name": "noc"})).unwrap();
    denied(s.execute_as(&as_user("noc"), "interface.list", &json!({})));
}

#[test]
fn passwords_never_show_up() {
    let (mut s, storage) = with_team();
    s.execute(
        "user.set",
        &json!({"name": "noc", "password": "an0ther-secret"}),
    )
    .unwrap();
    let bad = s.execute(
        "user.add",
        &json!({"name": "x", "group": "read", "password": "short"}),
    );
    assert!(!bad.unwrap_err().to_string().contains("short"));
    let journal = s.inspect(Some("journal")).unwrap().to_string();
    assert!(
        journal.contains("user.add") && journal.contains("***"),
        "{journal}"
    );
    let everything = [
        journal,
        s.execute("user.list", &json!({})).unwrap().to_string(),
        s.execute("config.diff", &json!({})).unwrap().to_string(),
        s.inspect(None).unwrap().to_string(),
        s.inspect(Some("running")).unwrap().to_string(),
        s.inspect(Some("system")).unwrap().to_string(),
    ];
    for text in &everything {
        assert!(
            !text.contains(SECRET) && !text.contains("an0ther"),
            "{text}"
        );
        assert!(!text.contains("argon2"), "no hash either: {text}");
    }
    // On disk only the hash.
    let file = storage.get(corerouter_engine::Slot::Current).unwrap();
    assert!(file.contains("$argon2id$") && !file.contains(SECRET));
}

#[test]
fn users_survive_a_restart_but_not_a_rollback() {
    let (mut s, storage) = with_team();
    s.execute("system.identity.set", &json!({"name": "r1"}))
        .unwrap();
    s.execute("user.remove", &json!({"name": "op"})).unwrap();
    // Rolling back to before the removal does not bring `op` back.
    s.execute("config.rollback", &json!({"revision": 0}))
        .unwrap();
    assert!(s.users().get("op").is_none());
    drop(s);
    let s = boot(&storage);
    assert!(s.users().get("admin").is_some() && s.users().get("op").is_none());
    let hash = s.password_hash("admin").unwrap();
    assert!(corerouter_engine::auth::verify_password(&hash, SECRET));
    assert!(s.password_hash("nobody").is_none());
}

#[test]
fn the_last_admin_cannot_be_locked_out() {
    let (mut s, _) = with_team();
    for (cmd, params) in [
        ("user.remove", json!({"name": "admin"})),
        ("user.set", json!({"name": "admin", "disabled": true})),
        ("user.set", json!({"name": "admin", "group": "write"})),
    ] {
        let e = s.execute(cmd, &params).unwrap_err().to_string();
        assert!(e.contains("group full"), "{cmd}: {e}");
    }
    assert!(s.users().get("admin").is_some_and(|u| !u.disabled));
    // With a second admin it is fine.
    s.execute("user.set", &json!({"name": "op", "group": "full"}))
        .unwrap();
    s.execute("user.remove", &json!({"name": "admin"})).unwrap();
}

#[test]
fn validation_and_safe_mode() {
    let (mut s, _) = with_team();
    for bad in [
        json!({"name": "a b", "group": "read", "password": SECRET}),
        json!({"name": "admin", "group": "read", "password": SECRET}),
        json!({"name": "z", "group": "root", "password": SECRET}),
        json!({"name": "z", "group": "read"}),
    ] {
        assert!(s.execute("user.add", &bad).is_err(), "{bad}");
    }
    assert!(
        s.execute("user.set", &json!({"name": "ghost", "disabled": true}))
            .is_err()
    );
    s.execute("config.safe-mode.enter", &json!({})).unwrap();
    let e = s.execute(
        "user.add",
        &json!({"name": "z", "group": "read", "password": SECRET}),
    );
    assert!(matches!(e, Err(EngineError::Disabled { .. })), "{e:?}");
}

#[test]
fn active_logins_are_listed_and_end_with_the_account() {
    let (mut s, _) = with_team();
    let a = s.login_begin("noc", "tcp 10.0.0.9:1234");
    s.login_begin("admin", "ws 127.0.0.1:9");
    let list = s.execute("user.active.list", &json!({})).unwrap();
    assert_eq!(list.as_array().unwrap().len(), 2);
    assert_eq!(list[0]["user"], "noc");
    assert!(s.login_touch(a));
    s.execute(
        "user.set",
        &json!({"name": "noc", "password": "brand-new-pass"}),
    )
    .unwrap();
    assert!(!s.login_touch(a), "a new password ends the old sessions");
    assert_eq!(s.logins().len(), 1);
}

#[test]
fn first_start_admin_has_no_password_until_set() {
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    assert!(s.bootstrap_admin(false).unwrap().contains("first start"));
    assert!(s.bootstrap_admin(false).is_none(), "only once");
    assert_eq!(s.admins_without_password(), ["admin"]);
    assert!(s.has_no_password("admin") && s.password_hash("admin").is_none());
    let list = s.execute("user.list", &json!({})).unwrap();
    assert_eq!(list[0]["no_password"], true);
    assert_eq!(list[0]["group"], "full");
    // Survives a restart as "no password", not as a hash of "".
    let mut again = boot(&storage);
    assert!(again.bootstrap_admin(false).is_none());
    assert!(again.has_no_password("admin"));
    // The admin sets one on the first login, from its own session: that
    // session stays, the others of admin end.
    let me = Caller::new(7, "tcp 127.0.0.1:4000").with_principal(Principal::User("admin".into()));
    let mine = s.login_begin("admin", "tcp 127.0.0.1:4000");
    let other = s.login_begin("admin", "ws 127.0.0.1:9");
    s.execute_as(
        &me,
        "user.set",
        &json!({"name": "admin", "password": SECRET}),
    )
    .unwrap();
    assert!(s.login_touch(mine), "the caller stays logged in");
    assert!(!s.login_touch(other));
    assert!(s.admins_without_password().is_empty());
    assert!(!s.has_no_password("admin"));
    let list = s.execute("user.list", &json!({})).unwrap();
    assert_eq!(list[0]["no_password"], false);
    // No command takes a password away.
    let e = s
        .execute("user.set", &json!({"name": "admin", "password": ""}))
        .unwrap_err();
    assert!(e.to_string().contains("at least"), "{e}");
}

#[test]
fn reset_admin_password_clears_it_again() {
    let (mut s, _) = with_team();
    s.execute(
        "user.set",
        &json!({"name": "admin", "group": "read", "disabled": true}),
    )
    .ok();
    let l = s.login_begin("admin", "tcp 127.0.0.1:1");
    assert!(s.bootstrap_admin(false).is_none(), "users exist: nothing");
    assert!(
        s.bootstrap_admin(true)
            .unwrap()
            .contains("no password again")
    );
    assert!(s.has_no_password("admin"));
    assert_eq!(
        s.group_of(&Principal::User("admin".into())),
        Some(corerouter_engine::auth::Group::Full)
    );
    assert!(!s.login_touch(l), "old sessions end");
    // The others keep their passwords.
    assert!(s.password_hash("op").is_some());
    // No admin at all yet (renamed away): reset creates it.
    let storage = MemoryStorage::default();
    let mut t = boot(&storage);
    t.execute(
        "user.add",
        &json!({"name": "root", "group": "full", "password": SECRET}),
    )
    .unwrap();
    assert!(t.bootstrap_admin(true).is_some());
    assert!(t.has_no_password("admin") && t.password_hash("root").is_some());
}

#[test]
fn reset_like_the_daemon() {
    let (mut s, _) = with_team();
    s.execute(
        "user.set",
        &json!({"name": "admin", "group": "full", "password": "-g7nmycjxmc66-9p-8r4", "disabled": false}),
    )
    .unwrap();
    let h = s.password_hash("admin").unwrap();
    assert!(corerouter_engine::auth::verify_password(
        &h,
        "-g7nmycjxmc66-9p-8r4"
    ));
}
