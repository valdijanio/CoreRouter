//! G1.4: Safe Mode. Changes made after `config.safe-mode.enter` are undone
//! when the owner cancels, its connection closes or the timeout expires;
//! `exit` confirms them; a restart in the middle boots the entry config.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use corerouter_engine::{Caller, EngineError, MemoryStorage, Principal, Session};
use corerouter_hal::{Hal, HalError, LinkInfo, LinkState, VirtualHal};
use corerouter_model::Config;
use serde_json::{Value, json};

const T0: u64 = 1_792_591_389;

fn gui() -> Caller {
    Caller::new(7, "tcp 127.0.0.1:50412").with_principal(Principal::Local)
}

fn cli() -> Caller {
    Caller::new(8, "tcp 127.0.0.1:50999").with_principal(Principal::Local)
}

fn boot(storage: &MemoryStorage) -> Session {
    let mut s = Session::with_storage(Box::new(VirtualHal::default()), Box::new(storage.clone()));
    s.tick(T0);
    s
}

fn disable(s: &mut Session, who: &Caller, name: &str) {
    s.execute_as(
        who,
        "interface.set",
        &json!({"name": name, "disabled": true}),
    )
    .unwrap();
}

fn disabled(s: &Session, name: &str) -> bool {
    s.store()
        .running()
        .interfaces
        .values()
        .find(|i| i.name.as_str() == name)
        .unwrap()
        .disabled
}

fn summary(s: &mut Session, who: &Caller) -> Value {
    s.inspect_as(who, None).unwrap()["safe_mode"].clone()
}

fn enter(s: &mut Session, who: &Caller, params: Value) -> Value {
    s.execute_as(who, "config.safe-mode.enter", &params)
        .unwrap()
}

#[test]
fn exit_confirms_and_saves() {
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    let r = enter(&mut s, &gui(), json!({}));
    assert_eq!(r["active"], true);
    assert_eq!(r["owner"], "tcp 127.0.0.1:50412");
    assert_eq!(r["since"], T0);
    disable(&mut s, &gui(), "ether2");
    let sm = summary(&mut s, &gui());
    assert_eq!(sm["yours"], true);
    assert_eq!(sm["pending_revisions"], 1);
    assert_eq!(summary(&mut s, &cli())["yours"], false);
    // Pending: on the data plane, not yet the boot config.
    assert!(disabled(&s, "ether2"));
    assert!(boot(&storage).store().current_revision() == 0);

    let r = s
        .execute_as(&gui(), "config.safe-mode.exit", &json!({}))
        .unwrap();
    assert_eq!(r["active"], false);
    assert_eq!(r["last"], "confirmed revisions 1..=1");
    s.hang_up(gui().id);
    assert!(
        disabled(&s, "ether2"),
        "a hang-up after exit undoes nothing"
    );
    let rebooted = boot(&storage);
    assert!(disabled(&rebooted, "ether2"));
    assert!(
        rebooted.store().history()[1]
            .comment
            .ends_with("[safe mode]")
    );
}

#[test]
fn cancel_undoes_everything_since_the_entry() {
    let mut s = boot(&MemoryStorage::default());
    disable(&mut s, &gui(), "ether1"); // before: stays
    enter(&mut s, &gui(), json!({}));
    disable(&mut s, &gui(), "ether2");
    disable(&mut s, &cli(), "ether3"); // other sessions too, as in RouterOS
    let r = s
        .execute_as(&gui(), "config.safe-mode.cancel", &json!({}))
        .unwrap();
    assert_eq!(r["active"], false);
    assert!(disabled(&s, "ether1"));
    assert!(!disabled(&s, "ether2"));
    assert!(!disabled(&s, "ether3"));
    // Undone by a new revision (history stays auditable).
    assert_eq!(s.store().current_revision(), 4);
    assert!(
        r["last"]
            .as_str()
            .unwrap()
            .contains("config of revision 1 restored as revision 4"),
        "{r}"
    );
    // Gone from the menu state.
    let err = s
        .execute_as(&gui(), "config.safe-mode.cancel", &json!({}))
        .unwrap_err();
    assert!(err.to_string().contains("not in Safe Mode"), "{err}");
}

#[test]
fn owner_hang_up_undoes() {
    let mut s = boot(&MemoryStorage::default());
    enter(&mut s, &gui(), json!({}));
    disable(&mut s, &gui(), "ether2");
    s.hang_up(cli().id); // someone else leaving changes nothing
    assert!(s.in_safe_mode());
    assert!(disabled(&s, "ether2"));
    s.hang_up(gui().id);
    assert!(!s.in_safe_mode());
    assert!(!disabled(&s, "ether2"));
    let journal = s.journal().last().unwrap();
    assert_eq!(journal.command, "config.safe-mode.cancel");
    assert_eq!(journal.params["automatic"], "the owner's connection closed");
    let last = summary(&mut s, &gui())["last"].clone();
    assert!(last.as_str().unwrap().starts_with("undone"), "{last}");
}

#[test]
fn timeout_undoes_and_can_be_rearmed() {
    let mut s = boot(&MemoryStorage::default());
    let r = enter(&mut s, &gui(), json!({"timeout_secs": 60}));
    assert_eq!(r["expires_in"], 60);
    disable(&mut s, &gui(), "ether2");
    s.tick(T0 + 50);
    assert_eq!(summary(&mut s, &gui())["expires_in"], 10);
    // The owner re-arms: 60 s from now, same entry point.
    let r = enter(&mut s, &gui(), json!({"timeout_secs": 60}));
    assert_eq!(r["entry_revision"], 0);
    assert_eq!(r["expires_in"], 60);
    s.tick(T0 + 100);
    assert!(s.in_safe_mode());
    assert!(disabled(&s, "ether2"));
    s.tick(T0 + 110);
    assert!(!s.in_safe_mode());
    assert!(!disabled(&s, "ether2"));
    let last = summary(&mut s, &gui())["last"].clone();
    assert!(last.as_str().unwrap().contains("timeout"), "{last}");
}

#[test]
fn confirming_after_the_deadline_is_too_late() {
    let mut s = boot(&MemoryStorage::default());
    enter(&mut s, &gui(), json!({"timeout_secs": 10}));
    disable(&mut s, &gui(), "ether2");
    s.tick(T0 + 10);
    let err = s
        .execute_as(&gui(), "config.safe-mode.exit", &json!({}))
        .unwrap_err();
    assert!(err.to_string().contains("not in Safe Mode"), "{err}");
    assert!(!disabled(&s, "ether2"));
}

#[test]
fn second_session_is_refused_with_who_and_since() {
    let mut s = boot(&MemoryStorage::default());
    enter(&mut s, &gui(), json!({}));
    s.tick(T0 + 40);
    let err = s
        .execute_as(&cli(), "config.safe-mode.enter", &json!({}))
        .unwrap_err();
    assert!(matches!(err, EngineError::Disabled { .. }), "{err}");
    let msg = err.to_string();
    assert!(msg.contains("held by tcp 127.0.0.1:50412"), "{msg}");
    assert!(
        msg.contains("since 2026-10-21 14:03:09 UTC (40 s ago)"),
        "{msg}"
    );
    // Nor may it end someone else's Safe Mode by accident...
    let err = s
        .execute_as(&cli(), "config.safe-mode.exit", &json!({}))
        .unwrap_err();
    assert!(err.to_string().contains("force: true"), "{err}");
    assert!(s.in_safe_mode());
    // ...only on purpose (RouterOS "release" / "unroll").
    disable(&mut s, &gui(), "ether2");
    s.execute_as(&cli(), "config.safe-mode.cancel", &json!({"force": true}))
        .unwrap();
    assert!(!s.in_safe_mode());
    assert!(!disabled(&s, "ether2"));
}

#[test]
fn restart_in_the_middle_boots_the_entry_revision() {
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    disable(&mut s, &gui(), "ether1");
    enter(&mut s, &gui(), json!({}));
    disable(&mut s, &gui(), "ether2");
    disable(&mut s, &gui(), "ether3");
    assert_eq!(s.store().current_revision(), 3);
    drop(s); // power cut: no exit, no hang-up

    let s = boot(&storage);
    assert_eq!(s.store().current_revision(), 1);
    assert!(disabled(&s, "ether1"));
    assert!(!disabled(&s, "ether2"));
    assert!(!disabled(&s, "ether3"));
    assert!(!s.in_safe_mode());
}

#[test]
fn bad_entries_are_refused() {
    let mut s = boot(&MemoryStorage::default());
    for t in [0, 9, 86_401] {
        let err = s
            .execute_as(
                &gui(),
                "config.safe-mode.enter",
                &json!({"timeout_secs": t}),
            )
            .unwrap_err();
        assert!(err.to_string().contains("timeout_secs"), "{err}");
    }
    // Pending candidate edits: there would be no clean point to go back to.
    s.execute("config.mode.set", &json!({"mode": "transactional"}))
        .unwrap();
    disable(&mut s, &gui(), "ether2");
    let err = s
        .execute_as(&gui(), "config.safe-mode.enter", &json!({}))
        .unwrap_err();
    assert!(err.to_string().contains("pending change"), "{err}");
    // No clock (virtual lab never ticked): no timeout, but Safe Mode works.
    let mut no_clock = Session::virtual_lab();
    let err = no_clock
        .execute("config.safe-mode.enter", &json!({"timeout_secs": 30}))
        .unwrap_err();
    assert!(err.to_string().contains("no clock"), "{err}");
    no_clock
        .execute("config.safe-mode.enter", &json!({}))
        .unwrap();
    assert!(no_clock.in_safe_mode());
}

#[test]
fn transactional_cancel_also_drops_pending_edits() {
    let mut s = boot(&MemoryStorage::default());
    s.execute("config.mode.set", &json!({"mode": "transactional"}))
        .unwrap();
    enter(&mut s, &gui(), json!({}));
    disable(&mut s, &gui(), "ether2");
    s.execute_as(&gui(), "config.commit", &json!({})).unwrap();
    disable(&mut s, &gui(), "ether3"); // not committed
    s.execute_as(&gui(), "config.safe-mode.cancel", &json!({}))
        .unwrap();
    assert!(!s.store().is_dirty());
    assert!(!disabled(&s, "ether2"));
    assert!(
        !s.store()
            .candidate()
            .interfaces
            .values()
            .any(|i| i.disabled)
    );
}

/// Audit #13: a cancel with only pending (uncommitted) edits dropped them
/// and said "nothing to undo".
#[test]
fn cancel_says_when_it_drops_pending_edits() {
    let mut s = boot(&MemoryStorage::default());
    s.execute("config.mode.set", &json!({"mode": "transactional"}))
        .unwrap();
    enter(&mut s, &gui(), json!({}));
    disable(&mut s, &gui(), "ether3"); // not committed
    s.execute_as(&gui(), "config.safe-mode.cancel", &json!({}))
        .unwrap();
    assert!(!s.store().is_dirty());
    let last = summary(&mut s, &gui())["last"].clone();
    let last = last.as_str().unwrap();
    assert!(last.contains("1 pending change(s) discarded"), "{last}");
}

/// Audit #2 (verified false): account changes save the store, which in
/// Safe Mode would hold the unconfirmed config; the user commands are
/// refused there. The save itself now writes the entry store anyway
/// (`safe_mode::tests::a_save_in_safe_mode_writes_the_entry_config`).
#[test]
fn user_changes_wait_for_the_end_of_safe_mode() {
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    enter(&mut s, &gui(), json!({}));
    disable(&mut s, &gui(), "ether2");
    let err = s
        .execute_as(
            &gui(),
            "user.add",
            &json!({"name": "op", "group": "write", "password": "s3cret-Passw0rd"}),
        )
        .unwrap_err();
    assert!(err.to_string().contains("leave Safe Mode first"), "{err}");
}

/// A clock pair the test moves by hand: the wall clock (NTP may step it)
/// and a monotonic one (seconds since boot).
struct Clocks {
    inner: VirtualHal,
    wall: Arc<AtomicU64>,
    mono: Arc<AtomicU64>,
}

impl Hal for Clocks {
    fn describe(&self) -> String {
        "lab with clocks".into()
    }
    fn discover_links(&mut self) -> Result<Vec<LinkInfo>, HalError> {
        self.inner.discover_links()
    }
    fn apply(&mut self, from: &Config, to: &Config) -> Result<(), HalError> {
        self.inner.apply(from, to)
    }
    fn poll(&mut self) -> Vec<LinkState> {
        self.inner.poll()
    }
    fn now_unix(&self) -> Option<u64> {
        Some(self.wall.load(Ordering::SeqCst))
    }
    fn monotonic_secs(&self) -> Option<u64> {
        Some(self.mono.load(Ordering::SeqCst))
    }
}

/// Audit #7: the Safe Mode deadline followed the wall clock, so an NTP
/// step (a router without RTC boots in 1970) undid the change at once.
#[test]
fn the_deadline_follows_the_monotonic_clock() {
    let wall = Arc::new(AtomicU64::new(1_000));
    let mono = Arc::new(AtomicU64::new(5));
    let hal = Clocks {
        inner: VirtualHal::default(),
        wall: Arc::clone(&wall),
        mono: Arc::clone(&mono),
    };
    let mut s = Session::new(Box::new(hal));
    enter(&mut s, &gui(), json!({"timeout_secs": 60}));
    disable(&mut s, &gui(), "ether2");
    // NTP steps the clock 56 years ahead, one second later.
    wall.store(1_800_000_000, Ordering::SeqCst);
    mono.store(6, Ordering::SeqCst);
    s.tick(1_800_000_000);
    assert!(s.in_safe_mode(), "a clock step is not elapsed time");
    assert_eq!(summary(&mut s, &gui())["expires_in"], 59);
    // And a step back does not push the deadline away.
    wall.store(10, Ordering::SeqCst);
    mono.store(65, Ordering::SeqCst);
    s.tick(10);
    assert!(!s.in_safe_mode());
    assert!(!disabled(&s, "ether2"));
}

/// G1.6qg: a user that logged in over the network, on connection `id`.
fn user(id: u64, name: &str) -> Caller {
    Caller::new(id, format!("tls 10.0.0.9:{}", 40_000 + id))
        .with_principal(Principal::User(name.into()))
}

/// The router with `admin` and `ops` (both group full) before Safe Mode.
fn with_users() -> Session {
    let mut s = boot(&MemoryStorage::default());
    for name in ["admin", "ops"] {
        s.execute(
            "user.add",
            &json!({"name": name, "group": "full", "password": "s3cret-Passw0rd"}),
        )
        .unwrap();
    }
    s
}

#[test]
fn detached_outlives_its_connection_and_undoes_at_the_deadline() {
    let mut s = with_users();
    let r = enter(
        &mut s,
        &user(8, "admin"),
        json!({"timeout_secs": 60, "detach": true}),
    );
    assert_eq!(
        (
            r["detached"].as_bool(),
            r["expires_in"].as_u64(),
            r["owner_user"].as_str()
        ),
        (Some(true), Some(60), Some("admin")),
        "{r}"
    );
    disable(&mut s, &user(8, "admin"), "ether2");
    // `corerouter-cli run`: the connection closes after each command.
    s.hang_up(8);
    assert!(s.in_safe_mode(), "a detached Safe Mode stays");
    assert!(disabled(&s, "ether2"));
    let sm = summary(&mut s, &user(9, "admin"));
    assert_eq!(
        (sm["owner_connected"].as_bool(), sm["yours"].as_bool()),
        (Some(false), Some(true)),
        "{sm}"
    );
    s.tick(T0 + 59);
    assert!(s.in_safe_mode());
    s.tick(T0 + 60);
    assert!(!s.in_safe_mode(), "undone at the deadline");
    assert!(!disabled(&s, "ether2"));
    let journal = s.journal().last().unwrap();
    assert_eq!(
        journal.params["automatic"],
        "the timeout expired without confirmation"
    );
    let log = s.execute("log.print", &json!({})).unwrap().to_string();
    assert!(
        log.contains("Safe Mode (detached) entered by admin"),
        "{log}"
    );
    assert!(
        log.contains("the connection that entered it closed; the changes are undone in 60 s"),
        "{log}"
    );
}

#[test]
fn the_same_user_confirms_from_another_connection_and_others_need_force() {
    let mut s = with_users();
    enter(&mut s, &user(8, "admin"), json!({"detach": true}));
    assert_eq!(
        summary(&mut s, &user(8, "admin"))["expires_in"],
        600,
        "default: 10 minutes, as Junos and VyOS"
    );
    disable(&mut s, &user(8, "admin"), "ether2");
    s.hang_up(8);
    // Another user cannot end it, nor take it over.
    let e = s
        .execute_as(&user(10, "ops"), "config.safe-mode.exit", &json!({}))
        .unwrap_err()
        .to_string();
    assert!(
        e.contains("detached, user admin") && e.contains("force: true"),
        "{e}"
    );
    let e = s
        .execute_as(
            &user(10, "ops"),
            "config.safe-mode.enter",
            &json!({"detach": true}),
        )
        .unwrap_err()
        .to_string();
    assert!(e.contains("held by"), "{e}");
    assert!(s.in_safe_mode());
    // The same user, a new connection: confirms, and it is saved.
    let r = s
        .execute_as(&user(9, "admin"), "config.safe-mode.exit", &json!({}))
        .unwrap();
    assert_eq!(r["active"], false);
    assert!(r["last"].as_str().unwrap().starts_with("confirmed"), "{r}");
    s.tick(T0 + 601);
    assert!(disabled(&s, "ether2"), "kept after the old deadline");
}

#[test]
fn force_ends_it_for_another_user_and_cancel_undoes_at_once() {
    let mut s = with_users();
    enter(
        &mut s,
        &user(8, "admin"),
        json!({"timeout_secs": 300, "detach": true}),
    );
    disable(&mut s, &user(8, "admin"), "ether2");
    s.hang_up(8);
    s.execute_as(
        &user(10, "ops"),
        "config.safe-mode.cancel",
        &json!({"force": true}),
    )
    .unwrap();
    assert!(!s.in_safe_mode());
    assert!(!disabled(&s, "ether2"), "cancel undoes now");
}

#[test]
fn the_same_user_rearms_it_and_an_attached_entry_cannot_take_it() {
    let mut s = with_users();
    enter(
        &mut s,
        &user(8, "admin"),
        json!({"timeout_secs": 60, "detach": true}),
    );
    disable(&mut s, &user(8, "admin"), "ether2");
    s.hang_up(8);
    s.tick(T0 + 50);
    // `commit confirmed` again: a new deadline, the same entry point.
    let r = enter(
        &mut s,
        &user(9, "admin"),
        json!({"timeout_secs": 120, "detach": true}),
    );
    assert_eq!(
        (r["expires_in"].as_u64(), r["entry_revision"].as_u64()),
        (Some(120), Some(0)),
        "{r}"
    );
    // Without detach the new connection would own it and its closing would
    // undo it: refused, said how.
    let e = s
        .execute_as(&user(9, "admin"), "config.safe-mode.enter", &json!({}))
        .unwrap_err()
        .to_string();
    assert!(e.contains("detached") && e.contains("detach: true"), "{e}");
    s.hang_up(9);
    s.tick(T0 + 169);
    assert!(s.in_safe_mode() && disabled(&s, "ether2"));
    s.tick(T0 + 170);
    assert!(!s.in_safe_mode() && !disabled(&s, "ether2"));
}

#[test]
fn an_attached_one_becomes_detached_and_every_login_is_warned() {
    let mut s = with_users();
    enter(&mut s, &user(8, "admin"), json!({}));
    disable(&mut s, &user(8, "admin"), "ether2");
    // The owner detaches it before leaving (a script that must log out).
    enter(
        &mut s,
        &user(8, "admin"),
        json!({"timeout_secs": 30, "detach": true}),
    );
    s.hang_up(8);
    assert!(s.in_safe_mode() && disabled(&s, "ether2"));
    let w = s.safe_mode_warning().unwrap();
    assert!(
        w.contains("entered by admin")
            && w.contains("1 change(s) are undone in 30 s")
            && w.contains("config.safe-mode.exit"),
        "{w}"
    );
    let me = corerouter_engine::auth::whoami(&s, &Principal::User("ops".into()), "tls");
    assert_eq!(me["safe_mode"].as_str(), Some(w.as_str()));
    // Not detached: no warning (the GUI's own Safe Mode has its button).
    s.tick(T0 + 30);
    assert!(s.safe_mode_warning().is_none());
    enter(&mut s, &gui(), json!({}));
    assert!(s.safe_mode_warning().is_none());
}

#[test]
fn bad_detached_entries_are_refused() {
    let mut s = with_users();
    let e = s
        .execute_as(
            &user(8, "admin"),
            "config.safe-mode.enter",
            &json!({"detach": true, "timeout_secs": 5}),
        )
        .unwrap_err()
        .to_string();
    assert!(e.contains("timeout_secs"), "{e}");
    let e = s
        .execute_as(
            &user(8, "admin"),
            "config.safe-mode.enter",
            &json!({"detach": "yes"}),
        )
        .unwrap_err()
        .to_string();
    assert!(e.contains("detach"), "{e}");
    assert!(!s.in_safe_mode());
    // A restart in the middle boots the entry config, detached or not.
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    enter(&mut s, &gui(), json!({"detach": true}));
    disable(&mut s, &gui(), "ether2");
    drop(s);
    let s = boot(&storage);
    assert!(!s.in_safe_mode());
    assert!(!disabled(&s, "ether2"));
}
