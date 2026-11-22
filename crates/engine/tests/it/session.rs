use corerouter_engine::{EngineError, Session};
use serde_json::json;

fn lab() -> Session {
    Session::virtual_lab()
}

#[test]
fn immediate_mode_commits_each_command() {
    let mut s = lab();
    let r = s
        .execute(
            "ip.address.add",
            &json!({"address": "10.0.0.1/24", "interface": "ether1"}),
        )
        .unwrap();
    assert_eq!(r["id"], "*1");
    assert_eq!(s.store().current_revision(), 1);
    assert!(!s.store().is_dirty());
    assert_eq!(s.store().running().ip.addresses.len(), 1);
}

#[test]
fn transactional_mode_needs_commit() {
    let mut s = lab();
    s.execute("config.mode.set", &json!({"mode": "transactional"}))
        .unwrap();
    s.execute(
        "routing.bgp.instance.set",
        &json!({"asn": 65000, "router_id": "10.255.0.1"}),
    )
    .unwrap();
    assert!(s.store().is_dirty());
    assert!(s.store().running().routing.bgp.is_empty());
    // Cannot go back to immediate with pending changes.
    assert!(
        s.execute("config.mode.set", &json!({"mode": "immediate"}))
            .is_err()
    );
    let r = s
        .execute("config.commit", &json!({"comment": "bgp"}))
        .unwrap();
    assert_eq!(r["revision"], 1);
    assert_eq!(s.store().running().routing.bgp.len(), 1);
}

#[test]
fn failed_validation_leaves_state_untouched() {
    let mut s = lab();
    let err = s
        .execute(
            "routing.bgp.instance.set",
            &json!({"asn": 23456, "router_id": "10.0.0.1"}),
        )
        .unwrap_err();
    assert!(matches!(err, EngineError::Validation(_)), "{err}");
    assert!(s.store().candidate().routing.bgp.is_empty());
    assert_eq!(s.store().current_revision(), 0);
}

#[test]
fn unknown_param_suggests_fix() {
    let mut s = lab();
    let err = s
        .execute(
            "ip.address.add",
            &json!({"adress": "10.0.0.1/24", "interface": "ether1"}),
        )
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        "unknown parameter 'adress'; did you mean 'address'?"
    );
    let err = s.execute("ip.adress.add", &json!({})).unwrap_err();
    assert!(err.to_string().contains("did you mean 'ip.address.add'"));
}

#[test]
fn disabled_reason_is_reported() {
    let mut s = lab();
    let err = s.execute("config.commit", &json!({})).unwrap_err();
    assert_eq!(
        err.to_string(),
        "command 'config.commit' is disabled: no pending changes"
    );
}

#[test]
fn rollback_restores_old_revision() {
    let mut s = lab();
    s.execute("system.identity.set", &json!({"name": "edge-1"}))
        .unwrap();
    s.execute("config.rollback", &json!({"revision": 0}))
        .unwrap();
    assert_eq!(s.store().running().system.identity, "CoreRouter");
    assert_eq!(s.store().current_revision(), 2);
}

#[test]
fn atomic_batch_with_refs() {
    let mut s = lab();
    let r = s
        .batch(
            &json!([
                {"command": "ip.address.add", "params": {"address": "10.0.0.1/24", "interface": "ether1"}},
                {"command": "ip.address.remove", "params": {"id": "$1.id"}},
                {"command": "ip.address.add", "params": {"address": "10.0.1.1/24", "interface": "ether2"}},
            ]),
            true,
        )
        .unwrap();
    assert_eq!(r["results"].as_array().unwrap().len(), 3);
    assert_eq!(s.store().running().ip.addresses.len(), 1);
    assert_eq!(s.store().current_revision(), 1, "one commit for the batch");

    let err = s
        .batch(
            &json!([
                {"command": "system.identity.set", "params": {"name": "x"}},
                {"command": "ip.address.add", "params": {"address": "bad", "interface": "ether1"}},
            ]),
            true,
        )
        .unwrap_err();
    assert!(matches!(err, EngineError::Batch { step: 2, .. }));
    assert_eq!(s.store().running().system.identity, "CoreRouter");
    assert!(!s.store().is_dirty());
}

#[test]
fn inspect_paths() {
    let s = lab();
    let summary = s.inspect(None).unwrap();
    assert_eq!(summary["counts"]["interfaces"], 8);
    assert!(s.inspect(Some("interfaces.ether1")).unwrap().is_object());
    assert!(s.inspect(Some("nope")).is_err());
}

/// Audit #4: the journal kept whole parameters (up to 16 MiB a line, 1024
/// entries); it now keeps them bounded, like the log.
#[test]
fn journal_entries_are_bounded() {
    let mut s = lab();
    let huge = "x".repeat(1 << 20);
    let err = s
        .execute(
            "ip.address.add",
            &json!({"address": huge, "interface": "ether1"}),
        )
        .unwrap_err();
    assert!(err.to_string().len() < 8 * 1024);
    let entry = serde_json::to_string(&s.journal()[0]).unwrap();
    assert!(entry.len() < 8 * 1024, "{} bytes", entry.len());
}

/// Audit #5: a commit or a mode change inside an atomic batch committed
/// for real, and a later failing step then left a hidden diff behind.
#[test]
fn an_atomic_batch_refuses_transaction_control_steps() {
    for control in [
        json!({"command": "config.commit", "params": {}}),
        json!({"command": "config.mode.set", "params": {"mode": "immediate"}}),
        json!({"command": "config.safe-mode.enter", "params": {}}),
        json!({"command": "config.discard", "params": {}}),
    ] {
        let mut s = lab();
        let rev = s.store().current_revision();
        let steps = json!([
            {"command": "ip.address.add", "params": {"address": "10.0.0.1/24", "interface": "ether1"}},
            control,
            {"command": "ip.address.add", "params": {"address": "bad", "interface": "ether1"}},
        ]);
        let err = s.batch(&steps, true).unwrap_err().to_string();
        assert!(err.contains("atomic batch"), "{control}: {err}");
        assert!(!s.store().is_dirty(), "{control}");
        assert_eq!(s.store().current_revision(), rev, "{control}");
        assert!(s.store().running().ip.addresses.is_empty(), "{control}");
        assert!(!s.in_safe_mode());
    }
    // Not atomic: each step runs on its own, a commit included.
    let mut s = lab();
    s.execute("config.mode.set", &json!({"mode": "transactional"}))
        .unwrap();
    let steps = json!([
        {"command": "ip.address.add", "params": {"address": "10.0.0.1/24", "interface": "ether1"}},
        {"command": "config.commit", "params": {}},
    ]);
    s.batch(&steps, false).unwrap();
    assert_eq!(s.store().running().ip.addresses.len(), 1);
}

/// Audit #9: `/import` of a real `/export` sends one atomic batch; past 256
/// steps it was refused, so a router could not restore its own backup.
#[test]
fn an_atomic_batch_takes_a_big_import() {
    let mut s = lab();
    let steps: Vec<_> = (0..3000u32)
        .map(|i| {
            json!({"command": "ip.firewall.address-list.add",
                   "params": {"list": "blocked", "address": format!("10.{}.{}.1", i / 256, i % 256)}})
        })
        .collect();
    s.batch(&json!(steps), true).unwrap();
    assert_eq!(s.store().running().ip.firewall.address_lists.len(), 3000);
    assert_eq!(s.store().current_revision(), 1);
    // Still bounded.
    let too_many = vec![
        json!({"command": "system.identity.set", "params": {"name": "x"}});
        corerouter_engine::session::MAX_BATCH + 1
    ];
    assert!(s.batch(&json!(too_many), true).is_err());
}

/// Audit #14: a failed command's parameters reached the log message with
/// their control characters (a forged second line, terminal escapes).
#[test]
fn log_messages_carry_no_control_characters() {
    let mut s = lab();
    s.execute(
        "ip.address.add",
        &json!({"address": "x\u{1b}[2J\nadmin logged in", "interface": "ether1"}),
    )
    .unwrap_err();
    let rows = s.execute("log.print", &json!({})).unwrap();
    let rows = rows.as_array().unwrap();
    assert!(!rows.is_empty());
    for r in rows {
        let m = r["message"].as_str().unwrap();
        assert!(!m.chars().any(char::is_control), "{m:?}");
    }
}

/// A data plane that panics on apply (a bug in a dependency).
struct Panics(corerouter_hal::VirtualHal);

impl corerouter_hal::Hal for Panics {
    fn describe(&self) -> String {
        "panicking lab".into()
    }
    fn discover_links(
        &mut self,
    ) -> Result<Vec<corerouter_hal::LinkInfo>, corerouter_hal::HalError> {
        self.0.discover_links()
    }
    #[allow(clippy::panic)]
    fn apply(
        &mut self,
        from: &corerouter_model::Config,
        to: &corerouter_model::Config,
    ) -> Result<(), corerouter_hal::HalError> {
        if from.system.identity != to.system.identity {
            panic!("bug in the data plane");
        }
        self.0.apply(from, to)
    }
    fn poll(&mut self) -> Vec<corerouter_hal::LinkState> {
        self.0.poll()
    }
    fn now_unix(&self) -> Option<u64> {
        None
    }
}

/// Audit #6: a panic during the commit escaped the guard and left the
/// failed edit in the candidate, for the next command to commit.
#[test]
fn a_panic_while_committing_leaves_nothing_pending() {
    let mut s = Session::new(Box::new(Panics(corerouter_hal::VirtualHal::default())));
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        s.execute("system.identity.set", &json!({"name": "boom"}))
    }));
    assert!(matches!(r, Ok(Err(EngineError::Internal(_)))), "{r:?}");
    assert!(!s.store().is_dirty());
    assert_eq!(s.store().running().system.identity, "CoreRouter");
    // The next command does not commit the failed edit along.
    s.execute(
        "ip.address.add",
        &json!({"address": "10.0.0.1/24", "interface": "ether1"}),
    )
    .unwrap();
    assert_eq!(s.store().running().system.identity, "CoreRouter");
}
