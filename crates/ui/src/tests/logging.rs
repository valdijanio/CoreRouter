//! System › Logging (G4.6e), a panel: Rules and Actions tabs and dialogs.

use super::*;
use crate::logging::{ACTIONS, FACILITIES, LogDialog, LogPanel, RULES, TOPICS, Tab, WIN};

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..3 {
        h.idle();
    }
}

fn lab() -> Harness {
    let mut s = Session::virtual_lab();
    s.execute(
        "system.logging.action.add",
        &json!({"name": "siem", "remote": "192.0.2.10", "syslog_facility": "local3"}),
    )
    .unwrap();
    s.execute(
        "system.logging.add",
        &json!({"topics": ["ntp", "!debug"], "action": "siem", "prefix": "edge"}),
    )
    .unwrap();
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    refresh(&mut h);
    h
}

fn tab(h: &mut Harness, t: Tab) {
    h.app.panel_mut::<LogPanel>().unwrap().tab = t;
    h.idle();
}

fn dialog(h: &mut Harness) -> &mut LogDialog {
    &mut h
        .app
        .panel_mut::<LogPanel>()
        .unwrap()
        .dialogs
        .first_mut()
        .unwrap()
        .dialog
}

#[test]
fn logging_rules_tab_lists_edits_and_adds() {
    let mut h = lab();
    assert!(h.has_text("ntp, !debug"), "topics column");
    assert!(h.has_text("edge"), "prefix column");

    let row = h
        .ctx
        .read_response(table::row_id(RULES, "*5"))
        .expect("row drawn")
        .rect
        .center();
    h.right_click(row);
    h.click(h.text("Properties…"));
    assert!(h.has_text("Logging Rule <*5>"));
    // The topic buttons: click "info" adds it.
    h.click(h.text("info"));
    if let LogDialog::Rule { form, .. } = dialog(&mut h) {
        assert_eq!(form.topics, "ntp, !debug, info");
        form.topics = "system, !debug".into();
    }
    h.idle();
    h.click(h.text("OK"));
    refresh(&mut h);
    let rules = lock(&h.session)
        .execute("system.logging.list", &Value::Null)
        .unwrap();
    assert_eq!(rules[4]["topics"], json!(["system", "!debug"]), "{:?}", h.app.log());
    assert!(h.app.panel_mut::<LogPanel>().unwrap().dialogs.is_empty());

    // Disable from the toolbar, with the row selected.
    h.click(row);
    let disable = h
        .ctx
        .read_response(table::tool_id(RULES, table::Icon::Disable))
        .expect("disable tool")
        .rect
        .center();
    h.click(disable);
    refresh(&mut h);
    let rules = lock(&h.session)
        .execute("system.logging.list", &Value::Null)
        .unwrap();
    assert_eq!(rules[4]["disabled"], true);

    // New: the first action is picked; a bad topic stays in the dialog.
    let add = h
        .ctx
        .read_response(table::tool_id(RULES, table::Icon::Add))
        .expect("add tool")
        .rect
        .center();
    h.click(add);
    refresh(&mut h);
    assert!(h.has_text("New Logging Rule"));
    if let LogDialog::NewRule { form, .. } = dialog(&mut h) {
        // The built-in memory action comes first (G4.6d).
        assert_eq!(form.action, "memory");
        form.topics = "nosuchtopic".into();
    }
    h.idle();
    h.click(h.text("OK"));
    refresh(&mut h);
    assert!(h.has_text_containing("topics"), "error in the dialog");
    if let LogDialog::NewRule { form, .. } = dialog(&mut h) {
        form.topics = "firewall".into();
    }
    h.idle();
    h.click(h.text("OK"));
    refresh(&mut h);
    let rules = lock(&h.session)
        .execute("system.logging.list", &Value::Null)
        .unwrap();
    assert_eq!(rules[5]["topics"], json!(["firewall"]), "{:?}", h.app.log());
}

#[test]
fn logging_actions_tab_lists_edits_and_refuses_removing_one_in_use() {
    let mut h = lab();
    tab(&mut h, Tab::Actions);
    assert!(h.has_text("192.0.2.10"), "remote column");
    assert!(h.has_text("local3"), "facility column");

    let row = h
        .ctx
        .read_response(table::row_id(ACTIONS, "siem"))
        .expect("row drawn")
        .rect
        .center();
    h.right_click(row);
    h.click(h.text("Properties…"));
    assert!(h.has_text("Logging Action <siem>"));
    if let LogDialog::Action { form, .. } = dialog(&mut h) {
        form.remote_port = "6514".into();
        form.severity = "warning".into();
    }
    h.idle();
    h.click(h.text("Apply"));
    refresh(&mut h);
    let actions = lock(&h.session)
        .execute("system.logging.action.list", &Value::Null)
        .unwrap();
    assert_eq!(actions[1]["remote_port"], 6514, "{:?}", h.app.log());
    assert_eq!(actions[1]["syslog_severity"], "warning");
    // Remove while a rule uses it: the engine says why, the window stays.
    h.click(h.text("Remove"));
    refresh(&mut h);
    assert!(h.has_text_containing("used by logging rule"));
    h.click(h.text("Cancel"));

    // New: a free name is proposed.
    let add = h
        .ctx
        .read_response(table::tool_id(ACTIONS, table::Icon::Add))
        .expect("add tool")
        .rect
        .center();
    h.click(add);
    refresh(&mut h);
    assert!(
        h.has_text("New Logging Action"),
        "{:?} {:?}",
        h.app.panel_mut::<LogPanel>().unwrap().dialogs.iter().map(|d| d.dialog.title()).collect::<Vec<_>>(),
        h.app.log()
    );
    if let LogDialog::NewAction { form, .. } = dialog(&mut h) {
        assert_eq!(form.name, "remote1");
        form.remote = "2001:db8::514".into();
    }
    h.idle();
    h.click(h.text("OK"));
    refresh(&mut h);
    let actions = lock(&h.session)
        .execute("system.logging.action.list", &Value::Null)
        .unwrap();
    assert_eq!(actions[2]["name"], "remote1", "{:?}", h.app.log());
    assert_eq!(actions[2]["remote_port"], 514);
}

#[test]
fn the_memory_action_only_takes_its_lines() {
    let mut h = lab();
    tab(&mut h, Tab::Actions);
    let row = h
        .ctx
        .read_response(table::row_id(ACTIONS, "memory"))
        .expect("memory row drawn")
        .rect
        .center();
    h.right_click(row);
    h.click(h.text("Properties…"));
    assert!(h.has_text("Logging Action <memory>"));
    assert!(!h.has_text("Syslog Facility"), "no remote fields");
    assert!(!h.has_text("Remove"), "the built-in action stays");
    if let LogDialog::Action { form, .. } = dialog(&mut h) {
        assert!(form.memory);
        assert_eq!(form.memory_lines, "1000");
        form.memory_lines = "300".into();
    }
    h.idle();
    h.click(h.text("OK"));
    refresh(&mut h);
    assert_eq!(
        lock(&h.session).store().running().system.logging.memory_lines,
        300,
        "{:?}",
        h.app.log()
    );
}

#[test]
fn logging_lists_match_the_model() {
    assert_eq!(TOPICS.as_slice(), corerouter_model::logging::TOPICS);
    let model: Vec<&str> = corerouter_model::logging::Facility::ALL
        .iter()
        .map(|f| f.as_str())
        .collect();
    assert_eq!(FACILITIES.as_slice(), model.as_slice());
}
