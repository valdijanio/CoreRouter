//! G2.1: IP › Firewall and Interfaces › Interface List, driven with
//! synthetic events through the real UI over a lab session.

use super::*;
use crate::dialog;
use crate::firewall::{self, Edit, FwTable};
use egui::Key;

const NONE: egui::Modifiers = egui::Modifiers::NONE;

impl Harness {
    /// Only the Firewall window, with a few filter rules in the lab.
    fn firewall() -> Self {
        let mut h = Self::new();
        {
            let mut s = lock(&h.session);
            for p in [
                json!({"section": "Router"}),
                json!({"connection_state": "established,related", "comment": "keep"}),
                json!({"connection_state": "invalid", "action": "drop"}),
                json!({"in_interface_list": "!LAN", "action": "drop"}),
            ] {
                s.execute("ip.firewall.filter.add", &p).unwrap();
            }
        }
        h.app.open.clear();
        h.app.open(Win::Firewall);
        h.app.cache.refreshed_at = None;
        h.idle();
        h.idle();
        h
    }

    fn fw_row(&self, t: FwTable, id: &str) -> egui::Pos2 {
        self.ctx
            .read_response(table::row_id(t.salt(), id))
            .unwrap_or_else(|| panic!("rule {id} not drawn"))
            .rect
            .center()
    }

    fn fw_tool(&self, t: FwTable, icon: table::Icon) -> egui::Response {
        self.ctx
            .read_response(table::tool_id(t.salt(), icon))
            .unwrap_or_else(|| panic!("no tool {icon:?}"))
    }

    fn rule_ids(&self) -> Vec<String> {
        let list = lock(&self.session)
            .execute("ip.firewall.filter.list", &Value::Null)
            .unwrap();
        list.as_array()
            .unwrap()
            .iter()
            .map(|r| r["id"].as_str().unwrap().to_owned())
            .collect()
    }

    fn rule(&self, id: &str) -> Value {
        let list = lock(&self.session)
            .execute("ip.firewall.filter.list", &Value::Null)
            .unwrap();
        list.as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == id)
            .cloned()
            .unwrap_or_else(|| panic!("no rule {id}"))
    }

    fn fw_dialog(&self) -> &firewall::FwDialogWin {
        self.app
            .fw
            .dialogs
            .first()
            .expect("a firewall dialog is open")
    }
}

#[test]
fn rules_sections_and_colours_are_listed() {
    let h = Harness::firewall();
    assert!(h.has_text("Router"), "section title");
    assert!(h.has_text("keep"), "comment");
    assert!(h.has_text("![LAN]"), "interface list");
    let dark = h.ctx.global_style().visuals.dark_mode;
    assert_eq!(
        Some(h.text_color("drop")),
        firewall::action_color("drop", dark),
        "drop is red"
    );
    assert_eq!(
        Some(h.text_color("accept")),
        firewall::action_color("accept", dark),
        "accept is green"
    );
}

#[test]
fn new_rule_dialog_with_tabs_adds_a_rule() {
    let mut h = Harness::firewall();
    h.click(h.fw_tool(FwTable::Filter, table::Icon::Add).rect.center());
    assert!(h.has_text("New Filter Rule"));
    assert!(h.has_text("General") && h.has_text("Advanced") && h.has_text("Action"));
    let win = interfaces::dialog_id(h.fw_dialog().id);
    let field = |h: &Harness, p: &str| {
        h.ctx
            .read_response(dialog::field_id(win, p))
            .unwrap_or_else(|| panic!("no field {p}"))
            .rect
            .center()
    };
    h.click(field(&h, "protocol"));
    h.type_text("tcp");
    h.click(field(&h, "dst_port"));
    h.type_text("22");
    // Action tab: drop.
    h.click(h.text("Action"));
    if let Edit::Rule { form, .. } = &mut h.app.fw.dialogs[0].edit {
        form.set("action", "drop");
    }
    h.idle();
    h.key(Key::Enter, NONE);
    assert!(h.app.fw.dialogs.is_empty(), "OK closes on success");
    let r = h.rule("*5");
    assert_eq!(r["action"], "drop");
    assert_eq!(r["dst_port"], "22");
    assert_eq!(r["position"], 4);
}

#[test]
fn engine_errors_stay_in_the_dialog() {
    let mut h = Harness::firewall();
    h.click(h.fw_tool(FwTable::Filter, table::Icon::Add).rect.center());
    let win = interfaces::dialog_id(h.fw_dialog().id);
    let at = h
        .ctx
        .read_response(dialog::field_id(win, "dst_port"))
        .unwrap()
        .rect
        .center();
    h.click(at);
    h.type_text("22");
    h.key(Key::Enter, NONE);
    let d = h.fw_dialog();
    let err = d.status.error.clone().unwrap_or_default();
    assert!(err.contains("dst_port"), "{err}");
    assert_eq!(h.rule_ids().len(), 4, "nothing added");
}

#[test]
fn move_with_buttons_and_drag() {
    let mut h = Harness::firewall();
    assert_eq!(h.rule_ids(), ["*1", "*2", "*3", "*4"]);
    h.click(h.fw_row(FwTable::Filter, "*4"));
    let up = h
        .ctx
        .read_response(firewall::arrow_id(FwTable::Filter.salt(), true))
        .unwrap()
        .rect
        .center();
    h.click(up);
    assert_eq!(h.rule_ids(), ["*1", "*2", "*4", "*3"]);
    // Drag *3 (now last) above *2.
    h.idle();
    let from = h.fw_row(FwTable::Filter, "*3");
    let to = h.fw_row(FwTable::Filter, "*2");
    h.drag(from, egui::vec2(0.0, to.y - from.y - 4.0));
    h.idle();
    assert_eq!(h.rule_ids(), ["*1", "*3", "*2", "*4"]);
    assert!(h.app.log().iter().all(|l| l.ok), "{:?}", h.app.log());
}

#[test]
fn toolbar_disable_and_remove_and_shortcuts() {
    let mut h = Harness::firewall();
    h.click(h.fw_row(FwTable::Filter, "*3"));
    h.click(
        h.fw_tool(FwTable::Filter, table::Icon::Disable)
            .rect
            .center(),
    );
    assert_eq!(h.rule("*3")["disabled"], true);
    h.click(h.fw_row(FwTable::Filter, "*3"));
    h.key(Key::E, CTRL);
    assert_eq!(h.rule("*3")["disabled"], false);
    h.key(Key::Delete, NONE);
    assert_eq!(h.rule_ids(), ["*1", "*2", "*4"]);
}

#[test]
fn address_lists_and_interface_lists_tabs() {
    let mut h = Harness::firewall();
    lock(&h.session)
        .execute(
            "ip.firewall.address-list.add",
            &json!({"list": "blocked", "address": "203.0.113.0/24"}),
        )
        .unwrap();
    h.app.fw.tab = firewall::Tab::Addr;
    h.app.cache.refreshed_at = None;
    h.idle();
    h.idle();
    assert!(h.has_text("203.0.113.0/24"));
    assert!(h.has_text("blocked"));

    h.app.open(Win::InterfaceList);
    h.app.cache.refreshed_at = None;
    h.idle();
    h.click(
        h.ctx
            .read_response(table::tool_id(
                firewall::Feed::Members.salt(),
                table::Icon::Add,
            ))
            .unwrap()
            .rect
            .center(),
    );
    assert!(h.has_text("New Interface List Member"));
    match &mut h.app.fw.dialogs[0].edit {
        Edit::Member { form, .. } => {
            form.list = "LAN".into();
            form.interface = "ether2".into();
        }
        _ => panic!("member dialog"),
    }
    h.idle();
    h.key(Key::Enter, NONE);
    assert!(h.app.fw.dialogs.is_empty(), "{:?}", h.app.log());
    let members = lock(&h.session)
        .execute("interface.list.member.list", &Value::Null)
        .unwrap();
    assert_eq!(members[0]["interface"], "ether2");
    h.app.cache.refreshed_at = None;
    h.idle();
    h.idle();
    assert!(h.has_text("ether2"));
}
