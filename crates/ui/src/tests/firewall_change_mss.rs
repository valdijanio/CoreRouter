//! G1.31d: a mangle `change-mss` rule made in the rule window, with the
//! ⓘ of its new fields.

use super::*;
use crate::dialog;
use crate::firewall::{Edit, FwTable, Tab};
use egui::Key;

const NONE: egui::Modifiers = egui::Modifiers::NONE;

#[test]
fn change_mss_rule_from_the_window() {
    let mut h = Harness::new();
    h.app.open.clear();
    h.app.open(Win::Firewall);
    h.app.fw.tab = Tab::Mangle;
    h.app.cache.refreshed_at = None;
    h.idle();
    h.idle();
    h.click(h.fw_tool(FwTable::Mangle, table::Icon::Add).rect.center());
    assert!(h.has_text("New Mangle Rule"));
    let win = interfaces::dialog_id(h.app.fw.dialogs[0].id);
    let field = |h: &Harness, p: &str| {
        h.ctx
            .read_response(dialog::field_id(win, p))
            .unwrap_or_else(|| panic!("no field {p}"))
            .rect
            .center()
    };
    h.click(field(&h, "protocol"));
    h.type_text("tcp");
    h.click(h.text("Advanced"));
    assert!(h.has_text("TCP Flags"));
    h.click(field(&h, "tcp_flags"));
    h.type_text("syn");
    h.click(h.text("Action"));
    assert!(!h.has_text("New MSS"), "only with action=change-mss");
    if let Edit::Rule { form, .. } = &mut h.app.fw.dialogs[0].edit {
        form.set("action", "change-mss");
        form.set("chain", "forward");
    }
    h.idle();
    assert!(h.has_text("New MSS") && h.has_text("Passthrough"));
    h.click(field(&h, "new_mss"));
    h.type_text("clamp-to-pmtu");
    // The ⓘ of New MSS opens its explanation.
    let info = h
        .ctx
        .read_response(win.with(("help", "firewall.rule.new_mss")))
        .expect("an ⓘ next to New MSS");
    h.click(info.rect.center());
    assert_eq!(
        h.app.fw.help.as_ref().map(|v| v.key.as_str()),
        Some("firewall.rule.new_mss")
    );
    assert!(h.has_text("clamp-to-pmtu"));
    h.app.fw.help = None;
    h.idle();
    h.click(field(&h, "new_mss"));
    h.key(Key::Enter, NONE);
    assert!(h.app.fw.dialogs.is_empty(), "OK closes on success");
    let list = lock(&h.session)
        .execute("ip.firewall.mangle.list", &Value::Null)
        .unwrap();
    let r = &list[0];
    assert_eq!(r["action"], "change-mss");
    assert_eq!(r["new_mss"], "clamp-to-pmtu");
    assert_eq!(r["tcp_flags"], "syn");
    assert_eq!(r["chain"], "forward");
}
