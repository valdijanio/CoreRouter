//! The interface list keeps the operator's column choices and comments.
use super::*;

#[test]
fn columns_are_local_and_preserve_inline_comments() {
    let mut h = Harness::new();
    lock(&h.session).execute("interface.set", &json!({"name":"ether2", "comment":"uplink"})).unwrap();
    h.app.cache.refreshed_at = None;
    h.idle();
    h.idle();
    h.right_click(h.row("ether1"));
    h.click(h.text("Inline Comments"));
    assert!(h.has_text("uplink"));
    h.click(h.text("Columns"));
    h.click(h.text("MTU"));
    assert!(h.app.tables.interfaces.hidden_columns.contains("MTU"));
    assert!(h.has_text("uplink"));
    let prefs = h.app.prefs();
    let mut restored = CoreRouterUi::new(shared(Session::virtual_lab()));
    restored.apply_prefs(&prefs);
    assert!(restored.tables.interfaces.inline_comments);
    assert!(restored.tables.interfaces.hidden_columns.contains("MTU"));
}
