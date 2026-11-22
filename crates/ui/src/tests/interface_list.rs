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

#[test]
fn summary_and_legend_render_in_both_themes_and_follow_columns() {
    let mut h = Harness::new();
    h.screen = egui::vec2(900.0, 600.0);
    h.idle();
    h.click(h.row("ether2"));
    for theme in [egui::Theme::Light, egui::Theme::Dark] {
        h.ctx.set_theme(theme);
        h.idle();
        h.idle();
        assert!(h.has_text("up to 5 min"));
        assert!(h.has_text("Rx"));
        assert!(h.has_text("Tx"));
        assert_eq!(h.selected(), ["ether2"]);
    }
    h.app.tables.interfaces.hidden_columns.insert("Traffic".into());
    h.idle();
    assert!(!h.has_text("up to 5 min"));
}
