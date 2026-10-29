//! PPP › PPPoE Client (G3.9ga): the list against the lab's simulated BNG,
//! the monitor of the selected client, Reconnect, the modal's preview, the
//! menu entries under PPP and the Interfaces window's `pppoe-out` row.

use super::*;
use crate::pppoe_client::{TABLE, WIN};

/// A lab session with one client up on the lab BNG.
fn dialed() -> Session {
    let mut s = Session::virtual_lab();
    s.tick(1_000);
    s.execute(
        "interface.pppoe-client.add",
        &json!({"name": "pppoe-out1", "interface": "ether1", "user": "cliente@isp", "password": "p",
                "allow": "pap", "add_default_route": true}),
    )
    .unwrap();
    for t in 0..8 {
        s.dhcp_service(1_000 + t * 250);
    }
    s
}

fn opened(s: Session) -> Harness {
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    h.app.cache.refreshed_at = None;
    h.idle();
    h.idle();
    h
}

#[test]
fn pppoe_client_window_lists_the_session_and_its_monitor() {
    let mut h = opened(dialed());
    assert!(h.has_text("connected"), "state chip");
    assert!(h.has_text("cliente@isp"), "user column");
    assert!(h.has_text_containing("100.64.0."), "address column");
    assert!(h.has_text_containing("distance 1"), "default route column");
    // Selecting the row shows its monitor under the table.
    let row = h
        .ctx
        .read_response(table::row_id(TABLE, "pppoe-out1"))
        .expect("row drawn")
        .rect
        .center();
    h.click(row);
    h.app.cache.refreshed_at = None;
    h.idle();
    h.idle();
    assert!(h.has_text(corerouter_engine::pppoe_client::LAB_AC_NAME), "AC Name in the monitor");
    assert!(h.has_text("pap"), "Encoding in the monitor");
    h.click(h.text("Reconnect"));
    assert!(
        h.app
            .log()
            .iter()
            .any(|l| l.ok && l.command == "interface.pppoe-client.reconnect"),
        "{:?}",
        h.app.log()
    );
}

#[test]
fn a_refused_login_shows_why_and_when_it_redials() {
    let mut s = dialed();
    s.execute("interface.pppoe-client.set", &json!({"name": "pppoe-out1", "password": "wrong"}))
        .unwrap();
    for t in 0..8 {
        s.dhcp_service(5_000 + t * 250);
    }
    let h = opened(s);
    assert!(h.has_text("disconnected"), "state chip");
    assert!(h.has_text("login refused"), "the reason chip");
    assert!(h.has_text_containing("redial in"), "when it dials again");
}

#[test]
fn new_client_modal_previews_and_adds() {
    let mut h = opened(Session::virtual_lab());
    let ctx = h.ctx.clone();
    h.app
        .with_panel_as::<crate::pppoe_client::PppoeClientPanel, _>(|p, app| {
            let _ = ctx.run_ui(egui::RawInput::default(), |ui| p.act_for_test(app, crate::list::Act::Add, ui));
        })
        .unwrap();
    for _ in 0..30 {
        h.idle();
    }
    assert!(h.has_text("New PPPoE Client") || h.has_text("Novo cliente PPPoE"), "the modal");
    let m = h
        .app
        .panel_mut::<crate::pppoe_client::PppoeClientPanel>()
        .unwrap()
        .modal
        .as_mut()
        .unwrap();
    m.values.insert("interface", "ether1".into());
    m.values.insert("user", "cliente@isp".into());
    m.values.insert("password", "p".into());
    for _ in 0..30 {
        h.idle();
    }
    // RouterOS defaults: no default route, so the preview warns.
    assert!(h.has_text_containing("no default route"), "the preview's warning");
    h.click(h.text("OK"));
    for _ in 0..4 {
        h.idle();
    }
    let rows = lock(&h.session)
        .execute("interface.pppoe-client.list", &Value::Null)
        .unwrap();
    assert_eq!(rows[0]["name"], "pppoe-out1", "default name");
    assert_eq!(rows[0]["max_mtu"], 1460);
}

#[test]
fn ppp_menu_has_the_server_and_the_client() {
    assert_eq!(crate::menu::label(Win::Panel(crate::ppp::WIN)), "PPPoE Server (BNG)");
    assert_eq!(crate::menu::label(Win::Panel(WIN)), "PPPoE Client");
    let ppp = crate::windows::menu()
        .into_iter()
        .find(|(g, _)| *g == "PPP")
        .map(|(_, items)| items)
        .unwrap();
    assert!(ppp.contains(&Win::Panel(WIN)) && ppp.contains(&Win::Panel(crate::ppp::WIN)));
    // The RouterOS path finds it.
    let hits = crate::menu_search::search("/interface pppoe-client", std::iter::empty());
    assert!(
        matches!(hits.first(), Some(crate::menu_search::Hit::Win(w)) if *w == Win::Panel(WIN)),
        "{hits:?}"
    );
}

#[test]
fn every_explanation_of_the_window_exists_in_both_languages() {
    for key in [
        "menu.pppoe-client",
        "interface.pppoe-client",
        "interface.pppoe-client.status",
        "interface.pppoe-client.max_mtu",
        "interface.pppoe-client.add_default_route",
    ] {
        for lang in [crate::i18n::Lang::Pt, crate::i18n::Lang::En] {
            let langs = crate::i18n::Langs { labels: lang, help: lang };
            let (got, _) = crate::i18n::explain(langs, key).unwrap_or_else(|| panic!("{key}"));
            assert_eq!(got, lang, "{key} in {lang:?}");
        }
    }
}
