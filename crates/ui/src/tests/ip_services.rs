//! IP › Services (G1.6p): the list, editing through the preview, and the
//! care with the service that carries this session.

use super::*;
use crate::ip_services::{ServicesPanel, WIN};

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..6 {
        h.idle();
    }
}

fn open(s: Session) -> Harness {
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    refresh(&mut h);
    h
}

fn get(h: &Harness, name: &str) -> Value {
    lock(&h.session).execute(&format!("ip.service.{name}.get"), &json!({})).unwrap()
}

#[test]
fn it_lists_the_three_services_with_their_state() {
    let mut s = Session::virtual_lab();
    s.execute("ip.service.metrics.set", &json!({"enabled": true, "port": 9273, "available_from": ["192.0.2.7"]})).unwrap();
    let h = open(s);
    for text in ["www-ssl", "www", "metrics", "443", "80", "9273", "192.0.2.7/32", "everyone", "stopped", ":: (all)"] {
        assert!(h.has_text_containing(text), "{text}");
    }
    assert!(!h.has_text("this session"), "this window runs inside the process");
}

#[test]
fn enable_and_disable_go_through_the_command() {
    let mut h = open(Session::virtual_lab());
    assert_eq!(get(&h, "www")["enabled"], false);
    h.app.with_panel_as::<ServicesPanel, _>(|p, app| p.act_for_test(app, crate::list::Act::Enable(vec!["www".into()])));
    refresh(&mut h);
    assert_eq!(get(&h, "www")["enabled"], true);
    assert!(h.has_text_containing("only redirects to www-ssl"), "the warning of set");
    h.app.with_panel_as::<ServicesPanel, _>(|p, app| p.act_for_test(app, crate::list::Act::Disable(vec!["www".into()])));
    refresh(&mut h);
    assert_eq!(get(&h, "www")["enabled"], false);
}

#[test]
fn the_modal_edits_and_the_preview_says_what_is_wrong() {
    let mut h = open(Session::virtual_lab());
    h.app.with_panel_as::<ServicesPanel, _>(|p, app| p.act_for_test(app, crate::list::Act::Edit("metrics".into())));
    refresh(&mut h);
    assert!(h.has_text_containing("IP Service <metrics>"));
    let set = |h: &mut Harness, k: &'static str, v: &str| {
        h.app.panel_mut::<ServicesPanel>().unwrap().modal.as_mut().unwrap().values.insert(k, v.to_owned());
        h.time += 1.0;
        refresh(h);
    };
    set(&mut h, "port", "99999");
    assert!(h.has_text_containing("must be 1..=65535"), "under the field");
    set(&mut h, "port", "9273");
    assert!(h.has_text_containing("/ip service metrics set port=9273"), "the preview of the command");
    h.click(h.text("OK"));
    refresh(&mut h);
    assert_eq!(get(&h, "metrics")["port"], 9273);
    assert!(h.app.panel_mut::<ServicesPanel>().unwrap().modal.is_none());
}

#[test]
fn the_service_of_this_session_is_marked_and_a_refusal_asks_as_any_lockout() {
    let mut h = open(Session::virtual_lab());
    // The rows of a session through `www-ssl` (the engine's tests and the
    // WSS run check `this_session` itself).
    let rows = lock(&h.session).execute("ip.service.print", &json!({})).unwrap();
    let mut rows = rows.as_array().unwrap().clone();
    rows[0]["this_session"] = json!(true);
    h.app.panel_mut::<ServicesPanel>().unwrap().rows = rows;
    h.idle();
    h.idle();
    assert!(h.has_text("this session"));
    assert!(h.has_text_containing("This window reaches the router through www-ssl"));
    // The command declares `force`, so the app's window can offer it.
    let refusal = Err("lockout: would turn off www-ssl".to_owned());
    let then = crate::panel::then("ip-services", ());
    let held = h.app.hold_lockout("ip.service.www-ssl.set".into(), json!({"enabled": false}), then, &refusal);
    assert!(held.is_none(), "held for the operator");
    h.idle();
    h.idle();
    h.idle();
    assert!(h.has_text("Safe Mode, then apply"));
    h.click(h.text("Apply anyway"));
    refresh(&mut h);
    assert_eq!(get(&h, "www-ssl")["enabled"], false);
}

#[test]
fn the_bar_says_there_is_nothing_to_add_and_acts_on_the_selection() {
    let mut h = open(Session::virtual_lab());
    h.click(h.text("www"));
    refresh(&mut h);
    h.click(h.ctx.read_response(table::tool_id("ip-services", table::Icon::Enable)).unwrap().rect.center());
    refresh(&mut h);
    assert_eq!(get(&h, "www")["enabled"], true);
    // + and − stay grey: a click does nothing.
    h.click(h.ctx.read_response(table::tool_id("ip-services", table::Icon::Add)).unwrap().rect.center());
    refresh(&mut h);
    assert!(h.app.panel_mut::<ServicesPanel>().unwrap().modal.is_none());
}

#[test]
fn every_explanation_exists_in_both_languages() {
    for key in ["menu.ip-services", "ip_services.address", "ip_services.available_from", "ip_services.enabled", "ip_services.last_error", "ip_services.name", "ip_services.port", "ip_services.refused", "ip_services.status"] {
        for lang in [crate::i18n::Lang::En, crate::i18n::Lang::Pt] {
            let langs = crate::i18n::Langs { labels: lang, help: lang };
            let (got, _) = crate::i18n::explain(langs, key).unwrap();
            assert_eq!(got, lang, "{key}");
        }
    }
}
