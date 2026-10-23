//! IP › Addresses (G1.28), the reference list window: chips, the bar, the
//! modal with the engine's preview (series, overlap), and the access
//! confirmation of ✗ and −.

use super::*;
use crate::ip_address::AddressPanel;
use crate::list::Act;

fn open(s: Session) -> Harness {
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Addresses);
    refresh(&mut h);
    h
}

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..3 {
        h.idle();
    }
}

/// Enough frames for the modal's pause before it asks for a preview.
fn settle(h: &mut Harness) {
    for _ in 0..30 {
        h.idle();
    }
}

fn panel(h: &mut Harness) -> &mut AddressPanel {
    h.app.panel_mut::<AddressPanel>().unwrap()
}

fn act(h: &mut Harness, a: Act) {
    let ctx = h.ctx.clone();
    h.app
        .with_panel_as::<AddressPanel, _>(|p, app| {
            let _ = ctx.run_ui(egui::RawInput::default(), |ui| p.act_for_test(app, a.clone(), ui));
        })
        .unwrap();
    h.idle();
}

fn addresses(h: &Harness) -> Vec<Value> {
    lock(&h.session)
        .execute("ip.address.list", &Value::Null)
        .unwrap()
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn the_list_shows_state_chips_and_the_footer() {
    let mut s = Session::virtual_lab();
    s.execute("ip.address.add", &json!({"address": "10.0.0.1/24", "interface": "ether1"})).unwrap();
    s.execute("ip.address.add", &json!({"address": "2001:db8::1/64", "interface": "ether2", "disabled": true}))
        .unwrap();
    let mut h = open(s);
    for t in ["10.0.0.1/24", "2001:db8::1/64", "active", "disabled", "ether1", "2 addresses", "1 IPv4", "1 IPv6"] {
        assert!(h.has_text(t), "{t}");
    }
    // The family chip filters.
    h.click(h.text("IPv6"));
    assert!(!h.has_text("10.0.0.1/24"));
    h.click(h.text("IPv6"));
    assert!(h.has_text("10.0.0.1/24"));
}

#[test]
fn enable_and_disable_go_to_the_engine() {
    let mut s = Session::virtual_lab();
    let id = s
        .execute("ip.address.add", &json!({"address": "10.0.0.1/24", "interface": "ether1"}))
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut h = open(s);
    act(&mut h, Act::Disable(vec![id.clone()]));
    assert_eq!(addresses(&h)[0]["state"], "disabled");
    act(&mut h, Act::Enable(vec![id.clone()]));
    assert_eq!(addresses(&h)[0]["state"], "active");
    act(&mut h, Act::Remove(vec![id]));
    assert!(addresses(&h).is_empty());
}

#[test]
fn the_modal_adds_a_series_in_one_go() {
    let mut h = open(Session::virtual_lab());
    act(&mut h, Act::Add);
    settle(&mut h);
    assert!(h.has_text("New Address"));
    let m = panel(&mut h).modal.as_mut().unwrap();
    m.values.insert("address", "10.20.0.1/24".into());
    m.values.insert("to", "10.20.0.5".into());
    m.values.insert("interface", "ether1".into());
    settle(&mut h);
    for t in ["10.20.0.0/24", "10.20.0.255", "254", "5 addresses, one transaction"] {
        assert!(h.has_text(t), "{t}");
    }
    assert!(h.has_text("/ip address add address=10.20.0.5/24 interface=ether1"), "the commands");
    h.click(h.text("OK"));
    settle(&mut h);
    assert_eq!(addresses(&h).len(), 5, "{:?}", h.app.log());
    assert!(panel(&mut h).modal.is_none(), "OK closes");
}

#[test]
fn an_overlap_keeps_ok_grey_and_says_why_by_the_field() {
    let mut s = Session::virtual_lab();
    s.execute("ip.address.add", &json!({"address": "10.0.0.1/16", "interface": "ether2"})).unwrap();
    let mut h = open(s);
    act(&mut h, Act::Add);
    let m = panel(&mut h).modal.as_mut().unwrap();
    m.values.insert("address", "10.0.5.1/24".into());
    m.values.insert("interface", "ether1".into());
    settle(&mut h);
    assert!(h.has_text("error"));
    let m = panel(&mut h).modal.as_ref().unwrap();
    assert!(m.blocking(&crate::ip_address::SPEC).is_err_and(|e| e.contains("overlaps")));
    h.key(egui::Key::Enter, egui::Modifiers::NONE);
    settle(&mut h);
    assert_eq!(addresses(&h).len(), 1, "Enter did nothing");
    h.key(egui::Key::Escape, egui::Modifiers::NONE);
    assert!(panel(&mut h).modal.is_none(), "Esc closes");
}

#[test]
fn apply_keeps_the_modal_open_and_double_click_edits() {
    let mut h = open(Session::virtual_lab());
    act(&mut h, Act::Add);
    let m = panel(&mut h).modal.as_mut().unwrap();
    m.values.insert("address", "10.1.0.1/24".into());
    m.values.insert("interface", "ether1".into());
    m.values.insert("arp", "no".into());
    settle(&mut h);
    h.click(h.text("Apply"));
    settle(&mut h);
    assert_eq!(addresses(&h).len(), 1);
    assert!(panel(&mut h).modal.is_some(), "Apply keeps it open");
    h.key(egui::Key::Escape, egui::Modifiers::NONE);

    let id = addresses(&h)[0]["id"].as_str().unwrap().to_owned();
    act(&mut h, Act::Edit(id.clone()));
    settle(&mut h);
    assert!(h.has_text("Address <10.1.0.1/24>"));
    panel(&mut h).modal.as_mut().unwrap().values.insert("comment", "uplink".into());
    settle(&mut h);
    assert!(h.has_text(&format!("/ip address set {id} comment=uplink")));
    h.click(h.text("OK"));
    settle(&mut h);
    assert_eq!(addresses(&h)[0]["comment"], "uplink");
}

#[test]
fn the_access_address_asks_before_the_bar_acts() {
    let mut s = Session::virtual_lab();
    let id = s
        .execute("ip.address.add", &json!({"address": "192.168.88.1/24", "interface": "ether2"}))
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut h = open(s);
    // As a remote session would see it.
    if let Some(r) = h.app.cache.addresses.first_mut() {
        r["access"] = json!("this session (tcp 192.168.88.10:5 -> 192.168.88.1:8729) connects to this address");
    }
    let ctx = h.ctx.clone();
    h.app
        .with_panel_as::<AddressPanel, _>(|p, app| {
            let _ = ctx.run_ui(egui::RawInput::default(), |ui| {
                p.act_for_test(app, Act::Disable(vec![id.clone()]), ui);
            });
        })
        .unwrap();
    let held = h.app.lockout.as_ref().expect("asks first");
    assert_eq!(held.command, "ip.address.set");
    assert_eq!(held.params, json!({"id": id, "disabled": true}));
    assert_eq!(addresses(&h)[0]["state"], "active", "nothing sent yet");
    h.app.lockout_answer(crate::lockout::Choice::Force);
    h.idle();
    assert_eq!(addresses(&h)[0]["state"], "disabled");
}

#[test]
fn every_column_explains_itself() {
    let mut s = Session::virtual_lab();
    s.execute("ip.address.add", &json!({"address": "10.0.0.1/24", "interface": "ether1"})).unwrap();
    let mut h = open(s);
    let at = h
        .ctx
        .read_response(crate::table::table_id("addresses").with(("help", 1usize)))
        .expect("the Address column has an ⓘ")
        .rect
        .center();
    h.click(at);
    let help = panel(&mut h).help.clone().expect("the ⓘ opens the explanation");
    assert_eq!(help.key, "ip.address.address");
    // Every key the window uses has its text, in both languages.
    for key in ["ip.address.state", "ip.address.network", "ip.address.vrf", "ip.address.lifetime"] {
        for lang in crate::i18n::Lang::ALL {
            let langs = crate::i18n::Langs { labels: lang, help: lang };
            assert_eq!(crate::i18n::explain(langs, key).map(|(l, _)| l), Some(lang), "{key}");
        }
    }
}
