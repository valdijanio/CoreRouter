//! IPv6 › ND (G3.9ha): the Interfaces tab with the entries and every
//! interface they reach (skipped ones with the reason), the Prefixes tab
//! with dynamic and static prefixes, the modals fed by the engine's
//! previews, and the ⓘ of every label in both languages.

use super::*;
use crate::ipv6_nd::{NdPanel, Tab, What};
use crate::list::Act;

fn lab() -> Session {
    let mut s = Session::virtual_lab();
    s.execute("ip.address.add", &json!({"address": "2001:db8:2::1/64", "interface": "ether2"})).unwrap();
    s.execute("ip.address.add", &json!({"address": "2001:db8:1::2/64", "interface": "ether1"})).unwrap();
    s.execute("ip.route.add", &json!({"dst_address": "::/0", "gateway": "2001:db8:1::1"})).unwrap();
    s.execute("ipv6.nd.add", &json!({"interface": "all", "ra_interval": "3s-5s"})).unwrap();
    s
}

fn open(s: Session) -> Harness {
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(crate::ipv6_nd::WIN));
    refresh(&mut h);
    h
}

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..4 {
        h.idle();
    }
}

fn settle(h: &mut Harness) {
    for _ in 0..30 {
        h.idle();
    }
}

fn panel(h: &mut Harness) -> &mut NdPanel {
    h.app.panel_mut::<NdPanel>().unwrap()
}

fn act(h: &mut Harness, what: What, a: Act) {
    let ctx = h.ctx.clone();
    h.app
        .with_panel_as::<NdPanel, _>(|p, app| {
            let _ = ctx.run_ui(egui::RawInput::default(), |ui| p.act_for_test(app, what, a.clone(), ui));
        })
        .unwrap();
    h.idle();
}

#[test]
fn interfaces_tab_shows_where_ras_go_and_why_not() {
    let h = open(lab());
    for t in [
        "Interfaces", "Prefixes", "all interfaces", "3s-5s", "30m", "1 advertising", "skipped", "ether2",
        "waiting", "2001:db8:2::/64", "WAN: the IPv6 default route leaves through it", "sender stopped (virtual lab)", "Interfaces reached",
    ] {
        assert!(h.has_text(t), "{t}");
    }
}

#[test]
fn prefixes_tab_lists_dynamic_ones() {
    let mut h = open(lab());
    panel(&mut h).tab = Tab::Prefixes;
    refresh(&mut h);
    for t in ["2001:db8:2::/64", "4w2d", "1w", "address", "1 prefixes"] {
        assert!(h.has_text(t), "{t}");
    }
}

#[test]
fn the_modal_adds_an_entry_through_the_preview() {
    let mut s = Session::virtual_lab();
    s.execute("ip.address.add", &json!({"address": "2001:db8:3::1/64", "interface": "ether3"})).unwrap();
    let mut h = open(s);
    act(&mut h, What::Entry, Act::Add);
    settle(&mut h);
    assert!(h.has_text("New ND Interface"));
    let (_, m) = panel(&mut h).modal.as_mut().unwrap();
    m.values.insert("interface", "ether3".into());
    m.values.insert("ra_interval", "3s-4s".into());
    settle(&mut h);
    assert!(h.has_text("ether3 (2001:db8:3::/64)"), "the preview's computed field");
    h.click(h.text("OK"));
    settle(&mut h);
    let nd = lock(&h.session).store().candidate().ipv6.nd.clone();
    assert_eq!(nd.interfaces.len(), 1, "{:?}", h.app.log());
    assert_eq!((nd.interfaces[0].ra_interval_min, nd.interfaces[0].ra_interval_max), (3, 4));
    assert!(panel(&mut h).modal.is_none(), "OK closes");
}

#[test]
fn a_dynamic_prefix_opens_as_a_new_static_one() {
    let mut h = open(lab());
    panel(&mut h).tab = Tab::Prefixes;
    refresh(&mut h);
    act(&mut h, What::Prefix, Act::Edit("2001:db8:2::/64@ether2".into()));
    settle(&mut h);
    assert!(h.has_text("New ND Prefix"));
    let (_, m) = panel(&mut h).modal.as_mut().unwrap();
    assert_eq!(m.values.get("prefix").map(String::as_str), Some("2001:db8:2::/64"));
    m.values.insert("disabled", "yes".into());
    settle(&mut h);
    h.click(h.text("OK"));
    settle(&mut h);
    let nd = lock(&h.session).store().candidate().ipv6.nd.clone();
    assert!(nd.prefixes.first().is_some_and(|p| p.disabled), "{:?}", h.app.log());
}

#[test]
fn dns_shows_in_the_entry_and_the_interfaces_reached() {
    let mut s = lab();
    s.execute("ipv6.nd.add", &json!({"interface": "ether2", "advertise_dns": true, "dns": "2001:db8::53"})).unwrap();
    let h = open(s);
    for t in ["DNS", "2001:db8::53"] {
        assert!(h.has_text(t), "{t}");
    }
}

#[test]
fn every_label_explains_itself_in_both_languages() {
    for key in NdPanel::help_keys() {
        for lang in crate::i18n::Lang::ALL {
            let langs = crate::i18n::Langs { labels: lang, help: lang };
            assert_eq!(crate::i18n::explain(langs, key).map(|(l, _)| l), Some(lang), "{key}");
        }
    }
}
