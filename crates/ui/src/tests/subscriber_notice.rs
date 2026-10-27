//! IP › Subscriber Notices (G4.10): profiles, walled garden, pages, active,
//! log, Test as Client, and "Block (com página)" in the lease and secret lists.

use super::*;
use crate::subscriber_notice::{NoticePanel, Tab, WIN, active_row, profile_row};

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..3 {
        h.idle();
    }
}

fn lab() -> Session {
    let mut s = Session::virtual_lab();
    s.tick(1_800_000_000);
    for (id, p) in [
        ("ip.address.add", json!({"address": "100.64.0.1/16", "interface": "ether2"})),
        ("ip.subscriber-notice.profile.add", json!({"name": "atraso", "mode": "block", "address_list": "bloqueados", "comment": "inadimplentes"})),
        ("ip.subscriber-notice.profile.add", json!({"name": "aviso", "mode": "notice", "address_list": "aviso", "interval": "6h"})),
        ("ip.subscriber-notice.walled-garden.add", json!({"dst_host": "pix.banco.com.br", "comment": "PIX"})),
        ("ip.subscriber-notice.page.add", json!({"name": "provedor", "title": "Provedor Exemplo", "text": "Olá {login}, sua fatura de {valor} venceu.", "color": "#2e7d32"})),
        ("ip.firewall.address-list.add", json!({"list": "bloqueados", "address": "100.64.0.10", "comment": "cliente 10"})),
        ("ip.firewall.address-list.add", json!({"list": "aviso", "address": "100.64.0.20"})),
    ] {
        s.execute(id, &p).unwrap();
    }
    s.notice_tick();
    s.notice_mark_seen("100.64.0.20".parse().unwrap(), "android", "Dalvik/2.1");
    s
}

fn open(s: Session) -> Harness {
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    refresh(&mut h);
    h
}

#[test]
fn profiles_show_mode_and_list_chips() {
    let mut h = open(lab());
    assert!(h.has_text("Subscriber Notices"));
    assert!(h.has_text("atraso"));
    assert!(h.has_text_containing("refused"), "the behaviour column");
    let p = h.app.panel_mut::<NoticePanel>().unwrap();
    let row = profile_row(&p.profiles[0]);
    assert_eq!(crate::chip::split(&row.cells[1]).1, vec![(crate::chip::Kind::Red, "block")]);
    assert!(matches!(crate::chip::split(&row.cells[2]).1[0].0, crate::chip::Kind::Hashed(_)), "list chip by key");
    assert!(h.has_text_containing("OS probes"), "the portal strip");
}

#[test]
fn every_tab_renders() {
    let mut h = open(lab());
    for (tab, needle) in [
        (Tab::Garden, "pix.banco.com.br"),
        (Tab::Pages, "Preview (sample values)"),
        (Tab::Active, "100.64.0.10"),
        (Tab::Log, "android"),
    ] {
        h.app.panel_mut::<NoticePanel>().unwrap().tab = tab;
        refresh(&mut h);
        assert!(h.has_text_containing(needle), "{tab:?}: {needle}");
    }
    let p = h.app.panel_mut::<NoticePanel>().unwrap();
    let rows = p.active["rows"].as_array().unwrap().clone();
    let seen = rows.iter().find(|r| r["address"] == "100.64.0.20").unwrap();
    assert!(active_row(seen).cells[6].contains("seen"));
}

#[test]
fn the_page_editor_previews_unsaved_text_and_saves() {
    let mut h = open(lab());
    {
        let p = h.app.panel_mut::<NoticePanel>().unwrap();
        p.tab = Tab::Pages;
        p.select_page(Some("provedor".into()));
    }
    refresh(&mut h);
    assert!(h.has_text("Provedor Exemplo"));
    h.app.panel_mut::<NoticePanel>().unwrap().form.text = "Pague {valor} até amanhã".into();
    refresh(&mut h);
    assert!(h.has_text_containing("R$ 99,90"), "the engine filled the sample value");
    h.click(h.text("Save"));
    refresh(&mut h);
    let pages = lock(&h.session).execute("ip.subscriber-notice.page.print", &json!({})).unwrap();
    assert_eq!(pages[0]["text"], "Pague {valor} até amanhã");
}

#[test]
fn test_as_client_shows_the_result() {
    let mut h = open(lab());
    h.app.panel_mut::<NoticePanel>().unwrap().tab = Tab::Active;
    refresh(&mut h);
    h.click(h.text("100.64.0.10"));
    h.idle();
    h.click(h.text("Test as Client"));
    refresh(&mut h);
    assert!(h.has_text_containing("refused"), "HTTPS refused");
    assert!(h.has_text_containing("android ×"), "the probes by OS");
}

#[test]
fn every_label_has_an_explanation_in_both_languages() {
    use crate::i18n::{Lang, Langs, explain};
    for key in [
        "menu.subscriber-notice",
        "subscriber-notice.profile",
        "subscriber-notice.profile.mode",
        "subscriber-notice.profile.address_list",
        "subscriber-notice.profile.intercept",
        "subscriber-notice.profile.interval",
        "subscriber-notice.profile.timeout",
        "subscriber-notice.profile.rate_limit",
        "subscriber-notice.profile.kill_connections",
        "subscriber-notice.profile.webhook",
        "subscriber-notice.profile.behaviour",
        "subscriber-notice.garden",
        "subscriber-notice.garden.dst_host",
        "subscriber-notice.garden.dst_address",
        "subscriber-notice.garden.addresses",
        "subscriber-notice.active.source",
        "subscriber-notice.active.seen",
        "subscriber-notice.log",
        "subscriber-notice.log.via",
        "subscriber-notice.test",
        "subscriber-notice.pages",
        "subscriber-notice.page.text",
        "subscriber-notice.page.button_url",
        "subscriber-notice.portal",
    ] {
        for l in [Lang::En, Lang::Pt] {
            let got = explain(Langs { labels: l, help: l }, key).map(|(lang, _)| lang);
            assert_eq!(got, Some(l), "{key} in {l:?}");
        }
    }
}

#[test]
fn leases_and_secrets_offer_block_with_page() {
    let mut s = lab();
    s.execute("ip.dhcp-server.lease.add", &json!({"address": "100.64.0.50", "mac_address": "02:00:00:00:00:50"})).unwrap();
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(crate::dhcp_server::WIN));
    refresh(&mut h);
    if let Some(p) = h.app.panel_mut::<crate::dhcp_server::DhcpServerPanel>() {
        p.tab = crate::dhcp_server::Tab::Leases;
    }
    refresh(&mut h);
    assert!(h.has_text("Block (com página)"), "the lease list has the action");
}
