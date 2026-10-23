//! IP › Firewall XDP (G2.5a), a panel over the lab: interfaces with their
//! mode and counters, the Filter form, the top sources, every ⓘ.

use super::*;
use crate::i18n::{self, Lang, Langs};
use crate::xdp::{HELP_KEYS, Tab, WIN, XdpPanel};
use corerouter_engine::lock;

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..4 {
        h.idle();
    }
}

fn lab() -> Harness {
    let mut h = Harness::with_session(Session::virtual_lab());
    {
        let mut s = lock(&h.session);
        for (id, p) in [
            ("ip.firewall.address-list.add", json!({"list": "attackers", "address": "203.0.113.0/24"})),
            ("ip.firewall.xdp.interface.add", json!({"interface": "ether1"})),
            ("ip.firewall.xdp.set", json!({"block_lists": "attackers"})),
        ] {
            s.execute(id, &p).unwrap_or_else(|e| panic!("{id}: {e}"));
        }
    }
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    refresh(&mut h);
    h
}

fn panel(h: &mut Harness) -> &mut XdpPanel {
    h.app.panel_mut::<XdpPanel>().unwrap()
}

#[test]
fn every_label_is_explained_in_both_languages() {
    for key in HELP_KEYS {
        for l in [Lang::En, Lang::Pt] {
            let got = i18n::explain(Langs { labels: l, help: l }, key);
            assert_eq!(got.map(|(l, _)| l), Some(l), "{key} in {l:?}");
        }
    }
}

#[test]
fn interfaces_show_mode_and_counters() {
    let mut h = lab();
    for t in ["ether1", "auto", "native", "Pass pps", "Blocked", "TCP Flags"] {
        assert!(h.has_text(t), "{t}");
    }
    assert_eq!(panel(&mut h).rows.len(), 1);
    // Reset Counters goes through the router.
    h.click(h.text("Reset Counters"));
    refresh(&mut h);
}

#[test]
fn filter_form_sends_only_what_changed() {
    let mut h = lab();
    h.click(h.text("Filter"));
    refresh(&mut h);
    assert_eq!(panel(&mut h).tab, Tab::Filter);
    for t in ["Block Lists", "Allow Lists", "Drop Malformed", "attackers 1"] {
        assert!(h.has_text(t), "{t}");
    }
    {
        let p = panel(&mut h);
        let mut f = XdpPanel::form_of(&p.filter);
        f.text[2] = "5000".into();
        p.form = Some(f);
    }
    h.idle();
    h.click(h.text("Apply"));
    refresh(&mut h);
    let s = lock(&h.session);
    let filter = &s.store().running().ip.xdp.filter;
    assert_eq!(filter.rate_limit, 5000);
    assert_eq!(filter.block_lists.len(), 1, "untouched");
}

#[test]
fn top_sources_and_the_info_modal() {
    let mut h = lab();
    h.click(h.text("Top Sources"));
    refresh(&mut h);
    assert!(h.has_text("203.0.113.0"), "the blocked prefix as a top source");
    assert!(h.has_text("blocked"));
    // The window's ⓘ opens the Portuguese explanation.
    h.app.lang = Langs::default();
    panel(&mut h).help = Some(crate::help::HelpView::new("xdp", "Firewall XDP"));
    h.idle();
    h.idle();
    assert!(h.has_text("O que é"));
    assert!(h.has_text("Equivalente no RouterOS"));
}
