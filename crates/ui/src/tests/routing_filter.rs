//! Routing › Filters (G3.2b): the rules with their chips, the lists, the
//! RFC 8212 warning and the commit impact above the tabs, the rule modal
//! fed by the engine's check, the Preview tab, and the ⓘ of every label.

use super::*;
use crate::list::Act;
use crate::routing_filter::{FilterPanel, Tab, What, WIN};

fn lab() -> Session {
    let mut s = Session::virtual_lab();
    for (cmd, p) in [
        ("routing.bgp.instance.set", json!({"asn": 65000, "router_id": "10.0.0.1"})),
        ("routing.bgp.connection.add", json!({"name": "upstream1", "remote_address": "198.51.100.2", "remote_as": 65100})),
        ("routing.bgp.connection.add", json!({"name": "ix-sp", "remote_address": "203.0.113.250", "remote_as": 26162})),
        ("routing.filter.prefix-list.add", json!({"name": "bogons", "entries": "0.0.0.0/8 le 32, 10.0.0.0/8 le 32, 100.64.0.0/10 le 32, 127.0.0.0/8 le 32, 169.254.0.0/16 le 32, 172.16.0.0/12 le 32, 192.168.0.0/16 le 32, 0.0.0.0/0, fc00::/7 le 128", "comment": "RFC 6890"})),
        ("routing.filter.community-list.add", json!({"name": "blackhole", "communities": "blackhole, 65100:666"})),
        ("routing.filter.rule.add", json!({"chain": "upstream-in", "rule": "if (dst in bogons) { reject }", "comment": "bogons"})),
        ("routing.filter.rule.add", json!({"chain": "upstream-in", "rule": "if (afi ipv4 && dst-len > 24) { reject }"})),
        ("routing.filter.rule.add", json!({"chain": "upstream-in", "rule": "if (bgp-communities any-list blackhole) { reject }"})),
        ("routing.filter.rule.add", json!({"chain": "upstream-in", "rule": "if (bgp-as-path \"^65100_\") { set bgp-local-pref 200 } accept"})),
        ("routing.filter.rule.add", json!({"chain": "upstream-out", "rule": "if (dst in 203.0.113.0/24) { set bgp-path-prepend 2; append bgp-communities 65000:10; accept }"})),
        ("routing.bgp.connection.set", json!({"id": "upstream1", "input_filter": "upstream-in", "output_filter": "upstream-out"})),
    ] {
        s.execute(cmd, &p).unwrap_or_else(|e| panic!("{cmd}: {e}"));
    }
    s
}

fn open(s: Session) -> Harness {
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
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

fn panel(h: &mut Harness) -> &mut FilterPanel {
    h.app.panel_mut::<FilterPanel>().unwrap()
}

fn act(h: &mut Harness, a: Act, what: What) {
    let ctx = h.ctx.clone();
    h.app
        .with_panel_as::<FilterPanel, _>(|p, app| {
            let _ = ctx.run_ui(egui::RawInput::default(), |ui| p.act_for_test(app, a.clone(), what, ui));
        })
        .unwrap();
    h.idle();
}

#[test]
fn rules_show_chains_matches_and_actions_and_rfc8212_warns() {
    let mut h = open(lab());
    for t in ["Rules", "upstream-in", "upstream-out", "dst-len", "bgp-communities", "local-pref 200", "accept", "reject", "prepend 2", "bogons", "5 rules", "2 chains"] {
        assert!(h.has_text(t), "{t}");
    }
    // ix-sp is eBGP without chains: the banner says so and what to set.
    assert!(h.has_text("RFC 8212"));
    assert!(h.has_text("eBGP connection ix-sp accepts no route and sends none until it has a filter chain (RFC 8212): set input_filter and output_filter"));
    panel(&mut h).tab = Tab::PrefixLists;
    refresh(&mut h);
    for t in ["bogons", "9", "8", "RFC 6890", "upstream-in", "1 lists", "1 in use"] {
        assert!(h.has_text(t), "{t}");
    }
    panel(&mut h).tab = Tab::CommunityLists;
    refresh(&mut h);
    for t in ["blackhole", "blackhole, 65100:666"] {
        assert!(h.has_text(t), "{t}");
    }
}

#[test]
fn the_modal_adds_a_rule_and_says_where_the_error_is() {
    let mut h = open(lab());
    act(&mut h, Act::Add, What::Rule);
    settle(&mut h);
    assert!(h.has_text("New Filter Rule"));
    let (_, m) = panel(&mut h).modal.as_mut().unwrap();
    m.values.insert("chain", "upstream-in".into());
    m.values.insert("rule", "if (dts in 10.0.0.0/8) { reject }".into());
    settle(&mut h);
    let (_, m) = panel(&mut h).modal.as_ref().unwrap();
    assert!(m.blocking(&crate::routing_filter::RULE_SPEC).is_err_and(|e| e.contains("did you mean \"dst\"")), "{:?}", m.preview);
    let (_, m) = panel(&mut h).modal.as_mut().unwrap();
    m.values.insert("rule", "if (bgp-as-path \"_64666_\") { reject }".into());
    settle(&mut h);
    assert!(h.has_text("Chain passes"));
    h.click(h.text("OK"));
    settle(&mut h);
    let rows = lock(&h.session).execute("routing.filter.rule.list", &json!({"chain": "upstream-in"})).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 5, "{:?}", h.app.log());
    assert!(panel(&mut h).modal.is_none(), "OK closes");
}

#[test]
fn the_preview_tab_counts_what_passes_and_the_banner_the_commit_impact() {
    let mut h = open(lab());
    {
        let p = panel(&mut h);
        p.tab = Tab::Preview;
        p.pv_connection = "upstream1".into();
        p.pv_wanted = true;
    }
    settle(&mut h);
    refresh(&mut h);
    let pv = panel(&mut h).preview.clone().unwrap();
    assert!(pv["rejected"].as_u64().unwrap() > 50, "{pv}");
    let accepted = format!("{} accepted", pv["accepted"]);
    let rejected = format!("{} rejected", pv["rejected"]);
    for t in ["source sample", "5000 routes", accepted.as_str(), rejected.as_str(), "Verdict", "AS Path"] {
        assert!(h.has_text(t), "{t}");
    }
    // A pending change: the banner measures it.
    lock(&h.session).execute("config.mode.set", &json!({"mode": "transactional"})).unwrap();
    let id = lock(&h.session).execute("routing.filter.rule.list", &json!({"chain": "upstream-out"})).unwrap()[0]["id"].clone();
    lock(&h.session).execute("routing.filter.rule.set", &json!({"id": id, "rule": "reject"})).unwrap();
    lock(&h.session).execute("routing.filter.rule.add", &json!({"chain": "upstream-in", "rule": "reject", "place_before": lock(&h.session).execute("routing.filter.rule.list", &json!({})).unwrap()[0]["id"].clone()})).unwrap();
    refresh(&mut h);
    assert!(h.has_text("Commit impact"));
    assert!(panel(&mut h).impact.iter().any(|r| r["message"].as_str().is_some_and(|m| m.contains("rejects") && m.contains("received from AS 65100"))), "{:?}", panel(&mut h).impact);
}

#[test]
fn every_label_explains_itself_in_both_languages() {
    for key in FilterPanel::help_keys() {
        for lang in crate::i18n::Lang::ALL {
            let langs = crate::i18n::Langs { labels: lang, help: lang };
            assert_eq!(crate::i18n::explain(langs, key).map(|(l, _)| l), Some(lang), "{key}");
        }
    }
}
