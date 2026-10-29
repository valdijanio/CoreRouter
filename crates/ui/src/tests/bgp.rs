//! Routing › BGP (G3.2a): the Sessions tab with the live state joined to
//! the connections and the detail of the selected one, the Connections and
//! Templates lists with the modal fed by the engine's preview, and the ⓘ
//! of every label.

use super::*;
use crate::bgp::{BgpPanel, Tab, What};
use crate::list::Act;
use corerouter_model::routing_state::{BgpSession, RoutingStatus};

fn lab() -> Session {
    let mut s = Session::virtual_lab();
    s.execute("routing.bgp.instance.set", &json!({"asn": 65000, "router_id": "10.0.0.1"})).unwrap();
    s.execute(
        "routing.bgp.template.add",
        &json!({"name": "transit", "local_role": "ebgp-customer", "hold_time": 90, "afi": "ip,ipv6", "max_prefix_ipv4": 1200000}),
    )
    .unwrap();
    s.execute(
        "routing.bgp.connection.add",
        &json!({"name": "upstream1", "remote_address": "198.51.100.2", "remote_as": 65100, "templates": "transit", "tcp_md5_key": "k3y"}),
    )
    .unwrap();
    s.execute(
        "routing.bgp.connection.add",
        &json!({"name": "rr1", "remote_address": "10.255.0.2", "local_role": "ibgp", "comment": "route reflector"}),
    )
    .unwrap();
    s.set_routing_status(RoutingStatus {
        backend: "frr 10.7.1".into(),
        updated: Some(1),
        error: None,
        bgp_sessions: vec![
            BgpSession {
                instance: "default".into(),
                vrf: "default".into(),
                remote_address: "198.51.100.2".into(),
                remote_as: 65100,
                local_as: 65000,
                state: "established".into(),
                established: true,
                uptime_secs: Some(93_784),
                prefix_count: Some(951_234),
                prefix_sent: Some(12),
                connection: Some("upstream1".into()),
                hold_time: Some(90),
                keepalive_time: Some(30),
                flaps: Some(2),
                bfd: Some("up".into()),
                afi: vec!["ipv4".into(), "ipv6".into()],
                ..BgpSession::default()
            },
            BgpSession {
                instance: "default".into(),
                vrf: "default".into(),
                remote_address: "10.255.0.2".into(),
                remote_as: 65000,
                local_as: 65000,
                state: "active".into(),
                connection: Some("rr1".into()),
                reason: Some("Waiting for peer OPEN".into()),
                last_error: Some("Hold Timer Expired".into()),
                flaps: Some(7),
                ..BgpSession::default()
            },
        ],
        ..RoutingStatus::default()
    });
    s
}

fn open(s: Session) -> Harness {
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Bgp);
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

fn panel(h: &mut Harness) -> &mut BgpPanel {
    h.app.panel_mut::<BgpPanel>().unwrap()
}

fn act(h: &mut Harness, a: Act, what: What) {
    let ctx = h.ctx.clone();
    h.app
        .with_panel_as::<BgpPanel, _>(|p, app| {
            let _ = ctx.run_ui(egui::RawInput::default(), |ui| p.act_for_test(app, a.clone(), what, ui));
        })
        .unwrap();
    h.idle();
}

#[test]
fn sessions_show_the_live_state_and_the_detail() {
    let mut h = open(lab());
    for t in ["Sessions", "upstream1", "rr1", "established", "active", "AS65100", "1d02:03:04", "951234", "2 sessions", "1 established", "1 down"] {
        assert!(h.has_text(t), "{t}");
    }
    // The selected session shows what the table has no room for.
    h.click(h.text("rr1"));
    h.idle();
    for t in ["Hold Timer Expired", "Flaps", "7", "Policy In", "none"] {
        assert!(h.has_text(t), "{t}");
    }
    // Actions go to the engine (no routing daemon in the lab: the refusal
    // is shown, nothing changes).
    h.click(h.text("Shutdown"));
    refresh(&mut h);
    let rows = lock(&h.session).execute("routing.bgp.connection.list", &json!({})).unwrap();
    let rr1 = rows.as_array().unwrap().iter().find(|r| r["name"] == "rr1").unwrap();
    assert_eq!(rr1["disabled"], true, "{:?}", h.app.log());
    assert!(h.has_text("disabled"));
}

#[test]
fn connections_and_templates_list_with_their_chips() {
    let mut h = open(lab());
    panel(&mut h).tab = Tab::Connections;
    refresh(&mut h);
    for t in ["upstream1", "198.51.100.2", "AS65100", "ebgp-customer", "transit", "ip, ipv6", "90", "md5", "route reflector", "2 connections", "1 iBGP"] {
        assert!(h.has_text(t), "{t}");
    }
    assert!(!h.has_text("k3y"), "the key is never shown");
    panel(&mut h).tab = Tab::Templates;
    refresh(&mut h);
    for t in ["transit", "ebgp-customer", "upstream1", "1 templates", "1 in use"] {
        assert!(h.has_text(t), "{t}");
    }
}

#[test]
fn the_modal_adds_a_connection_through_the_preview() {
    let mut h = open(lab());
    panel(&mut h).tab = Tab::Connections;
    refresh(&mut h);
    act(&mut h, Act::Add, What::Connection);
    settle(&mut h);
    assert!(h.has_text("New BGP Connection"));
    let (_, m) = panel(&mut h).modal.as_mut().unwrap();
    m.values.insert("name", "ix1".into());
    m.values.insert("remote_address", "203.0.113.9".into());
    m.values.insert("remote_as", "64500".into());
    m.values.insert("hold_time", "30".into());
    m.values.insert("templates", "transit".into());
    settle(&mut h);
    for t in ["keepalive 10 s, hold 30 s", "eBGP without input_filter and output_filter: no route is accepted or sent (RFC 8212); set the chains (Routing › Filters)"] {
        assert!(h.has_text(t), "{t}");
    }
    h.click(h.text("OK"));
    settle(&mut h);
    let rows = lock(&h.session).execute("routing.bgp.connection.list", &json!({})).unwrap();
    let ix = rows.as_array().unwrap().iter().find(|r| r["name"] == "ix1").cloned();
    let ix = ix.unwrap_or_else(|| panic!("{:?}", h.app.log()));
    assert_eq!(ix["params"]["hold_time"], 30);
    assert_eq!(ix["effective"]["afi"], json!(["ip", "ipv6"]), "inherited");
    assert!(panel(&mut h).modal.is_none(), "OK closes");

    // A reserved AS keeps OK grey and says why.
    act(&mut h, Act::Edit("ix1".into()), What::Connection);
    let (_, m) = panel(&mut h).modal.as_mut().unwrap();
    m.values.insert("remote_as", "23456".into());
    settle(&mut h);
    let (_, m) = panel(&mut h).modal.as_ref().unwrap();
    assert!(m.blocking(&crate::bgp::CONN_SPEC).is_err_and(|e| e.contains("reserved")));
    h.key(egui::Key::Escape, egui::Modifiers::NONE);
    assert!(panel(&mut h).modal.is_none());
}

/// G3.9f: the Filters page has what the router announces itself.
#[test]
fn the_filters_page_sets_what_the_connection_announces() {
    let mut h = open(lab());
    panel(&mut h).tab = Tab::Connections;
    refresh(&mut h);
    act(&mut h, Act::Add, What::Connection);
    panel(&mut h).page = 3;
    settle(&mut h);
    for t in ["Output Network", "Redistribute", "address-list name", "connected,static,ospf"] {
        assert!(h.has_text(t), "{t}");
    }
    let (_, m) = panel(&mut h).modal.as_mut().unwrap();
    m.values.insert("name", "ix2".into());
    m.values.insert("remote_address", "203.0.113.10".into());
    m.values.insert("remote_as", "64501".into());
    m.values.insert("output_network", "bgp-out".into());
    m.values.insert("output_redistribute", "connected,static".into());
    settle(&mut h);
    h.click(h.text("OK"));
    settle(&mut h);
    let rows = lock(&h.session).execute("routing.bgp.connection.list", &json!({})).unwrap();
    let ix = rows.as_array().unwrap().iter().find(|r| r["name"] == "ix2").cloned();
    let ix = ix.unwrap_or_else(|| panic!("{:?}", h.app.log()));
    assert_eq!(ix["params"]["output_network"], "bgp-out");
    assert_eq!(ix["params"]["output_redistribute"], json!(["connected", "static"]));
    // Editing shows them back, the list as the operator typed it.
    act(&mut h, Act::Edit("ix2".into()), What::Connection);
    let (_, m) = panel(&mut h).modal.as_ref().unwrap();
    assert_eq!(m.values.get("output_redistribute").map(String::as_str), Some("connected,static"));
    assert_eq!(m.values.get("output_network").map(String::as_str), Some("bgp-out"));
}

/// G3.9fj: the Instances tab lists the graceful-restart timers and edits
/// them in the modal, with the engine's preview.
#[test]
fn the_instances_tab_edits_the_graceful_restart_timers() {
    let mut s = lab();
    s.execute("routing.bgp.connection.set", &json!({"id": "rr1", "graceful_restart": true})).unwrap();
    let mut h = open(s);
    panel(&mut h).tab = Tab::Instances;
    refresh(&mut h);
    for t in ["default", "AS65000", "10.0.0.1", "120 s (default)", "360 s (default)", "10 s (default)", "1 instances"] {
        assert!(h.has_text(t), "{t}");
    }
    act(&mut h, Act::Edit("default".into()), What::Instance);
    settle(&mut h);
    let (_, m) = panel(&mut h).modal.as_mut().unwrap();
    assert_eq!(m.values.get("asn").map(String::as_str), Some("65000"));
    assert_eq!(m.values.get("graceful_restart_time").map(String::as_str), Some(""), "unset: the default");
    m.values.insert("graceful_restart_time", "200".into());
    m.values.insert("graceful_defer_time", "30".into());
    settle(&mut h);
    assert!(h.has_text("the Restart Time (200 s) is not shorter than the hold time of rr1 (hold 180 s): RFC 4724 §3 recommends it below the hold time"));
    h.click(h.text("OK"));
    settle(&mut h);
    assert!(panel(&mut h).modal.is_none(), "OK closes: {:?}", h.app.log());
    let rows = lock(&h.session).execute("routing.bgp.instance.list", &json!({})).unwrap();
    assert_eq!((rows[0]["graceful_restart_time"].as_u64(), rows[0]["graceful_defer_time"].as_u64()), (Some(200), Some(30)), "{rows}");
    assert_eq!(rows[0]["graceful_stale_time"], Value::Null, "untouched");
    refresh(&mut h);
    for t in ["200 s", "30 s", "Rendered for FRR bgpd:"] {
        assert!(h.has_text(t), "{t}");
    }
    // Emptying a timer puts the default back.
    act(&mut h, Act::Edit("default".into()), What::Instance);
    let (_, m) = panel(&mut h).modal.as_mut().unwrap();
    m.values.insert("graceful_restart_time", String::new());
    settle(&mut h);
    h.click(h.text("OK"));
    settle(&mut h);
    let rows = lock(&h.session).execute("routing.bgp.instance.list", &json!({})).unwrap();
    assert_eq!((rows[0]["graceful_restart_time"].clone(), rows[0]["graceful_defer_time"].as_u64()), (Value::Null, Some(30)), "{rows}");
}

#[test]
fn every_label_explains_itself_in_both_languages() {
    for key in BgpPanel::help_keys() {
        for lang in crate::i18n::Lang::ALL {
            let langs = crate::i18n::Langs { labels: lang, help: lang };
            assert_eq!(crate::i18n::explain(langs, key).map(|(l, _)| l), Some(lang), "{key}");
        }
    }
}
