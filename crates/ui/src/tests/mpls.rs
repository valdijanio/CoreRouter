//! MPLS › LDP and Forwarding Table (G3.5): the tabs, the MTU chip of the
//! mockup ("MTU 1500 < 1504"), static LSPs in the table, the reason of a
//! FEC without a label, and the ⓘ of every label in both languages.

use super::*;
use crate::mpls_forwarding::ForwardingPanel;
use crate::mpls_ldp::{LdpPanel, Tab};

fn lab() -> Session {
    let mut s = Session::virtual_lab();
    for (cmd, p) in [
        ("mpls.settings.set", json!({"dynamic_label_range": "16-99999"})),
        ("mpls.ldp.add", json!({"lsr_id": "10.255.0.1"})),
        ("mpls.ldp.interface.add", json!({"interface": "ether1"})),
        ("mpls.ldp.neighbor.add", json!({"lsr_id": "10.255.0.2", "password": "k3y"})),
        ("mpls.static.add", json!({"label": 100_000, "nexthop": "10.0.12.2", "interface": "ether2", "out_labels": "200"})),
    ] {
        s.execute(cmd, &p).unwrap_or_else(|e| panic!("{cmd}: {e}"));
    }
    s
}

fn open(s: Session, win: &'static str) -> Harness {
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(win));
    refresh(&mut h);
    h
}

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..4 {
        h.idle();
    }
}

#[test]
fn ldp_tabs_show_neighbors_interfaces_and_the_mtu_check() {
    let mut h = open(lab(), crate::mpls_ldp::WIN);
    for t in ["Neighbors", "Interfaces", "Settings", "10.255.0.2", "MD5", "no daemon", "IGP sync", "GTSM"] {
        assert!(h.has_text(t), "{t}");
    }
    h.app.panel_mut::<LdpPanel>().unwrap().tab = Tab::Interfaces;
    refresh(&mut h);
    for t in ["ether1", "MTU 1500 < 1504", "1 MTU too small"] {
        assert!(h.has_text(t), "{t}");
    }
    h.app.panel_mut::<LdpPanel>().unwrap().tab = Tab::Settings;
    refresh(&mut h);
    for t in ["LSR ID", "Dynamic Label Range", "IGP Sync Holddown", "Apply"] {
        assert!(h.has_text(t), "{t}");
    }
    let f = h.app.panel_mut::<LdpPanel>().unwrap().form.clone().unwrap();
    assert_eq!(f["lsr_id"], "10.255.0.1");
    assert_eq!(f["igp_sync"], "yes");
    assert_eq!(f["dynamic_label_range"], "16-99999");
}

#[test]
fn settings_go_as_one_transaction() {
    let mut f = std::collections::BTreeMap::new();
    for (k, v) in [("lsr_id", "10.0.0.1"), ("afi", "ip"), ("igp_sync", "yes"), ("gtsm", "no"), ("igp_sync_holddown", ""), ("dynamic_label_range", "16-9999"), ("propagate_ttl", "yes"), ("payload_mtu", "1500")] {
        f.insert(k, v.to_owned());
    }
    let steps = crate::mpls_ldp::settings_steps(&f, false);
    assert_eq!(steps[0]["command"], "mpls.settings.set");
    assert_eq!(steps[0]["params"]["payload_mtu"], 1500);
    assert_eq!(steps[1]["command"], "mpls.ldp.add");
    assert_eq!(steps[1]["params"]["gtsm"], false);
    assert!(steps[1]["params"].get("igp_sync_holddown").is_none(), "{}", steps[1]);
    // Editing: an emptied holddown is cleared (null).
    let steps = crate::mpls_ldp::settings_steps(&f, true);
    assert_eq!(steps[1]["command"], "mpls.ldp.set");
    assert!(steps[1]["params"]["igp_sync_holddown"].is_null());
}

#[test]
fn forwarding_table_lists_static_lsps_and_reasons() {
    let mut h = open(lab(), crate::mpls_forwarding::WIN);
    for t in ["FEC", "In Label", "Out Label", "100000", "200", "10.0.12.2", "ether2", "static", "LDP: no daemon", "+ Static LSP"] {
        assert!(h.has_text(t), "{t}");
    }
    let r = crate::mpls_forwarding::row(&json!({"fec": "10.9.0.0/24", "in_label": 17, "out_label": "-", "origin": "ldp", "installed": true, "reason": "no neighbor advertised a label for it"}));
    assert_eq!(r.cells[0], "10.9.0.0/24");
    assert!(r.cells[7].contains("no neighbor advertised"));
    let php = crate::mpls_forwarding::row(&json!({"fec": "10.255.0.1/32", "in_label": 3, "out_label": "implicit-null (pop)", "origin": "ldp", "installed": true, "mtu": "MTU 1500 < 1504: a 1500-byte…"}));
    assert_eq!(php.cells[1], "implicit-null");
    assert!(php.cells[2].contains("MTU 1500 < 1504"));
    let _ = h.app.panel_mut::<ForwardingPanel>().unwrap();
}

#[test]
fn every_label_explains_itself_in_both_languages() {
    for key in LdpPanel::help_keys().into_iter().chain(ForwardingPanel::help_keys()) {
        for lang in crate::i18n::Lang::ALL {
            let langs = crate::i18n::Langs { labels: lang, help: lang };
            assert_eq!(crate::i18n::explain(langs, key).map(|(l, _)| l), Some(lang), "{key}");
        }
    }
}
