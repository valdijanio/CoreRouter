//! G6.3d: the MTR table's look. One line per hop, the same height for
//! all; private/CGNAT/MPLS as pills (no brackets); the AS pill's colour is
//! fixed by its number.

use serde_json::{Value, json};

use super::*;
use crate::mtr::{as_hue, as_text, as_tone, host_id, path_hues};
use crate::ping::TaskView;

fn hop(n: u64, host: Option<&str>, extra: Value) -> Value {
    let hosts: Vec<&str> = host.into_iter().collect();
    let mut h = json!({
        "hop": n, "hosts": hosts, "host": host, "sent": 10,
        "loss_pct": if host.is_some() { 0.0 } else { 100.0 },
        "last_ms": host.map(|_| 1.5), "avg_ms": host.map(|_| 1.5),
        "best_ms": host.map(|_| 1.0), "worst_ms": host.map(|_| 2.0),
        "stddev_ms": host.map(|_| 0.2),
    });
    if let (Value::Object(o), Value::Object(e)) = (&mut h, extra) {
        o.extend(e);
    }
    h
}

/// A finished run with every kind of hop, drawn in the MTR window.
fn shown(dark: bool) -> Harness {
    let mut h = Harness::new();
    if dark {
        h.ctx.set_visuals(egui::Visuals::dark());
    }
    h.app.open.remove(&Win::Interfaces);
    h.app.open(Win::Mtr);
    let mut t = TaskView::new(1);
    t.done = true;
    t.state = "done".into();
    t.summary = json!({
        "host": "8.8.8.8", "address": "8.8.8.8", "rounds": 10, "reached": true,
        "as_lookup": true,
        "hops": [
            hop(1, Some("10.15.0.1"), json!({"scope": "private"})),
            hop(2, Some("100.64.10.77"), json!({"scope": "cgnat"})),
            hop(3, Some("200.221.1.1"), json!({
                "name": "xe-0-1-0.core1.spo.uol.example.com.br.very-long-suffix",
                "asn": 7162, "as_name": "UOL Diveo S.A., BR",
                "mpls_text": "L=85260",
                "hosts_info": [{"mpls": [{"label": 85260, "tc": 0, "bottom": true, "ttl": 1}]}],
            })),
            hop(4, Some("200.221.2.2"), json!({"asn": 7162, "as_name": "UOL Diveo S.A., BR"})),
            hop(5, None, json!({})),
            hop(6, Some("8.8.8.8"), json!({"name": "dns.google", "asn": 15169, "as_name": "GOOGLE, US"})),
        ],
    });
    h.app.mtr.task = Some(t);
    for _ in 0..4 {
        h.idle();
    }
    h
}

#[test]
fn chips_replace_the_bracketed_tags() {
    for dark in [false, true] {
        let h = shown(dark);
        assert!(h.has_text("privada") && h.has_text("CGNAT") && h.has_text("MPLS 85260"));
        assert!(!h.has_text_containing("[private]") && !h.has_text_containing("[cgnat]"));
        assert!(!h.has_text_containing("L=85260"), "the label sits in the chip");
        // The name, cut with "…", in place of the address.
        assert!(h.has_text_containing("xe-0-1-0.core1.spo") && h.has_text_containing("…"));
        assert!(!h.has_text("200.221.1.1"), "the address is in the tooltip");
        assert!(h.has_text("dns.google"));
        // A hop that never answered.
        assert!(h.has_text("sem resposta") && !h.has_text_containing("???"));
        assert!(h.has_text("–"));
        assert_eq!(h.text_color("sem resposta"), h.ctx.global_style().visuals.weak_text_color());
        // The AS pills, the short name.
        assert!(h.has_text("Network") && h.has_text("AS7162 UOL") && h.has_text("AS15169 GOOGLE"));
        assert!(!h.has_text("ASN"));
    }
}

#[test]
fn every_row_has_the_same_height() {
    for dark in [false, true] {
        let h = shown(dark);
        let tops: Vec<f32> = (1..=6)
            .map(|n| {
                h.ctx
                    .read_response(host_id(n))
                    .unwrap_or_else(|| panic!("hop {n} drawn"))
                    .rect
                    .center()
                    .y
            })
            .collect();
        let pitch = tops[1] - tops[0];
        assert!(pitch > 10.0, "{tops:?}");
        for w in tops.windows(2) {
            assert!(((w[1] - w[0]) - pitch).abs() < 0.5, "uneven rows: {tops:?}");
        }
    }
}

#[test]
fn as_colours_follow_the_number() {
    // Stable: the same number, the same colour, in every run.
    assert_eq!(as_hue(7162), as_hue(7162));
    // Consecutive numbers never share one; nor do the lab's ASs or
    // neighbours common on Brazilian paths (UOL, Embratel, Google, Lumen).
    for n in 1..70_000u64 {
        assert_ne!(as_hue(n), as_hue(n + 1), "AS{n}");
    }
    let lab = [64500u64, 64510, 64999];
    for (i, a) in lab.iter().enumerate() {
        for b in lab.iter().skip(i + 1) {
            assert_ne!(as_hue(*a), as_hue(*b), "AS{a} AS{b}");
        }
    }
    // Eight colours, so two numbers can share one (UOL and Embratel do):
    // on a path the second of two neighbours takes the next colour.
    assert_eq!(as_hue(7162), as_hue(4230));
    let path = path_hues([7162, 7162, 4230, 4230, 15169, 7162]);
    assert_eq!(path.get(&7162), Some(&as_hue(7162)));
    assert_ne!(path.get(&7162), path.get(&4230));
    assert_ne!(path.get(&4230), path.get(&15169));
    // Two hops of one AS draw the same pill colour, on each theme, and the
    // themes differ (dark ink is lighter).
    for v in [egui::Visuals::light(), egui::Visuals::dark()] {
        assert_eq!(as_tone(&v, as_hue(7162)), as_tone(&v, as_hue(7162)));
        assert_ne!(as_tone(&v, as_hue(7162)).ink, as_tone(&v, as_hue(15169)).ink);
    }
    let (l, d) = (
        as_tone(&egui::Visuals::light(), as_hue(7162)).ink,
        as_tone(&egui::Visuals::dark(), as_hue(7162)).ink,
    );
    let lum = |c: egui::Color32| u32::from(c.r()) + u32::from(c.g()) + u32::from(c.b());
    assert!(lum(d) > lum(l));
    let text = |n: u64, name: &str| as_text(&json!({"asn": n, "as_name": name}));
    assert_eq!(text(7162, "UOL Diveo S.A., BR").as_deref(), Some("AS7162 UOL"));
    assert_eq!(as_text(&json!({"asn": 3356})).as_deref(), Some("AS3356"));
    assert_eq!(as_text(&json!({"scope": "cgnat"})), None);
}
