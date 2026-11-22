//! The "Queue <name>" modal (G4.9g): opened on a fixed queue it has the
//! edit form on General/Advanced and the live pages; the lab's simulated
//! shaper feeds Traffic and Statistics; the explanations exist in both
//! languages.

use serde_json::{Value, json};

use super::*;
use crate::queue_view::{Page, Point, QueueView};
use crate::queues::{QueuesPanel, WIN};

const T0: u64 = 1_800_000_000;

fn lab() -> Harness {
    let mut s = Session::virtual_lab();
    s.execute(
        "queue.simple.add",
        &json!({"name": "cliente-ana", "target": "10.0.0.5", "max_limit": "10M/50M", "burst_limit": "20M/80M", "burst_threshold": "8M/40M", "burst_time": "16s"}),
    )
    .unwrap();
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    // A few seconds of the `queue` service in the lab.
    for t in 0..4 {
        let mut s = lock(&h.session);
        s.tick(T0 + t);
        s.queue_sync();
    }
    refresh(&mut h);
    h
}

fn refresh(h: &mut Harness) {
    for _ in 0..3 {
        h.app.cache.refreshed_at = None;
        h.idle();
    }
}

fn row(h: &mut Harness) -> Value {
    let p = h.app.panel_mut::<QueuesPanel>().unwrap();
    p.simple["rows"][0].clone()
}

fn view(h: &mut Harness) -> &mut QueueView {
    h.app.panel_mut::<QueuesPanel>().unwrap().view.as_mut().unwrap()
}

fn open_view(h: &mut Harness) {
    let r = row(h);
    let mut p = std::mem::take(h.app.panel_mut::<QueuesPanel>().unwrap());
    p.open_view(&mut h.app, &r);
    *h.app.panel_mut::<QueuesPanel>().unwrap() = p;
    refresh(h);
}

#[test]
fn a_fixed_queue_opens_on_its_form_with_the_live_tabs() {
    let mut h = lab();
    open_view(&mut h);
    assert!(h.has_text("Queue <cliente-ana>"));
    for t in ["General", "Advanced", "Traffic", "Statistics", "History"] {
        assert!(h.has_text(t), "{t}");
    }
    assert!(h.has_text("Max Limit"), "General has the form");
    assert!(!h.has_text("Bucket Size"), "…and not Advanced's fields");
    view(&mut h).page = Page::Advanced;
    refresh(&mut h);
    assert!(h.has_text("Bucket Size"));
    assert!(h.has_text("Keep History"));
}

#[test]
fn traffic_and_statistics_come_from_the_stats_of_one_queue() {
    let mut h = lab();
    open_view(&mut h);
    view(&mut h).page = Page::Traffic;
    refresh(&mut h);
    let st = view(&mut h).live.stats.clone().expect("queue.simple.stats answered");
    assert_eq!(st["name"], "cliente-ana");
    assert_eq!(st["counted"], true, "the lab's shaper counts: {st}");
    assert!(h.has_text("Download"));
    assert!(h.has_text("Queue Delay"));
    assert!(h.has_text("Drops/s"));
    assert!(h.has_text("15 min"));
    // One more second of the service: the ring grows by one point.
    let before = view(&mut h).live.ring.len();
    {
        let mut s = lock(&h.session);
        s.tick(T0 + 10);
        s.queue_sync();
    }
    refresh(&mut h);
    assert!(view(&mut h).live.ring.len() > before);
    view(&mut h).page = Page::Statistics;
    refresh(&mut h);
    for t in ["Packet Rate", "Bytes", "Dropped", "Queued p95", "Burst", "Burst Average", "PCQ Addresses"] {
        assert!(h.has_text(t), "{t}");
    }
    view(&mut h).page = Page::History;
    refresh(&mut h);
    assert!(h.has_text("Week"));
}

#[test]
fn pause_freezes_the_window_and_csv_has_its_points() {
    let mut v = crate::queue_view::Live::default();
    for t in 0..400u64 {
        v.ring.push_back(Point { t: T0 + t, up: 1e6, down: 2e6, delay: 1.5, drops: 0.0 });
    }
    v.window = 60;
    assert_eq!(v.shown().len(), 60);
    v.paused = Some(T0 + 100);
    let shown = v.shown();
    assert_eq!(shown.last().map(|p| p.t), Some(T0 + 100));
    let csv = v.csv();
    assert_eq!(csv.lines().count(), 61, "header + 60 points");
    assert!(csv.starts_with("time_utc,unix,upload_bps,download_bps,delay_ms,drops_per_s"));
}

#[test]
fn every_view_explanation_exists_in_both_languages() {
    use crate::i18n::{Lang, Langs, explain};
    let src = include_str!("../queue_view.rs");
    let mut keys: Vec<String> = src
        .split('"')
        .filter(|k| k.starts_with("queues.") && k.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)))
        .map(str::to_owned)
        .collect();
    // `self.info(ui, l, "<key>", …)` and `self.label(…)` add the prefix.
    for part in src.split("self.info(ui, l, \"").skip(1).chain(src.split("self.label(ui, l, \"").skip(1)) {
        if let Some(k) = part.split('"').next().filter(|k| !k.is_empty() && !k.contains('{')) {
            keys.push(format!("queues.view.{k}"));
        }
    }
    for k in ["current", "avg", "max", "p95"] {
        keys.push(format!("queues.view.history.{k}"));
    }
    keys.push("queues.view".into());
    keys.sort_unstable();
    keys.dedup();
    assert!(keys.len() > 25, "{keys:?}");
    for k in keys {
        for l in [Lang::Pt, Lang::En] {
            let found = explain(Langs { labels: l, help: l }, &k);
            assert_eq!(found.map(|(got, _)| got), Some(l), "{k} in {l:?}");
        }
    }
}
