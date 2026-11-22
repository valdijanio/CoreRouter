//! Queues (G4.9c): the three tabs over the virtual lab, the modal's preview,
//! the PPP fields that pick a session's queue, and every explanation in both
//! languages.

use serde_json::json;

use super::*;
use crate::queues::{QueuesPanel, Tab, WIN};

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..3 {
        h.idle();
    }
}

fn open(tab: Tab) -> Harness {
    let mut s = Session::virtual_lab();
    s.execute(
        "queue.simple.add",
        &json!({"name": "cliente-ana", "target": "10.0.0.5", "max_limit": "10M/50M", "comment": "plano 50M"}),
    )
    .unwrap();
    s.execute("queue.simple.add", &json!({"name": "escritorio", "target": "10.0.1.0/24", "max_limit": "20M/20M"}))
        .unwrap();
    s.execute(
        "queue.type.add",
        &json!({"name": "pcq-down", "kind": "pcq", "pcq_rate": "5M", "pcq_classifier": "dst-address"}),
    )
    .unwrap();
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    h.app.panel_mut::<QueuesPanel>().unwrap().tab = tab;
    refresh(&mut h);
    refresh(&mut h);
    h
}

#[test]
fn simple_queues_list_name_target_and_limit() {
    let mut h = open(Tab::Simple);
    assert!(h.has_text("Simple Queues"));
    assert!(h.has_text("Per-IP (PCQ)"));
    assert!(h.has_text("Queue Types"));
    assert!(h.has_text("cliente-ana"));
    assert!(h.has_text("10.0.0.5"));
    assert!(h.has_text("10M/50M"));
    assert!(h.has_text("escritorio"));
    assert!(h.has_text("plano 50M"), "the comment");
    refresh(&mut h);
}

#[test]
fn queue_types_show_the_built_ins_and_the_new_one() {
    let mut h = open(Tab::Types);
    assert!(h.has_text("fq-codel-default"));
    assert!(h.has_text("pcq-down"));
    refresh(&mut h);
}

#[test]
fn the_wait_column_is_empty_while_nothing_waits() {
    assert_eq!(crate::queues::wait_text(0), "");
    assert_eq!(crate::queues::wait_text(12_345), "12.3 ms");
}

#[test]
fn ppp_shows_the_queue_columns_and_profile_fields() {
    let mut h = Harness::with_session(Session::virtual_lab());
    h.app.open.clear();
    h.app.open(Win::Panel(crate::ppp::WIN));
    h.app.panel_mut::<crate::ppp::PppPanel>().unwrap().tab = crate::ppp::Tab::Active;
    refresh(&mut h);
    assert!(h.has_text("Queue"));
    assert!(h.has_text("Drops"));
}

#[test]
fn every_explanation_exists_in_both_languages() {
    use crate::i18n::{Lang, Langs, explain};
    let src = include_str!("../queues.rs");
    let mut keys: Vec<&str> = src
        .split('"')
        .filter(|k| k.starts_with("queues.") && k.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)))
        .collect();
    keys.extend([
        "ppp.profile.download_mode",
        "ppp.profile.queue_type",
        "ppp.active.queue",
        "ppp.active.drops",
    ]);
    keys.sort_unstable();
    keys.dedup();
    assert!(keys.len() > 30, "{keys:?}");
    for k in keys {
        for l in [Lang::Pt, Lang::En] {
            let found = explain(Langs { labels: l, help: l }, k);
            assert_eq!(found.map(|(got, _)| got), Some(l), "{k} in {l:?}");
        }
    }
}
