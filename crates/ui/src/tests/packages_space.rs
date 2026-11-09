//! System › Packages (G1.6x): the room in `/config` in one line and Free
//! space with the `dry_run` before anything goes.

use super::*;
use crate::packages::WIN;
use corerouter_engine::package::{self, JobKind};

fn status(trial: bool, fits: bool) -> Value {
    json!({
        "supported": true, "running": "a", "primary": "a",
        "trial": if trial { json!({"slot": "b", "from": "a", "config_backup": "config-a", "version": "2", "confirm": "auto", "timeout_s": 300}) } else { Value::Null },
        "slots": [{"slot": "a", "state": "running", "running": true}, {"slot": "b", "state": "standby", "running": false}],
        "snapshots": [{"name": "config-a", "version": "1", "format_version": 3, "files": 9, "bytes": 13_811_709u64, "own_bytes": 13_811_709u64}],
        "partials": [{"name": "config-b.new", "own_bytes": 9_000_000u64}],
        "config_space": {
            "total": 58_720_256u64, "free": 20_971_520u64, "snapshot_need": 4096u64, "snapshot_fits": fits,
            "usage_rows": 9,
            "usage": [
                {"path": "package/config-a", "bytes": 13_811_709u64, "kind": "snapshot"},
                {"path": "rev-81.json", "bytes": 11_000_000u64, "kind": "config"},
                {"path": "package/config-b.new", "bytes": 9_000_000u64, "kind": "partial"},
                {"path": "graphs", "bytes": 1_000u64, "kind": "graphs"},
            ],
        },
    })
}

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..6 {
        h.idle();
    }
}

fn open(st: Value) -> Harness {
    let mut s = Session::virtual_lab();
    package::feed_status(&mut s, st);
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    refresh(&mut h);
    h
}

fn job(h: &Harness) -> Option<JobKind> {
    package::take_job(&mut corerouter_engine::lock(&h.session)).map(|j| j.kind)
}

#[test]
fn the_line_shows_use_biggest_items_and_what_can_go() {
    let h = open(status(false, true));
    for text in ["/config", "36.0 MiB / 56.0 MiB", "20.0 MiB free", "snapshot fits", "Free space…", "config-a 13.2 MiB", "config-b.new 8.6 MiB"] {
        assert!(h.has_text_containing(text), "{text}");
    }
    assert!(h.has_text_containing("Biggest: package/config-a 13.2 MiB · rev-81.json 10.5 MiB · package/config-b.new 8.6 MiB"));
    assert!(!h.has_text_containing("graphs 1000 B"), "only the first three in the line");
}

#[test]
fn it_says_when_the_next_snapshot_does_not_fit() {
    let h = open(status(false, false));
    assert!(h.has_text("no room for the snapshot"));
    assert!(!h.has_text("snapshot fits"));
}

#[test]
fn free_space_shows_the_plan_first_and_removes_only_on_the_button() {
    let mut h = open(status(false, true));
    h.click(h.text("Free space…"));
    refresh(&mut h);
    assert!(h.has_text("config-b.new"), "the partial copy");
    assert!(h.has_text_containing("Frees 8.6 MiB"));
    assert_eq!(job(&h), None, "a dry run queues nothing");
    h.click(h.text("Remove"));
    refresh(&mut h);
    assert_eq!(job(&h), Some(JobKind::SnapshotRemove { names: vec!["config-b.new".into()] }));
    assert!(!h.has_text("Partial copies only"), "the question closed");
}

#[test]
fn every_snapshot_keeps_what_a_trial_needs_and_says_so() {
    let mut h = open(status(true, true));
    h.click(h.text("Free space…"));
    refresh(&mut h);
    h.click(h.text("Every snapshot too"));
    refresh(&mut h);
    assert!(h.has_text("kept"), "the trial's backup");
    assert!(h.has_text_containing("Without its snapshot"));
    h.click(h.text("Remove"));
    refresh(&mut h);
    assert_eq!(job(&h), Some(JobKind::SnapshotRemove { names: vec!["config-b.new".into()] }));
}

#[test]
fn cancel_removes_nothing_and_nothing_to_remove_greys_the_button() {
    let mut h = open(status(false, true));
    h.click(h.text("Free space…"));
    refresh(&mut h);
    h.click(h.text("Cancel"));
    refresh(&mut h);
    assert_eq!(job(&h), None);
    assert!(!h.has_text("Partial copies only"));

    let mut st = status(false, true);
    st["snapshots"] = json!([]);
    st["partials"] = json!([]);
    let mut h = open(st);
    h.click(h.text("Free space…"));
    refresh(&mut h);
    assert!(!h.has_text("Partial copies only"), "nothing to free: no question");
}
