//! System › Packages › System disk (G1.6zn): the root in RAM or on the
//! disk, the choice for the next boot sent as `system.boot.set`, and the
//! red band when the system disk went away.

use super::*;
use crate::packages::WIN;
use corerouter_engine::package;

const GONE: &str = "system disk sda removed: the router keeps running from RAM, but configuration changes are no longer saved; reboot with the disk in place";

fn status(root: Value, gone: Option<&str>) -> Value {
    let mut st = json!({
        "supported": true, "running": "a", "primary": "a", "trial": null,
        "slots": [{"slot": "a", "state": "running", "running": true}, {"slot": "b", "state": "standby", "running": false}],
        "root": root,
    });
    if let (Some(line), Some(o)) = (gone, st.as_object_mut()) {
        o.insert("system_disk_removed".into(), json!(line));
    }
    st
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

fn to_ram(h: &Harness) -> bool {
    lock(&h.session).store().running().system.boot.to_ram
}

#[test]
fn the_checkbox_sends_system_boot_set_and_marks_the_next_boot() {
    let mut h = open(status(json!({"in_ram": false, "bytes": 0, "copy_ms": 0, "disk": "sda"}), None));
    assert!(h.has_text("System disk"));
    assert!(h.has_text("root on disk sda"));
    assert!(!h.has_text_containing("next boot:"), "the choice is this boot's");
    h.click(h.text("Run the system from RAM"));
    refresh(&mut h);
    assert!(to_ram(&h), "{:?}", h.app.log());
    assert!(h.has_text("next boot: RAM"));
    assert!(h.has_text("Next boot from RAM."));
    h.click(h.text("Run the system from RAM"));
    refresh(&mut h);
    assert!(!to_ram(&h));
    assert!(!h.has_text_containing("next boot:"));
}

#[test]
fn the_root_in_ram_and_a_removed_disk_lock_the_choice() {
    let mut h = open(status(json!({"in_ram": true, "bytes": 91_226_112u64, "copy_ms": 412, "disk": "sda"}), Some(GONE)));
    assert!(h.has_text("root in RAM"));
    assert!(h.has_text("disk removed"));
    assert!(h.has_text(GONE));
    assert!(h.has_text("next boot: disk"), "to_ram is off");
    h.click(h.text("Run the system from RAM"));
    refresh(&mut h);
    assert!(!to_ram(&h), "disabled while the disk is gone");
}

#[test]
fn a_boot_that_stayed_on_the_disk_says_so() {
    let h = open(status(json!({"in_ram": false, "bytes": 0, "copy_ms": 0, "note": "only 180 MiB free after the copy"}), None));
    assert!(h.has_text("stayed on disk"));
    assert!(!h.has_text("root on disk"));
}

#[test]
fn the_row_shows_in_the_lab_without_a_root() {
    let h = open(status(Value::Null, None));
    assert!(h.has_text("Run the system from RAM"));
    assert!(!h.has_text("root in RAM") && !h.has_text_containing("root on disk"));
}

#[test]
fn the_explanations_exist_in_both_languages() {
    use crate::i18n::{Lang, Langs, explain};
    for key in ["packages.to_ram", "packages.disk_removed"] {
        for l in [Lang::En, Lang::Pt] {
            let got = explain(Langs { labels: l, help: l }, key).map(|(lang, _)| lang);
            assert_eq!(got, Some(l), "{key} in {l:?}");
        }
    }
}
