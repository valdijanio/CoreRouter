//! PPP › Secrets › Import from MikroTik (G4.3n): paste, preview chips,
//! the profile mapping, import, and the passwords nowhere on screen.

use std::time::{Duration, Instant};

use serde_json::json;

use super::*;
use crate::ppp::{PppPanel, Tab, WIN};

const EXPORT: &str = "/ppp profile\nadd name=plano-100M rate-limit=50M/100M\n/ppp secret\nadd name=joao password=Pw-ui-j0ao profile=plano-100M service=pppoe\nadd name=maria password=Pw-ui-m4ria profile=VELHO\nadd name=pedro profile=default\n";

fn open() -> Harness {
    let mut h = Harness::with_session(Session::virtual_lab());
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    h.app.panel_mut::<PppPanel>().unwrap().tab = Tab::Secrets;
    for _ in 0..3 {
        h.idle();
    }
    h
}

fn until(h: &mut Harness, what: &str, done: impl Fn(&mut Harness) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done(h) {
        assert!(Instant::now() < deadline, "{what}: {:?}", h.app.log());
        h.time += 0.2;
        h.idle();
    }
}

fn dialog(h: &mut Harness) -> &mut crate::ppp_import::ImportDialog {
    h.app.panel_mut::<PppPanel>().unwrap().import.as_mut().expect("the dialog is open")
}

#[test]
fn paste_preview_map_and_import() {
    let mut h = open();
    h.click(h.text("Import from MikroTik…"));
    h.idle();
    assert!(h.has_text_containing("password in clear"), "the warning");
    dialog(&mut h).paste = EXPORT.into();
    h.idle();
    assert!(dialog(&mut h).has_text() && dialog(&mut h).paste.is_empty(), "the paste goes into the export");
    h.idle();
    for _ in 0..3 {
        h.idle();
    }
    let at = h.text("Preview");
    h.click(at);
    until(&mut h, "preview", |h| dialog(h).report.is_some());
    h.idle();
    assert!(h.has_text("2 with password"), "chips");
    assert!(h.has_text("1 without password"));
    assert!(h.has_text("1 missing profiles"));
    assert!(h.has_text_containing("VELHO"));
    // Map VELHO to default: a new preview comes by itself.
    dialog(&mut h).map.insert("VELHO".into(), "default".into());
    let p = dialog(&mut h).params(true);
    assert_eq!(p["profile_map"], json!({"VELHO": "default"}));
    dialog(&mut h).report = None;
    h.idle();
    h.click(h.text("Preview"));
    until(&mut h, "second preview", |h| dialog(h).report.is_some());
    h.idle();
    assert!(h.has_text("0 missing profiles"), "mapped");
    for pw in ["Pw-ui-j0ao", "Pw-ui-m4ria"] {
        assert!(!h.has_text_containing(pw), "{pw} on screen");
    }
    for _ in 0..3 {
        h.idle();
    }
    h.click(h.text("Import"));
    until(&mut h, "import", |h| dialog(h).done.is_some());
    h.idle();
    assert!(h.has_text("3 imported"));
    assert!(h.has_text_containing("delete the export file"));
    assert!(!dialog(&mut h).has_text(), "forgotten once imported");
    let s = lock(&h.session);
    assert_eq!(s.store().running().ppp.secrets.len(), 3);
    assert_eq!(s.store().running().ppp.secret("maria").unwrap().profile, "default");
    let log = format!("{:?}", h.app.log());
    assert!(!log.contains("Pw-ui"), "{log}");
}

#[test]
fn without_a_file_reader_it_says_how() {
    let mut h = open();
    h.click(h.text("Import from MikroTik…"));
    h.idle();
    dialog(&mut h).path = "/tmp/x.rsc".into();
    h.click(h.text("Load"));
    h.idle();
    h.idle();
    assert!(h.has_text_containing("paste it"), "no reader in tests: paste or drop");
}
