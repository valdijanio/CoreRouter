//! System › Reboot and Shutdown (G1.6qh): the question before the command,
//! with what the router would refuse, what clears it, Force, and after the
//! answer the wait for the connection.

use super::*;
use corerouter_engine::power::{self, Action};

const REBOOT: Win = Win::Panel(crate::power::REBOOT);
const SHUTDOWN: Win = Win::Panel(crate::power::SHUTDOWN);

fn image() -> Session {
    let mut s = Session::virtual_lab();
    power::set_support(&mut s, Ok(()));
    s
}

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..6 {
        h.idle();
    }
}

fn open(s: Session, win: Win) -> Harness {
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(win);
    refresh(&mut h);
    h
}

fn taken(h: &Harness) -> Option<Action> {
    power::take_request(&mut corerouter_engine::lock(&h.session)).map(|r| r.action)
}

#[test]
fn nothing_is_sent_until_the_button_and_then_the_window_waits() {
    let mut h = open(image(), REBOOT);
    for text in ["What goes down", "Safe Mode is off", "The connection comes back on its own"] {
        assert!(h.has_text_containing(text), "{text}");
    }
    assert!(!h.has_text("Force"), "nothing to force");
    assert_eq!(taken(&h), None, "opening the window asks nothing");

    // The heading is first; the button is the last text "Reboot" drawn.
    h.click(h.text("Reboot"));
    refresh(&mut h);
    assert_eq!(taken(&h), Some(Action::Reboot));
    assert!(h.has_text("rebooting"), "the window follows the request");
    assert!(!h.has_text("Cancel"), "no second request from here");
}

#[test]
fn cancel_closes_and_sends_nothing() {
    let mut h = open(image(), SHUTDOWN);
    assert!(h.has_text_containing("until someone turns it on"));
    h.click(h.text("Cancel"));
    refresh(&mut h);
    assert!(!h.app.open.contains(&SHUTDOWN));
    assert_eq!(taken(&h), None);
}

#[test]
fn safe_mode_asks_for_force_or_offers_to_leave() {
    let mut s = image();
    s.execute("config.safe-mode.enter", &json!({})).unwrap();
    let mut h = open(s, REBOOT);
    assert!(h.has_text("Safe Mode on"));
    assert!(h.has_text("Force"));

    // Grey without Force: the click does nothing.
    h.click(h.text("Reboot"));
    refresh(&mut h);
    assert_eq!(taken(&h), None);

    // With Force it goes, and the engine says it undid Safe Mode.
    h.click(h.text("Force"));
    refresh(&mut h);
    h.click(h.text("Reboot"));
    refresh(&mut h);
    assert_eq!(taken(&h), Some(Action::Reboot));
}

#[test]
fn the_fix_button_clears_the_check_and_the_tick_does_not_stay() {
    let mut s = image();
    s.execute("config.mode.set", &json!({"mode": "transactional"})).unwrap();
    s.execute("system.identity.set", &json!({"name": "pending"})).unwrap();
    let mut h = open(s, REBOOT);
    assert!(h.has_text("pending changes"));
    h.click(h.text("Force"));
    h.click(h.text("Commit"));
    refresh(&mut h);
    assert!(!corerouter_engine::lock(&h.session).store().is_dirty(), "committed");
    assert!(!h.has_text("pending changes"));
    assert!(h.has_text_containing("Safe Mode is off"));
    assert!(!h.has_text("Force"));
}

#[test]
fn off_the_image_it_says_why_and_the_button_is_grey() {
    let mut h = open(Session::virtual_lab(), REBOOT);
    assert!(h.has_text("not available"));
    assert!(h.has_text_containing("virtual lab"));
    h.click(h.text("Reboot"));
    refresh(&mut h);
    assert!(!h.has_text("rebooting"));
}

#[test]
fn every_explanation_of_the_window_exists_in_both_languages() {
    for key in ["menu.reboot", "menu.shutdown", "power.checks", "power.comes_back", "power.force", "power.impact"] {
        for lang in [crate::i18n::Lang::En, crate::i18n::Lang::Pt] {
            let langs = crate::i18n::Langs { labels: lang, help: lang };
            let (got, text) = crate::i18n::explain(langs, key).unwrap();
            assert_eq!(got, lang, "{key}");
            assert!(!text.is_empty());
        }
    }
}
