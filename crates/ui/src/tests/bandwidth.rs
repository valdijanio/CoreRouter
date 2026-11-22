//! Tools › Bandwidth Test (G6.4b): Start asks first, the simulated test of
//! the lab fills the chart and the results, and the Server tab saves the
//! server's settings and shows its status.

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use corerouter_engine::tasks::SimClock;
use corerouter_engine::{Job, Runner};

use super::*;
use crate::bandwidth::{BandwidthPanel, Tab};

struct Threads;
impl Runner for Threads {
    fn spawn(&self, _name: &str, job: Job) -> Result<(), String> {
        thread::spawn(move || job(&SimClock::default()));
        Ok(())
    }
}

fn open() -> Harness {
    let mut s = Session::virtual_lab();
    s.set_runner(Arc::new(Threads));
    s.tick(1_000);
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(crate::bandwidth::WIN));
    for _ in 0..6 {
        h.idle();
    }
    h
}

fn panel(h: &mut Harness) -> &mut BandwidthPanel {
    h.app.panel_mut::<BandwidthPanel>().unwrap()
}

#[test]
fn a_test_asks_first_then_runs_and_shows_both_ways() {
    let mut h = open();
    {
        let p = panel(&mut h);
        p.address = "192.0.2.50".into();
        p.protocol = "udp".into();
        p.direction = "both".into();
        p.duration = "2".into();
        p.bandwidth = "40M".into();
    }
    h.idle();
    h.click(h.text("Start"));
    h.idle();
    assert!(panel(&mut h).confirm, "Start asks first");
    assert!(h.has_text_containing("It fills the path for 2 s"));
    // The modal's Start is drawn last: the topmost one.
    h.click(h.text("Start"));
    let deadline = Instant::now() + Duration::from_secs(15);
    while !panel(&mut h).done {
        assert!(Instant::now() < deadline, "{:?}", h.app.log());
        thread::sleep(Duration::from_millis(30));
        h.app.cache.refreshed_at = None;
        h.time += 0.3;
        h.idle();
    }
    h.idle();
    let p = panel(&mut h);
    assert_eq!(p.state, "done");
    assert_eq!(p.summary["samples"].as_array().unwrap().len(), 2);
    assert!(h.has_text_containing("simulated"));
    assert!(h.has_text_containing("router CPU"));
    assert!(h.has_text("Average") && h.has_text("Peak"));
    assert!(h.has_text("0.0 %"), "UDP loss chip");
}

#[test]
fn the_form_builds_the_parameters() {
    let p = BandwidthPanel {
        address: " 10.0.0.1 ".into(),
        streams: "4".into(),
        bandwidth: "100M".into(),
        ..BandwidthPanel::default()
    };
    assert_eq!(
        p.params(),
        json!({"address": "10.0.0.1", "port": 5201, "streams": 4, "duration": 10, "protocol": "tcp", "direction": "send", "bandwidth": "100M"})
    );
}

#[test]
fn the_server_tab_saves_and_shows_the_status() {
    let mut h = open();
    panel(&mut h).tab = Tab::Server;
    for _ in 0..4 {
        h.app.cache.refreshed_at = None;
        h.idle();
    }
    assert!(h.has_text("stopped"));
    {
        let p = panel(&mut h);
        let f = p.server_form.as_mut().expect("loaded");
        f.enabled = true;
        f.allowed = "100.64.0.0/10".into();
    }
    h.idle();
    h.click(h.text("Apply"));
    for _ in 0..4 {
        h.app.cache.refreshed_at = None;
        h.idle();
    }
    let cfg = &h.app.panel_mut::<BandwidthPanel>().unwrap().server;
    assert_eq!(cfg["enabled"], true, "{cfg}");
    assert_eq!(cfg["allowed_addresses"], json!(["100.64.0.0/10"]));
    // Enabling without an allow list: the engine's reason, in the tab.
    {
        let p = panel(&mut h);
        p.server_form.as_mut().unwrap().allowed.clear();
    }
    h.idle();
    h.click(h.text("Apply"));
    for _ in 0..3 {
        h.idle();
    }
    assert!(panel(&mut h).server_error.as_deref().unwrap_or("").contains("allowed_addresses"));
}

#[test]
fn every_explanation_exists() {
    for key in [
        "bandwidth.address", "bandwidth.port", "bandwidth.protocol", "bandwidth.direction",
        "bandwidth.streams", "bandwidth.duration", "bandwidth.bandwidth", "bandwidth.results",
        "bandwidth.server", "bandwidth.server_enabled", "bandwidth.server_port",
        "bandwidth.server_allowed", "bandwidth.server_max_duration", "bandwidth.server_max_streams",
        "bandwidth.server_max_rate", "menu.bandwidth",
    ] {
        for l in crate::i18n::Lang::ALL {
            let langs = crate::i18n::Langs { labels: l, help: l };
            assert_eq!(crate::i18n::explain(langs, key).map(|(x, _)| x), Some(l), "{key} in {l:?}");
        }
    }
}
