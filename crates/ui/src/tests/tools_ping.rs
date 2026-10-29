//! G6.2: Tools › Ping through the real UI over the in-process lab (the
//! simulated network), with the engine's tasks on test threads.

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use corerouter_engine::tasks::SimClock;
use corerouter_engine::{Job, Runner};
use egui::Key;

use super::*;

struct Threads;

impl Runner for Threads {
    fn spawn(&self, name: &str, job: Job) -> Result<(), String> {
        thread::Builder::new()
            .name(name.into())
            .spawn(move || job(&SimClock::default()))
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

fn lab() -> Harness {
    let mut s = Session::virtual_lab();
    s.set_runner(Arc::new(Threads));
    let mut h = Harness::with_session(s);
    // Alone on screen: nothing covers its fields.
    h.app.open.remove(&Win::Interfaces);
    h.app.open(Win::Ping);
    for _ in 0..6 {
        h.idle();
    }
    h
}

impl Harness {
    /// Click into a form field of `window` and replace its text.
    pub(crate) fn type_into(&mut self, window: egui::Id, param: &str, text: &str) {
        let at = self
            .ctx
            .read_response(crate::dialog::field_id(window, param))
            .unwrap_or_else(|| panic!("no field {param}"))
            .rect
            .center();
        self.click(at);
        self.key(Key::A, CTRL);
        self.type_text(text);
    }

    /// Frames (and real time, for the task threads) until `done` holds.
    pub(crate) fn until(&mut self, what: &str, mut done: impl FnMut(&Self) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done(self) {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            thread::sleep(Duration::from_millis(20));
            self.time += 0.3;
            self.idle();
        }
        self.idle();
    }

    fn ping_received(&self, target: usize) -> u64 {
        self.app
            .ping
            .ping
            .as_ref()
            .and_then(|t| t.summary["targets"][target]["received"].as_u64())
            .unwrap_or(0)
    }
}

#[test]
fn ping_two_targets_chart_stats_export_and_mtu() {
    let mut h = lab();
    let win = win_id(Win::Ping);
    assert!(h.has_text("General") && h.has_text("Advanced"));
    h.type_into(win, "address", "127.0.0.1, 198.51.100.7");
    h.app.ping.form.count = "4".into();
    // Enter in the form starts it.
    h.key(Key::Enter, egui::Modifiers::NONE);
    assert!(h.app.ping.ping.is_some(), "{:?}", h.app.log());
    h.until("both targets", |h| {
        h.app.ping.ping.as_ref().is_some_and(|t| t.done)
    });
    assert_eq!(h.ping_received(0), 4);
    assert!(h.has_text("127.0.0.1"));
    assert!(h.has_text("198.51.100.7"));
    assert!(h.has_text("Histogram"));
    // The lossy target trips the 10 % loss alert, loopback does not.
    let lossy = &h.app.ping.ping.as_ref().unwrap().summary["targets"][1];
    if lossy["loss_pct"].as_f64().unwrap() > 10.0 {
        // A red chip (docs/ui-style.md), the details in its tooltip.
        assert!(h.has_text("alerta"));
        assert!(!h.has_text_containing("ALERT"));
    }
    // Statistics come from the engine, not the UI.
    assert!(h.has_text_containing("Loss %"));

    h.click(h.text("Export CSV"));
    let files = h.app.take_exports();
    assert_eq!(files.len(), 1);
    let csv = String::from_utf8(files[0].bytes.clone()).unwrap();
    assert!(csv.starts_with("target,host,address,seq,status,rtt_ms"));
    assert_eq!(csv.lines().count(), 1 + 8, "{csv}");
    assert_eq!(files[0].mime, "text/csv");

    h.click(h.text("Discover MTU"));
    h.until("MTU", |h| h.has_text_containing("Path MTU to 127.0.0.1"));
    // Polls are not logged; starts and the export are.
    assert!(!h.log_ids().contains(&"tool.task.poll"));
    assert!(h.log_ids().contains(&"tool.ping.start"));
}

#[test]
fn esc_stops_a_continuous_ping_then_closes_the_window() {
    let mut h = lab();
    let win = win_id(Win::Ping);
    h.type_into(win, "address", "10.20.30.40");
    h.app.ping.form.interval = "50".into();
    h.click(h.text("Start"));
    h.until("replies", |h| h.ping_received(0) >= 2);
    assert!(h.app.ping.ping.as_ref().unwrap().running());
    h.key(Key::Escape, egui::Modifiers::NONE);
    h.until("stop", |h| h.app.ping.ping.as_ref().is_some_and(|t| t.done));
    assert_eq!(h.app.ping.ping.as_ref().unwrap().state, "stopped");
    assert!(h.app.open.contains(&Win::Ping), "the first Esc only stops");
    h.key(Key::Escape, egui::Modifiers::NONE);
    assert!(!h.app.open.contains(&Win::Ping));
}

#[test]
fn closing_the_window_stops_its_ping() {
    let mut h = lab();
    let win = win_id(Win::Ping);
    h.type_into(win, "address", "10.20.30.41");
    h.app.ping.form.interval = "50".into();
    h.click(h.text("Start"));
    h.until("replies", |h| h.ping_received(0) >= 1);
    h.app.open.remove(&Win::Ping);
    h.app.ping_closed();
    h.idle();
    let tasks = lock(&h.session)
        .execute("tool.task.list", &json!({}))
        .unwrap();
    let id = tasks[0]["id"].as_u64().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let p = lock(&h.session)
            .execute("tool.task.poll", &json!({"id": id}))
            .unwrap();
        if p["state"] == "stopped" {
            break;
        }
        assert!(Instant::now() < deadline, "still {}", p["state"]);
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn bad_input_shows_the_engine_error_and_web_lab_greys_start() {
    let mut h = lab();
    let win = win_id(Win::Ping);
    h.type_into(win, "address", "not a host!");
    h.click(h.text("Start"));
    h.idle();
    assert!(h.has_text_containing("neither an IP address nor a DNS name"));
    // Without a task runner (the in-browser lab) Start is grey, with why.
    let mut h = Harness::new();
    h.app.open.remove(&Win::Interfaces);
    h.app.open(Win::Ping);
    h.idle();
    h.idle();
    h.app.ping.form.address = "127.0.0.1".into();
    h.idle();
    h.tooltip_at(h.text("Start"));
    assert!(h.has_text_containing("connect the GUI to a daemon"));
}

#[test]
fn mtr_window_shows_one_row_per_hop() {
    let mut s = Session::virtual_lab();
    s.set_runner(Arc::new(Threads));
    let mut h = Harness::with_session(s);
    h.app.open.remove(&Win::Interfaces);
    h.app.open(Win::Mtr);
    for _ in 0..6 {
        h.idle();
    }
    h.type_into(win_id(Win::Mtr), "address", "198.51.100.20");
    h.app.mtr.form.count = "3".into();
    h.app.mtr.form.interval = "100".into();
    h.key(Key::Enter, egui::Modifiers::NONE);
    h.until("mtr", |h| h.app.mtr.task.as_ref().is_some_and(|t| t.done));
    let t = h.app.mtr.task.as_ref().unwrap();
    assert_eq!(t.state, "done");
    let hops = t.summary["hops"].as_array().unwrap().len();
    assert_eq!(hops, 6, "{}", t.summary);
    assert!(h.has_text("Worst"));
    assert!(h.has_text("198.51.100.20"));
    // G6.3d: chips, no brackets.
    assert!(h.has_text("privada"), "first router: 10.0.0.x");
    assert!(h.has_text("CGNAT"), "second router: 100.64.2.x");
    // Use DNS is on by default: the lab's routers have names.
    assert!(h.has_text_containing(".sim-transit.example"));
    // G6.3d: the labels are a chip next to the host.
    assert!(h.has_text_containing("MPLS "), "the lossy path has labels");
    assert!(h.has_text_containing("reached"));
    // Esc with nothing running closes it.
    h.key(Key::Escape, egui::Modifiers::NONE);
    assert!(!h.app.open.contains(&Win::Mtr));
}
