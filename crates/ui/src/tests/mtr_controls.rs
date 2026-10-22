//! MTR window controls: a click selects a hop (the row is highlighted, a
//! second click clears it); Enter in Address starts, and while running a
//! changed address restarts with it.

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use corerouter_engine::{Clock, Job, Runner};
use egui::Key;
use serde_json::json;

use super::*;
use crate::mtr::host_id;
use crate::ping::TaskView;

struct Threads;

struct Wall(Instant);

impl Clock for Wall {
    fn elapsed(&self) -> Duration {
        self.0.elapsed()
    }
    fn sleep(&self, d: Duration) {
        thread::sleep(d);
    }
}

impl Runner for Threads {
    fn spawn(&self, name: &str, job: Job) -> Result<(), String> {
        thread::Builder::new()
            .name(name.into())
            .spawn(move || job(&Wall(Instant::now())))
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

fn mtr_alone(mut h: Harness) -> Harness {
    h.app.open.remove(&Win::Interfaces);
    h.app.open(Win::Mtr);
    for _ in 0..6 {
        h.idle();
    }
    h
}

#[test]
fn a_click_selects_a_hop_and_a_second_click_clears_it() {
    let mut h = mtr_alone(Harness::new());
    let mut t = TaskView::new(1);
    t.done = true;
    t.state = "done".into();
    t.summary = json!({"address": "8.8.8.8", "rounds": 3, "hops": [
        {"hop": 1, "hosts": ["10.0.0.1"], "sent": 3, "loss_pct": 0.0, "avg_ms": 1.0},
        {"hop": 2, "hosts": ["8.8.8.8"], "name": "dns.google", "sent": 3, "loss_pct": 0.0, "avg_ms": 9.0},
    ]});
    h.app.mtr.task = Some(t);
    for _ in 0..4 {
        h.idle();
    }
    let row2 = h.ctx.read_response(host_id(2)).expect("hop 2 drawn").rect.center();
    h.click(row2);
    assert_eq!(h.app.mtr.selected, Some(2));
    h.click(row2);
    assert_eq!(h.app.mtr.selected, None);
    // A right click selects too and opens the copy menu.
    h.click_with(row2, egui::PointerButton::Secondary, egui::Modifiers::NONE);
    assert_eq!(h.app.mtr.selected, Some(2));
    assert!(h.has_text("Copy address") && h.has_text("Copy host"));
}

#[test]
fn enter_starts_and_a_new_address_restarts() {
    let mut s = Session::virtual_lab();
    s.set_runner(Arc::new(Threads));
    let mut h = mtr_alone(Harness::with_session(s));
    let win = win_id(Win::Mtr);
    h.type_into(win, "address", "127.0.0.1");
    h.key(Key::Enter, egui::Modifiers::NONE);
    h.until("running", |h| {
        h.app.mtr.task.as_ref().is_some_and(TaskView::running)
    });
    let first = h.app.mtr.task.as_ref().map(|t| t.id);
    // The same address again: keeps running, no restart.
    h.key(Key::Enter, egui::Modifiers::NONE);
    h.idle();
    assert_eq!(h.app.mtr.task.as_ref().map(|t| t.id), first);
    // A new address: stop, then start with it.
    h.type_into(win, "address", "198.51.100.7");
    h.key(Key::Enter, egui::Modifiers::NONE);
    h.until("restarted", |h| {
        h.app.mtr.task.as_ref().is_some_and(|t| {
            Some(t.id) != first && t.summary.get("address").and_then(|a| a.as_str()) == Some("198.51.100.7")
        })
    });
    assert!(h.log_ids().contains(&"tool.task.stop"));
}
