//! IP › DNS Resolve (G4.1d): `ip.dns.resolve` as a task, read by polling.

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use corerouter_engine::{Clock, Job, Runner};

use super::*;
use crate::dns_resolve::{ResolvePanel, WIN};

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
    fn spawn(&self, _name: &str, job: Job) -> Result<(), String> {
        thread::spawn(move || job(&Wall(Instant::now())));
        Ok(())
    }
}

#[test]
fn resolve_window_runs_the_task_and_shows_the_answer() {
    let mut s = Session::virtual_lab();
    s.set_runner(Arc::new(Threads));
    s.tick(1_000);
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(crate::dns::WIN_CACHE));
    h.idle();
    h.idle();
    h.click(h.text("Resolve…"));
    h.idle();
    assert!(h.app.open.contains(&Win::Panel(WIN)), "opened from DNS Cache");
    {
        let p = h.app.panel_mut::<ResolvePanel>().unwrap();
        p.name = "localhost".into();
        p.rtype = "A".into();
    }
    h.idle();
    h.click(h.text("Resolve"));
    let deadline = Instant::now() + Duration::from_secs(10);
    while !h.has_text("simulated") {
        assert!(Instant::now() < deadline, "no answer: {:?}", h.app.log());
        thread::sleep(Duration::from_millis(20));
        h.app.cache.refreshed_at = None;
        h.time += 0.3;
        h.idle();
    }
    assert!(h.has_text("127.0.0.1"), "the lab's localhost");
    assert!(h.app.panel_mut::<ResolvePanel>().unwrap().done);
}
