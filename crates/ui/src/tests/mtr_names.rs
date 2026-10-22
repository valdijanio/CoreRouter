//! G6.3b: Tools › MTR shows each hop's address at once and its name when
//! the (slow) reverse lookup answers, without holding up the table; the
//! AS column appears with "AS lookup".

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use corerouter_engine::dns::DnsBackend;
use corerouter_engine::{Clock, Job, Runner};
use corerouter_hal::probe::{AsInfo, Lookup};
use corerouter_model::dns::CacheRow;
use corerouter_proto_dns::resolver::ResolveError;
use egui::Key;

use super::*;

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

/// A resolver whose answers stay pending until `ready`.
#[derive(Default)]
struct Slow {
    ready: AtomicBool,
}

impl DnsBackend for Slow {
    fn lookup(&self, _: &str) -> Result<Vec<IpAddr>, ResolveError> {
        Err(ResolveError::NoServers)
    }
    fn cache_rows(&self) -> Vec<CacheRow> {
        Vec::new()
    }
    fn cache_used_bytes(&self) -> usize {
        0
    }
    fn flush(&self) {}
    fn reverse_nowait(&self, ip: IpAddr) -> Option<Lookup<Option<String>>> {
        Some(if self.ready.load(Ordering::Relaxed) {
            Lookup::Done(Some(format!("slow-{}.example", ip.to_string().replace(['.', ':'], "-"))))
        } else {
            Lookup::Pending
        })
    }
    fn origin_as_nowait(&self, _: IpAddr) -> Option<Lookup<Option<AsInfo>>> {
        Some(Lookup::Done(Some(AsInfo {
            asn: 3356,
            name: Some("LEVEL3".into()),
            prefix: None,
        })))
    }
}

fn hops(h: &Harness) -> Vec<serde_json::Value> {
    h.app
        .mtr
        .task
        .as_ref()
        .and_then(|t| t.summary["hops"].as_array().cloned())
        .unwrap_or_default()
}

#[test]
fn names_join_the_addresses_when_they_arrive() {
    let slow = Arc::new(Slow::default());
    let mut s = Session::virtual_lab();
    s.set_runner(Arc::new(Threads));
    s.set_dns_backend(slow.clone());
    let mut h = Harness::with_session(s);
    h.app.open.remove(&Win::Interfaces);
    h.app.open(Win::Mtr);
    for _ in 0..6 {
        h.idle();
    }
    h.type_into(win_id(Win::Mtr), "address", "8.8.8.8");
    h.app.mtr.form.interval = "100".into();
    h.app.mtr.form.as_lookup = true;
    h.key(Key::Enter, egui::Modifiers::NONE);
    // Measured and drawn while every name is still pending.
    h.until("rounds", |h| {
        h.app
            .mtr
            .task
            .as_ref()
            .is_some_and(|t| t.summary["rounds"].as_u64().unwrap_or(0) >= 3 && t.summary["reached"] == true)
    });
    assert!(h.has_text("8.8.8.8"), "the address shows at once");
    assert!(!h.has_text_containing("slow-"), "no name yet");
    assert!(h.has_text("ASN") && h.has_text_containing("AS3356 LEVEL3"));
    assert!(hops(&h).iter().all(|x| x["name"].is_null()));
    // The names arrive: they show above the addresses, the task never
    // stopped measuring.
    slow.ready.store(true, Ordering::Relaxed);
    h.until("names", |h| h.has_text("slow-8-8-8-8.example"));
    assert!(h.has_text("8.8.8.8"), "the address stays under the name");
    let last = hops(&h).last().cloned().unwrap();
    assert_eq!(last["name"], "slow-8-8-8-8.example");
    // Private and CGNAT hops are never looked up.
    assert!(hops(&h).iter().any(|x| x["scope"] == "private" && x["name"].is_null()));
    h.key(Key::Escape, egui::Modifiers::NONE);
    h.until("stopped", |h| h.app.mtr.task.as_ref().is_some_and(|t| t.done));
}
