use std::cell::Cell;

use super::*;
use crate::tasks::{Clock, TaskCell};
use corerouter_hal::lsp::sim::SimLspProber;

/// Virtual time: sleeping advances it, nothing really waits.
struct Fake(Cell<Duration>);

impl Clock for Fake {
    fn elapsed(&self) -> Duration {
        self.0.get()
    }
    fn sleep(&self, d: Duration) {
        self.0.set(self.0.get() + d);
    }
}

fn job(fec: &str, mode: Mode) -> LspJob {
    LspJob {
        fec: Fec::Ldp(fec.parse().unwrap()),
        mode,
        timeout: Duration::from_secs(2),
        size: 0,
        ttl: 255,
        exp: 0,
        validate: true,
    }
}

fn run_sim(job: LspJob) -> (Result<(), String>, Vec<Value>, Value, Duration) {
    let cell = TaskCell::for_test();
    let clock = Fake(Cell::new(Duration::ZERO));
    let ctx = TaskCtx::new(&cell, &clock);
    let r = run(job, &SimLspProber, &ctx);
    let (events, summary) = cell.snapshot();
    (r, events, summary, clock.0.get())
}

const PING: Mode = Mode::Ping {
    count: 4,
    interval: Duration::from_secs(1),
};

#[test]
fn a_dropped_lsp_times_out() {
    let (r, events, summary, took) = run_sim(job("10.255.9.9/32", PING));
    r.unwrap();
    assert_eq!(events.len(), 4);
    assert!(events.iter().all(|e| e["status"] == "timeout" && e["letter"] == "."));
    assert_eq!(summary["stats"]["loss_pct"], 100.0);
    // 4 requests a second apart, the last waits its 2 s timeout.
    assert!(took >= Duration::from_secs(5) && took <= Duration::from_secs(6), "{took:?}");
}

#[test]
fn round_trips_and_codes_are_counted() {
    let (r, events, summary, _) = run_sim(job("10.255.0.3/32", PING));
    r.unwrap();
    assert!(events.iter().all(|e| e["code"] == 3), "{events:?}");
    // 2 hops: 0.4 + 2 × 0.6 ms, plus up to 0.2 ms of jitter.
    let rtt = events[0]["rtt_ms"].as_f64().unwrap();
    assert!((1.6..=1.8).contains(&rtt), "{rtt}");
    assert_eq!(summary["codes"][0]["count"], 4);
    assert_eq!(summary["codes"][0]["letter"], "!");
}

#[test]
fn a_label_of_another_fec_stops_the_trace_with_code_10() {
    let (r, events, summary, _) = run_sim(job(
        "10.255.8.8/32",
        Mode::Trace {
            max_hops: 30,
            probes: 1,
        },
    ));
    r.unwrap();
    let last = events.last().unwrap();
    assert_eq!((last["hop"].as_u64(), last["code"].as_u64(), last["letter"].as_str()), (Some(2), Some(10), Some("f")));
    assert!(summary["result"].as_str().unwrap().starts_with("stopped at hop 2"));
}

#[test]
fn the_pad_fills_the_request_to_size() {
    let mut j = job("10.255.0.3/32", PING);
    j.size = 200;
    let b = request(&j, 1, 1, None);
    assert_eq!(b.len(), 200);
    let e = wire::parse(&b).unwrap();
    // "Drop Pad TLV from reply": the reply stays small.
    assert_eq!(e.pad.as_ref().map(|p| p[0]), Some(1));
    j.size = 0;
    assert!(wire::parse(&request(&j, 1, 1, None)).unwrap().pad.is_none());
}

#[test]
fn each_task_has_its_own_handle() {
    let a = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    let b = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    assert_ne!(a, b);
}
