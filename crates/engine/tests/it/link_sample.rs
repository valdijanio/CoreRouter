//! G1.3f: the links read with the session unlocked. A fresh sample is
//! folded in with no poll under the lock; one read before a commit is
//! refused and the session polls again.
#![allow(clippy::unwrap_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use corerouter_engine::Session;
use corerouter_hal::link_reader::{LinkReader, LinkSample};
use corerouter_hal::{Hal, HalError, LinkInfo, LinkState, VirtualHal};
use corerouter_model::Config;
use serde_json::json;

#[derive(Default)]
struct Counts {
    /// Polls under the lock (`Hal::poll`).
    polls: AtomicU64,
    /// Samples folded in.
    folded: AtomicU64,
    /// Samples refused.
    refused: AtomicU64,
}

/// The virtual lab, with a link reader whose samples go stale on apply.
struct Sampled {
    lab: VirtualHal,
    epoch: u64,
    counts: Arc<Counts>,
}

struct Reader {
    epoch: u64,
    links: Vec<LinkState>,
}

impl LinkReader for Reader {
    fn read(&mut self) -> LinkSample {
        LinkSample::new(self.epoch, std::mem::take(&mut self.links))
    }
}

impl Hal for Sampled {
    fn describe(&self) -> String {
        "sampled lab".into()
    }
    fn discover_links(&mut self) -> Result<Vec<LinkInfo>, HalError> {
        self.lab.discover_links()
    }
    fn apply(&mut self, from: &Config, to: &Config) -> Result<(), HalError> {
        self.epoch += 1;
        self.lab.apply(from, to)
    }
    fn poll(&mut self) -> Vec<LinkState> {
        self.counts.polls.fetch_add(1, Ordering::Relaxed);
        self.lab.poll()
    }
    fn link_reader(&self) -> Option<Box<dyn LinkReader>> {
        let mut lab = self.lab.clone();
        Some(Box::new(Reader {
            epoch: self.epoch,
            links: lab.poll(),
        }))
    }
    fn poll_sample(&mut self, sample: LinkSample) -> Option<Vec<LinkState>> {
        if sample.epoch() != self.epoch {
            self.counts.refused.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        self.counts.folded.fetch_add(1, Ordering::Relaxed);
        sample.take()
    }
    fn now_unix(&self) -> Option<u64> {
        None
    }
}

fn session() -> (Session, Arc<Counts>) {
    let counts = Arc::new(Counts::default());
    let hal = Sampled {
        lab: VirtualHal::default(),
        epoch: 0,
        counts: Arc::clone(&counts),
    };
    (Session::new(Box::new(hal)), counts)
}

fn n(c: &AtomicU64) -> u64 {
    c.load(Ordering::Relaxed)
}

#[test]
fn a_fresh_sample_needs_no_poll_under_the_lock() {
    let (mut s, c) = session();
    for t in 0..3 {
        let sample = s.link_reader().map(|mut r| r.read());
        s.tick_sampled(1_900_000_000 + t, sample);
    }
    assert_eq!((n(&c.polls), n(&c.folded), n(&c.refused)), (0, 3, 0));
    // The links were seen: `interface.list` has them with their times.
    let v = s.execute("interface.list", &json!({})).unwrap();
    assert!(v.to_string().contains("ether1"), "{v}");
}

#[test]
fn a_sample_from_before_a_commit_is_refused_and_polled_again() {
    let (mut s, c) = session();
    let sample = s.link_reader().map(|mut r| r.read());
    // A commit lands while the links are read.
    s.execute(
        "ip.address.add",
        &json!({"address": "10.9.0.1/24", "interface": "ether1"}),
    )
    .unwrap();
    s.tick_sampled(1_900_000_000, sample);
    assert_eq!((n(&c.refused), n(&c.polls)), (1, 1));
    // The link events' look does the same.
    let sample = s.link_reader().map(|mut r| r.read());
    s.execute("system.identity.set", &json!({"name": "r2"}))
        .unwrap();
    assert!(s.link_events_wanted(Some(&["ether1".to_owned()])));
    assert!(!s.link_events_wanted(Some(&["ppp7".to_owned()])));
    s.link_events_sampled(sample);
    assert_eq!((n(&c.refused), n(&c.polls)), (2, 2));
}
