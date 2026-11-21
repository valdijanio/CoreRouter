//! G1.22: the module scan read with the session unlocked. With a module
//! reader the tick reads no EEPROM under the lock; the readings handed
//! back are noted like the tick's, and ports without a cage are not asked
//! again. (The DOM watch's lines go to the process log, G1.20.)
#![allow(clippy::unwrap_used)]

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use corerouter_engine::Session;
use corerouter_engine::dom_watch::SCAN_SECS;
use corerouter_hal::sff::{ModuleReader, SfpModule};
use corerouter_hal::{Hal, HalError, LinkInfo, LinkState, VirtualHal};
use corerouter_model::{Config, IfName, InterfaceKind};

/// The virtual lab (its last port has an SFP+ module), counting the
/// module reads done under the lock and by the reader.
struct Lab {
    lab: VirtualHal,
    under_lock: Arc<AtomicU64>,
    by_reader: Arc<AtomicU64>,
}

/// Reads a copy of the lab taken when the scan was.
struct Reader {
    lab: VirtualHal,
    reads: Arc<AtomicU64>,
}

impl ModuleReader for Reader {
    fn read(&mut self, name: &IfName) -> Result<SfpModule, HalError> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.lab.sfp_module(name)
    }
}

impl Hal for Lab {
    fn describe(&self) -> String {
        "lab with a module reader".into()
    }
    fn discover_links(&mut self) -> Result<Vec<LinkInfo>, HalError> {
        self.lab.discover_links()
    }
    fn apply(&mut self, from: &Config, to: &Config) -> Result<(), HalError> {
        self.lab.apply(from, to)
    }
    fn poll(&mut self) -> Vec<LinkState> {
        self.lab.poll()
    }
    fn now_unix(&self) -> Option<u64> {
        None
    }
    fn sfp_module(&mut self, name: &IfName) -> Result<SfpModule, HalError> {
        self.under_lock.fetch_add(1, Ordering::Relaxed);
        self.lab.sfp_module(name)
    }
    fn module_reader(&self) -> Option<Box<dyn ModuleReader>> {
        Some(Box::new(Reader {
            lab: self.lab.clone(),
            reads: Arc::clone(&self.by_reader),
        }))
    }
}

fn lab() -> (Session, Arc<AtomicU64>, Arc<AtomicU64>) {
    let under_lock = Arc::new(AtomicU64::new(0));
    let by_reader = Arc::new(AtomicU64::new(0));
    let hal = Lab {
        lab: VirtualHal::default(),
        under_lock: Arc::clone(&under_lock),
        by_reader: Arc::clone(&by_reader),
    };
    (Session::new(Box::new(hal)), under_lock, by_reader)
}

fn ethernet(s: &Session) -> Vec<IfName> {
    s.store()
        .running()
        .interfaces
        .values()
        .filter(|i| i.kind == InterfaceKind::Ethernet)
        .map(|i| i.name.clone())
        .collect()
}

#[test]
fn with_a_reader_the_tick_reads_no_module_under_the_lock() {
    let (mut s, under_lock, _) = lab();
    for t in 0..4 {
        s.tick(1_900_000_000 + t * SCAN_SECS);
    }
    assert_eq!(under_lock.load(Ordering::Relaxed), 0);
    // A backend without a reader (the plain lab) still scans in the tick.
    let mut plain = Session::virtual_lab();
    plain.tick(1_900_000_000);
}

#[test]
fn a_scan_reads_every_port_then_only_the_cages() {
    let (mut s, under_lock, by_reader) = lab();
    let all = ethernet(&s);
    let scan = s.module_scan().unwrap();
    assert_eq!(scan.ports(), all.as_slice());
    let mut seen = Vec::new();
    let readings = scan.read(|p| seen.push(p.clone()));
    assert_eq!(seen, all, "the heartbeat runs before each port");
    assert_eq!(readings.len(), all.len());
    assert_eq!(readings.failed(), 0, "a copper port is no failure");
    s.module_scan_feed(readings);
    // The copper ports answered "no cage": the next scan skips them.
    let again = s.module_scan().unwrap();
    assert!(
        !again.ports().is_empty() && again.ports().len() < all.len(),
        "{again:?}"
    );
    assert_eq!(
        by_reader.load(Ordering::Relaxed),
        u64::try_from(all.len()).unwrap()
    );
    assert_eq!(under_lock.load(Ordering::Relaxed), 0);
}
