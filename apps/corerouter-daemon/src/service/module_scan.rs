//! The SFP/QSFP module scan (G1.22) as a service: every
//! [`SCAN_SECS`](corerouter_engine::dom_watch::SCAN_SECS) it reads the
//! EEPROM of each Ethernet port's module **outside the session lock** and
//! only then takes the lock to hand the readings over (the thresholds and
//! the log lines of G1.20, O(ports) there).
//!
//! Each read is up to four ethtool netlink requests that the kernel serves
//! under its `rtnl_lock` (Linux 6.18.59, `net/ethtool/netlink.c:526`), and a
//! driver that hangs on its I²C bus answers after seconds or never. Done in
//! the session tick, that froze every command, the GUI and MCP for as long.
//! Here it holds only this thread: the row of `system.service.print` stops
//! beating ("no heartbeat (stuck?)") and the router keeps answering.
//!
//! The ports are read one after the other, not on several threads: the
//! kernel serializes them on the `rtnl_lock` anyway, and a parallel scan
//! would only hold it more often against the route and address applies.
//! Without this service (the virtual lab, no module reader) the tick
//! reads by itself.

use std::time::{Duration, Instant};

use corerouter_engine::dom_watch::SCAN_SECS;
use corerouter_engine::{Shared, lock};

/// Between two scans.
const EVERY: Duration = if cfg!(test) { Duration::from_millis(100) } else { Duration::from_secs(SCAN_SECS) };
/// Between two heartbeats while idle (well under the supervisor's stall
/// limit, which a scan every 30 s would reach).
const BEAT: Duration = if cfg!(test) { Duration::from_millis(20) } else { Duration::from_secs(1) };

pub(crate) const SERVICE: super::Service = super::Service {
    name: "module-scan",
    flags: &[],
    topic: "interface",
    enable: "always on with --backend linux",
    depends: &[],
    start,
};

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let session = ctx.session.clone();
    Ok(Box::new(move |health: &super::Health| {
        run(&session, health);
        Ok(())
    }))
}

fn run(session: &Shared, health: &super::Health) {
    let mut next = Instant::now();
    loop {
        health.beat();
        if Instant::now() >= next {
            scan(session, health);
            next = Instant::now() + EVERY;
        }
        if !health.sleep(BEAT) {
            return;
        }
    }
}

fn scan(session: &Shared, health: &super::Health) {
    // Taken under the lock (cheap: the port list and a reader); read with
    // it released.
    let scan = lock(session).module_scan();
    let Some(scan) = scan else {
        health.disabled(Some("no module reader on this backend (the tick reads)"));
        return;
    };
    health.disabled(None);
    let readings = scan.read(|_| health.beat());
    let ports = readings.len();
    let failed = readings.failed();
    lock(session).module_scan_feed(readings);
    if failed == 0 {
        health.clear_error();
    } else {
        health.error(format!("{failed} of {ports} module reads failed"));
    }
    health.event(format!("{ports} ports read"));
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Instant;

    use corerouter_engine::{Session, shared};
    use corerouter_hal::sff::{self, ModuleReader, SfpModule};
    use corerouter_hal::{Hal, HalError, LinkInfo, LinkState, VirtualHal};
    use corerouter_model::{Config, IfName};
    use serde_json::json;

    use super::*;

    /// What the slow reader saw.
    #[derive(Default)]
    struct Probe {
        /// A read is sleeping now.
        reading: AtomicBool,
        reads: AtomicU32,
        /// Reads done with the session lock held (by the tick).
        under_lock: AtomicU32,
    }

    /// Every port but `ether1` (copper) has a module whose EEPROM takes
    /// `delay` to read (a driver slow on its I²C bus).
    struct SlowModules {
        delay: Duration,
        probe: Arc<Probe>,
    }

    impl SlowModules {
        fn read(&self, name: &IfName) -> Result<SfpModule, HalError> {
            self.probe.reading.store(true, Ordering::Release);
            thread::sleep(self.delay);
            self.probe.reads.fetch_add(1, Ordering::AcqRel);
            self.probe.reading.store(false, Ordering::Release);
            if name.as_str() == "ether1" {
                return Err(HalError::Unsupported("copper: no cage".into()));
            }
            let (a0, a2) = sff::lab_sfp_plus(name.as_str(), 40.0, -2.0, -3.0);
            Ok(sff::decode(&a0, Some(&a2)))
        }
    }

    struct Reader(Arc<SlowModules>);

    impl ModuleReader for Reader {
        fn read(&mut self, name: &IfName) -> Result<SfpModule, HalError> {
            self.0.read(name)
        }
    }

    /// The virtual lab with [`SlowModules`] in its cages: `sfp_module`
    /// (the tick, under the lock) and the reader (this service) both slow.
    struct Lab {
        lab: VirtualHal,
        modules: Arc<SlowModules>,
        /// Offer the reader (Linux since G1.22); without it the tick reads
        /// under the lock, as every backend did before.
        reader: bool,
    }

    impl Hal for Lab {
        fn describe(&self) -> String {
            "slow modules lab".into()
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
            self.modules.probe.under_lock.fetch_add(1, Ordering::AcqRel);
            self.modules.read(name)
        }
        fn module_reader(&self) -> Option<Box<dyn ModuleReader>> {
            self.reader
                .then(|| Box::new(Reader(Arc::clone(&self.modules))) as Box<dyn ModuleReader>)
        }
    }

    fn lab(delay: Duration, reader: bool) -> (Shared, Arc<Probe>) {
        let probe = Arc::new(Probe::default());
        let hal = Lab {
            lab: VirtualHal::default(),
            modules: Arc::new(SlowModules {
                delay,
                probe: Arc::clone(&probe),
            }),
            reader,
        };
        (shared(Session::new(Box::new(hal))), probe)
    }

    fn wait(what: &str, mut f: impl FnMut() -> bool) {
        let t = Instant::now();
        while !f() {
            assert!(t.elapsed() < Duration::from_secs(20), "timed out waiting for {what}");
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// G1.22's criterion: with 200 ms per module, a command during the scan
    /// answers in under 50 ms, and the tick reads nothing under the lock.
    #[test]
    fn a_command_during_a_slow_scan_answers_at_once() {
        let (session, probe) = lab(Duration::from_millis(200), true);
        let health = super::super::Health::new(corerouter_control::Shutdown::default());
        let body = {
            let (session, health) = (session.clone(), health.clone());
            thread::Builder::new()
                .name("module-scan-test".into())
                .spawn(move || run(&session, &health))
                .unwrap()
        };
        wait("the scan's first read", || probe.reading.load(Ordering::Acquire));
        // The clock's tick, due to scan by itself, leaves it to the service.
        lock(&session).tick(1_900_000_000);
        // A query and a change, each while a module is being read.
        let (mut worst, mut wait_lock) = (Duration::ZERO, Duration::ZERO);
        for i in 0..6 {
            wait("a read in progress", || probe.reading.load(Ordering::Acquire));
            let t = Instant::now();
            let mut s = lock(&session);
            wait_lock = wait_lock.max(t.elapsed());
            let v = if i % 2 == 0 {
                s.execute("system.identity.get", &json!({}))
            } else {
                s.execute("system.identity.set", &json!({"name": format!("r{i}")}))
            };
            drop(s);
            v.unwrap();
            worst = worst.max(t.elapsed());
            thread::sleep(Duration::from_millis(150));
        }
        assert!(worst < Duration::from_millis(50), "a command took {worst:?}");
        eprintln!(
            "6 commands during a scan of 200 ms modules: slowest {worst:?}, \
             longest wait for the lock {wait_lock:?}"
        );
        // Every Ethernet port of the lab read, none by the tick.
        let ports = lock(&session)
            .store()
            .running()
            .interfaces
            .values()
            .filter(|i| i.kind == corerouter_model::InterfaceKind::Ethernet)
            .count();
        let ports = u32::try_from(ports).unwrap();
        wait("the whole scan", || probe.reads.load(Ordering::Acquire) >= ports);
        assert_eq!(probe.under_lock.load(Ordering::Acquire), 0);
        // The readings reached the engine: the copper port is not asked
        // again.
        wait("the readings handed over", || {
            lock(&session)
                .module_scan()
                .is_some_and(|scan| scan.ports().len() + 1 == usize::try_from(ports).unwrap())
        });
        health.stop();
        body.join().unwrap();
    }

    /// The old way (a backend with no reader), for the PR's number: the
    /// tick reading the same modules holds the lock for the whole scan, and
    /// the service stands aside.
    #[test]
    fn without_a_reader_the_tick_holds_the_lock_for_the_scan() {
        let (session, probe) = lab(Duration::from_millis(20), false);
        assert!(lock(&session).module_scan().is_none());
        let t = Instant::now();
        lock(&session).tick(1_900_000_000);
        let held = t.elapsed();
        let reads = probe.under_lock.load(Ordering::Acquire);
        assert!(reads > 0, "the tick read the modules itself");
        let floor = Duration::from_millis(20) * reads;
        assert!(held >= floor, "{held:?} < {floor:?}");
        eprintln!("tick with {reads} modules of 20 ms read under the lock: held {held:?}");
    }
}
