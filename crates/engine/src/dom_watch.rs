//! SFP/QSFP diagnostics against the module's own thresholds (G1.20): a
//! reading that crosses a warning or alarm limit is logged once, when it
//! crosses (and again when it comes back), never on every read. Modules
//! going in and out of a cage are logged too.
//!
//! The readings come from every `interface.ethernet.monitor` and from a
//! scan of the Ethernet ports every [`SCAN_SECS`], so an alert is logged
//! even with no window open. Operational state: never saved.
//!
//! The scan (G1.22): a module read is up to four kernel requests, and a
//! driver stuck on its I²C bus answers after seconds. When the hal has a
//! [`ModuleReader`] (Linux), a thread of the app takes a [`ModuleScan`]
//! under the lock ([`Session::module_scan`]: the ports and the reader),
//! reads with the lock released and hands the readings back
//! ([`Session::module_scan_feed`]); the tick then reads nothing. A hal
//! without one (the virtual lab, cheap) is read by [`Session::tick`].

use std::collections::{BTreeMap, BTreeSet};

use corerouter_hal::HalError;
use corerouter_hal::sff::{Level, ModuleReader, SfpModule};
use corerouter_model::{IfName, InterfaceKind};

use crate::Session;

/// How often the tick scans the ports' modules.
pub const SCAN_SECS: u64 = 30;
/// Ports scanned at most per tick (bounded work under the session lock).
const MAX_SCAN: usize = 64;
/// Ports one [`ModuleScan`] reads at most: off the lock there is no reason
/// to leave the ports of a big chassis out, but a config with thousands of
/// "Ethernet" ports must not make a scan endless.
const MAX_SCAN_OFF_LOCK: usize = 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct PortState {
    present: bool,
    /// Last level of each reading (`rx-power lane 2` → low-alarm).
    levels: BTreeMap<String, Level>,
}

#[derive(Debug, Clone, Default)]
pub struct DomWatch {
    ports: BTreeMap<IfName, PortState>,
    last_scan: Option<u64>,
    /// Ports that answered "no module EEPROM" (copper, a driver without
    /// module access): the scan skips them instead of asking the kernel
    /// again every [`SCAN_SECS`] under the session lock. Reading one by
    /// hand (`interface.ethernet.monitor`) still asks.
    no_cage: BTreeSet<IfName>,
}

/// `-25.10 dBm`.
fn value(v: f64, unit: &str) -> String {
    match unit {
        "V" => format!("{v:.3} V"),
        "C" => format!("{v:.1} C"),
        _ => format!("{v:.2} {unit}"),
    }
}

impl DomWatch {
    /// Note `m` for `name`; returns the log lines it caused (also logged).
    /// While the port is disabled its laser is off on purpose: the TX
    /// readings do not alert.
    pub fn observe(&mut self, name: &IfName, m: &SfpModule, disabled: bool) -> Vec<String> {
        let mut lines = Vec::new();
        let st = self.ports.entry(name.clone()).or_default();
        if m.module_present != st.present {
            let who = [&m.vendor_name, &m.vendor_part_number, &m.vendor_serial]
                .iter()
                .filter_map(|x| x.as_deref())
                .collect::<Vec<_>>()
                .join(" ");
            let line = if m.module_present {
                format!(
                    "{name}: module inserted ({})",
                    if who.is_empty() { "unknown" } else { &who }
                )
            } else {
                format!("{name}: module removed")
            };
            log::info!("{line}");
            lines.push(line);
            st.present = m.module_present;
        }
        let mut now = BTreeMap::new();
        for r in &m.dom {
            let Some(mut level) = r.level else {
                continue;
            };
            if disabled && r.name.starts_with("tx-") {
                level = Level::Ok;
            }
            let key = r.key();
            let before = st.levels.get(&key).copied().unwrap_or(Level::Ok);
            if level != before {
                let line = match (level, r.limits) {
                    (Level::Ok, _) => format!(
                        "{name}: module {key} back to normal ({})",
                        value(r.value, r.unit)
                    ),
                    (l, Some(lim)) => {
                        let limit = match l {
                            Level::HighAlarm => lim.high_alarm,
                            Level::HighWarning => lim.high_warning,
                            Level::LowWarning => lim.low_warning,
                            _ => lim.low_alarm,
                        };
                        let dir = if matches!(l, Level::HighAlarm | Level::HighWarning) {
                            "above"
                        } else {
                            "below"
                        };
                        format!(
                            "{name}: module {key} {} {dir} the {} limit {}",
                            value(r.value, r.unit),
                            l.label(),
                            value(limit, r.unit)
                        )
                    }
                    (l, None) => format!("{name}: module {key} {}", l.label()),
                };
                if level.is_alarm() {
                    log::error!("{line}");
                } else if level == Level::Ok {
                    log::info!("{line}");
                } else {
                    log::warn!("{line}");
                }
                lines.push(line);
            }
            if level != Level::Ok {
                now.insert(key, level);
            }
        }
        st.levels = now;
        lines
    }

    /// A port that has no cage: forget it.
    pub fn forget(&mut self, name: &IfName) {
        self.ports.remove(name);
    }
}

/// The ports to read and a reader, taken under the session lock, read
/// with it released (see the module docs).
pub struct ModuleScan {
    reader: Box<dyn ModuleReader>,
    ports: Vec<IfName>,
}

impl std::fmt::Debug for ModuleScan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModuleScan")
            .field("ports", &self.ports)
            .finish_non_exhaustive()
    }
}

impl ModuleScan {
    pub fn ports(&self) -> &[IfName] {
        &self.ports
    }

    /// Read every port, one after the other; `before` runs before each
    /// (a heartbeat: one read may take seconds).
    pub fn read(mut self, mut before: impl FnMut(&IfName)) -> ModuleReadings {
        let mut read = Vec::with_capacity(self.ports.len());
        for p in self.ports {
            before(&p);
            let r = self.reader.read(&p);
            read.push((p, r));
        }
        ModuleReadings { read }
    }
}

/// What a [`ModuleScan`] read, for [`Session::module_scan_feed`].
#[derive(Debug)]
pub struct ModuleReadings {
    read: Vec<(IfName, Result<SfpModule, HalError>)>,
}

impl ModuleReadings {
    pub fn len(&self) -> usize {
        self.read.len()
    }

    pub fn is_empty(&self) -> bool {
        self.read.is_empty()
    }

    /// Reads that failed (a port without a cage is not a failure).
    pub fn failed(&self) -> usize {
        self.read
            .iter()
            .filter(|(_, r)| matches!(r, Err(e) if !matches!(e, HalError::Unsupported(_))))
            .count()
    }
}

impl Session {
    /// Read `name`'s module and note it; `Unsupported` means no cage.
    pub(crate) fn read_module(&mut self, name: &IfName) -> Result<SfpModule, HalError> {
        let r = self.hal_mut().sfp_module(name);
        self.note_module(name, &r);
        r
    }

    /// Note a reading of `name`'s module.
    fn note_module(&mut self, name: &IfName, r: &Result<SfpModule, HalError>) {
        let disabled = self
            .store()
            .running()
            .interfaces
            .get(name)
            .is_some_and(|i| i.disabled);
        match r {
            Ok(m) => {
                self.dom.observe(name, m, disabled);
            }
            Err(HalError::Unsupported(_)) => self.dom.forget(name),
            Err(_) => {}
        }
    }

    /// The Ethernet ports of the running config worth reading (not known
    /// to have no cage), at most `max`.
    fn module_ports(&mut self, max: usize) -> Vec<IfName> {
        let ethernet: BTreeSet<IfName> = self
            .store()
            .running()
            .interfaces
            .values()
            .filter(|i| i.kind == InterfaceKind::Ethernet)
            .map(|i| i.name.clone())
            .collect();
        // A port gone from the config is asked again if it comes back.
        self.dom.no_cage.retain(|n| ethernet.contains(n));
        ethernet
            .difference(&self.dom.no_cage)
            .take(max)
            .cloned()
            .collect()
    }

    /// Every [`SCAN_SECS`]: read the module of each Ethernet port, here
    /// only when the hal has no [`ModuleReader`] (an app thread reads with
    /// one, off the lock).
    pub(crate) fn scan_modules(&mut self) {
        let Some(now) = self.now() else {
            return;
        };
        if self
            .dom
            .last_scan
            .is_some_and(|t| now.saturating_sub(t) < SCAN_SECS)
        {
            return;
        }
        self.dom.last_scan = Some(now);
        if self.hal().module_reader().is_some() {
            return;
        }
        for p in self.module_ports(MAX_SCAN) {
            if let Err(HalError::Unsupported(_)) = self.read_module(&p) {
                self.dom.no_cage.insert(p);
            }
        }
    }

    /// A scan for the caller to read with the session unlocked, then hand
    /// to [`Session::module_scan_feed`]; `None`: the hal has no module
    /// reader, the tick reads by itself. The caller paces the scans
    /// (every [`SCAN_SECS`]).
    pub fn module_scan(&mut self) -> Option<ModuleScan> {
        let reader = self.hal().module_reader()?;
        Some(ModuleScan {
            reader,
            ports: self.module_ports(MAX_SCAN_OFF_LOCK),
        })
    }

    /// Note what a [`ModuleScan`] read. A port that stopped being an
    /// Ethernet port of the running config while it was read is skipped.
    pub fn module_scan_feed(&mut self, readings: ModuleReadings) {
        for (p, r) in readings.read {
            let still = self
                .store()
                .running()
                .interfaces
                .get(&p)
                .is_some_and(|i| i.kind == InterfaceKind::Ethernet);
            if !still {
                continue;
            }
            self.note_module(&p, &r);
            if let Err(HalError::Unsupported(_)) = r {
                self.dom.no_cage.insert(p);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_hal::sff;

    fn n(s: &str) -> IfName {
        s.parse().unwrap()
    }

    #[test]
    fn logs_crossings_once_and_recoveries() {
        let mut w = DomWatch::default();
        let (a0, a2) = sff::lab_sfp_plus("S1", 40.0, -2.0, -3.0);
        let ok = sff::decode(&a0, Some(&a2));
        let lines = w.observe(&n("ether8"), &ok, false);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains("module inserted (CoreRouter Lab CR-SFP10G-SR S1)"));
        assert!(w.observe(&n("ether8"), &ok, false).is_empty());

        let (a0, a2) = sff::lab_sfp_plus("S1", 40.0, -2.0, -16.0);
        let low = sff::decode(&a0, Some(&a2));
        let lines = w.observe(&n("ether8"), &low, false);
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(
            lines[0].contains("rx-power -16.00 dBm below the low-alarm limit -13.90 dBm"),
            "{lines:?}"
        );
        assert!(w.observe(&n("ether8"), &low, false).is_empty(), "once");
        let lines = w.observe(&n("ether8"), &ok, false);
        assert!(lines[0].contains("rx-power back to normal"), "{lines:?}");
    }

    #[test]
    fn a_disabled_port_has_its_laser_off_on_purpose() {
        let mut w = DomWatch::default();
        let (a0, a2) = sff::lab_sfp_plus("S1", 40.0, sff::MIN_DBM, -3.0);
        let off = sff::decode(&a0, Some(&a2));
        let lines = w.observe(&n("ether8"), &off, true);
        assert_eq!(lines.len(), 1, "only the insertion: {lines:?}");
        let lines = w.observe(&n("ether8"), &off, false);
        assert!(lines.iter().any(|l| l.contains("tx-power")), "{lines:?}");
    }

    #[test]
    fn removal_is_logged() {
        let mut w = DomWatch::default();
        let (a0, a2) = sff::lab_sfp_plus("S1", 40.0, -2.0, -3.0);
        w.observe(&n("ether8"), &sff::decode(&a0, Some(&a2)), false);
        let lines = w.observe(&n("ether8"), &SfpModule::empty("gone"), false);
        assert_eq!(lines, ["ether8: module removed"]);
    }
}
