//! USB Ethernet adapters (G1.29b): what the router says about one beyond
//! what a PCI card shows. The rule that matters in production: a port
//! slower than the adapter caps the traffic without any error anywhere (a
//! gigabit RTL8153 on a USB 2.0 port moves ~300 Mbit/s; a USB 3 adapter on
//! a USB 2 port, or through a USB 2 hub or cable, negotiates 480 Mbit/s).
//! The kernel does not warn about it; RouterOS and pfSense do not either.
//!
//! A pure function of [`UsbInfo`] and the link's best rate, so the Hardware
//! tab, the interface list and the health check say the same thing.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};

use corerouter_hal::nic::{UsbInfo, UsbResetLevel, UsbResetReport, mode_speed};
use corerouter_hal::{LinkState, NicHardware};
use corerouter_model::IfName;
use serde::Serialize;
use serde_json::{Value, json};

use crate::Session;

/// What a USB 2.0 high-speed bus carries in Ethernet frames, in practice:
/// 480 Mbit/s of signalling, minus the bulk protocol and the driver's
/// framing. ~280–320 Mbit/s in public RTL8153 / AX88179 reports (iperf3,
/// one TCP stream; **estimated** here, not measured on this machine).
pub const USB2_REAL_MBPS: u32 = 300;

/// The judgment on one adapter.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct UsbAssessment {
    /// The port caps the adapter.
    pub slow_port: bool,
    /// Ethernet rate the bus lets through, about (`None`: not capped).
    pub cap_mbps: Option<u32>,
    /// One line for the operator, with the fix.
    pub alert: Option<String>,
}

/// `5000` → `USB 3.0 (5 Gbps)`.
pub fn usb_rate_name(mbps: u32) -> &'static str {
    match mbps {
        0..=1 => "USB 1.0 (1.5 Mbps)",
        2..=12 => "USB 1.1 (12 Mbps)",
        13..=480 => "USB 2.0 (480 Mbps)",
        481..=5000 => "USB 3.0 (5 Gbps)",
        5001..=10_000 => "USB 3.1 (10 Gbps)",
        _ => "USB 3.2 (20 Gbps)",
    }
}

/// `USB 3.0 (5 Gbps)` → `USB 3.0`.
fn short(mbps: u32) -> &'static str {
    let n = usb_rate_name(mbps);
    n.split(" (").next().unwrap_or(n)
}

/// `u` on its port; `link_max_mbps`: the best Ethernet rate the adapter
/// supports (its link modes), when known.
pub fn assess(u: &UsbInfo, link_max_mbps: Option<u32>) -> UsbAssessment {
    let Some(bus) = u.speed_mbps else {
        return UsbAssessment::default();
    };
    let below_adapter = u.adapter_max_mbps.is_some_and(|a| bus < a);
    // The Ethernet side outruns a high-speed bus (any gigabit adapter on
    // USB 2): the cap is real even when the adapter itself is USB 2.
    let ether_capped = bus <= 480 && link_max_mbps.is_some_and(|l| l > USB2_REAL_MBPS);
    if !below_adapter && !ether_capped {
        return UsbAssessment::default();
    }
    let cap = (bus <= 480).then_some(USB2_REAL_MBPS);
    let fix = match u.port_max_mbps {
        Some(p) if p > bus => "the port is faster: the cable or a hub in between is USB 2",
        _ => "use a USB 3 port (blue or marked SS) and a USB 3 cable",
    };
    let about = cap.map(|c| format!(": about {c} Mbit/s at most")).unwrap_or_default();
    let alert = match u.adapter_max_mbps.filter(|_| below_adapter) {
        Some(a) => format!("{} adapter negotiated {}{about}; {fix}", short(a), usb_rate_name(bus)),
        None => format!(
            "{} Mbit/s adapter on {}{about}; {fix}",
            link_max_mbps.unwrap_or(0),
            usb_rate_name(bus)
        ),
    };
    UsbAssessment {
        slow_port: true,
        cap_mbps: cap,
        alert: Some(alert),
    }
}

/// Most USB adapters looked at per `interface.list` (each is a few sysfs
/// reads and an ethtool query; a router has a handful at most).
pub const MAX_LISTED: usize = 16;

/// The adapter's best Ethernet rate, from the link modes it supports.
fn link_max(s: &mut Session, name: &IfName) -> Option<u32> {
    let m = s.hal_mut().ethernet_monitor(name).ok()?;
    m.supported.iter().filter_map(|m| mode_speed(m)).map(|(r, _)| r).max()
}

/// The `usb` object of `interface.hardware`: the device, the judgment and
/// the names the GUI shows; `null` for a port on another bus.
pub fn detail(s: &mut Session, name: &IfName, hw: &NicHardware) -> Value {
    let Some(u) = &hw.usb else {
        return Value::Null;
    };
    let a = assess(u, link_max(s, name));
    let hex = |id: Option<u16>| id.map_or(Value::Null, |v| json!(format!("{v:04x}")));
    json!({
        "port": u.port,
        "speed_mbps": u.speed_mbps,
        "speed": u.speed_mbps.map(usb_rate_name),
        "adapter_max_mbps": u.adapter_max_mbps,
        "adapter": u.adapter_max_mbps.map(usb_rate_name),
        "port_max_mbps": u.port_max_mbps,
        "version": u.version,
        "vendor_id": hex(u.vendor_id),
        "product_id": hex(u.product_id),
        "manufacturer": u.manufacturer,
        "product": u.product,
        "serial": u.serial,
        "revision": u.revision,
        "max_power_ma": u.max_power_ma,
        "autosuspend": u.autosuspend,
        "lpm": u.lpm,
        "over_current": u.over_current,
        "tx_timeouts": u.tx_timeouts,
        "port_power_switch": u.port_power_switch,
        "slow_port": a.slow_port,
        "cap_mbps": a.cap_mbps,
        "alert": a.alert,
        "recoveries": recoveries(s, name),
        "watchdog": s.usb_watchdog_row(name),
    })
}

/// The short `usb` object of an `interface.list` row (what the icon and its
/// tooltip need); `None` when the platform has nothing for it.
pub fn summary(s: &mut Session, name: &IfName) -> Option<Value> {
    let hw = s.hal_mut().hardware(name).ok()?;
    let u = hw.usb.as_ref()?;
    let a = assess(u, link_max(s, name));
    Some(json!({
        "port": u.port,
        "speed": u.speed_mbps.map(usb_rate_name),
        "driver": hw.driver,
        "slow_port": a.slow_port,
        "alert": a.alert,
    }))
}

/// Finished recoveries the task threads hand back, at most this many
/// waiting (more is a stuck tick: the oldest go).
const MAX_DONE: usize = 64;

/// One recovery a task finished: the port, how deep, and what it did.
pub(crate) type Done = (IfName, UsbResetLevel, std::result::Result<UsbResetReport, String>);

/// The queue the task threads push into (G1.29c: a callback between
/// threads only queues; the tick reads it under the session).
#[derive(Clone, Default)]
pub(crate) struct DoneQueue(Arc<Mutex<VecDeque<Done>>>);

impl DoneQueue {
    pub(crate) fn push(&self, d: Done) {
        let mut q = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        if q.len() >= MAX_DONE {
            q.pop_front();
        }
        q.push_back(d);
    }

    fn drain(&self) -> Vec<Done> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).drain(..).collect()
    }
}

/// Recoveries of one adapter since the start (operational, not saved).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PortRecovery {
    pub link: u32,
    pub driver: u32,
    pub port: u32,
    /// The last one: level, unix seconds (when the router has a clock),
    /// whether the interface came back, and the error if it failed.
    pub last_level: Option<UsbResetLevel>,
    pub last_at: Option<u64>,
    pub last_back: Option<bool>,
    pub last_error: Option<String>,
    /// A recovery that recreated the network device: its configuration
    /// goes back on when it is there again (the kernel dropped addresses,
    /// MTU, state with the old device).
    pub reapply: bool,
    /// A recovery is under way.
    pub running: Option<UsbResetLevel>,
}

/// G1.29c: manual recoveries of USB adapters (`Session::ext`).
#[derive(Default)]
pub struct UsbRecovery {
    pub ports: BTreeMap<IfName, PortRecovery>,
    pub(crate) done: DoneQueue,
}

impl Session {
    /// Every second with the links just read (`poll_links`): the results
    /// of finished recoveries, then the configuration of a recreated port
    /// put back once it is there again.
    pub(crate) fn usb_tick(&mut self, live: &[LinkState]) {
        // G1.29d: the watchdog first; what it starts finishes on a later tick.
        self.usb_watchdog_tick(live);
        let Some(r) = self.ext::<UsbRecovery>() else {
            return;
        };
        let done = r.done.drain();
        let now = self.now();
        for (name, level, result) in done {
            let (msg, detail) = {
                let Some(r) = self.ext_mut::<UsbRecovery>() else { return };
                let p = r.ports.entry(name.clone()).or_default();
                p.running = None;
                p.last_level = Some(level);
                p.last_at = now;
                match &result {
                    Ok(rep) => {
                        match level {
                            UsbResetLevel::Link => p.link = p.link.saturating_add(1),
                            UsbResetLevel::Driver => p.driver = p.driver.saturating_add(1),
                            UsbResetLevel::Port => p.port = p.port.saturating_add(1),
                        }
                        p.last_back = Some(rep.back);
                        p.last_error = None;
                        p.reapply |= level != UsbResetLevel::Link;
                    }
                    Err(e) => {
                        p.last_back = None;
                        p.last_error = Some(e.chars().take(200).collect());
                    }
                }
                let msg = match &result {
                    Ok(rep) if rep.back => format!("{name}: USB adapter recovered ({}{})", level.as_str(), if rep.power_cycled { ", port power cycled" } else { "" }),
                    Ok(_) => format!("{name}: USB adapter reset ({}) but it did not come back within 20 s", level.as_str()),
                    Err(e) => format!("{name}: USB adapter reset ({}) failed: {e}", level.as_str()),
                };
                (msg, serde_json::to_value(result.as_ref().ok()).unwrap_or(Value::Null))
            };
            self.log_event(&["interface", "warning"], "usb", msg, detail);
        }
        let due: Vec<IfName> = self
            .ext::<UsbRecovery>()
            .map(|r| {
                r.ports
                    .iter()
                    .filter(|(n, p)| p.reapply && live.iter().any(|l| &l.name == *n))
                    .map(|(n, _)| n.clone())
                    .collect()
            })
            .unwrap_or_default();
        if due.is_empty() {
            return;
        }
        let cfg = self.effective(self.store().running()).into_owned();
        let res = self.hal_mut().reconcile(&cfg);
        for name in due {
            if let Some(p) = self.ext_mut::<UsbRecovery>().and_then(|r| r.ports.get_mut(&name)) {
                p.reapply = false;
            }
            let msg = match &res {
                Ok(()) => format!("{name}: configuration put back on the recovered USB adapter"),
                Err(e) => format!("{name}: configuration could not be put back after the recovery: {e} (config.drift.reconcile)"),
            };
            self.log_event(&["interface", "info"], "usb", msg, Value::Null);
        }
    }
}

/// The recoveries of `name` for `interface.hardware`.
pub(crate) fn recoveries(s: &Session, name: &IfName) -> Value {
    s.ext::<UsbRecovery>()
        .and_then(|r| r.ports.get(name))
        .map_or_else(|| serde_json::to_value(PortRecovery::default()).unwrap_or(Value::Null), |p| {
            serde_json::to_value(p).unwrap_or(Value::Null)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rtl8153(bus: u32, port: u32) -> UsbInfo {
        UsbInfo {
            port: "4-2".into(),
            speed_mbps: Some(bus),
            adapter_max_mbps: Some(5000),
            port_max_mbps: Some(port),
            ..UsbInfo::default()
        }
    }

    #[test]
    fn usb3_adapter_on_usb3_port_is_fine() {
        assert_eq!(assess(&rtl8153(5000, 10_000), Some(1000)), UsbAssessment::default());
    }

    #[test]
    fn usb3_adapter_on_usb2_port() {
        let a = assess(&rtl8153(480, 480), Some(1000));
        assert!(a.slow_port);
        assert_eq!(a.cap_mbps, Some(300));
        let t = a.alert.unwrap();
        assert!(t.starts_with("USB 3.0 adapter negotiated USB 2.0 (480 Mbps): about 300"), "{t}");
        assert!(t.contains("use a USB 3 port"), "{t}");
        // A USB 3 port and still 480: the cable or a hub.
        let t = assess(&rtl8153(480, 5000), Some(1000)).alert.unwrap();
        assert!(t.contains("cable or a hub"), "{t}");
    }

    #[test]
    fn gigabit_usb2_adapter_is_capped_a_fast_ethernet_one_is_not() {
        let mut u = rtl8153(480, 480);
        u.adapter_max_mbps = Some(480);
        let a = assess(&u, Some(1000));
        assert!(a.slow_port);
        assert!(a.alert.unwrap().starts_with("1000 Mbit/s adapter on USB 2.0"));
        // RTL8152: 100 Mbit/s over USB 2 fits.
        assert!(!assess(&u, Some(100)).slow_port);
        // Nothing known: nothing said.
        assert!(!assess(&UsbInfo::default(), Some(1000)).slow_port);
    }
}
