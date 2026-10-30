//! The USB adapter watchdog (G1.29d): a stalled USB Ethernet adapter is
//! recovered without an operator, with the levels of G1.29c.
//!
//! A stall is the kernel's transmit watchdog firing on it (`tx_timeout`
//! grew: `NETDEV WATCHDOG`), or its link up and sending (at least
//! [`MIN_TX`] packets) with nothing received for `stall_secs`: the RTL8153
//! failure seen in the field leaves the carrier up and the queue dead.
//! The first action is a driver restart, the next (if it stalls again
//! before [`HEALTHY_SECS`] of calm) a port reset; between actions the
//! watchdog waits [`COOLDOWN_SECS`], doubling each time up to
//! [`MAX_COOLDOWN_SECS`]. After [`MAX_ACTIONS_PER_HOUR`] actions in an hour
//! it gives up and says so (log, health): something a reset does not fix
//! (cable, power, the chip) needs a person. RouterOS has no such watchdog
//! (operators script Netwatch + `usb power-reset`).
//!
//! One tick a second (`Session::usb_tick`), one cheap read per adapter
//! (`Hal::usb_tx_timeouts`) and the link counters the tick already has.

use std::collections::{BTreeMap, VecDeque};

use corerouter_hal::LinkState;
use corerouter_hal::nic::UsbResetLevel;
use corerouter_model::IfName;
use serde::Serialize;
use serde_json::{Value, json};

use crate::auth::Principal;
use crate::usb_nic::UsbRecovery;
use crate::{Caller, Session};

/// Packets sent without one received that make a quiet link a stalled one.
pub const MIN_TX: u64 = 5;
pub const COOLDOWN_SECS: u64 = 30;
pub const MAX_COOLDOWN_SECS: u64 = 900;
/// Calm after an action that brings the next one back to a driver restart.
pub const HEALTHY_SECS: u64 = 600;
pub const MAX_ACTIONS_PER_HOUR: usize = 6;
const HOUR: u64 = 3600;

/// What the watchdog is doing with one adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WatchState {
    Ok,
    /// Recovered; the next stall waits for the cooldown.
    Cooldown,
    /// Too many actions in an hour: it stopped acting.
    GaveUp,
    Disabled,
}

/// One adapter followed by the watchdog.
#[derive(Debug, Clone, Default)]
pub struct Watched {
    /// Ticks seen (about seconds).
    clock: u64,
    last_tx_timeouts: Option<u64>,
    /// (tick, rx packets, tx packets) over the stall window.
    window: VecDeque<(u64, u64, u64)>,
    /// The next action escalates to a port reset.
    escalate: bool,
    cooldown_until: u64,
    cooldown: u64,
    /// Ticks of the actions in the last hour.
    actions: VecDeque<u64>,
    gave_up: bool,
    last_stall: Option<u64>,
    pub stalls: u32,
    /// (level, tick, why) of the last action.
    last: Option<(UsbResetLevel, u64, String)>,
}

/// G1.29d: the watchdog's state per adapter (`Session::ext`).
#[derive(Default)]
pub struct UsbWatchdogState {
    pub ports: BTreeMap<IfName, Watched>,
}

impl Watched {
    fn state(&self) -> WatchState {
        if self.gave_up {
            WatchState::GaveUp
        } else if self.clock < self.cooldown_until {
            WatchState::Cooldown
        } else {
            WatchState::Ok
        }
    }

    fn actions_last_hour(&self) -> usize {
        self.actions
            .iter()
            .filter(|t| self.clock.saturating_sub(**t) < HOUR)
            .count()
    }

    /// One reading; `Some(why)` when the adapter stalled.
    fn observe(&mut self, link: &LinkState, tx_timeouts: Option<u64>, stall_secs: u64) -> Option<String> {
        self.clock = self.clock.saturating_add(1);
        let now = self.clock;
        let mut why = None;
        if let (Some(t), Some(prev)) = (tx_timeouts, self.last_tx_timeouts)
            && t > prev
        {
            why = Some(format!("the kernel's transmit watchdog fired {} time(s)", t - prev));
        }
        if tx_timeouts.is_some() {
            self.last_tx_timeouts = tx_timeouts;
        }
        if link.running {
            self.window.push_back((now, link.rx_packets, link.tx_packets));
            while self.window.front().is_some_and(|(t, _, _)| now.saturating_sub(*t) > stall_secs) {
                self.window.pop_front();
            }
            if let (Some(first), Some(last)) = (self.window.front(), self.window.back())
                && now.saturating_sub(first.0) >= stall_secs
                && last.1 == first.1
                && last.2.saturating_sub(first.2) >= MIN_TX
                && why.is_none()
            {
                why = Some(format!(
                    "link up, {} packets sent and none received in {stall_secs} s",
                    last.2.saturating_sub(first.2)
                ));
            }
        } else {
            self.window.clear();
        }
        // Calm long enough: the next action starts over at the driver.
        if self.last.as_ref().is_some_and(|(_, t, _)| now.saturating_sub(*t) >= HEALTHY_SECS)
            && self.last_stall.is_none_or(|t| now.saturating_sub(t) >= HEALTHY_SECS)
        {
            self.escalate = false;
            self.cooldown = 0;
            if self.gave_up && self.actions_last_hour() == 0 {
                self.gave_up = false;
            }
        }
        if why.is_some() {
            self.last_stall = Some(now);
            self.stalls = self.stalls.saturating_add(1);
        }
        why
    }

    /// The level to act at now, if any (and books the action).
    fn act(&mut self) -> Option<UsbResetLevel> {
        let now = self.clock;
        if self.gave_up || now < self.cooldown_until {
            return None;
        }
        while self.actions.front().is_some_and(|t| now.saturating_sub(*t) >= HOUR) {
            self.actions.pop_front();
        }
        if self.actions.len() >= MAX_ACTIONS_PER_HOUR {
            self.gave_up = true;
            return None;
        }
        let level = if self.escalate { UsbResetLevel::Port } else { UsbResetLevel::Driver };
        self.escalate = true;
        self.cooldown = if self.cooldown == 0 { COOLDOWN_SECS } else { (self.cooldown * 2).min(MAX_COOLDOWN_SECS) };
        self.cooldown_until = now.saturating_add(self.cooldown);
        self.actions.push_back(now);
        // The recovery's own quiet seconds are not a new stall.
        self.window.clear();
        Some(level)
    }
}

impl Session {
    /// Every second from `usb_tick`: follow each USB adapter of `live` and
    /// recover the stalled ones.
    pub(crate) fn usb_watchdog_tick(&mut self, live: &[LinkState]) {
        let usb: Vec<&LinkState> = live
            .iter()
            .filter(|l| l.bus.as_deref() == Some("usb"))
            .take(crate::usb_nic::MAX_LISTED)
            .collect();
        if usb.is_empty() && self.ext::<UsbWatchdogState>().is_none_or(|w| w.ports.is_empty()) {
            return;
        }
        let settings = self.store().running().system.usb_watchdog.clone();
        let mut todo: Vec<(IfName, UsbResetLevel, String)> = Vec::new();
        let mut gave_up: Vec<IfName> = Vec::new();
        for l in usb {
            let cfg = settings.port(&l.name);
            let busy = self
                .ext::<UsbRecovery>()
                .and_then(|r| r.ports.get(&l.name))
                .is_some_and(|p| p.running.is_some());
            let tx = self.hal_mut().usb_tx_timeouts(&l.name);
            let Some(state) = self.ext_mut::<UsbWatchdogState>() else { return };
            let w = state.ports.entry(l.name.clone()).or_default();
            let why = w.observe(l, tx, u64::from(cfg.stall_secs));
            if !cfg.enabled || busy {
                continue;
            }
            if let Some(why) = why {
                let was = w.gave_up;
                match w.act() {
                    Some(level) => {
                        w.last = Some((level, w.clock, why.clone()));
                        todo.push((l.name.clone(), level, why));
                    }
                    None if w.gave_up && !was => gave_up.push(l.name.clone()),
                    None => {}
                }
            }
        }
        if let Some(state) = self.ext_mut::<UsbWatchdogState>() {
            state.ports.retain(|n, _| live.iter().any(|l| &l.name == n));
        }
        let caller = Caller::new(Caller::LOCAL_ID, "router: USB watchdog").with_principal(Principal::Local);
        for (name, level, why) in todo {
            let what = match level {
                UsbResetLevel::Port => "resetting its USB port",
                _ => "restarting its driver",
            };
            self.log_event(
                &["interface", "warning"],
                "usb",
                format!("{name}: USB adapter stalled ({why}): {what}"),
                json!({"level": level.as_str(), "why": why}),
            );
            // The connection guard does not hold the watchdog back: a
            // stalled port carries no connection anyway.
            if let Err(e) = self.execute_as(
                &caller,
                "interface.usb.reset",
                &json!({"name": name, "level": level.as_str(), "force": true}),
            ) {
                self.log_event(&["interface", "error"], "usb", format!("{name}: watchdog could not reset it: {e}"), Value::Null);
            }
        }
        for name in gave_up {
            self.log_event(
                &["interface", "error"],
                "usb",
                format!(
                    "{name}: USB adapter still stalling after {MAX_ACTIONS_PER_HOUR} recoveries in an hour: the watchdog stopped acting; check the cable, the port's power and the adapter"
                ),
                Value::Null,
            );
        }
    }

    /// The watchdog's view of `name` for `interface.hardware` and
    /// `interface.usb.watchdog.print`.
    pub(crate) fn usb_watchdog_row(&self, name: &IfName) -> Value {
        let cfg = self.store().running().system.usb_watchdog.port(name);
        let w = self.ext::<UsbWatchdogState>().and_then(|s| s.ports.get(name));
        let state = if !cfg.enabled {
            WatchState::Disabled
        } else {
            w.map_or(WatchState::Ok, Watched::state)
        };
        json!({
            "name": name,
            "enabled": cfg.enabled,
            "stall_secs": cfg.stall_secs,
            "state": state,
            "stalls": w.map_or(0, |w| w.stalls),
            "actions_last_hour": w.map_or(0, Watched::actions_last_hour),
            "next_level": w.map_or("driver", |w| if w.escalate { "port" } else { "driver" }),
            "last_action": w.and_then(|w| w.last.as_ref()).map(|(l, t, why)| json!({
                "level": l.as_str(),
                "secs_ago": w.map_or(0, |w| w.clock.saturating_sub(*t)),
                "why": why,
            })),
        })
    }

    /// For the health check: (adapter, actions in the last hour, gave up,
    /// the last reason).
    pub(crate) fn usb_watchdog_health(&self) -> Vec<(String, usize, bool, Option<String>)> {
        self.ext::<UsbWatchdogState>()
            .map(|s| {
                s.ports
                    .iter()
                    .map(|(n, w)| (n.to_string(), w.actions_last_hour(), w.gave_up, w.last.as_ref().map(|l| l.2.clone())))
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(rx: u64, tx: u64, running: bool) -> LinkState {
        LinkState {
            name: "ether4".parse().unwrap(),
            running,
            rx_bytes: 0,
            tx_bytes: 0,
            rx_packets: rx,
            tx_packets: tx,
            kind: "ether".into(),
            mtu: 1500,
            mac: None,
            unmanaged: None,
            errors: None,
            bus: Some("usb".into()),
        }
    }

    #[test]
    fn a_tx_timeout_is_a_stall_a_quiet_link_is_not() {
        let mut w = Watched::default();
        assert_eq!(w.observe(&link(0, 0, true), Some(0), 30), None);
        for _ in 0..60 {
            assert_eq!(w.observe(&link(0, 0, true), Some(0), 30), None, "quiet, not stalled");
        }
        let why = w.observe(&link(0, 0, true), Some(2), 30).unwrap();
        assert!(why.contains("transmit watchdog fired 2"), "{why}");
    }

    #[test]
    fn sending_without_receiving_for_the_window_is_a_stall() {
        let mut w = Watched::default();
        let mut tx = 0;
        let mut out = None;
        for _ in 0..40 {
            tx += 1;
            out = out.or(w.observe(&link(100, tx, true), None, 30));
        }
        assert!(out.unwrap().contains("none received in 30 s"));
        // Receiving: fine.
        let mut w = Watched::default();
        for i in 0..40 {
            assert_eq!(w.observe(&link(i, i, true), None, 30), None);
        }
    }

    #[test]
    fn driver_then_port_then_cooldown_then_gives_up() {
        let mut w = Watched::default();
        w.observe(&link(0, 0, true), Some(0), 30);
        assert_eq!(w.act(), Some(UsbResetLevel::Driver));
        assert_eq!(w.act(), None, "cooldown");
        for _ in 0..COOLDOWN_SECS {
            w.observe(&link(0, 0, false), Some(0), 30);
        }
        assert_eq!(w.act(), Some(UsbResetLevel::Port), "stalled again soon: escalate");
        let mut levels = 2;
        for _ in 0..(2 * HOUR) {
            w.observe(&link(0, 0, false), Some(0), 30);
            // Stalling all the time: act whenever allowed.
            if w.act().is_some() {
                levels += 1;
            }
            if w.gave_up {
                break;
            }
        }
        assert!(w.gave_up, "gave up after {levels} actions");
        assert_eq!(w.actions_last_hour(), MAX_ACTIONS_PER_HOUR);
    }

    #[test]
    fn calm_brings_the_next_action_back_to_the_driver() {
        let mut w = Watched::default();
        w.observe(&link(0, 0, true), Some(0), 30);
        w.act();
        w.last = Some((UsbResetLevel::Driver, w.clock, "x".into()));
        for _ in 0..HEALTHY_SECS {
            w.observe(&link(0, 0, false), Some(0), 30);
        }
        assert_eq!(w.act(), Some(UsbResetLevel::Driver));
    }
}
