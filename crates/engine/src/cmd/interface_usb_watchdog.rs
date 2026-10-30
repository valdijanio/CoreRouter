//! `/interface usb watchdog` (G1.29d): the per-adapter switch and stall
//! window of the USB adapter watchdog (`usb_watchdog.rs`), and what it is
//! doing. On by default for every USB Ethernet adapter.

use corerouter_model::usb_watchdog::{MAX_ENTRIES, MAX_STALL_SECS, MIN_STALL_SECS, UsbWatchdogPort};
use corerouter_model::{IfName, InterfaceKind};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_u32, req_parse};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "interface.usb.watchdog.set",
        "USB Watchdog",
        [],
        None,
        "{name: string, enabled?: bool (default true: a stalled adapter is recovered by itself), stall_secs?: u32 (10..3600, default 30: link up, sending and receiving nothing this long is a stall)} → {name, enabled, stall_secs}",
        always,
        set
    ),
    cmd!(query "interface.usb.watchdog.print", "USB Watchdog", [], None,
        "{} → [{name, enabled, stall_secs, state (ok | cooldown | gave-up | disabled), stalls, actions_last_hour, next_level (driver | port), last_action: null | {level, secs_ago, why}}]",
        always, print),
];

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let name: IfName = req_parse(p, "name")?;
    let enabled = opt_bool(p, "enabled")?;
    let stall = opt_u32(p, "stall_secs")?;
    if let Some(v) = stall
        && !(MIN_STALL_SECS..=MAX_STALL_SECS).contains(&v)
    {
        return Err(EngineError::bad(
            "stall_secs",
            format!("{v} is out of range: {MIN_STALL_SECS}..={MAX_STALL_SECS} seconds"),
        ));
    }
    let cfg = s.store().candidate();
    match cfg.interfaces.get(&name) {
        Some(i) if i.kind == InterfaceKind::Ethernet => {}
        Some(i) => {
            return Err(EngineError::bad(
                "name",
                format!("'{name}' is a {}, not an Ethernet port", i.kind.label()),
            ));
        }
        None => {
            return Err(EngineError::bad("name", format!("no interface '{name}' (see interface.list)")));
        }
    }
    let wd = &cfg.system.usb_watchdog;
    if !wd.ports.contains_key(&name) && wd.ports.len() >= MAX_ENTRIES {
        return Err(EngineError::bad("name", format!("at most {MAX_ENTRIES} adapters with their own settings")));
    }
    let mut port = wd.port(&name);
    if let Some(e) = enabled {
        port.enabled = e;
    }
    if let Some(v) = stall {
        port.stall_secs = v;
    }
    let out = json!({"name": name, "enabled": port.enabled, "stall_secs": port.stall_secs});
    let ports = &mut s.store_mut().candidate_mut().system.usb_watchdog.ports;
    if port == UsbWatchdogPort::default() {
        ports.remove(&name);
    } else {
        ports.insert(name, port);
    }
    Ok(out)
}

fn print(s: &mut Session, _: &Value) -> Result<Value> {
    let live = s.hal_mut().poll();
    let rows: Vec<Value> = live
        .iter()
        .filter(|l| l.bus.as_deref() == Some("usb"))
        .take(crate::usb_nic::MAX_LISTED)
        .map(|l| s.usb_watchdog_row(&l.name))
        .collect();
    Ok(Value::Array(rows))
}

#[cfg(test)]
mod tests {
    use corerouter_hal::virt::VirtualHal;
    use serde_json::{Value, json};

    use crate::Session;

    /// The lab with ether6 stalling from poll `from` on.
    fn stalling(from: u64) -> Session {
        let hal = VirtualHal::new(8).with_usb_stall("ether6".parse().unwrap(), from..u64::MAX);
        let mut s = Session::new(Box::new(hal));
        s.set_runner(crate::tasks::test_runner::sim());
        s
    }

    fn row(s: &mut Session, name: &str) -> Value {
        let rows = s.execute("interface.usb.watchdog.print", &json!({})).unwrap();
        rows.as_array().unwrap().iter().find(|r| r["name"] == name).cloned().unwrap()
    }

    /// Ticks, letting the recoveries' task threads finish between them.
    fn run(s: &mut Session, ticks: u64) {
        for t in 0..ticks {
            s.tick(1_000 + t);
            // A recovery's thread (simulated clock) ends in microseconds.
            if t % 30 == 0 {
                std::thread::sleep(std::time::Duration::from_millis(1));
            } else {
                std::thread::yield_now();
            }
        }
    }

    #[test]
    fn a_stalled_adapter_is_recovered_driver_first_then_port() {
        let mut s = stalling(3);
        run(&mut s, 2);
        assert_eq!(row(&mut s, "ether6")["state"], "ok");
        run(&mut s, 3);
        let r = row(&mut s, "ether6");
        assert_eq!(r["state"], "cooldown", "{r}");
        assert_eq!(r["last_action"]["level"], "driver");
        assert!(r["last_action"]["why"].as_str().unwrap().contains("transmit watchdog"));
        run(&mut s, 40);
        let r = row(&mut s, "ether6");
        assert_eq!(r["last_action"]["level"], "port", "still stalling: escalated ({r})");
        let log = s.execute("log.print", &json!({"find": "ether6"})).unwrap().to_string();
        assert!(log.contains("USB adapter stalled"), "{log}");
        assert!(log.contains("restarting its driver") && log.contains("resetting its USB port"), "{log}");
        let health = s.execute("system.health.check", &json!({})).unwrap();
        let c = health["checks"].as_array().unwrap().iter().find(|c| c["key"] == "interface.usb.watchdog").unwrap().clone();
        assert_eq!(c["severity"], "warning", "{c}");
        // The other lab adapter is fine.
        assert_eq!(row(&mut s, "ether5")["state"], "ok");
    }

    #[test]
    fn it_gives_up_after_too_many_actions_and_says_so() {
        let mut s = stalling(1);
        // Cooldowns 30, 60, 120, 240, 480 s: the 7th stall in the hour
        // comes at ~1830 s.
        run(&mut s, 1_900);
        let r = row(&mut s, "ether6");
        assert_eq!(r["state"], "gave-up", "{r}");
        let health = s.execute("system.health.check", &json!({})).unwrap();
        let c = health["checks"].as_array().unwrap().iter().find(|c| c["key"] == "interface.usb.watchdog").unwrap().clone();
        assert_eq!(c["severity"], "error", "{c}");
        let log = s.execute("log.print", &json!({"find": "stopped acting"})).unwrap();
        assert_eq!(log.as_array().unwrap().len(), 1, "said once");
    }

    #[test]
    fn disabled_per_adapter_it_only_watches() {
        let mut s = stalling(1);
        s.execute("interface.usb.watchdog.set", &json!({"name": "ether6", "enabled": false})).unwrap();
        run(&mut s, 60);
        let r = row(&mut s, "ether6");
        assert_eq!(r["state"], "disabled");
        assert_eq!(r["last_action"], Value::Null);
        assert!(r["stalls"].as_u64().unwrap() > 0, "still counted");
        // Back to the default: no entry left in the config.
        s.execute("interface.usb.watchdog.set", &json!({"name": "ether6", "enabled": true})).unwrap();
        assert!(s.store().running().system.usb_watchdog.is_default());
    }

    #[test]
    fn set_validates_before_changing_anything() {
        let mut s = Session::virtual_lab();
        let before = s.store().current_revision();
        let e = s
            .execute("interface.usb.watchdog.set", &json!({"name": "ether6", "stall_secs": 5}))
            .unwrap_err()
            .to_string();
        assert!(e.contains("out of range: 10..=3600"), "{e}");
        let e = s
            .execute("interface.usb.watchdog.set", &json!({"name": "ether99", "enabled": false}))
            .unwrap_err()
            .to_string();
        assert!(e.contains("no interface"), "{e}");
        assert_eq!(s.store().current_revision(), before);
        // Rollback: the setting goes back with the revision.
        s.execute("interface.usb.watchdog.set", &json!({"name": "ether6", "stall_secs": 60})).unwrap();
        assert_eq!(s.store().running().system.usb_watchdog.port(&"ether6".parse().unwrap()).stall_secs, 60);
        s.execute("config.rollback", &json!({"revision": before})).unwrap();
        assert!(s.store().running().system.usb_watchdog.is_default());
    }
}
