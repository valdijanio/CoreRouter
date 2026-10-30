//! Manual recovery of a USB Ethernet adapter (G1.29c), in three levels,
//! lightest first: the interface down and up; the driver let go and probe
//! it again (unbind/bind); the whole USB device again (the port's power
//! cut when its hub switches power per port, else de-authorized and
//! authorized). RouterOS has `/system routerboard usb power-reset` for the
//! whole bus; here it is per adapter and named for what it touches.
//!
//! A recovery is a task (like the cable test): the adapter goes away for
//! seconds and the session is not held meanwhile. When it is done, the
//! tick logs it, counts it and, for the levels that recreate the network
//! device, puts the configuration back on it once PID 1 has given it its
//! name again (G1.6n).

use corerouter_hal::HalError;
use corerouter_hal::nic::UsbResetLevel;
use corerouter_model::{IfName, InterfaceKind};
use serde_json::{Value, json};

use super::args::{opt_bool, req_parse, req_str};
use super::ethernet::guard_link;
use super::interface::refuse_unmanaged;
use super::CommandSpec;
use crate::tasks::can_run;
use crate::usb_nic::UsbRecovery;
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "interface.usb.reset", "USB Reset", [], None,
        "{name: string, level: link | driver | port (link: down and up, ~1 s; driver: unbind and bind, ~3 s, the device is recreated; port: power off and on, or de-authorize and authorize, ~5 s), force?: bool (reset the port this connection uses outside Safe Mode)} → {id, task_id, name, level}",
        can_run, reset)
    .positional("name"),
];

/// What each level costs the traffic, for the guard's refusal.
fn what(level: UsbResetLevel) -> &'static str {
    match level {
        UsbResetLevel::Link => "its link goes down for about a second",
        UsbResetLevel::Driver => "its driver lets go of it: no link for about three seconds",
        UsbResetLevel::Port => "its USB port goes off and on: no link for about five seconds",
    }
}

fn reset(s: &mut Session, p: &Value) -> Result<Value> {
    let name: IfName = req_parse(p, "name")?;
    refuse_unmanaged(s, p, &["name"])?;
    let raw = req_str(p, "level")?;
    let level = UsbResetLevel::parse(raw).ok_or_else(|| {
        EngineError::bad(
            "level",
            format!(
                "'{}' is not a level: link, driver or port",
                raw.chars().take(32).collect::<String>()
            ),
        )
    })?;
    let force = opt_bool(p, "force")?.unwrap_or(false);
    let iface = s.store().candidate().interfaces.get(&name).ok_or_else(|| {
        EngineError::bad("name", format!("no interface '{name}' (see interface.list)"))
    })?;
    if iface.kind != InterfaceKind::Ethernet {
        return Err(EngineError::bad(
            "name",
            format!("'{name}' is a {}, not a USB Ethernet adapter", iface.kind.label()),
        ));
    }
    if let Some(running) = s
        .ext::<UsbRecovery>()
        .and_then(|r| r.ports.get(&name))
        .and_then(|p| p.running)
    {
        return Err(EngineError::bad(
            "name",
            format!("'{name}' is being reset already ({})", running.as_str()),
        ));
    }
    guard_link(s, &name, force, what(level))?;
    let mut job = s.hal_mut().usb_reset(&name, level).map_err(|e| match e {
        HalError::Unsupported(why) | HalError::Rejected(why) => EngineError::bad("name", why),
        other => EngineError::Hal(other.to_string()),
    })?;
    let done = s.ext_mut::<UsbRecovery>().map(|r| r.done.clone()).unwrap_or_default();
    let label = name.clone();
    let id = s.start_task(
        "usb-reset",
        format!("USB reset {name} ({})", level.as_str()),
        move |ctx| {
            let r = job.run(&|d| ctx.sleep(d));
            let result = r.clone().map_err(|e| e.to_string());
            done.push((label.clone(), level, result));
            match r {
                Ok(rep) => {
                    for step in &rep.steps {
                        ctx.emit(json!({"step": step}));
                    }
                    ctx.summary(json!({
                        "name": label,
                        "level": level.as_str(),
                        "back": rep.back,
                        "power_cycled": rep.power_cycled,
                    }));
                    Ok(())
                }
                Err(_) if ctx.stopped() => Ok(()),
                Err(e) => Err(e.to_string()),
            }
        },
    )?;
    if let Some(p) = s.ext_mut::<UsbRecovery>().map(|r| r.ports.entry(name.clone()).or_default()) {
        p.running = Some(level);
    }
    Ok(json!({"id": id, "task_id": id, "name": name, "level": level.as_str()}))
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use crate::Session;
    use crate::tasks::{MAX_POLL, test_runner};

    fn lab() -> Session {
        let mut s = Session::virtual_lab();
        s.set_runner(test_runner::sim());
        s
    }

    /// Run a recovery to its end (simulated time), then the tick that
    /// takes its result.
    fn recover(s: &mut Session, name: &str, level: &str) -> Value {
        let v = s
            .execute("interface.usb.reset", &json!({"name": name, "level": level}))
            .unwrap();
        let id = v["task_id"].as_u64().unwrap();
        for _ in 0..400 {
            if s.task_poll(id, 0, MAX_POLL).unwrap()["state"] != "running" {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        s.tick(1_000);
        v
    }

    #[test]
    fn each_level_recovers_a_lab_usb_adapter_and_is_counted() {
        let mut s = lab();
        for level in ["link", "driver", "port"] {
            assert_eq!(recover(&mut s, "ether6", level)["level"], level);
        }
        let hw = s.execute("interface.hardware", &json!({"name": "ether6"})).unwrap();
        let r = &hw["usb"]["recoveries"];
        assert_eq!(
            (r["link"].as_u64(), r["driver"].as_u64(), r["port"].as_u64()),
            (Some(1), Some(1), Some(1))
        );
        assert_eq!(r["last_level"], "port");
        assert_eq!(r["last_back"], true);
        assert_eq!(r["running"], Value::Null);
        assert_eq!(r["reapply"], false, "the configuration went back on");
        let text = s.execute("log.print", &json!({"find": "ether6"})).unwrap().to_string();
        assert!(text.contains("USB adapter recovered (port, port power cycled)"), "{text}");
        assert!(text.contains("configuration put back on the recovered USB adapter"), "{text}");
    }

    #[test]
    fn validation_refuses_before_touching_anything() {
        let mut s = lab();
        let err = |s: &mut Session, p: Value| s.execute("interface.usb.reset", &p).unwrap_err().to_string();
        let e = err(&mut s, json!({"name": "ether6", "level": "nuke"}));
        assert!(e.contains("not a level: link, driver or port"), "{e}");
        let e = err(&mut s, json!({"name": "ether1", "level": "driver"}));
        assert!(e.contains("not a USB adapter"), "{e}");
        let e = err(&mut s, json!({"name": "ether9", "level": "link"}));
        assert!(e.contains("no interface 'ether9'"), "{e}");
        let e = err(&mut s, json!({"name": "ether6"}));
        assert!(e.contains("level"), "{e}");
        let hw = s.execute("interface.hardware", &json!({"name": "ether6"})).unwrap();
        assert_eq!(hw["usb"]["recoveries"]["driver"], 0, "nothing counted");
        assert_eq!(hw["usb"]["recoveries"]["running"], Value::Null);
    }

    /// Nothing to roll back: a recovery changes no configuration, and one
    /// that fails leaves the counters alone and says why.
    #[test]
    fn a_failed_recovery_changes_nothing_and_is_logged() {
        let mut s = lab();
        let before = s.store().running().clone();
        let done = s
            .ext_mut::<crate::usb_nic::UsbRecovery>()
            .map(|r| r.done.clone())
            .unwrap();
        done.push((
            "ether5".parse().unwrap(),
            corerouter_hal::nic::UsbResetLevel::Driver,
            Err("/sys/bus/usb/drivers/r8152/unbind: Permission denied".into()),
        ));
        s.tick(1_000);
        assert_eq!(s.store().running(), &before);
        let hw = s.execute("interface.hardware", &json!({"name": "ether5"})).unwrap();
        let r = &hw["usb"]["recoveries"];
        assert_eq!(r["driver"], 0);
        assert!(r["last_error"].as_str().unwrap().contains("Permission denied"));
        let text = s.execute("log.print", &json!({"find": "ether5"})).unwrap().to_string();
        assert!(text.contains("USB adapter reset (driver) failed"), "{text}");
    }

    #[test]
    fn one_recovery_at_a_time_per_adapter() {
        let mut s = Session::virtual_lab();
        // A runner that never runs the job: the first stays "running".
        s.set_runner(std::sync::Arc::new(Never));
        s.execute("interface.usb.reset", &json!({"name": "ether5", "level": "driver"}))
            .unwrap();
        let e = s
            .execute("interface.usb.reset", &json!({"name": "ether5", "level": "port"}))
            .unwrap_err()
            .to_string();
        assert!(e.contains("being reset already (driver)"), "{e}");
    }

    struct Never;
    impl crate::tasks::Runner for Never {
        fn spawn(&self, _name: &str, _job: crate::tasks::Job) -> std::result::Result<(), String> {
            Ok(())
        }
    }
}
