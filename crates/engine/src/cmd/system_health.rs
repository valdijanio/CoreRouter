//! `/system health` (G4.8a, RouterOS `/system health`): every sensor the
//! machine has — temperatures with the driver's `max` and `crit`, fans,
//! voltages, power — and how each reads against its limits; and the health
//! checks (`crate::health_check`), Juniper `show system alarms` style.

use serde_json::{Value, json};

use super::system_resource::{monitor, r1, watched};
use super::{CommandSpec, always};
use crate::{Result, Session};
use crate::health_check::{Severity, evaluate, overall};
use crate::system_resource::sensor_level;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "system.health.print", "Health", [], None,
        "{} → [{name, chip, label, type: temperature|fan|voltage|power, value, unit, max, crit, state: ok|warning|error, board: bool (read by the motherboard's sensor chip: an input the board does not wire reads anything, so it has no limits and is not the router's temperature)}]",
        always, print),
    cmd!(query "system.health.check", "Health Checks", [], None,
        "{} → {status: ok|warning|error, warnings, errors, checks: [{key, name, severity: ok|warning|error|unknown, value, reason, action}]}",
        always, check),
];

/// `k10temp Tctl` → `k10temp-tctl`, like RouterOS's `cpu-temperature`.
fn name(chip: &str, label: &str) -> String {
    format!("{chip}-{label}")
        .chars()
        .map(|c| if c.is_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
        .collect::<String>()
        .split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

fn print(s: &mut Session, _: &Value) -> Result<Value> {
    let m = monitor(s, false)?;
    let Some(l) = &m.last else {
        return Ok(json!([]));
    };
    Ok(Value::Array(
        l.sensors
            .iter()
            .map(|x| {
                json!({
                    "name": name(&x.chip, &x.label),
                    "chip": x.chip,
                    "label": x.label,
                    "type": x.kind,
                    "value": if x.kind == corerouter_hal::system_resource::SensorKind::Fan { x.value.round() } else { r1(x.value) },
                    "unit": x.kind.unit(),
                    "max": x.max.map(r1),
                    "crit": x.crit.map(r1),
                    "state": sensor_level(x).as_str(),
                    "board": x.board,
                })
            })
            .collect(),
    ))
}

/// The checks now. Does not mark the readings as watched (the top bar's
/// chip asks every 5 s) and never logs: the alerts are the service's.
fn check(s: &mut Session, _: &Value) -> Result<Value> {
    // No readings (a backend without a sampler) still answers: the checks
    // that need them say `unknown`.
    let _ = watched(s, false, false);
    let checks = evaluate(&s.health_inputs());
    let count = |sev| checks.iter().filter(|c| c.severity == sev).count();
    Ok(json!({
        "status": overall(&checks).as_str(),
        "warnings": count(Severity::Warning),
        "errors": count(Severity::Error),
        "checks": checks,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensors_with_limits_and_names() {
        let mut s = Session::virtual_lab();
        let v = s.execute("system.health.print", &json!({})).unwrap();
        let rows = v.as_array().unwrap();
        assert!(rows.len() >= 4);
        let pkg = rows.iter().find(|r| r["name"] == "coretemp-package").unwrap();
        assert_eq!(pkg["crit"], 100.0);
        assert_eq!(pkg["unit"], "°C");
        assert_eq!(pkg["state"], "ok");
        assert!(rows.iter().any(|r| r["type"] == "fan" && r["unit"] == "rpm"));
        assert_eq!(name("nvme", "Sensor 1"), "nvme-sensor-1");
        assert!(s.execute("system.health.print", &json!({"x": 1})).is_err());
    }

    #[test]
    fn checks_on_the_lab() {
        let mut s = Session::virtual_lab();
        let v = s.execute("system.health.check", &json!({})).unwrap();
        let checks = v["checks"].as_array().unwrap();
        assert_eq!(checks.len(), 22);
        let by = |k: &str| checks.iter().find(|c| c["key"] == k).unwrap().clone();
        assert_eq!(by("root.verity")["severity"], "unknown", "no A/B image in the lab");
        assert_eq!(by("routes.ecmp")["severity"], "ok", "the lab has no ECMP (G1.27j)");
        assert_eq!(by("auth.no_password")["severity"], "ok", "the lab has no admin yet");
        assert_eq!(by("nic.errors")["severity"], "warning", "ether4's bad cable");
        assert!(by("nic.errors")["reason"].as_str().unwrap().contains("ether4"));
        assert_eq!(by("ntp")["severity"], "ok", "NTP is off in the lab session; a router's first boot turns it on (G1.6zh)");
        assert_eq!(by("services")["severity"], "unknown", "no supervisor in the lab");
        assert_eq!(by("bgp.end-of-rib")["severity"], "unknown", "no routing daemon in the lab (G3.9fj)");
        assert_eq!(by("bgp.gr-bfd")["severity"], "unknown");
        assert_eq!(by("temperature")["severity"], "ok");
        // G1.29b: ether6 is a USB 3 adapter on a USB 2.0 port.
        assert_eq!(by("interface.usb")["severity"], "warning");
        assert!(by("interface.usb")["reason"].as_str().unwrap().contains("ether6: USB 3.0 adapter negotiated USB 2.0"));
        assert_eq!(v["status"], "warning");
        assert_eq!(v["errors"], 0);
        assert!(by("nic.errors")["action"].is_string());
        assert!(by("temperature")["action"].is_null(), "no action when ok");
        assert!(s.execute("system.health.check", &json!({"all": true})).is_err());
    }

    /// G1.6qb: the running slot booted without dm-verity (first boot of a
    /// qcow2/OVA by the fallback path) is a warning that says to reboot once.
    #[test]
    fn root_without_verity_says_reboot_once() {
        let mut s = Session::virtual_lab();
        let status = |verity: bool| {
            json!({"supported": true, "lab": false, "running": "a", "slots": [
                {"slot": "a", "running": true, "verity": verity},
                {"slot": "b", "running": false, "verity": false}]})
        };
        let check = |s: &mut Session| {
            let v = s.execute("system.health.check", &json!({})).unwrap();
            v["checks"].as_array().unwrap().iter().find(|c| c["key"] == "root.verity").unwrap().clone()
        };
        crate::package::feed_status(&mut s, status(false));
        let c = check(&mut s);
        assert_eq!(c["severity"], "warning");
        assert_eq!(c["value"], "slot a");
        assert!(c["reason"].as_str().unwrap().contains("dm-verity"), "{c}");
        assert!(c["action"].as_str().unwrap().contains("Reinicie uma vez"), "{c}");
        assert!(c["action"].as_str().unwrap().contains("system.reboot"), "{c}");
        crate::package::feed_status(&mut s, status(true));
        assert_eq!(check(&mut s)["severity"], "ok");
        // The package service's lab has no real root: not judged.
        let mut lab = status(false);
        lab["lab"] = json!(true);
        crate::package::feed_status(&mut s, lab);
        assert_eq!(check(&mut s)["severity"], "unknown");
    }

    /// A package signed by a key the installed image does not carry leaves
    /// the running slot unverified (test VM, 2026-11-11: `verified: false,
    /// signed_by: null, verity: false`). Rebooting does not fix that, so the
    /// check must not say "reboot once".
    #[test]
    fn root_signed_by_an_untrusted_key_says_install_not_reboot() {
        let mut s = Session::virtual_lab();
        let status = |verified: bool| {
            json!({"supported": true, "lab": false, "running": "b", "keys": ["df0376340ceee539"], "slots": [
                {"slot": "a", "running": false, "state": "invalid", "verified": false, "verity": false},
                {"slot": "b", "running": true, "state": "running", "signed_by": null,
                 "verified": verified, "verity": false}]})
        };
        let check = |s: &mut Session| {
            let v = s.execute("system.health.check", &json!({})).unwrap();
            v["checks"].as_array().unwrap().iter().find(|c| c["key"] == "root.verity").unwrap().clone()
        };
        crate::package::feed_status(&mut s, status(false));
        let c = check(&mut s);
        assert_eq!(c["severity"], "warning");
        assert_eq!(c["value"], "slot b");
        assert!(c["reason"].as_str().unwrap().contains("chave"), "{c}");
        let action = c["action"].as_str().unwrap();
        assert!(action.contains("Reiniciar não resolve"), "{c}");
        assert!(!action.contains("Reinicie uma vez"), "{c}");
        // Verified header on the fallback root (first boot of a dd image):
        // the reboot advice stays.
        crate::package::feed_status(&mut s, status(true));
        assert!(check(&mut s)["action"].as_str().unwrap().contains("Reinicie uma vez"));
    }

    /// G1.6zf: a Super-I/O input the board does not wire reads 127 °C. It is
    /// listed, and it is neither the router's temperature nor a health alarm.
    #[test]
    fn a_motherboard_chips_open_input_is_not_the_routers_temperature() {
        use corerouter_hal::system_resource::{Sample, Sensor, SensorKind};
        use crate::system_resource::{hottest, temperatures};
        let t = |chip: &str, label: &str, value, crit, board| Sensor {
            chip: chip.into(),
            label: label.into(),
            kind: SensorKind::Temperature,
            value,
            crit,
            board,
            ..Sensor::default()
        };
        let mut s = Sample {
            sensors: vec![
                t("k10temp", "Tctl", 61.0, None, false),
                t("nct6798", "AUXTIN1", 127.0, None, true),
                t("nvme0", "Composite", 44.0, Some(90.0), false),
                Sensor { chip: "nct6798".into(), label: "fan2".into(), kind: SensorKind::Fan, value: 0.0, board: true, ..Sensor::default() },
            ],
            ..Sample::default()
        };
        assert_eq!(hottest(&s).unwrap().2, "k10temp Tctl");
        assert_eq!(temperatures(&s).count(), 2);
        // A machine whose only temperatures are the board's: better than none.
        s.sensors.retain(|x| x.board);
        assert_eq!(hottest(&s).unwrap().2, "nct6798 AUXTIN1");
        s.sensors.clear();
        assert!(hottest(&s).is_none());
        // The lab's rows say which are the board's.
        let mut lab = Session::virtual_lab();
        let v = lab.execute("system.health.print", &json!({})).unwrap();
        let rows = v.as_array().unwrap();
        assert!(rows.iter().any(|r| r["chip"] == "board" && r["board"] == true));
        assert!(rows.iter().all(|r| r["chip"] == "board" || r["board"] == false));
    }

    #[test]
    fn temperature_levels() {
        use corerouter_hal::system_resource::{Sensor, SensorKind};
        use crate::system_resource::Level;
        let t = |value, max, crit| Sensor { kind: SensorKind::Temperature, value, max, crit, ..Sensor::default() };
        for (sensor, want) in [
            (t(50.0, None, Some(100.0)), Level::Ok),
            (t(90.0, None, Some(100.0)), Level::Warning),
            (t(97.0, None, Some(100.0)), Level::Error),
            (t(85.0, Some(80.0), None), Level::Warning),
            (t(85.0, None, None), Level::Ok),
        ] {
            assert_eq!(sensor_level(&sensor), want, "{sensor:?}");
        }
    }
}
