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
        "{} → [{name, chip, label, type: temperature|fan|voltage|power, value, unit, max, crit, state: ok|warning|error}]",
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
        assert_eq!(checks.len(), 17);
        let by = |k: &str| checks.iter().find(|c| c["key"] == k).unwrap().clone();
        assert_eq!(by("root.verity")["severity"], "unknown", "no A/B image in the lab");
        assert_eq!(by("routes.ecmp")["severity"], "ok", "the lab has no ECMP (G1.27j)");
        assert_eq!(by("auth.no_password")["severity"], "ok", "the lab has no admin yet");
        assert_eq!(by("nic.errors")["severity"], "warning", "ether4's bad cable");
        assert!(by("nic.errors")["reason"].as_str().unwrap().contains("ether4"));
        assert_eq!(by("ntp")["severity"], "ok", "NTP off is the factory default (G4.6i)");
        assert_eq!(by("services")["severity"], "unknown", "no supervisor in the lab");
        assert_eq!(by("bgp.end-of-rib")["severity"], "unknown", "no routing daemon in the lab (G3.9fj)");
        assert_eq!(by("temperature")["severity"], "ok");
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
