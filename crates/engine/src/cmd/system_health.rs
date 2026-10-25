//! `/system health` (G4.8a, RouterOS `/system health`): every sensor the
//! machine has — temperatures with the driver's `max` and `crit`, fans,
//! voltages, power — and how each reads against its limits.

use serde_json::{Value, json};

use super::system_resource::{monitor, r1};
use super::{CommandSpec, always};
use crate::{Result, Session};
use crate::system_resource::sensor_level;

pub(super) const COMMANDS: &[CommandSpec] = &[cmd!(query "system.health.print", "Health", [], None,
    "{} → [{name, chip, label, type: temperature|fan|voltage|power, value, unit, max, crit, state: ok|warning|error}]",
    always, print)];

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
