//! `interface.hardware.problems` (G1.6ja): the network cards the kernel could
//! not bring up in full, with the reason and what to do.

use serde_json::Value;

use super::{CommandSpec, always};
use crate::{Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[cmd!(query "interface.hardware.problems", "Interface Hardware Problems", [], None,
    "{} → {scanned, reason, live, kernel_log, kernel_log_reason, devices, problems: [{kind: no-driver|firmware|safe-mode, device, bus: pci|usb|mdio, ports, driver, vendor_id, product_id, name, files, error, module, expected, reason, action, line}], ignored: [{device, bus, name, why}]}",
    always, problems)];

fn problems(s: &mut Session, _: &Value) -> Result<Value> {
    Ok(s.nic_problems_json())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::Session;

    #[test]
    fn the_lab_has_a_card_without_driver_and_one_in_safe_mode() {
        let mut s = Session::virtual_lab();
        let v = s.execute("interface.hardware.problems", &json!({})).unwrap();
        assert_eq!(v["scanned"], true);
        let rows = v["problems"].as_array().unwrap();
        let kinds: Vec<&str> = rows.iter().map(|r| r["kind"].as_str().unwrap()).collect();
        assert_eq!(kinds, ["safe-mode", "no-driver"]);
        assert_eq!(rows[0]["ports"][0], "ether7");
        assert_eq!(rows[0]["files"][0], "intel/ice/ddp/ice.pkg");
        assert!(rows[0]["action"].as_str().unwrap().contains("system.package.update"));
        assert_eq!(v["ignored"][0]["device"], "0000:06:00.0");
        // Nothing about regulatory.db, anywhere.
        assert!(!v.to_string().contains("regulatory"), "{v}");
    }

    #[test]
    fn refuses_what_it_does_not_declare() {
        let mut s = Session::virtual_lab();
        assert!(s.execute("interface.hardware.problems", &json!({"all": true})).is_err());
    }

    #[test]
    fn the_list_marks_the_port_and_the_health_check_warns() {
        let mut s = Session::virtual_lab();
        let list = s.execute("interface.list", &json!({})).unwrap();
        let row = |n: &str| list.as_array().unwrap().iter().find(|r| r["name"] == n).unwrap().clone();
        assert_eq!(row("ether7")["hardware_problem"], "safe-mode");
        assert!(row("ether7")["hardware_problem_reason"].as_str().unwrap().contains("Safe Mode"));
        assert!(row("ether1")["hardware_problem"].is_null());
        let v = s.execute("system.health.check", &json!({})).unwrap();
        let c = v["checks"].as_array().unwrap().iter().find(|c| c["key"] == "interface.hardware").unwrap().clone();
        assert_eq!(c["severity"], "warning");
        assert_eq!(c["value"], "2 de 3");
        assert!(c["reason"].as_str().unwrap().contains("ice em Safe Mode"), "{c}");
        assert!(c["reason"].as_str().unwrap().contains("sem driver"), "{c}");
        assert!(c["action"].as_str().unwrap().contains("docs/os-image.md"), "{c}");
    }
}
