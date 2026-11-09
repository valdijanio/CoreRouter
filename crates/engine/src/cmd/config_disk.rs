//! G1.6w: how the histories share `/config`.

use serde_json::Value;

use super::{CommandSpec, always};
use crate::{Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[cmd!(query "system.config-disk.print", "Config Disk", [], None,
    "{} → {capacity_bytes (null: no disk measured), history: {bytes, budget_bytes, percent, revisions_saved, revisions_not_saved}, graphs: {bytes, budget_bytes, percent, refused, removed}}",
    always, print)];

fn print(s: &mut Session, _: &Value) -> Result<Value> {
    Ok(s.config_disk_json())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::Session;

    #[test]
    fn no_disk_measured_says_so() {
        let mut s = Session::virtual_lab();
        let v = s.execute("system.config-disk.print", &json!({})).unwrap();
        assert!(v["capacity_bytes"].is_null(), "{v}");
    }

    #[test]
    fn the_shares_follow_the_capacity() {
        let mut s = Session::virtual_lab();
        s.set_config_capacity(Some(56_000_000));
        let v = s.execute("system.config-disk.print", &json!({})).unwrap();
        assert_eq!(v["history"]["budget_bytes"], 5_600_000);
        assert_eq!(v["graphs"]["budget_bytes"], 14_000_000);
        // Refused by a typo in a parameter, as every query.
        s.execute("system.config-disk.print", &json!({"nope": 1})).unwrap_err();
    }
}
