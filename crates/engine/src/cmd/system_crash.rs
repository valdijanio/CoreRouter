//! `system.crash.print` (G1.6zx): the kernel panics and oopses of earlier
//! boots, as the crash-log service saved them from pstore under
//! `/config/crash/` (`crate::crash_log`). Cisco's `show version` "Last
//! reload reason" and Junos' `show system core-dumps`, for the kernel.

use serde_json::{Value, json};

use super::args::{opt_bool, opt_u32};
use super::{CommandSpec, always};
use crate::crash_log::{CrashLog, MAX_KEPT};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[cmd!(query "system.crash.print", "Crash Log", [], None,
    "{lines?: bool (the whole kernel log of each dump, oldest line first; default false), limit?: int 1..8 (default 8)} → {fed: bool (false: no crash-log service, the lab or the browser), backend: string|null (where the kernel writes a dump now: erst, efi_pstore; null: nowhere), efi: {total, free, enabled, turned_off}|null (the UEFI variable store; turned_off: too little NVRAM left, the service switched efi_pstore off), problems: [string], crashes: [{time, reason: panic|oops|emergency|shutdown|<record type>, backend, uptime_s, boot_start, slot, kernel, summary, parts, complete, this_boot: bool (found at this boot: the previous boot ended in it), lines?}]}",
    always, print)];

fn print(s: &mut Session, p: &Value) -> Result<Value> {
    let lines = opt_bool(p, "lines")?.unwrap_or(false);
    let limit = opt_u32(p, "limit")?.unwrap_or(8);
    let limit = usize::try_from(limit).unwrap_or(MAX_KEPT);
    if !(1..=MAX_KEPT).contains(&limit) {
        return Err(EngineError::bad("limit", "1 to 8"));
    }
    Ok(match s.ext::<CrashLog>() {
        Some(log) => log.to_json(limit, lines),
        None => json!({"fed": false, "backend": null, "efi": null, "problems": [], "crashes": []}),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crash_log::{Crash, Found};

    #[test]
    fn empty_in_the_lab_then_what_the_service_found() {
        let mut s = Session::virtual_lab();
        let v = s.execute("system.crash.print", &json!({})).unwrap();
        assert_eq!(v["fed"], false);
        assert_eq!(v["crashes"], json!([]));
        let c = |t: u64| Crash {
            time: Some(t),
            reason: "panic".into(),
            backend: "efi_pstore".into(),
            summary: "Kernel panic - not syncing: x".into(),
            lines: vec!["[ 1.0] Kernel panic - not syncing: x".into()],
            ..Crash::default()
        };
        s.crash_found(Found { new: vec![c(20)], saved: vec![c(10)], backend: Some("efi_pstore".into()), ..Found::default() });
        let v = s.execute("system.crash.print", &json!({})).unwrap();
        assert_eq!(v["fed"], true);
        assert_eq!(v["crashes"].as_array().unwrap().len(), 2);
        assert_eq!(v["crashes"][0]["this_boot"], true);
        assert_eq!(v["crashes"][1]["this_boot"], false);
        assert!(v["crashes"][0].get("lines").is_none());
        let v = s.execute("system.crash.print", &json!({"lines": true, "limit": 1})).unwrap();
        assert_eq!(v["crashes"].as_array().unwrap().len(), 1);
        assert_eq!(v["crashes"][0]["lines"][0], "[ 1.0] Kernel panic - not syncing: x");
    }

    #[test]
    fn bad_params() {
        let mut s = Session::virtual_lab();
        assert!(s.execute("system.crash.print", &json!({"limit": 0})).is_err());
        assert!(s.execute("system.crash.print", &json!({"limit": 9})).is_err());
        assert!(s.execute("system.crash.print", &json!({"lines": "yes"})).is_err());
        assert!(s.execute("system.crash.print", &json!({"x": 1})).is_err());
    }
}
