//! `/system boot` (G1.6zn): the system in RAM. `to_ram` is kept in the
//! config like any setting and takes effect at the next boot: the daemon's
//! package service copies it to the file the init reads
//! (`corerouter_sysupdate::system_disk`), and reports back where this
//! boot's root came from and whether the system disk is still there.
//!
//! No RouterOS equivalent (RouterOS runs from its disk); VMware ESXi and
//! the `toram` of Debian's live-boot are the model: the root in RAM, the
//! disk only for the configuration.

use serde_json::{Value, json};

use super::args::opt_bool;
use super::{CommandSpec, always};
use crate::{Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "system.boot.print", "Boot", [], None,
        "{} → {to_ram, next_boot: ram|disk, running: {in_ram, bytes, copy_ms, disk?, note? (why the root stayed on the disk)} | null (not on the image, or the package service has not reported), system_disk_removed: string | null (the line of a system disk that went away)}",
        always, print),
    cmd!(
        "system.boot.set",
        "Set Boot",
        [],
        None,
        "{to_ram?: bool (copy the root to RAM at the next boot and run from there: the system disk can be pulled out with the router running; the root takes ~90 MiB of RAM, and a machine without 256 MiB to spare after it boots from the disk and says so)} → {to_ram, next_boot}",
        always,
        set
    ),
];

fn next(to_ram: bool) -> &'static str {
    if to_ram { "ram" } else { "disk" }
}

fn print(s: &mut Session, _: &Value) -> Result<Value> {
    let to_ram = s.store().candidate().system.boot.to_ram;
    let st = crate::package::status(s);
    let running = st.get("root").filter(|r| r.is_object()).cloned().unwrap_or(Value::Null);
    let gone = st.get("system_disk_removed").cloned().unwrap_or(Value::Null);
    Ok(json!({
        "to_ram": to_ram,
        "next_boot": next(to_ram),
        "running": running,
        "system_disk_removed": gone,
    }))
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let boot = &mut s.store_mut().candidate_mut().system.boot;
    if let Some(v) = opt_bool(p, "to_ram")? {
        boot.to_ram = v;
    }
    let to_ram = boot.to_ram;
    Ok(json!({"to_ram": to_ram, "next_boot": next(to_ram)}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryStorage;
    use corerouter_hal::VirtualHal;

    #[test]
    fn to_ram_waits_for_the_next_boot_and_rolls_back() {
        let mut s = Session::virtual_lab();
        let v = s.execute("system.boot.print", &json!({})).unwrap();
        assert_eq!(v["to_ram"], false);
        assert_eq!(v["running"], Value::Null);
        let rev = s.store().current_revision();
        let out = s.execute("system.boot.set", &json!({"to_ram": true})).unwrap();
        assert_eq!(out, json!({"to_ram": true, "next_boot": "ram"}));
        assert!(s.store().running().system.boot.to_ram);
        assert!(s.execute("system.boot.set", &json!({"to_ram": "maybe"})).is_err());
        assert!(s.execute("system.boot.set", &json!({"to_ram": true, "x": 1})).is_err());
        s.execute("config.rollback", &json!({"revision": rev})).unwrap();
        assert!(!s.store().running().system.boot.to_ram);

        crate::package::feed_status(
            &mut s,
            json!({"supported": true, "root": {"in_ram": true, "bytes": 91_226_112, "copy_ms": 412, "disk": "sda"}}),
        );
        let v = s.execute("system.boot.print", &json!({})).unwrap();
        assert_eq!(v["running"]["in_ram"], true);
        assert_eq!(v["running"]["disk"], "sda");
        assert_eq!(v["system_disk_removed"], Value::Null);
    }

    /// The system disk went away: a commit is refused with its line before
    /// it reaches the data plane; Safe Mode (never saved) still changes the
    /// router; the package jobs, which need the disk, are refused too.
    #[test]
    fn without_the_disk_changes_are_refused_with_its_line() {
        let storage = MemoryStorage::default();
        let mut s = Session::with_storage(Box::new(VirtualHal::default()), Box::new(storage.clone()));
        s.execute("system.identity.set", &json!({"name": "before"})).unwrap();
        let line = "system disk sda removed: the router keeps running from RAM, but configuration changes are no longer saved; reboot with the disk in place";
        storage.set_unavailable(Some(line.to_owned()));
        let e = s.execute("system.identity.set", &json!({"name": "after"})).unwrap_err();
        assert_eq!(e.to_string(), line);
        assert_eq!(s.store().running().system.identity, "before");
        assert_eq!(s.store().candidate().system.identity, "before", "the edit goes back");
        s.execute("config.safe-mode.enter", &json!({})).unwrap();
        s.execute("system.identity.set", &json!({"name": "for now"})).unwrap();
        assert_eq!(s.store().running().system.identity, "for now");
        s.execute("config.safe-mode.cancel", &json!({})).unwrap();
        assert_eq!(s.store().running().system.identity, "before");

        crate::package::feed_status(&mut s, json!({"supported": true, "system_disk_removed": line}));
        let e = s.execute("system.package.scrub", &json!({"slot": "a"})).unwrap_err();
        assert_eq!(e.to_string(), line);
        let v = s.execute("system.boot.print", &json!({})).unwrap();
        assert_eq!(v["system_disk_removed"], line);
    }
}
