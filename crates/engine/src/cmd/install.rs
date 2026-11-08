//! `/system install` (G1.6y): install the running live image on a disk, from
//! the GUI, the web or the terminal. The work is the daemon's `install`
//! service (`crate::install`); `print` shows how far it went. Only on the
//! live image: an installed router refuses all of it.

use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, req_str};
use super::{CommandSpec, always};
use crate::auth::Group;
use crate::install::{
    CHALLENGE_ATTEMPTS, CHALLENGE_SECS, Challenge, Disk, Holds, Install, Job, new_code,
};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "system.install.print", "Install to Disk", ["System", "Install to Disk"], None,
        "{} → {supported, reason?, scanned, medium: {device, version, commit, channel, signed_by, min_disk} | null, disks: [{name, bytes, model, serial, bus, removable, holds: empty|data|corerouter, detail, config_keepable, refused, confirm: name|name+code}], challenge: {disk, serial, attempts_left, presence, remaining_s} | null, job: {disk, phase, done, total} | null, result: {ok, error?, ...} | null}",
        always, print),
    cmd!(
        "system.install.rescan",
        "Rescan Disks",
        [],
        None,
        "{} → {queued}",
        supported,
        rescan
    ),
    cmd!(
        "system.install.challenge",
        "Ask for Code",
        [],
        None,
        "{disk: string, serial: string (as print shows it, empty if the disk has none)} → {disk, expires_s, attempts}",
        supported,
        challenge
    ),
    cmd!(
        "system.install.cancel",
        "Cancel Code",
        [],
        None,
        "{} → {cancelled: bool}",
        supported,
        cancel
    ),
    cmd!(
        "system.install.run",
        "Install",
        [],
        None,
        "{disk: string, serial: string, size: u64 (bytes, as print shows them: the disk must still be that one), typed_name: string (the disk's name, typed by the person), code?: string (from the console; a disk that holds something needs it or the power button), keep_config?: bool (keep the configuration of the CoreRouter on it)} → {disk, queued}",
        supported,
        run
    ),
];

const INSTALLED: &str = "this router is installed: only the live image installs";

fn state(s: &Session) -> Option<&Install> {
    s.ext::<Install>()
}

/// Two locks: the flag `--live` and what the service saw on this system.
fn supported(s: &Session) -> std::result::Result<(), String> {
    if !crate::live::is_live(s) {
        return Err(INSTALLED.to_owned());
    }
    match state(s).and_then(|i| i.support.as_ref()) {
        Some(Ok(())) => Ok(()),
        Some(Err(why)) => Err(why.clone()),
        None => Err("the install service has not started".to_owned()),
    }
}

fn print(s: &mut Session, _: &Value) -> Result<Value> {
    let live = crate::live::is_live(s);
    let mut v = state(s).map_or_else(|| Install::default().status(), Install::status);
    if !live && let Some(o) = v.as_object_mut() {
        o.insert("supported".into(), json!(false));
        o.insert("reason".into(), json!(INSTALLED));
    }
    Ok(v)
}

fn full(s: &Session) -> Result<()> {
    s.permit(Group::Full)
        .map_err(|reason| EngineError::Disabled { id: "system.install".into(), reason })
}

fn conflict(reason: String) -> EngineError {
    EngineError::Disabled { id: "system.install".into(), reason }
}

fn rescan(s: &mut Session, _: &Value) -> Result<Value> {
    if let Some(i) = s.ext_mut::<Install>() {
        i.rescan = true;
    }
    Ok(json!({"queued": true}))
}

/// The disk `print` showed: the same name, serial and, if given, size.
fn disk<'a>(i: &'a Install, name: &str, serial: &str, size: Option<u64>) -> Result<&'a Disk> {
    let clip: String = name.chars().take(32).collect();
    let d = i
        .disks
        .iter()
        .find(|d| d.name == name)
        .ok_or_else(|| EngineError::bad("disk", format!("no disk '{clip}': system.install.rescan")))?;
    if d.serial != serial || size.is_some_and(|b| b != d.bytes) {
        return Err(EngineError::bad(
            "disk",
            format!("{clip} is not the disk it was (serial or size changed): look at the list again"),
        ));
    }
    if let Some(r) = &d.refused {
        return Err(EngineError::bad("disk", format!("{clip} cannot be the target: {r}")));
    }
    Ok(d)
}

fn challenge(s: &mut Session, p: &Value) -> Result<Value> {
    full(s)?;
    let name = req_str(p, "disk")?.to_owned();
    let serial = req_str(p, "serial")?.to_owned();
    let by = s.caller().name.clone();
    let code = new_code().map_err(EngineError::Internal)?;
    let i = s
        .ext_mut::<Install>()
        .ok_or_else(|| EngineError::Internal("install state".into()))?;
    if let Some(busy) = i.busy() {
        return Err(conflict(busy));
    }
    if disk(i, &name, &serial, None)?.holds == Holds::Empty {
        return Err(EngineError::bad("disk", format!("{name} is empty: typing its name is enough")));
    }
    // A new one replaces the old: the last code shown is the one that works.
    i.challenge = Some(Challenge {
        disk: name.clone(),
        serial,
        code,
        attempts_left: CHALLENGE_ATTEMPTS,
        presence: false,
        remaining_s: CHALLENGE_SECS,
        by,
        shown: false,
    });
    Ok(json!({"disk": name, "expires_s": CHALLENGE_SECS, "attempts": CHALLENGE_ATTEMPTS}))
}

fn cancel(s: &mut Session, _: &Value) -> Result<Value> {
    full(s)?;
    let cancelled = s.ext_mut::<Install>().is_some_and(|i| i.challenge.take().is_some());
    Ok(json!({"cancelled": cancelled}))
}

/// The code or the button for this disk; consumes the challenge on success,
/// counts a wrong code and drops the challenge at the last attempt.
fn confirmed(i: &mut Install, name: &str, serial: &str, code: Option<&str>) -> Result<()> {
    let Some(c) = i.challenge.as_mut().filter(|c| c.disk == name && c.serial == serial) else {
        return Err(EngineError::bad(
            "code",
            format!("{name} holds something: ask for a code first (system.install.challenge)"),
        ));
    };
    let right = c.presence
        || code.is_some_and(|t| t.trim().eq_ignore_ascii_case(&c.code));
    if right {
        i.challenge = None;
        return Ok(());
    }
    if code.is_none() {
        return Err(EngineError::bad(
            "code",
            "needs the code on the console, or the power button pressed three times",
        ));
    }
    c.attempts_left = c.attempts_left.saturating_sub(1);
    let left = c.attempts_left;
    if left == 0 {
        i.challenge = None;
        return Err(EngineError::bad("code", "wrong code, and the last try: ask for a new one"));
    }
    Err(EngineError::bad("code", format!("wrong code: {left} tries left")))
}

fn run(s: &mut Session, p: &Value) -> Result<Value> {
    full(s)?;
    let name = req_str(p, "disk")?.to_owned();
    let serial = req_str(p, "serial")?.to_owned();
    let size = p
        .get("size")
        .and_then(Value::as_u64)
        .ok_or_else(|| EngineError::bad("size", "needs the disk's size in bytes, as print shows it"))?;
    let typed = req_str(p, "typed_name")?;
    let code = opt_str(p, "code")?.map(str::to_owned);
    let keep_config = opt_bool(p, "keep_config")?.unwrap_or(false);
    let clip: String = typed.chars().take(32).collect();
    if typed != name {
        return Err(EngineError::bad(
            "typed_name",
            format!("'{clip}' is not the disk's name: nothing was written"),
        ));
    }
    let by = s.caller().name.clone();
    let i = s
        .ext_mut::<Install>()
        .ok_or_else(|| EngineError::Internal("install state".into()))?;
    if let Some(busy) = i.busy() {
        return Err(conflict(busy));
    }
    if i.medium.is_none() {
        return Err(conflict("the installer medium is gone: put it back".into()));
    }
    let d = disk(i, &name, &serial, Some(size))?;
    let holds = d.holds;
    if keep_config && !d.config_keepable {
        return Err(EngineError::bad(
            "keep_config",
            format!("{name} has no configuration this image can keep"),
        ));
    }
    if holds != Holds::Empty {
        confirmed(i, &name, &serial, code.as_deref())?;
    }
    i.result = None;
    i.job = Some(Job { disk: name.clone(), serial, bytes: size, holds, keep_config, by });
    Ok(json!({"disk": name, "queued": true}))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::Session;
    use crate::install::{self, Disk, Holds, Install, MediumInfo};

    fn disk(name: &str, holds: Holds) -> Disk {
        Disk {
            name: name.into(),
            bytes: 1 << 34,
            model: "M".into(),
            serial: "S1".into(),
            bus: "SATA".into(),
            removable: false,
            holds,
            detail: holds.as_str().into(),
            config_keepable: holds == Holds::CoreRouter,
            refused: None,
        }
    }

    fn live() -> Session {
        let mut s = Session::virtual_lab();
        crate::live::set(&mut s);
        install::set_support(&mut s, Ok(()));
        let mut stick = disk("sdb", Holds::Data);
        stick.refused = Some("the installer medium".into());
        install::set_scan(
            &mut s,
            Some(MediumInfo {
                device: "sdb".into(),
                version: "1".into(),
                commit: "c".into(),
                channel: "dev".into(),
                signed_by: "k".into(),
                min_disk: 1 << 30,
            }),
            vec![disk("vda", Holds::Empty), disk("sda", Holds::Data), disk("nvme0n1", Holds::CoreRouter), stick],
        );
        s
    }

    fn run(name: &str, extra: serde_json::Value) -> serde_json::Value {
        let mut p = json!({"disk": name, "serial": "S1", "size": 1u64 << 34, "typed_name": name});
        if let (Some(o), Some(e)) = (p.as_object_mut(), extra.as_object()) {
            o.extend(e.clone());
        }
        p
    }

    fn code(s: &Session) -> String {
        s.ext::<Install>().unwrap().challenge.as_ref().unwrap().code.clone()
    }

    #[test]
    fn an_installed_router_refuses_everything() {
        let mut s = Session::virtual_lab();
        let v = s.execute("system.install.print", &json!({})).unwrap();
        assert_eq!(v["supported"], false);
        assert!(v["reason"].as_str().unwrap().contains("installed"), "{v}");
        // The flag is what counts, even if the service said yes.
        install::set_support(&mut s, Ok(()));
        let e = s.execute("system.install.run", &run("vda", json!({}))).unwrap_err().to_string();
        assert!(e.contains("installed"), "{e}");
        // And the service's look at the system counts too.
        let mut l = live();
        install::set_support(&mut l, Err("/config is a disk".into()));
        let e = l.execute("system.install.rescan", &json!({})).unwrap_err().to_string();
        assert!(e.contains("/config is a disk"), "{e}");
    }

    #[test]
    fn an_empty_disk_needs_only_its_name() {
        let mut s = live();
        let e = s
            .execute("system.install.run", &run("vda", json!({"typed_name": "sda"})))
            .unwrap_err()
            .to_string();
        assert!(e.contains("nothing was written"), "{e}");
        assert!(s.ext::<Install>().unwrap().job.is_none());
        s.execute("system.install.run", &run("vda", json!({}))).unwrap();
        let job = install::take_job(&mut s).unwrap();
        assert_eq!((job.disk.as_str(), job.holds), ("vda", Holds::Empty));
        let v = s.execute("system.install.print", &json!({})).unwrap();
        assert_eq!(v["job"]["disk"], "vda");
        let e = s.execute("system.install.run", &run("sda", json!({"code": "X"}))).unwrap_err().to_string();
        assert!(e.contains("installing"), "{e}");
        install::finish(&mut s, Ok(json!({"disk": "vda"})));
        let e = s.execute("system.install.run", &run("vda", json!({}))).unwrap_err().to_string();
        assert!(e.contains("already installed"), "{e}");
    }

    #[test]
    fn a_failed_install_can_be_tried_again() {
        let mut s = live();
        s.execute("system.install.run", &run("vda", json!({}))).unwrap();
        install::take_job(&mut s).unwrap();
        install::finish(&mut s, Err("/dev/vda: busy".into()));
        let v = s.execute("system.install.print", &json!({})).unwrap();
        assert_eq!(v["result"]["ok"], false);
        s.execute("system.install.run", &run("vda", json!({}))).unwrap();
    }

    #[test]
    fn a_disk_with_data_needs_the_code_and_print_never_shows_it() {
        for name in ["sda", "nvme0n1"] {
            let mut s = live();
            let e = s.execute("system.install.run", &run(name, json!({}))).unwrap_err().to_string();
            assert!(e.contains("challenge"), "{e}");
            s.execute("system.install.challenge", &json!({"disk": name, "serial": "S1"})).unwrap();
            let c = code(&s);
            assert_eq!(c.len(), 6);
            let printed = s.execute("system.install.print", &json!({})).unwrap().to_string();
            assert!(!printed.contains(&c), "{printed}");
            let e = s.execute("system.install.run", &run(name, json!({}))).unwrap_err().to_string();
            assert!(e.contains("power button"), "{e}");
            let right = c.to_lowercase();
            s.execute("system.install.run", &run(name, json!({"code": right}))).unwrap();
            let i = s.ext::<Install>().unwrap();
            assert!(i.challenge.is_none(), "one use");
            assert_eq!(i.job.as_ref().unwrap().disk, name);
        }
    }

    #[test]
    fn three_wrong_codes_end_the_challenge() {
        let mut s = live();
        s.execute("system.install.challenge", &json!({"disk": "sda", "serial": "S1"})).unwrap();
        for left in ["2 tries", "1 tries", "last try"] {
            let e = s.execute("system.install.run", &run("sda", json!({"code": "!"}))).unwrap_err().to_string();
            assert!(e.contains(left), "{e}");
        }
        assert!(s.ext::<Install>().unwrap().challenge.is_none());
        let e = s.execute("system.install.run", &run("sda", json!({"code": "!"}))).unwrap_err().to_string();
        assert!(e.contains("challenge"), "{e}");
    }

    #[test]
    fn a_code_is_bound_to_its_disk_and_expires() {
        let mut s = live();
        s.execute("system.install.challenge", &json!({"disk": "sda", "serial": "S1"})).unwrap();
        let c = code(&s);
        let e = s.execute("system.install.run", &run("nvme0n1", json!({"code": c}))).unwrap_err().to_string();
        assert!(e.contains("challenge"), "{e}");
        install::set_remaining(&mut s, 0);
        let e = s.execute("system.install.run", &run("sda", json!({"code": c}))).unwrap_err().to_string();
        assert!(e.contains("challenge"), "{e}");
    }

    #[test]
    fn the_power_button_stands_for_the_code() {
        let mut s = live();
        s.execute("system.install.challenge", &json!({"disk": "sda", "serial": "S1"})).unwrap();
        install::set_presence(&mut s);
        s.execute("system.install.run", &run("sda", json!({}))).unwrap();
    }

    #[test]
    fn shutdown_cannot_stand_for_the_button() {
        let mut s = live();
        crate::power::set_support(&mut s, Ok(()));
        s.execute("system.install.challenge", &json!({"disk": "sda", "serial": "S1"})).unwrap();
        let e = s.execute("system.shutdown", &json!({"confirm": true})).unwrap_err().to_string();
        assert!(e.contains("code"), "{e}");
        s.execute("system.install.cancel", &json!({})).unwrap();
        s.execute("system.shutdown", &json!({"confirm": true})).unwrap();
    }

    #[test]
    fn the_disk_must_be_the_one_listed() {
        let mut s = live();
        for (p, want) in [
            (run("vda", json!({"serial": "other"})), "not the disk"),
            (run("vda", json!({"size": 1})), "not the disk"),
            (run("xyz", json!({})), "no disk"),
            (run("sdb", json!({"code": "X"})), "installer medium"),
            (run("vda", json!({"keep_config": true})), "no configuration"),
        ] {
            let e = s.execute("system.install.run", &p).unwrap_err().to_string();
            assert!(e.contains(want), "{p}: {e}");
        }
        let e = s.execute("system.install.challenge", &json!({"disk": "vda", "serial": "S1"})).unwrap_err().to_string();
        assert!(e.contains("empty"), "{e}");
    }
}
