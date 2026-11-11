//! `/system install` (G1.6y): install the running live image on a disk, from
//! the GUI, the web or the terminal. The work is the daemon's `install`
//! service (`crate::install`); `print` shows how far it went. Only on the
//! live image: an installed router refuses all of it.

use std::net::IpAddr;

use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, req_str};
use super::{CommandSpec, always};
use crate::auth::Group;
use crate::install::{
    CHALLENGE_ATTEMPTS, CHALLENGE_SECS, Challenge, Disk, Holds, Install, Job, Mgmt, TestRequest,
    new_code,
};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "system.install.print", "Install to Disk", ["System", "Install to Disk"], None,
        "{} → {supported, reason?, scanned, medium: {device, version, commit, channel, signed_by, min_disk} | null, disks: [{name, bytes, model, serial, bus, removable, holds: empty|data|corerouter, detail, config_keepable, refused, confirm: name|name+code}], challenge: {disk, serial, attempts_left, presence, remaining_s} | null, job: {disk, phase, done, total} | null, result: {ok, error?, ...} | null, testing, network: {connected_port, problems, ports: [{name, mac, driver, link, speed_mbps, address, dhcp_status, gateway, gateway_ok, dns, dns_ok, firmware, connected}], firmware} | null}",
        always, print),
    // G0.3f: looking again and testing change nothing: group write, but no
    // line in the journal nor in the log (the window runs the test by itself).
    cmd!(quiet "system.install.rescan", "Rescan Disks", [], None,
        "{} → {queued}",
        supported, rescan),
    cmd!(quiet "system.install.test", "Test Network", [], None,
        "{} → {queued} (driver, firmware, link, DHCP, gateway and DNS of each port, and the port this connection came through: system.install.print shows them)",
        supported, test),
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
        "{disk: string, serial: string, size: u64 (bytes, as print shows them: the disk must still be that one), typed_name: string (the disk's name, typed by the person), code?: string (from the console; a disk that holds something needs it or the power button), keep_config?: bool (keep the configuration of the CoreRouter on it), mgmt_port?: string (the port for management after the first boot), mgmt_mode?: dhcp|static, mgmt_address?: string (static: address/prefix), mgmt_gateway?: ip, mgmt_dns?: [ip]} → {disk, queued}",
        supported,
        run
    ),
];

const MAX_DNS: usize = 3;
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

fn test(s: &mut Session, _: &Value) -> Result<Value> {
    let local = s.caller().link.as_ref().map(|l| match l.local.ip() {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    });
    let i = s
        .ext_mut::<Install>()
        .ok_or_else(|| EngineError::Internal("install state".into()))?;
    if !i.testing {
        i.test = Some(TestRequest { local });
    }
    Ok(json!({"queued": true}))
}

/// What the operator chose for the first boot (hostile: checked here, read by
/// PID 1 from a file on the disk).
fn mgmt(s: &mut Session, p: &Value) -> Result<Option<Mgmt>> {
    let Some(port) = opt_str(p, "mgmt_port")?.map(str::to_owned) else {
        for k in ["mgmt_mode", "mgmt_address", "mgmt_gateway", "mgmt_dns"] {
            if p.get(k).is_some() {
                return Err(EngineError::bad(k, "needs mgmt_port"));
            }
        }
        return Ok(None);
    };
    let clip: String = port.chars().take(32).collect();
    if !s.hal_mut().poll().iter().any(|l| l.name.as_str() == port) {
        return Err(EngineError::bad("mgmt_port", format!("no port '{clip}' here")));
    }
    let ip = |k: &str, v: &str| -> Result<String> {
        v.parse::<IpAddr>().map(|a| a.to_string()).map_err(|_| {
            EngineError::bad(k, format!("'{}' is not an IP address", v.chars().take(45).collect::<String>()))
        })
    };
    let gateway = opt_str(p, "mgmt_gateway")?.map(|g| ip("mgmt_gateway", g)).transpose()?;
    let mut dns = Vec::new();
    if let Some(list) = p.get("mgmt_dns") {
        let list = list
            .as_array()
            .filter(|l| l.len() <= MAX_DNS)
            .ok_or_else(|| EngineError::bad("mgmt_dns", format!("a list of up to {MAX_DNS} addresses")))?;
        for d in list {
            let d = d.as_str().ok_or_else(|| EngineError::bad("mgmt_dns", "a list of addresses"))?;
            dns.push(ip("mgmt_dns", d)?);
        }
    }
    let address = match opt_str(p, "mgmt_mode")? {
        Some("dhcp") => {
            if p.get("mgmt_address").is_some() || gateway.is_some() || !dns.is_empty() {
                return Err(EngineError::bad("mgmt_mode", "dhcp takes no address, gateway or DNS"));
            }
            None
        }
        Some("static") => {
            let a = opt_str(p, "mgmt_address")?
                .ok_or_else(|| EngineError::bad("mgmt_address", "static needs address/prefix"))?;
            let bad = || EngineError::bad("mgmt_address", format!("'{}' is not address/prefix", a.chars().take(49).collect::<String>()));
            let (addr, prefix) = a.split_once('/').ok_or_else(bad)?;
            let addr: IpAddr = addr.parse().map_err(|_| bad())?;
            let max = if addr.is_ipv4() { 32 } else { 128 };
            if !prefix.parse::<u8>().is_ok_and(|n| n <= max) {
                return Err(bad());
            }
            Some(format!("{addr}/{prefix}"))
        }
        _ => return Err(EngineError::bad("mgmt_mode", "must be dhcp or static")),
    };
    Ok(Some(Mgmt { port, address, gateway, dns }))
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
    let mgmt = mgmt(s, p)?;
    if keep_config && mgmt.is_some() {
        return Err(EngineError::bad(
            "mgmt_port",
            "the configuration kept on the disk says how it is managed",
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
    i.job = Some(Job { disk: name.clone(), serial, bytes: size, holds, keep_config, mgmt, by });
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

    /// G0.3f: the network test and the rescan change nothing: they are not
    /// in the journal nor in the log ("Alterado: /system install test" was
    /// there every time the window opened), and still need group write.
    #[test]
    fn testing_and_rescanning_leave_no_journal_entry() {
        let mut s = live();
        let before = (s.journal().len(), s.log_seq());
        assert_eq!(s.execute("system.install.test", &json!({})).unwrap()["queued"], true);
        assert_eq!(s.execute("system.install.rescan", &json!({})).unwrap()["queued"], true);
        assert!(s.ext::<Install>().unwrap().test.is_some(), "the test was asked for");
        assert_eq!((s.journal().len(), s.log_seq()), before);
        let reader = crate::Caller::new(1, "x").with_principal(crate::auth::Principal::User("noc".into()));
        s.execute("user.add", &json!({"name": "noc", "group": "read", "password": "noc-password"}))
            .unwrap();
        for id in ["system.install.test", "system.install.rescan"] {
            let e = s.execute_as(&reader, id, &json!({})).unwrap_err().to_string();
            assert!(e.contains("needs group write"), "{id}: {e}");
        }
        // What is done to the router still is: the install itself.
        s.execute("system.install.run", &run("vda", json!({}))).unwrap();
        assert_eq!(s.journal().last().unwrap().command, "system.install.run");
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
    fn the_management_choice_is_checked_before_anything_runs() {
        let mut s = live();
        for (extra, want) in [
            (json!({"mgmt_mode": "dhcp"}), "needs mgmt_port"),
            (json!({"mgmt_port": "nope", "mgmt_mode": "dhcp"}), "no port"),
            (json!({"mgmt_port": "ether1"}), "dhcp or static"),
            (json!({"mgmt_port": "ether1", "mgmt_mode": "static"}), "address/prefix"),
            (json!({"mgmt_port": "ether1", "mgmt_mode": "static", "mgmt_address": "10.0.0.1"}), "address/prefix"),
            (json!({"mgmt_port": "ether1", "mgmt_mode": "static", "mgmt_address": "10.0.0.1/33"}), "address/prefix"),
            (json!({"mgmt_port": "ether1", "mgmt_mode": "static", "mgmt_address": "10.0.0.1/24", "mgmt_gateway": "x"}), "not an IP"),
            (json!({"mgmt_port": "ether1", "mgmt_mode": "static", "mgmt_address": "10.0.0.1/24", "mgmt_dns": ["1.1.1.1", "x"]}), "not an IP"),
            (json!({"mgmt_port": "ether1", "mgmt_mode": "dhcp", "mgmt_gateway": "10.0.0.1"}), "takes no"),
            (json!({"mgmt_port": "ether1", "mgmt_mode": "dhcp", "keep_config": true}), "kept"),
        ] {
            let p = run(if extra.get("keep_config").is_some() { "nvme0n1" } else { "vda" }, extra);
            let e = s.execute("system.install.run", &p).unwrap_err().to_string();
            assert!(e.contains(want), "{p}: {e}");
            assert!(s.ext::<Install>().unwrap().job.is_none());
        }
        let p = run("vda", json!({"mgmt_port": "ether1", "mgmt_mode": "static", "mgmt_address": "10.0.0.1/24", "mgmt_gateway": "10.0.0.254", "mgmt_dns": ["1.1.1.1"]}));
        s.execute("system.install.run", &p).unwrap();
        let m = s.ext::<Install>().unwrap().job.as_ref().unwrap().mgmt.clone().unwrap();
        assert_eq!(m.address.as_deref(), Some("10.0.0.1/24"));
        assert_eq!(m.dns, ["1.1.1.1"]);
    }

    #[test]
    fn a_network_test_is_queued_once() {
        let mut s = live();
        s.execute("system.install.test", &json!({})).unwrap();
        assert_eq!(s.execute("system.install.print", &json!({})).unwrap()["testing"], true);
        assert!(install::take_test(&mut s).is_some());
        s.execute("system.install.test", &json!({})).unwrap();
        assert!(install::take_test(&mut s).is_none(), "one at a time");
        install::set_network(&mut s, json!({"problems": []}));
        let v = s.execute("system.install.print", &json!({})).unwrap();
        assert_eq!((v["testing"].as_bool(), v["network"]["problems"].is_array()), (Some(false), true));
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
