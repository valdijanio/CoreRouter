//! `/ppp redundancy` (G4.3h): two BNGs as an active/standby pair. Not in
//! RouterOS; the knobs follow its VRRP and the BNGs that have it (Cisco
//! SRG, Nokia MC-Sync/SRRP). The daemon's `pppoe` service reads the config
//! and answers `monitor`, `switchover` and `simulate-failure` through
//! [`crate::ppp_redundancy::HaBackend`]. Design: `docs/bng-ha.md`.

use std::net::IpAddr;

use corerouter_model::MacAddr;
use corerouter_model::ppp_redundancy::{
    Fencing, HaMode, MAX_INTERFACES, MAX_SECRET, MAX_WITNESSES, Redundancy,
};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_names, opt_parse, opt_str, opt_text, opt_u32};
use super::dhcp_client::opt_list;
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!("ppp.redundancy.set", "PPP Redundancy", [], None,
        "{enabled?: bool, mode?: stateless|hot-standby (default hot-standby: sessions survive a takeover), group?: int 1..255 (the same on both nodes; default 1), peer?: host:port | \"\" (the other node's sync address, TLS), listen_port?: int 1..65535 (default 8730), secret?: string 16..256 (the same on both nodes; write-only), priority?: int 1..254 (default 100; higher wins an election), preempt?: bool (default no), preempt_delay?: int 0..3600 (s, default 60), virtual_mac?: mac | \"\" (default 02:43:52:48:41:<group>), interfaces?: [string] (access ports; empty: every pppoe-server interface), fencing?: witness|access|witness-and-access (default witness-and-access), witness?: [ip] | string (at most 4; the gateway is a good one), track?: [string] (a port of these down fences the node), hello_interval?: int 50..10000 (ms, default 300), dead_interval?: int (ms, at least 3 × hello, at most 60000; default 1200), init_hold?: int 0..600 (s, default 5), recover_hold?: int 0..600 (s, default 3), bfd?: string (BFD profile on the sync path, to peer's address; fast = 50 ms × 3 detects in 150 ms; \"\" = hellos only), access_bfd?: string (BFD profile on the access path, to access_peer), access_peer?: ip | \"\" (the peer's address on the access network), comment?: string} → {enabled, mode, group, peer?, listen_port, secret (*** when set), priority, preempt, preempt_delay, virtual_mac? (set), virtual_mac_in_use, interfaces, fencing, witness, track, hello_interval, dead_interval, init_hold, recover_hold, bfd, access_bfd, access_peer?, detection_ms, comment?, warnings}",
        always, set),
    cmd!(query "ppp.redundancy.get", "PPP Redundancy", ["PPP"], None,
        "{} → {enabled, mode, group, peer?, listen_port, secret (*** when set), priority, preempt, preempt_delay, virtual_mac? (set), virtual_mac_in_use, interfaces, fencing, witness, track, hello_interval, dead_interval, init_hold, recover_hold, bfd, access_bfd, access_peer?, detection_ms, comment?, warnings}",
        always, get),
    cmd!(query "ppp.redundancy.monitor", "PPP Redundancy Monitor", [], None,
        "{} → {running (the pppoe service runs the pair), enabled, role (disabled|init|standby|active|fenced|yielding), epoch, role_since_secs, answering, peer: {connected, role?, priority, sync_path, access_path, witness, fingerprint?}, witness, track, in_sync, sync: {sessions, synced, lag, delay_ms, snapshots, snapshot?, gaps, bytes_sent, bytes_received}, drift: [string], simulating_secs?, duplicate_node_id, history: [{at, from, to, epoch, reason, stateful}], last_error?, bfd: [{path, peer, profile, state, detect_ms, rx_gap_p99_us?, tx_jitter_p99_us?, suppressed, penalty, losses, false_alarms}], confirming, witness_age_ms?, takeovers: [{at, reason, epoch, detected_by, detected_ms, witness_ms, active_ms, announced_ms, adopted_ms, first_frame_ms, stateful, handed, adopted, skipped, lost, test}], peer_takeover?, alerts: [string], test?: {started, method, state, checks, note}}",
        always, monitor),
    cmd!("ppp.redundancy.switchover", "PPP Redundancy Switchover", [], None,
        "{force?: bool (switch even if the standby's replica is incomplete: those sessions redial)} → {role, note}",
        has_backend, switchover),
    cmd!("ppp.redundancy.simulate-failure", "PPP Redundancy Simulate Failure", [], None,
        "{seconds?: int 1..600 (default 30)} → {role, until_secs, note}",
        has_backend, simulate_failure),
    cmd!("ppp.redundancy.test-takeover", "PPP Redundancy Test Takeover", [], None,
        "{method?: failure|switchover (failure, the default: this node goes silent and the peer must detect it as a crash; switchover: planned handover), seconds?: int 5..600 (failure: how long silent, default 15), confirm?: string (\"takeover\" runs it: this node stops serving; without it only the checks run), force?: bool (run with a check failed)} → {started, method, state (checked|refused|running), checks: [{name, ok, detail}], note}",
        has_backend, test_takeover),
];

fn has_backend(s: &Session) -> std::result::Result<(), String> {
    if s.ha_backend().is_none() {
        Err("redundancy is not running: ppp.redundancy.set enabled=yes, on the daemon with the pppoe service".into())
    } else {
        Ok(())
    }
}

fn view(s: &Session) -> Value {
    let cfg = s.store().candidate();
    let r = &cfg.ppp.redundancy;
    let mut v = json!({
        "enabled": r.enabled,
        "mode": r.mode.as_str(),
        "group": r.group,
        "listen_port": r.listen_port,
        "secret": if r.secret.is_empty() { "" } else { "***" },
        "priority": r.priority,
        "preempt": r.preempt,
        "preempt_delay": r.preempt_delay,
        "virtual_mac": r.virtual_mac.map(|m| m.to_string()),
        "virtual_mac_in_use": r.mac().to_string(),
        "interfaces": r.interfaces.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "fencing": r.fencing.as_str(),
        "witness": r.witness.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "track": r.track.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "hello_interval": r.hello_interval,
        "dead_interval": r.dead_interval,
        "init_hold": r.init_hold,
        "recover_hold": r.recover_hold,
        "bfd": r.bfd,
        "access_bfd": r.access_bfd,
        "detection_ms": detection_ms(s, r),
        "warnings": warnings(s, r),
    });
    if let Some(o) = v.as_object_mut() {
        if let Some(p) = &r.peer {
            o.insert("peer".into(), json!(p));
        }
        if !r.comment.is_empty() {
            o.insert("comment".into(), json!(r.comment));
        }
        if let Some(a) = r.access_peer {
            o.insert("access_peer".into(), json!(a.to_string()));
        }
    }
    v
}

/// How long the peer's failure takes to find (G3.6h): the BFD detection
/// time when every path it listens on runs BFD, else the dead interval.
fn detection_ms(s: &Session, r: &Redundancy) -> u64 {
    let cfg = s.store().candidate();
    let detect = |name: &str| (!name.is_empty()).then(|| cfg.routing.bfd.profile(name).map(|p| p.detect_ms())).flatten();
    let sync = detect(&r.bfd);
    let access = if r.fencing.uses_access() { detect(&r.access_bfd).map(Some) } else { Some(None) };
    match (sync, access) {
        (Some(a), Some(b)) => a.max(b.unwrap_or(0)),
        _ => u64::from(r.dead_interval),
    }
}

/// What works but deserves a look, in plain words.
fn warnings(s: &Session, r: &Redundancy) -> Vec<String> {
    let cfg = s.store().candidate();
    let mut w = Vec::new();
    if !r.enabled {
        return w;
    }
    if cfg.ppp.pppoe_servers.iter().all(|x| x.disabled) {
        w.push("no enabled PPPoE server: the pair has nothing to serve yet".into());
    }
    for i in &r.interfaces {
        if !cfg.ppp.pppoe_servers.iter().any(|x| x.interface == *i) {
            w.push(format!("interface {i} has no PPPoE server"));
        }
    }
    if let Some(m) = r.virtual_mac
        && m.0.first().is_some_and(|b| b & 2 == 0)
    {
        w.push("virtual_mac is not locally administered (the second bit of the first octet): it may clash with a real card".into());
    }
    if r.fencing == Fencing::Witness {
        w.push("fencing=witness: a cut sync link with both nodes on the witness makes two actives; witness-and-access also listens on the access network".into());
    }
    if r.mode == HaMode::Stateless {
        w.push("mode=stateless: after a takeover every subscriber redials (seconds of outage); hot-standby keeps the sessions".into());
    }
    if r.bfd.is_empty() && r.access_bfd.is_empty() {
        w.push(format!(
            "no BFD: a failure is found by the dead interval ({} ms); bfd=fast (and access_bfd=fast) finds it in 150 ms",
            r.dead_interval
        ));
    } else if r.fencing.uses_access() && (r.bfd.is_empty() || r.access_bfd.is_empty()) {
        w.push(format!(
            "BFD on one path only: the takeover still waits for the other path's hellos ({} ms); set {} too",
            r.dead_interval,
            if r.bfd.is_empty() { "bfd" } else { "access_bfd" }
        ));
    }
    for (key, name) in [("bfd", &r.bfd), ("access_bfd", &r.access_bfd)] {
        if let Some(p) = cfg.routing.bfd.profile(name)
            && p.detect_ms() < 100
        {
            w.push(format!(
                "{key}={name}: {} ms detection; a busy link or node may lose 3 packets in a row and cause a takeover nobody needed (the pair damps a flapping path)",
                p.detect_ms()
            ));
        }
    }
    if r.dead_interval < 600 {
        w.push(format!(
            "dead_interval={} ms: a busy node may miss hellos and cause a takeover nobody needed",
            r.dead_interval
        ));
    }
    w
}

fn bounded(p: &Value, key: &str, lo: u32, hi: u32) -> Result<Option<u32>> {
    match opt_u32(p, key)? {
        Some(v) if !(lo..=hi).contains(&v) => Err(EngineError::bad(key, format!("must be {lo}..={hi}"))),
        v => Ok(v),
    }
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let mut r = s.store().candidate().ppp.redundancy.clone();
    if let Some(v) = opt_bool(p, "enabled")? {
        r.enabled = v;
    }
    if let Some(v) = opt_parse::<HaMode>(p, "mode")? {
        r.mode = v;
    }
    if let Some(v) = bounded(p, "group", 1, 255)? {
        r.group = u8::try_from(v).unwrap_or(1);
    }
    match opt_str(p, "peer")? {
        Some(t) if t.trim().is_empty() => r.peer = None,
        Some(t) => r.peer = Some(t.trim().to_owned()),
        None => {}
    }
    if let Some(v) = bounded(p, "listen_port", 1, 65_535)? {
        r.listen_port = u16::try_from(v).unwrap_or(r.listen_port);
    }
    if let Some(t) = opt_text(p, "secret", MAX_SECRET)? {
        r.secret = t;
    }
    if let Some(v) = bounded(p, "priority", 1, 254)? {
        r.priority = u8::try_from(v).unwrap_or(r.priority);
    }
    if let Some(v) = opt_bool(p, "preempt")? {
        r.preempt = v;
    }
    if let Some(v) = bounded(p, "preempt_delay", 0, 3600)? {
        r.preempt_delay = v;
    }
    match opt_str(p, "virtual_mac")? {
        Some(t) if t.trim().is_empty() => r.virtual_mac = None,
        Some(t) => {
            let m: MacAddr = t
                .trim()
                .parse()
                .map_err(|e: corerouter_model::ParseError| EngineError::bad("virtual_mac", e.to_string()))?;
            r.virtual_mac = Some(m);
        }
        None => {}
    }
    let cfg = s.store().candidate();
    for key in ["interfaces", "track"] {
        if let Some(list) = opt_names(p, key, MAX_INTERFACES)? {
            if let Some(i) = list.iter().find(|i| !cfg.interfaces.contains_key(i)) {
                return Err(EngineError::bad(key, format!("no interface '{i}'")));
            }
            if key == "interfaces" {
                r.interfaces = list;
            } else {
                r.track = list;
            }
        }
    }
    if let Some(v) = opt_parse::<Fencing>(p, "fencing")? {
        r.fencing = v;
    }
    if let Some(list) = opt_list(p, "witness")? {
        if list.len() > MAX_WITNESSES {
            return Err(EngineError::bad("witness", format!("at most {MAX_WITNESSES} addresses")));
        }
        r.witness = list
            .iter()
            .map(|t| {
                t.trim()
                    .parse::<IpAddr>()
                    .map_err(|_| EngineError::bad("witness", format!("'{}' is not an IP address", t.chars().take(64).collect::<String>())))
            })
            .collect::<Result<_>>()?;
    }
    if let Some(v) = bounded(p, "hello_interval", 1, 10_000)? {
        r.hello_interval = v;
    }
    if let Some(v) = bounded(p, "dead_interval", 1, 60_000)? {
        r.dead_interval = v;
    }
    if let Some(v) = bounded(p, "init_hold", 0, 600)? {
        r.init_hold = v;
    }
    if let Some(v) = bounded(p, "recover_hold", 0, 600)? {
        r.recover_hold = v;
    }
    for key in ["bfd", "access_bfd"] {
        if let Some(name) = opt_str(p, key)? {
            let name = name.trim();
            if !name.is_empty() && cfg.routing.bfd.profile(name).is_none() {
                let all: Vec<String> = cfg.routing.bfd.all_profiles().into_iter().map(|p| p.name).collect();
                return Err(EngineError::bad(
                    key,
                    format!("no BFD profile '{}' (routing.bfd.profile: {})", name.chars().take(64).collect::<String>(), all.join(", ")),
                ));
            }
            if key == "bfd" {
                r.bfd = name.to_owned();
            } else {
                r.access_bfd = name.to_owned();
            }
        }
    }
    match opt_str(p, "access_peer")? {
        Some(t) if t.trim().is_empty() => r.access_peer = None,
        Some(t) => {
            r.access_peer = Some(t.trim().parse::<IpAddr>().map_err(|_| {
                EngineError::bad("access_peer", format!("'{}' is not an IP address", t.chars().take(64).collect::<String>()))
            })?);
        }
        None => {}
    }
    if let Some(t) = opt_text(p, "comment", 256)? {
        r.comment = t;
    }
    if let Some((key, why)) = r.problems().into_iter().next() {
        return Err(EngineError::bad(key, why));
    }
    s.store_mut().candidate_mut().ppp.redundancy = r;
    Ok(view(s))
}

fn get(s: &mut Session, _: &Value) -> Result<Value> {
    Ok(view(s))
}

fn monitor(s: &mut Session, _: &Value) -> Result<Value> {
    let enabled = s.store().running().ppp.redundancy.enabled;
    let Some(b) = s.ha_backend() else {
        return Ok(json!({"running": false, "enabled": enabled, "role": "disabled"}));
    };
    let mut v = serde_json::to_value(b.status()).unwrap_or_else(|_| json!({}));
    if let Some(o) = v.as_object_mut() {
        o.insert("running".into(), json!(true));
        o.insert("enabled".into(), json!(enabled));
    }
    Ok(v)
}

fn switchover(s: &mut Session, p: &Value) -> Result<Value> {
    let force = opt_bool(p, "force")?.unwrap_or(false);
    let b = s.ha_backend().ok_or_else(|| EngineError::bad("force", "redundancy is not running"))?;
    b.switchover(force).map_err(|e| EngineError::bad("force", e))?;
    Ok(json!({
        "role": b.status().role,
        "note": "this node stopped answering and handed the sessions over; it becomes standby when the peer is active, or resumes in 2 s if the peer does not take over",
    }))
}

fn simulate_failure(s: &mut Session, p: &Value) -> Result<Value> {
    let secs = bounded(p, "seconds", 1, 600)?.unwrap_or(30);
    let b = s.ha_backend().ok_or_else(|| EngineError::bad("seconds", "redundancy is not running"))?;
    b.simulate_failure(secs).map_err(|e| EngineError::bad("seconds", e))?;
    Ok(json!({
        "role": b.status().role,
        "until_secs": secs,
        "note": "this node behaves as dead (no answers, no hellos): the peer takes over; it comes back as standby",
    }))
}

fn test_takeover(s: &mut Session, p: &Value) -> Result<Value> {
    let method = opt_str(p, "method")?.unwrap_or("failure").to_owned();
    if !matches!(method.as_str(), "failure" | "switchover") {
        return Err(EngineError::bad("method", "failure or switchover"));
    }
    let secs = bounded(p, "seconds", 5, 600)?.unwrap_or(15);
    let run = match opt_str(p, "confirm")? {
        None => false,
        Some(c) if c == "takeover" => true,
        Some(_) => return Err(EngineError::bad("confirm", "type takeover to run it (this node stops serving)")),
    };
    let force = opt_bool(p, "force")?.unwrap_or(false);
    let b = s.ha_backend().ok_or_else(|| EngineError::bad("method", "redundancy is not running"))?;
    let t = b
        .test_takeover(&method, secs, run, force)
        .map_err(|e| EngineError::bad("method", e))?;
    if run && t.state == "running" {
        s.log_event(
            &["ppp", "warning"],
            crate::logging::DAEMON,
            format!("ppp redundancy: takeover test started ({method}, {secs} s)"),
            json!({"method": method, "seconds": secs}),
        );
    }
    Ok(serde_json::to_value(t).unwrap_or_else(|_| json!({})))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use corerouter_model::ppp_redundancy::RedundancyStatus;

    use super::*;
    use crate::ppp_redundancy::HaBackend;

    fn ready(s: &mut Session) {
        s.execute(
            "ppp.redundancy.set",
            &json!({"peer": "10.0.0.2:8730", "secret": "segredo-do-par-123", "witness": ["10.0.0.254"]}),
        )
        .unwrap();
    }

    #[test]
    fn set_get_and_rollback() {
        let mut s = Session::virtual_lab();
        let g = s.execute("ppp.redundancy.get", &json!({})).unwrap();
        assert_eq!((g["enabled"].clone(), g["mode"].clone()), (json!(false), json!("hot-standby")));
        assert_eq!(g["virtual_mac_in_use"], "02:43:52:48:41:01");
        assert!(g["virtual_mac"].is_null(), "the default is not pinned by an export");
        ready(&mut s);
        let r = s.execute("ppp.redundancy.set", &json!({"enabled": true, "priority": 200, "track": "ether2"})).unwrap();
        assert_eq!(r["secret"], "***", "write-only");
        assert!(r["warnings"].as_array().unwrap().iter().any(|w| w.as_str().unwrap().contains("no enabled PPPoE server")));
        let run = &s.store().running().ppp.redundancy;
        assert!(run.enabled && run.priority == 200 && run.secret == "segredo-do-par-123");
        s.execute("config.mode.set", &json!({"mode": "transactional"})).unwrap();
        s.execute("ppp.redundancy.set", &json!({"enabled": false})).unwrap();
        s.execute("config.discard", &json!({})).unwrap();
        assert!(s.store().candidate().ppp.redundancy.enabled);
        // The journal never sees the secret.
        let journal = format!("{:?}", s.journal());
        assert!(journal.contains("ppp.redundancy.set") && !journal.contains("segredo-do-par-123"));
    }

    #[test]
    fn unsafe_pairs_are_refused_with_the_parameter() {
        let mut s = Session::virtual_lab();
        for (p, key) in [
            (json!({"enabled": true}), "peer"),
            (json!({"enabled": true, "peer": "10.0.0.2:8730"}), "secret"),
            (json!({"enabled": true, "peer": "10.0.0.2:8730", "secret": "0123456789abcdef"}), "witness"),
            (json!({"secret": "short", "enabled": true, "peer": "a:1", "fencing": "access"}), "secret"),
            (json!({"peer": "sem-porta"}), "peer"),
            (json!({"hello_interval": 500, "dead_interval": 1000}), "dead_interval"),
            (json!({"virtual_mac": "01:00:5e:00:00:01"}), "virtual_mac"),
            (json!({"witness": ["gateway"]}), "witness"),
            (json!({"track": ["nope"]}), "track"),
            (json!({"priority": 255}), "priority"),
            (json!({"mode": "active-active"}), "mode"),
            (json!({"fencing": "none"}), "fencing"),
        ] {
            let e = s.execute("ppp.redundancy.set", &p).unwrap_err();
            assert!(e.to_string().contains(key), "{p}: {e}");
        }
        assert!(s.store().running().ppp.redundancy.is_default(), "nothing half applied");
    }

    struct Fake(Mutex<Vec<String>>);

    impl HaBackend for Fake {
        fn status(&self) -> RedundancyStatus {
            RedundancyStatus {
                role: "active".into(),
                ..RedundancyStatus::default()
            }
        }
        fn switchover(&self, force: bool) -> std::result::Result<(), String> {
            self.0.lock().unwrap().push(format!("switchover {force}"));
            if force { Ok(()) } else { Err("the peer's replica is not complete".into()) }
        }
        fn simulate_failure(&self, secs: u32) -> std::result::Result<(), String> {
            self.0.lock().unwrap().push(format!("simulate {secs}"));
            Ok(())
        }
        fn test_takeover(
            &self,
            method: &str,
            secs: u32,
            run: bool,
            force: bool,
        ) -> std::result::Result<corerouter_model::ppp_redundancy::TakeoverTest, String> {
            self.0.lock().unwrap().push(format!("test {method} {secs} {run} {force}"));
            Ok(corerouter_model::ppp_redundancy::TakeoverTest {
                method: method.into(),
                state: if run { "running" } else { "checked" }.into(),
                ..Default::default()
            })
        }
    }

    #[test]
    fn monitor_and_actions_go_to_the_service() {
        let mut s = Session::virtual_lab();
        let m = s.execute("ppp.redundancy.monitor", &json!({})).unwrap();
        assert_eq!((m["running"].clone(), m["role"].clone()), (json!(false), json!("disabled")));
        let e = s.execute("ppp.redundancy.switchover", &json!({})).unwrap_err();
        assert!(e.to_string().contains("not running"), "{e}");
        let fake = Arc::new(Fake(Mutex::new(Vec::new())));
        s.set_ha_backend(fake.clone());
        let m = s.execute("ppp.redundancy.monitor", &json!({})).unwrap();
        assert_eq!((m["running"].clone(), m["role"].clone()), (json!(true), json!("active")));
        let e = s.execute("ppp.redundancy.switchover", &json!({})).unwrap_err();
        assert!(e.to_string().contains("replica"), "{e}");
        s.execute("ppp.redundancy.switchover", &json!({"force": true})).unwrap();
        s.execute("ppp.redundancy.simulate-failure", &json!({"seconds": 10})).unwrap();
        assert!(s.execute("ppp.redundancy.simulate-failure", &json!({"seconds": 0})).is_err());
        assert_eq!(*fake.0.lock().unwrap(), ["switchover false", "switchover true", "simulate 10"]);
    }

    #[test]
    fn bfd_profiles_and_the_detection_time() {
        let mut s = Session::virtual_lab();
        ready(&mut s);
        let g = s.execute("ppp.redundancy.get", &json!({})).unwrap();
        assert_eq!(g["detection_ms"], 1200, "hellos only");
        assert!(g["warnings"].as_array().unwrap().is_empty(), "disabled: no warnings");
        s.execute("ppp.redundancy.set", &json!({"enabled": true})).unwrap();
        let g = s.execute("ppp.redundancy.get", &json!({})).unwrap();
        assert!(g["warnings"].to_string().contains("no BFD"), "{g}");
        let e = s.execute("ppp.redundancy.set", &json!({"bfd": "nope"})).unwrap_err();
        assert!(e.to_string().contains("bfd") && e.to_string().contains("fast"), "{e}");
        let r = s.execute("ppp.redundancy.set", &json!({"bfd": "fast"})).unwrap();
        assert_eq!(r["bfd"], "fast");
        assert_eq!(r["detection_ms"], 1200, "the access hellos still decide");
        assert!(r["warnings"].to_string().contains("one path only"), "{r}");
        let e = s.execute("ppp.redundancy.set", &json!({"access_bfd": "fast"})).unwrap_err();
        assert!(e.to_string().contains("access_peer"), "{e}");
        let e = s.execute("ppp.redundancy.set", &json!({"access_bfd": "fast", "access_peer": "x"})).unwrap_err();
        assert!(e.to_string().contains("access_peer"), "{e}");
        let r = s
            .execute("ppp.redundancy.set", &json!({"access_bfd": "fast", "access_peer": "100.64.0.2"}))
            .unwrap();
        assert_eq!((r["access_peer"].clone(), r["detection_ms"].clone()), (json!("100.64.0.2"), json!(150)));
        assert!(!r["warnings"].to_string().contains("BFD"), "{r}");
        // A name as the peer has no address for BFD.
        let e = s.execute("ppp.redundancy.set", &json!({"peer": "bng2.isp:8730"})).unwrap_err();
        assert!(e.to_string().contains("bfd"), "{e}");
        // Back to hellos only.
        let r = s.execute("ppp.redundancy.set", &json!({"bfd": "", "access_bfd": "", "access_peer": ""})).unwrap();
        assert_eq!(r["detection_ms"], 1200);
        assert!(r.get("access_peer").is_none());
    }

    #[test]
    fn test_takeover_checks_first_and_runs_only_on_confirmation() {
        let mut s = Session::virtual_lab();
        let e = s.execute("ppp.redundancy.test-takeover", &json!({})).unwrap_err();
        assert!(e.to_string().contains("not running"), "{e}");
        let fake = Arc::new(Fake(Mutex::new(Vec::new())));
        s.set_ha_backend(fake.clone());
        let t = s.execute("ppp.redundancy.test-takeover", &json!({})).unwrap();
        assert_eq!(t["state"], "checked", "no confirm: only the checks");
        for (p, key) in [
            (json!({"confirm": "yes"}), "confirm"),
            (json!({"method": "reboot"}), "method"),
            (json!({"seconds": 1}), "seconds"),
        ] {
            let e = s.execute("ppp.redundancy.test-takeover", &p).unwrap_err();
            assert!(e.to_string().contains(key), "{p}: {e}");
        }
        let t = s
            .execute("ppp.redundancy.test-takeover", &json!({"confirm": "takeover", "seconds": 20}))
            .unwrap();
        assert_eq!(t["state"], "running");
        s.execute("ppp.redundancy.test-takeover", &json!({"method": "switchover", "confirm": "takeover", "force": true}))
            .unwrap();
        assert_eq!(
            *fake.0.lock().unwrap(),
            ["test failure 15 false false", "test failure 20 true false", "test switchover 15 true true"]
        );
    }
}
