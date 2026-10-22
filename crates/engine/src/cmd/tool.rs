//! /tool: diagnostic tools (ping, MTU discovery) and the tasks they run in.
//!
//! Every tool command starts a task and returns its id at once; results
//! come from `tool.task.poll`. All of them are operational (`query`): no
//! journal entry, no revision. See `docs/tools.md`.

use std::net::IpAddr;
use std::time::Duration;

use corerouter_hal::probe::{MAX_PACKET, SocketOptions, V4_OVERHEAD};
use corerouter_model::{IfName, InterfaceKind, RoutingTable};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_u32, req_u32};
use super::{CommandSpec, always};
use crate::tasks::{MAX_POLL, can_start};
use crate::tools::{Target, mtu, ping};
use crate::{EngineError, Result, Session};

/// Targets one ping task may have.
pub const MAX_TARGETS: usize = 16;
const MAX_NAME: usize = 253;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "tool.ping.start", "Ping", ["Tools", "Ping"], None,
        "{address: string|[string] (1..16 IPs or DNS names), count?: int 0..1000000 (0 = until stopped), interval_ms?: int 10..60000, timeout_ms?: int 10..10000, size?: int 28..65535 (whole IP packet), ttl?: int 1..255, dscp?: int 0..63, do_not_fragment?: bool, src_address?: ip, interface?: string, routing_table?: string} → {task_id, targets}",
        can_start, ping_start),
    cmd!(query "tool.ping.mtu", "Discover MTU", ["Tools", "Ping"], None,
        "{address: string, max_size?: int 28..65535 (default 1500), timeout_ms?: int 10..10000, retries?: int 1..5, dscp?: int 0..63, src_address?: ip, interface?: string, routing_table?: string} → {task_id}",
        can_start, ping_mtu),
    cmd!(query "tool.task.list", "Tasks", [], None,
        "{} → [{id, kind, title, state: running|done|stopped|failed, reason, owner, events, age_secs}]",
        always, task_list),
    cmd!(query "tool.task.poll", "Poll Task", [], None,
        "{id: int, after_seq?: int, max?: int 1..256} → {id, kind, title, state, done, reason, summary, events: [{seq, …}], next_seq, more, lost}",
        always, task_poll),
    cmd!(query "tool.task.stop", "Stop Task", [], None,
        "{id: int} → {id, state, stopping}",
        always, task_stop),
];

fn ranged(p: &Value, key: &str, lo: u32, hi: u32, default: u32) -> Result<u32> {
    let v = opt_u32(p, key)?.unwrap_or(default);
    if !(lo..=hi).contains(&v) {
        return Err(EngineError::bad(key, format!("must be {lo}..={hi}")));
    }
    Ok(v)
}

fn narrow<T: TryFrom<u32>>(key: &str, v: u32) -> Result<T> {
    T::try_from(v).map_err(|_| EngineError::bad(key, "out of range"))
}

/// A DNS name: 1..=253 characters, labels of 1..=63 letters, digits, `-`
/// and `_`, not starting or ending with `-`.
fn valid_name(s: &str) -> bool {
    let s = s.strip_suffix('.').unwrap_or(s);
    !s.is_empty()
        && s.len() <= MAX_NAME
        && s.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

fn target(key: &str, raw: &str) -> Result<Target> {
    let t = raw.trim();
    if let Ok(addr) = t.parse::<IpAddr>() {
        return Ok(Target {
            input: t.to_owned(),
            addr: Some(addr),
        });
    }
    if !valid_name(t) {
        let shown: String = t.chars().take(64).collect();
        return Err(EngineError::bad(
            key,
            format!("'{shown}' is neither an IP address nor a DNS name"),
        ));
    }
    Ok(Target {
        input: t.to_owned(),
        addr: None,
    })
}

/// `address`: one string (comma-separated for several, as the CLI types
/// it) or a list of strings. Duplicates are dropped.
fn targets(p: &Value) -> Result<Vec<Target>> {
    let raw: Vec<&str> = match p.get("address") {
        Some(Value::String(s)) => s.split(',').filter(|x| !x.trim().is_empty()).collect(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str()
                    .ok_or_else(|| EngineError::bad("address", "must be a list of strings"))
            })
            .collect::<Result<_>>()?,
        _ => {
            return Err(EngineError::bad(
                "address",
                "must be an IP address or name, or a list of them",
            ));
        }
    };
    if raw.is_empty() {
        return Err(EngineError::bad("address", "is required"));
    }
    if raw.len() > MAX_TARGETS {
        return Err(EngineError::bad(
            "address",
            format!("at most {MAX_TARGETS} targets"),
        ));
    }
    let mut out: Vec<Target> = Vec::with_capacity(raw.len());
    for r in raw {
        let t = target("address", r)?;
        if !out.iter().any(|o| o.input.eq_ignore_ascii_case(&t.input)) {
            out.push(t);
        }
    }
    Ok(out)
}

/// Socket options shared by ping and MTU: DSCP, source, and the device
/// for `interface` / `routing_table` (a VRF is reached by binding to its
/// device, or to one of its members).
fn options(s: &Session, p: &Value, targets: &[Target]) -> Result<SocketOptions> {
    let dscp = ranged(p, "dscp", 0, 63, 0)?;
    let src: Option<IpAddr> = opt_parse(p, "src_address")?;
    if let Some(src) = src {
        if let Some(t) = targets
            .iter()
            .find(|t| t.addr.is_some_and(|a| a.is_ipv6() != src.is_ipv6()))
        {
            return Err(EngineError::bad(
                "src_address",
                format!("{src} and {} are of different IP versions", t.input),
            ));
        }
        if src.is_unspecified() || src.is_multicast() {
            return Err(EngineError::bad("src_address", "must be a unicast address"));
        }
    }
    let cfg = s.store().running();
    let table: Option<RoutingTable> = opt_parse(p, "routing_table")?;
    let vrf = match table {
        None | Some(RoutingTable::Main) => None,
        Some(RoutingTable::Vrf(name)) => match cfg.interfaces.get(&name).map(|i| &i.kind) {
            Some(InterfaceKind::Vrf { .. }) => Some(name),
            _ => {
                return Err(EngineError::bad(
                    "routing_table",
                    format!("no VRF '{name}' (see ip.vrf.list)"),
                ));
            }
        },
    };
    let interface: Option<IfName> = opt_parse(p, "interface")?;
    let device = match (interface, vrf) {
        (None, vrf) => vrf,
        (Some(i), vrf) => {
            let Some(iface) = cfg.interfaces.get(&i) else {
                return Err(EngineError::bad(
                    "interface",
                    format!("no interface '{i}' (see interface.list)"),
                ));
            };
            if let Some(v) = &vrf
                && iface.vrf.as_ref() != Some(v)
                && &i != v
            {
                return Err(EngineError::bad(
                    "interface",
                    format!("{i} is not in VRF {v}"),
                ));
            }
            Some(i)
        }
    };
    Ok(SocketOptions {
        tos: narrow::<u8>("dscp", dscp)? << 2,
        dont_fragment: opt_bool(p, "do_not_fragment")?.unwrap_or(false),
        src,
        device: device.map(|d| d.to_string()),
    })
}

fn title(verb: &str, targets: &[Target]) -> String {
    let names: Vec<&str> = targets.iter().map(|t| t.input.as_str()).collect();
    let mut t = format!("{verb} {}", names.join(", "));
    if t.chars().count() > 120 {
        t = t.chars().take(117).collect::<String>() + "...";
    }
    t
}

fn ping_start(s: &mut Session, p: &Value) -> Result<Value> {
    let targets = targets(p)?;
    let count = ranged(p, "count", 0, 1_000_000, 0)?;
    let interval = ranged(p, "interval_ms", 10, 60_000, 1000)?;
    let timeout = ranged(p, "timeout_ms", 10, 10_000, 1000)?;
    let size = ranged(p, "size", u32::from(V4_OVERHEAD), u32::from(MAX_PACKET), 56)?;
    let ttl = match opt_u32(p, "ttl")? {
        None => None,
        Some(t) if (1..=255).contains(&t) => Some(narrow::<u8>("ttl", t)?),
        Some(_) => return Err(EngineError::bad("ttl", "must be 1..=255")),
    };
    let options = options(s, p, &targets)?;
    let prober = s.hal().prober().map_err(EngineError::Hal)?;
    let job = ping::PingJob {
        targets: targets.clone(),
        count,
        interval: Duration::from_millis(u64::from(interval)),
        timeout: Duration::from_millis(u64::from(timeout)),
        size: narrow("size", size)?,
        ttl,
        options,
    };
    let id = s.start_task("ping", title("ping", &targets), move |ctx| {
        ping::run(job, prober.as_ref(), ctx)
    })?;
    let names: Vec<&str> = targets.iter().map(|t| t.input.as_str()).collect();
    Ok(json!({ "task_id": id, "targets": names }))
}

fn ping_mtu(s: &mut Session, p: &Value) -> Result<Value> {
    let raw = super::args::req_str(p, "address")?;
    let target = target("address", raw)?;
    let max = ranged(
        p,
        "max_size",
        u32::from(V4_OVERHEAD),
        u32::from(MAX_PACKET),
        1500,
    )?;
    let timeout = ranged(p, "timeout_ms", 10, 10_000, 1000)?;
    let retries = ranged(p, "retries", 1, 5, 2)?;
    let targets = [target.clone()];
    let options = options(s, p, &targets)?;
    let prober = s.hal().prober().map_err(EngineError::Hal)?;
    let job = mtu::MtuJob {
        target,
        max: narrow("max_size", max)?,
        timeout: Duration::from_millis(u64::from(timeout)),
        retries: narrow("retries", retries)?,
        options,
    };
    let id = s.start_task("mtu", title("mtu", &targets), move |ctx| {
        mtu::run(job, prober.as_ref(), ctx)
    })?;
    Ok(json!({ "task_id": id }))
}

fn task_list(s: &mut Session, _: &Value) -> Result<Value> {
    Ok(s.task_list())
}

fn task_poll(s: &mut Session, p: &Value) -> Result<Value> {
    let id = req_u32(p, "id")?;
    let after = match p.get("after_seq") {
        None | Some(Value::Null) => 0,
        Some(v) => v
            .as_u64()
            .ok_or_else(|| EngineError::bad("after_seq", "must be a non-negative integer"))?,
    };
    let max = ranged(p, "max", 1, MAX_POLL as u32, MAX_POLL as u32)?;
    s.task_poll(u64::from(id), after, max as usize)
}

fn task_stop(s: &mut Session, p: &Value) -> Result<Value> {
    let id = req_u32(p, "id")?;
    s.task_stop(u64::from(id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tasks::test_runner;
    use std::thread;

    fn lab() -> Session {
        let mut s = Session::virtual_lab();
        s.set_runner(test_runner::threads());
        s
    }

    fn until_done(s: &mut Session, id: u64) -> Value {
        for _ in 0..500 {
            let p = s
                .execute("tool.task.poll", &json!({"id": id, "max": 256}))
                .unwrap();
            if p["done"] == true {
                return p;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("task {id} did not finish");
    }

    #[test]
    fn ping_two_targets_in_the_lab() {
        let mut s = lab();
        let r = s
            .execute(
                "tool.ping.start",
                &json!({"address": "127.0.0.1, ::1", "count": 3, "interval_ms": 10}),
            )
            .unwrap();
        assert_eq!(r["targets"], json!(["127.0.0.1", "::1"]));
        let p = until_done(&mut s, r["task_id"].as_u64().unwrap());
        assert_eq!(p["state"], "done");
        assert_eq!(p["summary"]["targets"][0]["received"], 3);
        assert_eq!(p["summary"]["targets"][1]["received"], 3);
        assert_eq!(p["events"].as_array().unwrap().len(), 6);
        // Operational: nothing in the journal, no revision.
        assert!(s.journal().is_empty());
        assert_eq!(s.store().current_revision(), 0);
    }

    #[test]
    fn mtu_task_reports_the_path_mtu() {
        let mut s = lab();
        let r = s
            .execute(
                "tool.ping.mtu",
                &json!({"address": "8.8.8.8", "max_size": 9000}),
            )
            .unwrap();
        let p = until_done(&mut s, r["task_id"].as_u64().unwrap());
        assert_eq!(p["summary"]["mtu"], 1500);
        assert_eq!(p["summary"]["payload"], 1472);
    }

    #[test]
    fn stop_a_continuous_ping() {
        let mut s = lab();
        let r = s
            .execute(
                "tool.ping.start",
                &json!({"address": ["10.1.1.1"], "interval_ms": 50}),
            )
            .unwrap();
        let id = r["task_id"].as_u64().unwrap();
        thread::sleep(Duration::from_millis(120));
        let stop = s.execute("tool.task.stop", &json!({"id": id})).unwrap();
        assert_eq!(stop["stopping"], true);
        let p = until_done(&mut s, id);
        assert_eq!(p["state"], "stopped");
        assert!(p["summary"]["targets"][0]["sent"].as_u64().unwrap() >= 1);
        let list = s.execute("tool.task.list", &json!({})).unwrap();
        assert_eq!(list[0]["kind"], "ping");
        assert_eq!(list[0]["title"], "ping 10.1.1.1");
    }

    #[test]
    fn bad_parameters_are_refused_before_anything_starts() {
        let mut s = lab();
        let bad = [
            json!({"address": ""}),
            json!({"address": "bad name!"}),
            json!({"address": "-x.com"}),
            json!({"address": vec!["1.1.1.1"; 17].join(",")}),
            json!({"address": "1.1.1.1", "count": -1}),
            json!({"address": "1.1.1.1", "interval_ms": 5}),
            json!({"address": "1.1.1.1", "size": 20}),
            json!({"address": "1.1.1.1", "ttl": 0}),
            json!({"address": "1.1.1.1", "dscp": 64}),
            json!({"address": "1.1.1.1", "src_address": "::1"}),
            json!({"address": "1.1.1.1", "interface": "nope0"}),
            json!({"address": "1.1.1.1", "routing_table": "blue"}),
            json!({"address": "1.1.1.1", "do_not_fragment": "yes"}),
            json!({"address": "1.1.1.1", "bogus": 1}),
            json!({"address": 7}),
        ];
        for p in bad {
            assert!(s.execute("tool.ping.start", &p).is_err(), "accepted {p}");
        }
        assert!(s.task_list().as_array().unwrap().is_empty());
        assert!(s.execute("tool.task.poll", &json!({"id": 99})).is_err());
        assert!(s.execute("tool.task.stop", &json!({"id": 99})).is_err());
    }

    #[test]
    fn interface_and_vrf_become_the_bound_device() {
        let mut s = lab();
        let targets = targets(&json!({"address": "1.1.1.1"})).unwrap();
        let o = options(&s, &json!({"interface": "ether1", "dscp": 46}), &targets).unwrap();
        assert_eq!(o.device.as_deref(), Some("ether1"));
        assert_eq!(o.tos, 46 << 2);
        s.execute(
            "ip.vrf.add",
            &json!({"name": "blue", "interfaces": ["ether2"]}),
        )
        .unwrap();
        let o = options(&s, &json!({"routing_table": "blue"}), &targets).unwrap();
        assert_eq!(o.device.as_deref(), Some("blue"));
        let o = options(
            &s,
            &json!({"routing_table": "blue", "interface": "ether2"}),
            &targets,
        )
        .unwrap();
        assert_eq!(o.device.as_deref(), Some("ether2"));
        assert!(
            options(
                &s,
                &json!({"routing_table": "blue", "interface": "ether1"}),
                &targets
            )
            .is_err()
        );
    }

    #[test]
    fn names_are_checked() {
        assert!(valid_name("example.com"));
        assert!(valid_name("a_b.example.com."));
        assert!(!valid_name("a..b"));
        assert!(!valid_name(&"a".repeat(64)));
        assert!(!valid_name("x-.com"));
        assert!(!valid_name("ex ample.com"));
    }

    #[test]
    fn disabled_without_a_runner() {
        let mut s = Session::virtual_lab();
        let e = s
            .execute("tool.ping.start", &json!({"address": "127.0.0.1"}))
            .unwrap_err();
        assert!(e.to_string().contains("disabled"), "{e}");
    }
}
