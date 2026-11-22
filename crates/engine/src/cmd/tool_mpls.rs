//! /tool ping mpls, /tool traceroute mpls (G3.5b): LSP ping and
//! traceroute (RFC 8029). Tasks like the other tools: the command returns
//! the task id at once, results come from `tool.task.poll`. Operational
//! (`query`): no journal entry. See `docs/mpls.md`.

use std::net::IpAddr;
use std::time::Duration;

use corerouter_hal::lsp::wire::{Echo, Fec, HEADER_LEN};
use ipnet::IpNet;
use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, opt_u32, req_str};
use super::CommandSpec;
use crate::tools::lsp::{LspJob, Mode};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "tool.mpls.ping.start", "LSP Ping", ["Tools", "LSP Ping"], None,
        "{fec: string (prefix or address of the LSP's egress, e.g. 10.255.0.3/32), fec_type?: ldp|generic (default ldp; generic for a static LSP), count?: int 0..1000000 (default 5, 0 = until stopped), interval_ms?: int 100..60000 (default 1000), timeout_ms?: int 100..10000 (default 2000), size?: int 64..9000 (UDP payload, filled with a Pad TLV), ttl?: int 1..255 (top label TTL, default 255), exp?: int 0..7 (label traffic class), validate?: bool (default true: the LSRs check the FEC, V flag)} → {id, task_id, fec, columns}",
        can_start, ping_start)
    .alias("lsp-ping")
    .positional("fec")
    .task(),
    cmd!(query "tool.mpls.traceroute.start", "LSP Traceroute", ["Tools", "LSP Ping"], None,
        "{fec: string (prefix or address of the LSP's egress), fec_type?: ldp|generic (default ldp), max_hops?: int 1..64 (default 30), probes?: int 1..5 (tries per hop, default 1), timeout_ms?: int 100..10000 (default 2000), exp?: int 0..7, validate?: bool (default true)} → {id, task_id, fec, columns}",
        can_start, traceroute_start)
    .alias("lsp-traceroute")
    .positional("fec")
    .task(),
];

/// Disabled with the reason when no background task can run or the
/// backend cannot send MPLS echo requests.
fn can_start(s: &Session) -> std::result::Result<(), String> {
    crate::tasks::can_run(s)?;
    s.hal().lsp_prober().map(|_| ())
}

fn ranged(p: &Value, key: &str, lo: u32, hi: u32, default: u32) -> Result<u32> {
    let v = opt_u32(p, key)?.unwrap_or(default);
    if !(lo..=hi).contains(&v) {
        return Err(EngineError::bad(key, format!("must be {lo}..={hi}")));
    }
    Ok(v)
}

fn small<T: TryFrom<u32>>(key: &str, v: u32) -> Result<T> {
    T::try_from(v).map_err(|_| EngineError::bad(key, "out of range"))
}

/// `fec`: a prefix, or an address (a host route: LDP's FECs are the
/// routers' /32 and /128 loopbacks).
fn fec(p: &Value) -> Result<Fec> {
    let raw = req_str(p, "fec")?.trim();
    let shown: String = raw.chars().take(64).collect();
    let net: IpNet = match raw.parse::<IpNet>() {
        Ok(n) => n,
        Err(_) => match raw.parse::<IpAddr>() {
            Ok(a) => IpNet::from(a),
            Err(_) => {
                return Err(EngineError::bad(
                    "fec",
                    format!("'{shown}' is not a prefix or an IP address"),
                ));
            }
        },
    };
    let a = net.addr();
    let bad = match a {
        IpAddr::V4(v) => v.is_unspecified() && net.prefix_len() > 0 || v.is_loopback() || v.is_multicast() || v.is_broadcast(),
        IpAddr::V6(v) => v.is_loopback() || v.is_multicast() || (v.is_unspecified() && net.prefix_len() > 0),
    };
    if bad {
        return Err(EngineError::bad(
            "fec",
            format!("{shown}: a loopback, multicast or broadcast address has no LSP"),
        ));
    }
    let net = net.trunc();
    Ok(match opt_str(p, "fec_type")?.map(str::trim) {
        None | Some("" | "ldp") => Fec::Ldp(net),
        Some("generic") => Fec::Generic(net),
        Some(_) => return Err(EngineError::bad("fec_type", "must be ldp or generic")),
    })
}

/// The smallest request for `fec`: header + Target FEC Stack.
fn min_size(fec: &Fec) -> usize {
    corerouter_hal::lsp::wire::encode(&Echo::request(0, 0, vec![fec.clone()])).len().max(HEADER_LEN)
}

fn common(p: &Value) -> Result<(Fec, Duration, u8, bool)> {
    let fec = fec(p)?;
    let timeout = ranged(p, "timeout_ms", 100, 10_000, 2000)?;
    let exp = small::<u8>("exp", ranged(p, "exp", 0, 7, 0)?)?;
    let validate = opt_bool(p, "validate")?.unwrap_or(true);
    Ok((fec, Duration::from_millis(u64::from(timeout)), exp, validate))
}

fn title(verb: &str, fec: &Fec) -> String {
    format!(
        "{verb} {}",
        fec.prefix().map(|p| p.to_string()).unwrap_or_default()
    )
}

fn start(s: &mut Session, kind: &'static str, job: LspJob) -> Result<Value> {
    let prober = s.hal().lsp_prober().map_err(EngineError::Hal)?;
    let fec = job.fec.prefix().map(|p| p.to_string());
    let verb = if kind == "lsp-ping" { "lsp-ping" } else { "lsp-traceroute" };
    let title = title(verb, &job.fec);
    let id = s.start_task(kind, title, move |ctx| {
        crate::tools::lsp::run(job, prober.as_ref(), ctx)
    })?;
    let columns: &[&str] = if kind == "lsp-ping" {
        &["seq", "letter", "address", "rtt_ms", "code", "detail"]
    } else {
        &["hop", "letter", "address", "rtt_ms", "mtu", "out_label", "code", "detail"]
    };
    Ok(json!({"id": id, "task_id": id, "fec": fec, "columns": columns}))
}

fn ping_start(s: &mut Session, p: &Value) -> Result<Value> {
    let (fec, timeout, exp, validate) = common(p)?;
    let count = ranged(p, "count", 0, 1_000_000, 5)?;
    let interval = ranged(p, "interval_ms", 100, 60_000, 1000)?;
    let ttl = small::<u8>("ttl", ranged(p, "ttl", 1, 255, 255)?)?;
    let min = u32::try_from(min_size(&fec)).unwrap_or(u32::MAX);
    let size = ranged(p, "size", 64, 9000, min.max(64))?;
    let job = LspJob {
        fec,
        mode: Mode::Ping {
            count,
            interval: Duration::from_millis(u64::from(interval)),
        },
        timeout,
        size: small("size", size)?,
        ttl,
        exp,
        validate,
    };
    start(s, "lsp-ping", job)
}

fn traceroute_start(s: &mut Session, p: &Value) -> Result<Value> {
    let (fec, timeout, exp, validate) = common(p)?;
    let max_hops = small::<u8>("max_hops", ranged(p, "max_hops", 1, 64, 30)?)?;
    let probes = small::<u8>("probes", ranged(p, "probes", 1, 5, 1)?)?;
    let job = LspJob {
        fec,
        mode: Mode::Trace { max_hops, probes },
        timeout,
        size: 0,
        ttl: 255,
        exp,
        validate,
    };
    start(s, "lsp-traceroute", job)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tasks::test_runner;

    fn lab() -> Session {
        let mut s = Session::virtual_lab();
        s.set_runner(test_runner::sim());
        s
    }

    fn until_done(s: &mut Session, id: u64) -> Value {
        for _ in 0..500 {
            let p = s
                .execute("tool.task.poll", &json!({"id": id, "max": 256, "text": true}))
                .unwrap();
            if p["done"] == true {
                return p;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("task {id} did not finish");
    }

    #[test]
    fn lsp_ping_in_the_lab_reaches_the_egress() {
        let mut s = lab();
        let r = s
            .execute("tool.mpls.ping.start", &json!({"fec": "10.255.0.4", "count": 3, "interval_ms": 100}))
            .unwrap();
        assert_eq!(r["fec"], "10.255.0.4/32");
        let p = until_done(&mut s, r["id"].as_u64().unwrap());
        assert_eq!(p["kind"], "lsp-ping");
        let ev = p["events"].as_array().unwrap();
        assert_eq!(ev.len(), 3, "{p}");
        assert!(ev.iter().all(|e| e["code"] == 3 && e["letter"] == "!"), "{p}");
        let sum = &p["summary"];
        assert_eq!(sum["stats"]["received"], 3);
        assert_eq!(sum["path"]["out_label"], "1401");
        assert!(p["lines"][0].as_str().unwrap().contains("egress"), "{p}");
        assert!(p["summary_lines"][0].as_str().unwrap().contains("received=3"), "{p}");
    }

    #[test]
    fn lsp_traceroute_in_the_lab_lists_each_hop() {
        let mut s = lab();
        let r = s
            .execute("tool.mpls.traceroute.start", &json!({"fec": "10.255.0.4/32"}))
            .unwrap();
        let p = until_done(&mut s, r["id"].as_u64().unwrap());
        let ev = p["events"].as_array().unwrap();
        let hops: Vec<(u64, &str)> = ev
            .iter()
            .map(|e| (e["hop"].as_u64().unwrap(), e["status"].as_str().unwrap()))
            .collect();
        assert_eq!(hops, vec![(0, "local"), (1, "transit"), (2, "transit"), (3, "egress")], "{p}");
        assert_eq!(ev[1]["out_label"], "1402");
        assert_eq!(ev[2]["out_label"], "implicit-null");
        assert_eq!(p["summary"]["result"], "reached the egress at hop 3");
        // A broken LSP stops where it breaks, saying why.
        let r = s
            .execute("tool.mpls.traceroute.start", &json!({"fec": "10.255.9.9"}))
            .unwrap();
        let p = until_done(&mut s, r["id"].as_u64().unwrap());
        let last = p["events"].as_array().unwrap().last().unwrap().clone();
        assert_eq!((last["hop"].as_u64(), last["code"].as_u64(), last["letter"].as_str()), (Some(2), Some(11), Some("N")), "{p}");
    }

    #[test]
    fn a_fec_without_route_fails_the_task_with_the_reason() {
        let mut s = lab();
        let r = s
            .execute("tool.mpls.ping.start", &json!({"fec": "192.0.2.1/32"}))
            .unwrap();
        let p = until_done(&mut s, r["id"].as_u64().unwrap());
        assert_eq!(p["state"], "failed");
        assert!(p["reason"].as_str().unwrap().contains("no route"), "{p}");
    }

    #[test]
    fn bad_parameters_are_refused() {
        let mut s = lab();
        for bad in [
            json!({}),
            json!({"fec": "nonsense"}),
            json!({"fec": "127.0.0.1"}),
            json!({"fec": "224.0.0.5"}),
            json!({"fec": "10.0.0.1", "fec_type": "rsvp"}),
            json!({"fec": "10.0.0.1", "count": -1}),
            json!({"fec": "10.0.0.1", "ttl": 0}),
            json!({"fec": "10.0.0.1", "exp": 8}),
            json!({"fec": "10.0.0.1", "size": 10_000}),
            json!({"fec": "10.0.0.1", "timeout_ms": 5}),
            json!({"fec": "10.0.0.1", "bogus": 1}),
        ] {
            assert!(s.execute("tool.mpls.ping.start", &bad).is_err(), "accepted {bad}");
        }
        assert!(s.execute("tool.mpls.traceroute.start", &json!({"fec": "10.0.0.1", "max_hops": 65})).is_err());
        assert!(s.execute("tool.mpls.traceroute.start", &json!({"fec": "10.0.0.1", "probes": 6})).is_err());
    }

    #[test]
    fn disabled_without_a_runner() {
        let s = Session::virtual_lab();
        let spec = crate::cmd::find("tool.mpls.ping.start").unwrap();
        assert!((spec.enabled)(&s).is_err());
    }
}
