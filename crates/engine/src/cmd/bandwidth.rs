//! /tool bandwidth-test and /tool bandwidth-server (G6.4b): throughput
//! tests with the iperf3 protocol (`docs/tools.md` §4.6).
//!
//! A test is a task like ping (`tool.task.poll` / `tool.task.stop`). It
//! fills the path for its whole duration, so: at most
//! [`crate::bandwidth::MAX_DURATION`] seconds, and a test whose route
//! leaves through the port this connection uses is refused unless in Safe
//! Mode or with `force` (losing the management link to your own test is
//! the lockout the "risk" of the feature is about).

use std::net::IpAddr;

use corerouter_model::IfName;
use corerouter_model::bandwidth::{
    BandwidthServer, MAX_ALLOWED, MAX_DURATION as SERVER_MAX_DURATION, MAX_STREAMS,
};
use corerouter_proto_iperf::{
    DEFAULT_TCP_LEN, DEFAULT_UDP_LEN, Direction, MAX_TCP_LEN, MAX_UDP_LEN, MIN_UDP_LEN, Params,
    Proto,
};
use ipnet::IpNet;
use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, opt_u32, req_str};
use super::{CommandSpec, always};
use crate::bandwidth::{MAX_DURATION, SimBandwidth, TestRequest, run_job};
use crate::tasks::can_run;
use crate::{EngineError, Result, Session};

/// UDP rate when none is given (iperf3's own default, 1 Mbit/s, measures
/// nothing on a router's links).
pub const DEFAULT_UDP_RATE: u64 = 10_000_000;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "tool.bandwidth-test.start", "Bandwidth Test", ["Tools", "Bandwidth Test"], None,
        "{address: string (IP or DNS name of an iperf3 server), port?: int 1..65535 (default 5201), protocol?: tcp|udp (default tcp), direction?: send|receive|both (default send; transmit = send), streams?: int 1..128 (default 1), duration?: int 1..300 (s, default 10), bandwidth?: string|int (bit/s per stream, k/M/G; UDP default 10M, TCP default unlimited), length?: int (block bytes: TCP 1..1048576, UDP 16..65507), dscp?: int 0..63, force?: bool (test through the port of this connection outside Safe Mode)} → {id, task_id, columns, interface, warning}",
        can_run, start)
    .alias("bandwidth-test")
    .positional("address")
    .task(),
    cmd!(
        "tool.bandwidth-server.set",
        "Bandwidth Server",
        ["Tools", "Bandwidth Test"],
        None,
        "{enabled?: bool, port?: int 1..65535, allowed_addresses?: [string] (prefixes allowed to test; needed to enable; 0.0.0.0/0 = anyone), max_duration?: int 1..3600 (s), max_streams?: int 1..128, max_rate?: string|int (bit/s per test, k/M/G; 0 = no cap)} → {enabled, port, allowed_addresses, max_duration, max_streams, max_rate}",
        always,
        server_set
    ),
    cmd!(query "tool.bandwidth-server.get", "Bandwidth Server", [], None,
        "{} → {enabled, port, allowed_addresses, max_duration, max_streams, max_rate, status: {state, listening, tests_served, refused, current, last, last_error}}",
        always, server_get),
];

/// A rate: an integer (bit/s) or text with a k/M/G suffix (×1000, as
/// iperf3's `-b` and RouterOS).
pub fn rate(p: &Value, key: &str) -> Result<Option<u64>> {
    let text = match p.get(key) {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Number(n)) => {
            return n
                .as_u64()
                .map(Some)
                .ok_or_else(|| EngineError::bad(key, "must be a non-negative number of bit/s"));
        }
        Some(Value::String(s)) => s.trim().to_owned(),
        Some(_) => return Err(EngineError::bad(key, "must be bit/s, e.g. 100M")),
    };
    let lower = text.to_ascii_lowercase();
    let lower = lower.trim_end_matches("bps").trim_end_matches("bit/s");
    let (digits, mult) = match lower.chars().last() {
        Some('k') => (&lower[..lower.len() - 1], 1e3),
        Some('m') => (&lower[..lower.len() - 1], 1e6),
        Some('g') => (&lower[..lower.len() - 1], 1e9),
        _ => (lower, 1.0),
    };
    let v: f64 = digits.trim().parse().map_err(|_| {
        let shown: String = text.chars().take(24).collect();
        EngineError::bad(key, format!("'{shown}' is not a rate (e.g. 500k, 100M, 1G)"))
    })?;
    let total = v * mult;
    if !total.is_finite() || !(0.0..=1e12).contains(&total) {
        return Err(EngineError::bad(key, "must be 0..1T bit/s"));
    }
    Ok(Some(total.round() as u64))
}

fn ranged(p: &Value, key: &str, lo: u32, hi: u32) -> Result<Option<u32>> {
    match opt_u32(p, key)? {
        Some(v) if !(lo..=hi).contains(&v) => {
            Err(EngineError::bad(key, format!("must be {lo}..={hi}")))
        }
        v => Ok(v),
    }
}

/// `100.0 Mbit/s`, for messages.
fn rate_text(bps: u64) -> String {
    let b = bps as f64;
    if b >= 1e9 {
        format!("{:.1} Gbit/s", b / 1e9)
    } else if b >= 1e6 {
        format!("{:.1} Mbit/s", b / 1e6)
    } else {
        format!("{:.0} kbit/s", b / 1e3)
    }
}

/// The interface the route to `addr` leaves by, when the router knows.
fn egress(s: &mut Session, addr: IpAddr) -> Option<IfName> {
    super::route_lookup::run(s, &json!({"address": addr.to_string()}))
        .ok()?
        .get("interface")
        .and_then(Value::as_str)?
        .parse()
        .ok()
}

fn start(s: &mut Session, p: &Value) -> Result<Value> {
    let host = req_str(p, "address")?.trim().to_owned();
    let addr = host.parse::<IpAddr>().ok();
    if addr.is_none() && !super::tool::valid_name(&host) {
        let shown: String = host.chars().take(64).collect();
        return Err(EngineError::bad(
            "address",
            format!("'{shown}' is neither an IP address nor a DNS name"),
        ));
    }
    if addr.is_some_and(|a| a.is_unspecified() || a.is_multicast()) {
        return Err(EngineError::bad("address", "must be a unicast address"));
    }
    let port = ranged(p, "port", 1, 65_535)?.unwrap_or(5201);
    let proto = match opt_str(p, "protocol")?.map(str::trim) {
        None | Some("" | "tcp") => Proto::Tcp,
        Some("udp") => Proto::Udp,
        Some(_) => return Err(EngineError::bad("protocol", "must be tcp or udp")),
    };
    let direction = match opt_str(p, "direction")?.map(str::trim) {
        None | Some("" | "send" | "transmit" | "tx") => Direction::Send,
        Some("receive" | "rx") => Direction::Receive,
        Some("both") => Direction::Both,
        Some(_) => {
            return Err(EngineError::bad(
                "direction",
                "must be send, receive or both",
            ));
        }
    };
    let streams = ranged(p, "streams", 1, MAX_STREAMS)?.unwrap_or(1);
    let duration = ranged(p, "duration", 1, MAX_DURATION)?.unwrap_or(10);
    let bandwidth = match (proto, rate(p, "bandwidth")?) {
        (Proto::Udp, None | Some(0)) => DEFAULT_UDP_RATE,
        (_, b) => b.unwrap_or(0),
    };
    let len = match (proto, opt_u32(p, "length")?) {
        (Proto::Tcp, None) => DEFAULT_TCP_LEN,
        (Proto::Udp, None) => DEFAULT_UDP_LEN,
        (Proto::Tcp, Some(l)) if (1..=MAX_TCP_LEN).contains(&l) => l,
        (Proto::Udp, Some(l)) if (MIN_UDP_LEN..=MAX_UDP_LEN).contains(&l) => l,
        (Proto::Tcp, Some(_)) => return Err(EngineError::bad("length", format!("TCP: 1..={MAX_TCP_LEN}"))),
        (Proto::Udp, Some(_)) => {
            return Err(EngineError::bad("length", format!("UDP: {MIN_UDP_LEN}..={MAX_UDP_LEN}")));
        }
    };
    let dscp = ranged(p, "dscp", 0, 63)?.unwrap_or(0);
    let force = opt_bool(p, "force")?.unwrap_or(false);
    // The lockout guard: the route to the server and the port of this
    // connection (a name is checked once resolved; it cannot be here).
    let iface = addr.and_then(|a| egress(s, a));
    if let (Some(i), Some((from, ports))) = (&iface, super::ethernet::management_ports(s))
        && ports.contains(i)
        && !s.in_safe_mode()
        && !force
    {
        return Err(EngineError::bad(
            "address",
            format!(
                "the test leaves through {i}, which carries this connection (from {from}): \
                 filling it can cut you off. Enter Safe Mode first (config.safe-mode.enter), \
                 test another way, or pass force=yes"
            ),
        ));
    }
    let ways: u64 = if direction == Direction::Both { 2 } else { 1 };
    let load = if bandwidth == 0 {
        "as much as the path takes".to_owned()
    } else {
        rate_text(bandwidth.saturating_mul(u64::from(streams)).saturating_mul(ways))
    };
    let warning = format!(
        "fills the path with {load} for {duration} s{}",
        iface.as_ref().map(|i| format!(" through {i}")).unwrap_or_default()
    );
    let backend = s
        .bandwidth_backend()
        .unwrap_or_else(|| std::sync::Arc::new(SimBandwidth));
    let req = TestRequest {
        host: host.clone(),
        addr,
        port: u16::try_from(port).unwrap_or(5201),
        params: Params {
            proto,
            direction,
            time: duration,
            parallel: streams,
            len,
            bandwidth,
            tos: u8::try_from(dscp << 2).unwrap_or(0),
            get_server_output: true,
            ..Params::default()
        },
    };
    let id = s.start_task("bandwidth-test", format!("bandwidth-test {host}"), move |ctx| {
        run_job(req, backend, ctx)
    })?;
    Ok(json!({
        "id": id,
        "task_id": id,
        "columns": ["t", "tx_bps", "rx_bps", "lost", "jitter_ms", "cpu"],
        "interface": iface.map(|i| i.to_string()),
        "warning": warning,
    }))
}

fn settings_json(c: &BandwidthServer) -> Value {
    json!({
        "enabled": c.enabled,
        "port": c.port,
        "allowed_addresses": c.allowed_addresses.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "max_duration": c.max_duration,
        "max_streams": c.max_streams,
        "max_rate": c.max_rate,
    })
}

fn prefixes(p: &Value) -> Result<Option<Vec<IpNet>>> {
    let raw: Vec<String> = match p.get("allowed_addresses") {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) => s
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect(),
        Some(Value::Array(a)) => a
            .iter()
            .map(|v| {
                v.as_str().map(|s| s.trim().to_owned()).ok_or_else(|| {
                    EngineError::bad("allowed_addresses", "each item must be a prefix")
                })
            })
            .collect::<Result<_>>()?,
        Some(_) => return Err(EngineError::bad("allowed_addresses", "must be a list of prefixes")),
    };
    if raw.len() > MAX_ALLOWED {
        return Err(EngineError::bad(
            "allowed_addresses",
            format!("at most {MAX_ALLOWED} prefixes"),
        ));
    }
    let mut out: Vec<IpNet> = Vec::new();
    for r in raw {
        let net = match r.parse::<IpAddr>() {
            Ok(a) => IpNet::from(a),
            Err(_) => r.parse::<IpNet>().map(|n| n.trunc()).map_err(|_| {
                let shown: String = r.chars().take(48).collect();
                EngineError::bad("allowed_addresses", format!("'{shown}' is not a prefix"))
            })?,
        };
        if !out.contains(&net) {
            out.push(net);
        }
    }
    Ok(Some(out))
}

fn server_set(s: &mut Session, p: &Value) -> Result<Value> {
    let enabled = opt_bool(p, "enabled")?;
    let port = ranged(p, "port", 1, 65_535)?;
    let allowed = prefixes(p)?;
    let max_duration = ranged(p, "max_duration", 1, SERVER_MAX_DURATION)?;
    let max_streams = ranged(p, "max_streams", 1, MAX_STREAMS)?;
    let max_rate = rate(p, "max_rate")?;
    let mut c = s.store().candidate().system.bandwidth_server.clone();
    if let Some(e) = enabled {
        c.enabled = e;
    }
    if let Some(v) = port {
        c.port = u16::try_from(v).unwrap_or(c.port);
    }
    if let Some(v) = allowed {
        c.allowed_addresses = v;
    }
    if let Some(v) = max_duration {
        c.max_duration = v;
    }
    if let Some(v) = max_streams {
        c.max_streams = v;
    }
    if let Some(v) = max_rate {
        c.max_rate = v;
    }
    if c.enabled && c.allowed_addresses.is_empty() {
        return Err(EngineError::bad(
            "allowed_addresses",
            "an enabled bandwidth server needs the prefixes that may test \
             (e.g. 100.64.0.0/10; 0.0.0.0/0 and ::/0 for anyone)",
        ));
    }
    let out = settings_json(&c);
    s.store_mut().candidate_mut().system.bandwidth_server = c;
    Ok(out)
}

fn server_get(s: &mut Session, _: &Value) -> Result<Value> {
    let mut out = settings_json(&s.store().candidate().system.bandwidth_server);
    if let Value::Object(o) = &mut out {
        o.insert(
            "status".into(),
            serde_json::to_value(s.bandwidth_server_status()).unwrap_or(Value::Null),
        );
    }
    Ok(out)
}

/// Shared with the tests: waits for a task without a clock of its own.
#[cfg(test)]
fn until_done(s: &mut Session, id: u64) -> Value {
    for _ in 0..1000 {
        let p = s
            .execute("tool.task.poll", &json!({"id": id, "max": 256}))
            .unwrap();
        if p["done"] == true {
            return p;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    panic!("task {id} did not finish");
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

    #[test]
    fn rates_parse_like_iperf3() {
        let r = |v: Value| rate(&json!({"b": v}), "b");
        assert_eq!(r(json!("100M")).unwrap(), Some(100_000_000));
        assert_eq!(r(json!("1.5g")).unwrap(), Some(1_500_000_000));
        assert_eq!(r(json!("500kbps")).unwrap(), Some(500_000));
        assert_eq!(r(json!(64_000)).unwrap(), Some(64_000));
        assert!(r(json!("fast")).is_err());
        assert!(r(json!("-5M")).is_err());
        assert!(r(json!("9e20")).is_err());
        assert!(r(json!(true)).is_err());
    }

    #[test]
    fn a_simulated_test_in_the_lab() {
        let mut s = lab();
        let r = s
            .execute(
                "tool.bandwidth-test.start",
                &json!({"address": "192.0.2.10", "protocol": "udp", "direction": "both", "duration": 2, "bandwidth": "50M", "streams": 2}),
            )
            .unwrap();
        assert!(r["warning"].as_str().unwrap().contains("200.0 Mbit/s for 2 s"), "{r}");
        let p = until_done(&mut s, r["task_id"].as_u64().unwrap());
        assert_eq!(p["state"], "done", "{p}");
        assert_eq!(p["kind"], "bandwidth-test");
        let sum = &p["summary"];
        assert!(sum["backend"].as_str().unwrap().contains("simulated"));
        let up = sum["upload"]["received_bps"].as_f64().unwrap();
        assert!((95e6..105e6).contains(&up), "2 × 50M: {up}");
        assert_eq!(sum["download"]["loss_pct"], 0.0);
        assert_eq!(p["events"].as_array().unwrap().len(), 2);
        assert!(s.journal().is_empty(), "operational");
    }

    #[test]
    fn bad_tests_are_refused() {
        let mut s = lab();
        for p in [
            json!({}),
            json!({"address": "not a host!"}),
            json!({"address": "0.0.0.0"}),
            json!({"address": "10.0.0.1", "protocol": "sctp"}),
            json!({"address": "10.0.0.1", "direction": "sideways"}),
            json!({"address": "10.0.0.1", "streams": 0}),
            json!({"address": "10.0.0.1", "streams": 129}),
            json!({"address": "10.0.0.1", "duration": 301}),
            json!({"address": "10.0.0.1", "protocol": "udp", "length": 8}),
            json!({"address": "10.0.0.1", "length": 2_000_000}),
            json!({"address": "10.0.0.1", "dscp": 64}),
            json!({"address": "10.0.0.1", "bandwidth": "lots"}),
            json!({"address": "10.0.0.1", "port": 0}),
            json!({"address": "10.0.0.1", "extra": 1}),
        ] {
            assert!(s.execute("tool.bandwidth-test.start", &p).is_err(), "accepted {p}");
        }
        assert!(s.task_list().as_array().unwrap().is_empty());
    }

    #[test]
    fn server_settings_need_an_allow_list_to_enable() {
        let mut s = lab();
        let e = s
            .execute("tool.bandwidth-server.set", &json!({"enabled": true}))
            .unwrap_err();
        assert!(e.to_string().contains("allowed_addresses"), "{e}");
        let v = s
            .execute(
                "tool.bandwidth-server.set",
                &json!({"enabled": true, "allowed_addresses": "100.64.0.0/10, 192.168.88.7", "max_rate": "1G", "max_duration": 30}),
            )
            .unwrap();
        assert_eq!(v["allowed_addresses"], json!(["100.64.0.0/10", "192.168.88.7/32"]));
        assert_eq!(v["max_rate"], 1_000_000_000);
        let g = s.execute("tool.bandwidth-server.get", &json!({})).unwrap();
        assert_eq!(g["enabled"], true);
        assert_eq!(g["status"]["tests_served"], 0);
        assert!(!s.journal().is_empty(), "config: in the journal");
        // Rollback restores the default.
        let rev = s.store().current_revision();
        assert!(rev >= 1);
        for bad in [
            json!({"port": 70_000}),
            json!({"allowed_addresses": ["300.1.1.1/8"]}),
            json!({"max_streams": 0}),
            json!({"max_duration": 0}),
        ] {
            assert!(s.execute("tool.bandwidth-server.set", &bad).is_err(), "accepted {bad}");
        }
        s.execute("config.rollback", &json!({"revision": 0})).unwrap();
        assert!(s.store().running().system.bandwidth_server.is_default());
    }
}
