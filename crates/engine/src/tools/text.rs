//! Task output as terminal text, RouterOS `/tool ping` style. Front ends
//! that print (the CLI's `watch`, the terminal of G0.8) share these, so a
//! ping looks the same everywhere:
//!
//! ```text
//!   SEQ HOST                                     SIZE TTL TIME       STATUS
//!     0 8.8.8.8                                    56 117 12.401ms
//!     1 8.8.8.8                                                      timeout
//!     sent=2 received=1 packet-loss=50% min-rtt=12.401ms avg-rtt=12.401ms max-rtt=12.401ms
//! ```

use serde_json::Value;

fn s(v: &Value, k: &str) -> String {
    match v.get(k) {
        Some(Value::String(x)) => x.clone(),
        Some(Value::Null) | None => String::new(),
        Some(x) => x.to_string(),
    }
}

fn time(v: &Value, k: &str) -> String {
    v.get(k)
        .and_then(Value::as_f64)
        .map(|ms| format!("{ms:.3}ms"))
        .unwrap_or_default()
}

/// Column header printed before the first event of `kind`.
pub fn header(kind: &str) -> Option<String> {
    match kind {
        "ping" => Some(format!(
            "{:>5} {:<40} {:>5} {:>3} {:<10} STATUS",
            "SEQ", "HOST", "SIZE", "TTL", "TIME"
        )),
        "mtu" => Some(format!(
            "{:>5} {:>7}  {:<10} STATUS",
            "SIZE", "PAYLOAD", "TIME"
        )),
        "mtr" => Some(format!(
            "{:>5} {:>3} {:<40} {:<10} STATUS",
            "ROUND", "HOP", "ADDRESS", "TIME"
        )),
        "cable-test" => Some(format!("{:<4} {:<20} DISTANCE", "PAIR", "STATUS")),
        "torch" => Some(super::torch::text_header()),
        "lsp-ping" | "lsp-traceroute" => super::lsp::text::header(kind),
        "bandwidth-test" => Some(format!(
            "{:>5} {:>12} {:>12} {:>8} {:>10} {:>6}",
            "TIME", "TX-RATE", "RX-RATE", "LOST", "JITTER", "CPU"
        )),
        "sniffer" => Some(format!("{:>5} {:>10} {:>12} {:>12}", "TIME", "PACKETS", "BYTES", "FILE-SIZE")),
        _ => None,
    }
}

/// One event as a line.
pub fn line(kind: &str, ev: &Value) -> String {
    match kind {
        "ping" => {
            let status = match s(ev, "status").as_str() {
                "ok" => String::new(),
                _ => {
                    let detail = s(ev, "detail");
                    let from = s(ev, "from");
                    let mut t = if detail.is_empty() {
                        s(ev, "status")
                    } else {
                        detail
                    };
                    if !from.is_empty() {
                        t = format!("{t} from {from}");
                    }
                    t
                }
            };
            let ok = s(ev, "status") == "ok";
            let host = s(ev, "address");
            let host = if host.is_empty() { s(ev, "host") } else { host };
            format!(
                "{:>5} {:<40} {:>5} {:>3} {:<10} {}",
                s(ev, "icmp_seq"),
                host,
                if ok { s(ev, "size") } else { String::new() },
                if ok { s(ev, "ttl") } else { String::new() },
                if ok {
                    time(ev, "rtt_ms")
                } else {
                    String::new()
                },
                status
            )
            .trim_end()
            .to_owned()
        }
        "mtu" => format!(
            "{:>5} {:>7}  {:<10} {}",
            s(ev, "size"),
            s(ev, "payload"),
            time(ev, "rtt_ms"),
            match s(ev, "mtu").as_str() {
                "" => s(ev, "status"),
                m => format!("{} (mtu {m})", s(ev, "status")),
            }
        )
        .trim_end()
        .to_owned(),
        "mtr" => format!(
            "{:>5} {:>3} {:<40} {:<10} {} {}",
            s(ev, "round"),
            s(ev, "hop"),
            s(ev, "address"),
            time(ev, "rtt_ms"),
            s(ev, "status"),
            ev.get("mpls")
                .and_then(Value::as_str)
                .map(|m| format!("MPLS {m}"))
                .unwrap_or_default()
        )
        .trim_end()
        .to_owned(),
        "cable-test" => format!(
            "{:<4} {:<20} {}",
            s(ev, "pair"),
            s(ev, "status"),
            ev.get("distance_m")
                .and_then(Value::as_f64)
                .map(|d| format!("{d:.1}m"))
                .unwrap_or_default()
        )
        .trim_end()
        .to_owned(),
        // G6.6: the `dig` text, or a compare/trace row (may be several lines).
        "dns-lookup" => crate::dns_lookup::text_line(ev),
        "torch" => super::torch::text_line(ev),
        // The table at the end is the output (`traceroute` prints per hop).
        "traceroute" => String::new(),
        "lsp-ping" | "lsp-traceroute" => super::lsp::text::line(kind, ev),
        "bandwidth-test" => {
            let f = |k: &str| ev.get(k).and_then(Value::as_f64);
            format!(
                "{:>4}s {:>12} {:>12} {:>8} {:>10} {:>6}",
                f("t").map_or(String::new(), |t| format!("{t:.0}")),
                super::torch::rate(f("tx_bps").unwrap_or(0.0)),
                super::torch::rate(f("rx_bps").unwrap_or(0.0)),
                s(ev, "lost"),
                f("jitter_ms").map_or(String::new(), |j| format!("{j:.3}ms")),
                f("cpu").map_or(String::new(), |c| format!("{c:.0}%")),
            )
        }
        "sniffer" => format!(
            "{:>4}s {:>10} {:>12} {:>12}",
            s(ev, "t"),
            s(ev, "packets"),
            s(ev, "bytes"),
            s(ev, "file_size")
        ),
        "dns-watch" => crate::dns_watch::text_line(ev),
        "dns-upstreams" => crate::dns_upstreams::text_line(ev),
        _ => ev.to_string(),
    }
}

/// The closing statistics, one line per target.
pub fn summary(kind: &str, summary: &Value) -> Vec<String> {
    match kind {
        "ping" => {
            let targets: Vec<&Value> = summary
                .get("targets")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .collect();
            let many = targets.len() > 1;
            targets
                .into_iter()
                .map(|t| {
                    let loss = t.get("loss_pct").and_then(Value::as_f64).unwrap_or(0.0);
                    let loss = if loss.fract() == 0.0 {
                        format!("{loss:.0}")
                    } else {
                        format!("{loss:.1}")
                    };
                    let mut l = format!(
                        "{}sent={} received={} packet-loss={loss}%",
                        if many {
                            format!("{}: ", s(t, "host"))
                        } else {
                            String::new()
                        },
                        s(t, "sent"),
                        s(t, "received"),
                    );
                    if t.get("min_ms").is_some_and(Value::is_number) {
                        l.push_str(&format!(
                            " min-rtt={} avg-rtt={} max-rtt={}",
                            time(t, "min_ms"),
                            time(t, "avg_ms"),
                            time(t, "max_ms"),
                        ));
                        if t.get("jitter_ms").is_some_and(Value::is_number) {
                            l.push_str(&format!(" jitter={}", time(t, "jitter_ms")));
                        }
                    }
                    let err = s(t, "error");
                    if !err.is_empty() {
                        l.push_str(&format!(" error: {err}"));
                    }
                    l
                })
                .collect()
        }
        // RouterOS: `cable-pairs: open:4,open:4,open:4,open:4`.
        "cable-test" => vec![format!(
            "{}: {} cable-pairs: {}",
            s(summary, "name"),
            s(summary, "status"),
            s(summary, "cable_pairs")
        )],
        "mtu" => vec![match summary.get("mtu").and_then(Value::as_u64) {
            Some(m) => format!(
                "{}: path MTU {m} bytes (ICMP payload {}), {} probes",
                s(summary, "address"),
                s(summary, "payload"),
                s(summary, "probes")
            ),
            None => format!("{}: no MTU found", s(summary, "address")),
        }],
        "mtr" => {
            let asn = summary.get("as_lookup").and_then(Value::as_bool) == Some(true);
            let mut out = vec![
                format!(
                    "{:>3} {:<40} {:>6} {:>5} {:>9} {:>9} {:>9} {:>9} {:>9} {}",
                    "HOP",
                    "HOST",
                    "LOSS%",
                    "SENT",
                    "LAST",
                    "AVG",
                    "BEST",
                    "WORST",
                    "STDEV",
                    if asn { "ASN" } else { "" }
                )
                .trim_end()
                .to_owned(),
            ];
            let num = |t: &Value, k: &str| {
                t.get(k)
                    .and_then(Value::as_f64)
                    .map(|x| format!("{x:.2}"))
                    .unwrap_or_else(|| "-".into())
            };
            for h in summary
                .get("hops")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                // mtr -b: the name and the address; marks for addresses
                // that mean nothing outside their network.
                let mut host = match (s(h, "host").as_str(), s(h, "name").as_str()) {
                    ("", _) => "???".to_owned(),
                    (ip, "") => ip.to_owned(),
                    (ip, name) => format!("{name} ({ip})"),
                };
                if let Some(scope) = h.get("scope").and_then(Value::as_str) {
                    host = format!("{host} [{scope}]");
                }
                let as_text = match (h.get("asn").and_then(Value::as_u64), s(h, "as_name")) {
                    (Some(n), name)
                        if !name.is_empty() && !name.eq_ignore_ascii_case(&format!("AS{n}")) =>
                    {
                        format!("AS{n} {name}")
                    }
                    (Some(n), _) => format!("AS{n}"),
                    (None, _) if asn && !s(h, "host").is_empty() => "AS???".to_owned(),
                    (None, _) => String::new(),
                };
                out.push(format!(
                    "{:>3} {:<40} {:>6} {:>5} {:>9} {:>9} {:>9} {:>9} {:>9} {}",
                    s(h, "hop"),
                    host,
                    format!(
                        "{:.1}",
                        h.get("loss_pct").and_then(Value::as_f64).unwrap_or(0.0)
                    ),
                    s(h, "sent"),
                    num(h, "last_ms"),
                    num(h, "avg_ms"),
                    num(h, "best_ms"),
                    num(h, "worst_ms"),
                    num(h, "stddev_ms"),
                    as_text,
                ).trim_end().to_owned());
                // mtr -e: the label stack under the hop, top first.
                for l in h
                    .pointer("/hosts_info/0/mpls")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    out.push(format!(
                        "    MPLS L={} TC={} S={} TTL={}",
                        s(l, "label"),
                        s(l, "tc"),
                        u8::from(l.get("bottom").and_then(Value::as_bool) == Some(true)),
                        s(l, "ttl")
                    ));
                }
            }
            out
        }
        "dns-lookup" => crate::dns_lookup::summary_lines(summary),
        "torch" => Vec::new(),
        "traceroute" => traceroute_table(summary),
        "lsp-ping" | "lsp-traceroute" => super::lsp::text::summary(kind, summary),
        "bandwidth-test" => {
            let f = |v: &Value, k: &str| v.get(k).and_then(Value::as_f64);
            let mut out = Vec::new();
            for (name, way) in [("tx", "upload"), ("rx", "download")] {
                let Some(w) = summary.get(way).filter(|w| !w.is_null()) else {
                    continue;
                };
                let mut line = format!(
                    "{name}-total-average={} (sent {} received {} bytes)",
                    super::torch::rate(f(w, "received_bps").unwrap_or(0.0)),
                    s(w, "sent"),
                    s(w, "received"),
                );
                if let Some(l) = w.get("lost").filter(|l| !l.is_null()) {
                    line += &format!(" lost-packets={l} loss={}%", s(w, "loss_pct"));
                }
                if let Some(j) = f(w, "jitter_ms") {
                    line += &format!(" jitter={j:.3}ms");
                }
                if let Some(r) = w.get("retransmits").filter(|r| !r.is_null()) {
                    line += &format!(" retransmits={r}");
                }
                out.push(line);
            }
            out.push(format!(
                "cpu-load={}% (max {}%) remote-cpu-load={}%",
                s(summary, "cpu_avg"),
                s(summary, "cpu_max"),
                s(summary, "remote_cpu"),
            ));
            out
        }
        "sniffer" => vec![format!(
            "packets={} bytes={} file-size={} ({}): tool.sniffer.download id=<task>",
            s(summary, "packets"),
            s(summary, "bytes"),
            s(summary, "file_size"),
            s(summary, "end"),
        )],
        "dns-watch" => crate::dns_watch::summary_lines(summary),
        "dns-upstreams" => crate::dns_upstreams::summary_lines(summary),
        _ => vec![summary.to_string()],
    }
}

/// The classic `traceroute` output: one line per hop, its address(es),
/// name and AS, then each probe's RTT (`*` for none) and why it ended.
fn traceroute_table(summary: &Value) -> Vec<String> {
    let mut out = vec![format!(
        "traceroute to {} ({}), {} hops max, {}{}{}",
        s(summary, "host"),
        s(summary, "address"),
        s(summary, "max_hops"),
        s(summary, "protocol"),
        summary
            .get("port")
            .and_then(Value::as_u64)
            .map(|p| format!(" port {p}"))
            .unwrap_or_default(),
        if summary.get("paris").and_then(Value::as_bool) == Some(true) { ", paris" } else { "" },
    )];
    for h in summary.get("hops").and_then(Value::as_array).into_iter().flatten() {
        let hosts: Vec<String> = h
            .get("hosts_info")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|x| {
                let ip = s(x, "address");
                let mut t = match x.get("name").and_then(Value::as_str) {
                    Some(n) => format!("{n} ({ip})"),
                    None => ip,
                };
                if let Some(a) = x.get("asn").and_then(Value::as_u64) {
                    t += &format!(" [AS{a}]");
                }
                if let Some(m) = x.get("mpls_text").and_then(Value::as_str) {
                    t += &format!(" <MPLS {m}>");
                }
                t
            })
            .collect();
        let rtts: Vec<String> = h
            .get("rtts")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|r| r.as_f64().map_or_else(|| "*".to_owned(), |ms| format!("{ms:.3} ms")))
            .collect();
        let note = match h.get("note").and_then(Value::as_str) {
            Some("host unreachable") => " !H",
            Some("network unreachable") => " !N",
            Some("protocol unreachable") => " !P",
            Some("fragmentation needed") => " !F",
            Some(n) if n.contains("prohibited") => " !X",
            _ => "",
        };
        let who = if hosts.is_empty() { String::new() } else { format!("{}  ", hosts.join(" / ")) };
        out.push(format!("{:>2}  {who}{}{note}", s(h, "hop"), rtts.join("  ")).trim_end().to_owned());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ping_lines_look_like_routeros() {
        let ok = json!({"icmp_seq": 0, "address": "8.8.8.8", "size": 56, "ttl": 117,
            "rtt_ms": 12.4011, "status": "ok"});
        let l = line("ping", &ok);
        assert!(l.starts_with("    0 8.8.8.8"), "{l}");
        assert!(l.ends_with("56 117 12.401ms"), "{l}");
        let to = json!({"icmp_seq": 1, "address": "8.8.8.8", "status": "timeout"});
        assert!(line("ping", &to).ends_with("timeout"));
        let te = json!({"icmp_seq": 2, "address": "8.8.8.8", "status": "ttl-exceeded",
            "detail": "TTL exceeded", "from": "10.0.0.1"});
        assert!(line("ping", &te).ends_with("TTL exceeded from 10.0.0.1"));
        let sum = summary(
            "ping",
            &json!({"targets": [{"host": "8.8.8.8", "sent": 2, "received": 1,
                "loss_pct": 50.0, "min_ms": 1.0, "avg_ms": 1.0, "max_ms": 1.0, "jitter_ms": null}]}),
        );
        assert_eq!(
            sum[0],
            "sent=2 received=1 packet-loss=50% min-rtt=1.000ms avg-rtt=1.000ms max-rtt=1.000ms"
        );
        let two = summary(
            "ping",
            &json!({"targets": [{"host": "a", "sent": 3, "received": 2, "loss_pct": 33.333},
                {"host": "b", "sent": 3, "received": 3, "loss_pct": 0.0}]}),
        );
        assert_eq!(two[0], "a: sent=3 received=2 packet-loss=33.3%");
        assert_eq!(two[1], "b: sent=3 received=3 packet-loss=0%");
        assert!(header("ping").unwrap().contains("STATUS"));
    }

    #[test]
    fn mtr_table() {
        let t = summary(
            "mtr",
            &json!({"hops": [{"hop": 1, "host": "10.0.0.1", "loss_pct": 0.0, "sent": 3,
                "last_ms": 1.0, "avg_ms": 1.0, "best_ms": 1.0, "worst_ms": 1.0, "stddev_ms": 0.0},
                {"hop": 2, "host": null, "loss_pct": 100.0, "sent": 3}]}),
        );
        assert!(t[0].contains("WORST"));
        assert!(header("mtr").unwrap().contains("HOP"));
        assert!(t[1].contains("10.0.0.1"));
        assert!(t[2].contains("???") && t[2].contains("100.0"));
    }

    #[test]
    fn mtr_table_with_names_as_numbers_and_labels() {
        let t = summary(
            "mtr",
            &json!({"as_lookup": true, "hops": [
                {"hop": 1, "host": "10.0.0.1", "scope": "private", "loss_pct": 0.0, "sent": 1},
                {"hop": 2, "host": "4.69.1.1", "name": "ae1.core.example", "asn": 3356,
                 "as_name": "LEVEL3", "loss_pct": 0.0, "sent": 1,
                 "hosts_info": [{"mpls": [{"label": 24017, "tc": 0, "bottom": true, "ttl": 1}]}]},
                {"hop": 3, "host": "4.69.1.2", "loss_pct": 0.0, "sent": 1}]}),
        );
        assert!(t[0].ends_with("ASN"), "{}", t[0]);
        assert!(t[1].contains("10.0.0.1 [private]"), "{}", t[1]);
        assert!(t[2].contains("ae1.core.example (4.69.1.1)") && t[2].ends_with("AS3356 LEVEL3"));
        assert_eq!(t[3], "    MPLS L=24017 TC=0 S=1 TTL=1");
        assert!(t[4].ends_with("AS???"));
        let l = line("mtr", &json!({"round": 1, "hop": 2, "address": "4.69.1.1", "rtt_ms": 1.0, "status": "ttl-exceeded", "mpls": "L=24017"}));
        assert!(l.ends_with("ttl-exceeded MPLS L=24017"), "{l}");
    }

    #[test]
    fn mtu_lines() {
        let l = line(
            "mtu",
            &json!({"size": 1501, "payload": 1473, "status": "too-big", "mtu": 1500}),
        );
        assert!(l.ends_with("too-big (mtu 1500)"), "{l}");
        let s = summary(
            "mtu",
            &json!({"address": "8.8.8.8", "mtu": 1500, "payload": 1472, "probes": 3}),
        );
        assert!(s[0].contains("path MTU 1500"));
    }
}

