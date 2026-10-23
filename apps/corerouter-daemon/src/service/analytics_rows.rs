//! Rows of the ClickHouse exporter (G4.4f) in `JSONEachRow`: one JSON
//! object per line, the column names of `docs/analytics.md`. Pure
//! functions, tested here; the service batches what they return.
//!
//! Why JSONEachRow and not RowBinary: the server matches columns by name
//! (a column added to the schema later, or one the operator dropped, does
//! not break the export with `input_format_skip_unknown_fields=1`), a
//! refused row can be read in the server's log, and gzip takes most of its
//! size back (docs/perf.md, G4.4f: rows/s and bytes per row, **medido**).

use std::net::IpAddr;

use corerouter_model::analytics::{FlowRecord, NatEvent};
use corerouter_model::logging::LogEvent;
use serde_json::{Value, json};

/// A log message or detail longer than this is cut (bytes).
pub(crate) const MAX_TEXT: usize = 4096;
/// Labels of one metric sample at most.
const MAX_LABELS: usize = 32;

/// Unix milliseconds as ClickHouse's `DateTime64(3)` text
/// (`2026-10-23 12:00:05.123`, read as UTC by the `'UTC'` column).
pub(crate) fn datetime(ms: u64) -> String {
    let secs = ms / 1000;
    let days = secs / 86_400;
    let rem = secs % 86_400;
    // Days to civil date (H. Hinnant's algorithm).
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}.{:03}",
        rem / 3600,
        rem / 60 % 60,
        rem % 60,
        ms % 1000
    )
}

/// An address for an `IPv6` column: IPv4 as `::ffff:a.b.c.d`.
pub(crate) fn ipv6(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().to_string(),
        IpAddr::V6(v6) => v6.to_string(),
    }
}

fn cut(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s.get(..end).unwrap_or_default()
}

/// One row as a line (`\n` ended).
fn line(v: &Value) -> Vec<u8> {
    let mut out = v.to_string().into_bytes();
    out.push(b'\n');
    out
}

/// Severity number of the OpenTelemetry log data model (DEBUG 5, INFO 9,
/// WARN 13, ERROR 17, FATAL 21) and the syslog severity (RFC 5424 §6.2.1)
/// of a RouterOS level.
fn severities(level: &str) -> (u8, u8) {
    match level {
        "debug" => (5, 7),
        "warning" => (13, 4),
        "error" => (17, 3),
        "critical" => (21, 2),
        _ => (9, 6),
    }
}

/// A log event of the router (G4.6d) as a row of `logs`. `now_ms` stands
/// in for an event logged before the clock was known (time 0).
pub(crate) fn log_row(router: &str, ev: &LogEvent, prefix: &str, now_ms: u64) -> Vec<u8> {
    let level = ev.level();
    let (number, priority) = severities(level);
    let topic = ev
        .topics
        .iter()
        .find(|t| !corerouter_model::logging::LEVELS.contains(&t.as_str()))
        .map_or("system", String::as_str);
    let message = if prefix.is_empty() {
        cut(&ev.message, MAX_TEXT).to_owned()
    } else {
        format!("{prefix} {}", cut(&ev.message, MAX_TEXT))
    };
    let detail = if ev.detail.is_null() {
        String::new()
    } else {
        let d = ev.detail.to_string();
        // A cut JSON is not JSON: say so instead.
        if d.len() > MAX_TEXT {
            json!({"truncated": true, "bytes": d.len()}).to_string()
        } else {
            d
        }
    };
    let ms = if ev.time == 0 { now_ms } else { ev.time.saturating_mul(1000) };
    line(&json!({
        "router": router,
        "time": datetime(ms),
        "seq": ev.seq,
        "severity": level,
        "severity_number": number,
        "priority": priority,
        "topic": topic,
        "topics": ev.topics,
        "origin": cut(&ev.origin, 256),
        "message": message,
        "detail": detail,
    }))
}

pub(crate) fn flow_row(router: &str, f: &FlowRecord) -> Vec<u8> {
    let unspecified = IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED);
    line(&json!({
        "router": router,
        "time": datetime(f.end_ms),
        "time_start": datetime(f.start_ms),
        "src_addr": ipv6(f.src_addr),
        "dst_addr": ipv6(f.dst_addr),
        "src_port": f.src_port,
        "dst_port": f.dst_port,
        "proto": f.proto,
        "in_if": cut(&f.in_if, 64),
        "out_if": cut(&f.out_if, 64),
        "bytes": f.bytes,
        "packets": f.packets,
        "tcp_flags": f.tcp_flags,
        "sampling_rate": f.sampling_rate.max(1),
        "nat_src_addr": ipv6(f.nat_src_addr.unwrap_or(unspecified)),
        "nat_src_port": f.nat_src_port.unwrap_or(0),
    }))
}

pub(crate) fn nat_row(router: &str, e: &NatEvent) -> Vec<u8> {
    let unspecified = IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED);
    line(&json!({
        "router": router,
        "time": datetime(e.time_ms),
        "event": cut(&e.event, 32),
        "proto": e.proto,
        "src_addr": ipv6(e.src_addr),
        "src_port": e.src_port,
        "nat_addr": ipv6(e.nat_addr),
        "nat_port": e.nat_port,
        "dst_addr": ipv6(e.dst_addr.unwrap_or(unspecified)),
        "dst_port": e.dst_port.unwrap_or(0),
        "port_start": e.port_start,
        "port_end": e.port_end,
    }))
}

/// Rows of `metrics` from a Prometheus text exposition (what `/metrics`
/// serves, `metrics::render`): one row per sample, the labels as a map.
/// Comments, malformed lines and values that are not finite are skipped.
pub(crate) fn metric_rows(router: &str, time_ms: u64, text: &str) -> Vec<Vec<u8>> {
    let time = datetime(time_ms);
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(sample)
        .map(|(name, labels, value)| {
            line(&json!({
                "router": router,
                "time": time,
                "name": name,
                "labels": labels,
                "value": value,
            }))
        })
        .collect()
}

/// Rows of `metrics` from the router's traffic history (G4.5, one closed
/// bucket of `GraphDb::export`): one row per value, named
/// `corerouter_<series>_<field>` (`corerouter_interface_rx_bps` with label
/// `interface`, `corerouter_system_cpu`), the bucket's maximum as
/// `…_max`. A value that is not a number (no sample in the bucket) is
/// skipped.
pub(crate) fn graph_rows(router: &str, row: &corerouter_engine::graph::ExportRow) -> Vec<Vec<u8>> {
    use corerouter_engine::graph::{INTERFACE, sources};
    let (key, start, avg, max) = row;
    let (series, labels) = match key.strip_prefix(INTERFACE) {
        Some(name) => ("interface", json!({ "interface": name })),
        None => (key.as_str(), json!({})),
    };
    let time = datetime(start.saturating_mul(1000));
    let mut out = Vec::new();
    for (i, src) in sources(key).iter().enumerate() {
        let values = [(avg.get(i), ""), (max.as_ref().and_then(|m| m.get(i)), "_max")];
        for (v, suffix) in values {
            let Some(v) = v.copied().filter(|v| v.is_finite()) else {
                continue;
            };
            out.push(line(&json!({
                "router": router,
                "time": time,
                "name": format!("corerouter_{series}_{}{suffix}", src.key),
                "labels": labels,
                "value": f64::from(v),
            })));
        }
    }
    out
}

/// `name{k="v",…} value [timestamp]`.
fn sample(l: &str) -> Option<(&str, serde_json::Map<String, Value>, f64)> {
    let name_end = l.find(['{', ' '])?;
    let name = l.get(..name_end)?;
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b':') {
        return None;
    }
    let mut rest = l.get(name_end..)?;
    let mut labels = serde_json::Map::new();
    if let Some(r) = rest.strip_prefix('{') {
        let mut chars = r.char_indices();
        let mut key = String::new();
        let mut value = String::new();
        let mut in_value = false;
        let mut escaped = false;
        let mut end = None;
        while let Some((i, c)) = chars.next() {
            if in_value {
                match (escaped, c) {
                    (true, 'n') => {
                        value.push('\n');
                        escaped = false;
                    }
                    (true, c) => {
                        value.push(c);
                        escaped = false;
                    }
                    (false, '\\') => escaped = true,
                    (false, '"') => {
                        in_value = false;
                        if labels.len() < MAX_LABELS {
                            labels.insert(std::mem::take(&mut key), Value::String(std::mem::take(&mut value)));
                        }
                        key.clear();
                    }
                    (false, c) => value.push(c),
                }
                continue;
            }
            match c {
                '}' => {
                    end = Some(i + 1);
                    break;
                }
                ',' | ' ' => {}
                '=' => {
                    if chars.next().map(|(_, c)| c) != Some('"') {
                        return None;
                    }
                    in_value = true;
                }
                c if c.is_ascii_alphanumeric() || c == '_' => key.push(c),
                _ => return None,
            }
        }
        rest = r.get(end?..)?;
    }
    let value: f64 = rest.split_whitespace().next()?.parse().ok()?;
    value.is_finite().then_some((name, labels, value))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(row: &[u8]) -> Value {
        assert_eq!(row.last(), Some(&b'\n'));
        serde_json::from_slice(row).unwrap()
    }

    #[test]
    fn datetime_is_utc_with_milliseconds() {
        assert_eq!(datetime(0), "1970-01-01 00:00:00.000");
        // 2026-10-23 12:34:56.789 UTC.
        assert_eq!(datetime(1_792_758_896_789), "2026-10-23 12:34:56.789");
        assert_eq!(datetime(951_782_400_000), "2000-02-29 00:00:00.000");
    }

    #[test]
    fn addresses_are_ipv6_with_mapped_ipv4() {
        assert_eq!(ipv6("100.64.1.2".parse().unwrap()), "::ffff:100.64.1.2");
        assert_eq!(ipv6("2001:db8::1".parse().unwrap()), "2001:db8::1");
    }

    #[test]
    fn a_log_event_has_every_column() {
        let ev = LogEvent {
            seq: 7,
            time: 1_792_758_896,
            topics: vec!["dhcp".into(), "warning".into()],
            origin: "daemon".into(),
            message: "conflito em 10.0.0.9".into(),
            detail: json!({"mac": "00:11:22:33:44:55"}),
        };
        let r = parse(&log_row("edge-1", &ev, "r1", 5));
        assert_eq!(r["router"], "edge-1");
        assert_eq!(r["time"], "2026-10-23 12:34:56.000");
        assert_eq!(r["severity"], "warning");
        assert_eq!(r["severity_number"], 13);
        assert_eq!(r["priority"], 4);
        assert_eq!(r["topic"], "dhcp");
        assert_eq!(r["topics"], json!(["dhcp", "warning"]));
        assert_eq!(r["message"], "r1 conflito em 10.0.0.9");
        assert_eq!(r["detail"], r#"{"mac":"00:11:22:33:44:55"}"#);
        // No clock yet: the exporter's time; huge detail: a note, still JSON.
        let ev = LogEvent { time: 0, detail: json!("x".repeat(MAX_TEXT + 1)), ..ev };
        let r = parse(&log_row("e", &ev, "", 1_000));
        assert_eq!(r["time"], "1970-01-01 00:00:01.000");
        let d: Value = serde_json::from_str(r["detail"].as_str().unwrap()).unwrap();
        assert_eq!(d["truncated"], true);
    }

    #[test]
    fn hostile_text_stays_one_json_line() {
        let ev = LogEvent {
            seq: 1,
            time: 1,
            topics: vec!["system".into()],
            origin: "a\"\n\u{0}".into(),
            message: format!("{}\n\"}}{{", "é".repeat(MAX_TEXT)),
            detail: Value::Null,
        };
        let row = log_row("r\n1", &ev, "", 0);
        assert_eq!(row.iter().filter(|b| **b == b'\n').count(), 1);
        let r = parse(&row);
        assert!(r["message"].as_str().unwrap().len() <= MAX_TEXT);
        assert_eq!(r["detail"], "");
    }

    #[test]
    fn prometheus_text_becomes_metric_rows() {
        let text = "# HELP x y\n# TYPE x counter\n\
                    corerouter_interface_receive_bytes_total{interface=\"ether1\"} 1234\n\
                    corerouter_safe_mode 0\n\
                    weird{a=\"q\\\"uote\\\\\",b=\"line\\nbreak\"} 1.5e3 1700000000\n\
                    nan_metric NaN\n\
                    broken{a=x} 1\n\
                    {nameless} 1\n";
        let rows: Vec<Value> = metric_rows("r", 0, text).iter().map(|r| parse(r)).collect();
        assert_eq!(rows.len(), 3, "{rows:?}");
        assert_eq!(rows[0]["name"], "corerouter_interface_receive_bytes_total");
        assert_eq!(rows[0]["labels"], json!({"interface": "ether1"}));
        assert_eq!(rows[0]["value"], 1234.0);
        assert_eq!(rows[1]["labels"], json!({}));
        assert_eq!(rows[2]["labels"], json!({"a": "q\"uote\\", "b": "line\nbreak"}));
        assert_eq!(rows[2]["value"], 1500.0);
    }

    #[test]
    fn graph_buckets_become_metric_rows() {
        let row: corerouter_engine::graph::ExportRow = (
            "interface:ether1".into(),
            1_792_758_840,
            vec![1e6, 2e6, 100.0, f32::NAN, 0.0, 0.0],
            Some(vec![3e6, 4e6, 150.0, f32::NAN, 1.0, 0.0]),
        );
        let rows: Vec<Value> = graph_rows("r", &row).iter().map(|r| parse(r)).collect();
        assert_eq!(rows.len(), 10, "NaN (no sample) skipped, avg and max of the rest");
        assert_eq!(rows[0]["name"], "corerouter_interface_rx_bps");
        assert_eq!(rows[0]["labels"], json!({"interface": "ether1"}));
        assert_eq!(rows[0]["time"], "2026-10-23 12:34:00.000");
        assert_eq!(rows[1]["name"], "corerouter_interface_rx_bps_max");
        assert_eq!(rows[1]["value"], 3e6);
        let sys: corerouter_engine::graph::ExportRow = ("system".into(), 60, vec![12.5, 1e9, 400.0], None);
        let rows: Vec<Value> = graph_rows("r", &sys).iter().map(|r| parse(r)).collect();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0]["name"], "corerouter_system_cpu");
        assert_eq!(rows[0]["labels"], json!({}));
    }

    #[test]
    fn flows_and_nat_events_fill_their_columns() {
        let f = FlowRecord {
            start_ms: 1000,
            end_ms: 2000,
            src_addr: "100.64.0.9".parse().unwrap(),
            dst_addr: "2001:db8::2".parse().unwrap(),
            src_port: 40000,
            dst_port: 443,
            proto: 6,
            in_if: "ether2".into(),
            out_if: "ether1".into(),
            bytes: 1500,
            packets: 3,
            tcp_flags: 0x12,
            sampling_rate: 0,
            nat_src_addr: Some("203.0.113.5".parse().unwrap()),
            nat_src_port: Some(1025),
        };
        let r = parse(&flow_row("r", &f));
        assert_eq!(r["src_addr"], "::ffff:100.64.0.9");
        assert_eq!(r["nat_src_addr"], "::ffff:203.0.113.5");
        assert_eq!(r["sampling_rate"], 1);
        assert_eq!(r["time_start"], "1970-01-01 00:00:01.000");
        let e = NatEvent {
            time_ms: 0,
            event: "block_alloc".into(),
            proto: 0,
            src_addr: "100.64.0.9".parse().unwrap(),
            src_port: 0,
            nat_addr: "203.0.113.5".parse().unwrap(),
            nat_port: 0,
            dst_addr: None,
            dst_port: None,
            port_start: 1024,
            port_end: 2047,
        };
        let r = parse(&nat_row("r", &e));
        assert_eq!(r["dst_addr"], "::");
        assert_eq!(r["port_end"], 2047);
    }
}
