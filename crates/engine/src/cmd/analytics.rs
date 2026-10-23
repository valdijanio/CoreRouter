//! `/system analytics` (G4.4f): where the ClickHouse exporter sends, with
//! which credentials, what, and how (batch, interval, queue). The daemon's
//! `analytics` service follows the running config and reports its status
//! here (`s.ext::<AnalyticsStatus>()`); the network is never touched from
//! the engine. Secrets (`password`, `private_key`) never come back: print
//! shows `***` when they are set, like an export of the audit.

use corerouter_model::analytics::{
    self as model, Analytics, AnalyticsStatus, BATCH_SIZE, Compression, DISK_QUEUE,
    FLUSH_INTERVAL, MAX_NAME, MAX_PASSWORD, MAX_PEM, MAX_URL, METRICS_INTERVAL, QUEUE_SIZE, Table,
    valid_identifier,
};
use serde_json::{Map, Value, json};

use super::args::{opt_bool, opt_str, opt_text, opt_u32};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "system.analytics.set",
        "Analytics",
        [],
        None,
        "{enabled?: bool, url?: string, database?: string, user?: string, password?: string, certificate?: string, private_key?: string, ca_certificate?: string, tls_verify?: bool, router_id?: string, metrics?: bool, logs?: bool, flows?: bool, nat_events?: bool, metrics_interval?: int 10..3600, batch_size?: int 100..1000000, flush_interval?: int 1..3600, queue_size?: int 1..1024, disk_queue?: int 0..65536, compression?: none|gzip} → {settings…, warning?}",
        always,
        set
    ),
    cmd!(query "system.analytics.print", "Analytics", [], None,
        "{} → {settings…, state: stopped|running|retrying|error, sent_rows, sent_batches, sent_bytes, queued_rows, queued_bytes, disk_rows, disk_bytes, dropped_rows, retries, tables, last_error, last_error_at, last_sent_at, retry_in, test}",
        always, print),
    cmd!(query "system.analytics.test", "Test Analytics Connection", [], None,
        "{} → {requested}",
        exporter_running, test),
    cmd!(query "system.analytics.schema", "Analytics Schema", [], None,
        "{database?: string, metrics_days?: int 1..36500, logs_days?: int 1..36500, flows_days?: int 1..36500, nat_events_days?: int 1..36500} → {database, sql}",
        always, schema),
];

/// The settings as print and set return them: secrets as `***` when set.
fn settings_json(a: &Analytics) -> Value {
    let secret = |v: &str| if v.is_empty() { json!("") } else { json!("***") };
    json!({
        "enabled": a.enabled,
        "url": a.url,
        "database": a.database,
        "user": a.user,
        "password": secret(&a.password),
        "certificate": a.certificate,
        "private_key": secret(&a.private_key),
        "ca_certificate": a.ca_certificate,
        "tls_verify": a.tls_verify,
        "router_id": a.router_id,
        "metrics": a.metrics,
        "logs": a.logs,
        "flows": a.flows,
        "nat_events": a.nat_events,
        "metrics_interval": a.metrics_interval,
        "batch_size": a.batch_size,
        "flush_interval": a.flush_interval,
        "queue_size": a.queue_size,
        "disk_queue": a.disk_queue,
        "compression": a.compression.as_str(),
    })
}

/// `http(s)://host[:port]` with an optional `/`: what the exporter
/// connects to. Returns whether it is TLS and the host.
pub fn check_url(url: &str) -> std::result::Result<(bool, String), String> {
    let shown: String = url.chars().take(64).collect();
    let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(format!(
            "'{shown}' must start with http:// or https:// (ClickHouse's HTTP interface: port 8123, 8443 with TLS)"
        ));
    };
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.is_empty()
        || authority.contains(['/', '?', '#', '@'])
        || authority.bytes().any(|b| b <= b' ' || b == 0x7f)
    {
        return Err(format!(
            "'{shown}': only scheme, host and port (user and password go in their own fields)"
        ));
    }
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (h, after) = v6
            .split_once(']')
            .ok_or_else(|| format!("'{shown}': bad [address]"))?;
        (h, after.strip_prefix(':'))
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        (h, Some(p))
    } else {
        (authority, None)
    };
    if let Some(p) = port
        && !p.parse::<u16>().is_ok_and(|p| p != 0)
    {
        return Err(format!("'{shown}': bad port"));
    }
    if host.is_empty() {
        return Err(format!("'{shown}' has no host"));
    }
    Ok((tls, host.to_ascii_lowercase()))
}

/// A PEM block of `kind` (`CERTIFICATE`, `PRIVATE KEY`), or "" to clear.
fn pem(p: &Value, key: &str, kinds: &[&str]) -> Result<Option<String>> {
    let Some(v) = opt_str(p, key)? else {
        return Ok(None);
    };
    let v = v.trim();
    if v.is_empty() {
        return Ok(Some(String::new()));
    }
    if v.len() > MAX_PEM {
        return Err(EngineError::bad(key, format!("at most {MAX_PEM} bytes")));
    }
    let ok = kinds
        .iter()
        .any(|k| v.contains(&format!("-----BEGIN {k}-----")) && v.contains(&format!("-----END {k}-----")));
    if !ok || v.chars().any(|c| c.is_control() && c != '\n' && c != '\r') {
        return Err(EngineError::bad(
            key,
            format!("must be PEM text (-----BEGIN {}-----)", kinds.first().copied().unwrap_or("")),
        ));
    }
    Ok(Some(format!("{v}\n")))
}

fn in_range(p: &Value, key: &str, range: std::ops::RangeInclusive<u32>) -> Result<Option<u32>> {
    opt_u32(p, key)?
        .map(|v| {
            if range.contains(&v) {
                Ok(v)
            } else {
                Err(EngineError::bad(
                    key,
                    format!("must be {}..={}", range.start(), range.end()),
                ))
            }
        })
        .transpose()
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let mut a = s.store().candidate().system.analytics.clone();
    if let Some(v) = opt_bool(p, "enabled")? {
        a.enabled = v;
    }
    if let Some(v) = opt_str(p, "url")? {
        let v = v.trim();
        if v.len() > MAX_URL {
            return Err(EngineError::bad("url", format!("at most {MAX_URL} characters")));
        }
        if !v.is_empty() {
            check_url(v).map_err(|e| EngineError::bad("url", e))?;
        }
        a.url = v.trim_end_matches('/').to_owned();
    }
    if let Some(v) = opt_str(p, "database")? {
        if !valid_identifier(v) {
            return Err(EngineError::bad(
                "database",
                format!("1..={MAX_NAME} letters, digits or '_', not starting with a digit"),
            ));
        }
        v.clone_into(&mut a.database);
    }
    if let Some(v) = opt_text(p, "user", MAX_NAME)? {
        if v.is_empty() || v.chars().any(char::is_whitespace) {
            return Err(EngineError::bad("user", "a ClickHouse user name, without spaces"));
        }
        a.user = v;
    }
    if let Some(v) = opt_text(p, "password", MAX_PASSWORD)? {
        a.password = v;
    }
    if let Some(v) = pem(p, "certificate", &["CERTIFICATE"])? {
        a.certificate = v;
    }
    if let Some(v) = pem(p, "private_key", &["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"])? {
        a.private_key = v;
    }
    if let Some(v) = pem(p, "ca_certificate", &["CERTIFICATE"])? {
        a.ca_certificate = v;
    }
    if let Some(v) = opt_bool(p, "tls_verify")? {
        a.tls_verify = v;
    }
    if let Some(v) = opt_text(p, "router_id", MAX_NAME)? {
        a.router_id = v.trim().to_owned();
    }
    for (key, slot) in [
        ("metrics", &mut a.metrics),
        ("logs", &mut a.logs),
        ("flows", &mut a.flows),
        ("nat_events", &mut a.nat_events),
    ] {
        if let Some(v) = opt_bool(p, key)? {
            *slot = v;
        }
    }
    if let Some(v) = in_range(p, "metrics_interval", METRICS_INTERVAL)? {
        a.metrics_interval = v;
    }
    if let Some(v) = in_range(p, "batch_size", BATCH_SIZE)? {
        a.batch_size = v;
    }
    if let Some(v) = in_range(p, "flush_interval", FLUSH_INTERVAL)? {
        a.flush_interval = v;
    }
    if let Some(v) = in_range(p, "queue_size", QUEUE_SIZE)? {
        a.queue_size = v;
    }
    if let Some(v) = in_range(p, "disk_queue", DISK_QUEUE)? {
        a.disk_queue = v;
    }
    if let Some(v) = opt_str(p, "compression")? {
        a.compression = match v {
            "none" => Compression::None,
            "gzip" => Compression::Gzip,
            _ => return Err(EngineError::bad("compression", "none or gzip")),
        };
    }
    // Checks across fields.
    if a.enabled && a.url.is_empty() {
        return Err(EngineError::bad(
            "url",
            "is required to enable the exporter (e.g. http://192.0.2.20:8123)",
        ));
    }
    if a.certificate.is_empty() != a.private_key.is_empty() {
        let missing = if a.certificate.is_empty() { "certificate" } else { "private_key" };
        return Err(EngineError::bad(
            missing,
            "certificate and private_key go together (ClickHouse's certificate login)",
        ));
    }
    let tls = check_url(&a.url).is_ok_and(|(tls, _)| tls);
    if !a.certificate.is_empty() && !a.url.is_empty() && !tls {
        return Err(EngineError::bad(
            "certificate",
            "a client certificate needs an https:// url",
        ));
    }
    let mut warnings = Vec::new();
    if a.enabled && !tls && !a.password.is_empty() {
        warnings.push(
            "the password crosses the network in clear text over http://; use https:// (port 8443) \
             unless the server is on a trusted management network",
        );
    }
    if a.enabled && tls && !a.tls_verify {
        warnings.push("tls_verify=no: anyone on the path can pose as the server and read the data");
    }
    if a.batch_size < 1000 && a.flush_interval < 5 {
        warnings.push(
            "small batches sent often make many parts on the server (ClickHouse: 'too many parts'); \
             ClickHouse recommends at least 1000 rows per insert and about one insert per second",
        );
    }
    let mut out = settings_json(&a);
    if !warnings.is_empty()
        && let Some(o) = out.as_object_mut()
    {
        o.insert("warning".into(), json!(warnings.join("; ")));
    }
    s.store_mut().candidate_mut().system.analytics = a;
    Ok(out)
}

fn print(s: &mut Session, _: &Value) -> Result<Value> {
    let mut out = settings_json(&s.store().candidate().system.analytics);
    let mut status = s.ext::<AnalyticsStatus>().cloned().unwrap_or_default();
    if !s.store().running().system.analytics.enabled {
        status.state = model::AnalyticsState::Stopped;
    }
    let status = serde_json::to_value(status).unwrap_or(Value::Null);
    if let (Some(o), Value::Object(st)) = (out.as_object_mut(), status) {
        o.extend(st);
    }
    Ok(out)
}

/// The daemon's exporter is there to run a test (not in the GUI's lab).
fn exporter_running(s: &Session) -> std::result::Result<(), String> {
    if s.ext::<AnalyticsStatus>().is_some_and(|st| st.exporter) {
        Ok(())
    } else {
        Err("no exporter runs here: the router's daemon runs it".into())
    }
}

fn test(s: &mut Session, _: &Value) -> Result<Value> {
    if s.store().running().system.analytics.url.is_empty() {
        return Err(EngineError::bad(
            "url",
            "no server to test: set url and commit first (system.analytics.set url=…)",
        ));
    }
    let Some(st) = s.ext_mut::<AnalyticsStatus>() else {
        return Err(EngineError::Internal("no status".into()));
    };
    st.test.requested = st.test.requested.saturating_add(1);
    Ok(json!({ "requested": st.test.requested }))
}

fn schema(s: &mut Session, p: &Value) -> Result<Value> {
    let database = match opt_str(p, "database")? {
        Some(d) if valid_identifier(d) => d.to_owned(),
        Some(_) => {
            return Err(EngineError::bad(
                "database",
                "letters, digits or '_', not starting with a digit",
            ));
        }
        None => s.store().candidate().system.analytics.database.clone(),
    };
    let mut days = Map::new();
    for t in Table::ALL {
        let key = format!("{}_days", t.name());
        if let Some(v) = in_range(p, &key, 1..=36_500)? {
            days.insert(t.name().to_owned(), json!(v));
        }
    }
    let ttl = |t: Table| {
        days.get(t.name())
            .and_then(Value::as_u64)
            .and_then(|v| u32::try_from(v).ok())
    };
    Ok(json!({ "database": database, "sql": model::schema(&database, ttl) }))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::Session;
    use corerouter_model::analytics::{AnalyticsState, AnalyticsStatus};

    #[test]
    fn set_validates_and_print_masks_secrets() {
        let mut s = Session::virtual_lab();
        let r = s
            .execute(
                "system.analytics.set",
                &json!({"url": "http://192.0.2.20:8123/", "password": "s3cret", "enabled": true}),
            )
            .unwrap();
        assert_eq!(r["url"], "http://192.0.2.20:8123");
        assert_eq!(r["password"], "***");
        assert!(r["warning"].as_str().unwrap().contains("clear text"), "{r}");
        let p = s.execute("system.analytics.print", &json!({})).unwrap();
        assert_eq!(p["password"], "***");
        assert_eq!(p["state"], "stopped", "no daemon: stopped");
        assert!(!p.to_string().contains("s3cret"));
        // The journal never has it either.
        let log = s.execute("log.print", &json!({})).unwrap().to_string();
        assert!(!log.contains("s3cret"), "{log}");
        assert_eq!(s.store().running().system.analytics.password, "s3cret");
    }

    #[test]
    fn bad_values_are_refused_and_change_nothing() {
        let mut s = Session::virtual_lab();
        for (p, key) in [
            (json!({"url": "ftp://x"}), "url"),
            (json!({"url": "http://u:p@host:8123"}), "url"),
            (json!({"url": "http://host:8123/db?x=1"}), "url"),
            (json!({"url": "http://host:99999"}), "url"),
            (json!({"database": "db; DROP TABLE x"}), "database"),
            (json!({"batch_size": 5}), "batch_size"),
            (json!({"queue_size": 0}), "queue_size"),
            (json!({"compression": "zstd"}), "compression"),
            (json!({"enabled": true}), "url"),
            (json!({"certificate": "not pem"}), "certificate"),
            (json!({"url": "https://h:8443", "certificate": "-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----"}), "private_key"),
        ] {
            let e = s.execute("system.analytics.set", &p).unwrap_err().to_string();
            assert!(e.contains(key), "{p}: {e}");
        }
        assert!(s.store().running().system.analytics.is_default());
    }

    #[test]
    fn a_rollback_restores_the_previous_settings() {
        let mut s = Session::virtual_lab();
        s.execute("system.analytics.set", &json!({"url": "https://ch.isp:8443", "enabled": true}))
            .unwrap();
        let rev = s.store().current_revision();
        s.execute("system.analytics.set", &json!({"enabled": false, "logs": false}))
            .unwrap();
        assert!(!s.store().running().system.analytics.logs);
        s.execute("config.rollback", &json!({"revision": rev})).unwrap();
        let a = &s.store().running().system.analytics;
        assert!(a.enabled && a.logs, "{a:?}");
    }

    #[test]
    fn test_needs_a_url_and_an_exporter() {
        let mut s = Session::virtual_lab();
        let e = s.execute("system.analytics.test", &json!({})).unwrap_err().to_string();
        assert!(e.contains("daemon"), "{e}");
        if let Some(st) = s.ext_mut::<AnalyticsStatus>() {
            st.exporter = true;
            st.state = AnalyticsState::Running;
        }
        let e = s.execute("system.analytics.test", &json!({})).unwrap_err().to_string();
        assert!(e.contains("url"), "{e}");
        s.execute("system.analytics.set", &json!({"url": "http://127.0.0.1:8123"}))
            .unwrap();
        let r = s.execute("system.analytics.test", &json!({})).unwrap();
        assert_eq!(r["requested"], 1);
        let p = s.execute("system.analytics.print", &json!({})).unwrap();
        assert_eq!(p["test"]["requested"], 1);
        assert_eq!(p["state"], "stopped", "disabled shows stopped");
    }

    #[test]
    fn schema_uses_the_database_and_days() {
        let mut s = Session::virtual_lab();
        let r = s
            .execute("system.analytics.schema", &json!({"database": "isp", "flows_days": 7}))
            .unwrap();
        let sql = r["sql"].as_str().unwrap();
        assert!(sql.contains("CREATE TABLE IF NOT EXISTS isp.flows"));
        assert!(sql.contains("INTERVAL 7 DAY"));
        assert!(s.execute("system.analytics.schema", &json!({"database": "a-b"})).is_err());
    }

    #[test]
    fn the_analytics_log_action_is_built_in() {
        let mut s = Session::virtual_lab();
        let list = s.execute("system.logging.action.list", &json!({})).unwrap();
        assert!(list.as_array().unwrap().iter().any(|a| a["target"] == "analytics"));
        s.execute("system.logging.add", &json!({"topics": ["info"], "action": "analytics"}))
            .unwrap();
        assert!(s.execute("system.logging.action.remove", &json!({"name": "analytics"})).is_err());
        assert!(
            s.execute("system.logging.action.add", &json!({"name": "analytics", "remote": "192.0.2.1"}))
                .is_err()
        );
        let topics = vec!["system".to_owned(), "info".to_owned()];
        assert!(s.store().running().system.logging.to_analytics(&topics).is_some());
    }
}
