//! `/ip service metrics` (G4.4c): the Prometheus `/metrics` endpoint
//! as a service of the config, like RouterOS `/ip service` (on/off, port,
//! `available-from`). The daemon follows the running config, so a commit
//! opens, moves or closes the listener without a restart.

use corerouter_model::metrics::{MAX_AVAILABLE_FROM, MetricsService, MetricsStatus};
use ipnet::IpNet;
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_u32};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "ip.service.metrics.set",
        "Metrics Service",
        [],
        None,
        "{enabled?: bool, address?: ip, port?: int 1..65535, available_from?: [prefix]} → {enabled, address, port, available_from, warning?}",
        always,
        set
    ),
    cmd!(query "ip.service.metrics.get", "Metrics Service", [], None,
        "{} → {enabled, address, port, available_from, status: stopped|listening|error, listening, last_error, requests, refused}",
        always, get),
];

fn settings_json(c: &MetricsService) -> Value {
    json!({
        "enabled": c.enabled,
        "address": c.address,
        "port": c.port,
        "available_from": c.available_from,
    })
}

/// A JSON array of prefixes or, for the CLI, one comma-separated string.
/// A bare address is a host (`/32`, `/128`); host bits are cleared.
pub(super) fn available_from(p: &Value) -> Result<Option<Vec<IpNet>>> {
    const KEY: &str = "available_from";
    let raw: Vec<&str> = match p.get(KEY) {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) => s.split(',').map(str::trim).filter(|s| !s.is_empty()).collect(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::trim)
                    .ok_or_else(|| EngineError::bad(KEY, "each item must be a string"))
            })
            .collect::<Result<_>>()?,
        Some(_) => {
            return Err(EngineError::bad(
                KEY,
                "must be a list of prefixes, e.g. [\"192.0.2.0/24\", \"2001:db8::/32\"]",
            ));
        }
    };
    if raw.len() > MAX_AVAILABLE_FROM {
        return Err(EngineError::bad(
            KEY,
            format!("at most {MAX_AVAILABLE_FROM} prefixes"),
        ));
    }
    let mut out: Vec<IpNet> = Vec::new();
    for s in raw {
        let net = s
            .parse::<IpNet>()
            .or_else(|_| s.parse::<std::net::IpAddr>().map(IpNet::from))
            .map_err(|_| {
                EngineError::bad(
                    KEY,
                    format!(
                        "'{}' is not an address or prefix",
                        s.chars().take(64).collect::<String>()
                    ),
                )
            })?
            .trunc();
        if !out.contains(&net) {
            out.push(net);
        }
    }
    Ok(Some(out))
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let enabled = opt_bool(p, "enabled")?;
    let address = opt_parse::<std::net::IpAddr>(p, "address")?;
    let port = opt_u32(p, "port")?
        .map(|v| {
            u16::try_from(v)
                .ok()
                .filter(|v| *v != 0)
                .ok_or_else(|| EngineError::bad("port", "must be 1..=65535 (Prometheus' node_exporter uses 9100)"))
        })
        .transpose()?;
    let from = available_from(p)?;
    let mut c = s.store().candidate().system.metrics.clone();
    if let Some(e) = enabled {
        c.enabled = e;
    }
    if let Some(a) = address {
        if a.is_multicast() {
            return Err(EngineError::bad("address", "a multicast address cannot be listened on"));
        }
        c.address = a;
    }
    if let Some(port) = port {
        c.port = port;
    }
    if let Some(list) = from {
        c.available_from = list;
    }
    let mut out = settings_json(&c);
    // The endpoint has no login: say so when anyone on the network can read it.
    if c.enabled && !c.address.is_loopback() && c.available_from.is_empty()
        && let Some(o) = out.as_object_mut()
    {
        o.insert(
            "warning".into(),
            json!("metrics are readable without login from any network that reaches this address; \
                   set available_from (e.g. the Prometheus server's address)"),
        );
    }
    s.store_mut().candidate_mut().system.metrics = c;
    Ok(out)
}

fn get(s: &mut Session, _: &Value) -> Result<Value> {
    let mut out = settings_json(&s.store().candidate().system.metrics);
    let status = if s.store().running().system.metrics.enabled {
        s.ext::<MetricsStatus>().cloned().unwrap_or_default()
    } else {
        MetricsStatus::default()
    };
    let status = serde_json::to_value(status).unwrap_or(Value::Null);
    if let (Some(o), Value::Object(st)) = (out.as_object_mut(), status) {
        o.extend(st);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::Session;
    use corerouter_model::metrics::{MetricsState, MetricsStatus};

    #[test]
    fn set_changes_only_what_is_given() {
        let mut s = Session::virtual_lab();
        let r = s
            .execute(
                "ip.service.metrics.set",
                &json!({"enabled": true, "port": 9273, "available_from": "192.0.2.7, 2001:db8::/32"}),
            )
            .unwrap();
        assert_eq!(r["address"], "127.0.0.1");
        assert_eq!(r["available_from"], json!(["192.0.2.7/32", "2001:db8::/32"]));
        assert!(r.get("warning").is_none(), "loopback needs no warning");
        let g = s.execute("ip.service.metrics.get", &json!({})).unwrap();
        assert_eq!(g["enabled"], true);
        assert_eq!(g["port"], 9273);
        assert_eq!(g["status"], "stopped", "no daemon in the lab");
    }

    #[test]
    fn open_to_the_network_warns() {
        let mut s = Session::virtual_lab();
        let r = s
            .execute("ip.service.metrics.set", &json!({"enabled": true, "address": "0.0.0.0"}))
            .unwrap();
        assert!(r["warning"].as_str().unwrap().contains("available_from"));
        let r = s
            .execute("ip.service.metrics.set", &json!({"available_from": ["10.0.0.0/8"]}))
            .unwrap();
        assert!(r.get("warning").is_none());
    }

    #[test]
    fn bad_values_are_refused_and_nothing_changes() {
        let mut s = Session::virtual_lab();
        for (p, key) in [
            (json!({"port": 0}), "port"),
            (json!({"port": 70000}), "port"),
            (json!({"address": "nope"}), "address"),
            (json!({"address": "224.0.0.1"}), "address"),
            (json!({"available_from": ["10.0.0.0/33"]}), "available_from"),
            (json!({"available_from": 5}), "available_from"),
            (json!({"available_from": vec!["10.0.0.1"; 65]}), "available_from"),
            (json!({"enabled": "yes"}), "enabled"),
        ] {
            let e = s.execute("ip.service.metrics.set", &p).unwrap_err().to_string();
            assert!(e.contains(key), "{p}: {e}");
        }
        assert!(s.store().candidate().system.metrics.is_default());
    }

    #[test]
    fn rollback_restores_the_previous_service() {
        let mut s = Session::virtual_lab();
        s.execute("ip.service.metrics.set", &json!({"enabled": true}))
            .unwrap();
        let rev = s.store().current_revision();
        s.execute("ip.service.metrics.set", &json!({"port": 9999}))
            .unwrap();
        s.execute("config.rollback", &json!({"revision": rev})).unwrap();
        let m = &s.store().running().system.metrics;
        assert!(m.enabled);
        assert_eq!(m.port, 9100);
    }

    #[test]
    fn status_comes_from_the_daemon_only_while_enabled() {
        let mut s = Session::virtual_lab();
        if let Some(st) = s.ext_mut::<MetricsStatus>() {
            st.status = MetricsState::Listening;
            st.listening = Some("127.0.0.1:9100".into());
        }
        let g = s.execute("ip.service.metrics.get", &json!({})).unwrap();
        assert_eq!(g["status"], "stopped", "disabled in the running config");
        s.execute("ip.service.metrics.set", &json!({"enabled": true}))
            .unwrap();
        let g = s.execute("ip.service.metrics.get", &json!({})).unwrap();
        assert_eq!(g["status"], "listening");
        assert_eq!(g["listening"], "127.0.0.1:9100");
    }
}
