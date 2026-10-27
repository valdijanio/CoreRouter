//! /routing bgp session (G3.1): the sessions the routing daemons run, as
//! RouterOS v7 `/routing bgp session print` lists them, and the state of
//! the backend. Read from the last sample of the daemon's `frr` service
//! (never from FRR under the session lock): empty in the virtual lab.

use serde_json::{Value, json};

use super::args::opt_str;
use super::{CommandSpec, always};
use crate::{Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "routing.bgp.session.list", "BGP Sessions", ["Routing", "BGP"], None,
        "{instance?: string} → [{instance, vrf, remote_address, remote_as, local_as, remote_id, state, established, uptime_secs, prefix_count, prefix_sent, messages_received, messages_sent, reason, description}]",
        always, session_list),
    cmd!(query "routing.backend.get", "Routing Backend", ["Routing"], None,
        "{} → {backend, attached, updated, error, bgp_sessions}",
        always, backend_get),
];

fn session_list(s: &mut Session, p: &Value) -> Result<Value> {
    let instance = opt_str(p, "instance")?;
    let Some(status) = s.routing_status() else {
        return Ok(json!([]));
    };
    let rows: Vec<Value> = status
        .bgp_sessions
        .iter()
        .filter(|b| instance.is_none_or(|i| b.instance == i))
        .map(|b| serde_json::to_value(b).unwrap_or(Value::Null))
        .collect();
    Ok(Value::Array(rows))
}

fn backend_get(s: &mut Session, _: &Value) -> Result<Value> {
    let attached = s.has_routing();
    let status = s.routing_status().cloned().unwrap_or_default();
    Ok(json!({
        "backend": status.backend,
        "attached": attached,
        "updated": status.updated,
        "error": status.error,
        "bgp_sessions": status.bgp_sessions.len(),
    }))
}

#[cfg(test)]
mod tests {
    use corerouter_hal::VirtualHal;
    use corerouter_model::routing_state::{BgpSession, RoutingStatus};

    use super::*;

    #[test]
    fn lists_the_last_sample() {
        let mut s = Session::new(Box::new(VirtualHal::default()));
        assert_eq!(s.execute("routing.bgp.session.list", &json!({})).unwrap(), json!([]));
        let b = s.execute("routing.backend.get", &json!({})).unwrap();
        assert_eq!(b["attached"], false);
        let one = |instance: &str, addr: &str| BgpSession {
            instance: instance.into(),
            vrf: "default".into(),
            remote_address: addr.into(),
            remote_as: 65001,
            local_as: 65000,
            state: "established".into(),
            established: true,
            ..BgpSession::default()
        };
        s.set_routing_status(RoutingStatus {
            backend: "frr 10.7.1".into(),
            updated: Some(1),
            error: None,
            bgp_sessions: vec![one("default", "192.0.2.2"), one("lab", "192.0.2.6")],
        });
        let all = s.execute("routing.bgp.session.list", &json!({})).unwrap();
        assert_eq!(all.as_array().map(Vec::len), Some(2));
        let lab = s
            .execute("routing.bgp.session.list", &json!({"instance": "lab"}))
            .unwrap();
        assert_eq!(lab[0]["remote_address"], "192.0.2.6");
        assert_eq!(lab[0]["established"], true);
        let e = s
            .execute("routing.bgp.session.list", &json!({"instance": 3}))
            .unwrap_err();
        assert!(e.to_string().contains("instance"));
        let b = s.execute("routing.backend.get", &json!({})).unwrap();
        assert_eq!(b["backend"], "frr 10.7.1");
        assert_eq!(b["bgp_sessions"], 2);
    }
}
