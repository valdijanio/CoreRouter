//! Bandwidth alerts of `/tool graphing` (G4.5): "above X % of the link for
//! N minutes" goes to the log (topic `interface`, `warning`) when it starts
//! and when it ends. The rules are config; their state is `crate::graph::alert`.

use corerouter_model::graphing::{BandwidthAlert, Direction, MAX_ALERT_MINUTES, MAX_ALERTS};
use corerouter_model::{IfName, ItemId};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, opt_text, opt_u32, req_parse};
use super::{CommandSpec, always};
use crate::graph::GraphDb;
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "system.graph.alert.add",
        "Add Bandwidth Alert",
        [],
        None,
        "{interface: ifname, percent: int 1..100, minutes: int 1..1440, direction?: any|rx|tx, capacity_mbps?: int, comment?: string} → {id}",
        always,
        add
    ),
    cmd!(
        "system.graph.alert.set",
        "Bandwidth Alert",
        [],
        None,
        "{id: string, percent?: int 1..100, minutes?: int 1..1440, direction?: any|rx|tx, capacity_mbps?: int (0 = link speed), disabled?: bool, comment?: string} → {id}",
        always,
        set
    ),
    cmd!(
        "system.graph.alert.remove",
        "Remove Bandwidth Alert",
        [],
        None,
        "{id: string} → {removed}",
        always,
        remove
    ),
    cmd!(query "system.graph.alert.print", "Bandwidth Alerts", [], None,
        "{} → [{id, interface, direction, percent, minutes, capacity_mbps, disabled, comment, state: ok|alerting|unknown, since, last_percent, capacity_used_mbps, capacity_from, reason}]",
        always, print),
];

fn direction(p: &Value) -> Result<Option<Direction>> {
    Ok(match opt_str(p, "direction")? {
        None => None,
        Some("any") => Some(Direction::Any),
        Some("rx") => Some(Direction::Rx),
        Some("tx") => Some(Direction::Tx),
        Some(_) => return Err(EngineError::bad("direction", "any, rx or tx")),
    })
}

fn percent(p: &Value) -> Result<Option<u8>> {
    opt_u32(p, "percent")?
        .map(|v| {
            u8::try_from(v)
                .ok()
                .filter(|v| (1..=100).contains(v))
                .ok_or_else(|| EngineError::bad("percent", "must be 1..=100 (% of the link)"))
        })
        .transpose()
}

fn minutes(p: &Value) -> Result<Option<u32>> {
    opt_u32(p, "minutes")?
        .map(|v| {
            if (1..=MAX_ALERT_MINUTES).contains(&v) {
                Ok(v)
            } else {
                Err(EngineError::bad("minutes", format!("must be 1..={MAX_ALERT_MINUTES}")))
            }
        })
        .transpose()
}

fn find(s: &Session, id: ItemId) -> Result<usize> {
    s.store()
        .candidate()
        .system
        .graphing
        .alerts
        .iter()
        .position(|a| a.id == id)
        .ok_or_else(|| EngineError::bad("id", format!("no bandwidth alert {id} (system.graph.alert.print lists them)")))
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    let interface: IfName = req_parse(p, "interface")?;
    let percent = percent(p)?.ok_or_else(|| EngineError::bad("percent", "is required"))?;
    let minutes = minutes(p)?.ok_or_else(|| EngineError::bad("minutes", "is required"))?;
    let direction = direction(p)?.unwrap_or_default();
    let capacity_mbps = opt_u32(p, "capacity_mbps")?.filter(|c| *c > 0);
    let comment = opt_text(p, "comment", 256)?.unwrap_or_default();
    let cfg = s.store().candidate();
    let Some(iface) = cfg.interfaces.get(&interface) else {
        return Err(EngineError::bad(
            "interface",
            format!("no interface {interface} in the config"),
        ));
    };
    if !cfg.system.graphing.keeps(&interface, iface.kind.label()) {
        return Err(EngineError::bad(
            "interface",
            format!(
                "{interface} has no traffic history to judge: keep it first (system.graph.set include={interface})"
            ),
        ));
    }
    if cfg.system.graphing.alerts.len() >= MAX_ALERTS {
        return Err(EngineError::bad("interface", format!("at most {MAX_ALERTS} bandwidth alerts")));
    }
    let g = &mut s.store_mut().candidate_mut().system.graphing;
    let id = g.next_alert_id();
    g.alerts.push(BandwidthAlert {
        id,
        interface,
        direction,
        percent,
        minutes,
        capacity_mbps,
        disabled: false,
        comment,
    });
    Ok(json!({"id": id}))
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let id: ItemId = req_parse(p, "id")?;
    let i = find(s, id)?;
    let percent = percent(p)?;
    let minutes = minutes(p)?;
    let direction = direction(p)?;
    let capacity = opt_u32(p, "capacity_mbps")?;
    let disabled = opt_bool(p, "disabled")?;
    let comment = opt_text(p, "comment", 256)?;
    let alerts = &mut s.store_mut().candidate_mut().system.graphing.alerts;
    let Some(a) = alerts.get_mut(i) else {
        return Err(EngineError::bad("id", "gone"));
    };
    if let Some(v) = percent {
        a.percent = v;
    }
    if let Some(v) = minutes {
        a.minutes = v;
    }
    if let Some(v) = direction {
        a.direction = v;
    }
    if let Some(v) = capacity {
        a.capacity_mbps = (v > 0).then_some(v);
    }
    if let Some(v) = disabled {
        a.disabled = v;
    }
    if let Some(v) = comment {
        a.comment = v;
    }
    Ok(json!({"id": id}))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let id: ItemId = req_parse(p, "id")?;
    let i = find(s, id)?;
    s.store_mut().candidate_mut().system.graphing.alerts.remove(i);
    Ok(json!({"removed": id}))
}

fn print(s: &mut Session, _: &Value) -> Result<Value> {
    let db = s.ext::<GraphDb>();
    let rows: Vec<Value> = s
        .store()
        .candidate()
        .system
        .graphing
        .alerts
        .iter()
        .map(|a| {
            let st = db.and_then(|d| d.alert_state(a.id)).cloned().unwrap_or_default();
            json!({
                "id": a.id,
                "interface": a.interface,
                "direction": a.direction.as_str(),
                "percent": a.percent,
                "minutes": a.minutes,
                "capacity_mbps": a.capacity_mbps,
                "disabled": a.disabled,
                "comment": a.comment,
                "state": st.state,
                "since": st.since,
                "last_percent": st.last_percent,
                "capacity_used_mbps": st.capacity_mbps,
                "capacity_from": st.capacity_from,
                "reason": st.reason,
            })
        })
        .collect();
    Ok(Value::Array(rows))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::Session;

    const T0: u64 = 1_800_000_000;

    #[test]
    fn add_set_remove_and_refusals() {
        let mut s = Session::virtual_lab();
        let r = s
            .execute(
                "system.graph.alert.add",
                &json!({"interface": "ether1", "percent": 80, "minutes": 5}),
            )
            .unwrap();
        assert_eq!(r["id"], "*1");
        for bad in [
            json!({"interface": "ether1", "percent": 0, "minutes": 5}),
            json!({"interface": "ether1", "percent": 80, "minutes": 0}),
            json!({"interface": "ether1", "percent": 80, "minutes": 5, "direction": "up"}),
            json!({"interface": "nope0", "percent": 80, "minutes": 5}),
        ] {
            assert!(s.execute("system.graph.alert.add", &bad).is_err(), "{bad}");
        }
        s.execute("interface.vlan.add", &json!({"name": "v10", "parent": "ether1", "vlan_id": 10}))
            .unwrap();
        let err = s
            .execute("system.graph.alert.add", &json!({"interface": "v10", "percent": 80, "minutes": 5}))
            .unwrap_err()
            .to_string();
        assert!(err.contains("include=v10"), "{err}");
        s.execute("system.graph.alert.set", &json!({"id": "*1", "direction": "rx", "capacity_mbps": 100}))
            .unwrap();
        let p = s.execute("system.graph.alert.print", &json!({})).unwrap();
        assert_eq!(p[0]["direction"], "rx");
        assert_eq!(p[0]["capacity_mbps"], 100);
        assert!(s.execute("system.graph.alert.set", &json!({"id": "*9"})).is_err());
        s.execute("system.graph.alert.remove", &json!({"id": "*1"})).unwrap();
        assert_eq!(s.execute("system.graph.alert.print", &json!({})).unwrap(), json!([]));
    }

    #[test]
    fn a_busy_link_alerts_once_then_clears() {
        let mut s = Session::virtual_lab();
        // ether8 carries tens of Mbit/s in the lab: 1 Mbit/s of capacity
        // is far above 50 %.
        s.execute(
            "system.graph.alert.add",
            &json!({"interface": "ether8", "percent": 50, "minutes": 2, "capacity_mbps": 1}),
        )
        .unwrap();
        for t in 0..300 {
            s.tick(T0 + t);
        }
        let p = s.execute("system.graph.alert.print", &json!({})).unwrap();
        assert_eq!(p[0]["state"], "alerting", "{p}");
        assert_eq!(p[0]["capacity_from"], "rule");
        assert!(p[0]["last_percent"].as_f64().unwrap() > 50.0);
        let log = s.execute("log.print", &json!({})).unwrap().to_string();
        assert_eq!(log.matches("above for 2 min").count(), 1, "logged once: {log}");
        // The link goes quiet: the next closed minute is below, it ends.
        s.execute("interface.set", &json!({"name": "ether8", "disabled": true})).unwrap();
        for t in 300..450 {
            s.tick(T0 + t);
        }
        let p = s.execute("system.graph.alert.print", &json!({})).unwrap();
        assert_eq!(p[0]["state"], "ok", "{p}");
        let log = s.execute("log.print", &json!({})).unwrap().to_string();
        assert_eq!(log.matches("back below").count(), 1, "{log}");
        s.execute("system.graph.alert.set", &json!({"id": "*1", "disabled": true})).unwrap();
        s.tick(T0 + 451);
        let p = s.execute("system.graph.alert.print", &json!({})).unwrap();
        assert_eq!(p[0]["reason"], "disabled");
    }

    #[test]
    fn without_a_capacity_the_link_speed_is_used() {
        let mut s = Session::virtual_lab();
        s.execute("system.graph.alert.add", &json!({"interface": "ether1", "percent": 90, "minutes": 1}))
            .unwrap();
        for t in 0..130 {
            s.tick(T0 + t);
        }
        let p = s.execute("system.graph.alert.print", &json!({})).unwrap();
        assert_eq!(p[0]["capacity_from"], "link speed", "{p}");
        assert!(p[0]["capacity_used_mbps"].as_u64().unwrap() >= 1000);
        assert_eq!(p[0]["state"], "ok", "the lab is far below 90 % of its link");
    }
}
