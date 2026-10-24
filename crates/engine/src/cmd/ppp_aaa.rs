//! `/ppp aaa` (G4.3j, RouterOS v7): whether PPP asks `/radius`
//! (service=ppp) and how it accounts. The PPP server (G4.3d) and the
//! daemon's `radius` service read it from the running config.

use corerouter_model::ppp::{MAX_INTERIM, PppAaa};
use corerouter_model::radius::AaaService;
use serde_json::{Value, json};

use super::args::{opt_bool, opt_u32};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!("ppp.aaa.set", "PPP AAA", [], None,
        "{use_radius?: bool (default no), accounting?: bool (default yes), interim_update?: int 0|60..86400 (s; 0 = only Acct-Interim-Interval from the server), interim_jitter?: int 0..50 (% of the interval, default 20), use_circuit_id_in_nas_port_id?: bool, enable_ipv6_accounting?: bool} → {use_radius, accounting, interim_update, interim_jitter, use_circuit_id_in_nas_port_id, enable_ipv6_accounting, warning?}",
        always, set),
    cmd!(query "ppp.aaa.get", "PPP AAA", ["PPP"], None,
        "{} → {use_radius, accounting, interim_update, interim_jitter, use_circuit_id_in_nas_port_id, enable_ipv6_accounting, radius_servers (enabled /radius entries with service=ppp)}",
        always, get),
];

fn settings(a: &PppAaa) -> Value {
    json!({
        "use_radius": a.use_radius,
        "accounting": a.accounting,
        "interim_update": a.interim_update,
        "interim_jitter": a.interim_jitter,
        "use_circuit_id_in_nas_port_id": a.use_circuit_id_in_nas_port_id,
        "enable_ipv6_accounting": a.enable_ipv6_accounting,
    })
}

fn ppp_servers(s: &Session) -> usize {
    s.store()
        .candidate()
        .radius
        .servers
        .iter()
        .filter(|e| e.serves(AaaService::Ppp))
        .count()
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let mut a = s.store().candidate().ppp.aaa.clone();
    for (key, slot) in [
        ("use_radius", &mut a.use_radius),
        ("accounting", &mut a.accounting),
        ("use_circuit_id_in_nas_port_id", &mut a.use_circuit_id_in_nas_port_id),
        ("enable_ipv6_accounting", &mut a.enable_ipv6_accounting),
    ] {
        if let Some(v) = opt_bool(p, key)? {
            *slot = v;
        }
    }
    if let Some(v) = opt_u32(p, "interim_update")? {
        // RFC 2869 §5.16: "MUST NOT" be smaller than 60.
        if v != 0 && !(60..=MAX_INTERIM).contains(&v) {
            return Err(EngineError::bad(
                "interim_update",
                format!("0 or 60..={MAX_INTERIM} seconds (RFC 2869 §5.16: at least 60)"),
            ));
        }
        a.interim_update = v;
    }
    if let Some(v) = opt_u32(p, "interim_jitter")? {
        let v = u8::try_from(v)
            .ok()
            .filter(|v| *v <= 50)
            .ok_or_else(|| EngineError::bad("interim_jitter", "must be 0..=50 (%)"))?;
        a.interim_jitter = v;
    }
    s.store_mut().candidate_mut().ppp.aaa = a.clone();
    let mut out = settings(&a);
    if a.use_radius
        && ppp_servers(s) == 0
        && let Some(o) = out.as_object_mut()
    {
        o.insert(
            "warning".into(),
            json!("use_radius=yes but no enabled /radius entry has service=ppp: radius.add address=… service=ppp secret=…"),
        );
    }
    Ok(out)
}

fn get(s: &mut Session, _: &Value) -> Result<Value> {
    let mut out = settings(&s.store().candidate().ppp.aaa);
    let n = ppp_servers(s);
    if let Some(o) = out.as_object_mut() {
        o.insert("radius_servers".into(), json!(n));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_get_and_rollback() {
        let mut s = Session::virtual_lab();
        let g = s.execute("ppp.aaa.get", &json!({})).unwrap();
        assert_eq!(g["use_radius"], false);
        assert_eq!(g["accounting"], true);
        assert_eq!(g["interim_update"], 0);
        let r = s.execute("ppp.aaa.set", &json!({"use_radius": true, "interim_update": 300})).unwrap();
        assert!(r["warning"].is_string(), "{r}");
        s.execute("radius.add", &json!({"address": "10.0.0.1", "service": "ppp", "secret": "x"})).unwrap();
        let r = s.execute("ppp.aaa.set", &json!({"interim_jitter": 10})).unwrap();
        assert!(r.get("warning").is_none(), "{r}");
        assert_eq!(s.execute("ppp.aaa.get", &json!({})).unwrap()["radius_servers"], 1);
        assert_eq!(s.store().running().ppp.aaa.interim_update, 300);
        s.execute("config.mode.set", &json!({"mode": "transactional"})).unwrap();
        s.execute("ppp.aaa.set", &json!({"accounting": false})).unwrap();
        s.execute("config.discard", &json!({})).unwrap();
        assert!(s.store().candidate().ppp.aaa.accounting);
    }

    #[test]
    fn bad_values_are_refused() {
        let mut s = Session::virtual_lab();
        for p in [
            json!({"interim_update": 30}),
            json!({"interim_update": 100_000}),
            json!({"interim_jitter": 51}),
            json!({"use_radius": "yes"}),
        ] {
            let err = s.execute("ppp.aaa.set", &p).unwrap_err();
            assert!(matches!(err, EngineError::BadParam { .. }), "{p}: {err}");
        }
    }
}
