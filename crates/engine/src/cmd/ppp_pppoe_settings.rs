//! `/interface pppoe-server` settings of the service (G4.3g): how many
//! control-plane workers it runs. Not in RouterOS (its PPPoE runs in the
//! kernel); `auto` = the machine's CPUs minus two, at most 8.

use corerouter_model::ppp::{PPPOE_WORKERS_MAX, pppoe_workers_auto};
use serde_json::{Value, json};

use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!("interface.pppoe-server.settings.set", "PPPoE Settings", [], None,
        "{workers?: auto | int 1..64 (control-plane threads, each with its share of the sessions; read when the pppoe service starts)} → {workers, auto_workers, running, note}",
        always, set),
    cmd!(query "interface.pppoe-server.settings.get", "PPPoE Settings", [], None,
        "{} → {workers (auto or a number), auto_workers (what auto is on this machine), running (workers of the running service; 0: not running)}",
        always, get),
];

fn cpus() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
}

fn view(s: &Session) -> Value {
    let w = s.store().candidate().ppp.pppoe_workers;
    let running = s.ppp_backend().map_or(0, |b| b.stats().workers);
    json!({
        "workers": if w == 0 { json!("auto") } else { json!(w) },
        "auto_workers": pppoe_workers_auto(cpus()),
        "running": running,
    })
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    match p.get("workers") {
        None | Some(Value::Null) => {}
        Some(Value::String(t)) if t.trim() == "auto" => {
            s.store_mut().candidate_mut().ppp.pppoe_workers = 0;
        }
        Some(v) => {
            let n = v
                .as_u64()
                .filter(|n| (1..=u64::from(PPPOE_WORKERS_MAX)).contains(n))
                .ok_or_else(|| EngineError::bad("workers", format!("auto or 1..={PPPOE_WORKERS_MAX}")))?;
            s.store_mut().candidate_mut().ppp.pppoe_workers = u16::try_from(n).unwrap_or(1);
        }
    }
    let mut v = view(s);
    if let Some(o) = v.as_object_mut() {
        o.insert(
            "note".into(),
            json!("vale quando o serviço pppoe começar de novo (system.service.restart pppoe derruba as sessões)"),
        );
    }
    Ok(v)
}

fn get(s: &mut Session, _: &Value) -> Result<Value> {
    Ok(view(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workers_auto_or_a_number() {
        let mut s = Session::virtual_lab();
        let v = s.execute("interface.pppoe-server.settings.get", &json!({})).unwrap();
        assert_eq!(v["workers"], "auto");
        assert!(v["auto_workers"].as_u64().unwrap() >= 1);
        s.execute("interface.pppoe-server.settings.set", &json!({"workers": 4})).unwrap();
        assert_eq!(s.store().running().ppp.pppoe_workers, 4);
        for bad in [json!(0), json!(65), json!("many"), json!(-1)] {
            let e = s.execute("interface.pppoe-server.settings.set", &json!({"workers": bad})).unwrap_err();
            assert!(e.to_string().contains("workers"), "{e}");
        }
        assert_eq!(s.store().running().ppp.pppoe_workers, 4, "a refused value changes nothing");
        s.execute("interface.pppoe-server.settings.set", &json!({"workers": "auto"})).unwrap();
        assert_eq!(s.store().running().ppp.pppoe_workers, 0);
    }

    #[test]
    fn auto_leaves_two_cpus_and_stops_at_eight() {
        assert_eq!(pppoe_workers_auto(1), 1);
        assert_eq!(pppoe_workers_auto(4), 2);
        assert_eq!(pppoe_workers_auto(32), 8);
    }
}
