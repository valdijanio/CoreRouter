//! One queue live (G4.9g): `queue.simple.stats` for the "Queue <name>"
//! modal (counters, rates, burst, at-limit, delay p95; `crate::queue_live`)
//! and `queue.simple.graph`, which keeps or stops the traffic history of
//! any queue — a fixed one by its own `graph`, a dynamic one by its name in
//! graphing's `queue_include`.

use corerouter_model::graphing::MAX_NAMES;
use serde_json::{Value, json};

use super::args::{opt_bool, opt_str};
use super::{CommandSpec, always};
use crate::graph::queue_key;
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "queue.simple.stats", "Simple Queue Statistics", [], None,
        "{id: *hex | ppp:<session> | dhcp:<address> | name, recent?: bool (also the samples kept: [[time, up_bps, down_bps, queued_us, drops]])} → {id, name, origin, dynamic, disabled, target, address?, interface?, queue, max_limit: [up, down], max_limit_text, burst_limit: [up, down], time, counted, running, note?, rate_bps: [up, down], bytes: [up, down], packets: [up, down], dropped: [up, down], queued_us: [up, down], pcq_queues, pps: [up, down] | null, drops_ps: [up, down] | null, queued_p95_us: [up, down], at_limit_s: [up, down], at_limit: [bool, bool], burst: [{state: off|ready|bursting|spent, average_bps?, threshold_bps?, limit_bps?, window_s?, known_s?, left_s?}] (up, down), samples, graph, series, kept, refused, recent?}",
        always, stats),
    cmd!("queue.simple.graph", "Simple Queue History", [], None,
        "{id: *hex | ppp:<session> | dhcp:<address> | name, graph: bool} → {id, name, graph, series}",
        always, graph),
];

fn id_of(p: &Value) -> Result<&str> {
    let raw = opt_str(p, "id")?.ok_or_else(|| EngineError::bad("id", "is required"))?;
    if raw.trim().is_empty() || raw.len() > 256 {
        return Err(EngineError::bad("id", "a queue id or name"));
    }
    Ok(raw)
}

fn stats(s: &mut Session, p: &Value) -> Result<Value> {
    let raw = id_of(p)?;
    let recent = opt_bool(p, "recent")?.unwrap_or(false);
    s.queue_stats(raw, recent)
}

fn graph(s: &mut Session, p: &Value) -> Result<Value> {
    let raw = id_of(p)?.trim().to_owned();
    let on = opt_bool(p, "graph")?.ok_or_else(|| EngineError::bad("graph", "is required (yes or no)"))?;
    // A fixed queue: its own flag, in the candidate.
    if !raw.starts_with("ppp:") && !raw.starts_with("dhcp") && !raw.starts_with('<')
        && let Ok(i) = super::queue_simple::index_of(s, &raw)
    {
        let simple = &mut s.store_mut().candidate_mut().queue.simple;
        let name = simple.update(i, |q| {
            q.graph = on;
            q.name.clone()
        });
        let name = name.ok_or_else(|| EngineError::bad("id", "gone"))?;
        let id = s.store().candidate().queue.simple.get(i).map(|q| q.id.to_string());
        return Ok(json!({"id": id, "name": name, "graph": on, "series": queue_key(&name)}));
    }
    // A dynamic one: marked by name (a session that logs in again keeps
    // its mark and its series).
    let stat = s.queue_stats(&raw, false)?;
    let name = stat.get("name").and_then(Value::as_str).unwrap_or_default().to_owned();
    let id = stat.get("id").cloned().unwrap_or(Value::Null);
    if stat.get("dynamic").and_then(Value::as_bool) != Some(true) {
        return Err(EngineError::bad("id", format!("no queue '{}'", crate::logging::cut(&raw, 64))));
    }
    let series = queue_key(&name);
    if on && series.is_none() {
        return Err(EngineError::bad("id", "the name is too long for a series (64 bytes with 'queue:')"));
    }
    let g = &mut s.store_mut().candidate_mut().system.graphing;
    let had = g.queue_include.iter().any(|n| *n == name);
    if on && !had {
        if g.queue_include.len() >= MAX_NAMES {
            return Err(EngineError::bad("graph", format!("at most {MAX_NAMES} marked queues (system.graph.set dynamic_queues keeps them all)")));
        }
        g.queue_include.push(name.clone());
    } else if !on && had {
        g.queue_include.retain(|n| *n != name);
    }
    Ok(json!({"id": id, "name": name, "graph": on, "series": series}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::queue::QueueStats;
    use corerouter_hal::queue::QueueCounters;

    const T0: u64 = 1_800_000_000;

    fn lab() -> Session {
        let mut s = Session::virtual_lab();
        s.tick(T0);
        s
    }

    fn ok(s: &mut Session, id: &str, p: Value) -> Value {
        s.execute(id, &p).unwrap_or_else(|e| panic!("{id} {p}: {e}"))
    }

    fn count(s: &mut Session, key: &str, c: QueueCounters) {
        s.ext_mut::<QueueStats>().unwrap().by_key.insert(key.into(), c);
    }

    #[test]
    fn stats_of_one_queue_and_its_watch() {
        let mut s = lab();
        let r = ok(&mut s, "queue.simple.add", json!({"name": "cam", "target": "10.0.1.5", "max_limit": "1M/2M", "burst_limit": "2M/4M", "burst_threshold": "1M/1500k", "burst_time": "8s"}));
        let key = r["id"].as_str().unwrap().to_owned();
        let st = ok(&mut s, "queue.simple.stats", json!({"id": "cam"}));
        assert_eq!(st["id"], key);
        assert_eq!(st["max_limit"], json!([1_000_000, 2_000_000]));
        assert_eq!(st["counted"], false, "the lab shapes nothing until the service runs");
        assert_eq!(st["graph"], true, "fixed queues keep a history by default");
        assert_eq!(st["series"], "queue:cam");
        assert_eq!(st["burst"][1]["state"], "ready");
        // Two seconds of counters: rates per second from the difference.
        let mut c = QueueCounters { rate_bps: [500_000, 1_950_000], packets: [100, 1000], dropped: [0, 10], queued_us: [0, 4000], ..QueueCounters::default() };
        count(&mut s, &key, c);
        ok(&mut s, "queue.simple.stats", json!({"id": key}));
        s.tick(T0 + 1);
        c.packets = [150, 1800];
        c.dropped = [0, 30];
        count(&mut s, &key, c);
        let st = ok(&mut s, "queue.simple.stats", json!({"id": key, "recent": true}));
        assert_eq!(st["counted"], true);
        assert_eq!(st["pps"], json!([50, 800]));
        assert_eq!(st["drops_ps"], json!([0, 20]));
        assert_eq!(st["at_limit_s"], json!([0, 1]), "1.95M of 2M is above 95 %");
        assert_eq!(st["at_limit"], json!([false, false]), "not yet for 10 s");
        assert_eq!(st["queued_p95_us"][1], 4000);
        assert_eq!(st["recent"].as_array().unwrap().len(), 1);
        // A second call in the same second takes no sample.
        let again = ok(&mut s, "queue.simple.stats", json!({"id": key}));
        assert_eq!(again["samples"], 1);
    }

    #[test]
    fn stats_refuse_what_is_not_a_queue_and_bound_the_watches() {
        let mut s = lab();
        for p in [json!({}), json!({"id": ""}), json!({"id": "nope"}), json!({"id": "*ff"}), json!({"id": "ppp:*1"}), json!({"id": "dhcp:10.0.0.9"}), json!({"id": "<pppoe-x>"}), json!({"id": 7})] {
            let err = s.execute("queue.simple.stats", &p).unwrap_err();
            assert!(matches!(err, EngineError::BadParam { .. }), "{p}: {err}");
        }
        for i in 0..crate::queue_live::MAX_WATCHED {
            ok(&mut s, "queue.simple.add", json!({"name": format!("q{i}"), "target": format!("10.1.{}.{}", i / 250, i % 250 + 1)}));
            ok(&mut s, "queue.simple.stats", json!({"id": format!("q{i}")}));
        }
        ok(&mut s, "queue.simple.add", json!({"name": "late", "target": "10.9.9.9"}));
        let err = s.execute("queue.simple.stats", &json!({"id": "late"})).unwrap_err();
        assert!(err.to_string().contains("busy"), "{err}");
        // Watches nobody asks for go away.
        s.tick(T0 + crate::queue_live::IDLE + 1);
        ok(&mut s, "queue.simple.stats", json!({"id": "late"}));
        assert_eq!(s.ext::<crate::queue_live::QueueWatch>().unwrap().len(), 1);
    }

    #[test]
    fn graph_flag_on_fixed_queues_with_rollback() {
        let mut s = lab();
        ok(&mut s, "queue.simple.add", json!({"name": "a", "target": "10.0.0.1", "graph": false}));
        assert!(!s.store().running().queue.simple.get(0).unwrap().graph);
        let l = ok(&mut s, "queue.simple.list", json!({}));
        assert_eq!(l["rows"][0]["graph"], false);
        let rev = s.store().history().last().map(|r| r.number).unwrap();
        let r = ok(&mut s, "queue.simple.graph", json!({"id": "a", "graph": true}));
        assert_eq!(r["series"], "queue:a");
        assert!(s.store().running().queue.simple.get(0).unwrap().graph);
        s.execute("config.rollback", &json!({"revision": rev})).unwrap();
        assert!(!s.store().running().queue.simple.get(0).unwrap().graph);
        // Transactional: nothing until the commit.
        s.execute("config.mode.set", &json!({"mode": "transactional"})).unwrap();
        ok(&mut s, "queue.simple.graph", json!({"id": "a", "graph": true}));
        assert!(!s.store().running().queue.simple.get(0).unwrap().graph);
        s.execute("config.discard", &json!({})).unwrap();
        assert!(!s.store().candidate().queue.simple.get(0).unwrap().graph);
        for p in [json!({"id": "a"}), json!({"id": "a", "graph": "maybe"}), json!({"id": "nope", "graph": true}), json!({"graph": true})] {
            let err = s.execute("queue.simple.graph", &p).unwrap_err();
            assert!(matches!(err, EngineError::BadParam { .. }), "{p}: {err}");
        }
        // The flag survives a save (default yes is not written).
        let text = serde_json::to_string(&s.store().candidate().queue.simple.get(0).unwrap()).unwrap();
        assert!(text.contains("\"graph\":false"), "{text}");
    }

    #[test]
    fn graphing_switches_for_queues() {
        let mut s = lab();
        let r = ok(&mut s, "system.graph.set", json!({"queues": false, "dynamic_queues": true, "queue_include": ["<pppoe-ana>", "dhcp-ds<pc1>"]}));
        assert_eq!(r["queues"], false);
        assert_eq!(r["queue_include"], json!(["<pppoe-ana>", "dhcp-ds<pc1>"]));
        let p = ok(&mut s, "system.graph.print", json!({}));
        assert_eq!(p["dynamic_queues"], true);
        assert!(p["queue_series_bytes"].as_u64().unwrap() > 0);
        let err = s.execute("system.graph.set", &json!({"queue_include": [""]})).unwrap_err();
        assert!(matches!(err, EngineError::BadParam { .. }), "{err}");
    }

    /// The `queue` service's round keeps the history of fixed queues with
    /// `graph`, drops it when the flag goes off (after the grace).
    #[test]
    fn queue_series_follow_the_flag() {
        let mut s = lab();
        let r = ok(&mut s, "queue.simple.add", json!({"name": "web", "target": "10.0.0.0/24", "max_limit": "10M/20M"}));
        ok(&mut s, "queue.simple.add", json!({"name": "off", "target": "10.0.1.0/24", "graph": false}));
        for t in 1..=5 {
            s.tick(T0 + t);
            s.queue_sync();
        }
        let _ = r;
        let db = s.ext::<crate::graph::GraphDb>().unwrap();
        assert!(db.get("queue:web").is_some());
        assert!(db.get("queue:off").is_none());
        let q = ok(&mut s, "system.graph.query", json!({"series": "queue:web", "range": 60, "stats": true}));
        let st = &q["series"][0]["stats"];
        let down = st["down_bps"]["max"].as_f64().unwrap();
        assert!(down > 0.0 && down <= 20e6, "the lab shaper counts up to max-limit: {q}");
        assert!(st["delay"].get("max").is_some(), "{q}");
        // The list's "near limit": the rate now at 90 % of max-limit or more.
        let l = ok(&mut s, "queue.simple.list", json!({}));
        let row = &l["rows"][0];
        let near = |i: usize| {
            let r = row["rate_bps"][i].as_u64().unwrap();
            let max = [10_000_000u64, 20_000_000][i];
            r * 100 >= max * 90
        };
        assert_eq!(row["near_limit"], json!([near(0), near(1)]), "{row}");
        let st = ok(&mut s, "queue.simple.stats", json!({"id": "web"}));
        assert_eq!(st["kept"], true);
        assert_eq!(st["counted"], true);
        ok(&mut s, "queue.simple.graph", json!({"id": "web", "graph": false}));
        s.tick(T0 + 10);
        s.queue_sync();
        s.tick(T0 + 11 + crate::graph::GRACE);
        s.queue_sync();
        assert!(s.ext::<crate::graph::GraphDb>().unwrap().get("queue:web").is_none());
    }
}
