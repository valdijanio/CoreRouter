//! `/tool graphing` (G4.5): what the traffic history keeps
//! (`system.graph.set`/`print`) and reading it (`system.graph.query` for
//! graphs, `system.graph.export` for an exporter that sends what it has not
//! sent yet). The history itself is `crate::graph`.

use corerouter_model::graphing::{
    Graphing, MAX_MAX_MEMORY_MIB, MAX_NAMES, MAX_STORE_EVERY, MIN_MAX_MEMORY_MIB, MIN_STORE_EVERY,
};
use serde_json::{Map, Value, json};

use super::args::{opt_bool, opt_names, opt_u32};
use super::{CommandSpec, always};
use crate::graph::query::{self, Request};
use crate::graph::{GraphDb, rrd, sources};
use crate::{EngineError, Result, Session};

/// Rows one `system.graph.export` hands out at most.
pub const MAX_EXPORT_ROWS: usize = 10_000;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "system.graph.set",
        "Graphing",
        [],
        None,
        "{enabled?: bool, store_every?: int 60..86400, physical?: bool, bridges?: bool, vlans?: bool, tunnels?: bool, resources?: bool, include?: [ifname], exclude?: [ifname], max_memory_mib?: int 1..4096} → {enabled, store_every, physical, bridges, vlans, tunnels, resources, include, exclude, max_memory_mib}",
        always,
        set
    ),
    cmd!(query "system.graph.print", "Graphing", [], None,
        "{} → {enabled, store_every, physical, bridges, vlans, tunnels, resources, include, exclude, max_memory_mib, series: [{series, bytes, last, kept}], refused: [ifname], memory_bytes, max_memory_bytes, series_bytes, tiers: [{step, rows, window}], disk: {dir, files, last_store, last_store_bytes, last_store_ms, stores, bytes_written, last_error, loaded, load_errors}}",
        always, print),
    cmd!(query "system.graph.query", "Graph Query", [], None,
        "{series: string | [string], range: hour|day|week|month|year|int, step?: int, end?: int, fields?: [string], stats?: bool, max?: bool} → {start, end, step, resolution, points, series: [{series, units, data: {<field>: [number|null], <field>_max}, stats: {<field>: {current, avg, max, p95}}, totals, coverage, p95_step, p95_approximate, p95_billing, p95_sum}]}",
        always, query_cmd),
    cmd!(query "system.graph.export", "Graph Export", [], None,
        "{since?: int, resolution?: 1|60|300|3600, series?: [string], limit?: int 1..10000} → {resolution, rows: [{series, time, avg: {<field>: number|null}, max?: {<field>: number|null}}], next, more}",
        always, export),
];

fn settings_json(g: &Graphing) -> Value {
    json!({
        "enabled": g.enabled,
        "store_every": g.store_every,
        "physical": g.physical,
        "bridges": g.bridges,
        "vlans": g.vlans,
        "tunnels": g.tunnels,
        "resources": g.resources,
        "include": g.include,
        "exclude": g.exclude,
        "max_memory_mib": g.max_memory_mib,
    })
}

fn in_range(p: &Value, key: &str, lo: u32, hi: u32, hint: &str) -> Result<Option<u32>> {
    opt_u32(p, key)?
        .map(|v| {
            if (lo..=hi).contains(&v) {
                Ok(v)
            } else {
                Err(EngineError::bad(key, format!("must be {lo}..={hi} ({hint})")))
            }
        })
        .transpose()
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let mut g = s.store().candidate().system.graphing.clone();
    for (key, field) in [
        ("enabled", &mut g.enabled),
        ("physical", &mut g.physical),
        ("bridges", &mut g.bridges),
        ("vlans", &mut g.vlans),
        ("tunnels", &mut g.tunnels),
        ("resources", &mut g.resources),
    ] {
        if let Some(v) = opt_bool(p, key)? {
            *field = v;
        }
    }
    if let Some(v) = in_range(
        p,
        "store_every",
        MIN_STORE_EVERY,
        MAX_STORE_EVERY,
        "seconds; RouterOS store-every is 5min, hour or 24hours",
    )? {
        g.store_every = v;
    }
    if let Some(v) = in_range(
        p,
        "max_memory_mib",
        MIN_MAX_MEMORY_MIB,
        MAX_MAX_MEMORY_MIB,
        "a year of one interface takes about 0.7 MiB",
    )? {
        g.max_memory_mib = v;
    }
    if let Some(v) = opt_names(p, "include", MAX_NAMES)? {
        g.include = v;
    }
    if let Some(v) = opt_names(p, "exclude", MAX_NAMES)? {
        g.exclude = v;
    }
    if let Some(both) = g.include.iter().find(|n| g.exclude.contains(n)) {
        return Err(EngineError::bad(
            "include",
            format!("{both} is also in exclude; exclude wins, so take it out of one"),
        ));
    }
    let out = settings_json(&g);
    s.store_mut().candidate_mut().system.graphing = g;
    Ok(out)
}

fn print(s: &mut Session, _: &Value) -> Result<Value> {
    let g = s.store().candidate().system.graphing.clone();
    let mut out = settings_json(&g);
    let status = s
        .ext::<GraphDb>()
        .map_or_else(|| GraphDb::default().status(&g), |db| db.status(&g));
    if let (Some(o), Value::Object(st)) = (out.as_object_mut(), status) {
        o.extend(st);
    }
    Ok(out)
}

fn strings(p: &Value, key: &str, max: usize) -> Result<Option<Vec<String>>> {
    let list: Vec<String> = match p.get(key) {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::String(s)) => s.split(',').map(|x| x.trim().to_owned()).collect(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str()
                    .map(|x| x.trim().to_owned())
                    .ok_or_else(|| EngineError::bad(key, "must be a list of strings"))
            })
            .collect::<Result<_>>()?,
        Some(_) => return Err(EngineError::bad(key, "must be a string or a list of strings")),
    };
    if list.len() > max {
        return Err(EngineError::bad(key, format!("at most {max} items")));
    }
    if let Some(long) = list.iter().find(|x| x.len() > 64 || x.is_empty()) {
        return Err(EngineError::bad(
            key,
            format!("'{}' is not a series name", crate::logging::cut(long, 64)),
        ));
    }
    Ok(Some(list))
}

fn query_cmd(s: &mut Session, p: &Value) -> Result<Value> {
    let names = strings(p, "series", query::MAX_SERIES)?
        .filter(|v| !v.is_empty())
        .ok_or_else(|| EngineError::bad("series", "is required (e.g. \"ether1\", \"system\", \"interface:*\")"))?;
    let range = query::parse_range(p.get("range").unwrap_or(&Value::Null))
        .map_err(|e| EngineError::bad("range", e))?;
    let step = opt_u32(p, "step")?.map(u64::from).filter(|s| *s > 0);
    let end = match p.get("end") {
        None | Some(Value::Null) => None,
        Some(v) => Some(v.as_u64().ok_or_else(|| EngineError::bad("end", "Unix seconds"))?),
    };
    let fields = strings(p, "fields", 16)?;
    let stats = opt_bool(p, "stats")?.unwrap_or(true);
    let max = opt_bool(p, "max")?.unwrap_or(true);
    let now = s.now().unwrap_or(0);
    let empty = GraphDb::default();
    let db = s.ext::<GraphDb>().unwrap_or(&empty);
    let keys = query::resolve(db, &names).map_err(|e| EngineError::bad("series", e))?;
    if let Some(f) = &fields {
        for name in f {
            if !keys.iter().any(|k| sources(k).iter().any(|s| s.key == name)) {
                return Err(EngineError::bad(
                    "fields",
                    format!("no series has '{}'", crate::logging::cut(name, 32)),
                ));
            }
        }
    }
    let req = Request {
        keys,
        range,
        step,
        end,
        fields,
        stats,
        max,
    };
    query::run(db, &req, now).map_err(|e| EngineError::bad("range", e))
}

fn export(s: &mut Session, p: &Value) -> Result<Value> {
    let since = match p.get("since") {
        None | Some(Value::Null) => 0,
        Some(v) => v
            .as_u64()
            .ok_or_else(|| EngineError::bad("since", "Unix seconds (the `next` of the last answer)"))?,
    };
    let resolution = u64::from(opt_u32(p, "resolution")?.unwrap_or(60));
    if !rrd::TIERS.iter().any(|t| t.step == resolution) {
        return Err(EngineError::bad("resolution", "1, 60, 300 or 3600 seconds"));
    }
    let limit = opt_u32(p, "limit")?.unwrap_or(1000) as usize;
    if !(1..=MAX_EXPORT_ROWS).contains(&limit) {
        return Err(EngineError::bad("limit", format!("must be 1..={MAX_EXPORT_ROWS}")));
    }
    let empty = GraphDb::default();
    let db = s.ext::<GraphDb>().unwrap_or(&empty);
    let keys = match strings(p, "series", query::MAX_SERIES)? {
        Some(names) => Some(query::resolve(db, &names).map_err(|e| EngineError::bad("series", e))?),
        None => None,
    };
    // One row more than asked tells whether there is more.
    let mut rows = db.export(resolution, since, keys.as_deref(), limit + 1);
    let more = rows.len() > limit;
    // A page must not end in the middle of a bucket: the next one starts
    // after the last time handed out, so a cut bucket would lose series.
    let spill = rows.get(limit).map(|r| r.1);
    rows.truncate(limit);
    if let Some(t) = spill
        && rows.last().is_some_and(|r| r.1 == t)
    {
        let cut = rows.iter().position(|r| r.1 == t).unwrap_or(rows.len());
        if cut > 0 {
            rows.truncate(cut);
        }
    }
    let next = rows.last().map_or(since, |r| r.1);
    let out: Vec<Value> = rows
        .into_iter()
        .map(|(key, time, avg, max)| {
            let src = sources(&key);
            let obj = |v: &[f32]| -> Map<String, Value> {
                src.iter()
                    .zip(v)
                    .map(|(s, x)| (s.key.to_owned(), if x.is_finite() { json!(f64::from(*x)) } else { Value::Null }))
                    .collect()
            };
            let mut row = json!({"series": key, "time": time, "avg": obj(&avg)});
            if let (Some(m), Some(o)) = (max, row.as_object_mut()) {
                o.insert("max".into(), Value::Object(obj(&m)));
            }
            row
        })
        .collect();
    Ok(json!({"resolution": resolution, "rows": out, "next": next, "more": more}))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::Session;

    #[test]
    fn set_validates_and_rolls_back() {
        let mut s = Session::virtual_lab();
        let r = s
            .execute("system.graph.set", &json!({"vlans": true, "include": "lo", "max_memory_mib": 128}))
            .unwrap();
        assert_eq!(r["vlans"], true);
        assert_eq!(r["include"], json!(["lo"]));
        let g = &s.store().running().system.graphing;
        assert!(g.vlans && g.max_memory_mib == 128);
        for bad in [
            json!({"store_every": 5}),
            json!({"max_memory_mib": 0}),
            json!({"include": ["bad name!"]}),
            json!({"include": ["ether1"], "exclude": ["ether1"]}),
            json!({"vlans": "yes please"}),
        ] {
            let err = s.execute("system.graph.set", &bad).unwrap_err().to_string();
            assert!(!err.is_empty(), "{bad}");
        }
        assert!(s.store().running().system.graphing.vlans, "a refused set changes nothing");
        let print = s.execute("system.graph.print", &json!({})).unwrap();
        assert_eq!(print["max_memory_mib"], 128);
        assert_eq!(print["tiers"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn query_names_what_is_missing() {
        let mut s = Session::virtual_lab();
        let err = s
            .execute("system.graph.query", &json!({"series": "ether99", "range": "hour"}))
            .unwrap_err()
            .to_string();
        assert!(err.contains("no history of 'interface:ether99'"), "{err}");
        let err = s
            .execute("system.graph.query", &json!({"series": [], "range": "hour"}))
            .unwrap_err()
            .to_string();
        assert!(err.contains("series"), "{err}");
        assert!(s
            .execute("system.graph.export", &json!({"resolution": 7}))
            .is_err());
    }
}
