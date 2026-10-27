//! `system.graph.query`: points of a range at a step, and the numbers an
//! operator reads off a graph — current, average, maximum, the 95th
//! percentile and the total.
//!
//! - **Tier:** the finest ring that covers the range (hour → 1 s, day →
//!   1 min, week → 5 min, month and year → 1 h). Points coarser than the
//!   ring average its slots and keep the largest maximum.
//! - **95th percentile** (burstable billing): of the 5-minute averages, the
//!   value below which 95 % of them fall (sort, drop the top 5 %, nearest
//!   rank), as LibreNMS and the transit contracts do. A range longer than
//!   the 5-minute ring (a week) only has 1 h averages, which hide bursts:
//!   the answer says so (`p95_step: 3600`, `p95_approximate`). Per
//!   direction, plus `p95_billing` (the larger of the two, LibreNMS'
//!   default) and `p95_sum` (of receive + transmit per sample).
//! - **Total:** the average rate of each known slot times its length
//!   (bits → bytes); unknown slots add nothing and `coverage` says how
//!   much of the range was known.

use serde_json::{Map, Value, json};

use super::rrd::{Rrd, TIERS, TierSpec};
use super::{GraphDb, INTERFACE, SYSTEM, Source, sources};

/// Named ranges (`range: "day"`), seconds.
pub const RANGES: [(&str, u64); 5] = [
    ("hour", 3600),
    ("day", 86_400),
    ("week", 7 * 86_400),
    ("month", 30 * 86_400),
    ("year", 365 * 86_400),
];
/// Points of a graph when no step is given (about one per pixel column of
/// a window).
pub const DEFAULT_POINTS: u64 = 720;
pub const MAX_POINTS: u64 = 10_000;
/// Most series in one query (comparison, or the Interfaces sparklines).
pub const MAX_SERIES: usize = 1024;
/// Most points × series in one answer.
pub const MAX_CELLS: u64 = 2_000_000;
/// The 5-minute ring: where the 95th percentile comes from.
const P95_TIER: usize = 2;

/// A parsed `system.graph.query`.
#[derive(Debug, Clone)]
pub struct Request {
    pub keys: Vec<String>,
    pub range: u64,
    pub step: Option<u64>,
    pub end: Option<u64>,
    /// Only these values (`rx_bps`, `cpu`…); `None`: all.
    pub fields: Option<Vec<String>>,
    pub stats: bool,
    pub max: bool,
}

/// The tier a range is read from, and the step of its points.
pub fn plan(range: u64, step: Option<u64>) -> Result<(usize, u64), String> {
    let covering = |t: &TierSpec| t.window() >= range;
    let finest = TIERS.iter().position(covering).unwrap_or(TIERS.len() - 1);
    let tier = step
        .and_then(|s| {
            TIERS
                .iter()
                .enumerate()
                .rfind(|(_, t)| covering(t) && t.step <= s)
                .map(|(i, _)| i)
        })
        .unwrap_or(finest);
    let spec = TIERS.get(tier).copied().ok_or("no tier")?;
    let step = match step {
        Some(s) => (s / spec.step).max(1) * spec.step,
        None => range.div_ceil(spec.step).div_ceil(DEFAULT_POINTS).max(1) * spec.step,
    };
    let points = range.div_ceil(step);
    if points > MAX_POINTS {
        return Err(format!(
            "{points} points: at most {MAX_POINTS} (raise step to at least {})",
            range.div_ceil(MAX_POINTS)
        ));
    }
    Ok((tier, step))
}

/// Seconds of a range: a name of [`RANGES`] or a number of seconds
/// (60..=one year).
pub fn parse_range(v: &Value) -> Result<u64, String> {
    let year = RANGES[4].1;
    match v {
        Value::String(s) => RANGES
            .iter()
            .find(|(n, _)| n == s)
            .map(|(_, r)| *r)
            .or_else(|| s.parse().ok().filter(|r| (60..=year).contains(r)))
            .ok_or_else(|| "hour, day, week, month, year or seconds (60..=31536000)".to_string()),
        Value::Number(n) => n
            .as_u64()
            .filter(|r| (60..=year).contains(r))
            .ok_or_else(|| "seconds must be 60..=31536000".to_string()),
        _ => Err("hour, day, week, month, year or seconds".into()),
    }
}

/// The series keys a request names: `system`, `interface:<name>`, a bare
/// interface name, or `interface:*` (every kept interface).
pub fn resolve(db: &GraphDb, names: &[String]) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for n in names {
        let wanted: Vec<String> = if n == "interface:*" {
            db.keys().filter(|k| k.starts_with(INTERFACE)).map(str::to_owned).collect()
        } else if n == SYSTEM || n.starts_with(INTERFACE) || n.starts_with(super::QUEUE) {
            vec![n.clone()]
        } else {
            vec![format!("{INTERFACE}{n}")]
        };
        for k in wanted {
            if db.get(&k).is_none() {
                let kept: Vec<&str> = db.keys().take(8).collect();
                return Err(format!(
                    "no history of '{}' (kept: {}{}); system.graph.set chooses what is kept",
                    crate::logging::cut(&k, 64),
                    if kept.is_empty() { "nothing yet".to_string() } else { kept.join(", ") },
                    if db.keys().count() > 8 { ", …" } else { "" }
                ));
            }
            if !out.contains(&k) {
                out.push(k);
            }
        }
    }
    if out.len() > MAX_SERIES {
        return Err(format!("{} series: at most {MAX_SERIES}", out.len()));
    }
    Ok(out)
}

fn num(v: f64) -> Value {
    if v.is_finite() {
        json!((v * 1000.0).round() / 1000.0)
    } else {
        Value::Null
    }
}

/// The 95th percentile by nearest rank (`None` without samples).
pub fn p95(values: &mut [f32]) -> Option<f32> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(f32::total_cmp);
    let rank = (values.len() * 95).div_ceil(100).max(1);
    values.get(rank - 1).copied()
}

/// Slots of tier `tier` in `[from, to)`, as (bucket, averages, maxima).
fn slots<'a>(
    rrd: &'a Rrd,
    tier: usize,
    from: u64,
    to: u64,
) -> impl Iterator<Item = (u64, &'a [f32], Option<&'a [f32]>)> + 'a {
    let step = TIERS.get(tier).map_or(1, |t| t.step);
    (from.div_ceil(step)..to / step).filter_map(move |k| rrd.row(tier, k).map(|(a, m)| (k, a, m)))
}

/// Answer a query over `db` at time `now`.
pub fn run(db: &GraphDb, req: &Request, now: u64) -> Result<Value, String> {
    let (tier, step) = plan(req.range, req.step)?;
    let cells = req.range.div_ceil(step).saturating_mul(req.keys.len() as u64);
    if cells > MAX_CELLS {
        return Err(format!("{cells} points in all: at most {MAX_CELLS}; ask fewer series or a larger step"));
    }
    let spec = TIERS.get(tier).copied().ok_or("no tier")?;
    let end = req.end.unwrap_or(now).min(now) / step * step;
    let points = req.range.div_ceil(step);
    let start = end.saturating_sub(points * step);
    let mut series = Vec::with_capacity(req.keys.len());
    for key in &req.keys {
        let Some(rrd) = db.get(key) else { continue };
        let all = sources(key);
        let picked: Vec<(usize, &Source)> = all
            .iter()
            .enumerate()
            .filter(|(_, s)| req.fields.as_ref().is_none_or(|f| f.iter().any(|x| x == s.key)))
            .collect();
        let mut data = Map::new();
        let show_max = req.max && (spec.max || step > spec.step);
        for (i, src) in &picked {
            let mut avg = Vec::with_capacity(points as usize);
            let mut max = Vec::with_capacity(if show_max { points as usize } else { 0 });
            for p in 0..points {
                let b = start + p * step;
                let (mut sum, mut n, mut peak) = (0.0f64, 0u32, f32::NAN);
                for (_, a, m) in slots(rrd, tier, b, b + step) {
                    let v = a.get(*i).copied().unwrap_or(f32::NAN);
                    if v.is_finite() {
                        sum += f64::from(v);
                        n += 1;
                    }
                    let top = m.and_then(|m| m.get(*i).copied()).unwrap_or(v);
                    if top.is_finite() && (peak.is_nan() || top > peak) {
                        peak = top;
                    }
                }
                avg.push(if n > 0 { num(sum / f64::from(n)) } else { Value::Null });
                if show_max {
                    max.push(num(f64::from(peak)));
                }
            }
            data.insert(src.key.into(), Value::Array(avg));
            if show_max {
                data.insert(format!("{}_max", src.key), Value::Array(max));
            }
        }
        let mut out = json!({
            "series": key,
            "units": picked.iter().map(|(_, s)| (s.key.to_owned(), json!(s.unit))).collect::<Map<String, Value>>(),
            "data": data,
        });
        if req.stats
            && let Some(o) = out.as_object_mut()
        {
            o.extend(stats(rrd, key, &picked, tier, start, end, now));
        }
        series.push(out);
    }
    Ok(json!({
        "start": start,
        "end": end,
        "step": step,
        "resolution": spec.step,
        "points": points,
        "series": series,
    }))
}

/// Current, average, maximum, 95th percentile and totals of one series.
fn stats(
    rrd: &Rrd,
    key: &str,
    picked: &[(usize, &Source)],
    tier: usize,
    start: u64,
    end: u64,
    now: u64,
) -> Map<String, Value> {
    let spec = TIERS.get(tier).copied().unwrap_or(TIERS[0]);
    let p95_tier = if end - start <= TIERS[P95_TIER].window() { P95_TIER } else { TIERS.len() - 1 };
    let p95_step = TIERS.get(p95_tier).map_or(0, |t| t.step);
    let newest = rrd.closed(0);
    let current_row = (newest > 0 && now.saturating_sub(newest) <= super::HEARTBEAT)
        .then(|| rrd.row(0, newest).map(|(a, _)| a))
        .flatten();
    let mut fields = Map::new();
    let mut totals = Map::new();
    let mut known = 0u64;
    let mut p95_by: Map<String, Value> = Map::new();
    for (i, src) in picked {
        let (mut sum, mut n, mut peak, mut total) = (0.0f64, 0u64, f32::NAN, 0.0f64);
        for (_, a, m) in slots(rrd, tier, start, end) {
            let v = a.get(*i).copied().unwrap_or(f32::NAN);
            if v.is_finite() {
                sum += f64::from(v);
                n += 1;
                total += f64::from(v) * spec.step as f64 * src.per_total;
            }
            let top = m.and_then(|m| m.get(*i).copied()).unwrap_or(v);
            if top.is_finite() && (peak.is_nan() || top > peak) {
                peak = top;
            }
        }
        // The newest second may be past the last closed slot: a maximum
        // below the current value would read as a bug.
        if let Some(c) = current_row.and_then(|r| r.get(*i)).filter(|c| c.is_finite())
            && (peak.is_nan() || *c > peak)
        {
            peak = *c;
        }
        known = known.max(n);
        let mut samples: Vec<f32> = slots(rrd, p95_tier, start, end)
            .filter_map(|(_, a, _)| a.get(*i).copied().filter(|v| v.is_finite()))
            .collect();
        let p = p95(&mut samples);
        p95_by.insert(src.key.into(), p.map_or(Value::Null, |v| num(f64::from(v))));
        fields.insert(
            src.key.into(),
            json!({
                "current": current_row.and_then(|r| r.get(*i)).map_or(Value::Null, |v| num(f64::from(*v))),
                "avg": if n > 0 { num(sum / n as f64) } else { Value::Null },
                "max": num(f64::from(peak)),
                "p95": p.map_or(Value::Null, |v| num(f64::from(v))),
            }),
        );
        if let Some(t) = src.total {
            totals.insert(t.into(), if n > 0 { num(total.round()) } else { Value::Null });
        }
    }
    let mut out = Map::new();
    out.insert("stats".into(), Value::Object(fields));
    if !totals.is_empty() {
        out.insert("totals".into(), Value::Object(totals));
    }
    let slots_in_range = (end - start) / spec.step;
    out.insert(
        "coverage".into(),
        num(if slots_in_range == 0 { 0.0 } else { known as f64 / slots_in_range as f64 }),
    );
    out.insert("p95_step".into(), json!(p95_step));
    out.insert("p95_approximate".into(), json!(p95_step > TIERS[P95_TIER].step));
    if key.starts_with(INTERFACE) {
        let rx = p95_by.get("rx_bps").and_then(Value::as_f64);
        let tx = p95_by.get("tx_bps").and_then(Value::as_f64);
        let billing = match (rx, tx) {
            (Some(r), Some(t)) => num(r.max(t)),
            (Some(v), None) | (None, Some(v)) => num(v),
            _ => Value::Null,
        };
        out.insert("p95_billing".into(), billing);
        if p95_by.contains_key("rx_bps") && p95_by.contains_key("tx_bps") {
            // Per bucket, so the two directions must come from the same
            // slots: read them again together.
            let mut sums: Vec<f32> = slots(rrd, p95_tier, start, end)
                .filter_map(|(_, a, _)| {
                    let (r, t) = (a.first()?, a.get(1)?);
                    (r.is_finite() && t.is_finite()).then_some(r + t)
                })
                .collect();
            out.insert(
                "p95_sum".into(),
                p95(&mut sums).map_or(Value::Null, |v| num(f64::from(v))),
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_pick_the_finest_covering_tier() {
        assert_eq!(plan(3600, None).unwrap(), (0, 5));
        assert_eq!(plan(86_400, None).unwrap(), (1, 120));
        assert_eq!(plan(7 * 86_400, None).unwrap(), (2, 900));
        assert_eq!(plan(30 * 86_400, None).unwrap(), (3, 3600));
        assert_eq!(plan(365 * 86_400, None).unwrap(), (3, 3600 * 13));
        assert_eq!(plan(3600, Some(60)).unwrap(), (1, 60), "a 60 s step reads the 1 min ring");
        assert_eq!(plan(86_400, Some(1)).unwrap(), (1, 60), "finer than the ring: its step");
        assert_eq!(plan(3600, Some(7)).unwrap(), (0, 7));
        assert_eq!(plan(365 * 86_400, Some(60)).unwrap(), (3, 3600), "a year has hours only");
    }

    #[test]
    fn p95_drops_the_top_five_percent() {
        // 8640 five-minute samples of a 30-day month: 432 are dropped.
        let mut v: Vec<f32> = (1..=8640).map(|x| x as f32).collect();
        assert_eq!(p95(&mut v), Some(8208.0));
        let mut v: Vec<f32> = (1..=20).map(|x| x as f32).collect();
        assert_eq!(p95(&mut v), Some(19.0));
        assert_eq!(p95(&mut []), None);
        assert_eq!(p95(&mut [7.0]), Some(7.0));
    }

    #[test]
    fn ranges_by_name_or_seconds() {
        assert_eq!(parse_range(&json!("week")), Ok(604_800));
        assert_eq!(parse_range(&json!(600)), Ok(600));
        assert_eq!(parse_range(&json!("600")), Ok(600));
        assert!(parse_range(&json!(5)).is_err());
        assert!(parse_range(&json!("decade")).is_err());
    }
}
