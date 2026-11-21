//! G0.30k: the nightly regression check. Each night the labs write their
//! numbers (`metrics.jsonl`, one JSON object per line:
//! `{"metric": "dns.qps.cpus0_3.static.sat.qps", "value": 812345,
//! "unit": "qps", "better": "higher"}`); `compare` puts them beside the
//! last green night of the history and says which got worse by more than
//! the noise of that metric.
//!
//! The margin is calibrated per metric, as rustc-perf does
//! (docs/comparison-analysis.md of rust-lang/rustc-perf): the relative
//! changes between consecutive green nights are the noise, and a change is
//! significant above the upper fence `Q3 + 3 × IQR` of them, never below
//! [`FLOOR`]. Until a metric has [`MIN_NIGHTS`] changes it is still being
//! calibrated: a change beyond [`DEFAULT_MARGIN`] is reported
//! ([`Verdict::Uncalibrated`]) but does not make the night red. Two runs of
//! the same build on a loaded host differed by up to 23× in a p99
//! (**medido**, 2026-11-21): a fixed margin would cry wolf.
//!
//! ```text
//! cargo xtask nightly compare --metrics <file> --history <dir>
//!     [--report <file.md>] [--commits <file>]
//! ```
//!
//! The history holds one file per night, `<YYYYMMDD>-<sha>.<green|red>.jsonl`
//! (sorted by name = by date). The verdict is stdout's last line
//! (`verdict: ok` or `verdict: regressed`); the exit status is 0 either
//! way, 1 only for bad input.

use std::collections::BTreeMap;
use std::path::Path;

use crate::Outcome;

/// Below this the margin never goes: two nights on the same code differ
/// by a few percent even on a quiet runner.
pub const FLOOR: f64 = 0.03;
/// The margin of a metric with too little history (**estimado**): only
/// reported, never red.
pub const DEFAULT_MARGIN: f64 = 0.15;
/// Changes between green nights needed before the margin is calibrated.
pub const MIN_NIGHTS: usize = 5;
/// The newest green nights the noise is measured on.
pub const WINDOW: usize = 30;

/// Which way is better for a metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Better {
    Higher,
    Lower,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Metric {
    pub name: String,
    pub value: f64,
    pub unit: String,
    pub better: Better,
}

/// One night of the history.
#[derive(Debug, Clone, PartialEq)]
pub struct Night {
    /// The file name without `.green.jsonl` / `.red.jsonl`.
    pub label: String,
    pub green: bool,
    pub metrics: BTreeMap<String, Metric>,
}

/// One line of `metrics.jsonl`; `None` for a blank line. Errors quote at
/// most 120 characters of the line.
pub fn parse_line(line: &str) -> Result<Option<Metric>, String> {
    let line = line.trim();
    if line.is_empty() {
        return Ok(None);
    }
    let cut = |s: &str| s.chars().take(120).collect::<String>();
    let v: serde_json::Value =
        serde_json::from_str(line).map_err(|e| format!("{e}: {}", cut(line)))?;
    let name = v
        .get("metric")
        .and_then(serde_json::Value::as_str)
        .filter(|n| !n.is_empty() && n.len() <= 200)
        .ok_or_else(|| format!("no metric name (1 to 200 bytes): {}", cut(line)))?;
    let value = v
        .get("value")
        .and_then(serde_json::Value::as_f64)
        .filter(|x| x.is_finite())
        .ok_or_else(|| format!("no finite value: {}", cut(line)))?;
    let better = match v.get("better").and_then(serde_json::Value::as_str) {
        Some("higher") => Better::Higher,
        Some("lower") => Better::Lower,
        _ => return Err(format!("better must be higher or lower: {}", cut(line))),
    };
    let unit = v
        .get("unit")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .chars()
        .take(20)
        .collect();
    Ok(Some(Metric {
        name: name.to_owned(),
        value,
        unit,
        better,
    }))
}

/// Every metric of a file; a name seen twice keeps the last value.
pub fn parse(text: &str) -> Result<BTreeMap<String, Metric>, String> {
    let mut out = BTreeMap::new();
    for (i, line) in text.lines().enumerate() {
        if let Some(m) = parse_line(line).map_err(|e| format!("line {}: {e}", i + 1))? {
            out.insert(m.name.clone(), m);
        }
    }
    Ok(out)
}

/// The history directory, oldest first. Files that do not follow the
/// naming are left out; a missing directory is an empty history.
pub fn read_history(dir: &Path) -> Result<Vec<Night>, String> {
    let mut nights = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(nights);
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let (label, green) = if let Some(l) = name.strip_suffix(".green.jsonl") {
            (l.to_owned(), true)
        } else if let Some(l) = name.strip_suffix(".red.jsonl") {
            (l.to_owned(), false)
        } else {
            continue;
        };
        let text = std::fs::read_to_string(e.path()).map_err(|err| format!("{name}: {err}"))?;
        let metrics = parse(&text).map_err(|err| format!("{name}: {err}"))?;
        nights.push(Night {
            label,
            green,
            metrics,
        });
    }
    nights.sort_by(|a, b| a.label.cmp(&b.label));
    Ok(nights)
}

/// How much worse `new` is than `base`, relative (positive = worse). A
/// base of 0: 0 if the new value is 0 too, else infinitely worse or better.
pub fn worse_by(base: f64, new: f64, better: Better) -> f64 {
    let d = match better {
        Better::Higher => base - new,
        Better::Lower => new - base,
    };
    if base.abs() < f64::EPSILON {
        if d.abs() < f64::EPSILON {
            0.0
        } else {
            d.signum() * f64::INFINITY
        }
    } else {
        d / base.abs()
    }
}

/// Linear-interpolated quantile `q` of sorted values.
fn quantile(sorted: &[f64], q: f64) -> f64 {
    let Some(last) = sorted.len().checked_sub(1) else {
        return 0.0;
    };
    let pos = q * last as f64;
    let (lo, hi) = (pos.floor() as usize, pos.ceil() as usize);
    let a = sorted.get(lo).copied().unwrap_or(0.0);
    let b = sorted.get(hi).copied().unwrap_or(a);
    a + (b - a) * (pos - lo as f64)
}

/// The margin of `name` from the green nights: the upper IQR fence of the
/// size of the changes between consecutive ones, never under [`FLOOR`],
/// and how many changes it came from (`None`: too few, the default).
pub fn margin(name: &str, nights: &[Night]) -> (f64, Option<usize>) {
    let values: Vec<(f64, Better)> = nights
        .iter()
        .filter(|n| n.green)
        .filter_map(|n| n.metrics.get(name).map(|m| (m.value, m.better)))
        .collect();
    let start = values.len().saturating_sub(WINDOW + 1);
    let mut changes: Vec<f64> = values
        .get(start..)
        .unwrap_or(&[])
        .windows(2)
        .filter_map(|w| match w {
            [(a, b), (c, _)] => Some(worse_by(*a, *c, *b).abs()),
            _ => None,
        })
        .filter(|x| x.is_finite())
        .collect();
    if changes.len() < MIN_NIGHTS {
        return (DEFAULT_MARGIN, None);
    }
    changes.sort_by(f64::total_cmp);
    let (q1, q3) = (quantile(&changes, 0.25), quantile(&changes, 0.75));
    ((q3 + 3.0 * (q3 - q1)).max(FLOOR), Some(changes.len()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Regressed,
    /// Beyond the default margin, but the metric has too few green nights
    /// to know its noise: reported, the night stays green.
    Uncalibrated,
    Improved,
    Same,
    /// No green night has this metric yet.
    New,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub name: String,
    pub unit: String,
    /// The last green night with the metric: its label and value.
    pub base: Option<(String, f64)>,
    pub value: f64,
    pub worse: f64,
    pub margin: f64,
    pub calibrated_from: Option<usize>,
    pub verdict: Verdict,
}

/// Tonight's metrics against the history.
pub fn compare(tonight: &BTreeMap<String, Metric>, nights: &[Night]) -> Vec<Row> {
    tonight
        .values()
        .map(|m| {
            let base = nights
                .iter()
                .rev()
                .filter(|n| n.green)
                .find_map(|n| n.metrics.get(&m.name).map(|b| (n.label.clone(), b.value)));
            let (margin, calibrated_from) = margin(&m.name, nights);
            let (worse, verdict) = match &base {
                None => (0.0, Verdict::New),
                Some((_, b)) => {
                    let w = worse_by(*b, m.value, m.better);
                    let v = if w > margin && calibrated_from.is_none() {
                        Verdict::Uncalibrated
                    } else if w > margin {
                        Verdict::Regressed
                    } else if -w > margin {
                        Verdict::Improved
                    } else {
                        Verdict::Same
                    };
                    (w, v)
                }
            };
            Row {
                name: m.name.clone(),
                unit: m.unit.clone(),
                base,
                value: m.value,
                worse,
                margin,
                calibrated_from,
                verdict,
            }
        })
        .collect()
}

fn pct(x: f64) -> String {
    if x.is_infinite() {
        if x > 0.0 {
            "+∞".into()
        } else {
            "−∞".into()
        }
    } else {
        format!("{:+.1} %", x * 100.0)
    }
}

/// The table of `list`.
fn table(out: &mut String, list: &[&Row]) {
    out.push_str(
        "| métrica | última noite verde | esta noite | piora | margem |\n|---|---|---|---|---|\n",
    );
    for r in list {
        let (label, base) = r.base.as_ref().map_or_else(
            || ("—".to_owned(), "—".to_owned()),
            |(l, b)| (l.clone(), format!("{b} {}", r.unit)),
        );
        let margin = match r.calibrated_from {
            Some(n) => format!("{} (ruído de {n} noites)", pct(r.margin)),
            None => format!("{} (padrão: pouco histórico)", pct(r.margin)),
        };
        out.push_str(&format!(
            "| `{}` | {base} ({label}) | {} {} | {} | {margin} |\n",
            r.name,
            r.value,
            r.unit,
            pct(r.worse)
        ));
    }
}

/// The markdown of the issue (and of the run's summary): what got worse,
/// what got better and the commits since the last green night.
pub fn report(rows: &[Row], commits: &str) -> String {
    let of = |v: Verdict| rows.iter().filter(|r| r.verdict == v).collect::<Vec<_>>();
    let (bad, good, new) = (
        of(Verdict::Regressed),
        of(Verdict::Improved),
        of(Verdict::New),
    );
    let calibrating = of(Verdict::Uncalibrated);
    let mut out = format!(
        "{} métricas: {} pioraram além da margem, {} melhoraram, {} ainda calibrando fora da margem padrão, {} novas (sem noite verde para comparar).\n\n",
        rows.len(),
        bad.len(),
        good.len(),
        calibrating.len(),
        new.len()
    );
    if !bad.is_empty() {
        out.push_str("## Pioraram\n\n");
        table(&mut out, &bad);
        out.push('\n');
    }
    if !calibrating.is_empty() {
        out.push_str(&format!(
            "## Ainda calibrando (menos de {MIN_NIGHTS} variações entre noites verdes: não deixa a noite vermelha)\n\n"
        ));
        table(&mut out, &calibrating);
        out.push('\n');
    }
    if !good.is_empty() {
        out.push_str("## Melhoraram\n\n");
        table(&mut out, &good);
        out.push('\n');
    }
    let commits: Vec<&str> = commits
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .take(200)
        .collect();
    if !commits.is_empty() {
        out.push_str("## Entraram desde a última noite verde\n\n");
        for c in commits {
            out.push_str(&format!("- {c}\n"));
        }
        out.push('\n');
    }
    out
}

fn arg<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

pub fn main(args: &[String]) -> Outcome {
    if args.first().map(String::as_str) != Some("compare") {
        return Outcome::Fail(
            "usage: cargo xtask nightly compare --metrics <file> --history <dir> [--report <file.md>] [--commits <file>]".into(),
        );
    }
    let (Some(metrics), Some(history)) = (arg(args, "--metrics"), arg(args, "--history")) else {
        return Outcome::Fail("compare needs --metrics and --history".into());
    };
    let tonight = match std::fs::read_to_string(metrics)
        .map_err(|e| format!("{metrics}: {e}"))
        .and_then(|t| parse(&t).map_err(|e| format!("{metrics}: {e}")))
    {
        Ok(t) => t,
        Err(e) => return Outcome::Fail(e),
    };
    if tonight.is_empty() {
        return Outcome::Fail(format!("{metrics}: no metric (did the labs run?)"));
    }
    let nights = match read_history(Path::new(history)) {
        Ok(n) => n,
        Err(e) => return Outcome::Fail(e),
    };
    let commits = arg(args, "--commits")
        .and_then(|f| std::fs::read_to_string(f).ok())
        .unwrap_or_default();
    let rows = compare(&tonight, &nights);
    let text = report(&rows, &commits);
    if let Some(r) = arg(args, "--report")
        && let Err(e) = std::fs::write(r, &text)
    {
        return Outcome::Fail(format!("{r}: {e}"));
    }
    print!("{text}");
    let regressed = rows.iter().any(|r| r.verdict == Verdict::Regressed);
    println!("verdict: {}", if regressed { "regressed" } else { "ok" });
    Outcome::Ok
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(name: &str, value: f64, better: Better) -> Metric {
        Metric {
            name: name.into(),
            value,
            unit: "u".into(),
            better,
        }
    }

    fn night(label: &str, green: bool, ms: &[Metric]) -> Night {
        Night {
            label: label.into(),
            green,
            metrics: ms.iter().map(|x| (x.name.clone(), x.clone())).collect(),
        }
    }

    #[test]
    fn lines_parse_and_hostile_ones_are_refused() {
        let ok = parse_line(r#"{"metric":"a.b","value":12.5,"unit":"qps","better":"higher"}"#)
            .unwrap()
            .unwrap();
        assert_eq!(
            ok,
            Metric {
                name: "a.b".into(),
                value: 12.5,
                unit: "qps".into(),
                better: Better::Higher
            }
        );
        assert_eq!(parse_line("   ").unwrap(), None);
        for bad in [
            "not json",
            r#"{"value":1,"better":"lower"}"#,
            r#"{"metric":"a","value":"x","better":"lower"}"#,
            r#"{"metric":"a","value":1,"better":"sideways"}"#,
            r#"{"metric":"","value":1,"better":"lower"}"#,
        ] {
            assert!(parse_line(bad).is_err(), "{bad}");
        }
        let long = format!(
            "{{\"metric\":\"{}\",\"value\":1,\"better\":\"lower\"}}",
            "x".repeat(500)
        );
        let e = parse_line(&long).unwrap_err();
        assert!(e.len() < 300, "the error truncates the input: {e}");
        assert!(parse("ok\n").unwrap_err().starts_with("line 1:"));
    }

    #[test]
    fn worse_follows_the_direction_and_zero_bases() {
        assert!((worse_by(100.0, 90.0, Better::Higher) - 0.10).abs() < 1e-9);
        assert!((worse_by(100.0, 110.0, Better::Lower) - 0.10).abs() < 1e-9);
        assert!(worse_by(100.0, 110.0, Better::Higher) < 0.0);
        assert_eq!(worse_by(0.0, 0.0, Better::Lower), 0.0);
        assert_eq!(worse_by(0.0, 3.0, Better::Lower), f64::INFINITY);
        assert_eq!(worse_by(0.0, 3.0, Better::Higher), f64::NEG_INFINITY);
    }

    /// Default margin with little history; calibrated from the noise (IQR
    /// fence, never under the floor) with enough; red nights do not count.
    #[test]
    fn the_margin_comes_from_the_noise_of_green_nights() {
        let few: Vec<Night> = (0..4)
            .map(|i| {
                night(
                    &format!("2026110{i}"),
                    true,
                    &[m("q", 100.0, Better::Higher)],
                )
            })
            .collect();
        assert_eq!(margin("q", &few), (DEFAULT_MARGIN, None));
        let mut nights = Vec::new();
        for (i, v) in [100.0, 102.0, 100.0, 98.0, 100.0, 102.0, 100.0, 98.0]
            .iter()
            .enumerate()
        {
            nights.push(night(
                &format!("202611{i:02}"),
                true,
                &[m("q", *v, Better::Higher)],
            ));
        }
        nights.push(night("20261120", false, &[m("q", 10.0, Better::Higher)]));
        let (mg, n) = margin("q", &nights);
        assert_eq!(n, Some(7));
        assert!((FLOOR..0.10).contains(&mg), "{mg}");
        let quiet: Vec<Night> = (0..8)
            .map(|i| {
                night(
                    &format!("202611{i:02}"),
                    true,
                    &[m("q", 100.0, Better::Lower)],
                )
            })
            .collect();
        assert_eq!(margin("q", &quiet), (FLOOR, Some(7)));
    }

    #[test]
    fn compare_finds_the_regression_against_the_last_green_night() {
        // Six quiet green nights calibrate `qps` and `p99`; `slow` has one.
        let mut nights: Vec<Night> = (0..6)
            .map(|i| {
                night(
                    &format!("2026111{i}-aaaaaaa"),
                    true,
                    &[
                        m("qps", 1000.0 + f64::from(i % 2) * 10.0, Better::Higher),
                        m("p99", 500.0, Better::Lower),
                    ],
                )
            })
            .collect();
        nights.push(night(
            "20261118-aaaaaaa",
            true,
            &[
                m("qps", 1000.0, Better::Higher),
                m("p99", 500.0, Better::Lower),
                m("slow", 10.0, Better::Lower),
            ],
        ));
        // A red night is never the baseline.
        nights.push(night(
            "20261119-bbbbbbb",
            false,
            &[m("qps", 100.0, Better::Higher)],
        ));
        let tonight: BTreeMap<String, Metric> = [
            m("qps", 800.0, Better::Higher),
            m("p99", 510.0, Better::Lower),
            m("rss", 64.0, Better::Lower),
            m("slow", 100.0, Better::Lower),
        ]
        .into_iter()
        .map(|x| (x.name.clone(), x))
        .collect();
        let rows = compare(&tonight, &nights);
        let by = |n: &str| rows.iter().find(|r| r.name == n).unwrap();
        assert_eq!(by("qps").verdict, Verdict::Regressed);
        assert_eq!(by("qps").base, Some(("20261118-aaaaaaa".into(), 1000.0)));
        assert_eq!(by("p99").verdict, Verdict::Same);
        assert_eq!(by("rss").verdict, Verdict::New);
        assert_eq!(
            by("slow").verdict,
            Verdict::Uncalibrated,
            "one night: no noise known"
        );
        let text = report(&rows, "abc1234 G9.9: algo (#999)\n");
        assert!(
            text.contains("## Pioraram") && text.contains("`qps`") && text.contains("+20.0 %"),
            "{text}"
        );
        assert!(text.contains("#999"), "{text}");
        assert!(!text.contains("`p99`"), "only what moved is listed: {text}");
        assert!(
            text.contains("## Ainda calibrando") && text.contains("`slow`"),
            "{text}"
        );
    }

    #[test]
    fn the_history_is_read_in_order_and_strange_files_are_skipped() {
        let d = std::env::temp_dir().join(format!("xtask-nightly-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let line = |v: f64| {
            format!("{{\"metric\":\"q\",\"value\":{v},\"unit\":\"qps\",\"better\":\"higher\"}}\n")
        };
        std::fs::write(d.join("20261120-bbbbbbb.red.jsonl"), line(1.0)).unwrap();
        std::fs::write(d.join("20261119-aaaaaaa.green.jsonl"), line(2.0)).unwrap();
        std::fs::write(d.join("README.md"), "x").unwrap();
        let n = read_history(&d).unwrap();
        assert_eq!(n.len(), 2);
        assert_eq!(
            (n[0].label.as_str(), n[0].green),
            ("20261119-aaaaaaa", true)
        );
        assert_eq!(
            (n[1].label.as_str(), n[1].green),
            ("20261120-bbbbbbb", false)
        );
        assert!(read_history(&d.join("none")).unwrap().is_empty());
        std::fs::remove_dir_all(&d).unwrap();
    }
}
