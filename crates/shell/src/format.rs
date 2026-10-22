//! `print` output, RouterOS style: a flags legend, a numbered table with a
//! flags column, `;;; comment` lines above items, `detail` as
//! `key=value` lines, one-object menus as right-aligned `key: value`.
//!
//! Columns and flags come from the command's result doc and the rows
//! themselves: a `flags` field with its legend (`flags (X disabled, …)`),
//! else the conventional boolean fields below.

use serde_json::{Map, Value};

use crate::doc::{Shape, kebab};
use crate::parse::{Cond, Op, PrintOpts, Term};
use crate::style::{Line, Style};

/// Boolean fields shown as flags when a row has no `flags` field.
const FLAG_FIELDS: &[(&str, char)] = &[
    ("disabled", 'X'),
    ("invalid", 'I'),
    ("dynamic", 'D'),
    ("running", 'R'),
    ("active", 'A'),
];

/// Width at which `detail` wraps its `key=value` pairs.
const DETAIL_WIDTH: usize = 96;

pub fn value_text(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::Bool(true) => "yes".into(),
        Value::Bool(false) => "no".into(),
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Array(a) => a.iter().map(value_text).collect::<Vec<_>>().join(","),
        Value::Object(o) => o
            .iter()
            .filter(|(_, v)| !v.is_null())
            .map(|(k, v)| format!("{}={}", kebab(k), value_text(v)))
            .collect::<Vec<_>>()
            .join(" "),
    }
}

fn is_empty(v: &Value) -> bool {
    match v {
        Value::Null => true,
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
        _ => false,
    }
}

/// Fields the flags column stands for, and its legend.
fn flag_fields(shape: &Shape, rows: &[Value]) -> (Vec<String>, Vec<(char, String)>) {
    if !shape.legend.is_empty() {
        let mut hidden: Vec<String> = shape.legend.iter().map(|(_, m)| m.clone()).collect();
        hidden.push("flags".into());
        return (hidden, shape.legend.clone());
    }
    let present =
        |f: &str| shape.fields.iter().any(|x| x == f) || rows.iter().any(|r| r.get(f).is_some());
    let used: Vec<(char, String)> = FLAG_FIELDS
        .iter()
        .filter(|(f, _)| present(f))
        .map(|(f, c)| (*c, (*f).to_owned()))
        .collect();
    (used.iter().map(|(_, f)| f.clone()).collect(), used)
}

fn row_flags(row: &Value, legend: &[(char, String)]) -> String {
    if let Some(f) = row.get("flags").and_then(Value::as_str) {
        return f.chars().take(8).collect();
    }
    legend
        .iter()
        .filter(|(_, f)| row.get(f.as_str()).and_then(Value::as_bool) == Some(true))
        .map(|(c, _)| *c)
        .collect()
}

fn disabled(row: &Value) -> bool {
    row.get("disabled").and_then(Value::as_bool) == Some(true)
}

/// Field order: the doc's, then any extra field the rows carry.
fn field_order(shape: &Shape, rows: &[Value]) -> Vec<String> {
    let mut out = shape.fields.clone();
    for r in rows {
        if let Some(o) = r.as_object() {
            for k in o.keys() {
                if !out.contains(k) {
                    out.push(k.clone());
                }
            }
        }
    }
    out
}

fn legend_line(legend: &[(char, String)]) -> Option<Line> {
    if legend.is_empty() {
        return None;
    }
    let text = legend
        .iter()
        .map(|(c, m)| format!("{c} - {m}"))
        .collect::<Vec<_>>()
        .join(", ");
    Some(Line::styled(Style::Header, format!("Flags: {text}")))
}

fn pad(s: &str, width: usize) -> String {
    let n = s.chars().count();
    let mut out = s.to_owned();
    out.extend(std::iter::repeat_n(' ', width.saturating_sub(n)));
    out
}

fn rpad(s: &str, width: usize) -> String {
    let n = s.chars().count();
    let mut out: String = std::iter::repeat_n(' ', width.saturating_sub(n)).collect();
    out.push_str(s);
    out
}

/// The numbered table of `print` (or, `numbers = false`, a plain table for
/// query results such as `/config history`).
pub fn table(rows: &[Value], shape: &Shape, opts: &PrintOpts, numbers: bool) -> Vec<Line> {
    let (flag_cols, legend) = flag_fields(shape, rows);
    let mut cols: Vec<String> = match &opts.proplist {
        Some(p) => p.clone(),
        None => field_order(shape, rows)
            .into_iter()
            .filter(|f| f != "id" && f != "comment" && !flag_cols.contains(f))
            .filter(|f| rows.iter().any(|r| r.get(f).is_some_and(|v| !is_empty(v))))
            .collect(),
    };
    cols.dedup();
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|r| {
            cols.iter()
                .map(|c| r.get(c).map(value_text).unwrap_or_default())
                .collect()
        })
        .collect();
    let labels: Vec<String> = rows
        .iter()
        .enumerate()
        .map(
            |(i, r)| match (opts.show_ids, r.get("id").and_then(Value::as_str)) {
                (true, Some(id)) => id.to_owned(),
                _ => i.to_string(),
            },
        )
        .collect();
    let num_w = labels
        .iter()
        .map(|l| l.chars().count())
        .max()
        .unwrap_or(1)
        .max(1);
    let flags: Vec<String> = rows.iter().map(|r| row_flags(r, &legend)).collect();
    let flag_w = if legend.is_empty() {
        0
    } else {
        flags
            .iter()
            .map(|f| f.chars().count())
            .max()
            .unwrap_or(0)
            .max(1)
    };
    let widths: Vec<usize> = cols
        .iter()
        .enumerate()
        .map(|(i, c)| {
            cells
                .iter()
                .filter_map(|row| row.get(i))
                .map(|s| s.chars().count())
                .chain(std::iter::once(c.chars().count()))
                .max()
                .unwrap_or(0)
        })
        .collect();

    let mut out = Vec::new();
    if numbers && let Some(l) = legend_line(&legend) {
        out.push(l);
    }
    let lead = |num: &str, flags: &str| -> String {
        let mut s = String::new();
        if numbers {
            s.push(' ');
            s.push_str(&rpad(num, num_w));
            s.push(' ');
        }
        if flag_w > 0 {
            s.push_str(&pad(flags, flag_w));
            s.push(' ');
        }
        s
    };
    let mut header = Line::new();
    header.push(Style::Header, lead("#", ""));
    let heads: Vec<String> = cols
        .iter()
        .zip(&widths)
        .map(|(c, w)| pad(&kebab(c).to_uppercase(), *w))
        .collect();
    header.push(Style::Header, heads.join("  ").trim_end().to_owned());
    out.push(header);
    for (i, row) in rows.iter().enumerate() {
        let num = labels.get(i).map_or("", String::as_str);
        let fl = flags.get(i).map_or("", String::as_str);
        if let Some(c) = row
            .get("comment")
            .and_then(Value::as_str)
            .filter(|c| !c.is_empty())
        {
            let mut l = Line::new();
            l.push(Style::Plain, lead("", ""));
            l.push(Style::Comment, format!(";;; {c}"));
            out.push(l);
        }
        let mut l = Line::new();
        if numbers {
            l.push(Style::Item, format!(" {} ", rpad(num, num_w)));
        }
        if flag_w > 0 {
            l.push(Style::Flag, format!("{} ", pad(fl, flag_w)));
        }
        let style = if disabled(row) {
            Style::Dim
        } else {
            Style::Plain
        };
        let text: Vec<String> = cells
            .get(i)
            .map(|r| r.iter().zip(&widths).map(|(c, w)| pad(c, *w)).collect())
            .unwrap_or_default();
        l.push(style, text.join("  ").trim_end().to_owned());
        out.push(l);
    }
    out
}

/// `print detail`: one block per item, `key=value` pairs wrapped.
pub fn detail(rows: &[Value], shape: &Shape, opts: &PrintOpts) -> Vec<Line> {
    let (flag_cols, legend) = flag_fields(shape, rows);
    let mut out = Vec::new();
    if let Some(l) = legend_line(&legend) {
        out.push(l);
    }
    let num_w = rows.len().saturating_sub(1).to_string().len();
    let flag_w = rows
        .iter()
        .map(|r| row_flags(r, &legend).chars().count())
        .max()
        .unwrap_or(0);
    let indent = " ".repeat(num_w + 2 + flag_w + usize::from(flag_w > 0));
    for (i, row) in rows.iter().enumerate() {
        let label = match (opts.show_ids, row.get("id").and_then(Value::as_str)) {
            (true, Some(id)) => id.to_owned(),
            _ => i.to_string(),
        };
        let fl = row_flags(row, &legend);
        let mut first = Line::new();
        first.push(Style::Item, format!(" {} ", rpad(&label, num_w)));
        if flag_w > 0 {
            first.push(Style::Flag, format!("{} ", pad(&fl, flag_w)));
        }
        let fields: Vec<String> = match &opts.proplist {
            Some(p) => p.clone(),
            None => field_order(shape, rows)
                .into_iter()
                .filter(|f| f != "comment" && f != "flags" && !flag_cols.contains(f))
                .filter(|f| opts.show_ids || f != "id")
                .collect(),
        };
        let pairs: Vec<(String, String)> = fields
            .iter()
            .filter_map(|f| row.get(f).map(|v| (kebab(f), v)))
            .filter(|(_, v)| !v.is_null())
            .map(|(k, v)| {
                let t = value_text(v);
                (k, crate::lex::quote(&t))
            })
            .collect();
        let mut lines: Vec<Line> = Vec::new();
        let mut cur = first;
        let mut width = indent.chars().count();
        if let Some(c) = row
            .get("comment")
            .and_then(Value::as_str)
            .filter(|c| !c.is_empty())
        {
            cur.push(Style::Comment, format!(";;; {c}"));
            lines.push(cur);
            cur = Line::styled(Style::Plain, indent.clone());
        }
        let mut empty = true;
        for (k, v) in pairs {
            let len = k.chars().count() + v.chars().count() + 2;
            if !empty && width + len > DETAIL_WIDTH {
                lines.push(cur);
                cur = Line::styled(Style::Plain, indent.clone());
                width = indent.chars().count();
            }
            cur.push(Style::Key, format!("{k}="));
            cur.push(Style::Value, format!("{v} "));
            width += len;
            empty = false;
        }
        lines.push(cur);
        out.extend(lines);
        out.push(Line::new());
    }
    out
}

/// One object (`print` of a one-object menu, a command's result): keys
/// right-aligned, multi-line values indented under the first line.
pub fn object(v: &Value, fields: &[String]) -> Vec<Line> {
    let Some(o) = v.as_object() else {
        return vec![Line::plain(value_text(v))];
    };
    let mut keys: Vec<&String> = fields.iter().filter(|f| o.contains_key(*f)).collect();
    for k in o.keys() {
        if !keys.contains(&k) {
            keys.push(k);
        }
    }
    let w = keys
        .iter()
        .map(|k| kebab(k).chars().count())
        .max()
        .unwrap_or(0)
        + 2;
    let mut out = Vec::new();
    for k in keys {
        let val = o.get(k.as_str()).map(value_text).unwrap_or_default();
        let mut lines = val.lines();
        let mut l = Line::new();
        l.push(Style::Key, format!("{}: ", rpad(&kebab(k), w)));
        l.push(Style::Value, lines.next().unwrap_or("").to_owned());
        out.push(l);
        for more in lines {
            out.push(Line::plain(format!("{}{more}", " ".repeat(w + 2))));
        }
    }
    out
}

/// Rows kept by a `where` condition.
pub fn filter(rows: Vec<Value>, cond: Option<&Cond>) -> Vec<Value> {
    match cond {
        None => rows,
        Some(c) => rows.into_iter().filter(|r| matches(r, c)).collect(),
    }
}

pub fn matches(row: &Value, cond: &Cond) -> bool {
    cond.iter().any(|all| all.iter().all(|t| term(row, t)))
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        _ => !is_empty(v),
    }
}

fn parse_bool(s: &str) -> Option<bool> {
    match s {
        "yes" | "true" => Some(true),
        "no" | "false" => Some(false),
        _ => None,
    }
}

fn eq(v: &Value, rhs: &str) -> bool {
    match v {
        Value::Null => rhs.is_empty(),
        Value::Bool(b) => parse_bool(rhs) == Some(*b),
        Value::Number(n) => match (n.as_f64(), rhs.parse::<f64>()) {
            (Some(a), Ok(b)) => a == b,
            _ => n.to_string() == rhs,
        },
        Value::Array(a) => a.iter().any(|x| eq(x, rhs)) || value_text(v) == rhs,
        _ => value_text(v) == rhs,
    }
}

fn order(v: &Value, rhs: &str) -> Option<std::cmp::Ordering> {
    let text = value_text(v);
    match (text.parse::<f64>(), rhs.parse::<f64>()) {
        (Ok(a), Ok(b)) => a.partial_cmp(&b),
        _ => Some(text.as_str().cmp(rhs)),
    }
}

fn term(row: &Value, t: &Term) -> bool {
    let v = row.get(&t.field).unwrap_or(&Value::Null);
    let hit = match &t.op {
        None => truthy(v),
        Some((op, rhs)) => {
            use std::cmp::Ordering::{Greater, Less};
            match op {
                Op::Eq => eq(v, rhs),
                Op::Ne => !eq(v, rhs),
                Op::Contains => value_text(v).contains(rhs.as_str()),
                Op::Lt => order(v, rhs) == Some(Less),
                Op::Gt => order(v, rhs) == Some(Greater),
                Op::Le => order(v, rhs).is_some_and(|o| o != Greater),
                Op::Ge => order(v, rhs).is_some_and(|o| o != Less),
            }
        }
    };
    hit != t.negate
}

/// Rows reduced to the `proplist` (for `as-json`).
pub fn project(rows: &[Value], proplist: Option<&Vec<String>>) -> Value {
    let Some(p) = proplist else {
        return Value::Array(rows.to_vec());
    };
    Value::Array(
        rows.iter()
            .map(|r| {
                let mut m = Map::new();
                for k in p {
                    if let Some(v) = r.get(k) {
                        m.insert(k.clone(), v.clone());
                    }
                }
                Value::Object(m)
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doc::shape;
    use serde_json::json;

    fn routes() -> (Vec<Value>, Shape) {
        let s = shape(
            "{} → [{id, dst_address, gateway, distance, flags (X disabled, A active, D dynamic, C connected, S static), active, static, connected, disabled, comment}]",
        );
        let rows = vec![
            json!({"id": null, "dst_address": "10.0.0.0/24", "gateway": "ether1", "distance": 0, "flags": "DAC", "active": true, "static": false, "connected": true, "disabled": false, "comment": ""}),
            json!({"id": "*1", "dst_address": "0.0.0.0/0", "gateway": "10.0.0.254", "distance": 1, "flags": "XS", "active": false, "static": true, "connected": false, "disabled": true, "comment": "default via ISP"}),
        ];
        (rows, s)
    }

    #[test]
    fn table_has_legend_numbers_flags_and_comments() {
        let (rows, s) = routes();
        let text: Vec<String> = table(&rows, &s, &PrintOpts::default(), true)
            .iter()
            .map(Line::text)
            .collect();
        assert_eq!(
            text[0],
            "Flags: X - disabled, A - active, D - dynamic, C - connected, S - static"
        );
        assert!(text[1].contains("DST-ADDRESS") && text[1].contains("GATEWAY"));
        assert!(!text[1].contains("ACTIVE"), "flag fields are not columns");
        assert!(text[2].starts_with(" 0 DAC 10.0.0.0/24"), "{}", text[2]);
        assert!(text[3].contains(";;; default via ISP"));
        assert!(text[4].starts_with(" 1 XS  0.0.0.0/0"), "{}", text[4]);
    }

    #[test]
    fn conventional_flags_from_booleans() {
        let s = shape("{} → [{name, type, disabled, running, comment}]");
        let rows = vec![
            json!({"name": "ether1", "type": "ether", "disabled": false, "running": true}),
            json!({"name": "v10", "type": "vlan", "disabled": true, "running": false}),
        ];
        let text: Vec<String> = table(&rows, &s, &PrintOpts::default(), true)
            .iter()
            .map(Line::text)
            .collect();
        assert_eq!(text[0], "Flags: X - disabled, R - running");
        assert!(text[2].starts_with(" 0 R ether1"), "{}", text[2]);
        assert!(text[3].starts_with(" 1 X v10"), "{}", text[3]);
    }

    #[test]
    fn where_terms() {
        let (rows, _) = routes();
        let c = |field: &str, negate: bool, op: Option<(Op, &str)>| {
            vec![vec![Term {
                field: field.into(),
                negate,
                op: op.map(|(o, v)| (o, v.to_owned())),
            }]]
        };
        assert_eq!(
            filter(rows.clone(), Some(&c("static", false, None))).len(),
            1
        );
        assert_eq!(
            filter(rows.clone(), Some(&c("static", true, None))).len(),
            1
        );
        assert_eq!(
            filter(
                rows.clone(),
                Some(&c("disabled", false, Some((Op::Eq, "yes"))))
            )
            .len(),
            1
        );
        assert_eq!(
            filter(
                rows.clone(),
                Some(&c("distance", false, Some((Op::Ge, "1"))))
            )
            .len(),
            1
        );
        assert_eq!(
            filter(
                rows.clone(),
                Some(&c("comment", false, Some((Op::Contains, "ISP"))))
            )
            .len(),
            1
        );
        assert_eq!(
            filter(rows, Some(&c("gateway", false, Some((Op::Ne, "ether1"))))).len(),
            1
        );
    }

    #[test]
    fn object_aligns_keys_and_indents_lines() {
        let lines = object(
            &json!({"name": "default", "frr": "a\nb"}),
            &["name".into(), "frr".into()],
        );
        let text: Vec<String> = lines.iter().map(Line::text).collect();
        assert_eq!(text[0], "  name: default");
        assert_eq!(text[1], "   frr: a");
        assert_eq!(text[2], "        b");
    }
}
