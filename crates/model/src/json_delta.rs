//! Structural difference between two JSON trees (audit-history): what a
//! revision file stores instead of a full copy of its config.
//!
//! A [`diff`] says how to build `new` from `old`; [`apply`] does it. The
//! delta is JSON itself, in three shapes:
//!
//! - `{}` — the value is unchanged;
//! - `{"=": v}` — the value is `v`;
//! - `{"o": {key: delta, …}, "d": [key, …]}` — an object: the keys under
//!   `o` change (recursively), the keys in `d` are gone, the rest are kept;
//! - `{"a": [op, …]}` — an array, built in order from `[start, len]` (a run
//!   of `old` items copied) and `{"i": [v, …]}` (new items).
//!
//! Lists whose items carry a unique string `id` (every config list:
//! `"*1A"`) are matched by it, so a one-item change in a 65 536-entry
//! address list stores that item and two copy runs, not the list; a moved
//! firewall rule is a few runs. Other lists keep their common prefix and
//! suffix.
//!
//! On load the delta is hostile input: [`apply`] bounds the depth, checks
//! every copy run against `old` and never builds an array longer than
//! `old` plus the new items it carries, so a small file cannot expand
//! into a huge tree.

use std::collections::{HashMap, HashSet};

use serde_json::{Map, Value};

/// Nesting followed by [`diff`] and accepted by [`apply`]; config trees
/// are under 10 deep. Deeper changes are stored whole.
pub const MAX_DEPTH: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("bad delta at {path}: {reason}")]
pub struct DeltaError {
    pub path: String,
    pub reason: String,
}

/// How to build `new` from `old` (`{}` when they are equal).
pub fn diff(old: &Value, new: &Value) -> Value {
    diff_at(old, new, 0).unwrap_or_else(|| Value::Object(Map::new()))
}

/// `old` with `delta` applied.
pub fn apply(old: &Value, delta: &Value) -> Result<Value, DeltaError> {
    apply_owned(old.clone(), delta)
}

/// [`apply`] reusing `old`: the parts the delta keeps are moved, not
/// copied (a boot walks 63 revisions of a big config this way).
pub fn apply_owned(old: Value, delta: &Value) -> Result<Value, DeltaError> {
    apply_at(old, delta, 0, &mut String::new())
}

fn obj(key: &str, v: Value) -> Value {
    let mut m = Map::new();
    m.insert(key.to_owned(), v);
    Value::Object(m)
}

fn replace(new: &Value) -> Value {
    obj("=", new.clone())
}

/// `None` when equal.
fn diff_at(old: &Value, new: &Value, depth: usize) -> Option<Value> {
    match (old, new) {
        (Value::Object(a), Value::Object(b)) if depth < MAX_DEPTH => {
            let new: Vec<(&str, &Value)> = b.iter().map(|(k, v)| (k.as_str(), v)).collect();
            diff_object(
                a.iter().map(|(k, v)| (k.as_str(), v)),
                &new,
                |o, n| Ok(diff_at(o, n, depth + 1)),
                |v| Ok(v.clone()),
            )
            .unwrap_or_default()
        }
        (Value::Array(a), Value::Array(b)) if depth < MAX_DEPTH => {
            let a: Vec<Item<'_, &Value>> = a.iter().map(|v| Item { id: id_of(v), v }).collect();
            let b: Vec<Item<'_, &Value>> = b.iter().map(|v| Item { id: id_of(v), v }).collect();
            diff_array(&a, &b, |v| Ok(v.clone())).unwrap_or_default()
        }
        _ if old == new => None,
        _ => Some(replace(new)),
    }
}

/// Object diff over any representation: `old` and `new` as (key, value)
/// pairs, `sub` diffs two values, `whole` turns a new value into a tree.
fn diff_object<'a, T: Copy + 'a>(
    old: impl Iterator<Item = (&'a str, T)>,
    new: &[(&'a str, T)],
    mut sub: impl FnMut(T, T) -> Result<Option<Value>, DeltaError>,
    mut whole: impl FnMut(T) -> Result<Value, DeltaError>,
) -> Result<Option<Value>, DeltaError> {
    let old: HashMap<&str, T> = old.collect();
    let mut changed = Map::new();
    for &(k, nv) in new {
        match old.get(k) {
            Some(&ov) => {
                if let Some(d) = sub(ov, nv)? {
                    changed.insert(k.to_owned(), d);
                }
            }
            None => {
                changed.insert(k.to_owned(), obj("=", whole(nv)?));
            }
        }
    }
    let kept: HashSet<&str> = new.iter().map(|(k, _)| *k).collect();
    let mut gone: Vec<&str> = old.keys().copied().filter(|k| !kept.contains(k)).collect();
    gone.sort_unstable();
    if changed.is_empty() && gone.is_empty() {
        return Ok(None);
    }
    let mut m = Map::new();
    m.insert("o".into(), Value::Object(changed));
    if !gone.is_empty() {
        let gone = gone.into_iter().map(|k| Value::String(k.to_owned()));
        m.insert("d".into(), Value::Array(gone.collect()));
    }
    Ok(Some(Value::Object(m)))
}

/// The `"id"` of a list item, if it has one.
fn id_of(v: &Value) -> Option<&str> {
    v.as_object()?.get("id")?.as_str()
}

/// A list item and its id.
struct Item<'a, T> {
    id: Option<&'a str>,
    v: T,
}

/// Builds the `{"a": [...]}` op list.
#[derive(Default)]
struct Ops {
    ops: Vec<Value>,
    run: Option<(usize, usize)>,
    new: Vec<Value>,
    copied: usize,
    pushed: usize,
}

impl Ops {
    fn copy(&mut self, at: usize) {
        self.flush_new();
        self.copied += 1;
        match &mut self.run {
            Some((start, len)) if start.saturating_add(*len) == at => *len += 1,
            _ => {
                self.flush_run();
                self.run = Some((at, 1));
            }
        }
    }
    fn copy_range(&mut self, start: usize, len: usize) {
        for i in start..start.saturating_add(len) {
            self.copy(i);
        }
    }
    fn push(&mut self, v: Value) {
        self.flush_run();
        self.pushed += 1;
        self.new.push(v);
    }
    fn flush_run(&mut self) {
        if let Some((s, l)) = self.run.take() {
            self.ops.push(Value::Array(vec![s.into(), l.into()]));
        }
    }
    fn flush_new(&mut self) {
        if !self.new.is_empty() {
            self.ops
                .push(obj("i", Value::Array(std::mem::take(&mut self.new))));
        }
    }
    fn finish(mut self) -> Vec<Value> {
        self.flush_run();
        self.flush_new();
        self.ops
    }
}

/// Item positions of `a` by id, when every item has a distinct one.
fn ids<'a, T>(a: &[Item<'a, T>]) -> Option<HashMap<&'a str, usize>> {
    let mut m = HashMap::with_capacity(a.len());
    for (i, item) in a.iter().enumerate() {
        if m.insert(item.id?, i).is_some() {
            return None;
        }
    }
    Some(m)
}

/// Array diff: lists whose items have distinct ids are matched by id,
/// others by common prefix and suffix. `whole` turns a new item into a
/// tree.
fn diff_array<T: PartialEq + Copy>(
    a: &[Item<'_, T>],
    b: &[Item<'_, T>],
    mut whole: impl FnMut(T) -> Result<Value, DeltaError>,
) -> Result<Option<Value>, DeltaError> {
    let mut ops = Ops::default();
    if let Some(by_id) = ids(a) {
        // An old item is copied at most once ([`apply`] moves it).
        let mut used = vec![false; a.len()];
        for item in b {
            match item.id.and_then(|id| by_id.get(id)) {
                Some(&j)
                    if a.get(j).is_some_and(|x| x.v == item.v)
                        && used.get_mut(j).is_some_and(|u| !std::mem::replace(u, true)) =>
                {
                    ops.copy(j)
                }
                _ => ops.push(whole(item.v)?),
            }
        }
    } else {
        let prefix = a.iter().zip(b).take_while(|(x, y)| x.v == y.v).count();
        let rest = a.len().min(b.len()).saturating_sub(prefix);
        let suffix = a
            .iter()
            .rev()
            .zip(b.iter().rev())
            .take(rest)
            .take_while(|(x, y)| x.v == y.v)
            .count();
        ops.copy_range(0, prefix);
        for item in b.get(prefix..b.len().saturating_sub(suffix)).unwrap_or_default() {
            ops.push(whole(item.v)?);
        }
        ops.copy_range(a.len().saturating_sub(suffix), suffix);
    }
    // Every item kept in place: one run from 0 (or none, both empty).
    let identity = ops.pushed == 0
        && a.len() == b.len()
        && ops.ops.is_empty()
        && ops.run.is_none_or(|(s, l)| s == 0 && l == a.len());
    if identity {
        return Ok(None);
    }
    if ops.copied == 0 {
        // Nothing kept: the whole new list (all of it is in `new`).
        return Ok(Some(replace(&Value::Array(ops.new))));
    }
    Ok(Some(obj("a", Value::Array(ops.finish()))))
}

fn bad(path: &str, reason: impl Into<String>) -> DeltaError {
    DeltaError {
        path: if path.is_empty() { "/".into() } else { path.chars().take(200).collect() },
        reason: reason.into(),
    }
}

fn apply_at(old: Value, delta: &Value, depth: usize, path: &mut String) -> Result<Value, DeltaError> {
    if depth > MAX_DEPTH {
        return Err(bad(path, "too deep"));
    }
    let Some(d) = delta.as_object() else {
        return Err(bad(path, "not an object"));
    };
    if d.is_empty() {
        return Ok(old);
    }
    if let Some(v) = d.get("=") {
        if d.len() != 1 {
            return Err(bad(path, "\"=\" with other keys"));
        }
        return Ok(v.clone());
    }
    if let Some(ops) = d.get("a") {
        if d.len() != 1 {
            return Err(bad(path, "\"a\" with other keys"));
        }
        let Value::Array(base) = old else {
            return Err(bad(path, "array edit on a non-array"));
        };
        let Some(ops) = ops.as_array() else {
            return Err(bad(path, "\"a\" is not a list"));
        };
        return apply_array(base, ops, path);
    }
    let Value::Object(mut out) = old else {
        return Err(bad(path, "object edit on a non-object"));
    };
    let changed = match d.get("o") {
        Some(Value::Object(m)) => m,
        _ => return Err(bad(path, "unknown delta")),
    };
    let gone = match d.get("d") {
        None => &[][..],
        Some(Value::Array(g)) => g.as_slice(),
        Some(_) => return Err(bad(path, "\"d\" is not a list")),
    };
    if d.keys().any(|k| k != "o" && k != "d") {
        return Err(bad(path, "unknown key"));
    }
    for k in gone {
        let Some(k) = k.as_str() else {
            return Err(bad(path, "\"d\" holds a non-string"));
        };
        if out.remove(k).is_none() {
            return Err(bad(path, format!("removes missing key {}", trunc(k))));
        }
    }
    for (k, sub) in changed {
        let len = path.len();
        path.push('/');
        path.push_str(&trunc(k));
        let v = match out.remove(k) {
            Some(ov) => apply_at(ov, sub, depth + 1, path)?,
            // A key the old tree lacks can only be set whole.
            None => match sub.as_object().and_then(|m| m.get("=")) {
                Some(v) if sub.as_object().is_some_and(|m| m.len() == 1) => v.clone(),
                _ => return Err(bad(path, "edits a missing key")),
            },
        };
        path.truncate(len);
        out.insert(k.clone(), v);
    }
    Ok(Value::Object(out))
}

fn trunc(s: &str) -> String {
    s.chars().take(64).collect()
}

fn apply_array(base: Vec<Value>, ops: &[Value], path: &str) -> Result<Value, DeltaError> {
    // Each copy run is checked against `base` and takes its items once, so
    // the result is never larger than `base` plus what the delta carries.
    let total = base.len();
    let mut slots: Vec<Option<Value>> = base.into_iter().map(Some).collect();
    let mut out: Vec<Value> = Vec::with_capacity(total);
    for op in ops {
        match op {
            Value::Array(run) => {
                let (Some(start), Some(len), 2) = (
                    run.first().and_then(Value::as_u64),
                    run.get(1).and_then(Value::as_u64),
                    run.len(),
                ) else {
                    return Err(bad(path, "copy run is not [start, len]"));
                };
                let (Ok(start), Ok(len)) = (usize::try_from(start), usize::try_from(len)) else {
                    return Err(bad(path, "copy run out of range"));
                };
                let Some(items) = start
                    .checked_add(len)
                    .and_then(|end| slots.get_mut(start..end))
                else {
                    return Err(bad(path, format!("copy run {start}+{len} past {total}")));
                };
                for item in items {
                    let Some(v) = item.take() else {
                        return Err(bad(path, "copy runs overlap"));
                    };
                    out.push(v);
                }
            }
            Value::Object(m) => match (m.get("i"), m.len()) {
                (Some(Value::Array(items)), 1) => out.extend_from_slice(items),
                _ => return Err(bad(path, "unknown array op")),
            },
            _ => return Err(bad(path, "unknown array op")),
        }
    }
    Ok(Value::Array(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    fn round(a: &Value, b: &Value) -> Value {
        let d = diff(a, b);
        let back: Value = serde_json::from_str(&d.to_string()).unwrap();
        assert_eq!(apply(a, &back).unwrap(), *b, "delta {d}");
        d
    }

    fn list(n: usize) -> Vec<Value> {
        (0..n)
            .map(|i| json!({"id": format!("*{:X}", i + 1), "address": format!("10.0.{}.{}", i / 256, i % 256)}))
            .collect()
    }

    #[test]
    fn equal_trees_give_an_empty_delta() {
        let a = json!({"x": 1, "l": [1, 2]});
        assert_eq!(round(&a, &a), json!({}));
        assert_eq!(round(&json!([]), &json!([])), json!({}));
    }

    #[test]
    fn one_item_changed_in_a_big_id_list_stores_that_item_only() {
        let a = json!({"ip": {"lists": list(65_536)}, "name": "r"});
        let mut b = a.clone();
        b["ip"]["lists"][40_000]["address"] = json!("192.0.2.1");
        let d = round(&a, &b);
        let size = d.to_string().len();
        assert!(size < 200, "{size} bytes: {d}");
        // Removed, inserted and moved items too.
        let mut c = a.clone();
        let items = c["ip"]["lists"].as_array_mut().unwrap();
        items.remove(10);
        let moved = items.remove(500);
        items.insert(3, moved);
        items.push(json!({"id": "*FFFFF", "address": "1.1.1.1"}));
        let d = round(&a, &c);
        assert!(d.to_string().len() < 300, "{d}");
    }

    #[test]
    fn lists_without_ids_keep_prefix_and_suffix() {
        let a = json!(["a", "b", "c", "d", "e"]);
        round(&a, &json!(["a", "b", "x", "d", "e"]));
        round(&a, &json!(["a", "b", "d", "e"]));
        round(&a, &json!(["a", "b", "c", "c", "d", "e"]));
        round(&a, &json!([]));
        round(&json!([]), &a);
        // Duplicate ids: positional.
        round(&json!([{"id": "*1"}, {"id": "*1"}]), &json!([{"id": "*1"}]));
        // Duplicated in the new list: the old item is copied once.
        round(&json!([{"id": "*1"}, {"id": "*2"}]), &json!([{"id": "*1"}, {"id": "*1"}]));
    }

    #[test]
    fn keys_added_removed_and_type_changes() {
        let a = json!({"a": 1, "b": {"c": [1]}, "gone": true});
        round(&a, &json!({"a": "1", "b": {"c": {"x": null}}, "new": [1, 2]}));
        round(&a, &json!(3));
        round(&json!(null), &a);
    }

    #[test]
    fn hostile_deltas_are_refused() {
        let base = json!({"l": [1, 2, 3], "o": {"k": 1}});
        for d in [
            json!(1),
            json!({"x": 1}),
            json!({"=": 1, "o": {}}),
            json!({"o": {"l": {"a": [[2, 5]]}}}),
            json!({"o": {"l": {"a": [[0, 3], [0, 3]]}}}),
            json!({"o": {"l": {"a": [[-1, 1]]}}}),
            json!({"o": {"l": {"a": [[0]]}}}),
            json!({"o": {"l": {"a": ["x"]}}}),
            json!({"o": {"l": {"a": [{"i": 1}]}}}),
            json!({"o": {"o": {"a": []}}}),
            json!({"o": {"l": {"o": {}}}}),
            json!({"o": {"missing": {"o": {}}}}),
            json!({"o": {}, "d": ["missing"]}),
            json!({"o": {}, "d": [1]}),
        ] {
            assert!(apply(&base, &d).is_err(), "{d}");
        }
        // Deeper than MAX_DEPTH.
        let mut deep = json!({"=": 1});
        for _ in 0..=MAX_DEPTH {
            deep = json!({"o": {"k": deep}});
        }
        let mut tree = json!(1);
        for _ in 0..=MAX_DEPTH + 1 {
            tree = json!({"k": tree});
        }
        assert!(apply(&tree, &deep).is_err());
    }

    fn value() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof![
            Just(Value::Null),
            any::<bool>().prop_map(Value::from),
            (0u8..4).prop_map(Value::from),
            "[a-c]{0,2}".prop_map(Value::from),
        ];
        leaf.prop_recursive(4, 40, 6, |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
                prop::collection::btree_map("[a-d]", inner.clone(), 0..5)
                    .prop_map(|m| Value::Object(m.into_iter().collect())),
                // Lists of items with ids, as in the config.
                prop::collection::vec((0u8..6, inner), 0..6).prop_map(|v| {
                    Value::Array(
                        v.into_iter()
                            .map(|(id, x)| json!({"id": format!("*{id}"), "v": x}))
                            .collect(),
                    )
                }),
            ]
        })
    }

    proptest! {
        #[test]
        fn apply_of_diff_gives_the_new_tree(a in value(), b in value()) {
            let d = diff(&a, &b);
            prop_assert_eq!(apply(&a, &d).unwrap(), b.clone());
        }

        #[test]
        fn apply_never_panics_on_garbage(a in value(), d in value()) {
            let _ = apply(&a, &d);
        }
    }
}
