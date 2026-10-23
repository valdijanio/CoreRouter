//! A [`json_delta`] applied to a typed [`Config`], section by section
//! (audit-history): what a boot does 63 times to rebuild the history from
//! the revision files.
//!
//! The big sections of a config are [`CowArc`]s (G0.16). Revision `k` is
//! built from revision `k+1` by cloning it (reference counts only) and
//! replacing just the sections the delta touches: a section the delta does
//! not name is the same allocation in both revisions (`CowArc::ptr_eq`), so
//! 64 revisions of a 10 MiB config cost the memory of one plus what they
//! changed, and a boot parses only the changed sections. The small fields of
//! a level (`Config`, `Ip`, `Firewall`) are rebuilt through JSON together,
//! with the big sections left empty while they are.
//!
//! The result is the same as applying the delta to the whole tree and
//! deserializing it (tested), and the delta is as hostile here as there.
//! [`diff`] is the other way: a commit's revision file serializes only the
//! sections the commit changed, the ones it shares with the new revision
//! are skipped by pointer.

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use crate::config::{Config, Ip};
use crate::cow::CowArc;
use crate::firewall::Firewall;
use crate::json_delta;
use crate::persist::PersistError;

/// What the delta does to one big section.
#[derive(Clone, Copy)]
enum Op<'a> {
    Keep,
    Patch(&'a Value),
    Remove,
}

/// `base` with `delta` applied (a delta between the JSON forms of two
/// configs, [`json_delta::diff`]).
pub fn apply(base: &Config, delta: &Value) -> Result<Config, PersistError> {
    level(
        base,
        delta,
        &["interfaces", "ip"],
        |c| {
            let mut light = c.clone();
            light.interfaces = CowArc::default();
            light.ip = CowArc::default();
            light
        },
        |out, base, key, op| {
            match key {
                "interfaces" => out.interfaces = section(&base.interfaces, op)?,
                "ip" => {
                    out.ip = match op {
                        Op::Keep => base.ip.clone(),
                        Op::Remove => CowArc::default(),
                        Op::Patch(d) => CowArc::new(apply_ip(&base.ip, d)?),
                    }
                }
                _ => {}
            }
            Ok(())
        },
    )
}

fn apply_ip(base: &Ip, delta: &Value) -> Result<Ip, PersistError> {
    level(
        base,
        delta,
        &[
            "addresses",
            "routes",
            "firewall",
            "dns_static",
            "dns_zones",
            "dhcp_server",
        ],
        |ip| {
            let mut light = ip.clone();
            light.addresses = CowArc::default();
            light.routes = CowArc::default();
            light.firewall = CowArc::default();
            light.dns_static = CowArc::default();
            light.dns_zones = CowArc::default();
            light.dhcp_server = CowArc::default();
            light
        },
        |out, base, key, op| {
            match key {
                "addresses" => out.addresses = section(&base.addresses, op)?,
                "routes" => out.routes = section(&base.routes, op)?,
                "dns_static" => out.dns_static = section(&base.dns_static, op)?,
                "dns_zones" => out.dns_zones = section(&base.dns_zones, op)?,
                "dhcp_server" => out.dhcp_server = section(&base.dhcp_server, op)?,
                "firewall" => {
                    out.firewall = match op {
                        Op::Keep => base.firewall.clone(),
                        Op::Remove => CowArc::default(),
                        Op::Patch(d) => CowArc::new(apply_firewall(&base.firewall, d)?),
                    }
                }
                _ => {}
            }
            Ok(())
        },
    )
}

fn apply_firewall(base: &Firewall, delta: &Value) -> Result<Firewall, PersistError> {
    level(
        base,
        delta,
        &["filter", "nat", "mangle", "address_lists"],
        |f| {
            let mut light = f.clone();
            light.filter = CowArc::default();
            light.nat = CowArc::default();
            light.mangle = CowArc::default();
            light.address_lists = CowArc::default();
            light
        },
        |out, base, key, op| {
            match key {
                "filter" => out.filter = section(&base.filter, op)?,
                "nat" => out.nat = section(&base.nat, op)?,
                "mangle" => out.mangle = section(&base.mangle, op)?,
                "address_lists" => out.address_lists = section(&base.address_lists, op)?,
                _ => {}
            }
            Ok(())
        },
    )
}

/// How to build `new` from `old`: the same delta as [`json_delta::diff`] of
/// their JSON forms, but a big section the two share (`CowArc::ptr_eq`,
/// what a commit leaves untouched) or that is equal is never serialized.
/// A commit's revision file costs what the commit changed.
pub fn diff(old: &Config, new: &Config) -> Result<Value, PersistError> {
    Ok(diff_config(old, new)?.unwrap_or_else(|| Value::Object(Map::new())))
}

fn diff_config(a: &Config, b: &Config) -> Result<Option<Value>, PersistError> {
    let light = |c: &Config| {
        let mut l = c.clone();
        l.interfaces = CowArc::default();
        l.ip = CowArc::default();
        l
    };
    let Some(mut p) = Parts::small(a, b, light)? else {
        return whole(a, b);
    };
    p.section("interfaces", &a.interfaces, &b.interfaces, |_| true)?;
    if !CowArc::ptr_eq(&a.ip, &b.ip) && *a.ip != *b.ip {
        p.nested("ip", diff_ip(&a.ip, &b.ip)?);
    }
    Ok(p.finish())
}

fn diff_ip(a: &Ip, b: &Ip) -> Result<Option<Value>, PersistError> {
    let light = |ip: &Ip| {
        let mut l = ip.clone();
        l.addresses = CowArc::default();
        l.routes = CowArc::default();
        l.firewall = CowArc::default();
        l.dns_static = CowArc::default();
        l.dns_zones = CowArc::default();
        l.dhcp_server = CowArc::default();
        l
    };
    let Some(mut p) = Parts::small(a, b, light)? else {
        return whole(a, b);
    };
    p.section("addresses", &a.addresses, &b.addresses, |_| true)?;
    p.section("routes", &a.routes, &b.routes, |_| true)?;
    p.section("dns_static", &a.dns_static, &b.dns_static, |s| !s.is_empty())?;
    p.section("dns_zones", &a.dns_zones, &b.dns_zones, |s| !s.is_empty())?;
    p.section("dhcp_server", &a.dhcp_server, &b.dhcp_server, |s| !s.is_empty())?;
    if !CowArc::ptr_eq(&a.firewall, &b.firewall) && *a.firewall != *b.firewall {
        p.nested("firewall", diff_firewall(&a.firewall, &b.firewall)?);
    }
    Ok(p.finish())
}

fn diff_firewall(a: &Firewall, b: &Firewall) -> Result<Option<Value>, PersistError> {
    let light = |f: &Firewall| {
        let mut l = f.clone();
        l.filter = CowArc::default();
        l.nat = CowArc::default();
        l.mangle = CowArc::default();
        l.address_lists = CowArc::default();
        l
    };
    let Some(mut p) = Parts::small(a, b, light)? else {
        return whole(a, b);
    };
    p.section("filter", &a.filter, &b.filter, |_| true)?;
    p.section("nat", &a.nat, &b.nat, |_| true)?;
    p.section("mangle", &a.mangle, &b.mangle, |_| true)?;
    p.section("address_lists", &a.address_lists, &b.address_lists, |_| true)?;
    Ok(p.finish())
}

/// The delta of a whole value, through its JSON tree.
fn whole<S: Serialize>(a: &S, b: &S) -> Result<Option<Value>, PersistError> {
    let a = serde_json::to_value(a).map_err(malformed)?;
    let b = serde_json::to_value(b).map_err(malformed)?;
    let d = json_delta::diff(&a, &b);
    Ok(d.as_object().is_some_and(|m| !m.is_empty()).then_some(d))
}

/// An object delta being built: changed keys and removed keys.
struct Parts {
    changed: Map<String, Value>,
    gone: Vec<String>,
}

impl Parts {
    /// The small fields (big sections emptied by `light`), or `None` when
    /// the delta is not an object edit (never for these structs).
    fn small<S: Serialize>(a: &S, b: &S, light: impl Fn(&S) -> S) -> Result<Option<Self>, PersistError> {
        let la = serde_json::to_value(light(a)).map_err(malformed)?;
        let lb = serde_json::to_value(light(b)).map_err(malformed)?;
        let Value::Object(mut d) = json_delta::diff(&la, &lb) else {
            return Ok(None);
        };
        if d.contains_key("=") || d.contains_key("a") {
            return Ok(None);
        }
        let changed = match d.remove("o") {
            Some(Value::Object(m)) => m,
            _ => Map::new(),
        };
        let gone = match d.remove("d") {
            Some(Value::Array(g)) => g.into_iter().filter_map(|k| k.as_str().map(str::to_owned)).collect(),
            _ => Vec::new(),
        };
        Ok(Some(Self { changed, gone }))
    }

    /// A big section; `present` says whether the struct writes it (fields
    /// skipped when empty are absent from the JSON).
    fn section<T: Serialize + PartialEq>(
        &mut self,
        key: &str,
        a: &CowArc<T>,
        b: &CowArc<T>,
        present: impl Fn(&T) -> bool,
    ) -> Result<(), PersistError> {
        if CowArc::ptr_eq(a, b) || **a == **b {
            return Ok(());
        }
        match (present(a), present(b)) {
            (false, false) => {}
            (true, false) => self.gone.push(key.to_owned()),
            (false, true) => {
                let v = serde_json::to_value(&**b).map_err(malformed)?;
                self.changed.insert(key.to_owned(), obj("=", v));
            }
            (true, true) => {
                if let Some(d) = whole(&**a, &**b)? {
                    self.changed.insert(key.to_owned(), d);
                }
            }
        }
        Ok(())
    }

    fn nested(&mut self, key: &str, d: Option<Value>) {
        if let Some(d) = d {
            self.changed.insert(key.to_owned(), d);
        }
    }

    fn finish(mut self) -> Option<Value> {
        if self.changed.is_empty() && self.gone.is_empty() {
            return None;
        }
        let mut m = Map::new();
        m.insert("o".into(), Value::Object(self.changed));
        if !self.gone.is_empty() {
            self.gone.sort_unstable();
            let gone = self.gone.into_iter().map(Value::String).collect();
            m.insert("d".into(), Value::Array(gone));
        }
        Some(Value::Object(m))
    }
}

fn obj(key: &str, v: Value) -> Value {
    let mut m = Map::new();
    m.insert(key.to_owned(), v);
    Value::Object(m)
}

fn inconsistent(e: impl std::fmt::Display) -> PersistError {
    PersistError::Inconsistent(e.to_string())
}

fn malformed(e: serde_json::Error) -> PersistError {
    PersistError::Malformed(e.to_string())
}

/// One big section: kept (shared), emptied, or rebuilt from its delta.
fn section<T>(base: &CowArc<T>, op: Op<'_>) -> Result<CowArc<T>, PersistError>
where
    T: Serialize + DeserializeOwned + Default,
{
    match op {
        Op::Keep => Ok(base.clone()),
        Op::Remove => Ok(CowArc::default()),
        Op::Patch(d) => {
            let tree = serde_json::to_value(&**base).map_err(malformed)?;
            let tree = json_delta::apply_owned(tree, d).map_err(inconsistent)?;
            T::deserialize(&tree).map(CowArc::new).map_err(malformed)
        }
    }
}

/// One level (a struct with big sections named `cows`): the small fields
/// through JSON with the big ones emptied by `light`, then each big one
/// kept, emptied or patched by `put`.
fn level<S>(
    base: &S,
    delta: &Value,
    cows: &[&str],
    light: impl Fn(&S) -> S,
    mut put: impl FnMut(&mut S, &S, &str, Op<'_>) -> Result<(), PersistError>,
) -> Result<S, PersistError>
where
    S: Clone + Serialize + DeserializeOwned,
{
    let Some(d) = delta.as_object() else {
        return Err(inconsistent("bad delta: not an object"));
    };
    if d.is_empty() {
        return Ok(base.clone());
    }
    let (changed, gone) = match (d.get("o"), d.get("d")) {
        (Some(Value::Object(o)), None) if d.len() == 1 => (o, &[][..]),
        (Some(Value::Object(o)), Some(Value::Array(g))) if d.len() == 2 => (o, g.as_slice()),
        // A whole replacement, or something only the tree form explains.
        _ => {
            let tree = serde_json::to_value(base).map_err(malformed)?;
            let tree = json_delta::apply_owned(tree, delta).map_err(inconsistent)?;
            return S::deserialize(&tree).map_err(malformed);
        }
    };
    let is_cow = |k: &str| cows.contains(&k);
    let rest_changed: Map<String, Value> = changed
        .iter()
        .filter(|(k, _)| !is_cow(k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let rest_gone: Vec<Value> = gone
        .iter()
        .filter(|k| !k.as_str().is_some_and(is_cow))
        .cloned()
        .collect();
    let mut out = if rest_changed.is_empty() && rest_gone.is_empty() {
        base.clone()
    } else {
        let mut sub = Map::new();
        sub.insert("o".into(), Value::Object(rest_changed));
        if !rest_gone.is_empty() {
            sub.insert("d".into(), Value::Array(rest_gone));
        }
        let tree = serde_json::to_value(light(base)).map_err(malformed)?;
        let tree = json_delta::apply_owned(tree, &Value::Object(sub)).map_err(inconsistent)?;
        S::deserialize(&tree).map_err(malformed)?
    };
    for &key in cows {
        let op = match changed.get(key) {
            Some(sub) => Op::Patch(sub),
            None if gone.iter().any(|g| g.as_str() == Some(key)) => Op::Remove,
            None => Op::Keep,
        };
        put(&mut out, base, key, op)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AddressEntry, RouteEntry};
    use crate::firewall::AddressListEntry;
    use crate::types::{Gateway, ItemId, RoutingTable};

    fn big() -> Config {
        let mut c = Config::default();
        for i in 0..300u32 {
            c.ip.firewall.address_lists.push(AddressListEntry {
                id: ItemId(i + 1),
                list: "l".parse().unwrap(),
                address: format!("10.0.{}.{}", i / 256, i % 256).parse().unwrap(),
                disabled: false,
                comment: String::new(),
            });
            c.ip.routes.push(RouteEntry {
                id: ItemId(i + 1),
                dst_address: format!("172.16.{}.0/24", i % 256).parse().unwrap(),
                gateway: Gateway::ip("192.0.2.254".parse().unwrap()),
                distance: 1,
                routing_table: RoutingTable::Main,
                disabled: false,
                comment: String::new(),
            });
        }
        c.ip.addresses.push(AddressEntry {
            id: ItemId(1),
            address: "192.0.2.1/24".parse().unwrap(),
            interface: "ether1".parse().unwrap(),
            disabled: false,
            comment: String::new(),
            from_pool: None,
        });
        c
    }

    fn tree_apply(base: &Config, d: &Value) -> Config {
        let t = json_delta::apply(&serde_json::to_value(base).unwrap(), d).unwrap();
        Config::deserialize(&t).unwrap()
    }

    fn check(old: &Config, new: &Config) -> Config {
        let d = json_delta::diff(
            &serde_json::to_value(new).unwrap(),
            &serde_json::to_value(old).unwrap(),
        );
        // The typed diff gives the same delta, without the shared sections.
        assert_eq!(diff(new, old).unwrap(), d);
        let got = apply(new, &d).unwrap();
        assert_eq!(got, *old, "delta {d}");
        assert_eq!(got, tree_apply(new, &d));
        got
    }

    use serde::Deserialize;

    #[test]
    fn untouched_sections_are_shared_and_the_result_is_exact() {
        let new = big();
        let mut old = new.clone();
        old.system.identity = "older".into();
        if let Some(e) = old.ip.firewall.address_lists.get_mut(5) {
            e.comment = "x".into();
        }
        let got = check(&old, &new);
        assert!(CowArc::ptr_eq(&got.ip.routes, &new.ip.routes));
        assert!(CowArc::ptr_eq(&got.ip.addresses, &new.ip.addresses));
        assert!(CowArc::ptr_eq(&got.interfaces, &new.interfaces));
        assert!(CowArc::ptr_eq(&got.ip.firewall.filter, &new.ip.firewall.filter));
        assert!(!CowArc::ptr_eq(
            &got.ip.firewall.address_lists,
            &new.ip.firewall.address_lists
        ));
        // Only the small fields changed: every section shared.
        let mut old = new.clone();
        old.ip.next_route_id = 77;
        let got = check(&old, &new);
        assert!(CowArc::ptr_eq(&got.ip.firewall, &new.ip.firewall));
        assert!(CowArc::ptr_eq(&got.ip.routes, &new.ip.routes));
        // Sections emptied and filled (keys that disappear from the JSON).
        let mut old = new.clone();
        old.ip.routes = CowArc::default();
        old.ip.dns_static.entries.clear();
        check(&old, &new);
        check(&new, &old);
        check(&Config::default(), &new);
        check(&new, &Config::default());
        check(&new, &new);
    }

    #[test]
    fn hostile_deltas_are_refused() {
        let base = big();
        for d in [
            serde_json::json!(1),
            serde_json::json!({"o": {"ip": {"o": {"routes": {"a": [[0, 9999]]}}}}}),
            serde_json::json!({"o": {"ip": {"o": {"routes": {"=": 7}}}}}),
            serde_json::json!({"o": {"system": {"=": 7}}}),
            serde_json::json!({"o": {"nope": {"=": 7}}}),
            serde_json::json!({"o": {}, "d": ["system"], "x": 1}),
        ] {
            assert!(apply(&base, &d).is_err(), "{d}");
        }
    }
}
