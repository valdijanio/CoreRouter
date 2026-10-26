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
use crate::address_lists::AddressLists;
use crate::cow::CowArc;
use crate::cow_list::CowList;
use crate::dhcp_server::DhcpServers;
use crate::dns_static::DnsStatic;
use crate::firewall::Firewall;
use crate::ppp::Ppp;
use crate::queue::Queues;
use crate::ppp_secrets::Secrets;
use crate::simple_queues::SimpleQueues;
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
        &["interfaces", "ip", "ppp", "queue"],
        |c| {
            let mut light = c.clone();
            light.interfaces = CowArc::default();
            light.ip = CowArc::default();
            light.ppp = Ppp::default();
            light.queue = Queues::default();
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
                "ppp" => {
                    out.ppp = match op {
                        Op::Keep => base.ppp.clone(),
                        Op::Remove => Ppp::default(),
                        Op::Patch(d) => apply_ppp(&base.ppp, d)?,
                    }
                }
                "queue" => {
                    out.queue = match op {
                        Op::Keep => base.queue.clone(),
                        Op::Remove => Queues::default(),
                        Op::Patch(d) => apply_queue(&base.queue, d)?,
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
            light.addresses = CowList::default();
            light.routes = CowList::default();
            light.firewall = CowArc::default();
            light.dns_static = CowArc::default();
            light.dns_zones = CowArc::default();
            light.dhcp_server = CowArc::default();
            light
        },
        |out, base, key, op| {
            match key {
                "addresses" => out.addresses = list(&base.addresses, op)?,
                "routes" => out.routes = list(&base.routes, op)?,
                "dns_static" => out.dns_static = nested(&base.dns_static, op, apply_dns_static)?,
                "dns_zones" => out.dns_zones = section(&base.dns_zones, op)?,
                "dhcp_server" => out.dhcp_server = nested(&base.dhcp_server, op, apply_dhcp)?,
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
            light.filter = CowList::default();
            light.nat = CowList::default();
            light.mangle = CowList::default();
            light.address_lists = AddressLists::default();
            light
        },
        |out, base, key, op| {
            match key {
                "filter" => out.filter = list(&base.filter, op)?,
                "nat" => out.nat = list(&base.nat, op)?,
                "mangle" => out.mangle = list(&base.mangle, op)?,
                "address_lists" => out.address_lists = AddressLists::from_list(list(base.address_lists.list(), op)?),
                _ => {}
            }
            Ok(())
        },
    )
}

fn apply_dhcp(base: &DhcpServers, delta: &Value) -> Result<DhcpServers, PersistError> {
    level(
        base,
        delta,
        &["leases"],
        |d| {
            let mut light = d.clone();
            light.leases = CowList::default();
            light
        },
        |out, base, key, op| {
            if key == "leases" {
                out.leases = list(&base.leases, op)?;
            }
            Ok(())
        },
    )
}

fn apply_dns_static(base: &DnsStatic, delta: &Value) -> Result<DnsStatic, PersistError> {
    level(
        base,
        delta,
        &["entries"],
        |d| {
            let mut light = d.clone();
            light.entries = CowList::default();
            light
        },
        |out, base, key, op| {
            if key == "entries" {
                out.entries = list(&base.entries, op)?;
            }
            Ok(())
        },
    )
}

fn apply_queue(base: &Queues, delta: &Value) -> Result<Queues, PersistError> {
    level(
        base,
        delta,
        &["simple"],
        |q| {
            let mut light = q.clone();
            light.simple = SimpleQueues::default();
            light
        },
        |out, base, key, op| {
            if key == "simple" {
                out.simple = match op {
                    Op::Keep => base.simple.clone(),
                    Op::Remove => SimpleQueues::default(),
                    Op::Patch(_) => SimpleQueues::from_list(list(base.simple.list(), op)?),
                };
            }
            Ok(())
        },
    )
}

fn apply_ppp(base: &Ppp, delta: &Value) -> Result<Ppp, PersistError> {
    level(
        base,
        delta,
        &["secrets"],
        |p| {
            let mut light = p.clone();
            light.secrets = Secrets::default();
            light
        },
        |out, base, key, op| {
            if key == "secrets" {
                out.secrets = match op {
                    Op::Keep => base.secrets.clone(),
                    Op::Remove => Secrets::default(),
                    Op::Patch(_) => Secrets::from_list(list(base.secrets.list(), op)?),
                };
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
        l.ppp = Ppp::default();
        l.queue = Queues::default();
        l
    };
    let Some(mut p) = Parts::small(a, b, light)? else {
        return whole(a, b);
    };
    p.section("interfaces", &a.interfaces, &b.interfaces, |_| true)?;
    if !CowArc::ptr_eq(&a.ip, &b.ip) && *a.ip != *b.ip {
        p.nested("ip", diff_ip(&a.ip, &b.ip)?);
    }
    if a.ppp != b.ppp {
        match (a.ppp.is_default(), b.ppp.is_default()) {
            (true, true) => {}
            (false, true) => p.gone.push("ppp".into()),
            (true, false) => {
                let v = serde_json::to_value(&b.ppp).map_err(malformed)?;
                p.changed.insert("ppp".into(), obj("=", v));
            }
            (false, false) => p.nested("ppp", diff_ppp(&a.ppp, &b.ppp)?),
        }
    }
    if a.queue != b.queue {
        match (a.queue.is_default(), b.queue.is_default()) {
            (true, true) => {}
            (false, true) => p.gone.push("queue".into()),
            (true, false) => {
                let v = serde_json::to_value(&b.queue).map_err(malformed)?;
                p.changed.insert("queue".into(), obj("=", v));
            }
            (false, false) => {
                let light = |x: &Queues| {
                    let mut l = x.clone();
                    l.simple = SimpleQueues::default();
                    l
                };
                let d = match Parts::small(&a.queue, &b.queue, light)? {
                    Some(mut q) => {
                        q.list("simple", a.queue.simple.list(), b.queue.simple.list())?;
                        q.finish()
                    }
                    None => whole(&a.queue, &b.queue)?,
                };
                p.nested("queue", d);
            }
        }
    }
    Ok(p.finish())
}

fn diff_ppp(a: &Ppp, b: &Ppp) -> Result<Option<Value>, PersistError> {
    let light = |x: &Ppp| {
        let mut l = x.clone();
        l.secrets = Secrets::default();
        l
    };
    let Some(mut p) = Parts::small(a, b, light)? else {
        return whole(a, b);
    };
    p.list("secrets", a.secrets.list(), b.secrets.list())?;
    Ok(p.finish())
}

fn diff_ip(a: &Ip, b: &Ip) -> Result<Option<Value>, PersistError> {
    let light = |ip: &Ip| {
        let mut l = ip.clone();
        l.addresses = CowList::default();
        l.routes = CowList::default();
        l.firewall = CowArc::default();
        l.dns_static = CowArc::default();
        l.dns_zones = CowArc::default();
        l.dhcp_server = CowArc::default();
        l
    };
    let Some(mut p) = Parts::small(a, b, light)? else {
        return whole(a, b);
    };
    p.list("addresses", &a.addresses, &b.addresses)?;
    p.list("routes", &a.routes, &b.routes)?;
    p.nested_section("dns_static", &a.dns_static, &b.dns_static, |s| !s.is_empty(), |a, b| {
        let light = |d: &DnsStatic| {
            let mut l = d.clone();
            l.entries = CowList::default();
            l
        };
        let Some(mut p) = Parts::small(a, b, light)? else {
            return whole(a, b);
        };
        p.list("entries", &a.entries, &b.entries)?;
        Ok(p.finish())
    })?;
    p.section("dns_zones", &a.dns_zones, &b.dns_zones, |s| !s.is_empty())?;
    p.nested_section("dhcp_server", &a.dhcp_server, &b.dhcp_server, |s| !s.is_empty(), |a, b| {
        let light = |d: &DhcpServers| {
            let mut l = d.clone();
            l.leases = CowList::default();
            l
        };
        let Some(mut p) = Parts::small(a, b, light)? else {
            return whole(a, b);
        };
        p.list("leases", &a.leases, &b.leases)?;
        Ok(p.finish())
    })?;
    if !CowArc::ptr_eq(&a.firewall, &b.firewall) && *a.firewall != *b.firewall {
        p.nested("firewall", diff_firewall(&a.firewall, &b.firewall)?);
    }
    Ok(p.finish())
}

fn diff_firewall(a: &Firewall, b: &Firewall) -> Result<Option<Value>, PersistError> {
    let light = |f: &Firewall| {
        let mut l = f.clone();
        l.filter = CowList::default();
        l.nat = CowList::default();
        l.mangle = CowList::default();
        l.address_lists = AddressLists::default();
        l
    };
    let Some(mut p) = Parts::small(a, b, light)? else {
        return whole(a, b);
    };
    p.list("filter", &a.filter, &b.filter)?;
    p.list("nat", &a.nat, &b.nat)?;
    p.list("mangle", &a.mangle, &b.mangle)?;
    p.list("address_lists", a.address_lists.list(), b.address_lists.list())?;
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

    /// A big section with a list inside: [`Self::section`], the list
    /// diffed by `inner` instead of serialized.
    fn nested_section<T: Serialize + PartialEq>(
        &mut self,
        key: &str,
        a: &CowArc<T>,
        b: &CowArc<T>,
        present: impl Fn(&T) -> bool,
        inner: impl Fn(&T, &T) -> Result<Option<Value>, PersistError>,
    ) -> Result<(), PersistError> {
        if CowArc::ptr_eq(a, b) || **a == **b {
            return Ok(());
        }
        if present(a) && present(b) {
            if let Some(d) = inner(a, b)? {
                self.changed.insert(key.to_owned(), d);
            }
            return Ok(());
        }
        self.section(key, a, b, present)
    }

    /// A big list, present in the JSON when not empty (every config list
    /// is either always written or skipped when empty; an empty list
    /// written as `[]` on one side only is a whole replacement).
    fn list<T: Serialize + PartialEq>(&mut self, key: &str, a: &CowList<T>, b: &CowList<T>) -> Result<(), PersistError> {
        if CowList::ptr_eq(a, b) {
            return Ok(());
        }
        match (a.is_empty(), b.is_empty()) {
            (true, true) => Ok(()),
            (_, true) | (true, _) => {
                let v = serde_json::to_value(b).map_err(malformed)?;
                self.changed.insert(key.to_owned(), obj("=", v));
                Ok(())
            }
            (false, false) => {
                if let Some(d) = list_delta(a, b)? {
                    self.changed.insert(key.to_owned(), d);
                }
                Ok(())
            }
        }
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

/// The array delta of a block list ([`json_delta`]'s `{"a": [...]}`): the
/// blocks `new` still shares with `old` are copy runs, and only the items
/// between them are serialized and diffed. A commit that wrote one secret
/// of 100 000 serializes one block of each side, not the lists.
fn list_delta<T: Serialize + PartialEq>(old: &CowList<T>, new: &CowList<T>) -> Result<Option<Value>, PersistError> {
    let shared = new.shared_blocks(old);
    let mut ops = ListOps::default();
    // Old items before `cursor` are accounted for; new items from
    // `pending` to `at` are not yet.
    let (mut cursor, mut pending, mut at) = (0usize, 0usize, 0usize);
    let end = (0, Some(old.len()));
    for &(len, from) in shared.iter().chain(std::iter::once(&end)) {
        let Some(start) = from else {
            at += len;
            continue;
        };
        // Shared blocks out of order (the list's own writes never make
        // them): the tree diff.
        if start < cursor {
            let (a, b) = (to_tree(old.iter())?, to_tree(new.iter())?);
            let d = json_delta::diff(&a, &b);
            return Ok(d.as_object().is_some_and(|m| !m.is_empty()).then_some(d));
        }
        if start > cursor || at > pending {
            // The items equal at both ends of the region (a block that
            // changed one item) are copies too: only the rest is serialized.
            let (n_old, n_new) = (start - cursor, at - pending);
            let head = old
                .range(cursor, n_old)
                .zip(new.range(pending, n_new))
                .take_while(|(x, y)| x == y)
                .count();
            let room = n_old.min(n_new) - head;
            let tail = old
                .range(cursor + head, n_old - head)
                .rev()
                .zip(new.range(pending + head, n_new - head).rev())
                .take(room)
                .take_while(|(x, y)| x == y)
                .count();
            ops.copy(cursor, head);
            let a = to_tree(old.range(cursor + head, n_old - head - tail))?;
            let b = to_tree(new.range(pending + head, n_new - head - tail))?;
            ops.region(cursor + head, &a, &b)?;
            ops.copy(start - tail, tail);
        }
        ops.copy(start, len);
        cursor = start + len;
        at += len;
        pending = at;
    }
    Ok(ops.finish(old.len(), new.len()))
}

fn to_tree<'a, T: Serialize + 'a>(items: impl Iterator<Item = &'a T>) -> Result<Value, PersistError> {
    items
        .map(|x| serde_json::to_value(x).map_err(malformed))
        .collect::<Result<Vec<_>, _>>()
        .map(Value::Array)
}

/// The ops of an array delta, copy runs merged.
#[derive(Default)]
struct ListOps {
    ops: Vec<Value>,
    run: Option<(usize, usize)>,
    copied: bool,
}

impl ListOps {
    fn flush(&mut self) {
        if let Some((s, l)) = self.run.take() {
            self.ops.push(Value::Array(vec![s.into(), l.into()]));
        }
    }

    fn copy(&mut self, start: usize, len: usize) {
        if len == 0 {
            return;
        }
        self.copied = true;
        match &mut self.run {
            Some((s, l)) if *s + *l == start => *l += len,
            _ => {
                self.flush();
                self.run = Some((start, len));
            }
        }
    }

    fn items(&mut self, items: &[Value]) {
        if items.is_empty() {
            return;
        }
        self.flush();
        if let Some(Value::Object(m)) = self.ops.last_mut()
            && let Some(Value::Array(v)) = m.get_mut("i")
        {
            v.extend_from_slice(items);
            return;
        }
        self.ops.push(obj("i", Value::Array(items.to_vec())));
    }

    /// Old items `base..base + a.len()` became `b`.
    fn region(&mut self, base: usize, a: &Value, b: &Value) -> Result<(), PersistError> {
        let d = json_delta::diff(a, b);
        let Some(m) = d.as_object() else {
            return Err(inconsistent("list delta is not an object"));
        };
        if m.is_empty() {
            self.copy(base, a.as_array().map_or(0, Vec::len));
        } else if let Some(Value::Array(v)) = m.get("=") {
            self.items(v);
        } else if let Some(Value::Array(ops)) = m.get("a") {
            for op in ops {
                match op {
                    Value::Array(run) => {
                        let s = run.first().and_then(Value::as_u64).and_then(|s| usize::try_from(s).ok());
                        let l = run.get(1).and_then(Value::as_u64).and_then(|l| usize::try_from(l).ok());
                        let (Some(s), Some(l)) = (s, l) else {
                            return Err(inconsistent("list delta run"));
                        };
                        self.copy(base + s, l);
                    }
                    Value::Object(o) => match o.get("i") {
                        Some(Value::Array(items)) => self.items(items),
                        _ => return Err(inconsistent("list delta op")),
                    },
                    _ => return Err(inconsistent("list delta op")),
                }
            }
        } else {
            return Err(inconsistent("list delta shape"));
        }
        Ok(())
    }

    fn finish(mut self, old: usize, new: usize) -> Option<Value> {
        self.flush();
        if old == new && self.ops.len() == 1 && self.ops.first() == Some(&Value::Array(vec![0.into(), old.into()])) {
            return None;
        }
        if !self.copied {
            let all: Vec<Value> = self
                .ops
                .into_iter()
                .filter_map(|op| match op {
                    Value::Object(mut m) => match m.remove("i") {
                        Some(Value::Array(v)) => Some(v),
                        _ => None,
                    },
                    _ => None,
                })
                .flatten()
                .collect();
            return Some(obj("=", Value::Array(all)));
        }
        Some(obj("a", Value::Array(self.ops)))
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

/// A big section with a list inside: an object delta goes through `inner`
/// (the list patched block-wise), anything else through the tree.
fn nested<T>(
    base: &CowArc<T>,
    op: Op<'_>,
    inner: impl Fn(&T, &Value) -> Result<T, PersistError>,
) -> Result<CowArc<T>, PersistError>
where
    T: Serialize + DeserializeOwned + Default,
{
    match op {
        Op::Patch(d) => inner(base, d).map(CowArc::new),
        _ => section(base, op),
    }
}

/// One big list: kept (shared), emptied, or rebuilt from its delta.
fn list<T>(base: &CowList<T>, op: Op<'_>) -> Result<CowList<T>, PersistError>
where
    T: Clone + Serialize + DeserializeOwned,
{
    match op {
        Op::Keep => Ok(base.clone()),
        Op::Remove => Ok(CowList::default()),
        Op::Patch(d) => match d.get("a") {
            Some(Value::Array(ops)) if d.as_object().is_some_and(|m| m.len() == 1) => list_ops(base, ops),
            _ => {
                let tree = serde_json::to_value(base).map_err(malformed)?;
                let tree = json_delta::apply_owned(tree, d).map_err(inconsistent)?;
                <CowList<T> as serde::Deserialize>::deserialize(&tree).map_err(malformed)
            }
        },
    }
}

/// An array delta (`{"a": [...]}`) applied to a block list: copy runs
/// share `base`'s blocks ([`CowList::extend_from`]), only the new items are
/// parsed. The same checks as [`json_delta::apply`]: every run inside
/// `base`, every item of `base` taken at most once.
fn list_ops<T>(base: &CowList<T>, ops: &[Value]) -> Result<CowList<T>, PersistError>
where
    T: Clone + DeserializeOwned,
{
    let mut out = CowList::new();
    let mut taken = vec![false; base.len()];
    for op in ops {
        match op {
            Value::Array(run) => {
                let at = |i: usize| {
                    run.get(i)
                        .and_then(Value::as_u64)
                        .and_then(|n| usize::try_from(n).ok())
                };
                let (Some(start), Some(len), 2) = (at(0), at(1), run.len()) else {
                    return Err(inconsistent("copy run is not [start, len]"));
                };
                let Some(slots) = start.checked_add(len).and_then(|end| taken.get_mut(start..end)) else {
                    return Err(inconsistent(format!("copy run {start}+{len} past {}", base.len())));
                };
                if slots.iter().any(|t| *t) {
                    return Err(inconsistent("copy runs overlap"));
                }
                slots.fill(true);
                if !out.extend_from(base, start, len) {
                    return Err(inconsistent("copy run out of range"));
                }
            }
            Value::Object(m) => match (m.get("i"), m.len()) {
                (Some(Value::Array(items)), 1) => {
                    for item in items {
                        out.push(T::deserialize(item).map_err(malformed)?);
                    }
                }
                _ => return Err(inconsistent("unknown array op")),
            },
            _ => return Err(inconsistent("unknown array op")),
        }
    }
    Ok(out)
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
        // The typed diff serializes only what changed; its delta builds
        // the same config, typed or through the tree, and is never bigger
        // than the tree diff by more than a few merged runs.
        let typed = diff(new, old).unwrap();
        assert_eq!(tree_apply(new, &typed), *old, "typed delta {typed}");
        assert!(typed.to_string().len() <= d.to_string().len() + 64, "{typed} vs {d}");
        let got = apply(new, &d).unwrap();
        assert_eq!(got, *old, "delta {d}");
        assert_eq!(got, tree_apply(new, &d));
        let got = apply(new, &typed).unwrap();
        assert_eq!(got, *old, "typed delta {typed}");
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
        assert!(CowList::ptr_eq(&got.ip.routes, &new.ip.routes));
        assert!(CowList::ptr_eq(&got.ip.addresses, &new.ip.addresses));
        assert!(CowArc::ptr_eq(&got.interfaces, &new.interfaces));
        assert!(CowList::ptr_eq(&got.ip.firewall.filter, &new.ip.firewall.filter));
        assert!(!CowList::ptr_eq(
            &got.ip.firewall.address_lists,
            &new.ip.firewall.address_lists
        ));
        // Only the small fields changed: every section shared.
        let mut old = new.clone();
        old.ip.next_route_id = 77;
        let got = check(&old, &new);
        assert!(CowArc::ptr_eq(&got.ip.firewall, &new.ip.firewall));
        assert!(CowList::ptr_eq(&got.ip.routes, &new.ip.routes));
        // Sections emptied and filled (keys that disappear from the JSON).
        let mut old = new.clone();
        old.ip.routes = CowList::default();
        old.ip.dns_static.entries.clear();
        check(&old, &new);
        check(&new, &old);
        check(&Config::default(), &new);
        check(&new, &Config::default());
        check(&new, &new);
    }

    fn secret(i: u32) -> crate::ppp::PppSecret {
        crate::ppp::PppSecret {
            id: ItemId(i + 1),
            name: format!("c{i}"),
            password: "x".into(),
            profile: "default".into(),
            ..crate::ppp::PppSecret::default()
        }
    }

    #[test]
    fn one_secret_of_many_is_one_small_delta() {
        let mut new = big();
        for i in 0..5000 {
            new.ppp.secrets.push(secret(i));
        }
        let mut old = new.clone();
        old.ppp.secrets.update(2500, |s| s.comment = "vip".into());
        let d = diff(&new, &old).unwrap();
        assert!(d.to_string().len() < 400, "{d}");
        let got = check(&old, &new);
        assert!(!Secrets::ptr_eq(&got.ppp.secrets, &new.ppp.secrets));
        let mut gone = new.clone();
        gone.ppp.secrets.remove(4999);
        assert!(diff(&new, &gone).unwrap().to_string().len() < 200);
        check(&gone, &new);
        check(&new, &gone);
    }

    #[test]
    fn one_lease_or_static_name_of_many_is_one_small_delta() {
        let mut new = big();
        for i in 0..3000u32 {
            let lease = serde_json::from_value(serde_json::json!({
                "id": format!("*{:X}", i + 1),
                "address": format!("100.64.{}.{}", i >> 8, i & 0xff),
                "mac_address": format!("02:00:00:00:{:02x}:{:02x}", i >> 8, i & 0xff),
            }))
            .unwrap();
            new.ip.dhcp_server.leases.push(lease);
            let entry = serde_json::from_value(serde_json::json!({
                "id": format!("*{:X}", i + 1), "name": format!("h{i}.lan"), "address": "10.0.0.1",
            }))
            .unwrap();
            new.ip.dns_static.entries.push(entry);
        }
        let mut old = new.clone();
        old.ip.dhcp_server.leases.get_mut(1500).unwrap().comment = "x".into();
        old.ip.dns_static.entries.remove(10);
        let d = diff(&new, &old).unwrap();
        assert!(d.to_string().len() < 400, "{d}");
        let got = check(&old, &new);
        assert!(CowArc::ptr_eq(&got.ip.firewall, &new.ip.firewall));
        check(&new, &old);
    }

    #[test]
    fn one_queue_of_many_is_one_small_delta() {
        let mut new = big();
        for i in 0..3000u32 {
            let q = serde_json::from_value(serde_json::json!({
                "id": format!("*{:X}", i + 1), "name": format!("q{i}"),
                "target": [format!("10.0.{}.{}/32", i >> 8, i & 255)],
            }))
            .unwrap();
            new.queue.simple.push(q);
        }
        let mut old = new.clone();
        old.queue.simple.get_mut(1500).unwrap().comment = "x".into();
        old.queue.simple.remove(7);
        let d = diff(&new, &old).unwrap();
        assert!(d.to_string().len() < 500, "{d}");
        check(&old, &new);
        check(&new, &old);
        let mut gone = new.clone();
        gone.queue = Queues::default();
        check(&gone, &new);
        check(&new, &gone);
    }

    #[derive(Debug, Clone)]
    enum Edit {
        Push,
        Insert(usize),
        Remove(usize),
        Set(usize),
        Clear,
    }

    fn edit() -> impl proptest::strategy::Strategy<Value = Edit> {
        use proptest::prelude::*;
        prop_oneof![
            3 => Just(Edit::Push),
            1 => any::<usize>().prop_map(Edit::Insert),
            2 => any::<usize>().prop_map(Edit::Remove),
            3 => any::<usize>().prop_map(Edit::Set),
            1 => Just(Edit::Clear),
        ]
    }

    proptest::proptest! {
        /// Any run of edits on the block lists: the typed delta between
        /// any two points rebuilds the older one exactly.
        #[test]
        fn block_list_deltas_rebuild_the_revision(start in 0u32..700, edits in proptest::collection::vec(edit(), 1..40)) {
            let mut c = Config::default();
            for i in 0..start {
                c.ppp.secrets.push(secret(i));
            }
            let mut next = start;
            let mut history = vec![c.clone()];
            for e in edits {
                let n = c.ppp.secrets.len();
                match e {
                    Edit::Push => { c.ppp.secrets.push(secret(next)); next += 1; }
                    Edit::Insert(i) => {
                        let mut l = c.ppp.secrets.list().clone();
                        l.insert(i % (n + 1), secret(next));
                        next += 1;
                        c.ppp.secrets = Secrets::from_list(l);
                    }
                    Edit::Remove(i) if n > 0 => { c.ppp.secrets.remove(i % n); }
                    Edit::Set(i) if n > 0 => { c.ppp.secrets.update(i % n, |s| s.comment = format!("e{next}")); next += 1; }
                    Edit::Clear => c.ppp.secrets = Secrets::default(),
                    _ => {}
                }
                history.push(c.clone());
            }
            for w in history.windows(2) {
                let [old, new] = w else { continue };
                let d = diff(new, old).unwrap();
                proptest::prop_assert_eq!(&apply(new, &d).unwrap(), old);
                proptest::prop_assert_eq!(&tree_apply(new, &d), old);
                let d = diff(old, new).unwrap();
                proptest::prop_assert_eq!(&apply(old, &d).unwrap(), new);
            }
        }
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
