//! Transactional store: commands edit the candidate; `commit` promotes it to
//! running and records a revision; `rollback` restores an old revision into
//! the candidate (it still needs a commit, exactly like Junos/VyOS).
//!
//! The model has no clock (`SystemTime::now` is unavailable on wasm32), so
//! callers pass the timestamp they get from the HAL.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

use crate::config::{Config, Ip};
use crate::address_lists::AddressLists;
use crate::cow::CowArc;
use crate::cow_list::CowList;
use crate::firewall::Firewall;
use crate::ppp_secrets::Secrets;
use crate::simple_queues::SimpleQueues;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    #[error("revision {0} not found (see config.history)")]
    UnknownRevision(u32),
    #[error("nothing to commit")]
    NothingToCommit,
}

#[derive(Debug, Clone, Serialize)]
pub struct Revision {
    pub number: u32,
    pub comment: String,
    pub timestamp: Option<u64>,
    #[serde(skip)]
    pub config: Config,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum DiffLine {
    Add {
        path: String,
        value: Value,
    },
    Remove {
        path: String,
        value: Value,
    },
    Change {
        path: String,
        from: Value,
        to: Value,
    },
}

/// Copies of the config here share their sections (`crate::cow`): a
/// revision, the running config and the candidate cost one copy of what
/// changed between them, not one of the whole tree each (G0.16).
#[derive(Debug, Clone)]
pub struct ConfigStore {
    running: Config,
    candidate: Config,
    /// The candidate was handed out for writing (or replaced) since it was
    /// last equal to running: `is_dirty` compares only then (G0.16).
    touched: bool,
    history: Vec<Revision>,
    max_history: usize,
    /// Bumped whenever the candidate may have changed (G1.27c: what is
    /// computed from it can be kept until then). Not saved.
    generation: u64,
}

/// Generations come from one counter for the whole process, so two stores
/// (one replacing the other) never share one.
fn next_generation() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

impl Default for ConfigStore {
    fn default() -> Self {
        Self::new(Config::default())
    }
}

impl ConfigStore {
    pub const DEFAULT_MAX_HISTORY: usize = 64;

    pub fn new(initial: Config) -> Self {
        let rev0 = Revision {
            number: 0,
            comment: "initial".into(),
            timestamp: None,
            config: initial.clone(),
        };
        Self {
            running: initial.clone(),
            candidate: initial,
            touched: false,
            history: vec![rev0],
            max_history: Self::DEFAULT_MAX_HISTORY,
            generation: next_generation(),
        }
    }

    /// Rebuild a store from persisted parts (see `persist::decode`, which
    /// checks that `history` is non-empty, ordered and ends at `running`).
    /// The candidate starts clean; history keeps the newest
    /// [`Self::DEFAULT_MAX_HISTORY`] revisions.
    pub fn restore(running: Config, mut history: Vec<Revision>) -> Self {
        if history.is_empty() {
            return Self::new(running);
        }
        let max_history = Self::DEFAULT_MAX_HISTORY;
        if history.len() > max_history {
            let excess = history.len() - max_history;
            history.drain(..excess);
        }
        Self {
            candidate: running.clone(),
            running,
            touched: false,
            history,
            max_history,
            generation: next_generation(),
        }
    }

    pub fn running(&self) -> &Config {
        &self.running
    }

    pub fn candidate(&self) -> &Config {
        &self.candidate
    }

    pub fn candidate_mut(&mut self) -> &mut Config {
        self.touched = true;
        self.generation = next_generation();
        &mut self.candidate
    }

    /// Replace the candidate wholesale (used by the engine guard on rollback).
    pub fn set_candidate(&mut self, cfg: Config) {
        self.touched = true;
        self.generation = next_generation();
        self.candidate = cfg;
    }

    /// Changes whenever the candidate may have changed (handed out for
    /// writing, replaced, discarded, rolled back): equal generations, equal
    /// candidate.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Candidate differs from running. O(1) while nobody wrote to the
    /// candidate; otherwise the sections both still share compare by
    /// pointer, so only what was written is compared in full.
    pub fn is_dirty(&self) -> bool {
        self.touched && self.running != self.candidate
    }

    pub fn history(&self) -> &[Revision] {
        &self.history
    }

    pub fn current_revision(&self) -> u32 {
        self.history.last().map_or(0, |r| r.number)
    }

    /// Promote candidate → running. Validation and applying to the data plane
    /// happen in the engine *before* this call.
    pub fn commit(&mut self, comment: &str, timestamp: Option<u64>) -> Result<u32, StoreError> {
        if !self.is_dirty() {
            return Err(StoreError::NothingToCommit);
        }
        let number = self.current_revision().saturating_add(1);
        self.running = self.candidate.clone();
        self.touched = false;
        self.history.push(Revision {
            number,
            comment: comment.chars().take(256).collect(),
            timestamp,
            config: self.running.clone(),
        });
        if self.history.len() > self.max_history {
            let excess = self.history.len() - self.max_history;
            self.history.drain(..excess);
        }
        Ok(number)
    }

    pub fn discard(&mut self) {
        self.candidate = self.running.clone();
        self.generation = next_generation();
        self.touched = false;
    }

    /// Load revision `number` into the candidate.
    pub fn rollback(&mut self, number: u32) -> Result<(), StoreError> {
        let rev = self
            .history
            .iter()
            .find(|r| r.number == number)
            .ok_or(StoreError::UnknownRevision(number))?;
        self.candidate = rev.config.clone();
        self.generation = next_generation();
        self.touched = true;
        Ok(())
    }

    /// Path-level diff running → candidate.
    pub fn diff(&self) -> Vec<DiffLine> {
        diff_configs(&self.running, &self.candidate)
    }
}

pub fn diff_configs(from: &Config, to: &Config) -> Vec<DiffLine> {
    if from == to {
        return Vec::new();
    }
    let (from, to) = differing(from, to);
    let a = flatten(&from);
    let b = flatten(&to);
    let mut out = Vec::new();
    for (path, va) in &a {
        match b.get(path) {
            None => out.push(DiffLine::Remove {
                path: path.clone(),
                value: va.clone(),
            }),
            Some(vb) if vb != va => out.push(DiffLine::Change {
                path: path.clone(),
                from: va.clone(),
                to: vb.clone(),
            }),
            Some(_) => {}
        }
    }
    for (path, vb) in &b {
        if !a.contains_key(path) {
            out.push(DiffLine::Add {
                path: path.clone(),
                value: vb.clone(),
            });
        }
    }
    out
}

/// For each field `f` (bound by name from the left side): if it differs
/// from `$to.f`, copy both sides into `$x` and `$y`.
macro_rules! keep {
    ($x:ident, $y:ident, $to:ident: $($f:ident),* $(,)?) => {
        $(if *$f != $to.$f {
            $x.$f = $f.clone();
            $y.$f = $to.$f.clone();
        })*
    };
}

/// Copies `from` and `to` set equal sections back to their default on
/// both sides. An equal section adds no line, but serializing it was the
/// cost: 1.5 s for a clean config with 100 000 routes, 100 000
/// address-list entries and 10 000 rules, under the session lock, on
/// every refresh of the GUI (G0.31). Sections shared by the two compare
/// by pointer. The patterns are exhaustive: a new field must be sorted
/// here, or this does not compile.
fn differing(from: &Config, to: &Config) -> (Config, Config) {
    let Config {
        system,
        interfaces,
        interface_lists,
        ip,
        ipv6,
        routing,
        radius,
        ppp,
        queue,
    } = from;
    let (mut a, mut b) = (Config::default(), Config::default());
    keep!(a, b, to: system, interfaces, interface_lists, ipv6, routing, radius, ppp, queue);
    // `keep!` copied a changed section whole: its big list keeps only
    // what differs.
    if *ppp != to.ppp {
        let (x, y) = trim(ppp.secrets.list(), to.ppp.secrets.list());
        a.ppp.secrets = Secrets::from_list(x);
        b.ppp.secrets = Secrets::from_list(y);
    }
    if *queue != to.queue {
        let (x, y) = trim(queue.simple.list(), to.queue.simple.list());
        a.queue.simple = SimpleQueues::from_list(x);
        b.queue.simple = SimpleQueues::from_list(y);
    }
    if *ip != to.ip {
        let (x, y) = differing_ip(ip, &to.ip);
        a.ip = CowArc::new(x);
        b.ip = CowArc::new(y);
    }
    (a, b)
}

/// [`differing`] one level down: `ip` holds the big tables.
fn differing_ip(from: &Ip, to: &Ip) -> (Ip, Ip) {
    let Ip {
        addresses,
        next_id,
        routes,
        next_route_id,
        neighbor_discovery,
        firewall,
        xdp,
        dns_adlist,
        dns_forwarders,
        dhcp_clients,
        next_dhcp_client_id,
        dns,
        dns_static,
        dns_zones,
        dns_tsig,
        pools,
        dhcp_server,
        dhcp_relays,
        cgnat,
        fastpath,
        traffic_flow,
        subscriber_notice,
        arp,
    } = from;
    let (mut a, mut b) = (Ip::default(), Ip::default());
    keep!(a, b, to:
        next_id,
        next_route_id,
        neighbor_discovery,
        xdp,
        dns_adlist,
        dns_forwarders,
        dhcp_clients,
        next_dhcp_client_id,
        dns,
        dns_static,
        dns_zones,
        dns_tsig,
        pools,
        dhcp_server,
        dhcp_relays,
        cgnat,
        fastpath,
        traffic_flow,
        subscriber_notice,
        arp
    );
    trim_into(&mut a.addresses, &mut b.addresses, addresses, &to.addresses);
    trim_into(&mut a.routes, &mut b.routes, routes, &to.routes);
    if *dhcp_server != to.dhcp_server {
        let (x, y) = trim(&dhcp_server.leases, &to.dhcp_server.leases);
        a.dhcp_server.leases = x;
        b.dhcp_server.leases = y;
    }
    if *dns_static != to.dns_static {
        let (x, y) = trim(&dns_static.entries, &to.dns_static.entries);
        a.dns_static.entries = x;
        b.dns_static.entries = y;
    }
    if *firewall != to.firewall {
        let Firewall {
            filter,
            nat,
            mangle,
            raw,
            address_lists,
            next_rule_id,
            next_address_list_id,
            zones,
        } = &**firewall;
        let to = &*to.firewall;
        let (mut x, mut y) = (Firewall::default(), Firewall::default());
        keep!(x, y, to: next_rule_id, next_address_list_id, zones);
        trim_into(&mut x.filter, &mut y.filter, filter, &to.filter);
        trim_into(&mut x.nat, &mut y.nat, nat, &to.nat);
        trim_into(&mut x.mangle, &mut y.mangle, mangle, &to.mangle);
        trim_into(&mut x.raw, &mut y.raw, raw, &to.raw);
        if *address_lists != to.address_lists {
            let (l, r) = trim(address_lists.list(), to.address_lists.list());
            x.address_lists = AddressLists::from_list(l);
            y.address_lists = AddressLists::from_list(r);
        }
        a.firewall = CowArc::new(x);
        b.firewall = CowArc::new(y);
    }
    (a, b)
}

/// [`differing`] inside a big list (G0.31a): the items in the blocks the
/// two sides share are equal on both and add no line, so both keep only
/// the rest. Every list here is keyed by `id` (the diff pairs items by id,
/// not by position), so dropping items moves no path. A side left empty
/// keeps one shared item, on both: an empty list is a line of its own
/// (`ip.routes: []`) that the full lists would not give.
fn trim<T: Clone>(from: &CowList<T>, to: &CowList<T>) -> (CowList<T>, CowList<T>) {
    let (mut x, mut y) = (from.unshared(to), to.unshared(from));
    if ((x.is_empty() && !from.is_empty()) || (y.is_empty() && !to.is_empty()))
        && let Some(same) = from.any_shared(to)
    {
        x.push(same.clone());
        y.push(same.clone());
    }
    (x, y)
}

/// [`trim`] into `x` and `y` when the lists differ (equal, they stay
/// empty, as [`keep!`] leaves an equal field).
fn trim_into<T: Clone + PartialEq>(
    x: &mut CowList<T>,
    y: &mut CowList<T>,
    from: &CowList<T>,
    to: &CowList<T>,
) {
    if from != to {
        (*x, *y) = trim(from, to);
    }
}

fn flatten(cfg: &Config) -> BTreeMap<String, Value> {
    let mut out = BTreeMap::new();
    // Config is plain serde data: serialization cannot fail; fall back to Null anyway.
    let root = serde_json::to_value(cfg).unwrap_or(Value::Null);
    walk(String::new(), &root, &mut out);
    out
}

fn walk(prefix: String, v: &Value, out: &mut BTreeMap<String, Value>) {
    let join = |k: &str| {
        if prefix.is_empty() {
            k.to_owned()
        } else {
            format!("{prefix}.{k}")
        }
    };
    match v {
        Value::Object(map) if !map.is_empty() => {
            for (k, child) in map {
                walk(join(k), child, out);
            }
        }
        Value::Array(items) if !items.is_empty() => {
            for (i, child) in items.iter().enumerate() {
                // Lists of items keyed by MikroTik ids diff by id, not position.
                let key = child
                    .get("id")
                    .and_then(Value::as_str)
                    .map_or_else(|| format!("[{i}]"), |id| format!("[{id}]"));
                walk(format!("{prefix}{key}"), child, out);
            }
        }
        leaf => {
            out.insert(prefix, leaf.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_rollback_cycle() {
        let mut st = ConfigStore::default();
        assert!(!st.is_dirty());
        assert_eq!(st.commit("noop", None), Err(StoreError::NothingToCommit));

        st.candidate_mut().system.identity = "edge-1".into();
        assert!(st.is_dirty());
        assert_eq!(st.diff().len(), 1);
        assert_eq!(st.commit("rename", Some(10)).unwrap(), 1);
        assert_eq!(st.running().system.identity, "edge-1");

        st.rollback(0).unwrap();
        assert_eq!(st.candidate().system.identity, "CoreRouter");
        assert_eq!(st.commit("back", None).unwrap(), 2);
        assert_eq!(st.rollback(99), Err(StoreError::UnknownRevision(99)));
    }

    #[test]
    fn discard_restores_running() {
        let mut st = ConfigStore::default();
        st.candidate_mut().system.identity = "x".into();
        st.discard();
        assert!(!st.is_dirty());
    }

    #[test]
    fn copies_share_what_was_not_written() {
        use crate::cow::CowArc;
        let mut st = ConfigStore::default();
        st.candidate_mut().ip.routes.push(crate::RouteEntry {
            id: crate::ItemId(1),
            dst_address: "10.9.0.0/16".parse().unwrap(),
            gateway: crate::Gateway::ip("192.0.2.254".parse().unwrap()),
            distance: 1,
            routing_table: crate::RoutingTable::Main,
            disabled: false,
            comment: String::new(),
            check_gateway: Default::default(),
            bfd_profile: String::new(),
        });
        st.commit("routes", None).unwrap();
        // Running, candidate and the new revision are one copy.
        let rev = &st.history()[1].config;
        assert!(CowArc::ptr_eq(&st.running().ip, &rev.ip));
        assert!(CowArc::ptr_eq(&st.candidate().ip, &rev.ip));

        // Writing the system section leaves the routes shared...
        st.candidate_mut().system.identity = "edge".into();
        assert!(CowArc::ptr_eq(&st.candidate().ip, &st.running().ip));
        st.commit("rename", None).unwrap();
        let [.., a, b] = st.history() else { panic!() };
        assert!(CowArc::ptr_eq(&a.config.ip, &b.config.ip));
        // ...and writing the routes copies them, not the interfaces.
        st.candidate_mut().ip.routes.clear();
        assert!(!CowArc::ptr_eq(&st.candidate().ip, &st.running().ip));
        assert!(CowArc::ptr_eq(&st.candidate().interfaces, &st.running().interfaces));
        assert_eq!(st.running().ip.routes.len(), 1, "running kept its routes");
    }

    /// The diff before G0.31: both configs serialized whole.
    fn naive(from: &Config, to: &Config) -> Vec<DiffLine> {
        let (a, b) = (flatten(from), flatten(to));
        let mut out = Vec::new();
        for (path, va) in &a {
            match b.get(path) {
                None => out.push(DiffLine::Remove { path: path.clone(), value: va.clone() }),
                Some(vb) if vb != va => out.push(DiffLine::Change {
                    path: path.clone(),
                    from: va.clone(),
                    to: vb.clone(),
                }),
                Some(_) => {}
            }
        }
        for (path, vb) in &b {
            if !a.contains_key(path) {
                out.push(DiffLine::Add { path: path.clone(), value: vb.clone() });
            }
        }
        out
    }

    #[test]
    fn skipping_equal_sections_gives_the_same_diff() {
        let route = |id: u32, dst: &str| crate::RouteEntry {
            id: crate::ItemId(id),
            dst_address: dst.parse().unwrap(),
            gateway: crate::Gateway::ip("192.0.2.254".parse().unwrap()),
            distance: 1,
            routing_table: crate::RoutingTable::Main,
            disabled: false,
            comment: String::new(),
            check_gateway: Default::default(),
            bfd_profile: String::new(),
        };
        let mut base = Config::default();
        base.system.identity = "edge".into();
        base.ip.routes.push(route(1, "10.1.0.0/16"));
        base.ip.routes.push(route(2, "10.2.0.0/16"));
        base.ip.firewall.next_rule_id = 7;
        base.ipv6.next_dhcp_client_id = 4;
        let edits: [fn(&mut Config); 6] = [
            |c| c.system.identity = "core".into(),
            |c| c.ip.routes.retain(|r| r.id.0 != 1),
            |c| c.ip.next_route_id = 9,
            |c| c.ip.firewall.next_rule_id = 8,
            |c| c.ipv6 = Default::default(),
            |c| {
                c.system.identity.clear();
                c.ip.firewall.next_address_list_id = 3;
                c.ip.routes.clear();
            },
        ];
        assert_eq!(diff_configs(&base, &base.clone()), []);
        for (i, edit) in edits.iter().enumerate() {
            let mut to = base.clone();
            edit(&mut to);
            assert!(!naive(&base, &to).is_empty(), "edit {i} changes something");
            assert_eq!(diff_configs(&base, &to), naive(&base, &to), "edit {i}");
            assert_eq!(diff_configs(&to, &base), naive(&to, &base), "edit {i} reversed");
        }
    }

    /// G0.31a: big lists keep only the blocks the two sides do not share,
    /// and the diff stays the one of the whole lists.
    #[test]
    fn skipping_shared_blocks_gives_the_same_diff() {
        use crate::firewall::AddressListEntry;
        fn route(id: u32) -> crate::RouteEntry {
          crate::RouteEntry {
            id: crate::ItemId(id),
            dst_address: format!("10.{}.{}.0/24", id / 256, id % 256).parse().unwrap(),
            gateway: crate::Gateway::ip("192.0.2.254".parse().unwrap()),
            distance: 1,
            routing_table: crate::RoutingTable::Main,
            disabled: false,
            comment: String::new(),
            check_gateway: Default::default(),
            bfd_profile: String::new(),
          }
        }
        fn entry(id: u32) -> AddressListEntry {
          AddressListEntry {
            id: crate::ItemId(id),
            list: "l".parse().unwrap(),
            address: format!("10.9.{}.{}", id / 256, id % 256).parse().unwrap(),
            disabled: false,
            comment: String::new(),
          }
        }
        fn secret(id: u32) -> crate::ppp::PppSecret {
            crate::ppp::PppSecret {
                id: crate::ItemId(id),
                name: format!("u{id}"),
                ..Default::default()
            }
        }
        let mut base = Config::default();
        for id in 1..=1000 {
            base.ip.routes.push(route(id));
            base.ip.firewall.address_lists.push(entry(id));
            base.ppp.secrets.push(secret(id));
        }
        let edits: [fn(&mut Config); 11] = [
            |c| c.ip.routes.push(route(5000)),
            |c| c.ip.routes.get_mut(500).unwrap().distance = 9,
            |c| drop(c.ip.routes.remove(0)),
            |c| assert!(c.ip.routes.insert(300, route(4000))),
            |c| c.ip.routes.retain(|r| r.id.0 % 7 != 0),
            |c| c.ip.routes.retain(|r| r.id.0 <= 128),
            |c| c.ip.routes.clear(),
            |c| c.ip.firewall.address_lists.push(entry(7000)),
            |c| drop(c.ip.firewall.address_lists.remove(999)),
            |c| c.ppp.secrets.push(secret(9000)),
            |c| {
                c.ppp.next_id = 4;
                c.ip.routes.push(route(6000));
            },
        ];
        for (i, edit) in edits.iter().enumerate() {
            let mut to = base.clone();
            edit(&mut to);
            let want = naive(&base, &to);
            assert!(!want.is_empty(), "edit {i} changes something");
            assert_eq!(diff_configs(&base, &to), want, "edit {i}");
            assert_eq!(diff_configs(&to, &base), naive(&to, &base), "edit {i} reversed");
        }
        // Equal lists that share nothing (a config loaded twice) still diff
        // to nothing.
        let mut copy: Config = serde_json::from_value(serde_json::to_value(&base).unwrap()).unwrap();
        copy.system.identity = "x".into();
        assert_eq!(diff_configs(&base, &copy), naive(&base, &copy));
    }

    #[test]
    fn a_write_that_changes_nothing_is_not_dirty() {
        let mut st = ConfigStore::default();
        let same = st.candidate().system.identity.clone();
        st.candidate_mut().system.identity = same;
        st.candidate_mut().ip.routes.clear();
        assert!(!st.is_dirty());
        assert_eq!(st.commit("noop", None), Err(StoreError::NothingToCommit));
        st.candidate_mut().system.identity = "x".into();
        assert!(st.is_dirty());
        st.discard();
        assert!(!st.is_dirty());
        st.rollback(0).unwrap();
        assert!(!st.is_dirty(), "revision 0 is what runs");
    }

    #[test]
    fn history_is_bounded() {
        let mut st = ConfigStore::default();
        for i in 0..100 {
            st.candidate_mut().system.identity = format!("r{i}");
            st.commit("", None).unwrap();
        }
        assert_eq!(st.history().len(), ConfigStore::DEFAULT_MAX_HISTORY);
        assert_eq!(st.current_revision(), 100);
    }
}
