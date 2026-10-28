//! OSPF state for the commands (G3.4b): the neighbors and interfaces come
//! with every routing poll (`RoutingStatus`); the link-state database and
//! the routes are read on demand, never under the session lock — a
//! command asks ([`Session::ospf_db`] files the request and answers
//! "pending"), the daemon's FRR thread takes the requests
//! ([`Session::ospf_db_wanted`]), streams the LSDB outside the lock and
//! hands it back ([`Session::set_ospf_db`]). A result is kept for
//! [`FRESH_SECS`] and shared (`Arc`): pages, the topology and "why this
//! path?" read the same copy.
//!
//! Without a routing backend (the virtual lab) everything comes from
//! `proto_ospf::sample`, made up from the config.

use std::collections::HashMap;
use std::sync::Arc;

use corerouter_model::ospf_state::{Lsdb, OspfIfState, OspfNeighbor, OspfRoute};

use crate::Session;

/// How long a read LSDB is used before it is read again.
pub const FRESH_SECS: u64 = 10;
/// Most instances waiting to be read.
pub const MAX_WANTED: usize = 8;

/// One instance's database and routes.
pub type Db = Arc<(Lsdb, Vec<OspfRoute>)>;

struct Entry {
    at: u64,
    result: Result<Db, String>,
}

/// A [`Session`] extension.
#[derive(Default)]
pub struct OspfDbCache {
    entries: HashMap<String, Entry>,
    wanted: Vec<String>,
}

/// What a command gets.
pub enum DbView {
    /// Read from the daemon (`stale`: older than [`FRESH_SECS`], a new
    /// read is on its way).
    Daemon { db: Db, stale: bool },
    /// The virtual lab's made-up network.
    Sample(Db),
    /// Asked; nothing read yet.
    Pending,
    Error(String),
}

impl DbView {
    pub fn source(&self) -> &'static str {
        match self {
            DbView::Daemon { .. } => "frr",
            DbView::Sample(_) => "virtual lab sample",
            DbView::Pending => "pending",
            DbView::Error(_) => "error",
        }
    }

    pub fn db(&self) -> Option<&Db> {
        match self {
            DbView::Daemon { db, .. } | DbView::Sample(db) => Some(db),
            _ => None,
        }
    }
}

impl Session {
    /// The LSDB and routes of OSPF instance `instance`.
    pub fn ospf_db(&mut self, instance: &str) -> DbView {
        if !self.has_routing() {
            let cfg = self.store().running().clone();
            let (_, _, db, routes) = corerouter_proto_ospf::sample::lab(&cfg, instance);
            return DbView::Sample(Arc::new((db, routes)));
        }
        let now = self.hal_now().unwrap_or(0);
        let Some(cache) = self.ext_mut::<OspfDbCache>() else {
            return DbView::Pending;
        };
        let entry = cache.entries.get(instance);
        let fresh = entry.is_some_and(|e| now.saturating_sub(e.at) < FRESH_SECS);
        if !fresh && !cache.wanted.iter().any(|w| w == instance) && cache.wanted.len() < MAX_WANTED {
            cache.wanted.push(instance.to_owned());
        }
        match entry {
            None => DbView::Pending,
            Some(Entry { result: Ok(db), .. }) => DbView::Daemon { db: Arc::clone(db), stale: !fresh },
            Some(Entry { result: Err(e), .. }) => DbView::Error(e.clone()),
        }
    }

    /// The instances whose database the FRR thread should read now.
    pub fn ospf_db_wanted(&mut self) -> Vec<String> {
        self.ext_mut::<OspfDbCache>().map(|c| std::mem::take(&mut c.wanted)).unwrap_or_default()
    }

    /// What the FRR thread read for `instance`.
    pub fn set_ospf_db(&mut self, instance: String, result: Result<(Lsdb, Vec<OspfRoute>), String>) {
        let now = self.hal_now().unwrap_or(0);
        if let Some(c) = self.ext_mut::<OspfDbCache>() {
            if c.entries.len() >= MAX_WANTED * 4 {
                c.entries.retain(|_, e| now.saturating_sub(e.at) < FRESH_SECS);
            }
            c.entries.insert(instance, Entry { at: now, result: result.map(Arc::new) });
        }
    }

    /// The neighbors and interfaces: the last poll, or the lab's.
    pub fn ospf_live(&self) -> (Vec<OspfNeighbor>, Vec<OspfIfState>, &'static str) {
        if self.has_routing() {
            let st = self.routing_status();
            return (
                st.map(|s| s.ospf_neighbors.clone()).unwrap_or_default(),
                st.map(|s| s.ospf_interfaces.clone()).unwrap_or_default(),
                "frr",
            );
        }
        let cfg = self.store().running();
        let mut n = Vec::new();
        let mut i = Vec::new();
        for inst in cfg.routing.ospf.instances.keys() {
            let (a, b, _, _) = corerouter_proto_ospf::sample::lab(cfg, inst);
            n.extend(a);
            i.extend(b);
        }
        (n, i, "virtual lab sample")
    }
}

#[cfg(test)]
mod tests {
    use corerouter_hal::VirtualHal;

    use super::*;

    #[test]
    fn the_lab_answers_with_its_sample() {
        let mut s = Session::new(Box::new(VirtualHal::default()));
        assert!(matches!(s.ospf_db("none"), DbView::Sample(_)));
        assert!(s.ospf_db_wanted().is_empty());
        let (n, _, src) = s.ospf_live();
        assert!(n.is_empty());
        assert_eq!(src, "virtual lab sample");
    }
}
