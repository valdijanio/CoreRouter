//! BGP tables read from the routing daemon on demand (G3.2c), for
//! `routing.bgp.route.list` and `routing.bgp.route.explain`.
//!
//! A full table is ~1 M routes and bgpd takes seconds to print it, so it
//! is never read under the session lock: the command starts a job on the
//! app's runner (a thread of the daemon) and answers `loading`; the job
//! reads the table streaming (`hal-frr`), sorts and validates it
//! (`proto_bgp::rib::Indexed`) and leaves it in a [`Slot`]. Later pages,
//! searches and filters are answered from memory, under the lock, in
//! milliseconds (**medido**, `benches/bgp_rib.rs`). Bounds: at most
//! [`MAX_TABLES`] tables are kept (the least recently used goes), one
//! unused for [`KEEP_SECS`] is dropped, and a table is read again only on
//! `refresh` or after [`STALE_SECS`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use corerouter_hal::routing::RoutingReader;
use corerouter_model::bgp_rib::{BgpPrefix, Direction};
use corerouter_proto_bgp::decision::{self, Explanation};
use corerouter_proto_bgp::rib::Indexed;
use corerouter_proto_bgp::rpki::VrpTable;

use crate::routing_daemon::RoutingBackend;
use crate::{EngineError, Result, Session};

/// Tables kept at once (~24 B per route: four full tables ≈ 100 MiB,
/// **estimado** from the route size test of `model::bgp_rib`).
pub const MAX_TABLES: usize = 4;
/// A table nobody looked at for this long is dropped.
pub const KEEP_SECS: u64 = 600;
/// A table older than this is read again on the next look.
pub const STALE_SECS: u64 = 300;
/// Explanations kept, and for how long.
pub const MAX_EXPLAINS: usize = 32;
pub const EXPLAIN_SECS: u64 = 30;

/// Where a read is.
#[derive(Debug, Clone)]
pub enum Load<T> {
    Loading,
    Ready(Arc<T>),
    Failed(String),
}

#[derive(Debug)]
pub struct Slot<T> {
    pub load: Load<T>,
    /// Unix times: started, finished, last looked at.
    pub started: Option<u64>,
    pub finished: Option<u64>,
    pub used: Option<u64>,
    /// How long the read took, ms (by the runner's clock).
    pub ms: Option<u64>,
    /// The VRP table generation the routes were validated with.
    pub rpki_generation: u64,
}

impl<T> Slot<T> {
    fn new(now: Option<u64>, rpki_generation: u64) -> Self {
        Slot {
            load: Load::Loading,
            started: now,
            finished: None,
            used: now,
            ms: None,
            rpki_generation,
        }
    }
}

pub type Shared<T> = Arc<Mutex<Slot<T>>>;

pub fn lock<T>(s: &Shared<T>) -> MutexGuard<'_, Slot<T>> {
    s.lock().unwrap_or_else(PoisonError::into_inner)
}

/// An explanation and the paths it explains.
#[derive(Debug)]
pub struct Explained {
    pub prefix: BgpPrefix,
    pub explanation: Explanation,
}

/// The tables and explanations (a [`Session`] extension).
#[derive(Default)]
pub struct BgpRibs {
    tables: HashMap<(String, Direction), Shared<Indexed>>,
    explains: HashMap<(String, String), Shared<Explained>>,
}

fn evict<K: Clone + Eq + std::hash::Hash, T>(map: &mut HashMap<K, Shared<T>>, max: usize, keep: u64, now: Option<u64>) {
    if let Some(now) = now {
        map.retain(|_, s| {
            let s = lock(s);
            matches!(s.load, Load::Loading) || s.used.is_none_or(|u| now.saturating_sub(u) < keep)
        });
    }
    while map.len() > max {
        let oldest = map
            .iter()
            .filter(|(_, s)| !matches!(lock(s).load, Load::Loading))
            .min_by_key(|(_, s)| lock(s).used)
            .map(|(k, _)| k.clone());
        match oldest {
            Some(k) => {
                map.remove(&k);
            }
            None => break,
        }
    }
}

/// A connection as a job needs it.
pub(crate) struct Target {
    pub instance: String,
    pub neighbor: String,
    pub local_as: Option<u32>,
}

impl Session {
    fn routing_reader(&self) -> Result<Box<dyn RoutingReader>> {
        match self.ext::<RoutingBackend>() {
            Some(RoutingBackend(Some(d))) => Ok(d.reader()),
            _ => Err(EngineError::Hal(
                "routing: no routing daemon is attached (virtual lab, or the daemon runs without --frr)".into(),
            )),
        }
    }

    pub(crate) fn bgp_target(&self, connection: &str) -> Result<Target> {
        let routing = &self.store().running().routing;
        let c = routing.bgp_connections.get(connection).ok_or_else(|| {
            EngineError::bad(
                "connection",
                format!("no BGP connection {:?} (routing.bgp.connection.list)", crate::logging::cut(connection, 64)),
            )
        })?;
        Ok(Target {
            instance: c.instance.clone(),
            neighbor: c.remote_address.to_string(),
            local_as: routing.bgp.get(&c.instance).map(|i| i.asn.0),
        })
    }

    /// The table of `connection` one way: the one held, or a read started
    /// now (`refresh`, none held, or older than [`STALE_SECS`]).
    pub(crate) fn bgp_table(&mut self, connection: &str, direction: Direction, refresh: bool) -> Result<Shared<Indexed>> {
        let target = self.bgp_target(connection)?;
        let now = self.now();
        let (vrps, generation) = self.rpki_table();
        let key = (connection.to_owned(), direction);
        let held = self.ext::<BgpRibs>().and_then(|r| r.tables.get(&key).cloned());
        let runner = self.runner().ok_or_else(|| {
            EngineError::Hal("this build runs no background jobs (the in-browser lab): connect to a daemon".into())
        })?;
        if let Some(slot) = &held {
            let mut s = lock(slot);
            let stale = s
                .finished
                .zip(now)
                .is_some_and(|(f, n)| n.saturating_sub(f) >= STALE_SECS);
            // A new VRP table: validate again on the runner (a full table
            // takes ~0.1 s, not to be spent under the lock), keeping the
            // routes; the old answer stands until then.
            let revalidate = match &s.load {
                Load::Ready(ix) if s.rpki_generation != generation => Some(Arc::clone(ix)),
                _ => None,
            };
            if let Some(ix) = revalidate {
                s.rpki_generation = generation;
                let job_slot = Arc::clone(slot);
                let vrps = vrps.clone();
                let local_as = target.local_as;
                let _ = runner.spawn(
                    "bgp-rpki",
                    Box::new(move |_| {
                        let again = Arc::new(Indexed::new(ix.rib.clone(), vrps.as_deref(), local_as));
                        let mut s = lock(&job_slot);
                        if matches!(s.load, Load::Ready(_)) {
                            s.load = Load::Ready(again);
                        }
                    }),
                );
            }
            let loading = matches!(s.load, Load::Loading);
            if loading || !(refresh || stale) {
                s.used = now;
                drop(s);
                return Ok(Arc::clone(slot));
            }
        }
        let mut reader = self.routing_reader()?;
        let slot: Shared<Indexed> = Arc::new(Mutex::new(Slot::new(now, generation)));
        let job_slot = Arc::clone(&slot);
        let Target {
            instance,
            neighbor,
            local_as,
        } = target;
        runner
            .spawn(
                "bgp-routes",
                Box::new(move |clock| {
                    let got = reader.bgp_routes(&instance, &neighbor, direction);
                    let load = match got {
                        Ok(rib) => Load::Ready(Arc::new(Indexed::new(rib, vrps.as_deref(), local_as))),
                        Err(e) => Load::Failed(e.to_string()),
                    };
                    let ms = u64::try_from(clock.elapsed().as_millis()).unwrap_or(u64::MAX);
                    let mut s = lock(&job_slot);
                    s.load = load;
                    s.ms = Some(ms);
                    s.finished = s.started.map(|t| t.saturating_add(ms / 1_000));
                }),
            )
            .map_err(|e| EngineError::Hal(format!("cannot start the read: {e}")))?;
        if let Some(r) = self.ext_mut::<BgpRibs>() {
            r.tables.insert(key, Arc::clone(&slot));
            evict(&mut r.tables, MAX_TABLES, KEEP_SECS, now);
        }
        Ok(slot)
    }

    /// The tables held, for the share of each RPKI state per session.
    pub(crate) fn bgp_tables(&self) -> Vec<((String, Direction), Shared<Indexed>)> {
        self.ext::<BgpRibs>()
            .map(|r| r.tables.iter().map(|(k, v)| (k.clone(), Arc::clone(v))).collect())
            .unwrap_or_default()
    }

    /// Every path of `prefix` and why the best won: the one held (younger
    /// than [`EXPLAIN_SECS`]) or a read started now.
    pub(crate) fn bgp_explain(&mut self, instance: &str, prefix: &str) -> Result<Shared<Explained>> {
        let now = self.now();
        let key = (instance.to_owned(), prefix.to_owned());
        if let Some(slot) = self.ext::<BgpRibs>().and_then(|r| r.explains.get(&key).cloned()) {
            let mut s = lock(&slot);
            let fresh = s.started.zip(now).is_none_or(|(t, n)| n.saturating_sub(t) < EXPLAIN_SECS);
            if matches!(s.load, Load::Loading) || fresh {
                s.used = now;
                drop(s);
                return Ok(slot);
            }
        }
        let runner = self.runner().ok_or_else(|| {
            EngineError::Hal("this build runs no background jobs (the in-browser lab): connect to a daemon".into())
        })?;
        let mut reader = self.routing_reader()?;
        let local_as = self.store().running().routing.bgp.get(instance).map(|i| i.asn.0);
        let slot: Shared<Explained> = Arc::new(Mutex::new(Slot::new(now, 0)));
        let job_slot = Arc::clone(&slot);
        let (inst, pfx) = key.clone();
        runner
            .spawn(
                "bgp-explain",
                Box::new(move |clock| {
                    let load = match reader.bgp_prefix(&inst, &pfx) {
                        Ok(mut prefix) => {
                            prefix.local_as = prefix.local_as.or(local_as);
                            let explanation = decision::explain(&prefix, &decision::Options::default());
                            Load::Ready(Arc::new(Explained { prefix, explanation }))
                        }
                        Err(e) => Load::Failed(e.to_string()),
                    };
                    let mut s = lock(&job_slot);
                    s.load = load;
                    s.ms = Some(u64::try_from(clock.elapsed().as_millis()).unwrap_or(u64::MAX));
                    s.finished = s.started;
                }),
            )
            .map_err(|e| EngineError::Hal(format!("cannot start the read: {e}")))?;
        if let Some(r) = self.ext_mut::<BgpRibs>() {
            r.explains.insert(key, Arc::clone(&slot));
            evict(&mut r.explains, MAX_EXPLAINS, EXPLAIN_SECS * 4, now);
        }
        Ok(slot)
    }

    /// The VRP table, for the badges of explained paths.
    pub(crate) fn vrps(&self) -> Option<Arc<VrpTable>> {
        self.rpki_table().0
    }
}
