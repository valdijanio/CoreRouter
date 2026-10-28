//! Transactional store: commands edit the candidate; `commit` promotes it to
//! running and records a revision; `rollback` restores an old revision into
//! the candidate (it still needs a commit, exactly like Junos/VyOS).
//!
//! The model has no clock (`SystemTime::now` is unavailable on wasm32), so
//! callers pass the timestamp they get from the HAL.

use std::collections::BTreeMap;

use serde::Serialize;
use serde_json::Value;

use crate::config::Config;

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
    let a = flatten(from);
    let b = flatten(to);
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
