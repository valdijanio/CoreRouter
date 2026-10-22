//! `Session`: the single entry point for every front end.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use corerouter_hal::{Hal, VirtualHal};
use corerouter_model::{Config, ConfigStore, Interface, InterfaceKind, persist};
use serde::Serialize;
use serde_json::{Value, json};

use crate::cmd::{self, check_params, unknown_command};
use crate::storage::{ConfigStorage, MemoryStorage, Slot};
use crate::validate::validate_all;
use crate::{EngineError, Result, guard};

/// How config commands reach the running config.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CommitMode {
    /// RouterOS style: every successful config command commits at once.
    Immediate,
    /// VyOS/Junos style: edits stay in the candidate until `config.commit`.
    Transactional,
}

#[derive(Debug, Clone, Serialize)]
pub struct JournalEntry {
    pub seq: u64,
    pub command: String,
    pub params: Value,
    pub ok: bool,
    pub error: Option<String>,
}

/// Persistence health, shown under `storage` in the `state.inspect` summary.
#[derive(Debug, Clone, Serialize)]
pub struct StorageStatus {
    pub backend: String,
    /// Slot the running config was restored from at boot (`None`: fresh start).
    pub loaded_from: Option<&'static str>,
    /// Unreadable slots found at boot (they were quarantined).
    pub boot_errors: Vec<String>,
    /// Last save failure; cleared by the next successful save.
    pub last_error: Option<String>,
}

pub struct Session {
    store: ConfigStore,
    hal: Box<dyn Hal>,
    storage: Box<dyn ConfigStorage>,
    storage_status: StorageStatus,
    mode: CommitMode,
    journal: Vec<JournalEntry>,
    seq: u64,
}

/// Session shared between the UI thread and the control server.
pub type Shared = Arc<Mutex<Session>>;

pub fn shared(session: Session) -> Shared {
    Arc::new(Mutex::new(session))
}

/// Lock without unwrap: a poisoned lock still holds a consistent session,
/// because every mutation runs inside `guard` and is rolled back on panic.
pub fn lock(s: &Shared) -> MutexGuard<'_, Session> {
    s.lock().unwrap_or_else(PoisonError::into_inner)
}

const MAX_JOURNAL: usize = 1024;
pub const MAX_BATCH: usize = 256;

impl Session {
    /// Build a session on `hal`, seeding one interface per discovered port.
    /// Nothing outlives the process (in-memory storage).
    pub fn new(hal: Box<dyn Hal>) -> Self {
        Self::with_storage(hal, Box::new(MemoryStorage::default()))
    }

    /// Build a session that restores the committed config from `storage`
    /// (newest readable slot) and saves it there after every commit. With
    /// nothing readable stored, it starts from the discovered ports.
    pub fn with_storage(mut hal: Box<dyn Hal>, mut storage: Box<dyn ConfigStorage>) -> Self {
        let (restored, boot_errors) = restore(storage.as_mut());
        let mut status = StorageStatus {
            backend: storage.describe(),
            loaded_from: None,
            boot_errors,
            last_error: None,
        };
        let store = match restored {
            Some((store, slot)) => {
                log::info!(
                    "restored revision {} from {} ({})",
                    store.current_revision(),
                    slot.name(),
                    status.backend
                );
                for issue in validate_all(store.running()) {
                    log::warn!("restored config: {issue}");
                }
                if let Err(e) = hal.apply(&Config::default(), store.running()) {
                    log::error!("restored config not applied: {e}");
                }
                status.loaded_from = Some(slot.name());
                store
            }
            None => ConfigStore::new(discovered(hal.as_mut())),
        };
        Self {
            store,
            hal,
            storage,
            storage_status: status,
            mode: CommitMode::Immediate,
            journal: Vec::new(),
            seq: 0,
        }
    }

    /// Simulator / lab session on the virtual backend (8 ports).
    pub fn virtual_lab() -> Self {
        Self::new(Box::new(VirtualHal::default()))
    }

    /// The one door: UI, CLI, control channel and MCP all call this.
    pub fn execute(&mut self, id: &str, params: &Value) -> Result<Value> {
        let spec = cmd::find(id).ok_or_else(|| unknown_command(id))?;
        check_params(spec, params)?;
        (spec.enabled)(self).map_err(|reason| EngineError::Disabled {
            id: id.to_owned(),
            reason,
        })?;

        let snapshot = self.store.candidate().clone();
        let result = guard::run(id, || (spec.run)(self, params)).and_then(|value| {
            if spec.journal && self.mode == CommitMode::Immediate && self.store.is_dirty() {
                self.commit_candidate(id)?;
            }
            Ok(value)
        });
        if result.is_err() {
            self.store.set_candidate(snapshot);
        }
        if spec.journal {
            self.record(id, params, &result);
        }
        result
    }

    /// Run several commands as one step. `"$N.key"` in a parameter is replaced
    /// by `key` of step N's result (1-based). With `atomic`, any failure
    /// restores the candidate and nothing is committed.
    pub fn batch(&mut self, steps: &Value, atomic: bool) -> Result<Value> {
        let steps = steps
            .as_array()
            .ok_or_else(|| EngineError::bad("steps", "must be an array"))?;
        if steps.len() > MAX_BATCH {
            return Err(EngineError::bad(
                "steps",
                format!("at most {MAX_BATCH} steps"),
            ));
        }
        let saved_mode = self.mode;
        let snapshot = self.store.candidate().clone();
        if atomic {
            self.mode = CommitMode::Transactional;
        }
        let mut results: Vec<Value> = Vec::with_capacity(steps.len());
        let mut outcome = Ok(());
        for (i, step) in steps.iter().enumerate() {
            let n = i + 1;
            let run = (|| {
                let id = step
                    .get("command")
                    .and_then(Value::as_str)
                    .ok_or_else(|| EngineError::bad("command", "each step needs a command"))?;
                let params = resolve_refs(step.get("params").unwrap_or(&Value::Null), &results)?;
                self.execute(id, &params)
            })();
            match run {
                Ok(v) => results.push(v),
                Err(e) => {
                    outcome = Err(EngineError::Batch {
                        step: n,
                        error: Box::new(e),
                    });
                    break;
                }
            }
        }
        self.mode = saved_mode;
        if atomic {
            match outcome {
                Err(e) => {
                    self.store.set_candidate(snapshot);
                    return Err(e);
                }
                Ok(()) if saved_mode == CommitMode::Immediate && self.store.is_dirty() => {
                    if let Err(e) = self.commit_candidate("batch") {
                        self.store.set_candidate(snapshot);
                        return Err(e);
                    }
                }
                Ok(()) => {}
            }
        } else {
            outcome?;
        }
        Ok(json!({ "results": results }))
    }

    /// Validate → apply to the data plane → promote candidate to running.
    pub(crate) fn commit_candidate(&mut self, comment: &str) -> Result<u32> {
        let issues = validate_all(self.store.candidate());
        if !issues.is_empty() {
            return Err(EngineError::Validation(issues));
        }
        self.hal
            .apply(self.store.running(), self.store.candidate())
            .map_err(|e| EngineError::Hal(e.to_string()))?;
        let revision = self.store.commit(comment, self.hal.now_unix())?;
        self.save();
        Ok(revision)
    }

    /// Persist running + history. A failure does not undo the commit (the
    /// data plane already runs it): it is logged and shown by `state.inspect`.
    fn save(&mut self) {
        let saved = persist::encode(&self.store)
            .map_err(|e| e.to_string())
            .and_then(|text| self.storage.save(&text).map_err(|e| e.to_string()));
        match saved {
            Ok(()) => self.storage_status.last_error = None,
            Err(e) => {
                log::error!(
                    "revision {} is running but was not saved: {e}",
                    self.store.current_revision()
                );
                self.storage_status.last_error = Some(e);
            }
        }
    }

    fn record(&mut self, id: &str, params: &Value, result: &Result<Value>) {
        self.seq = self.seq.saturating_add(1);
        self.journal.push(JournalEntry {
            seq: self.seq,
            command: id.to_owned(),
            params: params.clone(),
            ok: result.is_ok(),
            error: result.as_ref().err().map(ToString::to_string),
        });
        if self.journal.len() > MAX_JOURNAL {
            self.journal.remove(0);
        }
    }

    /// Command registry with enabled state, for `list_commands` and menus.
    pub fn list(&self) -> Value {
        cmd::describe(self)
    }

    /// Compact state summary, or one subtree of the candidate by dotted path
    /// (`"interfaces"`, `"routing.bgp"`), so agents never pay for the whole tree.
    pub fn inspect(&self, path: Option<&str>) -> Result<Value> {
        let cand = self.store.candidate();
        match path.map(str::trim).filter(|p| !p.is_empty()) {
            None => Ok(json!({
                "identity": cand.system.identity,
                "backend": self.hal.describe(),
                "mode": self.mode,
                "revision": self.store.current_revision(),
                "dirty": self.store.is_dirty(),
                "pending_changes": self.store.diff().len(),
                "storage": self.storage_status,
                "counts": {
                    "interfaces": cand.interfaces.len(),
                    "ip_addresses": cand.ip.addresses.len(),
                    "bgp_instances": cand.routing.bgp.len(),
                },
                "paths": ["system", "interfaces", "ip", "routing", "running", "journal"],
            })),
            Some("journal") => serde_json::to_value(&self.journal)
                .map_err(|e| EngineError::Internal(e.to_string())),
            Some(p) => {
                let (root, rest) = match p.strip_prefix("running") {
                    Some(rest) => (self.store.running(), rest.trim_start_matches('.')),
                    None => (cand, p),
                };
                let mut v =
                    serde_json::to_value(root).map_err(|e| EngineError::Internal(e.to_string()))?;
                for seg in rest.split('.').filter(|s| !s.is_empty()) {
                    v = v
                        .get(seg)
                        .cloned()
                        .ok_or_else(|| EngineError::bad("path", format!("no '{seg}' in '{p}'")))?;
                }
                Ok(v)
            }
        }
    }

    pub fn store(&self) -> &ConfigStore {
        &self.store
    }

    pub(crate) fn store_mut(&mut self) -> &mut ConfigStore {
        &mut self.store
    }

    /// Read-only view of the backend, e.g. for `enabled` checks on its features.
    pub(crate) fn hal(&self) -> &dyn Hal {
        self.hal.as_ref()
    }

    pub(crate) fn hal_mut(&mut self) -> &mut dyn Hal {
        self.hal.as_mut()
    }

    pub fn backend(&self) -> String {
        self.hal.describe()
    }

    pub fn mode(&self) -> CommitMode {
        self.mode
    }

    pub(crate) fn set_mode(&mut self, mode: CommitMode) {
        self.mode = mode;
    }

    pub fn journal(&self) -> &[JournalEntry] {
        &self.journal
    }

    pub fn storage_status(&self) -> &StorageStatus {
        &self.storage_status
    }
}

/// Default config: one Ethernet interface per discovered port, applied.
fn discovered(hal: &mut dyn Hal) -> Config {
    let mut initial = Config::default();
    match hal.discover_links() {
        Ok(links) => {
            for l in links {
                let mut iface = Interface::new(l.name.clone(), InterfaceKind::Ethernet);
                iface.mtu = l.mtu;
                iface.mac = l.mac.and_then(|m| m.parse().ok());
                initial.interfaces.insert(l.name, iface);
            }
        }
        Err(e) => log::warn!("link discovery failed: {e}"),
    }
    if let Err(e) = hal.apply(&Config::default(), &initial) {
        log::warn!("initial apply skipped: {e}");
    }
    initial
}

/// Newest readable slot, quarantining the unreadable ones on the way.
fn restore(storage: &mut dyn ConfigStorage) -> (Option<(ConfigStore, Slot)>, Vec<String>) {
    let mut errors = Vec::new();
    for slot in [Slot::Current, Slot::Previous] {
        let text = match storage.load(slot) {
            Ok(Some(text)) => text,
            Ok(None) => continue,
            Err(e) => {
                log::error!("cannot read {} config: {e}", slot.name());
                errors.push(format!("{}: {e}", slot.name()));
                continue;
            }
        };
        match persist::decode(&text) {
            Ok(store) => return (Some((store, slot)), errors),
            Err(e) => {
                log::error!("{} config is unreadable, quarantined: {e}", slot.name());
                errors.push(format!("{}: {e}", slot.name()));
                if let Err(q) = storage.quarantine(slot) {
                    log::error!("cannot quarantine {} config: {q}", slot.name());
                }
            }
        }
    }
    if !errors.is_empty() {
        log::error!("no readable saved config; starting from discovered ports");
    }
    (None, errors)
}

/// Replace `"$N.key.sub"` strings with values from earlier step results.
fn resolve_refs(v: &Value, results: &[Value]) -> Result<Value> {
    Ok(match v {
        Value::String(s) if s.starts_with('$') => {
            let Some((num, path)) = s.get(1..).and_then(|r| r.split_once('.')) else {
                return Ok(v.clone());
            };
            let Ok(n) = num.parse::<usize>() else {
                return Ok(v.clone());
            };
            let mut cur = n
                .checked_sub(1)
                .and_then(|i| results.get(i))
                .ok_or_else(|| EngineError::bad(s, format!("step {n} has no result yet")))?;
            for seg in path.split('.') {
                cur = cur.get(seg).ok_or_else(|| {
                    EngineError::bad(s, format!("step {n} result has no '{seg}'"))
                })?;
            }
            cur.clone()
        }
        Value::Array(a) => Value::Array(
            a.iter()
                .map(|x| resolve_refs(x, results))
                .collect::<Result<_>>()?,
        ),
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, x)| Ok((k.clone(), resolve_refs(x, results)?)))
                .collect::<Result<_>>()?,
        ),
        other => other.clone(),
    })
}
