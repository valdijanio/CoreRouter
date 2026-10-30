//! `Session`: the single entry point for every front end.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use corerouter_hal::{Hal, VirtualHal};
use corerouter_model::sections::{self, Sections};
use corerouter_model::{Config, ConfigStore, Interface, InterfaceKind, User, Users, persist};
use serde::Serialize;
use serde_json::{Value, json};

use crate::auth::{self, Group, Login, Logins, Principal};
use crate::cmd::{self, check_params, unknown_command};
use crate::dhcp_client::DhcpRuntime;
use crate::dhcp6_client::Dhcp6Runtime;
use crate::dom_watch::DomWatch;
use crate::firewall_dyn::DynamicLists;
use crate::link_watch::LinkWatch;
use crate::metrics::EngineCounters;
use crate::neighbors::NeighborTable;
use crate::safe_mode::{Caller, SafeMode};
use crate::storage::{ConfigStorage, MemoryStorage, Slot};
use crate::tasks::Tasks;
use crate::validate::{validate_all, validate_commit};
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
    /// The restored config did not reach the data plane at boot: why. While
    /// set, every tick retries the whole config and the next commit applies
    /// everything, not only its change (audit #8).
    pub boot_apply_error: Option<String>,
    /// Oldest revisions the last save left out of the file to keep it
    /// under the size limit (they stay in memory until the restart).
    pub revisions_not_saved: usize,
}

pub struct Session {
    store: ConfigStore,
    hal: Box<dyn Hal>,
    storage: Box<dyn ConfigStorage>,
    storage_status: StorageStatus,
    mode: CommitMode,
    journal: Vec<JournalEntry>,
    seq: u64,
    /// Sender of the command being run (see [`Session::execute_as`]).
    caller: Caller,
    safe_mode: SafeMode,
    /// Heard by discovery protocols (operational state, never saved).
    pub(crate) neighbors: NeighborTable,
    /// Address-list entries with a timeout (operational, never saved; G2.1).
    pub(crate) dynamic_addresses: DynamicLists,
    /// Diagnostic tool jobs (operational state, never saved).
    pub(crate) tasks: Tasks,
    /// DHCP clients at run time: leases, what they installed, history
    /// (operational state, never saved; G4.7).
    pub(crate) dhcp: DhcpRuntime,
    /// DHCPv6 clients at run time (G4.7b), like `dhcp`.
    pub(crate) dhcp6: Dhcp6Runtime,
    /// Router accounts (G0.3): saved with the config, outside its revisions.
    users: Users,
    /// Logged-in sessions, for `user.active.list` (never saved).
    logins: Logins,
    /// The command being run said `force: true`: a lockout is accepted
    /// (G2.1b, see `crate::lockout`). Reset after each command or batch.
    pub(crate) lockout_ack: bool,
    /// Inside [`Session::batch`]: the steps share one acknowledgement.
    in_batch: bool,
    /// When links went up/down (operational, never saved; G1.19).
    pub(crate) links: LinkWatch,
    /// SFP diagnostics past their thresholds (operational; G1.20).
    pub(crate) dom: DomWatch,
    /// What the daemon's NTP client last learned (operational; G4.6).
    pub(crate) ntp: corerouter_model::ntp::NtpStatus,
    /// Commands and commits since start (operational; G4.4).
    pub(crate) counters: EngineCounters,
    /// Runtime state of features, by type (`ext`/`ext_mut`): a new feature
    /// keeps its state here instead of adding a field (crate::ext).
    ext: crate::ext::Extensions,
}

/// Inside an atomic [`Session::batch`]: its steps need no rollback point
/// of their own (a failure restores the batch's).
#[derive(Debug, Default)]
struct AtomicBatch(bool);

/// Session shared between the UI thread and the control server.
pub type Shared = Arc<Mutex<Session>>;

pub fn shared(session: Session) -> Shared {
    Arc::new(Mutex::new(session))
}

/// Lock without unwrap: a poisoned lock still holds a consistent session,
/// because every mutation (command, commit, tick) runs inside `guard` and
/// its candidate is rolled back on panic.
pub fn lock(s: &Shared) -> MutexGuard<'_, Session> {
    s.lock().unwrap_or_else(PoisonError::into_inner)
}

const MAX_JOURNAL: usize = 1024;
/// Entries past [`MAX_JOURNAL`] kept before a trim (see `record`).
const JOURNAL_SLACK: usize = 256;
/// Steps of one batch. `/import` sends a whole script as one atomic batch
/// (at most 1 MiB, ~30 bytes a command at the least): a router must be able
/// to import its own `/export` (audit #9).
pub const MAX_BATCH: usize = 32_768;

/// Steps an atomic batch refuses: they commit, end the transaction or
/// change how commits happen, so "all or nothing" could not hold (audit #5).
const NOT_IN_ATOMIC_BATCH: &[&str] = &[
    "config.commit",
    "config.discard",
    "config.mode.set",
    "config.safe-mode.enter",
    "config.safe-mode.exit",
    "config.safe-mode.cancel",
    // A reboot cannot be taken back if a later step fails (G1.6qa).
    "system.reboot",
    "system.shutdown",
];

impl Session {
    /// A feature's runtime state of type `T` (crate::ext), if set.
    pub fn ext<T: std::any::Any + Send>(&self) -> Option<&T> {
        self.ext.get()
    }

    /// A feature's runtime state of type `T`, created with `Default` the
    /// first time (crate::ext).
    pub fn ext_mut<T: std::any::Any + Send + Default>(&mut self) -> Option<&mut T> {
        self.ext.get_mut()
    }

    /// Build a session on `hal`, seeding one interface per discovered port.
    /// Nothing outlives the process (in-memory storage).
    pub fn new(hal: Box<dyn Hal>) -> Self {
        Self::with_storage(hal, Box::new(MemoryStorage::default()))
    }

    /// Build a session that restores the committed config from `storage`
    /// (newest readable slot) and saves it there after every commit. With
    /// nothing readable stored, it starts from the discovered ports.
    pub fn with_storage(mut hal: Box<dyn Hal>, mut storage: Box<dyn ConfigStorage>) -> Self {
        // The virtual lab's DHCP clients get leases from a simulated server.
        hal.offer_dhcp_lab_server(Arc::new(corerouter_proto_dhcp::lab::LabServer::default()));
        hal.offer_dhcp6_lab_server(Arc::new(corerouter_proto_dhcp::lab6::LabServer6::default()));
        hal.offer_pppoe_lab_server(crate::pppoe_client::lab_bng());
        hal.offer_dhcp_lab_clients(Arc::new(corerouter_proto_dhcp::lab_hosts::LabHosts::default()));
        hal.offer_dhcp6_lab_clients(Arc::new(corerouter_proto_dhcp::lab_hosts6::LabHosts6::default()));
        let (restored, mut boot_errors) = restore(storage.as_mut());
        let (restored, users, slot_bytes) = match restored {
            Some((store, users, slot, bytes)) => (Some((store, slot)), users, bytes),
            None => (None, Users::default(), 0),
        };
        // The commits since the slot was written (G0.22).
        let mut journal = None;
        let slot_rev = restored.as_ref().map_or(0, |(store, _)| store.current_revision());
        let restored = restored.map(|(store, slot)| {
            let (store, size) =
                crate::history_files::replay_journal(storage.as_mut(), store, &mut boot_errors);
            journal = size;
            (store, slot)
        });
        // The older revisions kept in files of their own (G1.23).
        let (slot, store) = restored.map_or((None, None), |(store, slot)| (Some(slot), Some(store)));
        let (store, files) =
            crate::history_files::restore_history(storage.as_mut(), store, &mut boot_errors);
        let restored = store.zip(slot);
        let mut files = files;
        if let Some((store, slot)) = &restored
            && let Some(newest) = store.history().last()
            && let Some(journal) = journal
            && storage.config_journal()
        {
            // Which revisions the two slots hold: a commit is journaled
            // only with both there (crate::history_files).
            let slots = match slot {
                Slot::Current => (
                    Some(slot_rev),
                    storage
                        .load(Slot::Previous)
                        .ok()
                        .flatten()
                        .and_then(|t| crate::history_files::slot_revision(&t)),
                ),
                Slot::Previous => (None, Some(slot_rev)),
            };
            files.note_boot(
                (newest.number, newest.config.clone()),
                // The slot holds the config twice (`running`, the newest
                // revision): half the file bounds it.
                slot_bytes / 2,
                journal,
                users.clone(),
                slots,
            );
        }
        let mut ext = crate::ext::Extensions::default();
        ext.set(files);
        let mut status = StorageStatus {
            backend: storage.describe(),
            loaded_from: None,
            boot_errors,
            last_error: None,
            boot_apply_error: None,
            revisions_not_saved: 0,
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
                // No pool has a prefix yet: addresses taken from pools wait.
                let mut boot = store.running().clone();
                boot.ip.addresses.retain(|a| a.from_pool.is_none());
                if let Err(e) = hal.apply(&Config::default(), &boot) {
                    log::error!("restored config not applied (retried every second): {e}");
                    status.boot_apply_error = Some(e.to_string());
                }
                status.loaded_from = Some(slot.name());
                store
            }
            None => ConfigStore::new(discovered(hal.as_mut())),
        };
        let mut s = Self {
            store,
            hal,
            storage,
            storage_status: status,
            mode: CommitMode::Immediate,
            journal: Vec::new(),
            seq: 0,
            caller: Caller::local(),
            safe_mode: SafeMode::default(),
            neighbors: NeighborTable::default(),
            dynamic_addresses: DynamicLists::default(),
            tasks: Tasks::default(),
            dhcp: DhcpRuntime::default(),
            dhcp6: Dhcp6Runtime::default(),
            users,
            logins: Logins::default(),
            lockout_ack: false,
            in_batch: false,
            links: LinkWatch::default(),
            dom: DomWatch::default(),
            ntp: Default::default(),
            counters: EngineCounters::default(),
            ext,
        };
        // G4.3n: passwords kept in clear by older versions get sealed.
        crate::sealing::seal_legacy(&mut s);
        s
    }

    /// Simulator / lab session on the virtual backend (8 ports).
    pub fn virtual_lab() -> Self {
        Self::new(Box::new(VirtualHal::default()))
    }

    /// The one door: UI, CLI, control channel and MCP all call this.
    pub fn execute(&mut self, id: &str, params: &Value) -> Result<Value> {
        let spec = cmd::find(id);
        // G0.31b: only the outermost command of a reply defers.
        self.off_lock_nest(true);
        let result = self.execute_counted(spec, id, params);
        self.off_lock_nest(false);
        self.counters
            .note_command(spec.map(|spec| spec.journal), result.is_ok());
        result
    }

    fn execute_counted(
        &mut self,
        spec: Option<&'static cmd::CommandSpec>,
        id: &str,
        params: &Value,
    ) -> Result<Value> {
        self.expire_safe_mode();
        let spec = spec.ok_or_else(|| unknown_command(id))?;
        self.permit(auth::required_group(spec.id, spec.journal))
            .map_err(|reason| EngineError::Denied {
                id: id.to_owned(),
                reason,
            })?;
        check_params(spec, params)?;
        (spec.enabled)(self).map_err(|reason| EngineError::Disabled {
            id: id.to_owned(),
            reason,
        })?;

        // Queries never change the config: no rollback point to copy
        // (`queries_leave_the_candidate_alone` runs every one of them).
        // Inside an atomic batch a failed step undoes the whole batch from
        // its own copy: one per step made `/import` quadratic (audit-perf).
        // The copy shares every section with the candidate (G0.16): the
        // command pays for copying only the sections it writes.
        let in_atomic = self.ext::<AtomicBatch>().is_some_and(|a| a.0);
        let snapshot = (spec.journal && !in_atomic).then(|| self.store.candidate().clone());
        let rev_before = self.store.current_revision();
        // The commit runs inside the guard too: a panic in a validator or
        // the data plane must not leave the edit behind for the next
        // command to commit (audit #6).
        let result = guard::run(id, || {
            let value = (spec.run)(self, params)?;
            if spec.journal && self.mode == CommitMode::Immediate && self.store.is_dirty() {
                self.commit_candidate(id)?;
            }
            Ok(value)
        });
        if let (Err(_), Some(snapshot)) = (&result, snapshot) {
            self.store.set_candidate(snapshot);
        }
        if !self.in_batch {
            self.lockout_ack = false;
        }
        if spec.journal {
            let rev = self.store.current_revision();
            self.record(id, params, &result, (rev != rev_before).then_some(rev));
        }
        result
    }

    /// [`Session::execute`] on behalf of a control-channel connection (it
    /// may own Safe Mode, which ends when that connection closes).
    pub fn execute_as(&mut self, caller: &Caller, id: &str, params: &Value) -> Result<Value> {
        self.as_caller(caller, |s| s.execute(id, params))
    }

    /// [`Session::batch`] on behalf of a connection.
    pub fn batch_as(&mut self, caller: &Caller, steps: &Value, atomic: bool) -> Result<Value> {
        self.as_caller(caller, |s| s.batch(steps, atomic))
    }

    /// [`Session::list`] as seen by a connection: commands its group may
    /// not run show `enabled: false` with the reason.
    pub fn list_as(&mut self, caller: &Caller) -> Value {
        self.as_caller(caller, |s| s.list())
    }

    /// [`Session::inspect`] as seen by a connection (`safe_mode.yours`).
    pub fn inspect_as(&mut self, caller: &Caller, path: Option<&str>) -> Result<Value> {
        self.as_caller(caller, |s| s.inspect(path))
    }

    fn as_caller<T>(&mut self, caller: &Caller, f: impl FnOnce(&mut Self) -> T) -> T {
        let outer = std::mem::replace(&mut self.caller, caller.clone());
        let out = f(self);
        self.caller = outer;
        out
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
        if atomic {
            let control = steps.iter().enumerate().find_map(|(i, step)| {
                let id = step.get("command").and_then(Value::as_str)?;
                NOT_IN_ATOMIC_BATCH.contains(&id).then_some((i, id))
            });
            if let Some((i, id)) = control {
                return Err(EngineError::Batch {
                    step: i.saturating_add(1),
                    error: Box::new(EngineError::bad(
                        "command",
                        format!(
                            "{id} cannot run inside an atomic batch (the batch is one \
                             transaction: it commits at the end, or nothing does); \
                             send it on its own, or use atomic: false"
                        ),
                    )),
                });
            }
        }
        let saved_mode = self.mode;
        let snapshot = self.store.candidate().clone();
        if atomic {
            self.mode = CommitMode::Transactional;
        }
        let outer_batch = std::mem::replace(&mut self.in_batch, true);
        let outer_atomic = self.ext::<AtomicBatch>().is_some_and(|a| a.0);
        self.ext.set(AtomicBatch(atomic || outer_atomic));
        let out = self.batch_steps(steps, atomic, saved_mode, snapshot);
        self.ext.set(AtomicBatch(outer_atomic));
        self.in_batch = outer_batch;
        if !outer_batch {
            self.lockout_ack = false;
        }
        out
    }

    fn batch_steps(
        &mut self,
        steps: &[Value],
        atomic: bool,
        saved_mode: CommitMode,
        snapshot: corerouter_model::Config,
    ) -> Result<Value> {
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
                    let committed = guard::run("batch", || self.commit_candidate("batch"));
                    if let Err(e) = committed {
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
    /// In Safe Mode the revision is marked and not saved: the boot config
    /// stays the one from the entry until `config.safe-mode.exit`.
    pub(crate) fn commit_candidate(&mut self, comment: &str) -> Result<u32> {
        self.commit_checked(comment, true)
    }

    /// [`Self::commit_candidate`] without the lockout check: for restoring a
    /// config that was running before (the Safe Mode undo).
    pub(crate) fn commit_restoring(&mut self, comment: &str) -> Result<u32> {
        self.commit_checked(comment, false)
    }

    fn commit_checked(&mut self, comment: &str, lockout: bool) -> Result<u32> {
        let result = self.commit_counted(comment, lockout);
        self.counters.note_commit(result.is_ok());
        result
    }

    fn commit_counted(&mut self, comment: &str, lockout: bool) -> Result<u32> {
        // G0.22: with the running config known valid, only the validators
        // that read a section this commit changed run (the others give the
        // running config's answer: none).
        let scope = match self.ext::<ValidRunning>() {
            Some(v) if sections::changed(&v.0, self.store.running()).is_empty() => {
                sections::changed(self.store.running(), self.store.candidate())
            }
            _ => Sections::ALL,
        };
        let issues = validate_commit(self.store.running(), self.store.candidate(), scope);
        // Debug builds (every test) check the table of what each validator
        // reads against the full validation on each commit: a dependency
        // left out fails the command that found it.
        #[cfg(debug_assertions)]
        if scope != Sections::ALL {
            let full = validate_all(self.store.candidate());
            if full != issues {
                return Err(EngineError::Internal(format!(
                    "incremental validation of {scope:?} missed: {full:?}, got {issues:?}"
                )));
            }
        }
        if !issues.is_empty() {
            return Err(EngineError::Validation(issues));
        }
        // It must fit in the saved file with its copy in the history, or
        // the next boot could not load it (audit #1). With the config
        // journal (G0.22) the commit serializes only what it changed, and
        // the size is bounded by the slot plus every line since; only when
        // that bound passes the limit is the config measured.
        let unencodable = |e: persist::PersistError| {
            EngineError::Validation(vec![corerouter_model::validate::Issue::new(
                "config",
                format!("cannot be encoded: {e}"),
            )])
        };
        let delta = match self.ext::<crate::history_files::RevisionFiles>() {
            Some(files) if self.storage.config_journal() && files.size_bound(0).is_some() => {
                let d = persist::revision_delta(self.store.running(), self.store.candidate())
                    .map_err(unencodable)?;
                let text = serde_json::to_string(&d).unwrap_or_default();
                files
                    .size_bound(text.len())
                    .filter(|&bound| bound <= persist::MAX_CONFIG_BYTES)
                    .map(|_| d)
            }
            _ => None,
        };
        let (encoded, size) = if delta.is_some() {
            (None, 0)
        } else {
            // Serialized once: the save after the commit reuses the text (G1.23).
            let text = persist::encode_config(self.store.candidate()).map_err(unencodable)?;
            let size = text.len();
            (Some(text), size)
        };
        if size > persist::MAX_CONFIG_BYTES {
            return Err(EngineError::Validation(vec![corerouter_model::validate::Issue::new(
                "config",
                format!(
                    "would be {} MiB, over the {} MiB that can be saved; remove items first",
                    size >> 20,
                    persist::MAX_CONFIG_BYTES >> 20
                ),
            )]));
        }
        // The data plane also holds what DHCP clients installed (G4.7).
        // Copied only when DHCP added something (audit-perf: two copies of
        // the whole config per commit before).
        let running_dyn = owned(self.effective(self.store.running()));
        let to_dyn = owned(self.effective(self.store.candidate()));
        let running = running_dyn.as_ref().unwrap_or(self.store.running());
        let to = to_dyn.as_ref().unwrap_or(self.store.candidate());
        // The lockout check sees the same: a DHCP address can be the one
        // the operator is connected to.
        if lockout {
            let dynamic = self.dynamic_now();
            self.check_lockout(running, to, &dynamic, &dynamic)?;
        }
        // The boot apply failed: the data plane may hold nothing of the
        // running config, so install all of it, not only the change.
        let empty;
        let from = if self.storage_status.boot_apply_error.is_some() {
            empty = Config::default();
            &empty
        } else {
            running
        };
        self.hal
            .apply(from, to)
            .map_err(|e| EngineError::Hal(e.to_string()))?;
        // G3.1: the routing daemons (FRR) take the routing part; when they
        // refuse, the data plane goes back too and the commit fails.
        if let Some(crate::routing_daemon::RoutingBackend(Some(daemon))) =
            self.ext.get_mut::<crate::routing_daemon::RoutingBackend>()
            && (from.routing != to.routing
                || corerouter_proto_bgp::networks_changed(from, to)
                || corerouter_proto_ospf::frr::statics_changed(from, to)
                || self.storage_status.boot_apply_error.is_some())
            && let Err(e) = daemon.apply(from, to)
        {
            if let Err(back) = self.hal.apply(to, from) {
                log::error!("routing refused the commit and the data plane could not go back: {back}");
            }
            return Err(EngineError::Hal(format!("routing: {e}")));
        }
        if self.storage_status.boot_apply_error.take().is_some() {
            log::info!("the whole config reached the data plane with this commit");
        }
        let pending = self.safe_mode.is_active();
        let comment = match (pending, comment.is_empty()) {
            (false, _) => comment.to_owned(),
            (true, true) => "[safe mode]".to_owned(),
            (true, false) => format!("{comment} [safe mode]"),
        };
        let base = self.store.current_revision();
        let revision = self.store.commit(&comment, self.now())?;
        self.ext.set(ValidRunning(self.store.running().clone()));
        // G2.3: the CGNAT mapping history ("who was") follows every commit.
        self.cgnat_note();
        let line = match (&delta, self.store.history().last()) {
            (Some(d), Some(rev)) => persist::encode_journal_line(rev, base, d).ok(),
            _ => None,
        };
        if let Some(files) = self.ext_mut::<crate::history_files::RevisionFiles>() {
            if let Some(text) = encoded {
                files.note_encoded(revision, text);
            }
            if let Some(line) = line {
                files.note_line(revision, base, line);
            }
        }
        if !pending {
            self.save();
        }
        Ok(revision)
    }

    /// Retry the boot apply that failed (called by [`Session::tick`]).
    pub(crate) fn retry_boot_apply(&mut self) {
        if self.storage_status.boot_apply_error.is_none() {
            return;
        }
        let to = self.effective(self.store.running()).into_owned();
        let tried = guard::run("boot apply", || {
            self.hal
                .apply(&Config::default(), &to)
                .map_err(|e| EngineError::Hal(e.to_string()))
        });
        match tried {
            Ok(()) => {
                log::info!(
                    "restored config (revision {}) applied on retry",
                    self.store.current_revision()
                );
                self.storage_status.boot_apply_error = None;
            }
            Err(e) => {
                let e = e.to_string();
                if self.storage_status.boot_apply_error.as_deref() != Some(e.as_str()) {
                    log::error!("restored config still not applied: {e}");
                }
                self.storage_status.boot_apply_error = Some(e);
            }
        }
    }

    /// Persist running + history (bounded: the oldest revisions are left
    /// out when the file would be too big). In Safe Mode what is saved is
    /// the store as it was at the entry, so a reboot never boots the
    /// unconfirmed changes, whatever triggers the save (audit #2). A
    /// failure does not undo the commit (the data plane already runs it):
    /// it is logged and shown by `state.inspect`.
    pub(crate) fn save(&mut self) {
        self.save_to(false);
    }

    /// G0.27: write the newest saved revision to the slot (a clean
    /// shutdown, before the process ends). Commits normally go to the
    /// config journal (G0.22) and the slot is rewritten only now and then:
    /// after this, the next boot replays no journal line, and a build from
    /// before the journal that boots the same directory finds every commit
    /// in the slot. The journal keeps its format (the lines the previous
    /// slot still needs stay, and the boot skips them). `Ok(false)`: nothing
    /// to write (no journal, or the slot already holds the newest revision).
    /// In Safe Mode the saved store is the one from before it, as for
    /// every save. `Err`: the write failed (the journal still holds the
    /// commits; the next boot replays them).
    pub fn checkpoint(&mut self) -> std::result::Result<bool, String> {
        if !self.storage.revision_files() {
            return Ok(false);
        }
        let entry_store = self.safe_mode_entry_store();
        let store = entry_store.as_ref().unwrap_or(&self.store);
        let files = self.ext.get::<crate::history_files::RevisionFiles>();
        let newest = match files {
            Some(f) => crate::history_files::slot_is_newest(self.storage.as_ref(), f, store),
            None => true,
        };
        if newest {
            return Ok(false);
        }
        self.save_to(true);
        match &self.storage_status.last_error {
            None => Ok(true),
            Some(e) => Err(e.clone()),
        }
    }

    /// [`Self::save`]; `slot`: the newest revision to the slot, not to the
    /// journal ([`Self::checkpoint`]).
    fn save_to(&mut self, slot: bool) {
        let entry_store = self.safe_mode_entry_store();
        let store = entry_store.as_ref().unwrap_or(&self.store);
        let saved = if self.storage.revision_files() {
            // Only what is new is written (G1.23).
            let mut files = self
                .ext
                .get_mut::<crate::history_files::RevisionFiles>()
                .map(std::mem::take)
                .unwrap_or_default();
            let saved = crate::history_files::save(
                self.storage.as_mut(),
                &mut files,
                store,
                &self.users,
                persist::SAVE_BUDGET_BYTES,
                slot,
            );
            self.ext.set(files);
            saved
        } else {
            persist::encode_bounded(store, &self.users, persist::SAVE_BUDGET_BYTES)
                .map_err(|e| e.to_string())
                .and_then(|(text, skipped)| {
                    self.storage
                        .save(&text)
                        .map(|()| skipped)
                        .map_err(|e| e.to_string())
                })
        };
        match saved {
            Ok(skipped) => {
                if skipped > 0 && skipped != self.storage_status.revisions_not_saved {
                    log::warn!(
                        "config file kept under {} MiB: the {skipped} oldest revision(s) \
                         were left out",
                        persist::SAVE_BUDGET_BYTES >> 20
                    );
                }
                self.storage_status.revisions_not_saved = skipped;
                self.storage_status.last_error = None;
            }
            Err(e) => {
                log::error!(
                    "revision {} is running but was not saved: {e}",
                    self.store.current_revision()
                );
                self.storage_status.last_error = Some(e);
            }
        }
    }

    /// Journal an action the engine took by itself (Safe Mode undo).
    pub(crate) fn record_automatic(
        &mut self,
        id: &str,
        reason: &str,
        result: &Result<Option<u32>>,
    ) {
        let revision = result.as_ref().ok().copied().flatten();
        let result = result
            .as_ref()
            .map(|rev| json!({ "revision": rev }))
            .map_err(Clone::clone);
        self.record(id, &json!({ "automatic": reason }), &result, revision);
    }

    /// Journal a command and log it (G4.6d); `revision`: the one it created.
    fn record(&mut self, id: &str, params: &Value, result: &Result<Value>, revision: Option<u32>) {
        self.seq = self.seq.saturating_add(1);
        // Passwords and tokens never reach the journal nor the log (G0.3).
        let params = auth::mask_params(id, params);
        // Bounded like the log detail: a 16 MiB parameter must not be kept
        // 1024 times (audit #4).
        self.journal.push(JournalEntry {
            seq: self.seq,
            command: id.to_owned(),
            params: crate::logging::bounded(&params),
            ok: result.is_ok(),
            error: result
                .as_ref()
                .err()
                .map(|e| crate::logging::cut(&e.to_string(), 512)),
        });
        // Trimmed in chunks: one shift of the whole journal per
        // `JOURNAL_SLACK` commands instead of one per command (audit-perf);
        // `journal()` shows the newest `MAX_JOURNAL` either way.
        if self.journal.len() > MAX_JOURNAL.saturating_add(JOURNAL_SLACK) {
            let excess = self.journal.len().saturating_sub(MAX_JOURNAL);
            self.journal.drain(..excess);
        }
        self.log_journal(self.seq, id, &params, result, revision);
    }

    /// Command registry with enabled state, for `list_commands` and menus.
    pub fn list(&self) -> Value {
        cmd::describe(self)
    }

    /// Compact state summary, or one subtree of the candidate by dotted path
    /// (`"interfaces"`, `"routing.bgp"`), so agents never pay for the whole tree.
    pub fn inspect(&self, path: Option<&str>) -> Result<Value> {
        self.permit(Group::Read)
            .map_err(|reason| EngineError::Denied {
                id: "state.inspect".into(),
                reason,
            })?;
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
                "safe_mode": self.safe_mode_summary(),
                "counts": {
                    "interfaces": cand.interfaces.len(),
                    "ip_addresses": cand.ip.addresses.len(),
                    "bgp_instances": cand.routing.bgp.len(),
                    "firewall_rules": cand.ip.firewall.filter.len()
                        + cand.ip.firewall.nat.len()
                        + cand.ip.firewall.mangle.len(),
                },
                "paths": ["system", "interfaces", "interface_lists", "ip", "ip.firewall", "routing", "running", "journal"],
            })),
            Some("journal") => serde_json::to_value(self.journal())
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
                Ok(self.redact(v))
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

    /// Where state outside the revisions is kept (DHCP leases, G4.7c).
    pub(crate) fn storage_mut(&mut self) -> &mut dyn ConfigStorage {
        self.storage.as_mut()
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

    /// The newest journal entries (at most `MAX_JOURNAL`), oldest first.
    pub fn journal(&self) -> &[JournalEntry] {
        let start = self.journal.len().saturating_sub(MAX_JOURNAL);
        self.journal.get(start..).unwrap_or_default()
    }

    pub fn storage_status(&self) -> &StorageStatus {
        &self.storage_status
    }

    pub fn caller(&self) -> &Caller {
        &self.caller
    }

    /// The group of `principal` now, or `None` (not logged in, or the
    /// account was removed or disabled).
    pub fn group_of(&self, principal: &Principal) -> Option<Group> {
        match principal {
            Principal::Local => Some(Group::Full),
            Principal::Anonymous => None,
            Principal::User(name) => self
                .users
                .get(name)
                .filter(|u| !u.disabled)
                .map(|u| u.group),
        }
    }

    /// `v` as the current caller may see it: secrets (TSIG keys, …) are
    /// masked below group `full`, like RouterOS's `sensitive` policy.
    pub(crate) fn redact(&self, v: Value) -> Value {
        if self.permit(Group::Full).is_ok() {
            v
        } else {
            auth::mask_secrets(&v)
        }
    }

    /// Whether the current caller may run something that needs `need`.
    pub(crate) fn permit(&self, need: Group) -> std::result::Result<(), String> {
        let p = &self.caller.principal;
        auth::permit(p, self.group_of(p), need)
    }

    pub fn users(&self) -> &Users {
        &self.users
    }

    /// Replace the accounts and save them (user commands only).
    pub(crate) fn set_users(&mut self, users: Users) {
        self.users = users;
        self.save();
    }

    /// The stored hash of an enabled account, for the login check (which
    /// runs outside the session lock: Argon2 is slow on purpose). `None`
    /// for an unknown or disabled account, or one without a password.
    pub fn password_hash(&self, user: &str) -> Option<String> {
        self.users
            .get(user)
            .filter(|u| !u.disabled)
            .and_then(|u| u.password_hash.clone())
    }

    /// An enabled account that has no password (G0.3b): it logs in with an
    /// empty one, from loopback only.
    pub fn has_no_password(&self, user: &str) -> bool {
        self.users
            .get(user)
            .is_some_and(|u| !u.disabled && u.password_hash.is_none())
    }

    /// Enabled accounts of group `full` without a password. While there is
    /// one, the control channel refuses logins from the network.
    pub fn admins_without_password(&self) -> Vec<String> {
        self.users.admins_without_password()
    }

    /// Start-up only, never a command: with no account at all, create
    /// `admin` (group full) **without a password**, as RouterOS does; with
    /// `reset`, also take `admin`'s password away again (re-enabled, group
    /// full; its sessions end). The operator sets one on the first login
    /// (`user.set`). Returns what was done, `None` when nothing was.
    pub fn bootstrap_admin(&mut self, reset: bool) -> Option<&'static str> {
        let first = self.users.is_empty();
        if !first && !reset {
            return None;
        }
        let mut users = self.users.clone();
        let mut admin = users.get("admin").cloned().unwrap_or_else(|| User {
            name: "admin".into(),
            group: Group::Full,
            password_hash: None,
            disabled: false,
            comment: String::new(),
        });
        admin.group = Group::Full;
        admin.disabled = false;
        admin.password_hash = None;
        if users.get("admin").is_none() && users.len() >= corerouter_model::users::MAX_USERS {
            log::error!("cannot create user 'admin': the user list is full");
            return None;
        }
        users.put(admin);
        self.set_users(users);
        self.logins.end_user("admin");
        Some(if first {
            "first start: created user 'admin' (group full) without a password"
        } else {
            "--reset-admin-password: user 'admin' has no password again"
        })
    }

    /// A login succeeded (control channel): shown by `user.active.list`.
    pub fn login_begin(&mut self, user: &str, via: &str) -> u64 {
        let now = self.now();
        self.logins.begin(user, via, now)
    }

    /// The login `id` was used; `false` when it no longer exists (ended,
    /// or its user was removed or disabled).
    pub fn login_touch(&mut self, id: u64) -> bool {
        let now = self.now();
        self.logins.touch(id, now)
    }

    pub fn login_end(&mut self, id: u64) {
        self.logins.end(id);
    }

    pub(crate) fn logins_end_user(&mut self, user: &str) {
        self.logins.end_user(user);
    }

    /// End `user`'s sessions except the caller's own (a user who changes
    /// their own password stays logged in, as in RouterOS).
    pub(crate) fn logins_end_others(&mut self, user: &str) {
        let me = self.caller.name.clone();
        self.logins.end_user_except(user, &me);
    }

    pub fn logins(&self) -> &[Login] {
        &self.logins.list
    }

    pub fn in_safe_mode(&self) -> bool {
        self.safe_mode.is_active()
    }

    pub(crate) fn safe_mode(&self) -> &SafeMode {
        &self.safe_mode
    }

    pub(crate) fn safe_mode_mut(&mut self) -> &mut SafeMode {
        &mut self.safe_mode
    }

    pub(crate) fn hal_now(&self) -> Option<u64> {
        self.hal.now_unix()
    }
}

/// Default config: one Ethernet interface per discovered (managed) port,
/// with the kernel's MTU, MAC and admin state, applied (a kernel no-op).
fn discovered(hal: &mut dyn Hal) -> Config {
    let mut initial = Config::default();
    match hal.discover_links() {
        Ok(links) => {
            for l in links {
                let mut iface = Interface::new(l.name.clone(), InterfaceKind::Ethernet);
                iface.mtu = l.mtu;
                iface.mac = l.mac.and_then(|m| m.parse().ok());
                // As the kernel has it, so the first apply changes nothing.
                iface.disabled = !l.up;
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
#[allow(clippy::type_complexity)]
fn restore(storage: &mut dyn ConfigStorage) -> (Option<(ConfigStore, Users, Slot, usize)>, Vec<String>) {
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
        match persist::decode_with_users(&text) {
            Ok((store, users)) => return (Some((store, users, slot, text.len())), errors),
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

/// The value of a `Cow` that had to be built, `None` for a borrowed one.
/// The running config as of the last commit, which passed every validator
/// (G0.22): while it is still the running one, a commit validates only what
/// it changed. A config restored, imported or edited another way is not
/// this one, and gets the full validation.
struct ValidRunning(Config);

fn owned<T: Clone>(c: std::borrow::Cow<'_, T>) -> Option<T> {
    match c {
        std::borrow::Cow::Owned(v) => Some(v),
        std::borrow::Cow::Borrowed(_) => None,
    }
}
