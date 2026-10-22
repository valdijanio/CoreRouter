//! `Session`: the single entry point for every front end.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use corerouter_hal::{Hal, VirtualHal};
use corerouter_model::{Config, ConfigStore, Interface, InterfaceKind, User, Users, persist};
use serde::Serialize;
use serde_json::{Value, json};

use crate::auth::{self, Group, Login, Logins, Principal};
use crate::cmd::{self, check_params, unknown_command};
use crate::dhcp_client::DhcpRuntime;
use crate::firewall_dyn::DynamicLists;
use crate::link_watch::LinkWatch;
use crate::neighbors::NeighborTable;
use crate::safe_mode::{Caller, SafeMode};
use crate::storage::{ConfigStorage, MemoryStorage, Slot};
use crate::tasks::Tasks;
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
        // The virtual lab's DHCP clients get leases from a simulated server.
        hal.offer_dhcp_lab_server(Arc::new(corerouter_proto_dhcp::lab::LabServer::default()));
        let (restored, boot_errors) = restore(storage.as_mut());
        let (restored, users) = match restored {
            Some((store, users, slot)) => (Some((store, slot)), users),
            None => (None, Users::default()),
        };
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
            caller: Caller::local(),
            safe_mode: SafeMode::default(),
            neighbors: NeighborTable::default(),
            dynamic_addresses: DynamicLists::default(),
            tasks: Tasks::default(),
            dhcp: DhcpRuntime::default(),
            users,
            logins: Logins::default(),
            lockout_ack: false,
            in_batch: false,
            links: LinkWatch::default(),
        }
    }

    /// Simulator / lab session on the virtual backend (8 ports).
    pub fn virtual_lab() -> Self {
        Self::new(Box::new(VirtualHal::default()))
    }

    /// The one door: UI, CLI, control channel and MCP all call this.
    pub fn execute(&mut self, id: &str, params: &Value) -> Result<Value> {
        self.expire_safe_mode();
        let spec = cmd::find(id).ok_or_else(|| unknown_command(id))?;
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
        if !self.in_batch {
            self.lockout_ack = false;
        }
        if spec.journal {
            self.record(id, params, &result);
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
        let saved_mode = self.mode;
        let snapshot = self.store.candidate().clone();
        if atomic {
            self.mode = CommitMode::Transactional;
        }
        let outer_batch = std::mem::replace(&mut self.in_batch, true);
        let out = self.batch_steps(steps, atomic, saved_mode, snapshot);
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
        let issues = validate_all(self.store.candidate());
        if !issues.is_empty() {
            return Err(EngineError::Validation(issues));
        }
        // The data plane also holds what DHCP clients installed (G4.7).
        let from = self.effective(self.store.running()).into_owned();
        let to = self.effective(self.store.candidate()).into_owned();
        // The lockout check sees the same: a DHCP address can be the one
        // the operator is connected to.
        if lockout {
            let dynamic = self.dynamic_now();
            self.check_lockout(&from, &to, &dynamic, &dynamic)?;
        }
        self.hal
            .apply(&from, &to)
            .map_err(|e| EngineError::Hal(e.to_string()))?;
        let pending = self.safe_mode.is_active();
        let comment = match (pending, comment.is_empty()) {
            (false, _) => comment.to_owned(),
            (true, true) => "[safe mode]".to_owned(),
            (true, false) => format!("{comment} [safe mode]"),
        };
        let revision = self.store.commit(&comment, self.now())?;
        if !pending {
            self.save();
        }
        Ok(revision)
    }

    /// Persist running + history. A failure does not undo the commit (the
    /// data plane already runs it): it is logged and shown by `state.inspect`.
    pub(crate) fn save(&mut self) {
        let saved = persist::encode_with_users(&self.store, &self.users)
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

    /// Journal an action the engine took by itself (Safe Mode undo).
    pub(crate) fn record_automatic(
        &mut self,
        id: &str,
        reason: &str,
        result: &Result<Option<u32>>,
    ) {
        let result = result
            .as_ref()
            .map(|rev| json!({ "revision": rev }))
            .map_err(Clone::clone);
        self.record(id, &json!({ "automatic": reason }), &result);
    }

    fn record(&mut self, id: &str, params: &Value, result: &Result<Value>) {
        self.seq = self.seq.saturating_add(1);
        self.journal.push(JournalEntry {
            seq: self.seq,
            command: id.to_owned(),
            // Passwords and tokens never reach the journal (G0.3).
            params: auth::mask_secrets(params),
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
fn restore(storage: &mut dyn ConfigStorage) -> (Option<(ConfigStore, Users, Slot)>, Vec<String>) {
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
            Ok((store, users)) => return (Some((store, users, slot)), errors),
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
