//! L5 — WinBox-style UI in egui.
//!
//! Thin by rule: panels only *read* engine state (through query commands) and
//! *act* through [`CoreRouterUi::run`], which calls `Session::execute`. No
//! business logic lives here. This crate depends on `egui` only — the window
//! (eframe/winit/wgpu) belongs to `apps/corerouter-gui`.

pub mod backend;
pub mod connect;
/// Saving exported files (the app installs how, G4.5).
pub mod export;
#[doc(hidden)]
pub mod perf;
// Every other `src/*.rs` is a module, and the ones defining `PANEL` are
// panels: `build.rs` lists them, so a new window is just a new file.
include!(concat!(env!("OUT_DIR"), "/ui_modules.rs"));

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use corerouter_engine::Shared;
use egui::{Color32, RichText};
use serde_json::{Value, json};

pub use backend::{Backend, Link, Local, Reply, RequestId};
pub use connect::{ConnectAction, ConnectScreen, Credentials, Failure, NeighborRow, SavedRouter};
pub use neighbors::uptime_text;
pub use prefs::stored_theme;
pub use windows::Win;

/// Seconds between automatic refreshes of the live tables.
const REFRESH_SECS: f64 = 1.0;
/// Repaint this often while replies are outstanding (a remote router).
const PENDING_REPAINT: Duration = Duration::from_millis(50);
const MAX_LOG: usize = 500;
/// Seconds a query, a tool poll or an interface tab's query may go
/// unanswered before it counts as lost (a reply dropped on the way, a
/// reply with no id): the refresh and the polls start again instead of
/// waiting for it forever.
const QUERY_TIMEOUT_SECS: f64 = 30.0;
/// The same for an operator's action and a terminal's call (the control
/// client's own read timeout).
const ACTION_TIMEOUT_SECS: f64 = 120.0;

#[derive(Debug, Clone)]
pub struct LogLine {
    pub ok: bool,
    pub command: String,
    pub message: String,
}

/// One cached query result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Field {
    Summary,
    Interfaces,
    Addresses,
    Routes,
    Vrfs,
    Bgp,
    History,
    Diff,
    /// `engine.list`: which commands the router allows now, and why not.
    Commands,
    /// `server.info`: name and version of the router's daemon.
    Info,
    Neighbors,
    Discovery,
    /// Firewall and interface-list tables (G2.1), only while their window is open.
    Fw(firewall::Feed),
    /// `auth.whoami`: the logged-in user and group (G0.3), top bar.
    Whoami,
    /// A panel's query: (panel, key), see `panel.rs`.
    Panel(&'static str, &'static str),
}

/// Cached query results, refreshed every `REFRESH_SECS` or after an action.
#[derive(Default)]
struct Cache {
    summary: Value,
    interfaces: Vec<Value>,
    addresses: Vec<Value>,
    routes: Vec<Value>,
    vrfs: Vec<Value>,
    bgp: Vec<Value>,
    history: Vec<Value>,
    diff: Vec<Value>,
    commands: Vec<Value>,
    info: Value,
    whoami: Value,
    neighbors: Vec<Value>,
    discovery: Value,
    refreshed_at: Option<f64>,
    /// Newest reply applied per field: an older one arriving late is dropped.
    applied: BTreeMap<Field, RequestId>,
}

/// Text fields of the forms (UI-local state only).
#[derive(Default)]
struct Forms {
    bgp_name: String,
    bgp_asn: String,
    bgp_router_id: String,
    bgp_frr: String,
    identity: String,
    discovery: neighbors::DiscoveryForm,
}

/// Selection and find text of each list window (UI-local state only).
#[derive(Default)]
struct Tables {
    interfaces: table::TableState,
    addresses: table::TableState,
    routes: table::TableState,
    vrfs: table::TableState,
    neighbors: table::TableState,
    fw_filter: table::TableState,
    fw_nat: table::TableState,
    fw_mangle: table::TableState,
    fw_addr: table::TableState,
    if_members: table::TableState,
    if_lists: table::TableState,
}

impl Tables {
    /// Every table with the salt it is drawn with (stored preferences name
    /// tables by salt).
    fn each(&mut self) -> [(&'static str, &mut table::TableState); 10] {
        [
            (interfaces::TABLE, &mut self.interfaces),
            ("addresses", &mut self.addresses),
            (routes::TABLE, &mut self.routes),
            (vrf::TABLE, &mut self.vrfs),
            (firewall::Feed::Filter.salt(), &mut self.fw_filter),
            (firewall::Feed::Nat.salt(), &mut self.fw_nat),
            (firewall::Feed::Mangle.salt(), &mut self.fw_mangle),
            (firewall::Feed::Addr.salt(), &mut self.fw_addr),
            (firewall::Feed::Members.salt(), &mut self.if_members),
            (firewall::Feed::Lists.salt(), &mut self.if_lists),
        ]
    }

    /// Salts of the tables showing comments inline.
    fn inline_comments(&self) -> Vec<&'static str> {
        [
            (interfaces::TABLE, &self.interfaces),
            ("addresses", &self.addresses),
            (routes::TABLE, &self.routes),
            (vrf::TABLE, &self.vrfs),
            (firewall::Feed::Filter.salt(), &self.fw_filter),
            (firewall::Feed::Nat.salt(), &self.fw_nat),
            (firewall::Feed::Mangle.salt(), &self.fw_mangle),
            (firewall::Feed::Addr.salt(), &self.fw_addr),
            (firewall::Feed::Members.salt(), &self.if_members),
            (firewall::Feed::Lists.salt(), &self.if_lists),
        ]
        .into_iter()
        .filter(|(_, t)| t.inline_comments)
        .map(|(salt, _)| salt)
        .collect()
    }
}

/// What a reply is for.
enum Pending {
    Query(Field),
    Action {
        command: String,
        /// Sent again (with `force` or after Safe Mode) if the router
        /// refuses it as a lockout (G2.1b).
        params: Value,
        then: Then,
    },
    /// A tool task poll (not logged: the UI asks it, not the operator).
    Tool(ping::ToolReq),
    /// A call of a terminal window's job.
    Terminal {
        term: u64,
    },
    /// A query of an "Interface <name>" window's tabs (not logged).
    Nic(iface_tabs::NicReq),
}

/// A file the UI wants saved (CSV export): the app writes it (native) or
/// offers it as a download (web). See [`CoreRouterUi::take_exports`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    pub file_name: String,
    pub mime: &'static str,
    pub bytes: Vec<u8>,
}

/// What to do when an action's reply arrives.
pub(crate) enum Then {
    Nothing,
    ShowFrr,
    Dialog {
        id: u64,
        effect: interfaces::Effect,
    },
    Route {
        id: u64,
        effect: routes::Effect,
    },
    Vrf {
        id: u64,
        effect: vrf::Effect,
    },
    /// A tool task started (Tools › Ping).
    Tool(ping::ToolReq),
    Fw {
        id: u64,
        effect: firewall::Effect,
    },
    /// A panel's command: its own value comes back to it (`panel.rs`).
    Panel {
        panel: &'static str,
        then: panel::PanelThen,
    },
    /// The first-login "Set a password" dialog's `user.set` (G0.3b).
    Password,
}

pub struct CoreRouterUi {
    backend: Box<dyn Backend>,
    pending: BTreeMap<RequestId, Pending>,
    /// UI time of the first frame each pending request was seen in.
    sent_at: BTreeMap<RequestId, f64>,
    /// Since when (UI time) a refresh got no answer and the lists may be
    /// out of date; cleared by the next answered query.
    stale: Option<f64>,
    /// Last link state seen, and whether its loss was already logged.
    link: Link,
    link_down_logged: bool,
    open: BTreeSet<Win>,
    log: Vec<LogLine>,
    cache: Cache,
    forms: Forms,
    tables: Tables,
    /// Floating "New …" / "Interface <name>" / "Comment" windows.
    dialogs: Vec<interfaces::DialogWin>,
    /// Live data of the open "Interface <name>" windows' tabs (G1.19).
    nic: BTreeMap<String, iface_tabs::NicView>,
    /// UI time of the last frame (when a tab query's reply is counted).
    nic_clock: f64,
    /// Maximized windows and where they were (UI-local).
    floats: float::Floats,
    next_dialog: u64,
    /// Interfaces to open once an `interface.list` at least this new arrives.
    open_after: Vec<(RequestId, String)>,
    /// Light, dark or the system's (a window preference, see `prefs`).
    theme: egui::ThemePreference,
    /// Languages of the labels and of the explanations (G0.15, `prefs`).
    pub(crate) lang: i18n::Langs,
    /// "New Route" / "Route <dst>" / route "Comment" windows.
    route_dialogs: Vec<routes::RouteDialogWin>,
    /// Routes to open once an `ip.route.list` sent after this id arrives.
    open_route_after: Vec<(RequestId, String)>,
    /// IP › Routes filters, lookup and open ECMP groups (G1.27).
    route_view: routes::View,
    /// "New VRF" / "VRF <name>" / VRF "Comment" windows.
    vrf_dialogs: Vec<vrf::VrfDialogWin>,
    /// VRFs to open once an `ip.vrf.list` sent after this id arrives.
    open_vrf_after: Vec<(RequestId, String)>,
    /// Firewall and interface-list windows (G2.1).
    fw: firewall::State,
    /// The panels' state, in `PANELS` order (`None` while one is at work).
    panels: Vec<Option<Box<dyn panel::PanelState>>>,
    /// What the router can run now (rebuilt when `engine.list`,
    /// `server.info` or the link change); every action asks it.
    can: Arc<avail::Avail>,
    /// Tools › Ping: form, followed tasks and their data (UI-local).
    ping: ping::PingWin,
    /// Tools › MTR (UI-local).
    mtr: mtr::MtrWin,
    /// Files waiting for the app to save.
    exports: Vec<Export>,
    /// "New Terminal" windows.
    terminals: Vec<terminal::TermWin>,
    /// The user the terminals' prompt shows.
    terminal_user: String,
    /// First login without a password: the dialog (G0.3b).
    password_ask: first_login::PasswordAsk,
    /// A change the router refused as a lockout, waiting for the
    /// operator's answer (G2.1b).
    lockout: Option<lockout::Held>,
    /// The side menu's open groups and selection (G0.23).
    menu: menu::MenuState,
}

impl CoreRouterUi {
    /// UI over a session in this process (the virtual lab).
    pub fn new(session: Shared) -> Self {
        Self::with_backend(Box::new(Local::new(session)))
    }

    /// UI over any backend, e.g. a remote router.
    pub fn with_backend(backend: Box<dyn Backend>) -> Self {
        let mut open = BTreeSet::new();
        open.insert(Win::Interfaces);
        let link = backend.link();
        let can = Arc::new(avail::Avail::new(&link, None, &Value::Null));
        Self {
            backend,
            pending: BTreeMap::new(),
            sent_at: BTreeMap::new(),
            stale: None,
            link,
            link_down_logged: false,
            open,
            log: Vec::new(),
            cache: Cache::default(),
            forms: Forms {
                bgp_name: "default".into(),
                ..Forms::default()
            },
            tables: Tables::default(),
            dialogs: Vec::new(),
            nic: BTreeMap::new(),
            nic_clock: 0.0,
            floats: float::Floats::default(),
            next_dialog: 0,
            open_after: Vec::new(),
            theme: egui::ThemePreference::System,
            lang: i18n::Langs::default(),
            route_dialogs: Vec::new(),
            open_route_after: Vec::new(),
            route_view: routes::View::default(),
            vrf_dialogs: Vec::new(),
            open_vrf_after: Vec::new(),
            fw: firewall::State::default(),
            panels: PANELS.iter().map(|p| Some((p.new)())).collect(),
            can,
            ping: ping::PingWin::default(),
            mtr: mtr::MtrWin::default(),
            exports: Vec::new(),
            terminals: Vec::new(),
            terminal_user: "admin".into(),
            password_ask: first_login::PasswordAsk::default(),
            lockout: None,
            menu: menu::MenuState::default(),
        }
    }

    /// The user shown in the terminals' prompt (`[user@identity]`).
    pub fn set_terminal_user(&mut self, user: impl Into<String>) {
        self.terminal_user = user.into();
    }

    pub fn open(&mut self, win: Win) {
        self.open.insert(win);
    }

    pub fn open_all(&mut self) {
        self.open.extend(Win::all());
    }

    pub fn log(&self) -> &[LogLine] {
        &self.log
    }

    /// Files the UI asked to save since the last call (CSV exports).
    pub fn take_exports(&mut self) -> Vec<Export> {
        std::mem::take(&mut self.exports)
    }

    /// Log a line from the app (where an export was saved, or why not).
    pub fn note(&mut self, ok: bool, command: &str, message: String) {
        self.push_log(LogLine {
            ok,
            command: command.to_owned(),
            message,
        });
    }

    pub fn link(&self) -> &Link {
        &self.link
    }

    /// The only way the UI changes anything: send a command to the router.
    /// The outcome is logged (and the tables refreshed) when the reply
    /// arrives, a later frame for a remote router.
    pub fn run(&mut self, id: &str, params: Value) -> RequestId {
        self.run_then(id, params, Then::Nothing)
    }

    /// A command the router cannot run now (see [`Self::can`]) is not sent:
    /// its reason is logged and handed to `then` as the failure, and the id
    /// returned is 0, which no backend ever answers.
    pub(crate) fn run_then(&mut self, id: &str, params: Value, then: Then) -> RequestId {
        if let Err(why) = self.can.check(id) {
            self.push_log(LogLine {
                ok: false,
                command: id.to_owned(),
                message: why.clone(),
            });
            self.then(then, &Err(why));
            return 0;
        }
        let req = self.backend.submit(
            "engine.execute",
            json!({"command": id, "params": params.clone()}),
        );
        self.pending.insert(
            req,
            Pending::Action {
                command: id.to_owned(),
                params,
                then,
            },
        );
        req
    }

    /// What the router can run now: `Ok`, or the reason to grey an action
    /// out with (missing on an older daemon, disabled by the engine, link
    /// not up). The engine decides; the UI keeps no list of its own.
    pub(crate) fn can(&self) -> Arc<avail::Avail> {
        Arc::clone(&self.can)
    }

    fn update_can(&mut self) {
        let loaded =
            self.cache.applied.contains_key(&Field::Commands) && !self.cache.commands.is_empty();
        let commands = loaded.then_some(self.cache.commands.as_slice());
        self.can = Arc::new(avail::Avail::new(&self.link, commands, &self.cache.info));
    }

    /// Actions sent and not answered yet.
    pub fn busy(&self) -> usize {
        self.pending
            .values()
            .filter(|p| matches!(p, Pending::Action { .. }))
            .count()
    }

    fn push_log(&mut self, line: LogLine) {
        self.log.push(line);
        if self.log.len() > MAX_LOG {
            self.log.remove(0);
        }
    }

    /// Apply every reply that has arrived. Never blocks.
    pub fn pump(&mut self) {
        // A local backend answers the queries a reply triggers (a reload)
        // at once; a few rounds settle it within the frame.
        for _ in 0..4 {
            let replies = self.backend.poll();
            if replies.is_empty() {
                break;
            }
            for (id, result) in replies {
                self.on_reply(id, result);
            }
        }
        self.watch_link();
    }

    fn on_reply(&mut self, id: RequestId, result: Result<Value, String>) {
        // Unknown or already answered ids are ignored.
        match self.pending.remove(&id) {
            None => {}
            Some(Pending::Query(field)) => self.on_query(field, id, result),
            Some(Pending::Tool(req)) => self.tool_reply(req, result),
            Some(Pending::Terminal { term }) => self.term_reply(term, id, result),
            Some(Pending::Nic(req)) => self.nic_reply(req, result),
            Some(Pending::Action {
                command,
                params,
                then,
            }) => {
                let message = match &result {
                    Ok(v) => redact::redacted(v).to_string(),
                    Err(e) => e.clone(),
                };
                self.push_log(LogLine {
                    ok: result.is_ok(),
                    command: command.clone(),
                    message,
                });
                self.cache.refreshed_at = None;
                if let Some(then) = self.hold_lockout(command, params, then, &result) {
                    self.then(then, &result);
                }
            }
        }
    }

    fn on_query(&mut self, field: Field, id: RequestId, result: Result<Value, String>) {
        // A failed query keeps the last good data; the link state says why.
        let Ok(value) = result else {
            return;
        };
        self.stale = None;
        if self
            .cache
            .applied
            .get(&field)
            .is_some_and(|&seen| seen > id)
        {
            return;
        }
        self.cache.applied.insert(field, id);
        let arr = |v: Value| match v {
            Value::Array(a) => a,
            _ => Vec::new(),
        };
        match field {
            Field::Summary => self.cache.summary = value,
            Field::Whoami => self.cache.whoami = value,
            Field::Interfaces => {
                self.cache.interfaces = arr(value);
                let (ready, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.open_after)
                    .into_iter()
                    .partition(|(req, _)| *req <= id);
                self.open_after = later;
                for (_, name) in ready {
                    self.open_props(&name);
                }
            }
            Field::Addresses => self.cache.addresses = arr(value),
            Field::Routes => {
                self.route_page_arrived(value);
                let (ready, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.open_route_after)
                    .into_iter()
                    .partition(|(req, _)| *req <= id);
                self.open_route_after = later;
                for (_, route) in ready {
                    self.open_route(&route);
                }
            }
            Field::Vrfs => {
                self.cache.vrfs = arr(value);
                let (ready, later): (Vec<_>, Vec<_>) = std::mem::take(&mut self.open_vrf_after)
                    .into_iter()
                    .partition(|(req, _)| *req <= id);
                self.open_vrf_after = later;
                for (_, name) in ready {
                    self.open_vrf(&name);
                }
            }
            Field::Bgp => self.cache.bgp = arr(value),
            Field::History => self.cache.history = arr(value),
            Field::Diff => self.cache.diff = arr(value),
            Field::Commands => {
                self.cache.commands = arr(value);
                self.update_can();
            }
            Field::Info => {
                self.cache.info = value;
                self.update_can();
            }
            Field::Neighbors => self.cache.neighbors = arr(value),
            Field::Discovery => self.cache.discovery = value,
            Field::Fw(firewall::Feed::Zones) => {
                self.fw_arrived(firewall::Feed::Zones, id, vec![value]);
            }
            Field::Fw(feed) => self.fw_arrived(feed, id, arr(value)),
            Field::Panel(name, key) => {
                self.with_panel(name, |p, app| p.arrived(app, key, id, value));
            }
        }
    }

    /// [`Self::then`] for a held change the operator cancelled.
    pub(crate) fn answer_then(&mut self, then: Then, result: &Result<Value, String>) {
        self.then(then, result);
    }

    fn then(&mut self, then: Then, result: &Result<Value, String>) {
        match then {
            Then::Nothing => {}
            Then::ShowFrr => {
                if let Ok(r) = result {
                    self.forms.bgp_frr = r.get("frr").map(value_text).unwrap_or_default();
                }
            }
            Then::Dialog { id, effect } => self.dialog_reply(id, effect, result),
            Then::Route { id, effect } => self.route_dialog_reply(id, effect, result),
            Then::Vrf { id, effect } => self.vrf_dialog_reply(id, effect, result),
            Then::Fw { id, effect } => self.fw_dialog_reply(id, effect, result),
            Then::Panel { panel, then } => {
                self.with_panel(panel, |p, app| p.reply(app, then, result));
            }
            Then::Tool(req) => self.tool_started(req, result),
            Then::Password => self.password_reply(result),
        }
    }

    /// Log when the router goes away or comes back (once, not per retry).
    fn watch_link(&mut self) {
        let link = self.backend.link();
        if link == self.link {
            return;
        }
        match &link {
            Link::Disconnected { target, reason } if !self.link_down_logged => {
                self.link_down_logged = true;
                let message = if reason.contains(target.as_str()) {
                    reason.clone()
                } else {
                    format!("{target}: {reason}")
                };
                self.push_log(LogLine {
                    ok: false,
                    command: "connection".into(),
                    message,
                });
            }
            Link::Connected { target } => {
                if self.link_down_logged {
                    self.push_log(LogLine {
                        ok: true,
                        command: "connection".into(),
                        message: format!("connected to {target}"),
                    });
                }
                self.link_down_logged = false;
                self.cache.refreshed_at = None;
                // Maybe another daemon now (restarted, upgraded): ask again.
                self.cache.info = Value::Null;
            }
            _ => {}
        }
        self.link = link;
        self.update_can();
    }

    /// Give up on requests that got no answer in time (see
    /// [`QUERY_TIMEOUT_SECS`]): a lost reply must not freeze the refresh,
    /// a Ping or a terminal for good.
    fn expire_pending(&mut self, now: f64) {
        self.stamp_pending(now);
        let late: Vec<(RequestId, f64)> = self
            .pending
            .iter()
            .filter_map(|(id, p)| {
                let limit = match p {
                    Pending::Action { .. } | Pending::Terminal { .. } => ACTION_TIMEOUT_SECS,
                    Pending::Query(_) | Pending::Tool(_) | Pending::Nic(_) => QUERY_TIMEOUT_SECS,
                };
                let sent = self.sent_at.get(id)?;
                (now - sent >= limit).then_some((*id, limit))
            })
            .collect();
        let mut lost_query = false;
        for (id, limit) in late {
            self.sent_at.remove(&id);
            match self.pending.get(&id) {
                Some(Pending::Query(_)) => {
                    self.pending.remove(&id);
                    lost_query = true;
                }
                // The interface window asks again on its own (STALE_SECS).
                Some(Pending::Nic(_)) | None => {
                    self.pending.remove(&id);
                }
                // A lost poll: poll again, the task itself may be fine.
                Some(Pending::Tool(req)) => {
                    let req = *req;
                    self.pending.remove(&id);
                    self.tool_timed_out(req);
                }
                Some(Pending::Action { .. } | Pending::Terminal { .. }) => {
                    let why = format!(
                        "no answer from the router in {limit:.0} s (it may still have \
                         applied it: check before trying again)"
                    );
                    self.on_reply(id, Err(why));
                }
            }
        }
        if lost_query {
            if self.stale.is_none() {
                self.stale = Some(now);
                self.push_log(LogLine {
                    ok: false,
                    command: "refresh".into(),
                    message: format!(
                        "no answer from the router in {QUERY_TIMEOUT_SECS:.0} s: \
                         the lists may be out of date; asking again"
                    ),
                });
            }
            self.cache.refreshed_at = None;
        }
    }

    /// Note when each request still waiting was first seen (end of the
    /// frame that sent it), and forget the answered ones.
    fn stamp_pending(&mut self, now: f64) {
        let pending = &self.pending;
        self.sent_at.retain(|id, _| pending.contains_key(id));
        for id in self.pending.keys() {
            self.sent_at.entry(*id).or_insert(now);
        }
    }

    fn refresh(&mut self, now: f64) {
        // One refresh at a time: a slow router must not pile requests up.
        if self
            .pending
            .values()
            .any(|p| matches!(p, Pending::Query(_)))
        {
            return;
        }
        if self
            .cache
            .refreshed_at
            .is_some_and(|t| now - t < REFRESH_SECS)
        {
            return;
        }
        self.reload();
        self.cache.refreshed_at = Some(now);
    }

    /// Ask for every table again. Returns the id of the `interface.list`
    /// (the other queries of the batch get larger ids).
    fn reload(&mut self) -> RequestId {
        let ask = |me: &mut Self, field: Field, method: &str, params: Value| {
            let id = me.backend.submit(method, params);
            me.pending.insert(id, Pending::Query(field));
            id
        };
        let exec = |command: &str| json!({ "command": command });
        ask(self, Field::Summary, "state.inspect", json!({}));
        let list = ask(
            self,
            Field::Interfaces,
            "engine.execute",
            exec("interface.list"),
        );
        ask(
            self,
            Field::Addresses,
            "engine.execute",
            exec("ip.address.list"),
        );
        let routes = self.route_query();
        ask(self, Field::Routes, "engine.execute", routes);
        ask(self, Field::Vrfs, "engine.execute", exec("ip.vrf.list"));
        ask(
            self,
            Field::Bgp,
            "engine.execute",
            exec("routing.bgp.instance.list"),
        );
        ask(
            self,
            Field::History,
            "engine.execute",
            exec("config.history"),
        );
        ask(self, Field::Diff, "engine.execute", exec("config.diff"));
        ask(self, Field::Commands, "engine.list", Value::Null);
        // An old router has no auth.whoami: no question it cannot answer.
        if !self.old_router() {
            ask(self, Field::Whoami, "auth.whoami", Value::Null);
        }
        if self.cache.info.is_null() {
            ask(self, Field::Info, "server.info", Value::Null);
        }
        let fw_open = self.open.contains(&Win::Firewall) || !self.fw.dialogs.is_empty();
        let lists_open = fw_open || self.open.contains(&Win::InterfaceList);
        for feed in firewall::Feed::ALL {
            let wanted = match feed {
                firewall::Feed::Lists | firewall::Feed::Members => lists_open,
                _ => fw_open,
            };
            if wanted {
                ask(self, Field::Fw(feed), "engine.execute", exec(feed.query()));
            }
        }
        for (panel, q) in self.panel_queries() {
            ask(
                self,
                Field::Panel(panel, q.key),
                "engine.execute",
                json!({"command": q.command, "params": q.params}),
            );
        }
        if self.open.contains(&Win::Neighbors) {
            ask(
                self,
                Field::Neighbors,
                "engine.execute",
                exec("ip.neighbor.list"),
            );
            ask(
                self,
                Field::Discovery,
                "engine.execute",
                exec("ip.neighbor.discovery.get"),
            );
        }
        list
    }

    /// Draw one frame into the root `Ui`.
    pub fn ui(&mut self, ui: &mut egui::Ui) {
        let now = ui.input(|i| i.time);
        // Before any text, so the icons work from the first frame.
        icons::install(ui.ctx());
        self.floats.begin_frame(ui.ctx());
        self.pump();
        self.expire_pending(now);
        self.refresh(now);
        self.tools_tick(ui.ctx(), now);
        self.nic_tick(now);
        self.pump();
        self.first_login_tick();
        let wake = if self.pending.is_empty() {
            Duration::from_secs_f64(REFRESH_SECS)
        } else {
            PENDING_REPAINT
        };
        ui.ctx().request_repaint_after(wake);
        self.sync_theme(ui.ctx());

        egui::Panel::top("top-bar").show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    self.theme_switch(ui);
                    resources::top_bar(self, ui);
                    ui.with_layout(egui::Layout::left_to_right(egui::Align::Center), |ui| {
                        // A narrow window cuts the left part instead of
                        // drawing it over the right one (G4.8a readout).
                        let room = ui.available_rect_before_wrap();
                        ui.set_clip_rect(ui.clip_rect().intersect(room));
                        self.top_bar(ui);
                    });
                });
            });
        });
        egui::Panel::bottom("status-bar").show(ui, |ui| self.status_bar(ui));
        egui::Panel::left("menu")
            .resizable(false)
            .exact_size(200.0)
            .show(ui, |ui| self.menu(ui));
        let area = egui::CentralPanel::default()
            .show(ui, |ui| {
                ui.centered_and_justified(|ui| {
                    ui.label(RichText::new("CoreRouter").size(32.0).weak());
                });
            })
            .response
            .rect;

        let ctx = ui.ctx().clone();
        let mut floats = std::mem::take(&mut self.floats);
        // Windows that size themselves to the work area read it here.
        self.floats.area = Some(area);
        for win in &Win::all() {
            if !self.open.contains(win) {
                continue;
            }
            let mut open = true;
            floats.show(
                &ctx,
                area,
                win_id(*win),
                i18n::tr(self.lang.labels, win.title()),
                &mut open,
                |w| w.default_size(win.default_size()),
                |ui| self.window(*win, ui),
            );
            if win.closes_on_escape()
                && floats
                    .keys(&ctx, win_id(*win), float::Takes::Escape)
                    .is_some()
            {
                open = self.escape(*win);
            }
            if *win == Win::Ping {
                // Enter starts, Esc stops a running ping, else closes.
                match floats.keys(&ctx, win_id(*win), float::Takes::Dialog) {
                    Some(float::Keyed::Enter) => self.ping_start(),
                    Some(float::Keyed::Escape) if !self.ping_stop() => open = false,
                    _ => {}
                }
            }
            if *win == Win::Mtr {
                match floats.keys(&ctx, win_id(*win), float::Takes::Dialog) {
                    Some(float::Keyed::Enter) => self.mtr_start(),
                    Some(float::Keyed::Escape) if !self.mtr_stop() => open = false,
                    _ => {}
                }
            }
            if floats.take_close(win_id(*win)) {
                open = false;
            } else if !open && !floats.close_family(&ctx, win_id(*win)) {
                // A child has edits not applied: the question asks first.
                open = true;
            }
            if !open {
                self.open.remove(win);
                floats.closed(win_id(*win));
                if *win == Win::Ping {
                    self.ping_closed();
                }
                if *win == Win::Mtr {
                    self.mtr_closed();
                }
            }
        }
        self.floats = floats;
        self.dialogs(&ctx, area);
        self.route_dialogs(&ctx, area);
        self.vrf_dialogs(&ctx, area);
        self.fw_dialogs(&ctx, area);
        self.panel_dialogs(&ctx, area);
        self.terminals(&ctx, area);
        self.password_window(&ctx);
        self.lockout_window(&ctx);
        self.floats.end_frame(&ctx);
        self.stamp_pending(now);
    }

    fn link_label(&self, ui: &mut egui::Ui) {
        match &self.link {
            Link::Local => {}
            Link::Connecting { target } => {
                ui.colored_label(ui.visuals().warn_fg_color, format!("connecting… {target}"));
                ui.separator();
            }
            Link::Connected { target } => {
                ui.label(target.as_str());
                ui.separator();
            }
            Link::Disconnected { target, reason } => {
                ui.colored_label(err_color(ui), format!("disconnected: {target}"))
                    .on_hover_text(reason.as_str());
                ui.separator();
            }
        }
    }

    /// Who this window is logged in as (G0.3); nothing for the lab.
    fn user_label(&self, ui: &mut egui::Ui) {
        if matches!(self.link, Link::Local) {
            return;
        }
        let Some(user) = self.cache.whoami.get("user").and_then(Value::as_str) else {
            return;
        };
        let group = self
            .cache
            .whoami
            .get("group")
            .and_then(Value::as_str)
            .unwrap_or("?");
        ui.label(RichText::new(format!("user: {user}")).strong())
            .on_hover_text(format!(
                "Logged in as {user}, group {group}: actions this group may not run are \
                 greyed out"
            ));
        ui.weak(format!("({group})"));
        ui.separator();
    }

    /// A router older than the login (G0.3c), managed after "Connect
    /// anyway": its `server.info` says nothing about `auth`.
    pub fn old_router(&self) -> bool {
        !matches!(self.link, Link::Local) && connect::old_router_info(&self.cache.info)
    }

    /// The commit of the daemon this GUI manages, when it differs from the
    /// GUI's own: a daemon left running after a rebuild (the user tested
    /// fixes against an old daemon). Local sessions are the GUI itself.
    pub fn stale_daemon(&self) -> Option<String> {
        if matches!(self.link, Link::Local) {
            return None;
        }
        let theirs = self.cache.info.get("commit").and_then(Value::as_str)?;
        let ours = corerouter_buildinfo::COMMIT;
        (theirs != ours && theirs != "unknown" && ours != "unknown").then(|| theirs.to_owned())
    }

    /// The top bar's warning when the daemon was built from another commit.
    fn stale_daemon_warning(&self, ui: &mut egui::Ui) {
        let Some(theirs) = self.stale_daemon() else {
            return;
        };
        ui.colored_label(
            ui.visuals().warn_fg_color,
            format!("daemon {theirs} ≠ GUI {}", corerouter_buildinfo::COMMIT),
        )
        .on_hover_text(
            "The router's daemon was built from another commit than this GUI: fixes may be \
             missing on one side. Restart it after building (bash plan/hw-lab.sh daemon in the \
             lab).",
        );
        ui.separator();
    }

    /// The top bar's warning while managing an old router.
    fn old_router_warning(&self, ui: &mut egui::Ui) {
        if !self.old_router() {
            return;
        }
        ui.colored_label(ui.visuals().warn_fg_color, "old router: no login")
            .on_hover_text(format!(
                "{} Until then anyone on its machine can manage it, and what it does not \
                 have yet is greyed out.",
                connect::OLD_ROUTER
            ));
        ui.separator();
    }

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        let s = &self.cache.summary;
        let txt = |k: &str| s.get(k).map(value_text).unwrap_or_default();
        let (identity, backend, mode, revision) = (
            txt("identity"),
            txt("backend"),
            txt("mode"),
            txt("revision"),
        );
        let dirty = s.get("dirty").and_then(Value::as_bool).unwrap_or(false);
        let pending = s
            .get("pending_changes")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let known = !s.is_null();
        let safe_mode = SafeModeView::from_summary(s);
        ui.horizontal(|ui| {
            self.link_label(ui);
            self.user_label(ui);
            self.old_router_warning(ui);
            self.stale_daemon_warning(ui);
            self.no_password_warning(ui);
            // Nothing heard from the router yet: no empty fields.
            if !known {
                return;
            }
            self.safe_mode_button(ui, &safe_mode);
            ui.separator();
            ui.strong(identity);
            ui.separator();
            ui.label(format!("backend: {backend}"));
            ui.separator();
            ui.label(format!("mode: {mode}"));
            ui.separator();
            ui.label(format!("revision {revision}"));
            if dirty {
                ui.separator();
                ui.colored_label(
                    ui.visuals().warn_fg_color,
                    format!("{pending} pending change(s)"),
                );
                let can = self.can();
                if table::action(ui, "Commit", can.check("config.commit")) {
                    self.run("config.commit", json!({"comment": "from GUI"}));
                }
                if table::action(ui, "Discard", can.check("config.discard")) {
                    self.run("config.discard", Value::Null);
                }
            }
        });
    }

    /// WinBox's "Safe Mode" button. Click: enter, or leave keeping the
    /// changes. Right click: timeouts, undo, and ending another client's.
    fn safe_mode_button(&mut self, ui: &mut egui::Ui, v: &SafeModeView) {
        let text = RichText::new(v.label()).strong();
        let button = match v {
            SafeModeView::Off { .. } => egui::Button::new(text),
            SafeModeView::Mine { .. } => {
                egui::Button::new(text.color(Color32::WHITE)).fill(SAFE_MODE_FILL)
            }
            SafeModeView::Theirs { .. } => {
                egui::Button::new(text.color(ui.visuals().warn_fg_color))
            }
        };
        // Theirs: the router answers with who holds it and since when.
        let click = match v {
            SafeModeView::Off { .. } | SafeModeView::Theirs { .. } => "config.safe-mode.enter",
            SafeModeView::Mine { .. } => "config.safe-mode.exit",
        };
        let can = self.can();
        let resp = match can.check(click) {
            Ok(()) => ui.add(button).on_hover_text(v.hover()),
            Err(why) => {
                // Greyed out, without its menu: on a router without Safe
                // Mode (or with the link down) none of its items would work.
                ui.add_enabled(false, egui::Button::new(v.label()))
                    .on_disabled_hover_text(format!("Safe Mode: {why}"));
                return;
            }
        };
        if resp.clicked() {
            self.run(click, json!({}));
        }
        resp.context_menu(|ui| {
            let mut pick = |ui: &mut egui::Ui, label: &str, id: &str, params: Value| {
                if table::action(ui, label, can.check(id)) {
                    self.run(id, params);
                    ui.close();
                }
            };
            match v {
                SafeModeView::Off { .. } | SafeModeView::Mine { .. } => {
                    let verb = if matches!(v, SafeModeView::Off { .. }) {
                        "Enter"
                    } else {
                        "Re-arm"
                    };
                    for (mins, secs) in [(1, 60), (5, 300), (10, 600)] {
                        pick(
                            ui,
                            &format!("{verb} with a {mins} min timeout"),
                            "config.safe-mode.enter",
                            json!({ "timeout_secs": secs }),
                        );
                    }
                    if matches!(v, SafeModeView::Mine { .. }) {
                        ui.separator();
                        pick(
                            ui,
                            "Leave, keep changes",
                            "config.safe-mode.exit",
                            json!({}),
                        );
                        pick(
                            ui,
                            "Leave, undo changes",
                            "config.safe-mode.cancel",
                            json!({}),
                        );
                    }
                }
                SafeModeView::Theirs { .. } => {
                    pick(
                        ui,
                        "Release it (keep their changes)",
                        "config.safe-mode.exit",
                        json!({"force": true}),
                    );
                    pick(
                        ui,
                        "Undo their changes",
                        "config.safe-mode.cancel",
                        json!({"force": true}),
                    );
                }
            }
        });
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        let busy = self.busy();
        let now = ui.input(|i| i.time);
        ui.horizontal(|ui| {
            if let Some(since) = self.stale {
                let tone = chip::AMBER.tone(ui.visuals());
                chip::chip(ui, "stale", tone).on_hover_text(format!(
                    "The router has not answered a refresh for {:.0} s: \
                     the lists show older data",
                    (now - since).max(0.0) + QUERY_TIMEOUT_SECS
                ));
            }
            self.status_text(ui, busy);
        });
    }

    fn status_text(&self, ui: &mut egui::Ui, busy: usize) {
        match self.log.last() {
            _ if busy > 0 => {
                ui.weak(format!("waiting for the router ({busy})…"));
            }
            Some(l) => {
                let color = if l.ok {
                    ui.visuals().text_color()
                } else {
                    ui.visuals().error_fg_color
                };
                ui.colored_label(color, format!("{}: {}", l.command, l.message));
            }
            None => {
                ui.weak("ready");
            }
        }
    }
}

impl CoreRouterUi {
    /// Esc on a list window, one layer at a time: clear the find text,
    /// else the selection, else close. Returns whether it stays open.
    fn escape(&mut self, win: Win) -> bool {
        let table = match win {
            Win::Interfaces => &mut self.tables.interfaces,
            Win::Addresses => &mut self.tables.addresses,
            Win::Routes => &mut self.tables.routes,
            Win::Vrf => &mut self.tables.vrfs,
            Win::Neighbors => &mut self.tables.neighbors,
            Win::Panel(id) => {
                let Some((p, _)) = panel::find(id) else {
                    return false;
                };
                return self
                    .with_panel(p.name, |s, _| s.escape(id))
                    .unwrap_or(false);
            }
            Win::Firewall => match self.fw.tab {
                firewall::Tab::Filter => &mut self.tables.fw_filter,
                firewall::Tab::Nat => &mut self.tables.fw_nat,
                firewall::Tab::Mangle => &mut self.tables.fw_mangle,
                firewall::Tab::Addr => &mut self.tables.fw_addr,
                firewall::Tab::Zones => return false,
                firewall::Tab::Connections => {
                    return self
                        .with_panel(crate::connections::NAME, |s, _| s.escape("fw-connections"))
                        .unwrap_or(false);
                }
            },
            Win::InterfaceList => match self.fw.if_tab {
                firewall::IfTab::Members => &mut self.tables.if_members,
                firewall::IfTab::Lists => &mut self.tables.if_lists,
            },
            _ => return false,
        };
        table.escape()
    }
}

pub(crate) fn win_id(win: Win) -> egui::Id {
    egui::Id::unique(("corerouter-win", win))
}

/// Form text → JSON: integers as numbers, blank as absent, anything else as
/// typed (the engine reports what is wrong with it).
fn form_number(s: &str) -> Value {
    let s = s.trim();
    match s.parse::<u64>() {
        Ok(n) => json!(n),
        Err(_) if s.is_empty() => Value::Null,
        Err(_) => json!(s),
    }
}

fn value_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// 1536 → "1.5 KiB".
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = n as f64;
    let mut unit = "B";
    for u in UNITS {
        unit = u;
        if v < 1024.0 {
            break;
        }
        v /= 1024.0;
    }
    if unit == "B" {
        format!("{n} B")
    } else {
        format!("{v:.1} {unit}")
    }
}

/// Background of the Safe Mode button while this client holds it.
const SAFE_MODE_FILL: Color32 = Color32::from_rgb(190, 40, 40);

/// The `safe_mode` part of the `state.inspect` summary, as the top bar
/// shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SafeModeView {
    Off {
        last: Option<String>,
    },
    Mine {
        entry_revision: u64,
        expires_in: Option<u64>,
    },
    Theirs {
        owner: String,
    },
}

impl SafeModeView {
    fn from_summary(summary: &Value) -> Self {
        let sm = summary.get("safe_mode").unwrap_or(&Value::Null);
        let text = |k: &str| sm.get(k).and_then(Value::as_str).map(str::to_owned);
        if sm.get("active").and_then(Value::as_bool) != Some(true) {
            return Self::Off { last: text("last") };
        }
        if sm.get("yours").and_then(Value::as_bool) == Some(true) {
            Self::Mine {
                entry_revision: sm
                    .get("entry_revision")
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                expires_in: sm.get("expires_in").and_then(Value::as_u64),
            }
        } else {
            Self::Theirs {
                owner: text("owner").unwrap_or_default(),
            }
        }
    }

    fn label(&self) -> String {
        match self {
            Self::Off { .. } => "Safe Mode".into(),
            Self::Mine {
                expires_in: Some(t),
                ..
            } => format!("Safe Mode {}:{:02}", t / 60, t % 60),
            Self::Mine { .. } => "Safe Mode".into(),
            Self::Theirs { owner } => format!("Safe Mode: {owner}"),
        }
    }

    fn hover(&self) -> String {
        match self {
            Self::Off { last } => {
                let mut s = "Enter Safe Mode: changes are undone if this connection drops.                              Right click for a timeout."
                    .to_owned();
                if let Some(last) = last {
                    s.push_str("\nLast Safe Mode: ");
                    s.push_str(last);
                }
                s
            }
            Self::Mine {
                entry_revision,
                expires_in,
            } => {
                let deadline = expires_in
                    .map(|t| format!(", or in {t} s without confirmation"))
                    .unwrap_or_default();
                format!(
                    "Safe Mode is on: changes since revision {entry_revision} are undone if                      this connection drops{deadline}.\nClick to keep them; right click to undo."
                )
            }
            Self::Theirs { owner } => format!(
                "Safe Mode is held by {owner}: their changes are undone if they disconnect. \
                 Right click to release or undo it."
            ),
        }
    }
}

fn err_color(ui: &egui::Ui) -> Color32 {
    ui.visuals().error_fg_color
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_engine::{Session, lock, shared};
    use std::cell::RefCell;
    use std::rc::Rc;

    #[test]
    fn every_window_renders_headless() {
        let mut app = CoreRouterUi::new(shared(Session::virtual_lab()));
        app.open_all();
        app.new_terminal();
        let ctx = egui::Context::default();
        for _ in 0..3 {
            ctx.run_ui(egui::RawInput::default(), |ui| app.ui(ui))
                .drop_without_applying_deltas();
        }
        assert_eq!(app.open.len(), Win::all().len());
    }

    #[test]
    fn safe_mode_button_follows_the_summary() {
        let session = shared(Session::virtual_lab());
        lock(&session).tick(1_000);
        let mut app = CoreRouterUi::new(session.clone());
        let ctx = egui::Context::default();
        let frame = |app: &mut CoreRouterUi| {
            ctx.run_ui(egui::RawInput::default(), |ui| app.ui(ui))
                .drop_without_applying_deltas();
        };
        frame(&mut app);
        let view = || SafeModeView::from_summary(&app.cache.summary);
        assert_eq!(view(), SafeModeView::Off { last: None });

        app.run("config.safe-mode.enter", json!({"timeout_secs": 300}));
        app.pump();
        frame(&mut app);
        let view = SafeModeView::from_summary(&app.cache.summary);
        assert_eq!(
            view,
            SafeModeView::Mine {
                entry_revision: 0,
                expires_in: Some(300)
            }
        );
        assert_eq!(view.label(), "Safe Mode 5:00");

        app.run("config.safe-mode.cancel", json!({}));
        app.pump();
        frame(&mut app);
        let SafeModeView::Off { last: Some(last) } = SafeModeView::from_summary(&app.cache.summary)
        else {
            panic!("{}", app.cache.summary);
        };
        assert!(last.contains("cancelled"), "{last}");

        // Held by another connection.
        let theirs =
            json!({"safe_mode": {"active": true, "yours": false, "owner": "tcp 10.0.0.9:4000"}});
        let v = SafeModeView::from_summary(&theirs);
        assert_eq!(v.label(), "Safe Mode: tcp 10.0.0.9:4000");
        assert!(SafeModeView::from_summary(&Value::Null) == SafeModeView::Off { last: None });
    }

    #[test]
    fn run_logs_errors() {
        let mut app = CoreRouterUi::new(shared(Session::virtual_lab()));
        app.run("ip.address.add", json!({"address": "x"}));
        assert_eq!(app.busy(), 1);
        app.pump();
        assert_eq!(app.busy(), 0);
        assert!(!app.log()[0].ok);
        app.run("system.identity.set", json!({"name": "r1"}));
        app.pump();
        assert!(app.log()[1].ok);
    }

    /// A router that answers only when the test says so, in any order.
    #[derive(Default)]
    struct Wire {
        next: RequestId,
        sent: Vec<(RequestId, String, Value)>,
        replies: Vec<Reply>,
        link: Option<Link>,
    }

    struct Scripted(Rc<RefCell<Wire>>);

    impl Backend for Scripted {
        fn submit(&mut self, method: &str, params: Value) -> RequestId {
            let mut w = self.0.borrow_mut();
            w.next += 1;
            let id = w.next;
            w.sent.push((id, method.to_owned(), params));
            id
        }

        fn poll(&mut self) -> Vec<Reply> {
            std::mem::take(&mut self.0.borrow_mut().replies)
        }

        fn link(&self) -> Link {
            self.0.borrow().link.clone().unwrap_or(Link::Connecting {
                target: "r1:7979".into(),
            })
        }
    }

    impl Wire {
        /// Id of the last request for `command` (or method).
        fn last(&self, what: &str) -> RequestId {
            self.sent
                .iter()
                .rev()
                .find(|(_, m, p)| m == what || p["command"] == what)
                .map(|(id, ..)| *id)
                .unwrap()
        }
    }

    fn frame(ctx: &egui::Context, app: &mut CoreRouterUi, t: f64) -> Vec<String> {
        let raw = egui::RawInput {
            time: Some(t),
            ..Default::default()
        };
        let mut out = ctx.run_ui(raw, |ui| app.ui(ui));
        out.textures_delta.clear();
        let mut texts = Vec::new();
        fn walk(s: &egui::Shape, out: &mut Vec<String>) {
            match s {
                egui::Shape::Text(t) => out.push(t.galley.text().to_owned()),
                egui::Shape::Vec(v) => v.iter().for_each(|s| walk(s, out)),
                _ => {}
            }
        }
        for c in &out.shapes {
            walk(&c.shape, &mut texts);
        }
        texts
    }

    #[test]
    fn late_replies_and_a_lost_link_do_not_break_the_ui() {
        let wire = Rc::new(RefCell::new(Wire::default()));
        let mut app = CoreRouterUi::with_backend(Box::new(Scripted(wire.clone())));
        app.open_all();
        let ctx = egui::Context::default();
        let texts = frame(&ctx, &mut app, 0.0);
        assert!(
            texts.iter().any(|t| t == "connecting… r1:7979"),
            "{texts:?}"
        );
        let old = wire.borrow().last("interface.list");

        // Nothing answered yet: no second refresh piles up.
        frame(&ctx, &mut app, 5.0);
        assert_eq!(wire.borrow().last("interface.list"), old);

        // A forced reload, answered before the first one.
        let new = app.reload();
        let row = |n: &str| json!({"name": n, "type": "ether"});
        {
            let mut w = wire.borrow_mut();
            w.link = Some(Link::Connected {
                target: "r1:7979".into(),
            });
            w.replies
                .push((new, Ok(json!([row("ether1"), row("ether2")]))));
            w.replies.push((old, Ok(json!([row("ether1")]))));
            // Garbage and unknown ids are ignored.
            w.replies.push((9999, Ok(json!("??"))));
            let all: Vec<RequestId> = w.sent.iter().map(|(id, ..)| *id).collect();
            for id in all.into_iter().filter(|id| *id != new && *id != old) {
                w.replies.push((id, Ok(json!({"not": "a list"}))));
            }
        }
        let texts = frame(&ctx, &mut app, 6.0);
        assert_eq!(app.cache.interfaces.len(), 2, "late reply did not win");
        assert!(texts.iter().any(|t| t == "r1:7979"));

        // An action in flight when the link drops gets an error, once.
        let req = app.run("interface.set", json!({"name": "ether1", "disabled": true}));
        assert_eq!(app.busy(), 1);
        {
            let mut w = wire.borrow_mut();
            w.link = Some(Link::Disconnected {
                target: "r1:7979".into(),
                reason: "connection reset".into(),
            });
            w.replies.push((req, Err("connection lost".into())));
            w.replies.push((req, Ok(json!({}))));
        }
        let texts = frame(&ctx, &mut app, 7.0);
        assert_eq!(app.busy(), 0);
        let failed: Vec<_> = app.log().iter().filter(|l| !l.ok).collect();
        assert_eq!(failed.len(), 2, "{:?}", app.log());
        assert!(failed.iter().any(|l| l.command == "connection"));
        assert!(
            texts.iter().any(|t| t == "disconnected: r1:7979"),
            "{texts:?}"
        );
        assert_eq!(app.cache.interfaces.len(), 2, "keeps the last data");
        for t in 8..20 {
            frame(&ctx, &mut app, f64::from(t));
        }
    }

    /// Drives the real UI with synthetic pointer/keyboard events, the way
    /// an operator would, and finds widgets by the text they paint.
    struct Harness {
        ctx: egui::Context,
        app: CoreRouterUi,
        session: Shared,
        time: f64,
        screen: egui::Vec2,
        shapes: Vec<egui::epaint::ClippedShape>,
    }

    const CTRL: egui::Modifiers = egui::Modifiers {
        alt: false,
        ctrl: true,
        shift: false,
        mac_cmd: false,
        command: true,
    };

    impl Harness {
        fn new() -> Self {
            Self::with_session(Session::virtual_lab())
        }

        fn with_session(session: Session) -> Self {
            let session = shared(session);
            let mut h = Self {
                ctx: egui::Context::default(),
                app: CoreRouterUi::new(session.clone()),
                session,
                time: 0.0,
                screen: egui::vec2(1400.0, 900.0),
                shapes: Vec::new(),
            };
            for _ in 0..3 {
                h.idle();
            }
            h
        }

        fn frame(&mut self, mut events: Vec<egui::Event>, modifiers: egui::Modifiers) {
            events.insert(0, egui::Event::ModifiersChanged(modifiers));
            let raw = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, self.screen)),
                time: Some(self.time),
                events,
                ..Default::default()
            };
            self.time += 0.02;
            let app = &mut self.app;
            let mut out = self.ctx.run_ui(raw, |ui| app.ui(ui));
            out.textures_delta.clear();
            self.shapes = out.shapes;
        }

        fn idle(&mut self) {
            self.frame(Vec::new(), egui::Modifiers::NONE);
        }

        fn click_with(&mut self, pos: egui::Pos2, button: egui::PointerButton, m: egui::Modifiers) {
            self.frame(vec![egui::Event::PointerMoved(pos)], m);
            let ev = |pressed| egui::Event::PointerButton {
                pos,
                button,
                pressed,
                modifiers: m,
            };
            self.frame(vec![ev(true), ev(false)], m);
            self.idle();
            self.idle();
        }

        fn click(&mut self, pos: egui::Pos2) {
            self.click_with(pos, egui::PointerButton::Primary, egui::Modifiers::NONE);
        }

        fn right_click(&mut self, pos: egui::Pos2) {
            self.click_with(pos, egui::PointerButton::Secondary, egui::Modifiers::NONE);
        }

        fn hover(&mut self, pos: egui::Pos2) {
            self.frame(vec![egui::Event::PointerMoved(pos)], egui::Modifiers::NONE);
            self.idle();
            self.idle();
        }

        fn key(&mut self, key: egui::Key, modifiers: egui::Modifiers) {
            let ev = egui::Event::Key {
                key,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers,
            };
            self.frame(vec![ev], modifiers);
            self.idle();
        }

        fn type_text(&mut self, text: &str) {
            self.frame(vec![egui::Event::Text(text.into())], egui::Modifiers::NONE);
            self.idle();
        }

        /// A point of a row of the Interfaces table, on its name (the left
        /// end, which a dialog open over the list leaves uncovered).
        fn row(&self, name: &str) -> egui::Pos2 {
            let r = self
                .ctx
                .read_response(table::row_id(interfaces::TABLE, name))
                .unwrap_or_else(|| panic!("row {name} not drawn"))
                .rect;
            egui::pos2(r.left() + 40.0, r.center().y)
        }

        fn tool(&self, icon: table::Icon) -> egui::Pos2 {
            self.ctx
                .read_response(table::tool_id(interfaces::TABLE, icon))
                .map(|r| r.rect.center())
                .unwrap_or_else(|| panic!("no tool {icon:?}"))
        }

        /// Centre of the topmost text painted exactly as `needle`.
        fn find_text(&self, needle: &str) -> Option<egui::Pos2> {
            fn find(shape: &egui::Shape, needle: &str, out: &mut Option<egui::Pos2>) {
                match shape {
                    egui::Shape::Text(t) if t.galley.text() == needle => {
                        *out = Some(t.visual_bounding_rect().center());
                    }
                    egui::Shape::Vec(v) => v.iter().for_each(|s| find(s, needle, out)),
                    _ => {}
                }
            }
            let mut out = None;
            for s in &self.shapes {
                find(&s.shape, needle, &mut out);
            }
            out
        }

        fn text(&self, needle: &str) -> egui::Pos2 {
            self.find_text(needle)
                .unwrap_or_else(|| panic!("no text {needle:?} on screen"))
        }

        fn has_text(&self, needle: &str) -> bool {
            self.find_text(needle).is_some()
        }

        /// Colour of the topmost text painted exactly as `needle`.
        fn text_color(&self, needle: &str) -> egui::Color32 {
            fn find(shape: &egui::Shape, needle: &str, out: &mut Option<egui::Color32>) {
                match shape {
                    egui::Shape::Text(t) if t.galley.text() == needle => {
                        *out = t.galley.job.sections.first().map(|s| s.format.color);
                    }
                    egui::Shape::Vec(v) => v.iter().for_each(|s| find(s, needle, out)),
                    _ => {}
                }
            }
            let mut out = None;
            for s in &self.shapes {
                find(&s.shape, needle, &mut out);
            }
            out.unwrap_or_else(|| panic!("no text {needle:?} on screen"))
        }

        fn selected(&self) -> Vec<String> {
            let rows: Vec<table::Row> = self
                .app
                .cache
                .interfaces
                .iter()
                .map(|r| table::Row {
                    key: r.get("name").map(value_text).unwrap_or_default(),
                    cells: Vec::new(),
                    dimmed: false,
                    section: false,
                    tint: None,
                })
                .collect();
            self.app.tables.interfaces.selection(&rows).into_vec()
        }

        /// The interface as the engine has it (not the UI cache).
        fn iface(&self, name: &str) -> Option<Value> {
            let list = lock(&self.session).execute("interface.list", &Value::Null);
            list.ok()?
                .as_array()?
                .iter()
                .find(|i| i["name"] == name)
                .cloned()
        }

        /// Where a floating window is now.
        fn win_rect(&self, id: egui::Id) -> egui::Rect {
            self.ctx
                .memory(|m| m.area_rect(id))
                .unwrap_or_else(|| panic!("window {id:?} not shown"))
        }

        fn title_bar(&self, id: egui::Id) -> float::Places {
            float::Bar::new(&self.ctx).places(self.win_rect(id))
        }

        fn drag(&mut self, from: egui::Pos2, by: egui::Vec2) {
            let none = egui::Modifiers::NONE;
            let ev = |pos, pressed| egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed,
                modifiers: none,
            };
            self.frame(vec![egui::Event::PointerMoved(from)], none);
            self.frame(vec![ev(from, true)], none);
            for step in 1..=5 {
                let at = from + by * (step as f32 / 5.0);
                self.frame(vec![egui::Event::PointerMoved(at)], none);
            }
            self.frame(vec![ev(from + by, false)], none);
            self.idle();
        }

        fn log_ids(&self) -> Vec<&str> {
            self.app.log().iter().map(|l| l.command.as_str()).collect()
        }
    }

    // Every `src/tests/*.rs` (build.rs): a feature's UI tests go in a file of
    // their own there, not at the end of this module.
    include!(concat!(env!("OUT_DIR"), "/ui_tests.rs"));

    #[test]
    fn rows_select_with_click_ctrl_shift_and_keys() {
        let mut h = Harness::new();
        h.click(h.row("ether2"));
        assert_eq!(h.selected(), ["ether2"]);
        h.click_with(h.row("ether4"), egui::PointerButton::Primary, CTRL);
        assert_eq!(h.selected(), ["ether2", "ether4"]);
        let shift = egui::Modifiers::SHIFT;
        h.click_with(h.row("ether6"), egui::PointerButton::Primary, shift);
        assert_eq!(
            h.selected(),
            ["ether4", "ether5", "ether6"],
            "range from anchor"
        );
        h.key(egui::Key::ArrowDown, egui::Modifiers::NONE);
        assert_eq!(h.selected(), ["ether7"]);

        // Empty space under the last row clears the selection …
        h.click(h.row("ether8") + egui::vec2(0.0, 60.0));
        assert!(h.selected().is_empty());
        // … and leaves the table focused for Ctrl+A.
        h.key(egui::Key::A, CTRL);
        assert_eq!(h.selected().len(), 8);

        // Delete runs interface.remove per row; the engine refuses physical
        // ports, so nothing changes and every refusal is logged.
        h.key(egui::Key::Delete, egui::Modifiers::NONE);
        let removes: Vec<_> = h
            .app
            .log()
            .iter()
            .filter(|l| l.command == "interface.remove")
            .collect();
        assert_eq!(removes.len(), 8);
        assert!(removes.iter().all(|l| !l.ok));
        assert!(h.iface("ether1").is_some());

        // Ctrl+D disables the selection, Ctrl+E enables it again.
        h.click(h.row("ether3"));
        h.key(egui::Key::D, CTRL);
        assert_eq!(h.iface("ether3").unwrap()["disabled"], true);
        h.key(egui::Key::E, CTRL);
        assert_eq!(h.iface("ether3").unwrap()["disabled"], false);
    }

    #[test]
    fn row_menu_adds_vlan_on_the_clicked_row() {
        let mut h = Harness::new();
        h.click(h.row("ether1"));
        // Right click on a row that is not selected makes it the selection.
        h.right_click(h.row("ether3"));
        assert_eq!(h.selected(), ["ether3"]);
        h.click(h.text("Add VLAN on ether3"));
        assert!(
            matches!(h.app.dialogs.as_slice(), [d] if matches!(&d.dialog,
                interfaces::Dialog::NewVlan { parent, .. } if parent == "ether3")),
            "dialog opened with the parent filled in"
        );
        h.click(h.text("vlan100"));
        h.type_text("vlan30");
        h.click(h.text("1..4094"));
        h.type_text("30");
        h.click(h.text("OK"));
        assert!(h.app.dialogs.is_empty(), "OK closes on success");
        assert_eq!(h.log_ids().last(), Some(&"interface.vlan.add"));
        let vlan = h.iface("vlan30").expect("vlan created");
        assert_eq!(
            (&vlan["parent"], &vlan["vlan_id"]),
            (&json!("ether3"), &json!(30))
        );

        // A failing OK keeps the dialog and shows the engine's error.
        h.right_click(h.row("ether3"));
        h.click(h.text("Add VLAN on ether3"));
        h.click(h.text("OK"));
        let d = h.app.dialogs.first().expect("still open");
        assert!(
            d.status
                .error
                .as_deref()
                .is_some_and(|e| e.contains("required")),
            "{:?}",
            d.status.error
        );
    }

    #[test]
    fn double_click_opens_properties() {
        let mut h = Harness::new();
        let at = h.row("ether2");
        h.click(at);
        h.click(at);
        assert!(h.has_text("Interface <ether2>"));
        match h.app.dialogs.first_mut().map(|d| &mut d.dialog) {
            Some(interfaces::Dialog::Props(p)) => {
                p.comment = "uplink".into();
                p.mtu = "9000".into();
            }
            _ => panic!("properties window not open"),
        }
        h.click(h.text("Apply"));
        let e2 = h.iface("ether2").unwrap();
        assert_eq!(
            (&e2["comment"], &e2["mtu"]),
            (&json!("uplink"), &json!(9000))
        );
        assert_eq!(h.app.dialogs.len(), 1, "Apply keeps the window");

        h.click(h.text("Disable"));
        assert_eq!(h.iface("ether2").unwrap()["disabled"], true);
        // Remove on a physical port is refused and explained in place.
        h.click(h.text("Remove"));
        assert!(
            h.app
                .dialogs
                .first()
                .is_some_and(|d| d.status.error.is_some())
        );
        h.click(h.text("OK"));
        assert!(h.app.dialogs.is_empty());
    }

    #[test]
    fn toolbar_and_empty_space_menu() {
        let mut h = Harness::new();
        let below = h.row("ether8") + egui::vec2(0.0, 60.0);
        h.right_click(below);
        h.click(h.text("Select All"));
        assert_eq!(h.selected().len(), 8);

        // "+" ▸ Bridge, then Apply turns "New Bridge" into its own window.
        h.click(h.tool(table::Icon::Add));
        h.click(h.text("Bridge"));
        h.click(h.text("bridge1"));
        h.type_text("br0");
        h.click(h.text("Apply"));
        assert!(h.iface("br0").is_some());
        assert!(h.has_text("Interface <br0>"));
        assert!(!h.has_text("New Bridge Interface"));

        // Row menu ▸ Add to Bridge ▸ br0.
        h.right_click(h.row("ether5"));
        h.hover(h.text("Add to Bridge"));
        h.click(h.text("br0"));
        assert_eq!(h.iface("ether5").unwrap()["bridge"], "br0");

        // Empty space ▸ Add ▸ Loopback.
        h.right_click(below);
        h.hover(h.text("Add"));
        h.click(h.text("Loopback"));
        assert!(h.has_text("New Loopback Interface"));
        h.click(h.text("Cancel"));
        assert!(!h.has_text("New Loopback Interface"));
        assert!(h.app.log().iter().all(|l| l.ok), "{:?}", h.app.log());
    }

    impl Harness {
        /// Only the Routes window, over a lab whose ether1 is 10.0.0.2/24.
        fn routes() -> Self {
            let mut h = Self::new();
            lock(&h.session)
                .execute(
                    "ip.address.add",
                    &json!({"address": "10.0.0.2/24", "interface": "ether1"}),
                )
                .unwrap();
            h.app.open.clear();
            h.app.open(Win::Routes);
            h.app.cache.refreshed_at = None;
            h.idle();
            h.idle();
            h
        }

        fn route_row(&self, key: &str) -> egui::Pos2 {
            self.ctx
                .read_response(table::row_id(routes::TABLE, key))
                .unwrap_or_else(|| panic!("route row {key} not drawn"))
                .rect
                .center()
        }

        fn route_tool(&self, icon: table::Icon) -> egui::Response {
            self.ctx
                .read_response(table::tool_id(routes::TABLE, icon))
                .unwrap_or_else(|| panic!("no route tool {icon:?}"))
        }

        /// The static route `id` as the engine lists it.
        fn route(&self, id: &str) -> Option<Value> {
            let list = lock(&self.session).execute("ip.route.list", &Value::Null);
            list.ok()?
                .as_array()?
                .iter()
                .find(|r| r["id"] == id)
                .cloned()
        }
    }

    #[test]
    fn new_route_dialog_adds_a_default_route() {
        let mut h = Harness::routes();
        assert!(
            h.has_text("10.0.0.0/24") && h.has_text("connected"),
            "connected route listed"
        );
        h.click(h.route_tool(table::Icon::Add).rect.center());
        assert!(h.has_text("New Route"));
        h.click(h.text("0.0.0.0/0"));
        h.type_text("0.0.0.0/0");
        h.click(h.text("10.0.0.1 or ether1"));
        h.type_text("10.0.0.1");
        h.click(h.text("OK"));
        assert!(h.app.route_dialogs.is_empty(), "OK closes on success");
        let r = h.route("*1").expect("route created");
        assert_eq!((&r["flags"], &r["distance"]), (&json!("AS"), &json!(1)));
        // G1.27: the gateway in parts, the state as a chip.
        assert!(
            h.has_text("10.0.0.1") && h.has_text("reachable") && h.has_text("ether1"),
            "gateway column"
        );
        assert!(h.has_text("active"));

        // A bad gateway keeps the dialog open with the engine's reason.
        h.click(h.route_tool(table::Icon::Add).rect.center());
        h.click(h.text("0.0.0.0/0"));
        h.type_text("10.9.0.0/16");
        h.click(h.text("10.0.0.1 or ether1"));
        h.type_text("172.16.0.1");
        h.click(h.text("OK"));
        let d = h.app.route_dialogs.first().expect("still open");
        assert!(
            d.status
                .error
                .as_deref()
                .is_some_and(|e| e.contains("not in any connected network")),
            "{:?}",
            d.status.error
        );
        h.click(h.text("Cancel"));
        assert!(h.app.route_dialogs.is_empty());
    }

    #[test]
    fn route_properties_toolbar_and_menu() {
        let mut h = Harness::routes();
        lock(&h.session)
            .execute(
                "ip.route.add",
                &json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1"}),
            )
            .unwrap();
        h.app.cache.refreshed_at = None;
        h.idle();
        h.idle(); // rows are laid out where the new list puts them

        // Connected routes cannot be removed, disabled or commented.
        let connected = "connected main 10.0.0.0/24 ether1";
        h.click(h.route_row(connected));
        assert!(!h.route_tool(table::Icon::Remove).sense.senses_click());
        h.key(egui::Key::Delete, egui::Modifiers::NONE);
        assert!(!h.log_ids().contains(&"ip.route.remove"));

        // Double click: "Route <0.0.0.0/0>"; Apply sends only what changed.
        // (Wait first, or the click above would make it a triple click.)
        h.time += 1.0;
        h.idle();
        let at = h.route_row("*1");
        h.click(at);
        h.click(at);
        assert!(h.has_text("Route <0.0.0.0/0>"));
        match h.app.route_dialogs.first_mut().map(|d| &mut d.dialog) {
            Some(routes::RouteDialog::Props { form, .. }) => {
                form.distance = "5".into();
                form.comment = "isp".into();
            }
            _ => panic!("route window not open"),
        }
        h.click(h.text("Apply"));
        let r = h.route("*1").unwrap();
        assert_eq!((&r["distance"], &r["comment"]), (&json!(5), &json!("isp")));
        h.click(h.text("Disable"));
        assert_eq!(h.route("*1").unwrap()["flags"], "XS");
        h.click(h.text("OK"));
        assert!(h.app.route_dialogs.is_empty());

        // Ctrl+E on the selected row enables it again.
        h.click(h.route_row("*1"));
        h.key(egui::Key::E, CTRL);
        assert_eq!(h.route("*1").unwrap()["flags"], "AS");

        // Right click ▸ Remove.
        h.right_click(h.route_row("*1"));
        h.click(h.text("Remove"));
        assert!(h.route("*1").is_none());
        assert!(h.app.log().iter().all(|l| l.ok), "{:?}", h.app.log());
    }

    impl Harness {
        /// Only the VRF window, over a lab where ether5 is a port of br0
        /// and VRF blue holds ether4 and ether6.
        fn vrfs() -> Self {
            let mut h = Self::new();
            for (cmd, p) in [
                ("interface.bridge.add", json!({"name": "br0"})),
                (
                    "interface.bridge.port.add",
                    json!({"bridge": "br0", "interface": "ether5"}),
                ),
                (
                    "ip.vrf.add",
                    json!({"name": "blue", "interfaces": ["ether4", "ether6"]}),
                ),
            ] {
                lock(&h.session).execute(cmd, &p).unwrap();
            }
            h.app.open.clear();
            h.app.open(Win::Vrf);
            h.app.cache.refreshed_at = None;
            h.idle();
            h.idle();
            h
        }

        fn vrf_row(&self, name: &str) -> egui::Pos2 {
            self.ctx
                .read_response(table::row_id(vrf::TABLE, name))
                .unwrap_or_else(|| panic!("vrf row {name} not drawn"))
                .rect
                .center()
        }

        fn vrf_tool(&self, icon: table::Icon) -> egui::Pos2 {
            self.ctx
                .read_response(table::tool_id(vrf::TABLE, icon))
                .map(|r| r.rect.center())
                .unwrap_or_else(|| panic!("no vrf tool {icon:?}"))
        }

        /// The VRF as the engine lists it.
        fn vrf(&self, name: &str) -> Option<Value> {
            let list = lock(&self.session).execute("ip.vrf.list", &Value::Null);
            list.ok()?
                .as_array()?
                .iter()
                .find(|v| v["name"] == name)
                .cloned()
        }
    }

    #[test]
    fn new_vrf_dialog_offers_only_free_interfaces() {
        let mut h = Harness::vrfs();
        assert!(h.has_text("ether4, ether6"), "members column");
        h.click(h.vrf_tool(table::Icon::Add));
        assert!(h.has_text("New VRF"));
        // Bridge ports and members of another VRF are not offered; a
        // bridge is (it joins with its ports).
        for taken in ["ether4", "ether5", "ether6"] {
            assert!(!h.has_text(taken), "{taken} offered");
        }
        // The whole list fits, so what is missing is left out, not scrolled away.
        for free in ["br0", "ether1", "ether2", "ether3", "ether7", "ether8"] {
            assert!(h.has_text(free), "{free} not offered");
        }

        h.click(h.text("vrf1"));
        h.type_text("red");
        h.click(h.text("ether2"));
        h.click(h.text("br0"));
        // Apply turns "New VRF" into "VRF <red>".
        h.click(h.text("Apply"));
        let red = h.vrf("red").expect("vrf created");
        assert_eq!(red["interfaces"], json!(["br0", "ether2"]));
        assert_eq!(red["table"], json!(1001), "next free table after blue");
        assert!(h.has_text("VRF <red>"), "properties opened");
        assert!(!h.has_text("New VRF"));
        assert!(h.has_text("br0, ether2"));

        // A name the engine refuses keeps the dialog open with its reason.
        h.click(h.vrf_tool(table::Icon::Add));
        h.click(h.text("vrf1"));
        h.type_text("main");
        h.click(h.text("OK"));
        let d = h
            .app
            .vrf_dialogs
            .iter()
            .find(|d| matches!(d.dialog, vrf::VrfDialog::New(_)))
            .expect("still open");
        assert!(
            d.status
                .error
                .as_deref()
                .is_some_and(|e| e.contains("main")),
            "{:?}",
            d.status.error
        );
        h.click(h.text("Cancel"));
        assert_eq!(h.app.vrf_dialogs.len(), 1, "only VRF <red> left");
    }

    /// The virtual lab on a "kernel" without CONFIG_NET_VRF (G1.14).
    struct NoVrf(corerouter_hal::VirtualHal);

    impl corerouter_hal::Hal for NoVrf {
        fn describe(&self) -> String {
            "virtual lab without vrf".into()
        }
        fn discover_links(
            &mut self,
        ) -> Result<Vec<corerouter_hal::LinkInfo>, corerouter_hal::HalError> {
            self.0.discover_links()
        }
        fn apply(
            &mut self,
            from: &corerouter_model::Config,
            to: &corerouter_model::Config,
        ) -> Result<(), corerouter_hal::HalError> {
            self.0.apply(from, to)
        }
        fn poll(&mut self) -> Vec<corerouter_hal::LinkState> {
            self.0.poll()
        }
        fn now_unix(&self) -> Option<u64> {
            None
        }
        fn features(&self) -> corerouter_hal::Features {
            corerouter_hal::Features { vrf: false }
        }
    }

    #[test]
    fn vrf_add_is_greyed_out_with_the_reason_without_kernel_vrf() {
        let session = Session::new(Box::new(NoVrf(corerouter_hal::VirtualHal::new(4))));
        let mut h = Harness::with_session(session);
        h.app.open.clear();
        h.app.open(Win::Vrf);
        h.idle();
        h.idle();
        let add = h
            .ctx
            .read_response(table::tool_id(vrf::TABLE, table::Icon::Add))
            .expect("add tool drawn");
        assert!(!add.sense.senses_click(), "+ is greyed out");
        h.click(add.rect.center());
        assert!(h.app.vrf_dialogs.is_empty());

        // The tooltip gives the engine's reason (after a click, egui shows
        // it only once the pointer has left and come back).
        h.hover(add.rect.center() + egui::vec2(200.0, 200.0));
        h.hover(add.rect.center());
        h.time += 1.0;
        h.idle();
        h.idle();
        let tip = format!("Add: {}", corerouter_hal::NO_VRF);
        assert!(h.has_text(&tip), "tooltip");

        // So does "Add VRF…" in the empty-space menu: clicking does nothing.
        h.right_click(add.rect.center() + egui::vec2(0.0, 120.0));
        h.click(h.text("Add VRF…"));
        assert!(h.app.vrf_dialogs.is_empty());
        assert!(!h.log_ids().contains(&"ip.vrf.add"));
    }

    #[test]
    fn vrf_properties_toolbar_and_menu() {
        let mut h = Harness::vrfs();

        // Double click: "VRF <blue>"; Apply sends the new member list.
        let at = h.vrf_row("blue");
        h.click(at);
        h.click(at);
        assert!(h.has_text("VRF <blue>"));
        assert!(h.has_text("1000"), "routing table shown");
        h.click(h.text("ether4")); // out
        h.click(h.text("ether3")); // in
        h.click(h.text("Apply"));
        assert_eq!(
            h.vrf("blue").unwrap()["interfaces"],
            json!(["ether3", "ether6"])
        );
        assert_eq!(h.iface("ether4").unwrap()["vrf"], Value::Null);
        h.click(h.text("Disable"));
        assert_eq!(h.vrf("blue").unwrap()["disabled"], true);
        h.click(h.text("OK"));
        assert!(h.app.vrf_dialogs.is_empty());

        // Ctrl+E on the selected row enables it again.
        h.time += 1.0;
        h.idle();
        h.click(h.vrf_row("blue"));
        h.key(egui::Key::E, CTRL);
        assert_eq!(h.vrf("blue").unwrap()["disabled"], false);

        // Toolbar comment.
        h.click(h.vrf_tool(table::Icon::Comment));
        assert!(h.has_text("Comment for VRF <blue>"));
        match h.app.vrf_dialogs.first_mut().map(|d| &mut d.dialog) {
            Some(vrf::VrfDialog::Comment { text, .. }) => *text = "customer A".into(),
            _ => panic!("comment window not open"),
        }
        h.click(h.text("OK"));
        assert_eq!(h.vrf("blue").unwrap()["comment"], "customer A");

        // Remove is refused while the VRF has an address: logged, kept.
        let addr = lock(&h.session)
            .execute(
                "ip.address.add",
                &json!({"address": "10.9.0.1/24", "interface": "blue"}),
            )
            .unwrap();
        h.right_click(h.vrf_row("blue"));
        h.click(h.text("Remove"));
        assert!(h.vrf("blue").is_some());
        let last = h.app.log().last().unwrap();
        assert!(
            !last.ok && last.message.contains("ip.address.remove"),
            "{last:?}"
        );

        // Without it, Delete removes the VRF and frees its members.
        lock(&h.session)
            .execute("ip.address.remove", &json!({"id": addr["id"]}))
            .unwrap();
        h.click(h.vrf_row("blue"));
        h.key(egui::Key::Delete, egui::Modifiers::NONE);
        assert!(h.vrf("blue").is_none());
        assert_eq!(h.iface("ether6").unwrap()["vrf"], Value::Null);
    }

    /// Same rectangle, give or take egui's pixel rounding.
    fn same_rect(a: egui::Rect, b: egui::Rect) -> bool {
        (a.min - b.min).length() < 1.5 && (a.max - b.max).length() < 1.5
    }

    #[test]
    fn maximize_fills_the_work_area_and_restore_puts_it_back() {
        let mut h = Harness::new();
        let id = win_id(Win::Interfaces);
        // Somewhere of its own first, so "back" is not the default place.
        h.drag(h.title_bar(id).strip.center(), egui::vec2(40.0, 30.0));
        let before = h.win_rect(id);
        let area = h.app.floats.area.unwrap();
        assert!(!same_rect(before, area));

        h.click(h.title_bar(id).button.center());
        assert!(h.app.floats.is_maximized(id));
        assert!(
            same_rect(h.win_rect(id), area),
            "{:?} vs {area:?}",
            h.win_rect(id)
        );
        // Not over the top bar, the side menu or the status bar.
        assert!(area.min.x >= 170.0 && area.min.y > 0.0 && area.max.y < 900.0);

        h.click(h.title_bar(id).button.center());
        assert!(!h.app.floats.is_maximized(id));
        h.idle();
        assert!(
            same_rect(h.win_rect(id), before),
            "{:?} vs {before:?}",
            h.win_rect(id)
        );
    }

    #[test]
    fn double_click_on_the_title_toggles_without_collapsing() {
        let mut h = Harness::new();
        let id = win_id(Win::Interfaces);
        let before = h.win_rect(id);
        let at = h.title_bar(id).strip.center();
        h.click(at);
        h.click(at);
        assert!(h.app.floats.is_maximized(id));
        assert!(same_rect(h.win_rect(id), h.app.floats.area.unwrap()));
        assert!(h.has_text("ether1"), "body still shown: not collapsed");

        // A pause, or the next click would make a triple click.
        h.time += 1.0;
        let at = h.title_bar(id).strip.center();
        h.click(at);
        h.click(at);
        h.idle();
        assert!(!h.app.floats.is_maximized(id));
        assert!(same_rect(h.win_rect(id), before));
        assert!(h.has_text("ether1"));
    }

    #[test]
    fn title_menu_maximizes_and_restores() {
        let mut h = Harness::new();
        let id = win_id(Win::Interfaces);
        h.right_click(h.title_bar(id).strip.center());
        h.click(h.text("Maximize"));
        assert!(h.app.floats.is_maximized(id));
        h.right_click(h.title_bar(id).strip.center());
        h.click(h.text("Restore"));
        assert!(!h.app.floats.is_maximized(id));
    }

    #[test]
    fn a_maximized_window_follows_the_app_window() {
        let mut h = Harness::new();
        let id = win_id(Win::Interfaces);
        h.click(h.title_bar(id).button.center());
        let big = h.app.floats.area.unwrap();
        h.screen = egui::vec2(1100.0, 700.0);
        h.idle();
        h.idle();
        let small = h.app.floats.area.unwrap();
        assert!(small.width() < big.width() && small.height() < big.height());
        assert!(
            same_rect(h.win_rect(id), small),
            "{:?} vs {small:?}",
            h.win_rect(id)
        );
        h.screen = egui::vec2(1600.0, 1000.0);
        h.idle();
        h.idle();
        assert!(same_rect(h.win_rect(id), h.app.floats.area.unwrap()));
    }

    #[test]
    fn the_title_still_drags_and_collapses() {
        let mut h = Harness::new();
        let id = win_id(Win::Interfaces);
        let before = h.win_rect(id);
        h.drag(h.title_bar(id).strip.center(), egui::vec2(60.0, 40.0));
        let moved = h.win_rect(id);
        assert!(
            (moved.min - before.min - egui::vec2(60.0, 40.0)).length() < 1.5,
            "{before:?} → {moved:?}"
        );

        // Collapsed, maximized and restored: expanding gives the old size.
        h.click(h.title_bar(id).collapse.center());
        for _ in 0..10 {
            h.idle();
        }
        assert!(
            h.win_rect(id).height() < 60.0,
            "collapsed: {:?}",
            h.win_rect(id)
        );
        h.click(h.title_bar(id).button.center());
        assert!(h.app.floats.is_maximized(id));
        h.click(h.title_bar(id).button.center());
        h.click(h.title_bar(id).collapse.center());
        for _ in 0..10 {
            h.idle();
        }
        assert!(
            same_rect(h.win_rect(id), moved),
            "{:?} vs {moved:?}",
            h.win_rect(id)
        );
    }

    #[test]
    fn properties_window_maximizes_too() {
        let mut h = Harness::new();
        let at = h.row("ether2");
        h.click(at);
        h.click(at);
        let id = match h.app.dialogs.first() {
            Some(d) => interfaces::dialog_id(d.id),
            None => panic!("properties window not open"),
        };
        let before = h.win_rect(id);
        h.click(h.title_bar(id).button.center());
        assert!(
            same_rect(h.win_rect(id), h.app.floats.area.unwrap()),
            "{:?}",
            h.win_rect(id)
        );
        h.click(h.title_bar(id).button.center());
        h.idle();
        assert!(
            same_rect(h.win_rect(id), before),
            "{:?} vs {before:?}",
            h.win_rect(id)
        );
        // Closing forgets it.
        h.click(h.text("OK"));
        assert!(h.app.dialogs.is_empty());
        assert!(!h.app.floats.is_maximized(id));
    }

    #[test]
    fn inline_comments_draw_a_band_that_belongs_to_the_item() {
        let mut h = Harness::new();
        lock(&h.session)
            .execute(
                "interface.set",
                &json!({"name": "ether2", "comment": "uplink to the core"}),
            )
            .unwrap();
        h.app.cache.refreshed_at = None;
        h.idle();
        h.idle();
        // Column mode: header "Comment", text on the row's own line.
        assert!(h.has_text("Comment"));
        let (note, name) = (h.text("uplink to the core"), h.text("ether2"));
        assert!((note.y - name.y).abs() < 4.0, "{note:?} {name:?}");

        // Row menu ▸ Inline Comments: the column goes, the band comes.
        h.right_click(h.row("ether1"));
        h.click(h.text("Inline Comments"));
        assert!(h.app.tables.interfaces.inline_comments);
        assert!(!h.has_text("Comment"), "column hidden");
        let (note, name) = (h.text("uplink to the core"), h.text("ether2"));
        assert!(note.y < name.y - 5.0, "band above: {note:?} {name:?}");
        assert!(h.app.prefs().contains("interfaces"));

        // A click on the band selects its item …
        h.click(note);
        assert_eq!(h.selected(), ["ether2"]);
        // … Shift extends from it, and arrows step over bands.
        h.click_with(
            h.row("ether4"),
            egui::PointerButton::Primary,
            egui::Modifiers::SHIFT,
        );
        assert_eq!(h.selected(), ["ether2", "ether3", "ether4"]);
        h.key(egui::Key::ArrowDown, egui::Modifiers::NONE);
        assert_eq!(h.selected(), ["ether5"]);

        // … double click on the band edits the comment, on the row opens it.
        let note = h.text("uplink to the core");
        h.time += 1.0;
        h.click(note);
        h.click(note);
        assert!(h.has_text("Comment for Interface <ether2>"));
        assert!(!h.has_text("Interface <ether2>"));
        h.click(h.text("Cancel"));

        // The band's menu acts on the item.
        h.right_click(h.text("uplink to the core"));
        assert_eq!(h.selected(), ["ether2"]);
        h.click(h.text("Disable"));
        assert_eq!(h.iface("ether2").unwrap()["disabled"], true);

        // Find matches the comment text with the column hidden.
        h.click(h.text("Find"));
        h.type_text("CORE");
        assert!(h.has_text("ether2"));
        assert!(!h.has_text("ether1"));

        // Empty-space menu turns it off again.
        h.right_click(h.row("ether2") + egui::vec2(0.0, 80.0));
        h.click(h.text("Inline Comments"));
        assert!(!h.app.tables.interfaces.inline_comments);
        assert!(h.has_text("Comment"));
    }

    #[test]
    fn comments_are_blue_when_enabled_and_grey_when_disabled() {
        let mut h = Harness::new();
        {
            let mut s = lock(&h.session);
            s.execute(
                "interface.set",
                &json!({"name": "ether4", "comment": "queimou"}),
            )
            .unwrap();
            s.execute(
                "interface.set",
                &json!({"name": "ether5", "comment": "reserva", "disabled": true}),
            )
            .unwrap();
        }
        h.app.cache.refreshed_at = None;
        h.idle();
        h.idle();
        let blue = |c: egui::Color32| c.b() > c.r() + 40 && c.b() > c.g();
        let grey = |c: egui::Color32| c.r() == c.g() && c.g() == c.b();
        for inline in [false, true] {
            h.app.tables.interfaces.inline_comments = inline;
            for theme in [egui::Theme::Light, egui::Theme::Dark] {
                h.ctx.set_theme(theme);
                h.idle();
                h.idle();
                let v = h.ctx.global_style().visuals.clone();
                let on = h.text_color("queimou");
                let off = h.text_color("reserva");
                let why = format!("inline={inline} {theme:?}: {on:?} {off:?}");
                assert_eq!(on, table::comment_style(&v, false, false).ink, "{why}");
                assert_eq!(off, table::comment_style(&v, true, false).ink, "{why}");
                assert!(blue(on) && grey(off), "{why}");
                // The grey still reads on the table's background.
                let bg = v.panel_fill;
                let gap = (i32::from(off.r()) - i32::from(bg.r())).abs();
                assert!(gap > 60, "{why} on {bg:?}");

                // A selected item's comment takes the selection's text colour.
                h.click(h.row("ether5"));
                assert_eq!(h.text_color("reserva"), v.selection.stroke.color, "{why}");
                h.click(h.row("ether5") + egui::vec2(0.0, 200.0));
                assert!(h.selected().is_empty());
            }
        }
    }

    #[test]
    fn theme_switch_changes_and_remembers_the_theme() {
        let mut h = Harness::new();
        let at = |h: &Harness, p| {
            h.ctx
                .read_response(prefs::theme_id(p))
                .map(|r| r.rect.center())
                .unwrap()
        };
        h.click(at(&h, egui::ThemePreference::Light));
        assert_eq!(h.ctx.theme(), egui::Theme::Light);
        assert!(!h.ctx.global_style().visuals.dark_mode);
        assert!(h.app.prefs().contains(r#""theme":"light""#));
        h.click(at(&h, egui::ThemePreference::Dark));
        assert_eq!(h.ctx.theme(), egui::Theme::Dark);
        h.click(at(&h, egui::ThemePreference::System));
        assert_eq!(
            h.ctx.options(|o| o.theme_preference),
            egui::ThemePreference::System
        );

        // Stored preferences apply on the first frame.
        let mut g = Harness::new();
        g.app
            .apply_prefs(r#"{"theme":"light","inline_comments":["interfaces"]}"#);
        g.idle();
        assert_eq!(g.ctx.theme(), egui::Theme::Light);
        assert!(g.app.tables.interfaces.inline_comments);
    }

    /// A daemon that may be older than this GUI: answers at once, from its
    /// own command list, and refuses what it does not have like a real one.
    struct Daemon {
        commands: Vec<Value>,
        summary: Value,
        link: Link,
        /// Actions it was asked to run (queries left out).
        executed: Vec<String>,
        replies: Vec<Reply>,
        next: RequestId,
    }

    struct Fake(Rc<RefCell<Daemon>>);

    impl Backend for Fake {
        fn submit(&mut self, method: &str, params: Value) -> RequestId {
            let mut d = self.0.borrow_mut();
            d.next += 1;
            let command = params["command"].as_str().unwrap_or_default().to_owned();
            let known = d.commands.iter().any(|c| c["id"] == command);
            let reply = match method {
                "state.inspect" => Ok(d.summary.clone()),
                "engine.list" => Ok(Value::Array(d.commands.clone())),
                "server.info" => Ok(json!({"name": "corerouter", "version": "0.0.9"})),
                "engine.execute" if command == "interface.list" => {
                    Ok(json!([{"name": "ether1", "type": "ether", "disabled": true}]))
                }
                "engine.execute"
                    if command.ends_with(".list")
                        || command.ends_with(".history")
                        || command == "config.diff"
                        || command == "ip.route.page"
                        || command == crate::graphs::QUERY
                        || command == crate::resources::CHECK =>
                {
                    Ok(json!([]))
                }
                "engine.execute" if !known => Err(format!("unknown command '{command}'")),
                // The interface window's tab queries (G1.19).
                "engine.execute"
                    if [iface_tabs::MONITOR, iface_tabs::HARDWARE, iface_tabs::STATS]
                        .contains(&command.as_str()) =>
                {
                    Ok(json!({"available": false, "reason": "fake daemon"}))
                }
                "engine.execute" => {
                    d.executed.push(command);
                    Ok(json!({}))
                }
                _ => Err("unknown method".into()),
            };
            let id = d.next;
            d.replies.push((id, reply));
            id
        }

        fn poll(&mut self) -> Vec<Reply> {
            std::mem::take(&mut self.0.borrow_mut().replies)
        }

        fn link(&self) -> Link {
            self.0.borrow().link.clone()
        }
    }

    fn command(id: &str) -> Value {
        json!({"id": id, "enabled": true, "disabledReason": null})
    }

    impl Harness {
        /// The UI over a fake daemon with these commands; dirty, so Commit
        /// and Discard are shown.
        fn daemon(commands: Vec<Value>) -> (Self, Rc<RefCell<Daemon>>) {
            let d = Rc::new(RefCell::new(Daemon {
                commands,
                summary: json!({"identity": "old", "mode": "transactional", "revision": 3,
                    "dirty": true, "pending_changes": 1, "safe_mode": {"active": false}}),
                link: Link::Connected {
                    target: "r1:7979".into(),
                },
                executed: Vec::new(),
                replies: Vec::new(),
                next: 0,
            }));
            let session = shared(Session::virtual_lab());
            let mut h = Self {
                ctx: egui::Context::default(),
                app: CoreRouterUi::with_backend(Box::new(Fake(d.clone()))),
                session,
                time: 0.0,
                screen: egui::vec2(1400.0, 900.0),
                shapes: Vec::new(),
            };
            for _ in 0..3 {
                h.idle();
            }
            (h, d)
        }

        /// The tooltip of what is drawn at `at`, as text on screen.
        fn tooltip_at(&mut self, at: egui::Pos2) {
            self.hover(at + egui::vec2(300.0, 300.0));
            self.hover(at);
            self.time += 1.0;
            self.idle();
            self.idle();
        }

        fn has_text_containing(&self, needle: &str) -> bool {
            fn find(shape: &egui::Shape, needle: &str) -> bool {
                match shape {
                    egui::Shape::Text(t) => t.galley.text().contains(needle),
                    egui::Shape::Vec(v) => v.iter().any(|s| find(s, needle)),
                    _ => false,
                }
            }
            self.shapes.iter().any(|s| find(&s.shape, needle))
        }
    }

    /// Everything the GUI knows except Safe Mode (a daemon from before G1.4).
    fn before_safe_mode() -> Vec<Value> {
        corerouter_engine::cmd::all()
            .filter(|c| !c.id.starts_with("config.safe-mode."))
            .map(|c| command(c.id))
            .collect()
    }

    #[test]
    fn safe_mode_is_greyed_out_on_a_daemon_without_it() {
        let (mut h, d) = Harness::daemon(before_safe_mode());
        let at = h.text("Safe Mode");
        h.click(at);
        h.right_click(at);
        assert!(d.borrow().executed.is_empty(), "{:?}", d.borrow().executed);
        assert!(
            !h.app
                .log()
                .iter()
                .any(|l| l.command.starts_with("config.safe-mode")),
            "{:?}",
            h.app.log()
        );
        assert!(!h.has_text("Enter with a 1 min timeout"), "no menu");
        h.tooltip_at(at);
        assert!(
            h.has_text_containing(
                "Safe Mode: this router (corerouter 0.0.9) has no config.safe-mode.enter"
            ),
            "tooltip"
        );
        assert!(h.has_text_containing("older than this GUI"));
        assert!(h.has_text_containing("update or restart it"));

        // Commit is there and works.
        h.click(h.text("Commit"));
        assert_eq!(d.borrow().executed, ["config.commit"]);
    }

    #[test]
    fn a_daemon_built_from_another_commit_is_flagged_in_the_top_bar() {
        let (mut h, _) = Harness::daemon(before_safe_mode());
        let ours = corerouter_buildinfo::COMMIT;
        h.app.cache.info = json!({"name": "corerouter", "version": "0.1.0", "auth": "required", "commit": "abc1234"});
        h.idle();
        if ours == "unknown" {
            // Built outside git: nothing to compare.
            assert_eq!(h.app.stale_daemon(), None);
            return;
        }
        assert_eq!(h.app.stale_daemon().as_deref(), Some("abc1234"));
        assert!(h.has_text(&format!("daemon abc1234 ≠ GUI {ours}")));
        // Same commit: no warning.
        h.app.cache.info =
            json!({"name": "corerouter", "version": "0.1.0", "auth": "required", "commit": ours});
        h.idle();
        assert_eq!(h.app.stale_daemon(), None);
        // The lab is the GUI itself.
        let mut lab = Harness::new();
        lab.idle();
        assert_eq!(lab.app.stale_daemon(), None);
    }

    #[test]
    fn an_old_router_without_login_is_flagged_in_the_top_bar() {
        // The fake daemon is 0.0.9: its server.info says nothing about auth.
        let (mut h, _) = Harness::daemon(before_safe_mode());
        assert!(h.app.old_router());
        let at = h.text("old router: no login");
        h.tooltip_at(at);
        assert!(h.has_text_containing("Update and restart corerouter-daemon"));
        // A router of this version says "auth": no warning.
        h.app.cache.info = json!({"name": "corerouter", "version": "0.1.0", "auth": "required"});
        h.idle();
        assert!(!h.app.old_router());
        assert!(!h.has_text("old router: no login"));
        // Nor in the lab, which has no login at all.
        let mut lab = Harness::new();
        lab.idle();
        assert!(!lab.app.old_router());
        assert!(!lab.has_text("old router: no login"));
    }

    #[test]
    fn engine_reason_greys_out_commit_and_safe_mode() {
        let mut list = before_safe_mode();
        for c in &mut list {
            if c["id"] == "config.commit" {
                *c = json!({"id": "config.commit", "enabled": false,
                    "disabledReason": "no pending changes"});
            }
        }
        list.push(json!({"id": "config.safe-mode.enter", "enabled": false,
            "disabledReason": "held by the maintenance window"}));
        let (mut h, d) = Harness::daemon(list);
        let commit = h.text("Commit");
        h.click(commit);
        h.click(h.text("Safe Mode"));
        assert!(d.borrow().executed.is_empty(), "{:?}", d.borrow().executed);
        h.tooltip_at(commit);
        assert!(h.has_text("no pending changes"), "engine's reason");
        h.tooltip_at(h.text("Safe Mode"));
        assert!(h.has_text("Safe Mode: held by the maintenance window"));
        // Discard is allowed and goes out.
        h.click(h.text("Discard"));
        assert_eq!(d.borrow().executed, ["config.discard"]);
    }

    #[test]
    fn a_lost_link_greys_out_actions_and_keys_send_nothing() {
        let (mut h, d) = Harness::daemon(before_safe_mode());
        // The interface row, selected while the router is there.
        h.click(h.row("ether1"));
        d.borrow_mut().link = Link::Disconnected {
            target: "r1:7979".into(),
            reason: "connection reset".into(),
        };
        h.idle();
        let enable = h.tool(table::Icon::Enable);
        h.click(enable);
        h.click(h.text("Commit"));
        h.click(h.row("ether1"));
        h.key(egui::Key::E, CTRL);
        h.key(egui::Key::Delete, egui::Modifiers::NONE);
        assert!(d.borrow().executed.is_empty(), "{:?}", d.borrow().executed);
        // A key on an unavailable action says why in the status bar.
        let last = h.app.log().last().unwrap();
        assert_eq!(
            (last.ok, last.message.as_str()),
            (false, "disconnected: r1:7979")
        );
        h.tooltip_at(enable);
        assert!(h.has_text("Enable: disconnected: r1:7979"), "tooltip");
        h.tooltip_at(h.text("Safe Mode"));
        assert!(h.has_text("Safe Mode: disconnected: r1:7979"));

        // Back: everything works again.
        d.borrow_mut().link = Link::Connected {
            target: "r1:7979".into(),
        };
        h.idle();
        h.click(h.row("ether1"));
        h.key(egui::Key::E, CTRL);
        assert_eq!(d.borrow().executed, ["interface.set"]);
    }

    #[test]
    fn a_missing_command_greys_out_its_toolbar_button_and_menu_item() {
        let list: Vec<Value> = before_safe_mode()
            .into_iter()
            .filter(|c| c["id"] != "interface.set")
            .collect();
        let (mut h, d) = Harness::daemon(list);
        h.click(h.row("ether1"));
        let enable = h.tool(table::Icon::Enable);
        h.click(enable);
        h.key(egui::Key::E, CTRL);
        h.right_click(h.row("ether1"));
        h.click(h.text("Enable"));
        assert!(d.borrow().executed.is_empty(), "{:?}", d.borrow().executed);
        h.key(egui::Key::Escape, egui::Modifiers::NONE);
        h.tooltip_at(enable);
        assert!(
            h.has_text_containing("Enable: this router (corerouter 0.0.9) has no interface.set"),
            "tooltip"
        );
    }

    #[test]
    fn dialog_ok_is_greyed_and_enter_sends_nothing_without_the_command() {
        let list: Vec<Value> = before_safe_mode()
            .into_iter()
            .filter(|c| c["id"] != "interface.set")
            .collect();
        let (mut h, d) = Harness::daemon(list);
        let at = h.row("ether1");
        h.click(at);
        h.click(at);
        let win = match h.app.dialogs.first() {
            Some(w) => interfaces::dialog_id(w.id),
            None => panic!("properties window not open"),
        };
        let mtu = h
            .ctx
            .read_response(dialog::field_id(win, "mtu"))
            .expect("mtu field")
            .rect
            .center();
        h.click(mtu);
        h.key(egui::Key::A, CTRL);
        h.type_text("9000");
        h.key(egui::Key::Enter, egui::Modifiers::NONE);
        h.key(egui::Key::Enter, CTRL);
        h.click(h.text("OK"));
        h.click(h.text("Apply"));
        h.click(h.text("Enable"));
        assert!(d.borrow().executed.is_empty(), "{:?}", d.borrow().executed);
        assert_eq!(h.app.dialogs.len(), 1, "still open, edits kept");
        h.tooltip_at(h.text("OK"));
        assert!(h.has_text_containing("has no interface.set"), "OK tooltip");

        // What the router has still works from the same window.
        h.click(h.text("Remove"));
        assert_eq!(d.borrow().executed, ["interface.remove"]);
        // Esc still closes it.
        h.key(egui::Key::Escape, egui::Modifiers::NONE);
        assert!(h.app.dialogs.is_empty());
    }

    #[test]
    fn bytes_are_human() {
        assert_eq!(human_bytes(10), "10 B");
        assert_eq!(human_bytes(1536), "1.5 KiB");
    }

    impl Harness {
        /// Every place `needle` is painted, top first.
        fn all_text(&self, needle: &str) -> Vec<egui::Pos2> {
            fn find(shape: &egui::Shape, needle: &str, out: &mut Vec<egui::Pos2>) {
                match shape {
                    egui::Shape::Text(t) if t.galley.text() == needle => {
                        out.push(t.visual_bounding_rect().center());
                    }
                    egui::Shape::Vec(v) => v.iter().for_each(|s| find(s, needle, out)),
                    _ => {}
                }
            }
            let mut out = Vec::new();
            for s in &self.shapes {
                find(&s.shape, needle, &mut out);
            }
            out.sort_by(|a, b| a.y.total_cmp(&b.y));
            out
        }

        /// Click the tab `label` of the open "Interface <name>" window.
        fn tab(&mut self, label: &str) {
            let at = *self
                .all_text(label)
                .first()
                .unwrap_or_else(|| panic!("no tab {label:?}"));
            self.click(at);
        }

        /// Idle `secs` of UI time (the tabs refresh once a second).
        fn wait(&mut self, secs: f64) {
            let until = self.time + secs;
            while self.time < until {
                self.idle();
            }
        }
    }

    #[test]
    fn interface_window_tabs() {
        let mut h = Harness::new();
        lock(&h.session).tick(1_000);
        h.app.open_props("ether1");
        h.wait(0.2);
        // General: the editable fields plus MACs and L2 MTU from the NIC.
        for t in ["General", "Status", "Hardware", "Traffic", "Statistics"] {
            assert!(h.has_text(t), "tab {t}");
        }
        assert!(h.has_text("Factory MAC"));
        assert!(h.has_text("02:00:00:00:00:01"));
        assert!(h.has_text("L2 MTU"));
        assert!(h.has_text("9216"));

        h.tab("Status");
        assert!(h.has_text("link-ok"));
        assert!(h.has_text("1Gbps"));
        assert!(h.has_text("done"));
        assert!(h.has_text("up since before watching began (0s ago)"));
        assert!(h.has_text("not since watching began (0s ago)"));
        assert!(
            h.has_text("10baseT/Half, 10baseT/Full, 100baseT/Half, 100baseT/Full, 1000baseT/Full")
        );
        assert!(
            !h.has_text("Factory MAC"),
            "General's fields are on their own tab"
        );

        h.tab("Hardware");
        assert!(h.has_text("CoreRouter"));
        assert!(h.has_text("Virtual NIC"));
        assert!(h.has_text("corerouter-virt"));
        assert!(h.has_text("not supported"), "the lab has no PCI ids");
        // The offloads are further down the tab: scroll there.
        let over = h.text("corerouter-virt");
        h.frame(vec![egui::Event::PointerMoved(over)], egui::Modifiers::NONE);
        h.frame(
            vec![egui::Event::MouseWheel {
                unit: egui::MouseWheelUnit::Point,
                delta: egui::vec2(0.0, -800.0),
                phase: egui::TouchPhase::Move,
                source: egui::MouseWheelSource::Unknown,
                modifiers: egui::Modifiers::NONE,
            }],
            egui::Modifiers::NONE,
        );
        h.wait(0.5);
        assert!(h.has_text("TSO"));
        assert!(h.has_text("fixed"), "LRO is fixed in the lab");

        h.tab("Traffic");
        h.wait(2.5);
        assert!(!h.has_text("Collecting samples…"));

        h.tab("Statistics");
        assert!(h.has_text("interface"));
        assert!(h.has_text("rx-bytes"));
        assert!(h.has_text("rx-crc-errors"));
        h.click(h.text("Zero view"));
        assert!(h.has_text("Show totals"));
        // Only the window's view moved: the router still counts from boot.
        let st = lock(&h.session)
            .execute("interface.stats", &json!({"name": "ether1"}))
            .unwrap();
        assert!(st["groups"][0]["counters"][0]["value"].as_u64().unwrap() > 0);
        h.click(h.text("Show totals"));
        assert!(!h.has_text("Show totals"));

        // Esc still cancels from any tab; the tab queries stop with it.
        h.key(egui::Key::Escape, egui::Modifiers::NONE);
        assert!(h.app.dialogs.is_empty());
        h.idle();
        assert!(h.app.nic.is_empty());
    }

    #[test]
    fn interface_tabs_explain_what_is_not_supported() {
        let mut h = Harness::new();
        lock(&h.session)
            .execute("interface.bridge.add", &json!({"name": "br1"}))
            .unwrap();
        h.wait(1.1);
        h.app.open_props("br1");
        h.wait(0.2);
        h.tab("Status");
        assert!(h.has_text("Not supported here: 'br1' is a bridge, not an Ethernet port"));
        assert!(h.has_text("link-ok"), "the link state is still known");
        h.tab("Hardware");
        assert!(h.has_text("bridge"));
    }
}
