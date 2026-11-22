//! The connect screen (WinBox 4 login style): pick the router to manage
//! before any session exists. Left: Connect to, Login, Password, Group,
//! Comment, Save to list, Connect. Right: Neighbors (heard on the network)
//! and Saved (the operator's list), each with Find.
//!
//! The screen only collects choices: the app supplies the neighbor rows
//! (CRDP listener natively, `ip.neighbor.list` on the web), stores the saved
//! list and does the connecting (G0.3: login over TLS, the certificate
//! confirmed on first use with [`ConnectScreen::ask_trust`]). The saved
//! list keeps the login name but never a password; "Remember password"
//! is offered only where the operating system has a secure store
//! ([`ConnectScreen::set_keyring`]), and the app keeps it there.
//!
//! G0.3c: Login comes filled with `admin`, as in WinBox. A failed connection
//! is a [`Failure`]: one short sentence for the operator ([`explain`] turns
//! the router's and the network's errors into one), and what the program
//! saw under "Details". A router older than the login (G0.3) is told apart
//! ([`old_router_info`], [`old_router_error`]) and, on this machine, can
//! still be managed after "Connect anyway".
//!
//! G0.3d: a certificate seen for the first time, or different from the one
//! remembered (a reinstalled router, or an interception), opens the same
//! modal, PuTTY style: the remembered fingerprint with when it was accepted,
//! the new one, why it may have changed, and Cancel (the default: Enter and
//! Esc cancel), "Connect once" (not remembered) and "Trust and connect" /
//! "Trust and update" (written to known_hosts).
//!
//! G0.3e: no hidden password. A password saved in the secure store for the
//! address and Login shown is put in the Password field (masked), with a
//! "saved password" pill, its ⓘ and "Forget saved password"; the app looks
//! it up when the pair changes ([`ConnectScreen::wants_saved_password`],
//! [`ConnectScreen::set_saved_password`]). Clearing the field sends an empty
//! password. A login refused with the saved password says so and offers to
//! forget it; "Trust and update" on a changed certificate offers the same.

use egui::{Key, RichText, TextEdit, Ui};
use serde_json::{Value, json};

use crate::chip;
use crate::help::{self, HelpView};
use crate::i18n::{Langs, tr_in};
use crate::neighbors::uptime_text;
use crate::table::{self, Menu, Row, Shortcut, TableState, col, num};

const NEIGHBORS: &str = "connect-neighbors";
/// Translation scope of the certificate modal (`i18n/auto/connect_*.rs`).
const SCOPE: &str = "connect";
/// The explanation the certificate modal's ⓘ opens.
pub const HELP_CERT: &str = "connect.certificate";
/// The explanation of the "saved password" pill (G0.3e).
pub const HELP_SAVED: &str = "connect.saved_password";

/// A certificate waiting for the operator (G0.3d).
#[derive(Debug, Clone)]
struct TrustAsk {
    creds: Credentials,
    fingerprint: String,
    /// Changed: the remembered fingerprint and when it was accepted.
    previous: Option<(String, String)>,
    /// A password is saved for this router and Login: "Trust and update"
    /// also forgets it while this is ticked (G0.3e).
    forget: Option<bool>,
}

/// The secure store's answer for one address and Login (G0.3e).
#[derive(Clone, PartialEq, Eq)]
struct Stored {
    address: String,
    user: String,
    password: Option<String>,
}

/// A SHA-256 fingerprint on two lines of 16 bytes, so the two can be
/// compared at a glance and the modal stays narrow.
fn fingerprint_lines(fp: &str) -> String {
    let parts: Vec<&str> = fp.split(':').collect();
    match (parts.get(..17), parts.get(17..)) {
        (Some(head), Some(tail)) if !tail.is_empty() => {
            format!("{}:\n{}", head.join(":"), tail.join(":"))
        }
        _ => fp.to_owned(),
    }
}

/// The answer in the certificate modal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decision {
    Cancel,
    Once,
    Trust,
}
const SAVED: &str = "connect-saved";
/// Saved entries kept at most, and the longest text of each field.
pub const MAX_SAVED: usize = 1000;
const MAX_FIELD: usize = 256;

const NEIGHBOR_COLUMNS: [table::Column; 7] = [
    col("Address"),
    col("MAC Address"),
    col("Identity"),
    col("Version"),
    col("Board"),
    num("Uptime"),
    col("Interface"),
];
const SAVED_COLUMNS: [table::Column; 3] = [col("Address"), col("Group"), col("Comment")];

/// One router heard on the network, as the Neighbors tab shows it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NeighborRow {
    /// Stable id of the row (node id, MAC …).
    pub key: String,
    /// Where it was heard (this machine's or the router's interface).
    pub interface: String,
    pub protocol: String,
    pub address: String,
    pub mac: String,
    pub identity: String,
    pub version: String,
    pub board: String,
    pub uptime_secs: Option<u64>,
    /// What "Connect to" gets; `None` when it advertises no CoreRouter
    /// management port (an LLDP or MNDP neighbor).
    pub connect_to: Option<String>,
    /// Runs on another machine and announces no TLS management port: its
    /// plain control port takes only clients on its own machine, so the
    /// row is greyed out and a double click explains instead.
    pub remote: bool,
}

/// Why a router on another machine cannot be managed from here.
pub const REMOTE_HINT: &str = "Greyed out: on another machine without a TLS management port. \
     Start its daemon with --listen 0.0.0.0:8729 to manage it from here.";

/// What Login holds on a fresh screen (the first account of every router).
pub const DEFAULT_LOGIN: &str = "admin";

/// A router older than G0.3: it has no login at all.
pub const OLD_ROUTER: &str =
    "This router runs an old version (without login). Update and restart corerouter-daemon.";
/// The login was refused (the router never says which part was wrong).
pub const BAD_LOGIN: &str = "Invalid user or password";
/// What a router between G0.3b and G0.3d answers to a network login while
/// an account of group full has no password (newer ones accept it).
pub const SET_PASSWORD_FIRST: &str = "Set the admin password first: this router version refuses \
     network logins until admin has one. Log in on its own machine (127.0.0.1, empty password) \
     and set it, or update the router.";
/// The login was refused with the password saved for this router (G0.3e).
pub const SAVED_FAILED: &str = "The saved password for this router did not work: forget it, or \
     type the password (empty if admin has none, e.g. after a reinstall).";
const TOO_MANY: &str = "Too many failed logins: wait a moment and try again";

/// Why a connection failed, for the operator.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Failure {
    /// One short sentence, shown in red.
    pub text: String,
    /// What the program saw (router errors, the local token's path…),
    /// shown only under "Details".
    pub detail: String,
    /// An old router without login on this machine: offer "Connect anyway".
    pub offer_anyway: bool,
}

impl Failure {
    pub fn new(text: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            detail: detail.into(),
            offer_anyway: false,
        }
    }
}

impl From<String> for Failure {
    fn from(text: String) -> Self {
        Self::new(text, String::new())
    }
}

/// `server.info` of a router older than G0.3: it answers but says nothing
/// about `auth` (every router since then says `"auth": "required"`).
pub fn old_router_info(info: &Value) -> bool {
    info.get("version").is_some() && info.get("auth").is_none()
}

/// The error of a router that does not know the `auth.*` methods.
pub fn old_router_error(error: &str) -> bool {
    error.contains("unknown method 'auth.")
}

/// A connection or login error as one short sentence, the original kept
/// as the detail. Matches the texts of `corerouter_control` (checked by
/// the GUI's tests: this crate does not depend on the network code).
pub fn explain(error: &str) -> Failure {
    let lower = error.to_ascii_lowercase();
    let text = if old_router_error(error) {
        OLD_ROUTER.to_owned()
    } else if lower.contains("invalid user or password") {
        BAD_LOGIN.to_owned()
    } else if lower.contains("login from the network is refused") {
        SET_PASSWORD_FIRST.to_owned()
    } else if lower.contains("too many failed logins") {
        TOO_MANY.to_owned()
    } else if lower.contains("connection refused") {
        "Nothing answers at that address: is corerouter-daemon running, on that port?".to_owned()
    } else if lower.contains("timed out") {
        "The router did not answer in time".to_owned()
    } else {
        return Failure::from(error.chars().take(MAX_ERROR).collect::<String>());
    };
    Failure::new(text, error.chars().take(MAX_ERROR).collect::<String>())
}

/// The detail of a failure worded again: its sentence, then its detail.
fn join_detail(f: &Failure) -> String {
    if f.detail.is_empty() {
        f.text.clone()
    } else {
        format!("{}: {}", f.text, f.detail)
    }
}

/// The grey example in an empty Connect to: an address of another router
/// (TLS), in italics so it never reads as a value.
const CONNECT_TO_HINT: &str = "e.g. 192.168.88.1:8729";
const FORGET: &str = "Forget saved password";

/// Longest error text kept from the router or the network (hostile input).
const MAX_ERROR: usize = 1000;

/// An entry of the Saved tab. Deliberately no password: that goes only to
/// the operating system's secure store ("Remember password").
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SavedRouter {
    pub address: String,
    pub group: String,
    pub comment: String,
    /// Login name (empty in lists saved before G0.3c: Login gets `admin`).
    pub user: String,
}

/// What the operator typed to log in.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Credentials {
    pub address: String,
    /// On this machine the local token is tried first, then this user.
    /// Empty: the local token only.
    pub user: String,
    pub password: String,
    /// Keep the password in the operating system's secure store.
    pub remember: bool,
    /// The operator chose "Connect anyway" for an old router without login.
    pub legacy: bool,
    /// TLS: the certificate accepted for this connection only ("Connect
    /// once", G0.3d); `None` uses known_hosts.
    pub pin: Option<String>,
    /// `password` is the one saved in the secure store, untouched (G0.3e).
    pub saved: bool,
}

impl std::fmt::Debug for Credentials {
    /// Never prints the password.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("address", &self.address)
            .field("user", &self.user)
            .field("remember", &self.remember)
            .field("legacy", &self.legacy)
            .field("pin", &self.pin)
            .field("saved", &self.saved)
            .finish_non_exhaustive()
    }
}

impl SavedRouter {
    pub fn list_to_json(list: &[SavedRouter]) -> Value {
        Value::Array(
            list.iter()
                .map(|s| {
                    json!({"address": s.address, "group": s.group, "comment": s.comment,
                           "user": s.user})
                })
                .collect(),
        )
    }

    /// Read a stored list; anything malformed is skipped, sizes are bounded.
    pub fn list_from_json(v: &Value) -> Vec<SavedRouter> {
        let field = |e: &Value, k: &str| -> String {
            e.get(k)
                .and_then(Value::as_str)
                .unwrap_or("")
                .chars()
                .filter(|c| !c.is_control())
                .take(MAX_FIELD)
                .collect()
        };
        v.as_array()
            .map(|a| {
                a.iter()
                    .take(MAX_SAVED)
                    .map(|e| SavedRouter {
                        address: field(e, "address"),
                        group: field(e, "group"),
                        comment: field(e, "comment"),
                        user: field(e, "user"),
                    })
                    .filter(|s| !s.address.trim().is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectAction {
    /// Manage the router at this address (as typed in "Connect to").
    Connect(Credentials),
    /// The operator checked and accepted this certificate (first TLS
    /// connection, or a changed one): remember it and connect.
    Trust {
        creds: Credentials,
        fingerprint: String,
        /// Also forget the password saved for `creds.address` and
        /// `creds.user` (a reinstalled router, G0.3e).
        forget_password: bool,
    },
    /// Connect to this certificate this time, without remembering it
    /// (`creds.pin` holds it).
    Once(Credentials),
    /// Delete the password saved for this address and Login (G0.3e).
    ForgetPassword { address: String, user: String },
    /// Run the in-process virtual lab instead.
    VirtualLab,
}

/// The line under the buttons.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Message {
    ok: bool,
    failure: Failure,
    /// The saved password was refused: offer to forget it.
    forget: bool,
}

impl Message {
    fn ok(text: impl Into<String>) -> Self {
        Self {
            ok: true,
            failure: Failure::new(text, String::new()),
            forget: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Neighbors,
    Saved,
}

pub struct ConnectScreen {
    pub connect_to: String,
    login: String,
    /// Sent with the login, then cleared; never saved by this screen.
    password: String,
    remember: bool,
    /// `None`: no secure store here (the checkbox is off, with the reason).
    keyring: Option<String>,
    /// The (address, Login) last handed to the app to look up.
    asked: Option<(String, String)>,
    /// What the secure store holds for `asked`.
    stored: Option<Stored>,
    /// The credentials of the last connection tried, to word its failure.
    last_try: Option<Credentials>,
    /// Connect once the saved password of the new address is looked up.
    pending_connect: bool,
    /// A certificate waiting for the operator's answer.
    trust: Option<TrustAsk>,
    /// The ⓘ's explanation in the certificate modal, while open.
    help: Option<HelpView>,
    /// Put the focus on Cancel when the modal opens.
    trust_focus: bool,
    group: String,
    comment: String,
    tab: Tab,
    neighbors: TableState,
    saved_table: TableState,
    saved: Vec<SavedRouter>,
    saved_changed: bool,
    /// Last message (error, or a hint) under the buttons.
    message: Option<Message>,
    /// Where the Neighbors tab gets its rows, shown above the table.
    source: String,
    offer_lab: bool,
    keyring_why: String,
}

impl ConnectScreen {
    pub fn new(saved: Vec<SavedRouter>) -> Self {
        Self {
            connect_to: String::new(),
            login: DEFAULT_LOGIN.into(),
            password: String::new(),
            remember: false,
            keyring: None,
            asked: None,
            stored: None,
            last_try: None,
            pending_connect: false,
            trust: None,
            help: None,
            trust_focus: false,
            group: String::new(),
            comment: String::new(),
            tab: Tab::Neighbors,
            neighbors: TableState::default(),
            saved_table: TableState::default(),
            saved,
            saved_changed: false,
            message: None,
            source: String::new(),
            offer_lab: true,
            keyring_why: "no secure password store on this platform".into(),
        }
    }

    /// Text above the Neighbors table, e.g. "listening for CRDP on UDP 7979".
    pub fn set_source(&mut self, text: impl Into<String>) {
        self.source = text.into();
    }

    pub fn set_error(&mut self, text: impl Into<String>) {
        self.fail(Failure::from(text.into()));
    }

    /// Show why connecting failed (the detail under "Details").
    pub fn fail(&mut self, failure: Failure) {
        let saved = self.last_try.as_ref().is_some_and(|c| c.saved);
        let message = if saved && failure.text == BAD_LOGIN {
            Message {
                ok: false,
                failure: Failure::new(SAVED_FAILED, join_detail(&failure)),
                forget: true,
            }
        } else {
            Message {
                ok: false,
                failure,
                forget: false,
            }
        };
        self.message = Some(message);
    }

    /// Where "Remember password" keeps it (e.g. "the system keyring"), or
    /// `Err(why)` to grey the checkbox out.
    pub fn set_keyring(&mut self, store: Result<String, String>) {
        match store {
            Ok(name) => self.keyring = Some(name),
            Err(why) => {
                self.keyring = None;
                self.remember = false;
                self.keyring_why = why;
            }
        }
    }

    /// The (address, Login) now on screen, once each time it changes, for
    /// the app to look up in the secure store and answer with
    /// [`Self::set_saved_password`]. `None` without a store.
    pub fn wants_saved_password(&mut self) -> Option<(String, String)> {
        self.keyring.as_ref()?;
        let key = self.key();
        if self.asked.as_ref() == Some(&key) {
            return None;
        }
        self.asked = Some(key.clone());
        (!key.0.is_empty() && !key.1.is_empty()).then_some(key)
    }

    /// The secure store's answer for `address` and `user`: a saved password
    /// goes into the field (masked, with the "saved password" pill); a
    /// field that held the previous router's saved password is cleared. A
    /// password the operator typed stays. Stale answers are ignored.
    pub fn set_saved_password(&mut self, address: &str, user: &str, password: Option<String>) {
        if self.key() != (address.to_owned(), user.to_owned()) {
            return;
        }
        let filled = self
            .stored
            .as_ref()
            .and_then(|s| s.password.as_deref())
            .is_some_and(|p| p == self.password);
        if filled || self.password.is_empty() {
            self.password = password.clone().unwrap_or_default();
            if password.is_some() {
                self.remember = self.keyring.is_some();
            }
        }
        self.stored = Some(Stored {
            address: address.to_owned(),
            user: user.to_owned(),
            password,
        });
    }

    /// The saved password of the address and Login on screen, if any.
    fn saved_password(&self) -> Option<&str> {
        let s = self.stored.as_ref()?;
        let (address, user) = self.key();
        (s.address == address && s.user == user)
            .then_some(s.password.as_deref())
            .flatten()
    }

    /// The Password field holds the saved password, untouched.
    fn holds_saved(&self) -> bool {
        self.saved_password().is_some_and(|p| p == self.password)
    }

    fn key(&self) -> (String, String) {
        (
            self.connect_to.trim().to_owned(),
            self.login.trim().to_owned(),
        )
    }

    /// Forget the saved password of `address` and `user` on screen (the
    /// app deletes it from the store): the field is emptied if it held it.
    fn forget_saved(&mut self, address: &str, user: &str, action: &mut Option<ConnectAction>) {
        if let Some(s) = self
            .stored
            .as_mut()
            .filter(|s| s.address == address && s.user == user)
        {
            if s.password.as_deref() == Some(self.password.as_str()) {
                self.password.clear();
            }
            s.password = None;
        }
        if self.last_try.as_ref().is_some_and(|c| c.saved) {
            self.message = None;
        }
        *action = Some(ConnectAction::ForgetPassword {
            address: address.to_owned(),
            user: user.to_owned(),
        });
    }

    /// Put `password` in the field (e.g. `$COREROUTER_PASSWORD` for
    /// `--connect`): typed, not saved.
    pub fn set_password(&mut self, password: String) {
        self.password = password;
    }

    /// The credentials on screen, to connect right away (`--connect`), as
    /// the Connect button would.
    pub fn connect_now(&mut self) -> Credentials {
        let c = self.credentials();
        self.last_try = Some(c.clone());
        c
    }

    /// First TLS connection to `creds.address`: show `fingerprint` and
    /// wait for the operator (the answer comes as [`ConnectAction::Trust`]
    /// or [`ConnectAction::Once`]).
    pub fn ask_trust(&mut self, creds: Credentials, fingerprint: String) {
        self.message = None;
        self.trust_focus = true;
        self.trust = Some(TrustAsk {
            creds,
            fingerprint,
            previous: None,
            forget: None,
        });
    }

    /// The router at `creds.address` shows `fingerprint`, not the `old` one
    /// remembered `since` (already a date, "unknown date" when the file has
    /// none): ask, PuTTY style (G0.3d).
    pub fn ask_changed(
        &mut self,
        creds: Credentials,
        old: String,
        since: String,
        fingerprint: String,
    ) {
        self.message = None;
        self.trust_focus = true;
        let saved = self.stored.as_ref().is_some_and(|s| {
            s.password.is_some() && s.address == creds.address.trim() && s.user == creds.user.trim()
        });
        self.trust = Some(TrustAsk {
            creds,
            fingerprint,
            previous: Some((old, since)),
            // A reinstalled router has a new admin: forget by default.
            forget: saved.then_some(true),
        });
    }

    /// The certificate modal is open.
    pub fn asking_trust(&self) -> bool {
        self.trust.is_some()
    }

    /// Fill the Login field (e.g. from `--user`; default `admin`).
    pub fn set_login(&mut self, user: &str) {
        self.login = user.to_owned();
    }

    /// The login worked: forget the typed password.
    pub fn connected(&mut self) {
        self.password.clear();
        self.trust = None;
    }

    /// Show the "Virtual lab" button (default: shown).
    pub fn offer_lab(&mut self, offer: bool) {
        self.offer_lab = offer;
    }

    pub fn saved(&self) -> &[SavedRouter] {
        &self.saved
    }

    /// The saved list, once after each change, for the app to store.
    pub fn take_saved_change(&mut self) -> Option<Vec<SavedRouter>> {
        std::mem::take(&mut self.saved_changed).then(|| self.saved.clone())
    }

    /// Draw the whole screen into the root `Ui`; returns what to do.
    pub fn ui(&mut self, ui: &mut Ui, neighbors: &[NeighborRow]) -> Option<ConnectAction> {
        let mut action = None;
        if std::mem::take(&mut self.pending_connect) {
            self.connect(&mut action);
        }
        egui::Panel::left("connect-form")
            .resizable(false)
            .exact_size(330.0)
            .show(ui, |ui| self.form(ui, &mut action));
        egui::CentralPanel::default().show(ui, |ui| self.lists(ui, neighbors, &mut action));
        self.trust_window(ui, &mut action);
        if let Some(
            ConnectAction::Connect(c)
            | ConnectAction::Once(c)
            | ConnectAction::Trust { creds: c, .. },
        ) = &action
        {
            self.message = Some(Message::ok(format!("connecting to {}…", c.address)));
            self.last_try = Some(c.clone());
        }
        action
    }

    /// The certificate modal, with its ⓘ explanation on top.
    fn trust_window(&mut self, ui: &mut Ui, action: &mut Option<ConnectAction>) {
        self.trust_modal(ui, action);
        help::modal(ui.ctx(), Langs::default(), &mut self.help);
    }

    /// The certificate modal (G0.3d): first use or changed, three answers.
    fn trust_modal(&mut self, ui: &mut Ui, action: &mut Option<ConnectAction>) {
        let langs = Langs::default();
        let Some(ask) = self.trust.clone() else {
            return;
        };
        let l = langs.labels;
        let t = |text: &'static str| tr_in(SCOPE, l, text);
        let changed = ask.previous.is_some();
        let mut answer = None;
        let mut open_help = false;
        let mut forget = ask.forget;
        let focus = std::mem::take(&mut self.trust_focus);
        egui::Modal::new(egui::Id::unique("corerouter-cert-modal")).show(ui.ctx(), |ui| {
            ui.set_width(560.0);
            ui.horizontal(|ui| {
                let title = if changed {
                    t("Router certificate CHANGED")
                } else {
                    t("Unknown router certificate")
                };
                let color = if changed { ui.visuals().warn_fg_color } else { ui.visuals().strong_text_color() };
                ui.label(RichText::new(title).heading().color(color));
                open_help = help::info_button(ui, egui::Id::unique("cert-modal-info"), t("What to check")).clicked();
            });
            ui.separator();
            ui.label(format!("{} {}", t("Router:"), ask.creds.address));
            ui.add_space(4.0);
            egui::Grid::new("cert-modal-grid").num_columns(2).spacing([10.0, 4.0]).show(ui, |ui| {
                if let Some((old, since)) = &ask.previous {
                    ui.label(t("Remembered"));
                    ui.vertical(|ui| {
                        ui.monospace(fingerprint_lines(old));
                        ui.weak(format!("{} {since}", t("accepted")));
                    });
                    ui.end_row();
                    ui.label(t("Now"));
                } else {
                    ui.label(t("Fingerprint"));
                }
                ui.monospace(RichText::new(fingerprint_lines(&ask.fingerprint)).strong());
                ui.end_row();
            });
            ui.add_space(6.0);
            if changed {
                ui.label(t("The router shows another TLS certificate than the one remembered. Nothing was sent to it."));
                ui.weak(t("Expected after a reinstall or a new certificate: compare the new fingerprint with the one the router prints at start-up (corerouter-daemon log, console). If you did not change anything, someone may be intercepting the connection: cancel."));
            } else {
                ui.weak(t("First connection to this router. Compare the fingerprint with the one the router prints at start-up (corerouter-daemon log, console) before trusting it."));
            }
            if let Some(f) = forget.as_mut() {
                ui.add_space(6.0);
                ui.checkbox(f, format!("{} {}", t("Also forget the saved password of"), ask.creds.user.trim()))
                    .on_hover_text(t("A reinstalled router has a new admin (without a password until one is set): the password saved for the old one would be refused. Applies to Trust and update."));
            }
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                let cancel = ui.button(RichText::new(t("Cancel")).strong());
                if focus {
                    cancel.request_focus();
                }
                if cancel.clicked() {
                    answer = Some(Decision::Cancel);
                }
                if ui
                    .button(t("Connect once"))
                    .on_hover_text(t("Connect with this certificate now; known_hosts keeps what it had."))
                    .clicked()
                {
                    answer = Some(Decision::Once);
                }
                let trust = if changed { t("Trust and update") } else { t("Trust and connect") };
                if ui
                    .button(trust)
                    .on_hover_text(t("Remember this certificate (known_hosts, with today's date) and connect."))
                    .clicked()
                {
                    answer = Some(Decision::Trust);
                }
            });
            // Enter never accepts: a stray Enter cancels, like Esc.
            if answer.is_none() && ui.input(|i| i.key_pressed(Key::Escape) || i.key_pressed(Key::Enter)) && self.help.is_none() {
                answer = Some(Decision::Cancel);
            }
        });
        if open_help {
            self.help = Some(HelpView::new(
                HELP_CERT,
                tr_in(
                    SCOPE,
                    l,
                    if changed {
                        "Router certificate CHANGED"
                    } else {
                        "Unknown router certificate"
                    },
                ),
            ));
        }
        let Some(answer) = answer else {
            if let Some(open) = self.trust.as_mut() {
                open.forget = forget;
            }
            return;
        };
        self.trust = None;
        let TrustAsk {
            mut creds,
            fingerprint,
            ..
        } = ask;
        match answer {
            Decision::Trust => {
                let forget_password = forget == Some(true);
                if forget_password {
                    let mut ignored = None;
                    self.forget_saved(creds.address.trim(), creds.user.trim(), &mut ignored);
                    // A password typed now still goes (and is remembered).
                    if creds.saved {
                        creds.password.clear();
                        creds.saved = false;
                    }
                }
                *action = Some(ConnectAction::Trust {
                    creds,
                    fingerprint,
                    forget_password,
                });
            }
            Decision::Once => {
                *action = Some(ConnectAction::Once(Credentials {
                    pin: Some(fingerprint),
                    ..creds
                }));
            }
            Decision::Cancel => self.set_error("Not connected: the certificate was not trusted"),
        }
    }

    fn credentials(&self) -> Credentials {
        Credentials {
            address: self.connect_to.trim().to_owned(),
            user: self.login.trim().to_owned(),
            password: self.password.clone(),
            remember: self.remember && self.keyring.is_some(),
            legacy: false,
            pin: None,
            saved: self.holds_saved(),
        }
    }

    fn connect(&mut self, action: &mut Option<ConnectAction>) {
        if self.connect_to.trim().is_empty() {
            self.set_error("Type an address in Connect to, or pick a neighbor or a saved router");
        } else if self.keyring.is_some() && self.asked != Some(self.key()) {
            // A neighbor or saved router just picked: its saved password
            // is looked up first, so the field shows what is sent.
            self.pending_connect = true;
        } else {
            *action = Some(ConnectAction::Connect(self.credentials()));
        }
    }

    fn form(&mut self, ui: &mut Ui, action: &mut Option<ConnectAction>) {
        ui.add_space(12.0);
        ui.heading("CoreRouter");
        ui.weak("Connect to a router");
        ui.add_space(12.0);
        let login_hint = "On this machine (127.0.0.1) the GUI gets in by itself when this \
                          OS user runs the router; otherwise it logs in with Login and \
                          Password. Any other address is TLS with a user and password. A \
                          new router's admin has no password: leave Password empty here \
                          (from any network) and set one when asked.";
        let mut enter = false;
        egui::Grid::new("connect-grid")
            .num_columns(2)
            .spacing([8.0, 8.0])
            .show(ui, |ui| {
                let w = 200.0;
                ui.label("Connect to:");
                // An example, never mistaken for a value (G0.3e).
                let r = ui.add(
                    TextEdit::singleline(&mut self.connect_to)
                        .hint_text(RichText::new(CONNECT_TO_HINT).italics())
                        .desired_width(w),
                );
                enter = r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                ui.end_row();
                ui.label("Login:");
                let r = ui
                    .add(
                        TextEdit::singleline(&mut self.login)
                            .hint_text("admin")
                            .desired_width(w),
                    )
                    .on_hover_text(login_hint);
                enter |= r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                ui.end_row();
                ui.label("Password:");
                let r = ui.add(
                    TextEdit::singleline(&mut self.password)
                        .password(true)
                        .desired_width(w),
                );
                enter |= r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                ui.end_row();
                if self.saved_password().is_some() {
                    ui.label("");
                    self.saved_row(ui, action);
                    ui.end_row();
                }
                ui.label("");
                match &self.keyring {
                    Some(store) => {
                        ui.checkbox(&mut self.remember, "Remember password")
                            .on_hover_text(format!("Kept in {store}, never in a file of this app"));
                    }
                    None => {
                        let mut off = false;
                        ui.add_enabled(false, egui::Checkbox::new(&mut off, "Remember password"))
                            .on_disabled_hover_text(self.keyring_why.as_str());
                    }
                }
                ui.end_row();
                ui.label("Group:");
                ui.add(TextEdit::singleline(&mut self.group).desired_width(w));
                ui.end_row();
                ui.label("Comment:");
                ui.add(TextEdit::singleline(&mut self.comment).desired_width(w));
                ui.end_row();
            });
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui
                .button("Save to list")
                .on_hover_text("Keep address, group and comment in the Saved tab")
                .clicked()
            {
                self.save_current();
            }
            if ui.button(RichText::new("Connect").strong()).clicked() || enter {
                self.connect(action);
            }
        });
        ui.add_space(8.0);
        ui.weak(login_hint);
        if self.offer_lab {
            ui.add_space(8.0);
            ui.separator();
            if ui
                .button("Virtual lab")
                .on_hover_text("An in-memory router inside this window; nothing is saved")
                .clicked()
            {
                *action = Some(ConnectAction::VirtualLab);
            }
        }
        self.message_ui(ui, action);
    }

    /// The message under the buttons: the sentence, then "Details" and
    /// "Connect anyway" when they apply.
    fn message_ui(&mut self, ui: &mut Ui, action: &mut Option<ConnectAction>) {
        let Some(Message {
            ok,
            failure,
            forget,
        }) = self.message.clone()
        else {
            return;
        };
        ui.add_space(8.0);
        let color = if ok {
            ui.visuals().text_color()
        } else {
            ui.visuals().error_fg_color
        };
        let r = ui.colored_label(color, failure.text.as_str());
        if !failure.detail.is_empty() {
            r.on_hover_text(failure.detail.as_str());
            egui::CollapsingHeader::new("Details")
                .id_salt("connect-details")
                .show(ui, |ui| {
                    ui.weak(failure.detail.as_str());
                });
        }
        if forget
            && ui
                .button(tr_in(SCOPE, Langs::default().labels, FORGET))
                .clicked()
        {
            let (address, user) = self
                .last_try
                .as_ref()
                .map(|c| (c.address.trim().to_owned(), c.user.trim().to_owned()))
                .unwrap_or_else(|| self.key());
            self.forget_saved(&address, &user, action);
            self.message = Some(Message::ok(format!(
                "saved password of {user} at {address} forgotten"
            )));
            return;
        }
        if failure.offer_anyway
            && ui
                .button("Connect anyway")
                .on_hover_text(
                    "An old router has no login: anyone on its machine can already manage \
                     it. The top bar warns until it is updated.",
                )
                .clicked()
        {
            *action = Some(ConnectAction::Connect(Credentials {
                legacy: true,
                ..self.credentials()
            }));
        }
    }

    /// Under Password while a password is saved for this address and
    /// Login: the pill (whether the field holds it), its ⓘ and Forget.
    fn saved_row(&mut self, ui: &mut Ui, action: &mut Option<ConnectAction>) {
        let l = Langs::default().labels;
        let t = |text: &'static str| tr_in(SCOPE, l, text);
        let in_field = self.holds_saved();
        ui.horizontal(|ui| {
            let v = ui.visuals();
            let (text, tone, tip) = if in_field {
                (
                    t("saved password"),
                    chip::BLUE.tone(v),
                    t("The Password field holds the password saved for this router and Login. Clear it to connect with an empty password."),
                )
            } else {
                (
                    t("saved password unused"),
                    chip::neutral_tone(v),
                    t("A password is saved for this router and Login, but Connect sends what the field holds now (empty: no password)."),
                )
            };
            chip::chip(ui, text, tone).on_hover_text(tip);
            if help::info_button(ui, egui::Id::unique("connect-saved-info"), t("Saved password")).clicked() {
                self.help = Some(HelpView::new(HELP_SAVED, t("Saved password")));
            }
            if ui
                .small_button(t("Forget"))
                .on_hover_text(t("Forget saved password: delete it from the secure store of this computer; the router is not touched."))
                .clicked()
            {
                let (address, user) = self.key();
                self.forget_saved(&address, &user, action);
            }
        });
    }

    fn save_current(&mut self) {
        let address = self.connect_to.trim().to_owned();
        if address.is_empty() {
            self.set_error("Nothing to save: Connect to is empty");
            return;
        }
        let entry = SavedRouter {
            address: address.chars().take(MAX_FIELD).collect(),
            group: self.group.trim().chars().take(MAX_FIELD).collect(),
            comment: self.comment.trim().chars().take(MAX_FIELD).collect(),
            user: self.login.trim().chars().take(MAX_FIELD).collect(),
        };
        let full = self.saved.len() >= MAX_SAVED;
        match self.saved.iter_mut().find(|s| s.address == entry.address) {
            Some(s) => *s = entry,
            None if full => {
                self.set_error(format!("The saved list is full ({MAX_SAVED})"));
                return;
            }
            None => self.saved.push(entry),
        }
        self.saved_changed = true;
        self.tab = Tab::Saved;
        self.message = Some(Message::ok(format!("saved {address}")));
    }

    fn lists(
        &mut self,
        ui: &mut Ui,
        neighbors: &[NeighborRow],
        action: &mut Option<ConnectAction>,
    ) {
        ui.horizontal(|ui| {
            let n = format!("Neighbors ({})", neighbors.len());
            if ui.selectable_label(self.tab == Tab::Neighbors, n).clicked() {
                self.tab = Tab::Neighbors;
            }
            let s = format!("Saved ({})", self.saved.len());
            if ui.selectable_label(self.tab == Tab::Saved, s).clicked() {
                self.tab = Tab::Saved;
            }
            match self.tab {
                Tab::Neighbors => table::find_field(ui, NEIGHBORS, &mut self.neighbors),
                Tab::Saved => table::find_field(ui, SAVED, &mut self.saved_table),
            }
        });
        ui.separator();
        match self.tab {
            Tab::Neighbors => self.neighbor_tab(ui, neighbors, action),
            Tab::Saved => self.saved_tab(ui, action),
        }
    }

    fn neighbor_tab(
        &mut self,
        ui: &mut Ui,
        neighbors: &[NeighborRow],
        action: &mut Option<ConnectAction>,
    ) {
        if !self.source.is_empty() {
            ui.weak(self.source.as_str());
        }
        let rows: Vec<Row> = neighbors
            .iter()
            .map(|n| Row {
                key: n.key.clone(),
                cells: vec![
                    n.address.clone(),
                    n.mac.clone(),
                    n.identity.clone(),
                    n.version.clone(),
                    n.board.clone(),
                    n.uptime_secs.map(uptime_text).unwrap_or_default(),
                    n.interface.clone(),
                ],
                dimmed: n.connect_to.is_none() || n.remote,
                section: false,
                tint: None,
            })
            .collect();
        if neighbors.iter().any(|n| n.remote && n.connect_to.is_some()) {
            ui.weak(REMOTE_HINT);
        }
        let before = self.neighbors.selection(&rows);
        let out = table::show(
            ui,
            NEIGHBORS,
            0.0,
            &mut self.neighbors,
            &NEIGHBOR_COLUMNS,
            &rows,
            |_, _| {},
        );
        let after = self.neighbors.selection(&rows);
        let find = |key: &str| neighbors.iter().find(|n| n.key == key);
        let opened = out.opened.or_else(|| {
            (out.shortcut == Some(Shortcut::Open))
                .then(|| after.first().cloned())
                .flatten()
        });
        if let Some(key) = opened {
            if let Some(n) = find(&key)
                && self.pick_neighbor(n)
            {
                self.connect(action);
            }
        } else if after != before
            && let [one] = after.as_slice()
            && let Some(n) = find(one)
        {
            self.pick_neighbor(n);
        }
    }

    /// Fill "Connect to" from a neighbor; false when it cannot be managed
    /// from here (the Connect button still tries what was filled in).
    fn pick_neighbor(&mut self, n: &NeighborRow) -> bool {
        let who = if n.identity.is_empty() {
            &n.address
        } else {
            &n.identity
        };
        match &n.connect_to {
            Some(addr) if n.remote => {
                self.connect_to = addr.clone();
                self.set_error(format!(
                    "{who} is on another machine and announces no TLS management port: \
                     its plain port only takes clients on its own machine. Start its daemon \
                     with --listen 0.0.0.0:8729; Connect still tries the address."
                ));
                false
            }
            Some(addr) => {
                self.connect_to = addr.clone();
                self.message = None;
                true
            }
            None => {
                self.set_error(format!(
                    "{who} ({}) advertises no CoreRouter management port",
                    n.protocol
                ));
                false
            }
        }
    }

    fn saved_tab(&mut self, ui: &mut Ui, action: &mut Option<ConnectAction>) {
        let rows: Vec<Row> = self
            .saved
            .iter()
            .map(|s| Row {
                key: s.address.clone(),
                cells: vec![s.address.clone(), s.group.clone(), s.comment.clone()],
                dimmed: false,
                section: false,
                tint: None,
            })
            .collect();
        let before = self.saved_table.selection(&rows);
        let mut remove: Option<Vec<String>> = None;
        let out = table::show(
            ui,
            SAVED,
            0.0,
            &mut self.saved_table,
            &SAVED_COLUMNS,
            &rows,
            |ui, menu| {
                if let Menu::Rows(sel) = menu
                    && ui.button("Remove").clicked()
                {
                    remove = Some(sel.to_vec());
                }
            },
        );
        let after = self.saved_table.selection(&rows);
        if out.shortcut == Some(Shortcut::Remove) {
            remove = Some(after.to_vec());
        }
        if let Some(gone) = remove.filter(|g| !g.is_empty()) {
            self.saved.retain(|s| !gone.contains(&s.address));
            self.saved_changed = true;
            return;
        }
        let opened = out.opened.or_else(|| {
            (out.shortcut == Some(Shortcut::Open))
                .then(|| after.first().cloned())
                .flatten()
        });
        let pick = opened.clone().or_else(|| match after.as_slice() {
            [one] if after != before => Some(one.clone()),
            _ => None,
        });
        if let Some(addr) = pick
            && let Some(s) = self.saved.iter().find(|s| s.address == addr).cloned()
        {
            self.connect_to = s.address;
            self.group = s.group;
            self.comment = s.comment;
            self.login = if s.user.is_empty() {
                DEFAULT_LOGIN.into()
            } else {
                s.user
            };
            self.message = None;
            if opened.is_some() {
                self.connect(action);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(addr: &str) -> ConnectAction {
        ConnectAction::Connect(Credentials {
            address: addr.into(),
            user: DEFAULT_LOGIN.into(),
            ..Credentials::default()
        })
    }

    #[test]
    fn login_goes_with_connect_and_a_new_certificate_is_asked() {
        let ctx = egui::Context::default();
        let mut s = ConnectScreen::new(Vec::new());
        s.connect_to = "10.0.0.1:8729".into();
        s.login = "admin".into();
        s.password = "pw-123456".into();
        let mut t = 0.0;
        let (_, texts) = frame(&ctx, &mut s, &[], Vec::new(), &mut t);
        let mut a = frame(
            &ctx,
            &mut s,
            &[],
            click_events(at(&texts, "Connect")),
            &mut t,
        )
        .0;
        a = a.or(frame(&ctx, &mut s, &[], Vec::new(), &mut t).0);
        let Some(ConnectAction::Connect(c)) = a else {
            panic!("{a:?}")
        };
        assert_eq!(
            (c.user.as_str(), c.password.as_str()),
            ("admin", "pw-123456")
        );
        assert!(!c.remember, "no keyring: never remembered");
        assert!(!format!("{c:?}").contains("pw-123456"));
        // First TLS connection: the fingerprint is shown and needs a yes.
        s.ask_trust(c.clone(), "SHA256:AA:BB".into());
        // A new window is laid out on its first frame, shown on the next.
        frame(&ctx, &mut s, &[], Vec::new(), &mut t);
        let (_, texts) = frame(&ctx, &mut s, &[], Vec::new(), &mut t);
        assert!(texts.iter().any(|(x, _)| x == "SHA256:AA:BB"));
        let mut a = frame(
            &ctx,
            &mut s,
            &[],
            click_events(at(&texts, "Trust and connect")),
            &mut t,
        )
        .0;
        a = a.or(frame(&ctx, &mut s, &[], Vec::new(), &mut t).0);
        assert_eq!(
            a,
            Some(ConnectAction::Trust {
                creds: c,
                fingerprint: "SHA256:AA:BB".into(),
                forget_password: false,
            })
        );
        s.connected();
        assert!(s.password.is_empty());
        // With a keyring the box can be ticked.
        s.set_keyring(Ok("the system keyring".into()));
        s.remember = true;
        assert!(s.credentials().remember);
        s.set_keyring(Err("none".into()));
        assert!(!s.credentials().remember);
    }

    fn neighbor(id: &str, connect: Option<&str>) -> NeighborRow {
        NeighborRow {
            key: id.into(),
            interface: "eth0".into(),
            protocol: "crdp".into(),
            address: format!("10.0.0.{}", id.len()),
            identity: format!("r-{id}"),
            connect_to: connect.map(str::to_owned),
            ..NeighborRow::default()
        }
    }

    /// Draw one frame with `events`; returns the action and painted texts.
    fn frame(
        ctx: &egui::Context,
        screen: &mut ConnectScreen,
        rows: &[NeighborRow],
        events: Vec<egui::Event>,
        t: &mut f64,
    ) -> (Option<ConnectAction>, Vec<(String, egui::Rect)>) {
        let raw = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1200.0, 700.0),
            )),
            time: Some(*t),
            events,
            ..Default::default()
        };
        *t += 0.02;
        let mut action = None;
        let mut out = ctx.run_ui(raw, |ui| {
            if let Some(a) = screen.ui(ui, rows) {
                action = Some(a);
            }
        });
        out.textures_delta.clear();
        let mut texts = Vec::new();
        fn walk(s: &egui::Shape, out: &mut Vec<(String, egui::Rect)>) {
            match s {
                egui::Shape::Text(t) => {
                    out.push((t.galley.text().to_owned(), t.visual_bounding_rect()))
                }
                egui::Shape::Vec(v) => v.iter().for_each(|s| walk(s, out)),
                _ => {}
            }
        }
        for c in &out.shapes {
            walk(&c.shape, &mut texts);
        }
        (action, texts)
    }

    fn click_events(pos: egui::Pos2) -> Vec<egui::Event> {
        let ev = |pressed| egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        vec![egui::Event::PointerMoved(pos), ev(true), ev(false)]
    }

    fn at(texts: &[(String, egui::Rect)], needle: &str) -> egui::Pos2 {
        texts
            .iter()
            .rev()
            .find(|(t, _)| t == needle)
            .map(|(_, r)| r.center())
            .unwrap_or_else(|| panic!("no {needle:?} on screen"))
    }

    /// G0.3d: a changed certificate, PuTTY style. Both fingerprints and the
    /// date on screen; Enter cancels; Connect once pins without trusting;
    /// Trust and update remembers.
    #[test]
    fn a_changed_certificate_asks_with_cancel_as_the_default() {
        let ctx = egui::Context::default();
        let mut s = ConnectScreen::new(Vec::new());
        let mut t = 0.0;
        let creds = Credentials {
            address: "tls://10.0.0.1:8729".into(),
            user: "admin".into(),
            ..Credentials::default()
        };
        let ask = |s: &mut ConnectScreen, t: &mut f64| {
            s.ask_changed(
                creds.clone(),
                "SHA256:OL:DD".into(),
                "2026-10-01 12:00 UTC".into(),
                "SHA256:NE:WW".into(),
            );
            frame(&ctx, s, &[], Vec::new(), t);
            frame(&ctx, s, &[], Vec::new(), t).1
        };
        let texts = ask(&mut s, &mut t);
        for needle in [
            "Router certificate CHANGED",
            "SHA256:OL:DD",
            "SHA256:NE:WW",
            "accepted 2026-10-01 12:00 UTC",
            "Cancel",
            "Connect once",
            "Trust and update",
        ] {
            assert!(
                texts.iter().any(|(x, _)| x == needle),
                "{needle}: {texts:?}"
            );
        }
        // Enter never accepts.
        let enter = vec![egui::Event::Key {
            key: Key::Enter,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        }];
        let (a, _) = frame(&ctx, &mut s, &[], enter, &mut t);
        assert_eq!(a, None);
        assert!(!s.asking_trust(), "Enter cancelled");
        assert!(s.message.as_ref().is_some_and(|m| !m.ok));
        // Connect once: the new fingerprint only for this connection.
        let texts = ask(&mut s, &mut t);
        let mut a = frame(
            &ctx,
            &mut s,
            &[],
            click_events(at(&texts, "Connect once")),
            &mut t,
        )
        .0;
        a = a.or(frame(&ctx, &mut s, &[], Vec::new(), &mut t).0);
        let Some(ConnectAction::Once(c)) = a else {
            panic!("{a:?}")
        };
        assert_eq!(c.pin.as_deref(), Some("SHA256:NE:WW"));
        assert_eq!(c.address, creds.address);
        // Trust and update: remembered by the app.
        let texts = ask(&mut s, &mut t);
        let mut a = frame(
            &ctx,
            &mut s,
            &[],
            click_events(at(&texts, "Trust and update")),
            &mut t,
        )
        .0;
        a = a.or(frame(&ctx, &mut s, &[], Vec::new(), &mut t).0);
        assert_eq!(
            a,
            Some(ConnectAction::Trust {
                creds: creds.clone(),
                fingerprint: "SHA256:NE:WW".into(),
                forget_password: false,
            })
        );
        // The first use offers the same three answers.
        s.ask_trust(creds.clone(), "SHA256:FI:RS".into());
        frame(&ctx, &mut s, &[], Vec::new(), &mut t);
        let texts = frame(&ctx, &mut s, &[], Vec::new(), &mut t).1;
        for needle in [
            "Unknown router certificate",
            "Cancel",
            "Connect once",
            "Trust and connect",
        ] {
            assert!(texts.iter().any(|(x, _)| x == needle), "{needle}");
        }
        for langs in [
            Langs::default(),
            Langs {
                help: crate::i18n::Lang::En,
                ..Langs::default()
            },
        ] {
            assert!(crate::i18n::explain(langs, HELP_CERT).is_some());
        }
    }

    #[test]
    fn fingerprints_break_in_two_halves() {
        let fp = format!("SHA256:{}", vec!["AB"; 32].join(":"));
        let two = fingerprint_lines(&fp);
        let (a, b) = two.split_once('\n').unwrap();
        assert_eq!((a.matches(':').count(), b.matches(':').count()), (17, 15));
        assert_eq!(two.replace('\n', ""), fp);
        assert_eq!(fingerprint_lines("SHA256:AA:BB"), "SHA256:AA:BB");
    }

    #[test]
    fn double_click_on_a_neighbor_fills_connect_to_and_connects() {
        let ctx = egui::Context::default();
        let mut s = ConnectScreen::new(Vec::new());
        let rows = [neighbor("a", Some("127.0.0.1:7979")), neighbor("bb", None)];
        let mut t = 0.0;
        let (_, texts) = frame(&ctx, &mut s, &rows, Vec::new(), &mut t);
        assert!(texts.iter().any(|(x, _)| x == "Neighbors (2)"));
        let row = at(&texts, "r-a");
        // Single click fills only.
        let (a, _) = frame(&ctx, &mut s, &rows, click_events(row), &mut t);
        assert_eq!(a, None);
        assert_eq!(s.connect_to, "127.0.0.1:7979");
        s.connect_to.clear();
        // Double click fills and connects.
        let mut both = click_events(row);
        both.extend(click_events(row));
        let mut action = frame(&ctx, &mut s, &rows, both, &mut t).0;
        for _ in 0..2 {
            action = action.or(frame(&ctx, &mut s, &rows, Vec::new(), &mut t).0);
        }
        assert_eq!(action, Some(conn("127.0.0.1:7979")));
        // A neighbor without a management port explains itself.
        let (_, texts) = frame(&ctx, &mut s, &rows, Vec::new(), &mut t);
        let (a, _) = frame(
            &ctx,
            &mut s,
            &rows,
            click_events(at(&texts, "r-bb")),
            &mut t,
        );
        assert_eq!(a, None);
        assert!(
            matches!(&s.message, Some(Message { ok: false, failure, .. }) if failure.text.contains("no CoreRouter management port"))
        );
    }

    #[test]
    fn a_remote_neighbor_explains_instead_of_connecting() {
        let ctx = egui::Context::default();
        let mut s = ConnectScreen::new(Vec::new());
        let mut far = neighbor("far", Some("10.0.0.3:7979"));
        far.remote = true;
        let rows = [neighbor("a", Some("127.0.0.1:7979")), far];
        let mut t = 0.0;
        let (_, texts) = frame(&ctx, &mut s, &rows, Vec::new(), &mut t);
        assert!(
            texts
                .iter()
                .any(|(x, _)| x.starts_with("Greyed out: on another"))
        );
        // Double click: filled, explained, no connection attempt.
        let row = at(&texts, "r-far");
        let mut both = click_events(row);
        both.extend(click_events(row));
        let mut action = frame(&ctx, &mut s, &rows, both, &mut t).0;
        for _ in 0..2 {
            action = action.or(frame(&ctx, &mut s, &rows, Vec::new(), &mut t).0);
        }
        assert_eq!(action, None);
        assert_eq!(s.connect_to, "10.0.0.3:7979");
        assert!(
            matches!(&s.message, Some(Message { ok: false, failure, .. }) if failure.text.contains("no TLS management port"))
        );
        // The operator may still try it by hand.
        let (_, texts) = frame(&ctx, &mut s, &rows, Vec::new(), &mut t);
        let mut action = frame(
            &ctx,
            &mut s,
            &rows,
            click_events(at(&texts, "Connect")),
            &mut t,
        )
        .0;
        action = action.or(frame(&ctx, &mut s, &rows, Vec::new(), &mut t).0);
        assert_eq!(action, Some(conn("10.0.0.3:7979")));
        // Without remote neighbors there is no hint.
        let (_, texts) = frame(&ctx, &mut s, &rows[..1], Vec::new(), &mut t);
        assert!(!texts.iter().any(|(x, _)| x.starts_with("Greyed out")));
    }

    #[test]
    fn save_to_list_keeps_no_password_and_round_trips() {
        let ctx = egui::Context::default();
        let mut s = ConnectScreen::new(Vec::new());
        s.connect_to = "10.0.0.1:7979".into();
        s.group = "pop-1".into();
        s.comment = "edge".into();
        s.password = "secret".into();
        let mut t = 0.0;
        let (_, texts) = frame(&ctx, &mut s, &[], Vec::new(), &mut t);
        frame(
            &ctx,
            &mut s,
            &[],
            click_events(at(&texts, "Save to list")),
            &mut t,
        );
        let saved = s.take_saved_change().expect("changed");
        assert_eq!(
            saved,
            [SavedRouter {
                address: "10.0.0.1:7979".into(),
                group: "pop-1".into(),
                comment: "edge".into(),
                user: DEFAULT_LOGIN.into(),
            }]
        );
        assert!(s.take_saved_change().is_none(), "reported once");
        let json = SavedRouter::list_to_json(&saved);
        assert!(!json.to_string().contains("secret"));
        assert_eq!(SavedRouter::list_from_json(&json), saved);
        // Hostile files: wrong shapes are skipped, sizes bounded.
        let junk = json!([{"address": "x".repeat(10_000)}, 5, {"group": "no address"}]);
        let back = SavedRouter::list_from_json(&junk);
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].address.len(), MAX_FIELD);
        // The Saved tab is now shown; a click there fills the form.
        s.connect_to.clear();
        s.group.clear();
        let (_, texts) = frame(&ctx, &mut s, &[], Vec::new(), &mut t);
        frame(&ctx, &mut s, &[], click_events(at(&texts, "pop-1")), &mut t);
        assert_eq!(
            (s.connect_to.as_str(), s.group.as_str()),
            ("10.0.0.1:7979", "pop-1")
        );
    }

    #[test]
    fn login_comes_filled_with_admin() {
        let ctx = egui::Context::default();
        let mut s = ConnectScreen::new(Vec::new());
        s.connect_to = "127.0.0.1:7979".into();
        let mut t = 0.0;
        let (_, texts) = frame(&ctx, &mut s, &[], Vec::new(), &mut t);
        // A value, not a placeholder: it goes with Connect.
        assert!(texts.iter().any(|(x, _)| x == "admin"));
        let mut a = frame(
            &ctx,
            &mut s,
            &[],
            click_events(at(&texts, "Connect")),
            &mut t,
        )
        .0;
        a = a.or(frame(&ctx, &mut s, &[], Vec::new(), &mut t).0);
        assert_eq!(a, Some(conn("127.0.0.1:7979")));
        // A list saved before G0.3c (no user) picks admin too.
        let mut s = ConnectScreen::new(vec![SavedRouter {
            address: "127.0.0.1:7980".into(),
            group: "lab".into(),
            ..SavedRouter::default()
        }]);
        s.login = "op".into();
        s.tab = Tab::Saved;
        let (_, texts) = frame(&ctx, &mut s, &[], Vec::new(), &mut t);
        frame(&ctx, &mut s, &[], click_events(at(&texts, "lab")), &mut t);
        assert_eq!(s.login, DEFAULT_LOGIN);
    }

    #[test]
    fn a_failure_shows_one_sentence_and_the_details_on_demand() {
        let ctx = egui::Context::default();
        let mut s = ConnectScreen::new(Vec::new());
        s.connect_to = "127.0.0.1:7979".into();
        let detail = "127.0.0.1:7979: no local token readable at /run/user/1/x.token";
        s.fail(Failure::new(BAD_LOGIN, detail));
        let mut t = 0.0;
        let (_, texts) = frame(&ctx, &mut s, &[], Vec::new(), &mut t);
        assert!(texts.iter().any(|(x, _)| x == BAD_LOGIN));
        assert!(
            !texts
                .iter()
                .any(|(x, _)| x.contains("local token readable"))
        );
        assert!(!texts.iter().any(|(x, _)| x == "Connect anyway"));
        frame(
            &ctx,
            &mut s,
            &[],
            click_events(at(&texts, "Details")),
            &mut t,
        );
        let mut texts = Vec::new();
        for _ in 0..10 {
            texts = frame(&ctx, &mut s, &[], Vec::new(), &mut t).1;
        }
        assert!(texts.iter().any(|(x, _)| x == detail), "{texts:?}");
        // The router's words become a sentence; unknown ones stay.
        let f = explain("127.0.0.1:7979: unknown method 'auth.whoami'; methods: ping");
        assert_eq!(f.text, OLD_ROUTER);
        assert!(f.detail.contains("unknown method"));
        assert_eq!(explain("odd").text, "odd");
        assert!(explain(&"x".repeat(5000)).text.len() <= MAX_ERROR);
    }

    #[test]
    fn an_old_router_offers_connect_anyway() {
        assert!(old_router_info(
            &json!({"name": "corerouter", "version": "0.1.0"})
        ));
        assert!(!old_router_info(
            &json!({"version": "0.1.0", "auth": "required"})
        ));
        assert!(!old_router_info(&Value::Null));
        let ctx = egui::Context::default();
        let mut s = ConnectScreen::new(Vec::new());
        s.connect_to = "127.0.0.1:7979".into();
        s.fail(Failure {
            text: OLD_ROUTER.into(),
            detail: "corerouter-daemon 0.1.0".into(),
            offer_anyway: true,
        });
        let mut t = 0.0;
        let (_, texts) = frame(&ctx, &mut s, &[], Vec::new(), &mut t);
        assert!(
            texts
                .iter()
                .any(|(x, _)| x.starts_with("This router runs an old version"))
        );
        let mut a = frame(
            &ctx,
            &mut s,
            &[],
            click_events(at(&texts, "Connect anyway")),
            &mut t,
        )
        .0;
        a = a.or(frame(&ctx, &mut s, &[], Vec::new(), &mut t).0);
        let Some(ConnectAction::Connect(c)) = a else {
            panic!("{a:?}")
        };
        assert!(c.legacy);
        assert_eq!(c.address, "127.0.0.1:7979");
        // A plain Connect never is.
        assert!(!s.credentials().legacy);
    }

    #[test]
    fn empty_connect_to_is_refused_and_lab_is_offered() {
        let ctx = egui::Context::default();
        let mut s = ConnectScreen::new(Vec::new());
        let mut t = 0.0;
        let (_, texts) = frame(&ctx, &mut s, &[], Vec::new(), &mut t);
        let (a, _) = frame(
            &ctx,
            &mut s,
            &[],
            click_events(at(&texts, "Connect")),
            &mut t,
        );
        assert_eq!(a, None);
        assert!(matches!(&s.message, Some(Message { ok: false, .. })));
        let (a, _) = frame(
            &ctx,
            &mut s,
            &[],
            click_events(at(&texts, "Virtual lab")),
            &mut t,
        );
        assert_eq!(a, Some(ConnectAction::VirtualLab));
    }

    /// The app's side of G0.3e: answer the screen from a fake store.
    fn answer(s: &mut ConnectScreen, store: &[(&str, &str, &str)]) {
        if let Some((address, user)) = s.wants_saved_password() {
            let pw = store
                .iter()
                .find(|(a, u, _)| *a == address && *u == user)
                .map(|(_, _, p)| (*p).to_owned());
            s.set_saved_password(&address, &user, pw);
        }
    }

    fn has(texts: &[(String, egui::Rect)], needle: &str) -> bool {
        texts.iter().any(|(x, _)| x == needle)
    }

    const STORE: &[(&str, &str, &str)] = &[("10.0.0.1:8729", "admin", "old-vm-pw")];

    /// G0.3e: the saved password is shown (masked, with its pill), never
    /// used behind the field; clearing the field sends an empty password.
    #[test]
    fn a_saved_password_is_shown_and_an_empty_field_sends_none() {
        let ctx = egui::Context::default();
        let mut s = ConnectScreen::new(Vec::new());
        let mut t = 0.0;
        // No store: nothing asked.
        s.connect_to = "10.0.0.1:8729".into();
        assert_eq!(s.wants_saved_password(), None);
        s.set_keyring(Ok("the system keyring".into()));
        answer(&mut s, STORE);
        assert_eq!(s.password, "old-vm-pw");
        assert!(s.remember, "a saved password is a remembered one");
        // Asked once per pair.
        assert_eq!(s.wants_saved_password(), None);
        let c = s.credentials();
        assert!(c.saved && c.password == "old-vm-pw");
        assert!(!format!("{c:?}").contains("old-vm-pw"));
        frame(&ctx, &mut s, &[], Vec::new(), &mut t);
        let texts = frame(&ctx, &mut s, &[], Vec::new(), &mut t).1;
        assert!(has(&texts, "saved password"), "{texts:?}");
        assert!(has(&texts, "Forget"));
        assert!(
            !texts.iter().any(|(x, _)| x.contains("old-vm-pw")),
            "masked"
        );
        // Cleared: an empty password, said so by the pill.
        s.password.clear();
        let c = s.credentials();
        assert!(!c.saved && c.password.is_empty());
        let texts = frame(&ctx, &mut s, &[], Vec::new(), &mut t).1;
        assert!(has(&texts, "saved password unused"), "{texts:?}");
        // Another router: no pill, an empty field stays empty.
        s.connect_to = "10.0.0.2:8729".into();
        answer(&mut s, STORE);
        assert!(s.password.is_empty());
        let texts = frame(&ctx, &mut s, &[], Vec::new(), &mut t).1;
        assert!(!has(&texts, "saved password") && !has(&texts, "saved password unused"));
        // Back: filled again; then to another router the filled one goes.
        s.connect_to = "10.0.0.1:8729".into();
        answer(&mut s, STORE);
        assert_eq!(s.password, "old-vm-pw");
        s.connect_to = "10.0.0.1:87".into();
        answer(&mut s, STORE);
        assert!(s.password.is_empty(), "never sent to another router");
        // A typed password is never replaced.
        s.password = "typed".into();
        s.connect_to = "10.0.0.1:8729".into();
        answer(&mut s, STORE);
        assert_eq!(s.password, "typed");
        assert!(!s.credentials().saved);
        // A late answer for another pair is ignored.
        s.set_saved_password("10.0.0.9:8729", "admin", Some("x".into()));
        assert_eq!(s.password, "typed");
        // Login is part of the pair.
        s.password.clear();
        s.login = "op".into();
        answer(&mut s, STORE);
        assert!(s.password.is_empty());
    }

    /// G0.3e: the saved password refused says so and offers Forget; the
    /// pill's Forget empties the field.
    #[test]
    fn a_refused_saved_password_offers_to_forget_it() {
        let ctx = egui::Context::default();
        let mut s = ConnectScreen::new(Vec::new());
        let mut t = 0.0;
        s.set_keyring(Ok("the system keyring".into()));
        s.connect_to = "10.0.0.1:8729".into();
        answer(&mut s, STORE);
        let texts = frame(&ctx, &mut s, &[], Vec::new(), &mut t).1;
        let mut a = frame(
            &ctx,
            &mut s,
            &[],
            click_events(at(&texts, "Connect")),
            &mut t,
        )
        .0;
        a = a.or(frame(&ctx, &mut s, &[], Vec::new(), &mut t).0);
        let Some(ConnectAction::Connect(c)) = a else {
            panic!("{a:?}")
        };
        assert!(c.saved);
        s.fail(Failure::new(BAD_LOGIN, "invalid user or password"));
        assert_eq!(
            s.message.as_ref().map(|m| m.failure.text.as_str()),
            Some(SAVED_FAILED)
        );
        frame(&ctx, &mut s, &[], Vec::new(), &mut t);
        let texts = frame(&ctx, &mut s, &[], Vec::new(), &mut t).1;
        assert!(has(&texts, SAVED_FAILED), "{texts:?}");
        // Two Forget buttons (the pill's and the message's): the message's.
        let mut a = frame(
            &ctx,
            &mut s,
            &[],
            click_events(at(&texts, "Forget saved password")),
            &mut t,
        )
        .0;
        a = a.or(frame(&ctx, &mut s, &[], Vec::new(), &mut t).0);
        assert_eq!(
            a,
            Some(ConnectAction::ForgetPassword {
                address: "10.0.0.1:8729".into(),
                user: "admin".into()
            })
        );
        assert!(s.password.is_empty());
        let texts = frame(&ctx, &mut s, &[], Vec::new(), &mut t).1;
        assert!(!has(&texts, "saved password") && !has(&texts, "Forget"));
        // A typed password refused is the usual sentence.
        s.password = "typed".into();
        let c = s.connect_now();
        assert!(!c.saved);
        s.fail(Failure::new(BAD_LOGIN, ""));
        assert_eq!(
            s.message.as_ref().map(|m| m.failure.text.as_str()),
            Some(BAD_LOGIN)
        );
        // The pill's Forget.
        s.password.clear();
        s.asked = None;
        answer(&mut s, STORE);
        s.message = None;
        let texts = frame(&ctx, &mut s, &[], Vec::new(), &mut t).1;
        let a = frame(
            &ctx,
            &mut s,
            &[],
            click_events(at(&texts, "Forget")),
            &mut t,
        )
        .0;
        assert!(
            matches!(a, Some(ConnectAction::ForgetPassword { .. })),
            "{a:?}"
        );
        assert!(s.password.is_empty());
        for langs in [
            Langs::default(),
            Langs {
                help: crate::i18n::Lang::En,
                ..Langs::default()
            },
        ] {
            assert!(crate::i18n::explain(langs, HELP_SAVED).is_some());
        }
    }

    /// G0.3e: Trust and update on a changed certificate also forgets the
    /// saved password (ticked by default) and connects without it.
    #[test]
    fn trust_and_update_offers_to_forget_the_saved_password() {
        let ctx = egui::Context::default();
        let mut s = ConnectScreen::new(Vec::new());
        let mut t = 0.0;
        s.set_keyring(Ok("the system keyring".into()));
        s.connect_to = "10.0.0.1:8729".into();
        answer(&mut s, STORE);
        let creds = s.connect_now();
        let ask = |s: &mut ConnectScreen, t: &mut f64| {
            s.ask_changed(
                creds.clone(),
                "SHA256:OL:DD".into(),
                "2026-10-01".into(),
                "SHA256:NE:WW".into(),
            );
            frame(&ctx, s, &[], Vec::new(), t);
            frame(&ctx, s, &[], Vec::new(), t).1
        };
        let texts = ask(&mut s, &mut t);
        assert!(
            has(&texts, "Also forget the saved password of admin"),
            "{texts:?}"
        );
        let mut a = frame(
            &ctx,
            &mut s,
            &[],
            click_events(at(&texts, "Trust and update")),
            &mut t,
        )
        .0;
        a = a.or(frame(&ctx, &mut s, &[], Vec::new(), &mut t).0);
        let Some(ConnectAction::Trust {
            creds: c,
            forget_password,
            ..
        }) = a
        else {
            panic!("{a:?}")
        };
        assert!(forget_password);
        assert!(c.password.is_empty() && !c.saved);
        assert!(s.password.is_empty());
        // Unticked: the saved password stays and goes with the login.
        s.asked = None;
        answer(&mut s, STORE);
        let texts = ask(&mut s, &mut t);
        frame(
            &ctx,
            &mut s,
            &[],
            click_events(at(&texts, "Also forget the saved password of admin")),
            &mut t,
        );
        let mut a = frame(
            &ctx,
            &mut s,
            &[],
            click_events(at(&texts, "Trust and update")),
            &mut t,
        )
        .0;
        a = a.or(frame(&ctx, &mut s, &[], Vec::new(), &mut t).0);
        let Some(ConnectAction::Trust {
            creds: c,
            forget_password,
            ..
        }) = a
        else {
            panic!("{a:?}")
        };
        assert!(!forget_password);
        assert_eq!(c.password, "old-vm-pw");
        // Nothing saved: no question.
        s.ask_trust(
            Credentials {
                address: "10.0.0.5:8729".into(),
                ..creds.clone()
            },
            "SHA256:X".into(),
        );
        frame(&ctx, &mut s, &[], Vec::new(), &mut t);
        let texts = frame(&ctx, &mut s, &[], Vec::new(), &mut t).1;
        assert!(!texts.iter().any(|(x, _)| x.starts_with("Also forget")));
    }

    /// G0.3e: a neighbor picked with a double click connects only after its
    /// saved password is in the field; Connect to's example reads as one.
    #[test]
    fn a_picked_router_connects_after_its_saved_password_is_shown() {
        let ctx = egui::Context::default();
        let mut s = ConnectScreen::new(Vec::new());
        let mut t = 0.0;
        let texts = frame(&ctx, &mut s, &[], Vec::new(), &mut t).1;
        assert!(has(&texts, CONNECT_TO_HINT), "{texts:?}");
        s.set_keyring(Ok("the system keyring".into()));
        let rows = [neighbor("a", Some("10.0.0.1:8729"))];
        let texts = frame(&ctx, &mut s, &rows, Vec::new(), &mut t).1;
        let row = at(&texts, "r-a");
        let mut both = click_events(row);
        both.extend(click_events(row));
        let mut action = frame(&ctx, &mut s, &rows, both, &mut t).0;
        assert_eq!(action, None, "not before the lookup");
        answer(&mut s, STORE);
        for _ in 0..2 {
            action = action.or(frame(&ctx, &mut s, &rows, Vec::new(), &mut t).0);
        }
        let Some(ConnectAction::Connect(c)) = action else {
            panic!("{action:?}")
        };
        assert_eq!(
            (c.address.as_str(), c.password.as_str(), c.saved),
            ("10.0.0.1:8729", "old-vm-pw", true)
        );
    }
}
