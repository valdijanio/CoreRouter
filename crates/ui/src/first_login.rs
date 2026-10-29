//! First login without a password (G0.3b, G0.3d), as in RouterOS 7: right
//! after the GUI connects, an account of group full that has no password
//! (the first `admin`) is asked to set one, with "Not now" to skip; and the
//! top bar keeps an amber chip with "Set password" and the ⓘ until it has
//! one. As on a CHR the router takes the empty password from the network
//! meanwhile (G0.3d): keeping it so is the operator's choice, so the GUI
//! warns on every connection and never forces it.
//!
//! What the router says is all the UI knows: `auth.whoami` lists the
//! accounts of group full without a password (`no_password`, only for a
//! caller of group full). Setting it is the normal `user.set {name,
//! password}` through the engine; the router checks the length. The only
//! rule here is that the two fields match.

use egui::{Key, RichText, TextEdit};
use serde_json::{Value, json};

use crate::help::{self, HelpView};
use crate::i18n::tr_in;
use crate::{CoreRouterUi, Then, chip};

/// Translation scope (`i18n/auto/first_login_*.rs`).
const SCOPE: &str = "first_login";
/// The explanation the ⓘ opens.
pub(crate) const HELP_KEY: &str = "first_login.no_password";

/// The dialog's state (UI-local; the password lives only while typed).
#[derive(Default)]
pub(crate) struct PasswordAsk {
    /// Shown once per connection by itself; later only from the top bar.
    shown: bool,
    open: bool,
    user: String,
    password: String,
    again: String,
    error: Option<String>,
    /// `user.set` sent, its answer not in yet.
    sending: bool,
    /// Put the cursor in the first field (when the dialog opens).
    focus: bool,
    /// The ⓘ's explanation, while open.
    help: Option<HelpView>,
}

impl CoreRouterUi {
    /// The account to ask for: the logged-in one if it has no password,
    /// else the first of group full without one; `None` when all have one.
    pub fn no_password_user(&self) -> Option<String> {
        // Disconnected: what whoami said may be stale (the password may
        // have been set elsewhere, which ended this session).
        if matches!(self.link, crate::Link::Disconnected { .. }) {
            return None;
        }
        let me = &self.cache.whoami;
        let missing: Vec<&str> = me
            .get("no_password")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let mine = me.get("user").and_then(Value::as_str);
        missing
            .iter()
            .find(|u| Some(**u) == mine)
            .or(missing.first())
            .map(|u| u.chars().take(64).collect())
    }

    /// The "Set a password" dialog is open.
    pub fn password_dialog_open(&self) -> bool {
        self.password_ask.open
    }

    /// Open the dialog for the account without a password (the top bar's
    /// warning does this).
    pub fn open_password_dialog(&mut self) {
        if let Some(user) = self.no_password_user() {
            let a = &mut self.password_ask;
            a.user = user;
            a.open = true;
            a.focus = true;
            a.error = None;
        }
    }

    /// "Not now": close and forget what was typed; the warning stays.
    pub fn password_not_now(&mut self) {
        let a = &mut self.password_ask;
        a.open = false;
        a.password.clear();
        a.again.clear();
        a.error = None;
    }

    /// "Set password" with the two fields as typed.
    pub fn password_submit(&mut self, password: &str, again: &str) {
        let a = &mut self.password_ask;
        a.password = password.to_owned();
        a.again = again.to_owned();
        self.password_send();
    }

    /// Open the dialog by itself the first time the router reports an
    /// account without a password; close it if that changed elsewhere.
    pub(crate) fn first_login_tick(&mut self) {
        match self.no_password_user() {
            Some(user) if !self.password_ask.shown => {
                self.password_ask.shown = true;
                self.password_ask.user = user;
                self.password_ask.open = true;
                self.password_ask.focus = true;
            }
            None if self.password_ask.open && !self.password_ask.sending => {
                self.password_not_now();
            }
            _ => {}
        }
    }

    fn password_send(&mut self) {
        let a = &mut self.password_ask;
        if a.sending {
            return;
        }
        if a.password.is_empty() {
            a.error = Some("Type a password (or Not now)".into());
            return;
        }
        if a.password != a.again {
            a.error = Some("The two passwords differ".into());
            return;
        }
        a.error = None;
        a.sending = true;
        let params = json!({"name": a.user, "password": a.password});
        self.run_then("user.set", params, Then::Password);
    }

    /// The answer to the dialog's `user.set`.
    pub(crate) fn password_reply(&mut self, result: &Result<Value, String>) {
        let a = &mut self.password_ask;
        a.sending = false;
        match result {
            Ok(_) => {
                let user = std::mem::take(&mut a.user);
                self.password_not_now();
                // Hide the warning now; the next whoami confirms it.
                if let Some(list) = self
                    .cache
                    .whoami
                    .get_mut("no_password")
                    .and_then(Value::as_array_mut)
                {
                    list.retain(|u| u.as_str() != Some(user.as_str()));
                }
            }
            Err(e) => a.error = Some(e.chars().take(300).collect()),
        }
    }

    /// The top bar's warning while an account of group full has no
    /// password: an amber chip, "Set password" and the ⓘ, on every
    /// connection until it has one (G0.3d).
    pub(crate) fn no_password_warning(&mut self, ui: &mut egui::Ui) {
        let Some(user) = self.no_password_user() else {
            return;
        };
        let l = self.lang.labels;
        let tone = chip::Kind::Amber.tone(ui.visuals());
        let text = format!("{} {user}: {}", crate::icons::LOCK_SIMPLE, tr_in(SCOPE, l, "no password"));
        chip::chip(ui, &text, tone).on_hover_text(tr_in(
            SCOPE,
            l,
            "Anyone who reaches the router, from this machine or the network, logs in as \
             this user with an empty password.",
        ));
        if ui.small_button(tr_in(SCOPE, l, "Set password")).clicked() {
            self.open_password_dialog();
        }
        if help::info_button(ui, egui::Id::unique("first-login-no-password-info"), tr_in(SCOPE, l, "Why this matters"))
            .clicked()
        {
            self.password_ask.help = Some(HelpView::new(HELP_KEY, tr_in(SCOPE, l, "Account without a password")));
        }
        ui.separator();
    }

    pub(crate) fn password_window(&mut self, ctx: &egui::Context) {
        help::modal(ctx, self.lang, &mut self.password_ask.help);
        if !self.password_ask.open {
            return;
        }
        let l = self.lang.labels;
        let mut set = false;
        let mut later = false;
        let a = &mut self.password_ask;
        egui::Window::new("First login")
            .id(egui::Id::unique("corerouter-first-password"))
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(RichText::new(format!("Set a password for {}", a.user)).strong());
                ui.add_space(4.0);
                ui.weak(tr_in(
                    SCOPE,
                    l,
                    "This account has no password: anyone who reaches the router, from this \
                     machine or the network, logs in with an empty password. You can keep it \
                     so (Not now); the warning stays in the top bar until it has one.",
                ));
                ui.add_space(8.0);
                let mut enter = false;
                egui::Grid::new("first-password-grid")
                    .num_columns(2)
                    .show(ui, |ui| {
                        ui.label("New password");
                        let r = ui.add(TextEdit::singleline(&mut a.password).password(true));
                        if std::mem::take(&mut a.focus) {
                            r.request_focus();
                        }
                        ui.end_row();
                        ui.label("Repeat");
                        let r = ui.add(TextEdit::singleline(&mut a.again).password(true));
                        enter = r.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                        ui.end_row();
                    });
                if let Some(e) = &a.error {
                    ui.colored_label(ui.visuals().error_fg_color, e.as_str());
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    let label = RichText::new("Set password").strong();
                    if ui
                        .add_enabled(!a.sending, egui::Button::new(label))
                        .clicked()
                        || enter
                    {
                        set = true;
                    }
                    if ui.button("Not now").clicked() || ui.input(|i| i.key_pressed(Key::Escape)) {
                        later = true;
                    }
                });
            });
        if later {
            self.password_not_now();
        } else if set {
            self.password_send();
        }
    }
}

#[cfg(test)]
mod tests {
    use corerouter_engine::{Session, lock, shared};

    use super::*;

    fn painted(
        app: &mut CoreRouterUi,
        ctx: &egui::Context,
        events: Vec<egui::Event>,
    ) -> Vec<(String, egui::Rect)> {
        let raw = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1400.0, 800.0),
            )),
            events,
            ..Default::default()
        };
        let mut out = ctx.run_ui(raw, |ui| app.ui(ui));
        out.textures_delta.clear();
        fn walk(s: &egui::Shape, out: &mut Vec<(String, egui::Rect)>) {
            match s {
                egui::Shape::Text(t) => {
                    out.push((t.galley.text().to_owned(), t.visual_bounding_rect()))
                }
                egui::Shape::Vec(v) => v.iter().for_each(|s| walk(s, out)),
                _ => {}
            }
        }
        let mut texts = Vec::new();
        for c in &out.shapes {
            walk(&c.shape, &mut texts);
        }
        texts
    }

    fn click(texts: &[(String, egui::Rect)], needle: &str) -> Vec<egui::Event> {
        let pos = texts
            .iter()
            .rev()
            .find(|(t, _)| t == needle)
            .map(|(_, r)| r.center())
            .unwrap_or_else(|| panic!("no {needle:?} on screen: {texts:?}"));
        let ev = |pressed| egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: egui::Modifiers::NONE,
        };
        vec![egui::Event::PointerMoved(pos), ev(true), ev(false)]
    }

    fn has(texts: &[(String, egui::Rect)], needle: &str) -> bool {
        texts.iter().any(|(t, _)| t.contains(needle))
    }

    #[test]
    fn first_login_asks_not_now_works_and_the_warning_goes_once_set() {
        let session = shared(Session::virtual_lab());
        lock(&session).bootstrap_admin(false);
        let mut app = CoreRouterUi::new(session.clone());
        let ctx = egui::Context::default();
        let mut texts = Vec::new();
        for _ in 0..3 {
            texts = painted(&mut app, &ctx, Vec::new());
        }
        assert!(app.password_dialog_open(), "asked right after the login");
        assert!(has(&texts, "Set a password for admin"), "{texts:?}");
        assert!(has(&texts, "admin: no password"));

        // "Not now" (a real click): closed, the warning stays.
        painted(&mut app, &ctx, click(&texts, "Not now"));
        let texts = painted(&mut app, &ctx, Vec::new());
        assert!(!app.password_dialog_open());
        assert!(!has(&texts, "Set a password for admin"));
        assert!(has(&texts, "admin: no password"), "the warning stays (G0.3d)");
        assert!(has(&texts, "Set password"));
        // The ⓘ has its explanation in both languages.
        for langs in [crate::i18n::Langs::default(), crate::i18n::Langs { help: crate::i18n::Lang::En, ..Default::default() }] {
            let (_, text) = crate::i18n::explain(langs, HELP_KEY).unwrap();
            assert!(text.contains("CHR"), "{text}");
        }
        // It does not come back by itself on the next refresh.
        app.cache.refreshed_at = None;
        let texts = painted(&mut app, &ctx, Vec::new());
        assert!(!app.password_dialog_open());

        // "Set password" in the top bar opens it again.
        painted(&mut app, &ctx, click(&texts, "Set password"));
        assert!(app.password_dialog_open());
        // Mismatch and too short: told, nothing changes.
        app.password_submit("first-password", "other");
        assert!(
            app.password_ask
                .error
                .as_deref()
                .unwrap()
                .contains("differ")
        );
        app.password_submit("short", "short");
        app.pump();
        assert!(
            app.password_ask
                .error
                .as_deref()
                .unwrap()
                .contains("at least")
        );
        assert!(lock(&session).has_no_password("admin"));
        // Set: through user.set; the dialog and the warning go.
        app.password_submit("first-password", "first-password");
        app.pump();
        assert!(!app.password_dialog_open());
        assert!(app.no_password_user().is_none());
        assert!(lock(&session).password_hash("admin").is_some());
        app.cache.refreshed_at = None;
        let texts = painted(&mut app, &ctx, Vec::new());
        assert!(!has(&texts, "no password"), "{texts:?}");
        assert!(app.password_ask.password.is_empty(), "nothing kept");
    }

    #[test]
    fn the_terminal_window_asks_too_and_hides_the_password() {
        let session = shared(Session::virtual_lab());
        lock(&session).bootstrap_admin(false);
        let mut app = CoreRouterUi::new(session.clone());
        let settle = |app: &mut CoreRouterUi| {
            for _ in 0..6 {
                app.pump();
            }
        };
        app.new_terminal();
        settle(&mut app);
        let text = app.terminal_text(0);
        assert!(text.contains("User admin has no password"), "{text}");
        app.terminal_submit(0, "");
        settle(&mut app);
        assert!(app.terminal_text(0).contains("Not now"));
        // A new terminal asks again; the typed passwords are never shown.
        app.new_terminal();
        settle(&mut app);
        app.terminal_submit(1, "terminal-password");
        settle(&mut app);
        app.terminal_submit(1, "terminal-password");
        settle(&mut app);
        let text = app.terminal_text(1);
        assert!(text.contains("Password set for admin"), "{text}");
        assert!(!text.contains("terminal-password"), "{text}");
        assert!(!lock(&session).has_no_password("admin"));
    }

    #[test]
    fn a_router_with_passwords_asks_nothing() {
        let session = shared(Session::virtual_lab());
        let mut app = CoreRouterUi::new(session);
        let ctx = egui::Context::default();
        let mut texts = Vec::new();
        for _ in 0..3 {
            texts = painted(&mut app, &ctx, Vec::new());
        }
        assert!(!app.password_dialog_open());
        assert!(!has(&texts, "has no password"));
    }
}
