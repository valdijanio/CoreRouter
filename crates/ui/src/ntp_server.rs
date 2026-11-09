//! The System › NTP Server window (G4.6c), WinBox `/system ntp server` style:
//! one settings form with Apply, and under it the server's state, refreshed
//! live: whose time it gives, stratum and the counters.
//!
//! The engine validates (`system.ntp.server.set`) and keeps the state
//! (`system.ntp.server.get`); the window only shows and sends.

use egui::{Grid, Id, TextEdit, Ui};
use serde_json::{Map, Value, json};

use crate::backend::RequestId;
use crate::dhcp_client::{flag, text};
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr_in};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::action;
use crate::{CoreRouterUi, Win, form_number};

const NAME: &str = "ntp-server";
/// The window's id (`Win::Panel`).
pub(crate) const WIN: &str = "ntp-server";
const SET: &str = "system.ntp.server.set";
const GET: &str = "system.ntp.server.get";
const SCOPE: &str = "ntp";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "System",
        title: "NTP Server",
        size: [500.0, 600.0],
        escape: false,
    }],
    new: || Box::new(NtpServerPanel::default()),
};

#[derive(Default)]
pub(crate) struct NtpServerPanel {
    pub(crate) state: Option<Value>,
    pub(crate) form: ServerForm,
    base: ServerForm,
    waiting: usize,
    pub(crate) error: Option<String>,
    help: Option<HelpView>,
}

/// The editable settings, as typed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ServerForm {
    pub enabled: bool,
    pub broadcast: bool,
    /// One per line (commas also separate).
    pub broadcast_addresses: String,
    pub use_local_clock: bool,
    pub local_clock_stratum: String,
    /// One per line (commas also separate).
    pub allowed: String,
    pub rate_limit: bool,
    pub vrf: String,
}

fn lines(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join("\n"))
        .unwrap_or_default()
}

fn items(s: &str) -> Vec<String> {
    s.split(['\n', ','])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

impl ServerForm {
    fn of(v: &Value) -> Self {
        Self {
            enabled: flag(v, "enabled"),
            broadcast: flag(v, "broadcast"),
            broadcast_addresses: lines(v, "broadcast_addresses"),
            use_local_clock: flag(v, "use_local_clock"),
            local_clock_stratum: text(v, "local_clock_stratum"),
            allowed: lines(v, "allowed"),
            rate_limit: flag(v, "rate_limit"),
            vrf: text(v, "vrf"),
        }
    }

    /// `system.ntp.server.set` params for what differs from `base`.
    pub(crate) fn set_params(&self, base: &ServerForm) -> Option<Value> {
        let mut p = Map::new();
        for (k, now, was) in [
            ("enabled", self.enabled, base.enabled),
            ("broadcast", self.broadcast, base.broadcast),
            ("use_local_clock", self.use_local_clock, base.use_local_clock),
            ("rate_limit", self.rate_limit, base.rate_limit),
        ] {
            if now != was {
                p.insert(k.into(), json!(now));
            }
        }
        for (k, now, was) in [
            ("broadcast_addresses", &self.broadcast_addresses, &base.broadcast_addresses),
            ("allowed", &self.allowed, &base.allowed),
        ] {
            if items(now) != items(was) {
                p.insert(k.into(), json!(items(now)));
            }
        }
        if self.local_clock_stratum.trim() != base.local_clock_stratum.trim() {
            p.insert("local_clock_stratum".into(), form_number(&self.local_clock_stratum));
        }
        if self.vrf.trim() != base.vrf.trim() {
            p.insert("vrf".into(), json!(self.vrf.trim()));
        }
        (!p.is_empty()).then_some(Value::Object(p))
    }
}

/// An Apply's reply: the form it sent.
struct Reply(ServerForm);

impl PanelState for NtpServerPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if app.open.contains(&Win::Panel(WIN)) {
            vec![Query {
                key: "get",
                command: GET,
                params: Value::Null,
            }]
        } else {
            Vec::new()
        }
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        if key != "get" || !value.is_object() {
            return;
        }
        let now = ServerForm::of(&value);
        // Edits not applied yet stay; an untouched form follows the router.
        if self.waiting == 0 && self.form == self.base {
            self.form = now.clone();
        }
        self.base = now;
        self.state = Some(value);
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut egui::Ui) {
        self.draw(app, ui);
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, _area: egui::Rect) {
        help::modal(ctx, app.lang, &mut self.help);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        let Ok(r) = then.downcast::<Reply>() else {
            return;
        };
        self.waiting = self.waiting.saturating_sub(1);
        match result {
            Ok(_) => {
                self.error = None;
                self.base = r.0;
            }
            Err(e) => self.error = Some(e.clone()),
        }
        app.cache.refreshed_at = None;
    }
}

/// A label with its ⓘ; the explanation key is `ntp.server.<key>`.
fn label(ui: &mut Ui, help: &mut Option<HelpView>, l: Lang, key: &str, text: &'static str) {
    ui.horizontal(|ui| {
        ui.label(tr_in(SCOPE, l, text));
        if help::info_button(ui, Id::unique(("ntp-server-help", key)), tr_in(SCOPE, l, text)).clicked() {
            *help = Some(HelpView::new(format!("ntp.server.{key}"), tr_in(SCOPE, l, text)));
        }
    });
}

impl NtpServerPanel {
    fn draw(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let can = app.can();
        let l = app.lang.labels;
        let dirty = self.form.set_params(&self.base).is_some();
        let help = &mut self.help;
        let form = &mut self.form;
        Grid::new("ntp-server-settings")
            .num_columns(2)
            .spacing([12.0, 6.0])
            .show(ui, |ui| {
                label(ui, help, l, "enabled", "Enabled");
                ui.checkbox(&mut form.enabled, "");
                ui.end_row();
                label(ui, help, l, "allowed", "Allowed");
                ui.add(
                    TextEdit::multiline(&mut form.allowed)
                        .hint_text("192.168.0.0/16")
                        .desired_rows(4)
                        .desired_width(220.0),
                );
                ui.end_row();
                label(ui, help, l, "use_local_clock", "Use Local Clock");
                ui.checkbox(&mut form.use_local_clock, "");
                ui.end_row();
                label(ui, help, l, "local_clock_stratum", "Local Clock Stratum");
                ui.add(TextEdit::singleline(&mut form.local_clock_stratum).desired_width(60.0));
                ui.end_row();
                label(ui, help, l, "broadcast", "Broadcast");
                ui.checkbox(&mut form.broadcast, "");
                ui.end_row();
                label(ui, help, l, "broadcast_addresses", "Broadcast Addresses");
                ui.add(
                    TextEdit::multiline(&mut form.broadcast_addresses)
                        .hint_text("192.168.88.255")
                        .desired_rows(2)
                        .desired_width(220.0),
                );
                ui.end_row();
                label(ui, help, l, "rate_limit", "Rate Limit");
                ui.checkbox(&mut form.rate_limit, "");
                ui.end_row();
                label(ui, help, l, "vrf", "VRF");
                ui.add(TextEdit::singleline(&mut form.vrf).desired_width(120.0));
                ui.end_row();
            });
        let mut apply = false;
        let mut reset = false;
        ui.horizontal(|ui| {
            let ok = if self.waiting > 0 {
                Err(tr_in(SCOPE, l, "Saving…").to_owned())
            } else if !dirty {
                Err(tr_in(SCOPE, l, "Nothing changed").to_owned())
            } else {
                can.check(SET)
            };
            apply = action(ui, tr_in(SCOPE, l, "Apply"), ok);
            reset = action(
                ui,
                tr_in(SCOPE, l, "Revert"),
                if dirty {
                    Ok(())
                } else {
                    Err(tr_in(SCOPE, l, "Nothing changed").to_owned())
                },
            );
            if dirty {
                ui.weak(format!("{} {}", crate::dialog::UNSAVED, tr_in(SCOPE, l, "not applied")));
            }
        });
        if let Some(e) = &self.error {
            ui.colored_label(ui.visuals().error_fg_color, e.as_str());
        }
        if apply && let Some(p) = self.form.set_params(&self.base) {
            self.waiting += 1;
            app.run_then(SET, p, crate::panel::then(NAME, Reply(self.form.clone())));
        }
        if reset {
            self.form = self.base.clone();
            self.error = None;
        }
        ui.separator();
        ui.strong(tr_in(SCOPE, l, "Status"));
        let Some(s) = self.state.clone() else {
            ui.weak(tr_in(SCOPE, l, "waiting for the router…"));
            return;
        };
        status(ui, &s, &mut self.help, l);
    }
}

fn status(ui: &mut Ui, s: &Value, help: &mut Option<HelpView>, l: Lang) {
    let serving = text(s, "serving");
    let tone = match serving.as_str() {
        "upstream" => Some(crate::chip::GREEN.tone(ui.visuals())),
        "local-clock" => Some(crate::chip::AMBER.tone(ui.visuals())),
        _ => None,
    };
    Grid::new("ntp-server-status")
        .num_columns(2)
        .spacing([12.0, 4.0])
        .show(ui, |ui| {
            label(ui, help, l, "serving", "Serving");
            match tone {
                Some(t) => crate::chip::chip(ui, &serving, t),
                None => ui.label(&serving),
            };
            ui.end_row();
            let rows: [(&str, &'static str, &str); 8] = [
                ("stratum", "Stratum", "stratum"),
                ("requests", "Requests", "requests"),
                ("replies", "Replies", "replies"),
                ("kisses", "Rate Kisses", "kisses"),
                ("limited", "Limited", "limited"),
                ("denied", "Denied", "denied"),
                ("malformed", "Malformed", "malformed"),
                ("unsynchronized", "Unsynchronized", "unsynchronized"),
            ];
            for (key, name, field) in rows {
                label(ui, help, l, key, name);
                ui.label(text(s, field));
                ui.end_row();
            }
            let err = text(s, "last_error");
            if !err.is_empty() {
                label(ui, help, l, "last_error", "Last Error");
                ui.colored_label(ui.visuals().warn_fg_color, err);
                ui.end_row();
            }
        });
}
