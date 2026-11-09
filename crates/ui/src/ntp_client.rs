//! The System › NTP Client window (G4.6e), WinBox `/system ntp client`
//! style: one settings form (Enabled, Servers, poll interval, VRF, Set System
//! Clock) with Apply, and under it the client's status, refreshed live: state,
//! synced server and stratum, offset, round trip, what is being done to the
//! clock (G4.6b), last sync and the last error. A step above 1000 s shows a
//! banner with the button that confirms it.
//!
//! The engine validates (`system.ntp.client.set`) and keeps the status
//! (`system.ntp.client.get`); the window only shows and sends.
//!
//! A panel (`panel.rs`): its state lives here, not in `CoreRouterUi`.

use egui::{Grid, Id, TextEdit, Ui};
use serde_json::{Map, Value, json};

use crate::backend::RequestId;
use crate::dhcp_client::{flag, text};
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr_in};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::action;
use crate::{CoreRouterUi, Win, form_number};

const NAME: &str = "ntp-client";
/// The window's id (`Win::Panel`).
pub(crate) const WIN: &str = "ntp-client";
const SET: &str = "system.ntp.client.set";
const GET: &str = "system.ntp.client.get";
const CONFIRM: &str = "system.ntp.client.confirm-step";
const SCOPE: &str = "ntp";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "System",
        title: "NTP Client",
        size: [500.0, 600.0],
        escape: false,
    }],
    new: || Box::new(NtpPanel::default()),
};

/// System › NTP Client: the form as typed and what the engine has.
#[derive(Default)]
pub(crate) struct NtpPanel {
    /// `system.ntp.client.get`, while the window is open.
    pub(crate) state: Option<Value>,
    pub(crate) form: NtpForm,
    /// The settings as the engine last reported them.
    base: NtpForm,
    /// Requests out (Apply): the form is not overwritten meanwhile.
    waiting: usize,
    /// The engine's refusal of the last Apply, shown under the form.
    pub(crate) error: Option<String>,
    /// The ⓘ modal.
    help: Option<HelpView>,
}

/// The editable settings, as typed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct NtpForm {
    pub enabled: bool,
    /// One server per line (commas also separate).
    pub servers: String,
    pub min_poll: String,
    pub max_poll: String,
    pub vrf: String,
    pub set_system_clock: bool,
}

impl NtpForm {
    fn of(v: &Value) -> Self {
        let servers = v
            .get("servers")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();
        Self {
            enabled: flag(v, "enabled"),
            servers,
            min_poll: text(v, "min_poll"),
            max_poll: text(v, "max_poll"),
            vrf: text(v, "vrf"),
            set_system_clock: flag(v, "set_system_clock"),
        }
    }

    fn server_list(&self) -> Vec<String> {
        self.servers
            .split(['\n', ','])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect()
    }

    /// `system.ntp.client.set` params for what differs from `base`.
    pub(crate) fn set_params(&self, base: &NtpForm) -> Option<Value> {
        let mut p = Map::new();
        if self.enabled != base.enabled {
            p.insert("enabled".into(), json!(self.enabled));
        }
        if self.server_list() != base.server_list() {
            p.insert("servers".into(), json!(self.server_list()));
        }
        for (k, now, was) in [
            ("min_poll", &self.min_poll, &base.min_poll),
            ("max_poll", &self.max_poll, &base.max_poll),
        ] {
            if now.trim() != was.trim() {
                p.insert(k.into(), form_number(now));
            }
        }
        if self.vrf.trim() != base.vrf.trim() {
            p.insert("vrf".into(), json!(self.vrf.trim()));
        }
        if self.set_system_clock != base.set_system_clock {
            p.insert("set_system_clock".into(), json!(self.set_system_clock));
        }
        (!p.is_empty()).then_some(Value::Object(p))
    }
}

/// An Apply's reply: the form it sent.
struct Reply(NtpForm);

impl PanelState for NtpPanel {
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
        let now = NtpForm::of(&value);
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

/// A label with its ⓘ; the explanation key is `ntp.<key>`.
fn label(ui: &mut Ui, help: &mut Option<HelpView>, l: Lang, key: &str, text: &'static str) {
    ui.horizontal(|ui| {
        ui.label(tr_in(SCOPE, l, text));
        if help::info_button(ui, Id::unique(("ntp-help", key)), tr_in(SCOPE, l, text)).clicked() {
            *help = Some(HelpView::new(format!("ntp.{key}"), tr_in(SCOPE, l, text)));
        }
    });
}

impl NtpPanel {
    fn draw(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let can = app.can();
        let l = app.lang.labels;
        let dirty = self.form.set_params(&self.base).is_some();
        let help = &mut self.help;
        Grid::new("ntp-settings")
            .num_columns(2)
            .spacing([12.0, 6.0])
            .show(ui, |ui| {
                label(ui, help, l, "enabled", "Enabled");
                ui.checkbox(&mut self.form.enabled, "");
                ui.end_row();
                label(ui, help, l, "servers", "Servers");
                ui.add(
                    TextEdit::multiline(&mut self.form.servers)
                        .hint_text("pool.ntp.org")
                        .desired_rows(3)
                        .desired_width(220.0),
                );
                ui.end_row();
                label(ui, help, l, "min_poll", "Min Poll");
                ui.add(TextEdit::singleline(&mut self.form.min_poll).desired_width(60.0));
                ui.end_row();
                label(ui, help, l, "max_poll", "Max Poll");
                ui.add(TextEdit::singleline(&mut self.form.max_poll).desired_width(60.0));
                ui.end_row();
                label(ui, help, l, "vrf", "VRF");
                ui.add(TextEdit::singleline(&mut self.form.vrf).desired_width(120.0));
                ui.end_row();
                label(ui, help, l, "set_system_clock", "Set System Clock");
                ui.checkbox(&mut self.form.set_system_clock, "");
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
        if let Some(pending) = s.get("pending_step_ms").and_then(Value::as_f64) {
            ui.colored_label(
                ui.visuals().warn_fg_color,
                format!(
                    "{}: {:+.0} s",
                    tr_in(SCOPE, l, "The clock needs a jump above 1000 s"),
                    pending / 1000.0
                ),
            );
            if action(ui, tr_in(SCOPE, l, "Confirm Clock Step"), can.check(CONFIRM)) {
                app.run(CONFIRM, json!({}));
            }
        }
        status(ui, &s, &mut self.help, l);
    }
}

fn status(ui: &mut Ui, s: &Value, help: &mut Option<HelpView>, l: Lang) {
    let state = text(s, "status");
    // A state is a chip in the theme's tones (docs/ui-style.md).
    let tone = |ui: &Ui, name: &str| match name {
        "synchronized" | "slewing" | "stepped" => Some(crate::chip::GREEN.tone(ui.visuals())),
        "waiting" | "holding-spike" | "awaiting-confirmation" | "using-local-clock" => {
            Some(crate::chip::AMBER.tone(ui.visuals()))
        }
        "refused" => Some(crate::chip::RED.tone(ui.visuals())),
        _ => None,
    };
    let ms = |k: &str| {
        s.get(k)
            .and_then(Value::as_f64)
            .map(|v| format!("{v:.3} ms"))
            .unwrap_or_default()
    };
    Grid::new("ntp-status")
        .num_columns(2)
        .spacing([12.0, 4.0])
        .show(ui, |ui| {
            label(ui, help, l, "status", "Status");
            match tone(ui, &state) {
                Some(t) => crate::chip::chip(ui, &state, t),
                None => ui.label(&state),
            };
            ui.end_row();
            let clock = text(s, "clock");
            label(ui, help, l, "clock", "System Clock");
            match tone(ui, &clock) {
                Some(t) => crate::chip::chip(ui, &clock, t),
                None => ui.label(&clock),
            };
            ui.end_row();
            let server = match (text(s, "synced_server"), text(s, "synced_address")) {
                (n, a) if a.is_empty() || n == a => n,
                (n, a) => format!("{n} ({a})"),
            };
            let poll = s
                .get("poll_secs")
                .and_then(Value::as_u64)
                .map(|p| format!("in {}", crate::firewall::duration(p)))
                .unwrap_or_default();
            let last = s
                .get("last_sync")
                .and_then(Value::as_u64)
                .map(utc)
                .unwrap_or_default();
            let dynamic = s
                .get("dynamic_servers")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "))
                .unwrap_or_default();
            let drift = s
                .get("freq_drift_ppm")
                .and_then(Value::as_f64)
                .map(|v| format!("{v:+.3} ppm"))
                .unwrap_or_default();
            let rows: [(&str, &'static str, String); 8] = [
                ("synced_server", "Synced Server", server),
                ("synced_stratum", "Synced Stratum", text(s, "synced_stratum")),
                ("system_offset", "System Offset", ms("system_offset_ms")),
                ("round_trip", "Round Trip", ms("round_trip_ms")),
                ("last_adjustment", "Last Adjustment", ms("last_adjustment_ms")),
                ("freq_drift", "Frequency Drift", drift),
                ("last_sync", "Last Sync", last),
                ("next_poll", "Next Poll", poll),
            ];
            for (key, name, value) in rows {
                label(ui, help, l, key, name);
                ui.label(value);
                ui.end_row();
            }
            if !dynamic.is_empty() {
                label(ui, help, l, "dynamic_servers", "Dynamic Servers");
                ui.label(dynamic);
                ui.end_row();
            }
            for (key, name, field) in [
                ("clock_error", "Clock Error", "clock_error"),
                ("last_error", "Last Error", "last_error"),
            ] {
                let err = text(s, field);
                if !err.is_empty() {
                    label(ui, help, l, key, name);
                    ui.colored_label(ui.visuals().warn_fg_color, err);
                    ui.end_row();
                }
            }
        });
}

/// Unix seconds as `2026-10-22 13:05:09 UTC` (proleptic Gregorian, the
/// days-from-civil inverse of H. Hinnant's algorithm).
pub(crate) fn utc(secs: u64) -> String {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}
