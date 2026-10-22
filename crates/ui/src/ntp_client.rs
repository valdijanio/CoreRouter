//! The System › NTP Client window (G4.6e), WinBox `/system ntp client`
//! style: one settings form (Enabled, Servers, poll interval) with Apply,
//! and under it the client's status, refreshed live: state, synced server
//! and stratum, offset, round trip, last sync and the last error.
//!
//! The engine validates (`system.ntp.client.set`) and keeps the status
//! (`system.ntp.client.get`); the window only shows and sends.
//!
//! A panel (`panel.rs`): its state lives here, not in `CoreRouterUi`.

use egui::{Color32, Grid, RichText, TextEdit, Ui};
use serde_json::{Map, Value, json};

use crate::backend::RequestId;
use crate::dhcp_client::{flag, text};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::action;
use crate::{CoreRouterUi, Win, form_number};

const NAME: &str = "ntp-client";
/// The window's id (`Win::Panel`).
pub(crate) const WIN: &str = "ntp-client";
const SET: &str = "system.ntp.client.set";
const GET: &str = "system.ntp.client.get";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "System",
        title: "NTP Client",
        size: [460.0, 420.0],
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
}

/// The editable settings, as typed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct NtpForm {
    pub enabled: bool,
    /// One server per line (commas also separate).
    pub servers: String,
    pub min_poll: String,
    pub max_poll: String,
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

impl NtpPanel {
    fn draw(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let can = app.can();
        let dirty = self.form.set_params(&self.base).is_some();
        Grid::new("ntp-settings")
            .num_columns(2)
            .spacing([12.0, 6.0])
            .show(ui, |ui| {
                ui.label("Enabled");
                ui.checkbox(&mut self.form.enabled, "");
                ui.end_row();
                ui.label("Servers").on_hover_text(
                    "One per line: an IP address or a DNS name (pool.ntp.org). \
                     The client asks them all and keeps the best answer.",
                );
                ui.add(
                    TextEdit::multiline(&mut self.form.servers)
                        .hint_text("pool.ntp.org")
                        .desired_rows(3)
                        .desired_width(220.0),
                );
                ui.end_row();
                ui.label("Min Poll").on_hover_text(
                    "Poll interval as a power of two in seconds: 6 = 64 s, 10 = 17 min",
                );
                ui.add(TextEdit::singleline(&mut self.form.min_poll).desired_width(60.0));
                ui.end_row();
                ui.label("Max Poll");
                ui.add(TextEdit::singleline(&mut self.form.max_poll).desired_width(60.0));
                ui.end_row();
            });
        let mut apply = false;
        let mut reset = false;
        ui.horizontal(|ui| {
            let ok = if self.waiting > 0 {
                Err("Saving…".to_owned())
            } else if !dirty {
                Err("Nothing changed".to_owned())
            } else {
                can.check(SET)
            };
            apply = action(ui, "Apply", ok);
            reset = action(
                ui,
                "Revert",
                if dirty {
                    Ok(())
                } else {
                    Err("Nothing changed".into())
                },
            );
            if dirty {
                ui.weak(format!("{} not applied", crate::dialog::UNSAVED));
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
        ui.strong("Status");
        match &self.state {
            Some(s) => status(ui, s),
            None => {
                ui.weak("waiting for the router…");
            }
        }
    }
}

fn status(ui: &mut Ui, s: &Value) {
    let state = text(s, "status");
    let colour = match state.as_str() {
        "synchronized" => Some(Color32::from_rgb(0x2e, 0x9e, 0x44)),
        "waiting" => Some(Color32::from_rgb(0xc8, 0x8a, 0x00)),
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
            ui.label("Status");
            match colour {
                Some(c) => ui.label(RichText::new(&state).color(c).strong()),
                None => ui.label(&state),
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
            for (label, value) in [
                ("Synced Server", server),
                ("Synced Stratum", text(s, "synced_stratum")),
                ("System Offset", ms("system_offset_ms")),
                ("Round Trip", ms("round_trip_ms")),
                ("Last Sync", last),
                ("Next Poll", poll),
            ] {
                ui.label(label);
                ui.label(value);
                ui.end_row();
            }
            let err = text(s, "last_error");
            if !err.is_empty() {
                ui.label("Last Error");
                ui.colored_label(ui.visuals().warn_fg_color, err);
                ui.end_row();
            }
        });
    if text(s, "status") == "synchronized" {
        ui.weak("Measured only: the system clock is not set yet (G4.6b).");
    }
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
