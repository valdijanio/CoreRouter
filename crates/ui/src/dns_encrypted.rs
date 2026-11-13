//! IP › DNS › Encrypted Service (G4.1zf): DNS over TLS for the LAN. One
//! settings form with Apply (DoT, port, certificate, idle time, sessions,
//! DDR), and under it the service's state, refreshed live: listening,
//! the certificate served, sessions and counters, and the engine's checks
//! (forwarder on, certificate, input firewall from the LAN and from the
//! Internet) with an ok/info/warning/error chip each.
//!
//! The engine validates and decides (`ip.dns.encrypted-service.*`); the
//! window only shows and sends. A panel (`panel.rs`).

use egui::{Grid, Id, RichText, TextEdit, Ui};
use serde_json::{Map, Value, json};

use crate::backend::RequestId;
use crate::dhcp_client::{flag, text};
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr_in};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::action;
use crate::{CoreRouterUi, Win, form_number};

const NAME: &str = "dns-encrypted";
pub(crate) const WIN: &str = "dns-encrypted";
const SET: &str = "ip.dns.encrypted-service.set";
const GET: &str = "ip.dns.encrypted-service.get";
const SCOPE: &str = "dns_encrypted";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef { id: WIN, group: "IP", title: "DNS Encrypted Service", size: [620.0, 620.0], escape: false }],
    new: || Box::new(EncryptedPanel::default()),
};

#[derive(Default)]
pub(crate) struct EncryptedPanel {
    pub(crate) state: Option<Value>,
    pub(crate) form: Form,
    base: Form,
    /// `/certificate` names with a key, for the Certificate combo.
    pub(crate) certificates: Vec<String>,
    waiting: usize,
    pub(crate) error: Option<String>,
    pub(crate) notes: Vec<String>,
    help: Option<HelpView>,
}

/// The editable settings, as typed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Form {
    pub dot: bool,
    pub dot_port: String,
    pub certificate: String,
    pub idle_timeout_secs: String,
    pub max_sessions: String,
    pub announce_ddr: bool,
}

impl Form {
    fn of(v: &Value) -> Self {
        Self {
            dot: flag(v, "dot"),
            dot_port: text(v, "dot_port"),
            certificate: text(v, "certificate"),
            idle_timeout_secs: text(v, "idle_timeout_secs"),
            max_sessions: text(v, "max_sessions"),
            announce_ddr: flag(v, "announce_ddr"),
        }
    }

    /// `ip.dns.encrypted-service.set` params for what differs from `base`.
    pub(crate) fn set_params(&self, base: &Form) -> Option<Value> {
        let mut p = Map::new();
        for (k, now, was) in [("dot", self.dot, base.dot), ("announce_ddr", self.announce_ddr, base.announce_ddr)] {
            if now != was {
                p.insert(k.into(), json!(now));
            }
        }
        for (k, now, was) in [
            ("dot_port", &self.dot_port, &base.dot_port),
            ("idle_timeout_secs", &self.idle_timeout_secs, &base.idle_timeout_secs),
            ("max_sessions", &self.max_sessions, &base.max_sessions),
        ] {
            if now.trim() != was.trim() {
                p.insert(k.into(), form_number(now));
            }
        }
        if self.certificate.trim() != base.certificate.trim() {
            p.insert("certificate".into(), json!(self.certificate.trim()));
        }
        (!p.is_empty()).then_some(Value::Object(p))
    }
}

/// An Apply's reply: the form it sent.
struct Reply(Form);

impl PanelState for EncryptedPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.open.contains(&Win::Panel(WIN)) {
            return Vec::new();
        }
        let mut q = vec![Query { key: "get", command: GET, params: Value::Null }];
        if app.has_command("certificate.print") {
            q.push(Query { key: "certificates", command: "certificate.print", params: json!({}) });
        }
        q
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        if key == "certificates"
            && let Some(rows) = value.as_array()
        {
            self.certificates = rows.iter().filter(|r| flag(r, "private_key")).map(|r| text(r, "name")).collect();
            return;
        }
        if key != "get" || !value.is_object() {
            return;
        }
        let now = Form::of(&value);
        // Edits not applied yet stay; an untouched form follows the router.
        if self.waiting == 0 && self.form == self.base {
            self.form = now.clone();
        }
        self.base = now;
        self.state = Some(value);
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        egui::ScrollArea::vertical().id_salt("dns-encrypted-scroll").show(ui, |ui| self.draw(app, ui));
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
            Ok(v) => {
                self.error = None;
                self.notes = v
                    .get("notes")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect())
                    .unwrap_or_default();
                self.base = r.0;
            }
            Err(e) => self.error = Some(e.clone()),
        }
        app.cache.refreshed_at = None;
    }
}

/// A label with its ⓘ; the explanation key is `dns_encrypted.<key>`.
fn label(ui: &mut Ui, help: &mut Option<HelpView>, l: Lang, key: &str, text: &'static str) {
    ui.horizontal(|ui| {
        ui.label(tr_in(SCOPE, l, text));
        if help::info_button(ui, Id::unique(("dns-encrypted-help", key)), tr_in(SCOPE, l, text)).clicked() {
            *help = Some(HelpView::new(format!("dns_encrypted.{key}"), tr_in(SCOPE, l, text)));
        }
    });
}

impl EncryptedPanel {
    fn draw(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let can = app.can();
        let l = app.lang.labels;
        ui.horizontal(|ui| {
            let title = tr_in(SCOPE, l, "DNS Encrypted Service");
            if help::info_button(ui, Id::unique("dns-encrypted-title"), title).clicked() {
                self.help = Some(HelpView::new("menu.dns-encrypted", title));
            }
            ui.weak(tr_in(SCOPE, l, "DNS over TLS (RFC 7858) for the LAN, answered by the same forwarder as UDP/TCP 53"));
        });
        ui.add_space(4.0);
        let dirty = self.form.set_params(&self.base).is_some();
        let certs = self.certificates.clone();
        let help = &mut self.help;
        let form = &mut self.form;
        Grid::new("dns-encrypted-settings").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
            label(ui, help, l, "dot", "DNS over TLS");
            ui.checkbox(&mut form.dot, "");
            ui.end_row();
            label(ui, help, l, "dot_port", "Port");
            ui.add(TextEdit::singleline(&mut form.dot_port).hint_text("853").desired_width(80.0));
            ui.end_row();
            label(ui, help, l, "certificate", "Certificate");
            let shown = if form.certificate.is_empty() { tr_in(SCOPE, l, "(made at the first Apply)").to_owned() } else { form.certificate.clone() };
            egui::ComboBox::from_id_salt("dns-encrypted-certificate").width(220.0).selected_text(shown).show_ui(ui, |ui| {
                for c in &certs {
                    ui.selectable_value(&mut form.certificate, c.clone(), c);
                }
            });
            ui.end_row();
            label(ui, help, l, "idle_timeout_secs", "Idle Timeout (s)");
            ui.add(TextEdit::singleline(&mut form.idle_timeout_secs).hint_text("30").desired_width(80.0));
            ui.end_row();
            label(ui, help, l, "max_sessions", "Max Sessions");
            ui.add(TextEdit::singleline(&mut form.max_sessions).hint_text("1000").desired_width(80.0));
            ui.end_row();
            label(ui, help, l, "announce_ddr", "Announce (DDR)");
            ui.checkbox(&mut form.announce_ddr, "");
            ui.end_row();
        });
        let mut apply = false;
        let mut reset = false;
        let mut open_certs = false;
        ui.horizontal(|ui| {
            let ok = if self.waiting > 0 {
                Err(tr_in(SCOPE, l, "Saving…").to_owned())
            } else if !dirty {
                Err(tr_in(SCOPE, l, "Nothing changed").to_owned())
            } else {
                can.check(SET)
            };
            apply = action(ui, tr_in(SCOPE, l, "Apply"), ok);
            reset = action(ui, tr_in(SCOPE, l, "Revert"), if dirty { Ok(()) } else { Err(tr_in(SCOPE, l, "Nothing changed").to_owned()) });
            open_certs = action(ui, tr_in(SCOPE, l, "Certificates…"), can.check("certificate.print"));
            if dirty {
                ui.weak(format!("{} {}", crate::dialog::UNSAVED, tr_in(SCOPE, l, "not applied")));
            }
        });
        if let Some(e) = &self.error {
            ui.colored_label(ui.visuals().error_fg_color, e.as_str());
        }
        for n in &self.notes {
            ui.weak(n);
        }
        if apply && let Some(p) = self.form.set_params(&self.base) {
            self.waiting += 1;
            app.run_then(SET, p, crate::panel::then(NAME, Reply(self.form.clone())));
        }
        if reset {
            self.form = self.base.clone();
            self.error = None;
        }
        if open_certs {
            app.open(Win::Panel(crate::certificates::WIN));
        }
        ui.separator();
        let Some(s) = self.state.clone() else {
            ui.weak(tr_in(SCOPE, l, "waiting for the router…"));
            return;
        };
        status(ui, &s, &mut self.help, l);
        checks(ui, &s, l);
    }
}

fn status(ui: &mut Ui, s: &Value, help: &mut Option<HelpView>, l: Lang) {
    let st = text(s, "status");
    let tone = match st.as_str() {
        "listening" => crate::chip::GREEN.tone(ui.visuals()),
        "error" => crate::chip::RED.tone(ui.visuals()),
        _ => crate::chip::neutral_tone(ui.visuals()),
    };
    Grid::new("dns-encrypted-status").num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
        label(ui, help, l, "status", "Status");
        ui.horizontal(|ui| {
            crate::chip::chip(ui, &st, tone);
            let at = s.get("listening").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", ")).unwrap_or_default();
            ui.weak(at);
        });
        ui.end_row();
        let fp = text(s, "fingerprint");
        if !fp.is_empty() {
            label(ui, help, l, "fingerprint", "Fingerprint");
            ui.label(RichText::new(fp).monospace().small());
            ui.end_row();
        }
        let rows: [(&str, &'static str); 8] = [
            ("sessions", "Sessions"),
            ("queries", "Queries"),
            ("handshakes", "Handshakes"),
            ("resumed", "Resumed"),
            ("handshake_failures", "Handshake Failures"),
            ("accepted", "Accepted"),
            ("refused", "Refused"),
            ("over_limit", "Over Limit"),
        ];
        for (key, name) in rows {
            label(ui, help, l, key, name);
            ui.label(text(s, key));
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

/// The engine's checks, one line each with its level chip.
fn checks(ui: &mut Ui, s: &Value, l: Lang) {
    let Some(list) = s.get("checks").and_then(Value::as_array).filter(|a| !a.is_empty()) else {
        return;
    };
    ui.separator();
    ui.strong(tr_in(SCOPE, l, "Checks"));
    for c in list {
        ui.horizontal_wrapped(|ui| {
            let (word, tone) = crate::list_modal::level_chip(&text(c, "level"), ui.visuals());
            crate::chip::chip(ui, word, tone);
            ui.label(text(c, "message"));
        });
    }
}
