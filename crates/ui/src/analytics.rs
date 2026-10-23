//! The System › Analytics window (G4.4f): the ClickHouse exporter. Tab
//! Settings: the export's state in chips and counters with Test
//! Connection, then the form (destination, credentials, what to send,
//! batching) with Apply. Tab Schema: the SQL to create once on the server,
//! with Copy.
//!
//! The engine validates (`system.analytics.set`), the daemon exports and
//! reports (`system.analytics.print`); the window only shows and sends.
//! Secrets come back as `***`: an empty password field leaves it as is.

use egui::{Grid, Id, RichText, ScrollArea, TextEdit, Ui};
use serde_json::{Map, Value, json};

use crate::backend::RequestId;
use crate::chip;
use crate::dhcp_client::{flag, text};
use crate::help::{self, HelpView};
use crate::i18n::tr;
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::action;
use crate::{CoreRouterUi, Win, form_number};

const NAME: &str = "analytics";
/// The window's id (`Win::Panel`).
pub(crate) const WIN: &str = "analytics";
const SET: &str = "system.analytics.set";
const PRINT: &str = "system.analytics.print";
const TEST: &str = "system.analytics.test";
const SCHEMA: &str = "system.analytics.schema";
const RULES: &str = "system.logging.list";
/// The levels a rule sends to `analytics` when the window adds them.
const LEVELS: [&str; 4] = ["info", "warning", "error", "critical"];

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "System",
        title: "Analytics",
        size: [560.0, 640.0],
        escape: false,
    }],
    new: || Box::new(AnalyticsPanel::default()),
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Tab {
    #[default]
    Settings,
    Schema,
}

#[derive(Default)]
pub(crate) struct AnalyticsPanel {
    pub(crate) tab: Tab,
    /// `system.analytics.print`, while the window is open.
    pub(crate) state: Option<Value>,
    pub(crate) form: Form,
    base: Form,
    waiting: usize,
    pub(crate) error: Option<String>,
    /// Some rule sends log events to the `analytics` action.
    pub(crate) has_log_rule: Option<bool>,
    /// The schema's SQL (tab Schema), once asked.
    pub(crate) schema: Option<String>,
    help: Option<HelpView>,
}

/// The editable settings, as typed. Secrets: empty = unchanged.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Form {
    pub enabled: bool,
    pub url: String,
    pub database: String,
    pub user: String,
    pub password: String,
    pub router_id: String,
    pub tls_verify: bool,
    pub ca_certificate: String,
    pub certificate: String,
    pub private_key: String,
    pub metrics: bool,
    pub logs: bool,
    pub flows: bool,
    pub nat_events: bool,
    pub batch_size: String,
    pub flush_interval: String,
    pub metrics_interval: String,
    pub queue_size: String,
    pub disk_queue: String,
    pub compression: String,
}

impl Form {
    fn of(v: &Value) -> Self {
        Self {
            enabled: flag(v, "enabled"),
            url: text(v, "url"),
            database: text(v, "database"),
            user: text(v, "user"),
            password: String::new(),
            router_id: text(v, "router_id"),
            tls_verify: flag(v, "tls_verify"),
            ca_certificate: text(v, "ca_certificate"),
            certificate: text(v, "certificate"),
            private_key: String::new(),
            metrics: flag(v, "metrics"),
            logs: flag(v, "logs"),
            flows: flag(v, "flows"),
            nat_events: flag(v, "nat_events"),
            batch_size: text(v, "batch_size"),
            flush_interval: text(v, "flush_interval"),
            metrics_interval: text(v, "metrics_interval"),
            queue_size: text(v, "queue_size"),
            disk_queue: text(v, "disk_queue"),
            compression: text(v, "compression"),
        }
    }

    /// `system.analytics.set` params for what differs from `base`.
    pub(crate) fn set_params(&self, base: &Form) -> Option<Value> {
        let mut p = Map::new();
        for (k, now, was) in [
            ("enabled", self.enabled, base.enabled),
            ("tls_verify", self.tls_verify, base.tls_verify),
            ("metrics", self.metrics, base.metrics),
            ("logs", self.logs, base.logs),
            ("flows", self.flows, base.flows),
            ("nat_events", self.nat_events, base.nat_events),
        ] {
            if now != was {
                p.insert(k.into(), json!(now));
            }
        }
        for (k, now, was) in [
            ("url", &self.url, &base.url),
            ("database", &self.database, &base.database),
            ("user", &self.user, &base.user),
            ("router_id", &self.router_id, &base.router_id),
            ("ca_certificate", &self.ca_certificate, &base.ca_certificate),
            ("certificate", &self.certificate, &base.certificate),
            ("compression", &self.compression, &base.compression),
        ] {
            if now.trim() != was.trim() {
                p.insert(k.into(), json!(now.trim()));
            }
        }
        for (k, v) in [("password", &self.password), ("private_key", &self.private_key)] {
            if !v.is_empty() {
                p.insert(k.into(), json!(v));
            }
        }
        for (k, now, was) in [
            ("batch_size", &self.batch_size, &base.batch_size),
            ("flush_interval", &self.flush_interval, &base.flush_interval),
            ("metrics_interval", &self.metrics_interval, &base.metrics_interval),
            ("queue_size", &self.queue_size, &base.queue_size),
            ("disk_queue", &self.disk_queue, &base.disk_queue),
        ] {
            if now.trim() != was.trim() {
                p.insert(k.into(), form_number(now));
            }
        }
        (!p.is_empty()).then_some(Value::Object(p))
    }
}

enum Reply {
    Set(Box<Form>),
    Test,
    Schema,
    Rule,
}

impl PanelState for AnalyticsPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.open.contains(&Win::Panel(WIN)) {
            return Vec::new();
        }
        let mut q = vec![Query {
            key: "print",
            command: PRINT,
            params: Value::Null,
        }];
        if app.has_command(RULES) {
            q.push(Query {
                key: "rules",
                command: RULES,
                params: Value::Null,
            });
        }
        q
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        match key {
            "print" if value.is_object() => {
                let now = Form::of(&value);
                if self.waiting == 0 && self.form.set_params(&self.base).is_none() {
                    self.form = now.clone();
                }
                self.base = now;
                self.state = Some(value);
            }
            "rules" => {
                let has = value.as_array().is_some_and(|rules| {
                    rules
                        .iter()
                        .any(|r| text(r, "action") == "analytics" && !flag(r, "disabled"))
                });
                self.has_log_rule = Some(has);
            }
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut egui::Ui) {
        let l = app.lang.labels;
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.tab, Tab::Settings, tr(l, "Settings"));
            ui.selectable_value(&mut self.tab, Tab::Schema, tr(l, "Schema"));
        });
        ui.separator();
        match self.tab {
            Tab::Settings => {
                // Apply and Revert stay in sight under the scrolled form.
                let h = (ui.available_height() - 64.0).max(120.0);
                ScrollArea::vertical()
                    .max_height(h)
                    .auto_shrink([false, true])
                    .show(ui, |ui| self.settings(app, ui));
                ui.separator();
                self.buttons(app, ui);
            }
            Tab::Schema => self.schema_tab(app, ui),
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, _area: egui::Rect) {
        help::modal(ctx, app.lang, &mut self.help);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        let Ok(r) = then.downcast::<Reply>() else {
            return;
        };
        match (*r, result) {
            (Reply::Set(form), Ok(v)) => {
                let form = *form;
                self.waiting = self.waiting.saturating_sub(1);
                self.error = v.get("warning").and_then(Value::as_str).map(|w| format!("⚠ {w}"));
                let mut base = form;
                base.password.clear();
                base.private_key.clear();
                self.base = base.clone();
                self.form = base;
            }
            (Reply::Set(_), Err(e)) => {
                self.waiting = self.waiting.saturating_sub(1);
                self.error = Some(e.clone());
            }
            (Reply::Schema, Ok(v)) => self.schema = v.get("sql").and_then(Value::as_str).map(str::to_owned),
            (Reply::Test | Reply::Rule | Reply::Schema, Err(e)) => self.error = Some(e.clone()),
            _ => {}
        }
        app.cache.refreshed_at = None;
    }

    fn escape(&mut self, _win: &'static str) -> bool {
        false
    }
}

impl AnalyticsPanel {
    /// A label with its ⓘ (explanation `analytics.<key>`).
    fn label(&mut self, ui: &mut Ui, l: crate::i18n::Lang, key: &str, en: &'static str) {
        ui.horizontal(|ui| {
            ui.label(tr(l, en));
            if help::info_button(ui, Id::unique(("analytics-help", key)), tr(l, en)).clicked() {
                self.help = Some(HelpView::new(format!("analytics.{key}"), tr(l, en)));
            }
        });
    }

    fn settings(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let can = app.can();
        self.status(app, ui);
        ui.separator();

        ui.strong(tr(l, "Destination"));
        Grid::new("analytics-destination").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
            self.label(ui, l, "enabled", "Enabled");
            ui.checkbox(&mut self.form.enabled, "");
            ui.end_row();
            self.label(ui, l, "url", "URL");
            ui.add(TextEdit::singleline(&mut self.form.url).hint_text("http://192.0.2.20:8123").desired_width(260.0));
            ui.end_row();
            self.label(ui, l, "database", "Database");
            ui.add(TextEdit::singleline(&mut self.form.database).desired_width(160.0));
            ui.end_row();
            self.label(ui, l, "user", "User");
            ui.add(TextEdit::singleline(&mut self.form.user).desired_width(160.0));
            ui.end_row();
            self.label(ui, l, "password", "Password");
            let set = self.state.as_ref().is_some_and(|s| text(s, "password") == "***");
            ui.add(
                TextEdit::singleline(&mut self.form.password)
                    .password(true)
                    .hint_text(if set { "*** (set; type to change)" } else { "" })
                    .desired_width(160.0),
            );
            ui.end_row();
            self.label(ui, l, "router_id", "Router ID");
            ui.add(TextEdit::singleline(&mut self.form.router_id).hint_text("(system identity)").desired_width(160.0));
            ui.end_row();
        });
        egui::CollapsingHeader::new(tr(l, "TLS")).id_salt("analytics-tls").show(ui, |ui| {
            Grid::new("analytics-tls-grid").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
                self.label(ui, l, "tls_verify", "Verify Certificate");
                ui.checkbox(&mut self.form.tls_verify, "");
                ui.end_row();
                self.label(ui, l, "ca_certificate", "CA Certificate");
                ui.add(TextEdit::multiline(&mut self.form.ca_certificate).hint_text("-----BEGIN CERTIFICATE----- (empty: public roots)").desired_rows(2).desired_width(300.0));
                ui.end_row();
                self.label(ui, l, "certificate", "Client Certificate");
                ui.add(TextEdit::multiline(&mut self.form.certificate).hint_text("-----BEGIN CERTIFICATE-----").desired_rows(2).desired_width(300.0));
                ui.end_row();
                self.label(ui, l, "private_key", "Private Key");
                let set = self.state.as_ref().is_some_and(|s| text(s, "private_key") == "***");
                ui.add(TextEdit::multiline(&mut self.form.private_key).hint_text(if set { "*** (set; paste to change)" } else { "-----BEGIN PRIVATE KEY-----" }).desired_rows(2).desired_width(300.0));
                ui.end_row();
            });
        });

        ui.separator();
        ui.strong(tr(l, "Send"));
        let no_rule = self.has_log_rule == Some(false);
        let mut add_rules = false;
        Grid::new("analytics-send").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
            self.label(ui, l, "metrics", "Metrics");
            ui.checkbox(&mut self.form.metrics, "");
            ui.end_row();
            self.label(ui, l, "logs", "Logs");
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.form.logs, "");
                if no_rule && self.form.logs {
                    chip::chip(ui, tr(l, "no rule"), chip::AMBER.tone(ui.visuals()))
                        .on_hover_text(tr(l, "No logging rule sends to the analytics action yet"));
                    add_rules = action(ui, tr(l, "Add rules"), can.check("system.logging.add"));
                }
            });
            ui.end_row();
            self.label(ui, l, "flows", "Flows");
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.form.flows, "");
                chip::chip(ui, tr(l, "no source yet"), chip::neutral_tone(ui.visuals()))
                    .on_hover_text(tr(l, "Traffic Flow (G4.4b) will feed this table"));
            });
            ui.end_row();
            self.label(ui, l, "nat_events", "NAT Events");
            ui.horizontal(|ui| {
                ui.checkbox(&mut self.form.nat_events, "");
                chip::chip(ui, tr(l, "CGNAT blocks"), chip::BLUE.tone(ui.visuals()))
                    .on_hover_text(tr(l, "Port blocks given and taken back by CGNAT (blocks mode); per-connection events come with Traffic Flow (G4.4b)"));
            });
            ui.end_row();
        });
        if add_rules {
            for level in LEVELS {
                app.run_then(
                    "system.logging.add",
                    json!({"topics": [level], "action": "analytics"}),
                    crate::panel::then(NAME, Reply::Rule),
                );
            }
        }

        ui.separator();
        ui.strong(tr(l, "Batching"));
        Grid::new("analytics-batch").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
            for (key, en, unit) in [
                ("batch_size", "Batch Size", "rows"),
                ("flush_interval", "Flush Interval", "s"),
                ("metrics_interval", "Metrics Interval", "s"),
                ("queue_size", "Queue Size", "MiB"),
                ("disk_queue", "Disk Queue", "MiB"),
            ] {
                self.label(ui, l, key, en);
                let field = match key {
                    "batch_size" => &mut self.form.batch_size,
                    "flush_interval" => &mut self.form.flush_interval,
                    "metrics_interval" => &mut self.form.metrics_interval,
                    "queue_size" => &mut self.form.queue_size,
                    _ => &mut self.form.disk_queue,
                };
                ui.horizontal(|ui| {
                    ui.add(TextEdit::singleline(field).desired_width(80.0));
                    ui.weak(unit);
                });
                ui.end_row();
            }
            self.label(ui, l, "compression", "Compression");
            egui::ComboBox::from_id_salt("analytics-compression")
                .selected_text(self.form.compression.clone())
                .show_ui(ui, |ui| {
                    for c in ["gzip", "none"] {
                        ui.selectable_value(&mut self.form.compression, c.to_owned(), c);
                    }
                });
            ui.end_row();
        });

    }

    fn buttons(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let can = app.can();
        let dirty = self.form.set_params(&self.base).is_some();
        let mut apply = false;
        let mut revert = false;
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let ok = if self.waiting > 0 {
                Err("Saving…".to_owned())
            } else if !dirty {
                Err("Nothing changed".to_owned())
            } else {
                can.check(SET)
            };
            apply = action(ui, tr(l, "Apply"), ok);
            revert = action(ui, tr(l, "Revert"), if dirty { Ok(()) } else { Err("Nothing changed".into()) });
            if dirty {
                ui.weak(format!("{} {}", crate::dialog::UNSAVED, tr(l, "not applied")));
            }
        });
        if let Some(e) = &self.error {
            let color = if e.starts_with('⚠') { ui.visuals().warn_fg_color } else { ui.visuals().error_fg_color };
            ui.colored_label(color, e.as_str());
        }
        if apply && let Some(p) = self.form.set_params(&self.base) {
            self.waiting += 1;
            app.run_then(SET, p, crate::panel::then(NAME, Reply::Set(Box::new(self.form.clone()))));
        }
        if revert {
            self.form = self.base.clone();
            self.error = None;
        }
    }

    /// State chip, counters, Test Connection and its result.
    fn status(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let Some(s) = self.state.clone() else {
            ui.weak(tr(l, "waiting for the router…"));
            return;
        };
        let num = |k: &str| s.get(k).and_then(Value::as_u64).unwrap_or(0);
        let mut test = false;
        ui.horizontal(|ui| {
            let state = text(&s, "state");
            let tone = match state.as_str() {
                "running" => chip::GREEN.tone(ui.visuals()),
                "retrying" => chip::AMBER.tone(ui.visuals()),
                "error" => chip::RED.tone(ui.visuals()),
                _ => chip::neutral_tone(ui.visuals()),
            };
            chip::chip(ui, &state, tone);
            if help::info_button(ui, Id::unique("analytics-help-state"), tr(l, "State")).clicked() {
                self.help = Some(HelpView::new("analytics.state", tr(l, "State")));
            }
            let dropped = num("dropped_rows");
            if dropped > 0 {
                chip::chip(ui, &format!("{} {dropped}", tr(l, "dropped")), chip::RED.tone(ui.visuals()))
                    .on_hover_text(tr(l, "Rows thrown away: the queue was full or the server refused them"));
            }
            if num("disk_rows") > 0 {
                chip::chip(ui, &format!("{} {}", tr(l, "on disk"), num("disk_rows")), chip::AMBER.tone(ui.visuals()));
            }
            if let Some(secs) = s.get("retry_in").and_then(Value::as_u64) {
                ui.weak(format!("{} {secs} s", tr(l, "retry in")));
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                test = action(ui, tr(l, "Test Connection"), app.can().check(TEST));
            });
        });
        let t = s.get("test").cloned().unwrap_or(Value::Null);
        let requested = t.get("requested").and_then(Value::as_u64).unwrap_or(0);
        let done = t.get("done").and_then(Value::as_u64).unwrap_or(0);
        if requested > done {
            ui.weak(tr(l, "testing…"));
        } else if done > 0 {
            ui.horizontal(|ui| {
                let (word, tone) = if flag(&t, "ok") {
                    ("ok", chip::GREEN.tone(ui.visuals()))
                } else {
                    ("failed", chip::RED.tone(ui.visuals()))
                };
                chip::chip(ui, word, tone);
                ui.label(format!("{} ({} ms)", text(&t, "message"), t.get("ms").and_then(Value::as_u64).unwrap_or(0)));
            });
        }
        if test {
            app.run_then(TEST, json!({}), crate::panel::then(NAME, Reply::Test));
        }
        let bytes = |n: u64| {
            if n >= 1 << 20 {
                format!("{:.1} MiB", n as f64 / f64::from(1u32 << 20))
            } else {
                format!("{:.1} KiB", n as f64 / 1024.0)
            }
        };
        Grid::new("analytics-status").num_columns(4).spacing([16.0, 4.0]).show(ui, |ui| {
            ui.label(tr(l, "Sent"));
            ui.label(format!("{} rows", num("sent_rows")));
            ui.label(tr(l, "Batches"));
            ui.label(format!("{} ({})", num("sent_batches"), bytes(num("sent_bytes"))));
            ui.end_row();
            ui.label(tr(l, "In Queue"));
            ui.label(format!("{} rows, {}", num("queued_rows"), bytes(num("queued_bytes"))));
            ui.label(tr(l, "On Disk"));
            ui.label(format!("{} rows, {}", num("disk_rows"), bytes(num("disk_bytes"))));
            ui.end_row();
            ui.label(tr(l, "Dropped"));
            ui.label(format!("{} rows", num("dropped_rows")));
            ui.label(tr(l, "Retries"));
            ui.label(num("retries").to_string());
            ui.end_row();
            let when = |k: &str| s.get(k).and_then(Value::as_u64).map(crate::ntp_client::utc).unwrap_or_else(|| "–".into());
            ui.label(tr(l, "Last Sent"));
            ui.label(when("last_sent_at"));
            ui.label(tr(l, "Last Error At"));
            ui.label(when("last_error_at"));
            ui.end_row();
        });
        if let Some(e) = s.get("last_error").and_then(Value::as_str) {
            ui.horizontal_wrapped(|ui| {
                ui.label(tr(l, "Last Error"));
                ui.colored_label(ui.visuals().warn_fg_color, e);
            });
        }
    }

    fn schema_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        ui.horizontal(|ui| {
            ui.label(tr(l, "Create these once on the ClickHouse server (clickhouse-client --multiquery < schema.sql)."));
            if help::info_button(ui, Id::unique("analytics-help-schema"), tr(l, "Schema")).clicked() {
                self.help = Some(HelpView::new("analytics.schema", tr(l, "Schema")));
            }
        });
        let Some(sql) = self.schema.clone() else {
            if app.has_command(SCHEMA) {
                self.schema = Some(String::new());
                app.run_then(SCHEMA, json!({}), crate::panel::then(NAME, Reply::Schema));
            }
            ui.weak(tr(l, "waiting for the router…"));
            return;
        };
        if ui.button(tr(l, "Copy")).clicked() {
            ui.ctx().copy_text(sql.clone());
        }
        // The note stays under the SQL; the SQL scrolls (never the window).
        let h = (ui.available_height() - 28.0).max(80.0);
        ScrollArea::both().max_height(h).auto_shrink([false, false]).show(ui, |ui| {
            let mut shown = sql.as_str();
            ui.add(TextEdit::multiline(&mut shown).code_editor().desired_width(f32::INFINITY));
        });
        ui.label(RichText::new(tr(l, "TTL: metrics 395 days, logs 90, flows 30, NAT events 400 (Marco Civil). Change the days with system.analytics.schema.")).weak());
    }
}
