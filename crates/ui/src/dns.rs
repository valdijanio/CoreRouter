//! The IP › DNS windows (G4.1b), WinBox `/ip dns` style:
//!
//! - **DNS** (Settings): servers, the LAN forwarder (Allow Remote Requests,
//!   who may ask, per-client limit), upstream selection, serve-stale, cache
//!   and limits, with Apply; buttons open Static, Cache and Statistics
//!   (`dns_statistics.rs`). Adlist, Forwarders and Zones are there greyed
//!   out with the part that brings them.
//! - **DNS Static**: the static entries, with New/properties dialogs.
//! - **DNS Cache**: what the cache holds, with hits, and Flush Cache.
//!
//! The engine validates (`ip.dns.set`, `ip.dns.static.*`); the windows only
//! show and send. A panel (`panel.rs`): its state lives here.

use egui::{Grid, RichText, ScrollArea, TextEdit, Ui};
use serde_json::{Map, Value, json};

use crate::avail::Avail;
use crate::backend::RequestId;
use crate::dhcp_client::{flag, text};
use crate::dialog::{self, Footer, Form, Head, Press, Status};
use crate::interfaces::{cascade, dialog_id};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Icon, Menu, Row, Shortcut, TableState, action, col, comment, num};
use crate::{CoreRouterUi, Win, form_number};

const NAME: &str = "dns";
pub(crate) const WIN: &str = "dns";
pub(crate) const WIN_STATIC: &str = "dns-static";
pub(crate) const WIN_CACHE: &str = "dns-cache";
pub(crate) const STATIC_TABLE: &str = "dns-static";
pub(crate) const CACHE_TABLE: &str = "dns-cache";
const SET: &str = "ip.dns.set";
const MAX_OPEN: usize = 8;
const TYPES: [&str; 9] = [
    "A", "AAAA", "CNAME", "FWD", "MX", "NS", "NXDOMAIN", "SRV", "TXT",
];
/// The buttons of parts still to come, with why they are greyed out.
const LATER: [(&str, &str); 3] = [
    ("Adlist", "Coming soon (G4.1d)"),
    ("Forwarders", "Coming soon (G4.1d)"),
    ("Zones", "Coming soon (G4.1c)"),
];

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[
        WinDef {
            id: WIN,
            group: "IP",
            title: "DNS",
            size: [540.0, 720.0],
            escape: false,
        },
        WinDef {
            id: WIN_STATIC,
            group: "IP",
            title: "DNS Static",
            size: [640.0, 300.0],
            escape: true,
        },
        WinDef {
            id: WIN_CACHE,
            group: "IP",
            title: "DNS Cache",
            size: [720.0, 320.0],
            escape: true,
        },
    ],
    new: || Box::new(DnsPanel::default()),
};

const STATIC_COLUMNS: [table::Column; 6] = [
    col(""),
    col("Name"),
    col("Type"),
    col("Data"),
    num("TTL"),
    comment(),
];

const CACHE_COLUMNS: [table::Column; 6] = [
    col("Name"),
    col("Type"),
    col("Data"),
    num("TTL"),
    num("Hits"),
    col("Server"),
];

/// IP › DNS: the three windows' state.
#[derive(Default)]
pub(crate) struct DnsPanel {
    /// `ip.dns.get`, while the DNS window is open.
    pub(crate) settings: Option<Value>,
    pub(crate) form: DnsForm,
    base: DnsForm,
    waiting: usize,
    pub(crate) error: Option<String>,
    /// `ip.dns.static.print`.
    pub(crate) statics: Vec<Value>,
    pub(crate) static_table: TableState,
    pub(crate) dialogs: Vec<StaticDialogWin>,
    /// `ip.dns.cache.print`.
    pub(crate) cache: Vec<Value>,
    pub(crate) cache_table: TableState,
}

/// The editable settings, as typed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DnsForm {
    /// One per line (commas also separate).
    pub servers: String,
    pub allow_remote_requests: bool,
    pub allowed_from: String,
    pub max_queries_per_client: String,
    pub server_selection: String,
    pub serve_stale_secs: String,
    pub max_udp_packet_size: String,
    pub query_server_timeout_ms: String,
    pub query_total_timeout_ms: String,
    pub max_concurrent_queries: String,
    pub max_concurrent_tcp_sessions: String,
    pub cache_size: String,
    pub cache_max_ttl_secs: String,
    pub address_list_extra_time_secs: String,
}

/// `["a","b"]` as `a, b` (or one per line).
fn list_text(v: &Value, k: &str, sep: &str) -> String {
    v.get(k)
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(sep))
        .unwrap_or_default()
}

fn split(s: &str) -> Vec<String> {
    s.split(['\n', ','])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

impl DnsForm {
    fn of(v: &Value) -> Self {
        Self {
            servers: list_text(v, "servers", "\n"),
            allow_remote_requests: flag(v, "allow_remote_requests"),
            allowed_from: list_text(v, "allowed_from", ", "),
            max_queries_per_client: text(v, "max_queries_per_client"),
            server_selection: text(v, "server_selection"),
            serve_stale_secs: text(v, "serve_stale_secs"),
            max_udp_packet_size: text(v, "max_udp_packet_size"),
            query_server_timeout_ms: text(v, "query_server_timeout_ms"),
            query_total_timeout_ms: text(v, "query_total_timeout_ms"),
            max_concurrent_queries: text(v, "max_concurrent_queries"),
            max_concurrent_tcp_sessions: text(v, "max_concurrent_tcp_sessions"),
            cache_size: text(v, "cache_size"),
            cache_max_ttl_secs: text(v, "cache_max_ttl_secs"),
            address_list_extra_time_secs: text(v, "address_list_extra_time_secs"),
        }
    }

    /// `ip.dns.set` params for what differs from `base`.
    pub(crate) fn set_params(&self, base: &DnsForm) -> Option<Value> {
        let mut p = Map::new();
        if split(&self.servers) != split(&base.servers) {
            p.insert("servers".into(), json!(split(&self.servers)));
        }
        if self.allow_remote_requests != base.allow_remote_requests {
            p.insert(
                "allow_remote_requests".into(),
                json!(self.allow_remote_requests),
            );
        }
        if split(&self.allowed_from) != split(&base.allowed_from) {
            p.insert("allowed_from".into(), json!(split(&self.allowed_from)));
        }
        if self.server_selection != base.server_selection {
            p.insert("server_selection".into(), json!(self.server_selection));
        }
        for (k, now, was) in [
            (
                "max_queries_per_client",
                &self.max_queries_per_client,
                &base.max_queries_per_client,
            ),
            ("serve_stale_secs", &self.serve_stale_secs, &base.serve_stale_secs),
            (
                "max_udp_packet_size",
                &self.max_udp_packet_size,
                &base.max_udp_packet_size,
            ),
            (
                "query_server_timeout_ms",
                &self.query_server_timeout_ms,
                &base.query_server_timeout_ms,
            ),
            (
                "query_total_timeout_ms",
                &self.query_total_timeout_ms,
                &base.query_total_timeout_ms,
            ),
            (
                "max_concurrent_queries",
                &self.max_concurrent_queries,
                &base.max_concurrent_queries,
            ),
            (
                "max_concurrent_tcp_sessions",
                &self.max_concurrent_tcp_sessions,
                &base.max_concurrent_tcp_sessions,
            ),
            ("cache_size", &self.cache_size, &base.cache_size),
            (
                "cache_max_ttl_secs",
                &self.cache_max_ttl_secs,
                &base.cache_max_ttl_secs,
            ),
            (
                "address_list_extra_time_secs",
                &self.address_list_extra_time_secs,
                &base.address_list_extra_time_secs,
            ),
        ] {
            if now.trim() != was.trim() {
                p.insert(k.into(), form_number(now));
            }
        }
        (!p.is_empty()).then_some(Value::Object(p))
    }
}

/// One static entry, as typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StaticForm {
    pub name: String,
    pub regexp: String,
    pub rtype: String,
    pub address: String,
    pub cname: String,
    pub forward_to: String,
    pub mx_exchange: String,
    pub mx_preference: String,
    pub ns: String,
    pub srv_target: String,
    pub srv_port: String,
    pub srv_priority: String,
    pub srv_weight: String,
    pub text: String,
    pub ttl_secs: String,
    pub match_subdomain: bool,
    pub address_list: String,
    pub disabled: bool,
    pub comment: String,
}

impl Default for StaticForm {
    fn default() -> Self {
        Self {
            name: String::new(),
            regexp: String::new(),
            rtype: "A".into(),
            address: String::new(),
            cname: String::new(),
            forward_to: String::new(),
            mx_exchange: String::new(),
            mx_preference: String::new(),
            ns: String::new(),
            srv_target: String::new(),
            srv_port: String::new(),
            srv_priority: String::new(),
            srv_weight: String::new(),
            text: String::new(),
            ttl_secs: "86400".into(),
            match_subdomain: false,
            address_list: String::new(),
            disabled: false,
            comment: String::new(),
        }
    }
}

impl StaticForm {
    fn of(r: &Value) -> Self {
        Self {
            name: text(r, "name"),
            regexp: text(r, "regexp"),
            rtype: text(r, "type"),
            address: text(r, "address"),
            cname: text(r, "cname"),
            forward_to: list_text(r, "forward_to", ", "),
            mx_exchange: text(r, "mx_exchange"),
            mx_preference: text(r, "mx_preference"),
            ns: text(r, "ns"),
            srv_target: text(r, "srv_target"),
            srv_port: text(r, "srv_port"),
            srv_priority: text(r, "srv_priority"),
            srv_weight: text(r, "srv_weight"),
            text: text(r, "text"),
            ttl_secs: text(r, "ttl_secs"),
            match_subdomain: flag(r, "match_subdomain"),
            address_list: text(r, "address_list"),
            disabled: flag(r, "disabled"),
            comment: text(r, "comment"),
        }
    }

    fn strings(&self) -> [(&'static str, &String); 14] {
        [
            ("name", &self.name),
            ("regexp", &self.regexp),
            ("address", &self.address),
            ("cname", &self.cname),
            ("mx_exchange", &self.mx_exchange),
            ("mx_preference", &self.mx_preference),
            ("ns", &self.ns),
            ("srv_target", &self.srv_target),
            ("srv_port", &self.srv_port),
            ("srv_priority", &self.srv_priority),
            ("srv_weight", &self.srv_weight),
            ("text", &self.text),
            ("address_list", &self.address_list),
            ("comment", &self.comment),
        ]
    }

    fn value(k: &str, s: &str) -> Value {
        if matches!(k, "mx_preference" | "srv_port" | "srv_priority" | "srv_weight") {
            form_number(s)
        } else {
            json!(s.trim())
        }
    }

    /// `ip.dns.static.add`: the fields filled in.
    fn add_params(&self) -> Value {
        let mut p = Map::new();
        p.insert("type".into(), json!(self.rtype));
        for (k, v) in self.strings() {
            if !v.trim().is_empty() {
                p.insert(k.into(), Self::value(k, v));
            }
        }
        if !split(&self.forward_to).is_empty() {
            p.insert("forward_to".into(), json!(split(&self.forward_to)));
        }
        p.insert("ttl_secs".into(), form_number(&self.ttl_secs));
        if self.match_subdomain {
            p.insert("match_subdomain".into(), json!(true));
        }
        if self.disabled {
            p.insert("disabled".into(), json!(true));
        }
        Value::Object(p)
    }

    /// `ip.dns.static.set` for what differs from `base` ("" clears).
    fn set_params(&self, id: &str, base: &StaticForm) -> Option<Value> {
        let mut p = Map::new();
        if self.rtype != base.rtype {
            p.insert("type".into(), json!(self.rtype));
        }
        for ((k, now), (_, was)) in self.strings().into_iter().zip(base.strings()) {
            if now.trim() != was.trim() {
                let v = if now.trim().is_empty() {
                    json!("")
                } else {
                    Self::value(k, now)
                };
                p.insert(k.into(), v);
            }
        }
        if split(&self.forward_to) != split(&base.forward_to) {
            p.insert("forward_to".into(), json!(split(&self.forward_to)));
        }
        if self.ttl_secs.trim() != base.ttl_secs.trim() {
            p.insert("ttl_secs".into(), form_number(&self.ttl_secs));
        }
        if self.match_subdomain != base.match_subdomain {
            p.insert("match_subdomain".into(), json!(self.match_subdomain));
        }
        if self.disabled != base.disabled {
            p.insert("disabled".into(), json!(self.disabled));
        }
        if p.is_empty() {
            return None;
        }
        p.insert("id".into(), json!(id));
        Some(Value::Object(p))
    }
}

pub(crate) enum StaticDialog {
    New(Box<StaticForm>),
    Props {
        id: String,
        form: Box<StaticForm>,
        base: Box<StaticForm>,
    },
}

impl StaticDialog {
    fn dirty(&self) -> bool {
        match self {
            Self::New(f) => **f != StaticForm::default(),
            Self::Props { id, form, base } => form.set_params(id, base).is_some(),
        }
    }
}

pub(crate) struct StaticDialogWin {
    pub id: u64,
    pub dialog: StaticDialog,
    pub status: Status,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Button {
    Remove,
}

/// What a reply changes.
enum Reply {
    Settings(DnsForm),
    Dialog { id: u64, applied: Option<StaticForm> },
    Flushed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Act {
    Enable(Vec<String>),
    Disable(Vec<String>),
    Remove(Vec<String>),
    Open(Vec<String>),
    New,
    SelectAll,
    Refresh,
}

fn some(picked: &[&Value]) -> Result<(), String> {
    if picked.is_empty() {
        Err("Select one or more entries first".into())
    } else {
        Ok(())
    }
}

fn can_enable(picked: &[&Value], enable: bool) -> Result<(), String> {
    some(picked)?;
    if picked.iter().any(|r| flag(r, "disabled") == enable) {
        Ok(())
    } else if enable {
        Err("Already enabled".into())
    } else {
        Err("Already disabled".into())
    }
}

fn static_row(r: &Value) -> Row {
    let regexp = text(r, "regexp");
    let name = if regexp.is_empty() {
        let n = text(r, "name");
        if flag(r, "match_subdomain") {
            format!("{n} (+ subdomains)")
        } else {
            n
        }
    } else {
        format!("regexp: {regexp}")
    };
    Row {
        key: text(r, "id"),
        cells: vec![
            text(r, "flags"),
            name,
            text(r, "type"),
            text(r, "data"),
            text(r, "ttl_secs"),
            text(r, "comment"),
        ],
        dimmed: flag(r, "disabled"),
        section: false,
        tint: None,
    }
}

fn cache_row(r: &Value) -> Row {
    let kind = text(r, "kind");
    let data = match kind.as_str() {
        "nx-domain" => "NXDOMAIN".to_owned(),
        "no-data" => "(no data)".to_owned(),
        // `A 192.0.2.7`: the type is in its own column (a CNAME on the
        // way keeps its name).
        _ => {
            let prefix = format!("{} ", text(r, "type"));
            r.get("data")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(|d| d.strip_prefix(prefix.as_str()).unwrap_or(d))
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default()
        }
    };
    let ttl = if flag(r, "stale") {
        "stale".to_owned()
    } else {
        text(r, "ttl")
    };
    Row {
        key: format!("{} {}", text(r, "name"), text(r, "type")),
        cells: vec![
            text(r, "name"),
            text(r, "type"),
            data,
            ttl,
            text(r, "hits"),
            text(r, "server"),
        ],
        dimmed: flag(r, "stale"),
        section: false,
        tint: None,
    }
}

impl PanelState for DnsPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        let mut out = Vec::new();
        let open = |w| app.open.contains(&Win::Panel(w));
        if open(WIN) {
            out.push(Query {
                key: "get",
                command: "ip.dns.get",
                params: Value::Null,
            });
        }
        if (open(WIN_STATIC) || !self.dialogs.is_empty()) && app.has_command("ip.dns.static.print")
        {
            out.push(Query {
                key: "static",
                command: "ip.dns.static.print",
                params: Value::Null,
            });
        }
        if open(WIN_CACHE) {
            out.push(Query {
                key: "cache",
                command: "ip.dns.cache.print",
                params: Value::Null,
            });
        }
        out
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        match key {
            "get" if value.is_object() => {
                let now = DnsForm::of(&value);
                // Edits not applied yet stay; an untouched form follows.
                if self.waiting == 0 && self.form == self.base {
                    self.form = now.clone();
                }
                self.base = now;
                self.settings = Some(value);
            }
            "static" => {
                if let Value::Array(a) = value {
                    self.statics = a;
                }
            }
            "cache" => {
                if let Value::Array(a) = value {
                    self.cache = a;
                }
            }
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, win: &'static str, ui: &mut egui::Ui) {
        match win {
            WIN_STATIC => self.static_window(app, ui),
            WIN_CACHE => self.cache_window(app, ui),
            _ => self.settings_window(app, ui),
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        self.draw_dialogs(app, ctx, area);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        let Ok(r) = then.downcast::<Reply>() else {
            return;
        };
        match *r {
            Reply::Settings(sent) => {
                self.waiting = self.waiting.saturating_sub(1);
                match result {
                    Ok(_) => {
                        self.error = None;
                        self.base = sent;
                    }
                    Err(e) => self.error = Some(e.clone()),
                }
            }
            Reply::Dialog { id, applied } => self.dialog_reply(app, id, applied, result),
            Reply::Flushed => {}
        }
        app.cache.refreshed_at = None;
    }

    fn escape(&mut self, win: &'static str) -> bool {
        match win {
            WIN_STATIC => self.static_table.escape(),
            WIN_CACHE => self.cache_table.escape(),
            _ => false,
        }
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        vec![
            (STATIC_TABLE, &self.static_table),
            (CACHE_TABLE, &self.cache_table),
        ]
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        vec![
            (STATIC_TABLE, &mut self.static_table),
            (CACHE_TABLE, &mut self.cache_table),
        ]
    }
}

/// A labelled one-line field in a two-column grid.
fn field(ui: &mut Ui, label: &str, tip: &str, value: &mut String, width: f32) {
    let l = ui.label(label);
    if !tip.is_empty() {
        l.on_hover_text(tip);
    }
    ui.add(TextEdit::singleline(value).desired_width(width));
    ui.end_row();
}

impl DnsPanel {
    fn settings_window(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let can = app.can();
        let dirty = self.form.set_params(&self.base).is_some();
        // WinBox: the buttons on top open the other windows.
        ui.horizontal_wrapped(|ui| {
            for (label, win) in [
                ("Static", WIN_STATIC),
                ("Cache", WIN_CACHE),
                ("Statistics", crate::dns_statistics::WIN),
            ] {
                if ui.button(label).clicked() {
                    open_window(app, win);
                }
            }
            for (label, why) in LATER {
                ui.add_enabled(false, egui::Button::new(label))
                    .on_disabled_hover_text(why);
            }
        });
        ui.separator();
        let settings = self.settings.clone().unwrap_or(Value::Null);
        ScrollArea::vertical()
            .max_height(ui.available_height() - 64.0)
            .show(ui, |ui| {
                Grid::new("dns-settings")
                    .num_columns(2)
                    .spacing([12.0, 5.0])
                    .show(ui, |ui| self.settings_fields(ui, &settings));
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
                ui.weak(format!("{} not applied", dialog::UNSAVED));
            }
        });
        if let Some(e) = &self.error {
            ui.colored_label(ui.visuals().error_fg_color, e.as_str());
        }
        if apply && let Some(p) = self.form.set_params(&self.base) {
            self.waiting += 1;
            app.run_then(
                SET,
                p,
                crate::panel::then(NAME, Reply::Settings(self.form.clone())),
            );
        }
        if reset {
            self.form = self.base.clone();
            self.error = None;
        }
    }

    fn settings_fields(&mut self, ui: &mut Ui, s: &Value) {
        let f = &mut self.form;
        ui.label("Servers").on_hover_text(
            "One per line. Asked before the dynamic servers (from DHCP use_peer_dns).",
        );
        ui.add(
            TextEdit::multiline(&mut f.servers)
                .hint_text("1.1.1.1")
                .desired_rows(2)
                .desired_width(220.0),
        );
        ui.end_row();
        ui.label("Dynamic Servers");
        ui.label(list_text(s, "dynamic_servers", ", "));
        ui.end_row();
        ui.label("Allow Remote Requests")
            .on_hover_text("Answer the LAN on UDP/TCP 53 (from the networks below only).");
        ui.checkbox(&mut f.allow_remote_requests, "");
        ui.end_row();
        field(
            ui,
            "Allowed From",
            "Interface lists (their interfaces' networks) and prefixes, comma-separated. \
             Anyone else gets REFUSED: never an open resolver.",
            &mut f.allowed_from,
            220.0,
        );
        ui.label("");
        let nets = list_text(s, "allowed_networks", ", ");
        if nets.is_empty() && f.allow_remote_requests {
            ui.colored_label(
                ui.visuals().warn_fg_color,
                "No network yet: only the router itself may ask (add interfaces to the list)",
            );
        } else {
            ui.weak(if nets.is_empty() {
                "(no network)".to_owned()
            } else {
                nets
            });
        }
        ui.end_row();
        field(
            ui,
            "Max Queries per Client",
            "Per second, with a burst of twice that; 0 = no limit. Over it, UDP queries are dropped.",
            &mut f.max_queries_per_client,
            80.0,
        );
        ui.label("Server Selection").on_hover_text(
            "fastest: measures each server and asks the fastest first.\n\
             sequential: in order, the last one that answered first (RouterOS).",
        );
        egui::ComboBox::from_id_salt("dns-selection")
            .selected_text(f.server_selection.as_str())
            .show_ui(ui, |ui| {
                for m in ["fastest", "sequential"] {
                    ui.selectable_value(&mut f.server_selection, m.to_owned(), m);
                }
            });
        ui.end_row();
        field(
            ui,
            "Serve Stale (s)",
            "RFC 8767: when no server answers, an expired answer is served for up to this \
             long after its TTL; 0 = off.",
            &mut f.serve_stale_secs,
            80.0,
        );
        field(ui, "Max UDP Packet Size", "", &mut f.max_udp_packet_size, 80.0);
        field(ui, "Query Server Timeout (ms)", "", &mut f.query_server_timeout_ms, 80.0);
        field(ui, "Query Total Timeout (ms)", "", &mut f.query_total_timeout_ms, 80.0);
        field(ui, "Max Concurrent Queries", "", &mut f.max_concurrent_queries, 80.0);
        field(
            ui,
            "Max Concurrent TCP Sessions",
            "",
            &mut f.max_concurrent_tcp_sessions,
            80.0,
        );
        field(ui, "Cache Size (KiB)", "", &mut f.cache_size, 80.0);
        field(ui, "Cache Max TTL (s)", "", &mut f.cache_max_ttl_secs, 80.0);
        ui.label("Cache Used");
        ui.label(format!("{} KiB", text(s, "cache_used")));
        ui.end_row();
        field(
            ui,
            "Address List Extra Time (s)",
            "Added to the TTL of addresses a static entry puts in an address list.",
            &mut f.address_list_extra_time_secs,
            80.0,
        );
        if let Some(up) = s.get("upstream").and_then(Value::as_array)
            && !up.is_empty()
        {
            ui.label("Upstream");
            ui.vertical(|ui| {
                for u in up {
                    let rtt = u
                        .get("srtt_ms")
                        .and_then(Value::as_u64)
                        .map_or("—".to_owned(), |ms| format!("{ms} ms"));
                    let line = format!(
                        "{}  {rtt}  {} answers, {} failures",
                        text(u, "server"),
                        text(u, "answers"),
                        text(u, "failures")
                    );
                    if flag(u, "down") {
                        ui.colored_label(ui.visuals().warn_fg_color, line);
                    } else {
                        ui.label(line);
                    }
                }
            });
            ui.end_row();
        }
    }

    fn static_window(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let entries = self.statics.clone();
        let rows: Vec<Row> = entries.iter().map(static_row).collect();
        let selection = self.static_table.selection(&rows);
        let picked: Vec<&Value> = entries
            .iter()
            .filter(|r| selection.contains(&text(r, "id")))
            .collect();
        let can = app.can();
        let mut act = None;
        ui.horizontal(|ui| {
            let add = can.check("ip.dns.static.add");
            if table::tool(ui, STATIC_TABLE, Icon::Add, "Add", add).clicked() {
                act = Some(Act::New);
            }
            let tools = [
                (
                    Icon::Remove,
                    "Remove",
                    can.and("ip.dns.static.remove", some(&picked)),
                ),
                (
                    Icon::Enable,
                    "Enable",
                    can.and("ip.dns.static.set", can_enable(&picked, true)),
                ),
                (
                    Icon::Disable,
                    "Disable",
                    can.and("ip.dns.static.set", can_enable(&picked, false)),
                ),
            ];
            for (icon, tip, enabled) in tools {
                if table::tool(ui, STATIC_TABLE, icon, tip, enabled).clicked() {
                    let sel = selection.clone();
                    act = Some(match icon {
                        Icon::Enable => Act::Enable(sel),
                        Icon::Disable => Act::Disable(sel),
                        _ => Act::Remove(sel),
                    });
                }
            }
            table::find_field(ui, STATIC_TABLE, &mut self.static_table);
        });
        ui.separator();
        self.static_table.open = self
            .dialogs
            .iter()
            .filter_map(|d| match &d.dialog {
                StaticDialog::Props { id, .. } => Some(id.clone()),
                StaticDialog::New(_) => None,
            })
            .collect();
        let out = table::show(
            ui,
            STATIC_TABLE,
            0.0,
            &mut self.static_table,
            &STATIC_COLUMNS,
            &rows,
            |ui, menu| match menu {
                Menu::Rows(sel) => {
                    let picked: Vec<&Value> = entries
                        .iter()
                        .filter(|r| sel.contains(&text(r, "id")))
                        .collect();
                    let owned = || sel.to_vec();
                    for (label, cmd, ok, a) in [
                        ("Enable", "ip.dns.static.set", can_enable(&picked, true), Act::Enable(owned())),
                        ("Disable", "ip.dns.static.set", can_enable(&picked, false), Act::Disable(owned())),
                        ("Remove", "ip.dns.static.remove", some(&picked), Act::Remove(owned())),
                    ] {
                        if action(ui, label, can.and(cmd, ok)) {
                            act = Some(a);
                        }
                    }
                    if action(ui, "Properties…", some(&picked)) {
                        act = Some(Act::Open(owned()));
                    }
                }
                Menu::Empty => {
                    if action(ui, "Add Static Entry…", can.check("ip.dns.static.add")) {
                        act = Some(Act::New);
                    }
                    if ui.button("Select All").clicked() {
                        act = Some(Act::SelectAll);
                    }
                    if ui.button("Refresh").clicked() {
                        act = Some(Act::Refresh);
                    }
                }
            },
        );
        if let Some(key) = out.opened {
            act = Some(Act::Open(vec![key]));
        }
        if let Some(s) = out.shortcut {
            let sel = self.static_table.selection(&rows);
            let picked: Vec<&Value> = entries
                .iter()
                .filter(|r| sel.contains(&text(r, "id")))
                .collect();
            act = match s {
                Shortcut::Remove if some(&picked).is_ok() => Some(Act::Remove(sel)),
                Shortcut::Open if some(&picked).is_ok() => Some(Act::Open(sel)),
                Shortcut::Enable if can_enable(&picked, true).is_ok() => Some(Act::Enable(sel)),
                Shortcut::Disable if can_enable(&picked, false).is_ok() => {
                    Some(Act::Disable(sel))
                }
                _ => act,
            };
        }
        if let Some(a) = act {
            self.static_act(app, a, &rows);
        }
    }

    fn static_act(&mut self, app: &mut CoreRouterUi, act: Act, rows: &[Row]) {
        match act {
            Act::Enable(keys) | Act::Disable(keys) if keys.is_empty() => {}
            Act::Enable(keys) => {
                for id in keys {
                    app.run("ip.dns.static.set", json!({"id": id, "disabled": false}));
                }
            }
            Act::Disable(keys) => {
                for id in keys {
                    app.run("ip.dns.static.set", json!({"id": id, "disabled": true}));
                }
            }
            Act::Remove(keys) => {
                for id in keys {
                    app.run("ip.dns.static.remove", json!({ "id": id }));
                }
            }
            Act::Open(keys) => {
                for k in keys.iter().take(MAX_OPEN) {
                    self.open_static(app, k);
                }
            }
            Act::New => self.open_dialog(app, StaticDialog::New(Box::default())),
            Act::SelectAll => self.static_table.select_all(rows),
            Act::Refresh => app.cache.refreshed_at = None,
        }
    }

    fn open_dialog(&mut self, app: &mut CoreRouterUi, dialog: StaticDialog) {
        app.next_dialog = app.next_dialog.wrapping_add(1);
        self.dialogs.push(StaticDialogWin {
            id: app.next_dialog,
            dialog,
            status: Status::default(),
        });
        app.cache.refreshed_at = None;
    }

    fn open_static(&mut self, app: &mut CoreRouterUi, id: &str) {
        let Some(row) = self.statics.iter().find(|r| text(r, "id") == id).cloned() else {
            return;
        };
        if let Some(d) = self
            .dialogs
            .iter_mut()
            .find(|d| matches!(&d.dialog, StaticDialog::Props { id: i, .. } if i == id))
        {
            d.status.bring_to_front();
            return;
        }
        let form = Box::new(StaticForm::of(&row));
        self.open_dialog(app, StaticDialog::Props {
            id: id.to_owned(),
            base: form.clone(),
            form,
        });
    }

    fn draw_dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        let entries = self.statics.clone();
        let mut dialogs = std::mem::take(&mut self.dialogs);
        dialogs.retain_mut(|d| {
            let wid = dialog_id(d.id);
            let title = match &d.dialog {
                StaticDialog::New(_) => "New DNS Static Entry".to_owned(),
                StaticDialog::Props { id, form, .. } => {
                    if !entries.is_empty() && !entries.iter().any(|r| text(r, "id") == *id) {
                        // Removed elsewhere: the window goes too.
                        app.floats.forget(wid);
                        return false;
                    }
                    let n = if form.regexp.is_empty() {
                        &form.name
                    } else {
                        &form.regexp
                    };
                    format!("DNS Static Entry <{n}>")
                }
            };
            let can = app.can();
            let head = Head {
                id: wid,
                title: &title,
                dirty: d.dialog.dirty(),
                pos: cascade(area, d.id),
                parent: Some(crate::win_id(Win::Panel(WIN_STATIC))),
            };
            let pressed = dialog::show(&mut app.floats, ctx, area, head, &mut d.status, |ui, f| {
                static_body(ui, f, &mut d.dialog, &can)
            });
            let keep = pressed.is_none_or(|b| self.static_button(app, d, b));
            if !keep {
                app.floats.forget(wid);
            }
            keep
        });
        dialogs.append(&mut self.dialogs);
        self.dialogs = dialogs;
    }

    fn static_button(&mut self, app: &mut CoreRouterUi, d: &mut StaticDialogWin, b: Press<Button>) -> bool {
        let (cmd, params, applied, close) = match (&d.dialog, b) {
            (_, Press::Cancel) => return false,
            (StaticDialog::New(form), _) => ("ip.dns.static.add", form.add_params(), None, true),
            (StaticDialog::Props { id, .. }, Press::Other(Button::Remove)) => {
                ("ip.dns.static.remove", json!({ "id": id }), None, true)
            }
            (StaticDialog::Props { id, form, base }, b) => match form.set_params(id, base) {
                Some(p) => ("ip.dns.static.set", p, Some((**form).clone()), b == Press::Ok),
                None => return b != Press::Ok,
            },
        };
        d.status.close_on_success = close;
        d.status.sent();
        app.run_then(
            cmd,
            params,
            crate::panel::then(NAME, Reply::Dialog { id: d.id, applied }),
        );
        true
    }

    fn dialog_reply(
        &mut self,
        app: &mut CoreRouterUi,
        id: u64,
        applied: Option<StaticForm>,
        result: &Result<Value, String>,
    ) {
        let Some(pos) = self.dialogs.iter().position(|d| d.id == id) else {
            return;
        };
        let close = match self.dialogs.get_mut(pos) {
            None => return,
            Some(d) => {
                let close = d.status.replied(result);
                if let (Ok(_), Some(sent), StaticDialog::Props { base, .. }) =
                    (result, applied, &mut d.dialog)
                {
                    **base = sent;
                }
                close
            }
        };
        if close {
            self.dialogs.remove(pos);
            app.floats.forget(dialog_id(id));
        }
    }

    fn cache_window(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let rows: Vec<Row> = self.cache.iter().map(cache_row).collect();
        let can = app.can();
        let mut flush = false;
        ui.horizontal(|ui| {
            flush = action(ui, "Flush Cache", can.check("ip.dns.cache.flush"));
            ui.separator();
            let hits: u64 = self
                .cache
                .iter()
                .filter_map(|r| r.get("hits").and_then(Value::as_u64))
                .sum();
            ui.weak(format!("{} entries, {hits} hits", self.cache.len()));
            table::find_field(ui, CACHE_TABLE, &mut self.cache_table);
        });
        ui.separator();
        table::show(
            ui,
            CACHE_TABLE,
            0.0,
            &mut self.cache_table,
            &CACHE_COLUMNS,
            &rows,
            |ui, menu| {
                if let Menu::Empty | Menu::Rows(_) = menu
                    && ui.button("Refresh").clicked()
                {
                    app.cache.refreshed_at = None;
                }
            },
        );
        if flush {
            app.run_then(
                "ip.dns.cache.flush",
                json!({}),
                crate::panel::then(NAME, Reply::Flushed),
            );
        }
    }
}

/// Opens (or raises) one of the panel's windows.
fn open_window(app: &mut CoreRouterUi, win: &'static str) {
    if !app.open.insert(Win::Panel(win)) {
        app.floats.raise(crate::win_id(Win::Panel(win)));
    }
    app.cache.refreshed_at = None;
}

fn static_body(ui: &mut Ui, f: &Form, d: &mut StaticDialog, can: &Avail) -> Footer<Button> {
    let props = matches!(d, StaticDialog::Props { .. });
    let form = match d {
        StaticDialog::New(form) | StaticDialog::Props { form, .. } => form,
    };
    Grid::new("dns-static-fields")
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            f.text(ui, "Name", "name", &mut form.name, "nas.lan");
            f.text(ui, "Regexp", "regexp", &mut form.regexp, "instead of Name");
            ui.label("Type");
            egui::ComboBox::from_id_salt(f.window().with("type"))
                .selected_text(form.rtype.as_str())
                .show_ui(ui, |ui| {
                    for t in TYPES {
                        ui.selectable_value(&mut form.rtype, t.to_owned(), t);
                    }
                });
            ui.end_row();
            match form.rtype.as_str() {
                "A" => f.text(ui, "Address", "address", &mut form.address, "192.168.88.10"),
                "AAAA" => f.text(ui, "Address", "address", &mut form.address, "2001:db8::10"),
                "CNAME" => f.text(ui, "CNAME", "cname", &mut form.cname, "nas.lan"),
                "FWD" => f.text(ui, "Forward To", "forward_to", &mut form.forward_to, "10.0.0.53"),
                "MX" => {
                    f.text(ui, "MX Exchange", "mx_exchange", &mut form.mx_exchange, "mail.lan");
                    f.text(ui, "MX Preference", "mx_preference", &mut form.mx_preference, "10");
                }
                "NS" => f.text(ui, "NS", "ns", &mut form.ns, "ns1.lan"),
                "SRV" => {
                    f.text(ui, "SRV Target", "srv_target", &mut form.srv_target, "sip.lan");
                    f.text(ui, "SRV Port", "srv_port", &mut form.srv_port, "5060");
                    f.text(ui, "SRV Priority", "srv_priority", &mut form.srv_priority, "0");
                    f.text(ui, "SRV Weight", "srv_weight", &mut form.srv_weight, "0");
                }
                "TXT" => f.text(ui, "Text", "text", &mut form.text, ""),
                _ => {}
            }
            f.text(ui, "TTL (s)", "ttl_secs", &mut form.ttl_secs, "86400");
            ui.label("Match Subdomain");
            ui.checkbox(&mut form.match_subdomain, "");
            ui.end_row();
            f.text(ui, "Address List", "address_list", &mut form.address_list, "");
            f.text(ui, "Comment", "comment", &mut form.comment, "");
            ui.label("Disabled");
            ui.checkbox(&mut form.disabled, "");
            ui.end_row();
        });
    if form.rtype == "FWD" || !form.address_list.is_empty() {
        ui.label(
            RichText::new(
                "FWD: the name (and its subdomains with Match Subdomain) is asked of these \
                 servers. Address List: answered addresses go into that firewall list.",
            )
            .weak()
            .small(),
        );
    }
    let ok = can.check(if props {
        "ip.dns.static.set"
    } else {
        "ip.dns.static.add"
    });
    let mut footer = Footer::edit(true, ok);
    if props {
        footer.extra = vec![("Remove", Button::Remove, can.check("ip.dns.static.remove"))];
    }
    footer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_send_only_what_changed() {
        let v = json!({"servers": ["1.1.1.1"], "allow_remote_requests": false,
            "allowed_from": ["LAN"], "max_queries_per_client": 200,
            "server_selection": "fastest", "serve_stale_secs": 86400, "cache_size": 2048});
        let base = DnsForm::of(&v);
        let mut f = base.clone();
        assert_eq!(f.set_params(&base), None);
        f.allow_remote_requests = true;
        f.allowed_from = "LAN, 10.0.0.0/8".into();
        f.cache_size = "4096".into();
        assert_eq!(
            f.set_params(&base).unwrap(),
            json!({"allow_remote_requests": true, "allowed_from": ["LAN", "10.0.0.0/8"],
                "cache_size": 4096})
        );
    }

    #[test]
    fn static_forms() {
        let f = StaticForm {
            name: "nas.lan".into(),
            address: "192.168.88.2".into(),
            ..StaticForm::default()
        };
        assert_eq!(
            f.add_params(),
            json!({"type": "A", "name": "nas.lan", "address": "192.168.88.2", "ttl_secs": 86400})
        );
        let row = json!({"id": "*1", "name": "nas.lan", "type": "A", "address": "192.168.88.2",
            "ttl_secs": 86400, "data": "192.168.88.2", "flags": ""});
        let base = StaticForm::of(&row);
        let mut now = base.clone();
        now.rtype = "CNAME".into();
        now.address.clear();
        now.cname = "files.lan".into();
        assert_eq!(
            now.set_params("*1", &base).unwrap(),
            json!({"id": "*1", "type": "CNAME", "address": "", "cname": "files.lan"})
        );
        assert_eq!(static_row(&row).cells[1], "nas.lan");
        let c = json!({"name": "www.x", "type": "A", "kind": "records",
            "data": ["CNAME x.", "A 192.0.2.7"], "ttl": 5, "hits": 2});
        assert_eq!(cache_row(&c).cells[2], "CNAME x., 192.0.2.7");
    }
}
