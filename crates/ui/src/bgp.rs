//! Routing › BGP (G3.2a), in the RouterOS v7 model: the tabs Sessions
//! (live, read-only, with the detail of the selected one and its actions),
//! Connections (the neighbors) and Templates (shared parameters), in the
//! list window pattern (G0.24, `docs/ui-style.md`), plus Instances (local
//! AS and router id). `routing.bgp.*` decides; this only shows and sends.
//!
//! The window stays `Win::Bgp` (its place in the menu and the stored
//! preferences); `windows.rs` hands this panel the drawing.

use std::collections::BTreeMap;

use egui::{Grid, RichText, TextEdit, Ui};
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind, cell};
use crate::help::{self, HelpView};
use crate::i18n::tr_in;
use crate::list::{self, Act, Cmds, Filters, Item, Tools};
use crate::list_modal::{self, Applied, Field, Input, Modal, Spec};
use crate::panel::{Panel, PanelState, PanelThen, Query};
use crate::table::{self, Menu, Row, TableState, col, comment, num};
use crate::{CoreRouterUi, Then, Win, value_text};

pub(crate) const NAME: &str = "bgp";
/// What `windows.rs` passes as the window id.
pub(crate) const WIN: &str = "bgp";
/// Labels' scope (`i18n/auto/bgp_*.rs`).
const SCOPE: &str = "bgp";
const SESSIONS: &str = "bgp-sessions";
const CONNECTIONS: &str = "bgp-connections";
const TEMPLATES: &str = "bgp-templates";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[],
    new: || Box::new(BgpPanel::default()),
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Tab {
    #[default]
    Sessions,
    Connections,
    Templates,
    Instances,
}

const TABS: [(Tab, &str, &str); 4] = [
    (Tab::Sessions, "Sessions", "bgp.tab.sessions"),
    (Tab::Connections, "Connections", "bgp.tab.connections"),
    (Tab::Templates, "Templates", "bgp.tab.templates"),
    (Tab::Instances, "Instances", "bgp.tab.instances"),
];

const CONN_CMDS: Cmds = Cmds {
    add: "routing.bgp.connection.add",
    remove: "routing.bgp.connection.remove",
    set: Some("routing.bgp.connection.set"),
    what: "connections",
};

const TPL_CMDS: Cmds = Cmds {
    add: "routing.bgp.template.add",
    remove: "routing.bgp.template.remove",
    set: Some("routing.bgp.template.set"),
    what: "templates",
};

const fn field(param: &'static str, label: &'static str, help: &'static str, input: Input) -> Field {
    Field {
        param,
        label,
        help,
        input,
        edit: true,
    }
}

/// The shared parameters, in the modal's pages.
const SESSION_PAGE: &[&str] = &["hold_time", "keepalive_time", "multihop", "update_source", "tcp_md5_key", "nexthop_choice"];
const LIMITS_PAGE: &[&str] = &["afi", "max_prefix_ipv4", "max_prefix_ipv6", "max_prefix_action", "max_prefix_restart"];

const CONN_FIELDS: &[Field] = &[
    field("name", "Name", "bgp.connection.name", Input::Text("upstream1")),
    field("remote_address", "Remote Address", "bgp.connection.remote_address", Input::Text("192.0.2.1")),
    field("remote_as", "Remote AS", "bgp.param.remote_as", Input::Text("65100 (empty: any)")),
    field("local_role", "Local Role", "bgp.param.local_role", Input::Choice),
    field("templates", "Templates", "bgp.param.templates", Input::Text("transit (comma-separated)")),
    field("instance", "Instance", "bgp.connection.instance", Input::Choice),
    field("disabled", "Disabled", "bgp.connection.disabled", Input::Check),
    field("comment", "Comment", "", Input::Text("")),
    field("hold_time", "Hold Time", "bgp.param.hold_time", Input::Text("180 s (0 = infinity)")),
    field("keepalive_time", "Keepalive Time", "bgp.param.keepalive_time", Input::Text("a third of the hold time")),
    field("multihop", "Multihop", "bgp.param.multihop", Input::Choice),
    field("update_source", "Local Address", "bgp.param.update_source", Input::Text("address or interface")),
    field("tcp_md5_key", "TCP MD5 Key", "bgp.param.tcp_md5_key", Input::Secret("empty keeps it")),
    field("nexthop_choice", "Nexthop Choice", "bgp.param.nexthop_choice", Input::Choice),
    field("afi", "Address Families", "bgp.param.afi", Input::Choice),
    field("max_prefix_ipv4", "Max Prefixes IPv4", "bgp.param.max_prefix", Input::Text("no limit")),
    field("max_prefix_ipv6", "Max Prefixes IPv6", "bgp.param.max_prefix", Input::Text("no limit")),
    field("max_prefix_action", "Over the Limit", "bgp.param.max_prefix_action", Input::Choice),
    field("max_prefix_restart", "Restart After", "bgp.param.max_prefix_restart", Input::Text("5 min")),
];

const TPL_FIELDS: &[Field] = &[
    field("name", "Name", "bgp.template.name", Input::Text("transit")),
    field("templates", "Templates", "bgp.param.templates", Input::Text("parents (comma-separated)")),
    field("remote_as", "Remote AS", "bgp.param.remote_as", Input::Text("empty: any")),
    field("local_role", "Local Role", "bgp.param.local_role", Input::Choice),
    field("comment", "Comment", "", Input::Text("")),
    field("hold_time", "Hold Time", "bgp.param.hold_time", Input::Text("180 s (0 = infinity)")),
    field("keepalive_time", "Keepalive Time", "bgp.param.keepalive_time", Input::Text("a third of the hold time")),
    field("multihop", "Multihop", "bgp.param.multihop", Input::Choice),
    field("update_source", "Local Address", "bgp.param.update_source", Input::Text("address or interface")),
    field("tcp_md5_key", "TCP MD5 Key", "bgp.param.tcp_md5_key", Input::Secret("empty keeps it")),
    field("nexthop_choice", "Nexthop Choice", "bgp.param.nexthop_choice", Input::Choice),
    field("afi", "Address Families", "bgp.param.afi", Input::Choice),
    field("max_prefix_ipv4", "Max Prefixes IPv4", "bgp.param.max_prefix", Input::Text("no limit")),
    field("max_prefix_ipv6", "Max Prefixes IPv6", "bgp.param.max_prefix", Input::Text("no limit")),
    field("max_prefix_action", "Over the Limit", "bgp.param.max_prefix_action", Input::Choice),
    field("max_prefix_restart", "Restart After", "bgp.param.max_prefix_restart", Input::Text("5 min")),
];

pub(crate) const CONN_SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Bgp,
    new_title: "New BGP Connection",
    edit_title: "BGP Connection",
    help: "bgp.connection",
    fields: CONN_FIELDS,
    preview: "routing.bgp.connection.check",
};

pub(crate) const TPL_SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Bgp,
    new_title: "New BGP Template",
    edit_title: "BGP Template",
    help: "bgp.template",
    fields: TPL_FIELDS,
    preview: "routing.bgp.template.check",
};

const SESSION_COLUMNS: [table::Column; 8] = [
    col("State").help("bgp.session.state"),
    col("Name").help("bgp.connection.name"),
    col("Remote Address").help("bgp.connection.remote_address"),
    col("Remote AS").help("bgp.param.remote_as"),
    num("Uptime").help("bgp.session.uptime"),
    num("Prefixes In").help("bgp.session.prefixes_in"),
    num("Prefixes Out").help("bgp.session.prefixes_out"),
    col("BFD").help("bgp.session.bfd"),
];

const CONN_COLUMNS: [table::Column; 10] = [
    col("State").help("bgp.session.state"),
    col("Name").help("bgp.connection.name"),
    col("Remote Address").help("bgp.connection.remote_address"),
    col("Remote AS").help("bgp.param.remote_as"),
    col("Kind").help("bgp.param.local_role"),
    col("Templates").help("bgp.param.templates"),
    col("Families").help("bgp.param.afi"),
    num("Hold").help("bgp.param.hold_time"),
    col("Key").help("bgp.param.tcp_md5_key"),
    comment(),
];

const TPL_COLUMNS: [table::Column; 8] = [
    col("Name").help("bgp.template.name"),
    col("Templates").help("bgp.param.templates"),
    col("Remote AS").help("bgp.param.remote_as"),
    col("Local Role").help("bgp.param.local_role"),
    num("Hold").help("bgp.param.hold_time"),
    col("Families").help("bgp.param.afi"),
    col("Used By").help("bgp.template.used_by"),
    comment(),
];

#[derive(Default)]
pub(crate) struct BgpPanel {
    pub(crate) tab: Tab,
    pub(crate) sessions: Vec<Value>,
    pub(crate) connections: Vec<Value>,
    pub(crate) templates: Vec<Value>,
    session_table: TableState,
    conn_table: TableState,
    tpl_table: TableState,
    filters: Filters,
    pub(crate) modal: Option<(What, Modal)>,
    /// The modal's page.
    page: usize,
    pub(crate) help: Option<HelpView>,
}

/// Which list a modal edits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum What {
    Connection,
    Template,
}

fn s(r: &Value, k: &str) -> String {
    r.get(k).map(value_text).unwrap_or_default()
}

fn u(r: &Value, k: &str) -> Option<u64> {
    r.get(k).and_then(Value::as_u64)
}

fn flag(r: &Value, k: &str) -> bool {
    r.get(k).and_then(Value::as_bool).unwrap_or(false)
}

/// `AS65100`, coloured by the AS (the same AS has the same colour in every
/// row and window).
fn as_chip(asn: Option<u64>) -> Option<(String, Kind)> {
    asn.filter(|a| *a > 0)
        .map(|a| (format!("AS{a}"), Kind::Hashed(chip::hashed(a))))
}

fn state_kind(state: &str, failed: bool) -> Kind {
    match state {
        "established" => Kind::Green,
        "disabled" | "unknown" => Kind::Neutral,
        _ if failed => Kind::Red,
        _ => Kind::Amber,
    }
}

fn dash(v: Option<u64>) -> String {
    v.map_or_else(|| "–".to_owned(), |n| n.to_string())
}

/// One row of the Sessions tab: a connection and its live session (or a
/// session FRR runs that no connection names).
#[derive(Debug, Clone, Default)]
pub(crate) struct SessionRow {
    pub key: String,
    pub connection: Option<Value>,
    pub session: Option<Value>,
}

impl SessionRow {
    fn get(&self, k: &str) -> Option<&Value> {
        self.session
            .as_ref()
            .and_then(|v| v.get(k))
            .filter(|v| !v.is_null())
            .or_else(|| self.connection.as_ref().and_then(|v| v.get(k)))
    }

    fn text(&self, k: &str) -> String {
        self.get(k).map(value_text).unwrap_or_default()
    }

    fn num(&self, k: &str) -> Option<u64> {
        self.get(k).and_then(Value::as_u64)
    }

    fn state(&self) -> String {
        if self.connection.as_ref().is_some_and(|c| flag(c, "disabled")) {
            return "disabled".into();
        }
        match self.session.as_ref().map(|v| s(v, "state")) {
            Some(st) if !st.is_empty() => st,
            _ => "unknown".into(),
        }
    }

    fn remote_as(&self) -> Option<u64> {
        self.session
            .as_ref()
            .and_then(|v| u(v, "remote_as"))
            .filter(|a| *a > 0)
            .or_else(|| {
                self.connection
                    .as_ref()
                    .and_then(|c| c.get("effective"))
                    .and_then(|e| u(e, "remote_as"))
            })
    }

    fn failed(&self) -> bool {
        self.session
            .as_ref()
            .is_some_and(|v| v.get("last_error").is_some_and(|e| !e.is_null()) || v.get("reason").is_some_and(|e| !e.is_null()))
    }

    fn row(&self) -> Row {
        let state = self.state();
        let shown_state = if state == "unknown" { "no daemon".to_owned() } else { state.clone() };
        let remote_as: Vec<(String, Kind)> = as_chip(self.remote_as()).into_iter().collect();
        let bfd = match self.text("bfd").as_str() {
            "" => "–".to_owned(),
            b => cell("", &[(b, if b == "up" { Kind::Green } else { Kind::Red })]),
        };
        let pair = |v: &[(String, Kind)]| -> String {
            let c: Vec<(&str, Kind)> = v.iter().map(|(t, k)| (t.as_str(), *k)).collect();
            cell("", &c)
        };
        let uptime = match (self.num("uptime_secs"), state.as_str()) {
            (Some(secs), "established") => crate::neighbors::uptime_text(secs),
            _ => "–".to_owned(),
        };
        Row {
            key: self.key.clone(),
            cells: vec![
                cell("", &[(shown_state.as_str(), state_kind(&state, self.failed()))]),
                self.text("name").chars().take(64).collect::<String>().replace('\u{1f}', ""),
                self.text("remote_address"),
                pair(&remote_as),
                uptime,
                dash(self.num("prefix_count")),
                dash(self.num("prefix_sent")),
                bfd,
            ],
            dimmed: state == "disabled",
            section: false,
            tint: None,
        }
    }
}

/// Connections joined with the sessions, by connection name; sessions no
/// connection names come last (typed into FRR by hand).
pub(crate) fn session_rows(connections: &[Value], sessions: &[Value]) -> Vec<SessionRow> {
    let by_name: BTreeMap<String, &Value> = sessions
        .iter()
        .filter_map(|v| v.get("connection").and_then(Value::as_str).map(|c| (c.to_owned(), v)))
        .collect();
    let mut out: Vec<SessionRow> = connections
        .iter()
        .map(|c| {
            let name = s(c, "name");
            SessionRow {
                key: name.clone(),
                session: by_name.get(&name).map(|v| (*v).clone()),
                connection: Some(c.clone()),
            }
        })
        .collect();
    for v in sessions {
        let named = v
            .get("connection")
            .and_then(Value::as_str)
            .is_some_and(|c| connections.iter().any(|x| s(x, "name") == c));
        if !named {
            let mut v = v.clone();
            if let Some(o) = v.as_object_mut() {
                let label = format!("({})", s(&Value::Object(o.clone()), "remote_address"));
                o.insert("name".into(), json!(label));
            }
            out.push(SessionRow {
                key: format!("frr:{}:{}", s(&v, "instance"), s(&v, "remote_address")),
                connection: None,
                session: Some(v),
            });
        }
    }
    out
}

fn conn_row(r: &Value) -> Row {
    let state = s(r, "state");
    let eff = r.get("effective").cloned().unwrap_or(Value::Null);
    let kind = s(r, "kind");
    // iBGP without a remote AS is in ours.
    let asn = u(&eff, "remote_as").or_else(|| (kind == "ibgp").then(|| u(r, "local_as")).flatten());
    let remote_as: Vec<(String, Kind)> = as_chip(asn).into_iter().collect();
    let role = eff.get("local_role").and_then(Value::as_str).unwrap_or(kind.as_str()).to_owned();
    let fams: Vec<String> = eff
        .get("afi")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect())
        .unwrap_or_else(|| vec!["ip".into()]);
    let hold = u(&eff, "hold_time").map_or_else(|| "180".to_owned(), |h| if h == 0 { "∞".into() } else { h.to_string() });
    let refs = |v: &[(String, Kind)]| -> String {
        let c: Vec<(&str, Kind)> = v.iter().map(|(t, k)| (t.as_str(), *k)).collect();
        cell("", &c)
    };
    let mut state_chips = vec![(if state == "unknown" { "no daemon".to_owned() } else { state.clone() }, state_kind(&state, false))];
    if r.get("error").is_some_and(|e| !e.is_null()) {
        state_chips.push(("invalid".into(), Kind::Red));
    }
    Row {
        key: s(r, "name"),
        cells: vec![
            refs(&state_chips),
            s(r, "name"),
            s(r, "remote_address"),
            refs(&remote_as),
            cell("", &[(role.as_str(), if kind == "ibgp" { Kind::Blue } else { Kind::Neutral })]),
            r.get("templates")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "))
                .unwrap_or_default(),
            fams.join(", "),
            hold,
            if flag(r, "key_set") { cell("", &[("md5", Kind::Green)]) } else { "–".to_owned() },
            s(r, "comment"),
        ],
        dimmed: flag(r, "disabled"),
        section: false,
        tint: None,
    }
}

fn tpl_row(r: &Value) -> Row {
    let eff = r.get("effective").cloned().unwrap_or(Value::Null);
    let remote_as: Vec<(&str, Kind)> = Vec::new();
    let asn = as_chip(u(&eff, "remote_as"));
    let as_cell = asn.as_ref().map_or_else(|| cell("", &remote_as), |(t, k)| cell("", &[(t.as_str(), *k)]));
    let list = |k: &str, v: &Value| -> String {
        v.get(k)
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "))
            .unwrap_or_default()
    };
    let mut name = cell(&s(r, "name"), &[]);
    if r.get("error").is_some_and(|e| !e.is_null()) {
        name = cell(&s(r, "name"), &[("invalid", Kind::Red)]);
    }
    Row {
        key: s(r, "name"),
        cells: vec![
            name,
            list("templates", r),
            as_cell,
            s(&eff, "local_role"),
            u(&eff, "hold_time").map(|h| h.to_string()).unwrap_or_default(),
            list("afi", &eff),
            list("used_by", r),
            s(r, "comment"),
        ],
        dimmed: false,
        section: false,
        tint: None,
    }
}

/// The modal's fields for an existing row: its own values (an empty field
/// inherits).
fn values_of(r: &Value, what: What) -> BTreeMap<&'static str, String> {
    let own = r.get("params").cloned().unwrap_or(Value::Null);
    let fields = match what {
        What::Connection => CONN_FIELDS,
        What::Template => TPL_FIELDS,
    };
    let mut out = BTreeMap::new();
    for f in fields {
        let v = match f.param {
            "name" | "remote_address" | "instance" | "comment" => s(r, f.param),
            "templates" => r
                .get("templates")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(","))
                .unwrap_or_default(),
            "disabled" => if flag(r, "disabled") { "yes" } else { "no" }.to_owned(),
            // Write-only: never shown, empty keeps it.
            "tcp_md5_key" => String::new(),
            "multihop" => match own.get("multihop").and_then(Value::as_bool) {
                Some(true) => "yes".into(),
                Some(false) => "no".into(),
                None => String::new(),
            },
            "afi" => own
                .get("afi")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(","))
                .unwrap_or_default(),
            p => own.get(p).map(value_text).unwrap_or_default(),
        };
        out.insert(f.param, v);
    }
    out
}

/// The choices of a choice field (empty: unset, inherit).
fn options(param: &str, instances: &[String]) -> Vec<String> {
    let v: &[&str] = match param {
        "local_role" => &["", "ibgp", "ebgp", "ebgp-provider", "ebgp-customer", "ebgp-peer", "ebgp-rs", "ebgp-rs-client"],
        "multihop" => &["", "yes", "no"],
        "nexthop_choice" => &["", "default", "force-self", "propagate"],
        "afi" => &["", "ip", "ipv6", "ip,ipv6"],
        "max_prefix_action" => &["", "shutdown", "warning", "restart"],
        "instance" => return instances.to_vec(),
        _ => &[],
    };
    v.iter().map(|s| (*s).to_owned()).collect()
}

impl BgpPanel {
    fn tabs(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        ui.horizontal(|ui| {
            for (tab, label, key) in TABS {
                if ui.selectable_label(self.tab == tab, tr_in(SCOPE, l, label)).clicked() {
                    self.tab = tab;
                    app.cache.refreshed_at = None;
                }
                if help::info_button(ui, egui::Id::unique(("bgp-tab-help", key)), tr_in(SCOPE, l, label)).clicked() {
                    self.help = Some(HelpView::new(key, tr_in(SCOPE, l, label)));
                }
                ui.add_space(6.0);
            }
        });
    }

    fn column_help(&mut self, app: &CoreRouterUi, key: Option<&'static str>, columns: &[table::Column]) {
        if let Some(key) = key {
            let title = columns.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help = Some(HelpView::new(key, tr_in(SCOPE, app.lang.labels, title)));
        }
    }

    fn sessions_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let rows_data = session_rows(&self.connections, &self.sessions);
        let rows: Vec<Row> = rows_data.iter().map(SessionRow::row).collect();
        let selection = self.session_table.selection(&rows);
        ui.horizontal(|ui| {
            table::find_field(ui, SESSIONS, &mut self.session_table);
        });
        ui.separator();
        let picked = selection
            .as_slice()
            .first()
            .and_then(|k| rows_data.iter().find(|r| &r.key == k))
            .cloned();
        let detail_h = if picked.is_some() { 170.0 } else { 0.0 };
        let footer_h = ui.spacing().interact_size.y + 6.0 + detail_h;
        let out = table::show(ui, SESSIONS, footer_h, &mut self.session_table, &SESSION_COLUMNS, &rows, |_, _| {});
        self.column_help(app, out.help, &SESSION_COLUMNS);
        if let Some(r) = picked {
            ui.separator();
            self.detail(app, ui, &r);
        }
        let v = ui.visuals().clone();
        let count = |f: &dyn Fn(&SessionRow) -> bool| rows_data.iter().filter(|r| f(r)).count();
        list::footer(
            ui,
            &[
                (rows_data.len(), "sessions", chip::neutral_tone(&v)),
                (count(&|r| r.state() == "established"), "established", chip::GREEN.tone(&v)),
                (
                    count(&|r| !matches!(r.state().as_str(), "established" | "disabled" | "unknown")),
                    "down",
                    chip::RED.tone(&v),
                ),
                (count(&|r| r.state() == "disabled"), "disabled", chip::neutral_tone(&v)),
            ],
            l,
        );
        if rows_data.is_empty() {
            ui.weak(tr_in(SCOPE, l, "No BGP connection yet: add one in the Connections tab."));
        }
    }

    /// The selected session: what the table has no room for, and its actions.
    fn detail(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, r: &SessionRow) {
        let l = app.lang.labels;
        let kind = r.connection.as_ref().map(|c| s(c, "kind")).unwrap_or_default();
        let policy = |k: &str| {
            let p = r.text(k);
            if !p.is_empty() {
                p
            } else if kind == "ebgp" {
                tr_in(SCOPE, l, "none (RFC 8212: nothing accepted or sent)").to_owned()
            } else {
                tr_in(SCOPE, l, "none").to_owned()
            }
        };
        let hold = match (r.num("hold_time"), r.num("keepalive_time")) {
            (Some(h), Some(k)) => format!("{h} s / {k} s"),
            _ => r
                .connection
                .as_ref()
                .and_then(|c| c.get("effective"))
                .map(|e| {
                    let h = u(e, "hold_time").unwrap_or(180);
                    let k = u(e, "keepalive_time").unwrap_or(h / 3);
                    format!("{h} s / {k} s ({})", tr_in(SCOPE, l, "configured"))
                })
                .unwrap_or_else(|| "–".into()),
        };
        let last_error = {
            let e = r.text("last_error");
            if e.is_empty() { r.text("reason") } else { e }
        };
        let families = r
            .get("afi")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "))
            .unwrap_or_default();
        let lines: [(&str, &str, String); 8] = [
            ("Last Error", "bgp.session.last_error", if last_error.is_empty() { "–".into() } else { last_error }),
            ("Hold / Keepalive", "bgp.session.timers", hold),
            ("Policy In", "bgp.session.policy", policy("policy_in")),
            ("Policy Out", "bgp.session.policy", policy("policy_out")),
            ("Flaps", "bgp.session.flaps", dash(r.num("flaps"))),
            ("Remote ID", "bgp.session.remote_id", { let t = r.text("remote_id"); if t.is_empty() { "–".into() } else { t } }),
            (
                "Messages",
                "bgp.session.messages",
                match (r.num("messages_received"), r.num("messages_sent")) {
                    (Some(a), Some(b)) => format!("{a} in / {b} out"),
                    _ => "–".into(),
                },
            ),
            ("Families", "bgp.param.afi", if families.is_empty() { "–".into() } else { families }),
        ];
        let mut help = None;
        ui.columns(2, |cols| {
            let (left, right) = cols.split_at_mut(1);
            for (i, (label, key, value)) in lines.iter().enumerate() {
                let Some(ui) = (if i < 4 { left.first_mut() } else { right.first_mut() }) else {
                    continue;
                };
                ui.horizontal(|ui| {
                    ui.label(RichText::new(tr_in(SCOPE, l, label)).weak());
                    if help::info_button(ui, egui::Id::unique(("bgp-detail-help", i)), tr_in(SCOPE, l, label)).clicked() {
                        help = Some(HelpView::new(*key, tr_in(SCOPE, l, label)));
                    }
                    let red = *label == "Last Error" && value != "–";
                    let text = RichText::new(value.as_str());
                    ui.label(if red { text.color(ui.visuals().error_fg_color) } else { text });
                });
            }
        });
        if help.is_some() {
            self.help = help;
        }
        let Some(conn) = r.connection.as_ref() else {
            ui.weak(tr_in(SCOPE, l, "Not a CoreRouter connection (typed into FRR by hand)."));
            return;
        };
        let name = s(conn, "name");
        let disabled = flag(conn, "disabled");
        let can = app.can();
        ui.horizontal(|ui| {
            let live = if disabled { Err("the connection is disabled".to_owned()) } else { Ok(()) };
            for (label, cmd, tip) in [
                ("Refresh", "routing.bgp.session.refresh", "Ask the neighbor to send its routes again (RFC 2918): new inbound policy, no reset"),
                ("Resend", "routing.bgp.session.resend", "Send our routes again: new outbound policy, no reset"),
                ("Clear", "routing.bgp.session.clear", "Close the session and open it again (its routes are withdrawn meanwhile)"),
            ] {
                if button(ui, tr_in(SCOPE, l, label), tr_in(SCOPE, l, tip), can.and(cmd, live.clone())) {
                    app.run(cmd, json!({"connection": name}));
                }
            }
            ui.separator();
            let (label, to) = if disabled { ("Enable", false) } else { ("Shutdown", true) };
            let tip = tr_in(SCOPE, l, "Shutdown closes the session (Cease, administrative shutdown) and keeps the connection");
            if button(ui, tr_in(SCOPE, l, label), tip, can.check("routing.bgp.connection.set")) {
                app.run("routing.bgp.connection.set", json!({"id": name, "disabled": to}));
            }
        });
    }

    fn connections_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let all = self.connections.clone();
        let shown: Vec<&Value> = all.iter().filter(|r| self.filters.shows(r)).collect();
        let rows: Vec<Row> = shown.iter().map(|r| conn_row(r)).collect();
        let selection = self.conn_table.selection(&rows);
        let picked: Vec<Item> = shown
            .iter()
            .filter(|r| selection.contains(&s(r, "name")))
            .map(|r| Item::of(r, "name", ""))
            .collect();
        let tools = Tools::new(&app.can(), &CONN_CMDS, &picked);
        let mut act = None;
        ui.horizontal(|ui| {
            act = list::toolbar(ui, CONNECTIONS, &tools, &selection, l);
            ui.separator();
            self.filters.chips(ui, "kind", &[("ebgp", "eBGP"), ("ibgp", "iBGP")], l);
            table::find_field(ui, CONNECTIONS, &mut self.conn_table);
        });
        ui.separator();
        let known = !app.cache.commands.is_empty();
        let footer_h = ui.spacing().interact_size.y + 6.0;
        let out = table::show(ui, CONNECTIONS, footer_h, &mut self.conn_table, &CONN_COLUMNS, &rows, |ui, menu| match menu {
            Menu::Rows(sel) => {
                let picked: Vec<Item> = all.iter().filter(|r| sel.contains(&s(r, "name"))).map(|r| Item::of(r, "name", "")).collect();
                let tools = Tools::new(&app.can, &CONN_CMDS, &picked);
                if let Some(a) = list::row_menu(ui, &tools, sel, known, l) {
                    act = Some(a);
                }
            }
            Menu::Empty => {
                if table::action(ui, tr_in(SCOPE, l, "New Connection…"), tools.add.clone()) {
                    act = Some(Act::Add);
                }
            }
        });
        self.column_help(app, out.help, &CONN_COLUMNS);
        act = act
            .or_else(|| list::from_shortcut(out.shortcut, &tools, &selection))
            .or_else(|| out.opened.or(out.comment).map(Act::Edit));
        let v = ui.visuals().clone();
        list::footer(
            ui,
            &[
                (all.len(), "connections", chip::neutral_tone(&v)),
                (all.iter().filter(|r| flag(r, "established")).count(), "established", chip::GREEN.tone(&v)),
                (list::count(&all, "kind", "ebgp"), "eBGP", chip::neutral_tone(&v)),
                (list::count(&all, "kind", "ibgp"), "iBGP", chip::BLUE.tone(&v)),
                (all.iter().filter(|r| flag(r, "disabled")).count(), "disabled", chip::neutral_tone(&v)),
            ],
            l,
        );
        if let Some(a) = act {
            self.act(app, a, ui, &rows, What::Connection);
        }
    }

    fn templates_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let all = self.templates.clone();
        let rows: Vec<Row> = all.iter().map(tpl_row).collect();
        let selection = self.tpl_table.selection(&rows);
        let picked: Vec<Item> = all
            .iter()
            .filter(|r| selection.contains(&s(r, "name")))
            .map(|r| Item::of(r, "name", ""))
            .collect();
        let mut tools = Tools::new(&app.can(), &TPL_CMDS, &picked);
        // A template has nothing to switch off: its connections do.
        let none = Err("a template is not enabled or disabled: its connections are".to_owned());
        tools.enable = none.clone();
        tools.disable = none;
        let mut act = None;
        ui.horizontal(|ui| {
            act = list::toolbar(ui, TEMPLATES, &tools, &selection, l);
            table::find_field(ui, TEMPLATES, &mut self.tpl_table);
        });
        ui.separator();
        let known = !app.cache.commands.is_empty();
        let footer_h = ui.spacing().interact_size.y + 6.0;
        let out = table::show(ui, TEMPLATES, footer_h, &mut self.tpl_table, &TPL_COLUMNS, &rows, |ui, menu| match menu {
            Menu::Rows(sel) => {
                if let Some(a) = list::row_menu(ui, &tools, sel, known, l) {
                    act = Some(a);
                }
            }
            Menu::Empty => {
                if table::action(ui, tr_in(SCOPE, l, "New Template…"), tools.add.clone()) {
                    act = Some(Act::Add);
                }
            }
        });
        self.column_help(app, out.help, &TPL_COLUMNS);
        act = act
            .or_else(|| list::from_shortcut(out.shortcut, &tools, &selection))
            .or_else(|| out.opened.or(out.comment).map(Act::Edit));
        let v = ui.visuals().clone();
        let used = all.iter().filter(|r| r.get("used_by").and_then(Value::as_array).is_some_and(|a| !a.is_empty())).count();
        list::footer(
            ui,
            &[(all.len(), "templates", chip::neutral_tone(&v)), (used, "in use", chip::BLUE.tone(&v))],
            l,
        );
        if let Some(a) = act {
            self.act(app, a, ui, &rows, What::Template);
        }
    }

    /// Instances: the local AS and router id (`routing.bgp.instance.set`).
    fn instances_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        Grid::new("bgp-instances").striped(true).show(ui, |ui| {
            for h in ["Name", "AS", "Router ID", "Disabled"] {
                ui.strong(tr_in(SCOPE, l, h));
            }
            ui.end_row();
            for row in &app.cache.bgp {
                ui.label(s(row, "name"));
                let asn = u(row, "asn");
                match as_chip(asn) {
                    Some((t, k)) => {
                        chip::chip(ui, &t, k.tone(ui.visuals()));
                    }
                    None => {
                        ui.label("–");
                    }
                }
                ui.label(s(row, "router_id"));
                ui.label(s(row, "disabled"));
                ui.end_row();
            }
        });
        ui.separator();
        let mut help = None;
        Grid::new("bgp-instance-form").num_columns(2).show(ui, |ui| {
            for (label, key, hint, which) in [
                ("Name", "bgp.instance.name", "default", 0),
                ("AS", "bgp.instance.asn", "65000 or 1.10", 1),
                ("Router ID", "bgp.instance.router_id", "10.255.0.1", 2),
            ] {
                ui.horizontal(|ui| {
                    ui.label(tr_in(SCOPE, l, label));
                    if help::info_button(ui, egui::Id::unique(("bgp-inst-help", which)), tr_in(SCOPE, l, label)).clicked() {
                        help = Some(HelpView::new(key, tr_in(SCOPE, l, label)));
                    }
                });
                let v = match which {
                    0 => &mut app.forms.bgp_name,
                    1 => &mut app.forms.bgp_asn,
                    _ => &mut app.forms.bgp_router_id,
                };
                ui.add(TextEdit::singleline(v).hint_text(hint));
                ui.end_row();
            }
        });
        if help.is_some() {
            self.help = help;
        }
        if table::action(ui, tr_in(SCOPE, l, "Apply"), app.can.check("routing.bgp.instance.set")) {
            let p = json!({
                "name": app.forms.bgp_name.trim(),
                "asn": app.forms.bgp_asn.trim(),
                "router_id": app.forms.bgp_router_id.trim(),
            });
            app.run_then("routing.bgp.instance.set", p, Then::ShowFrr);
        }
        if !app.forms.bgp_frr.is_empty() {
            ui.separator();
            ui.weak(tr_in(SCOPE, l, "Rendered for FRR bgpd:"));
            ui.monospace(&app.forms.bgp_frr);
        }
    }

    fn act(&mut self, app: &mut CoreRouterUi, act: Act, ui: &Ui, rows: &[Row], what: What) {
        let (data, cmds) = match what {
            What::Connection => (&self.connections, CONN_CMDS),
            What::Template => (&self.templates, TPL_CMDS),
        };
        let row_of = |k: &str| data.iter().find(|r| s(r, "name") == k).cloned();
        match act {
            Act::Add => {
                if self.modal.is_none() {
                    let mut values = BTreeMap::new();
                    if what == What::Connection {
                        values.insert("instance", "default".to_owned());
                        values.insert("disabled", "no".to_owned());
                    }
                    self.page = 0;
                    self.modal = Some((what, Modal::open(app, None, values)));
                }
            }
            Act::Edit(k) => {
                if let Some((_, m)) = &mut self.modal {
                    m.status.bring_to_front();
                } else if let Some(r) = row_of(&k) {
                    self.page = 0;
                    self.modal = Some((what, Modal::open(app, Some((k.clone(), k)), values_of(&r, what))));
                }
            }
            Act::Remove(keys) => {
                let steps: Vec<Value> = keys.iter().map(|k| json!({"command": cmds.remove, "params": {"id": k}})).collect();
                app.run_steps(steps, Then::Nothing);
            }
            Act::Enable(ref keys) | Act::Disable(ref keys) if what == What::Connection => {
                let to = matches!(act, Act::Disable(_));
                let steps: Vec<Value> = keys
                    .iter()
                    .map(|k| json!({"command": "routing.bgp.connection.set", "params": {"id": k, "disabled": to}}))
                    .collect();
                app.run_steps(steps, Then::Nothing);
            }
            Act::Enable(_) | Act::Disable(_) => {}
            Act::Comment(keys) => {
                if let Some(k) = keys.first()
                    && let Some(r) = row_of(k)
                    && self.modal.is_none()
                {
                    self.page = 0;
                    self.modal = Some((what, Modal::open(app, Some((k.clone(), k.clone())), values_of(&r, what))));
                }
            }
            Act::Copy(keys) => {
                let picked: Vec<&Row> = rows.iter().filter(|r| keys.contains(&r.key)).collect();
                ui.ctx().copy_text(list::copy_rows(&picked));
            }
            Act::CopyAs(keys, syntax) => {
                // The own parameters recreate the item (the key stays out).
                let picked: Vec<Value> = keys
                    .iter()
                    .filter_map(|k| row_of(k))
                    .map(|r| recreate(&r, what))
                    .collect();
                let refs: Vec<&Value> = picked.iter().collect();
                ui.ctx().copy_text(list::copy_commands(app, cmds.add, &refs, syntax));
            }
        }
    }
}

impl BgpPanel {
    /// Tests: act as the bar or the menu of a tab would.
    #[cfg(test)]
    pub(crate) fn act_for_test(&mut self, app: &mut CoreRouterUi, a: Act, what: What, ui: &Ui) {
        let rows: Vec<Row> = match what {
            What::Connection => self.connections.iter().map(conn_row).collect(),
            What::Template => self.templates.iter().map(tpl_row).collect(),
        };
        self.act(app, a, ui, &rows, what);
    }

    /// Every explanation key the window uses (the catalog test).
    #[cfg(test)]
    pub(crate) fn help_keys() -> Vec<&'static str> {
        let mut out: Vec<&'static str> = TABS.iter().map(|(_, _, k)| *k).collect();
        out.extend(SESSION_COLUMNS.iter().chain(&CONN_COLUMNS).chain(&TPL_COLUMNS).map(|c| c.help));
        out.extend(CONN_FIELDS.iter().chain(TPL_FIELDS).map(|f| f.help));
        out.extend([
            CONN_SPEC.help,
            TPL_SPEC.help,
            "bgp.session.last_error",
            "bgp.session.timers",
            "bgp.session.policy",
            "bgp.session.flaps",
            "bgp.session.remote_id",
            "bgp.session.messages",
            "bgp.instance.name",
            "bgp.instance.asn",
            "bgp.instance.router_id",
        ]);
        out.retain(|k| !k.is_empty());
        out
    }
}

/// A button with a tooltip; greyed with the reason when it cannot act.
fn button(ui: &mut Ui, text: &str, tip: &str, enabled: Result<(), String>) -> bool {
    match enabled {
        Ok(()) => ui.button(text).on_hover_text(tip).clicked(),
        Err(why) => {
            ui.add_enabled(false, egui::Button::new(text)).on_disabled_hover_text(why);
            false
        }
    }
}

/// The `add` parameters that recreate a row (own values; no key).
fn recreate(r: &Value, what: What) -> Value {
    let mut p = r.get("params").cloned().unwrap_or_else(|| json!({}));
    if let Some(o) = p.as_object_mut() {
        o.remove("tcp_md5_key");
        let keys: &[&str] = match what {
            What::Connection => &["name", "remote_address", "instance", "templates", "disabled", "comment"],
            What::Template => &["name", "templates", "comment"],
        };
        for k in keys {
            if let Some(v) = r.get(*k) {
                o.insert((*k).to_owned(), v.clone());
            }
        }
    }
    p
}

impl PanelState for BgpPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.open.contains(&Win::Bgp) {
            return Vec::new();
        }
        let mut out = Vec::new();
        for (key, command) in [
            ("connections", "routing.bgp.connection.list"),
            ("templates", "routing.bgp.template.list"),
            ("sessions", "routing.bgp.session.list"),
        ] {
            if app.has_command(command) {
                out.push(Query {
                    key,
                    command,
                    params: json!({}),
                });
            }
        }
        out
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        if key == list_modal::PREVIEW {
            if let Some((_, m)) = &mut self.modal {
                m.arrived(value);
            }
            return;
        }
        if let Value::Array(a) = value {
            match key {
                "connections" => self.connections = a,
                "templates" => self.templates = a,
                "sessions" => self.sessions = a,
                _ => {}
            }
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        self.tabs(app, ui);
        ui.separator();
        match self.tab {
            Tab::Sessions => self.sessions_tab(app, ui),
            Tab::Connections => self.connections_tab(app, ui),
            Tab::Templates => self.templates_tab(app, ui),
            Tab::Instances => self.instances_tab(app, ui),
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        if let Some((what, m)) = &mut self.modal {
            let instances: Vec<String> = app.cache.bgp.iter().map(|r| s(r, "name")).collect();
            let spec = match what {
                What::Connection => &CONN_SPEC,
                What::Template => &TPL_SPEC,
            };
            let l = app.lang.labels;
            let page = &mut self.page;
            let open = m.show_paged(app, ctx, area, spec, &|p| options(p, &instances), &mut |ui| {
                ui.horizontal(|ui| {
                    for (i, label) in ["General", "Session", "Limits"].iter().enumerate() {
                        if ui.selectable_label(*page == i, tr_in(SCOPE, l, label)).clicked() {
                            *page = i;
                        }
                    }
                });
                ui.separator();
                let general: &'static [&'static str] = match what {
                    What::Connection => &["name", "remote_address", "remote_as", "local_role", "templates", "instance", "disabled", "comment"],
                    What::Template => &["name", "templates", "remote_as", "local_role", "comment"],
                };
                Some(match *page {
                    1 => SESSION_PAGE,
                    2 => LIMITS_PAGE,
                    _ => general,
                })
            });
            if !open {
                self.modal = None;
            }
        }
        help::modal(ctx, app.lang, &mut self.help);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        if let Some(a) = then.downcast_ref::<Applied>()
            && let Some((_, m)) = self.modal.as_mut().filter(|(_, m)| m.id == a.0)
            && m.replied(app, result)
        {
            self.modal = None;
        }
        app.cache.refreshed_at = None;
    }

    fn escape(&mut self, _win: &'static str) -> bool {
        match self.tab {
            Tab::Sessions => self.session_table.escape(),
            Tab::Connections => self.conn_table.escape(),
            Tab::Templates => self.tpl_table.escape(),
            Tab::Instances => false,
        }
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        vec![(SESSIONS, &self.session_table), (CONNECTIONS, &self.conn_table), (TEMPLATES, &self.tpl_table)]
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        vec![
            (SESSIONS, &mut self.session_table),
            (CONNECTIONS, &mut self.conn_table),
            (TEMPLATES, &mut self.tpl_table),
        ]
    }
}
