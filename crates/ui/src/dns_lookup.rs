//! Tools › DNS Lookup (G6.6): a `dig` in a window. Name, type and server
//! (the router itself by default, any IP, a DoH/DoT URL, or every
//! upstream), options as toggle chips (recursion, DNSSEC, TCP, trace,
//! compare); Start runs `tool.dns.query` (a task, polled) and "Copy as
//! dig" copies the text the router rendered for the terminal.
//!
//! The reply reads like the screen the operator approved: a line of chips
//! (status, flags, time, server, and with the router as server the stage
//! of its chain that answered), then Answer, Authority and Additional,
//! one row per record, with the AS pill next to each address (the MTR's
//! colours). `compare` is a table of upstreams with an amber `diverge`
//! chip on the answers that differ from the majority; `trace` one row per
//! delegation from the root, `assinada` when a DS (or RRSIG) came with it
//! — signed, not validated: validation is G4.1f.
//!
//! With the router as the server, "Why this answer" (G6.8) lists what each
//! stage of its chain decided (passed, answered, not reached) with the rule
//! that matched and a button to its window; "Ask as" asks as a LAN address
//! would (the ACL, the per-client limit and the per-source rules see it).
//!
//! The window is as wide as its tables, up to the work area's edge (as the
//! height grows: `windows::grow_height`): a value ends in "…" only when it
//! does not fit even then.
//!
//! No logic here: the engine decides divergence, signatures and the text.

use std::collections::BTreeMap;

use egui::{Grid, RichText, TextEdit, Ui};
use serde_json::{Map, Value, json};

use crate::backend::RequestId;
use crate::chip::{AMBER, BLUE, GREEN, RED, chip, hashed, neutral_tone, palette_tone};
use crate::dhcp_client::text;
use crate::i18n::{self, Langs, tr};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::action;
use crate::{CoreRouterUi, Win, err_color};

const NAME: &str = "dns-lookup";
pub(crate) const WIN: &str = "dns-lookup";
const QUERY: &str = "tool.dns.query";
const STOP: &str = "tool.task.stop";
const WATCH: &str = "tool.dns.watch";
const UPSTREAMS: &str = "tool.dns.upstreams";
pub(crate) const TYPES: [&str; 10] = [
    "A", "AAAA", "MX", "TXT", "NS", "SOA", "PTR", "CAA", "SRV", "ANY",
];
/// Room kept between the tables and the work area's width (the window's
/// frame and its scroll bar).
const RIGHT_MARGIN: f32 = 40.0;
/// Narrowest a value gets before "…" (when the window cannot grow more).
const MIN_ROOM: f32 = 120.0;

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "Tools",
        title: "DNS Lookup",
        // Opens as tall as the form; the window grows with the answers.
        size: [780.0, 120.0],
        escape: true,
    }],
    new: || Box::new(LookupPanel::default()),
};

/// The window's tabs (G6.8).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Tab {
    #[default]
    Lookup,
    /// `tool.dns.watch`: the same query over and over.
    Watch,
    /// `tool.dns.upstreams`: every upstream measured.
    Upstreams,
}

/// Who is asked.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum Ask {
    /// The router's own chain, as a LAN client is answered.
    #[default]
    Router,
    /// The IP or URL typed in `server`.
    Server,
    /// Every upstream, side by side (compare).
    All,
}

pub(crate) struct LookupPanel {
    pub(crate) name: String,
    pub(crate) rtype: String,
    pub(crate) ask: Ask,
    pub(crate) server: String,
    /// "Ask as": a LAN address (empty: the router itself).
    pub(crate) as_client: String,
    pub(crate) recursion: bool,
    pub(crate) dnssec: bool,
    pub(crate) tcp: bool,
    pub(crate) trace: bool,
    pub(crate) task: Option<u64>,
    pub(crate) done: bool,
    pub(crate) events: Vec<Value>,
    /// The terminal text of the task (what "Copy as dig" copies).
    pub(crate) lines: Vec<String>,
    pub(crate) summary: Value,
    pub(crate) error: Option<String>,
    /// `dig …` of the running lookup (the Copy button's tooltip).
    pub(crate) command: String,
    /// The selected row: (table, index); click again to clear.
    pub(crate) selected: Option<(&'static str, usize)>,
    /// Each row's rectangle from the last frame (the click area).
    rows: BTreeMap<(&'static str, usize), egui::Rect>,
    pub(crate) tab: Tab,
    /// Watch: milliseconds between queries, as typed.
    pub(crate) interval: String,
    pub(crate) watch: crate::dns_analysis::TaskView,
    /// Upstreams: queries per server, as typed, and the hijack checks.
    pub(crate) count: String,
    pub(crate) hijack: bool,
    pub(crate) bench: crate::dns_analysis::TaskView,
}

/// Open Tools › DNS Lookup asking the router for `name` (DNS Cache's
/// Resolve…); an empty name keeps what the form had.
pub(crate) fn open_with(app: &mut CoreRouterUi, name: &str, rtype: &str) {
    if let Some(p) = app.panel_mut::<LookupPanel>()
        && !name.is_empty()
    {
        p.name = name.to_owned();
        p.ask = Ask::Router;
        if TYPES.contains(&rtype) {
            p.rtype = rtype.to_owned();
        }
    }
    if !app.open.insert(Win::Panel(WIN)) {
        app.floats.raise(crate::win_id(Win::Panel(WIN)));
    }
    app.cache.refreshed_at = None;
}

impl Default for LookupPanel {
    fn default() -> Self {
        Self {
            name: String::new(),
            rtype: "A".into(),
            ask: Ask::Router,
            server: String::new(),
            as_client: String::new(),
            recursion: true,
            dnssec: false,
            tcp: false,
            trace: false,
            task: None,
            done: false,
            events: Vec::new(),
            lines: Vec::new(),
            summary: Value::Null,
            error: None,
            command: String::new(),
            selected: None,
            rows: BTreeMap::new(),
            tab: Tab::Lookup,
            interval: "1000".into(),
            watch: Default::default(),
            count: "200".into(),
            hijack: true,
            bench: Default::default(),
        }
    }
}

impl LookupPanel {
    /// `tool.dns.query` params from the form (defaults left out).
    pub(crate) fn params(&self) -> Value {
        let mut p = Map::new();
        p.insert("name".into(), json!(self.name.trim()));
        p.insert("type".into(), json!(self.rtype));
        match self.ask {
            // Why this answer: only the router's chain has stages (and
            // trace starts at the root, not there).
            Ask::Router if !self.trace => {
                p.insert("explain".into(), json!(true));
                if !self.as_client.trim().is_empty() {
                    p.insert("as_client".into(), json!(self.as_client.trim()));
                }
            }
            Ask::Router => {}
            Ask::Server => {
                p.insert("server".into(), json!(self.server.trim()));
            }
            Ask::All => {
                p.insert("compare".into(), json!(true));
            }
        }
        if !self.recursion {
            p.insert("recursion".into(), json!(false));
        }
        for (k, on) in [("dnssec", self.dnssec), ("tcp", self.tcp), ("trace", self.trace)] {
            if on {
                p.insert(k.into(), json!(true));
            }
        }
        Value::Object(p)
    }

    fn running(&self) -> bool {
        self.task.is_some() && !self.done
    }

    /// The events of one kind.
    fn of(&self, kind: &str) -> Vec<&Value> {
        self.events.iter().filter(|e| text(e, "kind") == kind).collect()
    }

    /// Origin AS of each address answered, by address.
    fn as_by_address(&self) -> BTreeMap<String, Value> {
        self.of("asn")
            .into_iter()
            .map(|e| (text(e, "address"), e.clone()))
            .collect()
    }

    /// The text "Copy as dig" copies.
    pub(crate) fn dig_text(&self) -> String {
        let mut t = self.lines.join("\n");
        t.push('\n');
        t
    }

    fn start(&mut self, app: &mut CoreRouterUi) {
        self.events.clear();
        self.lines.clear();
        self.summary = Value::Null;
        self.error = None;
        self.done = false;
        self.task = None;
        self.selected = None;
        app.run_then(QUERY, self.params(), crate::panel::then(NAME, ()));
    }

    fn form(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let can = app.can();
        let mut go = false;
        Grid::new("dns-lookup-form")
            .num_columns(4)
            .spacing([10.0, 6.0])
            .show(ui, |ui| {
                ui.label("Name").on_hover_text("A name, or an address (its PTR name).");
                let r = ui.add(
                    TextEdit::singleline(&mut self.name)
                        .hint_text("example.com")
                        .desired_width(260.0),
                );
                if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    go = true;
                }
                ui.label("Type");
                egui::ComboBox::from_id_salt("dns-lookup-type")
                    .selected_text(self.rtype.as_str())
                    .width(80.0)
                    .show_ui(ui, |ui| {
                        for t in TYPES {
                            ui.selectable_value(&mut self.rtype, t.to_owned(), t);
                        }
                    });
                ui.end_row();
                ui.label("Server");
                ui.horizontal(|ui| {
                    let shown = match self.ask {
                        Ask::Router => "Router",
                        Ask::Server => "Server",
                        Ask::All => "All upstreams",
                    };
                    egui::ComboBox::from_id_salt("dns-lookup-ask")
                        .selected_text(shown)
                        .width(110.0)
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.ask, Ask::Router, "Router")
                                .on_hover_text("The router's own chain: static, adlist, zones, cache, upstream.");
                            ui.selectable_value(&mut self.ask, Ask::Server, "Server")
                                .on_hover_text("An IP, https://… (DoH) or tls://… (DoT).");
                            ui.selectable_value(&mut self.ask, Ask::All, "All upstreams")
                                .on_hover_text("The same question to every upstream, side by side.");
                        });
                    if self.ask == Ask::Server {
                        ui.add(
                            TextEdit::singleline(&mut self.server)
                                .hint_text("IP, https://… or tls://…")
                                .desired_width(250.0),
                        );
                    }
                });
                ui.end_row();
                if self.ask == Ask::Router && !self.trace {
                    ui.label(tr(app.lang.labels, "Ask as")).on_hover_text(
                        "Ask as if this LAN address asked: the ACL (allowed_from), the per-client limit and the per-source rules see it. No packet is sent. Empty: the router itself.",
                    );
                    ui.add(
                        TextEdit::singleline(&mut self.as_client)
                            .hint_text(tr(app.lang.labels, "router itself"))
                            .desired_width(160.0),
                    );
                    ui.end_row();
                }
                ui.label("Options");
                ui.horizontal(|ui| {
                    toggle(ui, "recursion", &mut self.recursion, "RD: the server resolves for us (dig +norecurse clears it).");
                    toggle(ui, "DNSSEC", &mut self.dnssec, "DO: ask for the signatures (RRSIG). Shown, not validated.");
                    toggle(ui, "TCP", &mut self.tcp, "Ask over TCP (a truncated UDP reply is asked again over TCP anyway).");
                    let mut trace = self.trace;
                    toggle(ui, "trace", &mut trace, "From the root servers down, one row per delegation.");
                    if trace != self.trace {
                        self.trace = trace;
                        if trace && self.ask != Ask::Router {
                            self.ask = Ask::Router;
                        }
                    }
                    let mut compare = self.ask == Ask::All;
                    toggle(ui, "compare", &mut compare, "Every upstream side by side; a diverging answer is flagged.");
                    if compare != (self.ask == Ask::All) {
                        self.ask = if compare { Ask::All } else { Ask::Router };
                        if compare {
                            self.trace = false;
                        }
                    }
                });
                ui.end_row();
            });
        ui.horizontal(|ui| {
            if self.running() {
                if action(ui, "Stop", can.check(STOP))
                    && let Some(id) = self.task
                {
                    app.run(STOP, json!({"id": id}));
                }
                ui.spinner();
            } else {
                let ok = if self.name.trim().is_empty() {
                    Err("Type a name first".to_owned())
                } else if self.ask == Ask::Server && self.server.trim().is_empty() {
                    Err("Type the server: an IP, https://… or tls://…".to_owned())
                } else {
                    can.check(QUERY)
                };
                if action(ui, "Start", ok) {
                    go = true;
                }
            }
            let copy = if self.lines.is_empty() {
                Err("Run a lookup first".to_owned())
            } else {
                Ok(())
            };
            let enabled = copy.is_ok();
            let r = ui.add_enabled(enabled, egui::Button::new("Copy as dig"));
            let r = match copy {
                Ok(()) if !self.command.is_empty() => r.on_hover_text(&self.command),
                Ok(()) => r,
                Err(why) => r.on_disabled_hover_text(why),
            };
            if r.clicked() {
                ui.ctx().copy_text(self.dig_text());
            }
        });
        let ready = !self.name.trim().is_empty()
            && !(self.ask == Ask::Server && self.server.trim().is_empty());
        if go && ready && !self.running() && can.check(QUERY).is_ok() {
            self.start(app);
        }
    }

    /// The results; a rule whose window the operator asked to open.
    /// `tool.dns.watch` params from the form.
    pub(crate) fn watch_params(&self) -> Value {
        let mut p = Map::new();
        p.insert("name".into(), json!(self.name.trim()));
        p.insert("type".into(), json!(self.rtype));
        if self.ask == Ask::Server {
            p.insert("server".into(), json!(self.server.trim()));
        }
        if let Ok(ms) = self.interval.trim().parse::<u32>() {
            p.insert("interval_ms".into(), json!(ms));
        }
        if self.tcp {
            p.insert("tcp".into(), json!(true));
        }
        Value::Object(p)
    }

    /// `tool.dns.upstreams` params from the form.
    pub(crate) fn bench_params(&self) -> Value {
        let mut p = Map::new();
        if let Ok(n) = self.count.trim().parse::<u32>() {
            p.insert("count".into(), json!(n));
        }
        if !self.hijack {
            p.insert("hijack".into(), json!(false));
        }
        Value::Object(p)
    }

    /// Start/Stop of a tab's task.
    fn start_stop(
        app: &mut CoreRouterUi,
        ui: &mut Ui,
        view: &mut crate::dns_analysis::TaskView,
        ok: Result<(), String>,
    ) -> bool {
        let mut go = false;
        if view.running() {
            if action(ui, "Stop", app.can().check(STOP))
                && let Some(id) = view.task
            {
                app.run(STOP, json!({"id": id}));
            }
            ui.spinner();
        } else if action(ui, "Start", ok) {
            go = true;
        }
        go
    }

    fn watch_form(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let mut go = false;
        Grid::new("dns-watch-form")
            .num_columns(4)
            .spacing([10.0, 6.0])
            .show(ui, |ui| {
                ui.label("Name");
                // Sized: inside this grid a desired width alone collapses.
                let r = ui.add_sized([260.0, 20.0], TextEdit::singleline(&mut self.name).hint_text("example.com"));
                if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    go = true;
                }
                ui.label("Type");
                egui::ComboBox::from_id_salt("dns-watch-type")
                    .selected_text(self.rtype.as_str())
                    .width(80.0)
                    .show_ui(ui, |ui| {
                        for t in TYPES {
                            ui.selectable_value(&mut self.rtype, t.to_owned(), t);
                        }
                    });
                ui.end_row();
                ui.label("Server");
                ui.horizontal(|ui| {
                    if self.ask == Ask::All {
                        self.ask = Ask::Router;
                    }
                    let shown = if self.ask == Ask::Server { "Server" } else { "Router" };
                    egui::ComboBox::from_id_salt("dns-watch-ask")
                        .selected_text(shown)
                        .width(110.0)
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.ask, Ask::Router, "Router");
                            ui.selectable_value(&mut self.ask, Ask::Server, "Server");
                        });
                    if self.ask == Ask::Server {
                        ui.add_sized(
                            [220.0, 20.0],
                            TextEdit::singleline(&mut self.server).hint_text("IP, https://… or tls://…"),
                        );
                    }
                });
                ui.label(tr(app.lang.labels, "Interval"));
                ui.horizontal(|ui| {
                    ui.add_sized([60.0, 20.0], TextEdit::singleline(&mut self.interval));
                    ui.label("ms");
                });
                ui.end_row();
            });
        let ok = if self.name.trim().is_empty() {
            Err("Type a name first".to_owned())
        } else if self.ask == Ask::Server && self.server.trim().is_empty() {
            Err("Type the server: an IP, https://… or tls://…".to_owned())
        } else if !self.interval.trim().parse::<u32>().is_ok_and(|n| (100..=60_000).contains(&n)) {
            Err("Interval: 100 to 60000 ms".to_owned())
        } else {
            app.can().check(WATCH)
        };
        let mut start = false;
        ui.horizontal(|ui| {
            start = Self::start_stop(app, ui, &mut self.watch, ok.clone());
        });
        if (start || go) && ok.is_ok() && !self.watch.running() {
            self.watch.reset();
            app.run_then(WATCH, self.watch_params(), crate::panel::then(NAME, Tab::Watch));
        }
    }

    fn bench_form(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        ui.horizontal(|ui| {
            ui.label(tr(app.lang.labels, "Queries per server"));
            ui.add_sized([60.0, 20.0], TextEdit::singleline(&mut self.count));
            toggle(
                ui,
                tr(app.lang.labels, "Check hijack"),
                &mut self.hijack,
                "Names that cannot exist (NXDOMAIN hijacking) and the resolver that reaches the authoritative servers (a proxy on the way).",
            );
        });
        let ok = if !self.count.trim().parse::<u32>().is_ok_and(|n| (10..=2000).contains(&n)) {
            Err("Queries per server: 10 to 2000".to_owned())
        } else {
            app.can().check(UPSTREAMS)
        };
        let mut start = false;
        ui.horizontal(|ui| {
            start = Self::start_stop(app, ui, &mut self.bench, ok.clone());
        });
        if start && ok.is_ok() && !self.bench.running() {
            self.bench.reset();
            app.run_then(UPSTREAMS, self.bench_params(), crate::panel::then(NAME, Tab::Upstreams));
        }
    }

    /// `right`: the farthest right the tables may reach (the window grows
    /// up to the work area's width).
    fn results(&mut self, langs: Langs, right: f32, ui: &mut Ui) -> Option<Value> {
        if let Some(e) = &self.error {
            ui.colored_label(err_color(ui), e.as_str());
        }
        let last = std::mem::take(&mut self.rows);
        let mut ctx = Rows {
            last,
            now: BTreeMap::new(),
            selected: self.selected,
            right,
        };
        let mut open = None;
        egui::ScrollArea::vertical()
            .id_salt("dns-lookup-results")
            .auto_shrink([false, true])
            .min_scrolled_height(crate::windows::grow_height(ui))
            .show(ui, |ui| {
                // A click selects the row (copies are in its right-click
                // menu), never starts a text selection inside a cell.
                ui.style_mut().interaction.selectable_labels = false;
                let answer = self.of("answer").last().map(|e| (*e).clone());
                let compare = self.of("compare");
                let trace = self.of("trace");
                if let Some(a) = answer {
                    status_line(ui, &a);
                    let asn = self.as_by_address();
                    for (title, key, salt) in [
                        ("Answer", "answer", "dns-lookup-answer"),
                        ("Authority", "authority", "dns-lookup-authority"),
                        ("Additional", "additional", "dns-lookup-additional"),
                    ] {
                        let recs: Vec<&Value> =
                            a.get(key).and_then(Value::as_array).into_iter().flatten().collect();
                        if recs.is_empty() && key != "answer" {
                            continue;
                        }
                        ui.add_space(6.0);
                        ui.strong(title);
                        records(ui, salt, &recs, &asn, &mut ctx);
                    }
                    let why: Vec<Value> = self.of("why").into_iter().cloned().collect();
                    if !why.is_empty() {
                        ui.add_space(6.0);
                        ui.strong(tr(langs.labels, "Why this answer"));
                        open = why_table(ui, langs, &why, &mut ctx);
                    }
                } else if !compare.is_empty() {
                    // The summary carries the divergence once all answered.
                    let rows: Vec<Value> = match self.summary.get("servers").and_then(Value::as_array) {
                        Some(r) if self.done => r.clone(),
                        _ => compare.into_iter().cloned().collect(),
                    };
                    compare_table(ui, &rows, &mut ctx);
                } else if !trace.is_empty() {
                    let rows: Vec<Value> = trace.into_iter().cloned().collect();
                    trace_table(ui, &rows, &mut ctx);
                } else if let Some(e) = self.of("error").first() {
                    ui.horizontal(|ui| {
                        if e.get("timeout").and_then(Value::as_bool) == Some(true) {
                            chip(ui, "timeout", RED.tone(ui.visuals()));
                        }
                        ui.label(RichText::new(text(e, "server")).weak());
                    });
                } else if self.task.is_none() {
                    ui.weak("Type a name and press Start (Enter). Server: the router answers as it answers the LAN.");
                }
            });
        self.rows = ctx.now;
        self.selected = ctx.selected;
        open
    }
}

/// Opens the window of a rule from "Why this answer", with it selected.
fn open_rule(app: &mut CoreRouterUi, rule: &Value) {
    let id = text(rule, "id");
    let name = text(rule, "name");
    let by_name = |rows: &[Value]| {
        rows.iter()
            .find(|r| text(r, "name") == name)
            .map(|r| text(r, "id"))
    };
    let win = match text(rule, "kind").as_str() {
        "static" => {
            if let Some(p) = app.panel_mut::<crate::dns::DnsPanel>() {
                p.static_table.reveal(&id);
            }
            crate::dns::WIN_STATIC
        }
        "adlist" => {
            if let Some(p) = app.panel_mut::<crate::dns_adlist::AdlistPanel>() {
                p.table.reveal(&id);
            }
            crate::dns_adlist::WIN
        }
        "forwarders" => {
            if let Some(p) = app.panel_mut::<crate::dns_forwarders::ForwardersPanel>()
                && let Some(id) = by_name(&p.lists)
            {
                p.table.reveal(&id);
            }
            crate::dns_forwarders::WIN
        }
        "zone" => {
            if let Some(p) = app.panel_mut::<crate::dns_zones::ZonesPanel>()
                && let Some(id) = by_name(&p.zones)
            {
                p.zone_table.reveal(&id);
            }
            crate::dns_zones::WIN
        }
        _ => return,
    };
    if !app.open.insert(Win::Panel(win)) {
        app.floats.raise(crate::win_id(Win::Panel(win)));
    }
    app.cache.refreshed_at = None;
}

/// The button of a rule's window.
fn rule_button(rule: &Value) -> Option<&'static str> {
    Some(match rule.get("kind").and_then(Value::as_str)? {
        "static" => "Open entry",
        "adlist" => "Open list",
        "forwarders" => "Open group",
        "zone" => "Open zone",
        _ => return None,
    })
}

/// The text of one decision, in the explanations' language: the GUI's
/// wording of the engine's id (`i18n/dns_lookup_pt.rs`), else the engine's
/// English.
pub(crate) fn why_text(lang: i18n::Lang, ev: &Value) -> String {
    let args: Vec<(String, String)> = ev
        .get("args")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .map(|(k, v)| (k.clone(), v.as_str().map_or_else(|| v.to_string(), str::to_owned)))
        .collect();
    let args: Vec<(&str, &str)> = args.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    match text(ev, "why").as_str() {
        "" => text(ev, "outcome"),
        id => i18n::template(lang, &format!("dnswhy.{id}"), &args, &text(ev, "text")),
    }
}

/// Why this answer: Stage, Decision, Why, one row per stage of the chain,
/// with the button to the rule's window.
fn why_table(ui: &mut Ui, langs: Langs, list: &[Value], rows: &mut Rows) -> Option<Value> {
    let mut open = None;
    Grid::new("dns-lookup-why")
        .striped(true)
        .num_columns(4)
        .spacing([14.0, 3.0])
        .show(ui, |ui| {
            for h in ["Stage", "Decision", "Why", ""] {
                ui.strong(tr(langs.labels, h));
            }
            ui.end_row();
            for (i, ev) in list.iter().enumerate() {
                let key = ("why", i);
                let says = why_text(langs.help, ev);
                let top = rows.begin(ui, key, &[("Copy", format!("{}: {says}", text(ev, "stage")))]);
                let outcome = text(ev, "outcome");
                let reached = outcome != "not-reached";
                let stage = text(ev, "stage");
                if reached {
                    ui.label(stage);
                } else {
                    ui.label(RichText::new(stage).weak());
                }
                let v = ui.visuals().clone();
                let (label, tone) = match outcome.as_str() {
                    "answered" if text(ev, "why").ends_with("refused") => ("refused", RED.tone(&v)),
                    "answered" => ("answered", GREEN.tone(&v)),
                    "dropped" => ("dropped", RED.tone(&v)),
                    "passed" => ("passed", neutral_tone(&v)),
                    _ => ("not reached", neutral_tone(&v)),
                };
                chip(ui, tr(langs.labels, label), tone);
                let room = (rows.right - ui.cursor().min.x - 110.0).max(MIN_ROOM);
                let (shown, cut) = fit(ui, &says, room);
                let l = if reached {
                    ui.label(shown)
                } else {
                    ui.label(RichText::new(shown).weak())
                };
                let mut right = l.rect.right();
                if cut {
                    l.on_hover_text(&says);
                }
                match ev.get("rule").filter(|r| !r.is_null()).and_then(|r| rule_button(r).map(|b| (r, b))) {
                    Some((rule, button)) => {
                        let b = ui.small_button(tr(langs.labels, button));
                        right = b.rect.right();
                        if b.clicked() {
                            open = Some(rule.clone());
                        }
                    }
                    None => {
                        ui.label("");
                    }
                }
                ui.end_row();
                rows.end(ui, key, top, right);
            }
        });
    open
}

/// A chip that switches an option: blue when on, quiet when off.
fn toggle(ui: &mut Ui, label: &str, on: &mut bool, tip: &str) {
    let tone = if *on {
        BLUE.tone(ui.visuals())
    } else {
        neutral_tone(ui.visuals())
    };
    let r = chip(ui, label, tone);
    let r = ui
        .interact(r.rect, egui::Id::unique(("dns-lookup-opt", label)), egui::Sense::click())
        .on_hover_text(tip);
    if r.clicked() {
        *on = !*on;
    }
}

/// The tone of a status (`NOERROR` green, `NXDOMAIN` amber, failures red).
fn status_tone(v: &egui::Visuals, rcode: &str) -> crate::chip::Tone {
    match rcode {
        "NOERROR" => GREEN.tone(v),
        "NXDOMAIN" => AMBER.tone(v),
        _ => RED.tone(v),
    }
}

/// Status, flags, time, server and the stage that answered, as chips.
fn status_line(ui: &mut Ui, a: &Value) {
    ui.horizontal_wrapped(|ui| {
        let v = ui.visuals().clone();
        let rcode = text(a, "rcode");
        chip(ui, &rcode, status_tone(&v, &rcode)).on_hover_text("Status (RCODE)");
        let flags: Vec<String> = a
            .get("flags")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        if !flags.is_empty() {
            chip(ui, &flags.join(" "), neutral_tone(&v)).on_hover_text(
                "Header flags. ad: the server says it validated; the router does not check that (G4.1f).",
            );
        }
        chip(ui, &format!("{} ms", text(a, "ms")), neutral_tone(&v)).on_hover_text("Query time");
        let server = text(a, "server");
        let shown = server.split('#').next().unwrap_or(&server).to_owned();
        let shown = if shown.starts_with("127.0.0.1") && !text(a, "stage").is_empty() {
            "router".to_owned()
        } else {
            shown
        };
        let shown = match a.get("as_client").and_then(Value::as_str) {
            Some(ip) => format!("{shown} · as {ip}"),
            None => shown,
        };
        chip(ui, &format!("{shown} · {}", text(a, "transport")), BLUE.tone(&v)).on_hover_text(server);
        match (text(a, "source").as_str(), text(a, "stage").as_str()) {
            (_, "") => {}
            ("cache", stage) => {
                chip(ui, &format!("from cache · etapa {stage}"), BLUE.tone(&v))
                    .on_hover_text("The router answered from its cache.");
            }
            (_, stage) => {
                chip(ui, &format!("etapa {stage}"), neutral_tone(&v))
                    .on_hover_text("The stage of the router's DNS chain that answered.");
            }
        }
        chip(ui, &format!("{} B", text(a, "size")), neutral_tone(&v)).on_hover_text("Reply size");
    });
}

/// What a frame needs to make rows selectable: last frame's rectangles,
/// this frame's, and the selection.
struct Rows {
    last: BTreeMap<(&'static str, usize), egui::Rect>,
    now: BTreeMap<(&'static str, usize), egui::Rect>,
    selected: Option<(&'static str, usize)>,
    /// The farthest right a cell may reach (the window's widest).
    right: f32,
}

impl Rows {
    /// Room for a value starting where the cursor is, leaving `after`.
    fn room(&self, ui: &Ui, after: f32) -> f32 {
        (self.right - ui.cursor().min.x - after).max(MIN_ROOM)
    }

    /// Before a row: the click area from last frame, painted when selected
    /// or hovered; the right-click menu copies `copies`.
    fn begin(&mut self, ui: &mut Ui, key: (&'static str, usize), copies: &[(&str, String)]) -> egui::Pos2 {
        if let Some(rect) = self.last.get(&key) {
            let resp = ui.interact(*rect, egui::Id::unique(("dns-lookup-row", key)), egui::Sense::click());
            if resp.clicked() {
                self.selected = (self.selected != Some(key)).then_some(key);
            }
            if resp.secondary_clicked() {
                self.selected = Some(key);
            }
            resp.context_menu(|ui| {
                for (label, value) in copies {
                    if ui.button(*label).clicked() {
                        ui.ctx().copy_text(value.clone());
                        ui.close();
                    }
                }
            });
            if self.selected == Some(key) {
                ui.painter().rect_filled(*rect, 2.0, ui.visuals().selection.bg_fill);
            } else if resp.hovered() {
                ui.painter().rect_filled(*rect, 2.0, ui.visuals().widgets.hovered.weak_bg_fill);
            }
        }
        ui.cursor().min
    }

    /// After the row's `end_row`: remember where it was.
    fn end(&mut self, ui: &Ui, key: (&'static str, usize), top_left: egui::Pos2, right: f32) {
        let bottom = ui.cursor().min.y - ui.spacing().item_spacing.y;
        self.now.insert(
            key,
            egui::Rect::from_min_max(
                top_left - egui::vec2(4.0, 1.0),
                egui::pos2(right + 4.0, bottom.max(top_left.y) + 1.0),
            ),
        );
    }
}

/// `s` as it fits in `room` points of body text: whole, or cut with "…"
/// (then `true`: the whole goes in the tooltip).
pub(crate) fn fit(ui: &Ui, s: &str, room: f32) -> (String, bool) {
    let font = egui::TextStyle::Body.resolve(ui.style());
    let width = |t: &str| {
        ui.painter()
            .layout_no_wrap(t.to_owned(), font.clone(), egui::Color32::WHITE)
            .size()
            .x
    };
    if width(s) <= room {
        return (s.to_owned(), false);
    }
    let chars: Vec<char> = s.chars().collect();
    let cut = |n: usize| {
        let mut t: String = chars.iter().take(n).collect();
        t.push('…');
        t
    };
    // The longest prefix that fits with its "…".
    let (mut lo, mut hi) = (0usize, chars.len());
    while lo < hi {
        let mid = lo + (hi - lo).div_ceil(2);
        if width(&cut(mid)) <= room {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    (cut(lo), true)
}

/// The AS pill's text: the number and the registry name's first word, whole
/// (the window grows for it; the MTR's columns cut it at 16).
fn as_label(a: &Value) -> Option<String> {
    let n = a.get("asn").and_then(Value::as_u64)?;
    let word = a
        .get("as_name")
        .and_then(Value::as_str)
        .and_then(|name| name.split(',').next())
        .and_then(|name| name.split_whitespace().next())
        .filter(|w| !w.eq_ignore_ascii_case(&format!("AS{n}")));
    Some(match word {
        Some(w) => format!("AS{n} {w}"),
        None => format!("AS{n}"),
    })
}

/// Width of a chip with `label` (as `chip` draws it), and the gap before it.
fn chip_width(ui: &Ui, label: &str) -> f32 {
    let font = egui::FontId::proportional(crate::chip::small(ui));
    let w = ui
        .painter()
        .layout_no_wrap(label.to_owned(), font, egui::Color32::WHITE)
        .size()
        .x;
    w + 14.0 + 4.0 + ui.spacing().item_spacing.x
}

/// A data cell: the text (whole when it fits, else cut with the whole in
/// the tooltip) and, for an address, its AS pill coloured by the AS number
/// (as in the MTR).
fn data_cell(ui: &mut Ui, data: &str, asn: Option<&Value>, rows: &Rows) -> f32 {
    let pill = asn.and_then(as_label);
    let after = pill.as_deref().map_or(0.0, |p| chip_width(ui, p));
    let room = rows.room(ui, after);
    let r = ui
        .horizontal(|ui| {
            let (shown, cut) = fit(ui, data, room);
            let l = ui.label(shown);
            if cut {
                l.on_hover_text(data);
            }
            if let Some(a) = asn
                && let (Some(label), Some(n)) = (pill.clone(), a.get("asn").and_then(Value::as_u64))
            {
                ui.add_space(4.0);
                let mut tip = format!("AS{n}");
                if let Some(name) = a.get("as_name").and_then(Value::as_str) {
                    tip = format!("{tip} {name}");
                }
                if let Some(p) = a.get("prefix").and_then(Value::as_str) {
                    tip = format!("{tip}\nprefix {p}");
                }
                chip(ui, &label, palette_tone(ui.visuals(), hashed(n))).on_hover_text(tip);
            }
        })
        .response;
    r.rect.right()
}

/// Answer, Authority or Additional: Name, TTL, Type, Data, one row each.
fn records(ui: &mut Ui, salt: &'static str, recs: &[&Value], asn: &BTreeMap<String, Value>, rows: &mut Rows) {
    if recs.is_empty() {
        ui.label(RichText::new("sem resposta").weak())
            .on_hover_text("No records in this section (see the status).");
        return;
    }
    Grid::new(salt)
        .striped(true)
        .num_columns(4)
        .spacing([14.0, 3.0])
        .min_col_width(40.0)
        .show(ui, |ui| {
            for h in ["Name", "TTL", "Type", "Data"] {
                ui.strong(h);
            }
            ui.end_row();
            for (i, r) in recs.iter().enumerate() {
                let data = text(r, "data");
                let line = format!(
                    "{}\t{}\t{}\t{}\t{}",
                    text(r, "name"),
                    text(r, "ttl"),
                    text(r, "class"),
                    text(r, "type"),
                    data
                );
                let key = (salt, i);
                let top = rows.begin(ui, key, &[("Copy record", line), ("Copy data", data.clone())]);
                ui.label(text(r, "name"));
                ui.label(text(r, "ttl"));
                ui.label(text(r, "type"));
                let right = data_cell(ui, &data, asn.get(&data), rows);
                ui.end_row();
                rows.end(ui, key, top, right);
            }
        });
}

/// compare: Server, Status, Time, Data; `diverge` (amber) on the answers
/// the engine found off the majority, `timeout` on the silent ones.
fn compare_table(ui: &mut Ui, list: &[Value], rows: &mut Rows) {
    Grid::new("dns-lookup-compare")
        .striped(true)
        .num_columns(4)
        .spacing([14.0, 3.0])
        .show(ui, |ui| {
            for h in ["Server", "Status", "Time", "Data"] {
                ui.strong(h);
            }
            ui.end_row();
            for (i, r) in list.iter().enumerate() {
                let data: Vec<String> = r
                    .get("data")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect();
                let key = ("compare", i);
                let top = rows.begin(ui, key, &[("Copy server", text(r, "server")), ("Copy data", data.join("\n"))]);
                ui.label(text(r, "server"));
                let timeout = r.get("timeout").and_then(Value::as_bool) == Some(true);
                ui.horizontal(|ui| {
                    if timeout {
                        chip(ui, "timeout", RED.tone(ui.visuals())).on_hover_text(text(r, "error"));
                    } else if r.get("error").is_some_and(|e| !e.is_null()) {
                        chip(ui, "error", RED.tone(ui.visuals())).on_hover_text(text(r, "error"));
                    } else {
                        let rcode = text(r, "rcode");
                        chip(ui, &rcode, status_tone(ui.visuals(), &rcode));
                    }
                    if r.get("diverge").and_then(Value::as_bool) == Some(true) {
                        chip(ui, "diverge", AMBER.tone(ui.visuals()))
                            .on_hover_text("This answer differs from what most upstreams said (or there is no majority). Addresses count as the same when the same AS announces them (a CDN hands each resolver its own servers).");
                    }
                });
                ui.label(r.get("ms").and_then(Value::as_u64).map_or("–".into(), |m| format!("{m} ms")));
                let right = if timeout || data.is_empty() {
                    let what = if timeout || r.get("rcode").is_none_or(Value::is_null) {
                        "sem resposta"
                    } else {
                        "(no records)"
                    };
                    ui.label(RichText::new(what).weak()).rect.right()
                } else {
                    let all = data.join(", ");
                    let (shown, cut) = fit(ui, &all, rows.room(ui, 0.0));
                    let l = ui.label(shown);
                    let right = l.rect.right();
                    if cut {
                        l.on_hover_text(data.join("\n"));
                    }
                    right
                };
                ui.end_row();
                rows.end(ui, key, top, right);
            }
        });
}

/// trace: Zone, Asked, Time, Answer; `assinada` when the delegation (DS)
/// or the answer (RRSIG) came signed.
fn trace_table(ui: &mut Ui, list: &[Value], rows: &mut Rows) {
    Grid::new("dns-lookup-trace")
        .striped(true)
        .num_columns(4)
        .spacing([14.0, 3.0])
        .show(ui, |ui| {
            for h in ["Zone", "Asked", "Time", "Answer"] {
                ui.strong(h);
            }
            ui.end_row();
            for (i, r) in list.iter().enumerate() {
                let key = ("trace", i);
                let top = rows.begin(ui, key, &[("Copy server", text(r, "address")), ("Copy answer", text(r, "answer"))]);
                ui.label(text(r, "zone"));
                ui.label(text(r, "asked")).on_hover_text(text(r, "address"));
                ui.label(r.get("ms").and_then(Value::as_u64).map_or("–".into(), |m| format!("{m} ms")));
                // The signature chip after the answer.
                let room = rows.room(ui, 110.0);
                let right = ui
                    .horizontal(|ui| {
                        if r.get("error").is_some() {
                            if r.get("timeout").and_then(Value::as_bool) == Some(true) {
                                chip(ui, "timeout", RED.tone(ui.visuals()));
                            }
                            let error = text(r, "error");
                            let (shown, cut) = fit(ui, &error, room);
                            let l = ui.label(RichText::new(shown).weak());
                            if cut {
                                l.on_hover_text(error);
                            }
                            return;
                        }
                        let answer = text(r, "answer");
                        let (shown, cut) = fit(ui, &answer, room);
                        let l = ui.label(shown);
                        if cut {
                            l.on_hover_text(&answer);
                        }
                        match r.get("signed").and_then(Value::as_bool) {
                            Some(true) => {
                                chip(ui, "assinada", BLUE.tone(ui.visuals())).on_hover_text(
                                    "A DS (delegation) or RRSIG (answer) came with it. Not validated: G4.1f.",
                                );
                            }
                            Some(false) => {
                                chip(ui, "sem assinatura", neutral_tone(ui.visuals()))
                                    .on_hover_text("No DS or RRSIG came with it.");
                            }
                            None => {}
                        }
                    })
                    .response
                    .rect
                    .right();
                ui.end_row();
                rows.end(ui, key, top, right);
            }
        });
}

impl PanelState for LookupPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        let mut out = Vec::new();
        if !app.open.contains(&crate::Win::Panel(WIN)) {
            return out;
        }
        if let Some(id) = self.task.filter(|_| !self.done) {
            out.push(Query {
                key: "poll",
                command: "tool.task.poll",
                params: json!({"id": id, "after_seq": 0, "max": 256, "text": true}),
            });
        }
        if let Some(id) = self.watch.task.filter(|_| !self.watch.done) {
            out.push(Query {
                key: "watch-poll",
                command: "tool.task.poll",
                params: self.watch.poll(id),
            });
        }
        if let Some(id) = self.bench.task.filter(|_| !self.bench.done) {
            out.push(Query {
                key: "bench-poll",
                command: "tool.task.poll",
                params: json!({"id": id, "after_seq": 0, "max": 256}),
            });
        }
        out
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        match key {
            "watch-poll" => return self.watch.arrived(&value, true),
            "bench-poll" => return self.bench.arrived(&value, false),
            "poll" => {}
            _ => return,
        }
        if let Some(ev) = value.get("events").and_then(Value::as_array) {
            self.events = ev.clone();
        }
        let strings = |k: &str| -> Vec<String> {
            value
                .get(k)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        };
        self.lines = strings("lines");
        self.lines.extend(strings("summary_lines"));
        if value.get("done").and_then(Value::as_bool) == Some(true) {
            self.done = true;
            self.summary = value.get("summary").cloned().unwrap_or(Value::Null);
            if value.get("state").and_then(Value::as_str) == Some("failed") {
                self.error = value.get("reason").and_then(Value::as_str).map(str::to_owned);
            }
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        for t in [&mut self.watch, &mut self.bench] {
            if std::mem::take(&mut t.stop)
                && let Some(id) = t.task.filter(|_| !t.done)
            {
                app.run(STOP, json!({"id": id}));
            }
        }
        ui.horizontal(|ui| {
            for (tab, label) in [(Tab::Lookup, "Lookup"), (Tab::Watch, "Watch"), (Tab::Upstreams, "Upstreams")] {
                let mut text = RichText::new(tr(app.lang.labels, label));
                let running = match tab {
                    Tab::Watch => self.watch.running(),
                    Tab::Upstreams => self.bench.running(),
                    Tab::Lookup => self.running(),
                };
                if running {
                    text = text.italics();
                }
                if ui.selectable_label(self.tab == tab, text).clicked() {
                    self.tab = tab;
                }
            }
        });
        ui.separator();
        match self.tab {
            Tab::Lookup => {}
            Tab::Watch => {
                self.watch_form(app, ui);
                ui.separator();
                egui::ScrollArea::vertical()
                    .id_salt("dns-watch-results")
                    .auto_shrink([false, true])
                    .min_scrolled_height(crate::windows::grow_height(ui))
                    .show(ui, |ui| crate::dns_analysis::watch_results(ui, app.lang, &self.watch));
                return;
            }
            Tab::Upstreams => {
                self.bench_form(app, ui);
                ui.separator();
                egui::ScrollArea::vertical()
                    .id_salt("dns-upstreams-results")
                    .auto_shrink([false, true])
                    .min_scrolled_height(crate::windows::grow_height(ui))
                    .show(ui, |ui| crate::dns_analysis::bench_results(ui, app.lang, &self.bench));
                return;
            }
        }
        self.form(app, ui);
        ui.separator();
        // The window grows with its tables up to the work area's width (it
        // is kept inside the area: growing past its edge moves it left).
        let width = app
            .floats
            .area
            .map_or_else(|| ui.ctx().content_rect().width(), |a| a.width());
        let right = ui.max_rect().left() + width - RIGHT_MARGIN;
        if let Some(rule) = self.results(app.lang, right, ui) {
            open_rule(app, &rule);
        }
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        let view = match then.downcast::<Tab>().map(|t| *t) {
            Ok(Tab::Watch) => Some(&mut self.watch),
            Ok(Tab::Upstreams) => Some(&mut self.bench),
            _ => None,
        };
        if let Some(view) = view {
            match result {
                Ok(v) => view.task = v.get("id").and_then(Value::as_u64),
                Err(e) => {
                    view.error = Some(e.clone());
                    view.done = true;
                }
            }
            app.cache.refreshed_at = None;
            return;
        }
        match result {
            Ok(v) => {
                self.task = v.get("id").and_then(Value::as_u64);
                self.command = v.get("command").and_then(Value::as_str).unwrap_or("").to_owned();
            }
            Err(e) => {
                self.error = Some(e.clone());
                self.done = true;
            }
        }
        app.cache.refreshed_at = None;
    }

    fn escape(&mut self, _win: &'static str) -> bool {
        // Esc stops a running watch (or benchmark) of the tab shown.
        let view = match self.tab {
            Tab::Watch => Some(&mut self.watch),
            Tab::Upstreams => Some(&mut self.bench),
            Tab::Lookup => None,
        };
        if let Some(v) = view
            && v.running()
        {
            v.stop = true;
            return true;
        }
        self.selected.take().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_follow_the_form() {
        let mut p = LookupPanel {
            name: " example.com ".into(),
            ..LookupPanel::default()
        };
        assert_eq!(p.params(), json!({"name": "example.com", "type": "A", "explain": true}));
        p.as_client = " 192.168.88.10 ".into();
        assert_eq!(
            p.params(),
            json!({"name": "example.com", "type": "A", "explain": true, "as_client": "192.168.88.10"})
        );
        p.trace = true;
        assert_eq!(p.params(), json!({"name": "example.com", "type": "A", "trace": true}), "trace: from the root");
        p.trace = false;
        p.ask = Ask::Server;
        p.server = "https://dns.google/dns-query".into();
        p.rtype = "MX".into();
        p.recursion = false;
        p.dnssec = true;
        assert_eq!(
            p.params(),
            json!({"name": "example.com", "type": "MX", "server": "https://dns.google/dns-query",
                "recursion": false, "dnssec": true})
        );
        p.ask = Ask::All;
        p.dnssec = false;
        p.recursion = true;
        assert_eq!(p.params(), json!({"name": "example.com", "type": "MX", "compare": true}));
    }
}
