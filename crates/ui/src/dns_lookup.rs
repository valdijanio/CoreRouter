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
//! No logic here: the engine decides divergence, signatures and the text.

use std::collections::BTreeMap;

use egui::{Grid, RichText, TextEdit, Ui};
use serde_json::{Map, Value, json};

use crate::backend::RequestId;
use crate::chip::{AMBER, BLUE, GREEN, RED, chip, hashed, neutral_tone, palette_tone};
use crate::dhcp_client::text;
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::action;
use crate::{CoreRouterUi, err_color};

const NAME: &str = "dns-lookup";
pub(crate) const WIN: &str = "dns-lookup";
const QUERY: &str = "tool.dns.query";
const STOP: &str = "tool.task.stop";
pub(crate) const TYPES: [&str; 10] = [
    "A", "AAAA", "MX", "TXT", "NS", "SOA", "PTR", "CAA", "SRV", "ANY",
];
/// Data longer than this is cut in the table (the whole in the tooltip).
const MAX_SHOWN: usize = 72;

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "Tools",
        title: "DNS Lookup",
        size: [780.0, 520.0],
        escape: true,
    }],
    new: || Box::new(LookupPanel::default()),
};

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
}

impl Default for LookupPanel {
    fn default() -> Self {
        Self {
            name: String::new(),
            rtype: "A".into(),
            ask: Ask::Router,
            server: String::new(),
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

    fn results(&mut self, ui: &mut Ui) {
        if let Some(e) = &self.error {
            ui.colored_label(err_color(ui), e.as_str());
        }
        let last = std::mem::take(&mut self.rows);
        let mut ctx = Rows {
            last,
            now: BTreeMap::new(),
            selected: self.selected,
        };
        egui::ScrollArea::vertical()
            .id_salt("dns-lookup-results")
            .auto_shrink([false, false])
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
    }
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
}

impl Rows {
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

/// At most [`MAX_SHOWN`] characters, with "…" when cut.
fn cut(s: &str) -> String {
    if s.chars().count() <= MAX_SHOWN {
        return s.to_owned();
    }
    let mut t: String = s.chars().take(MAX_SHOWN - 1).collect();
    t.push('…');
    t
}

/// A data cell: the text (cut, whole in the tooltip) and, for an address,
/// its AS pill coloured by the AS number (as in the MTR).
fn data_cell(ui: &mut Ui, data: &str, asn: Option<&Value>) -> f32 {
    let r = ui
        .horizontal(|ui| {
            let l = ui.label(cut(data));
            if data.chars().count() > MAX_SHOWN {
                l.on_hover_text(data);
            }
            if let Some(a) = asn
                && let (Some(label), Some(n)) = (crate::mtr::as_text(a), a.get("asn").and_then(Value::as_u64))
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
                let right = data_cell(ui, &data, asn.get(&data));
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
                    let l = ui.label(cut(&all));
                    let right = l.rect.right();
                    if all.chars().count() > MAX_SHOWN {
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
                let right = ui
                    .horizontal(|ui| {
                        if r.get("error").is_some() {
                            if r.get("timeout").and_then(Value::as_bool) == Some(true) {
                                chip(ui, "timeout", RED.tone(ui.visuals()));
                            }
                            ui.label(RichText::new(cut(&text(r, "error"))).weak());
                            return;
                        }
                        let answer = text(r, "answer");
                        let l = ui.label(cut(&answer));
                        if answer.chars().count() > MAX_SHOWN {
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
        match self.task {
            Some(id) if !self.done && app.open.contains(&crate::Win::Panel(WIN)) => vec![Query {
                key: "poll",
                command: "tool.task.poll",
                params: json!({"id": id, "after_seq": 0, "max": 256, "text": true}),
            }],
            _ => Vec::new(),
        }
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        if key != "poll" {
            return;
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
        self.form(app, ui);
        ui.separator();
        self.results(ui);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, _then: PanelThen, result: &Result<Value, String>) {
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
        assert_eq!(p.params(), json!({"name": "example.com", "type": "A"}));
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
        assert_eq!(cut(&"x".repeat(100)).chars().count(), MAX_SHOWN);
    }
}
