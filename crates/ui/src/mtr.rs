//! Tools › MTR (G6.3): continuous traceroute, one row per hop, live.
//!
//! Like Tools › Ping, the window drives an engine task (`tool.mtr.start`)
//! and polls it; the per-hop statistics come from the engine. The bar after
//! the numbers is each hop's average RTT next to the slowest one, so the
//! hop where latency jumps stands out.
//!
//! G6.3b: each hop shows its name (when the reverse lookup has answered),
//! its origin AS and the MPLS labels it reported.
//!
//! G6.3d: one line per hop, all the same height. The host is the name, or
//! the address while none is known, followed by small pills: `privada`
//! (quiet), `CGNAT` (amber) and `MPLS <label>` (blue). The Network column
//! is the AS as a pill whose colour comes from the AS number, so every hop
//! of one operator shares a colour and the hand-over to the next one
//! stands out. Full names, addresses and labels are in the tooltips.
//!
//! G6.4c: a Traceroute mode (one pass, `tool.traceroute.start`: N probes
//! per hop, each RTT in the Probes column), the probe protocol (ICMP, UDP,
//! TCP SYN, with the port) and Paris (one flow, so per-flow load balancers
//! keep every probe on one path; off, a hop behind ECMP shows its routers
//! with an `ECMP n` chip). Each new field has its ⓘ.

use std::collections::BTreeMap;

use egui::{Color32, Grid, RichText, TextEdit, Ui};
use serde_json::{Value, json};

pub(crate) use crate::chip::{
    hashed as as_hue, hues_along as path_hues, palette_tone as as_tone,
};
use crate::chip::{AMBER, BLUE, chip, neutral_tone};
use crate::ping::{TaskView, ToolReq};
use crate::table::action;
use crate::windows::combo;
use crate::{CoreRouterUi, Then, err_color, form_number, value_text};

pub(crate) struct MtrForm {
    /// `traceroute` (one pass) or the continuous MTR.
    pub(crate) traceroute: bool,
    pub(crate) probes: String,
    pub(crate) protocol: String,
    pub(crate) port: String,
    pub(crate) paris: bool,
    pub(crate) address: String,
    pub(crate) count: String,
    pub(crate) interval: String,
    pub(crate) max_hops: String,
    pub(crate) src: String,
    pub(crate) interface: String,
    pub(crate) routing_table: String,
    pub(crate) use_dns: bool,
    pub(crate) as_lookup: bool,
}

impl Default for MtrForm {
    fn default() -> Self {
        Self {
            traceroute: false,
            probes: "3".into(),
            protocol: "icmp".into(),
            port: String::new(),
            paris: true,
            address: String::new(),
            count: String::new(),
            interval: "1000".into(),
            max_hops: "30".into(),
            src: String::new(),
            interface: String::new(),
            routing_table: String::new(),
            use_dns: true,
            as_lookup: false,
        }
    }
}

#[derive(Default)]
pub(crate) struct MtrWin {
    pub(crate) form: MtrForm,
    pub(crate) help: Option<crate::help::HelpView>,
    pub(crate) task: Option<TaskView>,
    error: Option<String>,
    starting: bool,
    /// The selected hop (click a row; click it again to clear).
    pub(crate) selected: Option<u64>,
    /// Enter with a new address while running: stop, then start again.
    restart: bool,
    /// Each row's rectangle from the last frame: the click area sits under
    /// the cells, so their tooltips (full name, AS prefix) keep working.
    rows: BTreeMap<u64, egui::Rect>,
}

fn num(v: &Value, k: &str) -> Option<f64> {
    v.get(k).and_then(Value::as_f64)
}

fn ms(v: Option<f64>) -> String {
    v.map(|x| format!("{x:.2}")).unwrap_or_else(|| "–".into())
}

/// Loss colour: none, some, all.
fn loss_color(ui: &Ui, loss: f64) -> Color32 {
    if loss >= 100.0 {
        err_color(ui)
    } else if loss > 0.0 {
        ui.visuals().warn_fg_color
    } else {
        ui.visuals().text_color()
    }
}

impl CoreRouterUi {
    pub(crate) fn mtr_reply(&mut self, result: Result<Value, String>) {
        let Some(task) = self.mtr.task.as_mut() else {
            return;
        };
        match result {
            Ok(p) if p.get("id").and_then(Value::as_u64) == Some(task.id) => {
                // Events are per probe; the window draws the summary only.
                task.absorb(&p);
            }
            Ok(_) => task.polling = false,
            Err(e) => {
                task.polling = false;
                task.done = true;
                task.state = "lost".into();
                task.reason = Some(e);
            }
        }
    }

    pub(crate) fn mtr_started(&mut self, result: &Result<Value, String>) {
        let w = &mut self.mtr;
        w.starting = false;
        match result {
            Ok(r) => match r.get("task_id").and_then(Value::as_u64) {
                Some(id) => {
                    w.error = None;
                    w.task = Some(TaskView::new(id));
                }
                None => w.error = Some(format!("the router started no task: {r}")),
            },
            Err(e) => w.error = Some(e.clone()),
        }
    }

    /// Start (Enter), unless one runs or is being started.
    pub(crate) fn mtr_start(&mut self) {
        if self.mtr.starting || self.mtr.task.as_ref().is_some_and(TaskView::running) {
            return;
        }
        let f = &self.mtr.form;
        let (command, p) = mtr_params(f);
        self.mtr.starting = true;
        self.run_then(command, p, Then::Tool(ToolReq::Mtr));
    }

    /// Stop (Esc) a running MTR; `false` if none ran.
    pub(crate) fn mtr_stop(&mut self) -> bool {
        match &self.mtr.task {
            Some(t) if t.running() => {
                let id = t.id;
                self.run("tool.task.stop", json!({ "id": id }));
                true
            }
            _ => false,
        }
    }

    /// The window closed: stop its task.
    pub(crate) fn mtr_closed(&mut self) {
        self.mtr_stop();
    }

    pub(crate) fn mtr_window(&mut self, ui: &mut Ui) {
        let can = self.can();
        let running = self.mtr.task.as_ref().is_some_and(TaskView::running);
        let interfaces = self.interface_names(None);
        let mut tables = vec!["main".to_owned()];
        tables.extend(self.interface_names(Some("vrf")));
        let langs = self.lang;
        let l = langs.labels;
        let f = &mut self.mtr.form;
        let mut enter = false;
        let mut help: Option<crate::help::HelpView> = None;
        let mut info = |ui: &mut Ui, key: &str, title: &'static str| {
            if crate::help::info_button(ui, egui::Id::unique(("mtr-help", key)), crate::i18n::tr_in("traceroute", l, title)).clicked() {
                help = Some(crate::help::HelpView::new(format!("mtr.{key}"), crate::i18n::tr_in("traceroute", l, title)));
            }
        };
        ui.horizontal(|ui| {
            ui.add_enabled_ui(!running, |ui| {
                if crate::list::filter_chip(ui, "MTR", !f.traceroute) {
                    f.traceroute = false;
                }
                if crate::list::filter_chip(ui, "Traceroute", f.traceroute) {
                    f.traceroute = true;
                }
            });
            info(ui, "mode", "Mode");
            ui.separator();
            ui.label("Address");
            let r = ui.add(
                TextEdit::singleline(&mut f.address)
                    .id(crate::dialog::field_id(
                        crate::win_id(crate::Win::Mtr),
                        "address",
                    ))
                    .hint_text("8.8.8.8 or example.com")
                    .desired_width(260.0),
            );
            enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if f.traceroute {
                ui.label("Probes");
                ui.add(TextEdit::singleline(&mut f.probes).hint_text("3").desired_width(40.0));
                info(ui, "probes", "Probes");
            } else {
                ui.label("Count");
                ui.add(
                    TextEdit::singleline(&mut f.count)
                        .hint_text("until stopped")
                        .desired_width(90.0),
                );
            }
        });
        ui.horizontal(|ui| {
            ui.label("Protocol");
            let opts = ["icmp".to_owned(), "udp".to_owned(), "tcp".to_owned()];
            combo(ui, "mtr-proto", "icmp", &mut f.protocol, &opts);
            info(ui, "protocol", "Protocol");
            if f.protocol != "icmp" {
                ui.label("Port");
                let hint = if f.protocol == "tcp" { "80" } else { "33434" };
                ui.add(TextEdit::singleline(&mut f.port).hint_text(hint).desired_width(60.0));
                info(ui, "port", "Port");
            }
            ui.checkbox(&mut f.paris, "Paris");
            info(ui, "paris", "Paris");
        });
        Grid::new("mtr-form")
            .num_columns(6)
            .spacing([10.0, 4.0])
            .show(ui, |ui| {
                ui.label("Interval (ms)");
                // One pass: the probes of a hop leave 50 ms apart.
                ui.add_enabled(!f.traceroute, TextEdit::singleline(&mut f.interval).desired_width(70.0));
                ui.label("Max hops");
                ui.add(TextEdit::singleline(&mut f.max_hops).desired_width(50.0));
                ui.label("Src. address");
                ui.add(
                    TextEdit::singleline(&mut f.src)
                        .hint_text("any")
                        .desired_width(120.0),
                );
                ui.end_row();
                ui.label("Interface");
                let mut names = vec![String::new()];
                names.extend(interfaces);
                combo(ui, "mtr-iface", "any", &mut f.interface, &names);
                ui.label("Routing table");
                combo(
                    ui,
                    "mtr-routing-table",
                    "main",
                    &mut f.routing_table,
                    &tables,
                );
                ui.checkbox(&mut f.use_dns, "Use DNS")
                    .on_hover_text("Show hop names (reverse DNS through IP › DNS)");
                ui.checkbox(&mut f.as_lookup, "AS lookup").on_hover_text(
                    "Show each hop's origin AS (TXT queries to the Team Cymru service)",
                );
                ui.end_row();
            });
        if help.is_some() {
            self.mtr.help = help;
        }
        crate::help::modal(ui.ctx(), langs, &mut self.mtr.help);
        ui.separator();
        let mut start = false;
        let mut stop = false;
        ui.horizontal(|ui| {
            let start_ok = if running {
                Err("already running: Stop first".to_owned())
            } else if self.mtr.form.address.trim().is_empty() {
                Err("Type an address first".to_owned())
            } else {
                Ok(())
            };
            let command = if self.mtr.form.traceroute { "tool.traceroute.start" } else { "tool.mtr.start" };
            start = action(ui, "Start", can.and(command, start_ok));
            let stop_ok = if running {
                Ok(())
            } else {
                Err("not running".to_owned())
            };
            stop = action(ui, "Stop", can.and("tool.task.stop", stop_ok));
            ui.separator();
            if let Some(t) = &self.mtr.task {
                let s = &t.summary;
                let text = match (&t.reason, t.state.as_str()) {
                    (Some(r), "failed" | "lost") => format!("{}: {r}", t.state),
                    (_, st) => format!(
                        "{} ({}) — round {}{} — {st}",
                        s.get("host").map(value_text).unwrap_or_default(),
                        s.get("address").map(value_text).unwrap_or_default(),
                        s.get("rounds").map(value_text).unwrap_or_default(),
                        if s.get("reached").and_then(Value::as_bool) == Some(true) {
                            ", reached"
                        } else {
                            ""
                        },
                    ),
                };
                if matches!(t.state.as_str(), "failed" | "lost") {
                    ui.colored_label(err_color(ui), text);
                } else {
                    ui.weak(text);
                }
            }
        });
        // Enter in Address: start; while running, a changed address restarts
        // with it (the same address keeps running).
        if enter && !self.mtr.form.address.trim().is_empty() {
            let now = self
                .mtr
                .task
                .as_ref()
                .and_then(|t| t.summary.get("address"))
                .map(value_text)
                .unwrap_or_default();
            if !running {
                start = true;
            } else if now.trim() != self.mtr.form.address.trim() {
                self.mtr.restart = true;
                stop = true;
            }
        }
        if self.mtr.restart && !running && !self.mtr.starting && !stop {
            self.mtr.restart = false;
            start = true;
        }
        if start {
            self.mtr.selected = None;
            self.mtr_start();
        }
        if stop {
            self.mtr_stop();
        }
        if let Some(e) = &self.mtr.error {
            ui.colored_label(err_color(ui), e.as_str());
        }
        ui.separator();
        self.mtr_table(ui);
    }

    fn mtr_table(&mut self, ui: &mut Ui) {
        let Some(t) = &self.mtr.task else {
            ui.weak("Type an address and press Start (Enter): one row per hop, updated live.");
            return;
        };
        let empty = Vec::new();
        let hops = t
            .summary
            .get("hops")
            .and_then(Value::as_array)
            .unwrap_or(&empty);
        let slowest = hops
            .iter()
            .filter_map(|h| num(h, "avg_ms"))
            .fold(0.0f64, f64::max);
        let bar = ui.visuals().selection.bg_fill;
        let as_col = t.summary.get("as_lookup").and_then(Value::as_bool) == Some(true);
        let trace = t.summary.get("mode").and_then(Value::as_str) == Some("traceroute");
        let hues = path_hues(hops.iter().filter_map(|h| h.get("asn").and_then(Value::as_u64)));
        let mut selected = self.mtr.selected;
        let last_rows = std::mem::take(&mut self.mtr.rows);
        let mut rows = BTreeMap::new();
        let sel_fill = ui.visuals().selection.bg_fill;
        let hover_fill = ui.visuals().widgets.hovered.weak_bg_fill;
        egui::ScrollArea::vertical()
            .id_salt("mtr-hops")
            .min_scrolled_height(crate::windows::grow_height(ui))
            .show(ui, |ui| {
                Grid::new("mtr-table")
                    .striped(true)
                    .spacing([12.0, 3.0])
                    .show(ui, |ui| {
                        let mut heads = vec!["Hop", "Host"];
                        if as_col {
                            heads.push("Network");
                        }
                        heads.extend([
                            "Loss %", "Sent", "Last", "Avg", "Best", "Worst", "StDev",
                        ]);
                        if trace {
                            heads.push("Probes");
                        }
                        heads.push("");
                        for h in heads {
                            ui.strong(h);
                        }
                        ui.end_row();
                        for h in hops {
                            let g = |k: &str| h.get(k).map(value_text).unwrap_or_default();
                            let hop = h.get("hop").and_then(Value::as_u64).unwrap_or(0);
                            if let Some(rect) = last_rows.get(&hop) {
                                let resp = ui.interact(
                                    *rect,
                                    egui::Id::unique(("mtr-row", hop)),
                                    egui::Sense::click(),
                                );
                                if resp.clicked() {
                                    selected = (selected != Some(hop)).then_some(hop);
                                }
                                if resp.secondary_clicked() {
                                    selected = Some(hop);
                                }
                                row_menu(&resp, h);
                                if selected == Some(hop) {
                                    ui.painter().rect_filled(*rect, 2.0, sel_fill);
                                } else if resp.hovered() {
                                    ui.painter().rect_filled(*rect, 2.0, hover_fill);
                                }
                            }
                            let top_left = ui.cursor().min;
                            ui.label(g("hop"));
                            host_cell(ui, h);
                            if as_col {
                                network_cell(ui, h, &hues);
                            }
                            let loss = num(h, "loss_pct").unwrap_or(0.0);
                            ui.label(
                                RichText::new(format!("{loss:.1}")).color(loss_color(ui, loss)),
                            );
                            ui.label(g("sent"));
                            for k in ["last_ms", "avg_ms", "best_ms", "worst_ms", "stddev_ms"] {
                                ui.label(ms(num(h, k)));
                            }
                            if trace {
                                ui.label(probes_text(h));
                            }
                            let frac = match num(h, "avg_ms") {
                                Some(a) if slowest > 0.0 => (a / slowest) as f32,
                                _ => 0.0,
                            };
                            let (rect, _) = ui.allocate_exact_size(
                                egui::vec2(120.0, ui.spacing().interact_size.y * 0.6),
                                egui::Sense::hover(),
                            );
                            let mut fill = rect;
                            fill.set_width(rect.width() * frac.clamp(0.0, 1.0));
                            ui.painter().rect_filled(fill, 2.0, bar);
                            let right = rect.right();
                            ui.end_row();
                            let bottom = ui.cursor().min.y - ui.spacing().item_spacing.y;
                            rows.insert(
                                hop,
                                egui::Rect::from_min_max(
                                    top_left - egui::vec2(4.0, 1.0),
                                    egui::pos2(right + 4.0, bottom.max(top_left.y) + 1.0),
                                ),
                            );
                        }
                    });
            });
        self.mtr.rows = rows;
        self.mtr.selected = selected;
    }
}

/// `tool.mtr.start` or `tool.traceroute.start`, and its parameters.
pub(crate) fn mtr_params(f: &MtrForm) -> (&'static str, Value) {
    let text = |s: &str| {
        let s = s.trim();
        (!s.is_empty()).then(|| json!(s))
    };
    let mut p = json!({
        "address": f.address.trim(),
        "max_hops": form_number(&f.max_hops),
        "src_address": text(&f.src),
        "interface": text(&f.interface),
        "routing_table": text(&f.routing_table),
        "use_dns": f.use_dns,
        "as_lookup": f.as_lookup,
        "protocol": f.protocol,
        "paris": f.paris,
    });
    if let Value::Object(o) = &mut p {
        if f.protocol != "icmp" {
            o.insert("port".into(), form_number(&f.port));
        }
        if f.traceroute {
            o.insert("probes".into(), form_number(&f.probes));
        } else {
            o.insert("count".into(), form_number(&f.count));
            o.insert("interval_ms".into(), form_number(&f.interval));
        }
        o.retain(|_, v| !v.is_null());
    }
    let command = if f.traceroute { "tool.traceroute.start" } else { "tool.mtr.start" };
    (command, p)
}

/// A hop's probes in the traceroute mode: `1.21 1.30 *`.
fn probes_text(h: &Value) -> String {
    h.get("rtts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|r| r.as_f64().map_or_else(|| "*".to_owned(), |v| format!("{v:.2}")))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Right click on a hop: copy what an operator pastes into a ticket.
fn row_menu(resp: &egui::Response, h: &Value) {
    let address = h
        .get("hosts")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .map(value_text);
    let name = h.get("name").and_then(Value::as_str).map(str::to_owned);
    if address.is_none() {
        return;
    }
    resp.context_menu(|ui| {
        if let Some(a) = &address
            && ui.button("Copy address").clicked()
        {
            ui.ctx().copy_text(a.clone());
            ui.close();
        }
        if let Some(n) = &name
            && ui.button("Copy host").clicked()
        {
            ui.ctx().copy_text(n.clone());
            ui.close();
        }
    });
}

/// What the chip of a private, CGNAT, link-local… address says.
fn scope_chip(scope: &str) -> &str {
    match scope {
        "private" => "privada",
        "cgnat" => "CGNAT",
        other => other,
    }
}

/// "MPLS 85260", "MPLS 16005/24003" (top first) from the hop's labels.
fn mpls_chip(h: &Value) -> Option<String> {
    let labels: Vec<String> = h
        .get("hosts_info")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(|f| f.get("mpls"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|l| l.get("label").and_then(Value::as_u64))
        .map(|l| l.to_string())
        .collect();
    if !labels.is_empty() {
        return Some(format!("MPLS {}", labels.join("/")));
    }
    // An older router sends only the text ("L=24017").
    h.get("mpls_text")
        .and_then(Value::as_str)
        .map(|t| format!("MPLS {}", t.trim_start_matches("L=")))
}

/// What the AS pill says: "AS7162 UOL" (the first word of the registry
/// name), "AS7162" without a name.
pub(crate) fn as_text(h: &Value) -> Option<String> {
    let n = h.get("asn").and_then(Value::as_u64)?;
    let short = h
        .get("as_name")
        .and_then(Value::as_str)
        .and_then(|name| name.split(',').next())
        .and_then(|name| name.split_whitespace().next())
        // A registry "name" that is the number itself adds nothing.
        .filter(|w| !w.eq_ignore_ascii_case(&format!("AS{n}")))
        .map(|w| truncate(w, 16));
    Some(match short {
        Some(w) => format!("AS{n} {w}"),
        None => format!("AS{n}"),
    })
}

/// The Network cell: the AS pill, coloured by its number; empty without one.
fn network_cell(ui: &mut Ui, h: &Value, hues: &BTreeMap<u64, usize>) {
    let (Some(text), Some(n)) = (as_text(h), h.get("asn").and_then(Value::as_u64)) else {
        ui.label("");
        return;
    };
    let hue = hues.get(&n).copied().unwrap_or_else(|| as_hue(n));
    let tone = as_tone(ui.visuals(), hue);
    let mut tip = format!("AS{n}");
    if let Some(name) = h.get("as_name").and_then(Value::as_str) {
        tip = format!("{tip} {name}");
    }
    let prefix = h
        .get("hosts_info")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
        .and_then(|f| f.get("as_prefix"))
        .and_then(Value::as_str);
    if let Some(p) = prefix {
        tip = format!("{tip}\nprefix {p}");
    }
    chip(ui, &text, tone).on_hover_text(tip);
}

/// At most `max` characters, with "…" when cut.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_owned();
    }
    let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
    t.push('…');
    t
}

/// Longest host name before it ends in "…" (the whole one is in the tooltip).
const HOST_CHARS: usize = 40;

pub(crate) fn host_id(hop: u64) -> egui::Id {
    egui::Id::unique(("mtr-host", hop))
}

/// One line per hop: the name (or the address while none is known), then
/// the chips. Everything else (every address, the full name, the labels,
/// an unreachable note) is in the tooltip.
fn host_cell(ui: &mut Ui, h: &Value) {
    let hosts: Vec<String> = h
        .get("hosts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(value_text)
        .collect();
    let name = h.get("name").and_then(Value::as_str);
    let scope = h.get("scope").and_then(Value::as_str);
    let mpls = mpls_chip(h);
    let note = h.get("note").and_then(Value::as_str);
    let hop = h.get("hop").and_then(Value::as_u64).unwrap_or(0);
    let r = ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 8.0;
        let Some(first) = hosts.first() else {
            ui.weak("sem resposta");
            return;
        };
        let shown = name.unwrap_or(first);
        ui.add(egui::Label::new(truncate(shown, HOST_CHARS)).selectable(false));
        ui.spacing_mut().item_spacing.x = 4.0;
        if hosts.len() > 1 {
            // Several routers answered for this hop: a load balancer.
            chip(ui, &format!("ECMP {}", hosts.len()), AMBER.tone(ui.visuals()));
        }
        if let Some(s) = scope {
            let tone = if s == "cgnat" {
                AMBER.tone(ui.visuals())
            } else {
                neutral_tone(ui.visuals())
            };
            chip(ui, scope_chip(s), tone);
        }
        if let Some(m) = &mpls {
            chip(ui, m, BLUE.tone(ui.visuals()));
        }
        if let Some(n) = note {
            ui.weak(n);
        }
    });
    let mut tip: Vec<String> = Vec::new();
    if let Some(n) = name {
        tip.push(n.to_owned());
    }
    tip.extend(hosts.iter().cloned());
    if let Some(s) = scope {
        tip.push(format!("{s} address: not looked up"));
    }
    if let Some(m) = h.get("mpls_text").and_then(Value::as_str) {
        tip.push(format!("MPLS {m}"));
    }
    if let Some(n) = note {
        tip.push(n.to_owned());
    }
    let resp = ui.interact(r.response.rect, host_id(hop), egui::Sense::hover());
    if !tip.is_empty() {
        resp.on_hover_text(tip.join("\n"));
    }
}
