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

use std::collections::BTreeMap;

use egui::{Color32, Grid, RichText, TextEdit, Ui};
use serde_json::{Value, json};

use crate::ping::{TaskView, ToolReq};
use crate::table::action;
use crate::windows::combo;
use crate::{CoreRouterUi, Then, err_color, form_number, value_text};

pub(crate) struct MtrForm {
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
    pub(crate) task: Option<TaskView>,
    error: Option<String>,
    starting: bool,
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
        let text = |s: &str| {
            let s = s.trim();
            (!s.is_empty()).then(|| json!(s))
        };
        let mut p = json!({
            "address": f.address.trim(),
            "count": form_number(&f.count),
            "interval_ms": form_number(&f.interval),
            "max_hops": form_number(&f.max_hops),
            "src_address": text(&f.src),
            "interface": text(&f.interface),
            "routing_table": text(&f.routing_table),
            "use_dns": f.use_dns,
            "as_lookup": f.as_lookup,
        });
        if let Value::Object(o) = &mut p {
            o.retain(|_, v| !v.is_null());
        }
        self.mtr.starting = true;
        self.run_then("tool.mtr.start", p, Then::Tool(ToolReq::Mtr));
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
        let f = &mut self.mtr.form;
        ui.horizontal(|ui| {
            ui.label("Address");
            ui.add(
                TextEdit::singleline(&mut f.address)
                    .id(crate::dialog::field_id(
                        crate::win_id(crate::Win::Mtr),
                        "address",
                    ))
                    .hint_text("8.8.8.8 or example.com")
                    .desired_width(260.0),
            );
            ui.label("Count");
            ui.add(
                TextEdit::singleline(&mut f.count)
                    .hint_text("until stopped")
                    .desired_width(90.0),
            );
        });
        Grid::new("mtr-form")
            .num_columns(6)
            .spacing([10.0, 4.0])
            .show(ui, |ui| {
                ui.label("Interval (ms)");
                ui.add(TextEdit::singleline(&mut f.interval).desired_width(70.0));
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
            start = action(ui, "Start", can.and("tool.mtr.start", start_ok));
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
        if start {
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

    fn mtr_table(&self, ui: &mut Ui) {
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
        let hues = path_hues(hops.iter().filter_map(|h| h.get("asn").and_then(Value::as_u64)));
        egui::ScrollArea::vertical()
            .id_salt("mtr-hops")
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
                            "Loss %", "Sent", "Last", "Avg", "Best", "Worst", "StDev", "",
                        ]);
                        for h in heads {
                            ui.strong(h);
                        }
                        ui.end_row();
                        for h in hops {
                            let g = |k: &str| h.get(k).map(value_text).unwrap_or_default();
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
                            ui.end_row();
                        }
                    });
            });
    }
}

/// A pill's colours: soft fill, ink of the same hue, optional border.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Tone {
    pub(crate) fill: Color32,
    pub(crate) ink: Color32,
    pub(crate) border: Option<Color32>,
}

/// One hue for both themes: darker ink on the light one, lighter on the
/// dark one; the fill is the ink washed out, so it reads on striped rows.
struct Hue {
    light: (u8, u8, u8),
    dark: (u8, u8, u8),
}

impl Hue {
    fn tone(&self, v: &egui::Visuals) -> Tone {
        let ((r, g, b), wash) = if v.dark_mode {
            (self.dark, 0.20)
        } else {
            (self.light, 0.12)
        };
        let ink = Color32::from_rgb(r, g, b);
        Tone {
            fill: ink.gamma_multiply(wash),
            ink,
            border: None,
        }
    }
}

const AMBER: Hue = Hue {
    light: (140, 85, 0),
    dark: (245, 195, 105),
};

const BLUE: Hue = Hue {
    light: (30, 95, 175),
    dark: (140, 190, 245),
};

/// The AS palette: eight hues far enough apart that two operators side by
/// side on a path never look alike, each legible on both themes.
const AS_HUES: [Hue; 8] = [
    BLUE,
    Hue {
        light: (0, 120, 120),
        dark: (110, 215, 205),
    },
    Hue {
        light: (35, 125, 50),
        dark: (140, 215, 140),
    },
    Hue {
        light: (110, 110, 0),
        dark: (210, 205, 110),
    },
    Hue {
        light: (175, 80, 10),
        dark: (250, 170, 110),
    },
    Hue {
        light: (180, 35, 55),
        dark: (245, 145, 155),
    },
    Hue {
        light: (110, 60, 180),
        dark: (195, 165, 245),
    },
    Hue {
        light: (160, 40, 140),
        dark: (240, 150, 220),
    },
];

/// Which palette entry an AS gets: Fibonacci hashing, so the colour is
/// fixed by the number alone (every hop of an AS looks the same, in every
/// run) and consecutive numbers always land on different entries
/// (consecutive products differ by 0.618 of the range, more than 1/8).
pub(crate) fn as_hue(asn: u64) -> usize {
    let h = (asn as u32).wrapping_mul(0x9E37_79B9);
    (h >> 29) as usize
}

/// The colour of each AS on a path: its own (`as_hue`), except when the
/// AS right before it on the path (a different one) already has it; then
/// the next free one, so a hand-over between operators always shows. An
/// AS keeps the colour it got first for the whole table.
pub(crate) fn path_hues(asns: impl IntoIterator<Item = u64>) -> BTreeMap<u64, usize> {
    let mut out: BTreeMap<u64, usize> = BTreeMap::new();
    let mut prev: Option<usize> = None;
    for asn in asns {
        let hue = *out.entry(asn).or_insert_with(|| {
            let own = as_hue(asn);
            if prev == Some(own) {
                (own + 1) % AS_HUES.len()
            } else {
                own
            }
        });
        prev = Some(hue);
    }
    out
}

pub(crate) fn as_tone(v: &egui::Visuals, hue: usize) -> Tone {
    AS_HUES
        .get(hue)
        .map_or_else(|| neutral_tone(v), |h| h.tone(v))
}

fn neutral_tone(v: &egui::Visuals) -> Tone {
    Tone {
        fill: v.widgets.noninteractive.weak_bg_fill,
        ink: v.weak_text_color(),
        border: Some(v.widgets.noninteractive.bg_stroke.color),
    }
}

/// Font size of the pills: a step below the table's.
fn small(ui: &Ui) -> f32 {
    ui.style()
        .text_styles
        .get(&egui::TextStyle::Body)
        .map_or(11.0, |f| f.size * 0.85)
}

/// A small rounded pill, never taller than a table row.
fn chip(ui: &mut Ui, text: &str, tone: Tone) -> egui::Response {
    let font = egui::FontId::proportional(small(ui));
    let galley = ui
        .painter()
        .layout_no_wrap(text.to_owned(), font, tone.ink);
    let pad = egui::vec2(7.0, 2.0);
    let h = (galley.size().y + 2.0 * pad.y).min(ui.spacing().interact_size.y - 2.0);
    let (rect, resp) = ui.allocate_exact_size(
        egui::vec2(galley.size().x + 2.0 * pad.x, h),
        egui::Sense::hover(),
    );
    if ui.is_rect_visible(rect) {
        let stroke = tone
            .border
            .map_or(egui::Stroke::NONE, |c| egui::Stroke::new(1.0, c));
        ui.painter()
            .rect(rect, 8.0, tone.fill, stroke, egui::StrokeKind::Inside);
        let at = rect.center() - galley.size() / 2.0;
        ui.painter().galley(at, galley, tone.ink);
    }
    resp
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
            ui.weak(format!("+{}", hosts.len() - 1));
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
