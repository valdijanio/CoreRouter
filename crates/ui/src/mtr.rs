//! Tools › MTR (G6.3): continuous traceroute, one row per hop, live.
//!
//! Like Tools › Ping, the window drives an engine task (`tool.mtr.start`)
//! and polls it; the per-hop statistics come from the engine. The bar after
//! the numbers is each hop's average RTT next to the slowest one, so the
//! hop where latency jumps stands out.

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
    v.map(|x| format!("{x:.2}")).unwrap_or_else(|| "-".into())
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
                    .id(crate::dialog::field_id(crate::win_id(crate::Win::Mtr), "address"))
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
                combo(ui, "mtr-table", "main", &mut f.routing_table, &tables);
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
        egui::ScrollArea::vertical()
            .id_salt("mtr-hops")
            .show(ui, |ui| {
                Grid::new("mtr-table")
                    .striped(true)
                    .spacing([12.0, 3.0])
                    .show(ui, |ui| {
                        for h in [
                            "Hop", "Host", "Loss %", "Sent", "Last", "Avg", "Best", "Worst",
                            "StDev", "",
                        ] {
                            ui.strong(h);
                        }
                        ui.end_row();
                        for h in hops {
                            let g = |k: &str| h.get(k).map(value_text).unwrap_or_default();
                            ui.label(g("hop"));
                            let hosts: Vec<String> = h
                                .get("hosts")
                                .and_then(Value::as_array)
                                .into_iter()
                                .flatten()
                                .map(value_text)
                                .collect();
                            let mut host = if hosts.is_empty() {
                                "???".to_owned()
                            } else {
                                hosts.join(", ")
                            };
                            if let Some(n) = h.get("note").and_then(Value::as_str) {
                                host = format!("{host} ({n})");
                            }
                            ui.label(host);
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
