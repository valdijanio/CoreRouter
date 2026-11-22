//! IP › Firewall › Test and Diff (G2.1c), tabs of the Firewall window.
//!
//! - **Test**: a made-up packet (`ip.firewall.test`) and its way through
//!   the chains as chips, coloured by what each chain did, the routing
//!   decision and the fate; the rule that decided is highlighted. Below,
//!   **Trace real packets** (`ip.firewall.trace.*`): `meta nftrace` for a
//!   filter, for a bounded time and number of events, and the way of each
//!   real packet the same way.
//! - **Diff**: the nftables ruleset the next `config.commit` would load
//!   against the running one (`ip.firewall.preview`), next to the pending
//!   config changes (`config.diff`).
//!
//! A panel with no window of its own: `firewall.rs` draws it in its tabs.

use egui::{Color32, Grid, Id, RichText, ScrollArea, TextEdit, Ui};
use serde_json::{Map, Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind, Tone};
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr_in};
use crate::panel::{self, Panel, PanelState, PanelThen, Query};
use crate::{CoreRouterUi, Win, value_text};

pub(crate) const NAME: &str = "firewall-diag";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[],
    new: || Box::<Diag>::default(),
};

/// Which tab draws now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum View {
    Test,
    Diff,
}

/// The reply a command waits for.
pub(crate) enum Reply {
    Test,
    Trace,
}

#[derive(Default)]
struct Diag {
    /// Test form: (param, value).
    test: Vec<(&'static str, String)>,
    result: Option<Value>,
    error: Option<String>,
    /// Trace form.
    trace: Vec<(&'static str, String)>,
    trace_list: Value,
    trace_error: Option<String>,
    preview: Value,
    pending: Value,
    /// Show the whole table, not only the changes and their context.
    whole: bool,
    help: Option<HelpView>,
}

const TEST_FIELDS: [(&str, &str, &str); 7] = [
    ("src", "Src. Address", "203.0.113.9"),
    ("dst", "Dst. Address", "192.0.2.1"),
    ("protocol", "Protocol", "tcp (default)"),
    ("src_port", "Src. Port", "40000"),
    ("dst_port", "Dst. Port", "443"),
    ("in_interface", "In. Interface", "from the router"),
    ("state", "State", "new (default)"),
];

const TRACE_FIELDS: [(&str, &str, &str); 7] = [
    ("src", "Src. Address", "IP or prefix"),
    ("dst", "Dst. Address", "IP or prefix"),
    ("protocol", "Protocol", "any"),
    ("port", "Dst. Port", "22"),
    ("in_interface", "In. Interface", "any"),
    ("duration", "Duration", "60 (s, at most 300)"),
    ("max_events", "Max Events", "1000"),
];

fn get<'a>(form: &'a [(&'static str, String)], k: &str) -> &'a str {
    form.iter().find(|(f, _)| *f == k).map_or("", |(_, v)| v.trim())
}

/// Filled fields as params (numbers as numbers).
fn params(form: &[(&'static str, String)]) -> Value {
    let mut p = Map::new();
    for (k, v) in form {
        let v = v.trim();
        if v.is_empty() {
            continue;
        }
        let numeric = matches!(*k, "src_port" | "dst_port" | "port" | "duration" | "max_events");
        let value = match (numeric, v.parse::<u64>()) {
            (true, Ok(n)) => json!(n),
            _ => json!(v),
        };
        p.insert((*k).to_owned(), value);
    }
    Value::Object(p)
}

fn text(v: &Value, k: &str) -> String {
    v.get(k).map(value_text).unwrap_or_default()
}

fn showing(app: &CoreRouterUi, view: View) -> bool {
    app.open.contains(&Win::Firewall) && app.firewall_diag_view() == Some(view)
}

/// The colour of what a chain did, the same as the rule colours.
fn verdict_tone(v: &egui::Visuals, verdict: &str) -> Tone {
    let action = match verdict {
        "nat" => "dst-nat",
        "delivered" | "sent" => "accept",
        "dropped" | "no-route" => "drop",
        other => other,
    };
    match crate::firewall::action_color(action, v.dark_mode) {
        Some(ink) => Tone {
            fill: ink.gamma_multiply(if v.dark_mode { 0.22 } else { 0.14 }),
            ink,
            border: None,
        },
        None => chip::neutral_tone(v),
    }
}

/// A chip that says where the packet went, with a tooltip.
fn step_chip(ui: &mut Ui, label: &str, tone: Tone, tip: &str) {
    chip::chip(ui, label, tone).on_hover_text(tip);
}

/// One way: chips for the chains, the route and the fate.
fn way(ui: &mut Ui, l: Lang, steps: &[Value], route: Option<&str>, fate: &str) {
    let v = ui.visuals().clone();
    ui.horizontal_wrapped(|ui| {
        let mut routed = false;
        for st in steps {
            let (table, chain) = (text(st, "table"), text(st, "chain"));
            // The routing decision sits between prerouting and the rest.
            if !routed && let Some(r) = route
                && !matches!(chain.as_str(), "prerouting" | "dstnat")
            {
                step_chip(ui, &format!("route: {r}"), Kind::Neutral.tone(&v), tr_in("firewall", l, "Routing decision"));
                ui.label("›");
                routed = true;
            }
            let label = format!("{table} {chain}");
            match st.get("skipped").and_then(Value::as_str) {
                Some(why) => {
                    let label = format!("{label} (skipped)");
                    let tone = Tone {
                        fill: Color32::TRANSPARENT,
                        ink: v.weak_text_color(),
                        border: Some(v.widgets.noninteractive.bg_stroke.color),
                    };
                    step_chip(ui, &label, tone, why);
                }
                None => {
                    let verdict = text(st, "verdict");
                    let rule = st.get("rule").and_then(Value::as_str);
                    let tip = match rule {
                        Some(r) => format!("{verdict} ({r})"),
                        None => format!("{verdict} (policy)"),
                    };
                    let tone = if rule.is_some() || verdict != "accept" {
                        verdict_tone(&v, &verdict)
                    } else {
                        chip::neutral_tone(&v)
                    };
                    step_chip(ui, &label, tone, &tip);
                }
            }
            ui.label("›");
        }
        if !routed && let Some(r) = route {
            step_chip(ui, &format!("route: {r}"), Kind::Neutral.tone(&v), tr_in("firewall", l, "Routing decision"));
            ui.label("›");
        }
        let fate_tone = verdict_tone(&v, fate);
        chip::chip(ui, &fate.to_uppercase(), fate_tone);
    });
}

impl Diag {
    fn form(ui: &mut Ui, l: Lang, salt: &str, fields: &[(&'static str, &'static str, &'static str)], form: &mut Vec<(&'static str, String)>, help: &mut Option<HelpView>, ifaces: &[String]) {
        if form.is_empty() {
            *form = fields.iter().map(|(k, _, _)| (*k, String::new())).collect();
        }
        Grid::new((salt, "form")).num_columns(4).spacing([8.0, 6.0]).show(ui, |ui| {
            for (i, ((key, value), (_, label, hint))) in form.iter_mut().zip(fields).enumerate() {
                let title = tr_in("firewall", l, label);
                ui.horizontal(|ui| {
                    ui.label(title);
                    if help::info_button(ui, Id::unique((salt, *key)), title).clicked() {
                        *help = Some(HelpView::new(format!("firewall.{salt}.{key}"), title));
                    }
                });
                match *key {
                    "protocol" => {
                        let opts: Vec<String> = ["tcp", "udp", "icmp", "icmpv6", "gre", "sctp"].map(String::from).to_vec();
                        crate::windows::combo(ui, &format!("{salt}-proto"), hint, value, &opts);
                    }
                    "state" => {
                        let opts: Vec<String> = ["new", "established", "related", "invalid"].map(String::from).to_vec();
                        crate::windows::combo(ui, &format!("{salt}-state"), hint, value, &opts);
                    }
                    "in_interface" => {
                        let mut opts = vec![String::new()];
                        opts.extend(ifaces.iter().cloned());
                        egui::ComboBox::from_id_salt((salt, "iif"))
                            .selected_text(if value.is_empty() { hint } else { value.as_str() })
                            .show_ui(ui, |ui| {
                                for o in &opts {
                                    let shown = if o.is_empty() { hint } else { o.as_str() };
                                    ui.selectable_value(value, o.clone(), shown);
                                }
                            });
                    }
                    _ => {
                        ui.add(TextEdit::singleline(value).hint_text(*hint).desired_width(150.0));
                    }
                }
                if i % 2 == 1 {
                    ui.end_row();
                }
            }
            ui.end_row();
        });
    }

    fn test_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        ui.label(
            RichText::new(tr_in(
                "firewall",
                l,
                "Which way would this packet take? Nothing is sent: the rules are evaluated as the kernel would.",
            ))
            .weak(),
        );
        let ifaces = app.interface_names(None);
        Self::form(ui, l, "test", &TEST_FIELDS, &mut self.test, &mut self.help, &ifaces);
        ui.horizontal(|ui| {
            let can = app.can().check("ip.firewall.test");
            let missing = get(&self.test, "src").is_empty() || get(&self.test, "dst").is_empty();
            let enabled = can.and_then(|()| if missing { Err("Fill Src. and Dst. Address".to_owned()) } else { Ok(()) });
            if crate::table::action(ui, tr_in("firewall", l, "Test"), enabled) {
                self.error = None;
                app.run_then("ip.firewall.test", params(&self.test), panel::then(NAME, Reply::Test));
            }
        });
        if let Some(e) = &self.error {
            ui.colored_label(ui.visuals().error_fg_color, e);
        }
        if let Some(r) = self.result.clone() {
            ui.separator();
            let steps = r.get("steps").and_then(Value::as_array).cloned().unwrap_or_default();
            way(ui, l, &steps, r.get("route").and_then(Value::as_str), &text(&r, "fate"));
            ui.add_space(4.0);
            match r.get("decided_by").filter(|d| !d.is_null()) {
                Some(d) => {
                    let tone = verdict_tone(ui.visuals(), &text(&r, "fate"));
                    ui.horizontal_wrapped(|ui| {
                        ui.label(tr_in("firewall", l, "Decided by"));
                        chip::chip(ui, &format!("{} {}", text(d, "table"), text(d, "id")), tone);
                        ui.label(RichText::new(text(d, "summary")).strong().color(tone.ink));
                    });
                }
                None => {
                    ui.weak(tr_in("firewall", l, "No rule decided: the chain policies (accept) let it through."));
                }
            }
            let p = r.get("packet").cloned().unwrap_or_default();
            ui.weak(format!(
                "{}: {}:{} -> {}:{} · {} · {}",
                tr_in("firewall", l, "Leaves as"),
                text(&p, "src"),
                text(&p, "src_port"),
                text(&p, "dst"),
                text(&p, "dst_port"),
                text(&p, "state"),
                text(&p, "out_interface"),
            ));
            // Every rule the packet matched, chain by chain; the deciding
            // one highlighted.
            Grid::new("fw-test-hits").striped(true).num_columns(4).show(ui, |ui| {
                for h in [tr_in("firewall", l, "Chain"), tr_in("firewall", l, "Rule"), "Action", tr_in("firewall", l, "Result")] {
                    ui.strong(h);
                }
                ui.end_row();
                for st in &steps {
                    let decided = st.get("rule").and_then(Value::as_str);
                    for h in st.get("hits").and_then(Value::as_array).into_iter().flatten() {
                        let id = text(h, "id");
                        let deciding = decided == Some(id.as_str());
                        let tone = verdict_tone(ui.visuals(), &text(h, "action"));
                        let cell = |t: String| if deciding { RichText::new(t).strong().color(tone.ink) } else { RichText::new(t) };
                        ui.label(cell(format!("{} {}", text(st, "table"), text(h, "chain"))));
                        ui.label(cell(id.clone()));
                        ui.label(cell(text(h, "action")));
                        ui.label(cell(if deciding { "decides".into() } else { "goes on".into() }));
                        ui.end_row();
                    }
                }
            });
        }
        ui.add_space(8.0);
        egui::CollapsingHeader::new(tr_in("firewall", l, "Trace real packets"))
            .id_salt("fw-trace")
            .default_open(true)
            .show(ui, |ui| self.trace_section(app, ui, l));
    }

    fn trace_section(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        ui.label(
            RichText::new(tr_in(
                "firewall",
                l,
                "Marks real packets that match the filter (at most 20 a second, for a limited time) and shows their way through the kernel.",
            ))
            .weak(),
        );
        let ifaces = app.interface_names(None);
        Self::form(ui, l, "trace", &TRACE_FIELDS, &mut self.trace, &mut self.help, &ifaces);
        let active = self.trace_list.get("active").and_then(Value::as_bool).unwrap_or(false);
        ui.horizontal(|ui| {
            let can = app.can();
            let empty = ["src", "dst", "protocol", "port", "in_interface"].iter().all(|k| get(&self.trace, k).is_empty());
            let start = can.check("ip.firewall.trace.start").and_then(|()| if empty { Err("Set at least one filter field".to_owned()) } else { Ok(()) });
            if crate::table::action(ui, tr_in("firewall", l, "Start"), start) {
                self.trace_error = None;
                app.run_then("ip.firewall.trace.start", params(&self.trace), panel::then(NAME, Reply::Trace));
                app.cache.refreshed_at = None;
            }
            let stop = can.check("ip.firewall.trace.stop").and_then(|()| if active { Ok(()) } else { Err("No trace running".to_owned()) });
            if crate::table::action(ui, tr_in("firewall", l, "Stop"), stop) {
                app.run("ip.firewall.trace.stop", json!({}));
                app.cache.refreshed_at = None;
            }
            let packets = self.trace_list.get("packets").and_then(Value::as_array).map_or(0, Vec::len);
            if active {
                chip::chip(ui, &format!("running · {packets} packets"), Kind::Green.tone(ui.visuals()));
            } else if let Some(why) = self.trace_list.get("ended").and_then(Value::as_str) {
                chip::chip(ui, &format!("ended: {why} · {packets} packets"), Kind::Neutral.tone(ui.visuals()));
            }
        });
        if let Some(e) = &self.trace_error {
            ui.colored_label(ui.visuals().error_fg_color, e);
        }
        let packets = self.trace_list.get("packets").and_then(Value::as_array).cloned().unwrap_or_default();
        ScrollArea::vertical().id_salt("fw-trace-list").max_height(260.0).show(ui, |ui| {
            for p in packets.iter().rev().take(200) {
                let ports = match (text(p, "sport").as_str(), text(p, "dport").as_str()) {
                    ("", "") => String::new(),
                    (s, d) => format!(" {s} -> {d}"),
                };
                ui.horizontal_wrapped(|ui| {
                    ui.strong(format!("{} -> {}", text(p, "src"), text(p, "dst")));
                    ui.weak(format!("{}{ports} in {}", text(p, "protocol"), text(p, "iif")));
                });
                // Each event a step (rule events only name the rule).
                let steps: Vec<Value> = p
                    .get("steps")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .map(|e| {
                        let verdict = text(e, "verdict");
                        json!({
                            "table": text(e, "table"),
                            "chain": text(e, "chain"),
                            "verdict": if verdict == "continue" { "accept".into() } else { verdict },
                            "rule": e.get("rule"),
                        })
                    })
                    .collect();
                way(ui, l, &steps, None, &text(p, "fate"));
                ui.separator();
            }
        });
    }

    fn diff_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let v = ui.visuals().clone();
        let changed = self.preview.get("changed").and_then(Value::as_bool).unwrap_or(false);
        ui.horizontal(|ui| {
            if changed {
                chip::chip(ui, &format!("+{}", text(&self.preview, "added")), verdict_tone(&v, "accept"));
                chip::chip(ui, &format!("-{}", text(&self.preview, "removed")), verdict_tone(&v, "drop"));
                ui.label(tr_in("firewall", l, "lines of nftables change at the next commit"));
            } else {
                chip::chip(ui, tr_in("firewall", l, "no change"), chip::neutral_tone(&v));
                ui.label(tr_in("firewall", l, "The kernel already holds what the candidate config renders."));
            }
            ui.checkbox(&mut self.whole, tr_in("firewall", l, "Show whole table"));
        });
        // The pending config changes (config.diff): one line per field.
        let pending: Vec<String> = self
            .pending
            .as_array()
            .into_iter()
            .flatten()
            .map(|c| match text(c, "op").as_str() {
                "change" => format!("{}: {} -> {}", text(c, "path"), text(c, "from"), text(c, "to")),
                op => format!("{op} {} = {}", text(c, "path"), text(c, "value")),
            })
            .collect();
        if !pending.is_empty() {
            ui.weak(format!("{} ({}):", tr_in("firewall", l, "Pending config changes"), pending.len()));
            for p in pending.iter().take(12) {
                ui.label(RichText::new(format!("• {p}")).small());
            }
            if pending.len() > 12 {
                ui.weak(format!("… +{}", pending.len() - 12));
            }
        }
        ui.separator();
        let lines = self.preview.get("lines").and_then(Value::as_array).cloned().unwrap_or_default();
        let keep: Vec<bool> = if !self.whole {
            // A change and three lines around it.
            let near: Vec<bool> = lines.iter().map(|x| text(x, "op") != " ").collect();
            (0..lines.len())
                .map(|i| (i.saturating_sub(3)..=(i + 3).min(lines.len().saturating_sub(1))).any(|j| near.get(j).copied().unwrap_or(false)))
                .collect()
        } else {
            vec![true; lines.len()]
        };
        let mono = egui::FontId::monospace(ui.style().text_styles.get(&egui::TextStyle::Body).map_or(12.0, |f| f.size * 0.92));
        ScrollArea::both().id_salt("fw-diff").auto_shrink([false, false]).show(ui, |ui| {
            for (x, show) in lines.iter().zip(keep) {
                if !show {
                    continue;
                }
                let op = text(x, "op");
                let (ink, bg) = match op.as_str() {
                    "+" => (verdict_tone(&v, "accept").ink, verdict_tone(&v, "accept").fill),
                    "-" => (verdict_tone(&v, "drop").ink, verdict_tone(&v, "drop").fill),
                    _ => (v.text_color(), Color32::TRANSPARENT),
                };
                let line = format!("{op} {}", text(x, "text").replace('\t', "    "));
                ui.add(egui::Label::new(RichText::new(line).font(mono.clone()).color(ink).background_color(bg)).extend());
            }
        });
    }
}

impl PanelState for Diag {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        let mut out = Vec::new();
        if showing(app, View::Test) && app.has_command("ip.firewall.trace.list") {
            out.push(Query { key: "trace", command: "ip.firewall.trace.list", params: json!({}) });
        }
        if showing(app, View::Diff) && app.has_command("ip.firewall.preview") {
            out.push(Query { key: "preview", command: "ip.firewall.preview", params: json!({}) });
            out.push(Query { key: "pending", command: "config.diff", params: json!({}) });
        }
        out
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        match key {
            "trace" => self.trace_list = value,
            "preview" => self.preview = value,
            "pending" => self.pending = value,
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, win: &'static str, ui: &mut Ui) {
        match win {
            "fw-diff" => self.diff_tab(app, ui),
            _ => self.test_tab(app, ui),
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, _area: egui::Rect) {
        help::modal(ctx, app.lang, &mut self.help);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        match then.downcast::<Reply>().map(|b| *b) {
            Ok(Reply::Test) => match result {
                Ok(v) => {
                    self.result = Some(v.clone());
                    self.error = None;
                }
                Err(e) => {
                    self.result = None;
                    self.error = Some(e.clone());
                }
            },
            Ok(Reply::Trace) => {
                self.trace_error = result.as_ref().err().cloned();
                app.cache.refreshed_at = None;
            }
            Err(_) => {}
        }
    }
}

impl CoreRouterUi {
    /// Draw the Test or Diff tab of the Firewall window.
    pub(crate) fn firewall_diag_tab(&mut self, ui: &mut Ui, view: View) {
        let win = match view {
            View::Test => "fw-test",
            View::Diff => "fw-diff",
        };
        self.with_panel(NAME, |p, app| p.window(app, win, ui));
    }
}
