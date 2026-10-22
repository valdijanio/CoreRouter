//! L5 — WinBox-style UI in egui.
//!
//! Thin by rule: panels only *read* engine state (through query commands) and
//! *act* through [`CoreRouterUi::run`], which calls `Session::execute`. No
//! business logic lives here. This crate depends on `egui` only — the window
//! (eframe/winit/wgpu) belongs to `apps/corerouter-gui`.

mod windows;

use std::collections::BTreeSet;
use std::time::Duration;

use corerouter_engine::{Shared, lock};
use egui::{Color32, RichText};
use serde_json::{Value, json};

pub use windows::Win;

/// Seconds between automatic refreshes of the live tables.
const REFRESH_SECS: f64 = 1.0;
const MAX_LOG: usize = 500;

#[derive(Debug, Clone)]
pub struct LogLine {
    pub ok: bool,
    pub command: String,
    pub message: String,
}

/// Cached query results, refreshed every `REFRESH_SECS` or after an action.
#[derive(Default)]
struct Cache {
    summary: Value,
    interfaces: Vec<Value>,
    addresses: Vec<Value>,
    bgp: Vec<Value>,
    history: Vec<Value>,
    diff: Vec<Value>,
    refreshed_at: Option<f64>,
}

/// Text fields of the forms (UI-local state only).
#[derive(Default)]
struct Forms {
    addr_address: String,
    addr_interface: String,
    addr_comment: String,
    vlan_name: String,
    vlan_parent: String,
    vlan_id: String,
    vlan_mtu: String,
    bridge_name: String,
    loopback_name: String,
    port_bridge: String,
    port_interface: String,
    bgp_name: String,
    bgp_asn: String,
    bgp_router_id: String,
    bgp_frr: String,
    identity: String,
}

pub struct CoreRouterUi {
    session: Shared,
    open: BTreeSet<Win>,
    log: Vec<LogLine>,
    cache: Cache,
    forms: Forms,
}

impl CoreRouterUi {
    pub fn new(session: Shared) -> Self {
        let mut open = BTreeSet::new();
        open.insert(Win::Interfaces);
        Self {
            session,
            open,
            log: Vec::new(),
            cache: Cache::default(),
            forms: Forms {
                bgp_name: "default".into(),
                ..Forms::default()
            },
        }
    }

    pub fn open(&mut self, win: Win) {
        self.open.insert(win);
    }

    pub fn open_all(&mut self) {
        self.open.extend(Win::ALL.iter().copied());
    }

    pub fn log(&self) -> &[LogLine] {
        &self.log
    }

    /// The only way the UI changes anything: run a command, log the outcome,
    /// refresh the tables. Returns the result on success.
    pub fn run(&mut self, id: &str, params: Value) -> Option<Value> {
        let result = lock(&self.session).execute(id, &params);
        let line = match &result {
            Ok(v) => LogLine {
                ok: true,
                command: id.to_owned(),
                message: v.to_string(),
            },
            Err(e) => LogLine {
                ok: false,
                command: id.to_owned(),
                message: e.to_string(),
            },
        };
        self.log.push(line);
        if self.log.len() > MAX_LOG {
            self.log.remove(0);
        }
        self.cache.refreshed_at = None;
        result.ok()
    }

    /// Read-only command; errors are shown in place by the caller.
    fn query(&self, id: &str, params: Value) -> Value {
        lock(&self.session)
            .execute(id, &params)
            .unwrap_or(Value::Null)
    }

    fn refresh(&mut self, now: f64) {
        if self
            .cache
            .refreshed_at
            .is_some_and(|t| now - t < REFRESH_SECS)
        {
            return;
        }
        let arr = |v: Value| match v {
            Value::Array(a) => a,
            _ => Vec::new(),
        };
        self.cache.summary = lock(&self.session).inspect(None).unwrap_or(Value::Null);
        self.cache.interfaces = arr(self.query("interface.list", Value::Null));
        self.cache.addresses = arr(self.query("ip.address.list", Value::Null));
        self.cache.bgp = arr(self.query("routing.bgp.instance.list", Value::Null));
        self.cache.history = arr(self.query("config.history", Value::Null));
        self.cache.diff = arr(self.query("config.diff", Value::Null));
        self.cache.refreshed_at = Some(now);
    }

    /// Draw one frame into the root `Ui`.
    pub fn ui(&mut self, ui: &mut egui::Ui) {
        let now = ui.input(|i| i.time);
        self.refresh(now);
        ui.ctx()
            .request_repaint_after(Duration::from_secs_f64(REFRESH_SECS));

        egui::Panel::top("top-bar").show(ui, |ui| self.top_bar(ui));
        egui::Panel::bottom("status-bar").show(ui, |ui| self.status_bar(ui));
        egui::Panel::left("menu")
            .resizable(false)
            .exact_size(170.0)
            .show(ui, |ui| self.menu(ui));
        let area = egui::CentralPanel::default()
            .show(ui, |ui| {
                ui.centered_and_justified(|ui| {
                    ui.label(RichText::new("CoreRouter").size(32.0).weak());
                });
            })
            .response
            .rect;

        let ctx = ui.ctx().clone();
        for win in Win::ALL {
            if !self.open.contains(win) {
                continue;
            }
            let mut open = true;
            egui::Window::new(win.title())
                .id(egui::Id::unique(("corerouter-win", *win)))
                .open(&mut open)
                .constrain_to(area)
                .default_size(win.default_size())
                .show(&ctx, |ui| self.window(*win, ui));
            if !open {
                self.open.remove(win);
            }
        }
    }

    fn top_bar(&mut self, ui: &mut egui::Ui) {
        let s = &self.cache.summary;
        let txt = |k: &str| s.get(k).map(value_text).unwrap_or_default();
        let (identity, backend, mode, revision) = (
            txt("identity"),
            txt("backend"),
            txt("mode"),
            txt("revision"),
        );
        let dirty = s.get("dirty").and_then(Value::as_bool).unwrap_or(false);
        let pending = s
            .get("pending_changes")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        ui.horizontal(|ui| {
            ui.strong(identity);
            ui.separator();
            ui.label(format!("backend: {backend}"));
            ui.separator();
            ui.label(format!("mode: {mode}"));
            ui.separator();
            ui.label(format!("revision {revision}"));
            if dirty {
                ui.separator();
                ui.colored_label(
                    ui.visuals().warn_fg_color,
                    format!("{pending} pending change(s)"),
                );
                if ui.button("Commit").clicked() {
                    self.run("config.commit", json!({"comment": "from GUI"}));
                }
                if ui.button("Discard").clicked() {
                    self.run("config.discard", Value::Null);
                }
            }
        });
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| match self.log.last() {
            Some(l) => {
                let color = if l.ok {
                    ui.visuals().text_color()
                } else {
                    ui.visuals().error_fg_color
                };
                ui.colored_label(color, format!("{}: {}", l.command, l.message));
            }
            None => {
                ui.weak("ready");
            }
        });
    }

    fn menu(&mut self, ui: &mut egui::Ui) {
        ui.add_space(4.0);
        egui::ScrollArea::vertical().show(ui, |ui| {
            for (group, items) in windows::MENU {
                match items {
                    [only] if only.title() == *group => self.menu_item(ui, *only),
                    _ => {
                        ui.collapsing(*group, |ui| {
                            for w in *items {
                                self.menu_item(ui, *w);
                            }
                        });
                    }
                }
            }
        });
    }

    fn menu_item(&mut self, ui: &mut egui::Ui, win: Win) {
        let label = if win.gap().is_some() {
            RichText::new(win.title()).weak()
        } else {
            RichText::new(win.title())
        };
        if ui
            .selectable_label(self.open.contains(&win), label)
            .clicked()
        {
            self.open.insert(win);
        }
    }
}

/// Form text → JSON: integers as numbers, blank as absent, anything else as
/// typed (the engine reports what is wrong with it).
fn form_number(s: &str) -> Value {
    let s = s.trim();
    match s.parse::<u64>() {
        Ok(n) => json!(n),
        Err(_) if s.is_empty() => Value::Null,
        Err(_) => json!(s),
    }
}

fn value_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

/// 1536 → "1.5 KiB".
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = n as f64;
    let mut unit = "B";
    for u in UNITS {
        unit = u;
        if v < 1024.0 {
            break;
        }
        v /= 1024.0;
    }
    if unit == "B" {
        format!("{n} B")
    } else {
        format!("{v:.1} {unit}")
    }
}

fn err_color(ui: &egui::Ui) -> Color32 {
    ui.visuals().error_fg_color
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_engine::{Session, shared};

    #[test]
    fn every_window_renders_headless() {
        let mut app = CoreRouterUi::new(shared(Session::virtual_lab()));
        app.open_all();
        let ctx = egui::Context::default();
        for _ in 0..3 {
            ctx.run_ui(egui::RawInput::default(), |ui| app.ui(ui))
                .drop_without_applying_deltas();
        }
        assert_eq!(app.open.len(), Win::ALL.len());
    }

    #[test]
    fn run_logs_errors() {
        let mut app = CoreRouterUi::new(shared(Session::virtual_lab()));
        assert!(app.run("ip.address.add", json!({"address": "x"})).is_none());
        assert!(!app.log()[0].ok);
        assert!(
            app.run("system.identity.set", json!({"name": "r1"}))
                .is_some()
        );
    }

    #[test]
    fn interface_forms_go_through_commands() {
        let session = shared(Session::virtual_lab());
        let mut app = CoreRouterUi::new(session.clone());
        app.forms.vlan_name = "vlan100".into();
        app.forms.vlan_parent = "ether1".into();
        app.forms.vlan_id = " 100 ".into();
        app.add_vlan();
        app.forms.bridge_name = "bridge1".into();
        app.add_bridge();
        app.forms.port_bridge = "bridge1".into();
        app.forms.port_interface = "ether2".into();
        app.add_port();
        assert!(app.log().iter().all(|l| l.ok), "{:?}", app.log());
        assert!(app.forms.vlan_name.is_empty(), "form cleared on success");

        app.forms.vlan_name = "v2".into();
        app.forms.vlan_parent = "ether1".into();
        app.forms.vlan_id = "abc".into();
        app.add_vlan();
        assert!(app.log().last().is_some_and(|l| !l.ok));
        assert_eq!(app.forms.vlan_name, "v2", "form kept on error");

        let running = lock(&session).store().running().clone();
        assert_eq!(running.interfaces.len(), 10);
        assert!(
            app.run("interface.remove", json!({"name": "vlan100"}))
                .is_some()
        );
        assert_eq!(form_number(""), Value::Null);
        assert_eq!(form_number("7"), json!(7));
    }

    #[test]
    fn bytes_are_human() {
        assert_eq!(human_bytes(10), "10 B");
        assert_eq!(human_bytes(1536), "1.5 KiB");
    }
}
