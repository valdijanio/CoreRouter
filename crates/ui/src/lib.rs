//! L5 — WinBox-style UI in egui.
//!
//! Thin by rule: panels only *read* engine state (through query commands) and
//! *act* through [`CoreRouterUi::run`], which calls `Session::execute`. No
//! business logic lives here. This crate depends on `egui` only — the window
//! (eframe/winit/wgpu) belongs to `apps/corerouter-gui`.

mod interfaces;
mod table;
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
    bgp_name: String,
    bgp_asn: String,
    bgp_router_id: String,
    bgp_frr: String,
    identity: String,
}

/// Selection and find text of each list window (UI-local state only).
#[derive(Default)]
struct Tables {
    interfaces: table::TableState,
    addresses: table::TableState,
}

pub struct CoreRouterUi {
    session: Shared,
    open: BTreeSet<Win>,
    log: Vec<LogLine>,
    cache: Cache,
    forms: Forms,
    tables: Tables,
    /// Floating "New …" / "Interface <name>" / "Comment" windows.
    dialogs: Vec<interfaces::DialogWin>,
    next_dialog: u64,
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
            tables: Tables::default(),
            dialogs: Vec::new(),
            next_dialog: 0,
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
        self.reload();
        self.cache.refreshed_at = Some(now);
    }

    /// Re-read every table now (e.g. to open a window on what was just made).
    fn reload(&mut self) {
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
        self.dialogs(&ctx, area);
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

    /// Drives the real UI with synthetic pointer/keyboard events, the way
    /// an operator would, and finds widgets by the text they paint.
    struct Harness {
        ctx: egui::Context,
        app: CoreRouterUi,
        session: Shared,
        time: f64,
        shapes: Vec<egui::epaint::ClippedShape>,
    }

    const CTRL: egui::Modifiers = egui::Modifiers {
        alt: false,
        ctrl: true,
        shift: false,
        mac_cmd: false,
        command: true,
    };

    impl Harness {
        fn new() -> Self {
            let session = shared(Session::virtual_lab());
            let mut h = Self {
                ctx: egui::Context::default(),
                app: CoreRouterUi::new(session.clone()),
                session,
                time: 0.0,
                shapes: Vec::new(),
            };
            for _ in 0..3 {
                h.idle();
            }
            h
        }

        fn frame(&mut self, mut events: Vec<egui::Event>, modifiers: egui::Modifiers) {
            events.insert(0, egui::Event::ModifiersChanged(modifiers));
            let raw = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1400.0, 900.0),
                )),
                time: Some(self.time),
                events,
                ..Default::default()
            };
            self.time += 0.02;
            let app = &mut self.app;
            let mut out = self.ctx.run_ui(raw, |ui| app.ui(ui));
            out.textures_delta.clear();
            self.shapes = out.shapes;
        }

        fn idle(&mut self) {
            self.frame(Vec::new(), egui::Modifiers::NONE);
        }

        fn click_with(&mut self, pos: egui::Pos2, button: egui::PointerButton, m: egui::Modifiers) {
            self.frame(vec![egui::Event::PointerMoved(pos)], m);
            let ev = |pressed| egui::Event::PointerButton {
                pos,
                button,
                pressed,
                modifiers: m,
            };
            self.frame(vec![ev(true), ev(false)], m);
            self.idle();
            self.idle();
        }

        fn click(&mut self, pos: egui::Pos2) {
            self.click_with(pos, egui::PointerButton::Primary, egui::Modifiers::NONE);
        }

        fn right_click(&mut self, pos: egui::Pos2) {
            self.click_with(pos, egui::PointerButton::Secondary, egui::Modifiers::NONE);
        }

        fn hover(&mut self, pos: egui::Pos2) {
            self.frame(vec![egui::Event::PointerMoved(pos)], egui::Modifiers::NONE);
            self.idle();
            self.idle();
        }

        fn key(&mut self, key: egui::Key, modifiers: egui::Modifiers) {
            let ev = egui::Event::Key {
                key,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers,
            };
            self.frame(vec![ev], modifiers);
            self.idle();
        }

        fn type_text(&mut self, text: &str) {
            self.frame(vec![egui::Event::Text(text.into())], egui::Modifiers::NONE);
            self.idle();
        }

        /// Centre of a row of the Interfaces table.
        fn row(&self, name: &str) -> egui::Pos2 {
            self.ctx
                .read_response(table::row_id(interfaces::TABLE, name))
                .unwrap_or_else(|| panic!("row {name} not drawn"))
                .rect
                .center()
        }

        fn tool(&self, icon: table::Icon) -> egui::Pos2 {
            self.ctx
                .read_response(table::tool_id(interfaces::TABLE, icon))
                .map(|r| r.rect.center())
                .unwrap_or_else(|| panic!("no tool {icon:?}"))
        }

        /// Centre of the topmost text painted exactly as `needle`.
        fn find_text(&self, needle: &str) -> Option<egui::Pos2> {
            fn find(shape: &egui::Shape, needle: &str, out: &mut Option<egui::Pos2>) {
                match shape {
                    egui::Shape::Text(t) if t.galley.text() == needle => {
                        *out = Some(t.visual_bounding_rect().center());
                    }
                    egui::Shape::Vec(v) => v.iter().for_each(|s| find(s, needle, out)),
                    _ => {}
                }
            }
            let mut out = None;
            for s in &self.shapes {
                find(&s.shape, needle, &mut out);
            }
            out
        }

        fn text(&self, needle: &str) -> egui::Pos2 {
            self.find_text(needle)
                .unwrap_or_else(|| panic!("no text {needle:?} on screen"))
        }

        fn has_text(&self, needle: &str) -> bool {
            self.find_text(needle).is_some()
        }

        fn selected(&self) -> Vec<String> {
            let rows: Vec<table::Row> = self
                .app
                .cache
                .interfaces
                .iter()
                .map(|r| table::Row {
                    key: r.get("name").map(value_text).unwrap_or_default(),
                    cells: Vec::new(),
                    dimmed: false,
                })
                .collect();
            self.app.tables.interfaces.selection(&rows)
        }

        /// The interface as the engine has it (not the UI cache).
        fn iface(&self, name: &str) -> Option<Value> {
            let list = lock(&self.session).execute("interface.list", &Value::Null);
            list.ok()?
                .as_array()?
                .iter()
                .find(|i| i["name"] == name)
                .cloned()
        }

        fn log_ids(&self) -> Vec<&str> {
            self.app.log().iter().map(|l| l.command.as_str()).collect()
        }
    }

    #[test]
    fn rows_select_with_click_ctrl_shift_and_keys() {
        let mut h = Harness::new();
        h.click(h.row("ether2"));
        assert_eq!(h.selected(), ["ether2"]);
        h.click_with(h.row("ether4"), egui::PointerButton::Primary, CTRL);
        assert_eq!(h.selected(), ["ether2", "ether4"]);
        let shift = egui::Modifiers::SHIFT;
        h.click_with(h.row("ether6"), egui::PointerButton::Primary, shift);
        assert_eq!(
            h.selected(),
            ["ether4", "ether5", "ether6"],
            "range from anchor"
        );
        h.key(egui::Key::ArrowDown, egui::Modifiers::NONE);
        assert_eq!(h.selected(), ["ether7"]);

        // Empty space under the last row clears the selection …
        h.click(h.row("ether8") + egui::vec2(0.0, 60.0));
        assert!(h.selected().is_empty());
        // … and leaves the table focused for Ctrl+A.
        h.key(egui::Key::A, CTRL);
        assert_eq!(h.selected().len(), 8);

        // Delete runs interface.remove per row; the engine refuses physical
        // ports, so nothing changes and every refusal is logged.
        h.key(egui::Key::Delete, egui::Modifiers::NONE);
        let removes: Vec<_> = h
            .app
            .log()
            .iter()
            .filter(|l| l.command == "interface.remove")
            .collect();
        assert_eq!(removes.len(), 8);
        assert!(removes.iter().all(|l| !l.ok));
        assert!(h.iface("ether1").is_some());

        // Ctrl+D disables the selection, Ctrl+E enables it again.
        h.click(h.row("ether3"));
        h.key(egui::Key::D, CTRL);
        assert_eq!(h.iface("ether3").unwrap()["disabled"], true);
        h.key(egui::Key::E, CTRL);
        assert_eq!(h.iface("ether3").unwrap()["disabled"], false);
    }

    #[test]
    fn row_menu_adds_vlan_on_the_clicked_row() {
        let mut h = Harness::new();
        h.click(h.row("ether1"));
        // Right click on a row that is not selected makes it the selection.
        h.right_click(h.row("ether3"));
        assert_eq!(h.selected(), ["ether3"]);
        h.click(h.text("Add VLAN on ether3"));
        assert!(
            matches!(h.app.dialogs.as_slice(), [d] if matches!(&d.dialog,
                interfaces::Dialog::NewVlan { parent, .. } if parent == "ether3")),
            "dialog opened with the parent filled in"
        );
        h.click(h.text("vlan100"));
        h.type_text("vlan30");
        h.click(h.text("1..4094"));
        h.type_text("30");
        h.click(h.text("OK"));
        assert!(h.app.dialogs.is_empty(), "OK closes on success");
        assert_eq!(h.log_ids().last(), Some(&"interface.vlan.add"));
        let vlan = h.iface("vlan30").expect("vlan created");
        assert_eq!(
            (&vlan["parent"], &vlan["vlan_id"]),
            (&json!("ether3"), &json!(30))
        );

        // A failing OK keeps the dialog and shows the engine's error.
        h.right_click(h.row("ether3"));
        h.click(h.text("Add VLAN on ether3"));
        h.click(h.text("OK"));
        let d = h.app.dialogs.first().expect("still open");
        assert!(
            d.error.as_deref().is_some_and(|e| e.contains("required")),
            "{:?}",
            d.error
        );
    }

    #[test]
    fn double_click_opens_properties() {
        let mut h = Harness::new();
        let at = h.row("ether2");
        h.click(at);
        h.click(at);
        assert!(h.has_text("Interface <ether2>"));
        match h.app.dialogs.first_mut().map(|d| &mut d.dialog) {
            Some(interfaces::Dialog::Props(p)) => {
                p.comment = "uplink".into();
                p.mtu = "9000".into();
            }
            _ => panic!("properties window not open"),
        }
        h.click(h.text("Apply"));
        let e2 = h.iface("ether2").unwrap();
        assert_eq!(
            (&e2["comment"], &e2["mtu"]),
            (&json!("uplink"), &json!(9000))
        );
        assert_eq!(h.app.dialogs.len(), 1, "Apply keeps the window");

        h.click(h.text("Disable"));
        assert_eq!(h.iface("ether2").unwrap()["disabled"], true);
        // Remove on a physical port is refused and explained in place.
        h.click(h.text("Remove"));
        assert!(h.app.dialogs.first().is_some_and(|d| d.error.is_some()));
        h.click(h.text("OK"));
        assert!(h.app.dialogs.is_empty());
    }

    #[test]
    fn toolbar_and_empty_space_menu() {
        let mut h = Harness::new();
        let below = h.row("ether8") + egui::vec2(0.0, 60.0);
        h.right_click(below);
        h.click(h.text("Select All"));
        assert_eq!(h.selected().len(), 8);

        // "+" ▸ Bridge, then Apply turns "New Bridge" into its own window.
        h.click(h.tool(table::Icon::Add));
        h.click(h.text("Bridge"));
        h.click(h.text("bridge1"));
        h.type_text("br0");
        h.click(h.text("Apply"));
        assert!(h.iface("br0").is_some());
        assert!(h.has_text("Interface <br0>"));
        assert!(!h.has_text("New Bridge Interface"));

        // Row menu ▸ Add to Bridge ▸ br0.
        h.right_click(h.row("ether5"));
        h.hover(h.text("Add to Bridge"));
        h.click(h.text("br0"));
        assert_eq!(h.iface("ether5").unwrap()["bridge"], "br0");

        // Empty space ▸ Add ▸ Loopback.
        h.right_click(below);
        h.hover(h.text("Add"));
        h.click(h.text("Loopback"));
        assert!(h.has_text("New Loopback Interface"));
        h.click(h.text("Cancel"));
        assert!(!h.has_text("New Loopback Interface"));
        assert!(h.app.log().iter().all(|l| l.ok), "{:?}", h.app.log());
    }

    #[test]
    fn bytes_are_human() {
        assert_eq!(human_bytes(10), "10 B");
        assert_eq!(human_bytes(1536), "1.5 KiB");
    }
}
