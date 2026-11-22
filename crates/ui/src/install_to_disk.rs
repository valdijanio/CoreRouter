//! System › Install to disk (G1.6y): the live image from the ISO installs
//! itself, from this window and from the browser. One window: the disks, the
//! network test, the management port; the confirmation asks what the disk
//! calls for (the rule is the engine's, `system.install.*`; this only draws
//! what `system.install.print` says). After the reboot the window reconnects
//! and says what came up, or where to look.

use egui::{ProgressBar, RichText, TextEdit, Ui};
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind};
use crate::help::{self, HelpView};
use crate::i18n::tr_in;
use crate::panel::{self, Panel, PanelState, PanelThen, Query, WinDef};
use crate::{CoreRouterUi, Win};

/// A field of a JSON object, or null.
fn g<'a>(v: &'a Value, key: &str) -> &'a Value {
    v.get(key).unwrap_or(&Value::Null)
}

fn set(v: &mut Value, key: &str, value: Value) {
    if let Some(o) = v.as_object_mut() {
        o.insert(key.to_owned(), value);
    }
}

const SCOPE: &str = "install_to_disk";
pub(crate) const WIN: &str = "install_to_disk";
/// How long after the reboot the window keeps saying "coming back".
const COMEBACK_SECS: f64 = 180.0;

pub(crate) const PANEL: Panel = Panel {
    name: "install_to_disk",
    windows: &[WinDef {
        id: WIN,
        group: "System",
        title: "Install to disk",
        size: [640.0, 680.0],
        escape: false,
    }],
    new: || Box::new(InstallPanel::default()),
};

fn t(lang: crate::i18n::Lang, s: &'static str) -> &'static str {
    tr_in(SCOPE, lang, s)
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

fn human(bytes: u64) -> String {
    let g = bytes as f64 / 1_000_000_000.0;
    if g >= 1.0 { format!("{g:.0} GB") } else { format!("{} MB", bytes / 1_000_000) }
}

/// Replies of the commands this window sends.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Sent {
    Challenge,
    Password,
    Run,
    Reboot,
}

/// What came out of the install, for the screen after the reboot.
#[derive(Debug, Clone, PartialEq)]
struct After {
    version: String,
    port: Option<String>,
    address: Option<String>,
    /// `ctx` time of the reboot; `None`: asked, not yet answered.
    since: Option<f64>,
}

#[derive(Default)]
pub(crate) struct InstallPanel {
    status: Value,
    tested: bool,
    disk: Option<String>,
    port: Option<String>,
    fix_address: bool,
    password: String,
    again: String,
    /// The confirmation is open on `disk`.
    asking: bool,
    typed: String,
    code: String,
    keep: bool,
    error: Option<String>,
    help: Option<HelpView>,
    after: Option<After>,
}

impl InstallPanel {
    fn info(&mut self, ui: &mut Ui, key: &'static str, title: &str) {
        if help::info_button(ui, egui::Id::unique(("install-help", key)), title).clicked() {
            self.help = Some(HelpView::new(key, title));
        }
    }

    fn disk_row(&self) -> Option<&Value> {
        let name = self.disk.as_deref()?;
        g(&self.status, "disks").as_array()?.iter().find(|d| s(d, "name") == name)
    }

    fn connected(&self) -> Option<String> {
        g(g(&self.status, "network"), "connected_port").as_str().map(str::to_owned)
    }

    /// The port chosen, or the one this GUI comes through.
    fn chosen_port(&self) -> Option<String> {
        self.port.clone().or_else(|| self.connected())
    }

    fn port_row(&self, name: &str) -> Option<&Value> {
        g(g(&self.status, "network"), "ports").as_array()?.iter().find(|p| s(p, "name") == name)
    }

    /// The parameters of `run`; the engine checks them.
    fn run_params(&self, d: &Value) -> Value {
        let mut p = json!({
            "disk": s(d, "name"),
            "serial": s(d, "serial"),
            "size": g(d, "bytes"),
            "typed_name": self.typed,
        });
        if !self.code.trim().is_empty() {
            set(&mut p, "code", json!(self.code.trim()));
        }
        if self.keep {
            set(&mut p, "keep_config", json!(true));
            return p;
        }
        if let Some(port) = self.chosen_port() {
            let row = self.port_row(&port).cloned().unwrap_or(Value::Null);
            let address = s(&row, "address");
            if self.fix_address && !address.is_empty() {
                set(&mut p, "mgmt_port", json!(port));
                set(&mut p, "mgmt_mode", json!("static"));
                set(&mut p, "mgmt_address", json!(address));
                if !s(&row, "gateway").is_empty() {
                    set(&mut p, "mgmt_gateway", g(&row, "gateway").clone());
                }
                if g(&row, "dns").as_array().is_some_and(|d| !d.is_empty()) {
                    set(&mut p, "mgmt_dns", g(&row, "dns").clone());
                }
            } else {
                set(&mut p, "mgmt_port", json!(port));
                set(&mut p, "mgmt_mode", json!("dhcp"));
            }
        }
        p
    }

    fn send_run(&mut self, app: &mut CoreRouterUi) {
        let Some(d) = self.disk_row().cloned() else {
            return;
        };
        self.error = None;
        // A password first: the install carries what the router has.
        if !self.password.is_empty()
            && let Some(user) = app.no_password_user()
        {
            let params = json!({"name": user, "password": self.password});
            app.run_then("user.set", params, panel::then(PANEL.name, Sent::Password));
            return;
        }
        app.run_then("system.install.run", self.run_params(&d), panel::then(PANEL.name, Sent::Run));
    }

    fn open_confirmation(&mut self, app: &mut CoreRouterUi) {
        let Some(d) = self.disk_row().cloned() else {
            return;
        };
        self.asking = true;
        self.typed.clear();
        self.code.clear();
        self.keep = false;
        self.error = None;
        if s(&d, "holds") != "empty" {
            let params = json!({"disk": s(&d, "name"), "serial": s(&d, "serial")});
            app.run_then("system.install.challenge", params, panel::then(PANEL.name, Sent::Challenge));
        }
    }

    fn draw(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let lang = app.lang.labels;
        ui.horizontal(|ui| {
            ui.heading(t(lang, "Install to disk"));
            self.info(ui, "install_to_disk.overview", t(lang, "Install to disk"));
            if s(&app.cache.info, "boot") == "live" {
                chip::chip(ui, t(lang, "live: not installed"), Kind::Amber.tone(ui.visuals()));
            }
        });
        if self.after.is_some() {
            self.draw_after(app, ui);
            return;
        }
        if g(&self.status, "supported") != true {
            let reason = s(&self.status, "reason");
            ui.label(if reason.is_empty() { t(lang, "Waiting for the router…") } else { reason });
            return;
        }
        let m = g(&self.status, "medium").clone();
        if m.is_null() {
            ui.colored_label(ui.visuals().warn_fg_color, t(lang, "Looking for the installation medium…"));
            ui.weak(t(lang, "Keep it in the machine until the install ends: the image is read from it."));
            return;
        }
        ui.horizontal(|ui| {
            ui.label(format!("{} {}", t(lang, "Image"), s(&m, "version")));
            chip::chip(ui, t(lang, "signed"), Kind::Green.tone(ui.visuals()))
                .on_hover_text(format!("{} {}", t(lang, "Key"), s(&m, "signed_by")));
            ui.weak(t(lang, "Config in RAM until installed"));
        });
        ui.separator();
        self.draw_disks(app, ui);
        ui.separator();
        self.draw_network(app, ui);
        ui.separator();
        self.draw_mgmt(app, ui);
        ui.separator();
        self.draw_action(app, ui);
    }

    fn draw_disks(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let lang = app.lang.labels;
        ui.horizontal(|ui| {
            ui.strong(t(lang, "Disks"));
            self.info(ui, "install_to_disk.disks", t(lang, "Disks"));
            if ui.small_button(t(lang, "Rescan")).clicked() {
                app.run("system.install.rescan", json!({}));
            }
        });
        let disks = g(&self.status, "disks").as_array().cloned().unwrap_or_default();
        if disks.is_empty() {
            ui.colored_label(ui.visuals().warn_fg_color, t(lang, "No disk found"));
            return;
        }
        egui::Grid::new("install-disks").striped(true).num_columns(5).show(ui, |ui| {
            for (h, key) in [
                ("Name", "install_to_disk.col_name"),
                ("Size", "install_to_disk.col_size"),
                ("Model", "install_to_disk.col_model"),
                ("Bus", "install_to_disk.col_bus"),
                ("Holds", "install_to_disk.col_holds"),
            ] {
                ui.horizontal(|ui| {
                    ui.strong(t(lang, h));
                    self.info(ui, key, t(lang, h));
                });
            }
            ui.end_row();
            for d in &disks {
                let name = s(d, "name");
                let refused = s(d, "refused");
                let on = self.disk.as_deref() == Some(name);
                let row = ui.add_enabled(refused.is_empty(), egui::Button::selectable(on, name));
                if row.clicked() {
                    self.disk = Some(name.to_owned());
                }
                ui.label(human(g(d, "bytes").as_u64().unwrap_or(0)));
                ui.label(s(d, "model"));
                ui.label(s(d, "bus"));
                ui.horizontal(|ui| {
                    if refused.is_empty() {
                        let (label, kind) = match s(d, "holds") {
                            "empty" => (t(lang, "empty"), Kind::Green),
                            "corerouter" => (t(lang, "CoreRouter"), Kind::Blue),
                            _ => (t(lang, "data"), Kind::Amber),
                        };
                        chip::chip(ui, label, kind.tone(ui.visuals())).on_hover_text(s(d, "detail"));
                    } else {
                        chip::chip(ui, t(lang, "not offered"), Kind::Neutral.tone(ui.visuals()))
                            .on_hover_text(refused);
                    }
                });
                ui.end_row();
            }
        });
    }

    fn draw_network(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let lang = app.lang.labels;
        if !self.tested {
            self.tested = true;
            app.run("system.install.test", json!({}));
        }
        let testing = g(&self.status, "testing") == true;
        ui.horizontal(|ui| {
            ui.strong(t(lang, "Network test"));
            self.info(ui, "install_to_disk.network", t(lang, "Network test"));
            if ui.add_enabled(!testing, egui::Button::new(t(lang, "Run again")).small()).clicked() {
                app.run("system.install.test", json!({}));
            }
            if testing {
                ui.spinner();
            }
        });
        let net = g(&self.status, "network").clone();
        let ports = g(&net, "ports").as_array().cloned().unwrap_or_default();
        if ports.is_empty() && !testing {
            ui.colored_label(ui.visuals().warn_fg_color, t(lang, "No port found: its driver may be missing here"));
        }
        let line = |ui: &mut Ui, ok: Option<bool>, text: String| {
            ui.horizontal(|ui| {
                let (label, kind) = match ok {
                    Some(true) => (t(lang, "ok"), Kind::Green),
                    Some(false) => (t(lang, "warn"), Kind::Amber),
                    None => (t(lang, "info"), Kind::Neutral),
                };
                chip::chip(ui, label, kind.tone(ui.visuals()));
                ui.label(text);
            });
        };
        for p in &ports {
            let name = s(p, "name");
            let link = g(p, "link") == true;
            let speed = g(p, "speed_mbps").as_u64().map_or_else(String::new, |v| format!(" {v} Mbps"));
            let what = if link { format!("{}{speed}", t(lang, "link")) } else { t(lang, "no link").to_owned() };
            line(ui, link.then_some(true), format!("{name}: {} {} · {what}", t(lang, "driver"), s(p, "driver")));
            if !link {
                continue;
            }
            for f in g(p, "firmware").as_array().into_iter().flatten().filter_map(Value::as_str) {
                line(ui, Some(false), format!("{name}: {}: {f}", t(lang, "not on the live image, works in full once installed")));
            }
            let address = s(p, "address");
            if !address.is_empty() {
                line(ui, Some(true), format!("{name}: {address}"));
            } else {
                line(ui, Some(false), format!("{name}: {}", t(lang, "no address yet")));
            }
            if !s(p, "gateway").is_empty() {
                line(ui, g(p, "gateway_ok").as_bool(), format!("{} {}", t(lang, "Gateway"), s(p, "gateway")));
            }
            if g(p, "dns").as_array().is_some_and(|d| !d.is_empty()) {
                line(ui, g(p, "dns_ok").as_bool(), t(lang, "DNS answers").to_owned());
            }
        }
        if let Some(port) = self.connected() {
            ui.horizontal(|ui| {
                chip::chip(ui, t(lang, "you"), Kind::Blue.tone(ui.visuals()));
                ui.label(format!("{} {port}", t(lang, "This GUI comes in through")));
            });
        }
    }

    fn draw_mgmt(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let lang = app.lang.labels;
        ui.horizontal(|ui| {
            ui.strong(t(lang, "Management after install"));
            self.info(ui, "install_to_disk.mgmt", t(lang, "Management after install"));
        });
        let ports: Vec<String> = g(g(&self.status, "network"), "ports")
            .as_array()
            .into_iter()
            .flatten()
            .map(|p| s(p, "name").to_owned())
            .collect();
        let chosen = self.chosen_port();
        ui.horizontal(|ui| {
            ui.label(t(lang, "Port"));
            egui::ComboBox::from_id_salt("install-port")
                .selected_text(chosen.clone().unwrap_or_else(|| t(lang, "none: set on the console").to_owned()))
                .show_ui(ui, |ui| {
                    for p in &ports {
                        if ui.selectable_label(chosen.as_deref() == Some(p), p).clicked() {
                            self.port = Some(p.clone());
                        }
                    }
                });
            if chosen.is_some() && chosen == self.connected() {
                chip::chip(ui, t(lang, "suggested"), Kind::Blue.tone(ui.visuals()));
            }
        });
        let address = chosen
            .as_deref()
            .and_then(|p| self.port_row(p))
            .map(|r| s(r, "address").to_owned())
            .unwrap_or_default();
        ui.horizontal(|ui| {
            ui.radio_value(&mut self.fix_address, false, t(lang, "Keep DHCP"));
            ui.weak(t(lang, "the address may change"));
        });
        ui.add_enabled_ui(!address.is_empty(), |ui| {
            ui.radio_value(&mut self.fix_address, true, format!("{} {address}", t(lang, "Fix current address")));
        });
        if address.is_empty() {
            self.fix_address = false;
        }
        if app.no_password_user().is_some() {
            ui.horizontal(|ui| {
                ui.label(t(lang, "Admin password"));
                self.info(ui, "install_to_disk.password", t(lang, "Admin password"));
                ui.add(TextEdit::singleline(&mut self.password).password(true).desired_width(140.0));
                ui.label(t(lang, "again"));
                ui.add(TextEdit::singleline(&mut self.again).password(true).desired_width(140.0));
            });
        }
    }

    fn draw_action(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let lang = app.lang.labels;
        let job = g(&self.status, "job").clone();
        let result = g(&self.status, "result").clone();
        if !job.is_null() {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(format!("{} {}: {}", t(lang, "Installing on"), s(&job, "disk"), s(&job, "phase")));
            });
            let total = g(&job, "total").as_u64().unwrap_or(0).max(1);
            ui.add(ProgressBar::new(g(&job, "done").as_u64().unwrap_or(0) as f32 / total as f32).show_percentage());
            return;
        }
        if g(&result, "ok") == true {
            chip::chip(ui, t(lang, "written and read back"), Kind::Green.tone(ui.visuals()));
            if let Some(e) = g(&result, "boot_entry_error").as_str() {
                ui.colored_label(ui.visuals().warn_fg_color, format!("{}: {e}", t(lang, "No boot entry; remove the medium before rebooting")));
            }
            if let Some(e) = g(&result, "first_boot_error").as_str() {
                ui.colored_label(ui.visuals().warn_fg_color, format!("{}: {e}", t(lang, "Set the management address on the console after the reboot")));
            }
            if ui.button(t(lang, "Reboot")).clicked() {
                let port = g(&result, "mgmt_port").as_str().map(str::to_owned);
                let address = port.as_deref().and_then(|p| self.port_row(p)).map(|r| s(r, "address").to_owned());
                self.after = Some(After {
                    version: s(&result, "version").to_owned(),
                    port,
                    address,
                    since: None,
                });
                app.run_then("system.reboot", json!({"confirm": true}), panel::then(PANEL.name, Sent::Reboot));
            }
            return;
        }
        if let Some(e) = g(&result, "error").as_str() {
            ui.colored_label(ui.visuals().error_fg_color, format!("{}: {e}", t(lang, "Not installed")));
        }
        let problems = g(g(&self.status, "network"), "problems").as_array().map_or(0, Vec::len);
        for p in g(g(&self.status, "network"), "problems").as_array().into_iter().flatten().filter_map(Value::as_str) {
            ui.colored_label(ui.visuals().warn_fg_color, p);
        }
        let mismatch = self.password != self.again;
        if mismatch {
            ui.colored_label(ui.visuals().warn_fg_color, t(lang, "The two passwords differ"));
        }
        let label = if problems == 0 { t(lang, "Install…") } else { t(lang, "Install anyway…") };
        let ready = self.disk_row().is_some() && !mismatch;
        let button = ui.add_enabled(ready, egui::Button::new(label));
        let button = if self.disk_row().is_none() {
            button.on_disabled_hover_text(t(lang, "Choose a disk first"))
        } else {
            button
        };
        if button.clicked() {
            self.open_confirmation(app);
        }
    }

    fn draw_after(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let lang = app.lang.labels;
        let Some(a) = self.after.clone() else { return };
        // The app asks `server.info` again on every reconnect.
        let info = app.cache.info.clone();
        let up = s(&info, "boot") == "installed";
        if up {
            chip::chip(ui, t(lang, "installed"), Kind::Green.tone(ui.visuals()));
            let version = s(&info, "version");
            let mut text = format!("{} {}", t(lang, "Version"), if version.is_empty() { &a.version } else { version });
            if let Some(p) = &a.port {
                text.push_str(&format!(", {} {p}", t(lang, "reachable through")));
            }
            if let Some(ip) = a.address.as_deref().filter(|ip| !ip.is_empty()) {
                text.push_str(&format!(" ({ip})"));
            }
            ui.label(text);
            return;
        }
        let waited = a.since.map_or(0.0, |since| ui.input(|i| i.time) - since);
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(format!("{} {:.0} s", t(lang, "Rebooting into the disk…"), waited));
        });
        if waited > COMEBACK_SECS {
            ui.colored_label(
                ui.visuals().warn_fg_color,
                t(lang, "It did not come back. Look at the console: it shows the address and the port. With DHCP the address may have changed."),
            );
        }
        ui.ctx().request_repaint_after(std::time::Duration::from_secs(1));
    }
}

impl PanelState for InstallPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.open.contains(&Win::Panel(WIN)) {
            return Vec::new();
        }
        if self.after.is_some() {
            return Vec::new();
        }
        vec![Query { key: "print", command: "system.install.print", params: json!({}) }]
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _id: RequestId, value: Value) {
        if key == "print" {
            self.status = value;
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        if let Some(a) = &mut self.after
            && a.since.is_none()
        {
            a.since = Some(ui.input(|i| i.time));
        }
        egui::ScrollArea::vertical().id_salt("install-to-disk").show(ui, |ui| self.draw(app, ui));
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, _area: egui::Rect) {
        help::modal(ctx, app.lang, &mut self.help);
        if !self.asking {
            return;
        }
        let Some(d) = self.disk_row().cloned() else {
            self.asking = false;
            return;
        };
        let lang = app.lang.labels;
        let name = s(&d, "name").to_owned();
        let holds = s(&d, "holds").to_owned();
        let challenge = g(&self.status, "challenge").clone();
        let mine = s(&challenge, "disk") == name;
        let presence = mine && g(&challenge, "presence") == true;
        let mut cancel = false;
        let mut go = false;
        egui::Modal::new(egui::Id::unique("install-confirm")).show(ctx, |ui| {
            ui.set_max_width(460.0);
            let (title, button) = match holds.as_str() {
                "empty" => (t(lang, "Disk is empty"), t(lang, "Install")),
                "corerouter" => (t(lang, "CoreRouter installed"), t(lang, "Reinstall")),
                _ => (t(lang, "Disk has data"), t(lang, "Erase and install")),
            };
            ui.horizontal(|ui| {
                ui.heading(title);
                self.info(ui, "install_to_disk.confirm", title);
            });
            let size = human(g(&d, "bytes").as_u64().unwrap_or(0));
            ui.label(match s(&d, "model") {
                "" => format!("{name} · {size}"),
                model => format!("{name} · {size} · {model}"),
            });
            ui.weak(format!("{} {} · {}", t(lang, "Serial"), s(&d, "serial"), s(&d, "detail")));
            if holds == "corerouter" && g(&d, "config_keepable") == true {
                ui.horizontal(|ui| {
                    ui.checkbox(&mut self.keep, t(lang, "Keep configuration"));
                    self.info(ui, "install_to_disk.keep", t(lang, "Keep configuration"));
                });
                if self.keep {
                    ui.weak(t(lang, "Port names and management follow that configuration."));
                }
            }
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(t(lang, "Type disk name"));
                ui.add(TextEdit::singleline(&mut self.typed).desired_width(140.0));
            });
            let mut code_ok = true;
            if holds != "empty" {
                if presence {
                    chip::chip(ui, t(lang, "power button: confirmed"), Kind::Green.tone(ui.visuals()));
                } else {
                    ui.horizontal(|ui| {
                        ui.label(t(lang, "Code on the console"));
                        ui.add(TextEdit::singleline(&mut self.code).desired_width(100.0));
                        self.info(ui, "install_to_disk.code", t(lang, "Code on the console"));
                    });
                    if mine {
                        let left = g(&challenge, "remaining_s").as_u64().unwrap_or(0);
                        ui.weak(format!(
                            "{} {}:{:02}. {} {}. {}",
                            t(lang, "Expires in"),
                            left / 60,
                            left % 60,
                            t(lang, "Tries left:"),
                            g(&challenge, "attempts_left").as_u64().unwrap_or(0),
                            t(lang, "No screen? Press the power button 3 times."),
                        ));
                    } else if ui.small_button(t(lang, "Ask for a new code")).clicked() {
                        let params = json!({"disk": name, "serial": s(&d, "serial")});
                        app.run_then("system.install.challenge", params, panel::then(PANEL.name, Sent::Challenge));
                    }
                    code_ok = mine && !self.code.trim().is_empty();
                }
            }
            if let Some(e) = &self.error {
                ui.colored_label(ui.visuals().error_fg_color, e);
            }
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.button(t(lang, "Cancel")).clicked() {
                    cancel = true;
                }
                if ui.add_enabled(self.typed == name && code_ok, egui::Button::new(button)).clicked() {
                    go = true;
                }
            });
        });
        if cancel {
            self.asking = false;
            self.error = None;
            if holds != "empty" {
                app.run("system.install.cancel", json!({}));
            }
        }
        if go {
            self.send_run(app);
        }
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        let Ok(sent) = then.downcast::<Sent>() else {
            return;
        };
        match (*sent, result) {
            (Sent::Password, Ok(_)) => {
                self.password.clear();
                self.again.clear();
                self.send_run(app);
            }
            (Sent::Run, Ok(_)) => {
                self.asking = false;
                self.error = None;
            }
            // The connection dropping is the reboot working.
            (Sent::Reboot, _) | (Sent::Challenge, Ok(_)) => {}
            (Sent::Password | Sent::Run | Sent::Challenge, Err(e)) => {
                self.error = Some(e.chars().take(300).collect());
            }
        }
    }
}

#[cfg(test)]
impl InstallPanel {
    /// What the buttons of the confirmation do, with the fields as typed.
    pub(crate) fn confirm_for_test(&mut self, app: &mut CoreRouterUi, typed: &str, code: &str) {
        self.typed = typed.to_owned();
        self.code = code.to_owned();
        self.send_run(app);
    }
}

impl CoreRouterUi {
    /// The top bar while this router runs from the ISO: the chip, the button,
    /// and the window once by itself.
    pub(crate) fn live_warning(&mut self, ui: &mut Ui) {
        if s(&self.cache.info, "boot") != "live" {
            return;
        }
        let l = self.lang.labels;
        chip::chip(ui, t(l, "live: not installed"), Kind::Amber.tone(ui.visuals()))
            .on_hover_text(t(l, "This router runs from the installation medium, in RAM. Nothing survives a reboot."));
        if ui.small_button(RichText::new(t(l, "Install to disk…"))).clicked() {
            self.open(Win::Panel(WIN));
        }
        let shown = egui::Id::unique("install-to-disk-shown");
        if !ui.ctx().data(|d| d.get_temp::<bool>(shown).unwrap_or(false)) {
            ui.ctx().data_mut(|d| d.insert_temp(shown, true));
            self.open(Win::Panel(WIN));
        }
        ui.separator();
    }
}
