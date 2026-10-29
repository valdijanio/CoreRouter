//! System › Packages (G1.6b): the A/B image. One row per slot (state,
//! version, kernel, channel, signature and dm-verity), the trial boot in
//! progress with its deadline, and the actions: Check a package, Install
//! and reboot, Downgrade, Scrub. RouterOS `/system package update` names,
//! with the trial boot and its confirmation on top.
//!
//! The engine and the daemon's `package` service decide everything; the
//! window shows `system.package.print` and sends commands (each slot
//! change asks first: it reboots the router).
//!
//! G1.6e: a package on this computer (a typed path or a file dropped on
//! the window) is sent in chunks (`system.package.upload.*`), read by the
//! app a piece at a time (`crate::export::read_at`), one chunk in flight;
//! the router writes it to the other slot as it arrives. The browser has
//! no reader yet: there the package has to be on the router.

use base64::Engine as _;
use egui::{Grid, RichText, Ui};
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::chip::{AMBER, BLUE, GREEN, RED, Tone, chip, neutral_tone};
use crate::help::{self, HelpView};
use crate::i18n::{self, Lang};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::action;
use crate::{CoreRouterUi, Win};

const NAME: &str = "packages";
pub(crate) const WIN: &str = "packages";
const PRINT: &str = "system.package.print";
const SCOPE: &str = "packages";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "System",
        title: "Packages",
        size: [940.0, 560.0],
        escape: true,
    }],
    new: || Box::new(PackagesPanel::new()),
};

/// What a slot-changing button asks before it is sent.
#[derive(Debug, Clone, PartialEq)]
enum Ask {
    Install,
    Downgrade,
    /// Send the local file and install it.
    Upload,
}

/// A package being sent from this computer.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Sending {
    pub(crate) path: String,
    pub(crate) size: u64,
    pub(crate) check: bool,
    /// The upload id, once `upload.start` answered.
    pub(crate) job: Option<u64>,
    pub(crate) chunk: usize,
    pub(crate) sent: u64,
    /// The chunk in flight or to send again (offset, bytes, base64).
    pending: Option<(u64, usize, String)>,
    inflight: bool,
}

/// Replies of the upload.
struct UpStart;
struct UpChunk;

pub(crate) struct PackagesPanel {
    pub(crate) status: Value,
    pub(crate) path: String,
    /// A package on this computer (G1.6e).
    pub(crate) local: String,
    pub(crate) sending: Option<Sending>,
    manual: bool,
    timeout: u32,
    ask: Option<Ask>,
    help: Option<HelpView>,
    notice: Option<String>,
    error: Option<String>,
}

/// A command's reply: what it was, for the message.
struct Sent(&'static str);

fn t(lang: Lang, en: &'static str) -> &'static str {
    i18n::tr_in(SCOPE, lang, en)
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

fn mib(v: &Value, k: &str) -> String {
    v.get(k)
        .and_then(Value::as_u64)
        .map(|b| format!("{:.1} MiB", b as f64 / 1_048_576.0))
        .unwrap_or_else(|| "–".into())
}

/// The state chip of a slot row.
pub(crate) fn state_chip(v: &egui::Visuals, state: &str) -> Tone {
    match state {
        "running" | "standby" => GREEN.tone(v),
        "trial" => AMBER.tone(v),
        "failed" | "invalid" => RED.tone(v),
        _ => neutral_tone(v),
    }
}

/// `4:32` from seconds.
pub(crate) fn mm_ss(secs: u64) -> String {
    format!("{}:{:02}", secs / 60, secs % 60)
}

impl PackagesPanel {
    fn new() -> Self {
        Self {
            status: Value::Null,
            path: String::new(),
            local: String::new(),
            sending: None,
            manual: false,
            timeout: 300,
            ask: None,
            help: None,
            notice: None,
            error: None,
        }
    }

    fn info(&mut self, ui: &mut Ui, key: &'static str, title: &str) {
        if help::info_button(ui, egui::Id::unique(("packages-help", key)), title).clicked() {
            self.help = Some(HelpView::new(key, title));
        }
    }

    /// G1.6e: an `http(s)://` address in Package file: the router
    /// downloads it (`system.package.download`).
    fn is_url(&self) -> bool {
        let p = self.path.trim();
        p.starts_with("https://") || p.starts_with("http://")
    }

    fn params(&self) -> Value {
        json!({
            "path": self.path.trim(),
            "confirm": if self.manual { "manual" } else { "auto" },
            "timeout": self.timeout,
        })
    }

    fn send(&mut self, app: &mut CoreRouterUi, id: &'static str, params: Value) {
        self.error = None;
        self.notice = None;
        app.run_then(id, params, crate::panel::then(NAME, Sent(id)));
        app.cache.refreshed_at = None;
    }

    fn summary(&mut self, ui: &mut Ui, lang: Lang) {
        let v = ui.visuals().clone();
        let st = self.status.clone();
        ui.horizontal(|ui| {
            if let Some(r) = st.get("running").and_then(Value::as_str) {
                chip(ui, &format!("{} {}", t(lang, "running"), r.to_uppercase()), GREEN.tone(&v));
            }
            if let Some(p) = st.get("primary").and_then(Value::as_str) {
                chip(ui, &format!("{} {}", t(lang, "default"), p.to_uppercase()), BLUE.tone(&v));
            }
            if st.get("fallback") == Some(&json!(true)) {
                chip(ui, t(lang, "fallback boot"), RED.tone(&v)).on_hover_text(t(
                    lang,
                    "The firmware did not boot the default slot and fell back to this one.",
                ));
            }
            if st.get("lab") == Some(&json!(true)) {
                chip(ui, "lab", neutral_tone(&v))
                    .on_hover_text(t(lang, "Virtual lab: slots are files, reboots are simulated."));
            }
            let keys = st.get("keys").and_then(Value::as_array).map_or(0, Vec::len);
            ui.weak(format!("{keys} {}", t(lang, "trusted keys")));
            self.info(ui, "packages.overview", "Packages");
        });
    }

    fn trial(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, lang: Lang) {
        let Some(tr) = self.status.get("trial").filter(|x| !x.is_null()).cloned() else {
            return;
        };
        let slot = s(&tr, "slot").to_uppercase();
        let from = s(&tr, "from").to_uppercase();
        let running_it = self.status.get("running") == tr.get("slot");
        let can = app.can();
        let mut send: Option<&'static str> = None;
        egui::Frame::group(ui.style())
            .fill(ui.visuals().warn_fg_color.gamma_multiply(0.12))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    let text = if running_it {
                        match tr.get("remaining_s").and_then(Value::as_u64) {
                            Some(left) => format!(
                                "{} {slot} ({}): {} {} {} {from} {}",
                                t(lang, "Trial boot of slot"),
                                s(&tr, "version"),
                                t(lang, "confirm within"),
                                mm_ss(left),
                                t(lang, "or slot"),
                                t(lang, "boots again"),
                            ),
                            None => format!("{} {slot} ({})", t(lang, "Trial boot of slot"), s(&tr, "version")),
                        }
                    } else {
                        format!(
                            "{} {slot} ({}) — {} {} s",
                            t(lang, "The next boot tries slot"),
                            s(&tr, "version"),
                            t(lang, "it must be confirmed within"),
                            tr.get("timeout_s").and_then(Value::as_u64).unwrap_or(0),
                        )
                    };
                    ui.strong(text);
                    let mode = s(&tr, "confirm");
                    chip(ui, mode, if mode == "manual" { AMBER.tone(ui.visuals()) } else { BLUE.tone(ui.visuals()) });
                    self.info(ui, "packages.trial", "Trial boot");
                    if running_it {
                        let ok = can.check("system.package.confirm");
                        if action(ui, t(lang, "Confirm"), ok) {
                            send = Some("system.package.confirm");
                        }
                    } else if action(ui, t(lang, "Cancel"), can.check("system.package.cancel")) {
                        send = Some("system.package.cancel");
                    }
                });
            });
        if let Some(id) = send {
            self.send(app, id, json!({}));
        }
    }

    fn slots(&mut self, ui: &mut Ui, lang: Lang) {
        let rows: Vec<Value> = self
            .status
            .get("slots")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let v = ui.visuals().clone();
        let mut asked: Option<(&'static str, &'static str)> = None;
        Grid::new("packages-slots")
            .striped(true)
            .spacing([14.0, 5.0])
            .show(ui, |ui| {
                for (h, key) in [
                    ("Slot", "packages.slot"),
                    ("State", "packages.state"),
                    ("Version", "packages.version"),
                    ("Kernel", "packages.kernel"),
                    ("Channel", "packages.channel"),
                    ("Verified", "packages.verified"),
                    ("Boot", "packages.boot"),
                    ("Size", ""),
                ] {
                    ui.horizontal(|ui| {
                        ui.strong(t(lang, h));
                        if !key.is_empty()
                            && help::info_button(ui, egui::Id::unique(("packages-col", key)), t(lang, h)).clicked()
                        {
                            asked = Some((key, h));
                        }
                    });
                }
                ui.end_row();
                for r in &rows {
                    let slot = s(r, "slot").to_uppercase();
                    ui.horizontal(|ui| {
                        chip(ui, &slot, BLUE.tone(&v)).on_hover_text(s(r, "partition"));
                        if r.get("running") == Some(&json!(true)) {
                            chip(ui, t(lang, "this boot"), neutral_tone(&v));
                        }
                    });
                    let state = s(r, "state");
                    let resp = chip(ui, state, state_chip(&v, state));
                    if let Some(d) = r.get("detail").and_then(Value::as_str) {
                        resp.on_hover_text(d);
                    }
                    let version = s(r, "version");
                    ui.label(if version.is_empty() { "–" } else { version })
                        .on_hover_text(format!("commit {} · build {}", s(r, "commit"), r.get("build").and_then(Value::as_u64).unwrap_or(0)));
                    let k = s(r, "kernel");
                    ui.label(if k.is_empty() { "–" } else { k });
                    let c = s(r, "channel");
                    if c.is_empty() {
                        ui.weak("–");
                    } else {
                        chip(ui, c, if c == "stable" || c == "long-term" { neutral_tone(&v) } else { AMBER.tone(&v) });
                    }
                    ui.horizontal(|ui| {
                        if r.get("verified") == Some(&json!(true)) {
                            chip(ui, t(lang, "signed"), GREEN.tone(&v)).on_hover_text(format!("key {}", s(r, "signed_by")));
                        } else if !version.is_empty() {
                            chip(ui, t(lang, "unsigned"), RED.tone(&v));
                        }
                        if r.get("verity") == Some(&json!(true)) {
                            chip(ui, "dm-verity", GREEN.tone(&v))
                                .on_hover_text(format!("root hash {}", s(r, "root_hash")));
                        } else if r.get("running") == Some(&json!(true)) {
                            chip(ui, t(lang, "no verity"), AMBER.tone(&v)).on_hover_text(t(
                                lang,
                                "Booted by the fallback path (built-in command line): the root is not checked.",
                            ));
                        }
                    });
                    ui.horizontal(|ui| {
                        if r.get("primary") == Some(&json!(true)) {
                            chip(ui, t(lang, "default"), BLUE.tone(&v));
                        }
                        if r.get("next") == Some(&json!(true)) {
                            chip(ui, t(lang, "next boot"), AMBER.tone(&v));
                        }
                        let e = s(r, "boot_entry");
                        if !e.is_empty() {
                            ui.weak(e).on_hover_text(s(r, "cmdline"));
                        }
                    });
                    ui.label(mib(r, "rootfs_size")).on_hover_text(format!("kernel {}", mib(r, "kernel_size")));
                    ui.end_row();
                }
            });
        if let Some((key, h)) = asked {
            self.help = Some(HelpView::new(key, t(lang, h)));
        }
    }

    fn job(&self, ui: &mut Ui, lang: Lang) {
        if let Some(j) = self.status.get("job").filter(|j| !j.is_null()) {
            let done = j.get("done").and_then(Value::as_u64).unwrap_or(0);
            let total = j.get("total").and_then(Value::as_u64).unwrap_or(0);
            let frac = if total > 0 { done as f32 / total as f32 } else { 0.0 };
            ui.horizontal(|ui| {
                ui.label(format!("{} · {}", s(j, "kind"), s(j, "phase")));
                ui.add(egui::ProgressBar::new(frac).desired_width(280.0).show_percentage());
            });
        }
        if let Some(r) = self.status.get("result").filter(|r| !r.is_null()) {
            ui.horizontal_wrapped(|ui| {
                ui.weak(format!("{} {}:", t(lang, "Last job"), s(r, "kind")));
                if r.get("ok") == Some(&json!(true)) {
                    let res = r.get("result").cloned().unwrap_or(Value::Null);
                    let mut parts = Vec::new();
                    for (k, label) in [("write_ms", "write"), ("verify_ms", "verify"), ("total_ms", "total")] {
                        if let Some(ms) = res.get(k).and_then(Value::as_u64) {
                            parts.push(format!("{label} {ms} ms"));
                        }
                    }
                    if let Some(sig) = res.get("signature").and_then(Value::as_str) {
                        parts.push(format!("{} {}: {sig}", s(&res, "version"), t(lang, "signature")));
                    }
                    ui.label(if parts.is_empty() { "ok".to_owned() } else { parts.join(" · ") });
                } else {
                    ui.colored_label(ui.visuals().error_fg_color, s(r, "error"));
                }
            });
        }
        if let Some(o) = self.status.get("last").filter(|o| !o.is_null()) {
            ui.horizontal_wrapped(|ui| {
                let res = s(o, "result");
                let tone = if res == "confirmed" { GREEN.tone(ui.visuals()) } else { RED.tone(ui.visuals()) };
                chip(ui, res, tone);
                ui.label(format!("{} {} ({}) — {}", t(lang, "slot"), s(o, "slot").to_uppercase(), s(o, "version"), s(o, "detail")));
            });
        }
    }

    fn actions(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, lang: Lang) {
        let can = app.can();
        let busy = self.status.get("job").is_some_and(|j| !j.is_null());
        let trial = self.status.get("trial").is_some_and(|x| !x.is_null());
        let needs_path = |id: &str, path: &str| -> Result<(), String> {
            can.check(id)?;
            if busy {
                return Err("a job is running".into());
            }
            if path.trim().is_empty() {
                return Err("type the package's path on the router first".into());
            }
            Ok(())
        };
        let mut send: Option<(&'static str, Value)> = None;
        let mut upload_check = false;
        Grid::new("packages-actions").num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(t(lang, "Package file"));
                self.info(ui, "packages.path", "Package file");
            });
            ui.add(
                egui::TextEdit::singleline(&mut self.path)
                    .hint_text("/tmp/corerouter.crpkg  or  https://…/corerouter.crpkg")
                    .desired_width(360.0),
            );
            ui.end_row();
            ui.horizontal(|ui| {
                ui.label(t(lang, "From this computer"));
                self.info(ui, "packages.upload", "From this computer");
            });
            ui.add(
                egui::TextEdit::singleline(&mut self.local)
                    .hint_text("~/CoreRouter/os/out/build/images/corerouter.crpkg")
                    .desired_width(360.0),
            );
            ui.end_row();
            ui.horizontal(|ui| {
                ui.label(t(lang, "Confirm"));
                self.info(ui, "packages.confirm", "Confirm");
            });
            ui.horizontal(|ui| {
                ui.radio_value(&mut self.manual, false, "auto");
                ui.radio_value(&mut self.manual, true, "manual");
                ui.separator();
                ui.label(t(lang, "Timeout"));
                self.info(ui, "packages.timeout", "Timeout");
                ui.add(egui::DragValue::new(&mut self.timeout).range(30..=3600).suffix(" s"));
            });
            ui.end_row();
        });
        ui.horizontal(|ui| {
            if action(ui, t(lang, "Check"), needs_path("system.package.check", &self.path)) {
                send = Some(if self.is_url() {
                    ("system.package.download", json!({"url": self.path.trim(), "check": true}))
                } else {
                    ("system.package.check", json!({"path": self.path.trim()}))
                });
            }
            let install = needs_path("system.package.update", &self.path)
                .and_then(|()| if trial { Err("a trial boot is pending".into()) } else { Ok(()) });
            if action(ui, t(lang, "Install and reboot"), install) {
                self.ask = Some(Ask::Install);
            }
            ui.separator();
            let local = |id: &str| -> Result<(), String> {
                can.check(id)?;
                if busy || self.sending.is_some() {
                    return Err("a job is running".into());
                }
                if self.local.trim().is_empty() {
                    return Err("type the package's path on this computer, or drop it on the window".into());
                }
                Ok(())
            };
            if action(ui, t(lang, "Upload and check"), local("system.package.upload.start")) {
                upload_check = true;
            }
            let up = local("system.package.upload.start")
                .and_then(|()| if trial { Err("a trial boot is pending".into()) } else { Ok(()) });
            if action(ui, t(lang, "Upload and install…"), up) {
                self.ask = Some(Ask::Upload);
            }
            ui.separator();
            let down = can
                .check("system.package.downgrade")
                .and_then(|()| if busy || trial { Err("a job or a trial is pending".into()) } else { Ok(()) });
            if action(ui, t(lang, "Downgrade"), down) {
                self.ask = Some(Ask::Downgrade);
            }
            self.info(ui, "packages.downgrade", "Downgrade");
            ui.separator();
            let standby = self
                .status
                .get("slots")
                .and_then(Value::as_array)
                .and_then(|a| a.iter().find(|r| r.get("running") != Some(&json!(true))))
                .map(|r| s(r, "slot").to_owned());
            let scrub = can.check("system.package.scrub").and_then(|()| {
                if busy {
                    Err("a job is running".into())
                } else if standby.is_none() {
                    Err("no other slot".into())
                } else {
                    Ok(())
                }
            });
            if action(ui, t(lang, "Scrub"), scrub)
                && let Some(sl) = standby
            {
                send = Some(("system.package.scrub", json!({"slot": sl})));
            }
            self.info(ui, "packages.scrub", "Scrub");
        });
        if let Some((id, p)) = send {
            self.send(app, id, p);
        }
        if upload_check {
            self.start_upload(app, ui.ctx(), true);
        }
        self.upload_progress(app, ui, lang);
    }

    /// Asks the router for an upload of the local file (its size first).
    fn start_upload(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, check: bool) {
        self.error = None;
        self.notice = None;
        let path = self.local.trim().to_owned();
        let size = match crate::export::read_at(ctx, &path, 0, 0) {
            Ok((_, size)) => size,
            Err(e) => {
                self.error = Some(e);
                return;
            }
        };
        let mut p = self.params();
        if let Some(o) = p.as_object_mut() {
            o.remove("path");
            o.insert("size".into(), json!(size));
            o.insert("check".into(), json!(check));
        }
        self.sending = Some(Sending {
            path,
            size,
            check,
            job: None,
            chunk: crate::export::UPLOAD_CHUNK,
            sent: 0,
            pending: None,
            inflight: true,
        });
        app.run_then("system.package.upload.start", p, crate::panel::then(NAME, UpStart));
    }

    /// Sends the next chunk when none is in flight (called every frame).
    fn pump_upload(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context) {
        let Some(up) = self.sending.as_mut() else { return };
        // The next chunk goes as soon as the reply arrives.
        ctx.request_repaint();
        let Some(job) = up.job else { return };
        if up.inflight || up.sent >= up.size {
            return;
        }
        if up.pending.is_none() {
            match crate::export::read_at(ctx, &up.path, up.sent, up.chunk) {
                Ok((b, _)) if !b.is_empty() => {
                    let text = base64::engine::general_purpose::STANDARD.encode(&b);
                    up.pending = Some((up.sent, b.len(), text));
                }
                Ok(_) => {
                    self.error = Some(format!("{}: shorter than when the upload started", up.path));
                    self.abort_upload(app);
                    return;
                }
                Err(e) => {
                    self.error = Some(e);
                    self.abort_upload(app);
                    return;
                }
            }
        }
        if let Some((off, _, text)) = &up.pending {
            up.inflight = true;
            let p = json!({"upload": job, "offset": off, "data": text});
            app.run_then("system.package.upload.chunk", p, crate::panel::then(NAME, UpChunk));
        }
    }

    fn abort_upload(&mut self, app: &mut CoreRouterUi) {
        if let Some(job) = self.sending.take().and_then(|u| u.job) {
            app.run_then("system.package.upload.abort", json!({"upload": job}), crate::panel::then(NAME, Sent("system.package.upload.abort")));
        }
    }

    fn upload_progress(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, lang: Lang) {
        let Some(up) = &self.sending else { return };
        let frac = if up.size > 0 { up.sent as f32 / up.size as f32 } else { 0.0 };
        let mut abort = false;
        ui.horizontal(|ui| {
            ui.label(format!(
                "{} {:.1} / {:.1} MiB",
                t(lang, "Sending"),
                up.sent as f64 / 1_048_576.0,
                up.size as f64 / 1_048_576.0
            ));
            ui.add(egui::ProgressBar::new(frac).desired_width(280.0).show_percentage());
            abort = ui.button(t(lang, "Abort")).clicked();
        });
        if abort {
            self.abort_upload(app);
        }
    }

    fn draw(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let lang = app.lang.labels;
        if self.status.is_null() {
            ui.weak(t(lang, "Waiting for the router…"));
            return;
        }
        if self.status.get("supported") != Some(&json!(true)) {
            ui.horizontal_wrapped(|ui| {
                chip(ui, t(lang, "not available"), neutral_tone(ui.visuals()));
                ui.label(s(&self.status, "reason"));
                self.info(ui, "packages.overview", "Packages");
            });
            return;
        }
        self.summary(ui, lang);
        self.trial(app, ui, lang);
        ui.separator();
        self.slots(ui, lang);
        ui.separator();
        self.job(ui, lang);
        if let Some(n) = &self.notice {
            ui.weak(n);
        }
        if let Some(e) = &self.error {
            ui.colored_label(ui.visuals().error_fg_color, e);
        }
        ui.separator();
        self.actions(app, ui, lang);
        let snaps = self.status.get("snapshots").and_then(Value::as_array).cloned().unwrap_or_default();
        if !snaps.is_empty() {
            ui.add_space(4.0);
            ui.horizontal_wrapped(|ui| {
                ui.weak(t(lang, "Configuration snapshots:"));
                for sn in &snaps {
                    ui.weak(format!(
                        "{} ({}, format {}, {} files)",
                        s(sn, "name"),
                        s(sn, "version"),
                        sn.get("format_version").and_then(Value::as_u64).unwrap_or(0),
                        sn.get("files").and_then(Value::as_u64).unwrap_or(0)
                    ));
                }
                self.info(ui, "packages.snapshot", "Configuration snapshots");
            });
        }
    }
}

impl PanelState for PackagesPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if app.open.contains(&Win::Panel(WIN)) && app.has_command(PRINT) {
            vec![Query {
                key: "print",
                command: PRINT,
                params: Value::Null,
            }]
        } else {
            Vec::new()
        }
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        if key == "print" {
            self.status = value;
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        // A package dropped on the window is the one to send.
        let dropped = ui.ctx().input(|i| i.raw.dropped_files.clone());
        if let Some(p) = dropped
            .iter()
            .map(|f| f.path().display().to_string())
            .find(|p| p.ends_with(".crpkg"))
        {
            self.local = p;
        }
        self.pump_upload(app, ui.ctx());
        egui::ScrollArea::vertical().id_salt("packages").show(ui, |ui| self.draw(app, ui));
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, _area: egui::Rect) {
        help::modal(ctx, app.lang, &mut self.help);
        let Some(ask) = self.ask.clone() else { return };
        let lang = app.lang.labels;
        let other = self
            .status
            .get("slots")
            .and_then(Value::as_array)
            .and_then(|a| a.iter().find(|r| r.get("running") != Some(&json!(true))))
            .cloned()
            .unwrap_or(Value::Null);
        let mut decided: Option<bool> = None;
        egui::Modal::new(egui::Id::unique("packages-ask")).show(ctx, |ui| {
            ui.set_max_width(480.0);
            let (title, what) = match ask {
                Ask::Install => (
                    t(lang, "Install and reboot"),
                    format!("{} {}", t(lang, "Write this package to slot"), s(&other, "slot").to_uppercase()),
                ),
                Ask::Upload => (
                    t(lang, "Upload and install"),
                    format!("{} {}", t(lang, "Send this package and write it to slot"), s(&other, "slot").to_uppercase()),
                ),
                Ask::Downgrade => (
                    t(lang, "Downgrade"),
                    if self.path.trim().is_empty() {
                        format!(
                            "{} {} ({})",
                            t(lang, "Boot the other slot"),
                            s(&other, "slot").to_uppercase(),
                            s(&other, "version")
                        )
                    } else {
                        format!("{} {}", t(lang, "Write this older package to slot"), s(&other, "slot").to_uppercase())
                    },
                ),
            };
            ui.heading(title);
            ui.label(what);
            let file = if ask == Ask::Upload { self.local.trim() } else { self.path.trim() };
            ui.label(RichText::new(file).monospace());
            ui.add_space(4.0);
            ui.label(format!(
                "{} {} s ({}).",
                t(lang, "The router reboots into it on trial. It must be confirmed within"),
                self.timeout,
                if self.manual { "manual" } else { "auto" }
            ));
            ui.weak(t(
                lang,
                "Without confirmation it reboots into the running slot, with the configuration it has now.",
            ));
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui.button(t(lang, "Cancel")).clicked() {
                    decided = Some(false);
                }
                if ui.button(RichText::new(title).strong()).clicked() {
                    decided = Some(true);
                }
            });
        });
        match decided {
            Some(true) => {
                self.ask = None;
                let mut p = self.params();
                match ask {
                    Ask::Install if self.is_url() => {
                        if let Some(o) = p.as_object_mut()
                            && let Some(url) = o.remove("path")
                        {
                            o.insert("url".into(), url);
                        }
                        self.send(app, "system.package.download", p);
                    }
                    Ask::Install => self.send(app, "system.package.update", p),
                    Ask::Upload => self.start_upload(app, ctx, false),
                    Ask::Downgrade => {
                        if self.path.trim().is_empty()
                            && let Some(o) = p.as_object_mut()
                        {
                            o.remove("path");
                        }
                        self.send(app, "system.package.downgrade", p);
                    }
                }
            }
            Some(false) => self.ask = None,
            None => {}
        }
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        let then = match then.downcast::<UpStart>() {
            Ok(_) => {
                match (result, self.sending.as_mut()) {
                    (Ok(v), Some(up)) => {
                        up.job = v.get("upload").and_then(Value::as_u64);
                        if let Some(c) = v.get("chunk").and_then(Value::as_u64) {
                            up.chunk = (c as usize).clamp(64 << 10, 4 << 20);
                        }
                        up.inflight = false;
                    }
                    (Err(e), _) => {
                        self.sending = None;
                        self.error = Some(e.clone());
                    }
                    _ => {}
                }
                return;
            }
            Err(other) => other,
        };
        let then = match then.downcast::<UpChunk>() {
            Ok(_) => {
                match (result, self.sending.as_mut()) {
                    (Ok(v), Some(up)) => {
                        up.inflight = false;
                        if v.get("busy") != Some(&json!(true))
                            && let Some((_, n, _)) = up.pending.take()
                        {
                            up.sent += n as u64;
                        }
                        if up.sent >= up.size {
                            let what = if up.check { "checking" } else { "writing and reading back" };
                            self.notice = Some(format!("sent {:.1} MiB; the router is {what}", up.size as f64 / 1_048_576.0));
                            self.sending = None;
                        }
                    }
                    (Err(e), _) => {
                        // The job result (print) has the router's reason.
                        self.sending = None;
                        self.error = Some(e.clone());
                    }
                    _ => {}
                }
                return;
            }
            Err(other) => other,
        };
        let Ok(sent) = then.downcast::<Sent>() else { return };
        app.cache.refreshed_at = None;
        match result {
            Ok(v) => {
                self.notice = Some(format!("{}: job {} queued", sent.0, v.get("job").and_then(Value::as_u64).unwrap_or(0)));
            }
            Err(e) => self.error = Some(e.clone()),
        }
    }

    fn escape(&mut self, _win: &'static str) -> bool {
        if self.ask.is_some() {
            self.ask = None;
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_helpers() {
        assert_eq!(mm_ss(272), "4:32");
        assert_eq!(mm_ss(5), "0:05");
        let v = egui::Visuals::dark();
        assert_eq!(state_chip(&v, "trial"), AMBER.tone(&v));
        assert_eq!(state_chip(&v, "failed"), RED.tone(&v));
        assert_eq!(mib(&json!({"x": 1_572_864}), "x"), "1.5 MiB");
    }
}
