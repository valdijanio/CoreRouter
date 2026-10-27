//! IP › Subscriber Notices (G4.10): the ISP's block and notice page. One
//! window, five tabs (parts of a window are tabs, `docs/ui-style.md`):
//!
//! - **Profiles:** an address list tied to a mode (block, notice,
//!   throttle), in the list pattern (G0.24) with the engine's preview;
//! - **Walled Garden:** what a blocked subscriber still reaches (domains the
//!   router resolves, prefixes), same pattern;
//! - **Pages:** the template editor (title, text with `{variables}`,
//!   color, button) with the page drawn as the subscriber sees it, from the
//!   engine's own filling (`ip.subscriber-notice.page.preview`);
//! - **Active:** who is under a profile now, since when, whether they saw
//!   the page, and "Test as Client";
//! - **Log:** every page view (proof of notice) and every notice that ran
//!   out.
//!
//! [`block_menu`] is the "Block (com página)" action the DHCP lease and the
//! PPP secret lists add. The engine decides everything; this only shows
//! and sends.

use std::collections::BTreeMap;
use std::sync::Mutex;

use egui::{Color32, Grid, Id, RichText, TextEdit, Ui};
use serde_json::{Map, Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind};
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr_in};
use crate::list::{self, Act, Cmds, Item, Tools};
use crate::list_modal::{self, Applied, Field, Input, Modal, Spec};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Menu, Row, TableState, col, comment, num, weak};
use crate::{CoreRouterUi, Win, value_text};

pub(crate) const NAME: &str = "subscriber-notice";
pub(crate) const WIN: &str = "subscriber-notice";
const SCOPE: &str = "subscriber_notice";
const PROFILES: &str = "notice-profiles";
const GARDEN: &str = "notice-garden";
const ACTIVE: &str = "notice-active";
const LOG: &str = "notice-log";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "IP",
        title: "Subscriber Notices",
        size: [980.0, 580.0],
        escape: true,
    }],
    new: || Box::<NoticePanel>::default(),
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Tab {
    #[default]
    Profiles,
    Garden,
    Pages,
    Active,
    Log,
}

const PROFILE_COLUMNS: [table::Column; 6] = [
    col("Name"),
    col("Mode").help("subscriber-notice.profile.mode"),
    col("Address List").help("subscriber-notice.profile.address_list"),
    col("Behaviour").help("subscriber-notice.profile.behaviour"),
    num("Members"),
    comment(),
];

const GARDEN_COLUMNS: [table::Column; 4] = [
    col("Dst. Host").help("subscriber-notice.garden.dst_host"),
    col("Dst. Address").help("subscriber-notice.garden.dst_address"),
    num("Addresses").help("subscriber-notice.garden.addresses"),
    comment(),
];

const ACTIVE_COLUMNS: [table::Column; 7] = [
    col("Address"),
    col("Profile"),
    col("Mode").help("subscriber-notice.profile.mode"),
    col("Source").help("subscriber-notice.active.source"),
    col("Login"),
    col("Since"),
    col("Seen").help("subscriber-notice.active.seen"),
];

const LOG_COLUMNS: [table::Column; 6] = [
    col("Time"),
    col("Address"),
    col("Profile"),
    col("Via").help("subscriber-notice.log.via"),
    col("Login"),
    weak("User Agent"),
];

const PROFILE_CMDS: Cmds = Cmds {
    add: "ip.subscriber-notice.profile.add",
    remove: "ip.subscriber-notice.profile.remove",
    set: Some("ip.subscriber-notice.profile.set"),
    what: "profiles",
};

const GARDEN_CMDS: Cmds = Cmds {
    add: "ip.subscriber-notice.walled-garden.add",
    remove: "ip.subscriber-notice.walled-garden.remove",
    set: Some("ip.subscriber-notice.walled-garden.set"),
    what: "entries",
};

const PROFILE_FIELDS: &[Field] = &[
    Field { param: "name", label: "Name", help: "subscriber-notice.profile.name", input: Input::Text("atraso"), edit: true },
    Field { param: "mode", label: "Mode", help: "subscriber-notice.profile.mode", input: Input::Choice, edit: true },
    Field { param: "address_list", label: "Address List", help: "subscriber-notice.profile.address_list", input: Input::Text("bloqueados"), edit: true },
    Field { param: "page", label: "Page", help: "subscriber-notice.profile.page", input: Input::Choice, edit: true },
    Field { param: "intercept", label: "Intercept", help: "subscriber-notice.profile.intercept", input: Input::Choice, edit: true },
    Field { param: "interval", label: "Interval", help: "subscriber-notice.profile.interval", input: Input::Text("1d"), edit: true },
    Field { param: "timeout", label: "Timeout", help: "subscriber-notice.profile.timeout", input: Input::Text("1h"), edit: true },
    Field { param: "rate_limit", label: "Rate Limit", help: "subscriber-notice.profile.rate_limit", input: Input::Text("1M/1M"), edit: true },
    Field { param: "kill_connections", label: "Kill Connections", help: "subscriber-notice.profile.kill_connections", input: Input::Check, edit: true },
    Field { param: "webhook", label: "Webhook", help: "subscriber-notice.profile.webhook", input: Input::Check, edit: true },
    Field { param: "comment", label: "Comment", help: "", input: Input::Text(""), edit: true },
];

const PROFILE_SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New Notice Profile",
    edit_title: "Notice Profile",
    help: "subscriber-notice.profile",
    fields: PROFILE_FIELDS,
    preview: "ip.subscriber-notice.profile.preview",
};

const GARDEN_FIELDS: &[Field] = &[
    Field { param: "dst_host", label: "Dst. Host", help: "subscriber-notice.garden.dst_host", input: Input::Text("pix.banco.com.br"), edit: true },
    Field { param: "dst_address", label: "Dst. Address", help: "subscriber-notice.garden.dst_address", input: Input::Text("203.0.113.0/24"), edit: true },
    Field { param: "comment", label: "Comment", help: "", input: Input::Text(""), edit: true },
];

const GARDEN_SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New Walled Garden Entry",
    edit_title: "Walled Garden Entry",
    help: "subscriber-notice.garden",
    fields: GARDEN_FIELDS,
    preview: "ip.subscriber-notice.walled-garden.preview",
};

/// The profile names the "Block (com página)" menus of other windows offer
/// (filled by this panel's query while one of them is open).
static PROFILE_NAMES: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn names() -> Vec<String> {
    PROFILE_NAMES.lock().map(|v| v.clone()).unwrap_or_default()
}

fn text(v: &Value, k: &str) -> String {
    v.get(k).filter(|x| !x.is_null()).map(value_text).unwrap_or_default()
}

fn flag(v: &Value, k: &str) -> bool {
    v.get(k).and_then(Value::as_bool).unwrap_or(false)
}

fn n(v: &Value, k: &str) -> u64 {
    v.get(k).and_then(Value::as_u64).unwrap_or(0)
}

pub(crate) fn mode_kind(mode: &str) -> Kind {
    match mode {
        "block" => Kind::Red,
        "notice" => Kind::Amber,
        "throttle" => Kind::Blue,
        _ => Kind::Neutral,
    }
}

fn list_chip(list: &str) -> String {
    chip::cell("", &[(list, Kind::Hashed(chip::name_hue(list)))])
}

/// `5 min`, `2 h`: how long ago.
fn ago(secs: Option<u64>) -> String {
    match secs {
        None => "–".into(),
        Some(s) if s < 60 => format!("{s} s"),
        Some(s) if s < 3600 => format!("{} min", s / 60),
        Some(s) if s < 172_800 => format!("{} h", s / 3600),
        Some(s) => format!("{} d", s / 86_400),
    }
}

pub(crate) fn profile_row(r: &Value) -> Row {
    let mode = text(r, "mode");
    Row {
        key: text(r, "id"),
        cells: vec![
            text(r, "name"),
            chip::cell("", &[(mode.as_str(), mode_kind(&mode))]),
            list_chip(&text(r, "address_list")),
            text(r, "behaviour"),
            n(r, "members").to_string(),
            text(r, "comment"),
        ],
        dimmed: flag(r, "disabled"),
        section: false,
        tint: None,
    }
}

fn garden_row(r: &Value) -> Row {
    Row {
        key: text(r, "id"),
        cells: vec![text(r, "dst_host"), text(r, "dst_address"), n(r, "addresses").to_string(), text(r, "comment")],
        dimmed: flag(r, "disabled"),
        section: false,
        tint: None,
    }
}

pub(crate) fn active_row(r: &Value) -> Row {
    let mode = text(r, "mode");
    let source = text(r, "source");
    let seen = if flag(r, "seen") {
        chip::cell(&ago(r.get("seen_secs_ago").and_then(Value::as_u64)), &[("seen", Kind::Green)])
    } else {
        chip::cell("", &[("not yet", Kind::Neutral)])
    };
    Row {
        key: text(r, "address"),
        cells: vec![
            text(r, "address"),
            text(r, "profile"),
            chip::cell("", &[(mode.as_str(), mode_kind(&mode))]),
            chip::cell("", &[(source.as_str(), Kind::Neutral)]),
            text(r, "login"),
            ago(r.get("since_secs_ago").and_then(Value::as_u64)),
            seen,
        ],
        dimmed: false,
        section: false,
        tint: None,
    }
}

fn log_row(i: usize, r: &Value) -> Row {
    let via = text(r, "via");
    let kind = match via.as_str() {
        "timeout" => Kind::Neutral,
        "browser" | "continue" => Kind::Blue,
        _ => Kind::Green,
    };
    Row {
        key: i.to_string(),
        cells: vec![
            crate::ntp_client::utc(n(r, "at")),
            text(r, "address"),
            text(r, "profile"),
            chip::cell("", &[(via.as_str(), kind)]),
            text(r, "login"),
            text(r, "user_agent"),
        ],
        dimmed: false,
        section: false,
        tint: None,
    }
}

/// The page as typed in the editor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct PageForm {
    pub name: String,
    pub title: String,
    pub text: String,
    pub color: String,
    pub logo_url: String,
    pub button_text: String,
    pub button_url: String,
    pub continue_text: String,
}

const PAGE_FIELDS: [(&str, &str); 6] = [
    ("title", "Title"),
    ("color", "Color"),
    ("logo_url", "Logo URL"),
    ("button_text", "Button Text"),
    ("button_url", "Button URL"),
    ("continue_text", "Continue Text"),
];

impl PageForm {
    fn of(v: &Value) -> Self {
        Self {
            name: text(v, "name"),
            title: text(v, "title"),
            text: text(v, "text"),
            color: text(v, "color"),
            logo_url: text(v, "logo_url"),
            button_text: text(v, "button_text"),
            button_url: text(v, "button_url"),
            continue_text: text(v, "continue_text"),
        }
    }

    fn field_mut(&mut self, k: &str) -> &mut String {
        match k {
            "title" => &mut self.title,
            "color" => &mut self.color,
            "logo_url" => &mut self.logo_url,
            "button_text" => &mut self.button_text,
            "button_url" => &mut self.button_url,
            _ => &mut self.continue_text,
        }
    }

    /// The fields as command parameters (what the preview and Save send).
    pub(crate) fn params(&self) -> Map<String, Value> {
        let mut p = Map::new();
        for (k, v) in [
            ("title", &self.title),
            ("text", &self.text),
            ("color", &self.color),
            ("logo_url", &self.logo_url),
            ("button_text", &self.button_text),
            ("button_url", &self.button_url),
            ("continue_text", &self.continue_text),
        ] {
            p.insert(k.into(), json!(v));
        }
        p
    }
}

/// A command's reply that only refreshes.
struct Done;
/// Save of the page editor.
struct PageSaved;
/// "Test as Client".
struct Tested;

#[derive(Default)]
pub(crate) struct NoticePanel {
    pub(crate) tab: Tab,
    pub(crate) profiles: Vec<Value>,
    pub(crate) garden: Vec<Value>,
    pub(crate) pages: Vec<Value>,
    pub(crate) active: Value,
    pub(crate) log: Vec<Value>,
    pub(crate) settings: Value,
    /// The page being edited: `None` is the built-in one (read only: "Copy
    /// as new page" makes it editable).
    pub(crate) page: Option<String>,
    pub(crate) form: PageForm,
    base: PageForm,
    pub(crate) new_page: String,
    pub(crate) preview: Value,
    pub(crate) page_error: Option<String>,
    pub(crate) test: Option<Value>,
    profiles_table: TableState,
    garden_table: TableState,
    active_table: TableState,
    log_table: TableState,
    pub(crate) modal: Option<(Modal, bool)>,
    pub(crate) help: Option<HelpView>,
}

fn showing(app: &CoreRouterUi) -> bool {
    app.open.contains(&Win::Panel(WIN))
}

/// A label with its ⓘ (`subscriber-notice.<key>`).
fn label(ui: &mut Ui, help: &mut Option<HelpView>, l: Lang, key: &str, text: &'static str) {
    ui.horizontal(|ui| {
        ui.label(tr_in(SCOPE, l, text));
        if help::info_button(ui, Id::unique(("sn-help", key)), tr_in(SCOPE, l, text)).clicked() {
            *help = Some(HelpView::new(format!("subscriber-notice.{key}"), tr_in(SCOPE, l, text)));
        }
    });
}

fn parse_color(c: &str) -> Option<Color32> {
    let h = c.strip_prefix('#')?;
    let v = u32::from_str_radix(h, 16).ok().filter(|_| h.len() == 6)?;
    let [_, r, g, b] = v.to_be_bytes();
    Some(Color32::from_rgb(r, g, b))
}

impl NoticePanel {
    fn profiles_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let rows: Vec<Row> = self.profiles.iter().map(profile_row).collect();
        let sel = self.profiles_table.selection(&rows);
        let picked: Vec<Item> = sel
            .as_slice()
            .iter()
            .filter_map(|k| self.profiles.iter().find(|t| text(t, "id") == *k))
            .map(|t| Item::of(t, "id", ""))
            .collect();
        let tools = Tools::new(&app.can(), &PROFILE_CMDS, &picked);
        let mut act = None;
        ui.horizontal(|ui| {
            act = list::toolbar(ui, PROFILES, &tools, &sel, l);
            if help::info_button(ui, Id::unique("sn-help-profiles"), tr_in(SCOPE, l, "Profiles")).clicked() {
                self.help = Some(HelpView::new("subscriber-notice.profile", tr_in(SCOPE, l, "Profiles")));
            }
            table::find_field(ui, PROFILES, &mut self.profiles_table);
        });
        let out = table::show(ui, PROFILES, 24.0, &mut self.profiles_table, &PROFILE_COLUMNS, &rows, |ui, menu| {
            if let Menu::Rows(sel) = menu
                && let Some(a) = list::row_menu(ui, &tools, sel, true, l)
            {
                act = Some(a);
            }
        });
        if let Some(key) = out.help {
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, "Profiles")));
        }
        if act.is_none() {
            act = list::from_shortcut(out.shortcut, &tools, &sel);
        }
        if let Some(k) = out.opened.or(out.comment) {
            act = Some(Act::Edit(k));
        }
        let v = ui.visuals().clone();
        let count = |m: &str| self.profiles.iter().filter(|p| text(p, "mode") == m).count();
        let members: u64 = self.profiles.iter().map(|p| n(p, "members")).sum();
        list::footer(
            ui,
            &[
                (self.profiles.len(), "profiles", chip::neutral_tone(&v)),
                (count("block"), "block", chip::RED.tone(&v)),
                (count("notice"), "notice", chip::AMBER.tone(&v)),
                (count("throttle"), "throttle", chip::BLUE.tone(&v)),
                (usize::try_from(members).unwrap_or(usize::MAX), "members", chip::neutral_tone(&v)),
            ],
            l,
        );
        if self.profiles.is_empty() {
            ui.weak(tr_in(
                SCOPE,
                l,
                "No profiles. Add one: an address list (bloqueados, aviso) and what its members get. RADIUS Mikrotik-Address-List, PPP profiles and DHCP leases fill the list.",
            ));
        }
        if let Some(a) = act {
            self.list_act(app, a, ui, &rows, true);
        }
    }

    fn garden_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let rows: Vec<Row> = self.garden.iter().map(garden_row).collect();
        let sel = self.garden_table.selection(&rows);
        let picked: Vec<Item> = sel
            .as_slice()
            .iter()
            .filter_map(|k| self.garden.iter().find(|t| text(t, "id") == *k))
            .map(|t| Item::of(t, "id", ""))
            .collect();
        let tools = Tools::new(&app.can(), &GARDEN_CMDS, &picked);
        let mut act = None;
        ui.horizontal(|ui| {
            act = list::toolbar(ui, GARDEN, &tools, &sel, l);
            if help::info_button(ui, Id::unique("sn-help-garden"), tr_in(SCOPE, l, "Walled Garden")).clicked() {
                self.help = Some(HelpView::new("subscriber-notice.garden", tr_in(SCOPE, l, "Walled Garden")));
            }
            table::find_field(ui, GARDEN, &mut self.garden_table);
        });
        let out = table::show(ui, GARDEN, 24.0, &mut self.garden_table, &GARDEN_COLUMNS, &rows, |ui, menu| {
            if let Menu::Rows(sel) = menu
                && let Some(a) = list::row_menu(ui, &tools, sel, true, l)
            {
                act = Some(a);
            }
        });
        if let Some(key) = out.help {
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, "Walled Garden")));
        }
        if act.is_none() {
            act = list::from_shortcut(out.shortcut, &tools, &sel);
        }
        if let Some(k) = out.opened.or(out.comment) {
            act = Some(Act::Edit(k));
        }
        let v = ui.visuals().clone();
        let resolved: u64 = self.garden.iter().map(|g| n(g, "addresses")).sum();
        list::footer(
            ui,
            &[
                (self.garden.len(), "entries", chip::neutral_tone(&v)),
                (usize::try_from(resolved).unwrap_or(usize::MAX), "addresses", chip::GREEN.tone(&v)),
            ],
            l,
        );
        if self.garden.is_empty() {
            ui.weak(tr_in(
                SCOPE,
                l,
                "Empty: a blocked subscriber reaches only the page. Add the ISP's site and the payment pages (PIX, boleto).",
            ));
        }
        if let Some(a) = act {
            self.list_act(app, a, ui, &rows, false);
        }
    }

    fn values(fields: &[Field], r: &Value) -> BTreeMap<&'static str, String> {
        fields
            .iter()
            .map(|f| {
                let v = match f.input {
                    Input::Check => (if flag(r, f.param) { "yes" } else { "no" }).to_owned(),
                    _ => text(r, f.param),
                };
                (f.param, v)
            })
            .collect()
    }

    fn list_act(&mut self, app: &mut CoreRouterUi, a: Act, ui: &Ui, rows: &[Row], profiles: bool) {
        let (cmds, data, fields) = if profiles {
            (PROFILE_CMDS, &self.profiles, PROFILE_FIELDS)
        } else {
            (GARDEN_CMDS, &self.garden, GARDEN_FIELDS)
        };
        let step = |command: &str, params: Value| json!({"command": command, "params": params});
        let set = cmds.set.unwrap_or_default();
        let steps: Vec<Value> = match a {
            Act::Add => {
                let mut v = BTreeMap::new();
                if profiles {
                    v.insert("mode", "block".to_owned());
                    v.insert("intercept", "http".to_owned());
                    v.insert("kill_connections", "yes".to_owned());
                    v.insert("webhook", "yes".to_owned());
                }
                self.modal = Some((Modal::open(app, None, v), profiles));
                return;
            }
            Act::Edit(k) => {
                if let Some(r) = data.iter().find(|t| text(t, "id") == k) {
                    let name = if profiles { text(r, "name") } else { format!("{}{}", text(r, "dst_host"), text(r, "dst_address")) };
                    self.modal = Some((Modal::open(app, Some((k, name)), Self::values(fields, r)), profiles));
                }
                return;
            }
            Act::Comment(ids) => {
                if let Some(k) = ids.into_iter().next() {
                    self.list_act(app, Act::Edit(k), ui, rows, profiles);
                }
                return;
            }
            Act::Remove(ids) => ids.iter().map(|id| step(cmds.remove, json!({"id": id}))).collect(),
            Act::Enable(ids) => ids.iter().map(|id| step(set, json!({"id": id, "disabled": false}))).collect(),
            Act::Disable(ids) => ids.iter().map(|id| step(set, json!({"id": id, "disabled": true}))).collect(),
            Act::Copy(ids) => {
                let picked: Vec<&Row> = rows.iter().filter(|r| ids.contains(&r.key)).collect();
                ui.ctx().copy_text(list::copy_rows(&picked));
                return;
            }
            Act::CopyAs(ids, syntax) => {
                let picked: Vec<&Value> = data.iter().filter(|t| ids.contains(&text(t, "id"))).collect();
                ui.ctx().copy_text(list::copy_commands(app, cmds.add, &picked, syntax));
                return;
            }
        };
        if !steps.is_empty() {
            app.run_steps(steps, crate::panel::then(NAME, Done));
        }
    }

    fn pages_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let can = app.can();
        let mut help = self.help.take();
        let names: Vec<String> = self.pages.iter().map(|p| text(p, "name")).collect();
        let mut pick: Option<Option<String>> = None;
        ui.horizontal(|ui| {
            label(ui, &mut help, l, "pages", "Page");
            let shown = self.page.clone().unwrap_or_else(|| "default".into());
            egui::ComboBox::from_id_salt("sn-page").selected_text(shown).show_ui(ui, |ui| {
                if ui.selectable_label(self.page.is_none(), tr_in(SCOPE, l, "default (built-in)")).clicked() {
                    pick = Some(None);
                }
                for nm in &names {
                    if ui.selectable_label(self.page.as_deref() == Some(nm.as_str()), nm).clicked() {
                        pick = Some(Some(nm.clone()));
                    }
                }
            });
            ui.separator();
            ui.add(TextEdit::singleline(&mut self.new_page).hint_text(tr_in(SCOPE, l, "new page name")).desired_width(140.0));
            let add_ok = if self.new_page.trim().is_empty() { Err(tr_in(SCOPE, l, "Type a name").to_owned()) } else { can.check("ip.subscriber-notice.page.add") };
            if table::action(ui, tr_in(SCOPE, l, "Add as New Page"), add_ok) {
                // From the built-in page: its texts (only the name goes);
                // from another: a copy of what is in the editor.
                let mut p = if self.page.is_some() { self.form.params() } else { Map::new() };
                p.insert("name".into(), json!(self.new_page.trim()));
                app.run_then("ip.subscriber-notice.page.add", Value::Object(p), crate::panel::then(NAME, PageSaved));
                self.page = Some(self.new_page.trim().to_owned());
                self.new_page.clear();
            }
            if let Some(nm) = self.page.clone()
                && table::action(ui, tr_in(SCOPE, l, "Remove"), can.check("ip.subscriber-notice.page.remove"))
            {
                app.run_then("ip.subscriber-notice.page.remove", json!({"id": nm}), crate::panel::then(NAME, PageSaved));
                self.page = None;
            }
        });
        if let Some(p) = pick {
            self.select_page(p);
            app.cache.refreshed_at = None;
        }
        ui.separator();
        let dirty = self.form != self.base;
        ui.columns(2, |cols| {
            let [left, right] = cols else { return };
            if self.page.is_none() {
                left.weak(tr_in(SCOPE, l, "The built-in page is read only: type a name and add it as a new page to edit its texts."));
                right.label(RichText::new(tr_in(SCOPE, l, "Preview (sample values)")).weak());
                self.draw_preview(right);
                return;
            }
            Grid::new("sn-page-form").num_columns(2).spacing([12.0, 6.0]).show(left, |ui| {
                for (k, name) in PAGE_FIELDS {
                    label(ui, &mut help, l, &format!("page.{k}"), name);
                    ui.add(TextEdit::singleline(self.form.field_mut(k)).desired_width(260.0));
                    ui.end_row();
                }
            });
            label(left, &mut help, l, "page.text", "Text");
            left.add(TextEdit::multiline(&mut self.form.text).desired_rows(8).desired_width(f32::INFINITY));
            left.weak(tr_in(SCOPE, l, "Variables: {login} {plano} {valor} {vencimento} {link_pix} {endereco} {perfil}"));
            left.horizontal(|ui| {
                let save_ok = if !dirty {
                    Err(tr_in(SCOPE, l, "Nothing changed").to_owned())
                } else {
                    can.check("ip.subscriber-notice.page.set")
                };
                if table::action(ui, tr_in(SCOPE, l, "Save"), save_ok)
                    && let Some(nm) = &self.page
                {
                    let mut p = self.form.params();
                    p.insert("id".into(), json!(nm));
                    app.run_then("ip.subscriber-notice.page.set", Value::Object(p), crate::panel::then(NAME, PageSaved));
                }
                if table::action(ui, tr_in(SCOPE, l, "Revert"), if dirty { Ok(()) } else { Err(tr_in(SCOPE, l, "Nothing changed").to_owned()) }) {
                    self.form = self.base.clone();
                }
            });
            if let Some(e) = self.page_error.as_deref().or(self.preview.get("problem").and_then(Value::as_str)) {
                left.colored_label(left.visuals().error_fg_color, e);
            }
            right.label(RichText::new(tr_in(SCOPE, l, "Preview (sample values)")).weak());
            self.draw_preview(right);
        });
        self.help = help;
    }

    /// The page as a phone shows it: header in its color, the paragraphs
    /// filled by the engine, the button and the continue link.
    fn draw_preview(&self, ui: &mut Ui) {
        let p = &self.preview;
        let color = parse_color(&text(p, "color")).unwrap_or(Color32::from_rgb(0x15, 0x65, 0xc0));
        egui::Frame::new().stroke(ui.visuals().widgets.noninteractive.bg_stroke).inner_margin(0.0).show(ui, |ui| {
            ui.set_max_width(360.0);
            egui::Frame::new().fill(color).inner_margin(10.0).show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.label(RichText::new(text(p, "title")).color(Color32::WHITE).strong().size(17.0));
            });
            egui::Frame::new().inner_margin(10.0).show(ui, |ui| {
                for para in p.get("paragraphs").and_then(Value::as_array).into_iter().flatten() {
                    ui.label(value_text(para));
                    ui.add_space(4.0);
                }
                let button = text(p, "button_text");
                if !button.is_empty() {
                    egui::Frame::new().fill(color).corner_radius(6.0).inner_margin(8.0).show(ui, |ui| {
                        ui.set_min_width(ui.available_width());
                        ui.vertical_centered(|ui| ui.label(RichText::new(&button).color(Color32::WHITE).strong()));
                    })
                    .response
                    .on_hover_text(text(p, "button_url"));
                }
                let cont = text(p, "continue_text");
                if !cont.is_empty() {
                    ui.vertical_centered(|ui| ui.label(RichText::new(cont).color(color)));
                }
            });
        });
    }

    /// Edit page `name` (`None`: the built-in one, read only).
    pub(crate) fn select_page(&mut self, name: Option<String>) {
        self.page = name;
        self.load_page();
    }

    fn load_page(&mut self) {
        let v = self.page.as_ref().and_then(|nm| self.pages.iter().find(|p| text(p, "name") == *nm).cloned());
        let f = v.map(|v| PageForm::of(&v)).unwrap_or_default();
        self.form = f.clone();
        self.base = f;
        self.page_error = None;
    }

    fn active_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let data: Vec<Value> = self.active.get("rows").and_then(Value::as_array).cloned().unwrap_or_default();
        let rows: Vec<Row> = data.iter().map(active_row).collect();
        let sel = self.active_table.selection(&rows);
        let mut test = None;
        ui.horizontal(|ui| {
            let one = sel.as_slice().first().cloned();
            let ok = match &one {
                Some(_) => app.can().check("ip.subscriber-notice.test"),
                None => Err(tr_in(SCOPE, l, "Select a subscriber first").to_owned()),
            };
            if table::action(ui, tr_in(SCOPE, l, "Test as Client"), ok) {
                test = one;
            }
            if help::info_button(ui, Id::unique("sn-help-test"), tr_in(SCOPE, l, "Test as Client")).clicked() {
                self.help = Some(HelpView::new("subscriber-notice.test", tr_in(SCOPE, l, "Test as Client")));
            }
            ui.weak(format!("{} {}", n(&self.active, "total"), tr_in(SCOPE, l, "under a profile")));
            table::find_field(ui, ACTIVE, &mut self.active_table);
        });
        let out = table::show(ui, ACTIVE, 24.0, &mut self.active_table, &ACTIVE_COLUMNS, &rows, |_, _| {});
        if let Some(key) = out.help {
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, "Active")));
        }
        let v = ui.visuals().clone();
        let count = |m: &str| data.iter().filter(|r| text(r, "mode") == m).count();
        list::footer(
            ui,
            &[
                (data.len(), "subscribers", chip::neutral_tone(&v)),
                (count("block"), "block", chip::RED.tone(&v)),
                (count("notice"), "notice", chip::AMBER.tone(&v)),
                (count("throttle"), "throttle", chip::BLUE.tone(&v)),
                (list::count(&data, "seen", "true"), "seen", chip::GREEN.tone(&v)),
            ],
            l,
        );
        if let Some(a) = test.map(|k| k.split('/').next().unwrap_or_default().to_owned()) {
            app.run_then("ip.subscriber-notice.test", json!({"address": a}), crate::panel::then(NAME, Tested));
        }
    }

    fn log_tab(&mut self, ui: &mut Ui, l: Lang) {
        let rows: Vec<Row> = self.log.iter().enumerate().map(|(i, r)| log_row(i, r)).collect();
        ui.horizontal(|ui| {
            if help::info_button(ui, Id::unique("sn-help-log"), tr_in(SCOPE, l, "Log")).clicked() {
                self.help = Some(HelpView::new("subscriber-notice.log", tr_in(SCOPE, l, "Log")));
            }
            ui.weak(tr_in(SCOPE, l, "Each page view, newest first: proof that the subscriber was told."));
            table::find_field(ui, LOG, &mut self.log_table);
        });
        let out = table::show(ui, LOG, 0.0, &mut self.log_table, &LOG_COLUMNS, &rows, |_, _| {});
        if let Some(key) = out.help {
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, "Log")));
        }
    }

    fn status_strip(&mut self, ui: &mut Ui, l: Lang) {
        ui.horizontal_wrapped(|ui| {
            label(ui, &mut self.help, l, "portal", "Portal");
            let port = n(&self.settings, "port");
            chip::chip(ui, &format!("http :{port}"), chip::neutral_tone(ui.visuals()));
            let probes = n(&self.settings, "probes");
            chip::chip(ui, &format!("{probes} {}", tr_in(SCOPE, l, "OS probes")), chip::GREEN.tone(ui.visuals()))
                .on_hover_text(tr_in(SCOPE, l, "Captive-portal probes the router answers: Android, Apple, Windows, Firefox, Linux and others"));
            let capport = text(&self.settings, "capport_url");
            if capport.is_empty() {
                chip::chip(ui, "RFC 8910 off", chip::neutral_tone(ui.visuals()))
                    .on_hover_text(tr_in(SCOPE, l, "DHCP option 114 needs an https address with a valid certificate (capport_url)"));
            } else {
                chip::chip(ui, "RFC 8910", chip::BLUE.tone(ui.visuals())).on_hover_text(capport);
            }
            if !text(&self.settings, "webhook_url").is_empty() {
                chip::chip(ui, "webhook", chip::BLUE.tone(ui.visuals())).on_hover_text(text(&self.settings, "webhook_url"));
            }
        });
    }
}

/// "Block (com página)" for the selected rows of another window: a menu of
/// the notice profiles, and "none" to undo. `command` takes `key` (a
/// lease's `address`, a secret's `name`) and `profile`.
pub(crate) fn block_menu(ui: &mut Ui, app: &mut CoreRouterUi, l: Lang, command: &'static str, key: &str, values: &[String]) {
    let can = app.can().check(command);
    let names = names();
    let why = if values.is_empty() {
        Err(tr_in(SCOPE, l, "Select one or more rows first").to_owned())
    } else if names.is_empty() {
        Err(tr_in(SCOPE, l, "No notice profile: add one in IP › Subscriber Notices").to_owned())
    } else {
        can
    };
    let label = tr_in(SCOPE, l, "Block (com página)");
    match why {
        Err(e) => {
            ui.add_enabled(false, egui::Button::new(label)).on_disabled_hover_text(e);
        }
        Ok(()) => {
            ui.menu_button(label, |ui| {
                let mut chosen: Option<String> = None;
                for nm in &names {
                    if ui.button(nm).clicked() {
                        chosen = Some(nm.clone());
                    }
                }
                ui.separator();
                if ui.button(tr_in(SCOPE, l, "Unblock (no page)")).clicked() {
                    chosen = Some(String::new());
                }
                if let Some(profile) = chosen {
                    let steps: Vec<Value> = values
                        .iter()
                        .map(|v| json!({"command": command, "params": {key: v, "profile": profile}}))
                        .collect();
                    app.run_steps(steps, crate::panel::then(NAME, Done));
                    ui.close();
                }
            });
        }
    }
}

impl PanelState for NoticePanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.has_command("ip.subscriber-notice.profile.print") {
            return Vec::new();
        }
        let q = |key, command, params| Query { key, command, params };
        // The lease and secret lists offer the profiles in their menus.
        let others = [crate::dhcp_server::WIN, crate::ppp::WIN].iter().any(|w| app.open.contains(&Win::Panel(w)));
        if !showing(app) {
            return if others { vec![q("profiles", "ip.subscriber-notice.profile.print", json!({}))] } else { Vec::new() };
        }
        let mut out = vec![
            q("profiles", "ip.subscriber-notice.profile.print", json!({})),
            q("settings", "ip.subscriber-notice.settings.get", json!({})),
            q("pages", "ip.subscriber-notice.page.print", json!({})),
        ];
        match self.tab {
            Tab::Garden => out.push(q("garden", "ip.subscriber-notice.walled-garden.print", json!({}))),
            Tab::Pages => {
                let mut p = if self.page.is_some() { self.form.params() } else { Map::new() };
                if let Some(nm) = &self.page {
                    p.insert("page".into(), json!(nm));
                }
                out.push(q("preview", "ip.subscriber-notice.page.preview", Value::Object(p)));
            }
            Tab::Active => out.push(q("active", "ip.subscriber-notice.active.list", json!({"limit": 5000}))),
            Tab::Log => out.push(q("log", "ip.subscriber-notice.log", json!({"limit": 1000}))),
            Tab::Profiles => {}
        }
        out
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        match key {
            "profiles" => {
                if let Value::Array(a) = value {
                    if let Ok(mut n) = PROFILE_NAMES.lock() {
                        *n = a.iter().map(|p| text(p, "name")).collect();
                    }
                    self.profiles = a;
                }
            }
            "garden" => {
                if let Value::Array(a) = value {
                    self.garden = a;
                }
            }
            "pages" => {
                if let Value::Array(a) = value {
                    let changed = a != self.pages;
                    self.pages = a;
                    if changed && self.form == self.base {
                        self.load_page();
                    }
                }
            }
            "preview" => self.preview = value,
            "settings" => self.settings = value,
            "active" => self.active = value,
            "log" => {
                if let Value::Array(a) = value {
                    self.log = a;
                }
            }
            list_modal::PREVIEW => {
                if let Some((m, _)) = self.modal.as_mut() {
                    m.arrived(value);
                }
            }
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        let l = app.lang.labels;
        self.status_strip(ui, l);
        ui.horizontal(|ui| {
            for (t, name) in [
                (Tab::Profiles, "Profiles"),
                (Tab::Garden, "Walled Garden"),
                (Tab::Pages, "Pages"),
                (Tab::Active, "Active"),
                (Tab::Log, "Log"),
            ] {
                if ui.selectable_value(&mut self.tab, t, tr_in(SCOPE, l, name)).changed() {
                    app.cache.refreshed_at = None;
                }
            }
        });
        ui.separator();
        match self.tab {
            Tab::Profiles => self.profiles_tab(app, ui, l),
            Tab::Garden => self.garden_tab(app, ui, l),
            Tab::Pages => self.pages_tab(app, ui, l),
            Tab::Active => self.active_tab(app, ui, l),
            Tab::Log => self.log_tab(ui, l),
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        help::modal(ctx, app.lang, &mut self.help);
        let pages: Vec<String> = std::iter::once(String::new()).chain(self.pages.iter().map(|p| text(p, "name"))).collect();
        let options = |p: &str| -> Vec<String> {
            match p {
                "mode" => vec!["block".into(), "notice".into(), "throttle".into()],
                "intercept" => vec!["http".into(), "probes".into()],
                "page" => pages.clone(),
                _ => Vec::new(),
            }
        };
        if let Some((m, profiles)) = self.modal.as_mut() {
            let spec = if *profiles { &PROFILE_SPEC } else { &GARDEN_SPEC };
            if !m.show(app, ctx, area, spec, &options) {
                self.modal = None;
            }
        }
        if let Some(t) = self.test.clone() {
            let l = app.lang.labels;
            let mut open = true;
            egui::Window::new(format!("{} {}", tr_in(SCOPE, l, "Test as Client"), text(&t, "address")))
                .id(Id::unique("sn-test"))
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .constrain_to(area)
                .show(ctx, |ui| test_result(ui, l, &t));
            if !open {
                self.test = None;
            }
        }
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        let then = match then.downcast::<PageSaved>() {
            Ok(_) => {
                match result {
                    Ok(_) => {
                        self.page_error = None;
                        self.base = self.form.clone();
                    }
                    Err(e) => self.page_error = Some(e.clone()),
                }
                app.cache.refreshed_at = None;
                return;
            }
            Err(t) => t,
        };
        let then = match then.downcast::<Tested>() {
            Ok(_) => {
                self.test = Some(match result {
                    Ok(v) => v.clone(),
                    Err(e) => json!({"warnings": [e]}),
                });
                return;
            }
            Err(t) => t,
        };
        if let Ok(a) = then.downcast::<Applied>()
            && let Some((m, _)) = self.modal.as_mut().filter(|(m, _)| m.id == a.0)
            && m.replied(app, result)
        {
            self.modal = None;
        }
        app.cache.refreshed_at = None;
    }

    fn escape(&mut self, _win: &'static str) -> bool {
        match self.tab {
            Tab::Profiles => self.profiles_table.escape(),
            Tab::Garden => self.garden_table.escape(),
            Tab::Active => self.active_table.escape(),
            Tab::Log => self.log_table.escape(),
            Tab::Pages => false,
        }
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        vec![(PROFILES, &self.profiles_table), (GARDEN, &self.garden_table), (ACTIVE, &self.active_table), (LOG, &self.log_table)]
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        vec![
            (PROFILES, &mut self.profiles_table),
            (GARDEN, &mut self.garden_table),
            (ACTIVE, &mut self.active_table),
            (LOG, &mut self.log_table),
        ]
    }
}

/// What "Test as Client" found: the profile, what passes, each OS probe,
/// and why it would not work.
fn test_result(ui: &mut Ui, l: Lang, t: &Value) {
    let v = ui.visuals().clone();
    Grid::new("sn-test-grid").num_columns(2).spacing([12.0, 4.0]).show(ui, |ui| {
        ui.label(tr_in(SCOPE, l, "Profile"));
        match t.get("profile").and_then(Value::as_str) {
            Some(p) => {
                let mode = text(t, "mode");
                ui.horizontal(|ui| {
                    ui.label(p);
                    chip::chip(ui, &mode, mode_kind(&mode).tone(&v));
                    if flag(t, "seen") {
                        chip::chip(ui, "seen", chip::GREEN.tone(&v));
                    }
                });
            }
            None => {
                ui.label(tr_in(SCOPE, l, "none: this address browses normally"));
            }
        }
        ui.end_row();
        let yes_no = |b: bool| if b { ("yes", chip::GREEN.tone(&v)) } else { ("no", chip::neutral_tone(&v)) };
        for (name, on) in [("DNS", flag(t, "dns")), ("Port 80 to the page", flag(t, "portal"))] {
            ui.label(tr_in(SCOPE, l, name));
            let (txt, tone) = yes_no(on);
            chip::chip(ui, txt, tone);
            ui.end_row();
        }
        ui.label("HTTPS");
        let https = text(t, "https");
        chip::chip(ui, &https, if https == "refused" { chip::RED.tone(&v) } else { chip::GREEN.tone(&v) });
        ui.end_row();
        ui.label(tr_in(SCOPE, l, "Walled garden addresses"));
        ui.label(n(t, "walled_garden").to_string());
        ui.end_row();
    });
    let probes = t.get("probes").and_then(Value::as_array).cloned().unwrap_or_default();
    if !probes.is_empty() {
        ui.separator();
        ui.label(RichText::new(tr_in(SCOPE, l, "OS probes")).strong());
        let mut by_os: BTreeMap<String, (usize, String)> = BTreeMap::new();
        for p in &probes {
            let e = by_os.entry(text(p, "os")).or_insert((0, text(p, "answer")));
            e.0 += 1;
        }
        ui.horizontal_wrapped(|ui| {
            for (os, (count, answer)) in by_os {
                let tone = if answer == "redirect" { chip::AMBER.tone(&v) } else { chip::neutral_tone(&v) };
                chip::chip(ui, &format!("{os} ×{count}: {answer}"), tone);
            }
        });
    }
    for w in t.get("warnings").and_then(Value::as_array).into_iter().flatten() {
        ui.colored_label(v.warn_fg_color, value_text(w));
    }
}
