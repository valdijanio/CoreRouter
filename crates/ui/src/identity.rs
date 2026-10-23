//! Subscriber identity (G0.25): a chip with the subscriber's name next to
//! an address — the first source with a name, `+N` for the other names —
//! whose tooltip lists every source and whose click opens the item the name
//! came from (the lease, the address, the list entry, the PTR record).
//!
//! The names come from `ip.identity.lookup`, asked in one batch per refresh
//! for the addresses the windows drew without a name yet, and kept here a
//! while ([`STALE_SECS`]). Where to show it and the order of the sources are
//! preferences of this GUI (Settings › Subscriber identity, stored with the
//! theme, like G0.15's): the order goes to the command as `sources`.
//!
//! A panel with no window of its own. A window uses it in two ways:
//! - a table: [`cell_chips`] after the address in the cell, then
//!   [`table_chip`] with the table's output (tooltip and click);
//! - anywhere else: [`badge`], a chip that does both itself.

use std::collections::{BTreeSet, HashMap};

use egui::{Id, PopupAnchor, Tooltip, Ui};
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind};
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr};
use crate::icons;
use crate::panel::{Panel, PanelState, Query};
use crate::table::{Row, TableOutput};
use crate::{CoreRouterUi, Win};

pub(crate) const NAME: &str = "identity";
const COMMAND: &str = "ip.identity.lookup";
/// A name is asked again after this long (a lease changes hands).
pub(crate) const STALE_SECS: f64 = 30.0;
/// Addresses of one request (the command takes up to 4096).
const BATCH: usize = 1024;
/// Instants asked in one refresh (CGNAT › Who Was asks about the past).
const MAX_INSTANTS: usize = 4;
/// More names than this kept: forget them all and ask again.
const MAX_KNOWN: usize = 20_000;

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[],
    new: || Box::<Identity>::default(),
};

/// The windows that can show the chip: (preference key, label).
pub(crate) const PLACES: [(&str, &str); 6] = [
    ("torch", "Torch"),
    ("connections", "Connections"),
    ("traffic-flow", "Traffic Flow"),
    ("cgnat", "CGNAT › Who Was"),
    ("leases", "DHCP Leases"),
    ("mtr", "MTR"),
];

/// The sources, in the engine's default order: (id, label).
pub(crate) const SOURCES: [(&str, &str); 6] = [
    ("pppoe", "PPPoE login"),
    ("dhcp-static", "Static lease comment"),
    ("dhcp-dynamic", "Lease host name"),
    ("address", "IP › Addresses comment"),
    ("address-list", "Address list comment"),
    ("dns-ptr", "PTR of own zones"),
];

pub(crate) struct Identity {
    pub(crate) enabled: bool,
    /// Every source, in the order tried, and whether it is used.
    pub(crate) order: Vec<(&'static str, bool)>,
    pub(crate) places: BTreeSet<&'static str>,
    /// Lookup replies by the address asked, with when they came.
    known: HashMap<String, (f64, Value)>,
    /// Addresses drawn without a (fresh) name: the next request.
    wanted: BTreeSet<String>,
    /// The time of the last frame that drew a chip.
    now: f64,
    help: Option<HelpView>,
}

impl Default for Identity {
    fn default() -> Self {
        Self {
            enabled: true,
            order: SOURCES.iter().map(|(s, _)| (*s, true)).collect(),
            places: PLACES.iter().map(|(p, _)| *p).collect(),
            known: HashMap::new(),
            wanted: BTreeSet::new(),
            now: 0.0,
            help: None,
        }
    }
}

impl Identity {
    fn sources(&self) -> Vec<&'static str> {
        self.order.iter().filter(|(_, on)| *on).map(|(s, _)| *s).collect()
    }

    /// The name of `address` if known, and ask for it when not (or old).
    fn get(&mut self, place: &str, address: &str, now: f64) -> Option<&Value> {
        if !self.enabled || !self.places.contains(place) || address.is_empty() {
            return None;
        }
        self.now = now;
        let fresh = self.known.get(address).is_some_and(|(t, _)| now - t < STALE_SECS);
        if !fresh && self.wanted.len() < BATCH {
            self.wanted.insert(address.to_owned());
        }
        self.known.get(address).map(|(_, v)| v)
    }

    /// The order or the sources changed: names already shown are stale.
    fn forget(&mut self) {
        self.known.clear();
    }

    fn prefs(&self) -> Value {
        json!({
            "enabled": self.enabled,
            "order": self.order.iter().map(|(s, _)| s).collect::<Vec<_>>(),
            "off": self.order.iter().filter(|(_, on)| !on).map(|(s, _)| s).collect::<Vec<_>>(),
            "places": self.places.iter().collect::<Vec<_>>(),
        })
    }

    fn apply_prefs(&mut self, v: &Value) {
        if let Some(on) = v.get("enabled").and_then(Value::as_bool) {
            self.enabled = on;
        }
        let names = |k: &str| -> Option<Vec<String>> {
            v.get(k)?
                .as_array()
                .map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect())
        };
        if let Some(order) = names("order") {
            let off = names("off").unwrap_or_default();
            // Stored ones first, in their order; a source this GUI has and
            // the stored list lacks (a newer GUI) goes at the end.
            let mut out: Vec<(&'static str, bool)> = order
                .iter()
                .filter_map(|n| SOURCES.iter().find(|(s, _)| s == n))
                .map(|(s, _)| (*s, !off.iter().any(|o| o == s)))
                .collect();
            for (s, _) in SOURCES {
                if !out.iter().any(|(o, _)| *o == s) {
                    out.push((s, true));
                }
            }
            self.order = out;
        }
        if let Some(places) = names("places") {
            self.places = PLACES
                .iter()
                .map(|(p, _)| *p)
                .filter(|p| places.iter().any(|q| q == p))
                .collect();
        }
        self.forget();
    }

    /// Settings › Subscriber identity; whether something changed.
    fn settings(&mut self, ui: &mut Ui, l: Lang) -> bool {
        let mut changed = false;
        ui.horizontal(|ui| {
            ui.strong(tr(l, "Subscriber identity"));
            self.info(ui, l, "identity.chip", "Subscriber identity");
        });
        ui.horizontal(|ui| {
            changed |= ui
                .checkbox(&mut self.enabled, tr(l, "Show the subscriber's name next to addresses"))
                .changed();
            self.info(ui, l, "identity.enabled", "Show the subscriber's name next to addresses");
        });
        ui.add_enabled_ui(self.enabled, |ui| {
            ui.horizontal(|ui| {
                ui.label(tr(l, "Sources, in order"));
                self.info(ui, l, "identity.sources", "Sources, in order");
            });
            let mut swap: Option<(usize, usize)> = None;
            let last = self.order.len().saturating_sub(1);
            for (i, (src, on)) in self.order.iter_mut().enumerate() {
                ui.horizontal(|ui| {
                    ui.add_space(12.0);
                    let salt = format!("identity-source-{i}");
                    let first = if i > 0 { Ok(()) } else { Err(tr(l, "Tried first").to_owned()) };
                    if crate::firewall::arrow(ui, &salt, true, first) {
                        swap = Some((i, i - 1));
                    }
                    let last_one = if i < last { Ok(()) } else { Err(tr(l, "Tried last").to_owned()) };
                    if crate::firewall::arrow(ui, &salt, false, last_one) {
                        swap = Some((i, i + 1));
                    }
                    let label = SOURCES.iter().find(|(s, _)| s == src).map_or(*src, |(_, l)| l);
                    let text = if *src == "pppoe" {
                        format!("{} ({})", tr(l, label), tr(l, "soon: G4.3"))
                    } else {
                        tr(l, label).to_owned()
                    };
                    changed |= ui.checkbox(on, text).changed();
                });
            }
            if let Some((a, b)) = swap {
                self.order.swap(a, b);
                changed = true;
            }
            ui.horizontal(|ui| {
                ui.label(tr(l, "Show in"));
                self.info(ui, l, "identity.places", "Show in");
            });
            ui.horizontal_wrapped(|ui| {
                ui.add_space(12.0);
                for (key, label) in PLACES {
                    let mut on = self.places.contains(key);
                    if ui.checkbox(&mut on, tr(l, label)).changed() {
                        if on {
                            self.places.insert(key);
                        } else {
                            self.places.remove(key);
                        }
                    }
                }
            });
        });
        if changed {
            self.forget();
        }
        changed
    }

    fn info(&mut self, ui: &mut Ui, l: Lang, key: &str, label: &'static str) {
        if help::info_button(ui, Id::unique(("identity-help", key)), tr(l, label)).clicked() {
            self.help = Some(HelpView::new(key, tr(l, label)));
        }
    }
}

impl PanelState for Identity {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !self.enabled || self.wanted.is_empty() || !app.has_command(COMMAND) {
            return Vec::new();
        }
        // One request per instant asked (`address@instant`; none: now).
        let mut by_at: Vec<(Option<&str>, Vec<&str>)> = Vec::new();
        for key in self.wanted.iter().take(BATCH) {
            let (address, at) = match key.split_once('@') {
                Some((a, t)) => (a, Some(t)),
                None => (key.as_str(), None),
            };
            if let Some((_, list)) = by_at.iter_mut().find(|(t, _)| *t == at) {
                list.push(address);
            } else if by_at.len() < MAX_INSTANTS {
                by_at.push((at, vec![address]));
            }
        }
        by_at
            .into_iter()
            .map(|(at, addresses)| {
                let mut params = json!({"addresses": addresses, "sources": self.sources()});
                if let (Some(o), Some(at)) = (params.as_object_mut(), at) {
                    o.insert("at".into(), json!(at));
                }
                Query { key: "lookup", command: COMMAND, params }
            })
            .collect()
    }

    fn arrived(&mut self, _: &mut CoreRouterUi, _: &'static str, _: RequestId, value: Value) {
        let Some(rows) = value.as_array() else {
            return;
        };
        if self.known.len() + rows.len() > MAX_KNOWN {
            self.known.clear();
        }
        for r in rows {
            let address = match r.get("at").and_then(Value::as_str) {
                Some(at) => format!("{}@{at}", text(r, "address")),
                None => text(r, "address"),
            };
            self.wanted.remove(&address);
            self.known.insert(address, (self.now, r.clone()));
        }
    }

    fn window(&mut self, _: &mut CoreRouterUi, _: &'static str, _: &mut Ui) {}

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, _area: egui::Rect) {
        help::modal(ctx, app.lang, &mut self.help);
    }
}

fn text(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or("").to_owned()
}

/// The name of `address` for a chip in window `place` (one of [`PLACES`]):
/// `None` when the chip is off there or the name is not known yet — then it
/// is asked for with the next refresh. A public address with its port
/// (`203.0.113.5:40001`) is named through CGNAT.
pub(crate) fn lookup(app: &mut CoreRouterUi, ui: &Ui, place: &str, address: &str) -> Option<Value> {
    let now = ui.input(|i| i.time);
    // Unknown: asked with the next refresh (at most a second away).
    app.panel_mut::<Identity>()?.get(place, address, now).cloned()
}

/// The chip's label: the icon and the primary name.
fn label(r: &Value) -> Option<String> {
    let name = r.get("primary")?.get("name")?.as_str()?;
    Some(format!("{}{name}", icons::IDENTIFICATION_BADGE))
}

fn more(r: &Value) -> u64 {
    r.get("more").and_then(Value::as_u64).unwrap_or(0)
}

/// The chips of a table cell: the name, and `+N` for the other names.
pub(crate) fn cell_chips(r: Option<&Value>) -> Vec<(String, Kind)> {
    let Some(r) = r else {
        return Vec::new();
    };
    let Some(name) = label(r) else {
        return Vec::new();
    };
    let mut out = vec![(name, Kind::Blue)];
    if more(r) > 0 {
        out.push((format!("+{}", more(r)), Kind::Neutral));
    }
    out
}

/// Append the chips of `address` to cell `col` of `row` (asking for its
/// name when not known yet).
pub(crate) fn add_chips(app: &mut CoreRouterUi, ui: &Ui, place: &str, row: &mut Row, col: usize, address: &str) {
    let r = lookup(app, ui, place, address);
    let chips = cell_chips(r.as_ref());
    if chips.is_empty() {
        return;
    }
    let chips: Vec<(&str, Kind)> = chips.iter().map(|(t, k)| (t.as_str(), *k)).collect();
    if let Some(cell) = row.cells.get_mut(col) {
        cell.push_str(&chip::cell("", &chips));
    }
}

/// Whether a cell chip is one of [`cell_chips`].
pub(crate) fn is_chip(label: &str) -> bool {
    label.starts_with(icons::IDENTIFICATION_BADGE)
        || label.strip_prefix('+').is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// What a source is called in the tooltip.
fn source_label(source: &str) -> &'static str {
    SOURCES.iter().find(|(s, _)| *s == source).map_or("Name", |(_, l)| l)
}

/// The tooltip: every name with its source, and the CGNAT step.
pub(crate) fn tooltip_ui(ui: &mut Ui, l: Lang, r: &Value) {
    if let Some(c) = r.get("cgnat") {
        ui.label(format!(
            "CGNAT: {}:{} → {} ({})",
            text(c, "public"),
            c.get("port").and_then(Value::as_u64).unwrap_or(0),
            text(c, "subscriber"),
            text(c, "via"),
        ));
        ui.separator();
    }
    let all = r.get("all").and_then(Value::as_array).cloned().unwrap_or_default();
    egui::Grid::new("identity-tip").num_columns(2).spacing([10.0, 2.0]).show(ui, |ui| {
        for (i, n) in all.iter().enumerate() {
            let src = tr(l, source_label(&text(n, "source")));
            ui.weak(src);
            let mut line = text(n, "name");
            let detail = text(n, "detail");
            if !detail.is_empty() {
                line = format!("{line}  ·  {detail}");
            }
            if i == 0 {
                ui.strong(line);
            } else {
                ui.label(line);
            }
            ui.end_row();
        }
    });
    ui.weak(tr(l, "Click: open where this name comes from"));
}

/// Open the window of the primary name's item, with the item selected.
pub(crate) fn open(app: &mut CoreRouterUi, r: &Value) {
    let Some(item) = r.get("primary").and_then(|p| p.get("ref")) else {
        return;
    };
    let id = text(item, "id");
    let win = match text(item, "window").as_str() {
        "dhcp-server" => {
            if let Some(p) = app.panel_mut::<crate::dhcp_server::DhcpServerPanel>() {
                p.reveal_lease(&id);
            }
            Win::Panel(crate::dhcp_server::WIN)
        }
        "addresses" => {
            app.tables.addresses.reveal(&id);
            Win::Addresses
        }
        "firewall" => {
            app.fw.tab = crate::firewall::Tab::Addr;
            app.tables.fw_addr.reveal(&id);
            Win::Firewall
        }
        "dns-zones" => {
            if let Some(p) = app.panel_mut::<crate::dns_zones::ZonesPanel>() {
                p.zone = text(item, "zone");
                p.tab = crate::dns_zones::ZoneTab::Records;
                p.record_table.reveal(&id);
            }
            Win::Panel(crate::dns_zones::WIN)
        }
        _ => return,
    };
    if !app.open.insert(win) {
        app.floats.raise(crate::win_id(win));
    }
    app.cache.refreshed_at = None;
}

/// After `table::show`: the tooltip of a subscriber chip under the pointer
/// and its click. `address` gives the address of a row key, as asked.
pub(crate) fn table_chip(
    app: &mut CoreRouterUi,
    ui: &Ui,
    place: &str,
    out: &TableOutput,
    rows: &[Row],
    address: impl Fn(&str) -> Option<String>,
) {
    let Some((key, col, n)) = &out.chip else {
        return;
    };
    let on_chip = rows
        .iter()
        .find(|r| r.key == *key)
        .and_then(|r| r.cells.get(*col))
        .map(|c| chip::split(c).1.get(*n).is_some_and(|(_, label)| is_chip(label)));
    if on_chip != Some(true) {
        return;
    }
    let Some(addr) = address(key) else {
        return;
    };
    let Some(r) = lookup(app, ui, place, &addr) else {
        return;
    };
    let l = app.lang.labels;
    Tooltip::always_open(ui.ctx().clone(), ui.layer_id(), Id::unique(("identity-tip", key)), PopupAnchor::Pointer)
        .show(|ui| tooltip_ui(ui, l, &r));
    ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    if out.chip_clicked {
        open(app, &r);
    }
}

/// The chip of `address` on its own (a form, a result line): the name and
/// `+N`, its tooltip, and a click opening the item. Nothing while unknown.
pub(crate) fn badge(app: &mut CoreRouterUi, ui: &mut Ui, place: &str, address: &str) {
    badge_at(app, ui, place, address, None);
}

/// [`badge`] with the name of who held `address` at instant `at` (as the
/// command takes it: RFC 3339 or Unix seconds), from the lease history.
pub(crate) fn badge_at(app: &mut CoreRouterUi, ui: &mut Ui, place: &str, address: &str, at: Option<&str>) {
    let key = match at {
        Some(t) if !t.is_empty() && !t.contains('@') => format!("{address}@{t}"),
        _ => address.to_owned(),
    };
    let address = key.as_str();
    let Some(r) = lookup(app, ui, place, address) else {
        return;
    };
    let Some(name) = label(&r) else {
        return;
    };
    let l = app.lang.labels;
    let v = ui.visuals().clone();
    let mut resp = chip::chip(ui, &name, Kind::Blue.tone(&v));
    if more(&r) > 0 {
        resp = resp.union(chip::chip(ui, &format!("+{}", more(&r)), Kind::Neutral.tone(&v)));
    }
    let resp = ui
        .interact(resp.rect, Id::unique(("identity-badge", address)), egui::Sense::click())
        .on_hover_cursor(egui::CursorIcon::PointingHand);
    // At once, like the table chip's (a plain tooltip waits for the
    // pointer to rest).
    if resp.hovered() {
        Tooltip::always_open(ui.ctx().clone(), ui.layer_id(), resp.id, PopupAnchor::Pointer)
            .show(|ui| tooltip_ui(ui, l, &r));
    }
    if resp.clicked() {
        open(app, &r);
    }
}

/// Settings › Subscriber identity (drawn by `settings.rs`).
pub(crate) fn settings_ui(app: &mut CoreRouterUi, ui: &mut Ui) {
    let l = app.lang.labels;
    let changed = app.panel_mut::<Identity>().is_some_and(|p| p.settings(ui, l));
    if changed {
        app.cache.refreshed_at = None;
    }
}

fn state(app: &CoreRouterUi) -> Option<&Identity> {
    app.panels
        .iter()
        .flatten()
        .find_map(|p| (p.as_ref() as &dyn std::any::Any).downcast_ref::<Identity>())
}

/// The stored preference (`prefs.rs`).
pub(crate) fn prefs(app: &CoreRouterUi) -> Value {
    state(app).map_or(Value::Null, Identity::prefs)
}

pub(crate) fn apply_prefs(app: &mut CoreRouterUi, v: &Value) {
    if let Some(p) = app.panel_mut::<Identity>() {
        p.apply_prefs(v);
    }
}
