//! IPv6 › DHCPv6 Server (G4.2c): tabs Servers, Bindings (addresses and
//! delegated prefixes, dynamic and static), Pools and Relays, one row per
//! item, status as chips. `ipv6.dhcp-server.*`, `ipv6.pool.*` and
//! `ipv6.dhcp-relay.*` decide; this shows and sends. A panel.

use std::collections::BTreeMap;

use egui::{Grid, Ui};
use serde_json::{Map, Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind};
use crate::dhcp_client::text;
use crate::dialog::{self, Footer, Press, Status};
use crate::interfaces::{cascade, dialog_id};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Icon, Menu, Row, Shortcut, TableState, action, col, comment, num};
use crate::{CoreRouterUi, Win};

const NAME: &str = "dhcp6-server";
pub(crate) const WIN: &str = "dhcp6-server";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "IPv6",
        title: "DHCPv6 Server",
        size: [960.0, 380.0],
        escape: true,
    }],
    new: || Box::new(Dhcp6Panel::default()),
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Tab {
    #[default]
    Servers,
    Bindings,
    Pools,
    Relays,
}

/// (key, label, hint, yes/no).
type Field = (&'static str, &'static str, &'static str, bool);

struct TabDef {
    title: &'static str,
    salt: &'static str,
    print: &'static str,
    add: &'static str,
    set: Option<&'static str>,
    remove: &'static str,
    what: &'static str,
    columns: &'static [table::Column],
    fields: &'static [Field],
}

const SERVERS: TabDef = TabDef {
    title: "Servers",
    salt: "dhcp6-servers",
    print: "ipv6.dhcp-server.print",
    add: "ipv6.dhcp-server.add",
    set: Some("ipv6.dhcp-server.set"),
    remove: "ipv6.dhcp-server.remove",
    what: "DHCPv6 Server",
    columns: &[
        col("Name"),
        col("Interface"),
        col("Address Pool"),
        col("Prefix Pool"),
        col("Lease Time"),
        num("Bindings"),
        col("Status"),
        comment(),
    ],
    fields: &[
        ("name", "Name", "dhcp6-1", false),
        ("interface", "Interface", "bridge1", false),
        ("address_pool", "Address Pool", "a /128 pool (IA_NA)", false),
        ("prefix_pool", "Prefix Pool", "a /56 pool (IA_PD)", false),
        ("lease_time", "Lease Time", "1d", false),
        ("preference", "Preference", "255", false),
        ("rapid_commit", "Rapid Commit", "", true),
        ("route_distance", "Route Distance", "1", false),
        ("relay", "Relay", "the relay's link-address", false),
        ("dns_server", "DNS Servers", "2001:db8::1", false),
        ("domain", "Domain", "lan.example", false),
        ("dns_zone", "DNS Zone", "AAAA + PTR", false),
        ("disabled", "Disabled", "", true),
        ("comment", "Comment", "", false),
    ],
};

const BINDINGS: TabDef = TabDef {
    title: "Bindings",
    salt: "dhcp6-bindings",
    print: "ipv6.dhcp-server.binding.print",
    add: "ipv6.dhcp-server.binding.add",
    set: None,
    remove: "ipv6.dhcp-server.binding.remove",
    what: "DHCPv6 Binding",
    columns: &[
        col("Address / Prefix"),
        col("DUID"),
        num("IAID"),
        col("Host"),
        col("Server"),
        col("Via"),
        col("Expires After"),
        col("Status"),
    ],
    fields: &[
        ("duid", "DUID", "0x00030001…", false),
        ("iaid", "IAID", "any", false),
        ("address", "Address", "2001:db8:1::50", false),
        ("prefix", "Prefix", "2001:db8:100:300::/56", false),
        ("server", "Server", "all", false),
        ("comment", "Comment", "", false),
    ],
};

const POOLS: TabDef = TabDef {
    title: "Pools",
    salt: "dhcp6-pools",
    print: "ipv6.pool.list",
    add: "ipv6.pool.add",
    set: Some("ipv6.pool.set"),
    remove: "ipv6.pool.remove",
    what: "IPv6 Pool",
    columns: &[
        col("Name"),
        col("Prefix"),
        num("Prefix Length"),
        num("Size"),
        num("Used"),
        col("Checks"),
        comment(),
    ],
    fields: &[
        ("name", "Name", "cpe", false),
        ("prefix", "Prefix", "2001:db8:100::/40", false),
        ("prefix_length", "Prefix Length", "56 (128: addresses)", false),
        ("comment", "Comment", "", false),
    ],
};

const RELAYS: TabDef = TabDef {
    title: "Relays",
    salt: "dhcp6-relays",
    print: "ipv6.dhcp-relay.print",
    add: "ipv6.dhcp-relay.add",
    set: None,
    remove: "ipv6.dhcp-relay.remove",
    what: "DHCPv6 Relay",
    columns: &[
        col("Name"),
        col("Interface"),
        col("DHCP Servers"),
        col("Link Address"),
        num("Requests"),
        num("Replies"),
        comment(),
    ],
    fields: &[
        ("name", "Name", "relay6-1", false),
        ("interface", "Interface", "vlan20", false),
        ("dhcp_server", "DHCP Servers", "empty: ff05::1:3", false),
        ("link_address", "Link Address", "the interface's", false),
        ("comment", "Comment", "", false),
    ],
};

impl Tab {
    const ALL: [Self; 4] = [Self::Servers, Self::Bindings, Self::Pools, Self::Relays];

    fn def(self) -> &'static TabDef {
        match self {
            Self::Servers => &SERVERS,
            Self::Bindings => &BINDINGS,
            Self::Pools => &POOLS,
            Self::Relays => &RELAYS,
        }
    }
}

fn status_chip(status: &str) -> Kind {
    match status {
        "running" | "bound" => Kind::Green,
        "offered" => Kind::Blue,
        "declined" | "invalid" | "error" => Kind::Red,
        _ => Kind::Neutral,
    }
}

pub(crate) fn row(tab: Tab, r: &Value) -> Row {
    let checks = || {
        let v: Vec<(String, Kind)> = r
            .get("checks")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter(|c| text(c, "level") != "ok")
                    .map(|c| (text(c, "label"), if text(c, "level") == "warn" { Kind::Amber } else { Kind::Red }))
                    .collect()
            })
            .unwrap_or_default();
        let refs: Vec<(&str, Kind)> = v.iter().map(|(t, k)| (t.as_str(), *k)).collect();
        chip::cell("", &refs)
    };
    let (key, cells) = match tab {
        Tab::Servers => {
            let st = text(r, "status");
            (
                text(r, "name"),
                vec![
                    text(r, "name"),
                    text(r, "interface"),
                    text(r, "address_pool"),
                    text(r, "prefix_pool"),
                    text(r, "lease_time"),
                    text(r, "bindings"),
                    chip::cell("", &[(st.as_str(), status_chip(&st))]),
                    text(r, "comment"),
                ],
            )
        }
        Tab::Bindings => {
            let st = text(r, "status");
            let mut chips = vec![(st.as_str(), status_chip(&st))];
            if r.get("dynamic").and_then(Value::as_bool) == Some(false) {
                chips.push(("static", Kind::Neutral));
            }
            let kind = if text(r, "type") == "prefix" { ("PD", Kind::Blue) } else { ("NA", Kind::Neutral) };
            let mut host_chips = Vec::new();
            if r.get("dns").is_some() {
                host_chips.push(("DNS", Kind::Blue));
            }
            (
                text(r, "address"),
                vec![
                    chip::cell(&text(r, "address"), &[kind]),
                    text(r, "duid"),
                    text(r, "iaid"),
                    chip::cell(&text(r, "host_name"), &host_chips),
                    text(r, "server"),
                    text(r, "via"),
                    text(r, "expires_after"),
                    chip::cell("", &chips),
                ],
            )
        }
        Tab::Pools => (
            text(r, "name"),
            vec![
                text(r, "name"),
                text(r, "prefix"),
                text(r, "prefix_length"),
                text(r, "size_text"),
                text(r, "leases"),
                checks(),
                text(r, "comment"),
            ],
        ),
        Tab::Relays => (
            text(r, "name"),
            vec![
                text(r, "name"),
                text(r, "interface"),
                text(r, "dhcp_server"),
                text(r, "link_address"),
                text(r, "requests"),
                text(r, "replies"),
                text(r, "comment"),
            ],
        ),
    };
    Row {
        key,
        cells,
        dimmed: r.get("disabled").and_then(Value::as_bool) == Some(true),
        section: false,
        tint: None,
    }
}

pub(crate) struct Dialog6 {
    id: u64,
    tab: Tab,
    item: Option<String>,
    pub(crate) values: Vec<String>,
    orig: Vec<String>,
    status: Status,
}

struct Reply(u64);

#[derive(Default)]
pub(crate) struct Dhcp6Panel {
    pub(crate) tab: Tab,
    pub(crate) rows: BTreeMap<Tab, Vec<Value>>,
    tables: BTreeMap<Tab, TableState>,
    pub(crate) dialog: Option<Dialog6>,
}

impl PanelState for Dhcp6Panel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.open.contains(&Win::Panel(WIN)) && self.dialog.is_none() {
            return Vec::new();
        }
        Tab::ALL
            .iter()
            .map(|t| t.def().print)
            .filter(|p| app.has_command(p))
            .map(|p| Query {
                key: p,
                command: p,
                params: Value::Null,
            })
            .collect()
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        if let Some(tab) = Tab::ALL.into_iter().find(|t| t.def().print == key)
            && let Value::Array(mut a) = value
        {
            // `ipv6.pool.list` also has the pools DHCPv6 clients receive;
            // this tab edits the configured ones (they have an id).
            if tab == Tab::Pools {
                a.retain(|r| r.get("id").is_some());
            }
            self.rows.insert(tab, a);
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        ui.horizontal(|ui| {
            for t in Tab::ALL {
                if ui.selectable_label(self.tab == t, t.def().title).clicked() {
                    self.tab = t;
                }
            }
        });
        ui.separator();
        let tab = self.tab;
        let def = tab.def();
        let rows: Vec<Row> = self.rows.get(&tab).map(|v| v.iter().map(|r| row(tab, r)).collect()).unwrap_or_default();
        let state = self.tables.entry(tab).or_default();
        let selection = state.selection(&rows);
        let can = app.can();
        let mut new = false;
        let mut remove = false;
        let picked = if selection.is_empty() { Err("Select a row first".to_owned()) } else { Ok(()) };
        ui.horizontal(|ui| {
            new = table::tool(ui, def.salt, Icon::Add, "Add", can.check(def.add)).clicked();
            let label = if tab == Tab::Bindings { "Release / Remove" } else { "Remove" };
            remove = table::tool(ui, def.salt, Icon::Remove, label, can.and(def.remove, picked.clone())).clicked();
            table::find_field(ui, def.salt, self.tables.entry(tab).or_default());
        });
        ui.separator();
        let state = self.tables.entry(tab).or_default();
        let out = table::show(ui, def.salt, 0.0, state, def.columns, &rows, |ui, menu| {
            if let Menu::Empty = menu
                && action(ui, &format!("Add {}…", def.what), can.check(def.add))
            {
                new = true;
            }
        });
        if matches!(out.shortcut, Some(Shortcut::Remove)) && !selection.is_empty() {
            remove = true;
        }
        if remove {
            for k in &selection {
                // A static binding row carries its id; a dynamic one, its address.
                let id = if tab == Tab::Bindings {
                    self.rows
                        .get(&tab)
                        .and_then(|rs| rs.iter().find(|r| text(r, "address") == *k))
                        .map(|r| {
                            let id = text(r, "id");
                            if id.is_empty() { k.clone() } else { id }
                        })
                        .unwrap_or_else(|| k.clone())
                } else {
                    k.clone()
                };
                app.run(def.remove, json!({ "id": id }));
            }
        }
        let opened = def.set.and(out.opened.or(out.comment).or_else(|| {
            matches!(out.shortcut, Some(Shortcut::Open))
                .then(|| selection.first().cloned())
                .flatten()
        }));
        if (new || opened.is_some()) && self.dialog.is_none() {
            let r = opened
                .as_ref()
                .and_then(|k| self.rows.get(&tab).and_then(|rs| rs.iter().find(|r| row(tab, r).key == *k)));
            let values: Vec<String> = def
                .fields
                .iter()
                .map(|(k, _, _, yn)| match (r, yn) {
                    (Some(r), true) => if r.get(*k).and_then(Value::as_bool) == Some(true) { "yes" } else { "no" }.into(),
                    (Some(r), false) => text(r, k),
                    (None, true) => if *k == "rapid_commit" { "yes" } else { "no" }.into(),
                    (None, false) => String::new(),
                })
                .collect();
            app.next_dialog = app.next_dialog.wrapping_add(1);
            self.dialog = Some(Dialog6 {
                id: app.next_dialog,
                tab,
                item: opened,
                orig: values.clone(),
                values,
                status: Status::default(),
            });
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        let Some(mut d) = self.dialog.take() else {
            return;
        };
        let def = d.tab.def();
        let wid = dialog_id(d.id);
        let can = app.can();
        let title = match &d.item {
            Some(k) => format!("{} <{k}>", def.what),
            None => format!("New {}", def.what),
        };
        let cmd = match (&d.item, def.set) {
            (Some(_), Some(set)) => set,
            _ => def.add,
        };
        let head = dialog::Head {
            id: wid,
            title: &title,
            dirty: d.values != d.orig,
            pos: cascade(area, d.id),
            parent: Some(crate::win_id(Win::Panel(WIN))),
        };
        let mut values = std::mem::take(&mut d.values);
        let pressed = dialog::show(&mut app.floats, ctx, area, head, &mut d.status, |ui, f| {
            Grid::new(("dhcp6-fields", def.title)).num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
                for ((key, label, hint, yn), v) in def.fields.iter().zip(values.iter_mut()) {
                    if *yn {
                        ui.label(*label);
                        let mut on = v == "yes";
                        if ui.checkbox(&mut on, "").changed() {
                            *v = if on { "yes" } else { "no" }.into();
                        }
                        ui.end_row();
                    } else {
                        f.text(ui, label, key, v, hint);
                    }
                }
            });
            Footer::<()>::edit(false, can.check(cmd))
        });
        d.values = values;
        match pressed {
            Some(Press::Cancel) => {
                app.floats.forget(wid);
                return;
            }
            Some(Press::Ok | Press::Apply) => {
                let mut p = Map::new();
                if let Some(item) = &d.item {
                    p.insert("id".into(), json!(item));
                }
                for (((key, _, _, yn), v), old) in def.fields.iter().zip(&d.values).zip(&d.orig) {
                    if (d.item.is_some() && v == old) || (d.item.is_none() && v.trim().is_empty()) {
                        continue;
                    }
                    let value = if *yn {
                        json!(v == "yes")
                    } else if matches!(*key, "prefix_length" | "preference" | "route_distance" | "iaid") {
                        v.trim().parse::<u64>().map_or_else(|_| json!(v.trim()), |n| json!(n))
                    } else {
                        json!(v.trim())
                    };
                    p.insert((*key).into(), value);
                }
                d.status.close_on_success = true;
                d.status.sent();
                app.run_then(cmd, Value::Object(p), crate::panel::then(NAME, Reply(d.id)));
            }
            _ => {}
        }
        self.dialog = Some(d);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        if let Ok(r) = then.downcast::<Reply>()
            && let Some(d) = self.dialog.as_mut().filter(|d| d.id == r.0)
            && d.status.replied(result)
        {
            app.floats.forget(dialog_id(d.id));
            self.dialog = None;
        }
        app.cache.refreshed_at = None;
    }

    fn escape(&mut self, _win: &'static str) -> bool {
        self.tables.entry(self.tab).or_default().escape()
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        self.tables.iter().map(|(t, s)| (t.def().salt, s)).collect()
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        self.tables.iter_mut().map(|(t, s)| (t.def().salt, s)).collect()
    }
}
