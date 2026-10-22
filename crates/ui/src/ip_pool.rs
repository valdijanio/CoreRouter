//! IP › Pool (G4.2a): the address pools the DHCP server hands out, one row
//! each with its use (amber from 80 %), and the Used tab (`/ip pool used`:
//! which address went to whom). `ip.pool.*` decides; this only shows and
//! sends. A panel (`panel.rs`).

use egui::{Grid, Ui};
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind};
use crate::dhcp_client::text;
use crate::dialog::{self, Footer, Press, Status};
use crate::interfaces::{cascade, dialog_id};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Icon, Menu, Row, Shortcut, TableState, action, col, comment, num};
use crate::{CoreRouterUi, Win};

const NAME: &str = "ip-pool";
pub(crate) const WIN: &str = "ip-pool";
const TABLE: &str = "ip-pool";
const USED_TABLE: &str = "ip-pool-used";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "IP",
        title: "Pool",
        size: [720.0, 300.0],
        escape: true,
    }],
    new: || Box::new(PoolPanel::default()),
};

const COLUMNS: [table::Column; 7] = [
    col("Name"),
    col("Ranges"),
    col("Next Pool"),
    num("Size"),
    num("Used"),
    col("Use"),
    comment(),
];
const USED_COLUMNS: [table::Column; 5] = [
    col("Pool"),
    col("Address"),
    col("Owner"),
    col("Info"),
    col("State"),
];

#[derive(Default)]
pub(crate) struct PoolPanel {
    pub(crate) pools: Vec<Value>,
    pub(crate) used: Vec<Value>,
    pub(crate) show_used: bool,
    table: TableState,
    used_table: TableState,
    pub(crate) dialog: Option<PoolDialog>,
}

pub(crate) struct PoolDialog {
    id: u64,
    /// The pool's name when editing.
    item: Option<String>,
    name: String,
    ranges: String,
    next_pool: String,
    comment: String,
    orig: (String, String, String, String),
    status: Status,
}

struct Reply(u64);

pub(crate) fn row(r: &Value) -> Row {
    let pct = r.get("percent").and_then(Value::as_u64).unwrap_or(0);
    let kind = if pct >= 80 { Kind::Amber } else { Kind::Green };
    let mut chips = vec![(format!("{pct} %"), kind)];
    for c in r.get("checks").and_then(Value::as_array).into_iter().flatten() {
        if text(c, "level") != "ok" {
            chips.push((text(c, "label"), Kind::Amber));
        }
    }
    let refs: Vec<(&str, Kind)> = chips.iter().map(|(t, k)| (t.as_str(), *k)).collect();
    Row {
        key: text(r, "name"),
        cells: vec![
            text(r, "name"),
            text(r, "ranges"),
            text(r, "next_pool"),
            text(r, "size"),
            text(r, "used"),
            chip::cell("", &refs),
            text(r, "comment"),
        ],
        dimmed: false,
        section: false,
        tint: None,
    }
}

fn used_row(r: &Value) -> Row {
    let kind = match text(r, "state").as_str() {
        "bound" => Kind::Green,
        "offered" => Kind::Blue,
        _ => Kind::Red,
    };
    Row {
        key: text(r, "address"),
        cells: vec![
            text(r, "pool"),
            text(r, "address"),
            text(r, "owner"),
            text(r, "info"),
            chip::cell("", &[(text(r, "state").as_str(), kind)]),
        ],
        dimmed: false,
        section: false,
        tint: None,
    }
}

impl PanelState for PoolPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        let mut out = Vec::new();
        if app.open.contains(&Win::Panel(WIN)) && app.has_command("ip.pool.print") {
            out.push(Query {
                key: "pools",
                command: "ip.pool.print",
                params: Value::Null,
            });
            if self.show_used {
                out.push(Query {
                    key: "used",
                    command: "ip.pool.used.print",
                    params: Value::Null,
                });
            }
        }
        out
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        if let Value::Array(a) = value {
            match key {
                "pools" => self.pools = a,
                "used" => self.used = a,
                _ => {}
            }
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        ui.horizontal(|ui| {
            if ui.selectable_label(!self.show_used, "Pools").clicked() {
                self.show_used = false;
            }
            if ui.selectable_label(self.show_used, "Used Addresses").clicked() {
                self.show_used = true;
                app.cache.refreshed_at = None;
            }
        });
        ui.separator();
        if self.show_used {
            let rows: Vec<Row> = self.used.iter().map(used_row).collect();
            ui.horizontal(|ui| table::find_field(ui, USED_TABLE, &mut self.used_table));
            table::show(ui, USED_TABLE, 0.0, &mut self.used_table, &USED_COLUMNS, &rows, |_, _| {});
            return;
        }
        let rows: Vec<Row> = self.pools.iter().map(row).collect();
        let selection = self.table.selection(&rows);
        let can = app.can();
        let mut new = false;
        let mut remove = false;
        ui.horizontal(|ui| {
            new = table::tool(ui, TABLE, Icon::Add, "Add", can.check("ip.pool.add")).clicked();
            let picked = if selection.is_empty() {
                Err("Select a pool first".to_owned())
            } else {
                Ok(())
            };
            remove = table::tool(ui, TABLE, Icon::Remove, "Remove", can.and("ip.pool.remove", picked))
                .clicked();
            table::find_field(ui, TABLE, &mut self.table);
        });
        ui.separator();
        let out = table::show(ui, TABLE, 0.0, &mut self.table, &COLUMNS, &rows, |ui, menu| {
            if let Menu::Empty = menu
                && action(ui, "Add Pool…", can.check("ip.pool.add"))
            {
                new = true;
            }
        });
        if matches!(out.shortcut, Some(Shortcut::Remove)) && !selection.is_empty() {
            remove = true;
        }
        if remove {
            for name in &selection {
                app.run("ip.pool.remove", json!({ "id": name }));
            }
        }
        let key = out.opened.or(out.comment).or_else(|| {
            matches!(out.shortcut, Some(Shortcut::Open))
                .then(|| selection.first().cloned())
                .flatten()
        });
        let opened = key.and_then(|k| self.pools.iter().find(|p| text(p, "name") == k).cloned());
        if (new || opened.is_some()) && self.dialog.is_none() {
            app.next_dialog = app.next_dialog.wrapping_add(1);
            let get = |k: &str| opened.as_ref().map(|p| text(p, k)).unwrap_or_default();
            let vals = (get("name"), get("ranges"), get("next_pool"), get("comment"));
            self.dialog = Some(PoolDialog {
                id: app.next_dialog,
                item: opened.as_ref().map(|p| text(p, "name")),
                name: vals.0.clone(),
                ranges: vals.1.clone(),
                next_pool: vals.2.clone(),
                comment: vals.3.clone(),
                orig: vals,
                status: Status::default(),
            });
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        let Some(mut d) = self.dialog.take() else {
            return;
        };
        let wid = dialog_id(d.id);
        let can = app.can();
        let title = match &d.item {
            Some(n) => format!("Pool <{n}>"),
            None => "New Pool".to_owned(),
        };
        let cmd = if d.item.is_some() { "ip.pool.set" } else { "ip.pool.add" };
        let now = (d.name.clone(), d.ranges.clone(), d.next_pool.clone(), d.comment.clone());
        let head = dialog::Head {
            id: wid,
            title: &title,
            dirty: now != d.orig,
            pos: cascade(area, d.id),
            parent: Some(crate::win_id(Win::Panel(WIN))),
        };
        let (mut name, mut ranges, mut next, mut note) = now;
        let pressed = dialog::show(&mut app.floats, ctx, area, head, &mut d.status, |ui, f| {
            Grid::new("ip-pool-fields").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
                f.text(ui, "Name", "name", &mut name, "lan");
                f.text(ui, "Addresses", "ranges", &mut ranges, "192.168.88.10-192.168.88.254");
                f.text(ui, "Next Pool", "next_pool", &mut next, "none");
                f.text(ui, "Comment", "comment", &mut note, "");
            });
            Footer::<()>::edit(false, can.check(cmd))
        });
        d.name = name;
        d.ranges = ranges;
        d.next_pool = next;
        d.comment = note;
        match pressed {
            Some(Press::Cancel) => {
                app.floats.forget(wid);
                return;
            }
            Some(Press::Ok | Press::Apply) => {
                let mut p = json!({"name": d.name.trim(), "ranges": d.ranges.trim(), "next_pool": d.next_pool.trim(), "comment": d.comment});
                if let (Some(item), Some(o)) = (&d.item, p.as_object_mut()) {
                    o.insert("id".into(), json!(item));
                    if d.name == d.orig.0 {
                        o.remove("name");
                    }
                }
                d.status.close_on_success = true;
                d.status.sent();
                app.run_then(cmd, p, crate::panel::then(NAME, Reply(d.id)));
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
        if self.show_used {
            self.used_table.escape()
        } else {
            self.table.escape()
        }
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        vec![(TABLE, &self.table), (USED_TABLE, &self.used_table)]
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        vec![(TABLE, &mut self.table), (USED_TABLE, &mut self.used_table)]
    }
}
