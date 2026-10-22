//! IP › DHCP Server (G4.2a), WinBox style: one window with the tabs DHCP
//! (the servers), Networks, Leases, Options, Option Sets, Matchers and
//! Alerts, one row per item; and IP › DHCP Statistics (KPIs, pool use,
//! messages, why messages were dropped).
//!
//! Leases show their state as chips (bound, offered, static, conflict,
//! blocked) and their name in the DNS / option 82 as chips next to the
//! host; a network's form shows the engine's checks (the gateway inside
//! the network, the pool clear of the gateway and the router, a WAN-looking
//! interface…) as green and amber chips. Nothing is decided here: the rows
//! come from `ip.dhcp-server.*.print`, every change goes through
//! `CoreRouterUi::run`. A panel (`panel.rs`).

use std::collections::BTreeMap;

use egui::{Grid, RichText, Ui};
use serde_json::{Map, Value, json};

use crate::avail::Avail;
use crate::backend::RequestId;
use crate::chip::{self, AMBER, GREEN, Kind, chip, neutral_tone};
use crate::dhcp_client::text;
use crate::dialog::{self, Footer, Press, Status};
use crate::interfaces::{cascade, dialog_id};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Icon, Menu, Row, Shortcut, TableState, action, col, comment, num};
use crate::{CoreRouterUi, Win};

const NAME: &str = "dhcp-server";
pub(crate) const WIN: &str = "dhcp-server";
pub(crate) const WIN_STATS: &str = "dhcp-server-stats";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[
        WinDef {
            id: WIN,
            group: "IP",
            title: "DHCP Server",
            size: [980.0, 420.0],
            escape: true,
        },
        WinDef {
            id: WIN_STATS,
            group: "IP",
            title: "DHCP Statistics",
            size: [760.0, 560.0],
            escape: true,
        },
    ],
    new: || Box::new(DhcpServerPanel::default()),
};

/// A pool this full is drawn amber (the engine's alert threshold).
const POOL_ALERT: u64 = 80;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Tab {
    #[default]
    Dhcp,
    Networks,
    Leases,
    Options,
    OptionSets,
    Matchers,
    Alerts,
}

impl Tab {
    const ALL: [Self; 7] = [
        Self::Dhcp,
        Self::Networks,
        Self::Leases,
        Self::Options,
        Self::OptionSets,
        Self::Matchers,
        Self::Alerts,
    ];

    fn title(self) -> &'static str {
        match self {
            Self::Dhcp => "DHCP",
            Self::Networks => "Networks",
            Self::Leases => "Leases",
            Self::Options => "Options",
            Self::OptionSets => "Option Sets",
            Self::Matchers => "Matchers",
            Self::Alerts => "Alerts",
        }
    }

    fn salt(self) -> &'static str {
        match self {
            Self::Dhcp => "dhcp-server",
            Self::Networks => "dhcp-server-networks",
            Self::Leases => "dhcp-server-leases",
            Self::Options => "dhcp-server-options",
            Self::OptionSets => "dhcp-server-option-sets",
            Self::Matchers => "dhcp-server-matchers",
            Self::Alerts => "dhcp-server-alerts",
        }
    }

    #[cfg(test)]
    pub(crate) fn kind_for_test(self) -> &'static ItemKind {
        self.kind()
    }

    fn kind(self) -> &'static ItemKind {
        match self {
            Self::Dhcp => &SERVER,
            Self::Networks => &NETWORK,
            Self::Leases => &LEASE,
            Self::Options => &OPTION,
            Self::OptionSets => &OPTION_SET,
            Self::Matchers => &MATCHER,
            Self::Alerts => &ALERT,
        }
    }
}

/// How a form field is edited.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FieldKind {
    Text,
    Bool,
    Choice(&'static [&'static str]),
}

pub(crate) struct Field {
    pub key: &'static str,
    pub label: &'static str,
    pub kind: FieldKind,
    pub hint: &'static str,
}

const fn text_field(key: &'static str, label: &'static str, hint: &'static str) -> Field {
    Field {
        key,
        label,
        kind: FieldKind::Text,
        hint,
    }
}

const fn bool_field(key: &'static str, label: &'static str) -> Field {
    Field {
        key,
        label,
        kind: FieldKind::Bool,
        hint: "",
    }
}

/// One kind of item: its commands and its form.
pub(crate) struct ItemKind {
    pub what: &'static str,
    pub print: &'static str,
    pub add: &'static str,
    pub set: &'static str,
    pub remove: &'static str,
    pub fields: &'static [Field],
}

const SERVER: ItemKind = ItemKind {
    what: "DHCP Server",
    print: "ip.dhcp-server.print",
    add: "ip.dhcp-server.add",
    set: "ip.dhcp-server.set",
    remove: "ip.dhcp-server.remove",
    fields: &[
        text_field("name", "Name", "dhcp1"),
        text_field("interface", "Interface", "bridge1"),
        text_field("address_pool", "Address Pool", "static-only"),
        text_field("lease_time", "Lease Time", "30m"),
        Field {
            key: "authoritative",
            label: "Authoritative",
            kind: FieldKind::Choice(&["yes", "no", "after-2sec-delay", "after-10sec-delay"]),
            hint: "",
        },
        bool_field("conflict_detection", "Conflict Detection"),
        bool_field("always_broadcast", "Always Broadcast"),
        text_field("server_address", "Server Address", "the interface's"),
        text_field("relay", "Relay", "clients on the link"),
        text_field("dhcp_option_set", "DHCP Option Set", "none"),
        text_field("address_lists", "Address Lists", "lan-hosts, …"),
        text_field("client_mac_limit", "Client MAC Limit", "unlimited"),
        text_field("client_rate_limit", "Client Rate Limit", "10 messages/s"),
        bool_field("disabled", "Disabled"),
        text_field("comment", "Comment", ""),
    ],
};

const NETWORK: ItemKind = ItemKind {
    what: "DHCP Network",
    print: "ip.dhcp-server.network.print",
    add: "ip.dhcp-server.network.add",
    set: "ip.dhcp-server.network.set",
    remove: "ip.dhcp-server.network.remove",
    fields: &[
        text_field("address", "Address", "192.168.88.0/24"),
        text_field("gateway", "Gateway", "192.168.88.1"),
        text_field("netmask", "Netmask", "the address's"),
        text_field("dns_server", "DNS Servers", "the router"),
        bool_field("dns_none", "DNS None"),
        text_field("domain", "Domain", "lan.example"),
        text_field("dns_zone", "DNS Zone", "name leases in a zone"),
        text_field("ntp_server", "NTP Servers", ""),
        text_field("wins_server", "WINS Servers", ""),
        text_field("next_server", "Next Server", ""),
        text_field("boot_file_name", "Boot File Name", ""),
        text_field("dhcp_option", "DHCP Options", "option names"),
        text_field("dhcp_option_set", "DHCP Option Set", "none"),
        text_field("comment", "Comment", ""),
    ],
};

const LEASE: ItemKind = ItemKind {
    what: "DHCP Lease",
    print: "ip.dhcp-server.lease.print",
    add: "ip.dhcp-server.lease.add",
    set: "ip.dhcp-server.lease.set",
    remove: "ip.dhcp-server.lease.remove",
    fields: &[
        text_field("address", "Address", "192.168.88.50"),
        text_field("mac_address", "MAC Address", "AA:BB:CC:DD:EE:FF"),
        text_field("client_id", "Client ID", "1:aa:bb:cc:dd:ee:ff"),
        text_field("server", "Server", "all"),
        text_field("lease_time", "Lease Time", "the server's"),
        text_field("host_name", "Host Name (DNS)", "the client's"),
        bool_field("block_access", "Block Access"),
        text_field("address_lists", "Address Lists", ""),
        text_field("dhcp_option", "DHCP Options", ""),
        text_field("dhcp_option_set", "DHCP Option Set", "none"),
        bool_field("always_broadcast", "Always Broadcast"),
        bool_field("disabled", "Disabled"),
        text_field("comment", "Comment", ""),
    ],
};

const OPTION: ItemKind = ItemKind {
    what: "DHCP Option",
    print: "ip.dhcp-server.option.print",
    add: "ip.dhcp-server.option.add",
    set: "ip.dhcp-server.option.set",
    remove: "ip.dhcp-server.option.remove",
    fields: &[
        text_field("name", "Name", "tftp"),
        text_field("code", "Code", "66"),
        text_field("value", "Value", "'tftp.lan' | 0x0a0b | s'…'"),
        bool_field("force", "Force"),
        text_field("comment", "Comment", ""),
    ],
};

const OPTION_SET: ItemKind = ItemKind {
    what: "Option Set",
    print: "ip.dhcp-server.option-set.print",
    add: "ip.dhcp-server.option-set.add",
    set: "ip.dhcp-server.option-set.set",
    remove: "ip.dhcp-server.option-set.remove",
    fields: &[
        text_field("name", "Name", "cpe"),
        text_field("options", "Options", "option names"),
        text_field("comment", "Comment", ""),
    ],
};

const MATCHER: ItemKind = ItemKind {
    what: "Matcher",
    print: "ip.dhcp-server.matcher.print",
    add: "ip.dhcp-server.matcher.add",
    set: "ip.dhcp-server.matcher.set",
    remove: "ip.dhcp-server.matcher.remove",
    fields: &[
        text_field("name", "Name", "onu"),
        text_field("server", "Server", "all"),
        text_field("code", "Code", "60 (vendor class)"),
        text_field("value", "Value", "'MSFT 5.0'"),
        Field {
            key: "matching_type",
            label: "Matching Type",
            kind: FieldKind::Choice(&["exact", "substring"]),
            hint: "",
        },
        text_field("option_set", "Option Set", "none"),
        text_field("address_pool", "Address Pool", "the server's"),
        bool_field("disabled", "Disabled"),
        text_field("comment", "Comment", ""),
    ],
};

const ALERT: ItemKind = ItemKind {
    what: "DHCP Alert",
    print: "ip.dhcp-server.alert.print",
    add: "ip.dhcp-server.alert.add",
    set: "ip.dhcp-server.alert.set",
    remove: "ip.dhcp-server.alert.remove",
    fields: &[
        text_field("interface", "Interface", "bridge1"),
        text_field("valid_server", "Valid Servers", "MACs allowed to answer"),
        text_field("alert_timeout", "Alert Timeout", "1h"),
        bool_field("disabled", "Disabled"),
        text_field("comment", "Comment", ""),
    ],
};

const SERVER_COLUMNS: [table::Column; 8] = [
    col("Name"),
    col("Interface"),
    col("Relay"),
    col("Lease Time"),
    col("Address Pool"),
    num("Bound"),
    col("Status"),
    comment(),
];
const NETWORK_COLUMNS: [table::Column; 7] = [
    col("Address"),
    col("Gateway"),
    col("DNS Servers"),
    col("Domain"),
    col("DNS Zone"),
    col("Checks"),
    comment(),
];
const LEASE_COLUMNS: [table::Column; 7] = [
    col("Address"),
    col("MAC Address"),
    col("Host"),
    col("Server"),
    col("Expires After"),
    col("Status"),
    comment(),
];
const OPTION_COLUMNS: [table::Column; 6] = [
    col("Name"),
    num("Code"),
    col("Value"),
    col("Raw Value"),
    col("Force"),
    comment(),
];
const SET_COLUMNS: [table::Column; 3] = [col("Name"), col("Options"), comment()];
const MATCHER_COLUMNS: [table::Column; 8] = [
    col("Name"),
    col("Server"),
    num("Code"),
    col("Value"),
    col("Matching"),
    col("Option Set"),
    col("Address Pool"),
    comment(),
];
const ALERT_COLUMNS: [table::Column; 5] = [
    col("Interface"),
    col("Valid Servers"),
    col("Alert Timeout"),
    col("Unknown Servers"),
    comment(),
];

fn columns(tab: Tab) -> &'static [table::Column] {
    match tab {
        Tab::Dhcp => &SERVER_COLUMNS,
        Tab::Networks => &NETWORK_COLUMNS,
        Tab::Leases => &LEASE_COLUMNS,
        Tab::Options => &OPTION_COLUMNS,
        Tab::OptionSets => &SET_COLUMNS,
        Tab::Matchers => &MATCHER_COLUMNS,
        Tab::Alerts => &ALERT_COLUMNS,
    }
}

/// A form being edited: New (no `item`) or the properties of one item.
pub(crate) struct ItemDialog {
    pub id: u64,
    pub tab: Tab,
    /// The item's key (`*hex`, name or address) when editing.
    pub item: Option<String>,
    pub values: BTreeMap<&'static str, String>,
    orig: BTreeMap<&'static str, String>,
    pub status: Status,
}

struct Reply {
    dialog: u64,
}

#[derive(Default)]
pub(crate) struct DhcpServerPanel {
    pub(crate) tab: Tab,
    /// `*.print` replies, by tab.
    pub(crate) rows: BTreeMap<Tab, Vec<Value>>,
    /// `ip.dhcp-server.statistics.print`.
    pub(crate) stats: Option<Value>,
    tables: BTreeMap<Tab, TableState>,
    pub(crate) dialogs: Vec<ItemDialog>,
    reset_tables: TableState,
}

/// Status chip of a lease.
fn lease_status(r: &Value) -> Vec<(&'static str, Kind)> {
    let mut chips: Vec<(&'static str, Kind)> = Vec::new();
    let st = match text(r, "status").as_str() {
        "bound" => ("bound", Kind::Green),
        "offered" => ("offered", Kind::Blue),
        "testing" => ("testing", Kind::Blue),
        "conflict" => ("conflict", Kind::Red),
        "declined" => ("declined", Kind::Amber),
        "waiting" => ("waiting", Kind::Neutral),
        _ => ("unknown", Kind::Neutral),
    };
    chips.push(st);
    if r.get("dynamic").and_then(Value::as_bool) == Some(false) {
        chips.push(("static", Kind::Neutral));
    }
    if r.get("blocked").and_then(Value::as_bool) == Some(true) {
        chips.push(("blocked", Kind::Red));
    }
    chips
}

fn check_chips(r: &Value) -> String {
    let checks = r.get("checks").and_then(Value::as_array).cloned().unwrap_or_default();
    let chips: Vec<(String, Kind)> = checks
        .iter()
        .map(|c| {
            let kind = match text(c, "level").as_str() {
                "ok" => Kind::Green,
                "warn" => Kind::Amber,
                _ => Kind::Red,
            };
            (text(c, "label"), kind)
        })
        .collect();
    let refs: Vec<(&str, Kind)> = chips.iter().map(|(t, k)| (t.as_str(), *k)).collect();
    chip::cell("", &refs)
}

fn bool_text(r: &Value, k: &str) -> String {
    match r.get(k).and_then(Value::as_bool) {
        Some(true) => "yes".into(),
        Some(false) => "no".into(),
        None => String::new(),
    }
}

/// The row of an item, by tab.
pub(crate) fn row(tab: Tab, r: &Value) -> Row {
    let disabled = r.get("disabled").and_then(Value::as_bool) == Some(true);
    let (key, cells) = match tab {
        Tab::Dhcp => {
            let status = text(r, "status");
            let kind = match status.as_str() {
                "running" => Kind::Green,
                "disabled" | "starting" => Kind::Neutral,
                _ => Kind::Red,
            };
            let mut chips = vec![(status.as_str(), kind)];
            let warns: Vec<String> = r
                .get("checks")
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter(|c| text(c, "level") == "warn")
                        .map(|c| text(c, "label"))
                        .collect()
                })
                .unwrap_or_default();
            for w in &warns {
                chips.push((w.as_str(), Kind::Amber));
            }
            (
                text(r, "name"),
                vec![
                    text(r, "name"),
                    text(r, "interface"),
                    text(r, "relay"),
                    text(r, "lease_time"),
                    text(r, "address_pool"),
                    text(r, "bound"),
                    chip::cell("", &chips),
                    text(r, "comment"),
                ],
            )
        }
        Tab::Networks => (
            text(r, "id"),
            vec![
                text(r, "address"),
                text(r, "gateway"),
                if r.get("dns_none").and_then(Value::as_bool) == Some(true) {
                    "none".into()
                } else {
                    text(r, "dns_server")
                },
                text(r, "domain"),
                text(r, "dns_zone"),
                check_chips(r),
                text(r, "comment"),
            ],
        ),
        Tab::Leases => {
            let mut host_chips: Vec<(&str, Kind)> = Vec::new();
            if r.get("dns").is_some() {
                host_chips.push(("DNS", Kind::Blue));
            }
            if r.get("agent_info").is_some() {
                host_chips.push(("opt82", Kind::Neutral));
            }
            (
                text(r, "address"),
                vec![
                    text(r, "address"),
                    text(r, "mac_address"),
                    // A conflict has no client: its reason says who answered.
                    chip::cell(
                        &Some(text(r, "host_name"))
                            .filter(|h| !h.is_empty())
                            .unwrap_or_else(|| text(r, "reason")),
                        &host_chips,
                    ),
                    text(r, "server"),
                    text(r, "expires_after"),
                    chip::cell("", &lease_status(r)),
                    text(r, "comment"),
                ],
            )
        }
        Tab::Options => (
            text(r, "name"),
            vec![
                text(r, "name"),
                text(r, "code"),
                text(r, "value"),
                text(r, "raw_value"),
                bool_text(r, "force"),
                text(r, "comment"),
            ],
        ),
        Tab::OptionSets => (
            text(r, "name"),
            vec![text(r, "name"), text(r, "options"), text(r, "comment")],
        ),
        Tab::Matchers => (
            text(r, "name"),
            vec![
                text(r, "name"),
                text(r, "server"),
                text(r, "code"),
                text(r, "value"),
                text(r, "matching_type"),
                text(r, "option_set"),
                text(r, "address_pool"),
                text(r, "comment"),
            ],
        ),
        Tab::Alerts => {
            let seen: Vec<String> = r
                .get("unknown_server")
                .and_then(Value::as_array)
                .map(|a| a.iter().map(|s| format!("{} {}", text(s, "address"), text(s, "mac"))).collect())
                .unwrap_or_default();
            let chips: Vec<(&str, Kind)> = seen.iter().map(|s| (s.as_str(), Kind::Red)).collect();
            (
                text(r, "interface"),
                vec![
                    text(r, "interface"),
                    text(r, "valid_server"),
                    text(r, "alert_timeout"),
                    if seen.is_empty() {
                        chip::cell("", &[("none", Kind::Green)])
                    } else {
                        chip::cell("", &chips)
                    },
                    text(r, "comment"),
                ],
            )
        }
    };
    Row {
        key,
        cells,
        dimmed: disabled,
        section: false,
        tint: None,
    }
}

/// The form's values of an item.
fn values_of(kind: &ItemKind, r: Option<&Value>) -> BTreeMap<&'static str, String> {
    kind.fields
        .iter()
        .map(|f| {
            let v = match (r, f.kind) {
                (Some(r), FieldKind::Bool) => bool_text(r, f.key),
                (Some(r), _) => text(r, f.key),
                (None, FieldKind::Bool) => match f.key {
                    "conflict_detection" => "yes".into(),
                    _ => "no".into(),
                },
                (None, FieldKind::Choice(c)) => c.first().copied().unwrap_or("").to_owned(),
                (None, FieldKind::Text) => String::new(),
            };
            (f.key, v)
        })
        .collect()
}

/// The parameters OK sends: every typed field for New, the changed ones
/// for an edit.
pub(crate) fn params(kind: &ItemKind, d: &ItemDialog) -> Value {
    let mut p = Map::new();
    if let Some(item) = &d.item {
        p.insert("id".into(), json!(item));
    }
    for f in kind.fields {
        let v = d.values.get(f.key).cloned().unwrap_or_default();
        let old = d.orig.get(f.key).cloned().unwrap_or_default();
        if d.item.is_some() && v == old {
            continue;
        }
        if d.item.is_none() && v.trim().is_empty() {
            continue;
        }
        let val = match f.kind {
            FieldKind::Bool => json!(v == "yes"),
            _ => json!(v.trim()),
        };
        p.insert(f.key.into(), val);
    }
    Value::Object(p)
}

fn open_window(app: &mut CoreRouterUi, win: &'static str) {
    if !app.open.insert(Win::Panel(win)) {
        app.floats.raise(crate::win_id(Win::Panel(win)));
    }
    app.cache.refreshed_at = None;
}

impl PanelState for DhcpServerPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        let mut out = Vec::new();
        let main = app.open.contains(&Win::Panel(WIN)) || !self.dialogs.is_empty();
        if main {
            for tab in Tab::ALL {
                let print = tab.kind().print;
                if app.has_command(print) {
                    out.push(Query {
                        key: print,
                        command: print,
                        params: Value::Null,
                    });
                }
            }
        }
        if (main || app.open.contains(&Win::Panel(WIN_STATS)))
            && app.has_command("ip.dhcp-server.statistics.print")
        {
            out.push(Query {
                key: "stats",
                command: "ip.dhcp-server.statistics.print",
                params: Value::Null,
            });
        }
        out
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        if key == "stats" {
            self.stats = Some(value);
            return;
        }
        if let Some(tab) = Tab::ALL.into_iter().find(|t| t.kind().print == key)
            && let Value::Array(a) = value
        {
            self.rows.insert(tab, a);
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, win: &'static str, ui: &mut Ui) {
        if win == WIN_STATS {
            self.stats_window(app, ui);
        } else {
            self.main_window(app, ui);
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        let mut keep = Vec::new();
        for mut d in std::mem::take(&mut self.dialogs) {
            if self.draw_dialog(app, ctx, area, &mut d) {
                keep.push(d);
            }
        }
        self.dialogs = keep;
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        if let Ok(r) = then.downcast::<Reply>()
            && let Some(pos) = self.dialogs.iter().position(|d| d.id == r.dialog)
            && let Some(d) = self.dialogs.get_mut(pos)
            && d.status.replied(result)
        {
            app.floats.forget(dialog_id(d.id));
            self.dialogs.remove(pos);
        }
        app.cache.refreshed_at = None;
    }

    fn escape(&mut self, win: &'static str) -> bool {
        if win == WIN_STATS {
            return self.reset_tables.escape();
        }
        self.tables.entry(self.tab).or_default().escape()
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        self.tables.iter().map(|(t, s)| (t.salt(), s)).collect()
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        self.tables.iter_mut().map(|(t, s)| (t.salt(), s)).collect()
    }
}

impl DhcpServerPanel {
    fn main_window(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        ui.horizontal(|ui| {
            for t in Tab::ALL {
                if ui.selectable_label(self.tab == t, t.title()).clicked() {
                    self.tab = t;
                }
            }
        });
        ui.separator();
        let tab = self.tab;
        let kind = tab.kind();
        let rows: Vec<Row> = self
            .rows
            .get(&tab)
            .map(|v| v.iter().map(|r| row(tab, r)).collect())
            .unwrap_or_default();
        let state = self.tables.entry(tab).or_default();
        let selection = state.selection(&rows);
        let can = app.can();
        let mut new = false;
        let mut remove = false;
        let mut lease_cmd: Option<&'static str> = None;
        let mut stats = false;
        let picked = if selection.is_empty() {
            Err("Select a row first".to_owned())
        } else {
            Ok(())
        };
        ui.horizontal(|ui| {
            new = table::tool(ui, tab.salt(), Icon::Add, "Add", can.check(kind.add)).clicked();
            remove = table::tool(ui, tab.salt(), Icon::Remove, "Remove", can.and(kind.remove, picked.clone()))
                .clicked();
            ui.separator();
            if tab == Tab::Leases {
                for (label, cmd) in [
                    ("Make Static", "ip.dhcp-server.lease.make-static"),
                    ("Release", "ip.dhcp-server.lease.release"),
                    ("Block", "ip.dhcp-server.lease.block"),
                    ("Check Status", "ip.dhcp-server.lease.check-status"),
                ] {
                    if action(ui, label, can.and(cmd, picked.clone())) {
                        lease_cmd = Some(cmd);
                    }
                }
                ui.separator();
            }
            if tab == Tab::Alerts && action(ui, "Reset Alert", can.and("ip.dhcp-server.alert.reset-alert", picked.clone())) {
                lease_cmd = Some("ip.dhcp-server.alert.reset-alert");
            }
            stats = action(ui, "Statistics", can.check("ip.dhcp-server.statistics.print"));
            table::find_field(ui, tab.salt(), self.tables.entry(tab).or_default());
        });
        if tab == Tab::Leases {
            self.lease_summary(ui);
        }
        ui.separator();
        let state = self.tables.entry(tab).or_default();
        let out = table::show(ui, tab.salt(), 0.0, state, columns(tab), &rows, |ui, menu| {
            if let Menu::Empty = menu
                && action(ui, &format!("Add {}…", kind.what), can.check(kind.add))
            {
                new = true;
            }
        });
        if matches!(out.shortcut, Some(Shortcut::Remove)) && !selection.is_empty() {
            remove = true;
        }
        if new {
            self.open_dialog(app, tab, None);
        }
        let mut open: Vec<String> = out.opened.into_iter().chain(out.comment).collect();
        if matches!(out.shortcut, Some(Shortcut::Open)) {
            open.extend(selection.iter().cloned());
        }
        for key in open {
            self.open_dialog(app, tab, Some(key));
        }
        if remove {
            for k in &selection {
                app.run(kind.remove, json!({ "id": k }));
            }
        }
        if let Some(cmd) = lease_cmd {
            for k in &selection {
                let p = if tab == Tab::Alerts {
                    json!({ "id": k })
                } else {
                    json!({ "address": k })
                };
                app.run(cmd, p);
            }
        }
        if stats {
            open_window(app, WIN_STATS);
        }
    }

    /// The chips over the Leases table: how many in each state.
    fn lease_summary(&self, ui: &mut Ui) {
        let leases = self.rows.get(&Tab::Leases).cloned().unwrap_or_default();
        let count = |f: &dyn Fn(&Value) -> bool| leases.iter().filter(|r| f(r)).count();
        let v = ui.visuals().clone();
        ui.horizontal(|ui| {
            let bound = count(&|r| text(r, "status") == "bound");
            let offered = count(&|r| matches!(text(r, "status").as_str(), "offered" | "testing"));
            let statics = count(&|r| r.get("dynamic").and_then(Value::as_bool) == Some(false));
            let conflict = count(&|r| matches!(text(r, "status").as_str(), "conflict" | "declined"));
            let blocked = count(&|r| r.get("blocked").and_then(Value::as_bool) == Some(true));
            chip(ui, &format!("{bound} bound"), GREEN.tone(&v));
            chip(ui, &format!("{offered} offered"), crate::chip::BLUE.tone(&v));
            chip(ui, &format!("{statics} static"), neutral_tone(&v));
            let c = chip(
                ui,
                &format!("{conflict} conflict"),
                if conflict > 0 { crate::chip::RED.tone(&v) } else { neutral_tone(&v) },
            );
            if conflict > 0 {
                c.on_hover_text("Someone else answers ARP for these addresses (or the client declined them): held for the lease time. Check Status probes again.");
            }
            chip(
                ui,
                &format!("{blocked} blocked"),
                if blocked > 0 { AMBER.tone(&v) } else { neutral_tone(&v) },
            );
        });
    }

    fn open_dialog(&mut self, app: &mut CoreRouterUi, tab: Tab, item: Option<String>) {
        if let Some(d) = self.dialogs.iter_mut().find(|d| d.tab == tab && d.item == item && item.is_some()) {
            d.status.bring_to_front();
            return;
        }
        let kind = tab.kind();
        let r = item.as_ref().and_then(|k| {
            self.rows
                .get(&tab)
                .and_then(|rows| rows.iter().find(|r| row(tab, r).key == *k))
        });
        if item.is_some() && r.is_none() {
            return;
        }
        // A dynamic lease is not edited here: make it static first.
        if tab == Tab::Leases && r.is_some_and(|r| r.get("dynamic").and_then(Value::as_bool) == Some(true)) {
            return;
        }
        let values = values_of(kind, r);
        app.next_dialog = app.next_dialog.wrapping_add(1);
        let item = match (tab, r) {
            (Tab::Networks | Tab::Leases, Some(r)) => Some(text(r, "id")).filter(|s| !s.is_empty()).or(item),
            _ => item,
        };
        self.dialogs.push(ItemDialog {
            id: app.next_dialog,
            tab,
            item,
            orig: values.clone(),
            values,
            status: Status::default(),
        });
    }

    /// Draw one form; `false` once it closes.
    fn draw_dialog(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect, d: &mut ItemDialog) -> bool {
        let kind = d.tab.kind();
        let wid = dialog_id(d.id);
        let can = app.can();
        let title = match &d.item {
            // A network or a lease is known by its address, not its id.
            Some(_) if matches!(d.tab, Tab::Networks | Tab::Leases) => {
                let what = if d.tab == Tab::Networks { "Network" } else { "Lease" };
                format!("{what} <{}>", d.orig.get("address").cloned().unwrap_or_default())
            }
            Some(k) => format!("{} <{k}>", kind.what),
            None => format!("New {}", kind.what),
        };
        let head = dialog::Head {
            id: wid,
            title: &title,
            dirty: d.values != d.orig,
            pos: cascade(area, d.id),
            parent: Some(crate::win_id(Win::Panel(WIN))),
        };
        // The network's checks come with its row.
        let checks: Vec<Value> = match (&d.item, d.tab) {
            (Some(k), Tab::Networks) => self
                .rows
                .get(&Tab::Networks)
                .and_then(|rows| rows.iter().find(|r| text(r, "id") == *k))
                .and_then(|r| r.get("checks"))
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        let mut values = std::mem::take(&mut d.values);
        let cmd = if d.item.is_some() { kind.set } else { kind.add };
        let pressed = dialog::show(&mut app.floats, ctx, area, head, &mut d.status, |ui, f| {
            form_body(ui, f, kind, &mut values, &checks, d.tab == Tab::Networks, &can, cmd)
        });
        d.values = values;
        match pressed {
            Some(Press::Cancel) => {
                app.floats.forget(wid);
                return false;
            }
            Some(p @ (Press::Ok | Press::Apply)) => {
                let params = params(kind, d);
                d.status.close_on_success = p == Press::Ok;
                d.status.sent();
                app.run_then(cmd, params, crate::panel::then(NAME, Reply { dialog: d.id }));
                if p == Press::Apply {
                    d.orig = d.values.clone();
                }
            }
            _ => {}
        }
        true
    }

    fn stats_window(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let s = self.stats.clone().unwrap_or(Value::Null);
        let can = app.can();
        let n = |v: &Value, k: &str| v.get(k).and_then(Value::as_u64).unwrap_or(0);
        ui.horizontal(|ui| {
            if action(ui, "Reset Statistics", can.check("ip.dhcp-server.statistics.reset")) {
                app.run("ip.dhcp-server.statistics.reset", json!({}));
            }
            ui.separator();
            match s.get("since_secs").and_then(Value::as_u64) {
                Some(secs) => ui.weak(format!("counting for {}", crate::firewall::duration(secs))),
                None => ui.weak("no DHCP server has run yet"),
            };
            if let Some(e) = s.get("journal_error").and_then(Value::as_str) {
                chip(ui, "leases not saved", crate::chip::RED.tone(ui.visuals())).on_hover_text(e);
            }
        });
        ui.separator();
        // KPIs.
        let leases = s.get("leases").cloned().unwrap_or(Value::Null);
        let lat = s.get("latency_us").cloned().unwrap_or(Value::Null);
        let p99 = lat.get("p99").and_then(Value::as_u64);
        ui.horizontal(|ui| {
            kpi(ui, "Active leases", &n(&leases, "bound").to_string(), &format!("{} offered", n(&leases, "offered")));
            kpi(ui, "ACK/s", &n(&s, "ack_rate").to_string(), &format!("peak {}", n(&s, "peak_acks")));
            kpi(
                ui,
                "p99 reply",
                &p99.map_or_else(|| "–".to_owned(), us_text),
                &lat.get("p50").and_then(Value::as_u64).map_or_else(|| "p50 –".to_owned(), |p| format!("p50 {}", us_text(p))),
            )
            .on_hover_text("From a request's arrival to its reply leaving, including writing the lease to disk (synced) before an ACK; an offer's ARP probe wait is not counted");
            kpi(ui, "Dropped", &n(&s, "dropped_total").to_string(), &format!("{} conflicts", n(&s, "conflicts")));
        });
        ui.add_space(6.0);
        ui.strong("Pools");
        let pools = s.get("pools").and_then(Value::as_array).cloned().unwrap_or_default();
        if pools.is_empty() {
            ui.weak("no pool (ip.pool.add)");
        }
        Grid::new("dhcp-stats-pools").num_columns(3).spacing([12.0, 4.0]).show(ui, |ui| {
            for p in &pools {
                ui.label(text(p, "pool"));
                let pct = n(p, "percent");
                pool_bar(ui, pct);
                ui.label(format!("{} % · {} of {} ({} offered, {} held)", pct, n(p, "bound"), n(p, "size"), n(p, "offered"), n(p, "held")));
                ui.end_row();
            }
        });
        ui.add_space(6.0);
        let recv = s.get("received").cloned().unwrap_or(Value::Null);
        let sent = s.get("sent").cloned().unwrap_or(Value::Null);
        ui.horizontal_top(|ui| {
            ui.group(|ui| {
                ui.vertical(|ui| {
                    ui.strong("Messages");
                    Grid::new("dhcp-stats-messages").num_columns(3).striped(true).show(ui, |ui| {
                        ui.weak("Received");
                        ui.weak("");
                        ui.weak("Answered");
                        ui.end_row();
                        for (r, label, answer) in [
                            ("discover", "DISCOVER", format!("{} OFFER", n(&sent, "offer"))),
                            ("request", "REQUEST", format!("{} ACK · {} NAK", n(&sent, "ack"), n(&sent, "nak"))),
                            ("decline", "DECLINE", String::new()),
                            ("release", "RELEASE", String::new()),
                            ("inform", "INFORM", String::new()),
                        ] {
                            ui.label(label);
                            ui.label(n(&recv, r).to_string());
                            ui.label(answer);
                            ui.end_row();
                        }
                    });
                });
            });
            ui.group(|ui| {
                ui.vertical(|ui| {
                    ui.strong("Why no answer");
                    let drops = s.get("dropped").and_then(Value::as_array).cloned().unwrap_or_default();
                    Grid::new("dhcp-stats-drops").num_columns(2).striped(true).show(ui, |ui| {
                        for d in drops.iter().filter(|d| n(d, "count") > 0) {
                            let problem = d.get("problem").and_then(Value::as_bool) == Some(true);
                            let reason = text(d, "reason");
                            if problem {
                                chip(ui, &reason, AMBER.tone(ui.visuals())).on_hover_text(drop_help(&reason));
                            } else {
                                chip(ui, &reason, neutral_tone(ui.visuals())).on_hover_text(drop_help(&reason));
                            }
                            ui.label(n(d, "count").to_string());
                            ui.end_row();
                        }
                    });
                    if drops.iter().all(|d| n(d, "count") == 0) {
                        ui.weak("every message was answered");
                    }
                });
            });
            ui.group(|ui| {
                ui.vertical(|ui| {
                    ui.strong("Probes");
                    ui.label(format!("{} ARP probes", n(&s, "probes")));
                    ui.label(format!("{} conflicts", n(&s, "conflicts")));
                    ui.label(format!("{} rogue replies", n(&s, "rogue_replies")));
                });
            });
        });
        ui.add_space(4.0);
        let window: Vec<u64> = s
            .get("acks_per_sec")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_u64).collect())
            .unwrap_or_default();
        if !window.is_empty() {
            ui.weak("ACKs per second, last minute");
            sparkline(ui, &window);
        }
    }
}

fn us_text(us: u64) -> String {
    if us >= 10_000 {
        format!("{} ms", us / 1000)
    } else if us >= 1000 {
        format!("{:.1} ms", us as f64 / 1000.0)
    } else {
        format!("{us} µs")
    }
}

fn drop_help(reason: &str) -> &'static str {
    match reason {
        "malformed" => "Not a DHCP request (bad length, cookie or option)",
        "bootp" => "Plain BOOTP (no message type): not served",
        "no-server" => "No enabled server on that interface or for that relay",
        "rate-limited" => "The client sent more than Client Rate Limit messages a second",
        "mac-limit" => "The MAC holds Client MAC Limit leases already",
        "pool-exhausted" => "No free address in the pool nor its next pools",
        "static-only" => "A static-only server, and the client has no static lease",
        "not-authoritative" => "An address it cannot have, and the server is not authoritative (yet)",
        "other-server" => "The client chose another server's offer (normal with two servers)",
        "probing" => "A retransmission while its address was being probed",
        _ => "A message type a server never answers",
    }
}

/// A KPI card: big number, label, detail.
fn kpi(ui: &mut Ui, label: &str, value: &str, detail: &str) -> egui::Response {
    ui.group(|ui| {
        ui.set_min_width(150.0);
        ui.vertical(|ui| {
            ui.weak(label);
            ui.label(RichText::new(value).size(24.0).strong());
            ui.weak(detail);
        });
    })
    .response
}

/// A bar of `pct` %, amber from [`POOL_ALERT`].
fn pool_bar(ui: &mut Ui, pct: u64) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(220.0, 12.0), egui::Sense::hover());
    let v = ui.visuals();
    ui.painter().rect(
        rect,
        4.0,
        v.extreme_bg_color,
        v.widgets.noninteractive.bg_stroke,
        egui::StrokeKind::Inside,
    );
    let w = rect.width() * (pct.min(100) as f32 / 100.0);
    let tone = if pct >= POOL_ALERT {
        AMBER.tone(v)
    } else {
        GREEN.tone(v)
    };
    let fill = egui::Rect::from_min_size(rect.min, egui::vec2(w, rect.height()));
    ui.painter().rect_filled(fill, 4.0, tone.ink);
}

fn sparkline(ui: &mut Ui, values: &[u64]) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(ui.available_width().min(600.0), 40.0), egui::Sense::hover());
    let max = values.iter().copied().max().unwrap_or(0).max(1) as f32;
    let step = rect.width() / values.len().max(1) as f32;
    let ink = crate::chip::BLUE.tone(ui.visuals()).ink;
    for (i, v) in values.iter().enumerate() {
        let h = rect.height() * (*v as f32 / max);
        let x = rect.left() + i as f32 * step;
        let bar = egui::Rect::from_min_max(egui::pos2(x, rect.bottom() - h), egui::pos2(x + step * 0.8, rect.bottom()));
        ui.painter().rect_filled(bar, 1.0, ink);
    }
}

#[allow(clippy::too_many_arguments)]
fn form_body(
    ui: &mut Ui,
    f: &dialog::Form,
    kind: &ItemKind,
    values: &mut BTreeMap<&'static str, String>,
    checks: &[Value],
    network: bool,
    can: &Avail,
    cmd: &str,
) -> Footer<()> {
    Grid::new(("dhcp-server-form", kind.what))
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            for field in kind.fields {
                let v = values.entry(field.key).or_default();
                match field.kind {
                    FieldKind::Text => f.text(ui, field.label, field.key, v, field.hint),
                    FieldKind::Bool => {
                        ui.label(field.label);
                        let mut on = v == "yes";
                        if ui.checkbox(&mut on, "").changed() {
                            *v = if on { "yes" } else { "no" }.into();
                        }
                        ui.end_row();
                    }
                    FieldKind::Choice(options) => {
                        ui.label(field.label);
                        egui::ComboBox::from_id_salt(f.window().with(field.key))
                            .selected_text(v.as_str())
                            .show_ui(ui, |ui| {
                                for o in options {
                                    ui.selectable_value(v, (*o).to_owned(), *o);
                                }
                            });
                        ui.end_row();
                    }
                }
            }
        });
    if network {
        ui.separator();
        if checks.is_empty() {
            ui.weak("Checks appear here once the network is saved.");
        }
        ui.horizontal_wrapped(|ui| {
            for c in checks {
                let tone = match text(c, "level").as_str() {
                    "ok" => GREEN.tone(ui.visuals()),
                    "warn" => AMBER.tone(ui.visuals()),
                    _ => crate::chip::RED.tone(ui.visuals()),
                };
                chip(ui, &text(c, "label"), tone).on_hover_text(text(c, "text"));
            }
        });
    }
    Footer::edit(true, can.check(cmd))
}
