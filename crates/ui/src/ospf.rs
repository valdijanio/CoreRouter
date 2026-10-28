//! Routing › OSPF (G3.4c), in the RouterOS v7 model: the tabs Neighbors
//! (live, with the Diagnose of the selected one), Instances, Areas,
//! Interface Templates and Key Chains (list windows, G0.24, with the
//! engine's preview in the modal), LSDB, Routes (with "Why this path?") and
//! Topology (the network drawn from the LSDB, `crate::ospf_topology`).
//! `routing.ospf.*` decides; this only shows and sends.

use std::collections::BTreeMap;

use egui::{RichText, Ui};
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind, cell};
use crate::help::{self, HelpView};
use crate::i18n::tr_in;
use crate::list::{self, Act, Cmds, Item, Tools};
use crate::list_modal::{self, Applied, Field, Input, Modal, Spec};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Menu, Row, TableState, col, comment, num};
use crate::{CoreRouterUi, Then, Win, value_text};

pub(crate) const NAME: &str = "ospf";
pub(crate) const WIN: &str = "ospf";
/// Labels' scope (`i18n/auto/ospf_*.rs`).
pub(crate) const SCOPE: &str = "ospf";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef { id: WIN, group: "Routing", title: "OSPF", size: [1040.0, 560.0], escape: true }],
    new: || Box::new(OspfPanel::default()),
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Tab {
    #[default]
    Neighbors,
    Instances,
    Areas,
    Templates,
    Keychains,
    Lsdb,
    Routes,
    Topology,
}

pub(crate) const TABS: [(Tab, &str, &str); 8] = [
    (Tab::Neighbors, "Neighbors", "ospf.tab.neighbors"),
    (Tab::Instances, "Instances", "ospf.tab.instances"),
    (Tab::Areas, "Areas", "ospf.tab.areas"),
    (Tab::Templates, "Interface Templates", "ospf.tab.templates"),
    (Tab::Keychains, "Key Chains", "ospf.tab.keychains"),
    (Tab::Lsdb, "LSDB", "ospf.tab.lsdb"),
    (Tab::Routes, "Routes", "ospf.tab.routes"),
    (Tab::Topology, "Topology", "ospf.tab.topology"),
];

const NBR: &str = "ospf-neighbors";
const INST: &str = "ospf-instances";
const AREAS: &str = "ospf-areas";
const TPL: &str = "ospf-templates";
const KC: &str = "ospf-keychains";
const LSDB: &str = "ospf-lsdb";
const ROUTES: &str = "ospf-routes";

const INST_CMDS: Cmds = Cmds { add: "routing.ospf.instance.add", remove: "routing.ospf.instance.remove", set: Some("routing.ospf.instance.set"), what: "instances" };
const AREA_CMDS: Cmds = Cmds { add: "routing.ospf.area.add", remove: "routing.ospf.area.remove", set: Some("routing.ospf.area.set"), what: "areas" };
const TPL_CMDS: Cmds = Cmds {
    add: "routing.ospf.interface-template.add",
    remove: "routing.ospf.interface-template.remove",
    set: Some("routing.ospf.interface-template.set"),
    what: "templates",
};
const KC_CMDS: Cmds = Cmds { add: "routing.ospf.keychain.add", remove: "routing.ospf.keychain.remove", set: Some("routing.ospf.keychain.set"), what: "key chains" };

const fn field(param: &'static str, label: &'static str, help: &'static str, input: Input) -> Field {
    Field { param, label, help, input, edit: true }
}

const INST_FIELDS: &[Field] = &[
    field("name", "Name", "ospf.instance.name", Input::Text("v2")),
    field("version", "Version", "ospf.instance.version", Input::Choice),
    field("vrf", "VRF", "ospf.instance.vrf", Input::Text("main")),
    field("router_id", "Router ID", "ospf.instance.router_id", Input::Text("10.255.0.1")),
    field("redistribute", "Redistribute", "ospf.instance.redistribute", Input::Text("connected,static,bgp,kernel")),
    field("out_filter_chain", "Out Filter Chain", "ospf.instance.out_filter_chain", Input::Text("a /routing filter chain")),
    field("originate_default", "Originate Default", "ospf.instance.originate_default", Input::Choice),
    field("subscriber_pools", "Subscriber Pools", "ospf.instance.subscriber_pools", Input::Check),
    field("disabled", "Disabled", "ospf.disabled", Input::Check),
    field("comment", "Comment", "", Input::Text("")),
];

const AREA_FIELDS: &[Field] = &[
    field("name", "Name", "ospf.area.name", Input::Text("backbone")),
    field("instance", "Instance", "ospf.area.instance", Input::Choice),
    field("area_id", "Area ID", "ospf.area.area_id", Input::Text("0.0.0.0")),
    field("type", "Type", "ospf.area.type", Input::Choice),
    field("no_summaries", "No Summaries", "ospf.area.no_summaries", Input::Check),
    field("default_cost", "Default Cost", "ospf.area.default_cost", Input::Text("1")),
    field("nssa_translate", "NSSA Translate", "ospf.area.nssa_translate", Input::Choice),
    field("disabled", "Disabled", "ospf.disabled", Input::Check),
    field("comment", "Comment", "", Input::Text("")),
];

const TPL_FIELDS: &[Field] = &[
    field("area", "Area", "ospf.template.area", Input::Choice),
    field("interfaces", "Interfaces", "ospf.template.interfaces", Input::Text("ether1,uplinks")),
    field("networks", "Networks", "ospf.template.networks", Input::Text("10.0.0.0/16")),
    field("type", "Network Type", "ospf.template.type", Input::Choice),
    field("cost", "Cost", "ospf.template.cost", Input::Text("10")),
    field("priority", "Priority", "ospf.template.priority", Input::Text("1")),
    field("hello_interval", "Hello Interval", "ospf.template.hello_interval", Input::Text("10 s")),
    field("dead_interval", "Dead Interval", "ospf.template.dead_interval", Input::Text("40 s")),
    field("passive", "Passive", "ospf.template.passive", Input::Check),
    field("mtu_ignore", "MTU Ignore", "ospf.template.mtu_ignore", Input::Check),
    field("auth", "Authentication", "ospf.template.auth", Input::Choice),
    field("auth_id", "Auth ID", "ospf.template.auth_id", Input::Text("1")),
    field("auth_key", "Auth Key", "ospf.template.auth_key", Input::Secret("empty keeps it")),
    field("keychain", "Key Chain", "ospf.template.keychain", Input::Choice),
    field("bfd", "BFD Profile", "ospf.template.bfd", Input::Text("default")),
    field("disabled", "Disabled", "ospf.disabled", Input::Check),
    field("comment", "Comment", "", Input::Text("")),
];

const KC_FIELDS: &[Field] = &[
    field("name", "Name", "ospf.keychain.name", Input::Text("core")),
    field("comment", "Comment", "", Input::Text("")),
];

pub(crate) const INST_SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New OSPF Instance",
    edit_title: "OSPF Instance",
    help: "ospf.instance",
    fields: INST_FIELDS,
    preview: "routing.ospf.instance.check",
};
pub(crate) const AREA_SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New OSPF Area",
    edit_title: "OSPF Area",
    help: "ospf.area",
    fields: AREA_FIELDS,
    preview: "routing.ospf.area.check",
};
pub(crate) const TPL_SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New Interface Template",
    edit_title: "Interface Template",
    help: "ospf.template",
    fields: TPL_FIELDS,
    preview: "routing.ospf.interface-template.check",
};
pub(crate) const KC_SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New Key Chain",
    edit_title: "Key Chain",
    help: "ospf.keychain",
    fields: KC_FIELDS,
    preview: "routing.ospf.keychain.check",
};

const NBR_COLUMNS: [table::Column; 8] = [
    col("State").help("ospf.neighbor.state"),
    col("Router ID").help("ospf.neighbor.router_id"),
    col("Address").help("ospf.neighbor.address"),
    col("Interface").help("ospf.neighbor.interface"),
    col("Area").help("ospf.area.area_id"),
    num("Uptime").help("ospf.neighbor.uptime"),
    col("BFD").help("ospf.template.bfd"),
    col("Instance").help("ospf.area.instance"),
];
const INST_COLUMNS: [table::Column; 8] = [
    col("Name").help("ospf.instance.name"),
    col("Version").help("ospf.instance.version"),
    col("Router ID").help("ospf.instance.router_id"),
    col("VRF").help("ospf.instance.vrf"),
    col("Redistribute").help("ospf.instance.redistribute"),
    num("Areas").help("ospf.tab.areas"),
    num("Interfaces").help("ospf.template.interfaces"),
    comment(),
];
const AREA_COLUMNS: [table::Column; 7] = [
    col("Name").help("ospf.area.name"),
    col("Area ID").help("ospf.area.area_id"),
    col("Type").help("ospf.area.type"),
    col("Instance").help("ospf.area.instance"),
    col("Interfaces").help("ospf.template.interfaces"),
    num("Ranges").help("ospf.area.ranges"),
    comment(),
];
const TPL_COLUMNS: [table::Column; 9] = [
    col("Area").help("ospf.template.area"),
    col("Match").help("ospf.template.interfaces"),
    col("Type").help("ospf.template.type"),
    num("Cost").help("ospf.template.cost"),
    col("Auth").help("ospf.template.auth"),
    col("Passive").help("ospf.template.passive"),
    col("Interfaces Now").help("ospf.template.matched"),
    col("Warnings").help("ospf.template.warnings"),
    comment(),
];
const KC_COLUMNS: [table::Column; 5] = [
    col("Name").help("ospf.keychain.name"),
    col("Keys").help("ospf.keychain.keys"),
    col("Sending Now").help("ospf.keychain.sending"),
    col("Rotation").help("ospf.keychain.rotation"),
    col("Used By").help("ospf.keychain.used_by"),
];
const LSA_COLUMNS: [table::Column; 7] = [
    col("Type").help("ospf.lsa.type"),
    col("Area").help("ospf.area.area_id"),
    col("ID").help("ospf.lsa.id"),
    col("Originator").help("ospf.lsa.originator"),
    num("Age").help("ospf.lsa.age"),
    col("Sequence").help("ospf.lsa.sequence"),
    col("Body").help("ospf.lsa.body"),
];
const ROUTE_COLUMNS: [table::Column; 5] = [
    col("Prefix").help("ospf.route.prefix"),
    col("Kind").help("ospf.route.kind"),
    num("Cost").help("ospf.route.cost"),
    col("Area").help("ospf.area.area_id"),
    col("Next Hop").help("ospf.route.nexthop"),
];

/// The LSA types the LSDB tab filters by.
const LSA_TYPES: [(&str, &str); 6] = [
    ("router", "Router"),
    ("network", "Network"),
    ("summary", "Summary"),
    ("asbr-summary", "ASBR Summary"),
    ("external", "External"),
    ("nssa-external", "NSSA"),
];

#[derive(Default)]
pub(crate) struct OspfPanel {
    pub(crate) tab: Tab,
    pub(crate) neighbors: Value,
    pub(crate) instances: Vec<Value>,
    pub(crate) areas: Vec<Value>,
    pub(crate) templates: Vec<Value>,
    pub(crate) keychains: Vec<Value>,
    pub(crate) lsas: Value,
    pub(crate) routes: Value,
    pub(crate) topology: Value,
    pub(crate) path: Value,
    pub(crate) diagnose: Value,
    /// The instance the LSDB, Routes and Topology tabs show.
    pub(crate) instance: String,
    pub(crate) lsa_type: String,
    pub(crate) lsa_page: u32,
    /// "Why this path?" destination (typed, or a click in the topology).
    pub(crate) path_to: String,
    pub(crate) path_asked: Option<String>,
    /// The interface whose neighbor is diagnosed.
    pub(crate) diagnose_of: Option<String>,
    pub(crate) topo: crate::ospf_topology::View,
    nbr_table: TableState,
    inst_table: TableState,
    area_table: TableState,
    tpl_table: TableState,
    kc_table: TableState,
    lsa_table: TableState,
    route_table: TableState,
    pub(crate) modal: Option<(What, Modal)>,
    pub(crate) help: Option<HelpView>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum What {
    Instance,
    Area,
    Template,
    Keychain,
}

fn s(r: &Value, k: &str) -> String {
    r.get(k).map(value_text).unwrap_or_default()
}

fn flag(r: &Value, k: &str) -> bool {
    r.get(k).and_then(Value::as_bool).unwrap_or(false)
}

fn list_of(r: &Value, k: &str) -> Vec<String> {
    r.get(k)
        .and_then(Value::as_array)
        .map(|a| a.iter().map(value_text).collect())
        .unwrap_or_default()
}

fn rows_of(v: &Value) -> Vec<Value> {
    v.get("rows").and_then(Value::as_array).cloned().unwrap_or_default()
}

/// The area id as a selo colored by the id (the same area, the same color
/// everywhere).
pub(crate) fn area_chip(area: &str) -> (String, Kind) {
    let n = area.parse::<std::net::Ipv4Addr>().map_or(0, |a| u64::from(u32::from(a)));
    let label = if n == 0 { format!("{area} backbone") } else { area.to_owned() };
    (label, Kind::Hashed(chip::hashed(n + 1)))
}

/// The neighbor's state selo: Full green, the way up amber, Init/Down red.
pub(crate) fn state_kind(state: &str) -> Kind {
    match state.split(' ').next().unwrap_or("") {
        "Full" => Kind::Green,
        "2-Way" | "TwoWay" => Kind::Blue,
        "Loading" | "Exchange" | "ExStart" | "Attempt" => Kind::Amber,
        _ => Kind::Red,
    }
}

fn level_kind(level: &str) -> Kind {
    match level {
        "error" => Kind::Red,
        "warning" => Kind::Amber,
        "ok" => Kind::Green,
        _ => Kind::Neutral,
    }
}

fn chips(v: &[(String, Kind)]) -> String {
    let c: Vec<(&str, Kind)> = v.iter().map(|(t, k)| (t.as_str(), *k)).collect();
    cell("", &c)
}

pub(crate) fn nbr_row(r: &Value) -> Row {
    let state = s(r, "label");
    let uptime = r
        .get("state_secs")
        .and_then(Value::as_u64)
        .map_or_else(|| "–".to_owned(), crate::neighbors::uptime_text);
    let bfd = match s(r, "bfd").as_str() {
        "" => "–".to_owned(),
        b => cell("", &[(b, if b == "up" { Kind::Green } else { Kind::Red })]),
    };
    let area = s(r, "area");
    Row {
        key: format!("{}|{}|{}", s(r, "instance"), s(r, "interface"), s(r, "router_id")),
        cells: vec![
            cell("", &[(state.as_str(), state_kind(&state))]),
            s(r, "router_id"),
            s(r, "address"),
            s(r, "interface"),
            if area.is_empty() { "–".into() } else { chips(&[area_chip(&area)]) },
            uptime,
            bfd,
            s(r, "instance"),
        ],
        dimmed: false,
        section: false,
        tint: None,
    }
}

fn inst_row(r: &Value) -> Row {
    let v = s(r, "version");
    Row {
        key: s(r, "name"),
        cells: vec![
            s(r, "name"),
            cell("", &[(if v == "3" { "v3 IPv6" } else { "v2 IPv4" }, Kind::Blue)]),
            { let t = s(r, "router_id"); if t.is_empty() { cell("", &[("auto", Kind::Amber)]) } else { t } },
            s(r, "vrf"),
            {
                let mut c: Vec<(String, Kind)> = list_of(r, "redistribute").into_iter().map(|x| (x, Kind::Neutral)).collect();
                if flag(r, "subscriber_pools") {
                    c.push(("pools".into(), Kind::Blue));
                }
                chips(&c)
            },
            s(r, "areas"),
            s(r, "interfaces"),
            s(r, "comment"),
        ],
        dimmed: flag(r, "disabled"),
        section: false,
        tint: None,
    }
}

fn area_row(r: &Value) -> Row {
    let t = s(r, "type");
    let mut kind = vec![(t.clone(), if t == "default" { Kind::Neutral } else { Kind::Blue })];
    if flag(r, "no_summaries") {
        kind.push(("no-summaries".into(), Kind::Neutral));
    }
    Row {
        key: s(r, "name"),
        cells: vec![
            s(r, "name"),
            chips(&[area_chip(&s(r, "area_id"))]),
            chips(&kind),
            s(r, "instance"),
            list_of(r, "interfaces").join(", "),
            s(r, "ranges"),
            s(r, "comment"),
        ],
        dimmed: flag(r, "disabled"),
        section: false,
        tint: None,
    }
}

fn tpl_row(r: &Value) -> Row {
    let mut m = list_of(r, "interfaces");
    m.extend(list_of(r, "networks"));
    let auth = s(r, "auth");
    let auth_cell = match auth.as_str() {
        "" => cell("", &[("none", if flag(r, "passive") { Kind::Neutral } else { Kind::Amber })]),
        "simple" | "md5" => cell("", &[(auth.as_str(), Kind::Amber)]),
        a => {
            let chain = s(r, "keychain");
            let t = if chain.is_empty() { a.to_owned() } else { format!("{a} · {chain}") };
            cell("", &[(t.as_str(), Kind::Green)])
        }
    };
    let matched: Vec<String> = r
        .get("matched")
        .and_then(Value::as_array)
        .map(|a| a.iter().map(|x| s(x, "interface")).collect())
        .unwrap_or_default();
    let warnings = list_of(r, "warnings");
    let area = r.get("area_id").map(value_text).unwrap_or_default();
    Row {
        key: s(r, "id"),
        cells: vec![
            cell(&s(r, "area"), &[area_chip(&area)].iter().map(|(t, k)| (t.as_str(), *k)).collect::<Vec<_>>()),
            m.join(", "),
            s(r, "type"),
            { let c = s(r, "cost"); if c.is_empty() { "auto".into() } else { c } },
            auth_cell,
            if flag(r, "passive") { cell("", &[("passive", Kind::Neutral)]) } else { String::new() },
            if matched.is_empty() { "–".into() } else { matched.join(", ") },
            match warnings.len() {
                0 => String::new(),
                n => cell("", &[(format!("{n} warning{}", if n == 1 { "" } else { "s" }).as_str(), Kind::Amber)]),
            },
            s(r, "comment"),
        ],
        dimmed: flag(r, "disabled"),
        section: false,
        tint: None,
    }
}

fn kc_row(r: &Value) -> Row {
    let keys: Vec<String> = r
        .get("keys")
        .and_then(Value::as_array)
        .map(|a| a.iter().map(|k| format!("{} {}", s(k, "id"), s(k, "algorithm"))).collect())
        .unwrap_or_default();
    let worst = r
        .get("rotation")
        .and_then(Value::as_array)
        .and_then(|a| {
            ["error", "warning"]
                .into_iter()
                .find(|lv| a.iter().any(|x| s(x, "level") == *lv))
        })
        .unwrap_or("ok");
    let sending = list_of(r, "sending");
    Row {
        key: s(r, "name"),
        cells: vec![
            s(r, "name"),
            keys.join(", "),
            if sending.is_empty() { cell("", &[("none", Kind::Red)]) } else { sending.join(", ") },
            cell("", &[(worst, level_kind(worst))]),
            list_of(r, "used_by").join(", "),
        ],
        dimmed: false,
        section: false,
        tint: None,
    }
}

fn lsa_row(r: &Value) -> Row {
    let t = s(r, "type");
    let mut body = Vec::new();
    match t.as_str() {
        "router" => {
            body.push(format!("{} links", s(r, "links")));
            if flag(r, "abr") {
                body.push("ABR".into());
            }
            if flag(r, "asbr") {
                body.push("ASBR".into());
            }
        }
        "network" => body.push(format!("{} · {} routers", s(r, "prefix"), s(r, "routers"))),
        _ => {
            body.push(s(r, "prefix"));
            body.push(format!("metric {}", s(r, "metric")));
            if let Some(m) = r.get("metric_type") {
                body.push(format!("E{}", value_text(m)));
            }
        }
    }
    let area = s(r, "area");
    let mut type_chips = vec![(t.clone(), Kind::Neutral)];
    if flag(r, "self") {
        type_chips.push(("self".into(), Kind::Blue));
    }
    Row {
        key: format!("{}|{}|{}|{}", t, area, s(r, "id"), s(r, "originator")),
        cells: vec![
            chips(&type_chips),
            if area.is_empty() { "AS".into() } else { chips(&[area_chip(&area)]) },
            s(r, "id"),
            s(r, "originator"),
            s(r, "age"),
            s(r, "sequence"),
            body.join(" · "),
        ],
        dimmed: false,
        section: false,
        tint: None,
    }
}

fn route_row(r: &Value) -> Row {
    let hops: Vec<String> = r
        .get("nexthops")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|h| {
                    let addr = s(h, "address");
                    let i = s(h, "interface");
                    if addr.is_empty() { format!("directly · {i}") } else { format!("{addr} · {i}") }
                })
                .collect()
        })
        .unwrap_or_default();
    let area = s(r, "area");
    let kind = s(r, "kind");
    Row {
        key: s(r, "prefix"),
        cells: vec![
            s(r, "prefix"),
            cell("", &[(kind.as_str(), if kind.starts_with("ext") { Kind::Amber } else { Kind::Neutral })]),
            match r.get("type2_cost").filter(|v| !v.is_null()) {
                Some(t2) => format!("{} (+{})", value_text(t2), s(r, "cost")),
                None => s(r, "cost"),
            },
            if area.is_empty() { "–".into() } else { chips(&[area_chip(&area)]) },
            hops.join(", "),
        ],
        dimmed: false,
        section: false,
        tint: None,
    }
}

/// The modal's values of an existing row.
fn values_of(r: &Value, what: What) -> BTreeMap<&'static str, String> {
    let fields = match what {
        What::Instance => INST_FIELDS,
        What::Area => AREA_FIELDS,
        What::Template => TPL_FIELDS,
        What::Keychain => KC_FIELDS,
    };
    let mut out = BTreeMap::new();
    for f in fields {
        let v = match f.param {
            "auth_key" => String::new(),
            "disabled" | "passive" | "mtu_ignore" | "no_summaries" | "subscriber_pools" => {
                if flag(r, f.param) { "yes" } else { "no" }.to_owned()
            }
            "interfaces" | "networks" | "redistribute" => list_of(r, f.param).join(","),
            p => r.get(p).filter(|v| !v.is_null()).map(value_text).unwrap_or_default(),
        };
        out.insert(f.param, v);
    }
    out
}

/// The choices of a choice field.
fn options(param: &str, areas: &[String], instances: &[String], chains: &[String]) -> Vec<String> {
    let v: &[&str] = match param {
        "version" => &["2", "3"],
        "originate_default" => &["never", "if-installed", "always"],
        "type" if !areas.is_empty() && instances.is_empty() => &["broadcast", "ptp", "nbma", "ptmp", "virtual-link"],
        "type" => &["default", "stub", "nssa"],
        "nssa_translate" => &["candidate", "yes", "no"],
        "auth" => &["", "sha256", "sha384", "sha512", "sha1", "md5", "simple"],
        "area" => return areas.to_vec(),
        "instance" => return instances.to_vec(),
        "keychain" => {
            let mut c = vec![String::new()];
            c.extend(chains.iter().cloned());
            return c;
        }
        _ => &[],
    };
    v.iter().map(|x| (*x).to_owned()).collect()
}

impl OspfPanel {
    fn tabs(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        ui.horizontal_wrapped(|ui| {
            for (tab, label, key) in TABS {
                if ui.selectable_label(self.tab == tab, tr_in(SCOPE, l, label)).clicked() {
                    self.tab = tab;
                    app.cache.refreshed_at = None;
                }
                if help::info_button(ui, egui::Id::unique(("ospf-tab-help", key)), tr_in(SCOPE, l, label)).clicked() {
                    self.help = Some(HelpView::new(key, tr_in(SCOPE, l, label)));
                }
                ui.add_space(4.0);
            }
        });
    }

    fn column_help(&mut self, app: &CoreRouterUi, key: Option<&'static str>, columns: &[table::Column]) {
        if let Some(key) = key {
            let title = columns.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help = Some(HelpView::new(key, tr_in(SCOPE, app.lang.labels, title)));
        }
    }

    /// Instance picker of the LSDB, Routes and Topology tabs.
    fn instance_picker(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let names: Vec<String> = self.instances.iter().map(|r| s(r, "name")).collect();
        if (self.instance.is_empty() || !names.contains(&self.instance))
            && let Some(first) = names.first()
        {
            self.instance = first.clone();
        }
        ui.label(tr_in(SCOPE, l, "Instance"));
        egui::ComboBox::from_id_salt("ospf-instance").selected_text(self.instance.clone()).show_ui(ui, |ui| {
            for n in &names {
                if ui.selectable_value(&mut self.instance, n.clone(), n).clicked() {
                    app.cache.refreshed_at = None;
                }
            }
        });
    }

    fn source_note(&self, app: &CoreRouterUi, ui: &mut Ui, v: &Value) {
        let l = app.lang.labels;
        if flag(v, "pending") {
            ui.weak(tr_in(SCOPE, l, "Reading the database from the routing daemon…"));
        }
        if let Some(e) = v.get("error").filter(|e| !e.is_null()) {
            ui.colored_label(ui.visuals().error_fg_color, value_text(e));
        }
        if s(v, "source") == "virtual lab sample" {
            chip::chip(ui, tr_in(SCOPE, l, "virtual lab sample"), chip::AMBER.tone(ui.visuals()));
        }
    }

    fn neighbors_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let data = rows_of(&self.neighbors);
        let rows: Vec<Row> = data.iter().map(nbr_row).collect();
        let selection = self.nbr_table.selection(&rows);
        ui.horizontal(|ui| {
            self.source_note(app, ui, &self.neighbors.clone());
            table::find_field(ui, NBR, &mut self.nbr_table);
        });
        ui.separator();
        let picked = selection.as_slice().first().and_then(|k| data.iter().zip(&rows).find(|(_, r)| &r.key == k)).map(|(d, _)| d.clone());
        let detail_h = if picked.is_some() { 190.0 } else { 0.0 };
        let footer_h = ui.spacing().interact_size.y + 6.0 + detail_h;
        let out = table::show(ui, NBR, footer_h, &mut self.nbr_table, &NBR_COLUMNS, &rows, |_, _| {});
        self.column_help(app, out.help, &NBR_COLUMNS);
        if let Some(r) = picked {
            ui.separator();
            self.neighbor_detail(app, ui, &r);
        }
        let v = ui.visuals().clone();
        let full = data.iter().filter(|r| s(r, "state") == "Full").count();
        list::footer(
            ui,
            &[
                (data.len(), "neighbors", chip::neutral_tone(&v)),
                (full, "full", chip::GREEN.tone(&v)),
                (data.len() - full, "not full", chip::AMBER.tone(&v)),
            ],
            l,
        );
        if data.is_empty() {
            ui.weak(tr_in(SCOPE, l, "No neighbor: add an instance, an area and an interface template."));
        }
    }

    fn neighbor_detail(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, r: &Value) {
        let l = app.lang.labels;
        let iface = s(r, "interface");
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("{} · {}", s(r, "router_id"), iface)).strong());
            ui.weak(format!(
                "{} {} · {} {} · {} {}",
                tr_in(SCOPE, l, "priority"),
                s(r, "priority"),
                tr_in(SCOPE, l, "dead in"),
                s(r, "dead_secs"),
                tr_in(SCOPE, l, "retransmit"),
                s(r, "retransmit"),
            ));
            let can = app.can.check("routing.ospf.neighbor.diagnose");
            let tip = tr_in(SCOPE, l, "Why this neighbor is not Full, with the RFC section that says so");
            match can {
                Ok(()) => {
                    if ui.button(tr_in(SCOPE, l, "Diagnose")).on_hover_text(tip).clicked() {
                        self.diagnose_of = Some(iface.clone());
                        self.diagnose = Value::Null;
                        app.cache.refreshed_at = None;
                    }
                }
                Err(why) => {
                    ui.add_enabled(false, egui::Button::new(tr_in(SCOPE, l, "Diagnose"))).on_disabled_hover_text(why);
                }
            }
            if help::info_button(ui, egui::Id::unique("ospf-diagnose-help"), tr_in(SCOPE, l, "Diagnose")).clicked() {
                self.help = Some(HelpView::new("ospf.diagnose", tr_in(SCOPE, l, "Diagnose")));
            }
        });
        if self.diagnose_of.as_deref() != Some(iface.as_str()) {
            return;
        }
        let findings = self.diagnose.get("findings").and_then(Value::as_array).cloned().unwrap_or_default();
        if findings.is_empty() {
            ui.weak(tr_in(SCOPE, l, "Diagnosing…"));
        }
        egui::ScrollArea::vertical().id_salt("ospf-diagnose").max_height(150.0).show(ui, |ui| {
            for f in findings {
                ui.horizontal_wrapped(|ui| {
                    let lv = s(&f, "level");
                    chip::chip(ui, &lv, level_kind(&lv).tone(ui.visuals()));
                    ui.label(s(&f, "message"));
                    let rfc = s(&f, "rfc");
                    if !rfc.is_empty() {
                        chip::chip(ui, &rfc, chip::BLUE.tone(ui.visuals()));
                    }
                });
            }
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn list_tab(
        &mut self,
        app: &mut CoreRouterUi,
        ui: &mut Ui,
        what: What,
        salt: &'static str,
        columns: &[table::Column],
        key_field: &str,
        footer_what: &'static str,
    ) {
        let l = app.lang.labels;
        let (data, cmds, rowf): (Vec<Value>, Cmds, fn(&Value) -> Row) = match what {
            What::Instance => (self.instances.clone(), INST_CMDS, inst_row),
            What::Area => (self.areas.clone(), AREA_CMDS, area_row),
            What::Template => (self.templates.clone(), TPL_CMDS, tpl_row),
            What::Keychain => (self.keychains.clone(), KC_CMDS, kc_row),
        };
        let rows: Vec<Row> = data.iter().map(rowf).collect();
        let table = match what {
            What::Instance => &mut self.inst_table,
            What::Area => &mut self.area_table,
            What::Template => &mut self.tpl_table,
            What::Keychain => &mut self.kc_table,
        };
        let selection = table.selection(&rows);
        let picked: Vec<Item> = data.iter().filter(|r| selection.contains(&s(r, key_field))).map(|r| Item::of(r, key_field, "")).collect();
        let mut tools = Tools::new(&app.can(), &cmds, &picked);
        if what == What::Keychain {
            let none = Err("a key chain is not enabled or disabled: the templates using it are".to_owned());
            tools.enable = none.clone();
            tools.disable = none;
        }
        let mut act = None;
        ui.horizontal(|ui| {
            act = list::toolbar(ui, salt, &tools, &selection, l);
            table::find_field(ui, salt, table);
        });
        ui.separator();
        let known = !app.cache.commands.is_empty();
        let detail_h = if what == What::Template || what == What::Keychain { 120.0 } else { 0.0 };
        let footer_h = ui.spacing().interact_size.y + 6.0 + detail_h;
        let out = table::show(ui, salt, footer_h, table, columns, &rows, |ui, menu| match menu {
            Menu::Rows(sel) => {
                if let Some(a) = list::row_menu(ui, &tools, sel, known, l) {
                    act = Some(a);
                }
            }
            Menu::Empty => {
                if table::action(ui, tr_in(SCOPE, l, "New…"), tools.add.clone()) {
                    act = Some(Act::Add);
                }
            }
        });
        let help_key = out.help;
        act = act.or_else(|| list::from_shortcut(out.shortcut, &tools, &selection)).or_else(|| out.opened.or(out.comment).map(Act::Edit));
        self.column_help(app, help_key, columns);
        // The selected template's warnings and the key chain's rotation.
        if let Some(k) = selection.as_slice().first()
            && let Some(r) = data.iter().find(|r| &s(r, key_field) == k)
        {
            let lines: Vec<(String, String)> = match what {
                What::Template => list_of(r, "warnings").into_iter().map(|w| ("warning".to_owned(), w)).collect(),
                What::Keychain => r
                    .get("rotation")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().map(|x| (s(x, "level"), s(x, "message"))).collect())
                    .unwrap_or_default(),
                _ => Vec::new(),
            };
            if !lines.is_empty() {
                ui.separator();
                egui::ScrollArea::vertical().id_salt(("ospf-detail", salt)).max_height(100.0).show(ui, |ui| {
                    for (lv, m) in lines {
                        ui.horizontal_wrapped(|ui| {
                            chip::chip(ui, &lv, level_kind(&lv).tone(ui.visuals()));
                            ui.label(m);
                        });
                    }
                });
            }
        }
        let v = ui.visuals().clone();
        let disabled = data.iter().filter(|r| flag(r, "disabled")).count();
        list::footer(ui, &[(data.len(), footer_what, chip::neutral_tone(&v)), (disabled, "disabled", chip::neutral_tone(&v))], l);
        if let Some(a) = act {
            self.act(app, a, ui, &rows, what, &data, key_field);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn act(&mut self, app: &mut CoreRouterUi, act: Act, ui: &Ui, rows: &[Row], what: What, data: &[Value], key_field: &str) {
        let cmds = match what {
            What::Instance => INST_CMDS,
            What::Area => AREA_CMDS,
            What::Template => TPL_CMDS,
            What::Keychain => KC_CMDS,
        };
        let row_of = |k: &str| data.iter().find(|r| s(r, key_field) == k).cloned();
        let title_of = |r: &Value| match what {
            What::Template => format!("{} {}", s(r, "id"), s(r, "area")),
            _ => s(r, key_field),
        };
        match act {
            Act::Add => {
                if self.modal.is_none() {
                    let mut values = BTreeMap::new();
                    match what {
                        What::Instance => {
                            values.insert("version", "2".to_owned());
                            values.insert("vrf", "main".to_owned());
                            values.insert("originate_default", "never".to_owned());
                        }
                        What::Area => {
                            values.insert("type", "default".to_owned());
                            values.insert("nssa_translate", "candidate".to_owned());
                            if let Some(i) = self.instances.first() {
                                values.insert("instance", s(i, "name"));
                            }
                        }
                        What::Template => {
                            values.insert("type", "broadcast".to_owned());
                            values.insert("auth", "sha256".to_owned());
                            if let Some(a) = self.areas.first() {
                                values.insert("area", s(a, "name"));
                            }
                        }
                        What::Keychain => {}
                    }
                    self.modal = Some((what, Modal::open(app, None, values)));
                }
            }
            Act::Edit(k) => self.edit(app, what, row_of(&k), &k, title_of),
            Act::Comment(keys) => {
                if let Some(k) = keys.first() {
                    self.edit(app, what, row_of(k), k, title_of);
                }
            }
            Act::Remove(keys) => {
                let steps: Vec<Value> = keys.iter().map(|k| json!({"command": cmds.remove, "params": {"id": k}})).collect();
                app.run_steps(steps, Then::Nothing);
            }
            Act::Enable(ref keys) | Act::Disable(ref keys) => {
                if let Some(set) = cmds.set {
                    let to = matches!(act, Act::Disable(_));
                    let steps: Vec<Value> = keys.iter().map(|k| json!({"command": set, "params": {"id": k, "disabled": to}})).collect();
                    app.run_steps(steps, Then::Nothing);
                }
            }
            Act::Copy(keys) => {
                let picked: Vec<&Row> = rows.iter().filter(|r| keys.contains(&r.key)).collect();
                ui.ctx().copy_text(list::copy_rows(&picked));
            }
            Act::CopyAs(keys, syntax) => {
                let picked: Vec<Value> = keys.iter().filter_map(|k| row_of(k)).map(|r| recreate(&r, what)).collect();
                let refs: Vec<&Value> = picked.iter().collect();
                ui.ctx().copy_text(list::copy_commands(app, cmds.add, &refs, syntax));
            }
        }
    }

    fn edit(&mut self, app: &mut CoreRouterUi, what: What, row: Option<Value>, key: &str, title: impl Fn(&Value) -> String) {
        if let Some((_, m)) = &mut self.modal {
            m.status.bring_to_front();
        } else if let Some(r) = row {
            self.modal = Some((what, Modal::open(app, Some((key.to_owned(), title(&r))), values_of(&r, what))));
        }
    }

    fn lsdb_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        ui.horizontal(|ui| {
            self.instance_picker(app, ui);
            ui.separator();
            for (t, label) in [("", "All")].into_iter().chain(LSA_TYPES) {
                if ui.selectable_label(self.lsa_type == t, tr_in(SCOPE, l, label)).clicked() {
                    self.lsa_type = t.to_owned();
                    self.lsa_page = 0;
                    app.cache.refreshed_at = None;
                }
            }
            table::find_field(ui, LSDB, &mut self.lsa_table);
        });
        ui.horizontal(|ui| self.source_note(app, ui, &self.lsas.clone()));
        ui.separator();
        let data = rows_of(&self.lsas);
        let rows: Vec<Row> = data.iter().map(lsa_row).collect();
        let footer_h = ui.spacing().interact_size.y * 2.0 + 8.0;
        let out = table::show(ui, LSDB, footer_h, &mut self.lsa_table, &LSA_COLUMNS, &rows, |_, _| {});
        self.column_help(app, out.help, &LSA_COLUMNS);
        let total = self.lsas.get("total").and_then(Value::as_u64).unwrap_or(0);
        ui.horizontal(|ui| {
            let pages = total.div_ceil(200).max(1);
            if ui.add_enabled(self.lsa_page > 0, egui::Button::new("◀")).clicked() {
                self.lsa_page -= 1;
                app.cache.refreshed_at = None;
            }
            ui.label(format!("{} / {pages}", self.lsa_page + 1));
            if ui.add_enabled(u64::from(self.lsa_page + 1) < pages, egui::Button::new("▶")).clicked() {
                self.lsa_page += 1;
                app.cache.refreshed_at = None;
            }
        });
        let v = ui.visuals().clone();
        let by = self.lsas.get("by_type").cloned().unwrap_or(Value::Null);
        let n = |k: &str| by.get(k).and_then(Value::as_u64).unwrap_or(0) as usize;
        list::footer(
            ui,
            &[
                (total as usize, "LSAs", chip::neutral_tone(&v)),
                (n("router"), "router", chip::neutral_tone(&v)),
                (n("network"), "network", chip::neutral_tone(&v)),
                (n("external"), "external", chip::AMBER.tone(&v)),
            ],
            l,
        );
    }

    fn routes_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        ui.horizontal(|ui| {
            self.instance_picker(app, ui);
            ui.separator();
            table::find_field(ui, ROUTES, &mut self.route_table);
        });
        ui.horizontal(|ui| self.source_note(app, ui, &self.routes.clone()));
        self.path_bar(app, ui);
        ui.separator();
        let data = rows_of(&self.routes);
        let rows: Vec<Row> = data.iter().map(route_row).collect();
        let selection = self.route_table.selection(&rows);
        let path_h = if self.path.get("hops").is_some() { 130.0 } else { 0.0 };
        let footer_h = ui.spacing().interact_size.y + 6.0 + path_h;
        let out = table::show(ui, ROUTES, footer_h, &mut self.route_table, &ROUTE_COLUMNS, &rows, |_, _| {});
        self.column_help(app, out.help, &ROUTE_COLUMNS);
        if let Some(k) = selection.as_slice().first()
            && k.as_str() != self.path_asked.as_deref().unwrap_or("")
            && let Some(addr) = k.split('/').next()
        {
            // Selecting a route asks why its path is the one.
            self.path_to = addr.to_owned();
            self.path_asked = Some(k.clone());
            app.cache.refreshed_at = None;
        }
        if self.path.get("hops").is_some() {
            ui.separator();
            self.path_view(app, ui);
        }
        let v = ui.visuals().clone();
        list::footer(
            ui,
            &[
                (data.len(), "routes", chip::neutral_tone(&v)),
                (list::count(&data, "kind", "intra-area"), "intra-area", chip::neutral_tone(&v)),
                (list::count(&data, "kind", "inter-area"), "inter-area", chip::BLUE.tone(&v)),
                (data.iter().filter(|r| s(r, "kind").starts_with("ext")).count(), "external", chip::AMBER.tone(&v)),
            ],
            l,
        );
    }

    /// The "Why this path?" input.
    pub(crate) fn path_bar(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        ui.horizontal(|ui| {
            ui.label(tr_in(SCOPE, l, "Why this path?"));
            if help::info_button(ui, egui::Id::unique("ospf-path-help"), tr_in(SCOPE, l, "Why this path?")).clicked() {
                self.help = Some(HelpView::new("ospf.path", tr_in(SCOPE, l, "Why this path?")));
            }
            let r = ui.add(egui::TextEdit::singleline(&mut self.path_to).hint_text("10.0.0.1").desired_width(140.0));
            if (r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))) || ui.button(tr_in(SCOPE, l, "Show")).clicked() {
                self.path_asked = Some(self.path_to.clone());
                app.cache.refreshed_at = None;
            }
        });
    }

    /// The path: the cost added hop by hop, and the daemon's own route.
    pub(crate) fn path_view(&self, app: &CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let hops = self.path.get("hops").and_then(Value::as_array).cloned().unwrap_or_default();
        if let Some(e) = self.path.get("error").filter(|e| !e.is_null()) {
            ui.weak(value_text(e));
        }
        ui.horizontal_wrapped(|ui| {
            for (i, h) in hops.iter().enumerate() {
                if i > 0 {
                    ui.weak(format!("— {} —", s(h, "cost")));
                }
                let kind = if s(h, "kind") == "network" { Kind::Neutral } else { Kind::Blue };
                chip::chip(ui, &s(h, "id"), kind.tone(ui.visuals()));
                ui.weak(format!("Σ {}", s(h, "total")));
            }
        });
        if let Some(r) = self.path.get("route").filter(|r| !r.is_null()) {
            let agrees = self.path.get("agrees").and_then(Value::as_bool);
            ui.horizontal(|ui| {
                ui.weak(format!("{} {} · {} · {} {}", tr_in(SCOPE, l, "daemon's route"), s(r, "prefix"), s(r, "kind"), tr_in(SCOPE, l, "cost"), s(r, "cost")));
                match agrees {
                    Some(true) => {
                        chip::chip(ui, tr_in(SCOPE, l, "agrees"), chip::GREEN.tone(ui.visuals()));
                    }
                    Some(false) => {
                        chip::chip(ui, tr_in(SCOPE, l, "differs"), chip::AMBER.tone(ui.visuals()));
                    }
                    None => {}
                }
            });
        }
    }
}

/// The `add` parameters that recreate a row (the key stays out).
fn recreate(r: &Value, what: What) -> Value {
    let keys: &[&str] = match what {
        What::Instance => &["name", "version", "vrf", "router_id", "redistribute", "out_filter_chain", "originate_default", "subscriber_pools", "disabled", "comment"],
        What::Area => &["name", "instance", "area_id", "type", "no_summaries", "default_cost", "nssa_translate", "disabled", "comment"],
        What::Template => &["area", "interfaces", "networks", "type", "cost", "priority", "hello_interval", "dead_interval", "passive", "mtu_ignore", "auth", "auth_id", "keychain", "bfd", "disabled", "comment"],
        What::Keychain => &["name", "comment"],
    };
    let mut o = serde_json::Map::new();
    for k in keys {
        if let Some(v) = r.get(*k).filter(|v| !v.is_null() && v.as_str() != Some("") && v.as_array().is_none_or(|a| !a.is_empty())) {
            o.insert((*k).to_owned(), v.clone());
        }
    }
    Value::Object(o)
}

impl PanelState for OspfPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.open.contains(&Win::Panel(WIN)) {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut q = |key: &'static str, command: &'static str, params: Value| {
            if app.has_command(command) {
                out.push(Query { key, command, params });
            }
        };
        q("instances", "routing.ospf.instance.list", json!({}));
        match self.tab {
            Tab::Neighbors => {
                q("neighbors", "routing.ospf.neighbor.list", json!({}));
                if let Some(i) = &self.diagnose_of {
                    q("diagnose", "routing.ospf.neighbor.diagnose", json!({"interface": i}));
                }
            }
            Tab::Areas => q("areas", "routing.ospf.area.list", json!({})),
            Tab::Templates => {
                q("templates", "routing.ospf.interface-template.list", json!({}));
                q("areas", "routing.ospf.area.list", json!({}));
                q("keychains", "routing.ospf.keychain.list", json!({}));
            }
            Tab::Keychains => q("keychains", "routing.ospf.keychain.list", json!({})),
            Tab::Lsdb if !self.instance.is_empty() => {
                let mut p = json!({"instance": self.instance, "offset": self.lsa_page * 200, "limit": 200});
                if !self.lsa_type.is_empty()
                    && let Some(o) = p.as_object_mut()
                {
                    o.insert("type".into(), json!(self.lsa_type));
                }
                q("lsas", "routing.ospf.lsa.list", p);
            }
            Tab::Routes | Tab::Topology if !self.instance.is_empty() => {
                if self.tab == Tab::Routes {
                    q("routes", "routing.ospf.route.list", json!({"instance": self.instance}));
                } else {
                    let mut p = json!({"instance": self.instance});
                    if !self.topo.area.is_empty()
                        && let Some(o) = p.as_object_mut()
                    {
                        o.insert("area".into(), json!(self.topo.area));
                    }
                    q("topology", "routing.ospf.topology", p);
                    q("neighbors", "routing.ospf.neighbor.list", json!({}));
                }
                if let Some(to) = self.path_asked.as_ref().filter(|t| !t.is_empty()) {
                    let to = to.split('/').next().unwrap_or(to);
                    q("path", "routing.ospf.path", json!({"instance": self.instance, "to": to}));
                }
            }
            _ => {}
        }
        out
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        if key == list_modal::PREVIEW {
            if let Some((_, m)) = &mut self.modal {
                m.arrived(value);
            }
            return;
        }
        let arr = |v: Value| match v {
            Value::Array(a) => a,
            _ => Vec::new(),
        };
        match key {
            "instances" => self.instances = arr(value),
            "areas" => self.areas = arr(value),
            "templates" => self.templates = arr(value),
            "keychains" => self.keychains = arr(value),
            "neighbors" => self.neighbors = value,
            "diagnose" => self.diagnose = value,
            "lsas" => self.lsas = value,
            "routes" => self.routes = value,
            "topology" => {
                self.topo.arrived(&value);
                self.topology = value;
            }
            "path" => self.path = value,
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        self.tabs(app, ui);
        ui.separator();
        match self.tab {
            Tab::Neighbors => self.neighbors_tab(app, ui),
            Tab::Instances => self.list_tab(app, ui, What::Instance, INST, &INST_COLUMNS, "name", "instances"),
            Tab::Areas => self.list_tab(app, ui, What::Area, AREAS, &AREA_COLUMNS, "name", "areas"),
            Tab::Templates => self.list_tab(app, ui, What::Template, TPL, &TPL_COLUMNS, "id", "templates"),
            Tab::Keychains => self.list_tab(app, ui, What::Keychain, KC, &KC_COLUMNS, "name", "key chains"),
            Tab::Lsdb => self.lsdb_tab(app, ui),
            Tab::Routes => self.routes_tab(app, ui),
            Tab::Topology => crate::ospf_topology::tab(self, app, ui),
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        if let Some((what, m)) = &mut self.modal {
            let areas: Vec<String> = self.areas.iter().map(|r| s(r, "name")).collect();
            let instances: Vec<String> = self.instances.iter().map(|r| s(r, "name")).collect();
            let chains: Vec<String> = self.keychains.iter().map(|r| s(r, "name")).collect();
            let spec = match what {
                What::Instance => &INST_SPEC,
                What::Area => &AREA_SPEC,
                What::Template => &TPL_SPEC,
                What::Keychain => &KC_SPEC,
            };
            let w = *what;
            let open = m.show(app, ctx, area, spec, &|p| match (w, p) {
                (What::Template, "type") => options(p, &areas, &[], &chains),
                (What::Area, "type") => options(p, &[], &instances, &chains),
                _ => options(p, &areas, &instances, &chains),
            });
            if !open {
                self.modal = None;
            }
        }
        help::modal(ctx, app.lang, &mut self.help);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        if let Some(a) = then.downcast_ref::<Applied>()
            && let Some((_, m)) = self.modal.as_mut().filter(|(_, m)| m.id == a.0)
            && m.replied(app, result)
        {
            self.modal = None;
        }
        app.cache.refreshed_at = None;
    }

    fn escape(&mut self, _win: &'static str) -> bool {
        match self.tab {
            Tab::Neighbors => self.nbr_table.escape(),
            Tab::Instances => self.inst_table.escape(),
            Tab::Areas => self.area_table.escape(),
            Tab::Templates => self.tpl_table.escape(),
            Tab::Keychains => self.kc_table.escape(),
            Tab::Lsdb => self.lsa_table.escape(),
            Tab::Routes => self.route_table.escape(),
            Tab::Topology => false,
        }
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        vec![
            (NBR, &self.nbr_table),
            (INST, &self.inst_table),
            (AREAS, &self.area_table),
            (TPL, &self.tpl_table),
            (KC, &self.kc_table),
            (LSDB, &self.lsa_table),
            (ROUTES, &self.route_table),
        ]
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        vec![
            (NBR, &mut self.nbr_table),
            (INST, &mut self.inst_table),
            (AREAS, &mut self.area_table),
            (TPL, &mut self.tpl_table),
            (KC, &mut self.kc_table),
            (LSDB, &mut self.lsa_table),
            (ROUTES, &mut self.route_table),
        ]
    }
}

impl OspfPanel {
    /// Tests: press + on the list of `what`.
    #[cfg(test)]
    pub(crate) fn add_for_test(&mut self, app: &mut CoreRouterUi, what: What, ui: &Ui) {
        self.act(app, Act::Add, ui, &[], what, &[], "name");
    }

    /// Every explanation key the window uses (the catalog test).
    #[cfg(test)]
    pub(crate) fn help_keys() -> Vec<&'static str> {
        let mut out: Vec<&'static str> = TABS.iter().map(|(_, _, k)| *k).collect();
        for c in NBR_COLUMNS.iter().chain(&INST_COLUMNS).chain(&AREA_COLUMNS).chain(&TPL_COLUMNS).chain(&KC_COLUMNS).chain(&LSA_COLUMNS).chain(&ROUTE_COLUMNS) {
            out.push(c.help);
        }
        for f in INST_FIELDS.iter().chain(AREA_FIELDS).chain(TPL_FIELDS).chain(KC_FIELDS) {
            out.push(f.help);
        }
        out.extend([INST_SPEC.help, AREA_SPEC.help, TPL_SPEC.help, KC_SPEC.help, "ospf.diagnose", "ospf.path", "ospf.topology.legend"]);
        out.retain(|k| !k.is_empty());
        out.sort_unstable();
        out.dedup();
        out
    }
}
