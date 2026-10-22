//! The floating windows (WinBox MDI style) and the side menu layout.

use egui::{Grid, RichText, TextEdit};
use serde_json::{Value, json};

use crate::{CoreRouterUi, err_color, form_number, human_bytes, value_text};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Win {
    Interfaces,
    Addresses,
    Routes,
    Firewall,
    Dns,
    Dhcp,
    Bgp,
    Ospf,
    Mpls,
    Cgnat,
    Identity,
    History,
    Log,
}

/// Side menu: (group, items). A group with one item of the same name is a leaf.
pub(crate) const MENU: &[(&str, &[Win])] = &[
    ("Interfaces", &[Win::Interfaces]),
    (
        "IP",
        &[
            Win::Addresses,
            Win::Routes,
            Win::Firewall,
            Win::Dns,
            Win::Dhcp,
        ],
    ),
    ("Routing", &[Win::Bgp, Win::Ospf]),
    ("MPLS", &[Win::Mpls]),
    ("CGNAT", &[Win::Cgnat]),
    ("System", &[Win::Identity, Win::History]),
    ("Log", &[Win::Log]),
];

impl Win {
    pub const ALL: &'static [Win] = &[
        Win::Interfaces,
        Win::Addresses,
        Win::Routes,
        Win::Firewall,
        Win::Dns,
        Win::Dhcp,
        Win::Bgp,
        Win::Ospf,
        Win::Mpls,
        Win::Cgnat,
        Win::Identity,
        Win::History,
        Win::Log,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Win::Interfaces => "Interfaces",
            Win::Addresses => "Addresses",
            Win::Routes => "Routes",
            Win::Firewall => "Firewall",
            Win::Dns => "DNS",
            Win::Dhcp => "DHCP Server",
            Win::Bgp => "BGP",
            Win::Ospf => "OSPF",
            Win::Mpls => "MPLS",
            Win::Cgnat => "CGNAT",
            Win::Identity => "Identity",
            Win::History => "History",
            Win::Log => "Log",
        }
    }

    /// `Some(gap id)` while the area has no engine commands yet.
    pub fn gap(self) -> Option<&'static str> {
        match self {
            Win::Routes => Some("G1.5"),
            Win::Firewall => Some("G2.1"),
            Win::Cgnat => Some("G2.3"),
            Win::Ospf => Some("G3.4"),
            Win::Mpls => Some("G3.5"),
            Win::Dns => Some("G4.1"),
            Win::Dhcp => Some("G4.2"),
            _ => None,
        }
    }

    pub(crate) fn default_size(self) -> [f32; 2] {
        match self {
            Win::Interfaces => [780.0, 520.0],
            Win::Addresses | Win::Log => [640.0, 260.0],
            _ => [380.0, 200.0],
        }
    }
}

impl CoreRouterUi {
    pub(crate) fn window(&mut self, win: Win, ui: &mut egui::Ui) {
        if let Some(gap) = win.gap() {
            ui.label(format!("{} is not implemented yet.", win.title()));
            ui.weak(format!("Tracked in docs/gaps.md {gap}."));
            return;
        }
        match win {
            Win::Interfaces => self.interfaces(ui),
            Win::Addresses => self.addresses(ui),
            Win::Bgp => self.bgp(ui),
            Win::Identity => self.identity(ui),
            Win::History => self.history(ui),
            Win::Log => self.log_window(ui),
            _ => {}
        }
    }

    fn interfaces(&mut self, ui: &mut egui::Ui) {
        let mut toggle: Option<(String, bool)> = None;
        let mut remove: Option<String> = None;
        egui::ScrollArea::vertical()
            .id_salt("interfaces-table")
            .auto_shrink([false, false])
            .max_height((ui.available_height() - 110.0).max(80.0))
            .show(ui, |ui| {
                Grid::new("interfaces").striped(true).show(ui, |ui| {
                    for h in [
                        "", "Name", "Type", "MTU", "Rx", "Tx", "Rx pkt", "Tx pkt", "Info",
                        "Comment", "", "",
                    ] {
                        ui.strong(h);
                    }
                    ui.end_row();
                    for row in &self.cache.interfaces {
                        let get = |k: &str| row.get(k).map(value_text).unwrap_or_default();
                        let num = |k: &str| row.get(k).and_then(Value::as_u64).unwrap_or(0);
                        let disabled = row
                            .get("disabled")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        let running = row.get("running").and_then(Value::as_bool).unwrap_or(false);
                        // RouterOS flags: X = disabled, R = running.
                        ui.monospace(if disabled {
                            "X"
                        } else if running {
                            "R"
                        } else {
                            " "
                        });
                        ui.label(get("name"));
                        ui.label(get("type"));
                        ui.label(get("mtu"));
                        ui.label(human_bytes(num("rx_bytes")));
                        ui.label(human_bytes(num("tx_bytes")));
                        ui.label(num("rx_packets").to_string());
                        ui.label(num("tx_packets").to_string());
                        ui.label(interface_info(row));
                        ui.label(get("comment"));
                        let btn = if disabled { "Enable" } else { "Disable" };
                        if ui.small_button(btn).clicked() {
                            toggle = Some((get("name"), !disabled));
                        }
                        // Like WinBox: offered on every row; the engine
                        // explains why a physical or in-use port cannot go.
                        if ui.small_button("−").on_hover_text("Remove").clicked() {
                            remove = Some(get("name"));
                        }
                        ui.end_row();
                    }
                });
            });
        if let Some((name, disabled)) = toggle {
            self.run("interface.set", json!({"name": name, "disabled": disabled}));
        }
        if let Some(name) = remove {
            self.run("interface.remove", json!({ "name": name }));
        }
        ui.separator();
        self.interface_forms(ui);
    }

    fn interface_forms(&mut self, ui: &mut egui::Ui) {
        let names = self.interface_names(None);
        let bridges = self.interface_names(Some("bridge"));
        let (mut vlan, mut bridge, mut lo, mut port_add, mut port_remove) =
            (false, false, false, false, false);
        Grid::new("interface-forms").num_columns(2).show(ui, |ui| {
            ui.strong("VLAN");
            ui.horizontal(|ui| {
                ui.add(
                    TextEdit::singleline(&mut self.forms.vlan_name)
                        .hint_text("vlan100")
                        .desired_width(90.0),
                );
                combo(
                    ui,
                    "vlan-parent",
                    "parent",
                    &mut self.forms.vlan_parent,
                    &names,
                );
                ui.add(
                    TextEdit::singleline(&mut self.forms.vlan_id)
                        .hint_text("VLAN id")
                        .desired_width(70.0),
                );
                ui.add(
                    TextEdit::singleline(&mut self.forms.vlan_mtu)
                        .hint_text("MTU")
                        .desired_width(50.0),
                );
                vlan = ui.button("Add VLAN").clicked();
            });
            ui.end_row();
            ui.strong("Bridge");
            ui.horizontal(|ui| {
                ui.add(
                    TextEdit::singleline(&mut self.forms.bridge_name)
                        .hint_text("bridge1")
                        .desired_width(90.0),
                );
                bridge = ui.button("Add Bridge").clicked();
                ui.separator();
                ui.add(
                    TextEdit::singleline(&mut self.forms.loopback_name)
                        .hint_text("lo0")
                        .desired_width(90.0),
                );
                lo = ui.button("Add Loopback").clicked();
            });
            ui.end_row();
            ui.strong("Port");
            ui.horizontal(|ui| {
                combo(
                    ui,
                    "port-bridge",
                    "bridge",
                    &mut self.forms.port_bridge,
                    &bridges,
                );
                combo(
                    ui,
                    "port-iface",
                    "interface",
                    &mut self.forms.port_interface,
                    &names,
                );
                port_add = ui.button("Add Port").clicked();
                port_remove = ui.button("Remove Port").clicked();
            });
            ui.end_row();
        });
        if vlan {
            self.add_vlan();
        }
        if bridge {
            self.add_bridge();
        }
        if lo {
            let p = json!({"name": self.forms.loopback_name.trim()});
            if self.run("interface.loopback.add", p).is_some() {
                self.forms.loopback_name.clear();
            }
        }
        if port_add {
            self.add_port();
        }
        if port_remove {
            let p =
                json!({"bridge": self.forms.port_bridge, "interface": self.forms.port_interface});
            self.run("interface.bridge.port.remove", p);
        }
    }

    pub(crate) fn add_vlan(&mut self) {
        let f = &self.forms;
        let p = json!({
            "name": f.vlan_name.trim(),
            "parent": f.vlan_parent,
            "vlan_id": form_number(&f.vlan_id),
            "mtu": form_number(&f.vlan_mtu),
        });
        if self.run("interface.vlan.add", p).is_some() {
            self.forms.vlan_name.clear();
            self.forms.vlan_id.clear();
            self.forms.vlan_mtu.clear();
        }
    }

    pub(crate) fn add_bridge(&mut self) {
        let p = json!({"name": self.forms.bridge_name.trim()});
        if self.run("interface.bridge.add", p).is_some() {
            self.forms.bridge_name.clear();
        }
    }

    pub(crate) fn add_port(&mut self) {
        let p = json!({"bridge": self.forms.port_bridge, "interface": self.forms.port_interface});
        self.run("interface.bridge.port.add", p);
    }

    /// Names from the cached `interface.list`, optionally of one type.
    fn interface_names(&self, kind: Option<&str>) -> Vec<String> {
        self.cache
            .interfaces
            .iter()
            .filter(|r| kind.is_none_or(|k| r.get("type").and_then(Value::as_str) == Some(k)))
            .filter_map(|r| r.get("name").and_then(Value::as_str).map(str::to_owned))
            .collect()
    }

    fn addresses(&mut self, ui: &mut egui::Ui) {
        let mut remove: Option<String> = None;
        Grid::new("addresses").striped(true).show(ui, |ui| {
            for h in ["#", "Address", "Network", "Interface", "Comment", ""] {
                ui.strong(h);
            }
            ui.end_row();
            for row in &self.cache.addresses {
                let get = |k: &str| row.get(k).map(value_text).unwrap_or_default();
                ui.monospace(get("id"));
                ui.label(get("address"));
                ui.label(get("network"));
                ui.label(get("interface"));
                ui.label(get("comment"));
                if ui.small_button("−").on_hover_text("Remove").clicked() {
                    remove = Some(get("id"));
                }
                ui.end_row();
            }
        });
        if let Some(id) = remove {
            self.run("ip.address.remove", json!({"id": id}));
        }

        ui.separator();
        let names = self.interface_names(None);
        let mut add = false;
        ui.horizontal(|ui| {
            ui.add(
                TextEdit::singleline(&mut self.forms.addr_address)
                    .hint_text("10.0.0.1/24")
                    .desired_width(140.0),
            );
            combo(
                ui,
                "addr-iface",
                "interface",
                &mut self.forms.addr_interface,
                &names,
            );
            ui.add(
                TextEdit::singleline(&mut self.forms.addr_comment)
                    .hint_text("comment")
                    .desired_width(120.0),
            );
            add = ui.button("Add").clicked();
        });
        if add {
            let comment = &self.forms.addr_comment;
            let p = json!({
                "address": self.forms.addr_address.trim(),
                "interface": self.forms.addr_interface,
                "comment": (!comment.is_empty()).then_some(comment),
            });
            if self.run("ip.address.add", p).is_some() {
                self.forms.addr_address.clear();
                self.forms.addr_comment.clear();
            }
        }
    }

    fn bgp(&mut self, ui: &mut egui::Ui) {
        Grid::new("bgp").striped(true).show(ui, |ui| {
            for h in ["Name", "AS", "Router ID", "Disabled"] {
                ui.strong(h);
            }
            ui.end_row();
            for row in &self.cache.bgp {
                let get = |k: &str| row.get(k).map(value_text).unwrap_or_default();
                ui.label(get("name"));
                ui.label(get("asn"));
                ui.label(get("router_id"));
                ui.label(get("disabled"));
                ui.end_row();
            }
        });
        ui.separator();
        let mut apply = false;
        Grid::new("bgp-form").num_columns(2).show(ui, |ui| {
            ui.label("Name");
            ui.text_edit_singleline(&mut self.forms.bgp_name);
            ui.end_row();
            ui.label("AS");
            ui.add(TextEdit::singleline(&mut self.forms.bgp_asn).hint_text("65000 or 1.10"));
            ui.end_row();
            ui.label("Router ID");
            ui.add(TextEdit::singleline(&mut self.forms.bgp_router_id).hint_text("10.255.0.1"));
            ui.end_row();
        });
        if ui.button("Apply").clicked() {
            apply = true;
        }
        if apply {
            let p = json!({
                "name": self.forms.bgp_name.trim(),
                "asn": self.forms.bgp_asn.trim(),
                "router_id": self.forms.bgp_router_id.trim(),
            });
            if let Some(r) = self.run("routing.bgp.instance.set", p) {
                self.forms.bgp_frr = r.get("frr").map(value_text).unwrap_or_default();
            }
        }
        if !self.forms.bgp_frr.is_empty() {
            ui.separator();
            ui.weak("Rendered for FRR bgpd:");
            ui.monospace(&self.forms.bgp_frr);
        }
    }

    fn identity(&mut self, ui: &mut egui::Ui) {
        if self.forms.identity.is_empty() {
            self.forms.identity = self
                .cache
                .summary
                .get("identity")
                .map(value_text)
                .unwrap_or_default();
        }
        let mut apply = false;
        ui.horizontal(|ui| {
            ui.label("Identity");
            ui.text_edit_singleline(&mut self.forms.identity);
            apply = ui.button("Apply").clicked();
        });
        if apply {
            let name = self.forms.identity.clone();
            self.run("system.identity.set", json!({ "name": name }));
        }
    }

    fn history(&mut self, ui: &mut egui::Ui) {
        let mode = self
            .cache
            .summary
            .get("mode")
            .map(value_text)
            .unwrap_or_default();
        let mut set_mode: Option<&str> = None;
        ui.horizontal(|ui| {
            ui.label("Commit mode:");
            for m in ["immediate", "transactional"] {
                if ui.radio(mode == m, m).clicked() && mode != m {
                    set_mode = Some(m);
                }
            }
        });
        if let Some(m) = set_mode {
            self.run("config.mode.set", json!({ "mode": m }));
        }
        if !self.cache.diff.is_empty() {
            ui.separator();
            ui.strong("Pending changes");
            for d in &self.cache.diff {
                ui.monospace(format!(
                    "{} {}",
                    d.get("op").map(value_text).unwrap_or_default(),
                    d.get("path").map(value_text).unwrap_or_default()
                ));
            }
        }
        ui.separator();
        let mut rollback: Option<u64> = None;
        Grid::new("history").striped(true).show(ui, |ui| {
            for h in ["Rev", "Comment", ""] {
                ui.strong(h);
            }
            ui.end_row();
            for rev in self.cache.history.iter().rev() {
                let n = rev.get("number").and_then(Value::as_u64).unwrap_or(0);
                ui.label(n.to_string());
                ui.label(rev.get("comment").map(value_text).unwrap_or_default());
                if ui.small_button("Rollback").clicked() {
                    rollback = Some(n);
                }
                ui.end_row();
            }
        });
        if let Some(n) = rollback {
            self.run("config.rollback", json!({ "revision": n }));
        }
    }

    fn log_window(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .show(ui, |ui| {
                for l in &self.log {
                    let text = RichText::new(format!("{}  {}", l.command, l.message)).monospace();
                    if l.ok {
                        ui.label(text);
                    } else {
                        ui.label(text.color(err_color(ui)));
                    }
                }
            });
    }
}

/// "vlan 100 on ether1", "port of bridge1" — from `interface.list` fields.
fn interface_info(row: &Value) -> String {
    let field = |k: &str| row.get(k).filter(|v| !v.is_null()).map(value_text);
    let mut parts = Vec::new();
    if let (Some(id), Some(parent)) = (field("vlan_id"), field("parent")) {
        parts.push(format!("vlan {id} on {parent}"));
    }
    if let Some(b) = field("bridge") {
        parts.push(format!("port of {b}"));
    }
    parts.join(", ")
}

/// Combo box over `options`; `hint` shows while nothing is picked.
fn combo(ui: &mut egui::Ui, id: &str, hint: &str, value: &mut String, options: &[String]) {
    egui::ComboBox::from_id_salt(id)
        .selected_text(if value.is_empty() {
            hint
        } else {
            value.as_str()
        })
        .show_ui(ui, |ui| {
            for n in options {
                ui.selectable_value(value, n.clone(), n);
            }
        });
}
