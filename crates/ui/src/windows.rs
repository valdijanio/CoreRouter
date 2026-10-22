//! The floating windows (WinBox MDI style) and the side menu layout.

use egui::{Grid, RichText, TextEdit};
use serde_json::{Value, json};

use crate::{CoreRouterUi, err_color, human_bytes, value_text};

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
            Win::Interfaces | Win::Addresses | Win::Log => [640.0, 260.0],
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
        let mut action: Option<(String, bool)> = None;
        Grid::new("interfaces").striped(true).show(ui, |ui| {
            for h in [
                "", "Name", "Type", "MTU", "Rx", "Tx", "Rx pkt", "Tx pkt", "Comment", "",
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
                ui.label(get("comment"));
                let btn = if disabled { "Enable" } else { "Disable" };
                if ui.small_button(btn).clicked() {
                    action = Some((get("name"), !disabled));
                }
                ui.end_row();
            }
        });
        if let Some((name, disabled)) = action {
            self.run("interface.set", json!({"name": name, "disabled": disabled}));
        }
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
        let names: Vec<String> = self
            .cache
            .interfaces
            .iter()
            .filter_map(|r| r.get("name").and_then(Value::as_str).map(str::to_owned))
            .collect();
        let mut add = false;
        ui.horizontal(|ui| {
            ui.add(
                TextEdit::singleline(&mut self.forms.addr_address)
                    .hint_text("10.0.0.1/24")
                    .desired_width(140.0),
            );
            egui::ComboBox::from_id_salt("addr-iface")
                .selected_text(if self.forms.addr_interface.is_empty() {
                    "interface"
                } else {
                    self.forms.addr_interface.as_str()
                })
                .show_ui(ui, |ui| {
                    for n in &names {
                        ui.selectable_value(&mut self.forms.addr_interface, n.clone(), n);
                    }
                });
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
