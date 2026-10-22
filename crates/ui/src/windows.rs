//! The floating windows (WinBox MDI style) and the side menu layout.

use egui::{Grid, RichText, TextEdit};
use serde_json::{Value, json};

use crate::table::{self, Icon, Menu, Row, Shortcut, action, col, comment};
use crate::{CoreRouterUi, err_color, value_text};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Win {
    Interfaces,
    InterfaceList,
    Addresses,
    DhcpClient,
    Dhcp6Client,
    Ipv6Pool,
    Ipv6Settings,
    Neighbors,
    Routes,
    Vrf,
    Firewall,
    Dns,
    Dhcp,
    Bgp,
    Ospf,
    Mpls,
    Cgnat,
    Identity,
    History,
    Ping,
    Mtr,
    Log,
}

/// Side menu: (group, items). A group with one item of the same name is a leaf.
pub(crate) const MENU: &[(&str, &[Win])] = &[
    ("Interfaces", &[Win::Interfaces, Win::InterfaceList]),
    (
        "IP",
        &[
            Win::Addresses,
            Win::DhcpClient,
            Win::Neighbors,
            Win::Routes,
            Win::Vrf,
            Win::Firewall,
            Win::Dns,
            Win::Dhcp,
        ],
    ),
    (
        "IPv6",
        &[Win::Dhcp6Client, Win::Ipv6Pool, Win::Ipv6Settings],
    ),
    ("Routing", &[Win::Bgp, Win::Ospf]),
    ("MPLS", &[Win::Mpls]),
    ("CGNAT", &[Win::Cgnat]),
    ("System", &[Win::Identity, Win::History]),
    ("Tools", &[Win::Ping, Win::Mtr]),
    ("Log", &[Win::Log]),
];

impl Win {
    pub const ALL: &'static [Win] = &[
        Win::Interfaces,
        Win::InterfaceList,
        Win::Addresses,
        Win::DhcpClient,
        Win::Dhcp6Client,
        Win::Ipv6Pool,
        Win::Ipv6Settings,
        Win::Neighbors,
        Win::Routes,
        Win::Vrf,
        Win::Firewall,
        Win::Dns,
        Win::Dhcp,
        Win::Bgp,
        Win::Ospf,
        Win::Mpls,
        Win::Cgnat,
        Win::Identity,
        Win::History,
        Win::Ping,
        Win::Mtr,
        Win::Log,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Win::Interfaces => "Interfaces",
            Win::InterfaceList => "Interface List",
            Win::Addresses => "Addresses",
            Win::DhcpClient => "DHCP Client",
            Win::Dhcp6Client => "DHCPv6 Client",
            Win::Ipv6Pool => "IPv6 Pool",
            Win::Ipv6Settings => "IPv6 Settings",
            Win::Neighbors => "Neighbors",
            Win::Routes => "Routes",
            Win::Vrf => "VRF",
            Win::Firewall => "Firewall",
            Win::Dns => "DNS",
            Win::Dhcp => "DHCP Server",
            Win::Bgp => "BGP",
            Win::Ospf => "OSPF",
            Win::Mpls => "MPLS",
            Win::Cgnat => "CGNAT",
            Win::Identity => "Identity",
            Win::History => "History",
            Win::Ping => "Ping",
            Win::Mtr => "MTR",
            Win::Log => "Log",
        }
    }

    /// `Some(gap id)` while the area has no engine commands yet.
    pub fn gap(self) -> Option<&'static str> {
        match self {
            Win::Cgnat => Some("G2.3"),
            Win::Ospf => Some("G3.4"),
            Win::Mpls => Some("G3.5"),
            Win::Dns => Some("G4.1"),
            Win::Dhcp => Some("G4.2"),
            _ => None,
        }
    }

    /// List windows close on Esc (after clearing find text and selection).
    pub(crate) fn closes_on_escape(self) -> bool {
        matches!(
            self,
            Win::Interfaces
                | Win::Addresses
                | Win::Routes
                | Win::Firewall
                | Win::InterfaceList
                | Win::Vrf
                | Win::Neighbors
                | Win::DhcpClient
                | Win::Dhcp6Client
                | Win::Ipv6Pool
                | Win::History
                | Win::Log
        )
    }

    pub(crate) fn default_size(self) -> [f32; 2] {
        match self {
            Win::Interfaces => [780.0, 520.0],
            Win::Neighbors => [820.0, 320.0],
            Win::Addresses | Win::Log => [640.0, 260.0],
            Win::Routes => [700.0, 320.0],
            Win::DhcpClient => [760.0, 260.0],
            Win::Dhcp6Client => [860.0, 260.0],
            Win::Ipv6Pool => [760.0, 220.0],
            Win::Ipv6Settings => [620.0, 340.0],
            Win::Vrf => [600.0, 260.0],
            Win::Firewall => [980.0, 420.0],
            Win::InterfaceList => [520.0, 280.0],
            Win::Ping => [900.0, 700.0],
            Win::Mtr => [860.0, 520.0],
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
            Win::Neighbors => self.neighbors(ui),
            Win::Routes => self.routes(ui),
            Win::DhcpClient => self.dhcp_clients(ui),
            Win::Dhcp6Client => self.dhcp6_clients(ui),
            Win::Ipv6Pool => self.ipv6_pools(ui),
            Win::Ipv6Settings => self.ipv6_settings(ui),
            Win::Vrf => self.vrfs(ui),
            Win::Firewall => self.firewall(ui),
            Win::InterfaceList => self.interface_lists(ui),
            Win::Bgp => self.bgp(ui),
            Win::Identity => self.identity(ui),
            Win::History => self.history(ui),
            Win::Log => self.log_window(ui),
            Win::Ping => self.ping_window(ui),
            Win::Mtr => self.mtr_window(ui),
            _ => {}
        }
    }

    /// Names from the cached `interface.list`, optionally of one type.
    pub(crate) fn interface_names(&self, kind: Option<&str>) -> Vec<String> {
        self.cache
            .interfaces
            .iter()
            .filter(|r| kind.is_none_or(|k| r.get("type").and_then(Value::as_str) == Some(k)))
            .filter_map(|r| r.get("name").and_then(Value::as_str).map(str::to_owned))
            .collect()
    }

    fn addresses(&mut self, ui: &mut egui::Ui) {
        const COLUMNS: [table::Column; 6] = [
            col(""),
            col("#"),
            col("Address"),
            col("Network"),
            col("Interface"),
            comment(),
        ];
        let rows: Vec<Row> = self
            .cache
            .addresses
            .iter()
            .map(|r| {
                let get = |k: &str| r.get(k).map(value_text).unwrap_or_default();
                Row {
                    key: get("id"),
                    cells: ["flags", "id", "address", "network", "interface", "comment"]
                        .map(get)
                        .to_vec(),
                    dimmed: r.get("disabled").and_then(Value::as_bool).unwrap_or(false),
                    section: false,
                    tint: None,
                }
            })
            .collect();
        let selection = self.tables.addresses.selection(&rows);
        let mut remove: Option<Vec<String>> = None;
        let mut select_all = false;
        let can = self.can();
        ui.horizontal(|ui| {
            let dynamic = self.cache.addresses.iter().any(|r| {
                r.get("dynamic").and_then(Value::as_bool).unwrap_or(false)
                    && selection.contains(&r.get("id").map(value_text).unwrap_or_default())
            });
            let picked = if selection.is_empty() {
                Err("Select one or more addresses first".to_owned())
            } else if dynamic {
                Err(
                    "Dynamic addresses come from a DHCP client: release or disable it \
                     (IP › DHCP Client)"
                        .to_owned(),
                )
            } else {
                Ok(())
            };
            let enabled = can.and("ip.address.remove", picked);
            if table::tool(ui, "addresses", Icon::Remove, "Remove", enabled).clicked() {
                remove = Some(selection.clone());
            }
            table::find_field(ui, "addresses", &mut self.tables.addresses);
        });
        ui.separator();
        let out = table::show(
            ui,
            "addresses",
            ui.spacing().interact_size.y * 2.0,
            &mut self.tables.addresses,
            &COLUMNS,
            &rows,
            |ui, menu| match menu {
                Menu::Rows(sel) => {
                    if action(ui, "Remove", can.check("ip.address.remove")) {
                        remove = Some(sel.to_vec());
                    }
                }
                Menu::Empty => {
                    select_all = ui.button("Select All").clicked();
                }
            },
        );
        if out.shortcut == Some(Shortcut::Remove) {
            remove = Some(self.tables.addresses.selection(&rows));
        }
        if select_all {
            self.tables.addresses.select_all(&rows);
        }
        for id in remove.unwrap_or_default() {
            self.run("ip.address.remove", json!({ "id": id }));
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
            add = action(ui, "Add", can.check("ip.address.add"));
        });
        if add {
            let comment = &self.forms.addr_comment;
            let p = json!({
                "address": self.forms.addr_address.trim(),
                "interface": self.forms.addr_interface,
                "comment": (!comment.is_empty()).then_some(comment),
            });
            self.run_then("ip.address.add", p, crate::Then::ClearAddressForm);
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
        if action(ui, "Apply", self.can.check("routing.bgp.instance.set")) {
            apply = true;
        }
        if apply {
            let p = json!({
                "name": self.forms.bgp_name.trim(),
                "asn": self.forms.bgp_asn.trim(),
                "router_id": self.forms.bgp_router_id.trim(),
            });
            self.run_then("routing.bgp.instance.set", p, crate::Then::ShowFrr);
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
        let can = self.can();
        ui.horizontal(|ui| {
            ui.label("Identity");
            ui.text_edit_singleline(&mut self.forms.identity);
            apply = action(ui, "Apply", can.check("system.identity.set"));
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
        let can = self.can();
        ui.horizontal(|ui| {
            ui.label("Commit mode:");
            let enabled = can.check("config.mode.set");
            for m in ["immediate", "transactional"] {
                let resp = ui.add_enabled(enabled.is_ok(), egui::RadioButton::new(mode == m, m));
                if let Err(why) = &enabled {
                    resp.on_disabled_hover_text(why.as_str());
                } else if resp.clicked() && mode != m {
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
                if action(ui, "Rollback", can.check("config.rollback")) {
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

/// Combo box over `options`; `hint` shows while nothing is picked.
pub(crate) fn combo(
    ui: &mut egui::Ui,
    id: &str,
    hint: &str,
    value: &mut String,
    options: &[String],
) {
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
