//! The floating windows (WinBox MDI style) and the side menu layout.

use egui::Grid;
use serde_json::{Value, json};

use crate::table::action;
use crate::{CoreRouterUi, value_text};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Win {
    Interfaces,
    InterfaceList,
    Addresses,
    Neighbors,
    Routes,
    Vrf,
    Firewall,
    Bgp,
    Identity,
    History,
    Ping,
    Mtr,
    /// A panel's window, by its `WinDef::id` (`panel.rs`): new windows are
    /// panels, so this enum and the menu below need no edit.
    Panel(&'static str),
}

/// Side menu groups, in order, with their built-in windows. A group with one
/// item of the same name is a leaf. Panels add their windows to their group;
/// inside a group the items are alphabetical (as in WinBox), so a new one
/// has no place to fight over.
pub(crate) const MENU: &[(&str, &[Win])] = &[
    ("Interfaces", &[Win::Interfaces, Win::InterfaceList]),
    // The PPP window is a panel (`ppp.rs`, G4.3d); RouterOS has it at the
    // top of the menu, after the interfaces.
    ("PPP", &[]),
    (
        "IP",
        &[
            Win::Addresses,
            Win::Neighbors,
            Win::Routes,
            Win::Vrf,
            Win::Firewall,
        ],
    ),
    ("IPv6", &[]),
    // OSPF is a panel (`ospf.rs`, G3.4).
    ("Routing", &[Win::Bgp]),
    // MPLS › LDP and Forwarding Table are panels (`mpls_ldp.rs`,
    // `mpls_forwarding.rs`, G3.5).
    ("MPLS", &[]),
    // The CGNAT window is a panel (`cgnat.rs`, G2.3d).
    ("CGNAT", &[]),
    // The RADIUS window is a panel (`radius.rs`, G4.3j); RouterOS has it
    // at the top of the menu too.
    ("RADIUS", &[]),
    ("System", &[Win::Identity, Win::History]),
    // The Queues window is a panel (`queues.rs`, G4.9c).
    ("Queues", &[]),
    ("Tools", &[Win::Ping, Win::Mtr]),
    // The Log window is a panel (`system_log.rs`, G4.6d).
    ("Log", &[]),
    // Preferences of this GUI, not of the router (G0.15, `settings.rs`).
    ("Settings", &[]),
];

/// The side menu as drawn: every group with its built-in and panel windows,
/// alphabetical; empty groups are left out.
pub(crate) fn menu() -> Vec<(&'static str, Vec<Win>)> {
    MENU.iter()
        .map(|(group, built_in)| {
            let mut items: Vec<Win> = built_in.to_vec();
            items.extend(
                crate::panel::all()
                    .iter()
                    .flat_map(|p| p.windows)
                    .filter(|w| w.group == *group)
                    .map(|w| Win::Panel(w.id)),
            );
            items.sort_by_key(|w| w.title().to_lowercase());
            (*group, items)
        })
        .filter(|(_, items)| !items.is_empty())
        .collect()
}

impl Win {
    /// The built-in windows (panels' come from `panel::all`).
    const BUILT_IN: &'static [Win] = &[
        Win::Interfaces,
        Win::InterfaceList,
        Win::Addresses,
        Win::Neighbors,
        Win::Routes,
        Win::Vrf,
        Win::Firewall,
        Win::Bgp,
        Win::Identity,
        Win::History,
        Win::Ping,
        Win::Mtr,
    ];

    /// Every window: the built-in ones, then the panels'.
    pub fn all() -> Vec<Win> {
        let mut out = Self::BUILT_IN.to_vec();
        out.extend(
            crate::panel::all()
                .iter()
                .flat_map(|p| p.windows)
                .map(|w| Win::Panel(w.id)),
        );
        out
    }

    pub fn title(self) -> &'static str {
        match self {
            Win::Interfaces => "Interfaces",
            Win::InterfaceList => "Interface List",
            Win::Addresses => "Addresses",
            Win::Panel(id) => crate::panel::find(id).map_or(id, |(_, w)| w.title),
            Win::Neighbors => "Neighbors",
            Win::Routes => "Routes",
            Win::Vrf => "VRF",
            Win::Firewall => "Firewall",
            Win::Bgp => "BGP",
            Win::Identity => "Identity",
            Win::History => "History",
            Win::Ping => "Ping",
            Win::Mtr => "MTR",
        }
    }

    /// `Some(gap id)` while the area has no engine commands yet. None now:
    /// the last stubs (OSPF, MPLS) became panels; a new stub returns its
    /// gap here.
    pub fn gap(self) -> Option<&'static str> {
        let _ = self;
        None
    }

    /// List windows close on Esc (after clearing find text and selection).
    pub(crate) fn closes_on_escape(self) -> bool {
        if let Win::Panel(id) = self {
            return crate::panel::find(id).is_some_and(|(_, w)| w.escape);
        }
        matches!(
            self,
            Win::Interfaces
                | Win::Addresses
                | Win::Routes
                | Win::Firewall
                | Win::InterfaceList
                | Win::Vrf
                | Win::Neighbors
                | Win::History
        )
    }

    pub(crate) fn default_size(self) -> [f32; 2] {
        match self {
            Win::Interfaces => [780.0, 520.0],
            Win::Neighbors => [820.0, 320.0],
            Win::Addresses => [900.0, 380.0],
            Win::Routes => [1000.0, 640.0],
            Win::Panel(id) => crate::panel::find(id).map_or([380.0, 200.0], |(_, w)| w.size),
            Win::Vrf => [600.0, 260.0],
            Win::Firewall => [980.0, 420.0],
            Win::Bgp => [980.0, 520.0],
            Win::InterfaceList => [520.0, 280.0],
            Win::Ping => [900.0, 700.0],
            // Tools open as tall as their form and grow with the results.
            Win::Mtr => [860.0, 160.0],
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
            Win::Panel(id) => {
                if let Some((p, _)) = crate::panel::find(id) {
                    self.with_panel(p.name, |s, app| s.window(app, id, ui));
                }
            }
            Win::Vrf => self.vrfs(ui),
            Win::Firewall => self.firewall(ui),
            Win::InterfaceList => self.interface_lists(ui),
            Win::Bgp => self.bgp(ui),
            Win::Identity => self.identity(ui),
            Win::History => self.history(ui),
            Win::Ping => self.ping_window(ui),
            Win::Mtr => self.mtr_window(ui),
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

    /// IP › Addresses: the list window pattern (G0.24); the panel
    /// `ip_address.rs` (G1.28) draws it.
    fn addresses(&mut self, ui: &mut egui::Ui) {
        self.with_panel(crate::ip_address::NAME, |p, app| {
            p.window(app, crate::ip_address::WIN, ui);
        });
    }

    /// Routing › BGP: the panel `bgp.rs` (G3.2a) draws it.
    fn bgp(&mut self, ui: &mut egui::Ui) {
        self.with_panel(crate::bgp::NAME, |p, app| p.window(app, crate::bgp::WIN, ui));
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
}

/// Combo box over `options`; `hint` shows while nothing is picked.
pub(crate) fn combo(
    ui: &mut egui::Ui,
    id: &str,
    hint: &str,
    value: &mut String,
    options: &[String],
) {
    // G1.29b: a USB adapter's name carries the USB icon (amber: slow port).
    let shown: egui::WidgetText = if value.is_empty() {
        hint.into()
    } else {
        crate::usb_mark::rich(ui, value).into()
    };
    egui::ComboBox::from_id_salt(id)
        .selected_text(shown)
        .show_ui(ui, |ui| {
            for n in options {
                let r = ui.selectable_value(value, n.clone(), crate::usb_mark::rich(ui, n));
                if let Some(m) = crate::usb_mark::get(ui.ctx(), n) {
                    r.on_hover_text(m.tip);
                }
            }
        });
}

/// How tall the results of a tool window get before they scroll
/// (`ScrollArea::min_scrolled_height`). The window opens as tall as its form
/// and egui grows it with what is inside: the results ask for their whole
/// height up to this, so the window grows with them, then they scroll.
pub(crate) fn grow_height(ui: &egui::Ui) -> f32 {
    ui.ctx().content_rect().height() * 0.6
}
