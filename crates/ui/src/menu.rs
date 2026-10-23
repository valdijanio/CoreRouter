//! The side menu (G0.23): a tree of groups (bold, with an icon), subgroups
//! (IP › DHCP, IP › DNS) and windows, each with an icon. What a window
//! looks like in the menu — subgroup, short label, icon, RouterOS path,
//! commands, search synonyms — lives in [`CATALOG`], one table indexed by
//! the window's key, so the panels' files need no edit. A window missing
//! from it sits loose in its group with the default icon (a test keeps
//! every window in it).
//!
//! Which groups are open is a preference of the window (`prefs.rs`), like
//! the theme. The selected item shows an ⓘ: what the window does, its
//! RouterOS path and its commands, in the language of the explanations.

use std::collections::BTreeSet;

use egui::{Id, Rect, Response, Sense, Ui, pos2, vec2};
use serde_json::{Value, json};

use crate::help::{self, HelpView};
use crate::i18n::{self, tr};
use crate::windows::{self, Win};
use crate::{CoreRouterUi, icons, win_id};

/// How the menu shows one window.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Entry {
    /// `key(win)`: a panel's `WinDef::id`, or the built-in window's name.
    pub key: &'static str,
    /// Subgroup inside the window's group (`DHCP`, `DNS`).
    pub sub: Option<&'static str>,
    /// The label under its subgroup ("Static" under DNS); else the title.
    pub label: Option<&'static str>,
    pub icon: &'static str,
    /// The same place in RouterOS (`/ip dns static`); "" when none.
    pub path: &'static str,
    /// Its commands: an id, or a prefix of ids (`ip.dns.static` stands for
    /// `ip.dns.static.*` too).
    pub commands: &'static [&'static str],
    /// Other words an operator searches it by, lowercase.
    #[cfg_attr(not(test), allow(dead_code))] // the search reads them (G0.23b)
    pub synonyms: &'static [&'static str],
}

const fn e(
    key: &'static str,
    sub: Option<&'static str>,
    label: Option<&'static str>,
    icon: &'static str,
    path: &'static str,
    commands: &'static [&'static str],
    synonyms: &'static [&'static str],
) -> Entry {
    Entry {
        key,
        sub,
        label,
        icon,
        path,
        commands,
        synonyms,
    }
}

const DHCP: Option<&str> = Some("DHCP");
const DNS: Option<&str> = Some("DNS");

/// Every window of the menu, by key (sorted, a test checks).
pub(crate) const CATALOG: &[Entry] = &[
    e("addresses", None, None, icons::MAP_PIN, "/ip address", &["ip.address"], &["ip address", "ipv4", "endereço", "endereco", "gateway", "subnet"]),
    e("bgp", None, None, icons::GLOBE_HEMISPHERE_WEST, "/routing bgp", &["routing.bgp"], &["peer", "asn", "ebgp", "ibgp", "transit", "trânsito", "upstream"]),
    e("bonding", None, None, icons::LINK, "/interface bonding", &["interface.bonding"], &["lacp", "802.3ad", "bond", "link aggregation", "agregação"]),
    e("cgnat", None, None, icons::ARROWS_SPLIT, "", &[], &["nat444", "cgn", "port block", "ipv4 compartilhado", "rfc 6598"]),
    e("dhcp-client", DHCP, Some("Client"), icons::LAPTOP, "/ip dhcp-client", &["ip.dhcp-client"], &["wan", "ip dinâmico", "obter ip", "dynamic ip", "ipv4"]),
    e("dhcp-relay", DHCP, Some("Relay"), icons::ARROWS_LEFT_RIGHT, "/ip dhcp-relay", &["ip.dhcp-relay"], &["helper", "ip helper", "option 82"]),
    e("dhcp-server", DHCP, Some("Server"), icons::HARD_DRIVES, "/ip dhcp-server", &["ip.dhcp-server"], &["lease", "leases", "concessão", "network", "option", "reserva", "static lease", "ipv4"]),
    e("dhcp-server-stats", DHCP, Some("Statistics"), icons::CHART_BAR, "/ip dhcp-server statistics", &["ip.dhcp-server.statistics"], &["estatísticas", "lease count", "pool usage", "uso do pool"]),
    e("dhcp6-server", DHCP, Some("Server"), icons::HARD_DRIVES, "/ipv6 dhcp-server", &["ipv6.dhcp-server"], &["dhcpv6", "binding", "prefix delegation", "pd"]),
    e("dhcpv6-client", DHCP, Some("Client"), icons::LAPTOP, "/ipv6 dhcp-client", &["ipv6.dhcp-client"], &["dhcpv6", "prefix delegation", "pd", "ia_pd", "wan"]),
    e("dns", DNS, Some("Settings"), icons::GEAR_SIX, "/ip dns", &["ip.dns.get", "ip.dns.set"], &["resolver", "servers", "doh", "dot", "dns server", "allow remote requests"]),
    e("dns-adlist", DNS, Some("Adlist"), icons::PROHIBIT, "/ip dns adlist", &["ip.dns.adlist"], &["adblock", "blacklist", "bloqueio", "pi-hole", "ads", "propaganda"]),
    e("dns-cache", DNS, Some("Cache"), icons::DATABASE, "/ip dns cache", &["ip.dns.cache"], &["flush", "limpar cache"]),
    e("dns-forwarders", DNS, Some("Forwarders"), icons::ARROW_BEND_UP_RIGHT, "/ip dns forwarders", &["ip.dns.forwarders"], &["forward", "encaminhar", "conditional forwarding", "doh"]),
    e("dns-lookup", None, None, icons::MAGNIFYING_GLASS, "/tool dns-lookup", &["tool.dns", "ip.dns.resolve"], &["nslookup", "dig", "resolve", "host", "resolver nome"]),
    e("dns-static", DNS, Some("Static"), icons::PUSH_PIN, "/ip dns static", &["ip.dns.static"], &["hosts", "a record", "registro", "fwd", "cname", "estático"]),
    e("dns-statistics", DNS, Some("Statistics"), icons::CHART_BAR, "/ip dns statistics", &["ip.dns.statistics"], &["queries", "consultas", "top clients", "estatísticas"]),
    e("dns-tsig", DNS, Some("TSIG Keys"), icons::KEY, "/ip dns tsig-key", &["ip.dns.tsig-key"], &["tsig", "key", "chave", "rfc 8945"]),
    e("dns-zone-file", DNS, Some("Zone File"), icons::FILE_TEXT, "/ip dns zone file", &["ip.dns.zone.file"], &["zone file", "import", "export", "bind"]),
    e("dns-zone-records", DNS, Some("Zone Records"), icons::LIST, "/ip dns zone record", &["ip.dns.zone.record"], &["record", "registro", "soa", "mx", "ns"]),
    e("dns-zones", DNS, Some("Zones"), icons::FOLDERS, "/ip dns zone", &["ip.dns.zone"], &["zone", "zona", "authoritative", "autoritativo", "dnssec"]),
    e("firewall", None, None, icons::SHIELD_CHECK, "/ip firewall", &["ip.firewall"], &["nat", "masquerade", "srcnat", "dstnat", "port forward", "redirecionar porta", "filter", "mangle", "address list", "blacklist", "bloquear", "acl"]),
    e("history", None, None, icons::CLOCK_COUNTER_CLOCKWISE, "/system history", &["config.history", "config.rollback"], &["undo", "rollback", "desfazer", "revision", "revisão", "commit"]),
    e("identity", None, None, icons::IDENTIFICATION_BADGE, "/system identity", &["system.identity"], &["hostname", "nome", "name"]),
    e("interface-list", None, None, icons::LIST_BULLETS, "/interface list", &["interface.list"], &["lan", "wan", "lista", "member"]),
    e("interfaces", None, None, icons::PLUGS, "/interface", &["interface.print", "interface.set", "interface.ethernet", "interface.vlan", "interface.bridge"], &["ethernet", "porta", "port", "vlan", "bridge", "mtu", "link"]),
    e("ip-pool", DHCP, Some("Pool"), icons::STACK_SIMPLE, "/ip pool", &["ip.pool"], &["faixa", "range", "address pool", "ipv4"]),
    e("ipv6-pool", DHCP, Some("Pool"), icons::STACK_SIMPLE, "/ipv6 pool", &["ipv6.pool"], &["prefix", "prefixo", "prefix delegation"]),
    e("ipv6-settings", None, Some("Settings"), icons::GEAR_SIX, "/ipv6 settings", &["ipv6.settings"], &["forward", "ra", "accept router advertisements", "slaac"]),
    e("log", None, None, icons::SCROLL, "/log", &["log"], &["eventos", "messages", "mensagens"]),
    e("logging", None, None, icons::NOTEBOOK, "/system logging", &["system.logging"], &["syslog", "remote log", "topics", "rules", "regras"]),
    e("mpls", None, None, icons::TAG, "/mpls", &[], &["ldp", "label", "vpls", "rótulo"]),
    e("mtr", None, None, icons::PATH, "/tool traceroute", &["tool.mtr"], &["traceroute", "tracert", "path", "caminho", "perda", "loss"]),
    e("neighbors", None, None, icons::USERS_THREE, "/ip neighbor", &["ip.neighbor"], &["vizinhos", "lldp", "mndp", "cdp", "discovery"]),
    e("ntp-client", None, None, icons::CLOCK, "/system ntp client", &["system.ntp.client"], &["time", "hora", "relógio", "sntp", "clock"]),
    e("ospf", None, None, icons::GRAPH, "/routing ospf", &[], &["area", "lsa", "igp"]),
    e("ping", None, None, icons::PULSE, "/tool ping", &["tool.ping"], &["icmp", "latência", "latency", "mtu"]),
    e("routes", None, None, icons::SIGNPOST, "/ip route", &["ip.route"], &["rota", "rotas", "rota padrão", "default route", "gateway", "0.0.0.0/0", "static route", "ipv4"]),
    e("services", None, None, icons::HEARTBEAT, "/system service", &["system.service"], &["supervisor", "daemon", "processo", "failed", "restart", "reiniciar"]),
    e("settings", None, None, icons::SLIDERS_HORIZONTAL, "", &[], &["language", "idioma", "theme", "tema", "preferences", "preferências"]),
    e("tuning", None, None, icons::GAUGE, "/system tuning", &["system.tuning"], &["sysctl", "performance", "desempenho", "irq", "rps", "governor", "boot", "kernel"]),
    e("vrf", None, None, icons::STACK, "/ip vrf", &["ip.vrf"], &["routing table", "tabela de rotas", "l3vpn"]),
];

/// The groups' icons, by `windows::MENU` name.
const GROUP_ICONS: &[(&str, &str)] = &[
    ("CGNAT", icons::ARROWS_SPLIT),
    ("IP", icons::TREE_STRUCTURE),
    ("IPv6", icons::TREE_VIEW),
    ("Interfaces", icons::PLUGS_CONNECTED),
    ("Log", icons::SCROLL),
    ("MPLS", icons::TAG),
    ("Routing", icons::SHARE_NETWORK),
    ("Settings", icons::SLIDERS_HORIZONTAL),
    ("System", icons::GEAR),
    ("Tools", icons::WRENCH),
];

const SUB_ICONS: &[(&str, &str)] = &[("DHCP", icons::BROADCAST), ("DNS", icons::GLOBE)];

/// For a window missing from the catalog.
const DEFAULT_ICON: &str = icons::SQUARES_FOUR;

fn icon_of(table: &[(&str, &'static str)], name: &str) -> &'static str {
    table
        .iter()
        .find(|(n, _)| *n == name)
        .map_or(DEFAULT_ICON, |(_, i)| i)
}

/// The window's catalog key.
pub(crate) fn key(win: Win) -> &'static str {
    match win {
        Win::Panel(id) => id,
        Win::Interfaces => "interfaces",
        Win::InterfaceList => "interface-list",
        Win::Addresses => "addresses",
        Win::Neighbors => "neighbors",
        Win::Routes => "routes",
        Win::Vrf => "vrf",
        Win::Firewall => "firewall",
        Win::Bgp => "bgp",
        Win::Ospf => "ospf",
        Win::Mpls => "mpls",
        Win::Cgnat => "cgnat",
        Win::Identity => "identity",
        Win::History => "history",
        Win::Ping => "ping",
        Win::Mtr => "mtr",
    }
}

/// The catalog entry of `win`, if it has one.
pub(crate) fn entry(win: Win) -> Option<&'static Entry> {
    let k = key(win);
    CATALOG
        .binary_search_by(|e| e.key.cmp(k))
        .ok()
        .and_then(|i| CATALOG.get(i))
}

pub(crate) fn icon(win: Win) -> &'static str {
    entry(win).map_or(DEFAULT_ICON, |e| e.icon)
}

/// The label in the menu (English; `tr` translates it).
pub(crate) fn label(win: Win) -> &'static str {
    entry(win).and_then(|e| e.label).unwrap_or_else(|| win.title())
}

/// `i18n::explain` key of a window's explanation.
pub(crate) fn help_key(win: Win) -> String {
    format!("menu.{}", key(win))
}

/// Whether command `id` belongs to `entry`.
pub(crate) fn owns(entry: &Entry, id: &str) -> bool {
    entry.commands.iter().any(|p| {
        id == *p
            || id
                .strip_prefix(p)
                .is_some_and(|rest| rest.starts_with('.'))
    })
}

/// One line of the tree.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Node {
    Item(Win),
    Sub {
        name: &'static str,
        items: Vec<Win>,
    },
}

impl Node {
    fn label(&self) -> &'static str {
        match self {
            Node::Item(w) => label(*w),
            Node::Sub { name, .. } => name,
        }
    }
}

/// A group of the tree; `leaf` when it is one window of its own name.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Group {
    pub name: &'static str,
    pub nodes: Vec<Node>,
    pub leaf: Option<Win>,
}

/// The menu as drawn: `windows::menu()`'s groups with their subgroups,
/// everything alphabetical by its label (as in WinBox).
pub(crate) fn tree() -> Vec<Group> {
    windows::menu()
        .into_iter()
        .map(|(name, items)| {
            let leaf = match items.as_slice() {
                [only] if only.title() == name => Some(*only),
                _ => None,
            };
            let mut nodes: Vec<Node> = Vec::new();
            for w in items {
                match entry(w).and_then(|e| e.sub) {
                    None => nodes.push(Node::Item(w)),
                    Some(sub) => match nodes
                        .iter_mut()
                        .find(|n| matches!(n, Node::Sub { name, .. } if *name == sub))
                    {
                        Some(Node::Sub { items, .. }) => items.push(w),
                        _ => nodes.push(Node::Sub {
                            name: sub,
                            items: vec![w],
                        }),
                    },
                }
            }
            for n in &mut nodes {
                if let Node::Sub { items, .. } = n {
                    items.sort_by_key(|w| label(*w).to_lowercase());
                }
            }
            nodes.sort_by_key(|n| n.label().to_lowercase());
            Group { name, nodes, leaf }
        })
        .collect()
}

/// Key of a group (`IP`) or subgroup (`IP/DNS`) in the open set.
fn node_key(group: &str, sub: Option<&str>) -> String {
    match sub {
        Some(s) => format!("{group}/{s}"),
        None => group.to_owned(),
    }
}

/// Longest stored list of open groups; more were not written by us.
const MAX_OPEN: usize = 64;

/// The menu's own state (UI-local; `open` is a stored preference).
#[derive(Debug, Default)]
pub(crate) struct MenuState {
    /// Open groups and subgroups (`IP`, `IP/DNS`).
    pub open: BTreeSet<String>,
    /// The selected item: it shows the ⓘ.
    pub selected: Option<Win>,
    /// The explanation modal of the ⓘ.
    pub help: Option<HelpView>,
}

impl MenuState {
    pub(crate) fn is_open(&self, group: &str, sub: Option<&str>) -> bool {
        self.open.contains(&node_key(group, sub))
    }

    pub(crate) fn toggle(&mut self, group: &str, sub: Option<&str>) {
        let k = node_key(group, sub);
        if !self.open.remove(&k) {
            self.open.insert(k);
        }
    }

    /// For `prefs.rs`.
    pub(crate) fn prefs(&self) -> Value {
        json!({ "open": self.open })
    }

    pub(crate) fn apply_prefs(&mut self, v: &Value) {
        if let Some(list) = v.get("open").and_then(Value::as_array) {
            self.open = list
                .iter()
                .take(MAX_OPEN)
                .filter_map(Value::as_str)
                .filter(|s| s.len() <= 64)
                .map(str::to_owned)
                .collect();
        }
    }
}

/// Id of a menu row (tests click them).
pub(crate) fn row_id(name: &str) -> Id {
    Id::unique(("corerouter-menu-row", name))
}

/// Id of the selected item's ⓘ.
pub(crate) fn info_id() -> Id {
    Id::unique("corerouter-menu-info")
}

/// How a row looks.
struct Look<'a> {
    depth: u8,
    /// `Some(open)` on a group or subgroup.
    caret: Option<bool>,
    icon: &'static str,
    label: &'a str,
    strong: bool,
    weak: bool,
    /// Its window is open (the old menu's highlight).
    active: bool,
    selected: bool,
}

const INDENT: f32 = 14.0;
const ICON_SIZE: f32 = 15.0;
const CARET: f32 = 14.0;

/// A full-width menu row: caret, icon, label, then `right` (selos, ⓘ)
/// at the right end. The response is the row's click.
fn row(ui: &mut Ui, id: Id, look: &Look, right: impl FnOnce(&mut Ui)) -> Response {
    let h = ui.spacing().interact_size.y + 2.0;
    let (rect, _) = ui.allocate_exact_size(vec2(ui.available_width(), h), Sense::hover());
    let resp = ui.interact(rect, id, Sense::click());
    let v = ui.visuals().clone();
    let bg = if look.active {
        Some(v.selection.bg_fill.gamma_multiply(0.55))
    } else if resp.hovered() {
        Some(v.widgets.hovered.weak_bg_fill)
    } else {
        None
    };
    if let Some(bg) = bg {
        ui.painter().rect_filled(rect.shrink2(vec2(2.0, 0.5)), 3.0, bg);
    }
    if look.selected {
        ui.painter().rect_stroke(
            rect.shrink2(vec2(2.0, 0.5)),
            3.0,
            egui::Stroke::new(1.0, v.selection.stroke.color),
            egui::StrokeKind::Inside,
        );
    }
    let ink = if look.weak {
        v.weak_text_color()
    } else if look.strong {
        v.strong_text_color()
    } else {
        v.text_color()
    };
    let mut x = rect.left() + 4.0 + f32::from(look.depth) * INDENT;
    let slot = |x: f32, w: f32| Rect::from_min_size(pos2(x, rect.top()), vec2(w, h));
    // The caret's place is kept on every row, so icons line up.
    if let Some(open) = look.caret {
        let caret = if open {
            icons::CARET_DOWN
        } else {
            icons::CARET_RIGHT
        };
        icons::paint(ui, slot(x, CARET), caret, 12.0, v.weak_text_color());
    }
    x += CARET;
    icons::paint(ui, slot(x, ICON_SIZE), look.icon, ICON_SIZE, ink);
    x += ICON_SIZE + 6.0;
    let font = egui::TextStyle::Body.resolve(ui.style());
    let at = pos2(x, rect.center().y);
    let painter = ui.painter_at(rect);
    painter.text(at, egui::Align2::LEFT_CENTER, look.label, font.clone(), ink);
    if look.strong {
        // The default fonts have no bold face: a second pass half a point
        // to the right thickens the strokes.
        painter.text(
            at + vec2(0.6, 0.0),
            egui::Align2::LEFT_CENTER,
            look.label,
            font,
            ink,
        );
    }
    let mut strip = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(rect.shrink2(vec2(4.0, 0.0)))
            .layout(egui::Layout::right_to_left(egui::Align::Center)),
    );
    right(&mut strip);
    resp
}

impl CoreRouterUi {
    /// The side menu: New Terminal, then the tree.
    pub(crate) fn menu(&mut self, ui: &mut Ui) {
        ui.add_space(4.0);
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            let look = Look {
                depth: 0,
                caret: None,
                icon: icons::TERMINAL_WINDOW,
                label: tr(self.lang.labels, "New Terminal"),
                strong: true,
                weak: false,
                active: false,
                selected: false,
            };
            if row(ui, row_id("New Terminal"), &look, |_| {})
                .on_hover_text("RouterOS-style terminal: /ip address print, Tab, ?, Ctrl+X")
                .clicked()
            {
                self.new_terminal();
            }
            for g in tree() {
                self.menu_group(ui, &g);
            }
        });
        help::modal(ui.ctx(), self.lang, &mut self.menu.help);
    }

    fn menu_group(&mut self, ui: &mut Ui, g: &Group) {
        let labels = self.lang.labels;
        if let Some(w) = g.leaf {
            self.menu_item(ui, w, 0, Some(icon_of(GROUP_ICONS, g.name)), true);
            return;
        }
        let open = self.menu.is_open(g.name, None);
        let look = Look {
            depth: 0,
            caret: Some(open),
            icon: icon_of(GROUP_ICONS, g.name),
            label: tr(labels, g.name),
            strong: true,
            weak: false,
            active: false,
            selected: false,
        };
        if row(ui, row_id(g.name), &look, |_| {}).clicked() {
            self.menu.toggle(g.name, None);
        }
        if !open {
            return;
        }
        for n in &g.nodes {
            match n {
                Node::Item(w) => self.menu_item(ui, *w, 1, None, false),
                Node::Sub { name, items } => {
                    let open = self.menu.is_open(g.name, Some(name));
                    let look = Look {
                        depth: 1,
                        caret: Some(open),
                        icon: icon_of(SUB_ICONS, name),
                        label: tr(labels, name),
                        strong: false,
                        weak: false,
                        active: false,
                        selected: false,
                    };
                    let count = items.len().to_string();
                    let resp = row(ui, row_id(&node_key(g.name, Some(name))), &look, |ui| {
                        if !open {
                            crate::chip::chip(ui, &count, crate::chip::neutral_tone(ui.visuals()));
                        }
                    });
                    if resp.clicked() {
                        self.menu.toggle(g.name, Some(name));
                    }
                    if open {
                        for w in items {
                            self.menu_item(ui, *w, 2, None, false);
                        }
                    }
                }
            }
        }
    }

    /// A window's row; `icon` overrides the catalog's (a leaf group).
    fn menu_item(&mut self, ui: &mut Ui, win: Win, depth: u8, icon: Option<&'static str>, strong: bool) {
        let labels = self.lang.labels;
        let selected = self.menu.selected == Some(win);
        let soon = win.gap();
        let look = Look {
            depth,
            caret: None,
            icon: if soon.is_some() {
                icons::LOCK_SIMPLE
            } else {
                icon.unwrap_or_else(|| self::icon(win))
            },
            label: tr(labels, label(win)),
            strong,
            weak: soon.is_some(),
            active: self.open.contains(&win),
            selected,
        };
        let mut info = false;
        let resp = row(ui, row_id(&format!("win:{}", key(win))), &look, |ui| {
            if selected {
                info = help::info_button(ui, info_id(), tr(labels, "What this window does"))
                    .clicked();
            }
            if soon.is_some() {
                crate::chip::chip(ui, tr(labels, "soon"), crate::chip::neutral_tone(ui.visuals()));
            }
        });
        let resp = match soon {
            Some(gap) => resp.on_hover_text(format!(
                "{} — {gap} (docs/gaps.md)",
                tr(labels, "Not implemented yet")
            )),
            None => resp,
        };
        if info {
            self.menu.help = Some(self.menu_help(win));
        } else if resp.clicked() {
            self.menu.selected = Some(win);
            self.open_from_menu(win);
        }
    }

    /// Open `win`, or bring it to the front when it is open.
    pub(crate) fn open_from_menu(&mut self, win: Win) {
        if !self.open.insert(win) {
            // Already open: to the front, with its dialogs over it.
            self.floats.raise(win_id(win));
        }
        // Some lists are only asked for while their window is open.
        self.cache.refreshed_at = None;
    }

    /// The ⓘ modal of `win`: the explanation, its RouterOS path and the
    /// router's commands for it (from `engine.list`).
    pub(crate) fn menu_help(&self, win: Win) -> HelpView {
        let mut view = HelpView::new(help_key(win), i18n::tr(self.lang.labels, win.title()));
        let Some(e) = entry(win) else {
            return view;
        };
        if !e.path.is_empty() {
            view = view.with("RouterOS path", format!("`{}`", e.path));
        }
        let mut ids: Vec<&str> = self
            .cache
            .commands
            .iter()
            .filter_map(|c| c.get("id").and_then(Value::as_str))
            .filter(|id| owns(e, id))
            .collect();
        if ids.is_empty() {
            // Before `engine.list` arrives: the families themselves.
            ids = e.commands.to_vec();
        }
        if !ids.is_empty() {
            let list: Vec<String> = ids.iter().map(|id| format!("- `{id}`")).collect();
            view = view.with("Commands", list.join("\n"));
        }
        view
    }
}
