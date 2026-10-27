//! The side menu (G0.23): catalog, tree, remembered groups, ⓘ.

use super::*;
use crate::i18n::{Lang, Langs};
use crate::menu::{self, Node};

impl Harness {
    fn menu_row(&self, name: &str) -> Option<egui::Pos2> {
        self.ctx
            .read_response(menu::row_id(name))
            .map(|r| r.rect.center())
    }

    fn click_menu(&mut self, name: &str) {
        let at = self
            .menu_row(name)
            .unwrap_or_else(|| panic!("no menu row {name}"));
        self.click(at);
    }
}

fn win_row(key: &str) -> String {
    format!("win:{key}")
}

#[test]
fn every_window_has_an_icon_an_explanation_and_synonyms() {
    for w in menu::CATALOG.windows(2) {
        if let [a, b] = w {
            assert!(a.key < b.key, "CATALOG: {} before {}", a.key, b.key);
        }
    }
    let h = Harness::new();
    let ids: Vec<&str> = h
        .app
        .cache
        .commands
        .iter()
        .filter_map(|c| c["id"].as_str())
        .collect();
    assert!(ids.len() > 100, "engine.list arrived");
    for win in Win::all() {
        let e = menu::entry(win).unwrap_or_else(|| panic!("{win:?} has no menu entry"));
        assert!(icons::ALL.contains(&e.icon), "{}: icon not in icons.rs", e.key);
        assert!(!e.synonyms.is_empty(), "{}: no synonyms", e.key);
        for l in Lang::ALL {
            let langs = Langs { labels: l, help: l };
            let got = i18n::explain(langs, &menu::help_key(win)).map(|(lang, _)| lang);
            assert_eq!(got, Some(l), "{}: no explanation in {l:?}", e.key);
        }
        if win.gap().is_none() && !e.commands.is_empty() {
            assert!(
                ids.iter().any(|id| menu::owns(e, id)),
                "{}: none of {:?} is a command",
                e.key,
                e.commands
            );
        }
    }
}

#[test]
fn ip_groups_dhcp_and_dns_and_keeps_single_items_loose() {
    let tree = menu::tree();
    let ip = tree.iter().find(|g| g.name == "IP").unwrap();
    let sub = |name: &str| {
        ip.nodes.iter().find_map(|n| match n {
            Node::Sub { name: s, items } if *s == name => {
                Some(items.iter().map(|w| menu::label(*w)).collect::<Vec<_>>())
            }
            _ => None,
        })
    };
    assert_eq!(
        sub("DHCP").unwrap(),
        ["Client", "Pool", "Relay", "Server"]
    );
    let dns = sub("DNS").unwrap();
    for l in ["Settings", "Adlist", "Cache", "Forwarders", "Static", "Statistics", "TSIG Keys", "Zones"] {
        assert!(dns.contains(&l), "DNS lacks {l}: {dns:?}");
    }
    let loose: Vec<&str> = ip
        .nodes
        .iter()
        .filter_map(|n| match n {
            Node::Item(w) => Some(w.title()),
            Node::Sub { .. } => None,
        })
        .collect();
    assert_eq!(loose, ["Addresses", "Fast Path", "Firewall", "Firewall XDP", "Neighbors", "Routes", "Subscriber Notices", "Traffic Flow", "VRF"]);
    let names: Vec<&str> = ip.nodes.iter().map(|n| match n {
        Node::Item(w) => menu::label(*w),
        Node::Sub { name, .. } => name,
    }).collect();
    assert_eq!(names.first(), Some(&"Addresses"), "alphabetical: {names:?}");
    assert_eq!(names.get(1), Some(&"DHCP"), "alphabetical: {names:?}");

    let ipv6 = tree.iter().find(|g| g.name == "IPv6").unwrap();
    assert!(ipv6
        .nodes
        .iter()
        .any(|n| matches!(n, Node::Sub { name: "DHCP", items } if items.len() == 3)));
}

#[test]
fn groups_open_close_and_are_remembered() {
    let mut h = Harness::new();
    assert!(h.menu_row("IP/DNS").is_none(), "IP starts closed");
    h.click_menu("IP");
    assert!(h.menu_row("IP/DNS").is_some(), "IP opened");
    assert!(h.has_text("DNS"));
    // Closed subgroup: its count as a chip.
    assert!(h.has_text("4"), "DHCP shows its 4 items");
    assert!(h.menu_row(&win_row("dns-static")).is_none());
    h.click_menu("IP/DNS");
    assert!(h.menu_row(&win_row("dns-static")).is_some(), "DNS opened");
    assert!(h.has_text("Static"));

    let prefs = h.app.prefs();
    let mut other = Harness::new();
    other.app.apply_prefs(&prefs);
    other.idle();
    other.idle();
    assert!(other.menu_row(&win_row("dns-static")).is_some(), "remembered");

    h.click_menu("IP");
    assert!(h.menu_row("IP/DNS").is_none(), "IP closed again");
    assert!(!h.app.prefs().contains(r#""IP""#), "{}", h.app.prefs());
    assert!(h.app.prefs().contains(r#""IP/DNS""#), "the subgroup stays open inside");
}

#[test]
fn a_menu_item_opens_its_window_and_its_info_explains_it() {
    let mut h = Harness::new();
    h.app.open.clear();
    h.click_menu("IP");
    h.click_menu("IP/DNS");
    h.click_menu(&win_row("dns-static"));
    assert!(h.app.open.contains(&Win::Panel(crate::dns::WIN_STATIC)));
    assert!(h.has_text("DNS Static"), "window title");

    let info = h
        .ctx
        .read_response(menu::info_id())
        .expect("the selected item shows an ⓘ")
        .rect
        .center();
    h.click(info);
    assert!(h.has_text("O que faz"), "explanation in Portuguese");
    assert!(h.has_text("Caminho no RouterOS"));
    assert!(h.has_text("/ip dns static"));
    assert!(h.has_text("ip.dns.static.add"), "commands from engine.list");
    assert!(h.has_text("Close"), "labels stay English");

    h.key(egui::Key::Escape, egui::Modifiers::NONE);
    assert!(h.app.menu.help.is_none(), "Esc closes it");
}

#[test]
fn not_implemented_areas_show_a_lock_and_soon() {
    let mut h = Harness::new();
    h.click_menu("Routing");
    assert!(h.menu_row(&win_row("ospf")).is_some());
    assert!(h.has_text("soon"));
    assert!(h.has_text(icons::LOCK_SIMPLE));
}

fn first_win(query: &str) -> Option<Win> {
    crate::menu_search::search(query, []).into_iter().find_map(|h| match h {
        crate::menu_search::Hit::Win(w) => Some(w),
        crate::menu_search::Hit::Command(_) => None,
    })
}

fn finds(query: &str, win: Win) -> bool {
    crate::menu_search::search(query, []).contains(&crate::menu_search::Hit::Win(win))
}

#[test]
fn search_finds_by_name_synonym_and_routeros_path() {
    use crate::menu_search::{Hit, fold, search, terminal_line};
    let static_ = Win::Panel(crate::dns::WIN_STATIC);
    assert_eq!(first_win("DNS Static"), Some(static_), "by name");
    assert_eq!(first_win("static"), Some(static_));
    assert_eq!(first_win("/ip dns static"), Some(static_), "by RouterOS path");
    assert_eq!(first_win("nat"), Some(Win::Firewall), "by synonym");
    assert_eq!(first_win("masquerade"), Some(Win::Firewall));
    assert_eq!(first_win("rota padrão"), Some(Win::Routes));
    assert_eq!(first_win("ROTA PADRAO"), Some(Win::Routes), "case and accents");
    assert_eq!(
        first_win("lease"),
        Some(Win::Panel(crate::dhcp_server::WIN))
    );
    assert!(finds("blacklist", Win::Panel(crate::dns_adlist::WIN)));
    assert!(finds("blacklist", Win::Firewall));
    for w in [Win::Addresses, Win::Firewall, Win::Vrf, Win::Routes] {
        assert!(finds("ipv4", w), "ipv4 finds {w:?}");
    }
    assert!(!finds("ipv4", Win::Interfaces));
    assert_eq!(first_win("estatísticas dns"), Some(Win::Panel(crate::dns_statistics::WIN)), "Portuguese label");
    assert!(search("zzzz-nothing", []).is_empty());
    assert!(search("   ", []).is_empty());

    let ids = ["ip.dns.static.add", "ip.dns.static.print", "ip.route.add"];
    let hits = search("ip dns static add", ids);
    assert!(hits.contains(&Hit::Command("ip.dns.static.add".into())), "{hits:?}");
    assert!(!hits.contains(&Hit::Command("ip.route.add".into())));
    assert_eq!(fold("/IP › DNS  Estático"), "ip dns estatico");
    assert_eq!(terminal_line("ip.dns.static.add"), "/ip dns static add ");
    // A hostile paste stays bounded.
    let _ = search(&"a ".repeat(100_000), ids);
}

#[test]
fn slash_focuses_the_search_and_enter_opens_the_first_hit() {
    let mut h = Harness::new();
    h.app.open.clear();
    h.idle();
    h.type_text("/");
    assert!(h.ctx.memory(|m| m.has_focus(menu::search_id())), "/ focuses the search");
    h.type_text("nat");
    assert!(h.has_text("Firewall"));
    assert!(h.has_text("IP"), "where it is in the menu");
    assert!(h.menu_row("menu:hit:0").is_some());
    h.key(egui::Key::Enter, egui::Modifiers::NONE);
    assert!(h.app.open.contains(&Win::Firewall), "Enter opened it");
    assert!(h.app.menu.query.is_empty(), "query cleared");
    assert_eq!(h.app.menu.recent.first().map(String::as_str), Some("firewall"));
    assert_eq!(h.app.menu.selected(), Some(Win::Firewall));
    assert!(h.menu_row(&win_row("firewall")).is_some(), "revealed in the tree");
}

#[test]
fn ctrl_k_palette_shows_recent_and_opens_a_command_in_a_terminal() {
    let mut h = Harness::new();
    h.app.open.clear();
    h.click_menu("IP");
    h.click_menu(&win_row("routes"));
    h.key(egui::Key::K, CTRL);
    assert!(h.app.menu.palette.is_some(), "Ctrl+K opens the palette");
    assert!(h.has_text("Recent"));
    assert!(h.menu_row("palette:hit:0").is_some(), "the recent window");
    assert!(h.ctx.memory(|m| m.has_focus(crate::menu_search::palette_id())));
    h.type_text("ip dns static add");
    assert!(h.has_text("ip.dns.static.add"), "commands from engine.list");
    let before = h.app.terminal_count();
    h.click(h.text("ip.dns.static.add"));
    assert_eq!(h.app.terminal_count(), before + 1, "a terminal opened");
    assert_eq!(h.app.terminals.last().unwrap().input, "/ip dns static add ");
    assert!(h.app.menu.palette.is_none());

    h.key(egui::Key::K, CTRL);
    h.key(egui::Key::Escape, egui::Modifiers::NONE);
    assert!(h.app.menu.palette.is_none(), "Esc closes it");
}

#[test]
fn arrows_walk_the_tree_from_the_search_field() {
    use crate::menu::Nav;
    let mut h = Harness::new();
    h.app.open.clear();
    h.idle();
    h.type_text("/");
    h.key(egui::Key::Backspace, egui::Modifiers::NONE);
    assert!(h.app.menu.query.is_empty());
    let none = egui::Modifiers::NONE;
    h.key(egui::Key::ArrowDown, none);
    assert_eq!(h.app.menu.cursor, Some(Nav::Group("Interfaces")));
    // PPP (one window: a leaf) sits between them, as in RouterOS.
    h.key(egui::Key::ArrowDown, none);
    assert_eq!(h.app.menu.cursor, Some(Nav::Item(Win::Panel("ppp"))));
    h.key(egui::Key::ArrowDown, none);
    assert_eq!(h.app.menu.cursor, Some(Nav::Group("IP")));
    h.key(egui::Key::ArrowRight, none);
    assert!(h.app.menu.is_open("IP", None), "Right opens");
    h.key(egui::Key::ArrowDown, none);
    assert_eq!(h.app.menu.cursor, Some(Nav::Item(Win::Addresses)));
    assert!(h.ctx.read_response(menu::info_id()).is_some(), "selected shows ⓘ");
    h.key(egui::Key::Enter, none);
    assert!(h.app.open.contains(&Win::Addresses), "Enter opens");
    // The window took the keyboard; back to the menu.
    let field = h.ctx.read_response(menu::search_id()).unwrap().rect.center();
    h.click(field);
    h.key(egui::Key::ArrowLeft, none);
    assert_eq!(h.app.menu.cursor, Some(Nav::Group("IP")), "Left goes up");
    h.key(egui::Key::ArrowLeft, none);
    assert!(!h.app.menu.is_open("IP", None), "Left closes");
}

#[test]
fn favorites_pin_windows_at_the_top_and_are_remembered() {
    let mut h = Harness::new();
    h.click_menu("System");
    let at = h.menu_row(&win_row("services")).unwrap();
    h.right_click(at);
    h.click(h.text("Add to favorites"));
    assert!(h.app.menu.is_favorite(Win::Panel(crate::services::WIN)));
    assert!(h.has_text("Favorites"));
    h.click_menu("System");
    assert!(h.has_text("Services"), "the favorite stays with System closed");
    assert!(h.menu_row("fav:services").is_some(), "pinned while System is closed");
    h.click_menu("fav:services");
    assert!(h.app.open.contains(&Win::Panel(crate::services::WIN)));

    let mut other = Harness::new();
    other.app.apply_prefs(&h.app.prefs());
    other.idle();
    other.idle();
    assert!(other.menu_row("fav:services").is_some(), "remembered");
    assert_eq!(other.app.menu.recent.first().map(String::as_str), Some("services"));

    let at = h.menu_row("fav:services").unwrap();
    h.right_click(at);
    h.click(h.text("Remove from favorites"));
    assert!(!h.has_text("Favorites"));
    // Unknown or repeated keys in stored prefs are dropped.
    h.app.apply_prefs(r#"{"menu":{"favorites":["nope","services","services"],"recent":[1,"log"]}}"#);
    assert_eq!(h.app.menu.favorites, ["services"]);
    assert_eq!(h.app.menu.recent, ["log"]);
}

#[test]
fn esc_in_the_search_clears_it_and_leaves_the_windows_open() {
    let mut h = Harness::new();
    assert!(h.app.open.contains(&Win::Interfaces));
    let field = h.ctx.read_response(menu::search_id()).unwrap().rect.center();
    h.click(field);
    h.type_text("dns");
    assert!(h.has_text("DNS Static"));
    h.key(egui::Key::Escape, egui::Modifiers::NONE);
    assert!(h.app.menu.query.is_empty());
    assert!(h.app.open.contains(&Win::Interfaces), "Esc stayed in the menu");
    assert!(!h.ctx.memory(|m| m.has_focus(menu::search_id())));
}

#[test]
fn state_badges_come_from_the_existing_queries() {
    use crate::menu_badges::Badges;
    use crate::panel::PanelState;
    let mut h = Harness::new();
    // The lab answers the three queries: nothing failed, nothing in conflict.
    let b = h.app.panel_mut::<Badges>().unwrap();
    assert!(b.failed.is_empty() && b.conflicts == 0, "{b:?}");
    assert!(!h.has_text("1 failed"));

    h.app.with_panel_as::<Badges, _>(|b, app| {
        b.arrived(app, "services", 0, json!([
            {"name": "dns", "state": "failed"},
            {"name": "dhcp", "state": "running"},
        ]));
        b.arrived(app, "dhcp", 0, json!({"leases": {"bound": 3, "conflict": 2}}));
        b.arrived(app, "drift", 0, json!({"in_sync": false, "drift": [
            {"kind": "mtu", "interface": "ether2", "item": "", "expected": 1500, "actual": 9000},
        ]}));
    });
    h.idle();
    h.idle();
    // Closed groups sum up their windows' badges.
    assert!(h.has_text("2"), "System: two badges (Services, History)");
    assert!(h.has_text("2 conflict"), "IP: the DHCP conflict");
    h.click_menu("System");
    assert!(h.has_text("1 failed"));
    assert!(h.has_text("drift 1"));
    let red = crate::chip::RED.tone(&h.ctx.global_style().visuals).ink;
    assert_eq!(h.text_color("1 failed"), red, "failed is red");
    h.click_menu("IP");
    assert!(h.menu_row("IP/DHCP").is_some());
    assert!(h.has_text("2 conflict"), "DHCP subgroup, closed");
    h.click_menu("IP/DHCP");
    assert!(h.menu_row(&win_row("dhcp-server")).is_some());
    assert!(h.has_text("2 conflict"), "the DHCP Server item");
}
