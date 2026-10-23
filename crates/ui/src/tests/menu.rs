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
        ["Client", "Pool", "Relay", "Server", "Statistics"]
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
    assert_eq!(loose, ["Addresses", "Firewall", "Neighbors", "Routes", "VRF"]);
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
    assert!(h.has_text("5"), "DHCP shows its 5 items");
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
