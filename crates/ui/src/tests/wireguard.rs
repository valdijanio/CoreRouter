//! Interfaces › WireGuard (G1.31a): the Interfaces tab with ports, keys and
//! peers up; the Peers tab with the handshake states, filters and the hint
//! of the selected peer; the modals fed by the engine's previews (a prefix
//! another peer has, a key made on the router); the key regeneration that
//! asks first; the `wg` in Interfaces; and the ⓘ of every label in both
//! languages.

use super::*;
use crate::list::Act;
use crate::wireguard::{Tab, WireguardPanel};

const K1: &str = "YAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";

/// Two lab interfaces that know each other (their peers come up), and a
/// road warrior that never called.
fn lab() -> Session {
    let mut s = Session::virtual_lab();
    for (cmd, p) in [
        ("interface.wireguard.add", json!({"name": "wg0"})),
        ("interface.wireguard.add", json!({"name": "wg-s2s", "mtu": 1412, "comment": "filial"})),
        ("ip.address.add", json!({"address": "10.9.0.1/24", "interface": "wg0"})),
    ] {
        s.execute(cmd, &p).unwrap_or_else(|e| panic!("{cmd}: {e}"));
    }
    let l = s.execute("interface.wireguard.list", &json!({})).unwrap();
    let key = |n: &str| l.as_array().unwrap().iter().find(|r| r["name"] == n).unwrap()["public_key"].clone();
    let (k0, k1) = (key("wg0"), key("wg-s2s"));
    for p in [
        json!({"interface": "wg0", "name": "filial-sp", "public_key": k1, "allowed_address": "10.20.0.0/16",
               "endpoint_address": "127.0.0.1", "endpoint_port": 13232, "persistent_keepalive": 25}),
        json!({"interface": "wg-s2s", "name": "matriz", "public_key": k0, "allowed_address": "10.9.0.0/24"}),
        json!({"interface": "wg0", "name": "notebook", "public_key": K1, "allowed_address": "10.9.0.2/32"}),
        json!({"interface": "wg0", "name": "escritorio", "private_key": "auto", "allowed_address": "10.9.0.8/29",
               "endpoint_address": "192.0.2.44", "endpoint_port": 13231, "persistent_keepalive": 25}),
    ] {
        s.execute("interface.wireguard.peers.add", &p).unwrap_or_else(|e| panic!("{p}: {e}"));
    }
    s
}

fn open(s: Session) -> Harness {
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(crate::wireguard::WIN));
    refresh(&mut h);
    h
}

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..4 {
        h.idle();
    }
}

fn settle(h: &mut Harness) {
    for _ in 0..30 {
        h.idle();
    }
}

/// Some painted text contains `needle` (the checks are whole sentences).
fn shows(h: &Harness, needle: &str) -> bool {
    fn find(shape: &egui::Shape, needle: &str) -> bool {
        match shape {
            egui::Shape::Text(t) => t.galley.text().contains(needle),
            egui::Shape::Vec(v) => v.iter().any(|s| find(s, needle)),
            _ => false,
        }
    }
    h.shapes.iter().any(|s| find(&s.shape, needle))
}

fn panel(h: &mut Harness) -> &mut WireguardPanel {
    h.app.panel_mut::<WireguardPanel>().unwrap()
}

fn on_panel(h: &mut Harness, f: impl FnOnce(&mut WireguardPanel, &mut CoreRouterUi, &egui::Ui)) {
    let ctx = h.ctx.clone();
    let mut f = Some(f);
    h.app
        .with_panel_as::<WireguardPanel, _>(|p, app| {
            let _ = ctx.run_ui(egui::RawInput::default(), |ui| {
                if let Some(f) = f.take() {
                    f(p, app, ui);
                }
            });
        })
        .unwrap();
    h.idle();
}

fn peers_tab(h: &mut Harness) {
    panel(h).tab = Tab::Peers;
    refresh(h);
}

#[test]
fn interfaces_tab_shows_ports_keys_and_peers_up() {
    let h = open(lab());
    for t in ["Interfaces", "Peers", "wg0", "wg-s2s", "13231", "13232", "1412", "running", "1 up", "2 interfaces", "4 peers", "2 up", "filial"] {
        assert!(h.has_text(t), "{t}");
    }
}

#[test]
fn peers_tab_shows_states_filters_and_the_hint() {
    let mut h = open(lab());
    peers_tab(&mut h);
    for t in ["filial-sp", "matriz", "notebook", "escritorio", "up", "no-handshake", "never", "10.20.0.0/16", "192.0.2.44:13231", "4 peers", "2 up", "1 no-handshake", "1 never", "now"] {
        assert!(h.has_text(t), "{t}");
    }
    // Only wg-s2s: its one peer.
    panel(&mut h).filters.toggle("interface", "wg-s2s");
    refresh(&mut h);
    assert!(h.has_text("matriz") && !h.has_text("notebook"));
    panel(&mut h).filters.toggle("interface", "wg-s2s");
    // The selected peer says why it is in its state.
    panel(&mut h).peer_table.click("escritorio", false, false, &["escritorio"]);
    refresh(&mut h);
    assert!(shows(&h, "check the public keys on both sides"), "the engine's hint");
}

#[test]
fn the_peer_modal_checks_prefixes_and_makes_the_keys() {
    let mut h = open(lab());
    peers_tab(&mut h);
    // With one interface picked in the filter, a new peer goes there.
    panel(&mut h).filters.toggle("interface", "wg0");
    on_panel(&mut h, |p, app, ui| p.act_for_test(app, Act::Add, ui, true));
    settle(&mut h);
    assert!(h.has_text("New WireGuard Peer"));
    assert_eq!(panel(&mut h).peer_modal.as_ref().and_then(|m| m.values.get("interface")).map(String::as_str), Some("wg0"));
    assert!(h.has_text("10.9.0.3/32 (in 10.9.0.0/24)"), "the next free address");
    let m = panel(&mut h).peer_modal.as_mut().unwrap();
    m.values.insert("name", "celular".into());
    m.values.insert("allowed_address", "10.9.0.2/32".into());
    settle(&mut h);
    assert!(shows(&h, "already an allowed address of peer 'notebook'"), "the kernel would move it");
    let m = panel(&mut h).peer_modal.as_mut().unwrap();
    m.values.insert("allowed_address", "10.9.0.3/32".into());
    m.values.insert("preshared_key", "yes".into());
    settle(&mut h);
    assert!(shows(&h, "10.9.0.3/32 not used by another peer of wg0"));
    assert!(shows(&h, "the router makes the peer's key pair"), "no key pasted");
    h.click(h.text("OK"));
    settle(&mut h);
    assert!(panel(&mut h).peer_modal.is_none(), "OK closes: {:?}", h.app.log());
    let l = lock(&h.session).execute("interface.wireguard.peers.list", &json!({"show_sensitive": true})).unwrap();
    let cel = l.as_array().unwrap().iter().find(|r| r["name"] == "celular").unwrap().clone();
    assert_eq!(cel["allowed_address"], json!(["10.9.0.3/32"]));
    assert_eq!(cel["private_key"].as_str().unwrap().len(), 44, "made on the router");
    assert_eq!(cel["preshared_key"].as_str().unwrap().len(), 44);
}

#[test]
fn editing_a_peer_keeps_its_keys() {
    let mut h = open(lab());
    peers_tab(&mut h);
    let before = lock(&h.session).execute("interface.wireguard.peers.list", &json!({"show_sensitive": true})).unwrap();
    on_panel(&mut h, |p, app, ui| p.act_for_test(app, Act::Edit("escritorio".into()), ui, true));
    settle(&mut h);
    assert!(h.has_text("WireGuard Peer <escritorio>"));
    let m = panel(&mut h).peer_modal.as_mut().unwrap();
    assert_eq!(m.values.get("allowed_address").map(String::as_str), Some("10.9.0.8/29"));
    m.values.insert("comment", "escritório central".into());
    settle(&mut h);
    h.click(h.text("OK"));
    settle(&mut h);
    let after = lock(&h.session).execute("interface.wireguard.peers.list", &json!({"show_sensitive": true})).unwrap();
    let pick = |l: &Value| l.as_array().unwrap().iter().find(|r| r["name"] == "escritorio").unwrap().clone();
    assert_eq!(pick(&after)["comment"], "escritório central", "{:?}", h.app.log());
    assert_eq!(pick(&after)["private_key"], pick(&before)["private_key"], "the client's key stays");
}

#[test]
fn the_interface_modal_checks_port_and_mtu() {
    let mut s = lab();
    s.execute("ip.address.add", &json!({"address": "203.0.113.2/24", "interface": "ether1"})).unwrap();
    s.execute("ip.route.add", &json!({"dst_address": "0.0.0.0/0", "gateway": "203.0.113.1"})).unwrap();
    s.execute("interface.set", &json!({"name": "ether1", "mtu": 1492})).unwrap();
    let mut h = open(s);
    on_panel(&mut h, |p, app, ui| p.act_for_test(app, Act::Add, ui, false));
    settle(&mut h);
    assert!(h.has_text("New WireGuard Interface"));
    let m = panel(&mut h).if_modal.as_mut().unwrap();
    m.values.insert("name", "wg9".into());
    settle(&mut h);
    for t in ["UDP 13233 is no other WireGuard interface's", "use 1412", "lets UDP 13233 in from ether1", "generated on the router when applied", "/interface wireguard add"] {
        assert!(shows(&h, t), "{t}");
    }
    let m = panel(&mut h).if_modal.as_mut().unwrap();
    m.values.insert("mtu", "1412".into());
    settle(&mut h);
    h.click(h.text("OK"));
    settle(&mut h);
    let l = lock(&h.session).execute("interface.wireguard.list", &json!({})).unwrap();
    let wg9 = l.as_array().unwrap().iter().find(|r| r["name"] == "wg9").cloned();
    assert_eq!(wg9.map(|r| r["mtu"].clone()), Some(json!(1412)), "{:?}", h.app.log());
}

#[test]
fn regenerating_keys_asks_first() {
    let mut h = open(lab());
    let key = |h: &Harness| lock(&h.session).execute("interface.wireguard.list", &json!({})).unwrap()[0]["public_key"].clone();
    let before = key(&h);
    on_panel(&mut h, |p, app, ui| p.new_keys_for_test(app, ui, "wg-s2s"));
    settle(&mut h);
    assert!(shows(&h, "Every peer must then get the new public key"));
    assert_eq!(key(&h), before, "nothing changed before OK");
    h.click(h.text("OK"));
    settle(&mut h);
    assert!(panel(&mut h).confirm.is_none());
    let l = lock(&h.session).execute("interface.wireguard.list", &json!({})).unwrap();
    let s2s = l.as_array().unwrap().iter().find(|r| r["name"] == "wg-s2s").unwrap().clone();
    assert_ne!(s2s["public_key"], before, "{:?}", h.app.log());
}

#[test]
fn add_peer_from_an_interface_opens_the_modal_on_it() {
    let mut h = open(lab());
    on_panel(&mut h, |p, app, ui| p.add_peer_for_test(app, ui, "wg-s2s"));
    settle(&mut h);
    let p = panel(&mut h);
    assert_eq!(p.tab, Tab::Peers);
    assert_eq!(p.peer_modal.as_ref().and_then(|m| m.values.get("interface")).map(String::as_str), Some("wg-s2s"));
}

#[test]
fn client_config_shows_the_file_masked_and_its_qr_code() {
    let mut h = open(lab());
    peers_tab(&mut h);
    on_panel(&mut h, |p, app, ui| p.client_config_for_test(app, ui, "escritorio"));
    settle(&mut h);
    assert!(h.has_text("Client Config <escritorio>"));
    let t = panel(&mut h).text.as_ref().unwrap();
    let text = t.text.clone().unwrap();
    assert!(text.contains("[Interface]") && text.contains("Address = 10.9.0.8/29"), "{text}");
    assert!(crate::wireguard::qr_modules(&text).is_some_and(|(w, _)| w >= 21), "a QR code");
    assert!(shows(&h, "PrivateKey = ••••••••"), "the key masked until Show keys");
    let key = text.lines().find(|l| l.starts_with("PrivateKey")).unwrap().to_owned();
    fn walk(shape: &egui::Shape, out: &mut Vec<String>) {
        match shape {
            egui::Shape::Text(t) => out.push(t.galley.text().to_owned()),
            egui::Shape::Vec(v) => v.iter().for_each(|s| walk(s, out)),
            _ => {}
        }
    }
    let mut all = Vec::new();
    h.shapes.iter().for_each(|s| walk(&s.shape, &mut all));
    let leak: Vec<&String> = all.iter().filter(|t| t.contains(&key)).collect();
    assert!(leak.is_empty(), "{key} on screen: {leak:?}");
    // A peer whose key was pasted: the file says where the key goes.
    on_panel(&mut h, |p, app, ui| p.client_config_for_test(app, ui, "notebook"));
    settle(&mut h);
    assert!(shows(&h, "the router does not hold this client's private key"));
}

#[test]
fn import_makes_an_interface_from_a_pasted_file() {
    let mut h = open(lab());
    let text = format!("[Interface]\nPrivateKey = dwdtCnMYpX08FsFyUbJmRd9ML4frwJkqsXf7pR25LCo=\nAddress = 10.50.0.1/24\n\n# Name = loja\n[Peer]\nPublicKey = {K1}\nAllowedIPs = 10.50.0.2/32\nEndpoint = loja.example.com:51820\n");
    on_panel(&mut h, |p, app, _| p.import_for_test(app, &text));
    settle(&mut h);
    assert!(shows(&h, "Import WireGuard"));
    h.click(h.text("OK"));
    settle(&mut h);
    assert!(panel(&mut h).import.is_none(), "{:?}", h.app.log());
    let l = lock(&h.session).execute("interface.wireguard.peers.list", &json!({})).unwrap();
    let loja = l.as_array().unwrap().iter().find(|r| r["name"] == "loja").unwrap().clone();
    assert_eq!(loja["endpoint_address"], "loja.example.com");
}

#[test]
fn create_routes_goes_with_the_peer() {
    let mut h = open(lab());
    peers_tab(&mut h);
    panel(&mut h).filters.toggle("interface", "wg0");
    on_panel(&mut h, |p, app, ui| p.act_for_test(app, Act::Add, ui, true));
    settle(&mut h);
    let m = panel(&mut h).peer_modal.as_mut().unwrap();
    m.values.insert("name", "loja2".into());
    m.values.insert("allowed_address", "10.60.0.0/16".into());
    m.values.insert("create_routes", "yes".into());
    settle(&mut h);
    assert!(shows(&h, "routes through wg0: 10.60.0.0/16"));
    h.click(h.text("OK"));
    settle(&mut h);
    let r = lock(&h.session).execute("ip.route.list", &json!({})).unwrap();
    assert!(r.to_string().contains("10.60.0.0/16"), "{:?}", h.app.log());
}

#[test]
fn wireguard_interfaces_are_in_interfaces_too() {
    let mut h = Harness::with_session(lab());
    h.app.open.clear();
    h.app.open(Win::Interfaces);
    h.app.cache.refreshed_at = None;
    for _ in 0..4 {
        h.idle();
    }
    assert!(h.has_text("wg0") && h.has_text("wg-s2s"));
    assert!(h.has_text("wireguard"), "the type");
}

#[test]
fn the_window_is_in_the_menu_under_interfaces() {
    let m = crate::menu::CATALOG.iter().find(|e| e.key == "wireguard").unwrap();
    assert_eq!(m.path, "/interface wireguard");
    let (_, w) = crate::panel::find(crate::wireguard::WIN).unwrap();
    assert_eq!(w.group, "Interfaces");
}

#[test]
fn every_label_explains_itself_in_both_languages() {
    for key in WireguardPanel::help_keys() {
        for lang in crate::i18n::Lang::ALL {
            let langs = crate::i18n::Langs { labels: lang, help: lang };
            assert_eq!(crate::i18n::explain(langs, key).map(|(l, _)| l), Some(lang), "{key}");
        }
    }
}
