//! G1.30h: the Wi-Fi country from "Interface <wifi1>" and from Enable.
//! A radio without a country says so (amber chip, Set Country…) in the
//! General and Wi-Fi tabs; Enable on it opens the country dialog with
//! "Also enable" ticked, so one OK sets the country and turns it on; a
//! refused OK reads as the window's own warning, not a terminal command;
//! Enable from the lists asks for the country too; Scan… and Connect… open
//! Interfaces › Wi-Fi on this radio.

use super::*;
use crate::wifi::{WIN, WifiPanel};
use corerouter_hal::VirtualHal;
use corerouter_hal::lab_wifi::LAB_PASSPHRASE;

/// The lab with `wifi1` adopted: off, no network, no country.
fn lab() -> Session {
    let mut s = Session::new(Box::new(VirtualHal::new(8).with_wifi(1)));
    for t in 0..4 {
        s.tick(1_000 + t);
    }
    s
}

fn harness(s: Session) -> Harness {
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h
}

/// "Interface <wifi1>", with its queries answered.
fn props(s: Session) -> Harness {
    let mut h = harness(s);
    h.app.open_props("wifi1");
    h.wait(1.2);
    h
}

fn country_dialog(h: &mut Harness) -> Option<(Vec<String>, bool)> {
    let p = h.app.panel_mut::<WifiPanel>()?;
    p.country_dialog.as_ref().map(|d| (d.enable.clone(), d.enable_on))
}

fn type_country(h: &mut Harness, c: &str) {
    if let Some(d) = h.app.panel_mut::<WifiPanel>().and_then(|p| p.country_dialog.as_mut()) {
        d.value = c.into();
    }
    h.idle();
}

fn wifi1(h: &Harness) -> Value {
    let list = lock(&h.session)
        .execute("interface.wifi.list", &Value::Null)
        .unwrap();
    list.as_array()
        .and_then(|a| a.iter().find(|r| r["name"] == "wifi1").cloned())
        .expect("wifi1 listed")
}

fn country(h: &Harness) -> Value {
    lock(&h.session)
        .execute("interface.wifi.country.get", &Value::Null)
        .unwrap()["country"]
        .clone()
}

#[test]
fn a_radio_without_a_country_offers_set_country_in_general_and_wifi() {
    let mut h = props(lab());
    assert!(h.has_text("Country"), "General: the country row");
    assert!(h.has_text("no country"), "General: the amber chip");
    assert!(h.has_text("Set Country…"), "General: the button");
    h.tab("Wi-Fi");
    h.wait(1.2);
    assert!(h.has_text("no country"), "Wi-Fi: the state chip");
    assert!(h.has_text("Set Country…"), "Wi-Fi: the button");
    assert!(h.has_text("Scan…") && h.has_text("Connect…"), "Wi-Fi: join from here");
    h.click(h.text("Set Country…"));
    h.idle();
    let (enable, on) = country_dialog(&mut h).expect("the country dialog opened");
    assert_eq!(enable, ["wifi1"], "the off radio is offered");
    assert!(!on, "not ticked: Set Country… is not Enable");
    assert!(h.has_text("Wi-Fi Country") && h.has_text("Also enable wifi1"));
}

#[test]
fn enable_without_a_country_opens_the_dialog_and_one_ok_does_both() {
    let mut h = props(lab());
    h.click(h.text("Enable"));
    h.idle();
    let (enable, on) = country_dialog(&mut h).expect("Enable asks for the country");
    assert_eq!((enable, on), (vec!["wifi1".to_owned()], true));
    assert!(h.log_ids().is_empty(), "nothing sent yet: {:?}", h.log_ids());
    type_country(&mut h, "br");
    // Enter: OK of the front window, the country dialog.
    h.key(egui::Key::Enter, egui::Modifiers::NONE);
    h.wait(1.2);
    assert_eq!(country(&h), "BR");
    assert_eq!(wifi1(&h)["disabled"], false, "the same OK enabled it");
    assert!(country_dialog(&mut h).is_none(), "closed on success");
    let p = h
        .app
        .dialogs
        .iter()
        .find_map(|d| match &d.dialog {
            crate::interfaces::Dialog::Props(p) => Some(p),
            _ => None,
        })
        .expect("Interface <wifi1> stays open");
    assert!(!p.disabled, "the Disabled box follows the radio");
    assert!(!h.has_text("no country"));
}

#[test]
fn a_refused_ok_reads_as_the_window_warning_not_a_command() {
    let mut h = props(lab());
    // The operator unticks Disabled and presses OK.
    for d in &mut h.app.dialogs {
        if let crate::interfaces::Dialog::Props(p) = &mut d.dialog {
            p.disabled = false;
        }
    }
    h.idle();
    h.click(h.text("OK"));
    h.wait(0.5);
    assert!(
        h.has_text_containing("Set the Wi-Fi country before enabling this radio"),
        "the window's own words"
    );
    let d = h.app.dialogs.first().expect("the window stays open");
    // No red line with a terminal command (the router log keeps the
    // engine's words, command included, for the record).
    assert!(d.status.error.is_none(), "the refusal was the only issue");
    // The warning's button: the dialog, ticked (the operator wanted it on).
    let at = *h.all_text("Set Country…").last().expect("the warning's button");
    h.click(at);
    h.idle();
    let (enable, on) = country_dialog(&mut h).expect("the country dialog");
    assert_eq!(enable, ["wifi1"]);
    assert!(on || h.has_text("Also enable wifi1"));
}

#[test]
fn enable_from_the_interfaces_list_asks_for_the_country() {
    let mut h = harness(lab());
    h.app.open(Win::Interfaces);
    h.app.cache.refreshed_at = None;
    h.wait(0.5);
    h.click(h.row("wifi1"));
    h.idle();
    h.click(h.tool(table::Icon::Enable));
    h.wait(0.5);
    let (enable, on) = country_dialog(&mut h).expect("the refusal opened the country dialog");
    assert_eq!((enable, on), (vec!["wifi1".to_owned()], true));
    type_country(&mut h, "DE");
    h.key(egui::Key::Enter, egui::Modifiers::NONE);
    h.wait(0.5);
    assert_eq!(country(&h), "DE");
    assert_eq!(wifi1(&h)["disabled"], false);
}

#[test]
fn enable_in_the_wifi_window_asks_for_the_country_first() {
    let mut h = harness(lab());
    h.app.open(Win::Panel(WIN));
    h.app.cache.refreshed_at = None;
    h.wait(0.5);
    let row = h
        .ctx
        .read_response(table::row_id(crate::wifi::TABLE, "wifi1"))
        .expect("wifi1 drawn")
        .rect
        .center();
    h.click(row);
    h.idle();
    let enable = h
        .ctx
        .read_response(table::tool_id(crate::wifi::TABLE, table::Icon::Enable))
        .expect("the Enable tool")
        .rect
        .center();
    h.click(enable);
    h.idle();
    let (names, on) = country_dialog(&mut h).expect("the country dialog, not a refusal");
    assert_eq!((names, on), (vec!["wifi1".to_owned()], true));
    assert!(h.log_ids().is_empty(), "nothing refused: {:?}", h.log_ids());
}

#[test]
fn scan_and_connect_open_the_wifi_window_on_this_radio() {
    let mut s = lab();
    s.execute("interface.wifi.country.set", &json!({"country": "BR"}))
        .unwrap();
    s.execute(
        "interface.wifi.set",
        &json!({"name": "wifi1", "ssid": "CoreRouter-Lab", "passphrase": LAB_PASSPHRASE, "disabled": false}),
    )
    .unwrap();
    let mut h = props(s);
    h.tab("Wi-Fi");
    h.wait(1.2);
    assert!(!h.has_text("Set Country…"), "a country is set");
    assert!(h.has_text("Change…"));
    h.click(h.text("Scan…"));
    h.wait(0.5);
    assert!(h.app.open.contains(&Win::Panel(WIN)), "Interfaces › Wi-Fi opened");
    assert!(h.log_ids().contains(&"interface.wifi.scan"), "{:?}", h.log_ids());
    {
        let p = h.app.panel_mut::<WifiPanel>().unwrap();
        assert_eq!((p.tab, p.radio.as_str()), (crate::wifi::Tab::Networks, "wifi1"));
    }
    h.app.open.remove(&Win::Panel(WIN));
    h.wait(0.2);
    let at = *h.all_text("Connect…").first().expect("Connect…");
    h.click(at);
    h.wait(0.5);
    let p = h.app.panel_mut::<WifiPanel>().unwrap();
    assert_eq!(p.tab, crate::wifi::Tab::Radios);
    assert!(p.modal.is_some(), "the radio's modal opened");
}

#[test]
fn the_mark_is_in_the_engines_text_and_only_that_issue_goes() {
    use crate::interfaces::without_no_country;
    let msg = corerouter_model::wifi::NO_COUNTRY;
    assert!(crate::wifi::is_no_country(msg), "the UI recognises the engine's refusal");
    let one = format!("validation failed: interfaces.wifi1.disabled: {msg}");
    assert_eq!(without_no_country(&one), Some(None));
    let two = format!("validation failed: interfaces.wifi1.disabled: {msg}; interfaces.wifi1.ssid: too long");
    assert_eq!(
        without_no_country(&two),
        Some(Some("validation failed: interfaces.wifi1.ssid: too long".to_owned()))
    );
    assert_eq!(without_no_country("parameter 'mtu': too big"), None);
}

#[test]
fn the_new_explanation_exists_in_both_languages() {
    for lang in [crate::i18n::Lang::Pt, crate::i18n::Lang::En] {
        let langs = crate::i18n::Langs { labels: lang, help: lang };
        let (got, _) = crate::i18n::explain(langs, "iface_wifi.need_country").expect("written");
        assert_eq!(got, lang);
    }
    assert_eq!(crate::i18n::tr_in("wifi", crate::i18n::Lang::Pt, "Also enable"), "Ativar também");
}

#[test]
fn an_empty_field_does_not_try_to_enable() {
    let mut h = props(lab());
    h.click(h.text("Enable"));
    h.idle();
    // OK with the field left empty: the engine reads it as "no country".
    h.key(egui::Key::Enter, egui::Modifiers::NONE);
    h.wait(0.5);
    let p = h.app.panel_mut::<WifiPanel>().unwrap();
    let d = p.country_dialog.as_ref().expect("stays open");
    let error = d.status.error.clone().unwrap_or_default();
    assert!(error.contains("two letters"), "{error}");
    assert!(!h.log_ids().contains(&"interface.wifi.enable"), "{:?}", h.log_ids());
    assert_eq!(wifi1(&h)["disabled"], true);
}
