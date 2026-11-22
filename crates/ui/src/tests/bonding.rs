//! Interfaces › Bonding (G1.8), a panel: list, properties, New.

use super::*;
use crate::bonding::{BondDialog, BondPanel, TABLE, WIN};
use corerouter_hal::VirtualHal;

#[test]
fn bonding_window_lists_opens_and_adds() {
    let mut s = Session::virtual_lab();
    s.execute(
        "interface.bonding.add",
        &json!({"name": "bond1", "slaves": ["ether1", "ether2"], "mode": "802.3ad",
                "transmit_hash_policy": "layer-3-and-4", "comment": "uplink"}),
    )
    .unwrap();
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    h.app.cache.refreshed_at = None;
    h.idle();
    h.idle();
    assert!(h.has_text("802.3ad"), "mode column");
    assert!(h.has_text("ether1, ether2"), "slaves column");
    assert!(h.has_text("layer-3-and-4"), "hash column");

    let row = h
        .ctx
        .read_response(table::row_id(TABLE, "bond1"))
        .expect("row drawn")
        .rect
        .center();
    h.right_click(row);
    h.click(h.text("Properties…"));
    assert!(h.has_text("Bonding <bond1>"));
    // Switch to active-backup with a primary, as the operator would.
    if let Some(BondDialog::Props { form, .. }) = h
        .app
        .panel_mut::<BondPanel>()
        .unwrap()
        .dialogs
        .first_mut()
        .map(|d| &mut d.dialog)
    {
        form.mode = "active-backup".into();
        form.primary = "ether2".into();
    }
    h.idle();
    assert!(h.has_text("Primary"), "primary shows for active-backup");
    h.click(h.text("OK"));
    for _ in 0..3 {
        h.idle();
    }
    let list = lock(&h.session)
        .execute("interface.bonding.list", &Value::Null)
        .unwrap();
    assert_eq!(list[0]["mode"], "active-backup", "{list}");
    assert_eq!(list[0]["primary"], "ether2", "{list}");

    // New: a free name is proposed; picking two ports and OK adds it.
    let add = h
        .ctx
        .read_response(table::tool_id(TABLE, table::Icon::Add))
        .expect("add tool")
        .rect
        .center();
    h.click(add);
    for _ in 0..3 {
        h.idle();
    }
    assert!(h.has_text("New Bonding"));
    if let Some(BondDialog::New { form, .. }) = h
        .app
        .panel_mut::<BondPanel>()
        .unwrap()
        .dialogs
        .first_mut()
        .map(|d| &mut d.dialog)
    {
        assert_eq!(form.name, "bonding1");
        form.slaves = vec!["ether3".into(), "ether4".into()];
    }
    h.idle();
    h.click(h.text("OK"));
    for _ in 0..3 {
        h.idle();
    }
    let list = lock(&h.session)
        .execute("interface.bonding.list", &Value::Null)
        .unwrap();
    assert_eq!(list[1]["name"], "bonding1", "{list} {:?}", h.app.log());
    assert_eq!(list[1]["slaves"], json!(["ether3", "ether4"]));
    assert_eq!(list[1]["mode"], "802.3ad");
}

/// G1.30m: the lab's radio shows greyed in "New Bonding", with an ⓘ that
/// opens the explanation; it cannot be picked.
#[test]
fn wifi_ports_show_greyed_with_an_explanation() {
    let mut s = Session::new(Box::new(VirtualHal::new(8).with_wifi(1)));
    for t in 0..4 {
        s.tick(1_000 + t);
    }
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    h.app.cache.refreshed_at = None;
    h.idle();
    h.idle();
    let add = h
        .ctx
        .read_response(table::tool_id(TABLE, table::Icon::Add))
        .expect("add tool")
        .rect
        .center();
    h.click(add);
    for _ in 0..3 {
        h.idle();
    }
    assert!(h.has_text("New Bonding"));
    assert!(h.has_text("wifi1"), "the radio is listed");
    // Clicking it changes nothing: it is disabled.
    h.click(h.text("wifi1"));
    h.idle();
    let form = match h
        .app
        .panel_mut::<BondPanel>()
        .unwrap()
        .dialogs
        .first()
        .map(|d| &d.dialog)
    {
        Some(BondDialog::New { form, .. }) => form.clone(),
        _ => panic!("no New Bonding dialog"),
    };
    assert!(form.slaves.is_empty(), "{:?}", form.slaves);
    let info = h
        .ctx
        .read_response(egui::Id::unique("bond-wifi-help"))
        .expect("ⓘ drawn")
        .rect
        .center();
    h.click(info);
    h.idle();
    assert_eq!(
        h.app
            .panel_mut::<BondPanel>()
            .unwrap()
            .help
            .as_ref()
            .map(|v| v.key.as_str()),
        Some("bonding.wifi_slave")
    );
}
