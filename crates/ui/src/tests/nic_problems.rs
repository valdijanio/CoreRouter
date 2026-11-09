//! Interfaces (G1.6ja): the chip on the port, and the toolbar's chips of the
//! cards the kernel could not bring up, with the list behind them.

use serde_json::json;

use super::*;

#[test]
fn the_port_carries_the_chip_and_the_reason() {
    let row = json!({
        "name": "ether7", "type": "ether", "kind": "ether", "managed": true, "mtu": 1500,
        "disabled": false, "running": true, "comment": "",
        "hardware_problem": "safe-mode", "hardware_problem_reason": "ether7: ice em Safe Mode",
    });
    let r = crate::interfaces::iface_row(&row, &Default::default());
    assert!(r.cells[3].contains("up"), "{:?}", r.cells[3]);
    assert!(r.cells[3].contains("safe mode"), "{:?}", r.cells[3]);
    assert!(r.cells[10].contains("ice em Safe Mode"), "{:?}", r.cells[10]);
    // An older daemon sends nothing: as before.
    let old = json!({"name": "ether1", "type": "ether", "mtu": 1500, "disabled": false, "running": true});
    let r = crate::interfaces::iface_row(&old, &Default::default());
    assert!(!r.cells[3].contains("safe mode"), "{:?}", r.cells[3]);
}

#[test]
fn the_toolbar_counts_the_cards_and_opens_the_list() {
    let mut h = Harness::new();
    h.app.open.insert(Win::Interfaces);
    h.app.cache.refreshed_at = None;
    for _ in 0..4 {
        h.idle();
    }
    let panel = h.app.panel_mut::<crate::nic_problems::NicProblems>().unwrap();
    assert_eq!(panel.counts_for_test(), (vec![("no driver", 1), ("safe mode", 1)], 0));
    let at = h.find_text("1 no driver").expect("the chip");
    h.click(at);
    h.idle();
    assert!(h.has_text("Network card problems"), "the list opened");
    assert!(h.has_text("intel/ice/ddp/ice.pkg"), "the file is named");
    assert!(!h.has_text_containing("regulatory"), "and regulatory.db is not");
    assert!(h.has_text_containing("Wi-Fi"), "the card that does not count says why");
}
