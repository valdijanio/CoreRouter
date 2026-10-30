//! G1.3b: a port of the config not on this machine shows flag I and the
//! amber `invalid` chip, with the reason in Info.

use serde_json::json;

#[test]
fn an_absent_port_is_flagged_invalid() {
    let row = json!({
        "name": "ether2", "type": "ether", "kind": "ether", "managed": true, "mtu": 1500,
        "disabled": false, "running": false, "comment": "",
        "invalid": true, "invalid_reason": "port not on this machine (unplugged or failed): its configuration waits for it",
    });
    let r = crate::interfaces::iface_row(&row, &Default::default());
    assert_eq!(r.cells[0], "I");
    assert!(r.cells[3].contains("invalid"), "{:?}", r.cells[3]);
    assert!(r.cells[10].contains("invalid: port not on this machine"), "{:?}", r.cells[10]);
    assert!(r.dimmed);
    // An older daemon sends no `invalid`: as before.
    let old = json!({"name": "ether1", "type": "ether", "mtu": 1500, "disabled": false, "running": true});
    let r = crate::interfaces::iface_row(&old, &Default::default());
    assert_eq!(r.cells[0], "R");
    assert!(!r.dimmed);
}
