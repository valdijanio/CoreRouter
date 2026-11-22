//! G3.9hc: the S-tag (802.1ad) in Interfaces › New VLAN, the list and the
//! "Interface <name>" window.

use super::*;

#[test]
fn new_vlan_with_service_tag_shows_as_s_vlan() {
    let mut h = Harness::new();
    h.app
        .interface_act(interfaces::Act::NewVlan { parent: Some("ether1".into()) }, &[]);
    h.idle();
    h.idle();
    assert!(h.has_text("Use Service Tag"));
    h.click(h.text("vlan100"));
    h.type_text("s100");
    h.click(h.text("1..4094"));
    h.type_text("100");
    h.click(h.text("802.1ad S-tag (0x88a8)"));
    h.click(h.text("OK"));
    assert!(h.app.dialogs.is_empty(), "OK closes on success");
    let s = h.iface("s100").expect("S-VLAN created");
    assert_eq!(
        (&s["parent"], &s["vlan_id"], &s["use_service_tag"]),
        (&json!("ether1"), &json!(100), &json!(true))
    );
    h.idle();
    assert!(h.has_text_containing("s-vlan 100 on ether1 (802.1ad)"));

    // A plain VLAN sends no `use_service_tag` at all (older daemons).
    h.app
        .interface_act(interfaces::Act::NewVlan { parent: Some("ether1".into()) }, &[]);
    h.idle();
    h.idle();
    h.click(h.text("vlan100"));
    h.type_text("v30");
    h.click(h.text("1..4094"));
    h.type_text("30");
    h.click(h.text("OK"));
    assert_eq!(h.iface("v30").unwrap()["use_service_tag"], false);
    h.idle();
    assert!(h.has_text_containing("vlan 30 on ether1"));

    // The properties window says which tag it is.
    h.app.interface_act(interfaces::Act::Open(vec!["s100".into()]), &[]);
    h.idle();
    h.idle();
    assert!(h.has_text("yes (802.1ad, 0x88a8)"));
}
