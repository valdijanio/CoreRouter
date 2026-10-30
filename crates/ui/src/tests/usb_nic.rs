//! G1.29b: USB Ethernet adapters over the in-process lab, where ether5 is
//! a RTL8153 on a USB 3 port and ether6 the same chip on a USB 2.0 port.

use super::*;

#[test]
fn usb_marks_follow_the_interface_list() {
    let mut h = Harness::new();
    h.wait(1.1);
    let ctx = h.ctx.clone();
    let five = crate::usb_mark::get(&ctx, "ether5").expect("ether5 is USB");
    assert!(!five.slow);
    assert_eq!(five.tip, "USB 3.0 (5 Gbps) · port 5-1 · r8152");
    let six = crate::usb_mark::get(&ctx, "ether6").expect("ether6 is USB");
    assert!(six.slow, "a USB 3 adapter on a USB 2.0 port");
    assert!(six.tip.contains("Slow port: USB 3.0 adapter negotiated USB 2.0"));
    assert!(crate::usb_mark::get(&ctx, "ether1").is_none());
    assert!(crate::usb_mark::in_title(&ctx, "Interface <ether6>").is_some());
    assert!(crate::usb_mark::in_title(&ctx, "Interface <ether1>").is_none());
}

#[test]
fn hardware_tab_shows_the_usb_port_and_the_slow_port_alert() {
    let mut h = Harness::new();
    h.wait(1.1);
    h.app.open_props("ether6");
    h.wait(0.2);
    h.tab("Hardware");
    for text in ["USB", "USB Speed", "Adapter Supports", "Port", "USB ID", "Max Power", "Power Saving", "Tx Timeouts"] {
        assert!(h.has_text(text), "{text}");
    }
    assert!(h.has_text_containing("USB 2.0 (480 Mbps) · slow port"), "the amber chip");
    assert!(h.has_text("USB 3.0 (5 Gbps)"), "what the adapter can do");
    assert!(h.has_text("0bda:8153 rev 3100"));
    assert!(h.has_text("288 mA"));
    assert!(h.has_text_containing("USB 3.0 adapter negotiated USB 2.0 (480 Mbps): about 300 Mbit/s"));
    assert!(h.has_text("Realtek [0bda]"), "vendor row from the USB ids");
}

#[test]
fn a_fast_port_has_no_alert() {
    let mut h = Harness::new();
    h.wait(1.1);
    h.app.open_props("ether5");
    h.wait(0.2);
    h.tab("Hardware");
    assert!(h.has_text("USB 3.0 (5 Gbps)"));
    assert!(!h.has_text_containing("slow port"));
}

#[test]
fn a_pci_card_has_no_usb_section() {
    let mut h = Harness::new();
    h.wait(1.1);
    h.app.open_props("ether1");
    h.wait(0.2);
    h.tab("Hardware");
    assert!(!h.has_text("USB Speed"));
}
