//! G1.29b: USB Ethernet adapters over the in-process lab, where ether5 is
//! a RTL8153 on a USB 3 port and ether6 the same chip on a USB 2.0 port.

use std::sync::Arc;
use std::time::Duration;

use corerouter_engine::{Job, Runner};

use super::*;

/// Task threads on a clock that does not wait: a recovery's seconds cost
/// nothing (G0.30).
struct Instant0;

impl Runner for Instant0 {
    fn spawn(&self, _name: &str, job: Job) -> Result<(), String> {
        std::thread::spawn(move || job(&corerouter_engine::tasks::SimClock::default()));
        Ok(())
    }
}

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

/// G1.29c: the recovery buttons, confirmed inline, run the command and the
/// tab counts it.
#[test]
fn restart_driver_is_confirmed_then_counted() {
    let mut s = Session::virtual_lab();
    s.set_runner(Arc::new(Instant0));
    s.tick(1_000);
    let mut h = Harness::with_session(s);
    h.wait(1.1);
    h.app.open_props("ether6");
    h.wait(0.2);
    h.tab("Hardware");
    for b in ["Down/Up", "Restart Driver", "Reset USB Port"] {
        assert!(h.has_text(b), "{b}");
    }
    assert!(h.has_text("0 link · 0 driver · 0 port"));
    let at = h.find_text("Restart Driver").unwrap();
    h.click(at);
    h.idle();
    assert!(h.has_text_containing("Restart Driver? The driver lets go"), "asks first");
    let ok = h.find_text("Confirm").unwrap();
    h.click(ok);
    for _ in 0..40 {
        std::thread::sleep(Duration::from_millis(20));
        // The daemon's clock thread; here by hand.
        lock(&h.session).tick(1_001);
        h.wait(1.1);
        if h.has_text_containing("1 driver") {
            break;
        }
    }
    assert!(h.has_text_containing("0 link · 1 driver · 0 port · last: driver, came back"));
}

/// G1.29d: the watchdog's line and its switch.
#[test]
fn the_watchdog_switch_turns_it_off_for_the_adapter() {
    let mut h = Harness::new();
    h.wait(1.1);
    h.app.open_props("ether6");
    h.wait(0.2);
    h.tab("Hardware");
    assert!(h.has_text("Watchdog"));
    assert!(h.has_text_containing("ok · 0 stall(s)"));
    let at = h.find_text("enabled").unwrap();
    h.click(at);
    h.wait(1.5);
    let wd = lock(&h.session).store().running().system.usb_watchdog.clone();
    assert!(!wd.port(&"ether6".parse().unwrap()).enabled);
    assert!(h.has_text_containing("disabled · 0 stall(s)"));
}

/// G1.29g: a USB adapter outside the configuration (one that came back
/// with the kernel's name): the recovery buttons are off with the reason,
/// and "Adopt" sends `interface.ethernet.adopt`.
#[test]
fn a_port_outside_the_configuration_offers_adopt_not_reset() {
    let mut h = Harness::new();
    h.wait(1.1);
    h.app.open_props("ether6");
    h.wait(0.2);
    h.tab("Hardware");
    assert!(h.has_text("Restart Driver"));
    assert!(!h.has_text("Adopt"), "a managed port has no Adopt");
    // What interface.list says of a port the configuration does not have.
    let unmanage = |h: &mut Harness| {
        for row in h.app.cache.interfaces.iter_mut() {
            if row["name"] == "ether6" {
                row["managed"] = json!(false);
                row["unmanaged_reason"] = json!("not in the configuration (appeared after boot)");
            }
        }
    };
    unmanage(&mut h);
    h.idle();
    assert!(h.has_text("Not in the configuration (appeared after boot)"));
    assert!(h.has_text("Adopt"));
    // The buttons are off: a click asks nothing.
    let at = h.find_text("Restart Driver").unwrap();
    h.click(at);
    unmanage(&mut h);
    h.idle();
    assert!(!h.has_text_containing("Restart Driver? The driver lets go"), "disabled");
    let at = h.find_text("Adopt").unwrap();
    h.click(at);
    h.wait(0.5);
    assert!(
        h.app.log().iter().any(|l| l.command == "interface.ethernet.adopt"),
        "{:?}",
        h.app.log().iter().map(|l| &l.command).collect::<Vec<_>>()
    );
}
