//! IP › Fast Path (G2.4): the window over the lab (two simulated ConnectX
//! ports), turning it on from the form, the ports' offload and the fix.

use super::*;
use crate::fastpath::{FastPath, WIN};

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..3 {
        h.idle();
    }
}

fn harness() -> Harness {
    let mut h = Harness::with_session(Session::virtual_lab());
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    refresh(&mut h);
    h
}

#[test]
fn off_then_on_from_the_form() {
    let mut h = harness();
    assert!(h.has_text("off"), "the state chip");
    assert!(h.has_text("ether7") && h.has_text("legacy"));
    assert!(!lock(&h.session).store().running().ip.fastpath.enabled);
    h.click(h.text("Enabled"));
    h.idle();
    h.click(h.text("Apply"));
    refresh(&mut h);
    assert!(lock(&h.session).store().running().ip.fastpath.enabled, "{:?}", h.app.log());
    assert!(h.has_text("installed"));
    assert!(h.has_text("hardware"), "ether8, the switchdev port");
    assert!(h.has_text_containing("devlink dev eswitch set pci/0000:3b:00.0 mode switchdev"), "the fix for ether7");
    let fp = h.app.panel_mut::<FastPath>().unwrap();
    assert!(fp.form.is_none(), "the form follows the router again");
}

#[test]
fn a_refused_setting_says_why() {
    let mut h = harness();
    {
        let fp = h.app.panel_mut::<FastPath>().unwrap();
        let mut f = fp.form.clone().unwrap_or_default();
        f.enabled = true;
        f.interfaces = "ether1".into();
        f.hw_offload = "yes".into();
        fp.form = Some(f);
    }
    h.idle();
    h.click(h.text("Apply"));
    refresh(&mut h);
    assert!(h.has_text_containing("use auto"), "{:?}", h.app.log());
    assert!(!lock(&h.session).store().running().ip.fastpath.enabled);
}
