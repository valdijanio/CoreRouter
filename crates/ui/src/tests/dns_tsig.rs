//! IP › DNS TSIG Keys (G4.1c-3), a panel.

use super::*;
use crate::dns_tsig::{TABLE, TsigPanel, WIN};

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..3 {
        h.idle();
    }
}

#[test]
fn a_new_key_shows_its_secret_once() {
    let mut h = Harness::with_session(Session::virtual_lab());
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    refresh(&mut h);
    assert!(h.has_text("DNS TSIG Keys"));
    let add = h
        .ctx
        .read_response(table::tool_id(TABLE, table::Icon::Add))
        .unwrap()
        .rect
        .center();
    h.click(add);
    refresh(&mut h);
    assert!(h.has_text("New TSIG Key"));
    h.app.panel_mut::<TsigPanel>().unwrap().dialog.as_mut().unwrap().name = "ddns".into();
    h.idle();
    h.click(h.text("OK"));
    refresh(&mut h);
    let p = h.app.panel_mut::<TsigPanel>().unwrap();
    assert!(p.dialog.is_none(), "{:?}", h.app.log());
    let (name, secret) = p.secret.clone().unwrap();
    assert_eq!(name, "ddns");
    assert_eq!(corerouter_model::dns_tsig::base64_decode(&secret).unwrap().len(), 32);
    assert!(h.has_text("ddns"));
    // Hidden, then shown again on demand.
    h.app.panel_mut::<TsigPanel>().unwrap().secret = None;
    h.idle();
    h.click(h.text("ddns"));
    h.idle();
    h.click(h.text("Show Secret"));
    refresh(&mut h);
    let again = h.app.panel_mut::<TsigPanel>().unwrap().secret.clone().unwrap();
    assert_eq!(again.1, secret);
}
