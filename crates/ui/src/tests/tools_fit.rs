//! Tool windows open as tall as their form and grow with the results; DNS
//! Cache's Resolve… opens Tools › DNS Lookup (IP › DNS Resolve is gone).

use super::*;
use crate::dns_lookup::{LookupPanel, WIN as LOOKUP};

#[test]
fn dns_lookup_and_mtr_open_as_tall_as_their_form() {
    let mut h = Harness::new();
    h.app.open.clear();
    h.app.open(Win::Panel(LOOKUP));
    h.app.open(Win::Mtr);
    for _ in 0..4 {
        h.idle();
    }
    for win in [Win::Panel(LOOKUP), Win::Mtr] {
        let r = h.win_rect(win_id(win));
        assert!(r.height() < 260.0, "{win:?} opens {} tall", r.height());
    }
}

#[test]
fn resolve_in_dns_cache_opens_dns_lookup_with_the_name() {
    let mut h = Harness::new();
    h.app.open.clear();
    h.app.open(Win::Panel(crate::dns::WIN_CACHE));
    h.idle();
    h.idle();
    h.click(h.text("Resolve…"));
    h.idle();
    assert!(h.app.open.contains(&Win::Panel(LOOKUP)), "opened from DNS Cache");
    crate::dns_lookup::open_with(&mut h.app, "uol.com.br", "AAAA");
    let p = h.app.panel_mut::<LookupPanel>().unwrap();
    assert_eq!((p.name.as_str(), p.rtype.as_str()), ("uol.com.br", "AAAA"));
    // A type the form does not offer keeps the one it had.
    crate::dns_lookup::open_with(&mut h.app, "example.com", "HTTPS");
    let p = h.app.panel_mut::<LookupPanel>().unwrap();
    assert_eq!((p.name.as_str(), p.rtype.as_str()), ("example.com", "AAAA"));
}
