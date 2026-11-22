//! IPv6 › DHCPv6 Server (G4.2c), a panel: the lab's CPEs get an address and
//! a prefix, shown as rows with chips; the pools tab shows their use.

use super::*;
use crate::dhcp6_server::{Dhcp6Panel, Tab, WIN};
use corerouter_engine::lock;

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..3 {
        h.idle();
    }
}

#[test]
fn bindings_pools_and_servers() {
    let mut h = Harness::with_session(Session::virtual_lab());
    {
        let mut s = lock(&h.session);
        s.tick(1_700_000_000);
        for (id, p) in [
            ("ip.address.add", json!({"address": "2001:db8:1::1/64", "interface": "ether2"})),
            ("ipv6.pool.add", json!({"name": "addrs", "prefix": "2001:db8:1::/64", "prefix_length": 128})),
            ("ipv6.pool.add", json!({"name": "cpe", "prefix": "2001:db8:100::/48", "prefix_length": 56})),
            ("ipv6.dhcp-server.add", json!({"interface": "ether2", "address_pool": "addrs", "prefix_pool": "cpe"})),
        ] {
            s.execute(id, &p).unwrap_or_else(|e| panic!("{id}: {e}"));
        }
        for ms in (250..5_000).step_by(250) {
            s.tick(1_700_000_000 + ms / 1000);
            s.dhcp_service(ms);
        }
    }
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    refresh(&mut h);
    for t in ["dhcp6-1", "ether2", "running", "addrs", "cpe"] {
        assert!(h.has_text(t), "{t}");
    }
    h.app.panel_mut::<Dhcp6Panel>().unwrap().tab = Tab::Bindings;
    refresh(&mut h);
    assert!(h.has_text("PD") && h.has_text("NA") && h.has_text("bound"));
    assert!(h.has_text_containing("2001:db8:100:"));
    h.app.panel_mut::<Dhcp6Panel>().unwrap().tab = Tab::Pools;
    refresh(&mut h);
    assert!(h.has_text("2001:db8:100::/48"));
    let add = h
        .ctx
        .read_response(table::tool_id("dhcp6-pools", table::Icon::Add))
        .unwrap()
        .rect
        .center();
    h.click(add);
    refresh(&mut h);
    assert!(h.has_text("New IPv6 Pool"));
}
