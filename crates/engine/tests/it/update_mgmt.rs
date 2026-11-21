//! G1.6ba — the ports an update waits for before it confirms itself: the
//! static addresses *and* the leases (DHCP here), never the DHCP fallback
//! address. On the notebook (dev.701) the router was managed over a DHCP
//! lease on ether2 and the update recorded no port at all.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::sync::Arc;

use corerouter_engine::Session;
use corerouter_engine::package::{feed_status, reachable_ports, take_job};
use corerouter_hal::VirtualHal;
use corerouter_proto_dhcp::lab::{Knobs, LabServer};
use serde_json::{Value, json};

struct Lab {
    s: Session,
    server: Arc<LabServer>,
    now: u64,
}

impl Lab {
    fn new(knobs: Knobs) -> Self {
        let server = Arc::new(LabServer::new(knobs));
        let hal = VirtualHal::default().with_dhcp_server(server.clone());
        let mut s = Session::new(Box::new(hal));
        s.tick(1_000_000);
        feed_status(
            &mut s,
            json!({"supported": true, "running": "a", "trial": null, "slots": []}),
        );
        Self { s, server, now: 0 }
    }

    fn ok(&mut self, id: &str, p: Value) -> Value {
        self.s
            .execute(id, &p)
            .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
    }

    fn run(&mut self, ms: u64) {
        let end = self.now + ms;
        while self.now <= end {
            self.s.dhcp_service(self.now);
            self.now += 250;
        }
    }

    /// The ports a `system.package.update` queued now records.
    fn update_waits_for(&mut self) -> Vec<String> {
        self.ok("system.package.update", json!({"path": "/tmp/x.crpkg"}));
        take_job(&mut self.s).unwrap().mgmt
    }
}

#[test]
fn an_update_waits_for_the_lease_as_for_a_static_address() {
    let mut l = Lab::new(Knobs::default());
    l.ok(
        "ip.address.add",
        json!({"address": "10.9.0.1/24", "interface": "ether3"}),
    );
    l.ok("ip.dhcp-client.add", json!({"interface": "ether1"}));
    l.run(1_000);
    assert_eq!(
        l.ok("ip.dhcp-client.list", Value::Null)[0]["status"],
        "bound"
    );
    assert_eq!(l.update_waits_for(), ["ether1", "ether3"]);
    // After the reboot: the port runs but the client lost the lease (a new
    // image whose DHCP client does not work) — not reachable, no confirm.
    l.server.set(|k| k.silent = true);
    l.ok("ip.dhcp-client.release", json!({"id": "*1"}));
    l.run(1_000);
    assert_eq!(reachable_ports(&mut l.s), ["ether3"]);
    // The lease comes back: both ports reach the operator again.
    l.server.set(|k| k.silent = false);
    l.run(70_000);
    assert_eq!(reachable_ports(&mut l.s), ["ether1", "ether3"]);
}

#[test]
fn the_dhcp_fallback_address_does_not_count() {
    let mut l = Lab::new(Knobs {
        silent: true,
        ..Knobs::default()
    });
    l.ok(
        "ip.dhcp-client.add",
        json!({"interface": "ether1", "fallback_address": "192.168.100.2/24", "fallback_timeout": 5}),
    );
    l.run(6_000);
    assert_eq!(
        l.ok("ip.dhcp-client.list", Value::Null)[0]["fallback_active"],
        true
    );
    // No lease: nothing to wait for, as a router with no address at all.
    assert!(reachable_ports(&mut l.s).is_empty());
    assert!(l.update_waits_for().is_empty());
}
