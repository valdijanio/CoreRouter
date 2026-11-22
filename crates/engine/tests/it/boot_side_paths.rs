//! G1.3g: a boot section left out (G1.3e) stays out of the other ways a
//! change reaches the data plane (DHCP and PPPoE leases, ports that come
//! back), as it does of a commit.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::sync::{Arc, Mutex};

use corerouter_engine::{MemoryStorage, Session};
use corerouter_hal::{
    DhcpPort, Features, Hal, HalError, LinkInfo, LinkState, SharedResponder, VirtualHal,
};
use corerouter_model::{Config, IfName};
use corerouter_proto_dhcp::lab::{Knobs, LabServer};
use serde_json::{Value, json};

/// A kernel that refuses the XDP program, the way `hal-linux` does it:
/// `xdp.sync(to)` runs on every apply (`hal-linux/src/lib.rs`,
/// `apply_present`), whatever changed.
struct NoXdp {
    inner: VirtualHal,
    applied: Arc<Mutex<Config>>,
}

impl Hal for NoXdp {
    fn describe(&self) -> String {
        "lab without XDP".into()
    }
    fn discover_links(&mut self) -> Result<Vec<LinkInfo>, HalError> {
        self.inner.discover_links()
    }
    fn apply(&mut self, from: &Config, to: &Config) -> Result<(), HalError> {
        if !to.ip.xdp.interfaces.is_empty() {
            return Err(HalError::Rejected(
                "xdp: attach refused (no driver support)".into(),
            ));
        }
        self.inner.apply(from, to)?;
        *self.applied.lock().unwrap() = to.clone();
        Ok(())
    }
    fn poll(&mut self) -> Vec<LinkState> {
        self.inner.poll()
    }
    fn absent_ports(&self) -> Vec<IfName> {
        self.inner.absent_ports()
    }
    fn now_unix(&self) -> Option<u64> {
        None
    }
    fn features(&self) -> Features {
        self.inner.features()
    }
    fn dhcp_port(&mut self, name: &IfName) -> Result<Box<dyn DhcpPort>, HalError> {
        self.inner.dhcp_port(name)
    }
    fn offer_dhcp_lab_server(&mut self, server: SharedResponder) {
        self.inner.offer_dhcp_lab_server(server);
    }
}

/// With the `xdp` section out since the boot, a DHCP lease goes in. Before
/// G1.3g the lease (`before`/`after` from `running`, no boot mask) carried
/// the refused XDP again and was undone: "lease not applied: … xdp: attach
/// refused" (**medido**, 2026-10-30).
#[test]
fn a_lease_goes_in_while_the_xdp_section_is_out() {
    let storage = MemoryStorage::default();
    let mut s = Session::with_storage(Box::new(VirtualHal::default()), Box::new(storage.clone()));
    for (id, p) in [
        (
            "ip.address.add",
            json!({"address": "10.0.0.1/24", "interface": "ether2"}),
        ),
        (
            "ip.firewall.xdp.interface.add",
            json!({"interface": "ether2"}),
        ),
        ("ip.dhcp-client.add", json!({"interface": "ether1"})),
    ] {
        s.execute(id, &p).unwrap();
    }
    drop(s);
    let server = Arc::new(LabServer::new(Knobs::default()));
    let applied = Arc::new(Mutex::new(Config::default()));
    let hal = NoXdp {
        inner: VirtualHal::default().with_dhcp_server(server),
        applied: applied.clone(),
    };
    let mut s = Session::with_storage(Box::new(hal), Box::new(storage));
    let st = s.inspect(None).unwrap();
    assert_eq!(st["storage"]["boot_apply_failed"][0]["section"], "xdp");
    s.tick(1_000_000);
    let mut now = 0;
    while now <= 2_000 {
        s.dhcp_service(now);
        now += 250;
    }
    let rows = s.execute("ip.dhcp-client.list", &Value::Null).unwrap();
    let c = &rows[0];
    let addrs: Vec<String> = applied
        .lock()
        .unwrap()
        .ip
        .addresses
        .iter()
        .map(|a| a.address.to_string())
        .collect();
    assert!(c["error"].is_null(), "{c}");
    assert_eq!(c["status"], "bound", "{c}");
    assert!(addrs.contains(&"10.0.0.1/24".to_owned()), "{addrs:?}");
    assert_eq!(addrs.len(), 2, "the lease's address is in: {addrs:?}");
    let st = s.inspect(None).unwrap();
    assert_eq!(st["storage"]["boot_apply_failed"][0]["section"], "xdp");
}

/// A port replugged while the `xdp` section is out gets its config back
/// (G1.3d with G1.3e): before G1.3g the put-back waited until every
/// section was in.
#[test]
fn a_replugged_port_gets_its_config_back_while_xdp_is_out() {
    let storage = MemoryStorage::default();
    let mut s = Session::with_storage(Box::new(VirtualHal::new(4)), Box::new(storage.clone()));
    for (id, p) in [
        (
            "ip.address.add",
            json!({"address": "192.0.2.2/24", "interface": "ether2"}),
        ),
        (
            "ip.firewall.xdp.interface.add",
            json!({"interface": "ether3"}),
        ),
    ] {
        s.execute(id, &p).unwrap();
    }
    drop(s);
    let applied = Arc::new(Mutex::new(Config::default()));
    let hal = NoXdp {
        inner: VirtualHal::new(4).with_replug("ether2".parse().unwrap(), 8),
        applied,
    };
    let mut s = Session::with_storage(Box::new(hal), Box::new(storage));
    for t in 0..12 {
        s.tick(1_000 + t);
    }
    let log = s
        .execute("log.print", &json!({"find": "ether2"}))
        .unwrap()
        .to_string();
    assert!(log.contains("its configuration was applied again"), "{log}");
    let st = s.inspect(None).unwrap();
    assert_eq!(st["storage"]["boot_apply_failed"][0]["section"], "xdp");
}
