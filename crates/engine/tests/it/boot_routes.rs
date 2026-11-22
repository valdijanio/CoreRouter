//! G1.3g: a static route the kernel refuses at boot stays out alone; the
//! others go in one at a time (routes have no dry run), none taken back.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::sync::{Arc, Mutex};

use corerouter_engine::{MemoryStorage, Session};
use corerouter_hal::{
    DhcpPort, Features, Hal, HalError, LinkInfo, LinkState, RefusedItem, SharedResponder,
    VirtualHal,
};
use corerouter_model::{Config, IfName};
use corerouter_proto_dhcp::lab::{Knobs, LabServer};
use serde_json::{Value, json};

/// A route with this comment is one the kernel refuses.
const BAD: &str = "kernel refuses";

#[derive(Default)]
struct Seen {
    applied: Config,
    /// Calls of `apply_routes_each`.
    each: usize,
}

/// A kernel that refuses routes commented [`BAD`]: a whole apply with one
/// fails (and changes nothing), one at a time only that one stays out.
struct Picky {
    inner: VirtualHal,
    seen: Arc<Mutex<Seen>>,
}

fn bad(c: &Config) -> bool {
    c.ip.routes.iter().any(|r| !r.disabled && r.comment == BAD)
}

impl Hal for Picky {
    fn describe(&self) -> String {
        "picky lab".into()
    }
    fn discover_links(&mut self) -> Result<Vec<LinkInfo>, HalError> {
        self.inner.discover_links()
    }
    fn apply(&mut self, from: &Config, to: &Config) -> Result<(), HalError> {
        if bad(to) {
            return Err(HalError::Rejected("route: File exists".into()));
        }
        self.inner.apply(from, to)?;
        self.seen.lock().unwrap().applied = to.clone();
        Ok(())
    }
    fn apply_routes_each(
        &mut self,
        from: &Config,
        to: &Config,
    ) -> Result<Vec<RefusedItem>, HalError> {
        let mut take = to.clone();
        let refused: Vec<RefusedItem> = to
            .ip
            .routes
            .iter()
            .filter(|r| !r.disabled && r.comment == BAD)
            .map(|r| RefusedItem {
                id: r.id,
                reason: format!(
                    "could not add route {}: File exists (os error 17)",
                    r.dst_address
                ),
            })
            .collect();
        let mut routes = take.ip.routes.clone();
        for r in &refused {
            if let Some(i) = routes.iter().position(|x| x.id == r.id)
                && let Some(x) = routes.get_mut(i)
            {
                x.disabled = true;
            }
        }
        take.ip.routes = routes;
        self.inner.apply(from, &take)?;
        let mut seen = self.seen.lock().unwrap();
        seen.applied = take;
        seen.each += 1;
        Ok(refused)
    }
    fn poll(&mut self) -> Vec<LinkState> {
        self.inner.poll()
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

struct Booted {
    s: Session,
    seen: Arc<Mutex<Seen>>,
    ids: Vec<String>,
}

impl Booted {
    fn live_routes(&self) -> Vec<String> {
        let seen = self.seen.lock().unwrap();
        seen.applied
            .ip
            .routes
            .iter()
            .filter(|r| !r.disabled)
            .map(|r| r.dst_address.to_string())
            .collect()
    }
    fn failed(&self) -> Vec<Value> {
        let st = self.s.inspect(None).unwrap();
        st["storage"]["boot_apply_failed"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    }
    fn route(&mut self, id: &str) -> Value {
        let rows = self.s.execute("ip.route.list", &json!({})).unwrap();
        rows.as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == id)
            .cloned()
            .unwrap()
    }
}

/// Saved: an address on ether1, `routes` (dst, refused), maybe a DHCP
/// client on ether2; booted on [`Picky`].
fn boot(routes: &[(&str, bool)], dhcp: bool) -> Booted {
    let storage = MemoryStorage::default();
    let mut s = Session::with_storage(Box::new(VirtualHal::default()), Box::new(storage.clone()));
    s.execute(
        "ip.address.add",
        &json!({"address": "10.0.0.1/24", "interface": "ether1"}),
    )
    .unwrap();
    let mut ids = Vec::new();
    for (dst, refused) in routes {
        let mut p = json!({"dst_address": dst, "gateway": "10.0.0.254"});
        if *refused {
            p["comment"] = json!(BAD);
        }
        let v = s.execute("ip.route.add", &p).unwrap();
        ids.push(v["id"].as_str().unwrap().to_owned());
    }
    if dhcp {
        s.execute(
            "ip.dhcp-client.add",
            &json!({"interface": "ether2", "add_default_route": "no"}),
        )
        .unwrap();
    }
    drop(s);
    let seen = Arc::new(Mutex::new(Seen::default()));
    let hal = Picky {
        inner: VirtualHal::default().with_dhcp_server(Arc::new(LabServer::new(Knobs::default()))),
        seen: Arc::clone(&seen),
    };
    let s = Session::with_storage(Box::new(hal), Box::new(storage));
    Booted { s, seen, ids }
}

#[test]
fn only_the_refused_route_stays_out() {
    let mut b = boot(
        &[
            ("0.0.0.0/0", false),
            ("10.8.0.0/16", true),
            ("10.9.0.0/16", false),
        ],
        false,
    );
    assert_eq!(b.live_routes(), ["0.0.0.0/0", "10.9.0.0/16"]);
    assert_eq!(
        b.seen.lock().unwrap().each,
        1,
        "one pass, one route at a time"
    );
    let failed = b.failed();
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert_eq!(failed[0]["section"], "routes");
    let bad = b.ids[1].clone();
    assert_eq!(failed[0]["item"], bad.as_str());
    let row = b.route(&bad);
    assert!(row["flags"].as_str().unwrap().contains('I'), "{row}");
    assert_eq!(row["invalid"], true);
    assert!(
        row["invalid_reason"]
            .as_str()
            .unwrap()
            .contains("File exists"),
        "{row}"
    );
    let ok = b.ids[2].clone();
    assert_eq!(b.route(&ok)["invalid"], false);
    let v = b.s.execute("system.health.check", &json!({})).unwrap();
    let c = v["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["key"] == "boot.apply")
        .cloned()
        .unwrap();
    assert_eq!(c["value"], format!("routes {bad}"));
}

/// A commit elsewhere in the routes leaves the refused one out; removing
/// it clears the boot error.
#[test]
fn commits_with_a_route_out() {
    let mut b = boot(&[("0.0.0.0/0", false), ("10.8.0.0/16", true)], false);
    b.s.execute(
        "ip.route.add",
        &json!({"dst_address": "10.7.0.0/16", "gateway": "10.0.0.254"}),
    )
    .unwrap();
    assert_eq!(b.live_routes(), ["0.0.0.0/0", "10.7.0.0/16"]);
    assert_eq!(b.failed()[0]["item"], b.ids[1].as_str());
    let id = b.ids[1].clone();
    b.s.execute("ip.route.remove", &json!({"id": id})).unwrap();
    assert!(b.failed().is_empty());
}

/// A DHCP lease's routes go in with a static route out: the side path
/// masks the refused route only, not the routes section.
#[test]
fn a_lease_goes_in_with_a_route_out() {
    let mut b = boot(&[("10.8.0.0/16", true)], true);
    b.s.tick(1_000_000);
    let mut now = 0;
    while now <= 2_000 {
        b.s.dhcp_service(now);
        now += 250;
    }
    let rows = b.s.execute("ip.dhcp-client.list", &Value::Null).unwrap();
    assert!(rows[0]["error"].is_null(), "{}", rows[0]);
    assert_eq!(rows[0]["status"], "bound");
    let seen = b.seen.lock().unwrap();
    let addrs: Vec<String> = seen
        .applied
        .ip
        .addresses
        .iter()
        .map(|a| a.address.to_string())
        .collect();
    assert_eq!(addrs.len(), 2, "the lease's address is in: {addrs:?}");
    assert!(
        seen.applied
            .ip
            .routes
            .iter()
            .any(|r| r.comment == BAD && r.disabled),
        "the refused route stays out"
    );
    drop(seen);
    assert_eq!(b.failed()[0]["item"], b.ids[0].as_str());
}
