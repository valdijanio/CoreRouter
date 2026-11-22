//! G1.3e: a restored config the data plane refuses for a reason other than
//! an absent port (a firewall rule, a route, MPLS) still brings interfaces
//! and addresses up, so management stays reachable; the refused section
//! stays out, shown everywhere, and is retried with backoff.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::sync::{Arc, Mutex};

use corerouter_engine::auth::whoami;
use corerouter_engine::{MemoryStorage, Principal, Session};
use corerouter_hal::{Hal, HalError, LinkInfo, LinkState, VirtualHal};
use corerouter_model::Config;
use serde_json::{Value, json};

/// What the data plane refuses, switched by the test.
#[derive(Default, Clone, Copy)]
struct Refuse {
    firewall: bool,
    routes: bool,
    mpls: bool,
}

#[derive(Default)]
struct Seen {
    /// What the data plane holds.
    applied: Config,
    /// Every apply tried.
    tries: usize,
}

/// The virtual lab with a kernel that refuses what `Refuse` says (as one
/// without the nft module a rule needs, or without `mpls_router`). A
/// refused apply leaves the data plane as it was, as `hal-linux` does.
struct Picky {
    inner: VirtualHal,
    refuse: Arc<Mutex<Refuse>>,
    seen: Arc<Mutex<Seen>>,
}

impl Hal for Picky {
    fn describe(&self) -> String {
        "picky lab".into()
    }
    fn discover_links(&mut self) -> Result<Vec<LinkInfo>, HalError> {
        self.inner.discover_links()
    }
    fn apply(&mut self, from: &Config, to: &Config) -> Result<(), HalError> {
        let r = *self.refuse.lock().unwrap();
        let mut seen = self.seen.lock().unwrap();
        seen.tries += 1;
        if r.firewall && !to.ip.firewall.filter.is_empty() {
            return Err(HalError::Rejected(
                "nftables: Could not process rule: No such file or directory".into(),
            ));
        }
        if r.routes && !to.ip.routes.is_empty() {
            return Err(HalError::Rejected("route: Network is unreachable".into()));
        }
        if r.mpls && to.routing.mpls != Config::default().routing.mpls {
            return Err(HalError::Rejected("mpls: no mpls_router module".into()));
        }
        self.inner.apply(from, to)?;
        seen.applied = to.clone();
        Ok(())
    }
    fn poll(&mut self) -> Vec<LinkState> {
        self.inner.poll()
    }
    fn now_unix(&self) -> Option<u64> {
        None
    }
}

struct Booted {
    s: Session,
    refuse: Arc<Mutex<Refuse>>,
    seen: Arc<Mutex<Seen>>,
}

impl Booted {
    fn addresses(&self) -> Vec<String> {
        let seen = self.seen.lock().unwrap();
        let mut a: Vec<String> = seen
            .applied
            .ip
            .addresses
            .iter()
            .map(|a| a.address.to_string())
            .collect();
        a.sort();
        a
    }
    fn applied<T>(&self, f: impl Fn(&Config) -> T) -> T {
        f(&self.seen.lock().unwrap().applied)
    }
    fn tries(&self) -> usize {
        self.seen.lock().unwrap().tries
    }
    fn failed(&self) -> Vec<String> {
        let st = self.s.inspect(None).unwrap();
        st["storage"]["boot_apply_failed"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|f| f["section"].as_str().unwrap().to_owned())
                    .collect()
            })
            .unwrap_or_default()
    }
    fn error(&self) -> Value {
        self.s.inspect(None).unwrap()["storage"]["boot_apply_error"].clone()
    }
    fn check(&mut self, key: &str) -> Option<Value> {
        let v = self.s.execute("system.health.check", &json!({})).unwrap();
        v["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["key"] == key)
            .cloned()
    }
}

/// A config saved with a management address, a route, a firewall rule and
/// MPLS, booted on a data plane that refuses `refuse`.
fn boot(refuse: Refuse) -> Booted {
    let storage = MemoryStorage::default();
    let mut s = Session::with_storage(Box::new(VirtualHal::default()), Box::new(storage.clone()));
    for (id, p) in [
        (
            "ip.address.add",
            json!({"address": "10.0.0.1/24", "interface": "ether1"}),
        ),
        (
            "ip.route.add",
            json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.254"}),
        ),
        (
            "ip.firewall.filter.add",
            json!({"action": "drop", "chain": "forward"}),
        ),
        ("mpls.interface.add", json!({"interface": "all"})),
    ] {
        s.execute(id, &p).unwrap();
    }
    drop(s);
    let refuse = Arc::new(Mutex::new(refuse));
    let seen = Arc::new(Mutex::new(Seen::default()));
    let hal = Picky {
        inner: VirtualHal::default(),
        refuse: Arc::clone(&refuse),
        seen: Arc::clone(&seen),
    };
    let s = Session::with_storage(Box::new(hal), Box::new(storage));
    Booted { s, refuse, seen }
}

fn mpls_on(c: &Config) -> bool {
    c.routing.mpls != Config::default().routing.mpls
}

#[test]
fn a_clean_boot_is_one_apply() {
    let b = boot(Refuse::default());
    assert_eq!(b.tries(), 1);
    assert!(b.failed().is_empty());
    assert!(b.error().is_null());
    assert_eq!(b.addresses(), ["10.0.0.1/24"]);
    assert_eq!(b.applied(|c| c.ip.firewall.filter.len()), 1);
    assert!(b.applied(mpls_on));
}

/// The case that took a router off the network: one firewall rule the
/// kernel refuses kept every address down.
#[test]
fn management_comes_up_with_the_firewall_refused() {
    let mut b = boot(Refuse {
        firewall: true,
        ..Refuse::default()
    });
    assert_eq!(b.addresses(), ["10.0.0.1/24"], "management address applied");
    assert_eq!(b.applied(|c| c.ip.routes.len()), 1, "routes applied");
    assert!(b.applied(mpls_on), "MPLS applied");
    assert!(
        b.applied(|c| c.ip.firewall.filter.is_empty()),
        "the firewall stays out"
    );
    assert_eq!(b.failed(), ["firewall"]);
    let err = b.error();
    assert!(err.as_str().unwrap().starts_with("firewall: "), "{err}");
    assert!(
        err.as_str().unwrap().contains("Could not process rule"),
        "{err}"
    );
    // Health: an error, with the section and the kernel's reason.
    let c = b.check("boot.apply").unwrap();
    assert_eq!(c["severity"], "error");
    assert_eq!(c["value"], "firewall");
    assert!(
        c["reason"]
            .as_str()
            .unwrap()
            .contains("Could not process rule"),
        "{c}"
    );
    // Every client warns at login.
    let me = whoami(&b.s, &Principal::Local, "test");
    assert_eq!(me["boot_errors"][0]["section"], "firewall");
}

#[test]
fn a_refused_route_leaves_the_addresses_and_the_rest_up() {
    let b = boot(Refuse {
        routes: true,
        ..Refuse::default()
    });
    assert_eq!(b.addresses(), ["10.0.0.1/24"]);
    assert!(b.applied(|c| c.ip.routes.is_empty()));
    assert_eq!(
        b.applied(|c| c.ip.firewall.filter.len()),
        1,
        "the firewall is in"
    );
    assert!(b.applied(mpls_on));
    assert_eq!(b.failed(), ["routes"]);
}

#[test]
fn refused_mpls_leaves_the_rest_up() {
    let b = boot(Refuse {
        mpls: true,
        ..Refuse::default()
    });
    assert_eq!(b.addresses(), ["10.0.0.1/24"]);
    assert_eq!(b.applied(|c| c.ip.routes.len()), 1);
    assert_eq!(b.applied(|c| c.ip.firewall.filter.len()), 1);
    assert!(!b.applied(mpls_on));
    assert_eq!(b.failed(), ["mpls"]);
}

#[test]
fn several_sections_out_each_with_its_reason() {
    let b = boot(Refuse {
        firewall: true,
        mpls: true,
        routes: false,
    });
    assert_eq!(b.addresses(), ["10.0.0.1/24"]);
    assert_eq!(b.failed(), ["firewall", "mpls"]);
    let err = b.error();
    assert!(err.as_str().unwrap().contains("mpls: "), "{err}");
}

/// Not every second: 1, 2, 4… up to 60 s between retries.
#[test]
fn retries_back_off() {
    let mut b = boot(Refuse {
        firewall: true,
        ..Refuse::default()
    });
    let after_boot = b.tries();
    for t in 0..120 {
        b.s.tick(10_000 + t);
    }
    // Retries at +0, +1, +3, +7, +15, +31, +63: 7, not 120, each one
    // apply (only the firewall: the rest is in).
    assert_eq!(b.tries() - after_boot, 7);
    assert_eq!(b.failed(), ["firewall"]);
    assert_eq!(
        b.addresses(),
        ["10.0.0.1/24"],
        "management stays up across retries"
    );
}

#[test]
fn the_section_goes_in_once_the_kernel_takes_it() {
    let mut b = boot(Refuse {
        firewall: true,
        ..Refuse::default()
    });
    b.s.tick(10_000);
    b.refuse.lock().unwrap().firewall = false;
    b.s.tick(10_001);
    assert!(b.failed().is_empty());
    assert_eq!(b.applied(|c| c.ip.firewall.filter.len()), 1);
    assert!(b.error().is_null());
    assert!(b.check("boot.apply").is_none());
    assert!(
        whoami(&b.s, &Principal::Local, "test")
            .get("boot_errors")
            .is_none()
    );
}

/// A commit elsewhere works and leaves the refused section out; it does
/// not fail on the firewall it did not touch.
#[test]
fn a_commit_elsewhere_works_with_a_section_out() {
    let mut b = boot(Refuse {
        firewall: true,
        ..Refuse::default()
    });
    b.s.execute(
        "ip.address.add",
        &json!({"address": "10.9.0.1/24", "interface": "ether2"}),
    )
    .unwrap();
    assert_eq!(b.addresses(), ["10.0.0.1/24", "10.9.0.1/24"]);
    assert!(b.applied(|c| c.ip.firewall.filter.is_empty()));
    assert_eq!(b.failed(), ["firewall"]);
}

/// A commit that touches the refused section applies it whole: all or
/// nothing, as any commit.
#[test]
fn a_commit_on_the_refused_section_is_all_or_nothing() {
    let mut b = boot(Refuse {
        firewall: true,
        ..Refuse::default()
    });
    // Still refused: the commit fails and nothing changes.
    let before = b.s.store().running().clone();
    assert!(
        b.s.execute(
            "ip.firewall.filter.add",
            &json!({"action": "accept", "chain": "input"})
        )
        .is_err()
    );
    assert_eq!(*b.s.store().running(), before);
    assert_eq!(b.failed(), ["firewall"]);
    // The operator removes the rule the kernel refuses: the section is in.
    let id =
        b.s.store()
            .running()
            .ip
            .firewall
            .filter
            .first()
            .unwrap()
            .id
            .to_string();
    b.s.execute("ip.firewall.filter.remove", &json!({"id": id}))
        .unwrap();
    assert!(b.failed().is_empty());
    assert!(b.error().is_null());
    assert_eq!(b.addresses(), ["10.0.0.1/24"]);
}
