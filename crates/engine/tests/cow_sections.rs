//! G0.16: the rollback point of a command, the running config and the
//! history share the config sections nobody wrote, and a failed command
//! still puts back exactly the candidate it started from.

// Fixtures outside #[test] fns unwrap too (clippy.toml only covers tests).
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::Session;
use corerouter_hal::{Hal, HalError, LinkInfo, LinkState, VirtualHal};
use corerouter_model::cow::CowArc;
use corerouter_model::{Config, ConfigStore, Gateway, ItemId, RouteEntry, RoutingTable};
use serde_json::json;

/// A data plane that refuses any config with a port commented "refuse":
/// the commit fails after the command already changed the candidate.
struct Refuses(VirtualHal);

impl Hal for Refuses {
    fn describe(&self) -> String {
        "refusing lab".into()
    }
    fn discover_links(&mut self) -> Result<Vec<LinkInfo>, HalError> {
        self.0.discover_links()
    }
    fn apply(&mut self, from: &Config, to: &Config) -> Result<(), HalError> {
        if to.interfaces.values().any(|i| i.comment == "refuse") {
            return Err(HalError::Rejected("refused".into()));
        }
        self.0.apply(from, to)
    }
    fn poll(&mut self) -> Vec<LinkState> {
        self.0.poll()
    }
    fn now_unix(&self) -> Option<u64> {
        None
    }
}

/// `n` routes via 192.0.2.254 (reachable through ether1's 192.0.2.1/24).
fn with_routes(s: &mut Session, n: u32) {
    s.execute(
        "ip.address.add",
        &json!({"address": "192.0.2.1/24", "interface": "ether1"}),
    )
    .unwrap();
    let steps: Vec<_> = (0..n)
        .map(|i| {
            let [_, _, hi, lo] = i.to_be_bytes();
            json!({"command": "ip.route.add", "params": {
                "dst_address": format!("172.{}.{lo}.0/24", 16 + u32::from(hi)),
                "gateway": "192.0.2.254"}})
        })
        .collect();
    s.batch(&json!(steps), true).unwrap();
}

#[test]
fn a_failed_command_restores_the_candidate_it_started_from() {
    let mut s = Session::new(Box::new(Refuses(VirtualHal::default())));
    with_routes(&mut s, 2000);
    let before = s.store().candidate().clone();
    let revision = s.store().current_revision();

    let err = s
        .execute(
            "interface.set",
            &json!({"name": "ether2", "comment": "refuse"}),
        )
        .unwrap_err();
    assert!(err.to_string().contains("refused"), "{err}");

    let after = s.store().candidate();
    assert_eq!(*after, before);
    assert!(!s.store().is_dirty());
    assert_eq!(s.store().current_revision(), revision);
    // Bit for bit, through the saved form too.
    assert_eq!(
        serde_json::to_string(after).unwrap(),
        serde_json::to_string(&before).unwrap()
    );
    // What came back is the rollback point itself: nothing was copied.
    assert!(CowArc::ptr_eq(&after.ip, &before.ip));
    assert!(CowArc::ptr_eq(&after.interfaces, &before.interfaces));
}

#[test]
fn a_command_copies_only_the_section_it_writes() {
    let mut s = Session::virtual_lab();
    with_routes(&mut s, 1000);
    s.execute("config.mode.set", &json!({"mode": "transactional"}))
        .unwrap();
    s.execute(
        "interface.set",
        &json!({"name": "ether2", "comment": "uplink"}),
    )
    .unwrap();
    let st = s.store();
    assert!(st.is_dirty());
    // The 1000 routes are still the running config's, not a copy.
    assert!(CowArc::ptr_eq(&st.candidate().ip, &st.running().ip));
    assert!(!CowArc::ptr_eq(
        &st.candidate().interfaces,
        &st.running().interfaces
    ));
    s.execute("config.commit", &json!({})).unwrap();
    let st = s.store();
    let [.., older, newest] = st.history() else {
        panic!("history: {}", st.history().len())
    };
    // The new revision shares the routes with the one before it.
    assert!(CowArc::ptr_eq(&older.config.ip, &newest.config.ip));
    assert!(CowArc::ptr_eq(&newest.config.ip, &st.running().ip));
}

#[test]
fn rollback_points_survive_writes_to_the_shared_sections() {
    // The store alone: a copy taken before a write keeps the old routes.
    let mut st = ConfigStore::default();
    let route = |i: u32| RouteEntry {
        id: ItemId(i),
        dst_address: format!("10.{i}.0.0/16").parse().unwrap(),
        gateway: Gateway::ip("192.0.2.254".parse().unwrap()),
        distance: 1,
        routing_table: RoutingTable::Main,
        disabled: false,
        comment: String::new(),
    };
    st.candidate_mut().ip.routes.push(route(1));
    let point = st.candidate().clone();
    st.candidate_mut().ip.routes.push(route(2));
    st.candidate_mut().ip.routes[0].comment = "changed".into();
    assert_eq!(point.ip.routes.len(), 1);
    assert_eq!(point.ip.routes[0].comment, "");
    st.set_candidate(point.clone());
    assert_eq!(*st.candidate(), point);
}
