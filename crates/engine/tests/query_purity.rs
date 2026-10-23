//! audit-perf: `Session::execute` copies the candidate as a rollback point
//! only for commands that may change it (`journal`); queries run without
//! one. That holds only while no query edits the config: run every query
//! on a lab with some config and check nothing moved.
#![allow(clippy::unwrap_used)]

use corerouter_engine::{Session, cmd};
use serde_json::json;

#[test]
fn queries_leave_the_candidate_alone() {
    let mut s = Session::virtual_lab();
    for (id, params) in [
        ("ip.address.add", json!({"address": "192.0.2.1/24", "interface": "ether1"})),
        ("ip.route.add", json!({"dst_address": "198.51.100.0/24", "gateway": "192.0.2.254"})),
        ("ip.firewall.filter.add", json!({"chain": "input", "action": "accept"})),
        ("config.mode.set", json!({"mode": "transactional"})),
        ("system.identity.set", json!({"name": "pending"})),
    ] {
        s.execute(id, &params).unwrap();
    }
    assert!(s.store().is_dirty());
    let queries: Vec<_> = cmd::all().filter(|c| !c.journal).collect();
    assert!(queries.len() > 50, "{}", queries.len());
    for spec in queries {
        let before = s.store().candidate().clone();
        let revision = s.store().current_revision();
        let _ = s.execute(spec.id, &json!({}));
        assert!(
            s.store().candidate() == &before,
            "query {} changed the candidate",
            spec.id
        );
        assert_eq!(s.store().current_revision(), revision, "{} committed", spec.id);
    }
}
