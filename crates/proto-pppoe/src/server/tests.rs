//! Server behaviour, rule by rule, through the in-memory lab and raw frames.

use super::*;
use crate::client::ClientPhase;
use crate::lab::{Lab, LabConfig};
use crate::lcp::AuthProto;

fn lab(n: usize, f: impl FnOnce(&mut LabConfig)) -> Lab {
    let mut cfg = LabConfig {
        clients: n,
        ..LabConfig::default()
    };
    f(&mut cfg);
    let mut l = Lab::new(cfg);
    l.start_all();
    l
}

#[test]
fn every_auth_protocol_reaches_up() {
    for p in [
        AuthProto::Pap,
        AuthProto::ChapMd5,
        AuthProto::MsChapV1,
        AuthProto::MsChapV2,
    ] {
        let mut l = lab(3, |c| c.auth_cycle = vec![p]);
        l.run_until(10_000);
        assert_eq!(
            l.clients_up(),
            3,
            "{p:?}: {:?}",
            l.clients.iter().map(|c| c.phase()).collect::<Vec<_>>()
        );
        assert_eq!(l.stats.ups, 3);
        l.check().unwrap();
        for c in &l.clients {
            assert!(c.ipv4().is_some());
        }
    }
}

#[test]
fn ipv6cp_comes_up_with_ipcp() {
    let mut l = lab(2, |c| c.ipv6 = true);
    l.run_until(10_000);
    assert_eq!(l.clients_up(), 2);
    let sid = *l.up.keys().next().unwrap();
    let d = l.servers[0].session(sid.1).unwrap();
    assert!(d.ipv6_iid.is_some() && d.ipv4.is_some(), "{d:?}");
}

#[test]
fn wrong_password_is_refused_and_cleaned_up() {
    let mut l = lab(4, |c| c.bad_password_every = 2);
    l.run_until(30_000);
    assert_eq!(l.clients_up(), 2);
    assert_eq!(l.stats.auth_rejects, 2);
    assert_eq!(l.server_sessions(), 2, "failed sessions freed");
    assert!(
        l.clients
            .iter()
            .filter(|c| matches!(c.phase(), ClientPhase::Closed(_)))
            .count()
            == 2
    );
    l.check().unwrap();
}
