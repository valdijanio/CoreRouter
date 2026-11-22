use super::*;
use crate::server6::IaKind;
use crate::v6::{IaReq, Outgoing};
use proptest::prelude::*;

const CLIENT: &[u8] = &[0, 3, 0, 1, 2, 0, 0, 0, 0, 9];

fn grant() -> Grant6 {
    Grant6 {
        server_duid: duid_ll([2, 0, 0, 0, 0, 1]),
        address: Some("2001:db8:0:5::1234".parse().unwrap()),
        link: Some("2001:db8:0:5::/64".parse().unwrap()),
        prefix: Some("2001:db8:100:500::/56".parse().unwrap()),
        dns: vec!["2001:db8::53".parse().unwrap()],
        domains: vec!["isp.example".into()],
        lease_time: 86_400,
        rapid_commit: true,
    }
}

fn out(kind: u8) -> Outgoing<'static> {
    Outgoing {
        kind,
        xid: 0x00ab_cdef,
        client_id: CLIENT,
        server_id: None,
        elapsed_cs: 0,
        rapid_commit: false,
        ia_na: Some(IaReq {
            iaid: 1,
            ..IaReq::default()
        }),
        ia_pd: Some(IaReq {
            iaid: 2,
            ..IaReq::default()
        }),
        oro: &[opt::DNS_SERVERS, opt::DOMAIN_LIST],
    }
}

fn read(a: &Answer6) -> v6::Incoming {
    v6::decode(a.reply.as_ref().expect("a reply")).unwrap()
}

#[test]
fn rfc9915_18_3_1_solicit_gets_the_session_prefix_and_address() {
    let mut s = Sub6::new(grant());
    let a = s.handle(&out(msg::SOLICIT).encode());
    let r = read(&a);
    assert_eq!(r.kind, msg::ADVERTISE);
    assert_eq!(r.xid, 0x00ab_cdef);
    assert_eq!(r.server_id.as_deref(), Some(grant().server_duid.as_slice()));
    assert_eq!(r.client_id.as_deref(), Some(CLIENT));
    assert_eq!(r.ia_pd[0].iaid, 2);
    assert_eq!(r.ia_pd[0].prefixes[0].prefix, grant().prefix.unwrap());
    assert_eq!(r.ia_na[0].addrs[0].addr, grant().address.unwrap());
    assert_eq!(r.dns, grant().dns);
    assert_eq!(r.domains, vec!["isp.example".to_string()]);
    // An Advertise binds nothing.
    assert!(a.events.is_empty());
    assert_eq!(s.bound_prefix(), None);
}

#[test]
fn rfc9915_21_4_lifetimes_and_t1_t2() {
    let mut s = Sub6::new(grant());
    let r = read(&s.handle(&out(msg::SOLICIT).encode()));
    let p = &r.ia_pd[0];
    assert_eq!(p.prefixes[0].valid, 86_400);
    assert_eq!(p.prefixes[0].preferred, 57_600);
    assert_eq!(p.t1, 28_800, "T1 = 0.5 × preferred");
    assert_eq!(p.t2, 46_080, "T2 = 0.8 × preferred");
}

#[test]
fn rfc9915_18_3_2_request_binds_and_reports_it() {
    let mut s = Sub6::new(grant());
    let sid = grant().server_duid;
    let mut o = out(msg::REQUEST);
    o.server_id = Some(&sid);
    let a = s.handle(&o.encode());
    assert_eq!(read(&a).kind, msg::REPLY);
    assert_eq!(
        a.events,
        vec![
            Event6::Bound {
                kind: IaKind::Na,
                net: Ipv6Net::from(grant().address.unwrap()),
                duid: CLIENT.to_vec()
            },
            Event6::Bound {
                kind: IaKind::Pd,
                net: grant().prefix.unwrap(),
                duid: CLIENT.to_vec()
            },
        ]
    );
    assert_eq!(s.bound_prefix(), grant().prefix);
    assert_eq!(s.client(), Some(CLIENT));
}

#[test]
fn rfc9915_18_3_1_rapid_commit_replies_at_once() {
    let mut s = Sub6::new(grant());
    let mut o = out(msg::SOLICIT);
    o.rapid_commit = true;
    let a = s.handle(&o.encode());
    let r = read(&a);
    assert_eq!(r.kind, msg::REPLY);
    assert!(r.rapid_commit);
    assert_eq!(s.bound_prefix(), grant().prefix);
    // Not configured: an Advertise, without Rapid Commit.
    let mut s = Sub6::new(Grant6 {
        rapid_commit: false,
        ..grant()
    });
    let r = read(&s.handle(&o.encode()));
    assert_eq!(r.kind, msg::ADVERTISE);
    assert!(!r.rapid_commit);
}

#[test]
fn rfc9915_16_messages_for_another_server_are_dropped() {
    let mut s = Sub6::new(grant());
    let other = [0u8, 3, 0, 1, 9, 9, 9, 9, 9, 9];
    for k in [msg::REQUEST, msg::RENEW, msg::RELEASE, msg::DECLINE] {
        let mut o = out(k);
        o.server_id = Some(&other);
        assert!(s.handle(&o.encode()).reply.is_none(), "{k}");
        o.server_id = None;
        assert!(
            s.handle(&o.encode()).reply.is_none(),
            "{k} without Server-ID"
        );
    }
    // Solicit and Rebind must not carry a Server-ID.
    for k in [msg::SOLICIT, msg::REBIND] {
        let mut o = out(k);
        o.server_id = Some(&other);
        assert!(s.handle(&o.encode()).reply.is_none(), "{k}");
    }
    // No Client-ID.
    let b = v6::Builder::new(msg::SOLICIT, 1).bytes();
    assert!(s.handle(&b).reply.is_none());
    assert_eq!(s.stats.dropped, 11);
    assert_eq!(s.stats.replied, 0);
}

#[test]
fn rfc9915_18_3_4_renew_extends_and_zeroes_what_is_not_ours() {
    let mut s = Sub6::new(grant());
    let sid = grant().server_duid;
    let stale: Ipv6Net = "2001:db8:999::/56".parse().unwrap();
    let mut o = out(msg::RENEW);
    o.server_id = Some(&sid);
    o.ia_pd = Some(IaReq {
        iaid: 2,
        prefixes: vec![stale],
        ..IaReq::default()
    });
    let r = read(&s.handle(&o.encode()));
    let ps = &r.ia_pd[0].prefixes;
    assert_eq!(ps[0].prefix, grant().prefix.unwrap());
    assert!(ps[0].valid > 0);
    assert_eq!((ps[1].prefix, ps[1].valid, ps[1].preferred), (stale, 0, 0));
}

#[test]
fn rfc9915_18_3_5_rebind_without_server_id() {
    let mut s = Sub6::new(grant());
    let r = read(&s.handle(&out(msg::REBIND).encode()));
    assert_eq!(r.kind, msg::REPLY);
    assert_eq!(r.ia_pd[0].prefixes[0].prefix, grant().prefix.unwrap());
}

#[test]
fn rfc9915_18_3_7_release_ends_the_binding() {
    let mut s = Sub6::new(grant());
    let sid = grant().server_duid;
    let mut o = out(msg::REQUEST);
    o.server_id = Some(&sid);
    s.handle(&o.encode());
    let mut rel = out(msg::RELEASE);
    rel.server_id = Some(&sid);
    rel.ia_pd = Some(IaReq {
        iaid: 2,
        prefixes: vec![grant().prefix.unwrap()],
        ..IaReq::default()
    });
    rel.ia_na = None;
    let a = s.handle(&rel.encode());
    assert_eq!(read(&a).status_code(), status::SUCCESS);
    assert_eq!(
        a.events,
        vec![Event6::Released {
            kind: IaKind::Pd,
            net: grant().prefix.unwrap()
        }]
    );
    assert_eq!(s.bound_prefix(), None);
    assert!(s.bound_address().is_some());
}

#[test]
fn rfc9915_18_3_8_decline_marks_the_address() {
    let mut s = Sub6::new(grant());
    let sid = grant().server_duid;
    let mut o = out(msg::REQUEST);
    o.server_id = Some(&sid);
    s.handle(&o.encode());
    let mut d = out(msg::DECLINE);
    d.server_id = Some(&sid);
    d.ia_na = Some(IaReq {
        iaid: 1,
        addrs: vec![grant().address.unwrap()],
        ..IaReq::default()
    });
    let a = s.handle(&d.encode());
    assert_eq!(
        a.events,
        vec![Event6::Declined {
            addr: grant().address.unwrap()
        }]
    );
    assert_eq!(s.bound_address(), None);
}

#[test]
fn rfc9915_18_3_3_confirm_on_link_or_not() {
    let mut s = Sub6::new(grant());
    let mut c = out(msg::CONFIRM);
    c.ia_pd = None;
    c.ia_na = Some(IaReq {
        iaid: 1,
        addrs: vec!["2001:db8:0:5::77".parse().unwrap()],
        ..IaReq::default()
    });
    assert_eq!(read(&s.handle(&c.encode())).status_code(), status::SUCCESS);
    c.ia_na = Some(IaReq {
        iaid: 1,
        addrs: vec!["2001:db8:0:6::77".parse().unwrap()],
        ..IaReq::default()
    });
    assert_eq!(
        read(&s.handle(&c.encode())).status_code(),
        status::NOT_ON_LINK
    );
    c.ia_na = Some(IaReq {
        iaid: 1,
        ..IaReq::default()
    });
    assert!(
        s.handle(&c.encode()).reply.is_none(),
        "no addresses: no Reply"
    );
}

#[test]
fn rfc9915_18_3_6_information_request() {
    let mut s = Sub6::new(grant());
    let mut o = out(msg::INFORMATION_REQUEST);
    o.ia_na = None;
    o.ia_pd = None;
    let r = read(&s.handle(&o.encode()));
    assert_eq!(r.kind, msg::REPLY);
    assert_eq!(r.dns, grant().dns);
    assert!(r.ia_pd.is_empty());
    // §16.12: with an IA, discarded.
    let o = out(msg::INFORMATION_REQUEST);
    assert!(s.handle(&o.encode()).reply.is_none());
}

#[test]
fn ia_without_a_grant_says_no_prefix_or_address_available() {
    let mut s = Sub6::new(Grant6 {
        address: None,
        prefix: None,
        ..grant()
    });
    let r = read(&s.handle(&out(msg::SOLICIT).encode()));
    assert_eq!(r.ia_pd[0].status_code(), status::NO_PREFIX_AVAIL);
    assert_eq!(r.ia_na[0].status_code(), status::NO_ADDRS_AVAIL);
    assert!(r.ia_pd[0].prefixes.is_empty());
}

#[test]
fn a_new_duid_takes_the_binding_over() {
    let mut s = Sub6::new(grant());
    let mut o = out(msg::SOLICIT);
    o.rapid_commit = true;
    s.handle(&o.encode());
    let other = [0u8, 3, 0, 1, 2, 0, 0, 0, 0, 0x77];
    o.client_id = &other;
    let a = s.handle(&o.encode());
    assert_eq!(
        read(&a).ia_pd[0].prefixes[0].prefix,
        grant().prefix.unwrap()
    );
    assert_eq!(s.client(), Some(&other[..]));
}

#[test]
fn regrant_releases_what_changed() {
    let mut s = Sub6::new(grant());
    let mut o = out(msg::SOLICIT);
    o.rapid_commit = true;
    s.handle(&o.encode());
    let ev = s.regrant(Grant6 {
        prefix: Some("2001:db8:200::/56".parse().unwrap()),
        ..grant()
    });
    assert_eq!(
        ev,
        vec![Event6::Released {
            kind: IaKind::Pd,
            net: grant().prefix.unwrap()
        }]
    );
    assert_eq!(s.bound_prefix(), None);
    assert!(s.bound_address().is_some());
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, failure_persistence: None, ..ProptestConfig::default() })]

    /// Hostile bytes never panic; every reply decodes as a server message
    /// with our Server-ID.
    #[test]
    fn hostile_messages(b in proptest::collection::vec(any::<u8>(), 0..400)) {
        let mut s = Sub6::new(grant());
        let a = s.handle(&b);
        if let Some(r) = a.reply {
            let m = v6::decode(&r).map_err(|e| TestCaseError::fail(e.to_string()))?;
            prop_assert_eq!(m.server_id, Some(grant().server_duid));
        }
    }

    /// Real messages with bytes rewritten.
    #[test]
    fn mutated_messages(k in 0usize..6, edits in proptest::collection::vec((any::<u16>(), any::<u8>()), 0..6)) {
        let kinds = [msg::SOLICIT, msg::REQUEST, msg::RENEW, msg::REBIND, msg::RELEASE, msg::INFORMATION_REQUEST];
        let sid = grant().server_duid;
        let mut o = out(kinds[k]);
        if matches!(kinds[k], msg::REQUEST | msg::RENEW | msg::RELEASE) {
            o.server_id = Some(&sid);
        }
        let mut b = o.encode();
        for (pos, val) in edits {
            let p = usize::from(pos) % b.len();
            b[p] = val;
        }
        let mut s = Sub6::new(grant());
        if let Some(r) = s.handle(&b).reply {
            prop_assert!(v6::decode(&r).is_ok());
        }
    }
}
