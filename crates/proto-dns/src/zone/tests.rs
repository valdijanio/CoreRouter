//! Zones: lookups (RFC 1034 §4.3.2, RFC 4592, RFC 2308), the chain's
//! `zones` stage end to end, transfers (RFC 5936, RFC 1995) and NOTIFY
//! (RFC 1996) as messages.

use std::net::IpAddr;

use corerouter_model::Config;
use corerouter_model::dns_zone::{RecordType as ZType, Zone, ZoneRecord, ZoneType};
use corerouter_model::types::ItemId;
use hickory_proto::op::{Message, OpCode, Query as Q, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};

use super::xfr::{self, Ack, Transfer};
use super::*;
use crate::server::tests::{LAN, Up, ask, forwarder, run};

fn rec(id: u32, name: &str, t: ZType, data: &str) -> ZoneRecord {
    let mut r = ZoneRecord::new(ItemId(id), "example.com", name);
    r.rtype = t;
    match t {
        ZType::A | ZType::Aaaa => r.address = Some(data.parse().unwrap()),
        ZType::Txt => r.text = data.into(),
        ZType::Mx | ZType::Srv => {
            r.priority = 10;
            r.target = data.into();
        }
        _ => r.target = data.into(),
    }
    r
}

/// example.com: NS ns1 (+glue), www A, mail MX, alias CNAME www, a
/// wildcard under dev, an empty non-terminal (b in a.b), a delegation
/// (sub, with glue) and an alias out of the zone.
fn config(edit: impl FnOnce(&mut Config)) -> Config {
    let mut c = Config::default();
    let mut z = Zone::new(ItemId(1), "example.com");
    z.serial = 2_026_102_201;
    z.allow_transfer = vec![
        "127.0.0.0/8".parse().unwrap(),
        "192.0.2.0/24".parse().unwrap(),
    ];
    c.ip.dns_zones.zones.push(z);
    c.ip.dns_zones.records = vec![
        rec(1, "@", ZType::Ns, "ns1.example.com"),
        rec(2, "ns1", ZType::A, "192.0.2.53"),
        rec(3, "www", ZType::A, "192.0.2.80"),
        rec(4, "www", ZType::Aaaa, "2001:db8::80"),
        rec(5, "@", ZType::Mx, "mail.example.com"),
        rec(6, "mail", ZType::A, "192.0.2.25"),
        rec(7, "alias", ZType::Cname, "www.example.com"),
        rec(8, "*.dev", ZType::A, "192.0.2.99"),
        rec(9, "a.b", ZType::Txt, "deep"),
        rec(10, "sub", ZType::Ns, "ns.sub.example.com"),
        rec(11, "ns.sub", ZType::A, "192.0.2.153"),
        rec(12, "out", ZType::Cname, "www.example.net"),
    ];
    edit(&mut c);
    c
}

fn data(c: &Config) -> ZoneData {
    let z = c.ip.dns_zones.zones.first().unwrap();
    let recs: Vec<&ZoneRecord> = c.ip.dns_zones.records_of(&z.name).collect();
    primary(z, &recs).unwrap()
}

fn look(z: &ZoneData, name: &str, t: RecordType) -> Found {
    let n = Name::from_ascii(name).unwrap();
    z.lookup(&n, &key_of(&n), t)
}

fn texts(rs: &[Record]) -> Vec<String> {
    rs.iter()
        .map(|r| format!("{} {} {}", r.name, r.record_type(), r.data))
        .collect()
}

#[test]
fn lookups_follow_rfc1034() {
    let z = data(&config(|_| {}));
    let Found::Answer {
        records,
        additional,
    } = look(&z, "www.example.com.", RecordType::A)
    else {
        panic!()
    };
    assert_eq!(texts(&records), ["www.example.com. A 192.0.2.80"]);
    assert!(additional.is_empty());
    // Step 6: MX target addresses in the additional section.
    let Found::Answer { additional, .. } = look(&z, "example.com.", RecordType::MX) else {
        panic!()
    };
    assert_eq!(texts(&additional), ["mail.example.com. A 192.0.2.25"]);
    // The SOA at the apex; NODATA elsewhere.
    assert!(matches!(
        look(&z, "example.com.", RecordType::SOA),
        Found::Answer { .. }
    ));
    assert_eq!(
        look(&z, "mail.example.com.", RecordType::TXT),
        Found::NoData
    );
    assert_eq!(
        look(&z, "nope.example.com.", RecordType::A),
        Found::NxDomain
    );
    // Case does not matter (RFC 4343).
    assert!(matches!(
        look(&z, "WWW.Example.COM.", RecordType::AAAA),
        Found::Answer { .. }
    ));
    // CNAME, unless the CNAME itself is asked.
    let Found::Cname { target, .. } = look(&z, "alias.example.com.", RecordType::A) else {
        panic!()
    };
    assert_eq!(target.to_ascii(), "www.example.com.");
    assert!(matches!(
        look(&z, "alias.example.com.", RecordType::CNAME),
        Found::Answer { .. }
    ));
}

#[test]
fn wildcards_and_empty_non_terminals() {
    let z = data(&config(|_| {}));
    // RFC 4592 §3.3.3: owner is the query name.
    let Found::Answer { records, .. } = look(&z, "x.y.dev.example.com.", RecordType::A) else {
        panic!()
    };
    assert_eq!(texts(&records), ["x.y.dev.example.com. A 192.0.2.99"]);
    // dev exists (it has a child): NODATA, and the wildcard does not
    // cover the name `dev` itself.
    assert_eq!(look(&z, "dev.example.com.", RecordType::A), Found::NoData);
    // b is an empty non-terminal: NODATA, never NXDOMAIN (RFC 8020).
    assert_eq!(look(&z, "b.example.com.", RecordType::A), Found::NoData);
    // Below an existing name, no wildcard: NXDOMAIN.
    assert_eq!(look(&z, "x.b.example.com.", RecordType::A), Found::NxDomain);
}

#[test]
fn delegations_give_referrals_with_glue() {
    let z = data(&config(|_| {}));
    let Found::Referral { ns, glue } = look(&z, "host.sub.example.com.", RecordType::A) else {
        panic!()
    };
    assert_eq!(texts(&ns), ["sub.example.com. NS ns.sub.example.com."]);
    assert_eq!(texts(&glue), ["ns.sub.example.com. A 192.0.2.153"]);
    // DS at the cut belongs to the parent (RFC 4035 §3.1.4.1).
    assert_eq!(look(&z, "sub.example.com.", RecordType::DS), Found::NoData);
}

#[test]
fn a_zone_without_apex_ns_gets_its_mname() {
    let mut c = config(|_| {});
    c.ip.dns_zones.records.retain(|r| r.rtype != ZType::Ns);
    let z = data(&c);
    let Found::Answer { records, .. } = look(&z, "example.com.", RecordType::NS) else {
        panic!()
    };
    assert_eq!(texts(&records), ["example.com. NS ns1.example.com."]);
}

#[test]
fn the_chain_answers_from_zones_with_aa() {
    let f = forwarder(|c| *c = config(|c2| c2.ip.dns = c.ip.dns.clone()));
    let mut up = Up::new();
    let m = run(&f, &mut up, LAN, &ask("www.example.com.", RecordType::A)).unwrap();
    assert!(m.metadata.authoritative);
    assert_eq!(m.answers.len(), 1);
    // NXDOMAIN with the SOA, TTL = min(TTL, MINIMUM) (RFC 2308 §3).
    let m = run(&f, &mut up, LAN, &ask("nope.example.com.", RecordType::A)).unwrap();
    assert_eq!(m.metadata.response_code, ResponseCode::NXDomain);
    assert!(m.metadata.authoritative);
    assert_eq!(m.authorities[0].record_type(), RecordType::SOA);
    assert_eq!(m.authorities[0].ttl, 3600);
    // A CNAME out of the zone: our CNAME, then upstream for the target.
    let m = run(&f, &mut up, LAN, &ask("out.example.com.", RecordType::A)).unwrap();
    assert_eq!(m.answers.len(), 2);
    assert_eq!(m.answers[0].record_type(), RecordType::CNAME);
    assert_eq!(up.asked.len(), 1);
    assert_eq!(up.asked[0].1, "www.example.net.");
    // A delegation with RD: forwarded to the glue address.
    run(&f, &mut up, LAN, &ask("h.sub.example.com.", RecordType::A)).unwrap();
    assert_eq!(up.asked[1].0, IpAddr::from([192, 0, 2, 153]));
    // Without RD: a referral, not authoritative.
    let mut q = Message::query();
    q.add_query(Q::query(
        Name::from_ascii("h.sub.example.com.").unwrap(),
        RecordType::A,
    ));
    let m = run(&f, &mut up, LAN, &q.to_vec().unwrap()).unwrap();
    assert!(!m.metadata.authoritative);
    assert_eq!(m.authorities[0].record_type(), RecordType::NS);
    assert_eq!(m.additionals.len(), 1, "glue");
    // Outside the zones: the rest of the chain.
    run(&f, &mut up, LAN, &ask("www.example.org.", RecordType::A)).unwrap();
    assert_eq!(up.asked.len(), 3);
    // Disabled zone: not ours any more.
    let f2 = forwarder(|c| {
        *c = config(|c2| c2.ip.dns = c.ip.dns.clone());
        c.ip.dns_zones.zones[0].disabled = true;
    });
    let m = run(&f2, &mut up, LAN, &ask("www.example.com.", RecordType::A)).unwrap();
    assert!(!m.metadata.authoritative);
}

#[test]
fn a_secondary_not_loaded_fails_then_answers() {
    let f = forwarder(|c| {
        let dns = c.ip.dns.clone();
        *c = config(|_| {});
        c.ip.dns = dns;
        c.ip.dns_zones.records.clear();
        let z = &mut c.ip.dns_zones.zones[0];
        z.ztype = ZoneType::Secondary;
        z.primaries = vec![IpAddr::from([192, 0, 2, 1])];
    });
    let mut up = Up::new();
    let m = run(&f, &mut up, LAN, &ask("www.example.com.", RecordType::A)).unwrap();
    assert_eq!(m.metadata.response_code, ResponseCode::ServFail);
    set_secondary(&f, "example.com", data(&config(|_| {})));
    let m = run(&f, &mut up, LAN, &ask("www.example.com.", RecordType::A)).unwrap();
    assert!(m.metadata.authoritative);
    assert_eq!(m.answers.len(), 1);
}

fn xfr_query(kind: RecordType, serial: Option<u32>) -> Vec<u8> {
    let mut m = Message::query();
    m.add_query(Q::query(Name::from_ascii("example.com.").unwrap(), kind));
    if let Some(s) = serial {
        let mut soa = data(&config(|_| {})).soa;
        if let RData::SOA(x) = &mut soa.data {
            x.serial = s;
        }
        m.add_authority(soa);
    }
    m.to_vec().unwrap()
}

const SECONDARY: [u8; 4] = [192, 0, 2, 2];

fn messages(out: &[Vec<u8>]) -> Vec<Message> {
    out.iter().map(|b| Message::from_vec(b).unwrap()).collect()
}

#[test]
fn axfr_follows_rfc5936() {
    let f = forwarder(|c| *c = config(|c2| c2.ip.dns = c.ip.dns.clone()));
    let from = IpAddr::from(SECONDARY);
    // Ordinary queries are not intercepted.
    assert!(xfr::intercept(&f, &ask("www.example.com.", RecordType::A), from, true).is_none());
    let out = xfr::intercept(&f, &xfr_query(RecordType::AXFR, None), from, true).unwrap();
    let ms = messages(&out);
    assert!(ms.iter().all(|m| m.metadata.authoritative));
    assert_eq!(ms[0].queries.len(), 1, "question in the first message");
    let all: Vec<_> = ms.iter().flat_map(|m| m.answers.clone()).collect();
    assert_eq!(all.first().unwrap().record_type(), RecordType::SOA);
    assert_eq!(all.last().unwrap().record_type(), RecordType::SOA);
    assert_eq!(all.len(), 12 + 2);
    // Over UDP: refused (RFC 5936 §4.2).
    let out = xfr::intercept(&f, &xfr_query(RecordType::AXFR, None), from, false).unwrap();
    assert_eq!(
        messages(&out)[0].metadata.response_code,
        ResponseCode::Refused
    );
    // Outside allow_transfer: refused; another zone: NOTAUTH.
    let out = xfr::intercept(
        &f,
        &xfr_query(RecordType::AXFR, None),
        IpAddr::from(LAN),
        true,
    )
    .unwrap();
    assert_eq!(
        messages(&out)[0].metadata.response_code,
        ResponseCode::Refused
    );
    let mut q = Message::query();
    q.add_query(Q::query(
        Name::from_ascii("example.org.").unwrap(),
        RecordType::AXFR,
    ));
    let out = xfr::intercept(&f, &q.to_vec().unwrap(), from, true).unwrap();
    assert_eq!(
        messages(&out)[0].metadata.response_code,
        ResponseCode::NotAuth
    );
    // A transfer client reads it back into the same zone.
    let mut t = Transfer::new(0, "example.com", false);
    let mut done = false;
    for b in &out_axfr(&f) {
        done = t.push(b).unwrap();
    }
    assert!(done);
    let got = t.finish(None).unwrap().unwrap();
    assert_eq!(got, data(&config(|_| {})));
}

fn out_axfr(f: &Forwarder) -> Vec<Vec<u8>> {
    let mut q = Message::from_vec(&xfr_query(RecordType::AXFR, None)).unwrap();
    q.metadata.id = 0;
    xfr::intercept(f, &q.to_vec().unwrap(), IpAddr::from(SECONDARY), true).unwrap()
}

#[test]
fn big_zones_take_several_messages() {
    let f = forwarder(|c| {
        *c = config(|c2| c2.ip.dns = c.ip.dns.clone());
        for i in 0..2000u32 {
            c.ip.dns_zones.records.push(rec(
                100 + i,
                &format!("h{i}"),
                ZType::Txt,
                &"x".repeat(40),
            ));
        }
    });
    let out = out_axfr(&f);
    assert!(out.len() > 3);
    assert!(out.iter().all(|b| b.len() < 65_535));
    let ms = messages(&out);
    assert!(ms.iter().skip(1).all(|m| m.queries.is_empty()));
    let mut t = Transfer::new(0, "example.com", false);
    let mut done = false;
    for b in &out {
        assert!(!done, "nothing after the closing SOA");
        done = t.push(b).unwrap();
    }
    assert_eq!(t.finish(None).unwrap().unwrap().len(), 2012);
}

#[test]
fn ixfr_sends_what_changed() {
    let base = config(|_| {});
    let f = forwarder(|c| *c = config(|c2| c2.ip.dns = c.ip.dns.clone()));
    let old = data(&base);
    reload(&f);
    // A change: www moves, a record is added, the serial goes up.
    let mut cfg = (*f.config().config).clone();
    cfg.ip.dns_zones.zones[0].serial += 1;
    cfg.ip.dns_zones.records[2].address = Some("192.0.2.81".parse().unwrap());
    cfg.ip
        .dns_zones
        .records
        .push(rec(50, "new", ZType::A, "192.0.2.50"));
    f.configure(std::sync::Arc::new(cfg.clone()), Vec::new());
    let changed = reload(&f);
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0].serial, old.serial + 1);
    let from = IpAddr::from(SECONDARY);
    let out = xfr::intercept(
        &f,
        &xfr_query(RecordType::IXFR, Some(old.serial)),
        from,
        true,
    )
    .unwrap();
    let all: Vec<_> = messages(&out)
        .iter()
        .flat_map(|m| m.answers.clone())
        .collect();
    // new SOA, old SOA, -www, new SOA, +www +new, new SOA.
    assert_eq!(all.len(), 7, "{:?}", texts(&all));
    // The client applies it to its copy.
    let mut t = Transfer::new(0, "example.com", true);
    for m in messages(&out) {
        let mut m = m;
        m.metadata.id = 0;
        t.push(&m.to_vec().unwrap()).unwrap();
    }
    let got = t.finish(Some(&old)).unwrap().unwrap();
    assert_eq!(got, data(&cfg));
    // Up to date: one SOA, and the client says so.
    let out = xfr::intercept(
        &f,
        &xfr_query(RecordType::IXFR, Some(old.serial + 1)),
        from,
        true,
    )
    .unwrap();
    let ms = messages(&out);
    assert_eq!(ms[0].answers.len(), 1);
    let mut t = Transfer::new(ms[0].metadata.id, "example.com", true);
    assert!(t.push(&out[0]).unwrap());
    assert_eq!(t.finish(Some(&got)).unwrap(), None);
    // An unknown old serial: the whole zone, AXFR style (RFC 1995 §4).
    let out = xfr::intercept(&f, &xfr_query(RecordType::IXFR, Some(7)), from, true).unwrap();
    let all: Vec<_> = messages(&out)
        .iter()
        .flat_map(|m| m.answers.clone())
        .collect();
    assert_eq!(all.len(), 13 + 2);
    // Over UDP: one message that fits in 512 bytes, else the SOA alone
    // (RFC 1995 §2).
    let out = xfr::intercept(&f, &xfr_query(RecordType::IXFR, Some(7)), from, false).unwrap();
    assert_eq!(out.len(), 1);
    assert!(out[0].len() <= 512);
    let mut cfg2 = cfg.clone();
    for i in 0..40u32 {
        cfg2.ip
            .dns_zones
            .records
            .push(rec(100 + i, &format!("h{i}"), ZType::A, "192.0.2.7"));
    }
    f.configure(std::sync::Arc::new(cfg2), Vec::new());
    let out = xfr::intercept(&f, &xfr_query(RecordType::IXFR, Some(7)), from, false).unwrap();
    assert_eq!(messages(&out)[0].answers.len(), 1);
    // Without the client's SOA: FORMERR.
    let out = xfr::intercept(&f, &xfr_query(RecordType::IXFR, None), from, true).unwrap();
    assert_eq!(
        messages(&out)[0].metadata.response_code,
        ResponseCode::FormErr
    );
}

#[test]
fn notify_in_and_out() {
    let primary = IpAddr::from([192, 0, 2, 1]);
    let f = forwarder(|c| {
        let dns = c.ip.dns.clone();
        *c = config(|_| {});
        c.ip.dns = dns;
        c.ip.dns_zones.records.clear();
        let z = &mut c.ip.dns_zones.zones[0];
        z.ztype = ZoneType::Secondary;
        z.primaries = vec![primary];
    });
    let changed = Changed {
        zone: "example.com".into(),
        serial: 5,
        notify: vec![],
        soa: data(&config(|_| {})).soa,
    };
    let (id, msg) = xfr::notify_message(&changed).unwrap();
    let m = Message::from_vec(&msg).unwrap();
    assert_eq!(m.metadata.op_code, OpCode::Notify);
    assert!(m.metadata.authoritative);
    // From a stranger: REFUSED, nothing marked (RFC 1996 §3.10).
    let out = xfr::intercept(&f, &msg, IpAddr::from(LAN), false).unwrap();
    assert!(matches!(xfr::notify_ack(&out[0], id), Ack::No(_)));
    assert!(take_notified(&f).is_empty());
    // From the primary: acknowledged (§4.7), refresh asked (§3.11).
    let out = xfr::intercept(&f, &msg, primary, false).unwrap();
    assert_eq!(xfr::notify_ack(&out[0], id), Ack::Yes);
    let r = Message::from_vec(&out[0]).unwrap();
    assert!(r.metadata.authoritative);
    assert_eq!(r.queries.len(), 1);
    assert!(take_notified(&f).contains("example.com"));
    assert_eq!(xfr::notify_ack(&out[0], id.wrapping_add(1)), Ack::Other);
}

#[test]
fn soa_check_reads_the_serial() {
    let f = forwarder(|c| *c = config(|c2| c2.ip.dns = c.ip.dns.clone()));
    let (id, q) = xfr::soa_query("example.com").unwrap();
    let mut up = Up::new();
    let r = run(&f, &mut up, LAN, &q).unwrap();
    let mut r = r;
    r.metadata.id = id;
    assert_eq!(
        xfr::soa_serial(&r.to_vec().unwrap(), id, "example.com").unwrap(),
        Some(2_026_102_201)
    );
    r.metadata.authoritative = false;
    assert!(xfr::soa_serial(&r.to_vec().unwrap(), id, "example.com").is_err());
}

#[test]
fn transfers_with_bad_messages_fail() {
    let f = forwarder(|c| *c = config(|c2| c2.ip.dns = c.ip.dns.clone()));
    let out = out_axfr(&f);
    // Another id.
    let mut t = Transfer::new(9, "example.com", false);
    assert!(t.push(&out[0]).is_err());
    // Cut short.
    let mut t = Transfer::new(0, "example.com", false);
    let mut m = Message::from_vec(&out[0]).unwrap();
    m.answers.pop();
    t.push(&m.to_vec().unwrap()).unwrap();
    assert!(t.finish(None).is_err());
    // Another zone.
    let mut t = Transfer::new(0, "example.org", false);
    assert!(t.push(&out[0]).is_err());
}

#[test]
fn zone_files_round_trip() {
    let z = data(&config(|_| {}));
    let text = z.to_file();
    let back = file::import("example.com", &text).unwrap();
    let soa = back.soa.unwrap();
    assert_eq!(soa.serial, z.serial);
    assert_eq!(back.records.len(), z.len());
}

mod hostile {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// Bytes from the network never panic the transfer path or the
        /// transfer client.
        #[test]
        fn hostile_packets(b in proptest::collection::vec(any::<u8>(), 0..300)) {
            let f = forwarder(|c| *c = config(|c2| c2.ip.dns = c.ip.dns.clone()));
            let _ = xfr::intercept(&f, &b, IpAddr::from(SECONDARY), true);
            let mut t = Transfer::new(0, "example.com", true);
            let _ = t.push(&b);
            let _ = t.finish(None);
            let _ = xfr::soa_serial(&b, 0, "example.com");
            let _ = xfr::notify_ack(&b, 0);
        }

        /// A real transfer query, damaged.
        #[test]
        fn damaged_transfer_queries(i in 0usize..64, v in any::<u8>()) {
            let f = forwarder(|c| *c = config(|c2| c2.ip.dns = c.ip.dns.clone()));
            let mut q = xfr_query(RecordType::IXFR, Some(1));
            let at = i % q.len();
            if let Some(b) = q.get_mut(at) {
                *b = v;
            }
            let _ = xfr::intercept(&f, &q, IpAddr::from(SECONDARY), false);
        }
    }
}
