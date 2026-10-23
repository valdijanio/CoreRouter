//! RFC 2136 UPDATE with TSIG (RFC 8945), as messages.

use std::net::IpAddr;

use corerouter_model::Config;
use corerouter_model::dns_dynamic::DynamicOp;
use corerouter_model::dns_tsig::{TsigAlgorithm, TsigKey, base64_encode};
use corerouter_model::dns_zone::{RecordType as ZType, Zone, ZoneRecord};
use corerouter_model::types::ItemId;
use hickory_proto::op::{Message, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

use super::*;
use crate::server::tests::forwarder;

const NOW: u64 = 1_792_670_400;
const SECRET: [u8; 32] = [7; 32];
const DHCP: [u8; 4] = [192, 168, 88, 1];

fn config(edit: impl FnOnce(&mut Config)) -> Config {
    let mut c = Config::default();
    let mut z = Zone::new(ItemId(1), "lan.example");
    z.serial = 5;
    z.update_keys = vec!["ddns".into()];
    c.ip.dns_zones.zones.push(z);
    let mut r = ZoneRecord::new(ItemId(1), "lan.example", "nas");
    r.address = Some("192.168.88.2".parse().unwrap());
    c.ip.dns_zones.records.push(r);
    c.ip.dns_tsig.keys.push(TsigKey {
        id: ItemId(1),
        name: "ddns".into(),
        algorithm: TsigAlgorithm::HmacSha256,
        secret: base64_encode(&SECRET),
        comment: String::new(),
    });
    edit(&mut c);
    c
}

fn fwd(edit: impl FnOnce(&mut Config)) -> crate::server::Forwarder {
    forwarder(|c| {
        let dns = c.ip.dns.clone();
        *c = config(edit);
        c.ip.dns = dns;
    })
}

fn name(n: &str) -> Name {
    Name::from_ascii(n).unwrap()
}

/// An UPDATE of lan.example with `prereq` and `update`.
fn update(prereq: Vec<Record>, update: Vec<Record>) -> Message {
    let mut m = Message::query();
    m.metadata.op_code = OpCode::Update;
    m.add_query(Query::query(name("lan.example."), RecordType::SOA));
    m.add_answers(prereq);
    m.add_authorities(update);
    m
}

fn add_a(owner: &str, ip: [u8; 4]) -> Record {
    Record::from_rdata(
        name(owner),
        300,
        RData::A(A::from(std::net::Ipv4Addr::from(ip))),
    )
}

fn empty(owner: &str, t: RecordType, class: DNSClass) -> Record {
    let mut r = Record::from_rdata(name(owner), 0, RData::Update0(t));
    r.dns_class = class;
    r
}

fn rcode(reply: &[u8]) -> ResponseCode {
    Message::from_vec(reply).unwrap().metadata.response_code
}

fn unsigned(m: &Message) -> Vec<u8> {
    m.to_vec().unwrap()
}

#[test]
fn no_permission_no_update() {
    // A key is required and the message is not signed: REFUSED (§3.3).
    let f = fwd(|_| {});
    let m = update(vec![], vec![add_a("pc.lan.example.", [192, 168, 88, 50])]);
    let e = read(&f, &unsigned(&m), IpAddr::from(DHCP), NOW)
        .err()
        .unwrap();
    assert_eq!(rcode(&e), ResponseCode::Refused);
    // Another zone: NOTAUTH (§3.1.1).
    let mut other = m.clone();
    other.queries[0] = Query::query(name("example.org."), RecordType::SOA);
    let e = read(&f, &unsigned(&other), IpAddr::from(DHCP), NOW)
        .err()
        .unwrap();
    assert_eq!(rcode(&e), ResponseCode::NotAuth);
    // The zone section is one SOA (§3.1.1).
    let mut bad = m.clone();
    bad.queries[0] = Query::query(name("lan.example."), RecordType::A);
    let e = read(&f, &unsigned(&bad), IpAddr::from(DHCP), NOW)
        .err()
        .unwrap();
    assert_eq!(rcode(&e), ResponseCode::FormErr);
}

#[test]
fn unsigned_from_an_allowed_network() {
    let f = fwd(|c| {
        let z = &mut c.ip.dns_zones.zones[0];
        z.update_keys.clear();
        z.allow_update = vec!["192.168.88.0/24".parse().unwrap()];
    });
    let m = update(vec![], vec![add_a("pc.lan.example.", [192, 168, 88, 50])]);
    let u = read(&f, &unsigned(&m), IpAddr::from(DHCP), NOW).unwrap();
    assert!(u.key.is_none());
    let DynamicOp::Add(r) = &u.ops[0] else {
        panic!()
    };
    assert_eq!((r.name.as_str(), r.rtype), ("pc", ZType::A));
    assert_eq!(r.ttl_secs, Some(300));
    let e = read(&f, &unsigned(&m), IpAddr::from([10, 0, 0, 9]), NOW)
        .err()
        .unwrap();
    assert_eq!(rcode(&e), ResponseCode::Refused);
    // A reply to a checked update echoes the zone, NOERROR.
    let ok = answer(&u, ResponseCode::NoError, NOW);
    let r = Message::from_vec(&ok).unwrap();
    assert_eq!(r.metadata.op_code, OpCode::Update);
    assert_eq!(r.queries.len(), 1);
}

#[test]
fn prerequisites_follow_rfc2136() {
    let f = fwd(|c| {
        let z = &mut c.ip.dns_zones.zones[0];
        z.update_keys.clear();
        z.allow_update = vec!["192.168.88.0/24".parse().unwrap()];
    });
    let from = IpAddr::from(DHCP);
    let go = |pre: Vec<Record>| -> Result<(), ResponseCode> {
        let m = update(pre, vec![add_a("pc.lan.example.", [192, 168, 88, 50])]);
        read(&f, &unsigned(&m), from, NOW)
            .map(|_| ())
            .map_err(|e| rcode(&e))
    };
    // §2.4.5 name not in use (RFC 4703 §5.3.1's first step).
    assert_eq!(
        go(vec![empty(
            "nas.lan.example.",
            RecordType::ANY,
            DNSClass::NONE
        )]),
        Err(ResponseCode::YXDomain)
    );
    assert_eq!(
        go(vec![empty(
            "pc.lan.example.",
            RecordType::ANY,
            DNSClass::NONE
        )]),
        Ok(())
    );
    // §2.4.4 name in use.
    assert_eq!(
        go(vec![empty(
            "pc.lan.example.",
            RecordType::ANY,
            DNSClass::ANY
        )]),
        Err(ResponseCode::NXDomain)
    );
    // §2.4.1 RRset exists / §2.4.3 does not.
    assert_eq!(
        go(vec![empty(
            "nas.lan.example.",
            RecordType::A,
            DNSClass::ANY
        )]),
        Ok(())
    );
    assert_eq!(
        go(vec![empty(
            "nas.lan.example.",
            RecordType::AAAA,
            DNSClass::ANY
        )]),
        Err(ResponseCode::NXRRSet)
    );
    assert_eq!(
        go(vec![empty(
            "nas.lan.example.",
            RecordType::A,
            DNSClass::NONE
        )]),
        Err(ResponseCode::YXRRSet)
    );
    // §2.4.2 value dependent, TTL 0.
    let mut exact = add_a("nas.lan.example.", [192, 168, 88, 2]);
    exact.ttl = 0;
    assert_eq!(go(vec![exact.clone()]), Ok(()));
    let mut wrong = add_a("nas.lan.example.", [192, 168, 88, 3]);
    wrong.ttl = 0;
    assert_eq!(go(vec![wrong]), Err(ResponseCode::NXRRSet));
    // A TTL in a prerequisite is malformed; a name outside: NOTZONE.
    assert_eq!(
        go(vec![add_a("nas.lan.example.", [192, 168, 88, 2])]),
        Err(ResponseCode::FormErr)
    );
    assert_eq!(
        go(vec![empty(
            "x.example.org.",
            RecordType::ANY,
            DNSClass::ANY
        )]),
        Err(ResponseCode::NotZone)
    );
}

#[test]
fn the_update_section_becomes_changes() {
    let f = fwd(|c| {
        let z = &mut c.ip.dns_zones.zones[0];
        z.update_keys.clear();
        z.allow_update = vec!["192.168.88.0/24".parse().unwrap()];
    });
    let from = IpAddr::from(DHCP);
    let mut del_rr = add_a("pc.lan.example.", [192, 168, 88, 50]);
    del_rr.ttl = 0;
    del_rr.dns_class = DNSClass::NONE;
    let m = update(
        vec![],
        vec![
            empty("pc.lan.example.", RecordType::A, DNSClass::ANY),
            empty("old.lan.example.", RecordType::ANY, DNSClass::ANY),
            del_rr,
            empty("lan.example.", RecordType::SOA, DNSClass::ANY),
        ],
    );
    let u = read(&f, &unsigned(&m), from, NOW).unwrap();
    assert!(matches!(&u.ops[0], DynamicOp::DeleteRrset { name, rtype: ZType::A } if name == "pc"));
    assert!(matches!(&u.ops[1], DynamicOp::DeleteName { name } if name == "old"));
    assert!(matches!(&u.ops[2], DynamicOp::DeleteRecord(r) if r.name == "pc"));
    assert_eq!(u.ops.len(), 3, "the SOA is ours");
    // A type the zones do not hold: REFUSED; outside the zone: NOTZONE.
    let mut sshfp = add_a("pc.lan.example.", [1, 2, 3, 4]);
    sshfp.data = RData::Update0(RecordType::SSHFP);
    sshfp.dns_class = DNSClass::IN;
    let e = read(&f, &unsigned(&update(vec![], vec![sshfp])), from, NOW)
        .err()
        .unwrap();
    assert_eq!(rcode(&e), ResponseCode::Refused);
    let e = read(
        &f,
        &unsigned(&update(vec![], vec![add_a("x.example.org.", [1, 2, 3, 4])])),
        from,
        NOW,
    )
    .err()
    .unwrap();
    assert_eq!(rcode(&e), ResponseCode::NotZone);
}

#[cfg(feature = "dnssec")]
mod tsig {
    use hickory_proto::rr::TSigner;
    use hickory_proto::rr::rdata::tsig::TsigAlgorithm as HAlg;

    use super::*;

    fn signed(m: &Message, secret: &[u8], key: &str, at: u64) -> Vec<u8> {
        signed_fudge(m, secret, key, at, 300)
    }

    fn signed_fudge(m: &Message, secret: &[u8], key: &str, at: u64, fudge: u16) -> Vec<u8> {
        let signer = TSigner::new(secret.to_vec(), HAlg::HmacSha256, name(key), fudge).unwrap();
        let (tsig, _) = signer.sign_message(m, at).unwrap();
        let mut out = m.clone();
        out.set_signature(tsig);
        out.to_vec().unwrap()
    }

    fn tsig_error(reply: &[u8]) -> Option<String> {
        let m = Message::from_vec(reply).unwrap();
        m.signature().map(|s| format!("{:?}", s.data.error))
    }

    #[test]
    fn signed_updates_follow_rfc8945() {
        let f = fwd(|_| {});
        let from = IpAddr::from(DHCP);
        let m = update(vec![], vec![add_a("pc.lan.example.", [192, 168, 88, 50])]);
        // Right key: accepted, and the answer is signed.
        let u = read(&f, &signed(&m, &SECRET, "ddns.", NOW), from, NOW).unwrap();
        assert_eq!(u.key.as_deref(), Some("ddns"));
        let reply = answer(&u, ResponseCode::NoError, NOW);
        assert!(
            Message::from_vec(&reply).unwrap().signature().is_some(),
            "§5.3: signed answer"
        );
        // Wrong secret: BADSIG, NOTAUTH (§5.2.2).
        let e = read(&f, &signed(&m, &[9; 32], "ddns.", NOW + 1), from, NOW + 1)
            .err()
            .unwrap();
        assert_eq!(rcode(&e), ResponseCode::NotAuth);
        assert!(tsig_error(&e).unwrap().contains("BadSig"));
        // Unknown key: BADKEY (§5.2.1).
        let e = read(&f, &signed(&m, &SECRET, "other.", NOW), from, NOW)
            .err()
            .unwrap();
        assert_eq!(rcode(&e), ResponseCode::NotAuth);
        assert!(tsig_error(&e).unwrap().contains("BadKey"));
        // Outside the fudge: BADTIME, signed (§5.2.3).
        let e = read(&f, &signed(&m, &SECRET, "ddns.", NOW - 1000), from, NOW)
            .err()
            .unwrap();
        assert_eq!(rcode(&e), ResponseCode::NotAuth);
        assert!(tsig_error(&e).unwrap().contains("BadTime"));
        // Older than the last message of that key: a replay.
        read(&f, &signed(&m, &SECRET, "ddns.", NOW + 10), from, NOW + 10).unwrap();
        let e = read(&f, &signed(&m, &SECRET, "ddns.", NOW + 5), from, NOW + 10)
            .err()
            .unwrap();
        assert!(tsig_error(&e).unwrap().contains("BadTime"));
        // RFC 8945 §5.2.3 / §10: the window is ours (300 s), not the
        // client's Fudge: a captured update with fudge 65535 is not good
        // for 18 hours.
        let e = read(
            &f,
            &signed_fudge(&m, &SECRET, "ddns.", NOW + 20 - 3600, 65_535),
            from,
            NOW + 20,
        )
        .err()
        .unwrap();
        assert!(tsig_error(&e).unwrap().contains("BadTime"));
        // The exact same message again: a replay.
        let once = signed(&m, &SECRET, "ddns.", NOW + 30);
        read(&f, &once, from, NOW + 30).unwrap();
        let e = read(&f, &once, from, NOW + 31).err().unwrap();
        assert!(tsig_error(&e).unwrap().contains("BadTime"));
        // Another message signed in the same second is not one.
        let m2 = update(vec![], vec![add_a("pc2.lan.example.", [192, 168, 88, 51])]);
        read(&f, &signed(&m2, &SECRET, "ddns.", NOW + 30), from, NOW + 31).unwrap();
        // Time Signed below the fudge (1970): refused, and never a panic
        // in hickory's window arithmetic.
        let e = read(
            &f,
            &signed_fudge(&m, &SECRET, "ddns.", 10, 300),
            from,
            NOW + 31,
        )
        .err()
        .unwrap();
        assert_eq!(rcode(&e), ResponseCode::NotAuth);
        // A good key from outside allow_update: REFUSED.
        let f2 =
            fwd(|c| c.ip.dns_zones.zones[0].allow_update = vec!["10.0.0.0/8".parse().unwrap()]);
        let e = read(&f2, &signed(&m, &SECRET, "ddns.", NOW), from, NOW)
            .err()
            .unwrap();
        assert_eq!(rcode(&e), ResponseCode::Refused);
    }
}

mod hostile {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn hostile_updates_never_panic(b in proptest::collection::vec(any::<u8>(), 0..300)) {
            let f = fwd(|c| c.ip.dns_zones.zones[0].allow_update = vec!["0.0.0.0/0".parse().unwrap()]);
            let _ = read(&f, &b, IpAddr::from(DHCP), NOW);
        }

        #[test]
        fn damaged_updates_never_panic(i in 0usize..80, v in any::<u8>()) {
            let f = fwd(|c| {
                let z = &mut c.ip.dns_zones.zones[0];
                z.update_keys.clear();
                z.allow_update = vec!["0.0.0.0/0".parse().unwrap()];
            });
            let mut b = unsigned(&update(
                vec![empty("pc.lan.example.", RecordType::ANY, DNSClass::NONE)],
                vec![add_a("pc.lan.example.", [192, 168, 88, 50])],
            ));
            let at = i % b.len();
            if let Some(x) = b.get_mut(at) {
                *x = v;
            }
            let _ = read(&f, &b, IpAddr::from(DHCP), NOW);
        }
    }
}
