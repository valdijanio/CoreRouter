//! Signing checked with hickory's verifier, the NSEC3 chain against RFC
//! 5155 §7.1, and the proofs of §7.2.

use std::net::IpAddr;
use std::sync::Arc;

use corerouter_model::Config;
use corerouter_model::dns_zone::{RecordType as ZType, Zone, ZoneRecord};
use corerouter_model::dnssec::{DnssecAlgorithm, DnssecKey, KeyRole, KeyState};
use corerouter_model::types::ItemId;
use hickory_proto::dnssec::Verifier;
use hickory_proto::dnssec::rdata::{DNSKEY, DNSSECRData};
use hickory_proto::op::{Edns, Message, Query as Q, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

use super::*;
use crate::server::tests::{LAN, Up, forwarder, run};
use crate::zone::Found;
use crate::zone::dnssec::{Proof, Signatures, authenticate};
use crate::zone::{ZoneData, primary, set_signed};

const NOW: u32 = 1_792_670_400;

fn key(id: u32, role: KeyRole, a: DnssecAlgorithm) -> DnssecKey {
    let g = generate("example.com", a, role).unwrap();
    DnssecKey {
        id,
        zone: "example.com".into(),
        role,
        algorithm: a,
        key_tag: g.key_tag,
        state: KeyState::Active,
        private_key: g.private_key,
        dnskey: g.dnskey,
        ds: g.ds,
        created_unix: 0,
        changed_unix: 0,
    }
}

fn rec(id: u32, name: &str, t: ZType, data: &str) -> ZoneRecord {
    let mut r = ZoneRecord::new(ItemId(id), "example.com", name);
    r.rtype = t;
    match t {
        ZType::A => r.address = Some(data.parse().unwrap()),
        ZType::Txt => r.text = data.into(),
        _ => r.target = data.into(),
    }
    r
}

fn config() -> Config {
    let mut c = Config::default();
    let mut z = Zone::new(ItemId(1), "example.com");
    z.serial = 10;
    z.dnssec = true;
    c.ip.dns_zones.zones.push(z);
    c.ip.dns_zones.records = vec![
        rec(1, "@", ZType::Ns, "ns1.example.com"),
        rec(2, "ns1", ZType::A, "192.0.2.53"),
        rec(3, "www", ZType::A, "192.0.2.80"),
        rec(4, "www", ZType::A, "192.0.2.81"),
        rec(5, "*.dev", ZType::A, "192.0.2.99"),
        rec(6, "a.b", ZType::Txt, "deep"),
        rec(7, "sub", ZType::Ns, "ns.sub.example.com"),
        rec(8, "ns.sub", ZType::A, "192.0.2.153"),
        rec(9, "alias", ZType::Cname, "www.example.com"),
    ];
    c.ip.dns_zones.records[3].ttl_secs = Some(600);
    c
}

fn unsigned(c: &Config) -> ZoneData {
    let z = &c.ip.dns_zones.zones[0];
    let recs: Vec<&ZoneRecord> = c.ip.dns_zones.records.iter().collect();
    primary(z, &recs).unwrap()
}

/// One pair of keys for the whole test binary (a fresh pair per call
/// would not match the tags a test reads).
fn keys() -> Vec<DnssecKey> {
    static KEYS: std::sync::OnceLock<Vec<DnssecKey>> = std::sync::OnceLock::new();
    KEYS.get_or_init(|| {
        vec![
            key(1, KeyRole::Ksk, DnssecAlgorithm::EcdsaP256),
            key(2, KeyRole::Zsk, DnssecAlgorithm::EcdsaP256),
        ]
    })
    .clone()
}

fn signed() -> ZoneData {
    sign(&unsigned(&config()), &keys(), 11, NOW, 1_209_600).unwrap()
}

fn dnskeys(z: &ZoneData) -> Vec<DNSKEY> {
    z.records()
        .into_iter()
        .filter_map(|r| match &r.data {
            RData::DNSSEC(DNSSECRData::DNSKEY(k)) => Some(k.clone()),
            _ => None,
        })
        .collect()
}

/// Every RRSIG verifies with the DNSKEY of its tag (RFC 4035 §5.3).
fn verify_all(z: &ZoneData) -> usize {
    let s = z.dnssec.as_ref().unwrap();
    let keys = dnskeys(z);
    let mut checked = 0;
    for ((owner, t), sigs) in &s.rrsigs {
        let rrset: Vec<Record> = if *t == RecordType::SOA {
            vec![z.soa.clone()]
        } else if *t == RecordType::NSEC3 {
            s.nsec3
                .iter()
                .filter(|(_, r)| key_of(&r.name) == *owner)
                .map(|(_, r)| r.clone())
                .collect()
        } else {
            z.records()
                .into_iter()
                .filter(|r| key_of(&r.name) == *owner && r.record_type() == *t)
                .cloned()
                .collect()
        };
        assert!(!rrset.is_empty(), "{owner} {t}: signatures over nothing");
        for sig in sigs {
            let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = &sig.data else {
                panic!("not an RRSIG")
            };
            let k = keys
                .iter()
                .find(|k| k.calculate_key_tag().unwrap() == rrsig.input().key_tag)
                .expect("a DNSKEY with that tag");
            k.verify_rrsig(&rrset[0].name, DNSClass::IN, rrsig, rrset.iter())
                .unwrap_or_else(|e| panic!("{owner} {t}: {e}"));
            checked += 1;
        }
    }
    checked
}

#[test]
fn every_signature_verifies() {
    let z = signed();
    assert_eq!(z.serial, 11);
    assert!(verify_all(&z) > 10);
    // Ed25519 too (RFC 8624 RECOMMENDED).
    let ed = vec![
        key(1, KeyRole::Ksk, DnssecAlgorithm::Ed25519),
        key(2, KeyRole::Zsk, DnssecAlgorithm::Ed25519),
    ];
    let z = sign(&unsigned(&config()), &ed, 11, NOW, 86_400).unwrap();
    assert!(verify_all(&z) > 10);
}

#[test]
fn what_is_signed_and_what_is_not() {
    let z = signed();
    let s = z.dnssec.as_ref().unwrap();
    let ksk_tag = keys()[0].key_tag;
    let tags = |owner: &str, t: RecordType| -> Vec<u16> {
        s.sigs(owner, t)
            .iter()
            .map(|r| match &r.data {
                RData::DNSSEC(DNSSECRData::RRSIG(x)) => x.input().key_tag,
                _ => 0,
            })
            .collect()
    };
    // RFC 4035 §2.2: delegation NS and glue unsigned; apex NS signed.
    assert!(tags("sub.example.com", RecordType::NS).is_empty());
    assert!(tags("ns.sub.example.com", RecordType::A).is_empty());
    assert_eq!(tags("example.com", RecordType::NS).len(), 1);
    // The DNSKEY set by the KSK, the rest by the ZSK.
    let dnskey = tags("example.com", RecordType::DNSKEY);
    assert_eq!(dnskey, [ksk_tag]);
    assert_ne!(tags("www.example.com", RecordType::A), [ksk_tag]);
    // RFC 2181 §5.2: one TTL per RRset (the smallest), and the RRSIG's.
    let www: Vec<u32> = z
        .records()
        .into_iter()
        .filter(|r| key_of(&r.name) == "www.example.com" && r.record_type() == RecordType::A)
        .map(|r| r.ttl)
        .collect();
    assert_eq!(www, [600, 600]);
    // Inception an hour back, expiration after the validity.
    let RData::DNSSEC(DNSSECRData::RRSIG(x)) = &s.sigs("www.example.com", RecordType::A)[0].data
    else {
        panic!()
    };
    assert_eq!(x.input().sig_inception.get(), NOW - 3600);
    assert_eq!(x.input().sig_expiration.get(), NOW + 1_209_600);
    assert_eq!(s.expires, NOW + 1_209_600);
}

#[test]
fn the_nsec3_chain_follows_rfc5155() {
    let z = signed();
    let s: &Signatures = z.dnssec.as_ref().unwrap();
    // Owners: apex, ns1, www, *.dev, a.b, sub, alias + the empty
    // non-terminals dev and b; not the glue ns.sub (RFC 5155 §7.1).
    assert_eq!(s.nsec3.len(), 9);
    // Closed ring, sorted by hash, each next = the following owner.
    for (i, (h, r)) in s.nsec3.iter().enumerate() {
        let RData::DNSSEC(DNSSECRData::NSEC3(n)) = &r.data else {
            panic!()
        };
        let next = &s.nsec3[(i + 1) % s.nsec3.len()].0;
        assert_eq!(n.next_hashed_owner_name(), next.as_slice());
        assert_eq!(n.iterations(), 0, "RFC 9276");
        assert!(n.salt().is_empty(), "RFC 9276");
        assert!(!n.opt_out());
        assert_eq!(r.ttl, 3600, "RFC 9077: min(SOA TTL, MINIMUM)");
        assert_eq!(
            base32hex(h),
            r.name
                .iter()
                .next()
                .map(|l| String::from_utf8_lossy(l).into_owned())
                .unwrap()
        );
    }
    let bitmap = |key: &str| -> Vec<RecordType> {
        let h = hash(&[], 0, &Name::from_ascii(format!("{key}.")).unwrap()).unwrap();
        let (_, r) = s.nsec3.iter().find(|(x, _)| *x == h).unwrap();
        let RData::DNSSEC(DNSSECRData::NSEC3(n)) = &r.data else {
            panic!()
        };
        n.type_bit_maps().collect()
    };
    let apex = bitmap("example.com");
    for t in [
        RecordType::SOA,
        RecordType::NS,
        RecordType::DNSKEY,
        RecordType::NSEC3PARAM,
        RecordType::RRSIG,
    ] {
        assert!(apex.contains(&t), "{t} at the apex: {apex:?}");
    }
    assert_eq!(
        bitmap("sub.example.com"),
        [RecordType::NS],
        "unsigned delegation: no RRSIG bit"
    );
    assert!(bitmap("b.example.com").is_empty(), "empty non-terminal");
}

fn look(z: &ZoneData, name: &str, t: RecordType) -> (Found, Proof) {
    let n = Name::from_ascii(name).unwrap();
    let k = key_of(&n);
    let f = z.lookup(&n, &k, t);
    let p = authenticate(z, &k, t, &f);
    (f, p)
}

fn nsec3s(p: &Proof) -> usize {
    p.authority
        .iter()
        .filter(|r| r.record_type() == RecordType::NSEC3)
        .count()
}

#[test]
fn proofs_follow_rfc5155_7_2() {
    let z = signed();
    // A positive answer: its RRSIG.
    let (_, p) = look(&z, "www.example.com.", RecordType::A);
    assert_eq!(p.answer.len(), 1);
    assert!(p.authority.is_empty());
    // NXDOMAIN (§7.2.2): closest encloser + next closer + wildcard, 2 or 3
    // NSEC3 (one may cover two), each with its RRSIG, and the SOA's.
    let (f, p) = look(&z, "nope.example.com.", RecordType::A);
    assert_eq!(f, Found::NxDomain);
    assert!((2..=3).contains(&nsec3s(&p)), "{:?}", p.authority);
    assert!(
        p.authority
            .iter()
            .any(|r| r.record_type() == RecordType::RRSIG)
    );
    // NODATA (§7.2.3): the matching NSEC3.
    let (f, p) = look(&z, "www.example.com.", RecordType::TXT);
    assert_eq!(f, Found::NoData);
    assert_eq!(nsec3s(&p), 1);
    // An empty non-terminal is NODATA too.
    let (_, p) = look(&z, "b.example.com.", RecordType::A);
    assert_eq!(nsec3s(&p), 1);
    // A wildcard answer (§7.2.6): the wildcard's RRSIG under the query
    // name, and the NSEC3 covering the next closer name.
    let (f, p) = look(&z, "x.dev.example.com.", RecordType::A);
    assert!(matches!(f, Found::Answer { .. }));
    assert_eq!(p.answer.len(), 1);
    assert_eq!(p.answer[0].name.to_ascii(), "x.dev.example.com.");
    assert_eq!(nsec3s(&p), 1);
    // A referral to an unsigned child (§7.2.7): the matching NSEC3.
    let (f, p) = look(&z, "h.sub.example.com.", RecordType::A);
    assert!(matches!(f, Found::Referral { .. }));
    assert_eq!(nsec3s(&p), 1);
    // CNAME: its RRSIG.
    let (_, p) = look(&z, "alias.example.com.", RecordType::A);
    assert_eq!(p.answer.len(), 1);
}

#[test]
fn a_transferred_signed_zone_is_indexed() {
    let z = signed();
    // As a secondary gets it: every record, signatures included, flat.
    let flat = ZoneData::from_records(
        std::iter::once(z.soa.clone())
            .chain(z.records().into_iter().cloned())
            .collect(),
    )
    .unwrap();
    assert!(flat.dnssec.is_none());
    let back = index(flat).unwrap();
    let (a, b) = (back.dnssec.as_ref().unwrap(), z.dnssec.as_ref().unwrap());
    assert_eq!(a.nsec3, b.nsec3);
    assert_eq!(a.rrsigs.len(), b.rrsigs.len());
    assert_eq!(back.len(), z.len());
    let (_, p) = look(&back, "nope.example.com.", RecordType::A);
    assert!(nsec3s(&p) >= 2);
}

#[test]
fn keys_states_decide_who_signs() {
    let mut ks = keys();
    // A published ZSK is in the DNSKEY set but does not sign.
    let mut new_zsk = key(3, KeyRole::Zsk, DnssecAlgorithm::EcdsaP256);
    new_zsk.state = KeyState::Published;
    ks.push(new_zsk.clone());
    let z = sign(&unsigned(&config()), &ks, 12, NOW, 86_400).unwrap();
    assert_eq!(dnskeys(&z).len(), 3);
    let s = z.dnssec.as_ref().unwrap();
    assert!(s.sigs("www.example.com", RecordType::A).len() == 1);
    // No active key: refused.
    for k in &mut ks {
        k.state = KeyState::Retired;
    }
    assert!(sign(&unsigned(&config()), &ks, 12, NOW, 86_400).is_err());
    // A damaged private key: refused, with the key.
    let mut bad = keys();
    bad[1].private_key = "!!".into();
    assert!(
        sign(&unsigned(&config()), &bad, 12, NOW, 86_400)
            .unwrap_err()
            .contains("key 2")
    );
    let _ = IpAddr::from([0, 0, 0, 0]);
}

#[test]
fn the_chain_adds_dnssec_only_for_do() {
    let f = forwarder(|c| {
        let dns = c.ip.dns.clone();
        *c = config();
        c.ip.dns = dns;
    });
    set_signed(&f, "example.com", signed());
    let mut up = Up::new();
    let ask = |dnssec: bool, name: &str, t: RecordType| {
        let mut m = Message::query();
        m.add_query(Q::query(Name::from_ascii(name).unwrap(), t));
        let mut e = Edns::new();
        e.set_dnssec_ok(dnssec);
        e.set_max_payload(4096);
        m.set_edns(e);
        m.to_vec().unwrap()
    };
    let m = run(
        &f,
        &mut up,
        LAN,
        &ask(false, "www.example.com.", RecordType::A),
    )
    .unwrap();
    assert_eq!(m.answers.len(), 2, "RFC 4035 §3.1: no RRSIG without DO");
    assert!(!m.edns.as_ref().unwrap().flags().dnssec_ok);
    let m = run(
        &f,
        &mut up,
        LAN,
        &ask(true, "www.example.com.", RecordType::A),
    )
    .unwrap();
    assert_eq!(m.answers.len(), 3);
    assert!(
        m.edns.as_ref().unwrap().flags().dnssec_ok,
        "RFC 3225: DO copied"
    );
    assert_eq!(m.metadata.response_code, ResponseCode::NoError);
    let m = run(
        &f,
        &mut up,
        LAN,
        &ask(true, "nope.example.com.", RecordType::A),
    )
    .unwrap();
    assert_eq!(m.metadata.response_code, ResponseCode::NXDomain);
    assert!(
        m.authorities
            .iter()
            .filter(|r| r.record_type() == RecordType::NSEC3)
            .count()
            >= 2
    );
    // The DNSKEY set is data: anyone may ask for it.
    let m = run(
        &f,
        &mut up,
        LAN,
        &ask(false, "example.com.", RecordType::DNSKEY),
    )
    .unwrap();
    assert_eq!(m.answers.len(), 2);
    let _ = Arc::new(());
}
