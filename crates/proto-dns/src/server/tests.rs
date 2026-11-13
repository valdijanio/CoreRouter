//! The chain end to end: bytes in, bytes out, with a fake upstream.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use corerouter_model::Config;
use corerouter_model::dns::Dns;
use corerouter_model::dns_static::{StaticEntry, StaticType};
use corerouter_model::types::ItemId;
use hickory_proto::op::{Edns, Message, OpCode, Query as Q, ResponseCode};
use hickory_proto::rr::rdata::{A, SOA, TXT};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

use super::*;
use crate::resolver::{Settings, TransportError};

/// An upstream that answers A with `192.0.2.<n>` (n = queries so far),
/// TXT with "up", NXDOMAIN (with SOA) for `nope.*`; silent when `down`.
pub(crate) struct Up {
    pub now: u64,
    pub asked: Vec<(IpAddr, String, RecordType)>,
    pub down: bool,
}

impl Up {
    pub(crate) fn new() -> Self {
        Self {
            now: 1_000,
            asked: Vec::new(),
            down: false,
        }
    }
}

impl Transport for Up {
    fn now_ms(&self) -> u64 {
        self.now
    }

    fn exchange(
        &mut self,
        server: SocketAddr,
        query: &[u8],
        _tcp: bool,
        wait_ms: u64,
        accept: &mut dyn FnMut(&[u8]) -> bool,
    ) -> Result<Vec<u8>, TransportError> {
        self.now += 3;
        let q = Message::from_vec(query).map_err(|e| TransportError::Io(e.to_string()))?;
        let qq = q.queries[0].clone();
        self.asked
            .push((server.ip(), qq.name().to_ascii(), qq.query_type()));
        if self.down {
            self.now += wait_ms;
            return Err(TransportError::Timeout);
        }
        let mut m = Message::response(q.metadata.id, OpCode::Query);
        m.metadata.recursion_available = true;
        m.add_query(qq.clone());
        let n = u8::try_from(self.asked.len()).unwrap_or(255);
        if qq.name().to_ascii().starts_with("nope.") {
            m.metadata.response_code = ResponseCode::NXDomain;
            m.add_authority(Record::from_rdata(
                Name::from_ascii("example.").unwrap(),
                60,
                RData::SOA(SOA::new(
                    Name::from_ascii("ns.example.").unwrap(),
                    Name::from_ascii("h.example.").unwrap(),
                    1,
                    1,
                    1,
                    1,
                    60,
                )),
            ));
        } else if qq.query_type() == RecordType::A {
            m.add_answer(Record::from_rdata(
                qq.name().clone(),
                300,
                RData::A(A::new(192, 0, 2, n)),
            ));
        } else if qq.query_type() == RecordType::TXT {
            m.add_answer(Record::from_rdata(
                qq.name().clone(),
                300,
                RData::TXT(TXT::new(vec!["up".into()])),
            ));
        }
        let b = m.to_vec().map_err(|e| TransportError::Io(e.to_string()))?;
        if accept(&b) {
            Ok(b)
        } else {
            Err(TransportError::Timeout)
        }
    }
}

pub(crate) const LAN: [u8; 4] = [192, 168, 88, 10];

/// A forwarder with upstream 198.51.100.53, LAN 192.168.88.0/24 allowed.
pub(crate) fn forwarder(edit: impl FnOnce(&mut Config)) -> Forwarder {
    let mut cfg = Config::default();
    cfg.ip.dns = Dns {
        servers: vec![IpAddr::from([198, 51, 100, 53])],
        allow_remote_requests: true,
        ..Dns::default()
    };
    edit(&mut cfg);
    let resolver = Arc::new(Resolver::new(Settings::new(&cfg.ip.dns, &[])));
    let f = Forwarder::new(resolver);
    f.configure(Arc::new(cfg), vec!["192.168.88.0/24".parse().unwrap()]);
    f
}

pub(crate) fn ask(name: &str, t: RecordType) -> Vec<u8> {
    let mut m = Message::query();
    m.metadata.id = 0x4242;
    m.metadata.recursion_desired = true;
    m.add_query(Q::query(Name::from_ascii(name).unwrap(), t));
    m.to_vec().unwrap()
}

/// Runs the whole chain (a worker if needed) and decodes the reply.
pub(crate) fn run(f: &Forwarder, up: &mut Up, from: [u8; 4], packet: &[u8]) -> Option<Message> {
    let done = match f.start(packet, IpAddr::from(from), false, up.now) {
        Start::Done(d) => d,
        Start::Pending(p) => f.finish(*p, up),
    };
    done.reply.map(|b| Message::from_vec(&b).unwrap())
}

fn entry(id: u32, name: &str, t: StaticType, edit: impl FnOnce(&mut StaticEntry)) -> StaticEntry {
    let mut e = StaticEntry::new(ItemId(id));
    e.name = name.into();
    e.rtype = t;
    edit(&mut e);
    e
}

fn addrs(m: &Message) -> Vec<String> {
    m.answers.iter().map(|r| r.data.to_string()).collect()
}

#[test]
fn stages_are_in_order() {
    let names: Vec<&str> = stages().iter().map(|s| s.name).collect();
    assert_eq!(
        names,
        [
            "acl",
            "limit",
            "special",
            "adlist",
            "static",
            "zones",
            "cache",
            "upstream",
            "statistics"
        ]
    );
}

#[test]
fn chain_acl_static_cache_upstream() {
    let f = forwarder(|c| {
        c.ip.dns_static
            .entries
            .push(entry(1, "nas.lan", StaticType::A, |e| {
                e.address = Some([192, 168, 88, 2].into());
            }));
    });
    let mut up = Up::new();
    // Static: answered here, authoritative, upstream never asked.
    let m = run(&f, &mut up, LAN, &ask("NAS.lan.", RecordType::A)).unwrap();
    assert_eq!(m.metadata.id, 0x4242);
    assert!(m.metadata.authoritative && m.metadata.recursion_available);
    assert_eq!(
        m.queries[0].name().to_ascii(),
        "NAS.lan.",
        "question as asked"
    );
    assert_eq!(addrs(&m), ["192.168.88.2"]);
    assert!(up.asked.is_empty());
    // Upstream, then the cache (TTL counting down).
    let m = run(&f, &mut up, LAN, &ask("www.example.com.", RecordType::A)).unwrap();
    assert_eq!(addrs(&m), ["192.0.2.1"]);
    up.now += 10_000;
    let m = run(&f, &mut up, LAN, &ask("www.example.com.", RecordType::A)).unwrap();
    assert_eq!(addrs(&m), ["192.0.2.1"]);
    assert_eq!(m.answers[0].ttl, 290);
    assert_eq!(up.asked.len(), 1, "second from the cache");
    let rows = f.resolver.cache_rows(up.now);
    assert_eq!(rows[0].hits, 1);
    // Any type goes through (TXT).
    let m = run(&f, &mut up, LAN, &ask("example.com.", RecordType::TXT)).unwrap();
    assert_eq!(addrs(&m), ["up"]);
}

#[test]
fn outsiders_are_refused() {
    let f = forwarder(|_| {});
    let mut up = Up::new();
    let m = run(
        &f,
        &mut up,
        [203, 0, 113, 9],
        &ask("example.com.", RecordType::A),
    )
    .unwrap();
    assert_eq!(m.metadata.response_code, ResponseCode::Refused);
    assert!(m.answers.is_empty() && up.asked.is_empty());
    let m = run(
        &f,
        &mut up,
        [127, 0, 0, 1],
        &ask("example.com.", RecordType::A),
    )
    .unwrap();
    assert_eq!(
        m.metadata.response_code,
        ResponseCode::NoError,
        "the router itself"
    );
}

#[test]
fn per_client_limit_drops_udp() {
    let f = forwarder(|c| c.ip.dns.max_queries_per_client = 5);
    let mut up = Up::new();
    let q = ask("example.com.", RecordType::A);
    let answered = (0..20)
        .filter(|_| run(&f, &mut up, LAN, &q).is_some())
        .count();
    assert_eq!(answered, 10, "burst of twice the rate, then dropped");
    assert!(
        run(&f, &mut up, [192, 168, 88, 11], &q).is_some(),
        "other clients"
    );
    up.now += 1_000;
    assert!(run(&f, &mut up, LAN, &q).is_some(), "refilled");
}

#[test]
fn stale_answer_when_upstream_is_down() {
    let f = forwarder(|_| {});
    let mut up = Up::new();
    let q = ask("www.example.com.", RecordType::A);
    run(&f, &mut up, LAN, &q).unwrap();
    up.now += 301_000;
    up.down = true;
    let m = run(&f, &mut up, LAN, &q).unwrap();
    assert_eq!(m.metadata.response_code, ResponseCode::NoError, "RFC 8767");
    assert_eq!(addrs(&m), ["192.0.2.1"]);
    assert_eq!(m.answers[0].ttl, 30);
    // Nothing stale: SERVFAIL.
    let m = run(&f, &mut up, LAN, &ask("other.example.", RecordType::A)).unwrap();
    assert_eq!(m.metadata.response_code, ResponseCode::ServFail);
}

#[test]
fn static_regexp_subdomain_nxdomain_fwd() {
    let f = forwarder(|c| {
        let e = &mut c.ip.dns_static.entries;
        e.push(entry(1, "lan", StaticType::A, |e| {
            e.address = Some([192, 168, 88, 1].into());
            e.match_subdomain = true;
        }));
        // Regexp entries win over names (RouterOS), whatever the position.
        e.push(entry(2, "", StaticType::A, |e| {
            e.regexp = r"^printer[0-9]+\.lan$".into();
            e.address = Some([192, 168, 88, 50].into());
        }));
        e.push(entry(3, "ads.example", StaticType::Nxdomain, |e| {
            e.match_subdomain = true
        }));
        e.push(entry(4, "corp.example", StaticType::Fwd, |e| {
            e.forward_to = vec![[10, 0, 0, 53].into()];
            e.match_subdomain = true;
        }));
        e.push(entry(5, "off.lan", StaticType::A, |e| {
            e.address = Some([192, 168, 88, 99].into());
            e.disabled = true;
        }));
    });
    let mut up = Up::new();
    let a = |up: &mut Up, n: &str| run(&f, up, LAN, &ask(n, RecordType::A)).unwrap();
    assert_eq!(addrs(&a(&mut up, "printer7.lan.")), ["192.168.88.50"]);
    assert_eq!(
        addrs(&a(&mut up, "deep.x.lan.")),
        ["192.168.88.1"],
        "match_subdomain"
    );
    assert_eq!(
        addrs(&a(&mut up, "off.lan.")),
        ["192.168.88.1"],
        "disabled skipped"
    );
    assert!(up.asked.is_empty());
    let m = a(&mut up, "tracker.ads.example.");
    assert_eq!(m.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(
        a(&mut up, "notads.example.").metadata.response_code,
        ResponseCode::NoError
    );
    up.asked.clear();
    a(&mut up, "git.corp.example.");
    assert_eq!(up.asked[0].0, IpAddr::from([10, 0, 0, 53]), "FWD");
    // AAAA for a name with only an A entry goes upstream (RouterOS).
    up.asked.clear();
    run(&f, &mut up, LAN, &ask("lan.", RecordType::AAAA)).unwrap();
    assert_eq!(up.asked.len(), 1);
}

#[test]
fn static_cname_chain_ptr_and_txt() {
    let f = forwarder(|c| {
        let e = &mut c.ip.dns_static.entries;
        e.push(entry(1, "www.lan", StaticType::Cname, |e| {
            e.cname = "nas.lan".into()
        }));
        e.push(entry(2, "nas.lan", StaticType::A, |e| {
            e.address = Some([192, 168, 88, 2].into());
            e.ttl_secs = 600;
        }));
        e.push(entry(3, "out.lan", StaticType::Cname, |e| {
            e.cname = "www.example.com".into()
        }));
        e.push(entry(4, "loop1.lan", StaticType::Cname, |e| {
            e.cname = "loop2.lan".into()
        }));
        e.push(entry(5, "loop2.lan", StaticType::Cname, |e| {
            e.cname = "loop1.lan".into()
        }));
        e.push(entry(6, "t.lan", StaticType::Txt, |e| {
            e.text = "x".repeat(300)
        }));
    });
    let mut up = Up::new();
    let m = run(&f, &mut up, LAN, &ask("www.lan.", RecordType::A)).unwrap();
    assert_eq!(
        addrs(&m),
        ["nas.lan.", "192.168.88.2"],
        "CNAME then its target"
    );
    let m = run(&f, &mut up, LAN, &ask("out.lan.", RecordType::A)).unwrap();
    assert_eq!(
        addrs(&m),
        ["www.example.com.", "192.0.2.1"],
        "target from upstream"
    );
    let m = run(&f, &mut up, LAN, &ask("loop1.lan.", RecordType::A)).unwrap();
    assert_eq!(m.metadata.response_code, ResponseCode::ServFail);
    let m = run(
        &f,
        &mut up,
        LAN,
        &ask("2.88.168.192.in-addr.arpa.", RecordType::PTR),
    )
    .unwrap();
    assert_eq!(addrs(&m), ["nas.lan."], "automatic PTR");
    assert_eq!(m.answers[0].ttl, 600);
    let m = run(&f, &mut up, LAN, &ask("t.lan.", RecordType::TXT)).unwrap();
    let RData::TXT(txt) = &m.answers[0].data else {
        panic!()
    };
    assert_eq!(txt.txt_data.len(), 2, "split in 255-byte strings");
}

#[test]
fn address_list_effect() {
    let f = forwarder(|c| {
        c.ip.dns.address_list_extra_time_secs = 60;
        c.ip.dns_static
            .entries
            .push(entry(1, "vpn.example", StaticType::Fwd, |e| {
                e.forward_to = vec![[10, 0, 0, 53].into()];
                e.address_list = "vpn".into();
            }));
    });
    let mut up = Up::new();
    let Start::Pending(p) = f.start(&ask("vpn.example.", RecordType::A), LAN.into(), false, 0)
    else {
        panic!("needs upstream")
    };
    let done = f.finish(*p, &mut up);
    assert_eq!(
        done.effects,
        vec![Effect::AddressList {
            list: "vpn".into(),
            address: [192, 0, 2, 1].into(),
            timeout_secs: 360,
        }]
    );
    assert_eq!(done.answered_by, "upstream");
}

#[test]
fn hostile_and_odd_queries() {
    let f = forwarder(|_| {});
    let mut up = Up::new();
    // Too short, a response, junk after a header.
    assert!(run(&f, &mut up, LAN, &[1, 2, 3]).is_none());
    let mut resp = ask("example.com.", RecordType::A);
    resp[2] |= 0x80;
    assert!(
        run(&f, &mut up, LAN, &resp).is_none(),
        "never answer a response"
    );
    let mut junk = ask("example.com.", RecordType::A);
    junk.truncate(14);
    let m = run(&f, &mut up, LAN, &junk).unwrap();
    assert_eq!(m.metadata.response_code, ResponseCode::FormErr);
    // ANY: RFC 8482 HINFO, nothing upstream.
    let m = run(&f, &mut up, LAN, &ask("example.com.", RecordType::ANY)).unwrap();
    assert_eq!(m.answers[0].record_type(), RecordType::HINFO);
    // AXFR refused, CH class refused, two questions FORMERR.
    let m = run(&f, &mut up, LAN, &ask("example.com.", RecordType::AXFR)).unwrap();
    assert_eq!(m.metadata.response_code, ResponseCode::Refused);
    let mut ch = Message::query();
    let mut q = Q::query(Name::from_ascii("version.bind.").unwrap(), RecordType::TXT);
    q.set_query_class(DNSClass::CH);
    ch.add_query(q);
    let m = run(&f, &mut up, LAN, &ch.to_vec().unwrap()).unwrap();
    assert_eq!(m.metadata.response_code, ResponseCode::Refused);
    let mut two = Message::from_vec(&ask("a.example.", RecordType::A)).unwrap();
    two.add_query(Q::query(
        Name::from_ascii("b.example.").unwrap(),
        RecordType::A,
    ));
    let m = run(&f, &mut up, LAN, &two.to_vec().unwrap()).unwrap();
    assert_eq!(m.metadata.response_code, ResponseCode::FormErr);
    // localhost and .invalid never leave (RFC 6761).
    let m = run(&f, &mut up, LAN, &ask("localhost.", RecordType::A)).unwrap();
    assert_eq!(addrs(&m), ["127.0.0.1"]);
    let m = run(&f, &mut up, LAN, &ask("x.invalid.", RecordType::A)).unwrap();
    assert_eq!(m.metadata.response_code, ResponseCode::NXDomain);
    assert!(up.asked.is_empty());
}

#[test]
fn big_udp_answers_are_truncated() {
    let f = forwarder(|c| {
        for i in 0..40u8 {
            c.ip.dns_static
                .entries
                .push(entry(u32::from(i) + 1, "many.lan", StaticType::A, |e| {
                    e.address = Some([10, 0, 0, i].into());
                }));
        }
    });
    let mut up = Up::new();
    let m = run(&f, &mut up, LAN, &ask("many.lan.", RecordType::A)).unwrap();
    assert!(
        m.metadata.truncation && m.answers.is_empty(),
        "40 × 16 B > 512"
    );
    // With EDNS 1232 it fits; over TCP always.
    let mut q = Message::from_vec(&ask("many.lan.", RecordType::A)).unwrap();
    let mut e = Edns::new();
    e.set_max_payload(1232);
    q.set_edns(e);
    let m = run(&f, &mut up, LAN, &q.to_vec().unwrap()).unwrap();
    assert_eq!(m.answers.len(), 40);
    assert!(m.edns.is_some(), "EDNS answered with EDNS");
    let Start::Done(d) = f.start(&ask("many.lan.", RecordType::A), LAN.into(), true, 0) else {
        panic!()
    };
    assert_eq!(
        Message::from_vec(&d.reply.unwrap()).unwrap().answers.len(),
        40
    );
}

/// `packet` with EDNS (payload 1232), as a client that understands it.
fn with_edns(packet: &[u8]) -> Vec<u8> {
    let mut q = Message::from_vec(packet).unwrap();
    let mut e = Edns::new();
    e.set_max_payload(1232);
    q.set_edns(e);
    q.to_vec().unwrap()
}

/// The RFC 8914 options of a reply: (INFO-CODE, EXTRA-TEXT).
fn ede_of(m: &Message) -> Vec<(u16, String)> {
    let Some(e) = m.edns.as_ref() else {
        return Vec::new();
    };
    e.options()
        .options
        .iter()
        .filter_map(|(_, o)| match o {
            hickory_proto::rr::rdata::opt::EdnsOption::Unknown(EDE_OPTION, data) => Some((
                u16::from_be_bytes([data[0], data[1]]),
                String::from_utf8(data[2..].to_vec()).unwrap(),
            )),
            _ => None,
        })
        .collect()
}

/// G4.1ze, RFC 8914: the extended error goes to a client that sent an OPT
/// (§2), never to one that did not; one option, code and short text.
#[test]
fn extended_errors_are_sent_with_edns() {
    let f = forwarder(|c| {
        c.ip.dns_static
            .entries
            .push(entry(1, "ads.lan", StaticType::Nxdomain, |_| {}));
    });
    let mut up = Up::new();
    // §4.19 Prohibited: outside allowed_from.
    let q = ask("www.example.com.", RecordType::A);
    let m = run(&f, &mut up, [203, 0, 113, 9], &with_edns(&q)).unwrap();
    assert_eq!(m.metadata.response_code, ResponseCode::Refused);
    assert_eq!(
        ede_of(&m),
        [(18, "client not allowed by this resolver".to_owned())]
    );
    let m = run(&f, &mut up, [203, 0, 113, 9], &q).unwrap();
    assert!(
        m.edns.is_none(),
        "no OPT in the query: none in the reply (§2)"
    );
    // §4.4 Stale Answer, §4.23 No Reachable Authority.
    run(&f, &mut up, LAN, &q).unwrap();
    up.now += 301_000;
    up.down = true;
    let m = run(&f, &mut up, LAN, &with_edns(&q)).unwrap();
    assert_eq!(m.metadata.response_code, ResponseCode::NoError);
    assert_eq!(ede_of(&m).first().map(|e| e.0), Some(3), "RFC 8767 stale");
    let m = run(
        &f,
        &mut up,
        LAN,
        &with_edns(&ask("other.example.", RecordType::A)),
    )
    .unwrap();
    assert_eq!(m.metadata.response_code, ResponseCode::ServFail);
    assert_eq!(ede_of(&m).first().map(|e| e.0), Some(22));
    // A plain answer has none.
    let m = run(
        &f,
        &mut up,
        LAN,
        &with_edns(&ask("ads.lan.", RecordType::A)),
    )
    .unwrap();
    assert_eq!(m.metadata.response_code, ResponseCode::NXDomain);
    assert!(
        ede_of(&m).is_empty(),
        "a static NXDOMAIN is the operator's answer, not an error"
    );
}

/// RFC 8914 §2: the option on the wire, code 15, INFO-CODE in network
/// order, EXTRA-TEXT without a NUL.
#[test]
fn ede_option_wire_format() {
    let mut e = Edns::new();
    e.options_mut().insert(ede_option(22));
    let mut m = Message::response(1, OpCode::Query);
    m.set_edns(e);
    let bytes = m.to_vec().unwrap();
    let text = b"no upstream server answered";
    let mut want = vec![0, 15];
    want.extend_from_slice(&u16::try_from(2 + text.len()).unwrap().to_be_bytes());
    want.extend_from_slice(&[0, 22]);
    want.extend_from_slice(text);
    assert!(
        bytes.windows(want.len()).any(|w| w == want.as_slice()),
        "{bytes:02x?}"
    );
}

/// RFC 8914 §3: a UDP reply too large drops its EDE first and sets TC,
/// keeping the records; only if still too large, the records go.
#[test]
fn ede_is_dropped_first_when_the_reply_is_too_large() {
    let mut m = Message::response(1, OpCode::Query);
    for i in 0..20u8 {
        m.add_answer(Record::from_rdata(
            Name::from_ascii("a.lan.").unwrap(),
            60,
            RData::A(A::new(10, 0, 0, i)),
        ));
    }
    let mut e = Edns::new();
    e.options_mut().insert(ede_option(3));
    m.set_edns(e);
    let whole = m.to_vec().unwrap().len();
    let mut bare = m.clone();
    bare.edns
        .as_mut()
        .unwrap()
        .options_mut()
        .remove(EdnsCode::from(EDE_OPTION));
    let without = bare.to_vec().unwrap().len();
    assert!(without < whole);
    let (b, tc) = fit(m.clone(), whole).unwrap();
    assert!(!tc && b.len() == whole, "fits: as it is");
    let (b, tc) = fit(m.clone(), without).unwrap();
    let r = Message::from_vec(&b).unwrap();
    assert!(
        tc && r.metadata.truncation && r.answers.len() == 20 && ede_of(&r).is_empty(),
        "EDE dropped, TC set"
    );
    let (b, tc) = fit(m, without - 1).unwrap();
    let r = Message::from_vec(&b).unwrap();
    assert!(tc && r.answers.is_empty(), "then the records");
}

#[test]
fn negative_answers_carry_the_soa() {
    let f = forwarder(|_| {});
    let mut up = Up::new();
    for _ in 0..2 {
        let m = run(&f, &mut up, LAN, &ask("nope.example.", RecordType::A)).unwrap();
        assert_eq!(m.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(m.authorities.len(), 1, "RFC 2308 §3");
    }
    assert_eq!(up.asked.len(), 1, "negative answer cached");
}

proptest::proptest! {
    /// Hostile bytes from the LAN never panic the chain.
    #[test]
    fn any_packet_is_safe(bytes in proptest::collection::vec(proptest::num::u8::ANY, 0..700)) {
        let f = forwarder(|_| {});
        let mut up = Up::new();
        let _ = run(&f, &mut up, LAN, &bytes);
    }

    /// A real query with its tail scrambled.
    #[test]
    fn damaged_queries_are_safe(cut in 0usize..40, noise in proptest::collection::vec(proptest::num::u8::ANY, 0..64)) {
        let f = forwarder(|_| {});
        let mut up = Up::new();
        let mut q = ask("www.example.com.", RecordType::A);
        q.truncate(cut.min(q.len()));
        q.extend(noise);
        let _ = run(&f, &mut up, LAN, &q);
    }
}

/// G4.3x: the notebook (dev.607): `allowed_from: [LAN]`, ether2 in LAN
/// with 100.64.0.1/24 and a PPPoE server, profile pool 100.65.0.10–50 (its
/// `next_pool` .60–.61): the subscribers ask the router's DNS too. Without
/// the PPPoE server on a LAN interface, they do not.
#[test]
fn pppoe_subscribers_of_a_list_interface_are_allowed() {
    use corerouter_model::config::AddressEntry;
    use corerouter_model::interface_list::InterfaceListMember;
    let mut cfg = Config::default();
    cfg.ip.addresses.push(AddressEntry {
        id: ItemId(1),
        address: "100.64.0.1/24".parse().unwrap(),
        interface: "ether2".parse().unwrap(),
        disabled: false,
        comment: String::new(),
        from_pool: None,
    });
    cfg.interface_lists.members.push(InterfaceListMember {
        id: ItemId(1),
        list: "LAN".parse().unwrap(),
        interface: "ether2".parse().unwrap(),
        disabled: false,
        comment: String::new(),
    });
    cfg.ip.dns.allowed_from = vec!["LAN".into()];
    cfg.ip.pools = serde_json::from_value(serde_json::json!({"pools": [
        {"id": "*1", "name": "ppp", "ranges": ["100.65.0.10-100.65.0.50"], "next_pool": "more"},
        {"id": "*2", "name": "more", "ranges": ["100.65.0.60-100.65.0.61"]}
    ]}))
    .unwrap();
    cfg.ppp.profiles.push(
        serde_json::from_value(serde_json::json!({"id": "*1", "name": "teste", "remote_address": "ppp", "local_address": "100.65.0.1"}))
            .unwrap(),
    );
    let nets = |cfg: &Config| -> Vec<String> {
        allowed_networks(cfg)
            .iter()
            .map(ToString::to_string)
            .collect()
    };
    assert_eq!(nets(&cfg), ["100.64.0.0/24"], "no PPPoE server yet");
    cfg.ppp.pppoe_servers.push(
        serde_json::from_value(serde_json::json!({"id": "*1", "interface": "ether2"})).unwrap(),
    );
    let got = nets(&cfg);
    for want in [
        "100.64.0.0/24",
        "100.65.0.10/31",
        "100.65.0.12/30",
        "100.65.0.16/28",
        "100.65.0.32/28",
        "100.65.0.48/31",
        "100.65.0.50/32",
        "100.65.0.60/31",
    ] {
        assert!(got.iter().any(|g| g == want), "{want} not in {got:?}");
    }
    let allowed = allowed_networks(&cfg);
    let inside = |ip: &str| {
        allowed
            .iter()
            .any(|n| n.contains(&ip.parse::<std::net::IpAddr>().unwrap()))
    };
    assert!(inside("100.65.0.10") && inside("100.65.0.50") && inside("100.65.0.61"));
    assert!(!inside("100.65.0.9") && !inside("100.65.0.51") && !inside("100.65.0.62"));
}

#[test]
fn allowed_networks_and_validation() {
    use corerouter_model::config::AddressEntry;
    use corerouter_model::interface_list::InterfaceListMember;
    let mut cfg = Config::default();
    cfg.ip.addresses.push(AddressEntry {
        id: ItemId(1),
        address: "192.168.88.1/24".parse().unwrap(),
        interface: "bridge".parse().unwrap(),
        disabled: false,
        comment: String::new(),
        from_pool: None,
    });
    cfg.interface_lists.members.push(InterfaceListMember {
        id: ItemId(1),
        list: "LAN".parse().unwrap(),
        interface: "bridge".parse().unwrap(),
        disabled: false,
        comment: String::new(),
    });
    cfg.ip.dns.allowed_from = vec!["LAN".into(), "10.9.0.0/16".into()];
    let nets: Vec<String> = allowed_networks(&cfg)
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(nets, ["10.9.0.0/16", "192.168.88.0/24"]);
    assert!(crate::validate(&cfg).is_empty());
    cfg.ip.dns.allowed_from = vec!["NOPE".into()];
    cfg.ip
        .dns_static
        .entries
        .push(entry(1, "", StaticType::A, |e| {
            e.regexp = "(unclosed".into();
            e.address = Some([10, 0, 0, 1].into());
        }));
    let issues = crate::validate(&cfg);
    assert_eq!(issues.len(), 2, "{issues:?}");
}

/// G4.1zf: `resolver.arpa` is the router's (RFC 9462 §6.4, erratum 8278)
/// and `_dns.resolver.arpa` SVCB names its DNS over TLS service (DDR).
#[test]
fn resolver_arpa_is_answered_here_with_the_ddr_designation() {
    use hickory_proto::rr::rdata::svcb::{SvcParamKey, SvcParamValue};
    let f = forwarder(|c| {
        c.system.identity = "Lab Router".into();
        c.ip.addresses.push(corerouter_model::config::AddressEntry {
            id: corerouter_model::ItemId(1),
            address: "192.168.88.1/24".parse().unwrap(),
            interface: "ether2".parse().unwrap(),
            disabled: false,
            comment: String::new(),
            from_pool: None,
        });
    });
    let mut up = Up::new();
    // Off: NODATA, never forwarded.
    let m = run(
        &f,
        &mut up,
        LAN,
        &ask("_dns.resolver.arpa.", RecordType::SVCB),
    )
    .unwrap();
    assert_eq!(m.metadata.response_code, ResponseCode::NoError);
    assert!(m.answers.is_empty());
    let m = run(&f, &mut up, LAN, &ask("x.resolver.arpa.", RecordType::A)).unwrap();
    assert_eq!(
        m.metadata.response_code,
        ResponseCode::NXDomain,
        "erratum 8278"
    );
    let m = run(&f, &mut up, LAN, &ask("_dns.resolver.arpa.", RecordType::A)).unwrap();
    assert_eq!(
        (m.metadata.response_code, m.answers.len()),
        (ResponseCode::NoError, 0)
    );
    // On, on port 8853: alpn, port, the LAN address as hint and in additional.
    let cfg = f.config();
    let mut c = (*cfg.config).clone();
    c.ip.dns.encrypted_service.dot = true;
    c.ip.dns.encrypted_service.dot_port = 8853;
    c.ip.dns.encrypted_service.certificate = "dns-server".into();
    f.configure(Arc::new(c), cfg.allowed.clone());
    let m = run(
        &f,
        &mut up,
        LAN,
        &ask("_dns.resolver.arpa.", RecordType::SVCB),
    )
    .unwrap();
    assert!(m.metadata.authoritative);
    let RData::SVCB(svcb) = &m.answers[0].data else {
        panic!("{m:?}")
    };
    assert_eq!(svcb.svc_priority, 1);
    assert_eq!(svcb.target_name.to_string(), "lab-router.");
    let keys: Vec<SvcParamKey> = svcb.svc_params.iter().map(|(k, _)| *k).collect();
    assert_eq!(
        keys,
        [SvcParamKey::Alpn, SvcParamKey::Port, SvcParamKey::Ipv4Hint],
        "ascending, RFC 9460 §2.2"
    );
    assert!(matches!(&svcb.svc_params[1].1, SvcParamValue::Port(8853)));
    assert_eq!(m.additionals.len(), 1);
    assert_eq!(m.additionals[0].name.to_string(), "lab-router.");
    assert!(up.asked.is_empty(), "resolver.arpa never leaves");
}
