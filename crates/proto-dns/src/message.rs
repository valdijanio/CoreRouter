//! Queries and replies of the stub resolver, encoded and decoded by
//! `hickory-proto`. Only what a router needs to reach a name: A and AAAA,
//! CNAME chains, and the negative answers of RFC 2308.

use std::net::IpAddr;

use corerouter_model::dns::QType;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};

/// RFC 1035 §4.2.1: servers listen on port 53, UDP and TCP.
pub const PORT: u16 = 53;
/// RFC 1035 §2.3.4: 255 octets on the wire, 253 characters as text.
pub const MAX_NAME_LEN: usize = 253;
/// Longest CNAME chain followed inside one reply (BIND and Unbound stop
/// near 8–16; a longer chain is a loop or an attack).
pub const MAX_CNAME_HOPS: usize = 8;

/// A name the operator typed, checked. `key` is the cache key: lowercase
/// (RFC 1035 §2.3.3: names compare without case), without the final dot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QName {
    pub name: Name,
    pub key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NameError {
    #[error("empty name")]
    Empty,
    #[error("name longer than {MAX_NAME_LEN} characters")]
    TooLong,
    #[error("'{0}' is not a valid DNS label (letters, digits, '-' and '_', 1..=63 characters)")]
    BadLabel(String),
    #[error("'{0}' is not a valid name: {1}")]
    Invalid(String, String),
}

fn shown(s: &str) -> String {
    s.chars().take(64).collect()
}

/// Checks `text` as a host name. Non-ASCII names go through IDNA
/// (`açaí.com.br` → `xn--aa-...`), like a browser does.
pub fn parse_name(text: &str) -> Result<QName, NameError> {
    let trimmed = text.trim().strip_suffix('.').unwrap_or(text.trim());
    if trimmed.is_empty() {
        return Err(NameError::Empty);
    }
    if trimmed.len() > MAX_NAME_LEN * 4 {
        return Err(NameError::TooLong);
    }
    let parsed = if trimmed.is_ascii() {
        for label in trimmed.split('.') {
            let ok = (1..=63).contains(&label.len())
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
            if !ok {
                return Err(NameError::BadLabel(shown(label)));
            }
        }
        Name::from_ascii(trimmed)
    } else {
        Name::from_utf8(trimmed)
    };
    let mut name = parsed.map_err(|e| NameError::Invalid(shown(trimmed), e.to_string()))?;
    name.set_fqdn(true);
    let key = key_of(&name);
    if key.len() > MAX_NAME_LEN {
        return Err(NameError::TooLong);
    }
    Ok(QName { name, key })
}

/// Lowercase text of `name` without the final dot.
pub fn key_of(name: &Name) -> String {
    let text = name.to_lowercase().to_ascii();
    text.strip_suffix('.').unwrap_or(&text).to_owned()
}

fn rtype(q: QType) -> RecordType {
    match q {
        QType::A => RecordType::A,
        QType::Aaaa => RecordType::AAAA,
    }
}

/// A recursive query for `name`/`q` with a fresh random id (RFC 5452 §9.2),
/// advertising `udp_payload` bytes with EDNS(0) (RFC 6891 §6.2.5).
pub fn query(name: &Name, q: QType, udp_payload: u16) -> Result<(u16, Vec<u8>), String> {
    let mut m = Message::query();
    // RFC 1035 §4.1.1: RD asks the server to recurse for us.
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(name.clone(), rtype(q)));
    let mut edns = Edns::new();
    edns.set_max_payload(udp_payload.max(512));
    m.set_edns(edns);
    let id = m.metadata.id;
    m.to_vec().map(|b| (id, b)).map_err(|e| e.to_string())
}

/// What a good reply says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Addresses {
        addresses: Vec<IpAddr>,
        /// The last name of the CNAME chain, when there was one.
        canonical: Option<String>,
        /// Smallest TTL along the chain (RFC 2181 §5.2).
        ttl: u32,
    },
    /// `ttl`: how long it may be cached (RFC 2308 §5); `None` without SOA,
    /// which RFC 2308 §5 says SHOULD NOT be cached.
    NxDomain {
        ttl: Option<u32>,
    },
    NoData {
        ttl: Option<u32>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReplyError {
    /// Not an answer to this query (other id, question or not a reply):
    /// late, spoofed or stray. Keep waiting (RFC 5452 §9.1).
    #[error("reply to another query")]
    Mismatch,
    /// TC set: ask again over TCP (RFC 7766 §5).
    #[error("truncated reply")]
    Truncated,
    #[error("server failure (SERVFAIL)")]
    ServFail,
    #[error("query refused (REFUSED)")]
    Refused,
    #[error("error {0}")]
    Rcode(String),
    #[error("malformed reply: {0}")]
    Malformed(String),
}

/// RFC 2181 §8: a TTL with the top bit set is treated as zero.
fn ttl_of(r: &Record) -> u32 {
    if r.ttl > i32::MAX as u32 { 0 } else { r.ttl }
}

/// RFC 2308 §5: the negative TTL is the smaller of the SOA record's TTL
/// and its MINIMUM field.
fn negative_ttl(m: &Message) -> Option<u32> {
    m.authorities.iter().find_map(|r| match &r.data {
        RData::SOA(soa) => Some(ttl_of(r).min(soa.minimum)),
        _ => None,
    })
}

/// Checks `bytes` against the query (`id`, `name`, `q`) and reads it.
pub fn parse_reply(id: u16, name: &Name, q: QType, bytes: &[u8]) -> Result<Outcome, ReplyError> {
    let m = Message::from_vec(bytes).map_err(|e| {
        let mut s = e.to_string();
        s.truncate(120);
        ReplyError::Malformed(s)
    })?;
    let md = &m.metadata;
    if md.id != id || md.message_type != MessageType::Response || md.op_code != OpCode::Query {
        return Err(ReplyError::Mismatch);
    }
    // RFC 5452 §9.1: the question must be ours (case aside, RFC 1035 §2.3.3).
    let ours = matches!(m.queries.as_slice(),
        [one] if one.name() == name && one.query_type() == rtype(q));
    if !ours {
        return Err(ReplyError::Mismatch);
    }
    if md.truncation {
        return Err(ReplyError::Truncated);
    }
    match md.response_code {
        ResponseCode::NoError => {}
        // RFC 1035 §4.1.1 RCODE 3; RFC 2308 §2.1.
        ResponseCode::NXDomain => {
            return Ok(Outcome::NxDomain {
                ttl: negative_ttl(&m),
            });
        }
        ResponseCode::ServFail => return Err(ReplyError::ServFail),
        ResponseCode::Refused => return Err(ReplyError::Refused),
        other => return Err(ReplyError::Rcode(other.to_string())),
    }
    let want = rtype(q);
    let mut target = name.clone();
    let mut canonical = None;
    let mut ttl = u32::MAX;
    for _ in 0..=MAX_CNAME_HOPS {
        let mut addresses = Vec::new();
        let mut min = u32::MAX;
        // Only records owned by the name we follow count: anything else in
        // the answer section is out of the chain (RFC 2181 §5.4.1).
        for r in m.answers.iter().filter(|r| r.name == target) {
            let ip = match (&r.data, want) {
                (RData::A(a), RecordType::A) => IpAddr::V4(a.0),
                (RData::AAAA(a), RecordType::AAAA) => IpAddr::V6(a.0),
                _ => continue,
            };
            if !addresses.contains(&ip) {
                addresses.push(ip);
            }
            min = min.min(ttl_of(r));
        }
        if !addresses.is_empty() {
            return Ok(Outcome::Addresses {
                addresses,
                canonical,
                ttl: ttl.min(min),
            });
        }
        let next = m
            .answers
            .iter()
            .filter(|r| r.name == target)
            .find_map(|r| match &r.data {
                RData::CNAME(c) => Some((c.0.clone(), ttl_of(r))),
                _ => None,
            });
        let Some((alias, t)) = next else { break };
        ttl = ttl.min(t);
        canonical = Some(key_of(&alias));
        target = alias;
    }
    // RFC 2308 §2.2: NOERROR without the records asked for is NODATA.
    Ok(Outcome::NoData {
        ttl: negative_ttl(&m),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use hickory_proto::rr::rdata::{A, AAAA, CNAME, SOA};

    pub(crate) fn name(s: &str) -> Name {
        parse_name(s).unwrap().name
    }

    /// A reply to `query` with `answers`, `rcode` and maybe a SOA.
    pub(crate) fn reply(
        query: &[u8],
        rcode: ResponseCode,
        answers: Vec<Record>,
        soa: Option<(u32, u32)>,
    ) -> Vec<u8> {
        let q = Message::from_vec(query).unwrap();
        let mut m = Message::response(q.metadata.id, OpCode::Query);
        m.metadata.response_code = rcode;
        m.metadata.recursion_available = true;
        m.add_queries(q.queries.clone());
        m.add_answers(answers);
        if let Some((ttl, minimum)) = soa {
            m.add_authority(Record::from_rdata(
                name("arpa"),
                ttl,
                RData::SOA(SOA::new(
                    name("a.root-servers.net"),
                    name("nstld.verisign-grs.com"),
                    1,
                    1800,
                    900,
                    604_800,
                    minimum,
                )),
            ));
        }
        m.to_vec().unwrap()
    }

    pub(crate) fn a(owner: &str, ttl: u32, ip: [u8; 4]) -> Record {
        Record::from_rdata(name(owner), ttl, RData::A(A(ip.into())))
    }

    fn cname(owner: &str, ttl: u32, to: &str) -> Record {
        Record::from_rdata(name(owner), ttl, RData::CNAME(CNAME(name(to))))
    }

    /// RFC 1035 §6.2.1 / §6.2.2: "SRI-NIC.ARPA. 86400 IN A 26.0.0.73"
    /// and "10.0.0.51", asked in lowercase (§2.3.3: case does not matter).
    #[test]
    fn rfc1035_example_sri_nic() {
        let n = name("sri-nic.arpa");
        let (id, q) = query(&n, QType::A, 1232).unwrap();
        let bytes = reply(
            &q,
            ResponseCode::NoError,
            vec![
                a("SRI-NIC.ARPA", 86_400, [26, 0, 0, 73]),
                a("SRI-NIC.ARPA", 86_400, [10, 0, 0, 51]),
            ],
            None,
        );
        let got = parse_reply(id, &n, QType::A, &bytes).unwrap();
        assert_eq!(
            got,
            Outcome::Addresses {
                addresses: vec!["26.0.0.73".parse().unwrap(), "10.0.0.51".parse().unwrap()],
                canonical: None,
                ttl: 86_400,
            }
        );
    }

    #[test]
    fn query_asks_for_recursion_with_edns() {
        let n = name("example.com");
        let (id, q) = query(&n, QType::Aaaa, 1232).unwrap();
        let m = Message::from_vec(&q).unwrap();
        assert_eq!(m.metadata.id, id);
        assert!(m.metadata.recursion_desired);
        assert_eq!(m.queries[0].query_type(), RecordType::AAAA);
        assert_eq!(m.edns.unwrap().max_payload(), 1232);
    }

    #[test]
    fn cname_chain_is_followed_and_ttl_is_the_smallest() {
        let n = name("www.example.com");
        let (id, q) = query(&n, QType::A, 1232).unwrap();
        let bytes = reply(
            &q,
            ResponseCode::NoError,
            vec![
                cname("www.example.com", 300, "edge.cdn.example"),
                a("edge.cdn.example", 60, [192, 0, 2, 7]),
                // Not on the chain: ignored (RFC 2181 §5.4.1).
                a("evil.example", 99_999, [203, 0, 113, 66]),
            ],
            None,
        );
        let Outcome::Addresses {
            addresses,
            canonical,
            ttl,
        } = parse_reply(id, &n, QType::A, &bytes).unwrap()
        else {
            panic!("no addresses")
        };
        assert_eq!(addresses, vec![IpAddr::from([192, 0, 2, 7])]);
        assert_eq!(canonical.as_deref(), Some("edge.cdn.example"));
        assert_eq!(ttl, 60);
    }

    #[test]
    fn negative_answers_take_the_soa_ttl() {
        let n = name("nope.example");
        let (id, q) = query(&n, QType::A, 1232).unwrap();
        // RFC 2308 §5: min(SOA TTL, SOA MINIMUM).
        let nx = reply(&q, ResponseCode::NXDomain, vec![], Some((900, 300)));
        assert_eq!(
            parse_reply(id, &n, QType::A, &nx),
            Ok(Outcome::NxDomain { ttl: Some(300) })
        );
        let nodata = reply(&q, ResponseCode::NoError, vec![], Some((120, 3600)));
        assert_eq!(
            parse_reply(id, &n, QType::A, &nodata),
            Ok(Outcome::NoData { ttl: Some(120) })
        );
        let bare = reply(&q, ResponseCode::NXDomain, vec![], None);
        assert_eq!(
            parse_reply(id, &n, QType::A, &bare),
            Ok(Outcome::NxDomain { ttl: None })
        );
    }

    #[test]
    fn huge_ttl_counts_as_zero() {
        let n = name("x.example");
        let (id, q) = query(&n, QType::A, 1232).unwrap();
        let bytes = reply(
            &q,
            ResponseCode::NoError,
            vec![a("x.example", 0x8000_0001, [192, 0, 2, 1])],
            None,
        );
        let Ok(Outcome::Addresses { ttl, .. }) = parse_reply(id, &n, QType::A, &bytes) else {
            panic!()
        };
        assert_eq!(ttl, 0, "RFC 2181 §8");
    }

    #[test]
    fn foreign_replies_are_mismatches() {
        let n = name("example.com");
        let (id, q) = query(&n, QType::A, 1232).unwrap();
        let bytes = reply(&q, ResponseCode::NoError, vec![], None);
        assert_eq!(
            parse_reply(id.wrapping_add(1), &n, QType::A, &bytes),
            Err(ReplyError::Mismatch)
        );
        assert_eq!(
            parse_reply(id, &name("other.com"), QType::A, &bytes),
            Err(ReplyError::Mismatch)
        );
        assert_eq!(
            parse_reply(id, &n, QType::Aaaa, &bytes),
            Err(ReplyError::Mismatch)
        );
        // Our own query echoed back is not a reply.
        assert_eq!(parse_reply(id, &n, QType::A, &q), Err(ReplyError::Mismatch));
    }

    #[test]
    fn errors_and_truncation() {
        let n = name("example.com");
        let (id, q) = query(&n, QType::A, 1232).unwrap();
        let sf = reply(&q, ResponseCode::ServFail, vec![], None);
        assert_eq!(
            parse_reply(id, &n, QType::A, &sf),
            Err(ReplyError::ServFail)
        );
        let rf = reply(&q, ResponseCode::Refused, vec![], None);
        assert_eq!(parse_reply(id, &n, QType::A, &rf), Err(ReplyError::Refused));
        let mut tc = Message::from_vec(&reply(&q, ResponseCode::NoError, vec![], None)).unwrap();
        tc.metadata.truncation = true;
        assert_eq!(
            parse_reply(id, &n, QType::A, &tc.to_vec().unwrap()),
            Err(ReplyError::Truncated)
        );
        assert!(matches!(
            parse_reply(id, &n, QType::A, &[1, 2, 3]),
            Err(ReplyError::Malformed(_))
        ));
    }

    #[test]
    fn aaaa_answers() {
        let n = name("v6.example");
        let (id, q) = query(&n, QType::Aaaa, 1232).unwrap();
        let ip: std::net::Ipv6Addr = "2001:db8::53".parse().unwrap();
        let bytes = reply(
            &q,
            ResponseCode::NoError,
            vec![Record::from_rdata(
                name("v6.example"),
                30,
                RData::AAAA(AAAA(ip)),
            )],
            None,
        );
        assert!(matches!(
            parse_reply(id, &n, QType::Aaaa, &bytes),
            Ok(Outcome::Addresses { addresses, .. }) if addresses == vec![IpAddr::V6(ip)]
        ));
    }

    #[test]
    fn names_are_checked() {
        assert_eq!(parse_name("UOL.com.BR.").unwrap().key, "uol.com.br");
        assert!(parse_name("").is_err());
        assert!(parse_name("a..b").is_err());
        assert!(parse_name("bad name").is_err());
        assert!(parse_name(&"a".repeat(64)).is_err());
        assert!(parse_name(&format!("{}.com", ["a"; 130].join("."))).is_err());
        assert!(parse_name("açaí.com.br").unwrap().key.starts_with("xn--"));
    }

    proptest::proptest! {
        /// Hostile bytes never panic the decoder.
        #[test]
        fn any_bytes_are_safe(bytes in proptest::collection::vec(proptest::num::u8::ANY, 0..600)) {
            let n = name("example.com");
            let _ = parse_reply(0x1234, &n, QType::A, &bytes);
        }

        /// A real reply with its first bytes kept and the rest scrambled.
        #[test]
        fn damaged_replies_are_safe(cut in 0usize..200, noise in proptest::collection::vec(proptest::num::u8::ANY, 0..64)) {
            let n = name("www.example.com");
            let (id, q) = query(&n, QType::A, 1232).unwrap();
            let mut bytes = reply(&q, ResponseCode::NoError,
                vec![cname("www.example.com", 300, "e.example"), a("e.example", 60, [192, 0, 2, 7])], Some((60, 60)));
            bytes.truncate(cut.min(bytes.len()));
            bytes.extend(noise);
            let _ = parse_reply(id, &n, QType::A, &bytes);
        }
    }
}
