//! Queries and replies, encoded and decoded by `hickory-proto`: any record
//! type (the LAN forwarder asks what its clients ask), CNAME chains, and
//! the negative answers of RFC 2308.

use std::net::IpAddr;

use corerouter_model::dns::CacheKind;
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

impl QName {
    /// From a name decoded off the wire (already checked by the decoder).
    pub fn from_name(name: &Name) -> Self {
        let mut name = name.clone();
        name.set_fqdn(true);
        let key = key_of(&name);
        Self { name, key }
    }
}

/// Lowercase text of `name` without the final dot.
pub fn key_of(name: &Name) -> String {
    let text = name.to_lowercase().to_ascii();
    text.strip_suffix('.').unwrap_or(&text).to_owned()
}

/// A recursive query for `name`/`rtype` with a fresh random id (RFC 5452
/// §9.2), advertising `udp_payload` bytes with EDNS(0) (RFC 6891 §6.2.5).
pub fn query(name: &Name, rtype: RecordType, udp_payload: u16) -> Result<(u16, Vec<u8>), String> {
    let mut m = Message::query();
    // RFC 1035 §4.1.1: RD asks the server to recurse for us.
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(name.clone(), rtype));
    let mut edns = Edns::new();
    edns.set_max_payload(udp_payload.max(512));
    m.set_edns(edns);
    let id = m.metadata.id;
    m.to_vec().map(|b| (id, b)).map_err(|e| e.to_string())
}

/// The two final answers of a lookup (the others make it ask elsewhere).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rcode {
    NoError,
    /// RFC 1035 §4.1.1 RCODE 3; RFC 2308 §2.1.
    NxDomain,
}

impl Rcode {
    pub fn code(self) -> ResponseCode {
        match self {
            Self::NoError => ResponseCode::NoError,
            Self::NxDomain => ResponseCode::NXDomain,
        }
    }
}

/// What a good reply says, kept as records: the CNAME chain from the name
/// asked and the records of the type asked at its end (RFC 2181 §5.4.1:
/// nothing else), and for negative answers the SOA (RFC 2308 §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub rcode: Rcode,
    pub records: Vec<Record>,
    pub authority: Vec<Record>,
    /// How long it may be cached: the smallest TTL along the chain (RFC 2181
    /// §5.2); for negatives min(SOA TTL, MINIMUM) (RFC 2308 §5), `None`
    /// without SOA (RFC 2308 §5: SHOULD NOT be cached).
    pub ttl: Option<u32>,
}

impl Answer {
    /// An answer made here (static entries, special names).
    pub fn local(rcode: Rcode, records: Vec<Record>) -> Self {
        let ttl = records.iter().map(ttl_of).min();
        Self {
            rcode,
            records,
            authority: Vec::new(),
            ttl,
        }
    }

    pub fn kind(&self, rtype: RecordType) -> CacheKind {
        match self.rcode {
            Rcode::NxDomain => CacheKind::NxDomain,
            Rcode::NoError if self.records.iter().any(|r| r.record_type() == rtype) => {
                CacheKind::Records
            }
            Rcode::NoError => CacheKind::NoData,
        }
    }

    /// The A and AAAA addresses in the answer.
    pub fn addresses(&self) -> Vec<IpAddr> {
        let mut out = Vec::new();
        for r in &self.records {
            let ip = match &r.data {
                RData::A(a) => IpAddr::V4(a.0),
                RData::AAAA(a) => IpAddr::V6(a.0),
                _ => continue,
            };
            if !out.contains(&ip) {
                out.push(ip);
            }
        }
        out
    }

    /// The last name of the CNAME chain, when there was one.
    pub fn canonical(&self) -> Option<String> {
        self.records.iter().rev().find_map(|r| match &r.data {
            RData::CNAME(c) => Some(key_of(&c.0)),
            _ => None,
        })
    }

    /// The same answer with every TTL set to `ttl` (what is left of it in
    /// the cache).
    pub fn with_ttl(&self, ttl: u32) -> Self {
        let mut a = self.clone();
        for r in a.records.iter_mut().chain(a.authority.iter_mut()) {
            r.ttl = ttl;
        }
        a.ttl = Some(ttl);
        a
    }

    /// Reads a checked reply (see [`check_reply`]) to `name`/`rtype`.
    pub fn from_reply(name: &Name, rtype: RecordType, m: &Message) -> Self {
        let rcode = if m.metadata.response_code == ResponseCode::NXDomain {
            Rcode::NxDomain
        } else {
            Rcode::NoError
        };
        let mut records = Vec::new();
        let mut target = name.clone();
        let mut ttl = u32::MAX;
        let mut found = false;
        for _ in 0..=MAX_CNAME_HOPS {
            // Only records owned by the name we follow count: anything else
            // in the answer section is out of the chain (RFC 2181 §5.4.1).
            for r in m
                .answers
                .iter()
                .filter(|r| r.name == target && r.record_type() == rtype)
            {
                if !records.contains(r) {
                    records.push(r.clone());
                    ttl = ttl.min(ttl_of(r));
                    found = true;
                }
            }
            if found || rtype == RecordType::CNAME {
                break;
            }
            let next = m
                .answers
                .iter()
                .filter(|r| r.name == target)
                .find(|r| matches!(r.data, RData::CNAME(_)));
            let Some(r) = next else { break };
            let RData::CNAME(c) = &r.data else { break };
            records.push(r.clone());
            ttl = ttl.min(ttl_of(r));
            target = c.0.clone();
        }
        if found && rcode == Rcode::NoError {
            return Self {
                rcode,
                records,
                authority: Vec::new(),
                ttl: Some(ttl),
            };
        }
        // RFC 2308 §2.2: NOERROR without the records asked for is NODATA.
        let authority: Vec<Record> = m
            .authorities
            .iter()
            .filter(|r| matches!(r.data, RData::SOA(_)))
            .take(1)
            .cloned()
            .collect();
        let ttl = negative_ttl(m).map(|n| n.min(ttl));
        Self {
            rcode,
            records,
            authority,
            ttl,
        }
    }
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
pub fn ttl_of(r: &Record) -> u32 {
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

/// Checks `bytes` against the query (`id`, `name`, `rtype`): a reply to
/// it, final (NOERROR or NXDOMAIN).
pub fn check_reply(
    id: u16,
    name: &Name,
    rtype: RecordType,
    bytes: &[u8],
) -> Result<Message, ReplyError> {
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
        [one] if one.name() == name && one.query_type() == rtype);
    if !ours {
        return Err(ReplyError::Mismatch);
    }
    if md.truncation {
        return Err(ReplyError::Truncated);
    }
    match md.response_code {
        ResponseCode::NoError | ResponseCode::NXDomain => Ok(m),
        ResponseCode::ServFail => Err(ReplyError::ServFail),
        ResponseCode::Refused => Err(ReplyError::Refused),
        other => Err(ReplyError::Rcode(other.to_string())),
    }
}

/// [`check_reply`], then [`Answer::from_reply`].
pub fn parse_reply(
    id: u16,
    name: &Name,
    rtype: RecordType,
    bytes: &[u8],
) -> Result<Answer, ReplyError> {
    let m = check_reply(id, name, rtype, bytes)?;
    Ok(Answer::from_reply(name, rtype, &m))
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
        let (id, q) = query(&n, RecordType::A, 1232).unwrap();
        let bytes = reply(
            &q,
            ResponseCode::NoError,
            vec![
                a("SRI-NIC.ARPA", 86_400, [26, 0, 0, 73]),
                a("SRI-NIC.ARPA", 86_400, [10, 0, 0, 51]),
            ],
            None,
        );
        let got = parse_reply(id, &n, RecordType::A, &bytes).unwrap();
        assert_eq!(
            got.addresses(),
            vec![
                "26.0.0.73".parse::<IpAddr>().unwrap(),
                "10.0.0.51".parse().unwrap()
            ]
        );
        assert_eq!((got.canonical(), got.ttl), (None, Some(86_400)));
        assert_eq!(got.kind(RecordType::A), CacheKind::Records);
    }

    #[test]
    fn query_asks_for_recursion_with_edns() {
        let n = name("example.com");
        let (id, q) = query(&n, RecordType::AAAA, 1232).unwrap();
        let m = Message::from_vec(&q).unwrap();
        assert_eq!(m.metadata.id, id);
        assert!(m.metadata.recursion_desired);
        assert_eq!(m.queries[0].query_type(), RecordType::AAAA);
        assert_eq!(m.edns.unwrap().max_payload(), 1232);
    }

    #[test]
    fn cname_chain_is_followed_and_ttl_is_the_smallest() {
        let n = name("www.example.com");
        let (id, q) = query(&n, RecordType::A, 1232).unwrap();
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
        let got = parse_reply(id, &n, RecordType::A, &bytes).unwrap();
        assert_eq!(got.addresses(), vec![IpAddr::from([192, 0, 2, 7])]);
        assert_eq!(got.canonical().as_deref(), Some("edge.cdn.example"));
        assert_eq!(got.ttl, Some(60));
        assert_eq!(got.records.len(), 2, "the CNAME and the A, not the stray");
    }

    #[test]
    fn negative_answers_take_the_soa_ttl() {
        let n = name("nope.example");
        let (id, q) = query(&n, RecordType::A, 1232).unwrap();
        // RFC 2308 §5: min(SOA TTL, SOA MINIMUM).
        let nx = reply(&q, ResponseCode::NXDomain, vec![], Some((900, 300)));
        let got = parse_reply(id, &n, RecordType::A, &nx).unwrap();
        assert_eq!((got.rcode, got.ttl), (Rcode::NxDomain, Some(300)));
        assert_eq!(got.authority.len(), 1, "the SOA goes back to clients");
        let nodata = reply(&q, ResponseCode::NoError, vec![], Some((120, 3600)));
        let got = parse_reply(id, &n, RecordType::A, &nodata).unwrap();
        assert_eq!(got.kind(RecordType::A), CacheKind::NoData);
        assert_eq!(got.ttl, Some(120));
        let bare = reply(&q, ResponseCode::NXDomain, vec![], None);
        let got = parse_reply(id, &n, RecordType::A, &bare).unwrap();
        assert_eq!((got.rcode, got.ttl), (Rcode::NxDomain, None));
    }

    #[test]
    fn huge_ttl_counts_as_zero() {
        let n = name("x.example");
        let (id, q) = query(&n, RecordType::A, 1232).unwrap();
        let bytes = reply(
            &q,
            ResponseCode::NoError,
            vec![a("x.example", 0x8000_0001, [192, 0, 2, 1])],
            None,
        );
        let got = parse_reply(id, &n, RecordType::A, &bytes).unwrap();
        assert_eq!(got.ttl, Some(0), "RFC 2181 §8");
    }

    #[test]
    fn foreign_replies_are_mismatches() {
        let n = name("example.com");
        let (id, q) = query(&n, RecordType::A, 1232).unwrap();
        let bytes = reply(&q, ResponseCode::NoError, vec![], None);
        assert_eq!(
            parse_reply(id.wrapping_add(1), &n, RecordType::A, &bytes),
            Err(ReplyError::Mismatch)
        );
        assert_eq!(
            parse_reply(id, &name("other.com"), RecordType::A, &bytes),
            Err(ReplyError::Mismatch)
        );
        assert_eq!(
            parse_reply(id, &n, RecordType::AAAA, &bytes),
            Err(ReplyError::Mismatch)
        );
        // Our own query echoed back is not a reply.
        assert_eq!(
            parse_reply(id, &n, RecordType::A, &q),
            Err(ReplyError::Mismatch)
        );
    }

    #[test]
    fn errors_and_truncation() {
        let n = name("example.com");
        let (id, q) = query(&n, RecordType::A, 1232).unwrap();
        let sf = reply(&q, ResponseCode::ServFail, vec![], None);
        assert_eq!(
            parse_reply(id, &n, RecordType::A, &sf),
            Err(ReplyError::ServFail)
        );
        let rf = reply(&q, ResponseCode::Refused, vec![], None);
        assert_eq!(
            parse_reply(id, &n, RecordType::A, &rf),
            Err(ReplyError::Refused)
        );
        let mut tc = Message::from_vec(&reply(&q, ResponseCode::NoError, vec![], None)).unwrap();
        tc.metadata.truncation = true;
        assert_eq!(
            parse_reply(id, &n, RecordType::A, &tc.to_vec().unwrap()),
            Err(ReplyError::Truncated)
        );
        assert!(matches!(
            parse_reply(id, &n, RecordType::A, &[1, 2, 3]),
            Err(ReplyError::Malformed(_))
        ));
    }

    #[test]
    fn aaaa_answers() {
        let n = name("v6.example");
        let (id, q) = query(&n, RecordType::AAAA, 1232).unwrap();
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
        assert_eq!(
            parse_reply(id, &n, RecordType::AAAA, &bytes)
                .unwrap()
                .addresses(),
            vec![IpAddr::V6(ip)]
        );
    }

    #[test]
    fn other_types_and_cname_queries() {
        use hickory_proto::rr::rdata::{MX, TXT};
        let n = name("example.com");
        let (id, q) = query(&n, RecordType::MX, 1232).unwrap();
        let mx = Record::from_rdata(
            n.clone(),
            600,
            RData::MX(MX::new(10, name("mail.example.com"))),
        );
        let txt = Record::from_rdata(n.clone(), 600, RData::TXT(TXT::new(vec!["x".into()])));
        let bytes = reply(&q, ResponseCode::NoError, vec![mx.clone(), txt], None);
        let got = parse_reply(id, &n, RecordType::MX, &bytes).unwrap();
        assert_eq!(got.records, vec![mx], "only the type asked");
        // A CNAME query gets the CNAME itself, not its target.
        let w = name("www.example.com");
        let (id, q) = query(&w, RecordType::CNAME, 1232).unwrap();
        let bytes = reply(
            &q,
            ResponseCode::NoError,
            vec![
                cname("www.example.com", 60, "example.com"),
                a("example.com", 60, [192, 0, 2, 1]),
            ],
            None,
        );
        let got = parse_reply(id, &w, RecordType::CNAME, &bytes).unwrap();
        assert_eq!(got.records.len(), 1);
        assert_eq!(got.kind(RecordType::CNAME), CacheKind::Records);
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
            let _ = parse_reply(0x1234, &n, RecordType::A, &bytes);
        }

        /// A real reply with its first bytes kept and the rest scrambled.
        #[test]
        fn damaged_replies_are_safe(cut in 0usize..200, noise in proptest::collection::vec(proptest::num::u8::ANY, 0..64)) {
            let n = name("www.example.com");
            let (id, q) = query(&n, RecordType::A, 1232).unwrap();
            let mut bytes = reply(&q, ResponseCode::NoError,
                vec![cname("www.example.com", 300, "e.example"), a("e.example", 60, [192, 0, 2, 7])], Some((60, 60)));
            bytes.truncate(cut.min(bytes.len()));
            bytes.extend(noise);
            let _ = parse_reply(id, &n, RecordType::A, &bytes);
        }
    }
}
