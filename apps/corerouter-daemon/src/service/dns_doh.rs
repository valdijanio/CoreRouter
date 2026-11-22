//! DNS over HTTPS (G4.1zf, RFC 8484): what a request means and what its
//! answer carries, for HTTP/2 (`http2::server`) and HTTP/1.1 (here). Not a
//! service: `dns_tls` serves both on the DoH port.
//!
//! - §4.1: GET with the `dns` variable (base64url, RFC 4648 §5, padding
//!   left out, §6) and POST with the body, `application/dns-message`; both
//!   MUST be supported. Another path: 404; another method: 405; another
//!   media type: 415; a body over 64 KiB: 413; a missing or broken `dns`:
//!   400 (RFC 9110 semantics; Knot Resolver and dnsdist answer the same).
//! - §4.2.1: every DNS answer, SERVFAIL and NXDOMAIN included, is a 200.
//! - §5.1: `cache-control: max-age` is at most the smallest TTL of the
//!   answer section, or the SOA's for a negative answer (RFC 2308); 0 when
//!   there is neither.
//! - §6: the message has no length prefix; the EDNS UDP size is ignored
//!   (the chain answers as for TCP: no truncation).

use hickory_proto::op::Message;
use hickory_proto::rr::RData;

/// RFC 8484 §6: the media type.
pub(crate) const MEDIA_TYPE: &str = "application/dns-message";
/// One request head at most (HTTP/1.1).
const MAX_HEAD: usize = 8 * 1024;
const MAX_HEADERS: usize = 32;
/// A DNS message at most (RFC 8484 §6).
pub(crate) const MAX_MESSAGE: usize = 65_535;

/// What a request asks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Doh {
    Query(Vec<u8>),
    /// An HTTP error: status and a short text body.
    Reject(u16, &'static str),
}

/// RFC 4648 §5 base64url, padding optional (§6 says clients leave it out).
pub(crate) fn base64url(text: &str) -> Option<Vec<u8>> {
    let t = text.trim_end_matches('=');
    let mut out = Vec::with_capacity(t.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in t.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
        }
    }
    Some(out)
}

/// What `method` `path` with this body asks of the server at `doh_path`.
pub(crate) fn parse(method: &str, path: &str, content_type: Option<&str>, body: &[u8], too_big: bool, doh_path: &str) -> Doh {
    let (p, query) = path.split_once('?').unwrap_or((path, ""));
    if p != doh_path {
        return Doh::Reject(404, "not found");
    }
    match method {
        "GET" => {
            let Some(v) = query.split('&').find_map(|kv| kv.strip_prefix("dns=")) else {
                return Doh::Reject(400, "no dns= parameter");
            };
            if v.len() > MAX_MESSAGE * 4 / 3 + 4 {
                return Doh::Reject(414, "dns= too long");
            }
            match base64url(v) {
                Some(m) if !m.is_empty() => Doh::Query(m),
                _ => Doh::Reject(400, "dns= is not base64url"),
            }
        }
        "POST" => {
            let media = content_type.and_then(|c| c.split(';').next()).map(|c| c.trim().to_ascii_lowercase());
            if media.as_deref() != Some(MEDIA_TYPE) {
                return Doh::Reject(415, "the body must be application/dns-message");
            }
            if too_big || body.len() > MAX_MESSAGE {
                return Doh::Reject(413, "a DNS message is at most 65535 bytes");
            }
            if body.is_empty() {
                return Doh::Reject(400, "empty body");
            }
            Doh::Query(body.to_vec())
        }
        _ => Doh::Reject(405, "GET or POST"),
    }
}

/// RFC 8484 §5.1: how long an HTTP cache may keep `reply`.
pub(crate) fn max_age(reply: &[u8]) -> u32 {
    let Ok(m) = Message::from_vec(reply) else {
        return 0;
    };
    if let Some(ttl) = m.answers.iter().map(|r| r.ttl).min() {
        return ttl;
    }
    // A negative answer: the SOA's TTL, at most its MINIMUM (RFC 2308 §5).
    m.authorities
        .iter()
        .find_map(|r| match &r.data {
            RData::SOA(soa) => Some(r.ttl.min(soa.minimum)),
            _ => None,
        })
        .unwrap_or(0)
}

/// The headers of a DNS answer (besides `:status` and the length).
pub(crate) fn answer_headers(reply: &[u8]) -> [(&'static str, String); 2] {
    [("content-type", MEDIA_TYPE.to_owned()), ("cache-control", format!("max-age={}", max_age(reply)))]
}

/// One HTTP/1.1 request, whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct H1 {
    pub method: String,
    pub path: String,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
    pub too_big: bool,
    /// `Connection: close` (or HTTP/1.0): close after the answer.
    pub close: bool,
}

/// The first whole request in `buf` and how many bytes it took;
/// `Ok(None)`: not whole yet; `Err(status)`: answer that and close.
pub(crate) fn h1_request(buf: &[u8]) -> Result<Option<(H1, usize)>, u16> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    let head = match req.parse(buf) {
        Ok(httparse::Status::Complete(n)) => n,
        Ok(httparse::Status::Partial) => {
            return if buf.len() > MAX_HEAD { Err(431) } else { Ok(None) };
        }
        Err(httparse::Error::TooManyHeaders) => return Err(431),
        Err(_) => return Err(400),
    };
    if head > MAX_HEAD {
        return Err(431);
    }
    let header = |name: &str| {
        req.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .and_then(|h| std::str::from_utf8(h.value).ok())
            .map(str::trim)
    };
    if header("transfer-encoding").is_some() {
        // A DNS message has a known length: no chunked bodies.
        return Err(411);
    }
    let len = match header("content-length") {
        Some(v) => v.parse::<usize>().map_err(|_| 400u16)?,
        None => 0,
    };
    let too_big = len > MAX_MESSAGE;
    if too_big {
        return Err(413);
    }
    let Some(body) = buf.get(head..head + len) else {
        return Ok(None);
    };
    let close = req.version == Some(0) || header("connection").is_some_and(|c| c.eq_ignore_ascii_case("close"));
    Ok(Some((
        H1 {
            method: req.method.unwrap_or("").to_owned(),
            path: req.path.unwrap_or("").to_owned(),
            content_type: header("content-type").map(str::to_owned),
            body: body.to_vec(),
            too_big,
            close,
        },
        head + len,
    )))
}

/// An HTTP/1.1 answer.
pub(crate) fn h1_response(status: u16, headers: &[(&str, &str)], body: &[u8], close: bool) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        411 => "Length Required",
        413 => "Content Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        431 => "Request Header Fields Too Large",
        _ => "Error",
    };
    let mut out = format!("HTTP/1.1 {status} {reason}\r\n");
    for (k, v) in headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    if status == 405 {
        out.push_str("allow: GET, POST\r\n");
    }
    out.push_str(&format!("content-length: {}\r\n", body.len()));
    if close {
        out.push_str("connection: close\r\n");
    }
    out.push_str("\r\n");
    let mut b = out.into_bytes();
    b.extend_from_slice(body);
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, Query, ResponseCode};
    use hickory_proto::rr::rdata::{A, SOA};
    use hickory_proto::rr::{Name, RData, Record, RecordType};

    #[test]
    fn rfc_8484_example_get_decodes() {
        // RFC 8484 §4.1.1: www.example.com A, id 0, as base64url.
        let q = "AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB";
        let Doh::Query(m) = parse("GET", &format!("/dns-query?dns={q}"), None, &[], false, "/dns-query") else {
            panic!()
        };
        let m = Message::from_vec(&m).unwrap();
        assert_eq!(m.metadata.id, 0);
        assert_eq!(m.queries[0].name().to_string(), "www.example.com.");
    }

    #[test]
    fn wrong_requests_get_their_http_status() {
        let p = |m: &str, path: &str, ct: Option<&str>, body: &[u8]| parse(m, path, ct, body, false, "/dns-query");
        assert_eq!(p("GET", "/other?dns=AAAA", None, &[]), Doh::Reject(404, "not found"));
        assert_eq!(p("GET", "/dns-query", None, &[]).clone(), Doh::Reject(400, "no dns= parameter"));
        assert_eq!(p("GET", "/dns-query?dns=@@", None, &[]), Doh::Reject(400, "dns= is not base64url"));
        assert!(matches!(p("PUT", "/dns-query", None, &[]), Doh::Reject(405, _)));
        assert!(matches!(p("POST", "/dns-query", Some("text/plain"), b"x"), Doh::Reject(415, _)));
        assert!(matches!(p("POST", "/dns-query", Some("application/dns-message; x=1"), b"x"), Doh::Query(_)));
        assert!(matches!(parse("POST", "/dns-query", Some(MEDIA_TYPE), &[], true, "/dns-query"), Doh::Reject(413, _)));
        assert_eq!(base64url("AAEC"), Some(vec![0, 1, 2]));
        assert_eq!(base64url("-_8"), Some(vec![0xfb, 0xff]));
    }

    #[test]
    fn max_age_is_the_smallest_ttl_or_the_soa_minimum() {
        let mut m = Message::response(1, hickory_proto::op::OpCode::Query);
        m.add_query(Query::query(Name::from_ascii("a.lan.").unwrap(), RecordType::A));
        for ttl in [300, 60] {
            m.add_answer(Record::from_rdata(Name::from_ascii("a.lan.").unwrap(), ttl, RData::A(A([10, 0, 0, 1].into()))));
        }
        assert_eq!(max_age(&m.to_vec().unwrap()), 60);
        let mut n = Message::response(2, hickory_proto::op::OpCode::Query);
        n.metadata.response_code = ResponseCode::NXDomain;
        let soa = SOA::new(Name::root(), Name::root(), 1, 2, 3, 4, 30);
        n.add_authority(Record::from_rdata(Name::from_ascii("lan.").unwrap(), 900, RData::SOA(soa)));
        assert_eq!(max_age(&n.to_vec().unwrap()), 30);
        assert_eq!(max_age(b"junk"), 0);
    }

    #[test]
    fn http1_requests_are_framed_and_bounded() {
        let req = b"POST /dns-query HTTP/1.1\r\nHost: r\r\nContent-Type: application/dns-message\r\nContent-Length: 3\r\n\r\nabcGET";
        let (r, n) = h1_request(req).unwrap().unwrap();
        assert_eq!((r.method.as_str(), r.body.as_slice(), r.close), ("POST", &b"abc"[..], false));
        assert_eq!(&req[n..], b"GET");
        assert_eq!(h1_request(b"GET /dns-query?dns=AA HTTP/1.1\r\nHo").unwrap(), None, "not whole yet");
        assert_eq!(h1_request(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n").unwrap_err(), 411);
        assert_eq!(h1_request(b"POST / HTTP/1.1\r\nContent-Length: 70000\r\n\r\n").unwrap_err(), 413);
        assert_eq!(h1_request(&vec![b'a'; 9000]).unwrap_err(), 431, "a head that never ends");
        assert_eq!(h1_request(b"\x00\x01 junk\r\n\r\n").unwrap_err(), 400);
        let (r, _) = h1_request(b"GET /x HTTP/1.0\r\n\r\n").unwrap().unwrap();
        assert!(r.close);
        let out = String::from_utf8(h1_response(405, &[], b"no", true)).unwrap();
        assert!(out.starts_with("HTTP/1.1 405") && out.contains("allow: GET, POST") && out.ends_with("\r\n\r\nno"));
    }

    proptest::proptest! {
        /// Hostile input never panics the parsers.
        #[test]
        fn any_bytes_are_an_answer_not_a_panic(b in proptest::collection::vec(proptest::num::u8::ANY, 0..2000), s in ".{0,200}") {
            let _ = h1_request(&b);
            let _ = base64url(&s);
            let _ = max_age(&b);
            let _ = parse("GET", &s, None, &b, false, "/dns-query");
        }
    }
}
