//! G6.6 DNS Lookup (Tools, `tool.dns.query`): the codec of a `dig`. One
//! query built with the operator's flags (RD, DO), its reply read whole
//! (every section, flags, EDNS) into rows a table or JSON can show, the
//! reply printed as the text `dig` prints ("Copy as dig"), and the
//! referrals a `+trace` walks from the root down.
//!
//! No sockets: the daemon carries the bytes. Everything read from a reply
//! is hostile text: names and data are bounded and kept to printable ASCII
//! (RFC 1035 §5.1 escapes for the rest), so no terminal escape gets
//! through to the terminal or a ticket.

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr};

use hickory_proto::op::{Edns, Message, MessageType, Query};
use hickory_proto::rr::{DNSClass, RData, Record};
/// The name and type of an [`Ask`] (callers need no `hickory-proto`).
pub use hickory_proto::rr::{Name, RecordType};

/// The record types the tool offers; others are refused (no AXFR/IXFR:
/// zone transfers are not lookups).
pub const TYPES: [&str; 17] = [
    "A", "AAAA", "ANY", "CAA", "CNAME", "DNSKEY", "DS", "HTTPS", "MX", "NS", "PTR", "SOA", "SRV",
    "SSHFP", "SVCB", "TLSA", "TXT",
];

/// Rows read per section at most: a reply holds a few dozen at best; a
/// bigger one is clipped, never a reason to grow without bound.
pub const MAX_ROWS: usize = 64;
/// Longest data shown for one record (a DNSKEY is ~400 characters).
pub const MAX_DATA: usize = 1024;
/// EDNS(0) payload advertised: the 2020 DNS flag day value, as `dig`
/// and `kdig` use (no fragmentation on common paths).
pub const UDP_PAYLOAD: u16 = 1232;

/// IANA root hints (named.root): the thirteen root servers' IPv4
/// addresses, where `+trace` starts.
pub const ROOT_SERVERS: [(&str, Ipv4Addr); 13] = [
    ("a.root-servers.net.", Ipv4Addr::new(198, 41, 0, 4)),
    ("b.root-servers.net.", Ipv4Addr::new(170, 247, 170, 2)),
    ("c.root-servers.net.", Ipv4Addr::new(192, 33, 4, 12)),
    ("d.root-servers.net.", Ipv4Addr::new(199, 7, 91, 13)),
    ("e.root-servers.net.", Ipv4Addr::new(192, 203, 230, 10)),
    ("f.root-servers.net.", Ipv4Addr::new(192, 5, 5, 241)),
    ("g.root-servers.net.", Ipv4Addr::new(192, 112, 36, 4)),
    ("h.root-servers.net.", Ipv4Addr::new(198, 97, 190, 53)),
    ("i.root-servers.net.", Ipv4Addr::new(192, 36, 148, 17)),
    ("j.root-servers.net.", Ipv4Addr::new(192, 58, 128, 30)),
    ("k.root-servers.net.", Ipv4Addr::new(193, 0, 14, 129)),
    ("l.root-servers.net.", Ipv4Addr::new(199, 7, 83, 42)),
    ("m.root-servers.net.", Ipv4Addr::new(202, 12, 27, 33)),
];

/// What the operator asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ask {
    pub name: Name,
    pub rtype: RecordType,
    /// RD (RFC 1035 §4.1.1); `dig +norecurse` clears it.
    pub recursion: bool,
    /// DO (RFC 3225 §3): the server should send the RRSIGs.
    pub dnssec: bool,
}

/// The query's bytes: a random id (RFC 5452 §9.2), or `id` (DoH asks for
/// 0, RFC 8484 §4.1), and EDNS(0) (RFC 6891) with [`UDP_PAYLOAD`].
pub fn query(ask: &Ask, id: Option<u16>) -> Result<(u16, Vec<u8>), String> {
    let mut m = Message::query();
    if let Some(id) = id {
        m.metadata.id = id;
    }
    m.metadata.recursion_desired = ask.recursion;
    m.add_query(Query::query(ask.name.clone(), ask.rtype));
    let mut edns = Edns::new();
    edns.set_max_payload(UDP_PAYLOAD);
    edns.set_dnssec_ok(ask.dnssec);
    m.set_edns(edns);
    let id = m.metadata.id;
    m.to_vec().map(|b| (id, b)).map_err(|e| e.to_string())
}

/// Whether `bytes` is a reply to query `id`: the transport skips anything
/// else (late or forged datagrams, RFC 5452 §9.1).
pub fn is_reply_to(id: u16, bytes: &[u8]) -> bool {
    bytes.len() >= 12
        && bytes.get(..2) == Some(&id.to_be_bytes()[..])
        && bytes.get(2).is_some_and(|b| b & 0x80 != 0)
}

/// Whether the reply came truncated (TC: ask again over TCP, RFC 7766 §5).
pub fn truncated(bytes: &[u8]) -> bool {
    bytes.get(2).is_some_and(|b| b & 0x02 != 0)
}

/// One record, as a table row and a `dig` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// Owner name with the final dot (`example.com.`).
    pub name: String,
    pub ttl: u32,
    pub class: String,
    pub rtype: String,
    /// Presentation format (RFC 1035 §5.1), as `dig` prints it.
    pub data: String,
}

/// The OPT pseudo-record (RFC 6891 §6.1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Opt {
    pub version: u8,
    pub dnssec_ok: bool,
    pub udp: u16,
}

/// A reply, read whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub id: u16,
    pub opcode: String,
    /// `NOERROR`, `NXDOMAIN`, `SERVFAIL`… (the names `dig` prints).
    pub status: String,
    /// In `dig` order: qr aa tc rd ra ad cd.
    pub flags: Vec<&'static str>,
    /// Name and type of the question (none in some error replies).
    pub question: Option<(String, String)>,
    pub answer: Vec<Row>,
    pub authority: Vec<Row>,
    pub additional: Vec<Row>,
    pub edns: Option<Opt>,
    /// Bytes received.
    pub size: usize,
}

/// RFC 1035 §4.1.1 and RFC 6895 §2.3, extended RCODE included (RFC 6891
/// §6.1.3), as `dig` names them.
pub fn rcode_name(code: u16) -> String {
    match code {
        0 => "NOERROR".into(),
        1 => "FORMERR".into(),
        2 => "SERVFAIL".into(),
        3 => "NXDOMAIN".into(),
        4 => "NOTIMP".into(),
        5 => "REFUSED".into(),
        6 => "YXDOMAIN".into(),
        7 => "YXRRSET".into(),
        8 => "NXRRSET".into(),
        9 => "NOTAUTH".into(),
        10 => "NOTZONE".into(),
        16 => "BADVERS".into(),
        23 => "BADCOOKIE".into(),
        n => format!("RCODE{n}"),
    }
}

/// Reads a reply. Refuses what is not a reply (a query sent to us is not
/// an answer) and anything `hickory-proto` cannot decode.
pub fn decode(bytes: &[u8]) -> Result<Reply, String> {
    let m = Message::from_vec(bytes).map_err(|e| {
        let mut s = format!("malformed reply: {e}");
        s.truncate(160);
        s
    })?;
    let md = &m.metadata;
    if md.message_type != MessageType::Response {
        return Err("not a reply (QR clear)".into());
    }
    let mut flags = vec!["qr"];
    for (on, name) in [
        (md.authoritative, "aa"),
        (md.truncation, "tc"),
        (md.recursion_desired, "rd"),
        (md.recursion_available, "ra"),
        (md.authentic_data, "ad"),
        (md.checking_disabled, "cd"),
    ] {
        if on {
            flags.push(name);
        }
    }
    let rows =
        |records: &[Record]| -> Vec<Row> { records.iter().take(MAX_ROWS).map(row).collect() };
    Ok(Reply {
        id: md.id,
        opcode: clean(&md.op_code.to_string(), 16).to_ascii_uppercase(),
        status: rcode_name(u16::from(md.response_code)),
        flags,
        question: m
            .queries
            .first()
            .map(|q| (name_text(q.name()), q.query_type().to_string())),
        answer: rows(&m.answers),
        authority: rows(&m.authorities),
        additional: rows(&m.additionals),
        edns: m.edns.as_ref().map(|e| Opt {
            version: e.version(),
            dnssec_ok: e.flags().dnssec_ok,
            udp: e.max_payload(),
        }),
        size: bytes.len(),
    })
}

/// A name with its final dot, escaped and bounded.
fn name_text(n: &Name) -> String {
    let mut s = n.to_string();
    if !s.ends_with('.') {
        s.push('.');
    }
    clean(&s, crate::message::MAX_NAME_LEN + 8)
}

fn row(r: &Record) -> Row {
    let class = match r.dns_class {
        DNSClass::IN => "IN".to_owned(),
        c => clean(&c.to_string(), 16),
    };
    Row {
        name: name_text(&r.name),
        ttl: r.ttl,
        class,
        rtype: clean(&r.record_type().to_string(), 16),
        data: data_text(&r.data),
    }
}

/// RFC 1035 §5.1 presentation format of `data`, as `dig` prints it.
fn data_text(data: &RData) -> String {
    let text = match data {
        // Each string quoted, `"` and `\` escaped (`dig` style).
        RData::TXT(t) => t
            .txt_data
            .iter()
            .map(|s| quoted(s))
            .collect::<Vec<_>>()
            .join(" "),
        // The DNSSEC types in their RFC 4034 presentation format; anything
        // else (or a malformed one) in the generic form of RFC 3597 §5.
        RData::Unknown { code, rdata } => {
            let bytes = &rdata.anything;
            let known = match *code {
                RecordType::RRSIG => rrsig_text(bytes),
                RecordType::DS => ds_text(bytes),
                RecordType::DNSKEY => dnskey_text(bytes),
                _ => None,
            };
            known.unwrap_or_else(|| {
                let mut s = format!("\\# {}", bytes.len());
                if !bytes.is_empty() {
                    s.push(' ');
                    for b in bytes.iter().take(MAX_DATA / 2) {
                        let _ = write!(s, "{b:02X}");
                    }
                }
                s
            })
        }
        RData::OPT(_) => String::new(),
        other => other.to_string(),
    };
    clean(&text, MAX_DATA)
}

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

fn u32_at(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *b.get(i)?,
        *b.get(i + 1)?,
        *b.get(i + 2)?,
        *b.get(i + 3)?,
    ]))
}

/// Standard base64 (RFC 4648 §4), as keys and signatures are written.
fn base64(bytes: &[u8]) -> String {
    const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                let idx = usize::try_from((n >> shift) & 63).unwrap_or(0);
                out.push(char::from(ABC.get(idx).copied().unwrap_or(b'A')));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// An uncompressed wire name at `b[i..]` (RFC 4034 §3.1.7: the signer's
/// name is never compressed) and where it ends.
fn wire_name(b: &[u8], mut i: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    loop {
        let len = usize::from(*b.get(i)?);
        i += 1;
        if len == 0 {
            break;
        }
        if len > 63 || out.len() > crate::message::MAX_NAME_LEN {
            return None;
        }
        for &c in b.get(i..i + len)? {
            match c {
                b'.' | b'\\' => {
                    out.push('\\');
                    out.push(char::from(c));
                }
                0x21..=0x7e => out.push(char::from(c)),
                _ => {
                    let _ = write!(out, "\\{c:03}");
                }
            }
        }
        out.push('.');
        i += len;
    }
    if out.is_empty() {
        out.push('.');
    }
    Some((out, i))
}

/// RFC 4034 §3.2: a signature time as YYYYMMDDHHmmSS (UTC; serial
/// arithmetic past 2106 is beyond this tool).
fn sig_time(t: u32) -> String {
    let secs = i64::from(t);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil date from days since 1970-01-01 (H. Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}{m:02}{d:02}{:02}{:02}{:02}",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// RFC 4034 §3.2: `A 13 2 300 20261029000000 20261022000000 34505 example.com. <sig>`.
fn rrsig_text(b: &[u8]) -> Option<String> {
    let covered = RecordType::from(u16_at(b, 0)?);
    let (signer, at) = wire_name(b, 18)?;
    Some(format!(
        "{covered} {} {} {} {} {} {} {signer} {}",
        b.get(2)?,
        b.get(3)?,
        u32_at(b, 4)?,
        sig_time(u32_at(b, 8)?),
        sig_time(u32_at(b, 12)?),
        u16_at(b, 16)?,
        base64(b.get(at..)?)
    ))
}

/// RFC 4034 §5.3: `2371 13 2 <digest hex>`.
fn ds_text(b: &[u8]) -> Option<String> {
    let mut s = format!("{} {} {} ", u16_at(b, 0)?, b.get(2)?, b.get(3)?);
    for x in b.get(4..)? {
        let _ = write!(s, "{x:02X}");
    }
    Some(s)
}

/// RFC 4034 §2.2: `257 3 13 <key base64>`.
fn dnskey_text(b: &[u8]) -> Option<String> {
    Some(format!(
        "{} {} {} {}",
        u16_at(b, 0)?,
        b.get(2)?,
        b.get(3)?,
        base64(b.get(4..)?)
    ))
}

/// A character-string in quotes (RFC 1035 §5.1): `"` and `\` escaped,
/// bytes outside printable ASCII as `\DDD`.
fn quoted(bytes: &[u8]) -> String {
    let mut s = String::from("\"");
    for &b in bytes.iter().take(MAX_DATA) {
        match b {
            b'"' | b'\\' => {
                s.push('\\');
                s.push(char::from(b));
            }
            0x20..=0x7e => s.push(char::from(b)),
            _ => {
                let _ = write!(s, "\\{b:03}");
            }
        }
    }
    s.push('"');
    s
}

/// At most `max` characters, printable ASCII only: anything else becomes
/// `\DDD` (per byte), so a reply cannot carry control characters.
pub fn clean(text: &str, max: usize) -> String {
    let mut out = String::new();
    for c in text.chars() {
        if out.len() >= max {
            out.push_str("...");
            break;
        }
        if c == ' ' || c.is_ascii_graphic() {
            out.push(c);
        } else {
            let mut buf = [0u8; 4];
            for b in c.encode_utf8(&mut buf).bytes() {
                let _ = write!(out, "\\{b:03}");
            }
        }
    }
    out
}

/// How a reply got here, for the trailer of the `dig` text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    /// What `dig` would be called with (`@1.1.1.1 example.com MX +dnssec`).
    pub command: String,
    /// `1.1.1.1#53(1.1.1.1)`, `https://dns.google/dns-query(8.8.8.8)`.
    pub server: String,
    /// `UDP`, `TCP`, `HTTPS`, `TLS`.
    pub transport: String,
    pub ms: u64,
    /// The router's own chain: which stage answered (`;; STAGE:` line, ours).
    pub stage: Option<String>,
}

/// The arguments of the `dig` command line for this lookup.
pub fn command(server: Option<&str>, name: &str, rtype: &str, ask: &Ask, tcp: bool) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(s) = server {
        parts.push(format!("@{s}"));
    }
    parts.push(clean(name, crate::message::MAX_NAME_LEN + 8));
    parts.push(rtype.to_owned());
    if !ask.recursion {
        parts.push("+norecurse".into());
    }
    if ask.dnssec {
        parts.push("+dnssec".into());
    }
    if tcp {
        parts.push("+tcp".into());
    }
    parts.join(" ")
}

/// Column where each field of a record line starts (BIND's master-file
/// style that `dig` prints: TTL at 24, class at 32, type at 40, data at 48).
const COLUMNS: [usize; 3] = [24, 32, 40];

/// Tabs from `col` up to `to` (at least one), as `dig` lines up columns.
fn tab_to(out: &mut String, mut col: usize, to: usize) -> usize {
    loop {
        out.push('\t');
        col = (col / 8 + 1) * 8;
        if col >= to {
            return col;
        }
    }
}

/// `name TTL IN TYPE data`, columns as `dig`.
pub fn record_line(r: &Row) -> String {
    let mut out = r.name.clone();
    let mut col = tab_to(&mut out, r.name.len(), COLUMNS[0]);
    let ttl = r.ttl.to_string();
    out.push_str(&ttl);
    col = tab_to(&mut out, col + ttl.len(), COLUMNS[1]);
    out.push_str(&r.class);
    col = tab_to(&mut out, col + r.class.len(), COLUMNS[2]);
    out.push_str(&r.rtype);
    tab_to(&mut out, col + r.rtype.len(), COLUMNS[2] + 8);
    out.push_str(&r.data);
    out
}

/// The reply as `dig` prints it (ISC BIND 9 `dig`, default options):
/// header, flags and counts, OPT pseudo-section, the sections that have
/// records, and the statistics trailer.
pub fn dig_text(r: &Reply, meta: &Meta) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "; <<>> CoreRouter DNS Lookup <<>> {}", meta.command);
    out.push_str(";; global options: +cmd\n;; Got answer:\n");
    let _ = writeln!(
        out,
        ";; ->>HEADER<<- opcode: {}, status: {}, id: {}",
        r.opcode, r.status, r.id
    );
    // dig counts the OPT record in ADDITIONAL.
    let _ = writeln!(
        out,
        ";; flags: {}; QUERY: {}, ANSWER: {}, AUTHORITY: {}, ADDITIONAL: {}",
        r.flags.join(" "),
        usize::from(r.question.is_some()),
        r.answer.len(),
        r.authority.len(),
        r.additional.len() + usize::from(r.edns.is_some())
    );
    if let Some(e) = r.edns {
        let _ = write!(
            out,
            "\n;; OPT PSEUDOSECTION:\n; EDNS: version: {}, flags:{}; udp: {}\n",
            e.version,
            if e.dnssec_ok { " do" } else { "" },
            e.udp
        );
    }
    if let Some((name, rtype)) = &r.question {
        out.push_str(";; QUESTION SECTION:\n");
        let q = format!(";{name}");
        let mut line = q.clone();
        let col = tab_to(&mut line, q.len(), COLUMNS[1]);
        line.push_str("IN");
        tab_to(&mut line, col + 2, COLUMNS[2]);
        line.push_str(rtype);
        out.push_str(&line);
        out.push('\n');
    }
    for (title, rows) in [
        ("ANSWER", &r.answer),
        ("AUTHORITY", &r.authority),
        ("ADDITIONAL", &r.additional),
    ] {
        if rows.is_empty() {
            continue;
        }
        let _ = writeln!(out, "\n;; {title} SECTION:");
        for row in rows {
            out.push_str(&record_line(row));
            out.push('\n');
        }
    }
    let _ = write!(
        out,
        "\n;; Query time: {} msec\n;; SERVER: {} ({})\n",
        meta.ms, meta.server, meta.transport
    );
    if let Some(stage) = &meta.stage {
        let _ = writeln!(out, ";; STAGE: {stage}");
    }
    let _ = writeln!(out, ";; MSG SIZE  rcvd: {}", r.size);
    out
}

/// A delegation (RFC 1034 §4.3.2 step 3b): the reply names the servers of
/// a zone closer to the name instead of answering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Referral {
    /// The child zone (`com.`).
    pub zone: String,
    /// Its servers' names, lowercase.
    pub servers: Vec<String>,
    /// Addresses of those servers given in the additional section (glue).
    pub glue: Vec<(String, IpAddr)>,
    /// A DS for the child came with it (RFC 4035 §3.1.4): the delegation is
    /// signed. Whether the signature holds is validation (G4.1f).
    pub signed: bool,
}

/// The referral in `r`, if it is one: no answer, NS records in authority.
pub fn referral(r: &Reply) -> Option<Referral> {
    if r.status != "NOERROR" || !r.answer.is_empty() {
        return None;
    }
    let ns: Vec<&Row> = r.authority.iter().filter(|x| x.rtype == "NS").collect();
    let zone = ns.first()?.name.to_ascii_lowercase();
    let servers: Vec<String> = ns
        .iter()
        .filter(|x| x.name.eq_ignore_ascii_case(&zone))
        .map(|x| x.data.to_ascii_lowercase())
        .collect();
    let glue = r
        .additional
        .iter()
        .filter(|x| x.rtype == "A" || x.rtype == "AAAA")
        .filter(|x| servers.contains(&x.name.to_ascii_lowercase()))
        .filter_map(|x| Some((x.name.to_ascii_lowercase(), x.data.parse().ok()?)))
        .collect();
    let signed = r
        .authority
        .iter()
        .any(|x| x.rtype == "DS" && x.name.eq_ignore_ascii_case(&zone));
    Some(Referral {
        zone,
        servers,
        glue,
        signed,
    })
}

/// Whether `child` is strictly below `parent` (both with the final dot):
/// a referral must come closer to the name, or the walk loops.
pub fn is_below(child: &str, parent: &str) -> bool {
    let c = child.to_ascii_lowercase();
    let p = parent.to_ascii_lowercase();
    c != p && (p == "." || c.ends_with(&format!(".{p}")))
}

/// Whether the answer came signed: an RRSIG among the answers (DO set).
pub fn signed_answer(r: &Reply) -> bool {
    r.answer.iter().any(|x| x.rtype == "RRSIG")
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, OpCode, ResponseCode};
    use hickory_proto::rr::rdata::{A, CAA, MX, NS, SOA, TXT};
    use proptest::prelude::*;

    fn n(s: &str) -> Name {
        Name::from_ascii(s).unwrap()
    }

    fn ask(name: &str, rtype: RecordType) -> Ask {
        Ask {
            name: n(name),
            rtype,
            recursion: true,
            dnssec: false,
        }
    }

    fn reply_to(q: &[u8]) -> Message {
        let q = Message::from_vec(q).unwrap();
        let mut m = Message::response(q.metadata.id, OpCode::Query);
        m.metadata.recursion_desired = q.metadata.recursion_desired;
        m.metadata.recursion_available = true;
        m.add_queries(q.queries.clone());
        let mut e = Edns::new();
        e.set_max_payload(1232);
        m.set_edns(e);
        m
    }

    #[test]
    fn query_carries_the_flags() {
        let mut a = ask("example.com.", RecordType::MX);
        a.recursion = false;
        a.dnssec = true;
        let (id, bytes) = query(&a, None).unwrap();
        let m = Message::from_vec(&bytes).unwrap();
        assert_eq!(m.metadata.id, id);
        assert!(!m.metadata.recursion_desired);
        let e = m.edns.unwrap();
        assert!(e.flags().dnssec_ok);
        assert_eq!(e.max_payload(), UDP_PAYLOAD);
        assert_eq!(m.queries[0].query_type(), RecordType::MX);
        // DoH: id 0 (RFC 8484 §4.1).
        assert_eq!(query(&a, Some(0)).unwrap().0, 0);
        assert!(!is_reply_to(id, &bytes), "a query is not a reply");
    }

    #[test]
    fn reply_reads_whole_and_prints_like_dig() {
        let (id, q) = query(&ask("example.com.", RecordType::A), None).unwrap();
        let mut m = reply_to(&q);
        m.add_answer(Record::from_rdata(
            n("example.com."),
            3600,
            RData::A(A::new(93, 184, 216, 34)),
        ));
        m.add_authority(Record::from_rdata(
            n("example.com."),
            86400,
            RData::NS(NS(n("a.iana-servers.net."))),
        ));
        m.add_additional(Record::from_rdata(
            n("a.iana-servers.net."),
            60,
            RData::A(A::new(199, 43, 135, 53)),
        ));
        let bytes = m.to_vec().unwrap();
        assert!(is_reply_to(id, &bytes) && !truncated(&bytes));
        let r = decode(&bytes).unwrap();
        assert_eq!(r.status, "NOERROR");
        assert_eq!(r.flags, ["qr", "rd", "ra"]);
        assert_eq!(r.question, Some(("example.com.".into(), "A".into())));
        assert_eq!(r.answer[0].data, "93.184.216.34");
        assert_eq!(
            r.edns,
            Some(Opt {
                version: 0,
                dnssec_ok: false,
                udp: 1232
            })
        );
        let meta = Meta {
            command: command(
                Some("1.1.1.1"),
                "example.com",
                "A",
                &ask("example.com.", RecordType::A),
                false,
            ),
            server: "1.1.1.1#53(1.1.1.1)".into(),
            transport: "UDP".into(),
            ms: 12,
            stage: None,
        };
        let text = dig_text(&r, &meta);
        let expected = format!(
            "; <<>> CoreRouter DNS Lookup <<>> @1.1.1.1 example.com A\n\
             ;; global options: +cmd\n\
             ;; Got answer:\n\
             ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: {id}\n\
             ;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 2\n\
             \n\
             ;; OPT PSEUDOSECTION:\n\
             ; EDNS: version: 0, flags:; udp: 1232\n\
             ;; QUESTION SECTION:\n\
             ;example.com.\t\t\tIN\tA\n\
             \n\
             ;; ANSWER SECTION:\n\
             example.com.\t\t3600\tIN\tA\t93.184.216.34\n\
             \n\
             ;; AUTHORITY SECTION:\n\
             example.com.\t\t86400\tIN\tNS\ta.iana-servers.net.\n\
             \n\
             ;; ADDITIONAL SECTION:\n\
             a.iana-servers.net.\t60\tIN\tA\t199.43.135.53\n\
             \n\
             ;; Query time: 12 msec\n\
             ;; SERVER: 1.1.1.1#53(1.1.1.1) (UDP)\n\
             ;; MSG SIZE  rcvd: {}\n",
            bytes.len()
        );
        assert_eq!(text, expected);
    }

    #[test]
    fn data_in_presentation_format() {
        let (_, q) = query(&ask("example.com.", RecordType::ANY), None).unwrap();
        let mut m = reply_to(&q);
        m.metadata.response_code = ResponseCode::NXDomain;
        m.metadata.authoritative = true;
        let owner = n("example.com.");
        m.add_answer(Record::from_rdata(
            owner.clone(),
            60,
            RData::MX(MX::new(10, n("mail.example.com."))),
        ));
        m.add_answer(Record::from_rdata(
            owner.clone(),
            60,
            RData::TXT(TXT::from_bytes(vec![b"v=spf1 -all", b"say \"hi\"\x1b[31m"])),
        ));
        m.add_answer(Record::from_rdata(
            owner.clone(),
            60,
            RData::CAA(CAA::new_issue(false, Some(n("letsencrypt.org.")), vec![])),
        ));
        m.add_authority(Record::from_rdata(
            owner.clone(),
            300,
            RData::SOA(SOA::new(
                n("ns.example.com."),
                n("host.example.com."),
                7,
                3600,
                600,
                86400,
                300,
            )),
        ));
        let r = decode(&m.to_vec().unwrap()).unwrap();
        assert_eq!(r.status, "NXDOMAIN");
        assert_eq!(r.flags, ["qr", "aa", "rd", "ra"]);
        assert_eq!(r.answer[0].data, "10 mail.example.com.");
        assert_eq!(
            r.answer[1].data,
            "\"v=spf1 -all\" \"say \\\"hi\\\"\\027[31m\""
        );
        assert!(r.answer[2].data.contains("issue") && r.answer[2].data.contains("letsencrypt.org"));
        assert_eq!(
            r.authority[0].data,
            "ns.example.com. host.example.com. 7 3600 600 86400 300"
        );
        assert!(
            r.answer
                .iter()
                .all(|x| x.data.chars().all(|c| c == ' ' || c.is_ascii_graphic()))
        );
    }

    #[test]
    fn rcodes_and_junk() {
        assert_eq!(rcode_name(2), "SERVFAIL");
        assert_eq!(rcode_name(5), "REFUSED");
        assert_eq!(rcode_name(99), "RCODE99");
        assert!(decode(b"\x00\x01").is_err());
        let (_, q) = query(&ask("example.com.", RecordType::A), None).unwrap();
        assert!(decode(&q).unwrap_err().contains("not a reply"));
        assert_eq!(clean("a\u{1b}b", 10), "a\\027b");
        assert_eq!(clean(&"x".repeat(50), 10), format!("{}...", "x".repeat(10)));
    }

    #[test]
    fn referrals_from_the_root_down() {
        let (_, q) = query(&ask("www.example.com.", RecordType::A), None).unwrap();
        let mut m = reply_to(&q);
        for ns in ["a.gtld-servers.net.", "b.gtld-servers.net."] {
            m.add_authority(Record::from_rdata(n("com."), 172800, RData::NS(NS(n(ns)))));
        }
        m.add_authority(Record::from_rdata(
            n("com."),
            86400,
            RData::Unknown {
                code: RecordType::DS,
                rdata: hickory_proto::rr::rdata::NULL::with(vec![0x4d, 0x06, 0x0d, 0x02, 0xaa]),
            },
        ));
        m.add_additional(Record::from_rdata(
            n("a.gtld-servers.net."),
            172800,
            RData::A(A::new(192, 5, 6, 30)),
        ));
        m.add_additional(Record::from_rdata(
            n("evil.example."),
            1,
            RData::A(A::new(6, 6, 6, 6)),
        ));
        let r = decode(&m.to_vec().unwrap()).unwrap();
        let rf = referral(&r).unwrap();
        assert_eq!(rf.zone, "com.");
        assert_eq!(rf.servers, ["a.gtld-servers.net.", "b.gtld-servers.net."]);
        // Glue only for the zone's own servers.
        assert_eq!(
            rf.glue,
            [(
                "a.gtld-servers.net.".to_owned(),
                "192.5.6.30".parse().unwrap()
            )]
        );
        assert!(rf.signed);
        // A DS too short to be one keeps the generic form.
        assert!(
            r.authority
                .iter()
                .any(|x| x.rtype == "DS" && x.data == "19718 13 2 AA"),
            "{:?}",
            r.authority
        );
        assert!(is_below("com.", "."));
        assert!(is_below("example.com.", "COM."));
        assert!(!is_below("com.", "com."));
        assert!(!is_below("xcom.", "com."));
        assert!(!signed_answer(&r));
    }

    #[test]
    fn dnssec_types_in_presentation_format() {
        // RFC 4034 §3.3's example signature, shortened.
        let mut rrsig = vec![0, 1, 5, 3, 0, 0, 0x0e, 0x10];
        rrsig.extend_from_slice(&1_081_535_777u32.to_be_bytes()); // 20040409183617
        rrsig.extend_from_slice(&1_078_943_777u32.to_be_bytes()); // 20040310183617
        rrsig.extend_from_slice(&2642u16.to_be_bytes());
        rrsig.extend_from_slice(b"\x07example\x03com\x00");
        rrsig.extend_from_slice(b"Man");
        assert_eq!(
            rrsig_text(&rrsig).unwrap(),
            "A 5 3 3600 20040409183617 20040310183617 2642 example.com. TWFu"
        );
        assert_eq!(base64(b"Ma"), "TWE=");
        assert_eq!(base64(b"M"), "TQ==");
        assert_eq!(
            dnskey_text(&[1, 1, 3, 13, b'M', b'a', b'n']).unwrap(),
            "257 3 13 TWFu"
        );
        assert_eq!(
            ds_text(&[0x4d, 0x06, 13, 2, 0xab, 0xcd]).unwrap(),
            "19718 13 2 ABCD"
        );
        assert_eq!(sig_time(0), "19700101000000");
        assert_eq!(sig_time(951_782_400), "20000229000000", "leap day");
        // Truncated: none (the generic form is printed instead).
        assert!(rrsig_text(&rrsig[..10]).is_none());
        assert!(wire_name(b"\x05ab", 0).is_none());
    }

    #[test]
    fn dig_columns() {
        let r = Row {
            name: "a-very-long-owner-name.example.com.".into(),
            ttl: 5,
            class: "IN".into(),
            rtype: "AAAA".into(),
            data: "2001:db8::1".into(),
        };
        assert_eq!(
            record_line(&r),
            "a-very-long-owner-name.example.com.\t5\tIN\tAAAA\t2001:db8::1"
        );
    }

    proptest! {
        #[test]
        fn decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
            if let Ok(r) = decode(&bytes) {
                let text = dig_text(&r, &Meta {
                    command: String::new(), server: String::new(), transport: String::new(), ms: 0, stage: None,
                });
                prop_assert!(text.chars().all(|c| c == '\n' || c == '\t' || c == ' ' || c.is_ascii_graphic()));
                let _ = referral(&r);
            }
        }
    }
}
