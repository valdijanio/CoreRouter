//! Zone files (RFC 1035 §5): import into `/ip dns zone` records and export
//! of what a zone serves.
//!
//! Our own parser, not hickory's: its lexer decodes `\DDD` wrongly
//! (0.26.3), and its `$INCLUDE` reads any file of the router, which an
//! imported text must never do. The input is hostile: bounded in size,
//! records and token length, every name checked, errors say the line.
//!
//! Accepted: `$ORIGIN`, `$TTL`, `@`, owners inherited from the line above,
//! relative and absolute names, TTL and class in either order (TTLs with
//! BIND units: `1h30m`, `2d`), parentheses across lines, `;` comments,
//! quoted strings with `\"`, `\\`, `\X` and `\DDD`. The types are the ones
//! `/ip dns zone record` has, plus the SOA; anything else is refused with
//! its line (`$INCLUDE` too).

use std::net::{Ipv4Addr, Ipv6Addr};

use corerouter_model::ItemId;
use corerouter_model::dns::MAX_TTL_SECS;
use corerouter_model::dns_static::host_name_ok;
use corerouter_model::dns_zone::{MAX_RECORDS, RecordType as ZType, ZoneRecord};
use hickory_proto::rr::{RData, Record, RecordType};

use super::{ZoneData, within};
use crate::message::key_of;

/// Largest zone file accepted (a 50 000-record zone is ~3 MiB).
pub const MAX_FILE_BYTES: usize = 8 << 20;
/// Longest token (a TXT string is at most 255 bytes; quoted with escapes,
/// a few times that).
const MAX_TOKEN: usize = 4096;

/// The SOA of an imported file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Soa {
    pub mname: String,
    pub rname: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub minimum: u32,
    pub ttl: u32,
}

/// What a zone file holds, as `/ip dns zone` data.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Imported {
    pub soa: Option<Soa>,
    /// `$TTL` (RFC 2308 §4), if the file has one.
    pub default_ttl: Option<u32>,
    /// Records with id 0 (the caller numbers them); `ttl_secs` is the TTL
    /// the file gave (explicitly or by `$TTL`), `None` without one.
    pub records: Vec<ZoneRecord>,
}

fn err(line: usize, what: impl std::fmt::Display) -> String {
    let mut s = format!("line {line}: {what}");
    s.truncate(240);
    s
}

fn shown(s: &str) -> String {
    s.chars().take(64).collect()
}

/// One token: its text (escapes decoded) and whether it was quoted.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Tok {
    text: String,
    quoted: bool,
    /// Had a backslash escape (names never do).
    escaped: bool,
}

/// One logical line (parentheses joined): its first line number, whether
/// it began with a blank (no owner), and its tokens.
#[derive(Debug)]
struct Line {
    number: usize,
    blank_start: bool,
    toks: Vec<Tok>,
}

fn lex(text: &str) -> Result<Vec<Line>, String> {
    let mut lines = Vec::new();
    let mut cur: Option<Line> = None;
    let mut line_no = 1usize;
    let mut depth = 0u32;
    let mut chars = text.chars().peekable();
    let mut at_line_start = true;
    while let Some(&c) = chars.peek() {
        if at_line_start && depth == 0 {
            if let Some(l) = cur.take()
                && !l.toks.is_empty()
            {
                lines.push(l);
            }
            cur = Some(Line {
                number: line_no,
                blank_start: c == ' ' || c == '\t',
                toks: Vec::new(),
            });
        }
        at_line_start = false;
        match c {
            '\n' => {
                chars.next();
                line_no += 1;
                at_line_start = true;
            }
            ' ' | '\t' | '\r' => {
                chars.next();
            }
            ';' => {
                while chars.peek().is_some_and(|c| *c != '\n') {
                    chars.next();
                }
            }
            '(' => {
                chars.next();
                depth += 1;
                if depth > 1 {
                    return Err(err(line_no, "nested parentheses"));
                }
            }
            ')' => {
                chars.next();
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| err(line_no, "')' without '('"))?;
            }
            _ => {
                let tok = word(&mut chars, line_no)?;
                if let Some(l) = cur.as_mut() {
                    l.toks.push(tok);
                }
            }
        }
    }
    if depth != 0 {
        return Err(err(line_no, "'(' never closed"));
    }
    if let Some(l) = cur.take()
        && !l.toks.is_empty()
    {
        lines.push(l);
    }
    Ok(lines)
}

/// A word or a quoted string, with RFC 1035 §5.1 escapes.
fn word(chars: &mut std::iter::Peekable<std::str::Chars<'_>>, line: usize) -> Result<Tok, String> {
    let quoted = chars.peek() == Some(&'"');
    if quoted {
        chars.next();
    }
    let mut bytes: Vec<u8> = Vec::new();
    let mut escaped = false;
    loop {
        let Some(&c) = chars.peek() else {
            if quoted {
                return Err(err(line, "quoted string never closed"));
            }
            break;
        };
        if quoted {
            if c == '"' {
                chars.next();
                break;
            }
            if c == '\n' {
                return Err(err(line, "quoted string runs past the end of the line"));
            }
        } else if matches!(c, ' ' | '\t' | '\r' | '\n' | ';' | '(' | ')' | '"') {
            break;
        }
        chars.next();
        if c == '\\' {
            escaped = true;
            let Some(n) = chars.next() else {
                return Err(err(line, "'\\' at the end"));
            };
            if let Some(d1) = n.to_digit(10) {
                let d2 = chars.next().and_then(|c| c.to_digit(10));
                let d3 = chars.next().and_then(|c| c.to_digit(10));
                let (Some(d2), Some(d3)) = (d2, d3) else {
                    return Err(err(line, "'\\DDD' needs three digits"));
                };
                let v = d1 * 100 + d2 * 10 + d3;
                let b = u8::try_from(v).map_err(|_| err(line, format!("'\\{v}' is above 255")))?;
                bytes.push(b);
            } else {
                let mut buf = [0u8; 4];
                bytes.extend_from_slice(n.encode_utf8(&mut buf).as_bytes());
            }
        } else {
            let mut buf = [0u8; 4];
            bytes.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
        }
        if bytes.len() > MAX_TOKEN {
            return Err(err(line, format!("a token longer than {MAX_TOKEN} bytes")));
        }
    }
    let text = String::from_utf8(bytes).map_err(|_| err(line, "text that is not UTF-8"))?;
    Ok(Tok {
        text,
        quoted,
        escaped,
    })
}

/// A TTL: seconds, or BIND units (`1w2d3h4m5s`, case aside).
pub fn parse_ttl(text: &str) -> Option<u32> {
    if text.is_empty() {
        return None;
    }
    if let Ok(n) = text.parse::<u32>() {
        return (n <= MAX_TTL_SECS).then_some(n);
    }
    let mut total: u64 = 0;
    let mut num: Option<u64> = None;
    for c in text.chars() {
        if let Some(d) = c.to_digit(10) {
            num = Some(
                num.unwrap_or(0)
                    .checked_mul(10)?
                    .checked_add(u64::from(d))?,
            );
            if num > Some(u64::from(u32::MAX)) {
                return None;
            }
            continue;
        }
        let unit: u64 = match c.to_ascii_lowercase() {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86_400,
            'w' => 604_800,
            _ => return None,
        };
        total = total.checked_add(num.take()?.checked_mul(unit)?)?;
    }
    if num.is_some() {
        return None;
    }
    u32::try_from(total).ok().filter(|t| *t <= MAX_TTL_SECS)
}

/// A name token → fully qualified, lowercase, no final dot.
fn name(t: &Tok, origin: &str, line: usize) -> Result<String, String> {
    if t.quoted || t.escaped {
        return Err(err(
            line,
            format!("'{}' is not a host name", shown(&t.text)),
        ));
    }
    let full = if t.text == "@" {
        origin.to_owned()
    } else if let Some(abs) = t.text.strip_suffix('.') {
        abs.to_ascii_lowercase()
    } else {
        format!("{}.{origin}", t.text.to_ascii_lowercase())
    };
    let check = full.strip_prefix("*.").unwrap_or(&full);
    if full == "*" || !host_name_ok(check) {
        return Err(err(
            line,
            format!("'{}' is not a host name", shown(&t.text)),
        ));
    }
    Ok(full)
}

/// Text of a TXT or CAA value: printable, no control characters.
fn text_ok(s: &str, line: usize) -> Result<(), String> {
    if s.chars().any(char::is_control) {
        return Err(err(line, "control characters in text"));
    }
    Ok(())
}

fn num<T: std::str::FromStr>(t: Option<&Tok>, what: &str, line: usize) -> Result<T, String> {
    let t = t.ok_or_else(|| err(line, format!("{what} is missing")))?;
    t.text.parse().map_err(|_| {
        err(
            line,
            format!("{what}: '{}' is not a number in range", shown(&t.text)),
        )
    })
}

const TYPES: &str = "SOA, A, AAAA, CAA, CNAME, MX, NS, PTR, SRV, TXT";

/// Reads a zone file for `zone` (lowercase, no final dot).
pub fn import(zone: &str, text: &str) -> Result<Imported, String> {
    if text.len() > MAX_FILE_BYTES {
        return Err(format!(
            "the file is larger than {} MiB",
            MAX_FILE_BYTES >> 20
        ));
    }
    let mut out = Imported::default();
    let mut origin = zone.to_owned();
    let mut owner: Option<String> = None;
    let mut last_ttl: Option<u32> = None;
    for l in lex(text)? {
        let n = l.number;
        let mut toks = l.toks.iter().peekable();
        let Some(first) = toks.peek().copied() else {
            continue;
        };
        if !l.blank_start && !first.quoted && first.text.starts_with('$') {
            toks.next();
            let arg = toks.next();
            match first.text.to_ascii_uppercase().as_str() {
                "$ORIGIN" => {
                    let a = arg.ok_or_else(|| err(n, "$ORIGIN needs a name"))?;
                    if !a.text.ends_with('.') {
                        return Err(err(n, "$ORIGIN needs an absolute name (ending in '.')"));
                    }
                    origin = name(a, &origin, n)?;
                }
                "$TTL" => {
                    let a = arg.ok_or_else(|| err(n, "$TTL needs a value"))?;
                    let t = parse_ttl(&a.text).ok_or_else(|| {
                        err(n, format!("$TTL: '{}' is not a TTL", shown(&a.text)))
                    })?;
                    out.default_ttl = Some(t);
                }
                "$INCLUDE" => {
                    return Err(err(n, "$INCLUDE is not supported: paste the included file"));
                }
                other => return Err(err(n, format!("unknown directive {}", shown(other)))),
            }
            if toks.next().is_some_and(|t| !t.text.is_empty()) && first.text != "$INCLUDE" {
                return Err(err(n, format!("{} takes one value", first.text)));
            }
            continue;
        }
        if !l.blank_start {
            let o = toks.next().ok_or_else(|| err(n, "owner missing"))?;
            owner = Some(name(o, &origin, n)?);
        }
        let own = owner
            .clone()
            .ok_or_else(|| err(n, "a record without an owner (the first line starts blank)"))?;
        // [TTL] [class] type, TTL and class in either order (RFC 1035 §5.1).
        let mut ttl: Option<u32> = None;
        let rtype = loop {
            let t = toks.next().ok_or_else(|| err(n, "record type missing"))?;
            let up = t.text.to_ascii_uppercase();
            if t.text.starts_with(|c: char| c.is_ascii_digit()) {
                if ttl.is_some() {
                    return Err(err(n, "two TTLs"));
                }
                ttl = Some(
                    parse_ttl(&t.text)
                        .ok_or_else(|| err(n, format!("'{}' is not a TTL", shown(&t.text))))?,
                );
            } else if up == "IN" {
            } else if matches!(up.as_str(), "CH" | "HS" | "CS" | "NONE" | "ANY") {
                return Err(err(n, format!("class {up}: only IN")));
            } else {
                break up;
            }
        };
        let rest: Vec<&Tok> = toks.collect();
        let at = |i: usize| rest.get(i).copied();
        let ttl = ttl.or(out.default_ttl).or(last_ttl);
        if ttl.is_some() {
            last_ttl = ttl;
        }
        if !within(&own, zone) {
            return Err(err(
                n,
                format!("{} is outside the zone {zone}", shown(&own)),
            ));
        }
        let rel = if own == zone {
            "@".to_owned()
        } else {
            own.strip_suffix(&format!(".{zone}"))
                .unwrap_or(&own)
                .to_owned()
        };
        if rtype == "SOA" {
            if rel != "@" {
                return Err(err(n, "the SOA belongs at the zone apex"));
            }
            if out.soa.is_some() {
                return Err(err(n, "a second SOA"));
            }
            let time = |i: usize, what: &str| -> Result<u32, String> {
                let t = at(i).ok_or_else(|| err(n, format!("SOA {what} is missing")))?;
                parse_ttl(&t.text).ok_or_else(|| {
                    err(n, format!("SOA {what}: '{}' is not a time", shown(&t.text)))
                })
            };
            out.soa = Some(Soa {
                mname: name(
                    at(0).ok_or_else(|| err(n, "SOA MNAME is missing"))?,
                    &origin,
                    n,
                )?,
                rname: name(
                    at(1).ok_or_else(|| err(n, "SOA RNAME is missing"))?,
                    &origin,
                    n,
                )?,
                serial: num(at(2), "SOA serial", n)?,
                refresh: time(3, "refresh")?,
                retry: time(4, "retry")?,
                expire: time(5, "expire")?,
                minimum: time(6, "minimum")?,
                ttl: ttl.unwrap_or(0),
            });
            if rest.len() > 7 {
                return Err(err(n, "SOA has more than 7 fields"));
            }
            continue;
        }
        let zt: ZType = rtype.parse().map_err(|_| {
            err(
                n,
                format!("type {} is not supported ({TYPES})", shown(&rtype)),
            )
        })?;
        let mut r = ZoneRecord::new(ItemId(0), zone, &rel);
        r.rtype = zt;
        r.ttl_secs = ttl;
        let fields =
            match zt {
                ZType::A => {
                    let t = at(0).ok_or_else(|| err(n, "A needs an address"))?;
                    let a: Ipv4Addr = t.text.parse().map_err(|_| {
                        err(n, format!("'{}' is not an IPv4 address", shown(&t.text)))
                    })?;
                    r.address = Some(a.into());
                    1
                }
                ZType::Aaaa => {
                    let t = at(0).ok_or_else(|| err(n, "AAAA needs an address"))?;
                    let a: Ipv6Addr = t.text.parse().map_err(|_| {
                        err(n, format!("'{}' is not an IPv6 address", shown(&t.text)))
                    })?;
                    r.address = Some(a.into());
                    1
                }
                ZType::Cname | ZType::Ns | ZType::Ptr => {
                    r.target = name(
                        at(0).ok_or_else(|| err(n, "the target is missing"))?,
                        &origin,
                        n,
                    )?;
                    1
                }
                ZType::Mx => {
                    r.priority = num(at(0), "MX preference", n)?;
                    r.target = name(
                        at(1).ok_or_else(|| err(n, "MX exchange is missing"))?,
                        &origin,
                        n,
                    )?;
                    2
                }
                ZType::Srv => {
                    r.priority = num(at(0), "SRV priority", n)?;
                    r.weight = num(at(1), "SRV weight", n)?;
                    r.port = num(at(2), "SRV port", n)?;
                    r.target = name(
                        at(3).ok_or_else(|| err(n, "SRV target is missing"))?,
                        &origin,
                        n,
                    )?;
                    4
                }
                ZType::Txt => {
                    if rest.is_empty() {
                        return Err(err(n, "TXT needs text"));
                    }
                    // RFC 1035 §3.3.14: the strings, one after the other.
                    r.text = rest.iter().map(|t| t.text.as_str()).collect();
                    text_ok(&r.text, n)?;
                    rest.len()
                }
                ZType::Caa => {
                    r.caa_flags = num(at(0), "CAA flags", n)?;
                    let tag = at(1).ok_or_else(|| err(n, "CAA tag is missing"))?;
                    r.caa_tag = tag.text.to_ascii_lowercase();
                    r.text = at(2).map(|t| t.text.clone()).unwrap_or_default();
                    text_ok(&r.text, n)?;
                    3
                }
            };
        if rest.len() > fields {
            return Err(err(n, format!("{rtype} has more than {fields} fields")));
        }
        if let Some(p) = r.problem() {
            return Err(err(n, p));
        }
        if out.records.len() >= MAX_RECORDS {
            return Err(err(n, format!("more than {MAX_RECORDS} records")));
        }
        out.records.push(r);
    }
    Ok(out)
}

/// A string as RFC 1035 §5.1 quotes it: `"` and `\` escaped, the rest as
/// is (UTF-8 stays UTF-8).
fn quote(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut s = String::with_capacity(text.len() + 2);
    s.push('"');
    for c in text.chars() {
        match c {
            '"' | '\\' => {
                s.push('\\');
                s.push(c);
            }
            c if c.is_control() => s.push_str(&format!("\\{:03}", u32::from(c) & 0xff)),
            c => s.push(c),
        }
    }
    s.push('"');
    s
}

/// The data of `r` as a zone file writes it.
pub fn rdata_text(r: &Record) -> String {
    match &r.data {
        RData::A(a) => a.0.to_string(),
        RData::AAAA(a) => a.0.to_string(),
        RData::CNAME(c) => c.0.to_ascii(),
        RData::NS(n) => n.0.to_ascii(),
        RData::PTR(p) => p.0.to_ascii(),
        RData::MX(mx) => format!("{} {}", mx.preference, mx.exchange.to_ascii()),
        RData::SRV(s) => format!(
            "{} {} {} {}",
            s.priority,
            s.weight,
            s.port,
            s.target.to_ascii()
        ),
        RData::TXT(t) => t
            .txt_data
            .iter()
            .map(|b| quote(b))
            .collect::<Vec<_>>()
            .join(" "),
        RData::CAA(c) => format!("{} {} {}", c.flags(), c.tag, quote(&c.value)),
        RData::SOA(s) => format!(
            "{} {} {} {} {} {} {}",
            s.mname.to_ascii(),
            s.rname.to_ascii(),
            s.serial,
            s.refresh,
            s.retry,
            s.expire,
            s.minimum
        ),
        other => other.to_string(),
    }
}

/// `owner` relative to the zone (`@`, `www`), as the file writes it.
fn relative(z: &ZoneData, r: &Record) -> String {
    let k = key_of(&r.name);
    if k == z.key {
        "@".into()
    } else {
        k.strip_suffix(&format!(".{}", z.key))
            .map_or_else(|| r.name.to_ascii(), str::to_owned)
    }
}

fn line(z: &ZoneData, r: &Record, out: &mut String) {
    let t: RecordType = r.record_type();
    out.push_str(&format!(
        "{} {} IN {} {}\n",
        relative(z, r),
        r.ttl,
        t,
        rdata_text(r)
    ));
}

/// A zone file of `z`: `$ORIGIN`, `$TTL`, the SOA, then the records, apex
/// first.
pub fn export(z: &ZoneData) -> String {
    let mut out = format!(
        "; zone {}, serial {}\n$ORIGIN {}\n$TTL {}\n",
        z.key,
        z.serial,
        z.origin.to_ascii(),
        z.soa.ttl
    );
    line(z, &z.soa, &mut out);
    for r in z.records() {
        line(z, r, &mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const SAMPLE: &str = r#"
$ORIGIN example.com.
$TTL 1h
@   IN  SOA ns1 hostmaster (
        2026102201 ; serial
        1d 2h 1000h 1h )
    IN  NS  ns1
    IN  NS  ns2.example.net.
    IN  MX  10 mail
    IN  CAA 0 issue "letsencrypt.org"
ns1 300 IN A 192.0.2.53
mail    A   192.0.2.25
        AAAA 2001:db8::25
www IN 60 CNAME @
*.dev   TXT "a \"quoted\" word" "and more"
_sip._udp SRV 10 5 5060 pbx
pbx A 192.0.2.60
"#;

    #[test]
    fn a_bind_style_file_is_read() {
        let got = import("example.com", SAMPLE).unwrap();
        let soa = got.soa.unwrap();
        assert_eq!(soa.mname, "ns1.example.com");
        assert_eq!(soa.rname, "hostmaster.example.com");
        assert_eq!(
            (
                soa.serial,
                soa.refresh,
                soa.retry,
                soa.expire,
                soa.minimum,
                soa.ttl
            ),
            (2_026_102_201, 86_400, 7200, 3_600_000, 3600, 3600)
        );
        assert_eq!(got.default_ttl, Some(3600));
        let rows: Vec<String> = got
            .records
            .iter()
            .map(|r| {
                format!(
                    "{} {:?} {} {}",
                    r.name,
                    r.ttl_secs,
                    r.rtype.as_str(),
                    r.data()
                )
            })
            .collect();
        assert_eq!(
            rows,
            [
                "@ Some(3600) NS ns1.example.com.",
                "@ Some(3600) NS ns2.example.net.",
                "@ Some(3600) MX 10 mail.example.com.",
                "@ Some(3600) CAA 0 issue \"letsencrypt.org\"",
                "ns1 Some(300) A 192.0.2.53",
                "mail Some(3600) A 192.0.2.25",
                "mail Some(3600) AAAA 2001:db8::25",
                "www Some(60) CNAME example.com.",
                "*.dev Some(3600) TXT \"a \\\"quoted\\\" wordand more\"",
                "_sip._udp Some(3600) SRV 10 5 5060 pbx.example.com.",
                "pbx Some(3600) A 192.0.2.60",
            ]
        );
    }

    #[test]
    fn bad_files_say_the_line() {
        for (text, want) in [
            ("$INCLUDE /etc/shadow\n", "line 1: $INCLUDE"),
            (
                "@ IN SOA a b 1 2 3 4 5\n@ IN SOA a b 1 2 3 4 5\n",
                "line 2: a second SOA",
            ),
            ("www IN HINFO a b\n", "type HINFO is not supported"),
            ("www.other.org. IN A 192.0.2.1\n", "outside the zone"),
            ("www IN A 300.1.1.1\n", "not an IPv4"),
            ("www CH A 192.0.2.1\n", "only IN"),
            ("   IN A 192.0.2.1\n", "without an owner"),
            ("www IN A ( 192.0.2.1\n", "never closed"),
            ("www IN TXT \"open\n", "past the end"),
            ("www IN TXT \"\\999\"\n", "above 255"),
            ("bad_label!x IN A 192.0.2.1\n", "not a host name"),
            ("www IN MX 70000 mail\n", "MX preference"),
            ("www IN A 192.0.2.1 extra\n", "more than 1 fields"),
            ("www IN TXT \"a\\010b\"\n", "control"),
        ] {
            let e = import("example.com", text).unwrap_err();
            assert!(e.contains(want), "{text:?}: {e}");
        }
    }

    #[test]
    fn ttls_take_bind_units() {
        assert_eq!(parse_ttl("300"), Some(300));
        assert_eq!(parse_ttl("1h30m"), Some(5400));
        assert_eq!(parse_ttl("1W"), Some(604_800));
        assert_eq!(parse_ttl("1h30"), None);
        assert_eq!(parse_ttl("h"), None);
        assert_eq!(parse_ttl("99999999999"), None);
        assert_eq!(parse_ttl("4000w"), None, "above 2^31-1");
    }

    #[test]
    fn decimal_escapes_are_bytes() {
        let got = import("example.com", "t TXT \"\\065\\066\" \\067\n").unwrap();
        assert_eq!(got.records[0].text, "ABC");
    }

    proptest! {
        /// Hostile text never panics; it is read or refused.
        #[test]
        fn hostile_text_never_panics(s in "[ -~\\n\\t\"();\\\\$@*.]{0,400}") {
            let _ = import("example.com", &s);
        }

        #[test]
        fn hostile_bytes_never_panic(b in proptest::collection::vec(any::<u8>(), 0..400)) {
            let _ = import("example.com", &String::from_utf8_lossy(&b));
        }

        /// TXT text survives export → import (quotes, backslashes, UTF-8,
        /// long strings cut in 255-byte pieces).
        #[test]
        fn txt_round_trips(text in "[ -~çãé€]{1,600}") {
            let mut z = corerouter_model::dns_zone::Zone::new(ItemId(1), "example.com");
            z.serial = 1;
            let mut r = ZoneRecord::new(ItemId(1), "example.com", "t");
            r.rtype = ZType::Txt;
            r.text = text.clone();
            let data = super::super::primary(&z, &[&r]).unwrap();
            let back = import("example.com", &export(&data)).unwrap();
            let txt: Vec<&ZoneRecord> = back.records.iter().filter(|r| r.rtype == ZType::Txt).collect();
            prop_assert_eq!(txt.len(), 1);
            prop_assert_eq!(&txt[0].text, &text);
        }
    }
}
