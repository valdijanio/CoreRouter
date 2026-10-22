//! L2 — syslog messages (G4.6): RFC 5424 format for the UDP transport of
//! RFC 5426. Encode only: CoreRouter sends logs, it is not a collector.
//!
//! References (read 2026-10-22):
//! - RFC 5424 §6 (ABNF), §6.1 (length), §6.2.1 (PRI = facility × 8 +
//!   severity), §6.2.3 (TIMESTAMP, upper-case `T`/`Z`), §6.2.4–§6.2.7
//!   (HOSTNAME ≤ 255, APP-NAME ≤ 48, PROCID ≤ 128, MSGID ≤ 32 printable
//!   US-ASCII, or the NILVALUE `-`), §6.3 (no structured data: `-`), §6.4
//!   (UTF-8 MSG starts with a BOM). <https://www.rfc-editor.org/rfc/rfc5424>
//! - RFC 5426 §3.1 (one message per datagram, may be truncated), §3.2 (size:
//!   keep under the path MTU; 1180 octets is safe on IPv6), §3.3 (port 514).
//!   <https://www.rfc-editor.org/rfc/rfc5426>
//!
//! Every field comes from configuration or events that may hold anything:
//! header fields are reduced to printable ASCII and cut to their limits,
//! control characters in the text become spaces (collectors split on
//! newlines), and the whole message is cut at `max_len` bytes on a UTF-8
//! boundary, so the output is always well-formed.

/// RFC 5426 §3.3.
pub const PORT: u16 = 514;
/// RFC 5426 §3.2: fits the IPv6 minimum MTU (1280) after IP and UDP
/// headers; collectors SHOULD accept 2048 and MUST accept 480 (IPv4).
pub const DEFAULT_MAX_LEN: usize = 1180;
/// The smallest size a receiver must accept (RFC 5424 §6.1).
pub const MIN_MAX_LEN: usize = 480;

const NILVALUE: &str = "-";
const BOM: &[u8] = b"\xEF\xBB\xBF";

/// One message. Facility 0..=23 and severity 0..=7 (RFC 5424 Tables 1–2);
/// larger values are clamped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message<'a> {
    pub facility: u8,
    pub severity: u8,
    /// Unix time in microseconds; `None` sends the NILVALUE (§6.2.3: only
    /// when the sender has no clock).
    pub time_micros: Option<i64>,
    pub hostname: &'a str,
    pub app_name: &'a str,
    pub procid: &'a str,
    pub msgid: &'a str,
    pub msg: &'a str,
}

/// RFC 5424 §6: `<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID - MSG`,
/// at most `max_len` bytes (never below [`MIN_MAX_LEN`]).
pub fn encode(m: &Message<'_>, max_len: usize) -> Vec<u8> {
    let pri = u16::from(m.facility.min(23)) * 8 + u16::from(m.severity.min(7));
    let time = m
        .time_micros
        .and_then(rfc3339_utc)
        .unwrap_or_else(|| NILVALUE.to_owned());
    let mut out = format!(
        "<{pri}>1 {time} {} {} {} {} -",
        header_field(m.hostname, 255),
        header_field(m.app_name, 48),
        header_field(m.procid, 128),
        header_field(m.msgid, 32),
    )
    .into_bytes();
    let text: String = m
        .msg
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if !text.is_empty() {
        out.push(b' ');
        if !text.is_ascii() {
            out.extend_from_slice(BOM);
        }
        out.extend_from_slice(text.as_bytes());
    }
    truncate_utf8(&mut out, max_len.max(MIN_MAX_LEN));
    out
}

/// PRINTUSASCII (33..=126) only, at most `max` characters, `-` when empty.
fn header_field(s: &str, max: usize) -> String {
    let f: String = s
        .chars()
        .map(|c| if c.is_ascii_graphic() { c } else { '_' })
        .take(max)
        .collect();
    if f.is_empty() { NILVALUE.to_owned() } else { f }
}

/// Cut at `max` bytes without splitting a UTF-8 character (§6.1: truncate
/// at the end). The header is ASCII, so only MSG can be split.
fn truncate_utf8(out: &mut Vec<u8>, max: usize) {
    if out.len() <= max {
        return;
    }
    let mut cut = max;
    // Continuation bytes are 0b10xxxxxx; back up to a character start.
    while cut > 0 && out.get(cut).is_some_and(|b| b & 0xC0 == 0x80) {
        cut -= 1;
    }
    out.truncate(cut);
}

/// `YYYY-MM-DDThh:mm:ss.ffffffZ` (RFC 5424 §6.2.3, RFC 3339), years
/// 0000..=9999 only.
pub fn rfc3339_utc(micros: i64) -> Option<String> {
    let secs = micros.div_euclid(1_000_000);
    let frac = micros.rem_euclid(1_000_000);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (y, mo, d) = civil_from_days(days);
    if !(0..=9999).contains(&y) {
        return None;
    }
    Some(format!(
        "{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}.{frac:06}Z",
        tod / 3600,
        tod % 3600 / 60,
        tod % 60
    ))
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian
/// (H. Hinnant's public-domain `civil_from_days` algorithm).
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn msg(text: &str) -> Message<'_> {
        Message {
            facility: 20,
            severity: 5,
            time_micros: Some(1_066_480_620_003_000),
            hostname: "mymachine.example.com",
            app_name: "su",
            procid: "",
            msgid: "ID47",
            msg: text,
        }
    }

    #[test]
    fn rfc_5424_section_6_5_example_shape() {
        // §6.5 Example 1, without its BOM (the text is ASCII) and in UTC.
        let out = encode(&msg("'su root' failed for lonvick on /dev/pts/8"), 2048);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "<165>1 2003-10-18T12:37:00.003000Z mymachine.example.com su - ID47 - \
             'su root' failed for lonvick on /dev/pts/8"
        );
    }

    #[test]
    fn utf8_text_gets_a_bom_and_controls_become_spaces() {
        let out = encode(&msg("ação\nok"), 2048);
        let tail = b" - \xEF\xBB\xBF";
        let at = out.windows(tail.len()).position(|w| w == tail).unwrap();
        assert_eq!(&out[at + tail.len()..], "ação ok".as_bytes());
    }

    #[test]
    fn header_fields_are_printable_and_bounded() {
        let long = "x".repeat(300);
        let m = Message {
            hostname: "my host",
            app_name: &long,
            time_micros: None,
            ..msg("")
        };
        let out = String::from_utf8(encode(&m, 2048)).unwrap();
        assert!(out.starts_with("<165>1 - my_host "), "{out}");
        assert!(out.contains(&format!(" {} ", "x".repeat(48))));
        assert!(!out.contains(&"x".repeat(49)));
        assert!(out.ends_with(" -"), "no MSG: ends with the SD NILVALUE");
    }

    #[test]
    fn pri_is_clamped() {
        let m = Message {
            facility: 99,
            severity: 99,
            ..msg("x")
        };
        assert!(encode(&m, 2048).starts_with(b"<191>1 "));
    }

    #[test]
    fn dates() {
        assert_eq!(rfc3339_utc(0).unwrap(), "1970-01-01T00:00:00.000000Z");
        assert_eq!(
            rfc3339_utc(951_782_400_000_000).unwrap(),
            "2000-02-29T00:00:00.000000Z"
        );
        assert_eq!(
            rfc3339_utc(1_792_678_400_500_000).unwrap(),
            "2026-10-22T14:13:20.500000Z"
        );
        assert_eq!(rfc3339_utc(-1).unwrap(), "1969-12-31T23:59:59.999999Z");
        assert!(rfc3339_utc(i64::MAX).is_none());
    }

    proptest! {
        #[test]
        fn output_is_bounded_and_well_formed(
            host in ".{0,300}", app in ".{0,80}", text in ".{0,3000}",
            fac in any::<u8>(), sev in any::<u8>(), t in any::<Option<i64>>(),
            max in 0usize..4096,
        ) {
            let m = Message { facility: fac, severity: sev, time_micros: t,
                hostname: &host, app_name: &app, procid: "1", msgid: "x", msg: &text };
            let out = encode(&m, max);
            prop_assert!(out.len() <= max.max(MIN_MAX_LEN));
            let s = std::str::from_utf8(&out);
            prop_assert!(s.is_ok());
            let s = s.unwrap_or_default();
            prop_assert!(!s.contains('\n'));
            // Header: 7 space-separated printable fields + SD before MSG.
            let fields: Vec<&str> = s.splitn(8, ' ').collect();
            prop_assert!(fields.len() >= 7);
            prop_assert!(fields.iter().take(7).all(|f| !f.is_empty() && f.chars().all(|c| c.is_ascii_graphic())));
        }
    }
}
