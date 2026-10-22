//! Option values written the RouterOS way (`/ip dhcp-server option`), so an
//! operator can paste what they already use:
//!
//! | Written | Bytes |
//! |---|---|
//! | `0x0a0b` | as is |
//! | `'text'` | ASCII |
//! | `'10.0.0.1'` | the IPv4 address (4 bytes) |
//! | `'10'` | the number, big-endian, in as few bytes as it needs |
//! | `s'10.0.0.1'` | ASCII, whatever it looks like |
//! | `$(HOSTNAME)`, `$(CLIENT_MAC)` | the host name sent, the client MAC |
//!
//! Pieces concatenate: `0x01'cpe'$(CLIENT_MAC)`.

use std::net::Ipv4Addr;

/// What `$(…)` expands to.
#[derive(Debug, Clone, Copy)]
pub struct Vars<'a> {
    pub host_name: &'a str,
    pub mac: [u8; 6],
}

/// Longest option payload (one option's length byte).
pub const MAX_LEN: usize = 255;

/// Bytes of `text`, or what is wrong with it (the message quotes at most a
/// few characters of the input).
pub fn parse(text: &str, vars: &Vars<'_>) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut rest = text.trim();
    if rest.is_empty() {
        return Err("empty value".into());
    }
    while !rest.is_empty() {
        if let Some(r) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
            let end = r.find(|c: char| !c.is_ascii_hexdigit()).unwrap_or(r.len());
            let hex = r.get(..end).unwrap_or("");
            if hex.is_empty() || hex.len() % 2 != 0 {
                return Err(format!(
                    "hex after 0x needs an even number of digits near '{}'",
                    snippet(rest)
                ));
            }
            for pair in hex.as_bytes().chunks(2) {
                let s = std::str::from_utf8(pair).map_err(|e| e.to_string())?;
                out.push(u8::from_str_radix(s, 16).map_err(|e| e.to_string())?);
            }
            rest = r.get(end..).unwrap_or("");
        } else if let Some(r) = rest.strip_prefix("s'") {
            let (body, after) = quoted(r, rest)?;
            out.extend_from_slice(body.as_bytes());
            rest = after;
        } else if let Some(r) = rest.strip_prefix('\'') {
            let (body, after) = quoted(r, rest)?;
            out.extend(typed(body));
            rest = after;
        } else if let Some(r) = rest.strip_prefix("$(") {
            let end = r
                .find(')')
                .ok_or_else(|| format!("unclosed $( near '{}'", snippet(rest)))?;
            match r.get(..end).unwrap_or("") {
                "HOSTNAME" => out.extend_from_slice(vars.host_name.as_bytes()),
                "CLIENT_MAC" => out.extend_from_slice(&vars.mac),
                other => {
                    return Err(format!(
                        "unknown variable $({}); use $(HOSTNAME) or $(CLIENT_MAC)",
                        snippet(other)
                    ));
                }
            }
            rest = r.get(end.saturating_add(1)..).unwrap_or("");
        } else {
            return Err(format!(
                "expected 0x…, '…', s'…' or $(…) near '{}' (text goes in quotes: 'text')",
                snippet(rest)
            ));
        }
        if out.len() > MAX_LEN {
            return Err(format!("value is longer than {MAX_LEN} bytes"));
        }
    }
    Ok(out)
}

/// Plain text, or the option syntax when it starts like it (`0x`, `'`,
/// `s'`, `$(`): what `client_id` and `vendor_class` accept.
pub fn parse_or_text(text: &str, vars: &Vars<'_>) -> Result<Vec<u8>, String> {
    let t = text.trim();
    let syntax = ["0x", "0X", "'", "s'", "$("]
        .iter()
        .any(|p| t.starts_with(p));
    if syntax {
        return parse(t, vars);
    }
    if t.len() > MAX_LEN {
        return Err(format!("value is longer than {MAX_LEN} bytes"));
    }
    Ok(t.as_bytes().to_vec())
}

fn quoted<'a>(body_and_rest: &'a str, whole: &str) -> Result<(&'a str, &'a str), String> {
    let end = body_and_rest
        .find('\'')
        .ok_or_else(|| format!("unclosed quote near '{}'", snippet(whole)))?;
    Ok((
        body_and_rest.get(..end).unwrap_or(""),
        body_and_rest.get(end.saturating_add(1)..).unwrap_or(""),
    ))
}

/// `'…'`: an IPv4 address, a decimal number, or ASCII text.
fn typed(body: &str) -> Vec<u8> {
    if let Ok(ip) = body.parse::<Ipv4Addr>() {
        return ip.octets().to_vec();
    }
    if !body.is_empty()
        && body.bytes().all(|b| b.is_ascii_digit())
        && let Ok(n) = body.parse::<u64>()
    {
        let bytes = n.to_be_bytes();
        let skip = bytes
            .iter()
            .take(bytes.len().saturating_sub(1))
            .take_while(|b| **b == 0)
            .count();
        return bytes.get(skip..).unwrap_or(&[]).to_vec();
    }
    body.as_bytes().to_vec()
}

fn snippet(s: &str) -> String {
    s.chars().take(16).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const VARS: Vars<'static> = Vars {
        host_name: "cpe",
        mac: [2, 0, 0, 0, 0, 1],
    };

    #[test]
    fn routeros_examples() {
        assert_eq!(parse("'test'", &VARS).unwrap(), b"test");
        assert_eq!(parse("'10.10.10.10'", &VARS).unwrap(), [10, 10, 10, 10]);
        assert_eq!(parse("s'10.10.10.10'", &VARS).unwrap(), b"10.10.10.10");
        assert_eq!(parse("'10'", &VARS).unwrap(), [10]);
        assert_eq!(parse("'300'", &VARS).unwrap(), [1, 44]);
        assert_eq!(parse("'0'", &VARS).unwrap(), [0]);
        assert_eq!(parse("0x0a0a", &VARS).unwrap(), [10, 10]);
        assert_eq!(
            parse("0x01'vards'$(HOSTNAME)", &VARS).unwrap(),
            b"\x01vardscpe"
        );
        assert_eq!(
            parse("0x01$(CLIENT_MAC)", &VARS).unwrap(),
            [1, 2, 0, 0, 0, 0, 1]
        );
    }

    #[test]
    fn mistakes_say_what_to_write() {
        for (bad, want) in [
            ("", "empty"),
            ("0x0", "even"),
            ("0x", "even"),
            ("'open", "unclosed quote"),
            ("$(HOST", "unclosed"),
            ("$(PATH)", "unknown variable"),
            ("text", "in quotes"),
        ] {
            let e = parse(bad, &VARS).unwrap_err();
            assert!(e.contains(want), "{bad}: {e}");
        }
        let long = format!("0x{}", "ab".repeat(256));
        assert!(parse(&long, &VARS).unwrap_err().contains("255"));
        assert_eq!(parse_or_text("plain id", &VARS).unwrap(), b"plain id");
        assert_eq!(parse_or_text("0xff00", &VARS).unwrap(), [255, 0]);
    }

    proptest! {
        #[test]
        fn never_panics_and_respects_the_limit(s in ".{0,600}") {
            if let Ok(v) = parse(&s, &VARS) {
                prop_assert!(v.len() <= MAX_LEN);
            }
            if let Ok(v) = parse_or_text(&s, &VARS) {
                prop_assert!(v.len() <= MAX_LEN);
            }
        }

        #[test]
        fn hex_round_trips(bytes in proptest::collection::vec(any::<u8>(), 1..200)) {
            let text: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            prop_assert_eq!(parse(&format!("0x{text}"), &VARS).unwrap(), bytes);
        }
    }
}
