//! Reverse names: the owner name of an address's PTR record.
//!
//! RFC 1035 §3.5: an IPv4 address `a.b.c.d` lives at `d.c.b.a.in-addr.arpa`.
//! RFC 3596 §2.5: an IPv6 address is its 32 nibbles, lowest first, as hex
//! digits under `ip6.arpa`.

use std::fmt::Write;
use std::net::IpAddr;

/// `ip`'s nibbles (IPv6) or octets (IPv4) in reverse, dot-separated,
/// without the zone: `4.3.2.1` / `b.a.9.8.…`.
pub fn reversed(ip: IpAddr) -> String {
    let mut out = String::new();
    match ip {
        IpAddr::V4(v4) => {
            for o in v4.octets().iter().rev() {
                let _ = write!(out, "{o}.");
            }
        }
        IpAddr::V6(v6) => {
            for o in v6.octets().iter().rev() {
                let _ = write!(out, "{:x}.{:x}.", o & 0x0f, o >> 4);
            }
        }
    }
    out.pop();
    out
}

/// The PTR owner name of `ip` (an IPv4-mapped IPv6 address is the IPv4
/// one: the PTR lives under `in-addr.arpa`).
pub fn reverse_name(ip: IpAddr) -> String {
    match ip.to_canonical() {
        v4 @ IpAddr::V4(_) => format!("{}.in-addr.arpa", reversed(v4)),
        v6 @ IpAddr::V6(_) => format!("{}.ip6.arpa", reversed(v6)),
    }
}

/// A name from the network made safe to show: printable ASCII only (no
/// terminal escapes), at most `max` characters, without the final dot.
pub fn printable(text: &str, max: usize) -> String {
    text.trim_end_matches('.')
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(max)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc1035_3_5_in_addr_arpa() {
        // RFC 1035 §3.5: "the address 10.2.0.52 ... 52.0.2.10.IN-ADDR.ARPA".
        assert_eq!(
            reverse_name("10.2.0.52".parse().unwrap()),
            "52.0.2.10.in-addr.arpa"
        );
        assert_eq!(
            reverse_name("::ffff:192.0.2.1".parse().unwrap()),
            "1.2.0.192.in-addr.arpa"
        );
    }

    #[test]
    fn rfc3596_2_5_ip6_arpa() {
        // RFC 3596 §2.5: 4321:0:1:2:3:4:567:89ab →
        // b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.IP6.ARPA.
        assert_eq!(
            reverse_name("4321:0:1:2:3:4:567:89ab".parse().unwrap()),
            "b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.ip6.arpa"
        );
    }

    #[test]
    fn hostile_text_is_cleaned() {
        assert_eq!(printable("a\u{1b}[2Jb.example.", 64), "a[2Jb.example");
        assert_eq!(printable("ação", 64), "ao");
        assert_eq!(printable(&"x".repeat(300), 10).len(), 10);
    }
}
