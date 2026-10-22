//! Origin AS of an address over DNS, from the Team Cymru IP-to-ASN service
//! (<https://www.team-cymru.com/ip-asn-mapping>), the source `mtr -z` uses.
//! Two TXT lookups through the router's resolver (and its cache):
//!
//! - `<reversed address>.origin.asn.cymru.com` (IPv4) or
//!   `<reversed nibbles>.origin6.asn.cymru.com` (IPv6) →
//!   `"3356 | 4.0.0.0/9 | US | arin | 1992-12-01"`: origin AS (several when
//!   more than one AS announces the prefix), prefix, country, registry,
//!   allocation date;
//! - `AS3356.asn.cymru.com` → `"3356 | US | arin | 2000-03-10 | LEVEL3, US"`:
//!   the AS name.

use std::net::IpAddr;

use corerouter_model::dns::QType;

use crate::resolver::{ResolveError, Resolver, Transport};
use crate::reverse::{printable, reversed};

/// What Team Cymru says about an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub asn: u32,
    /// The announced prefix that covers the address.
    pub prefix: Option<String>,
    pub country: Option<String>,
    /// Short AS name ("LEVEL3"), from the second lookup.
    pub name: Option<String>,
}

/// The origin TXT name of `ip`.
pub fn origin_name(ip: IpAddr) -> String {
    match ip.to_canonical() {
        v4 @ IpAddr::V4(_) => format!("{}.origin.asn.cymru.com", reversed(v4)),
        v6 @ IpAddr::V6(_) => format!("{}.origin6.asn.cymru.com", reversed(v6)),
    }
}

/// The AS name TXT name of `asn`.
pub fn as_name(asn: u32) -> String {
    format!("AS{asn}.asn.cymru.com")
}

fn field(text: &str, max: usize) -> Option<String> {
    let t = printable(text.trim(), max);
    (!t.is_empty()).then_some(t)
}

/// One origin answer. Several origins ("23028 23029 | …") give the first.
pub fn parse_origin(txt: &str) -> Option<Origin> {
    let mut f = txt.split('|');
    let asn = f.next()?.split_whitespace().next()?.parse::<u32>().ok()?;
    let prefix = f.next().and_then(|p| field(p, 43));
    let country = f.next().and_then(|c| field(c, 8));
    Some(Origin {
        asn,
        prefix,
        country,
        name: None,
    })
}

/// Length of a `a.b.c.d/n` prefix (0 when unknown).
fn prefix_len(o: &Origin) -> u8 {
    o.prefix
        .as_deref()
        .and_then(|p| p.rsplit_once('/'))
        .and_then(|(_, n)| n.parse().ok())
        .unwrap_or(0)
}

/// The most specific of several origin answers (one per covering prefix).
pub fn best_origin<'a>(txts: impl IntoIterator<Item = &'a String>) -> Option<Origin> {
    txts.into_iter()
        .filter_map(|t| parse_origin(t))
        .max_by_key(prefix_len)
}

/// The short name of an AS answer: the fifth field up to its first " - "
/// or "," ("LEVEL3, US" → "LEVEL3"; "TEAM-CYMRU - Team Cymru Inc., US" →
/// "TEAM-CYMRU").
pub fn parse_as_name(txt: &str) -> Option<String> {
    let full = txt.split('|').nth(4)?;
    let short = full.split(" - ").next()?.split(',').next()?;
    field(short, 32)
}

/// Origin AS and its name for `ip`. `Ok(None)`: no AS announces it.
pub fn lookup(
    r: &Resolver,
    t: &mut dyn Transport,
    ip: IpAddr,
) -> Result<Option<Origin>, ResolveError> {
    let Some(mut o) = best_origin(&r.records(t, &origin_name(ip), QType::Txt)?) else {
        return Ok(None);
    };
    // Without a name the number still helps: a failure here is not one.
    o.name = r
        .records(t, &as_name(o.asn), QType::Txt)
        .ok()
        .and_then(|txts| txts.iter().find_map(|t| parse_as_name(t)));
    Ok(Some(o))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_names() {
        assert_eq!(
            origin_name("216.90.108.31".parse().unwrap()),
            "31.108.90.216.origin.asn.cymru.com"
        );
        let v6 = origin_name("2001:db8::1".parse().unwrap());
        assert!(
            v6.starts_with("1.0.0.0.") && v6.ends_with(".8.b.d.0.1.0.0.2.origin6.asn.cymru.com")
        );
        assert_eq!(as_name(23028), "AS23028.asn.cymru.com");
    }

    #[test]
    fn team_cymru_answers() {
        // The examples of the Team Cymru IP-to-ASN page.
        let o = parse_origin("23028 | 216.90.108.0/24 | US | arin | 1998-09-25").unwrap();
        assert_eq!(o.asn, 23028);
        assert_eq!(o.prefix.as_deref(), Some("216.90.108.0/24"));
        assert_eq!(o.country.as_deref(), Some("US"));
        assert_eq!(
            parse_as_name("23028 | US | arin | 2002-01-04 | TEAM-CYMRU - Team Cymru Inc., US")
                .as_deref(),
            Some("TEAM-CYMRU")
        );
        assert_eq!(
            parse_as_name("3356 | US | arin | 2000-03-10 | LEVEL3, US").as_deref(),
            Some("LEVEL3")
        );
        // Several origins: the first; several prefixes: the longest.
        assert_eq!(
            parse_origin("13335 209242 | 1.1.1.0/24 | AU | apnic |")
                .unwrap()
                .asn,
            13335
        );
        let txts = vec![
            "3356 | 4.0.0.0/9 | US | arin | 1992-12-01".to_owned(),
            "64500 | 4.2.0.0/16 | US | arin |".to_owned(),
        ];
        assert_eq!(best_origin(&txts).unwrap().asn, 64500);
    }

    #[test]
    fn junk_is_refused() {
        assert_eq!(parse_origin(""), None);
        assert_eq!(parse_origin("NA | 10.0.0.0/8"), None);
        assert_eq!(parse_origin("99999999999 | x"), None);
        assert_eq!(parse_as_name("3356 | US"), None);
        let o = parse_origin("1 | \u{1b}[31m1.0.0.0/24 | US").unwrap();
        assert_eq!(o.prefix.as_deref(), Some("[31m1.0.0.0/24"));
    }

    proptest::proptest! {
        #[test]
        fn any_text_is_safe(s in "\\PC{0,200}") {
            let _ = parse_origin(&s);
            if let Some(n) = parse_as_name(&s) {
                proptest::prop_assert!(n.len() <= 32 && n.chars().all(|c| c.is_ascii_graphic() || c == ' '));
            }
        }
    }
}
