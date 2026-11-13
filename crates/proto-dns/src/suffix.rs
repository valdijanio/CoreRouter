//! The domain a name belongs to, for counting failures by domain
//! (G4.1za): `x7f3k.victim.com.br` and `q01.victim.com.br` both count
//! under `victim.com.br`, so a random-subdomain attack (every name new,
//! every answer NXDOMAIN) shows as one domain with thousands of different
//! names instead of thousands of names asked once.
//!
//! Without the Public Suffix List: the last two labels, or three when the
//! top level is a country code (two letters) and the second level is one
//! of the generic words registries put under them (`com.br`, `co.uk`,
//! `gov.au`, `ac.jp`…). Reverse names keep the part an operator reads: a
//! /16 of `in-addr.arpa`, a /32 of `ip6.arpa`. The list is our own (words
//! like "com" and "gov", not the PSL's text); `docs/changes/G4.1za.md`
//! measures it against the PSL. Cost: one pass over the name from the
//! right, no allocation (a slice of it).

/// Second-level words that are a public suffix under most two-letter
/// top levels (sorted: binary search). Measured against the PSL (ICANN
/// part, 2026-11-12): they cover the second levels people use (com.br,
/// gov.br, co.uk, com.mx) but 35 % of the 3381 two-label rules under
/// country codes (the long tail: city names, `.jp`'s prefectures); "web"
/// and "nic" left out (`web.de`, `nic.br` are domains, not suffixes).
const GENERIC: [&str; 77] = [
    "ac", "ad", "adv", "arq", "art", "ato", "bio", "biz", "blog", "co", "com", "coop", "ecn", "ed",
    "edu", "emp", "eng", "esp", "etc", "far", "flog", "fm", "fot", "fst", "g12", "ggf", "go",
    "gob", "gouv", "gov", "govt", "gr", "imb", "ind", "inf", "info", "int", "jor", "jus", "k12",
    "lel", "lg", "lt", "ltd", "mat", "med", "mi", "mil", "mus", "ne", "net", "nom", "not", "ntr",
    "odo", "or", "org", "plc", "ppg", "pro", "psc", "psi", "qsl", "rec", "res", "sch", "slg",
    "srv", "tmp", "trd", "tur", "tv", "vet", "vlog", "wiki", "zlg", "zz",
];

/// `name` without its last label and the dot before it, and that label.
fn split_last(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(i) => (name.get(..i).unwrap_or(""), name.get(i + 1..).unwrap_or("")),
        None => ("", name),
    }
}

/// The last `n` labels of `name` (all of it when it has fewer).
fn last_labels(name: &str, n: usize) -> &str {
    let mut cut = name.len();
    for _ in 0..n {
        match name.get(..cut).and_then(|s| s.rfind('.')) {
            Some(i) => cut = i,
            None => return name,
        }
    }
    name.get(cut + 1..).unwrap_or(name)
}

/// The domain `name` (lowercase, without the final dot, as
/// [`crate::message::QName::key`]) is counted under.
pub fn domain_of(name: &str) -> &str {
    let name = name.strip_suffix('.').unwrap_or(name);
    if name.ends_with(".in-addr.arpa") {
        // b.a.in-addr.arpa: the /16 a.b.0.0.
        return last_labels(name, 4);
    }
    if name.ends_with(".ip6.arpa") {
        // 8 nibbles and ip6.arpa: the /32.
        return last_labels(name, 10);
    }
    let (rest, tld) = split_last(name);
    let (_, second) = split_last(rest);
    let country = tld.len() == 2 && tld.bytes().all(|b| b.is_ascii_alphabetic());
    if country && GENERIC.binary_search(&second).is_ok() {
        last_labels(name, 3)
    } else {
        last_labels(name, 2)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn domains() {
        for (name, domain) in [
            ("x7f3k.victim.com.br", "victim.com.br"),
            ("a.b.victim.com.br", "victim.com.br"),
            ("www.bbc.co.uk", "bbc.co.uk"),
            ("www.example.com", "example.com"),
            ("deep.sub.example.org.", "example.org"),
            ("example.com", "example.com"),
            ("google.de", "google.de"),
            ("x.google.de", "google.de"),
            ("com.br", "com.br"),
            ("localhost", "localhost"),
            ("nas.lan", "nas.lan"),
            ("", ""),
            ("t.co", "t.co"),
            ("abc.t.co", "t.co"),
            ("4.3.2.1.in-addr.arpa", "2.1.in-addr.arpa"),
            ("in-addr.arpa", "in-addr.arpa"),
            (
                "b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.ip6.arpa",
                "0.0.0.0.1.2.3.4.ip6.arpa",
            ),
            ("x.gov.br", "x.gov.br"),
            ("registro.nic.br", "nic.br"),
            ("mail.web.de", "web.de"),
            ("uol.com.br", "uol.com.br"),
            ("abc.example.xn--p1ai", "example.xn--p1ai"),
        ] {
            assert_eq!(domain_of(name), domain, "{name}");
        }
    }

    #[test]
    fn the_word_list_is_sorted() {
        assert!(GENERIC.windows(2).all(|w| w[0] < w[1]));
    }

    proptest! {
        /// Any name: the domain is a suffix of it, on a label boundary,
        /// of at most 10 labels.
        #[test]
        fn a_domain_is_a_suffix(labels in prop::collection::vec("[a-z0-9-]{1,8}", 0..12)) {
            let name = labels.join(".");
            let name = name.as_str();
            let d = domain_of(name);
            prop_assert!(name.ends_with(d));
            let before = name.len() - d.len();
            prop_assert!(before == 0 || name.as_bytes().get(before - 1) == Some(&b'.'));
            prop_assert!(d.split('.').count() <= 10);
        }
    }
}
