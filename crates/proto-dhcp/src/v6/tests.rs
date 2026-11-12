use proptest::prelude::*;

use super::*;

fn reply(xid: u32) -> Vec<u8> {
    let mut dom = Vec::new();
    encode_name("lab.test", &mut dom);
    Builder::new(msg::REPLY, xid)
        .opt(opt::SERVERID, &duid_ll([2, 0xdc, 0, 0, 0, 1]))
        .opt(opt::CLIENTID, &duid_ll([2, 0, 0, 0, 0, 7]))
        .opt(opt::PREFERENCE, &[9])
        .opt(
            opt::IA_NA,
            &ia_na_body(
                7,
                900,
                1440,
                &[("2001:db8::5".parse().unwrap(), 1800, 3600)],
                None,
            ),
        )
        .opt(
            opt::IA_PD,
            &ia_pd_body(
                7,
                900,
                1440,
                &[("2001:db8:1:100::/56".parse().unwrap(), 1800, 3600)],
                None,
            ),
        )
        .opt(
            opt::DNS_SERVERS,
            &"2001:db8::53".parse::<Ipv6Addr>().unwrap().octets(),
        )
        .opt(opt::DOMAIN_LIST, &dom)
        .opt(opt::NTP_SERVER, &sub(1, &ip6("2001:db8::123").octets()))
        .opt(opt::SOL_MAX_RT, &120u32.to_be_bytes())
        .bytes()
}

#[test]
fn a_reply_decodes() {
    let m = decode(&reply(0xabcdef)).unwrap();
    assert_eq!(m.kind, msg::REPLY);
    assert_eq!(m.xid, 0xabcdef);
    assert_eq!(m.preference, 9);
    assert_eq!(
        m.server_id.as_deref(),
        Some(&duid_ll([2, 0xdc, 0, 0, 0, 1])[..])
    );
    let na = &m.ia_na[0];
    assert_eq!((na.iaid, na.t1, na.t2), (7, 900, 1440));
    assert_eq!(na.addrs[0].addr, "2001:db8::5".parse::<Ipv6Addr>().unwrap());
    assert_eq!(
        m.ia_pd[0].prefixes[0].prefix.to_string(),
        "2001:db8:1:100::/56"
    );
    assert_eq!(m.dns, vec!["2001:db8::53".parse::<Ipv6Addr>().unwrap()]);
    assert_eq!(m.domains, vec!["lab.test"]);
    assert_eq!(m.ntp, vec![NtpSource::Server(ip6("2001:db8::123"))]);
    assert_eq!(m.sol_max_rt, Some(120));
    assert_eq!(m.status_code(), status::SUCCESS);
}

#[test]
fn client_messages_round_trip() {
    let duid = duid_ll([2, 0, 0, 0, 0, 7]);
    let out = Outgoing {
        kind: msg::SOLICIT,
        xid: 0x123456,
        client_id: &duid,
        server_id: None,
        elapsed_cs: 0,
        rapid_commit: true,
        ia_na: Some(IaReq {
            iaid: 7,
            ..IaReq::default()
        }),
        ia_pd: Some(IaReq {
            iaid: 7,
            addrs: Vec::new(),
            prefixes: vec!["::/56".parse().unwrap()],
        }),
        oro: &REQUESTED,
    }
    .encode();
    let m = decode_client(&out).unwrap();
    assert_eq!((m.kind, m.xid), (msg::SOLICIT, 0x123456));
    assert_eq!(m.client_id.as_deref(), Some(&duid[..]));
    assert!(m.rapid_commit);
    assert_eq!(m.elapsed_cs, Some(0));
    // RFC 9915 §18.2.1: the Solicit's ORO asks for SOL_MAX_RT.
    assert!(m.oro.contains(&opt::SOL_MAX_RT));
    let pd = m.ia_pd.unwrap();
    assert_eq!((pd.t1, pd.t2), (0, 0), "§21.21: a client sends T1/T2 0");
    assert_eq!(pd.prefixes[0].prefix.prefix_len(), 56, "a /56 length hint");
    assert!(
        decode(&out).is_err(),
        "a client message is not for a client"
    );
}

#[test]
fn rfc_option_rules() {
    // §21.6/§21.22: preferred > valid → the entry is discarded.
    let bad = Builder::new(msg::REPLY, 1)
        .opt(opt::SERVERID, &[0, 3, 0, 1, 1, 2, 3, 4, 5, 6])
        .opt(
            opt::IA_NA,
            &ia_na_body(1, 0, 0, &[("2001:db8::1".parse().unwrap(), 10, 5)], None),
        )
        .opt(
            opt::IA_PD,
            &ia_pd_body(1, 0, 0, &[("2001:db8::/48".parse().unwrap(), 10, 5)], None),
        )
        .opt(opt::SOL_MAX_RT, &5u32.to_be_bytes())
        .bytes();
    let m = decode(&bad).unwrap();
    assert!(m.ia_na[0].addrs.is_empty() && m.ia_na[0].dropped.len() == 1);
    assert!(m.ia_pd[0].prefixes.is_empty() && m.ia_pd[0].dropped.len() == 1);
    // §21.24: SOL_MAX_RT outside 60..=86400 is ignored.
    assert_eq!(m.sol_max_rt, None);
    // Status inside an IA, with its message.
    let st = Builder::new(msg::REPLY, 1)
        .opt(
            opt::IA_PD,
            &ia_pd_body(1, 0, 0, &[], Some((status::NO_PREFIX_AVAIL, "none left"))),
        )
        .bytes();
    let m = decode(&st).unwrap();
    assert_eq!(m.ia_pd[0].status_code(), status::NO_PREFIX_AVAIL);
    assert_eq!(
        m.ia_pd[0].status.as_ref().unwrap().text(),
        "NoPrefixAvail (none left)"
    );
}

#[test]
fn hostile_messages_are_refused_not_panicked_on() {
    // What dhcproto 0.15 gets wrong: Status Code of length 0 and 1, a
    // Preference longer than 1 byte, a Rapid Commit with data.
    for body in [&[][..], &[0][..]] {
        let m = Builder::new(msg::REPLY, 1)
            .opt(opt::STATUS_CODE, body)
            .bytes();
        let d = decode(&m).unwrap();
        assert!(d.status.is_none() || body.len() >= 2);
    }
    let m = Builder::new(msg::REPLY, 1)
        .opt(opt::PREFERENCE, &[1, 2, 3, 4, 5])
        .opt(opt::RAPID_COMMIT, &[9, 9])
        .opt(opt::SERVERID, &[0, 3, 0, 1, 1, 2, 3, 4, 5, 6])
        .bytes();
    let d = decode(&m).unwrap();
    assert!(d.server_id.is_some(), "the next option is still read right");
    // An option running past the end, at the top and inside an IA.
    let mut cut = reply(1);
    cut.truncate(cut.len() - 3);
    assert!(decode(&cut).is_err());
    let inner = Builder::new(msg::REPLY, 1)
        .opt(
            opt::IA_NA,
            &[0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0, 30, 1],
        )
        .bytes();
    assert!(decode(&inner).is_err());
    assert!(decode(&[msg::RELAY_REPL, 0, 0, 0]).is_err());
    assert!(decode(&vec![msg::REPLY; MAX_MESSAGE + 1]).is_err());
    // Too many options.
    let mut many = Builder::new(msg::REPLY, 1);
    for _ in 0..=MAX_OPTIONS {
        many = many.opt(99, &[]);
    }
    assert!(decode(&many.bytes()).is_err());
}

#[test]
fn names_and_duids() {
    let mut b = Vec::new();
    encode_name("a.example.com", &mut b);
    encode_name("lab.test.", &mut b);
    assert_eq!(domain_list(&b).unwrap(), vec!["a.example.com", "lab.test"]);
    assert!(domain_list(&[0xc0, 0x0c]).is_none(), "no compression");
    assert!(domain_list(&[3, b'a', b' ', b'c', 0]).is_none());
    let d = duid_ll([2, 0xdc, 0, 0, 0, 1]);
    assert_eq!(duid_mac(&d), Some([2, 0xdc, 0, 0, 0, 1]));
    let llt = [0, 1, 0, 1, 0, 0, 0, 9, 1, 2, 3, 4, 5, 6];
    assert_eq!(duid_mac(&llt), Some([1, 2, 3, 4, 5, 6]));
    assert_eq!(duid_mac(&[0, 2, 0, 0, 0, 9]), None);
    assert!(duid_text(&d).contains("02:DC:00:00:00:01"));
}

#[test]
fn options_are_described() {
    let raw = raw_options(&reply(1));
    let named: Vec<(&str, String)> = raw.iter().map(|(c, d)| describe(*c, d)).collect();
    assert!(
        named
            .iter()
            .any(|(n, v)| *n == "ia-pd" && v.contains("2001:db8:1:100::/56"))
    );
    assert!(
        named
            .iter()
            .any(|(n, v)| *n == "dns-servers" && v == "2001:db8::53")
    );
    assert!(
        named
            .iter()
            .any(|(n, v)| *n == "domain-list" && v == "lab.test")
    );
    assert_eq!(describe(9999, &[1, 2]), ("", "0x0102".into()));
}

fn sub(code: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    put(&mut out, code, body);
    out
}

fn ip6(s: &str) -> Ipv6Addr {
    s.parse().unwrap()
}

fn with(options: &[(u16, Vec<u8>)]) -> Incoming {
    let mut b = Builder::new(msg::REPLY, 1).opt(opt::SERVERID, &duid_ll([2, 0, 0, 0, 0, 1]));
    for (code, data) in options {
        b = b.opt(*code, data);
    }
    decode(&b.bytes()).unwrap()
}

/// RFC 5908 §4: one time source per option, the option repeated; §4.1
/// address, §4.2 multicast group, §4.3 FQDN in RFC 9915 §10 form.
#[test]
fn ntp_server_options_give_every_time_source() {
    let mut fqdn = Vec::new();
    encode_name("ntp.example.net", &mut fqdn);
    let m = with(&[
        (opt::NTP_SERVER, sub(1, &ip6("2001:db8::123").octets())),
        (opt::NTP_SERVER, sub(2, &ip6("ff02::101").octets())),
        (opt::NTP_SERVER, sub(3, &fqdn)),
    ]);
    assert_eq!(
        m.ntp,
        vec![
            NtpSource::Server(ip6("2001:db8::123")),
            NtpSource::Multicast(ip6("ff02::101")),
            NtpSource::Name("ntp.example.net".into()),
        ]
    );
}

/// dnsmasq puts every server in one option, against RFC 5908 §4's "one, and
/// only one"; systemd and odhcp6c read it, so do we. Repeats count once.
#[test]
fn several_suboptions_in_one_option_are_read() {
    let mut body = sub(1, &ip6("2001:db8::1").octets());
    body.extend(sub(1, &ip6("2001:db8::2").octets()));
    body.extend(sub(1, &ip6("2001:db8::1").octets()));
    let m = with(&[(opt::NTP_SERVER, body)]);
    assert_eq!(
        m.ntp,
        vec![
            NtpSource::Server(ip6("2001:db8::1")),
            NtpSource::Server(ip6("2001:db8::2"))
        ]
    );
}

/// §4.1 a unicast server, §4.2 a multicast group: the wrong kind, a wrong
/// length, a broken FQDN or an unknown suboption are skipped, the rest kept.
#[test]
fn bad_suboptions_are_skipped() {
    let mut body = sub(1, &ip6("ff05::101").octets()); // multicast as server
    body.extend(sub(2, &ip6("2001:db8::9").octets())); // unicast as group
    body.extend(sub(1, &[0; 15])); // short
    body.extend(sub(1, &Ipv6Addr::LOCALHOST.octets()));
    body.extend(sub(3, &[3, b'a', b' ', b'b', 0])); // not a host name
    body.extend(sub(9, &[1, 2, 3])); // unknown (IANA may add, §8)
    body.extend(sub(1, &ip6("2001:db8::7").octets()));
    let m = with(&[(opt::NTP_SERVER, body)]);
    assert_eq!(m.ntp, vec![NtpSource::Server(ip6("2001:db8::7"))]);
}

/// A truncated suboption breaks only its option, never the lease.
#[test]
fn a_broken_ntp_option_keeps_the_lease() {
    let m = with(&[
        (opt::NTP_SERVER, vec![0, 1, 0, 16, 1, 2]),
        (opt::DNS_SERVERS, ip6("2001:db8::53").octets().to_vec()),
    ]);
    assert!(m.ntp.is_empty());
    assert_eq!(m.dns, vec![ip6("2001:db8::53")]);
}

/// RFC 5908 §7 deprecates the SNTP option (RFC 4075): it counts only alone.
#[test]
fn the_sntp_option_counts_only_without_an_ntp_option() {
    let sntp = ip6("2001:db8::31").octets().to_vec();
    let m = with(&[(opt::SNTP_SERVERS, sntp.clone())]);
    assert_eq!(m.ntp, vec![NtpSource::Server(ip6("2001:db8::31"))]);
    let m = with(&[
        (opt::SNTP_SERVERS, sntp),
        (opt::NTP_SERVER, sub(1, &ip6("2001:db8::56").octets())),
    ]);
    assert_eq!(m.ntp, vec![NtpSource::Server(ip6("2001:db8::56"))]);
}

/// Hostile input: at most MAX_NTP sources, however many come.
#[test]
fn time_sources_are_bounded() {
    let options: Vec<(u16, Vec<u8>)> = (1..=40u16)
        .map(|i| {
            let a = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, i);
            (opt::NTP_SERVER, sub(1, &a.octets()))
        })
        .collect();
    assert_eq!(with(&options).ntp.len(), MAX_NTP);
}

proptest! {
    #[test]
    fn decode_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
        let _ = decode(&bytes);
        let _ = decode_client(&bytes);
        for (c, d) in raw_options(&bytes) {
            let _ = describe(c, &d);
        }
    }

    #[test]
    fn mangled_replies_never_panic(cuts in proptest::collection::vec((0usize..200, any::<u8>()), 0..12)) {
        let mut b = reply(7);
        for (at, v) in cuts {
            let n = b.len();
            if let Some(x) = b.get_mut(at % n) {
                *x = v;
            }
        }
        if let Ok(m) = decode(&b) {
            prop_assert!(m.ia_na.len() <= MAX_IA_ENTRIES);
            prop_assert!(m.ntp.len() <= MAX_NTP);
            for ia in m.ia_na.iter().chain(&m.ia_pd) {
                for a in &ia.addrs {
                    prop_assert!(a.preferred <= a.valid);
                }
                for p in &ia.prefixes {
                    prop_assert!(p.preferred <= p.valid);
                }
            }
        }
        for (c, d) in raw_options(&b) {
            let _ = describe(c, &d);
        }
    }

    #[test]
    fn describe_never_panics(code in any::<u16>(), data in proptest::collection::vec(any::<u8>(), 0..80)) {
        let _ = describe(code, &data);
        let _ = domain_list(&data);
        let _ = duid_mac(&data);
    }
}
