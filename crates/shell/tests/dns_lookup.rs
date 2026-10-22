//! G6.6: `/tool dns-lookup` (and `dns-lookup` from any menu) reaches
//! `tool.dns.query` of a real engine, the name as a bare word, the options
//! as RouterOS spells them.

use corerouter_engine::Session;
use corerouter_shell::Registry;
use corerouter_shell::parse::{self, Arg, Parsed};

#[test]
fn dns_lookup_is_a_tool_with_a_positional_name() {
    let reg = Registry::from_list(&Session::virtual_lab().list());
    for line in [
        "/tool dns-lookup example.com type=MX dnssec=yes",
        "dns-lookup example.com type=MX dnssec=yes",
        "/tool dns query example.com type=MX dnssec=yes",
    ] {
        let got = parse::parse(&reg, &[], line).unwrap_or_else(|e| panic!("{line}: {e:?}"));
        let Parsed::Command { id, args, .. } = got else {
            panic!("{line}: {got:?}");
        };
        assert_eq!(id, "tool.dns.query", "{line}");
        assert_eq!(
            args,
            [
                Arg::Positional("example.com".into()),
                Arg::Pair {
                    key: "type".into(),
                    value: "MX".into()
                },
                Arg::Pair {
                    key: "dnssec".into(),
                    value: "yes".into()
                },
            ],
            "{line}"
        );
    }
}
