//! Subscriber notices (G4.10) in the firewall's own table, `inet
//! corerouter`: the profiles' lists are its address-list sets, so a
//! subscriber entering or leaving a list (RADIUS, CoA, API, a lease) is one
//! set element, and the rules below never change per subscriber.
//!
//! | Chain | Hook | What |
//! |---|---|---|
//! | `notice_dstnat` | prerouting, `dstnat - 5` (ahead of the operator's dst-nat) | per profile and family, one rule: a member jumps to `notice_nat<4|6>_<profile>`, where port 80 of a member to the router's portal: every HTTP request (`intercept=http`) or only to the OS probe hosts' addresses (`sn-probe`); the walled garden and, for notice/throttle, those who saw the page (`sn-seen-<profile>`) are left alone |
//! | `notice_forward` | forward, `filter - 5` | block mode, the same jump to `notice_block<4|6>_<profile>`: the walled garden and DNS pass, TCP gets a reset and the rest ICMP administratively prohibited at once (an app fails fast instead of hanging) |
//!
//! A non-member's packet meets one set lookup per profile and hook, nothing
//! else (the chains of a profile run only for its members; measured in
//! `hal-linux/benches/netns_notice.rs`). A `return` leaves the profile's
//! chain: the packet goes on as if it were not a member.
//!
//! A verdict here does not skip the operator's own chains (nftables runs
//! every base chain of a hook): an accept means "not ours", a reject is
//! final. The router's own addresses are never redirected (`fib daddr type
//! != local`), so WebFig and the portal itself stay reachable.

use std::fmt::Write as _;

use corerouter_model::Config;
use corerouter_model::firewall::Name;
use corerouter_model::subscriber_notice::{
    GARDEN_LIST, Intercept, Mode, PROBE_LIST, Profile, SubscriberNotices, seen_list,
};

/// The set of the walled garden's fixed prefixes (`dst_address`).
const GARDEN4: &str = "notice_g4";
const GARDEN6: &str = "notice_g6";

fn name(s: &str) -> Option<Name> {
    s.parse().ok()
}

/// Whether the config has a profile that acts.
pub fn on(cfg: &Config) -> bool {
    cfg.ip.subscriber_notice.active().next().is_some()
}

/// The address lists the notice rules read (each needs its sets).
pub fn lists(cfg: &Config) -> Vec<Name> {
    let sn = &cfg.ip.subscriber_notice;
    if !on(cfg) {
        return Vec::new();
    }
    let mut out: Vec<Name> = [GARDEN_LIST, PROBE_LIST]
        .iter()
        .filter_map(|s| name(s))
        .collect();
    for p in sn.active() {
        out.push(p.address_list.clone());
        if p.mode != Mode::Block
            && let Some(n) = name(&seen_list(&p.name))
        {
            out.push(n);
        }
    }
    out
}

fn target(sn: &SubscriberNotices, v4: bool) -> String {
    let port = sn.settings.port;
    match sn.settings.portal_address {
        Some(std::net::IpAddr::V4(a)) if v4 => format!("dnat ip to {a}:{port}"),
        Some(std::net::IpAddr::V6(a)) if !v4 => format!("dnat ip6 to [{a}]:{port}"),
        _ => format!("redirect to :{port}"),
    }
}

/// A profile's chain names (one per family and hook).
fn chain(kind: &str, p: &Profile, fam: &str) -> String {
    format!("notice_{kind}{fam}_{}", p.name)
}

/// One profile and family: the jump from each base chain (the only rule a
/// non-member's packet meets: one set lookup) and the profile's own chains.
fn rules(
    sn: &SubscriberNotices,
    p: &Profile,
    v4: bool,
    base: &mut [Vec<String>; 2],
    chains: &mut Vec<(String, Vec<String>)>,
) {
    let (ip, fam) = if v4 { ("ip", "4") } else { ("ip6", "6") };
    let member = format!("{ip} saddr @al{fam}_{}", p.address_list);
    let garden = [
        format!("@al{fam}_{GARDEN_LIST}"),
        format!("@{}", if v4 { GARDEN4 } else { GARDEN6 }),
    ];
    let tag = format!("comment \"notice:{}\"", p.name);
    let mut nat = Vec::new();
    for g in &garden {
        nat.push(format!("{ip} daddr {g} return"));
    }
    if p.mode != Mode::Block {
        nat.push(format!("{ip} saddr @al{fam}_{} return", seen_list(&p.name)));
    }
    let to = target(sn, v4);
    match p.intercept {
        Intercept::Http => nat.push(format!("tcp dport 80 fib daddr type != local counter {to} {tag}")),
        Intercept::Probes => nat.push(format!(
            "{ip} daddr @al{fam}_{PROBE_LIST} tcp dport 80 fib daddr type != local counter {to} {tag}"
        )),
    }
    let name = chain("nat", p, fam);
    base[0].push(format!("{member} jump {name}"));
    chains.push((name, nat));
    if p.mode == Mode::Block {
        let mut fwd = Vec::new();
        for g in &garden {
            fwd.push(format!("{ip} daddr {g} return"));
        }
        fwd.push("meta l4proto { tcp, udp } th dport 53 return".to_owned());
        fwd.push(format!(
            "meta l4proto tcp counter reject with tcp reset {tag}"
        ));
        fwd.push(format!("counter reject with icmpx admin-prohibited {tag}"));
        let name = chain("block", p, fam);
        base[1].push(format!("{member} jump {name}"));
        chains.push((name, fwd));
    }
}

/// The sets and chains, inside `table inet corerouter { … }` (empty when
/// no profile acts).
pub fn render(cfg: &Config, out: &mut String) {
    if !on(cfg) {
        return;
    }
    let sn = &cfg.ip.subscriber_notice;
    for (set, ty, v4) in [(GARDEN4, "ipv4_addr", true), (GARDEN6, "ipv6_addr", false)] {
        let items: Vec<String> = sn
            .walled_garden
            .iter()
            .filter(|g| !g.disabled)
            .filter_map(|g| g.dst_address)
            .filter(|n| n.addr().is_ipv4() == v4)
            .map(|n| n.to_string())
            .collect();
        let elems = if items.is_empty() {
            String::new()
        } else {
            format!("\t\telements = {{ {} }}\n", items.join(", "))
        };
        let _ = write!(
            out,
            "\tset {set} {{\n\t\ttype {ty}\n\t\tflags interval\n\t\tauto-merge\n{elems}\t}}\n"
        );
    }
    let mut base: [Vec<String>; 2] = [Vec::new(), Vec::new()];
    let mut chains = Vec::new();
    for p in sn.active() {
        for v4 in [true, false] {
            rules(sn, p, v4, &mut base, &mut chains);
        }
    }
    for (name, rules) in &chains {
        let _ = writeln!(out, "\tchain {name} {{");
        for r in rules {
            let _ = writeln!(out, "\t\t{r}");
        }
        let _ = writeln!(out, "\t}}");
    }
    let [nat, fwd] = base;
    let _ = writeln!(
        out,
        "\tchain notice_dstnat {{\n\t\ttype nat hook prerouting priority dstnat - 5; policy accept;"
    );
    for r in &nat {
        let _ = writeln!(out, "\t\t{r}");
    }
    let _ = writeln!(out, "\t}}");
    if !fwd.is_empty() {
        let _ = writeln!(
            out,
            "\tchain notice_forward {{\n\t\ttype filter hook forward priority filter - 5; policy accept;"
        );
        for r in &fwd {
            let _ = writeln!(out, "\t\t{r}");
        }
        let _ = writeln!(out, "\t}}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_model::ItemId;
    use corerouter_model::subscriber_notice::GardenEntry;

    fn cfg() -> Config {
        let mut c = Config::default();
        let sn = &mut c.ip.subscriber_notice;
        sn.profiles.push(Profile::new(
            ItemId(1),
            "atraso".parse().unwrap(),
            Mode::Block,
            "bloqueados".parse().unwrap(),
        ));
        sn.profiles.push(Profile::new(
            ItemId(2),
            "aviso".parse().unwrap(),
            Mode::Notice,
            "aviso".parse().unwrap(),
        ));
        sn.walled_garden.push(GardenEntry {
            id: ItemId(3),
            dst_host: String::new(),
            dst_address: Some("203.0.113.0/24".parse().unwrap()),
            disabled: false,
            comment: String::new(),
        });
        c
    }

    #[test]
    fn rules_per_mode() {
        let c = cfg();
        let mut out = String::new();
        render(&c, &mut out);
        assert!(out.contains("elements = { 203.0.113.0/24 }"), "{out}");
        // Block: every HTTP request, the rest refused at once.
        // One lookup per packet in each base chain, per profile and family.
        assert!(
            out.contains("ip saddr @al4_bloqueados jump notice_nat4_atraso"),
            "{out}"
        );
        assert!(
            out.contains("ip saddr @al4_bloqueados jump notice_block4_atraso"),
            "{out}"
        );
        assert!(
            out.contains("ip6 saddr @al6_bloqueados jump notice_block6_atraso"),
            "{out}"
        );
        let block = out.split("chain notice_block4_atraso {").nth(1).unwrap();
        assert!(
            block.contains("meta l4proto { tcp, udp } th dport 53 return"),
            "{out}"
        );
        assert!(
            block.contains("meta l4proto tcp counter reject with tcp reset"),
            "{out}"
        );
        assert!(
            block.contains("counter reject with icmpx admin-prohibited"),
            "{out}"
        );
        let nat = out.split("chain notice_nat4_atraso {").nth(1).unwrap();
        assert!(
            nat.contains("tcp dport 80 fib daddr type != local counter redirect to :8880"),
            "{out}"
        );
        // Notice: only the probes, nothing refused, the seen ones left alone.
        let nat = out.split("chain notice_nat4_aviso {").nth(1).unwrap();
        assert!(nat.contains("ip daddr @al4_sn-probe tcp dport 80"), "{out}");
        assert!(nat.contains("ip saddr @al4_sn-seen-aviso return"), "{out}");
        assert!(!out.contains("notice_block4_aviso"), "{out}");
        let l: Vec<String> = lists(&c).iter().map(ToString::to_string).collect();
        assert_eq!(
            l,
            [
                "sn-garden",
                "sn-probe",
                "bloqueados",
                "aviso",
                "sn-seen-aviso"
            ]
        );
    }

    #[test]
    fn portal_address_and_off() {
        let mut c = cfg();
        c.ip.subscriber_notice.settings.portal_address = Some("10.0.0.1".parse().unwrap());
        let mut out = String::new();
        render(&c, &mut out);
        assert!(out.contains("dnat ip to 10.0.0.1:8880"), "{out}");
        let nat6 = out.split("chain notice_nat6_atraso {").nth(1).unwrap();
        assert!(
            nat6.contains("tcp dport 80 fib daddr type != local counter redirect to :8880"),
            "{out}"
        );
        for p in &mut c.ip.subscriber_notice.profiles {
            p.disabled = true;
        }
        let mut out = String::new();
        render(&c, &mut out);
        assert!(out.is_empty() && lists(&c).is_empty());
    }
}
