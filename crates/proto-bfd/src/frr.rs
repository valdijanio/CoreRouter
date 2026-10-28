//! The `bfd` block of FRR's config (G3.6b). `bfdd` runs with
//! `--dplaneaddr` and CoreRouter's engine as its data plane: it hands
//! every session it creates (BGP `neighbor … bfd profile`, OSPF `ip ospf
//! bfd profile`, the peers here) to the engine, which sends and receives
//! the packets, and it tells `bgpd`/`ospfd` what the engine reports. So
//! `bfdd` must know the profiles the protocols name and the operator's
//! peers; the timers it hands over are these.
//!
//! Rendered only when something uses BFD (an FRR without BFD keeps an
//! empty `bfd` context out of its config).

use std::collections::BTreeSet;
use std::fmt::Write as _;

use corerouter_model::bfd::BfdProfile;
use corerouter_model::{Config, Issue};

/// Commit checks (G3.6b): a profile named by a peer, a BGP connection or
/// template or an OSPF interface template exists; a multihop peer has a
/// local address (RFC 5883 §3: the session is the address pair; FRR's
/// `peer … multihop` asks for it too); a profile with auth has a key.
pub fn validate(cfg: &Config) -> Vec<Issue> {
    let r = &cfg.routing;
    let mut out = Vec::new();
    let missing = |name: &str| r.bfd.profile(name).is_none();
    for p in r.bfd.peers.values() {
        if missing(&p.profile) {
            out.push(Issue::new(
                format!("routing.bfd.peers.{}.profile", p.name),
                format!("no BFD profile {:?}", p.profile),
            ));
        }
        if p.multihop && p.local_address.is_none() {
            out.push(Issue::new(
                format!("routing.bfd.peers.{}.local_address", p.name),
                "a multihop BFD peer needs local_address (RFC 5883 §3: the session is the address pair)",
            ));
        }
    }
    for c in r.bgp_connections.values() {
        if let Some(b) = c.params.bfd.as_deref().filter(|b| missing(b)) {
            out.push(Issue::new(
                format!("routing.bgp_connections.{}.bfd", c.name),
                format!("no BFD profile {b:?} (routing.bfd.profile.add)"),
            ));
        }
    }
    for t in r.bgp_templates.values() {
        if let Some(b) = t.params.bfd.as_deref().filter(|b| missing(b)) {
            out.push(Issue::new(
                format!("routing.bgp_templates.{}.bfd", t.name),
                format!("no BFD profile {b:?} (routing.bfd.profile.add)"),
            ));
        }
    }
    for t in &r.ospf.templates {
        if let Some(b) = t.bfd.as_deref().filter(|b| missing(b)) {
            out.push(Issue::new(
                format!("routing.ospf.templates[{}].bfd", t.id),
                format!("no BFD profile {b:?} (routing.bfd.profile.add)"),
            ));
        }
    }
    for p in r.bfd.all_profiles() {
        if p.auth != corerouter_model::bfd::BfdAuth::None && p.auth_secret.is_empty() {
            out.push(Issue::new(
                format!("routing.bfd.profiles.{}.auth_secret", p.name),
                "authentication without a key",
            ));
        }
    }
    out
}

/// Who asked `bfdd` for a session it hands to the data plane, and the
/// profile whose extras (auth, dampening, minimum TTL) the engine applies:
/// the peers of `routing.bfd`, the BGP connections whose (effective)
/// params name a profile, the OSPF templates with `bfd` that list the
/// session's interface. With nobody found (a session typed into FRR by
/// hand), the profile whose timers match, else one made of the timers.
pub fn users_of(
    cfg: &Config,
    dst: std::net::IpAddr,
    multihop: bool,
    ifname: &str,
    timers: (u32, u32, u8),
) -> (BfdProfile, Vec<String>) {
    let r = &cfg.routing;
    let mut users = Vec::new();
    let mut prof: Option<String> = None;
    for p in r
        .bfd
        .peers
        .values()
        .filter(|p| !p.disabled && p.address == dst && p.multihop == multihop)
    {
        users.push(format!("peer {}", p.name));
        prof.get_or_insert_with(|| p.profile.clone());
    }
    let resolved = corerouter_model::bgp::resolve_templates(&r.bgp_templates);
    for c in r
        .bgp_connections
        .values()
        .filter(|c| c.remote_address == dst)
    {
        if let Ok(eff) = c.effective(&resolved)
            && let Some(b) = eff.bfd
        {
            users.push(format!("BGP {}", c.name));
            prof.get_or_insert(b);
        }
    }
    if !multihop && !ifname.is_empty() {
        for t in r
            .ospf
            .templates
            .iter()
            .filter(|t| t.interfaces.iter().any(|i| i == ifname))
        {
            if let Some(b) = &t.bfd {
                users.push(format!("OSPF {ifname}"));
                prof.get_or_insert_with(|| b.clone());
                break;
            }
        }
    }
    let (tx, rx, mult) = timers;
    let found = prof.and_then(|n| r.bfd.profile(&n)).or_else(|| {
        r.bfd
            .all_profiles()
            .into_iter()
            .find(|p| p.min_tx * 1000 == tx && p.min_rx * 1000 == rx && p.multiplier == mult)
    });
    let profile = found.unwrap_or_else(|| {
        let mut p = BfdProfile::new("bfdd", (tx / 1000).max(1), mult.max(1));
        p.min_rx = (rx / 1000).max(1);
        p
    });
    if users.is_empty() {
        users.push("FRR".into());
    }
    (profile, users)
}

/// Every profile some protocol or peer names.
pub fn used_profiles(cfg: &Config) -> BTreeSet<String> {
    let r = &cfg.routing;
    let mut out: BTreeSet<String> = BTreeSet::new();
    out.extend(
        r.bfd
            .peers
            .values()
            .filter(|p| !p.disabled)
            .map(|p| p.profile.clone()),
    );
    out.extend(
        r.bgp_connections
            .values()
            .filter_map(|c| c.params.bfd.clone()),
    );
    out.extend(
        r.bgp_templates
            .values()
            .filter_map(|t| t.params.bfd.clone()),
    );
    out.extend(r.ospf.templates.iter().filter_map(|t| t.bfd.clone()));
    out
}

fn profile(s: &mut String, p: &BfdProfile) {
    let _ = writeln!(s, " profile {}", p.name);
    let _ = writeln!(s, "  detect-multiplier {}", p.multiplier);
    let _ = writeln!(s, "  receive-interval {}", p.min_rx);
    let _ = writeln!(s, "  transmit-interval {}", p.min_tx);
    if p.passive {
        let _ = writeln!(s, "  passive-mode");
    }
    if p.min_ttl != 254 {
        let _ = writeln!(s, "  minimum-ttl {}", p.min_ttl.min(254));
    }
    let _ = writeln!(s, " exit");
}

/// The `bfd` context: every profile in force (a name nobody defined is
/// left out: the engine refuses it at commit) and the enabled peers.
pub fn render(cfg: &Config) -> String {
    let used = used_profiles(cfg);
    if used.is_empty() {
        return String::new();
    }
    let bfd = &cfg.routing.bfd;
    let mut s = String::from("bfd\n");
    for p in bfd.all_profiles() {
        profile(&mut s, &p);
    }
    for p in bfd.peers.values().filter(|p| !p.disabled) {
        let mut line = format!(" peer {}", p.address);
        if p.multihop {
            line.push_str(" multihop");
        }
        if let Some(l) = p.local_address {
            let _ = write!(line, " local-address {l}");
        }
        if let Some(i) = &p.interface {
            let _ = write!(line, " interface {i}");
        }
        let _ = writeln!(s, "{line}");
        let _ = writeln!(s, "  profile {}", p.profile);
        let _ = writeln!(s, " exit");
    }
    s.push_str("exit\n");
    s
}

#[cfg(test)]
mod tests {
    use corerouter_model::bfd::BfdPeer;

    use super::*;

    #[test]
    fn missing_profiles_and_multihop_without_local() {
        let mut cfg = Config::default();
        cfg.routing.bfd.peers.insert(
            "x".into(),
            BfdPeer {
                name: "x".into(),
                address: "192.0.2.9".parse().unwrap(),
                local_address: None,
                interface: None,
                multihop: true,
                profile: "nope".into(),
                disabled: false,
                comment: String::new(),
            },
        );
        let issues = validate(&cfg);
        assert_eq!(issues.len(), 2, "{issues:?}");
        assert!(issues[0].message.contains("nope"));
        assert!(issues[1].message.contains("RFC 5883"));
    }

    #[test]
    fn dplane_sessions_find_their_users() {
        let mut cfg = Config::default();
        cfg.routing
            .bfd
            .profiles
            .insert("wan".into(), BfdProfile::new("wan", 500, 5));
        cfg.routing.bgp_connections.insert(
            "up1".into(),
            serde_json::from_value(serde_json::json!({
                "name": "up1", "instance": "default", "remote_address": "192.0.2.6",
                "params": {"bfd": "wan"}
            }))
            .unwrap(),
        );
        let (p, users) = users_of(
            &cfg,
            "192.0.2.6".parse().unwrap(),
            false,
            "",
            (500_000, 500_000, 5),
        );
        assert_eq!(p.name, "wan");
        assert_eq!(users, ["BGP up1"]);
        // Typed into FRR by hand: the profile with the same timers.
        let (p, users) = users_of(
            &cfg,
            "192.0.2.9".parse().unwrap(),
            false,
            "",
            (50_000, 50_000, 3),
        );
        assert_eq!(p.name, "fast");
        assert_eq!(users, ["FRR"]);
        let (p, _) = users_of(
            &cfg,
            "192.0.2.9".parse().unwrap(),
            false,
            "",
            (70_000, 80_000, 4),
        );
        assert_eq!(
            (p.name.as_str(), p.min_tx, p.min_rx, p.multiplier),
            ("bfdd", 70, 80, 4)
        );
    }

    #[test]
    fn nothing_without_users() {
        assert_eq!(render(&Config::default()), "");
    }

    #[test]
    fn profiles_and_peers() {
        let mut cfg = Config::default();
        let mut wan = BfdProfile::new("wan", 500, 5);
        wan.passive = true;
        wan.min_ttl = 250;
        cfg.routing.bfd.profiles.insert("wan".into(), wan);
        cfg.routing.bfd.peers.insert(
            "rr".into(),
            BfdPeer {
                name: "rr".into(),
                address: "198.51.100.9".parse().unwrap(),
                local_address: Some("10.0.0.1".parse().unwrap()),
                interface: None,
                multihop: true,
                profile: "wan".into(),
                disabled: false,
                comment: String::new(),
            },
        );
        let out = render(&cfg);
        assert!(out.starts_with("bfd\n profile default\n  detect-multiplier 3\n  receive-interval 300\n  transmit-interval 300\n exit\n"), "{out}");
        assert!(out.contains(" profile fast\n  detect-multiplier 3\n  receive-interval 50\n  transmit-interval 50\n exit\n"));
        assert!(out.contains(" profile wan\n  detect-multiplier 5\n  receive-interval 500\n  transmit-interval 500\n  passive-mode\n  minimum-ttl 250\n exit\n"));
        assert!(
            out.ends_with(
                " peer 198.51.100.9 multihop local-address 10.0.0.1\n  profile wan\n exit\nexit\n"
            ),
            "{out}"
        );
    }
}
