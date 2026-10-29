//! The FRR configuration of a CoreRouter config: the renders of the
//! `proto-*` crates, joined into one tree, and which FRR daemon takes each
//! context.

use corerouter_model::Config;

use crate::conf::{Conf, ParseError};

/// An FRR daemon CoreRouter talks to, by the name of its vty socket
/// (`/var/run/frr/<name>.vty`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Daemon {
    Zebra,
    /// The management daemon (FRR 9+): holds the config of the converted
    /// daemons and the shared filters (prefix-lists) for them.
    Mgmtd,
    Bgpd,
    Ospfd,
    Ospf6d,
    Ldpd,
    Bfdd,
}

impl Daemon {
    pub const ALL: [Daemon; 7] = [
        Daemon::Zebra,
        Daemon::Mgmtd,
        Daemon::Bgpd,
        Daemon::Ospfd,
        Daemon::Ospf6d,
        Daemon::Ldpd,
        Daemon::Bfdd,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Daemon::Zebra => "zebra",
            Daemon::Mgmtd => "mgmtd",
            Daemon::Bgpd => "bgpd",
            Daemon::Ospfd => "ospfd",
            Daemon::Ospf6d => "ospf6d",
            Daemon::Ldpd => "ldpd",
            Daemon::Bfdd => "bfdd",
        }
    }
}

/// The FRR contexts CoreRouter owns, by the start of their header: they
/// hold exactly what the render says (anything else typed there by hand is
/// removed on the next sync). Every other context of FRR's config (`frr
/// version`, `hostname`, `log`, interfaces, `line vty`) is left alone.
/// A `proto-*` render that adds a context kind adds it here, with every
/// daemon that takes it: a shared filter (`ip prefix-list`, `route-map`)
/// is typed in mgmtd (FRR 10 hands it to zebra and staticd, which refuse
/// it on their own vty) and in each unconverted routing daemon (bgpd,
/// ospfd). A daemon left out keeps a stale copy, and `vtysh`, which shows
/// the copies merged, then hides the difference (measured: `frr-reload.py`
/// skipped lines the zebra copy still had).
pub const OWNED: Owned = &[
    ("router bgp ", &[Daemon::Bgpd]),
    // G3.4: OSPF. `router ospf6` before `router ospf`, which is a prefix
    // of it; the OSPF filters (`CR-O2-…` IPv4, `CR-O3-…` IPv6) before the
    // BGP ones (`CR-`), whose prefix they share. An interface context holds
    // only the lines [`CHILDREN`] gives each daemon.
    ("router ospf6", &[Daemon::Ospf6d]),
    ("router ospf", &[Daemon::Ospfd]),
    ("interface ", &[Daemon::Ospfd, Daemon::Ospf6d]),
    ("key chain CR-", &[Daemon::Ospfd, Daemon::Ospf6d]),
    ("ip prefix-list CR-O2-", &[Daemon::Ospfd]),
    ("ipv6 prefix-list CR-O3-", &[Daemon::Ospf6d]),
    ("route-map CR-O2-", &[Daemon::Ospfd]),
    ("route-map CR-O3-", &[Daemon::Ospf6d]),
    // G3.2b: the `/routing filter` render, all named `CR-` (the operator's
    // own lists and maps are left alone). Only bgpd filters with them.
    ("ip prefix-list CR-", &[Daemon::Bgpd]),
    ("ipv6 prefix-list CR-", &[Daemon::Bgpd]),
    ("bgp as-path access-list CR-", &[Daemon::Bgpd]),
    ("bgp community-list standard CR-", &[Daemon::Bgpd]),
    ("bgp large-community-list standard CR-", &[Daemon::Bgpd]),
    // G3.9fc: extended communities (RFC 4360).
    ("bgp extcommunity-list standard CR-", &[Daemon::Bgpd]),
    ("bgp extcommunity-list expanded CR-", &[Daemon::Bgpd]),
    ("route-map CR-", &[Daemon::Bgpd]),
    // G3.2c: RPKI validators and the route-map that drops invalid routes;
    // `match rpki` exists only in bgpd (its rpki module).
    ("rpki", &[Daemon::Bgpd]),
    ("route-map CR-RPKI-", &[Daemon::Bgpd]),
    // G3.5: LDP, and zebra's label block when `/mpls settings` narrows it.
    ("mpls ldp", &[Daemon::Ldpd]),
    ("mpls label dynamic-block", &[Daemon::Zebra]),
    // G3.6b: profiles and peers for bfdd (CoreRouter's engine is its data plane).
    ("bfd", &[Daemon::Bfdd]),
];

/// A table of owned contexts: header prefix → daemons that take it.
pub type Owned = &'static [(&'static str, &'static [Daemon])];

/// Contexts a daemon owns only part of: under a header with this prefix,
/// the daemon takes (and reads back) only the lines starting with one of
/// these. Every daemon prints `interface X` with its own lines and the
/// interface's `description` (zebra's): `ospfd` keeps `ip ospf …`,
/// `ospf6d` `ipv6 ospf6 …`, and an interface left empty is not ours.
pub const CHILDREN: &[(&str, Daemon, &[&str])] = &[
    ("interface ", Daemon::Ospfd, &["ip ospf ", "no ip ospf "]),
    ("interface ", Daemon::Ospf6d, &["ipv6 ospf6 "]),
];

/// `n` as daemon `d` owns it: the children [`CHILDREN`] gives `d` (all of
/// them for a context not listed); `None` when a partly owned context is
/// left with nothing.
pub fn part_of(d: Daemon, n: &crate::conf::Node) -> Option<crate::conf::Node> {
    let rule = CHILDREN
        .iter()
        .find(|(h, dd, _)| *dd == d && n.line.starts_with(h));
    match rule {
        None => Some(n.clone()),
        Some((_, _, keep)) => {
            let children: Vec<_> = n
                .children
                .iter()
                .filter(|c| keep.iter().any(|k| c.line.starts_with(k)))
                .cloned()
                .collect();
            (!children.is_empty()).then(|| crate::conf::Node {
                line: n.line.clone(),
                children,
            })
        }
    }
}

/// Whether CoreRouter owns the top-level context `line`.
pub fn owned(line: &str) -> bool {
    OWNED.iter().any(|(p, _)| line.starts_with(p))
}

/// The daemons a top-level context goes to under `table` (shared contexts
/// such as `route-map` go to every daemon that filters with it, as vtysh
/// does).
pub fn daemons_of(table: Owned, line: &str) -> &'static [Daemon] {
    table
        .iter()
        .find(|(p, _)| line.starts_with(p))
        .map(|(_, d)| *d)
        .unwrap_or(&[])
}

/// Why a config cannot be rendered.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RenderError {
    /// A `proto-*` render refused (a key that does not open).
    #[error("{0}")]
    Proto(String),
    #[error("render: {0}")]
    Parse(#[from] ParseError),
}

/// What FRR should run for `cfg` (the owned part only); `open` opens the
/// sealed TCP MD5 keys.
pub fn render(cfg: &Config, open: corerouter_proto_bgp::Opener<'_>) -> Result<Conf, RenderError> {
    let mut text = corerouter_proto_bgp::render_config(cfg, open).map_err(RenderError::Proto)?;
    // G3.4: the same key opener (both seal with the engine's key).
    text.push_str(&corerouter_proto_ospf::frr::render(cfg, open).map_err(RenderError::Proto)?);
    text.push_str(&corerouter_proto_bfd::frr::render(cfg));
    text.push_str(
        &corerouter_proto_mpls::render_frr(&cfg.routing.mpls, open).map_err(RenderError::Proto)?,
    );
    // G3.4f: while SR runs, LDP's labels keep out of the SR blocks (zebra
    // refuses an SRGB inside a narrowed dynamic block, and with the default
    // one LDP could take an SRGB label first).
    if let Some(b) = corerouter_proto_ospf::sr::dynamic_block(cfg) {
        text.push_str(&format!("mpls label dynamic-block {} {}\n", b.start, b.end));
    }
    let mut conf = Conf::parse(&text)?;
    ldp_sync(&mut conf, cfg);
    Ok(conf)
}

/// G3.5, RFC 5443: LDP-IGP synchronization goes inside the IGP's own
/// context (`router ospf`), whichever render made it.
fn ldp_sync(conf: &mut Conf, cfg: &Config) {
    let lines = corerouter_proto_mpls::igp_sync_lines(&cfg.routing.mpls);
    if lines.is_empty() {
        return;
    }
    for n in conf
        .nodes
        .iter_mut()
        .filter(|n| n.line == "router ospf" || n.line.starts_with("router ospf "))
    {
        for l in &lines {
            if !n.children.iter().any(|c| &c.line == l) {
                n.children.push(crate::conf::Node {
                    line: l.clone(),
                    children: Vec::new(),
                });
            }
        }
    }
}

/// `conf` split by daemon: each daemon's part, in [`Daemon::ALL`] order,
/// with the daemons that get nothing left out.
pub fn by_daemon(table: Owned, conf: &Conf) -> Vec<(Daemon, Conf)> {
    let mut out: Vec<(Daemon, Conf)> = Vec::new();
    for d in Daemon::ALL {
        let nodes: Vec<_> = conf
            .nodes
            .iter()
            .filter(|n| daemons_of(table, &n.line).contains(&d))
            .filter_map(|n| part_of(d, n))
            .collect();
        if !nodes.is_empty() {
            out.push((d, Conf { nodes }));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_model::{Asn, BgpInstance};

    #[test]
    fn renders_the_bgp_instances_for_bgpd() {
        let mut cfg = Config::default();
        cfg.routing.bgp.insert(
            "default".into(),
            BgpInstance {
                name: "default".into(),
                asn: Asn(65000),
                router_id: [10, 0, 0, 1].into(),
                disabled: true,
                comment: String::new(),
            },
        );
        let conf = render(&cfg, &|_| None).unwrap();
        assert_eq!(conf.nodes.len(), 1);
        assert_eq!(conf.nodes[0].line, "router bgp 65000");
        assert!(
            conf.nodes[0]
                .children
                .iter()
                .any(|c| c.line == "bgp shutdown")
        );
        let parts = by_daemon(OWNED, &conf);
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].0, Daemon::Bgpd);
        assert!(owned("router bgp 65000 view x"));
        assert!(owned("mpls ldp"));
        assert!(!owned("hostname r1"));
    }

    #[test]
    fn ldp_goes_to_ldpd_and_sync_into_router_ospf() {
        use corerouter_model::mpls::{LdpInstance, LdpInterface};
        let mut cfg = Config::default();
        let e1: corerouter_model::IfName = "ether1".parse().unwrap();
        cfg.routing.mpls.ldp = Some(LdpInstance::new([10, 0, 0, 1].into()));
        cfg.routing
            .mpls
            .ldp_interfaces
            .insert(e1, LdpInterface::default());
        let conf = render(&cfg, &|_| None).unwrap();
        let parts = by_daemon(OWNED, &conf);
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].0, Daemon::Ldpd);
        assert_eq!(parts[0].1.nodes[0].line, "mpls ldp");
        // With an OSPF context (G3.4 renders it), sync lands inside it.
        let mut c2 = Conf::parse("router ospf\n ospf router-id 10.0.0.1\n").unwrap();
        ldp_sync(&mut c2, &cfg);
        assert!(
            c2.nodes[0]
                .children
                .iter()
                .any(|c| c.line == "mpls ldp-sync")
        );
        ldp_sync(&mut c2, &cfg);
        assert_eq!(
            c2.nodes[0]
                .children
                .iter()
                .filter(|c| c.line == "mpls ldp-sync")
                .count(),
            1
        );
    }

    #[test]
    fn ospf_interfaces_split_by_daemon() {
        let conf = Conf::parse(
            "interface ether1\n ip ospf area 0.0.0.0\n ipv6 ospf6 area 0.0.0.0\n description uplink\nexit\n\
             interface ether9\n description zebra's\nexit\n\
             router ospf6\nexit\nrouter ospf\nexit\n\
             route-map CR-O2-a-connected permit 1\nexit\nroute-map CR-x permit 10\nexit\n",
        )
        .unwrap();
        let parts = by_daemon(OWNED, &conf);
        let get = |d: Daemon| {
            parts
                .iter()
                .find(|(x, _)| *x == d)
                .map(|(_, c)| c.render())
                .unwrap_or_default()
        };
        assert_eq!(
            get(Daemon::Ospfd),
            "interface ether1\n ip ospf area 0.0.0.0\nexit\nrouter ospf\nroute-map CR-O2-a-connected permit 1\n"
        );
        assert_eq!(
            get(Daemon::Ospf6d),
            "interface ether1\n ipv6 ospf6 area 0.0.0.0\nexit\nrouter ospf6\n"
        );
        assert_eq!(get(Daemon::Bgpd), "route-map CR-x permit 10\n");
    }
}
