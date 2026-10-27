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
pub const OWNED: Owned = &[("router bgp ", &[Daemon::Bgpd])];

/// A table of owned contexts: header prefix → daemons that take it.
pub type Owned = &'static [(&'static str, &'static [Daemon])];

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
    let text = corerouter_proto_bgp::render_all(&cfg.routing, open).map_err(RenderError::Proto)?;
    Ok(Conf::parse(&text)?)
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
            .cloned()
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
        assert!(!owned("hostname r1"));
    }
}
